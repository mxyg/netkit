//go:build darwin

package tools

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// readLinkCounters macOS：`netstat -ibn`。
//
// ★ 不用 `nettop` 的接口行、也不自己走 getifaddrs：这个仓库在 macOS 上已经有
//
//	lsof / netstat -rn 这条「读系统自带命令」的路子，再开一份 syscall 层反而多一处
//	会随 macOS 版本变的解析面。列错位的可能交给解析层用真机输出钉住。
//
// ★★ -n 不是可选的：不带它 netstat 会给每个地址做一次反解，本机实测同一台机器
//
//	`netstat -ib` 要 30 秒、`-ibn` 只要 0.2 秒。这个工具要在两次采样之间夹一个
//	用户指定的窗口，起点慢三十秒等于把「数三秒」变成「数三十三秒」，
//	而且两份口径的时间窗就错开了。
func readLinkCounters(ctx context.Context) ([]linkCount, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/netstat", "-ibn").Output()
	// netstat 偶尔在某个接口消失时非零退出，但正文是完整的 —— 有正文就当成功。
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
		return nil, fmt.Errorf("%w：netstat -ibn（%s）", errBandwidthSource, err)
	}
	cs := parseNetstatIB(string(out))
	if len(cs) == 0 {
		return nil, fmt.Errorf("%w：netstat -ibn 输出了，但一行字节计数都没解出来", errBandwidthSource)
	}
	return cs, nil
}

// readProcBytes macOS：`nettop -P -x -d -L 2 -s <秒>`。
//
// ★ 为什么这一路不用自己做两次采样再相减：nettop 自己有 -d（delta）模式，
//
//	它在窗口里持续看着每个套接字，比「起两次进程各读一次快照」少一次误差来源
//	（窗口边界上刚断掉的连接在两次快照里都会算成 0）。
//
// ★ -P 只给按进程汇总的行（不给每条连接），一行一个进程；-x 出原始数字而不是
//
//	"1.2M" 这种给人看的后缀 —— 后缀一到 MiB 以上就把有效数字砍掉了。
//	-L 2 出两块：第一块是累计值，第二块才是这一窗的增量，解析层取最后一块。
func readProcBytes(ctx context.Context, window time.Duration) (procSample, error) {
	secs := int(window / time.Second)
	if secs < 1 {
		secs = 1
	}
	cmdCtx, cancel := context.WithTimeout(ctx, window+10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "/usr/bin/nettop",
		"-P", "-x", "-d", "-L", "2", "-s", strconv.Itoa(secs)).Output()
	text := string(out)
	if err != nil && nettopBlocksSeen(text) < 2 {
		return procSample{attribution: bwAttribNone,
			reason: "nettop 没跑出这一窗的增量（" + err.Error() + "）",
			next:   "确认这台机器上 /usr/bin/nettop 还在（它是系统自带的），以及这个账号有没有权限看别人的套接字"}, nil
	}
	rows := parseNettopCSV(text)
	if len(rows) == 0 {
		return procSample{attribution: bwAttribNone,
			reason: "nettop 输出了，但里面没有一列能当字节数用",
			next:   "这一版 macOS 的 nettop 列名和已知格式不同，只能先看网卡那一栏"}, nil
	}
	// macOS 上 nettop 看的是全系统 tcp+udp 的套接字，普通用户也读得到字节计数
	// （本机实测：root 起的 mDNSResponder 的字节数照样列出来），所以算数全。
	return procSample{procs: rows, attribution: bwAttribFull}, nil
}
