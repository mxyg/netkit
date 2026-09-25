//go:build linux

package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// readLinkCounters Linux：/proc/net/dev。
//
// ★ 不跑 `netstat -ib`：精简系统上常常没有 net-tools，而 /proc 一定在。
func readLinkCounters(ctx context.Context) ([]linkCount, error) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("%w：读不到 /proc/net/dev（%s）", errBandwidthSource, err)
	}
	cs := parseProcNetDev(string(b))
	if len(cs) == 0 {
		return nil, fmt.Errorf("%w：/proc/net/dev 读到了，但一行字节计数都没解出来", errBandwidthSource)
	}
	return cs, nil
}

// readProcBytes Linux：`ss -tinp` 两次，按套接字把累计计数做一次差。
//
// ★★ 为什么这一路最多只到 partial，而且提权也变不成 full：
//
//  1. ss 的字节计数（bytes_sent / bytes_received）是 **TCP 才有**的。UDP 一路
//     内核不按套接字记累计字节，所以取流、DNS 这些 UDP 的量在这个口径里看不见
//     —— 换任何权限都看不见，要看得抓包。
//  2. 非管理员跑 ss 时，别人进程的套接字不带 users:(...)：看得见字节，不知道是谁。
//
// 两条都只往「少认」的方向错，不会冤枉某个进程在吃，所以数到的那些照样能用；
// 但结论必须带着这一栏说 —— 看到的这些在吃，看不见的还有。
func readProcBytes(ctx context.Context, window time.Duration) (procSample, error) {
	bin, err := exec.LookPath("ss")
	if err != nil {
		return procSample{attribution: bwAttribNone,
			reason: "这台 Linux 上没有 ss（iproute2），内核的按套接字字节计数没有别的用户态读法",
			next:   "装上 iproute2 再问一次；这一阵只能先看网卡那一栏"}, nil
	}
	first, err := runSS(ctx, bin)
	if err != nil {
		return procSample{attribution: bwAttribNone,
			reason: "ss 跑不动：" + err.Error(),
			next:   "确认这个账号能不能读内核的套接字表"}, nil
	}
	udp := hasUDPSockets(ctx, bin)
	select {
	case <-ctx.Done():
		return procSample{}, ctx.Err()
	case <-time.After(window):
	}
	second, err := runSS(ctx, bin)
	if err != nil {
		return procSample{attribution: bwAttribNone,
			reason: "窗口结束时第二次 ss 跑不动：" + err.Error(),
			next:   "确认这个账号能不能读内核的套接字表"}, nil
	}
	var reasons []string
	if second.unknown > 0 { // ★ 一条认不出主人就不算看全：看不见的等于没在吃？不行
		reasons = append(reasons, fmt.Sprintf("有 %d 条 TCP 连接看不到是哪个进程的（非管理员）", second.unknown))
	}
	if udp {
		reasons = append(reasons, "本机还有 UDP 套接字，而内核不按套接字记它的累计字节 —— 这一路看不见")
	} else {
		reasons = append(reasons, "另外 UDP 那一路内核不按套接字记累计字节（这次一条都没看到，不代表没有）")
	}
	attribution := bwAttribFull
	if len(reasons) > 0 {
		attribution = bwAttribPart
	}
	return procSample{
		procs:       ssDelta(first.socks, second.socks),
		attribution: attribution,
		reason:      strings.Join(reasons, "；"),
		next:        "要用管理员权限再问一次才能把别人的进程认出来；UDP 那一路无论什么权限都得靠抓包看",
	}, nil
}

// ssSnap 一次 ss 的结果：认得出主人的套接字，加上判 partial 要用的计数。
type ssSnap struct {
	socks   []ssSocket
	total   int // 一共多少条 TCP 记录
	unknown int // 没有 users:(...) 的条数
}

func runSS(ctx context.Context, bin string) (ssSnap, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// ★ -H 去掉表头：表头那一行列数和连接行不一样，留着就多一处能切错的地方。
	// -t 只看 TCP（UDP 没有字节计数，取了只会让人误以为在里面）；
	// -i 才带出 bytes_sent / bytes_received；-n 关掉反查；-p 带上归属。
	out, err := exec.CommandContext(cmdCtx, bin, "-H", "-t", "-i", "-n", "-p", "-a").Output()
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
		return ssSnap{}, err
	}
	socks, total := parseSSInetDiag(string(out), "tcp")
	return ssSnap{socks: socks, total: total, unknown: total - len(socks)}, nil
}

// hasUDPSockets 这台机器现在有没有 UDP 套接字 —— 只为把 partial 那句话说准：
// 「看不见 UDP」在一台跑满 DNS 客户端的机器上和一台纯 TCP 的机器上是两句不同的话。
func hasUDPSockets(ctx context.Context, bin string) bool {
	cmdCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, bin, "-H", "-u", "-n", "-a").Output()
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
		return false
	}
	_, total := parseSSInetDiag(string(out), "udp")
	return total > 0
}
