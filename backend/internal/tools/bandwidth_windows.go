//go:build windows

package tools

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// readLinkCounters Windows：PowerShell 问 Get-NetAdapterStatistics 拿每块网卡的累计字节。
//
// ★ 不用 `netstat -e`：那个只给一张总账（所有网卡加在一起），问不出「是哪块口在忙」。
//
//	而现场这句话十次有八次是关于两块口之间的选择的 —— 同时插着有线和 USB 网卡、
//	或者开了共享上网带出一块虚拟网桥的机器，总量会把毛病混成一团。
//	Name 是中文别名（「以太网」），按名字匹配出口网卡时就靠它和 Get-NetRoute 的
//	InterfaceAlias 同源，两边都是系统给的名字，不自己造。
func readLinkCounters(ctx context.Context) ([]linkCount, error) {
	script := "$ErrorActionPreference='SilentlyContinue'; " +
		"@(Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes) | ConvertTo-Json -Compress"
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil && len(strings.TrimSpace(string(out))) == 0 {
		return nil, fmt.Errorf("%w：PowerShell 问不到网卡统计（%s）", errBandwidthSource, err)
	}
	cs, err := parseNetAdapterStats(string(out))
	if err != nil {
		return nil, fmt.Errorf("%w：%s", errBandwidthSource, err)
	}
	if len(cs) == 0 {
		return nil, fmt.Errorf("%w：Get-NetAdapterStatistics 给了空表", errBandwidthSource)
	}
	return cs, nil
}

// parseNetAdapterStats 在不带构建标记的 bandwidth_parse.go 里：
// Windows 那条「一条一个对象时不给方括号」的分支，必须能在开发机上被同一批测试解一遍 ——
// 留在 windows 文件里就只剩编译过、从没被解过。

// readProcBytes Windows：这台机器上**数不到**每个进程收发多少字节。
//
// ★★ 为什么老老实实报 none，而不是退化成「按连接数凑一个名次」：
//
//	按进程网络字节在这台系统上只有两条路 —— ETW 的 Microsoft-Windows-Kernel-Network
//	（要管理员，而且是设计里划给「连接级观测/抓包」那一期的活），
//	或者 iphlpapi 的 GetPerTcpConnectionEStats（同样要管理员，且只有 TCP）。
//	用 netstat 的连接条数冒充「谁在吃带宽」，一条长连接能被打败给十个空转进程 ——
//	那是指错人，比说「数不到」坏得多。
//
// 判定层拿到 none 会走 bandwidth-link-only：网卡上过多少照样说清，
// 只是不点名，并把「要点名得用管理员的连接级观测」这句下一步给出去。
func readProcBytes(context.Context, time.Duration) (procSample, error) {
	return procSample{attribution: bwAttribNone,
		reason: "Windows 上按进程数网络字节要走 ETW 或者 iphlpapi 的每连接统计，两者都要管理员权限，" +
			"而这个工具不擅自替你提权",
		next: "要在这台机器上点出名：用管理员权限开资源监视器的「网络」那一栏看，" +
			"或者等这台的连接级观测（抓包一期）做进来；先按网卡这一栏判断「这条链路忙不忙」"}, nil
}
