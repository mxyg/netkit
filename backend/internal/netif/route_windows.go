//go:build windows

package netif

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

// defaultRoutes Windows：PowerShell 问 Get-NetRoute，一次拿回 v4/v6 两条默认路由的 JSON。
//
// ★ 不用 `netstat -rn`：它的 IPv6 表列宽和 v4 不一致、还本地化表头，按列号解析容易错。
//
//	Get-NetRoute 给的是结构化对象，稳。
func defaultRoutes() ([]DefaultRoute, error) {
	script := "Get-NetRoute -DestinationPrefix 0.0.0.0/0,::/0 -ErrorAction SilentlyContinue | " +
		"Select-Object DestinationPrefix,NextHop,InterfaceAlias | ConvertTo-Json -Compress"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil, nil // 读不到就当没有，不当错误：体检会如实报「拿不到默认路由」
	}
	return parseGetNetRoute(string(b)), nil
}

// routes Windows：Get-NetRoute 拿全表。
//
// ★★ 度量在这里是**两段相加**的：RouteMetric（这条路由自己的）+ InterfaceMetric
//
//	（那块网卡整体的）。只比 RouteMetric 会挑错默认路由 —— 多网卡机器上
//	「两条都是 0.0.0.0/0、谁优先」就是靠这个和算出来的，所以顺手多问一次
//	Get-NetIPInterface，回到 Go 里按 InterfaceIndex 拼。
func routes() ([]Route, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	script := "$ErrorActionPreference='SilentlyContinue'; " +
		"$r=@(Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,InterfaceIndex); " +
		"$m=@(Get-NetIPInterface | Select-Object InterfaceIndex,InterfaceMetric); " +
		"ConvertTo-Json -Compress -Depth 3 -InputObject @{r=$r; m=$m}"
	b, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil, nil // 读不到不报错：调用方要拿这个事实去说「这台机器上读不到」
	}
	return parseWinRouteTable(string(b)), nil
}

// routeFor Windows：这台机器上**不额外问系统**，让调用方用上面那张表自己算。
//
// ★ 理由不是偷懒：Windows 侧我们没有一条既稳又不改动、且能当场核实的命令给出
//
//	等价答案（Find-NetRoute 的输出形状随版本变）。宁缺勿假 —— 返回错误，
//	工具会降级成 from=table 并在结论里说明这是按表算出来的。
func routeFor(ctx context.Context, dst netip.Addr) (Route, error) {
	return Route{}, errNoRouteCmd
}
