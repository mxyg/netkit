//go:build linux

package netif

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

// defaultRoutes Linux：`ip -4/-6 route show default`。
func defaultRoutes() ([]DefaultRoute, error) {
	var out []DefaultRoute
	for _, q := range []struct{ flag, family string }{{"-4", "ipv4"}, {"-6", "ipv6"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		b, err := exec.CommandContext(ctx, "ip", q.flag, "route", "show", "default").Output()
		cancel()
		if err != nil {
			continue
		}
		out = append(out, parseIPRouteDefault(string(b), q.family)...)
	}
	return out, nil
}

// routes Linux：`ip route show` + `ip -6 route show`，读**主表全表**。
//
// ★ 只读主表是这里已知的局限，而且是**故意的**：Linux 常有策略路由
//
//	（ip rule 给每块 DHCP 网卡挂一张自己的表），只看主表会挑到系统根本不会用的路由。
//	所以本平台的选路结论优先走下面的 routeFor（`ip route get` 会尊重 ip rule），
//	全表只用来给人看和在没有 ip 命令时兜底。
func routes() ([]Route, error) {
	var out []Route
	for _, q := range []struct{ flag, family string }{{"-4", "ipv4"}, {"-6", "ipv6"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		b, err := exec.CommandContext(ctx, "ip", q.flag, "route", "show").Output()
		cancel()
		if err != nil {
			continue
		}
		out = append(out, parseIPRouteTable(string(b), q.family)...)
	}
	return out, nil
}

// routeFor Linux：`ip route get <目的地>` —— 系统自己给的、**含策略路由**的答案。
//
//	192.168.1.1 via 192.168.0.1 dev en0 src 192.168.0.101 uid 501
//	    cache
//
// ★ 这一族命令的输出第一栏就是目的地本身（不是网段），所以照旧按表算的人
//
//	会给出一个不同的 destination；这里把 cache 行里真正的网段留着由表去补。
func routeFor(ctx context.Context, dst netip.Addr) (Route, error) {
	b, err := exec.CommandContext(ctx, "ip", "route", "get", dst.String()).Output()
	if err != nil {
		return Route{}, err
	}
	r, ok := parseIPRouteGet(string(b), dst)
	if !ok {
		return Route{}, errNoRouteCmd
	}
	return r, nil
}
