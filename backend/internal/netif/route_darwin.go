//go:build darwin

package netif

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

// defaultRoutes macOS：问 `netstat -rn`，v4/v6 各一次（输出里不带族，靠 -f 区分）。
func defaultRoutes() ([]DefaultRoute, error) {
	var out []DefaultRoute
	for _, q := range []struct{ flag, family string }{{"inet", "ipv4"}, {"inet6", "ipv6"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		b, err := exec.CommandContext(ctx, "netstat", "-rn", "-f", q.flag).Output()
		cancel()
		if err != nil {
			continue // 一族读不到不拖累另一族
		}
		out = append(out, parseNetstatDefault(string(b), q.family)...)
	}
	return out, nil
}

// routes macOS / BSD：`netstat -rn -f inet|inet6` 各读一次。
//
// ★ 一族读不到不拖累另一族：这台机器关着 v6 时 inet6 那一次就是空的，
// 而 v4 的整张表照样是用户要的东西。
func routes() ([]Route, error) {
	var out []Route
	for _, q := range []struct{ flag, family string }{{"inet", "ipv4"}, {"inet6", "ipv6"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		b, err := exec.CommandContext(ctx, "netstat", "-rn", "-f", q.flag).Output()
		cancel()
		if err != nil {
			continue
		}
		out = append(out, parseNetstatTable(string(b), q.family)...)
	}
	return out, nil
}

// routeFor macOS：问 `route -n get <目的地>`，让系统自己说它选哪条。
//
// ★★ 「命令失败」**一律不当成「没有路」**，这一点是被实测钉住的：
//
//	本机 v6 只有 utun（VPN）上的默认路由时，`route -n get -inet6` 会回
//	「writing to routing socket: not in table」，可表里明明有一条 default。
//	把这句话读成「没有路由」就会指着一台能上 v6 的机器说它没路。
//	所以这里失败就返回错误，由调用方降级去按表算 —— 判定只在我们**确实读到表**时才下。
func routeFor(ctx context.Context, dst netip.Addr) (Route, error) {
	args := []string{"-n", "get"}
	if dst.Is6() {
		args = append(args, "-inet6")
	}
	cmd := exec.CommandContext(ctx, "route", append(args, dst.String())...)
	b, err := cmd.Output()
	if err != nil {
		return Route{}, err
	}
	r := parseRouteGet(string(b), dst)
	if r.Iface == "" {
		// 输出里没有 interface 栏 = 我们没读懂这段输出，不当成一条有效结论
		return Route{}, errNoRouteCmd
	}
	return r, nil
}
