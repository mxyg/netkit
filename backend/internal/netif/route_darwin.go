//go:build darwin

package netif

import (
	"context"
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
