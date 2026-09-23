//go:build linux

package netif

import (
	"context"
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
