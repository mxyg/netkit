//go:build darwin

package netif

import (
	"context"
	"os/exec"
	"time"
)

// systemDNSServers macOS：问 `scutil --dns`（见 dnsconf.go 里为什么不读 resolv.conf）。
func systemDNSServers() ([]DNSServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil {
		return nil, err
	}
	return parseScutilDNS(string(b)), nil
}
