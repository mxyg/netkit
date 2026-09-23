//go:build linux

package netif

import "os"

// systemDNSServers Linux：读 /etc/resolv.conf。
//
// ★ 它是**当前生效**的那份（发行版会按 systemd-resolved / NetworkManager 重写），
//
//	所以直接读，不去调 resolvectl —— 那个在不用 systemd-resolved 的机器上根本没有。
func systemDNSServers() ([]DNSServer, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return parseResolvConf(string(b)), nil
}
