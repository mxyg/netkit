//go:build windows

package netif

import (
	"context"
	"os/exec"
	"time"
)

// systemDNSServers Windows：优先用结构化的 Get-DnsClientServerAddress，拿不到再退回 WMI。
//
// ★ 为什么要留 WMI 这条路：Get-DnsClientServerAddress 是 Win8+ 的 cmdlet，
//
//	而现场的 Win7 机器还不少（老板 2026-09-19 特别交代 Win7 要单独出包）。
//	Win32_NetworkAdapterConfiguration 从 XP 就有，只是它给的是网卡描述而不是别名，
//	所以退回来时 iface 会显得"不像网卡名" —— 这是取舍，不是 bug。
const dnsServerScript = `
$a = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses } |
  Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json -Compress
if ($a) { $a } else {
  Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.DNSServerSearchOrder } |
    Select-Object @{n='InterfaceAlias';e={$_.Description}},
                  @{n='ServerAddresses';e={$_.DNSServerSearchOrder}} |
    ConvertTo-Json -Compress
}`

func systemDNSServers() ([]DNSServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", dnsServerScript).Output()
	if err != nil {
		return nil, err
	}
	return parseWinDNSServer(string(b)), nil
}
