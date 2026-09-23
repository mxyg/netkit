//go:build windows

package netif

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Windows 用 netsh。name= 认的是「网络连接」里的名字（如 "以太网 2"），
// 和 net.Interfaces() 给的名字一致。
func setStaticIPv4(iface, ip string, prefix int) error {
	mask := net.IP(net.CIDRMask(prefix, 32)).String()
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+iface, "static", ip, mask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address 失败：%s %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func unsetStaticIPv4(iface, ip string, prefix int) error {
	out, err := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+iface, "dhcp").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address dhcp 失败：%s %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
