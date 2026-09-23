//go:build linux

package netif

import (
	"fmt"
	"os/exec"
	"strings"
)

func setStaticIPv4(iface, ip string, prefix int) error {
	cidr := fmt.Sprintf("%s/%d", ip, prefix)
	// replace 而不是 add：已有同地址时幂等，不报 "File exists"
	out, err := exec.Command("ip", "addr", "replace", cidr, "dev", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr replace 失败：%s %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func unsetStaticIPv4(iface, ip string, prefix int) error {
	cidr := fmt.Sprintf("%s/%d", ip, prefix)
	out, err := exec.Command("ip", "addr", "del", cidr, "dev", iface).CombinedOutput()
	if err != nil {
		// 已经不在了 = 目的达到（还原要幂等）
		if strings.Contains(string(out), "Cannot assign") || strings.Contains(string(out), "does not exist") {
			return nil
		}
		return fmt.Errorf("ip addr del 失败：%s %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
