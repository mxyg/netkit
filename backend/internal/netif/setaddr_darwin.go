//go:build darwin

package netif

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// macOS 用 networksetup：它只认「网络服务名」（Wi-Fi、USB 10/100/1000 LAN），
// 不认 en0 这种接口名，所以先做一层映射。
func setStaticIPv4(iface, ip string, prefix int) error {
	svc, err := ServiceForIface(iface)
	if err != nil {
		return err
	}
	mask := net.IP(net.CIDRMask(prefix, 32)).String()
	out, err := exec.Command("networksetup", "-setmanual", svc, ip, mask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setmanual 失败：%s %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func unsetStaticIPv4(iface, ip string, prefix int) error {
	svc, err := ServiceForIface(iface)
	if err != nil {
		return err
	}
	out, err := exec.Command("networksetup", "-setdhcp", svc).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup -setdhcp 失败：%s %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ServiceForIface 把接口名（en0）映射成系统网络面板里的服务名（"Wi-Fi"）。
func ServiceForIface(iface string) (string, error) {
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return "", fmt.Errorf("问不到网络服务列表（networksetup 跑不了）：%s", err)
	}
	return parseServiceFor(string(out), iface)
}

// parseServiceFor 解析 -listallhardwareports 的输出：
//
//	Hardware Port: Wi-Fi
//	Device: en0
//	Ethernet Address: …
func parseServiceFor(out, iface string) (string, error) {
	var port string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		case strings.HasPrefix(line, "Device:"):
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev == iface && port != "" {
				return port, nil
			}
		}
	}
	return "", fmt.Errorf("系统网络设置里找不到 %s 对应的服务名 —— 这块网卡可能没在「网络」面板里注册", iface)
}
