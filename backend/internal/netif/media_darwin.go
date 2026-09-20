package netif

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"
)

// kinds 在 macOS 上问系统：`networksetup -listallhardwareports`。
//
// 它给的是**系统偏好设置里那张表**，也就是用户在「网络」面板里看到的同一份东西：
//
//	Hardware Port: Wi-Fi
//	Device: en0
//	Ethernet Address: 84:2f:57:a6:41:96
//
// ★★ 为什么非要问它：这台开发机上 **en0 是 Wi-Fi**，而 Mac mini、工控机上
// en0 常常是有线网口。按名字猜必错一半，而这一列正是用户拿去插线的依据。
//
// ★ 按 **Device 名**对应，不按 MAC。Wi-Fi 开了「专用地址」后
// 网卡实际在用的 MAC 和这里打印的不是同一个（本机实测：这里是 84:2f:57:…，
// `net.Interfaces()` 报的是 aa:d9:54:…）。拿 MAC 对，Wi-Fi 那一块正好对不上。
func kinds() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil // 问不到就回落到按名字猜，不让整个枚举失败
	}
	m := map[string]string{}
	var port string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		case strings.HasPrefix(line, "Device:"):
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev != "" && port != "" {
				if k := portKind(port); k != KindUnknown {
					m[dev] = k
				}
			}
		}
	}
	return m
}

// portKind 把 macOS 的硬件端口名翻成我们的类型。
//
// ★ 判断顺序有讲究：「USB 10/100/1000 LAN」同时含 USB 和 LAN，
// 先撞上 LAN 就会被报成板载网口 —— 用户会去找一个机器上根本没有的口。
func portKind(port string) string {
	p := strings.ToLower(port)
	switch {
	case strings.Contains(p, "wi-fi"), strings.Contains(p, "airport"), strings.Contains(p, "wifi"):
		return KindWiFi
	case strings.Contains(p, "bluetooth"):
		return KindBluetooth
	// iPhone/iPad 的 USB 共享网络：走的是手机的蜂窝或 Wi-Fi，不是本机网口
	case strings.Contains(p, "iphone"), strings.Contains(p, "ipad"), strings.Contains(p, "modem"):
		return KindCellular
	case strings.Contains(p, "usb"):
		return KindUSBLan
	case strings.Contains(p, "thunderbolt"):
		return KindThunderbolt
	case strings.Contains(p, "ethernet"), strings.Contains(p, "lan"):
		return KindEthernet
	}
	return KindUnknown
}
