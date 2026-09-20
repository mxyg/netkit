package netif

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

// kinds 在 Windows 上问系统：PowerShell 的 `Get-NetAdapter`。
//
// ★★ 为什么必须问：Windows 上网卡名是**用户可以随便改的**（「以太网 2」「办公网」
// 「小明的网卡」），而且默认名也分不出无线有线。名字在这个平台上完全不能当判据。
//
// 用 `NdisPhysicalMedium`（内核给的物理介质枚举，NDIS_PHYSICAL_MEDIUM）而不是
// 描述文字：文字会随驱动、随系统语言变，枚举值不会。
//
// ★ 起子进程有代价（PowerShell 冷启动能到几百毫秒），所以**整机只问一次**，
// 超时 8 秒后放弃并回落到按名字猜 —— 慢一点也不能让「看网卡」这一步卡死。
func kinds() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetAdapter -IncludeHidden | Select-Object Name,NdisPhysicalMedium,InterfaceDescription | ConvertTo-Json -Compress")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var rows []struct {
		Name   string `json:"Name"`
		Medium int    `json:"NdisPhysicalMedium"`
		Desc   string `json:"InterfaceDescription"`
	}
	// ★ 只有一块网卡时 ConvertTo-Json 给的是**对象不是数组**。
	//   不处理这一种，单网卡机器（很多工控机就是）会整列空白。
	if err := json.Unmarshal(out, &rows); err != nil {
		var one struct {
			Name   string `json:"Name"`
			Medium int    `json:"NdisPhysicalMedium"`
			Desc   string `json:"InterfaceDescription"`
		}
		if json.Unmarshal(out, &one) != nil {
			return nil
		}
		rows = append(rows, one)
	}
	m := map[string]string{}
	for _, r := range rows {
		if k := mediumKind(r.Medium, r.Desc); k != KindUnknown {
			m[r.Name] = k
		}
	}
	return m
}

// mediumKind 把 NDIS_PHYSICAL_MEDIUM 枚举翻成我们的类型。
// 取值见 Windows 的 ndis.h；这里只列现场会遇到的。
func mediumKind(medium int, desc string) string {
	switch medium {
	case 1: // NdisPhysicalMediumWirelessLan（老驱动用这个报 Wi-Fi）
		return KindWiFi
	case 9: // NdisPhysicalMedium802_3 —— 以太网
		// ★ USB 网卡在 Windows 上同样报成 802.3，靠描述文字再分一道。
		//   分不出来就当普通网口，不瞎猜。
		if isUSBDesc(desc) {
			return KindUSBLan
		}
		return KindEthernet
	case 8: // NdisPhysicalMediumBluetooth
		return KindBluetooth
	case 13: // NdisPhysicalMediumWiMax
		return KindCellular
	case 14: // NdisPhysicalMediumNative802_11 —— 现在的 Wi-Fi 走这个
		return KindWiFi
	case 16: // NdisPhysicalMediumWiredWAN / WWAN
		return KindCellular
	case 0: // NdisPhysicalMediumUnspecified —— 虚拟网卡基本都落这儿
		return KindVirtual
	}
	return KindUnknown
}

func isUSBDesc(desc string) bool {
	d := strings.ToLower(desc)
	return strings.Contains(d, "usb") || strings.Contains(d, "ax88") || strings.Contains(d, "rtl8153")
}
