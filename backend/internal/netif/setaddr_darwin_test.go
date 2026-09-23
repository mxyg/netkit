//go:build darwin

package netif

import "testing"

const hwPortsSample = `Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 84:2f:57:a6:41:96

Hardware Port: USB 10/100/1000 LAN
Device: en5
Ethernet Address: 00:e0:4c:68:00:01

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 00:00:00:00:00:00
`

func TestParseServiceFor(t *testing.T) {
	// networksetup 的设地址命令只认服务名，映射错了就设到别的卡上
	if svc, err := parseServiceFor(hwPortsSample, "en5"); err != nil || svc != "USB 10/100/1000 LAN" {
		t.Errorf("en5 该映射到 USB 网卡服务名，拿到 %q %v", svc, err)
	}
	if svc, err := parseServiceFor(hwPortsSample, "en0"); err != nil || svc != "Wi-Fi" {
		t.Errorf("en0 该映射到 Wi-Fi，拿到 %q %v", svc, err)
	}
	if _, err := parseServiceFor(hwPortsSample, "en9"); err == nil {
		t.Error("不存在的网卡该报错，不能瞎映射")
	}
}
