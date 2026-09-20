package netif

import "testing"

func Test名字猜不出来时不许兜底成有线网口(t *testing.T) {
	// ★ 这一条是这个功能的底线。en0 在 MacBook 上是 Wi-Fi、在 Mac mini 上是网口；
	//   eth0 可能是板载也可能是 USB 网卡。兜底成 ethernet 等于把"不知道"
	//   伪装成"有线网口"——而用户就是照着这一列去插线的。
	for _, name := range []string{"en0", "en7", "eth0", "以太网 2", "办公网"} {
		if got := guessKind(name); got != KindUnknown {
			t.Errorf("%q 光看名字判不出来，应给 KindUnknown，实际 %q", name, got)
		}
	}
}

func Test按名字猜的那几类(t *testing.T) {
	cases := map[string]string{
		"wlan0": KindWiFi, "wlp3s0": KindWiFi, "Wi-Fi": KindWiFi, "无线网络连接": KindWiFi,
		"bnep0": KindBluetooth, "Bluetooth PAN": KindBluetooth,
		"Thunderbolt Ethernet": KindThunderbolt,
		"rndis0":               KindCellular, // 手机 USB 共享 / 4G 棒
		"enx001122334455":      KindUSBLan,   // USB 转网线
		"enp0s31f6":            KindEthernet, // systemd 的稳定命名，只有它稳定表示板载网口
	}
	for name, want := range cases {
		if got := guessKind(name); got != want {
			t.Errorf("%q 应是 %q，实际 %q", name, want, got)
		}
	}
}

func Test系统给的结论优先于名字(t *testing.T) {
	// 本机实测：en0 在这台 MacBook 上是 Wi-Fi。名字完全看不出来，
	// 必须以系统给的为准，并且标成 os（不是猜的）。
	k, src := kindOf("en0", false, false, KindWiFi)
	if k != KindWiFi || src != SrcOS {
		t.Errorf("系统说是 Wi-Fi 就该是 Wi-Fi/os，实际 %q/%q", k, src)
	}
	// 问不到系统时如实标成 name —— 界面据此加「可能是」
	if _, src := kindOf("wlan0", false, false, ""); src != SrcName {
		t.Errorf("按名字猜出来的必须标成 %q，实际 %q", SrcName, src)
	}
}

func Test回环和虚拟不报介质(t *testing.T) {
	// 用户要的是「这块不是真网卡」，不是它的链路层类型
	if k, _ := kindOf("lo0", true, false, KindEthernet); k != KindLoopback {
		t.Errorf("回环就是回环，实际 %q", k)
	}
	if k, _ := kindOf("docker0", false, true, ""); k != KindVirtual {
		t.Errorf("虚拟网卡应报 virtual，实际 %q", k)
	}
}

func Test每块网卡都有类型和来源(t *testing.T) {
	ns, err := Interfaces()
	if err != nil {
		t.Skip("这台机器读不到网卡：", err)
	}
	for _, n := range ns {
		if n.KindSrc != SrcOS && n.KindSrc != SrcName {
			t.Errorf("%s 的 kindSrc 必须说清结论从哪来，实际 %q", n.Name, n.KindSrc)
		}
	}
}
