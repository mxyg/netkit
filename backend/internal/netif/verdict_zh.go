package netif

import "strings"

// ── 简体中文渲染 ──
//
// ★★ 这个文件是**唯一**允许在本包里出现给用户看的整句中文的地方，而且它是临时的。
//
//	正式的文案在前端词典（stage 那套「中文原文就是 key」，见 docs/设计.md「多语种」）。
//	后端留一份中文渲染只为三件事：命令行输出、日志、测试里好读。
//
// ★ 界面**不要**调它。界面拿 Verdict 自己渲染 —— 否则多语种就又回到
// 「后端拼好句子发给前端」的老路上，日语俄语的语序照样没地方放。
//
// 所以这里也刻意**不做**语序上的花活：中文能拼就拼，别的语言各自有各自的拼法，
// 那是词典的事，不是这个文件的事。

// NoteZH 把判定渲染成一句简体中文。**仅供命令行 / 日志 / 测试使用。**
func (v Verdict) NoteZH() string {
	usb := ""
	switch v.USB {
	case USBKindLAN:
		usb = "（看起来是 USB 网线网卡）"
	case USBKind4G:
		usb = "（看起来是 USB 共享网络 / 4G 上网卡）"
	}
	nets := strings.Join(v.Networks, "、")

	switch v.Code {
	case VerdictLoopback:
		return "本机回环，仅本机内部使用，不用管"
	case VerdictVirtual:
		return "虚拟网卡（容器 / 虚拟机 / VPN 创建的），一般不用管"
	case VerdictDown:
		return "网卡已禁用" + usb
	case VerdictNoCarrier:
		return "网卡已启用但没检测到连接，可能网线没插好或设备没插稳" + usb
	case VerdictDualStack:
		return "双栈正常，网段 " + nets + usb
	case VerdictV4Only:
		return "IPv4 正常（IPv6 没有可用地址），网段 " + nets + usb
	case VerdictV6Only:
		return "IPv6 正常（IPv4 没有可用地址），网段 " + nets + usb
	case VerdictLinkLocal:
		return "只有 IPv6 链路本地地址（fe80::），说明网卡本身是好的、但没拿到能上网的地址：" +
			"IPv4 这边 DHCP 没要到，IPv6 这边也没收到路由通告（RA）。" +
			"检查是否接了路由器，或手工设置固定 IP" + usb
	case VerdictNoAddress:
		return "没有拿到任何 IP 地址，检查是否接了路由器或需要手工设置固定 IP" + usb
	}
	return string(v.Code)
}
