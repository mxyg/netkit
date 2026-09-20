package netif

import "strings"

// 这块网卡是什么**介质**——无线、网口、USB 网卡、4G 棒、蓝牙、虚拟……
//
// ★★ 为什么单独一层，而不是继续按名字猜
//
// 名字猜不准，而且**猜错的方向恰好是最坑的那个**：
//
//	en0   在 MacBook 上是 Wi-Fi，在 Mac mini / 工控机上是有线网口
//	eth0  在树莓派上可能是板载网口，也可能是 USB 网卡枚举出来的
//	以太网 2  Windows 上这个名字什么都可能是，用户还能随手改名
//
// 现场判断「该把设备插哪个口」正是靠这一列。给错了，人就照着错的接线，
// 比不给还糟。所以这里的纪律和 net.discover 里 `hasIPv4` 那条一样：
//
//	★ **能问系统就问系统，问不到就如实说是猜的，不许把猜测当事实。**
//
// 于是每块网卡给两样东西：
//
//	Kind    是什么介质
//	KindSrc 这个结论**从哪来**（os = 系统告诉我们的，name = 按名字猜的）
//
// 界面拿 KindSrc 决定要不要加「可能是」。AI 拿它决定要不要复核。
// 各平台怎么问系统，见 media_darwin.go / media_linux.go / media_windows.go。
const (
	KindUnknown     = ""            // 问不出来，也猜不出来
	KindWiFi        = "wifi"        // 无线网卡
	KindEthernet    = "ethernet"    // 有线网口（板载或独立网卡）
	KindUSBLan      = "usb-lan"     // USB 转网线网卡
	KindCellular    = "cellular"    // 4G/5G 上网卡、手机 USB 共享网络
	KindBluetooth   = "bluetooth"   // 蓝牙共享网络
	KindThunderbolt = "thunderbolt" // 雷雳网桥 / 雷雳转网口
	KindVirtual     = "virtual"     // 容器、虚拟机、VPN 建出来的
	KindLoopback    = "loopback"    // 回环
)

// KindSrc 的取值。
const (
	SrcOS   = "os"   // 系统明确告诉我们的
	SrcName = "name" // 按名字猜的 —— 只能当提示，不能当事实
)

// kinds 一次性问出本机所有网卡的介质类型，key 是网卡名。
//
// ★ 整机问一次、不是每块网卡问一次：macOS / Windows 上这一步要起子进程，
// 24 块网卡就是 24 次 fork，`net.interfaces` 会从毫秒级掉到秒级。
// 问不出来返回 nil，调用方自动回落到按名字猜 —— 这一步失败绝不能让枚举整个失败。
// 实现按平台分文件（media_darwin.go / media_linux.go / media_windows.go / media_other.go）。

// kindOf 给一块网卡定类型。先用系统给的，没有再按名字猜。
//
// 参数 osKind 是 kinds() 查出来的结果（可能为空）。
func kindOf(name string, loop, virtual bool, osKind string) (kind, src string) {
	// ★ 回环和虚拟优先于系统给的介质：Linux 上 lo 的 type 也能读出来，
	//   但用户要的是「这块不是真网卡」这个结论，不是它的链路层类型。
	if loop {
		return KindLoopback, SrcOS
	}
	if osKind != "" {
		return osKind, SrcOS
	}
	if virtual {
		return KindVirtual, SrcName
	}
	return guessKind(name), SrcName
}

// wifiPrefixes 无线网卡的常见命名。
//
// ★ 故意**不含** en / eth：那两个在不同机器上什么都可能是（见本文件开头）。
// 宁可给 unknown，也不要给一个看着确定、实际靠不住的「Wi-Fi」。
var wifiPrefixes = []string{
	"wlan", "wlp", "wlx", "wl", "wifi", "Wi-Fi", "Wireless", "WLAN", "802.11", "无线",
}

// btPrefixes 蓝牙共享网络。
var btPrefixes = []string{"bnep", "Bluetooth", "蓝牙"}

// tbPrefixes 雷雳网桥 / 雷雳转网口。
var tbPrefixes = []string{"Thunderbolt", "雷雳"}

// guessKind 纯按名字猜。猜不出来就给 KindUnknown ——
// ★ **不许兜底成 ethernet**：那等于把「不知道」伪装成「有线网口」，
// 而用户就是照着这一列去插线的。
func guessKind(name string) string {
	switch {
	case matchesAny(name, wifiPrefixes):
		return KindWiFi
	case matchesAny(name, btPrefixes):
		return KindBluetooth
	case matchesAny(name, tbPrefixes):
		return KindThunderbolt
	}
	switch USBKind(name) {
	case USBKind4G:
		return KindCellular
	case USBKindLAN:
		return KindUSBLan
	}
	// 只有这几个在所有平台上都稳定表示"有线网口"
	l := strings.ToLower(name)
	if strings.HasPrefix(l, "eno") || strings.HasPrefix(l, "enp") || strings.HasPrefix(l, "ens") {
		return KindEthernet
	}
	return KindUnknown
}
