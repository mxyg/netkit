package netif

import (
	"net"
	"net/netip"
	"strings"
)

// netipFrom 把标准库的 net.IP 转成 netip.Addr。
//
// ★ 必须 Unmap：net.IPNet.IP 里的 v4 地址有时是 4 字节、有时是 16 字节的 v4-in-v6 形式，
// 不 Unmap 的话同一个 192.168.1.1 会变成两个互不相等的值 —— 拿它当 map key 就出鬼了。
// 这正是我们不再用 net.IP 的原因之一。
func netipFrom(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// virtualPrefixes 常见虚拟网卡名前缀。判断不了的一律当物理网卡，
// 宁可多列一张也不要把用户真正在用的网卡藏起来。
//
// 注意这里**故意不包含** ppp / usb / rndis / enx：
// 现场很常见的一种接法是「主板网口接内网，USB 网卡（或手机USB共享、4G棒）接公网」，
// 把它们当虚拟网卡过滤掉，用户就再也找不到自己的上行出口了。
var virtualPrefixes = []string{
	"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "utun", "tun", "tap",
	"wg", "zt", "tailscale", "anpi", "awdl", "llw", "bridge", "gif", "stf",
	"Hyper-V", "vEthernet", "VMware", "VirtualBox", "TAP-Windows", "Loopback Pseudo",
}

// usbLanPrefixes USB 转网线网卡的常见命名（USB 网口芯片、驱动名）。
// 现场常见接法：USB 网线网卡接内网刷卡机，跟 usb4GPrefixes 描述的
// USB/4G 拨号卡是完全不同的用途，不能用同一个标签，否则用户分不清哪张是内网口。
var usbLanPrefixes = []string{
	"usb", "enx", "USB", "Realtek USB", "AX88", "RTL8153",
}

// usb4GPrefixes USB 共享网络 / 4G 拨号上网卡的常见命名。
var usb4GPrefixes = []string{
	"rndis", "eem", "ncm", "ppp", "wwan", "ww", "cdc", "Remote NDIS", "移动宽带",
}

// USBKindNone / USBKindLAN / USBKind4G 是 USBKind 的取值。
const (
	USBKindNone = ""
	USBKindLAN  = "lan"
	USBKind4G   = "4g"
)

// USBKind 判断名字看起来像哪一类 USB 网卡：USB 网线网卡还是 USB/4G 拨号卡。
// 识别出来只是为了在界面上给一句提示，不影响任何功能判断 ——
// 真正判断哪张网卡能上外网，靠的是实测，不是靠名字。
func USBKind(name string) string {
	if matchesAny(name, usb4GPrefixes) {
		return USBKind4G
	}
	if matchesAny(name, usbLanPrefixes) {
		return USBKindLAN
	}
	return USBKindNone
}

// IsUSBLike 名字看起来像不像 USB 网卡 / USB 共享 / 4G 拨号。
func IsUSBLike(name string) bool { return USBKind(name) != USBKindNone }

// IsVirtualName 名字看起来像不像虚拟网卡。
func IsVirtualName(name string) bool { return matchesAny(name, virtualPrefixes) }

func matchesAny(name string, prefixes []string) bool {
	l := strings.ToLower(name)
	for _, p := range prefixes {
		if strings.HasPrefix(l, strings.ToLower(p)) || strings.Contains(name, p) {
			return true
		}
	}
	return false
}
