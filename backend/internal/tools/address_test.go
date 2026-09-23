package tools

import (
	"net/netip"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
)

func TestV4Conflict(t *testing.T) {
	mk := func(name string, cidrs ...string) netif.NIC {
		n := netif.NIC{Name: name}
		for _, c := range cidrs {
			p := netip.MustParsePrefix(c)
			n.Addrs = append(n.Addrs, netaddr.Addr{IP: p.Addr(), Prefix: p.Bits()})
		}
		return n
	}
	nics := []netif.NIC{
		mk("en0", "192.168.0.101/24"),
		mk("en5", "169.254.3.9/16"),
		mk("lo0", "127.0.0.1/8"),
	}
	nics[2].Loop = true // 真 Interfaces() 会给回环打上这个标志
	// ★ 和 Wi-Fi（en0）同段必须拦下：两块网卡抢一段路由 = 玄学断网
	if who, hit := v4Conflict(nics, "en5", netip.MustParsePrefix("192.168.0.1/24")); !hit || who != "en0" {
		t.Errorf("该判和 en0 重叠，拿到 hit=%v who=%s", hit, who)
	}
	// 换到没人用的段就放行
	if _, hit := v4Conflict(nics, "en5", netip.MustParsePrefix("192.168.50.1/24")); hit {
		t.Error("192.168.50.0/24 没人用，不该拦")
	}
	// 给自己（skip）设同段不算冲突；回环不参与
	if _, hit := v4Conflict(nics, "en0", netip.MustParsePrefix("192.168.0.200/24")); hit {
		t.Error("给自己网卡换地址不该判冲突")
	}
	if _, hit := v4Conflict(nics, "en5", netip.MustParsePrefix("127.0.0.5/24")); hit {
		t.Error("回环不该参与冲突判定")
	}
	// 子网被包含也算重叠：/16 罩住了 en0 的 /24
	if _, hit := v4Conflict(nics, "en5", netip.MustParsePrefix("192.168.99.1/16")); !hit {
		t.Error("192.168.0.0/16 罩住了 en0 的段，该拦")
	}
}

func TestPrefixEnd(t *testing.T) {
	for _, tc := range []struct{ pfx, want string }{
		{"192.168.50.0/24", "192.168.50.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"192.168.1.128/25", "192.168.1.255"},
		{"192.168.1.0/30", "192.168.1.3"},
	} {
		got := prefixEnd(netip.MustParsePrefix(tc.pfx)).String()
		if got != tc.want {
			t.Errorf("prefixEnd(%s)=%s，要 %s", tc.pfx, got, tc.want)
		}
	}
}

func TestAddressSetRejects(t *testing.T) {
	// 这些分支在碰到系统之前就该被拒
	for _, a := range []addressSetArgs{
		{Iface: "en5", IP: "999.1.1.1"},      // 不是地址
		{Iface: "en5", IP: "fe80::1"},        // 不是 v4
		{Iface: "en5", IP: "8.8.8.8"},        // 不是私网
		{Iface: "en5", IP: "169.254.50.1"},   // 链路本地不行
		{Iface: "", IP: "192.168.50.1"},      // 缺网卡名
		{Iface: "没有这块卡", IP: "192.168.50.1"}, // 网卡不存在
	} {
		if _, _, err := validateAddressArgs(a); err == nil {
			t.Errorf("%+v 该被拒，却放行了", a)
		}
	}
	// 拒绝的理由必须是人话，不是 "invalid argument"
	_, _, err := validateAddressArgs(addressSetArgs{Iface: "en5", IP: "8.8.8.8"})
	if err == nil || !strings.Contains(err.Error(), "私网") {
		t.Errorf("拒公网地址时该说清「必须用私网」：%v", err)
	}
}
