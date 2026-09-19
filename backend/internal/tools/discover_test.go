package tools

import (
	"net"
	"testing"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
)

// ★ 这条是这个文件里最要紧的测试。
// macOS 的 arp 打 MAC 不补零（3c:6d:66:ba:3:f7），ndp 补零（3c:6d:66:ba:03:f7）。
// 两张表对不上的后果不是"少一条信息"，而是**每台设备都被判成没配网**，
// 现场工程师照着结论去拔网线。所以这里逐位对齐。
func TestNormMAC补零后两张表能对上(t *testing.T) {
	fromARP := normMAC("3c:6d:66:ba:3:f7")  // macOS arp -an 的写法
	fromNDP := normMAC("3c:6d:66:ba:03:f7") // macOS ndp -an 的写法
	if fromARP != fromNDP {
		t.Fatalf("同一个 MAC 两张表对不上：arp=%q ndp=%q", fromARP, fromNDP)
	}
	if fromARP != "3c:6d:66:ba:03:f7" {
		t.Fatalf("规整结果不对：%q", fromARP)
	}
	if got := normMAC("3C-6D-66-BA-03-F7"); got != "3c:6d:66:ba:03:f7" {
		t.Fatalf("Windows 的连字符写法没处理：%q", got)
	}
	for _, bad := range []string{"", "  ", "(incomplete)", "3c:6d:66", "zz:zz", "3c:6d:66:ba:03:f7:99"} {
		if got := normMAC(bad); got != "" {
			t.Fatalf("垃圾输入 %q 应当返回空，得到 %q", bad, got)
		}
	}
}

func ll(name string) netaddr.Addr {
	a, err := netaddr.Parse("fe80::1%" + name)
	if err != nil {
		panic(err)
	}
	return a
}

// 没有 fe80:: 的网卡必须被挑掉**并说明理由** —— 直接往上面发只会得到
// 一句 no route to host，对现场毫无信息量。
func TestPickDiscoverNICs跳过的要给理由(t *testing.T) {
	nics := []netif.NIC{
		{Name: "lo0", Loop: true, Up: true, Running: true},
		{Name: "docker0", Virtual: true, Up: true, Running: true, Addrs: []netaddr.Addr{ll("docker0")}},
		{Name: "en0", Up: true, Running: true, Addrs: []netaddr.Addr{ll("en0")}},
		{Name: "en5", Up: true, Running: true}, // IPv6 被关了
		{Name: "en9", Up: false, Running: false, Addrs: []netaddr.Addr{ll("en9")}},
	}
	out, skipped := pickDiscoverNICs(nics, "")
	if len(out) != 1 || out[0].Name != "en0" {
		t.Fatalf("该挑中的是 en0，实际 %+v", out)
	}
	joined := ""
	for _, s := range skipped {
		joined += s + "\n"
	}
	if !contains(joined, "en5") || !contains(joined, "IPv6") {
		t.Fatalf("en5 没有 fe80:: 时必须说明是 IPv6 的问题，实际：%q", joined)
	}
	if !contains(joined, "en9") {
		t.Fatalf("没插线的网卡也要报出来，实际：%q", joined)
	}
	// 点名要虚拟网卡时不该被拦
	if out, _ := pickDiscoverNICs(nics, "docker0"); len(out) != 1 {
		t.Fatalf("点名 docker0 应当放行，实际 %+v", out)
	}
}

// ★ 只收 fe80::，且 zone 一律换成接口名。
// 内核回填的 zone 有时是接口索引（%19），索引换台机器就变了 ——
// 把带索引的地址给人复制粘贴去 ssh，到另一台机器上就连错网卡。
func TestPeerLinkLocal只要链路本地且zone用接口名(t *testing.T) {
	got := peerLinkLocal(&net.UDPAddr{IP: net.ParseIP("fe80::bad6:9b27:4bbd:61f4"), Zone: "19"}, "en7")
	if got != "fe80::bad6:9b27:4bbd:61f4%en7" {
		t.Fatalf("zone 没换成接口名：%q", got)
	}
	if got := peerLinkLocal(&net.UDPAddr{IP: net.ParseIP("2408:8000::1")}, "en7"); got != "" {
		t.Fatalf("全局地址不该被收进来，得到 %q", got)
	}
	if got := peerLinkLocal(&net.TCPAddr{IP: net.ParseIP("fe80::1")}, "en7"); got != "" {
		t.Fatalf("非 UDPAddr 应当返回空，得到 %q", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
