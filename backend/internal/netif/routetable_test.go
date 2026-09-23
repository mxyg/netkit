package netif

import (
	"net/netip"
	"strings"
	"testing"
)

// ★ 解析函数都不带 build tag，所以一台机器上就能把三个平台的表都跑一遍。

func Test_macOS全表解析(t *testing.T) {
	// 真机抓的输出（含 v4 网段**省掉主机位**、Flags 里的大小写混排、Expire 数字列）
	in := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
default            10.0.0.1           UGScI          en7     59
127.0.0.1          127.0.0.1          UHl            lo0
192.168.1          link#4             UCS            en0
10.0               link#3             UCS           eth0
224.0.0/4          link#4             UmSc           en0
192.168.1.1/32     link#4             UHl            en0
`
	rs := parseNetstatTable(in, "ipv4")
	if len(rs) != 7 {
		t.Fatalf("该认出 7 条（表头/分隔行不算），拿到 %d：%v", len(rs), rs)
	}
	d0 := rs[0]
	if d0.Destination != "0.0.0.0/0" || d0.Gateway != "192.168.1.1" || d0.Iface != "en0" || d0.Direct {
		t.Errorf("默认路由不对：%+v", d0)
	}
	// ★ macOS 把 v4 网段的主机位省掉：`192.168.1` 是 /24、`10.0` 是 /16。
	// 还原错了，「到不了那个网段」就会显示成一条没网段长度的行。
	if rs[3].Destination != "192.168.1.0/24" || rs[4].Destination != "10.0.0.0/16" {
		t.Errorf("省掉主机位的网段没还原：%q %q", rs[3].Destination, rs[4].Destination)
	}
	// 直连行第二栏是 link#N，那不是网关
	for _, i := range []int{3, 4, 5, 6} {
		if !rs[i].Direct || rs[i].Gateway != "" {
			t.Errorf("直连行第 %d 条不对：%+v", i, rs[i])
		}
	}
	// 带显式长度的照收
	if rs[6].Destination != "192.168.1.1/32" {
		t.Errorf("/32 那条不对：%+v", rs[6])
	}
	// 环回那行第二栏是本机地址，不是下一跳
	if rs[2].Destination != "127.0.0.1/32" || rs[2].Gateway != "" || !rs[2].Direct {
		t.Errorf("环回主机路由不对：%+v", rs[2])
	}
}

func Test_macOS默认路由不许被Flags认漏(t *testing.T) {
	// ★★ 这条钉的是实机踩到的坑：BSD 的 Flags **大小写各表一义**（UGcIg、UCi、UHs…）。
	// 按固定字母表挑，小写那几位被拒，结果**默认路由整族从表里消失**，
	// 只剩直连路由 —— 而「有没有默认路由」恰恰是最常被问的那一句。
	// 修成「纯字母 + 含 U」之后，这种写法必须一条不落地认出来。
	in := `Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                     UGcIg           en0
default                                 fe80::%utun4                    UGcIg          utun4       0
fe80::%en0/64                           link#4                          UCi             en0
::1                                     localhost                       UHl             lo0       0
`
	rs := parseNetstatTable(in, "ipv6")
	var n int
	for _, r := range rs {
		if r.Destination == "::/0" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("两条 v6 默认路由都要认出来（含小写 c/I/g 标志），拿到 %d：%v", n, rs)
	}
	if rs[0].Gateway != "fe80::1%en0" {
		t.Errorf("v6 网关要带 zone 原样留着：%+v", rs[0])
	}
	if rs[3].Iface != "lo0" {
		t.Errorf("带 Expire 的行网卡取错了：%+v", rs[3])
	}
}

func Test_macOS两张路由树去重(t *testing.T) {
	// netstat 会把网络树和主机树各打一遍，同一条件出现两次。
	// 不去重就是虚报条数，人会照着那个数怀疑自己看错了。
	in := `Destination Gateway Flags Netif Expire
default 192.168.1.1 UGSc en0
default 192.168.1.1 UGSc en0
`
	rs := parseNetstatTable(in, "ipv4")
	if len(rs) != 1 {
		t.Fatalf("同一条件只该留一条，拿到 %d", len(rs))
	}
}

func TestLinux全表解析(t *testing.T) {
	in := `default via 192.168.1.1 dev en0 proto dhcp src 192.168.1.50 metric 100
default via 10.0.0.1 dev eth0 proto static metric 200
192.168.1.0/24 dev en0 proto kernel scope link src 192.168.1.50 metric 100
unreachable 10.99.0.0/16
blackhole 8.8.8.8
`
	rs := parseIPRouteTable(in, "ipv4")
	if len(rs) != 3 {
		t.Fatalf("unreachable / blackhole 不收，拿到 %d：%v", len(rs), rs)
	}
	if rs[0].Destination != "0.0.0.0/0" || rs[0].Gateway != "192.168.1.1" || rs[0].Iface != "en0" || rs[0].Metric != 100 {
		t.Errorf("第一条默认路由不对：%+v", rs[0])
	}
	if !rs[2].Direct || rs[2].Gateway != "" || rs[2].Src != "192.168.1.50" {
		t.Errorf("直连那条不对：%+v", rs[2])
	}
}

func TestWindows全表度量按网卡相加(t *testing.T) {
	// Get-NetRoute 的 RouteMetric 只是路由自己的，网卡还有 InterfaceMetric，
	// 只比前者会挑错默认路由。
	in := `{"r":[
	 {"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","InterfaceAlias":"以太网","RouteMetric":25,"InterfaceIndex":11},
	 {"DestinationPrefix":"0.0.0.0/0","NextHop":"10.0.0.1","InterfaceAlias":"以太网 2","RouteMetric":10,"InterfaceIndex":22},
	 {"DestinationPrefix":"192.168.1.0/24","NextHop":"0.0.0.0","InterfaceAlias":"以太网","RouteMetric":256,"InterfaceIndex":11}
	],"m":[
	 {"InterfaceIndex":11,"InterfaceMetric":5256},
	 {"InterfaceIndex":22,"InterfaceMetric":25}
	]}`
	rs := parseWinRouteTable(in)
	if len(rs) != 3 {
		t.Fatalf("拿到 %d：%v", len(rs), rs)
	}
	if rs[0].Metric != 25+5256 {
		t.Errorf("默认路由度量要网卡+路由相加，拿到 %d", rs[0].Metric)
	}
	if rs[1].Metric != 35 {
		t.Errorf("另一块网卡的度量不对，拿到 %d", rs[1].Metric)
	}
	// NextHop 是 0.0.0.0 表示没有下一跳，那不是网关
	if !rs[2].Direct || rs[2].Gateway != "" {
		t.Errorf("直连那条被填了网关：%+v", rs[2])
	}
	// 只有一条时 ConvertTo-Json 给对象不给数组，两种形状都要认
	one := `{"r":{"DestinationPrefix":"0.0.0.0/0","NextHop":"1.1.1.1","InterfaceAlias":"wlan","RouteMetric":1,"InterfaceIndex":3},"m":[{"InterfaceIndex":3,"InterfaceMetric":4}]}`
	if got := parseWinRouteTable(one); len(got) != 1 || got[0].Metric != 5 {
		t.Errorf("单条对象形状没认出来：%v", got)
	}
}

func Test最长前缀匹配(t *testing.T) {
	table := []Route{
		{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"},
		{Family: "ipv4", Destination: "10.0.0.0/8", Gateway: "10.1.1.1", Iface: "eth0"},
		{Family: "ipv4", Destination: "10.2.0.0/16", Gateway: "10.2.2.1", Iface: "eth1"},
		{Family: "ipv4", Destination: "10.2.3.0/24", Gateway: "", Iface: "eth1", Direct: true},
		{Family: "ipv6", Destination: "::/0", Gateway: "fe80::1%en0", Iface: "en0"},
	}
	cases := []struct {
		dst, iface string
	}{
		{"8.8.8.8", "en0"},
		{"10.9.9.9", "eth0"},
		{"10.2.9.9", "eth1"},
		{"10.2.3.7", "eth1"},
		{"fd00::1", "en0"},
	}
	for _, c := range cases {
		got, ok := SelectRoute(table, netip.MustParseAddr(c.dst))
		if !ok || got.Iface != c.iface {
			t.Errorf("%s 该走 %s，拿到 %s (ok=%v)", c.dst, c.iface, got.Iface, ok)
		}
	}
	// v4 目的地不许匹配到 v6 的路由上（反过来也一样）：::/0 谁都能盖住，
	// 一旦族判断松了，v4 的包会被说成走 v6 出口。
	if got, ok := SelectRoute(table[:1], netip.MustParseAddr("fd00::1")); ok {
		t.Errorf("v4 默认路由盖不住 v6 目的地：%+v", got)
	}
}

func Test度量只在并列时才参与(t *testing.T) {
	table := []Route{
		{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "1.1.1.1", Iface: "slow", Metric: 100},
		{Family: "ipv4", Destination: "10.0.0.0/8", Gateway: "10.1.1.1", Iface: "near", Metric: 9999},
	}
	// 更长的那条赢，哪怕度量难看
	if got, _ := SelectRoute(table, netip.MustParseAddr("10.1.2.3")); got.Iface != "near" {
		t.Errorf("最长前缀优先没生效：%+v", got)
	}
	// 并列时才比度量
	table = append(table, Route{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "2.2.2.2", Iface: "fast", Metric: 50})
	if got, _ := SelectRoute(table, netip.MustParseAddr("8.8.8.8")); got.Iface != "fast" {
		t.Errorf("并列时该比度量：%+v", got)
	}
	// 两边都没度量（macOS 就是这种）时不许随机挑，按表里的顺序给
	noMetric := []Route{
		{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "a", Iface: "first"},
		{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "b", Iface: "second"},
	}
	if got, _ := SelectRoute(noMetric, netip.MustParseAddr("8.8.8.8")); got.Iface != "first" {
		t.Errorf("没有度量时要稳定按表顺序：%+v", got)
	}
	if n := TiedRoutes(noMetric, netip.MustParseAddr("8.8.8.8"), pickDefault(noMetric)); n != 1 {
		t.Errorf("还有一条并列，要报出来，拿到 %d", n)
	}
}

// pickDefault 从一张没有度量的表里挑默认路由，配合 TiedRoutes 断言并列条数。
func pickDefault(rs []Route) Route {
	r, _ := SelectRoute(rs, netip.MustParseAddr("8.8.8.8"))
	return r
}

func Test掩码转前缀长度(t *testing.T) {
	for _, c := range []struct {
		in   string
		bits int
		ok   bool
	}{
		{"255.255.255.0", 24, true},
		{"255.255.0.0", 16, true},
		{"255.255.255.254", 31, true},
		{"0.0.0.0", 0, true},
		{"255.0.255.0", 0, false}, // 非连续掩码：不猜长度
		{"fe80::1", 0, false},
		{"", 0, false},
	} {
		n, ok := netmaskBits(c.in)
		if ok != c.ok || (ok && n != c.bits) {
			t.Errorf("netmaskBits(%q) = %d,%v，要 %d,%v", c.in, n, ok, c.bits, c.ok)
		}
	}
}

func Test_macOS问系统要答案(t *testing.T) {
	gw := `   route to: 8.8.8.8
destination: 8.8.8.8
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`
	r := parseRouteGet(gw, netip.MustParseAddr("8.8.8.8"))
	if r.Iface != "en0" || r.Gateway != "192.168.1.1" || r.Direct {
		t.Errorf("走网关的答案不对：%+v", r)
	}
	// 命中本网段时**没有** gateway 栏，那不等于读不到
	onlink := `   route to: 192.168.1.1
destination: 192.168.1.0
       mask: 255.255.255.0
  interface: en0
`
	r2 := parseRouteGet(onlink, netip.MustParseAddr("192.168.1.1"))
	if r2.Iface != "en0" || !r2.Direct || r2.Gateway != "" {
		t.Errorf("直连要认成没网关：%+v", r2)
	}
	if !strings.HasSuffix(r2.Destination, "/24") {
		t.Errorf("mask 栏要点分转成前缀长度，拿到 %q", r2.Destination)
	}
	if r2.Destination != "192.168.1.0/24" {
		t.Errorf("destination + mask 两栏要合成网段，拿到 %q", r2.Destination)
	}
	// link#4 不是网关
	link := "   route to: 10.2.3.4\ngateway: link#4\n  interface: en0\n"
	if r3 := parseRouteGet(link, netip.MustParseAddr("10.2.3.4")); !r3.Direct || r3.Gateway != "" {
		t.Errorf("link#4 被当成网关了：%+v", r3)
	}
	// 整段读不懂时不许留半个答案
	if r4 := parseRouteGet("something else\n", netip.MustParseAddr("10.2.3.4")); r4.Iface != "" {
		t.Errorf("读不懂还给出了网卡：%+v", r4)
	}
}

func TestLinux问系统要答案(t *testing.T) {
	in := "192.168.1.10 via 192.168.1.1 dev en0 src 192.168.1.50 uid 1000 \n    cache \n"
	r, ok := parseIPRouteGet(in, netip.MustParseAddr("192.168.1.10"))
	if !ok || r.Iface != "en0" || r.Gateway != "192.168.1.1" || r.Src != "192.168.1.50" {
		t.Fatalf("不对：%+v ok=%v", r, ok)
	}
	// unreachable 是系统明确说没路，不是命令跑挂了
	if _, ok := parseIPRouteGet("unreachable 10.0.0.0/8 dev lo \n", netip.MustParseAddr("10.1.1.1")); ok {
		t.Error("unreachable 不该当成有效路由")
	}
	if _, ok := parseIPRouteGet("", netip.MustParseAddr("10.1.1.1")); ok {
		t.Error("空输出不该有答案")
	}
}
