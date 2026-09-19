package netaddr

import "testing"

func mustParse(t *testing.T, s string) Addr {
	t.Helper()
	a, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q) 出错：%v", s, err)
	}
	return a
}

func TestParse宽进(t *testing.T) {
	// 用户会从各种地方拷地址进来，这些写法全都要认
	cases := []struct {
		in     string
		want   string // String()
		prefix int
		is6    bool
	}{
		{"192.168.1.10", "192.168.1.10", 0, false},
		{"192.168.1.10/24", "192.168.1.10", 24, false},
		{" 10.0.0.1 ", "10.0.0.1", 0, false},
		{"fd00::1", "fd00::1", 0, true},
		{"fd00::1/64", "fd00::1", 64, true},
		{"[fd00::1]", "fd00::1", 0, true},       // 从 URL 里拷出来的
		{"[fd00::1]/64", "fd00::1", 64, true},   // 两样都带
		{"fe80::1%en0", "fe80::1%en0", 0, true}, // macOS/Linux 写法
		{"fe80::1%12", "fe80::1", 0, true},      // Windows 写法：zone 是索引，String 不拼名字
		{"::1", "::1", 0, true},
		{"::ffff:192.168.1.1", "::ffff:192.168.1.1", 0, false}, // v4-in-v6 本质是 v4
	}
	for _, c := range cases {
		a := mustParse(t, c.in)
		if got := a.String(); got != c.want {
			t.Errorf("Parse(%q).String() = %q，想要 %q", c.in, got, c.want)
		}
		if a.Prefix != c.prefix {
			t.Errorf("Parse(%q).Prefix = %d，想要 %d", c.in, a.Prefix, c.prefix)
		}
		if a.Is6() != c.is6 {
			t.Errorf("Parse(%q).Is6() = %v，想要 %v", c.in, a.Is6(), c.is6)
		}
	}
}

func TestParse严出(t *testing.T) {
	for _, in := range []string{"", "   ", "不是地址", "192.168.1.300", "192.168.1.1/33", "fd00::1/129", "192.168.1.1/abc"} {
		if a, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) 本该报错，却得到 %v", in, a)
		}
	}
}

func TestParse记住Windows的zone是索引(t *testing.T) {
	a := mustParse(t, "fe80::1%12")
	if a.ZoneID != 12 {
		t.Errorf("ZoneID = %d，想要 12", a.ZoneID)
	}
	if a.Zone != "" {
		t.Errorf("Zone = %q，纯数字的 zone 是索引不是接口名，不该塞进 Zone", a.Zone)
	}
	b := mustParse(t, "fe80::1%en0")
	if b.Zone != "en0" || b.ZoneID != 0 {
		t.Errorf("Zone=%q ZoneID=%d，想要 en0 / 0", b.Zone, b.ZoneID)
	}
}

func TestScope(t *testing.T) {
	cases := map[string]Scope{
		"127.0.0.1":    ScopeLoopback,
		"::1":          ScopeLoopback,
		"169.254.1.1":  ScopeLinkLocal,
		"fe80::1":      ScopeLinkLocal,
		"192.168.1.1":  ScopePrivate,
		"10.0.0.1":     ScopePrivate,
		"fd00::1":      ScopePrivate, // v6 的 ULA 相当于 v4 私有段
		"8.8.8.8":      ScopeGlobal,
		"2400:3200::1": ScopeGlobal,
		"224.0.0.1":    ScopeMulticast,
		"ff02::1":      ScopeMulticast, // v6 扫描要用的全节点组播
		"0.0.0.0":      ScopeUnspec,
	}
	for in, want := range cases {
		if got := mustParse(t, in).Scope(); got != want {
			t.Errorf("%s 的 Scope = %q，想要 %q", in, got, want)
		}
	}
}

// ★ 这条是本包的核心：zone 写法每个平台不一样，写错了不报错、只超时。
func TestDialString按平台拼zone(t *testing.T) {
	ll := Addr{IP: mustParse(t, "fe80::1").IP, Zone: "en0", ZoneID: 12}

	if got, err := ll.DialString("darwin"); err != nil || got != "fe80::1%en0" {
		t.Errorf("darwin: %q, %v；想要 fe80::1%%en0", got, err)
	}
	if got, err := ll.DialString("linux"); err != nil || got != "fe80::1%en0" {
		t.Errorf("linux: %q, %v；想要 fe80::1%%en0", got, err)
	}
	if got, err := ll.DialString("windows"); err != nil || got != "fe80::1%12" {
		t.Errorf("windows: %q, %v；想要 fe80::1%%12（索引不是接口名）", got, err)
	}

	// 非链路本地的地址不该被塞 zone
	g := Addr{IP: mustParse(t, "fd00::1").IP, Zone: "en0", ZoneID: 12}
	if got, _ := g.DialString("windows"); got != "fd00::1" {
		t.Errorf("非链路本地地址不该带 zone，得到 %q", got)
	}
}

// ★ 宁可报错，也不许拿接口名在 Windows 上硬拼一个连不上的地址。
func TestDialString缺了zone就报错不硬拼(t *testing.T) {
	noZone := Addr{IP: mustParse(t, "fe80::1").IP}
	if _, err := noZone.DialString("linux"); err == nil {
		t.Error("链路本地地址没有 zone，本该报错")
	}

	onlyName := Addr{IP: mustParse(t, "fe80::1").IP, Zone: "en0"} // 有名字没索引
	got, err := onlyName.DialString("windows")
	if err == nil {
		t.Errorf("Windows 上没有接口索引就该报错，却拼出了 %q —— 这种地址 Dial 会超时，是最难查的那种 bug", got)
	}
}

func TestHostPort给v6加方括号(t *testing.T) {
	v4 := mustParse(t, "192.168.1.10")
	if got, _ := v4.HostPort(8080, "linux"); got != "192.168.1.10:8080" {
		t.Errorf("v4 得到 %q", got)
	}
	v6 := mustParse(t, "fd00::1")
	if got, _ := v6.HostPort(8080, "linux"); got != "[fd00::1]:8080" {
		t.Errorf("v6 必须加方括号，得到 %q", got)
	}
	ll := Addr{IP: mustParse(t, "fe80::1").IP, Zone: "en0", ZoneID: 3}
	if got, _ := ll.HostPort(554, "windows"); got != "[fe80::1%3]:554" {
		t.Errorf("链路本地 + 端口（Windows），得到 %q", got)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		addr string
		port int
		bad  bool
	}{
		{in: "192.168.1.10:8080", addr: "192.168.1.10", port: 8080},
		{in: "192.168.1.10", addr: "192.168.1.10", port: 0},
		{in: "[fd00::1]:8080", addr: "fd00::1", port: 8080},
		{in: "[fe80::1%en0]:554", addr: "fe80::1%en0", port: 554},
		{in: "[fd00::1]", addr: "fd00::1", port: 0},
		{in: "fd00::1", addr: "fd00::1", port: 0}, // 裸 v6 地址，冒号多，不该被当成 host:port
		{in: "::1", addr: "::1", port: 0},
		{in: "[fd00::1:8080", bad: true}, // 方括号没闭合
		{in: "", bad: true},
	}
	for _, c := range cases {
		a, port, err := SplitHostPort(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("SplitHostPort(%q) 本该报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("SplitHostPort(%q) 出错：%v", c.in, err)
			continue
		}
		if a.String() != c.addr || port != c.port {
			t.Errorf("SplitHostPort(%q) = %q/%d，想要 %q/%d", c.in, a.String(), port, c.addr, c.port)
		}
	}
}

func TestNetwork(t *testing.T) {
	if p, ok := mustParse(t, "192.168.1.10/24").Network(); !ok || p.String() != "192.168.1.0/24" {
		t.Errorf("v4 网段 = %v / %v", p, ok)
	}
	if p, ok := mustParse(t, "fd00::abcd/64").Network(); !ok || p.String() != "fd00::/64" {
		t.Errorf("v6 网段 = %v / %v", p, ok)
	}
	if _, ok := mustParse(t, "192.168.1.10").Network(); ok {
		t.Error("没有前缀长度时不该编一个网段出来")
	}
}

func TestCIDR(t *testing.T) {
	if got := mustParse(t, "fd00::1/64").CIDR(); got != "fd00::1/64" {
		t.Errorf("CIDR = %q", got)
	}
	if got := mustParse(t, "fd00::1").CIDR(); got != "fd00::1" {
		t.Errorf("前缀未知时该退回 String，得到 %q", got)
	}
}

// Addr 能当 map key —— 这是改用 netip.Addr 的主要好处之一（net.IP 是 []byte，不可比较）。
func TestAddr可比较能当mapkey(t *testing.T) {
	m := map[Addr]string{}
	m[mustParse(t, "fd00::1")] = "甲"
	m[mustParse(t, "192.168.1.1")] = "乙"
	if m[mustParse(t, "fd00::1")] != "甲" {
		t.Error("同一个地址应该命中同一个 key")
	}
	if len(m) != 2 {
		t.Errorf("map 里应该有 2 个，实际 %d", len(m))
	}
}
