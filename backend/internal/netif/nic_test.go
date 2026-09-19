package netif

import (
	"net"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/netaddr"
)

// ipnet 造一个系统会给我们的地址对象。
func ipnet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q)：%v", cidr, err)
	}
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

func addrsOf(t *testing.T, cidrs ...string) []net.Addr {
	t.Helper()
	out := make([]net.Addr, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, ipnet(t, c))
	}
	return out
}

func mk(t *testing.T, name string, cidrs ...string) NIC {
	t.Helper()
	// ★ 要和 Interfaces() 的构造方式一致，否则测的就不是真实形态
	//   （早先这里漏了 Virtual，docker0 没被认成虚拟网卡，排序那条测试白跑）
	n := NIC{
		Name: name, Index: 7, Up: true, Running: true,
		Virtual: IsVirtualName(name),
		Addrs:   collect(addrsOf(t, cidrs...), name, 7),
	}
	n.Verdict = n.Judge()
	return n
}

// ★ 修掉的假设 ①：原 iface.go 直接丢掉 v6 链路本地地址。
func Test不许丢掉v6链路本地地址(t *testing.T) {
	got := collect(addrsOf(t, "192.168.1.10/24", "fe80::1/64", "fd00::5/64"), "en0", 7)
	if len(got) != 3 {
		t.Fatalf("收到 %d 个地址，想要 3 个（原实现会把 fe80:: 丢掉）：%v", len(got), got)
	}
	var ll *netaddr.Addr
	for i := range got {
		if got[i].Scope() == netaddr.ScopeLinkLocal {
			ll = &got[i]
		}
	}
	if ll == nil {
		t.Fatal("fe80:: 不见了 —— 它在 v6 上是每块网卡必有、且很多排障场合只能用它")
	}
	// ★ 两个 zone 字段都要填：接口名给 Linux/macOS，索引给 Windows
	if ll.Zone != "en0" {
		t.Errorf("Zone = %q，想要 en0", ll.Zone)
	}
	if ll.ZoneID != 7 {
		t.Errorf("ZoneID = %d，想要 7", ll.ZoneID)
	}
	if s, err := ll.DialString("windows"); err != nil || s != "fe80::1%7" {
		t.Errorf("Windows 上拼不出来：%q / %v —— 枚举时少填一个字段，到了 Windows 就 Dial 不出去", s, err)
	}
}

// ★ 修掉的假设 ②：地址要能分出用途，不是两个 []string。
func Test地址按用途分类并排序(t *testing.T) {
	got := collect(addrsOf(t, "fe80::1/64", "fd00::5/64", "2400:3200::1/64", "192.168.1.10/24"), "en0", 7)
	if len(got) != 4 {
		t.Fatalf("收到 %d 个", len(got))
	}
	// 公网 > 内网 > 链路本地
	if got[0].Scope() != netaddr.ScopeGlobal {
		t.Errorf("排第一的该是公网地址，实际 %s（%s）", got[0], got[0].Scope())
	}
	if got[len(got)-1].Scope() != netaddr.ScopeLinkLocal {
		t.Errorf("排最后的该是链路本地，实际 %s（%s）", got[len(got)-1], got[len(got)-1].Scope())
	}
}

// ★ 修掉的假设 ③：排序只看 v4，纯 v6 网卡被挤到最后。
func Test纯v6网卡不许被排到最后(t *testing.T) {
	v6only := mk(t, "eth1", "fd00::5/64")
	noAddr := mk(t, "eth2")
	virtual := mk(t, "docker0", "172.17.0.1/16")

	if score(v6only) <= score(noAddr) {
		t.Errorf("有 v6 地址的网卡(%d)该排在没地址的(%d)前面", score(v6only), score(noAddr))
	}
	if score(v6only) <= score(virtual) {
		t.Errorf("纯 v6 的物理网卡(%d)该排在虚拟网卡(%d)前面 —— "+
			"v6-only 现场里它才是用户唯一要找的那块", score(v6only), score(virtual))
	}
}

// ★ 修掉的假设 ④：v6-only 时说「没有拿到 IP 地址」是错误诊断。
func Test纯v6网卡不许被说成没有IP(t *testing.T) {
	n := mk(t, "eth1", "fd00::5/64", "fe80::1/64")
	if n.Verdict.Code == VerdictNoAddress || n.Verdict.Code == VerdictLinkLocal {
		t.Errorf("v6-only 网卡被判成 %q —— 这是错的，会把人往错方向带", n.Verdict.Code)
	}
	if n.Verdict.Code != VerdictV6Only {
		t.Errorf("判定码 = %q，想要 %q", n.Verdict.Code, VerdictV6Only)
	}
}

func Test双栈与单栈的说明分开给(t *testing.T) {
	both := mk(t, "eth0", "192.168.1.10/24", "fd00::5/64")
	if both.Verdict.Code != VerdictDualStack {
		t.Errorf("双栈网卡判定 = %q", both.Verdict.Code)
	}
	// v4 能用但 v6 没有：不能笼统判成「正常」，这个事实排查「某些网站打不开」时要用
	v4only := mk(t, "eth0", "192.168.1.10/24", "fe80::1/64")
	if v4only.Verdict.Code != VerdictV4Only {
		t.Errorf("只有 v4 时要单独判出来，实际 = %q", v4only.Verdict.Code)
	}
}

// 只有 fe80:: 是个**很具体**的故障形态，要给出对应的下一步，不能和「什么都没有」混为一谈。
func Test只有链路本地时要说清是没拿到地址(t *testing.T) {
	n := mk(t, "eth0", "fe80::1/64")
	if n.Verdict.Code != VerdictLinkLocal {
		t.Errorf("判定码 = %q，想要 %q（和「什么都没有」是两种状态，下一步做什么不一样）",
			n.Verdict.Code, VerdictLinkLocal)
	}
	if n.HasUsableV6() {
		t.Error("fe80:: 不算可用的 v6 地址（它只能在本链路上用）")
	}
	if !n.HasLinkLocalV6() {
		t.Error("HasLinkLocalV6 该为真")
	}
}

// v4 的 169.254 和 v6 的 fe80:: 长得像，含义正相反：前者是故障信号。
func Test自动私有地址169254不算可用(t *testing.T) {
	n := mk(t, "eth0", "169.254.3.4/16")
	if n.HasUsableV4() {
		t.Error("169.254 表示 DHCP 没要到地址，是故障信号，不能算可用地址")
	}
	if n.Verdict.Code != VerdictNoAddress {
		t.Errorf("判定码 = %q，想要 %q", n.Verdict.Code, VerdictNoAddress)
	}
}

func TestNetworks不把链路本地算成网段(t *testing.T) {
	n := mk(t, "eth0", "192.168.1.10/24", "fd00::5/64", "fe80::1/64")
	got := n.Networks()
	for _, s := range got {
		if strings.HasPrefix(s, "fe80") {
			t.Errorf("网段里不该有链路本地：%v", got)
		}
	}
	if len(got) != 2 {
		t.Errorf("想要 2 个网段（v4 一个 v6 一个），实际 %v", got)
	}
}

// ★ net.IP 的 v4 有 4 字节和 16 字节两种表示，不 Unmap 就会变成两个不相等的值。
func TestNetipFrom会Unmap(t *testing.T) {
	four, _ := netipFrom(net.IPv4(192, 168, 1, 1).To4())
	sixteen, _ := netipFrom(net.IPv4(192, 168, 1, 1)) // 16 字节的 v4-in-v6
	if four != sixteen {
		t.Errorf("同一个地址的两种表示不相等：%v vs %v —— 拿它当 map key 就出鬼了", four, sixteen)
	}
	if !four.Is4() {
		t.Error("Unmap 之后该是 v4")
	}
}

func Test虚拟网卡与USB识别(t *testing.T) {
	for _, s := range []string{"docker0", "veth1234", "vEthernet (WSL)", "utun3", "tailscale0"} {
		if !IsVirtualName(s) {
			t.Errorf("%q 该认成虚拟网卡", s)
		}
	}
	// ★ 故意不认成虚拟的：现场靠它们上网
	for _, s := range []string{"eth0", "en0", "enx001122334455", "ppp0", "以太网"} {
		if IsVirtualName(s) {
			t.Errorf("%q 不该被当成虚拟网卡藏起来 —— 现场可能正靠它上网", s)
		}
	}
	if USBKind("rndis0") != USBKind4G {
		t.Error("rndis 是 USB 共享/4G 拨号")
	}
	if USBKind("enx001122334455") != USBKindLAN {
		t.Error("enx 是 USB 网线网卡")
	}
	if USBKind("eth0") != USBKindNone {
		t.Error("eth0 不是 USB")
	}
}

// 冒烟：在真机上跑一次，只验不变式（本机有几块网卡、是什么地址，各台机器都不一样）。
func TestInterfaces冒烟(t *testing.T) {
	nics, err := Interfaces()
	if err != nil {
		t.Fatalf("Interfaces()：%v", err)
	}
	if len(nics) == 0 {
		t.Fatal("一块网卡都没枚举到")
	}
	for _, n := range nics {
		if n.Name == "" {
			t.Error("网卡没有名字")
		}
		if n.Verdict.Code == "" {
			t.Errorf("%s 没有判定结果", n.Name)
		}
		for _, a := range n.Addrs {
			if !a.IP.IsValid() {
				t.Errorf("%s 上有个无效地址", n.Name)
			}
			// ★ 不变式：链路本地地址一定带着 zone，否则它是个废地址
			if a.NeedsZone() && (a.Zone == "" || a.ZoneID == 0) {
				t.Errorf("%s 上的 %s 没填全 zone（Zone=%q ZoneID=%d）", n.Name, a, a.Zone, a.ZoneID)
			}
		}
	}
	t.Logf("本机枚举到 %d 块网卡，排第一的是 %s（%s）", len(nics), nics[0].Name, nics[0].Verdict.NoteZH())
}

// ★ 多语种的地基：后端给的是判定码，不是句子。
//
// 这条测试钉住的是**边界**——哪天有人又想在 Go 里拼句子发给界面，这里会提醒他。
func Test后端只给判定不给句子(t *testing.T) {
	n := mk(t, "eth0", "192.168.1.10/24", "fd00::5/64")

	// 判定是结构化的：码 + 参数，参数单独放，不拼进句子
	if n.Verdict.Code != VerdictDualStack {
		t.Fatalf("判定码 = %q", n.Verdict.Code)
	}
	if len(n.Verdict.Networks) != 2 {
		t.Errorf("网段该作为**参数**单独给，实际 %v", n.Verdict.Networks)
	}

	// USB 类型也是独立字段，不是拼在句子尾巴上的后缀
	// （原来 `+ usb` 那种写法，在语序不同的语言里根本没地方放）
	u := mk(t, "enx001122334455", "192.168.1.10/24")
	if u.Verdict.USB != USBKindLAN {
		t.Errorf("USB 类型该是独立字段，实际 %q", u.Verdict.USB)
	}

	// 中文渲染是**其中一门语言**，只给命令行/日志/测试用；界面走前端词典
	if s := n.Verdict.NoteZH(); !strings.Contains(s, "双栈正常") {
		t.Errorf("中文渲染 = %q", s)
	}
}

// 每个判定码都得有中文文案，不能漏一个（漏了会把判定码本身显示给用户）
func Test每个判定码都有中文文案(t *testing.T) {
	all := []VerdictCode{
		VerdictLoopback, VerdictVirtual, VerdictDown, VerdictNoCarrier,
		VerdictDualStack, VerdictV4Only, VerdictV6Only, VerdictLinkLocal, VerdictNoAddress,
	}
	for _, c := range all {
		got := Verdict{Code: c, Networks: []string{"192.168.1.0/24"}}.NoteZH()
		if got == string(c) {
			t.Errorf("判定码 %q 没有中文文案，会把码本身显示给用户", c)
		}
		if got == "" {
			t.Errorf("判定码 %q 渲染成了空串", c)
		}
	}
}
