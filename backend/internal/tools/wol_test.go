package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

func wolMac(t *testing.T, s string) []byte {
	t.Helper()
	m, err := parseMAC(s)
	if err != nil {
		t.Fatalf("测试用的 MAC 都解不开：%s", err)
	}
	return m
}

func wolNIC(name, cidr, kind string, virtual bool) netif.NIC {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(cidr)
	}
	return netif.NIC{Name: name, Kind: kind, Virtual: virtual, Up: true, Running: true,
		Addrs: []netaddr.Addr{{IP: p.Addr(), Prefix: p.Bits()}}}
}

func Test唤醒目标先筛掉不是一台设备的地址(t *testing.T) {
	for _, bad := range []struct{ mac, want string }{
		{"ff:ff:ff:ff:ff:ff", "无差别开机"},        // ★ 全网唤醒 = 一整层楼一起开，拒
		{"01:00:5e:00:00:01", "组播地址"},         // IGMP
		{"33:33:00:00:00:01", "组播地址"},         // IPv6 组播
		{"00:00:00:00:00:00", "全零"},           // 没烧 MAC
		{"00:11:22:33:44:55:66:77", "EUI-64"}, // 8 字节，帧里没那一格
		{"", "没给 mac"},
		{"192.168.1.1", "IPv4"},
	} {
		if _, err := wolTargetMAC(bad.mac); err == nil {
			t.Errorf("%q 竟然被当成唤醒目标收下了", bad.mac)
		} else if !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%q 报错没说到点上：%s（想看到 %q）", bad.mac, err, bad.want)
		}
	}
	for _, ok := range []string{"AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "aabbccddeeff"} {
		m, err := wolTargetMAC(ok)
		if err != nil {
			t.Errorf("%q 该收下：%v", ok, err)
			continue
		}
		if got := formatMAC(m, ":"); got != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("%q 归一成了 %s", ok, got)
		}
	}
}

func Test魔术帧就是六枚全F加十六份MAC(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	f := wolFrame(mac, nil)
	if len(f) != 102 {
		t.Fatalf("帧长 %d，标准是 6+%d×6=102", len(f), wolRepeats)
	}
	for i := 0; i < 6; i++ {
		if f[i] != 0xff {
			t.Fatalf("第 %d 字节不是同步流", i)
		}
	}
	for i := 0; i < wolRepeats; i++ {
		if string(f[6+i*6:12+i*6]) != string(mac) {
			t.Fatalf("第 %d 份 MAC 不对", i+1)
		}
	}
	if got := wolMagicHex(mac, nil); !strings.HasPrefix(got, "ffffffffffff") ||
		!strings.Contains(got, strings.Repeat("aabbccddeeff", 2)) {
		t.Errorf("给界面看的帧形不对：%s", got[:40])
	}
}

func TestSecureOn口令只认两种合法长度(t *testing.T) {
	if b, err := parseWOLPassword(""); err != nil || b != nil {
		t.Errorf("不填口令该给空：%v %v", b, err)
	}
	if b, err := parseWOLPassword("11:22:33:44:55:66"); err != nil || hex.EncodeToString(b) != "112233445566" {
		t.Errorf("6 字节口令该收：%s %v", hex.EncodeToString(b), err)
	}
	if _, err := parseWOLPassword("11220000"); err != nil {
		t.Errorf("4 字节（低两字节为 0）那一档该收：%v", err)
	}
	const leaky = "aabbccddeeff0011" // 故意用不可能合法的输入，查报错会不会回显口令
	for _, bad := range []string{"11223344", "aabbccddee", "11223344556677", leaky, "zz"} {
		_, err := parseWOLPassword(bad)
		if err == nil {
			t.Errorf("%q 是不合法的口令，竟然收下了", bad)
			continue
		}
		// ★ 凭据纪律：结果会被发给 AI，报错里连口令的原文和归一写法都不许出现
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(strings.ReplaceAll(bad, ":", ""))) {
			t.Errorf("%q 的报错回显了口令内容：%s", bad, err)
		}
	}
}

func Test带口令时帧形不给出口令(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	pass := []byte{1, 2, 3, 4, 5, 6}
	s := wolMagicHex(mac, pass)
	if strings.Contains(s, "010203040506") {
		t.Errorf("帧那一栏把口令带出去了：%s", s)
	}
	if !strings.HasSuffix(s, "…") {
		t.Errorf("带口令时该说明后面还有内容：%s", s)
	}
}

func Test选网卡先看MAC在哪块学到的再看默认路由(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	nics := []netif.NIC{
		wolNIC("en0", "192.168.0.101/24", "wifi", false),
		wolNIC("en5", "10.0.0.9/24", "usb-lan", false),
	}
	routes := []netif.DefaultRoute{{Family: "ipv4", Gateway: "192.168.0.1", Iface: "en0"}}
	neigh := []neighbor{{Addr: "10.0.0.40", MAC: "aa:bb:cc:dd:ee:ff", Iface: "en5", Family: "ipv4", State: "REACHABLE"}}

	p, err := wolPlan(nics, routes, neigh, mac, "", "")
	if err != nil {
		t.Fatalf("选网卡失败：%v", err)
	}
	if p.Iface != "en5" || p.IfaceFrom != wolIfaceNeighbor {
		t.Errorf("该从学到这个 MAC 的 en5 发，实际 %s（%s）", p.Iface, p.IfaceFrom)
	}
	if p.Dst.String() != "10.0.0.255" || p.DstKind != wolDstDirected {
		t.Errorf("定向广播算错了：%s %s", p.Dst, p.DstKind)
	}
	if p.NeedsRelay {
		t.Error("目标就在本机网段，不该说要靠路由器")
	}

	// 邻居表里没有它 → 退回默认路由那块网卡
	p2, err := wolPlan(nics, routes, nil, mac, "", "")
	if err != nil {
		t.Fatalf("退回默认路由那步失败：%v", err)
	}
	if p2.Iface != "en0" || p2.IfaceFrom != wolIfaceRoute || p2.Dst.String() != "192.168.0.255" {
		t.Errorf("默认路由那块没选对：%s %s %s", p2.Iface, p2.IfaceFrom, p2.Dst)
	}

	// 人指定了网卡就照他说的发，不许自己换
	p3, err := wolPlan(nics, routes, neigh, mac, "en0", "")
	if err != nil {
		t.Fatalf("指定网卡那步失败：%v", err)
	}
	if p3.Iface != "en0" || p3.IfaceFrom != wolIfaceGiven {
		t.Errorf("没照用户说的走：%s %s", p3.Iface, p3.IfaceFrom)
	}
}

func Test没有默认路由时只有一块可用网卡才敢自动选(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	one := []netif.NIC{wolNIC("en5", "10.0.0.9/24", "usb-lan", false)}
	p, err := wolPlan(one, nil, nil, mac, "", "")
	if err != nil {
		t.Fatalf("只有一块网卡时该敢选：%v", err)
	}
	if p.Iface != "en5" || p.IfaceFrom != wolIfaceOnly {
		t.Errorf("选错了：%s %s", p.Iface, p.IfaceFrom)
	}
	two := append(one, wolNIC("en0", "192.168.0.101/24", "wifi", false))
	if _, err := wolPlan(two, nil, nil, mac, "", ""); err == nil {
		t.Fatal("两块网卡时猜一块 = 可能吵错一层楼，必须让人指")
	} else if !strings.Contains(err.Error(), "en0") || !strings.Contains(err.Error(), "en5") {
		t.Errorf("报错没列出候选：%v", err)
	}
}

func Test点对点段没有广播地址要当场拒(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	nics := []netif.NIC{wolNIC("en0", "10.0.0.5/31", "ethernet", false)}
	_, err := wolPlan(nics, nil, nil, mac, "en0", "")
	if err == nil || !strings.Contains(err.Error(), "没有广播地址") {
		t.Fatalf("/31 该拒并说清原因：%v", err)
	}
}

func Test没要到地址的网卡不能当出发点(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	nics := []netif.NIC{wolNIC("en0", "169.254.7.7/16", "ethernet", false)}
	_, err := wolPlan(nics, nil, nil, mac, "en0", "")
	if err == nil || !strings.Contains(err.Error(), "能用的 IPv4") {
		t.Fatalf("169.254 该拒：%v", err)
	}
	if _, err := wolPlan(nics, nil, nil, mac, "en9", ""); err == nil ||
		!strings.Contains(err.Error(), "没有叫 en9") {
		t.Fatalf("不存在的网卡该说清：%v", err)
	}
}

func Test跨网段那一发要说清靠谁转发(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	nics := []netif.NIC{wolNIC("en0", "192.168.0.101/24", "wifi", false)}
	p, err := wolPlan(nics, nil, nil, mac, "en0", "10.20.30.255")
	if err != nil {
		t.Fatalf("跨网段该收下：%v", err)
	}
	if p.DstKind != wolDstForward || p.NeedsRelay != true {
		t.Errorf("没标出这一发要经路由器：%+v", p)
	}
	// 目标地址其实就在本机网段里 —— 那就不是「要靠路由器」的事
	p2, err := wolPlan(nics, nil, nil, mac, "en0", "192.168.0.255")
	if err != nil {
		t.Fatalf("本网段广播地址该收下：%v", err)
	}
	if p2.NeedsRelay {
		t.Error("目标就在本机网段，却被说要经路由器")
	}
}

func Test全局广播和v6地址都不能当host(t *testing.T) {
	nics := []netif.NIC{wolNIC("en0", "192.168.0.101/24", "wifi", false)}
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	for _, bad := range []struct{ host, want string }{
		{"255.255.255.255", "默认路由"},
		{"fe80::1%en0", "不需要 zone"},
		{"fd00::1", "IPv4"},
		{"192.168.1.1:9", "端口"},
		{"224.0.1.2", "组播"},
		{"hostname", "地址"},
	} {
		if _, err := wolPlan(nics, nil, nil, mac, "en0", bad.host); err == nil {
			t.Errorf("host=%q 竟然收下了", bad.host)
		} else if !strings.Contains(err.Error(), bad.want) {
			t.Errorf("host=%q 报错没说到点上：%s（想看到 %q）", bad.host, err, bad.want)
		}
	}
}

func Test邻居表里有它不等于醒着(t *testing.T) {
	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	// 静态条目是配置出来的，不是有人应答过；incomplete / FAILED 更是「问过没人应」
	for _, state := range []string{"永久", "PERMANENT", "static", "静态", "incomplete", "FAILED"} {
		if _, ok := wolSeenAt([]neighbor{{Addr: "10.0.0.40", MAC: "aa:bb:cc:dd:ee:ff", State: state}}, mac); ok {
			t.Errorf("状态 %q 被当成了「刚才醒着」", state)
		}
	}
	for _, state := range []string{"", "REACHABLE", "STALE", "DELAY", "动态"} {
		if _, ok := wolSeenAt([]neighbor{{Addr: "10.0.0.40", MAC: "AA:BB:CC:DD:EE:FF", State: state}}, mac); !ok {
			t.Errorf("状态 %q 该算「刚才见过」", state)
		}
	}
	// 自家 MAC 写成了 Windows 的连字符写法也要认出来
	if _, ok := wolSeenAt([]neighbor{{Addr: "10.0.0.40", MAC: "aa-bb-cc-dd-ee-ff"}}, mac); !ok {
		t.Error("分隔符不同的同一条地址没认出来")
	}
	// 8 字节的 EUI-64 条目不该和 6 字节目标算成同一台
	if _, ok := wolSeenAt([]neighbor{{Addr: "fe80::1", MAC: "aa:bb:cc:ff:fe:dd:ee:ff"}}, mac); ok {
		t.Error("EUI-64 条目被当成了同一个目标")
	}
}

func Test批准框里说的是叫醒哪一台(t *testing.T) {
	raw := json.RawMessage(`{"mac":"AA-BB-CC-DD-EE-FF","iface":"en5","repeats":3,` +
		`"secureOn":"112233445566","force":true}`)
	s := describeWOL(raw)
	for _, want := range []string{"aa:bb:cc:dd:ee:ff", "en5", "连发 3 枚", "重启"} {
		if !strings.Contains(s, want) {
			t.Errorf("批准框里少了 %q：\n%s", want, s)
		}
	}
	// ★ 口令不进批准文本、不进结果、不进账本
	if strings.Contains(s, "112233445566") {
		t.Errorf("批准框里把 SecureOn 口令写出来了：%s", s)
	}
	if !strings.Contains(s, "Wake-on-LAN") {
		t.Errorf("没说是去干什么的：%s", s)
	}
	if d := describeWOL(json.RawMessage(`{}`)); d == "" {
		t.Error("空参数也要给一句说得下去的话")
	}
}

func Test没有账本就不发唤醒帧(t *testing.T) {
	old := journal
	journal = nil
	t.Cleanup(func() { journal = old })
	// 参数是完整合法的 —— 走到「没有账本」这一步才停，说明拦的是账本不是别的
	_, err := sendWOL(context.Background(), json.RawMessage(`{"mac":"aa:bb:cc:dd:ee:ff"}`))
	if err == nil || !strings.Contains(err.Error(), "账本") {
		t.Fatalf("没有账本时该拒绝动手：%v", err)
	}
}

func Test唤醒了哪台要留在账上(t *testing.T) {
	dir := t.TempDir()
	j, err := state.Open(dir + "/journal.json")
	if err != nil {
		t.Fatal(err)
	}
	old := journal
	journal = j
	t.Cleanup(func() { journal = old })

	// ★ 换成假发的：测试不许真往网段里丢唤醒帧，那等于拿别人家的机器当测试床。
	var got int
	var sentPlan wolRoute
	oldDispatch := wolDispatch
	wolDispatch = func(_ context.Context, p wolRoute, _ int, frame []byte, repeats int) (int, error) {
		got = repeats
		sentPlan = p
		if len(frame) != 102 {
			return 0, ots.Errf(ots.ErrInternal, "帧长 %d", len(frame))
		}
		return repeats, nil
	}
	t.Cleanup(func() { wolDispatch = oldDispatch })

	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	plan := wolRoute{Iface: "en5", Src: wolAddr(t, "10.0.0.9/24"),
		Dst: netip.MustParseAddr("10.0.0.255"), DstKind: wolDstDirected}
	sent, err := wolCommit(context.Background(), describeWOL(
		json.RawMessage(`{"mac":"aa:bb:cc:dd:ee:ff","iface":"en5"}`)), mac, plan,
		wolFrame(mac, nil), 9, 3)
	if err != nil || sent != 3 || got != 3 {
		t.Fatalf("没走完这一步：%v sent=%d dispatch=%d", err, sent, got)
	}
	if sentPlan.Dst.String() != "10.0.0.255" {
		t.Errorf("发往了 %s", sentPlan.Dst)
	}
	entries := j.All()
	if len(entries) != 1 {
		t.Fatalf("账本里 %d 笔，应恰好一笔", len(entries))
	}
	e := entries[0]
	if e.Kind != "wake-on-lan" || !strings.Contains(e.What, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("这一笔记得不像话：%+v", e)
	}
	if !strings.Contains(string(e.After), "10.0.0.255") {
		t.Errorf("账上没写发到哪：%s", e.After)
	}
	// ★ 一次性动作必须当场了结：挂着的话下次启动的还原流程会去认领一个不存在的东西
	if e.Status != state.StatusReverted {
		t.Errorf("状态是 %s，唤醒这种事该当场翻篇", e.Status)
	}
	if len(j.Outstanding()) != 0 {
		t.Errorf("还有 %d 笔没 of 结的账", len(j.Outstanding()))
	}
	for _, line := range []string{e.What, string(e.After), e.Note} {
		if strings.Contains(line, "112233445566") {
			t.Errorf("账本里出现了口令：%s", line)
		}
	}
}

func Test发不出去时账要翻篇但留个说法(t *testing.T) {
	dir := t.TempDir()
	j, err := state.Open(dir + "/journal.json")
	if err != nil {
		t.Fatal(err)
	}
	old := journal
	journal = j
	t.Cleanup(func() { journal = old })
	oldDispatch := wolDispatch
	wolDispatch = func(context.Context, wolRoute, int, []byte, int) (int, error) {
		return 0, ots.Errf(ots.ErrPermissionRequired, "系统拦住了往广播地址发包")
	}
	t.Cleanup(func() { wolDispatch = oldDispatch })

	mac := wolMac(t, "aa:bb:cc:dd:ee:ff")
	plan := wolRoute{Iface: "en5", Src: wolAddr(t, "10.0.0.9/24"),
		Dst: netip.MustParseAddr("10.0.0.255"), DstKind: wolDstDirected}
	if _, err := wolCommit(context.Background(), "叫醒 aa:bb:cc:dd:ee:ff", mac, plan,
		wolFrame(mac, nil), 9, 1); err == nil {
		t.Fatal("发不出去该报错")
	}
	entries := j.All()
	if len(entries) != 1 || entries[0].Status != state.StatusReverted {
		t.Fatalf("失败的那笔没翻篇：%+v", entries)
	}
	if !strings.Contains(entries[0].Note, "拦") {
		t.Errorf("失败原因没记进账：%s", entries[0].Note)
	}
	if len(j.Outstanding()) != 0 {
		t.Error("一笔没发出去的账，不该留在待还原里")
	}
}

func wolAddr(t *testing.T, cidr string) netaddr.Addr {
	t.Helper()
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return netaddr.Addr{IP: p.Addr(), Prefix: p.Bits()}
}

func netWOLRegistered(t *testing.T) ots.Tool {
	t.Helper()
	r := ots.NewRegistry(true)
	Register(r)
	tool, ok := r.Lookup("net.wol")
	if !ok {
		t.Fatal("net.wol 没注册上")
	}
	return tool
}

func Test_wol是mutate且必须带批准说明(t *testing.T) {
	tool := netWOLRegistered(t)
	if tool.Class != ots.ClassMutate {
		t.Errorf("发魔术帧会改变那台机器的状态，类别是 %s", tool.Class)
	}
	if tool.Describe == nil {
		t.Error("mutate 工具没有 Describe，批准框里就没话说 [OTS-7.2]")
	}
	// 关掉 mutate 总开关后它必须整个消失 [OTS-4.4]
	off := ots.NewRegistry(false)
	Register(off)
	for _, v := range off.Visible() {
		if v.Name == "net.wol" {
			t.Error("mutations=false 时 net.wol 还在对外提供")
		}
	}
}

func Test唤醒的判定码界面上都有人话(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面文件：%v", err)
	}
	js := string(b)
	for _, code := range []string{verdictWOLSent, verdictWOLForwarded, verdictWOLAwake} {
		if !inJS(js, code) {
			t.Errorf("界面里没有判定码 %s —— [OTS-4.5] 每个工具都要有按钮，判定也要有中文", code)
		}
	}
	for _, ifaceFrom := range []string{wolIfaceGiven, wolIfaceNeighbor, wolIfaceRoute, wolIfaceOnly} {
		if !inJS(js, ifaceFrom) {
			t.Errorf("界面里没有「网卡是怎么选出来的」这一档：%s", ifaceFrom)
		}
	}
}

// inJS 这个码在界面里是不是当成一个键出现了（界面用单引号，别处可能双引号）。
func inJS(js, code string) bool {
	return strings.Contains(js, `"`+code+`"`) || strings.Contains(js, `'`+code+`'`)
}
