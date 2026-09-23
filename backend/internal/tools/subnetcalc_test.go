package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

// net.subnet.calc 的测试钉四类事：
//
//	① 不合法的输入不许硬算（不连续掩码、v6 写点分掩码）—— 算出来的段是假的，
//	   而人会拿着它去改设备；
//	② 填的到底是不是一个段（网络地址 / 主机地址 / 广播地址 / 单地址）必须分清，
//	   分清的标准是「人下一步会不会抄错」；
//	③ v4 的「总数减二」不许漏到 v6 上，/31、/32 也不许沿用；
//	④ 两个段的关系：CIDR 只有嵌套和不相交两种，跨族是不可比 ——
//	   把「不可比」说成「不重叠」，人就以为两段可以各自配下去。

// ── 夹具 ──

func scRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doSubnetCalc(context.Background(), b)
	if err != nil {
		t.Fatalf("跑不动：%v", err)
	}
	return v.(ots.Verdict)
}

func scStr(t *testing.T, v ots.Verdict, key string) string {
	t.Helper()
	s, ok := v.Values[key].(string)
	if !ok {
		t.Fatalf("%s 不是字符串（ %+v ）", key, v.Values[key])
	}
	return s
}

func scNotes(t *testing.T, v ots.Verdict) map[string]any {
	t.Helper()
	m, ok := v.Values["v6Notes"].(map[string]any)
	if !ok {
		t.Fatalf("v6Notes 不在（ %+v ）", v.Values["v6Notes"])
	}
	return m
}

func scFacts(t *testing.T, cidr string) ots.Verdict {
	t.Helper()
	return scRun(t, map[string]any{"cidr": cidr})
}

// ── 输入形态 ──

// 点分掩码是从设备配置页抄下来的常态写法，必须认，且要和 /24 算成同一个段。
func Test点分掩码和CIDR算成同一个段(t *testing.T) {
	dotted := scRun(t, map[string]any{"cidr": "192.168.1.0/255.255.255.0"})
	cidr := scRun(t, map[string]any{"cidr": "192.168.1.0/24"})
	if got := scStr(t, dotted, "canonical"); got != "192.168.1.0/24" {
		t.Errorf("解成 %s，想要 192.168.1.0/24", got)
	}
	if dotted.Values["prefix"] != cidr.Values["prefix"] {
		t.Errorf("两种写法前缀长度不一样：%v / %v", dotted.Values["prefix"], cidr.Values["prefix"])
	}
}

// ★★ 255.0.255.0 这种手滑掩码必须当场拒。
// 硬算会得到一个「网段」，人抄进设备才发现配不上，中间那段时间全算他的锅。
func Test不连续的掩码当场拒(t *testing.T) {
	for _, bad := range []string{
		"192.168.1.0/255.0.255.0",
		"10.0.0.1/255.255.0.255",
	} {
		b, _ := json.Marshal(map[string]any{"cidr": bad})
		if _, err := doSubnetCalc(context.Background(), b); err == nil {
			t.Errorf("%s 竟然收了", bad)
		}
	}
	// 报错的话要说清「不连续」，并把二进制摆出来 —— 只说「掩码非法」人看不出自己哪里手滑了
	b, _ := json.Marshal(map[string]any{"cidr": "10.0.0.1/255.0.0.255"})
	_, err := doSubnetCalc(context.Background(), b)
	if err == nil || !strings.Contains(err.Error(), "连续") {
		t.Errorf("报错没说不连续：%v", err)
	}
}

// 连续的半字节掩码（255.255.128.0 = /17）是合法的，不许被上一条误伤。
func Test半字节的连续掩码照常收(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.128/255.255.128.0"})
	if got := scStr(t, v, "canonical"); got != "192.168.0.0/17" {
		t.Errorf("算成 %s，想要 192.168.0.0/17", got)
	}
}

// 没写掩码就按单地址算，★ 而且不许替他猜一个 /24。
func Test裸地址按单地址算并说明是补的(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.100"})
	if v.Code != scSingle {
		t.Fatalf("判定是 %s，想要 %s", v.Code, scSingle)
	}
	if v.Values["prefixAssum"] != true {
		t.Error("没带出「这个 /32 是补出来的」")
	}
	if !strings.Contains(v.Note, "没写掩码") && !strings.Contains(v.Note, "没填") {
		t.Errorf("话里没告诉人掩码缺失：%s", v.Note)
	}
	if got := scStr(t, v, "canonical"); got != "192.168.1.100/32" {
		t.Errorf("算成 %s —— 猜段了", got)
	}
}

// 填的是段里一个主机地址：照样能算，但必须点名，否则人会把 .100 登记成网段地址。
func Test主机地址点出来并给出所在段(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.100/24"})
	if v.Code != scHost {
		t.Fatalf("判定是 %s，想要 %s", v.Code, scHost)
	}
	if got := scStr(t, v, "canonical"); got != "192.168.1.0/24" {
		t.Errorf("所在段是 %s", got)
	}
	if !strings.Contains(v.Note, "主机地址") {
		t.Errorf("话里没点出来：%s", v.Note)
	}
	if v.Values["givenIsNet"] != false {
		t.Error("givenIsNet 判错了")
	}
}

func Test网络地址与广播地址分得开(t *testing.T) {
	if got := scRun(t, map[string]any{"cidr": "192.168.1.0/24"}).Code; got != scNetwork {
		t.Errorf("网络地址判成 %s", got)
	}
	v := scRun(t, map[string]any{"cidr": "192.168.1.255/24"})
	if v.Code != scBroadcast {
		t.Fatalf("广播地址判成 %s", v.Code)
	}
	if !strings.Contains(v.Note, "广播") {
		t.Errorf("话里没说清：%s", v.Note)
	}
}

// ── 算得对不对 ──

// /24 的一整套数：这三处（通配码、首尾可用、可用数）是配设备时直接抄的字段。
func Test一个C段的全部字段(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.0/24"})
	want := map[string]string{
		"network": "192.168.1.0", "mask": "255.255.255.0",
		"wildcard": "0.0.0.255", // ★ 不是 128.0.0.0 —— 通配码是掩码取反，不是「剩下的高位 1」
		"size":     "256", "usable": "254",
		"firstUsable": "192.168.1.1", "lastUsable": "192.168.1.254", "broadcast": "192.168.1.255",
	}
	for k, w := range want {
		if got := scStr(t, v, k); got != w {
			t.Errorf("%s = %s，想要 %s", k, got, w)
		}
	}
}

// ★ /31（RFC 3021）是路由器互联口：两个地址都能用，没有网络/广播地址这一步。
// 按「总数减二」算会得到 0 个可用地址，人就不敢配；按下末地址判成广播，同样卡住开通。
func Test三十一这一段两个地址都能用(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "10.0.0.0/31"})
	if got := scStr(t, v, "usable"); got != "2" {
		t.Errorf("可用数 %s，想要 2", got)
	}
	if _, ok := v.Values["broadcast"]; ok {
		t.Error("/31 不该有广播地址")
	}
	if v.Values["pointToPoint"] != true {
		t.Error("没标出这是点对点段")
	}
	if got := scStr(t, v, "lastUsable"); got != "10.0.0.1" {
		t.Errorf("末地址 %s", got)
	}
	// 末地址也不能判成广播
	if got := scRun(t, map[string]any{"cidr": "10.0.0.1/31"}).Code; got != scHost {
		t.Errorf("10.0.0.1/31 判成 %s，想要 %s", got, scHost)
	}
}

func Test三十二只算一个地址(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.100/32"})
	if v.Code != scSingle {
		t.Fatalf("判定是 %s", v.Code)
	}
	if got := scStr(t, v, "usable"); got != "1" {
		t.Errorf("可用数 %s，想要 1", got)
	}
	// ★ /32 也没有广播地址：把「它自己」填进 broadcast，界面上就成了
	// 「广播地址：192.168.1.100」和「本机地址：192.168.1.100」并排，人以为配错了。
	if _, ok := v.Values["broadcast"]; ok {
		t.Error("/32 不该有广播地址")
	}
}

// 0.0.0.0/0 是「所有地址」，不是一个可以分配的段 —— 说成段会诱导人去扫全网。
func Test全零段说的是所有地址(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "0.0.0.0/0"})
	if v.Code != scNetwork {
		t.Fatalf("判定是 %s", v.Code)
	}
	if !strings.Contains(v.Note, "所有地址") {
		t.Errorf("话里没说清这是全部地址：%s", v.Note)
	}
	if got := scStr(t, v, "reverseZone"); got != "" {
		t.Errorf("反向区域名给成了 %q", got)
	}
}

// 大段跨字节边界：可用数用普通 int 会溢出，这里必须是大数。
func Test大段地址数不溢出(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "10.0.0.0/8"})
	if got := scStr(t, v, "size"); got != "16777216" {
		t.Errorf("总数 %s", got)
	}
	if got := scStr(t, v, "usable"); got != "16777214" {
		t.Errorf("可用数 %s", got)
	}
}

// ── 反向解析区 ──

func Test反向区域名带半字节切法(t *testing.T) {
	for cidr, want := range map[string]string{
		"192.168.1.0/24":   "1.168.192.in-addr.arpa",
		"192.168.0.0/16":   "168.192.in-addr.arpa",
		"10.0.0.0/8":       "10.in-addr.arpa",
		"192.168.1.128/25": "128-255.1.168.192.in-addr.arpa", // ★ RFC 2317：不切就撞邻居的区
		"192.168.1.0/26":   "0-63.1.168.192.in-addr.arpa",
		"192.168.1.100/32": "100.1.168.192.in-addr.arpa",
	} {
		if got := scStr(t, scFacts(t, cidr), "reverseZone"); got != want {
			t.Errorf("%s 的反向区是 %q，想要 %q", cidr, got, want)
		}
	}
}

// ── IPv6 ──

// ★★ v6 不许沿用 v4 的「总数减二」，也不许有广播地址那一栏。
// 减了就是把答案算小两名还装作有依据；给广播是凭空造一个不存在的地址。
func Test六十四段不减二也没有广播(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "2001:db8::/64"})
	n := "18446744073709551616" // 2^64
	if got := scStr(t, v, "usable"); got != n {
		t.Errorf("可用数 %s，想要 %s", got, n)
	}
	if got := scStr(t, v, "size"); got != n {
		t.Errorf("总数 %s", got)
	}
	if _, ok := v.Values["broadcast"]; ok {
		t.Error("v6 不该有广播地址")
	}
	if got := scStr(t, v, "family"); got != "ipv6" {
		t.Errorf("族判成 %s", got)
	}
	if notes := scNotes(t, v); notes["noBroadcast"] != true {
		t.Errorf("v6Notes 没说明白：%+v", notes)
	}
	if _, ok := v.Values["mask"]; ok {
		t.Error("v6 不该给点分掩码")
	}
}

// 地址性质要判对：链路本地出不了这条链路，ULA 不该往公网上发 ——
// 把 fe80::/64 说成公网段，人就去公网解析它了。
func Test六的性质分得清(t *testing.T) {
	for cidr, kind := range map[string]string{
		"fe80::/64":     "link-local",
		"fd00::/8":      "ula",
		"2001:db8::/48": "global",
		"ff02::1/128":   "multicast",
		"::1/128":       "loopback",
	} {
		if got := scNotes(t, scFacts(t, cidr))["kind"]; got != kind {
			t.Errorf("%s 判成 %v，想要 %s", cidr, got, kind)
		}
	}
}

// 现场问 v6 真正想知道的是「能切出多少个 /64」，一个 /48 就是 65536 个。
func Test四十八段给出能切出多少个子网(t *testing.T) {
	v := scFacts(t, "2001:db8::/48")
	if got := scNotes(t, v)["sla64Count"]; got != "65536" {
		t.Errorf("sla64Count = %v", got)
	}
	if !strings.Contains(v.Note, "65536") {
		t.Errorf("话里没带这个数：%s", v.Note)
	}
	if _, ok := scNotes(t, scFacts(t, "2001:db8::/64"))["sla64Count"]; ok {
		t.Error("/64 本身不该再给 sla64Count")
	}
}

// ::ffff:1.2.3.4 本质上就是个 v4 地址。带着 v6 的壳去算，段会算成 128 位、
// 掩码那一栏干脆没有 —— 人问的是 v4 的段。
func Test四点六地址按四算(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "::ffff:192.168.1.100/24"})
	if got := scStr(t, v, "family"); got != "ipv4" {
		t.Fatalf("族判成 %s", got)
	}
	if got := scStr(t, v, "canonical"); got != "192.168.1.0/24" {
		t.Errorf("段算成 %s", got)
	}
}

// 从界面/命令行进来的 fe80::1%en0 写法：netip 认为「带 zone 的前缀」非法，
// 不去掉 zone 的话 Masked() 返回空前缀 —— 不报错，只是整栏答案变成 0.0.0.0/0。
func Test作用域后缀不许把答案变成空段(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "fe80::1%en0/64"})
	if got := scStr(t, v, "canonical"); got != "fe80::/64" {
		t.Errorf("算成 %q", got)
	}
	if strings.Contains(scStr(t, v, "given"), "%") {
		t.Error("given 带着 zone —— 和 canonical 成了两套写法")
	}
}

func Test方括号写法也认(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "[fd00::10]/64"})
	if got := scStr(t, v, "canonical"); got != "fd00::/64" {
		t.Errorf("算成 %s", got)
	}
}

// ── 两段的关系 ──

// ★★ 这一档是整个工具唯一需要「有人去改配置」的结论：
// 重叠的表现是「有时候连得上有时候连不上」，谁都不会往掩码上想。
func Test包含关系判成重叠并说清谁包谁(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.0/24", "peer": "192.168.1.128/25"})
	if v.Code != scOverlap {
		t.Fatalf("判定是 %s，想要 %s", v.Code, scOverlap)
	}
	if v.Values["overlaps"] != true {
		t.Error("没标 overlaps")
	}
	if got := v.Values["contains"]; got != "peer-inside" {
		t.Errorf("关系判成 %v", got)
	}
	if got := scStr(t, v, "overlapSize"); got != "128" {
		t.Errorf("重叠部分是 %s 个地址", got)
	}
	if !strings.Contains(v.Note, "包住") {
		t.Errorf("话里没说清怎么撞的：%s", v.Note)
	}

	back := scRun(t, map[string]any{"cidr": "192.168.1.128/25", "peer": "192.168.1.0/24"})
	if got := back.Values["contains"]; got != "peer-contains" {
		t.Errorf("反过来问判成 %v，想要 peer-contains", got)
	}
	same := scRun(t, map[string]any{"cidr": "192.168.1.0/24", "peer": "192.168.1.0/24"})
	if got := same.Values["contains"]; got != "identical" {
		t.Errorf("两段相同判成 %v", got)
	}
}

// 挨着但不重叠：结论必须还是「这个输入长什么样」，不能因为问了 peer 就报撞。
// 报成重叠人会去改一个本来没配的段。
func Test不相交的段不报重叠(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "10.0.0.0/8", "peer": "192.168.0.0/16"})
	if v.Values["overlaps"] != false {
		t.Fatal("不相交被判成重叠")
	}
	if v.Code != scNetwork {
		t.Errorf("判定是 %s，想要 %s", v.Code, scNetwork)
	}
	if got := scStr(t, v, "peer"); got != "192.168.0.0/16" {
		t.Errorf("对照段回显成 %s", got)
	}
	if _, ok := v.Values["contains"]; ok {
		t.Error("不撞就不该给 contains")
	}
}

// ★ v4 和 v6 各自编址，谈不上撞。把「不可比」当成「不重叠」，
// 人就以为双栈配下去一定通 —— 症状是其中一族时不时不通。
// 所以这里要一个自己的判定码，而不是咽下去答成 v4-network。
func Test跨族说的是不可比(t *testing.T) {
	v := scRun(t, map[string]any{"cidr": "192.168.1.0/24", "peer": "fd00::/64"})
	if v.Code != scCrossFam {
		t.Fatalf("判定是 %s，想要 %s", v.Code, scCrossFam)
	}
	if v.Values["notComparable"] != true {
		t.Errorf("没标不可比：%+v", v.Values)
	}
	if v.Values["overlaps"] == true {
		t.Error("跨族判成重叠")
	}
	if !strings.Contains(v.Note, "谈不上撞") || !strings.Contains(v.Note, "dualstack") {
		t.Errorf("话里没说清这问题问不成立、下一步问谁：%s", v.Note)
	}
}

// peer 本身写错了要报得清是哪一个 —— 只说「看不懂」人第一反应是查自己填的那段。
func Test对照段写错时报错点名是哪一段(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"cidr": "192.168.1.0/24", "peer": "192.168.1.0/x"})
	_, err := doSubnetCalc(context.Background(), b)
	if err == nil {
		t.Fatal("坏 peer 竟然收了")
	}
	if !strings.Contains(err.Error(), "对照段") {
		t.Errorf("没说是对照段：%v", err)
	}
}

// ── 参数 ──

func Test参数不合法当场拒(t *testing.T) {
	for _, cidr := range []string{
		"", "  ", "384.1.1.1/24", "192.168.1.0/33", "fe80::/129",
		"192.168.1.0/255.255.255.256", "not-an-address", "192.168.1.0/",
	} {
		b, _ := json.Marshal(map[string]any{"cidr": cidr})
		if _, err := doSubnetCalc(context.Background(), b); err == nil {
			t.Errorf("%q 竟然收了", cidr)
		}
	}
	// 192.168.1.0/ 后面空的：按裸地址算比报错靠近人想问的？不 —— 这里已经明确写了斜杠，
	// 说明他以为自己在填掩码，所以按上面那条走：不收。
	v := scRun(t, map[string]any{"cidr": "192.168.1.0"}) // 完全没写斜杠才当单地址
	if v.Code != scSingle {
		t.Errorf("裸地址判定 %s", v.Code)
	}
	if _, err := doSubnetCalc(context.Background(), json.RawMessage(`{`)); err == nil {
		t.Error("坏 JSON 竟然收了")
	}
	if _, err := doSubnetCalc(context.Background(), nil); err == nil {
		t.Error("没参数竟然收了")
	}
}

// v6 写成点分掩码：如果按 v4 掩码解，会得到一个 /0 到 /32 之间的长度，
// 于是「一个 v6 段」被算成大得离谱的段 —— 报错比硬算有用。
func Test六不认点分掩码(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"cidr": "fe80::/255.255.255.0"})
	_, err := doSubnetCalc(context.Background(), b)
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("没挡住：%v", err)
	}
}

// ── 声明 ──

func Test子网计算工具声明(t *testing.T) {
	r := ots.NewRegistry(true)
	r.MustRegister(subnetCalcTool)
	got, ok := r.Lookup("net.subnet.calc")
	if !ok {
		t.Fatal("net.subnet.calc 没注册进注册表")
	}
	if got.Class != ots.ClassRead {
		t.Errorf("纯算术，不该是 %s", got.Class)
	}
	// ★ 这是整个 §小工具里唯一不发包的段类工具，说明里必须写清 ——
	// 否则 AI 会拿它当扫描的替代品去判断「这个段里有没有人」。
	if !strings.Contains(subnetCalcTool.Summary, "不发任何包") {
		t.Error("说明里没写「纯计算、不发任何包」")
	}
	if !strings.Contains(string(subnetCalcTool.Schema), "peer") {
		t.Error("schema 里没提对照段，AI 不知道能问重叠")
	}
	for _, code := range []string{scSingle, scNetwork, scHost, scBroadcast, scV6Prefix, scOverlap, scCrossFam} {
		if !strings.Contains(subnetCalcTool.Summary, code) {
			t.Errorf("说明里漏了判定码 %s", code)
		}
	}
}

// 判定码不许有拼写漂移：界面是按这几个字符串贴标签的。
func Test判定码拼写(t *testing.T) {
	for got, want := range map[string]string{
		scSingle: "single-address", scNetwork: "v4-network", scHost: "v4-host-address",
		scBroadcast: "v4-broadcast-address", scV6Prefix: "v6-prefix", scOverlap: "networks-overlap",
	} {
		if got != want {
			t.Errorf("判定码是 %q，界面认的是 %q", got, want)
		}
	}
}
