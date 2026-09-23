package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.checkup 的测试 ──
//
// ★ 这一栏卖的是**顺序**，所以测试的重心不是「每一项测得准不准」（那些算术各自有别的文件钉），
//   而是三件事：
//     1. 顶层只报「第一个坏掉的是哪一步」，顺序错了就等于让人去修一个没坏的东西；
//     2. 每一项的 warn / bad / skip 分界 —— 特别是**问不到的那些一律 skip**，
//        内网封 UDP、拦 ping、读不到代理都是常态，报成 bad 会让人去查一个没坏的环节；
//     3. 代理这一项不许把带账号密码的地址抄进结果 —— 结果会原样发给 AI、也会进诊断包。
//
//   会发流量的部分全部走 checkProbes 注入：真网络的坏法没法在 CI 里造，
//   而「网关丢包时后面都不许当准」这条恰恰是这一栏存在的理由，必须钉得住。

// ckNIC 造一块网卡。
func ckNIC(t *testing.T, name string, mtu int, up, running, virtual bool, cidrs ...string) netif.NIC {
	t.Helper()
	var addrs []netaddr.Addr
	for _, c := range cidrs {
		a, err := netaddr.Parse(c)
		if err != nil {
			t.Fatalf("%s 的地址 %s 看不懂：%v", name, c, err)
		}
		addrs = append(addrs, a)
	}
	return netif.NIC{Name: name, MTU: mtu, Up: up, Running: running, Virtual: virtual,
		Addrs: addrs, Kind: "ethernet"}
}

// ckFam 造一个地址族的静态结果。★ 只填这一栏要判断的那几个字段。
func ckFam(family string, hasAddr, hasRoute bool, gw, egress string) familyResult {
	return familyResult{
		Family: family, HasAddress: hasAddr, HasRoute: hasRoute,
		Gateway: gw, RouteIface: "en0", RouteCount: b2i(hasRoute), Egress: egress,
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ── 喂给 runCheckup 的脚本 ──

// ckSpec 是一次「假体检」的全部输入。★ 用结构体而不是十几个参数：
// 每个测试只想改自己关心的那一格，其余走默认（一切都好的那台机器）。
type ckSpec struct {
	nics    []netif.NIC
	routes  []netif.DefaultRoute
	servers []netif.DNSServer

	domErr  string
	a       []string // 解析出来的 A，全部按「连上了」记账
	aaaa    []string
	lan4    string // 到 v4 网关那一小轮的判定码（"" = 没问）
	lan6    string
	eg4     string // 固定 IP 出口探测的码
	eg6     string
	loss4   int // lan4=loss 时顺便造几条统计，给 facts 用
	clock   string
	offset  float64
	proxy   string
	prxFact map[string]any
}

// ckProbes 把 ckSpec 翻成可注入的探测。
func ckProbes(t *testing.T, s ckSpec) checkProbes {
	t.Helper()
	lan := func(ctx context.Context, gw string, count int, interval, timeout time.Duration) (string, watchStats, error) {
		code := s.lan4
		lost := s.loss4
		if strings.Contains(gw, ":") {
			code, lost = s.lan6, 0
		}
		st := watchStats{Sent: 6, Recv: 6 - lost, Unreachable: lost, LossPercent: lost * 100 / 6}
		if code == "" {
			return "", watchStats{}, nil
		}
		return code, st, nil
	}
	return checkProbes{
		nics:       func() ([]netif.NIC, error) { return s.nics, nil },
		routes:     func() ([]netif.DefaultRoute, error) { return s.routes, nil },
		dnsServers: func() ([]netif.DNSServer, error) { return s.servers, nil },
		resolve: func(ctx context.Context, domain string, port int, timeout time.Duration) domainResult {
			d := domainResult{Name: domain, Port: port, A: []addrAttempt{}, AAAA: []addrAttempt{}}
			for _, ip := range s.a {
				d.A = append(d.A, addrAttempt{Addr: ip, Code: verdictOpen, RTTMs: 12})
			}
			for _, ip := range s.aaaa {
				d.AAAA = append(d.AAAA, addrAttempt{Addr: ip, Code: verdictOpen, RTTMs: 12})
			}
			d.Err = s.domErr
			return d
		},
		connect: func(ctx context.Context, d *domainResult, timeout time.Duration) {},
		egress: func(ctx context.Context, f *familyResult, target string, timeout time.Duration) {
			if !f.present() {
				f.Egress = egressSkipped
				return
			}
			want := s.eg4
			if f.Family == "ipv6" {
				want = s.eg6
			}
			f.Egress, f.EgressTarget = want, target
		},
		lan: lan,
		clock: func(ctx context.Context, server string, timeout time.Duration) timeSource {
			code := s.clock
			if code == "" {
				code = timeOK
			}
			return timeSource{Server: server, Code: code, OffsetMs: s.offset}
		},
		proxy: func(ctx context.Context) (string, map[string]any) {
			code := s.proxy
			if code == "" {
				code = "none"
			}
			f := s.prxFact
			if f == nil {
				f = map[string]any{}
			}
			return code, f
		},
	}
}

// ckRun 跑一次假体检，返回八项。
func ckRun(t *testing.T, s ckSpec) []checkItem {
	t.Helper()
	items, _, err := runCheckup(context.Background(), checkupArgs{
		Domain: "www.example.com", EgressV4: "1.1.1.1:443", EgressV6: "[2606::1]:443",
		NTPServer: "pool.ntp.org",
	}, 6, time.Second, ckProbes(t, s))
	if err != nil {
		t.Fatalf("体检跑失败了：%v", err)
	}
	return items
}

func ckHealthy(t *testing.T) ckSpec {
	return ckSpec{
		nics: []netif.NIC{
			ckNIC(t, "en0", 1500, true, true, false, "192.168.1.7/24", "2400:3200::7/64"),
			ckNIC(t, "lo0", 16384, true, true, false, "127.0.0.1/8"),
		},
		routes: []netif.DefaultRoute{
			{Family: "ipv4", Gateway: "192.168.1.1", Iface: "en0"},
			{Family: "ipv6", Gateway: "fe80::1%en0", Iface: "en0"},
		},
		servers: []netif.DNSServer{{Addr: "192.168.1.1"}},
		a:       []string{"104.16.1.1"},
		aaaa:    []string{"2606:4700::1111"},
		lan4:    watchStable,
		lan6:    watchStable,
		eg4:     verdictOpen,
		eg6:     verdictOpen,
		clock:   timeOK,
		proxy:   "none",
	}
}

// ── 顶层判定：这一栏的存在理由 ──

func itemByStep(items []checkItem, step string) checkItem {
	for _, it := range items {
		if it.Step == step {
			return it
		}
	}
	return checkItem{}
}

// 两个环节同时坏，顶层只能说一个。★ 报的顺序必须是排查顺序，不是严重程度排序：
// 网关在丢包时 DNS 也问不出来，去重启 DNS 服务是白跑一趟。
func Test顶层只报第一个坏掉的步骤(t *testing.T) {
	items := []checkItem{
		{Step: stepIface, Severity: sevOK},
		{Step: stepRoute, Severity: sevOK},
		{Step: stepGateway, Code: watchLoss, Severity: sevBad},
		{Step: stepDNS, Code: "error", Severity: sevBad},
		{Step: stepEgress, Code: "broken", Severity: sevBad},
	}
	top, first := rollup(items)
	if top != topBrokenGateway || first != stepGateway {
		t.Errorf("顶层给的是 %s / %s，应该是 %s / gateway（DNS 和出口的坏是网关带出来的）",
			top, first, topBrokenGateway)
	}
}

// 反过来：网卡根本没插线，那才是真根因，哪怕后面的项也全在报坏。
func Test更靠前的硬件坏时轮不到后面的背锅(t *testing.T) {
	items := []checkItem{
		{Step: stepIface, Code: "no-link", Severity: sevBad},
		{Step: stepGateway, Code: watchLoss, Severity: sevBad},
		{Step: stepDNS, Code: "error", Severity: sevBad},
	}
	top, first := rollup(items)
	if top != topBrokenIface || first != stepIface {
		t.Errorf("%s / %s，应该是 %s / iface", top, first, topBrokenIface)
	}
}

// 没有硬故障、但有机会坏的东西 —— 这一档不能省：现场大量问题就是「没断，只是慢」。
func Test只有值得看一眼的算degraded(t *testing.T) {
	items := []checkItem{
		{Step: stepIface, Severity: sevOK},
		{Step: stepGateway, Code: watchJitter, Severity: sevWarn},
		{Step: stepMTU, Code: "small", Severity: sevWarn},
	}
	top, first := rollup(items)
	if top != topDegraded {
		t.Errorf("顶层 = %s，应该是 %s", top, topDegraded)
	}
	if first != stepGateway {
		t.Errorf("first = %s，应该指出最前面那个值得看的（gateway，不是 mtu）", first)
	}
}

func Test全过时时first为空(t *testing.T) {
	top, first := rollup(ckItemsAllOK())
	if top != topAllGood || first != "" {
		t.Errorf("%s / %s，应该是 all-good 且不指任何一步", top, first)
	}
}

// ★ 问不到 ≠ 坏。内网封 UDP/123、拦 ping、读不到代理，全是常态；
//
//	把它们算进 degraded 会让人以为自己的机器有问题，一天里没人能凑出一个 all-good。
func Test问不到的项不许把结论拖成degraded(t *testing.T) {
	items := []checkItem{
		{Step: stepIface, Severity: sevOK},
		{Step: stepRoute, Severity: sevOK},
		{Step: stepGateway, Code: "not-asked", Severity: sevSkip},
		{Step: stepDNS, Severity: sevOK},
		{Step: stepEgress, Severity: sevOK},
		{Step: stepMTU, Code: "unknown", Severity: sevSkip},
		{Step: stepClock, Code: "not-asked", Severity: sevSkip},
		{Step: stepProxy, Code: "unsupported", Severity: sevSkip},
	}
	top, first := rollup(items)
	if top != topAllGood || first != "" {
		t.Errorf("四个 skip 就把结论弄成了 %s / %s", top, first)
	}
}

func ckItemsAllOK() []checkItem {
	var out []checkItem
	for _, s := range []string{stepIface, stepRoute, stepGateway, stepDNS, stepEgress, stepMTU, stepClock, stepProxy} {
		out = append(out, checkItem{Step: s, Code: "ok", Severity: sevOK})
	}
	return out
}

// ── 各步骤的分级界线 ──

// 网卡这一项要分清「没启用」「没插线」「插了没地址」：三种坏法查的东西完全不同，
// 而界面只会照这一格去提示人。
func Test网卡项分得清没启用没插线没地址(t *testing.T) {
	v4 := func(nics []netif.NIC) checkItem {
		f := ckFam("ipv4", false, false, "", egressSkipped)
		return ifaceItem(nics, f, ckFam("ipv6", false, false, "", egressSkipped))
	}
	cases := []struct {
		name string
		nics []netif.NIC
		want string
	}{
		{"一块网卡都没有", nil, "no-nic"},
		{
			"全被禁用了",
			[]netif.NIC{ckNIC(t, "en0", 1500, false, false, false, "192.168.1.7/24")},
			"all-disabled",
		},
		{
			"启用了但没插线",
			[]netif.NIC{ckNIC(t, "en0", 1500, true, false, false, "192.168.1.7/24")},
			"no-link",
		},
		{
			"插了线没要到地址",
			[]netif.NIC{ckNIC(t, "en0", 1500, true, true, false, "169.254.7.7/16")},
			"no-address",
		},
		{
			"只有 VPN 口有地址",
			[]netif.NIC{ckNIC(t, "utun3", 1400, true, true, true, "10.9.0.5/24")},
			"virtual-only",
		},
		{
			"物理口在用",
			[]netif.NIC{
				ckNIC(t, "utun3", 1400, true, true, true, "10.9.0.5/24"),
				ckNIC(t, "en0", 1500, true, true, false, "192.168.1.7/24"),
			},
			"ok",
		},
	}
	for _, c := range cases {
		it := v4(c.nics)
		if it.Code != c.want {
			t.Errorf("%s：判成 %s，应该是 %s", c.name, it.Code, c.want)
		}
		if it.Code == "ok" && it.Severity != sevOK {
			t.Errorf("%s：码对了但严重度是 %s", c.name, it.Severity)
		}
		if c.want == "virtual-only" && it.Severity != sevWarn {
			t.Errorf("只有虚拟口时应该是 warn（有人就是只走 VPN），拿到 %s", it.Severity)
		}
		if c.want != "ok" && c.want != "virtual-only" && it.Severity != sevBad {
			t.Errorf("%s：严重度 %s，应该算 bad", c.name, it.Severity)
		}
	}
}

// 只有一族有默认路由不算坏，但**只有 v6** 要提一句：
// 应用普遍先试 v4，那时它得白等一次才回落。
func Test路由只有一族时v6only要提醒(t *testing.T) {
	cases := []struct {
		name   string
		v4, v6 familyResult
		code   string
		sev    string
	}{
		{"两族都有路", ckFam("ipv4", true, true, "192.168.1.1", ""), ckFam("ipv6", true, true, "fe80::1", ""), "ok", sevOK},
		{"只有 v4", ckFam("ipv4", true, true, "192.168.1.1", ""), ckFam("ipv6", false, false, "", ""), "v4-only", sevOK},
		{"只有 v6", ckFam("ipv4", false, false, "", ""), ckFam("ipv6", true, true, "fe80::1", ""), "v6-only", sevWarn},
		{"都没有路", ckFam("ipv4", true, false, "", ""), ckFam("ipv6", false, false, "", ""), "none", sevBad},
	}
	for _, c := range cases {
		it := routeItem(c.v4, c.v6)
		if it.Code != c.code || it.Severity != c.sev {
			t.Errorf("%s：%s/%s，应该是 %s/%s", c.name, it.Code, it.Severity, c.code, c.sev)
		}
	}
}

// ★ 网关「不回 ping」只算 warn：现场太多路由器默认拦 ICMP。
//
//	把它当故障会让人去翻一台根本没问题的设备。丢包和明确不可达才是 bad —— 那两个说明路有问题。
func Test网关不吭声只算warn(t *testing.T) {
	v4, v6 := ckFam("ipv4", true, true, "192.168.1.1", ""), ckFam("ipv6", false, false, "", "")
	cases := []struct {
		lan string
		// want  ""表示沿用网关那族的 watch 码
		want string
		sev  string
	}{
		{watchStable, "ok", sevOK},
		{watchJitter, watchJitter, sevWarn},
		{watchNoReply, watchNoReply, sevWarn},
		{watchLoss, watchLoss, sevBad},
		{watchUnreachable, watchUnreachable, sevBad},
		{watchNoRoute, watchNoRoute, sevBad},
	}
	for _, c := range cases {
		code, sev := worstGW(c.lan, "", v4, v6)
		if code != c.want || sev != c.sev {
			t.Errorf("网关 %s：判成 %s/%s，应该是 %s/%s", c.lan, code, sev, c.want, c.sev)
		}
	}
}

// 两族各测一小轮时取更坏的那一族 —— 但坏的程度不能跨族平均。
func Test网关两族取更坏的一族(t *testing.T) {
	v4, v6 := ckFam("ipv4", true, true, "192.168.1.1", ""), ckFam("ipv6", true, true, "fe80::1", "")
	code, sev := worstGW(watchStable, watchLoss, v4, v6)
	if code != watchLoss || sev != sevBad {
		t.Errorf("v4 稳 v6 丢：判成 %s/%s，应该说丢", code, sev)
	}
	// 一族没问（没有下一跳）不能把另一族的结论冲淡
	code, sev = worstGW(watchJitter, "", v4, v6)
	if code != watchJitter || sev != sevWarn {
		t.Errorf("只问到一族：%s/%s", code, sev)
	}
}

// 有默认路由但没有下一跳（点对点、蜂窝拨号）是正常的，不是「网关不通」。
func Test没有下一跳时网关项不算坏(t *testing.T) {
	v4, v6 := ckFam("ipv4", true, true, "", ""), ckFam("ipv6", false, false, "", "")
	code, sev := worstGW("", "", v4, v6)
	if code != "no-gateway" || sev != sevOK {
		t.Errorf("%s/%s，点对点链路应该是 no-gateway/ok", code, sev)
	}
	// 两族都没有路由时根本没得问，别报 ok 也别报 bad
	code, sev = worstGW("", "", ckFam("ipv4", true, false, "", ""), ckFam("ipv6", false, false, "", ""))
	if code != "not-asked" || sev != sevSkip {
		t.Errorf("%s/%s，没有默认路由应该是 not-asked/skip", code, sev)
	}
}

// DNS 这一项只判「问不问得出」，不判域名有几条记录：
// ★ 一个域名本来就可以只有 A 没有 AAAA，报成坏了会让人去重启一个没坏的解析器。
func TestDNS只看问不问得出(t *testing.T) {
	srv := []netif.DNSServer{{Addr: "192.168.1.1"}}
	cases := []struct {
		name string
		dom  domainResult
		srv  []netif.DNSServer
		want string
		sev  string
	}{
		{"没配服务器", domainResult{Name: "a", A: []addrAttempt{}, AAAA: []addrAttempt{}}, nil, "no-server", sevBad},
		{"问崩了", domainResult{Name: "a", Err: "server misbehaving", A: []addrAttempt{}, AAAA: []addrAttempt{}}, srv, "error", sevBad},
		{"一条记录都没回", domainResult{Name: "a", A: []addrAttempt{}, AAAA: []addrAttempt{}}, srv, "no-record", sevBad},
		{"只有 v6 记录", domainResult{Name: "a", A: []addrAttempt{}, AAAA: []addrAttempt{{Addr: "2606::1", Code: verdictOpen}}}, srv, "no-v4-record", sevWarn},
		{"只有 A 记录（太常见了）", domainResult{Name: "a", A: []addrAttempt{{Addr: "1.1.1.1", Code: verdictOpen}}, AAAA: []addrAttempt{}}, srv, "ok", sevOK},
		{"双栈都有", domainResult{Name: "a", A: []addrAttempt{{Addr: "1.1.1.1", Code: verdictOpen}}, AAAA: []addrAttempt{{Addr: "2606::1", Code: verdictOpen}}}, srv, "ok", sevOK},
	}
	for _, c := range cases {
		it := dnsItem(c.srv, c.dom)
		if it.Code != c.want || it.Severity != c.sev {
			t.Errorf("%s：%s/%s，应该是 %s/%s", c.name, it.Code, it.Severity, c.want, c.sev)
		}
	}
}

// ★ 出口这一栏的招牌场景：v6 有地址有路由却出不了外网。
//
//	它不能报成「断网」（人就不往下查了），也不能不报（那正是「网很慢」的真身）。
func Test有v6却出不了外网时报成warn而不是断网(t *testing.T) {
	v4 := ckFam("ipv4", true, true, "192.168.1.1", verdictOpen)
	v6 := ckFam("ipv6", true, true, "fe80::1", verdictFiltered)
	it := egressItem(v4, v6)
	if it.Code != "v6-egress-broken" || it.Severity != sevWarn {
		t.Errorf("%s/%s，应该是 v6-egress-broken/warn", it.Code, it.Severity)
	}
	if !strings.Contains(checkupNote(topDegraded, []checkItem{it}), "gateway") &&
		!strings.Contains(checkupNote(topDegraded, []checkItem{it}), "egress") {
		t.Error("degraded 的话里没点名是哪一项")
	}
}

// 纯 v4 内网（v6 根本不在场）出得去就是 ok —— 不许因为没有 v6 而扣分。
func Test只有一族在场时另一族谈不上坏(t *testing.T) {
	v4 := ckFam("ipv4", true, true, "192.168.1.1", verdictOpen)
	v6 := ckFam("ipv6", false, false, "", egressSkipped)
	if it := egressItem(v4, v6); it.Code != "ok" || it.Severity != sevOK {
		t.Errorf("纯 v4 判成 %s/%s", it.Code, it.Severity)
	}
	// 但 v4 在场又出不去，就是真坏了
	if it := egressItem(ckFam("ipv4", true, true, "192.168.1.1", verdictFiltered), v6); it.Severity != sevBad {
		t.Errorf("唯一的一族出不了外网却只给了 %s", it.Code)
	}
	// 两族都不在场：没问，不是坏
	if it := egressItem(v6, v6); it.Code != "not-asked" || it.Severity != sevSkip {
		t.Errorf("两族都不在场：%s/%s", it.Code, it.Severity)
	}
}

// ★ MTU 这一项只判物理口。隧道和 VPN 的 1400 / 1280 是本来就该那样，
//
//	报成「偏小」会让人去改一个不该改的东西。
func TestMTU不冤枉隧道口(t *testing.T) {
	phys := ckNIC(t, "en0", 1400, true, true, false, "192.168.1.7/24")
	tun := ckNIC(t, "utun3", 1400, true, true, true, "10.9.0.5/24")
	if it := mtuItem([]netif.NIC{tun}, "utun3"); it.Code != "tunnel" || it.Severity != sevOK {
		t.Errorf("隧道口 1400 判成 %s/%s", it.Code, it.Severity)
	}
	if it := mtuItem([]netif.NIC{phys}, "en0"); it.Code != "small" || it.Severity != sevWarn {
		t.Errorf("物理口 1400 判成 %s/%s", it.Code, it.Severity)
	}
	full := ckNIC(t, "en0", 1500, true, true, false, "192.168.1.7/24")
	if it := mtuItem([]netif.NIC{full}, "en0"); it.Code != "ok" {
		t.Errorf("1500 判成 %s", it.Code)
	}
	// 认不出出口网卡时只说不知道，别猜一个「偏小」
	if it := mtuItem([]netif.NIC{full}, ""); it.Code != "unknown" || it.Severity != sevSkip {
		t.Errorf("不知道出口网卡：%s/%s", it.Code, it.Severity)
	}
}

// 出口网卡取默认路由那块（v4 优先）。
func Test出口网卡按默认路由认(t *testing.T) {
	nics := []netif.NIC{
		ckNIC(t, "en0", 1500, true, true, false, "192.168.1.7/24"),
		ckNIC(t, "en7", 1500, true, true, false, "10.0.0.7/24"),
	}
	routes := []netif.DefaultRoute{
		{Family: "ipv6", Gateway: "fe80::1", Iface: "en7"},
		{Family: "ipv4", Gateway: "10.0.0.1", Iface: "en7"},
	}
	if got := egressIfaceName(nics, routes); got != "en7" {
		t.Errorf("认成 %s，应该跟着 v4 默认路由走 en7", got)
	}
	if got := egressIfaceName(nics, routes[:1]); got != "en7" {
		t.Errorf("只有 v6 路由时应该回落到 en7，拿到 %s", got)
	}
	if got := egressIfaceName(nics, nil); got != "" {
		t.Errorf("没有默认路由应该给空，拿到 %s", got)
	}
}

// ★ 时钟：偏差量级大到会出事才算 bad，问不到只算 skip。
//
//	「谁不对」是 net.time.check 的活（要多个源互相印证），体检里不许越权下那个结论。
func Test时钟问不到不许报成坏(t *testing.T) {
	cases := []struct {
		code string
		off  float64
		want string
		sev  string
	}{
		// ★ askSource 回的码只有「答了没有」，偏多少算事是按毫秒数分的（和校时那栏同一份阈值）。
		{timeAnswered, 112.4, "ok", sevOK},
		{timeAnswered, -3000, "skew", sevWarn}, // 本机快着也一样算偏差
		{timeAnswered, 300000, "big-skew", sevBad},
		{timeWayOff, 900000, "big-skew", sevBad},
		{timeKissed, 0, "big-skew", sevBad}, // 服务器回了 STEP：明说你的钟太离谱
		{timeNoResponse, 0, "not-asked", sevSkip},
		{timeBadFormat, 0, "not-asked", sevSkip},
		{timeDisagree, 0, "not-asked", sevSkip},
		{tlsNameUnresolved, 0, "not-asked", sevSkip}, // 连域名都问不到，扯不上时钟坏
	}
	for _, c := range cases {
		it := clockItem(timeSource{Server: "pool.ntp.org", Code: c.code, OffsetMs: c.off})
		if it.Code != c.want || it.Severity != c.sev {
			t.Errorf("源码 %s（偏 %.0fms）：判成 %s/%s，应该是 %s/%s",
				c.code, c.off, it.Code, it.Severity, c.want, c.sev)
		}
	}
}

// ★ 挂着 VPN 的机器不该拿到一条假的「网关不通」。
//
//	隧道口上那个下一跳是本机自己编出来的链路本地地址，问它不通是设计如此 ——
//	所以这一族根本不问，并且说明为什么没问。
func Test只走VPN时不去问网关(t *testing.T) {
	nics := []netif.NIC{ckNIC(t, "en0", 1500, true, true, false, "192.168.1.7/24")}
	// v6 的默认路由走 VPN 隧道口（macOS 上 utun 常这样）
	f := ckFam("ipv6", true, true, "fe80::1", "")
	f.RouteIface = "utun3"
	phys := append(nics, ckNIC(t, "utun3", 1400, true, true, true, "10.9.0.5/24"))
	gw, why := lanLeg(phys, f)
	if gw != "" || why != "tunnel" {
		t.Errorf("问 %q / 原因 %q，隧道口应该不问并给出 tunnel", gw, why)
	}
	// 认不出这块网卡时照问：宁可多一条证据，也别替人编一个「没问」的理由
	gw, why = lanLeg(nics, f)
	if gw != "fe80::1" || why != "" {
		t.Errorf("认不出网卡时不该编原因：%q / %q", gw, why)
	}
	// 没有路由 / 没有下一跳也各自说清，别混成「网关不通」
	if _, why = lanLeg(phys, ckFam("ipv4", true, false, "", "")); why != "no-route" {
		t.Errorf("没有默认路由的原因说成 %q", why)
	}
	if _, why = lanLeg(phys, ckFam("ipv4", true, true, "", "")); why != "no-gateway" {
		t.Errorf("点对点链路说成 %q，应该叫 no-gateway", why)
	}
}

// 隧道那一族跳过之后，网关项必须是 skip 而不是 warn —— 否则每个挂 VPN 的人
// 都会看到「有值得看一眼的东西」，真毛病反倒混在假警报里。
func Test网关整项都没问时给skip(t *testing.T) {
	v4, v6 := ckFam("ipv4", true, true, "", ""), ckFam("ipv6", true, true, "fe80::1", "")
	it := gatewayItem(v4, v6, lanResult{Reason: "no-gateway"}, lanResult{Reason: "tunnel"})
	if it.Code != "tunnel" || it.Severity != sevSkip {
		t.Errorf("%s/%s，隧道口挂着时应该是 tunnel/skip", it.Code, it.Severity)
	}
	it = gatewayItem(v4, v6, lanResult{Reason: "no-gateway"}, lanResult{})
	if it.Code != "no-gateway" || it.Severity != sevOK {
		t.Errorf("%s/%s，纯点对点链路应该算正常", it.Code, it.Severity)
	}
	// 一族问了、一族没问：以问到的那族为准
	it = gatewayItem(v4, v6, lanResult{Code: watchLoss}, lanResult{Reason: "tunnel"})
	if it.Code != watchLoss || it.Severity != sevBad {
		t.Errorf("%s/%s，问到的那族在丢包就必须报丢包", it.Code, it.Severity)
	}
	// 没问的那一族要在事实里留下为什么
	if f, _ := it.Facts["ipv6"].(map[string]any); f["code"] != "tunnel" {
		t.Errorf("ipv6 事实里没写没问的原因：%v", it.Facts["ipv6"])
	}
}

// ── 代理：结果会原样发给 AI、也会进诊断包，所以凭据必须在出门前切掉 ──

func Test代理地址剥掉账号密码(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://user:pass@proxy.corp:8080", "proxy.corp:8080"},
		{"https://u:p@10.0.0.9:3128/", "10.0.0.9:3128"},
		{"socks5://user:secret@socks.internal", "socks.internal"},
		{"10.0.0.9:3128", "10.0.0.9:3128"},
		{"proxy.corp:8080", "proxy.corp:8080"},
		{"  http://proxy.corp:8080  ", "proxy.corp:8080"},
		{"user:pass@proxy.corp:8080", "proxy.corp:8080"}, // 没有 scheme 的那种写法
	}
	for _, c := range cases {
		got := hostOnly(c.in)
		if got != c.want {
			t.Errorf("%q 收成 %q，应该是 %q", c.in, got, c.want)
		}
		if strings.Contains(got, "user:") || strings.Contains(got, "pass") || strings.Contains(got, "secret") || strings.Contains(got, "@") {
			t.Errorf("%q 收完还留着凭据：%q", c.in, got)
		}
	}
}

// scutil 输出里三个开关各自独立：只列真开着的，关掉的不能混进来。
func TestScutil只列开着的代理(t *testing.T) {
	out := `
  HTTPEnable : 1
  HTTPProxy : 10.0.0.9
  HTTPPort : 3128
  HTTPSEnable : 0
  HTTPSProxy : 10.0.0.9
  HTTPSPort : 3128
  SOCKSEnable : 1
  SOCKSProxy : socks.corp
  SOCKSPort : 1080
`
	got := strings.Join(proxyFromScutil(out), " ")
	if !strings.Contains(got, "http=10.0.0.9:3128") {
		t.Errorf("开着的 http 代理没列出来：%s", got)
	}
	if !strings.Contains(got, "socks=socks.corp:1080") {
		t.Errorf("开着的 socks 代理没列出来：%s", got)
	}
	if strings.Contains(got, "https=") {
		t.Errorf("HTTPS 开关是 0 却列进了结果：%s", got)
	}
}

// ★ Windows / Linux 上没有可靠的统一读法，必须报 unsupported 而不是 none：
// 后者会把一台确实开着代理的机器判成干净，然后人照着「没代理」去查半天。
func Test读不到代理时说的是读不到(t *testing.T) {
	if proxySeverity("unsupported") != sevSkip {
		t.Error("读不到被算成了坏或者 warn")
	}
	if proxySeverity("none") != sevOK {
		t.Error("确认没设代理应该是 ok")
	}
	if proxySeverity("set") != sevWarn {
		t.Error("设了代理至少该让人看一眼（代理会让「直连不通」的判断整体变样）")
	}
}

// ── 整跑一遍：八项、顺序、以及几条「前面的坏会带出后面的坏」 ──

func Test体检跑完八项且顺序固定(t *testing.T) {
	items := ckRun(t, ckHealthy(t))
	var got []string
	for _, it := range items {
		got = append(got, it.Step)
	}
	want := strings.Join([]string{stepIface, stepRoute, stepGateway, stepDNS, stepEgress, stepMTU, stepClock, stepProxy}, " ")
	if strings.Join(got, " ") != want {
		t.Errorf("步骤顺序是 %v，应该是 %s", got, want)
	}
}

// 一切都好的那台机器必须真的能拿到 all-good —— 否则上面那一长串 warn 的门槛就白设了。
func Test健康机器跑出来就是allgood(t *testing.T) {
	items := ckRun(t, ckHealthy(t))
	top, first := rollup(items)
	if top != topAllGood {
		var bad []string
		for _, it := range items {
			if it.Severity != sevOK {
				bad = append(bad, it.Step+"="+it.Code+"/"+it.Severity)
			}
		}
		t.Errorf("跑成 %s（first=%s），没过的项：%s", top, first, strings.Join(bad, "、"))
	}
}

// ★ 网关丢包时，即使 DNS 也问不出来，顶层也必须说是网关 ——
//
//	「先修 DNS」是这一类现场最浪费时间的一条路。
func Test网关丢包时不许把锅甩给DNS(t *testing.T) {
	s := ckHealthy(t)
	s.lan4 = watchLoss
	s.loss4 = 2
	s.domErr = "i/o timeout"
	items := ckRun(t, s)
	top, first := rollup(items)
	if top != topBrokenGateway || first != stepGateway {
		t.Errorf("顶层 = %s/%s，应该是 broken-at-gateway", top, first)
	}
	// DNS 那一格仍然要留着坏痕：它是证据，只是不是根因
	if it := itemByStep(items, stepDNS); it.Severity != sevBad {
		t.Errorf("DNS 被网关带坏却标成 %s/%s", it.Code, it.Severity)
	}
	n := checkupNote(top, items)
	if !strings.Contains(n, "别当准") {
		t.Errorf("话里没提醒后面的数字不可信：%s", n)
	}
}

// ★ 固定 IP 被这个网络单独丢掉，不等于出不了外网。
//
//	域名解析出来的地址真连上了，就是这一族能出网的直接证据 —— 只认 1.1.1.1 那一次失败，
//	会把「能上网」判成「断网」。这条复用双栈那栏踩出来的教训。
func Test域名连上了就不许说断网(t *testing.T) {
	s := ckHealthy(t)
	s.eg4 = verdictFiltered // 固定的 1.1.1.1 / 2606::1 都被这个网络丢了
	s.eg6 = verdictFiltered
	items := ckRun(t, s)
	it := itemByStep(items, stepEgress)
	if it.Code != "ok" || it.Severity != sevOK {
		t.Errorf("域名地址连上了还判成 %s/%s", it.Code, it.Severity)
	}
	if got, _ := json.Marshal(it.Facts["ipv4"]); !strings.Contains(string(got), verdictOpen) {
		t.Errorf("出口事实里没留下 open：%s", got)
	}
}

// 有 v6 地址和路由、v4 也好，只有 v6 出不去 —— 顶层应该停在 degraded，
// 并指出是 gateway/egress 那一类「不拦你但让你慢」的毛病。
func Test双栈只出一半时顶层是degraded而不是断网(t *testing.T) {
	s := ckHealthy(t)
	s.eg6 = verdictFiltered
	s.aaaa = nil // 域名也没有 AAAA 可连 —— v6 这一族是真的出不去
	items := ckRun(t, s)
	top, first := rollup(items)
	if top != topDegraded {
		t.Errorf("判成 %s，双栈一半出不了网应该是 degraded", top)
	}
	if first != stepEgress {
		t.Errorf("first = %s，应该指出动手的是 egress", first)
	}
}

// 没有默认路由时网关那一项根本不问 —— 白等一个超时之外什么也换不来，
// 而且要在事实里留下「为什么没问」这个原因。
func Test没有默认路由时不去问网关(t *testing.T) {
	s := ckHealthy(t)
	s.routes = []netif.DefaultRoute{{Family: "ipv4", Gateway: "192.168.1.1", Iface: "en0"}}
	items := ckRun(t, s) // v6 有地址没路由
	it := itemByStep(items, stepGateway)
	if v6f, ok := it.Facts["ipv6"].(map[string]any); !ok || v6f["code"] != "no-route" {
		t.Errorf("v6 没路由却没在事实里说清原因：%v", it.Facts["ipv6"])
	}
	if v4f, _ := it.Facts["ipv4"].(map[string]any); v4f["code"] != watchStable {
		t.Errorf("v4 问了应该拿到 stable，实际 %v", v4f["code"])
	}
}

// ★ 挂着 VPN 的现场：v6 默认路由整个落在隧道口上。这时网关一项必须是不问，
//
//	否则每一个开 VPN 的人都会因为一个「本来就不该问」的地址收到一条假 warn，
//	真毛病反倒混在假警报里看不见了。
func Test挂VPN体检时网关一项不算毛病(t *testing.T) {
	s := ckHealthy(t)
	s.nics = append(s.nics, ckNIC(t, "utun3", 1400, true, true, true, "10.9.0.5/24"))
	s.routes = []netif.DefaultRoute{
		{Family: "ipv4", Gateway: "192.168.1.1", Iface: "en0"},
		{Family: "ipv6", Gateway: "fe80::1%utun3", Iface: "utun3"},
	}
	s.lan6 = "" // 这一族不该被问到；一旦被问到就会拿到 no-reply 变成假 warn
	items := ckRun(t, s)
	it := itemByStep(items, stepGateway)
	if it.Code != "ok" || it.Severity != sevOK {
		t.Errorf("网关项 = %s/%s，v4 稳、v6 不该问，应该算 ok", it.Code, it.Severity)
	}
	if v6f, _ := it.Facts["ipv6"].(map[string]any); v6f["code"] != "tunnel" {
		t.Errorf("v6 走隧道口却没在事实里说明：%v", it.Facts["ipv6"])
	}
}

// ── 给 CLI / 日志看的 note ──

func Test判定话不复述八行只点名动手那一步(t *testing.T) {
	s := ckHealthy(t)
	s.proxy = "set"
	s.prxFact = map[string]any{"entries": []string{"http=proxy.corp:8080"}}
	items := ckRun(t, s)
	n := checkupNote(topDegraded, items)
	if !strings.Contains(n, "proxy=set") {
		t.Errorf("degraded 的话里没点出是哪一项：%s", n)
	}
	for _, bad := range []string{"**", "#", "- ", "\n\n"} {
		if strings.Contains(n, bad) {
			t.Errorf("note 里出现了 %q（note 会被原样贴进日志，不渲染 markdown）", bad)
		}
	}
	all := checkupNote(topAllGood, ckItemsAllOK())
	if !strings.Contains(all, "设备之间通不通") {
		t.Errorf("all-good 的话里没提醒「这只说明到公网这一段」：%s", all)
	}
}

// ── 工具声明 ──

func Test体检工具声明(t *testing.T) {
	if checkupTool.Name != "net.checkup" {
		t.Errorf("名字是 %s", checkupTool.Name)
	}
	if checkupTool.Class != ots.ClassRead {
		t.Errorf("只是发流量观察，类别却是 %s", checkupTool.Class)
	}
	if !json.Valid(checkupTool.Schema) {
		t.Error("Schema 不是合法 JSON")
	}
	var m map[string]any
	if err := json.Unmarshal(checkupTool.Schema, &m); err != nil {
		t.Fatalf("Schema 解析不了：%v", err)
	}
	if m["additionalProperties"] != false {
		t.Error("必须明确拒收多余字段")
	}
	// 什么都不用填才配叫「一键」
	props, _ := m["properties"].(map[string]any)
	if req, _ := m["required"].([]any); len(req) != 0 {
		t.Errorf("声明了必填参数 %v，体检就不是一键了", req)
	}
	for _, need := range []string{"domain", "egressV4", "egressV6", "ntpServer", "lanProbes", "timeoutMs"} {
		if _, ok := props[need]; !ok {
			t.Errorf("参数 %s 没声明", need)
		}
	}
	if !strings.Contains(checkupTool.Summary, "第一个坏掉的是哪一步") {
		t.Error("摘要没把这一栏的卖点写出来")
	}
	r := ots.NewRegistry(true)
	Register(r)
	if _, ok := r.Lookup("net.checkup"); !ok {
		t.Error("net.checkup 没注册进注册表")
	}
}
