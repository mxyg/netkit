package tools

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.checkup 一键体检 ──
//
// ★★ 这一栏卖的不是「八个结果」，是**顺序**。
//
//	工程师脑子里的排查顺序本来就是「本机有没有地址 → 有没有路 → 网关通不通、
//	丢不丢 → DNS → 出不出得去 → 几时」，而每一项单独看都不说明问题：
//	「网关丢包 8%」足以让后面的 DNS 和出口全部失真（那时测到的慢是链路的，不是服务的）。
//	所以顶层判定只说一件事：**第一个坏掉的是哪一步**。
//
// ★ v4 / v6 分开给，不许合成一句「网络正常」（docs/设计.md）。有 v6 地址和路由却出不了外网，
//
//	应用会先卡在 v6 上再回落 —— 现场读到「网络正常」就再也不会往下查了，而那恰恰是毛病。
//
// ★ 有一项不硬判：网关不回 ping。现场太多路由器默认拦 ICMP，
//
//	把它当故障会让人去翻一个根本没问题的设备 —— 所以它是 warn 并写明「也可能是它自己拦了」。
//
// ★ 代理这一项只给 host:port，绝不把带账号密码的代理地址抄进结果 ——
//
//	结果会原样发给 AI、也会进诊断包。
const (
	topAllGood       = "all-good"
	topDegraded      = "degraded"
	topBrokenIface   = "broken-at-iface"
	topBrokenRoute   = "broken-at-route"
	topBrokenGateway = "broken-at-gateway"
	topBrokenDNS     = "broken-at-dns"
	topBrokenEgress  = "broken-at-egress"
	topBrokenClock   = "broken-at-clock"
)

// 每一项的坏法分三级。★ warn 和 bad 的界线是「要不要现在动手」：
// bad 说明这一步就是根因（或者至少是根因的现场），warn 说明它值得看一眼但不必停在这。
const (
	sevOK   = "ok"
	sevWarn = "warn"
	sevBad  = "bad"
	sevSkip = "skip"
)

// 体检项的名字。顺序就是这里列的顺序 —— 顶层判定按它挑第一个坏的。
const (
	stepIface   = "iface"
	stepRoute   = "route"
	stepGateway = "gateway"
	stepDNS     = "dns"
	stepEgress  = "egress"
	stepMTU     = "mtu"
	stepClock   = "clock"
	stepProxy   = "proxy"
)

var checkupTool = ots.Tool{
	Name:  "net.checkup",
	Class: ots.ClassRead,
	Summary: "按排查顺序把本机网络过一遍（八项，什么都不用填），顶层只说**第一个坏掉的是哪一步**：" +
		"all-good（都好）、degraded（没有硬故障，但有值得看一眼的）、" +
		"broken-at-iface（连一块在用的网卡都没有）、broken-at-route（没有默认路由）、" +
		"broken-at-gateway（到网关就丢包/不可达，后面的测量都不可信）、" +
		"broken-at-dns（配了服务器却解析不出来）、broken-at-egress（局域网好但出不了外网）、" +
		"broken-at-clock（本机时钟偏到会让证书和日志出错）。" +
		"★ 八项依次是 iface / route / gateway / dns / egress / mtu / clock / proxy，" +
		"每项带自己的判定码和事实，v4 与 v6 分开给。" +
		"顺序是有意义的：网关丢包时 DNS 和出口的慢都是链路的，不是服务的，所以不能从中间开始查。" +
		"proxy 一项只报 host:port，不抄带账号的代理地址。全程只发少量探测包，不改动任何东西。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "domain": {"type": "string",
	      "description": "测 DNS 和出口用哪个域名，默认 www.cloudflare.com。内网不通公网时把它换成内网里一定解析得到的名字。"},
	    "egressV4": {"type": "string", "description": "v4 出口探测目标 host:port，默认 1.1.1.1:443。"},
	    "egressV6": {"type": "string", "description": "v6 出口探测目标 [host]:port，默认 [2606:4700:4700::1111]:443。"},
	    "ntpServer": {"type": "string", "description": "校时用哪个 NTP 源，默认 pool.ntp.org。内网有自己的时钟源就填它。"},
	    "lanProbes": {"type": "integer", "minimum": 3, "maximum": 20,
	      "description": "到网关连发几发看丢包和抖动，默认 6。★ 一发ping 看不出「偶尔掉一下」，所以这里按发数算。"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 8000,
	      "description": "单个探测的最长等待，默认 2000。"}
	  }
	}`),
	Invoke: doCheckup,
}

type checkupArgs struct {
	Domain    string `json:"domain,omitempty"`
	EgressV4  string `json:"egressV4,omitempty"`
	EgressV6  string `json:"egressV6,omitempty"`
	NTPServer string `json:"ntpServer,omitempty"`
	LanProbes int    `json:"lanProbes,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// checkItem 一项体检。★ Code 是给人判的，Severity 是给顺序判的，Facts 是给人对着看的。
type checkItem struct {
	Step     string         `json:"step"`
	Code     string         `json:"code"`
	Severity string         `json:"severity"`
	Facts    map[string]any `json:"facts,omitempty"`
}

// checkProbes 把「会发流量」的部分抽出来。★ 抽出来不是为了好看：
// 顶层判定「第一个坏掉的是哪一步」是这一栏的全部价值，
// 而它不该只能靠把一台真的机器搞坏来验。
type checkProbes struct {
	nics       func() ([]netif.NIC, error)
	routes     func() ([]netif.DefaultRoute, error)
	dnsServers func() ([]netif.DNSServer, error)
	resolve    func(ctx context.Context, domain string, port int, timeout time.Duration) domainResult
	connect    func(ctx context.Context, d *domainResult, timeout time.Duration)
	egress     func(ctx context.Context, f *familyResult, target string, timeout time.Duration)
	lan        func(ctx context.Context, gw string, count int, interval, timeout time.Duration) (string, watchStats, error)
	clock      func(ctx context.Context, server string, timeout time.Duration) timeSource
	proxy      func(ctx context.Context) (string, map[string]any)
}

func doCheckup(ctx context.Context, raw json.RawMessage) (any, error) {
	var a checkupArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Domain == "" {
		a.Domain = "www.cloudflare.com"
	}
	if a.EgressV4 == "" {
		a.EgressV4 = "1.1.1.1:443"
	}
	if a.EgressV6 == "" {
		a.EgressV6 = "[2606:4700:4700::1111]:443"
	}
	if a.NTPServer == "" {
		a.NTPServer = defaultNTPServers[0]
	}
	probes := a.LanProbes
	if probes == 0 {
		probes = 6
	}
	if probes < 3 || probes > 20 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"lanProbes %d 不在 3 到 20 之间 —— 少于 3 发看不出「偶尔掉一下」，多于 20 发就不是体检了", probes)
	}
	timeoutMS := a.TimeoutMS
	if timeoutMS == 0 {
		timeoutMS = 2000
	}
	if timeoutMS < 500 || timeoutMS > 8000 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "timeoutMs %d 不在 500 到 8000 之间", timeoutMS)
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	items, notes, err := runCheckup(ctx, a, probes, timeout, defaultProbes())
	if err != nil {
		return nil, err
	}
	top, first := rollup(items)
	values := map[string]any{
		"items": items,
		"first": first,
	}
	for k, v := range notes {
		values[k] = v
	}
	return ots.Verdict{Code: top, Values: values,
		Note: checkupNote(top, items)}, nil
}

// defaultProbes 接上真的系统调用与探测。
func defaultProbes() checkProbes {
	return checkProbes{
		nics:       netif.Interfaces,
		routes:     netif.DefaultRoutes,
		dnsServers: netif.SystemDNSServers,
		resolve:    resolveDomain,
		connect:    connectDomain,
		egress:     probeEgress,
		lan:        lanQuality,
		clock: func(ctx context.Context, server string, timeout time.Duration) timeSource {
			return askSource(ctx, server, 123, 2, timeout)
		},
		proxy: systemProxy,
	}
}

// lanProbeInterval 到网关那一小轮的发包间隔。局域网里 200ms 绰绰有余，再长就把体检拖成等待游戏。
const lanProbeInterval = 200 * time.Millisecond

// lanProbeTimeout 网关单发的等待上限。★ 故意比调用方给的 timeoutMs 短：
//
//	局域网里网关答话是亚毫秒级的，等它 2 秒和等它 0.5 秒结论一样，
//	但六发串下来，「网关完全不吭声」的现场要白等 12 秒还是 3 秒的差别。
const lanProbeTimeout = 500 * time.Millisecond

// lanQuality 朝一个网关连发几发，把判定交给 net.ping.watch 那套算术。
//
// ★ 为什么这里要多发、而且要按发数发：「网关偶尔丢一下」正是后面 DNS/出口慢起来的原因，
//
//	一发 ping 看不出来，而这一栏的判断顺序要求先把它挑出来。
func lanQuality(ctx context.Context, gw string, count int, interval, timeout time.Duration) (string, watchStats, error) {
	addr, err := netaddr.Parse(gw)
	if err != nil {
		return "", watchStats{}, err
	}
	if timeout > lanProbeTimeout {
		timeout = lanProbeTimeout
	}
	w, err := newICMPWatcher(addr, timeout)
	if err != nil {
		return "", watchStats{}, err
	}
	defer w.Close()
	samples, noRoute := w.runN(ctx, interval, count)
	st := statsOf(samples)
	code, _ := watchVerdict(st, noRoute)
	return code, st, nil
}

// runCheckup 按顺序跑八项。★ 顺序不只是显示顺序：前一项坏到一定程度，
// 后面的测量就不可信了 —— 但它仍然要跑完，因为「网关丢包、DNS 也慢」和
// 「网关丢包、DNS 很利索」指向的毛病不一样。
func runCheckup(ctx context.Context, a checkupArgs, lanProbes int, timeout time.Duration, pr checkProbes) ([]checkItem, map[string]any, error) {
	nics, err := pr.nics()
	if err != nil {
		return nil, nil, ots.Errf(ots.ErrInternal, "读网卡失败：%s", err)
	}
	routes, _ := pr.routes() // 读不到不致命：route 一项会如实说「没有默认路由」
	dnsServers, _ := pr.dnsServers()

	v4 := familyResult{Family: "ipv4", Addresses: []string{}, DNS: egressSkipped, Egress: egressSkipped, GwReachable: egressSkipped}
	v6 := familyResult{Family: "ipv6", Addresses: []string{}, DNS: egressSkipped, Egress: egressSkipped, GwReachable: egressSkipped}
	fillFamilyStatic(nics, routes, &v4, &v6)

	egressIface := egressIfaceName(nics, routes)

	var dom domainResult
	domCh := make(chan domainResult, 1)
	go func() {
		// ★ 解析完接着把 A / AAAA 各连一次：域名地址连上了，是这一族出得了外网的**直接证据**，
		//   只用固定 IP（1.1.1.1）判会把「这个网络单独丢了那个 IP」判成「上不了网」。
		d := pr.resolve(ctx, a.Domain, 443, timeout)
		pr.connect(ctx, &d, timeout)
		domCh <- d
	}()

	// 到网关的质量：两族各跑一小轮。★ 它和出口探测并行，
	// 因为两者都慢，串行会把体检拖到十几秒。
	var (
		lan4, lan6 lanResult
		wg         sync.WaitGroup
	)
	gw4, why4 := lanLeg(nics, v4)
	gw6, why6 := lanLeg(nics, v6)
	lan4.Reason, lan6.Reason = why4, why6
	if gw4 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, st, _ := pr.lan(ctx, gw4, lanProbes, lanProbeInterval, timeout)
			lan4.Code, lan4.Stats = code, st
		}()
	}
	if gw6 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, st, _ := pr.lan(ctx, gw6, lanProbes, lanProbeInterval, timeout)
			lan6.Code, lan6.Stats = code, st
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		pr.egress(ctx, &v4, a.EgressV4, timeout)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		pr.egress(ctx, &v6, a.EgressV6, timeout)
	}()
	// 校时和代理也一起跑。★ 它们互相独立，串行会把一次体检拖到六七秒 ——
	// 而「一键体检」卖的就是十秒内拿到「先修哪一个」。
	wg.Add(1)
	var clock timeSource
	var proxyCode string
	var proxyFacts map[string]any
	go func() {
		defer wg.Done()
		clock = pr.clock(ctx, a.NTPServer, timeout)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		proxyCode, proxyFacts = pr.proxy(ctx)
	}()
	wg.Wait()
	dom = <-domCh
	markDNS(&v4, &v6, dom)
	reconcileEgress(&v4, &v6, dom)

	items := []checkItem{
		ifaceItem(nics, v4, v6),
		routeItem(v4, v6),
		gatewayItem(v4, v6, lan4, lan6),
		dnsItem(dnsServers, dom),
		egressItem(v4, v6),
		mtuItem(nics, egressIface),
		clockItem(clock),
		{Step: stepProxy, Code: proxyCode, Severity: proxySeverity(proxyCode), Facts: proxyFacts},
	}
	notes := map[string]any{
		"v4":          v4,
		"v6":          v6,
		"domain":      a.Domain,
		"egressIface": egressIface,
		"lanProbes":   lanProbes,
	}
	return items, notes, nil
}

// lanResult 一族到网关的那一小轮。★ Code 和 Reason 只会各有一个：
// 问了给判定码，没问给为什么没问 —— 「没问」和「问了没回」是两种结论。
type lanResult struct {
	Code   string
	Reason string
	Stats  watchStats
}

// lanLeg 这一族的默认路由值不值得去问网关，返回（该问的网关, 不问的原因）。
//
// ★★ 隧道 / VPN 口（utun、ppp、tap）上那个「下一跳」不是局域网网关：
//
//	它常常是本机自己编出来的链路本地地址，问它不通是设计如此。把它算成「网关不吭声」，
//	每一个挂着 VPN 的人都会得到一条假的 warn，而真毛病反而混在里面看不见。
//	（和 MTU 那一项同一个道理：虚拟口的形状不是物理链路的坏法。）
func lanLeg(nics []netif.NIC, f familyResult) (string, string) {
	switch {
	case !f.HasRoute:
		return "", "no-route"
	case f.Gateway == "":
		return "", "no-gateway" // 点对点链路本来就没有下一跳
	case f.RouteIface != "" && virtualIface(nics, f.RouteIface):
		return "", "tunnel"
	}
	return f.Gateway, ""
}

func virtualIface(nics []netif.NIC, name string) bool {
	for _, n := range nics {
		if n.Name == name {
			return n.Virtual
		}
	}
	return false // 认不出这块网卡时照问 —— 宁可多一条证据，别替人编一个原因
}

// ── 各项判定（纯算术，喂样本就能测）──

// ifaceItem 有没有一块**真在用**的网卡带全局地址。
func ifaceItem(nics []netif.NIC, v4, v6 familyResult) checkItem {
	var real, up, running, virtualWithAddr int
	var names []string
	for _, n := range nics {
		if n.Loop {
			continue
		}
		real++
		if n.Up {
			up++
		}
		if n.Running {
			running++
		}
		hasGlobal := false
		for _, ad := range n.Addrs {
			if usableScope(ad) {
				hasGlobal = true
			}
		}
		if hasGlobal {
			names = append(names, n.Name)
			if n.Virtual {
				virtualWithAddr++
			}
		}
	}
	facts := map[string]any{
		"nics": real, "up": up, "running": running, "withAddress": names,
	}
	code, sev := "ok", sevOK
	switch {
	case real == 0:
		code, sev = "no-nic", sevBad
	case up == 0:
		code, sev = "all-disabled", sevBad
	case running == 0:
		code, sev = "no-link", sevBad // 线没插 / 没连上 AP：这一步之前查什么都白查
	case len(names) == 0:
		code, sev = "no-address", sevBad
	case virtualWithAddr > 0 && len(names) == virtualWithAddr:
		// ★ 只有 VPN / 隧道网卡上有地址：物理口一个都没有。
		//   这不一定是坏（有人就是只走 VPN），但它会让人把「我能上网」理解错方向。
		code, sev = "virtual-only", sevWarn
	}
	return checkItem{Step: stepIface, Code: code, Severity: sev, Facts: facts}
}

// routeItem 默认路由分族给。★ 两族都有算 ok；只有一族不算坏，
// 但「只有 v6」要提一句 —— 应用普遍先试 v4，那时它得等超时才回落。
func routeItem(v4, v6 familyResult) checkItem {
	facts := map[string]any{
		"ipv4": routeFacts(v4), "ipv6": routeFacts(v6),
	}
	switch {
	case !v4.HasRoute && !v6.HasRoute:
		return checkItem{Step: stepRoute, Code: "none", Severity: sevBad, Facts: facts}
	case v4.HasRoute && v6.HasRoute:
		return checkItem{Step: stepRoute, Code: "ok", Severity: sevOK, Facts: facts}
	case v4.HasRoute:
		return checkItem{Step: stepRoute, Code: "v4-only", Severity: sevOK, Facts: facts}
	}
	return checkItem{Step: stepRoute, Code: "v6-only", Severity: sevWarn, Facts: facts}
}

func routeFacts(f familyResult) map[string]any {
	return map[string]any{
		"hasRoute": f.HasRoute, "gateway": f.Gateway,
		"iface": f.RouteIface, "count": f.RouteCount,
	}
}

// gatewayItem 到网关通不通、稳不稳。★ 这里用「连发几发」而不是一发 ping：
// 偶尔丢一下恰恰是后面所有测量变慢的真凶。
func gatewayItem(v4, v6 familyResult, lan4, lan6 lanResult) checkItem {
	facts := map[string]any{
		"ipv4": gwFacts(v4, lan4), "ipv6": gwFacts(v6, lan6),
	}
	code, sev := worstGW(lan4.Code, lan6.Code, v4, v6)
	if lan4.Code == "" && lan6.Code == "" {
		code, sev = gwSkipReason(lan4.Reason, lan6.Reason, v4, v6)
	}
	return checkItem{Step: stepGateway, Code: code, Severity: sev, Facts: facts}
}

// gwSkipReason 一族都没问时的说法。★ 不许把「不该问」报成「问了不通」。
func gwSkipReason(r4, r6 string, v4, v6 familyResult) (string, string) {
	switch {
	case r4 == "tunnel" || r6 == "tunnel":
		return "tunnel", sevSkip
	case !v4.HasRoute && !v6.HasRoute:
		return "not-asked", sevSkip
	}
	return "no-gateway", sevOK // 有路由但没有下一跳（点对点链路），正常
}

func gwFacts(f familyResult, lan lanResult) map[string]any {
	code := lan.Code
	if code == "" {
		code = lan.Reason
		if code == "" {
			code = "not-asked"
		}
	}
	m := map[string]any{"gateway": f.Gateway, "code": code}
	if lan.Stats.Sent > 0 {
		m["sent"] = lan.Stats.Sent
		m["lossPercent"] = lan.Stats.LossPercent
		m["rttMedianMs"] = lan.Stats.Median
		m["jitterAvgMs"] = lan.Stats.Jitter
		m["unreachable"] = lan.Stats.Unreachable
	}
	return m
}

// worstGW 两族合一个判定码。★ 优先级按「能不能拿后面的测量当数」排：
//
//	丢包和不可达会让 DNS/出口的数全失真（bad），不吭声只是问不到（warn）。
func worstGW(c4, c6 string, v4, v6 familyResult) (string, string) {
	if !v4.HasRoute && !v6.HasRoute {
		return "not-asked", sevSkip // 没有默认路由，没得问
	}
	rank := map[string]int{
		watchLoss: 5, watchNoRoute: 5, watchUnreachable: 4,
		watchJitter: 3, watchNoReply: 2, watchStable: 1,
		"": 0, "skipped": 0, "no-gateway": 0,
	}
	sev := map[string]string{
		watchLoss: sevBad, watchNoRoute: sevBad, watchUnreachable: sevBad,
		watchJitter: sevWarn, watchNoReply: sevWarn, watchStable: sevOK,
	}
	best, bestRank := watchStable, 0
	asked := false
	for _, c := range []string{c4, c6} {
		if rank[c] == 0 {
			continue
		}
		asked = true
		if rank[c] > bestRank {
			best, bestRank = c, rank[c]
		}
	}
	if !asked {
		return "no-gateway", sevOK // 有路由但都是点对点链路（没有下一跳），正常
	}
	if best == watchStable {
		return "ok", sevOK
	}
	return best, sev[best]
}

// dnsItem 系统有没有配 DNS、配了问得出名字吗。
//
// ★ 这一项只判「问不问得出」，不判「域名有几条记录」：一个域名本来就可以只有 A 没有 AAAA，
//
//	把「另一族没记录」报成 DNS 坏了，会让人去重启一个没坏的解析器。所以只有
//	**A 一条都没有、AAAA 却有** 这种「v4 问空了」的情形才值得看一眼。
func dnsItem(servers []netif.DNSServer, dom domainResult) checkItem {
	facts := map[string]any{
		"servers": servers, "domain": dom.Name,
		"v4": dom.A, "v6": dom.AAAA, "lookupMs": dom.LookupMs,
	}
	if dom.Err != "" {
		facts["error"] = dom.Err
	}
	switch {
	case len(servers) == 0:
		return checkItem{Step: stepDNS, Code: "no-server", Severity: sevBad, Facts: facts}
	case dom.Err != "":
		return checkItem{Step: stepDNS, Code: "error", Severity: sevBad, Facts: facts}
	case len(dom.A) == 0 && len(dom.AAAA) == 0:
		return checkItem{Step: stepDNS, Code: "no-record", Severity: sevBad, Facts: facts}
	case len(dom.A) == 0:
		return checkItem{Step: stepDNS, Code: "no-v4-record", Severity: sevWarn, Facts: facts}
	}
	return checkItem{Step: stepDNS, Code: "ok", Severity: sevOK, Facts: facts}
}

// egressItem 出不出得去。★ 以「TCP 真连上了 443」为准，不看 ICMP：
// 现场一堆设备拦 ping 却照常出网，拿 ping 判会把能上网判成不能。
func egressItem(v4, v6 familyResult) checkItem {
	facts := map[string]any{
		"ipv4": egressFacts(v4), "ipv6": egressFacts(v6),
	}
	egressOK := v4.egressOK() || v6.egressOK()
	switch {
	case !v4.present() && !v6.present():
		return checkItem{Step: stepEgress, Code: "not-asked", Severity: sevSkip, Facts: facts}
	case v4.egressOK() && v6.egressOK():
		return checkItem{Step: stepEgress, Code: "ok", Severity: sevOK, Facts: facts}
	case egressOK && !v6.present():
		// 这一族本来就不在场，谈不上坏（纯 v4 内网天天如此）
		return checkItem{Step: stepEgress, Code: "ok", Severity: sevOK, Facts: facts}
	case egressOK && v6.present():
		// ★ 有 v6 地址/路由却只有 v4 出得去 —— 「网很慢」的真身：
		//   应用先试 v6，等一次超时才回落。它不拦你的网，但会让每一次连接都慢半拍。
		return checkItem{Step: stepEgress, Code: "v6-egress-broken", Severity: sevWarn, Facts: facts}
	case egressOK && v4.present():
		return checkItem{Step: stepEgress, Code: "v4-egress-broken", Severity: sevWarn, Facts: facts}
	}
	return checkItem{Step: stepEgress, Code: "broken", Severity: sevBad, Facts: facts}
}

func egressFacts(f familyResult) map[string]any {
	return map[string]any{
		"present": f.present(), "egress": f.Egress,
		"target": f.EgressTarget, "rttMs": f.EgressRTTMs,
	}
}

// mtuItem 出口网卡这层的 MTU。★ 只判**物理口**：
// 隧道和 VPN 的 1400/1280 是本来就该那样，报成「偏小」会让人去改一个不该改的东西。
func mtuItem(nics []netif.NIC, egressIface string) checkItem {
	var (
		facts   = map[string]any{}
		nicList []map[string]any
		eg      int
		egKind  string
		egVirt  bool
	)
	for _, n := range nics {
		if n.Loop || n.MTU == 0 {
			continue
		}
		nicList = append(nicList, map[string]any{
			"iface": n.Name, "mtu": n.MTU, "kind": n.Kind, "virtual": n.Virtual,
		})
		if egressIface != "" && n.Name == egressIface {
			eg, egKind, egVirt = n.MTU, n.Kind, n.Virtual
		}
	}
	facts["egressIface"] = egressIface
	facts["egressMtu"] = eg
	facts["egressKind"] = egKind
	facts["nics"] = nicList
	switch {
	case eg == 0:
		return checkItem{Step: stepMTU, Code: "unknown", Severity: sevSkip, Facts: facts}
	case egVirt:
		return checkItem{Step: stepMTU, Code: "tunnel", Severity: sevOK, Facts: facts}
	case eg < 1500:
		return checkItem{Step: stepMTU, Code: "small", Severity: sevWarn, Facts: facts}
	}
	return checkItem{Step: stepMTU, Code: "ok", Severity: sevOK, Facts: facts}
}

// egressIfaceName 默认路由走的那块网卡（v4 优先，没有再看 v6）。
func egressIfaceName(nics []netif.NIC, routes []netif.DefaultRoute) string {
	for _, want := range []string{"ipv4", "ipv6"} {
		for _, r := range routes {
			if r.Family == want && r.Iface != "" {
				return r.Iface
			}
		}
	}
	return ""
}

// clockItem 本机时钟。★ 只看偏差量级：体检里问不到「谁不对」（那要多个源互相印证，
// 是 net.time.check 的活），所以偏差大到会出事才报 bad，一个数都不给的情况只报 skip。
//
// 阈值和 net.time.check 共用同一份常量（timeOKMs / timeBigMs）—— 两个工具对
// 「差多少算事」给出两个答案，人不知道信哪个。
func clockItem(src timeSource) checkItem {
	facts := map[string]any{
		"server": src.Server, "code": src.Code, "offsetMs": src.OffsetMs,
		"rttMs": src.RTTMs, "serverTime": src.ServerTime, "localTime": src.LocalTime,
		"answers": src.Answers, "samples": src.Samples,
	}
	switch src.Code {
	case timeAnswered, timeOK, timeSkewed, timeWayOff:
		// ★ askSource 只回答「问到了没有」，偏多少才算事得这里按量级分档。
		switch off := math.Abs(src.OffsetMs); {
		case off <= timeOKMs:
			return checkItem{Step: stepClock, Code: "ok", Severity: sevOK, Facts: facts}
		case off <= timeBigMs:
			return checkItem{Step: stepClock, Code: "skew", Severity: sevWarn, Facts: facts}
		}
		return checkItem{Step: stepClock, Code: "big-skew", Severity: sevBad, Facts: facts}
	case timeKissed:
		// 服务器回了 STEP —— 明说「你的钟偏得太离谱，我不带你了」，和量级超大是同一件事。
		return checkItem{Step: stepClock, Code: "big-skew", Severity: sevBad, Facts: facts}
	}
	// 问不到（没回、格式不对、几个源互相矛盾、连域名都解析不了）：这一项只能说「没判成」。
	// ★ 不许报成 bad —— 内网封 UDP/123 是常态，那样会让人去查一个没坏的时钟。
	return checkItem{Step: stepClock, Code: "not-asked", Severity: sevSkip, Facts: facts}
}

// ── 系统代理 ──

// proxyVars 会读到代理的环境变量名。★ 大小写两种都要看：
// 很多工具只认小写，而人习惯设大写，于是出现「命令行有代理、图形界面没有」。
var proxyVars = []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"}

// systemProxy 读这台机器的代理设置。返回判定码 + 事实（只含 host:port）。
//
// ★ 凭据不进结果：代理地址常见形如 http://user:pass@proxy:8080，
//
//	而体检结果会原样发给 AI、也会进诊断包。这里只留 host:port，
//	解析不出来的也一律切掉 @ 前面那段，不许退化成「原样抄进去」。
func systemProxy(ctx context.Context) (string, map[string]any) {
	facts := map[string]any{}
	var set []string
	for _, k := range proxyVars {
		v := os.Getenv(k)
		if strings.TrimSpace(v) == "" {
			continue
		}
		set = append(set, k+"="+hostOnly(v))
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.CommandContext(ctx, "scutil", "--proxy").Output(); err == nil {
			for _, l := range proxyFromScutil(string(out)) {
				set = append(set, l)
			}
		} else {
			facts["scutilError"] = err.Error()
		}
	}
	facts["entries"] = set
	if len(set) > 0 {
		return "set", facts
	}
	if runtime.GOOS != "darwin" && len(envProxyNames()) == 0 {
		// ★ Windows / Linux 上这一项没有可靠的统一读法（注册表 / 桌面环境各家不同），
		//   读不到就说读不到，不许当成「没设代理」——那会把一个开着代理的机器判成干净。
		return "unsupported", facts
	}
	return "none", facts
}

func envProxyNames() []string {
	var out []string
	for _, k := range proxyVars {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			out = append(out, k)
		}
	}
	return out
}

// hostOnly 把代理地址收成 host[:port]，顺手把用户名密码丢掉。
func hostOnly(v string) string {
	s := strings.TrimSpace(v)
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Host
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(s, "//")
	if i := strings.IndexAny(s, "/\\"); i >= 0 {
		s = s[:i]
	}
	return s
}

// proxyFromScutil 从 `scutil --proxy` 的输出里挑出开着的代理，给 host:port。
func proxyFromScutil(out string) []string {
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, " : ")
		if i < 0 {
			continue
		}
		vals[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+3:])
	}
	var out2 []string
	for _, pair := range []struct{ on, host, port, label string }{
		{"HTTPEnable", "HTTPProxy", "HTTPPort", "http"},
		{"HTTPSEnable", "HTTPSProxy", "HTTPSPort", "https"},
		{"SOCKSEnable", "SOCKSProxy", "SOCKSPort", "socks"},
	} {
		if vals[pair.on] != "1" || vals[pair.host] == "" {
			continue
		}
		s := pair.label + "://" + vals[pair.host]
		if vals[pair.port] != "" && vals[pair.port] != "0" {
			s += ":" + vals[pair.port]
		}
		out2 = append(out2, pair.label+"="+hostOnly(s))
	}
	return out2
}

func proxySeverity(code string) string {
	switch code {
	case "set":
		return sevWarn
	case "unsupported":
		return sevSkip
	}
	return sevOK
}

// ── 顶层判定 ──

// rollup 挑第一个坏掉的步骤。★ 这一步是整个工具的存在理由：
// 八行结果谁都会列，「先修哪一个」才省时间。
// 返回 (顶层码, 第一个坏掉的步骤名)。
func rollup(items []checkItem) (string, string) {
	var firstBad, firstWarn string
	for _, it := range items {
		switch it.Severity {
		case sevBad:
			if firstBad == "" {
				firstBad = it.Step
			}
		case sevWarn:
			if firstWarn == "" {
				firstWarn = it.Step
			}
		}
	}
	if firstBad != "" {
		return brokenAt(firstBad), firstBad
	}
	if firstWarn != "" {
		return topDegraded, firstWarn
	}
	return topAllGood, ""
}

// brokenAt 把步骤名翻成顶层码。★ 顺序就是 items 的顺序，这里只做翻译。
// mtu / proxy 这两步只出 warn（见上面的判定），所以没有对应的 broken-at 码；
// 真出现了说明判定写错了，宁可回落到 degraded 也不要编一个不存在的码。
func brokenAt(step string) string {
	switch step {
	case stepIface:
		return topBrokenIface
	case stepRoute:
		return topBrokenRoute
	case stepGateway:
		return topBrokenGateway
	case stepDNS:
		return topBrokenDNS
	case stepEgress:
		return topBrokenEgress
	case stepClock:
		return topBrokenClock
	}
	return topDegraded
}

// checkupNote 给 CLI 和日志看的一句话。★ 点名第一项要动手的，而不是复述八行。
func checkupNote(top string, items []checkItem) string {
	byStep := map[string]checkItem{}
	for _, it := range items {
		byStep[it.Step] = it
	}
	switch top {
	case topAllGood:
		return "八项都过：本机有地址、有路由、到网关不丢、解析得出、出得去外网、时钟对得上。" +
			"★ 这只说明「这台到公网这一段」没问题，设备之间通不通要另问那两台。"
	case topDegraded:
		w := []string{}
		for _, it := range items {
			if it.Severity == sevWarn {
				w = append(w, it.Step+"="+it.Code)
			}
		}
		return "没有硬故障，但有几项值得看一眼：" + strings.Join(w, "、") +
			"。★ 这些不会让网断，却常常就是「慢」和「偶尔一下」的来源。"
	}
	step := strings.TrimPrefix(top, "broken-at-")
	it := byStep[step]
	return "第一个坏掉的是 " + step + "（" + it.Code + "）：后面的项是在它不修好的情况下测的，" +
		"数字都别当准。"
}
