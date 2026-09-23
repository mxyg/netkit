package tools

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// net.dualstack.check —— 双栈体检（docs/设计.md「IPv6 支持 · 三、★ 双栈排障」点名要做的招牌功能）。
//
// ★★ 它替人做的是这一串只有老手才会的判断：
//
//	现场最难查的 v6 问题不是「v6 不通」，而是——v6 看着是通的（有地址、有默认路由），
//	却出不了外网；应用又优先走 v6，于是每次连接先卡几秒超时再回落 v4，
//	表现成「网很慢」而不是「网不通」。
//
// 四步（和设计里写的一一对应）：
//  1. v4 / v6 各自：有没有地址、有没有默认路由、网关通不通、出口通不通、DNS 通不通
//  2. 目标域名解析出的 A 和 AAAA 分别能不能连、各自耗时多少
//  3. 按 Happy Eyeballs（RFC 8305）模拟应用实际会怎么选，**指出会不会卡**
//  4. 顶层给一个判定码 —— 后端只给码，人话由界面按语言渲染
//
// ★ 全程只是**发流量去观察**，不改任何东西，所以是 read（[OTS-4.3]）。
var dualStackTool = ots.Tool{
	Name:  "net.dualstack.check",
	Class: ots.ClassRead,
	Summary: "双栈体检：分别测 IPv4 与 IPv6 有没有地址、有没有默认路由、网关通不通、能不能出外网、DNS 能不能解析；" +
		"再对目标域名的 A 和 AAAA 各连一次比耗时，最后按 Happy Eyeballs(RFC8305) 模拟应用会怎么选、会不会卡。" +
		"★ 专治「v6 有地址却出不了外网，导致每次连接先卡几秒再回落 v4」这类现场最难查的问题。" +
		"结论 v4/v6 分开给，不合成一句「网络正常」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "domain":      {"type": "string", "description": "用来测解析与连接的域名，默认 www.cloudflare.com"},
	    "port":        {"type": "integer", "minimum": 1, "maximum": 65535, "description": "连域名时用的端口，默认 443"},
	    "egressV4":    {"type": "string", "description": "测 v4 出口的 host:port，默认 1.1.1.1:443"},
	    "egressV6":    {"type": "string", "description": "测 v6 出口的 [addr]:port，默认 [2606:4700:4700::1111]:443"},
	    "timeoutMs":   {"type": "integer", "minimum": 200, "maximum": 20000, "description": "每一步的超时，默认 2500"}
	  }
	}`),
	Invoke: doDualStack,
}

// 顶层判定码。★ 后端只给这些码，人话由界面渲染（多语种就靠这条）。
const (
	dsNoAddress        = "no-address"         // 两族都没有可用地址、也没有默认路由
	dsDualHealthy      = "dual-healthy"       // 两族都能出外网
	dsV6EgressBroken   = "v6-egress-broken"   // ★ 招牌场景：v4 正常、v6 有路却出不了外网
	dsV4EgressBroken   = "v4-egress-broken"   // v6 正常、v4 出不了外网
	dsBothEgressBroken = "both-egress-broken" // 两族都有地址/路由但都出不了外网（多半纯内网或上游全断）
	dsV4Only           = "v4-only"            // 只有 v4，且能出外网
	dsV6Only           = "v6-only"            // 只有 v6，且能出外网
	dsSingleNoEgress   = "single-no-egress"   // 只有一族在线，但出不了外网
	dsEyeballsOK       = "eyeballs-ok"        // 应用不会卡
	dsEyeballsStall    = "eyeballs-stall"     // ★ 应用会先卡在 v6 上再回落 —— 这就是「网很慢」的真身
	dsEyeballsSingle   = "eyeballs-single"    // 只有一族可连，没得选，不存在卡
	dsEyeballsFail     = "eyeballs-fail"      // 两族都连不上这个域名
)

// 各族子项的判定码（复用 net.go/ping.go 的 open/closed/filtered/reachable/no-reply，
// 这里只补这一页特有的几种）。
const (
	egressNoRoute = "no-route"   // 没有默认路由 = 出不了本网，不必白等一个连接超时
	egressError   = "error"      // 探测本身出错
	egressSkipped = "skipped"    // 这一族不在场，没测
	egressPending = "pending"    // 解析出来了但还没轮到连（内部用，最终会被改写）
	gwNoGateway   = "no-gateway" // 有默认路由但没有下一跳（点对点链路，正常）
	dnsOK         = "ok"
	dnsNoRecord   = "no-record"
	dnsError      = "error"
)

type dualStackArgs struct {
	Domain    string `json:"domain"`
	Port      int    `json:"port"`
	EgressV4  string `json:"egressV4"`
	EgressV6  string `json:"egressV6"`
	TimeoutMS int    `json:"timeoutMs"`
}

// familyResult 一个地址族的体检结果。
type familyResult struct {
	Family       string   `json:"family"`
	HasAddress   bool     `json:"hasAddress"`
	Addresses    []string `json:"addresses"`
	HasRoute     bool     `json:"hasRoute"`
	Gateway      string   `json:"gateway,omitempty"`
	RouteIface   string   `json:"routeIface,omitempty"`
	RouteCount   int      `json:"routeCount"`
	GwReachable  string   `json:"gwReachable"` // reachable / no-reply / unreachable / no-gateway / skipped
	GwRTTMs      float64  `json:"gwRttMs,omitempty"`
	Egress       string   `json:"egress"` // open / closed / filtered / no-route / error / skipped
	EgressRTTMs  int64    `json:"egressRttMs,omitempty"`
	EgressTarget string   `json:"egressTarget,omitempty"`
	DNS          string   `json:"dns"` // ok / no-record / error / skipped
	DNSRTTMs     int64    `json:"dnsRttMs,omitempty"`
}

// egressOK 出口通不通，以「TCP 真连上了」为准 —— 这正是应用眼里的「能不能上网」。
func (f familyResult) egressOK() bool { return f.Egress == verdictOpen }

// present 这一族在不在场：有可用地址或有默认路由，任一即算。
//
// ★ 为什么地址和路由分开看：VPN 场景下 v6 可能只在 utun 上有路由、物理网卡没有全局 v6，
//
//	只认「有地址」会漏判。所以任一在场就把这族纳入体检，最终通不通交给出口探测说了算。
func (f familyResult) present() bool { return f.HasAddress || f.HasRoute }

type addrAttempt struct {
	Addr  string `json:"addr"`
	Code  string `json:"code"` // open / closed / filtered / error
	RTTMs int64  `json:"rttMs,omitempty"`
}

type domainResult struct {
	Name     string        `json:"name"`
	Port     int           `json:"port"`
	LookupMs int64         `json:"lookupMs"`
	A        []addrAttempt `json:"a"`
	AAAA     []addrAttempt `json:"aaaa"`
	Err      string        `json:"err,omitempty"`
}

type eyeballsResult struct {
	Code        string `json:"code"` // eyeballs-ok / eyeballs-stall / eyeballs-single / eyeballs-fail
	Preferred   string `json:"preferred,omitempty"`
	Winner      string `json:"winner,omitempty"`
	WillStall   bool   `json:"willStall"`
	StallMs     int64  `json:"stallMs,omitempty"` // 守 HE 的应用大约会卡这么久
	WorstMs     int64  `json:"worstMs,omitempty"` // 不守 HE（串行先试 v6 到超时）最坏会卡这么久
	ConnDelayMs int64  `json:"connDelayMs"`       // RFC 8305 的 Connection Attempt Delay
}

func doDualStack(ctx context.Context, raw json.RawMessage) (any, error) {
	var a dualStackArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Domain == "" {
		a.Domain = "www.cloudflare.com"
	}
	if a.Port == 0 {
		a.Port = 443
	}
	if a.EgressV4 == "" {
		a.EgressV4 = "1.1.1.1:443"
	}
	if a.EgressV6 == "" {
		a.EgressV6 = "[2606:4700:4700::1111]:443"
	}
	timeout := 2500 * time.Millisecond
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}

	// 先静态盘点：每族的地址、默认路由（不发流量）
	nics, err := netif.Interfaces()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "读网卡失败：%s", err)
	}
	routes, _ := netif.DefaultRoutes() // 读不到不致命，体检会如实说「没有默认路由」

	v4 := familyResult{Family: "ipv4", Addresses: []string{}, DNS: egressSkipped, Egress: egressSkipped, GwReachable: egressSkipped}
	v6 := familyResult{Family: "ipv6", Addresses: []string{}, DNS: egressSkipped, Egress: egressSkipped, GwReachable: egressSkipped}
	fillFamilyStatic(nics, routes, &v4, &v6)

	// 域名解析（A / AAAA 分开），后面的连接与 HE 模拟都基于它
	dom := resolveDomain(ctx, a.Domain, a.Port, timeout)

	// 并发跑所有发流量的探测：网关 ping、出口 TCP、域名 TCP
	ctxAll, cancel := context.WithTimeout(ctx, timeout*3)
	defer cancel()
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { defer wg.Done(); probeGateway(ctxAll, &v4, timeout) }()
	wg.Add(1)
	go func() { defer wg.Done(); probeGateway(ctxAll, &v6, timeout) }()
	wg.Add(1)
	go func() { defer wg.Done(); probeEgress(ctxAll, &v4, a.EgressV4, timeout) }()
	wg.Add(1)
	go func() { defer wg.Done(); probeEgress(ctxAll, &v6, a.EgressV6, timeout) }()
	wg.Add(1)
	go func() { defer wg.Done(); connectDomain(ctxAll, &dom, timeout) }()
	wg.Wait()

	// DNS 通不通：以解析结果为准，分别记到两族头上
	markDNS(&v4, &v6, dom)

	// ★ 域名的连接结果反过来修出口判定，再定顶层码
	reconcileEgress(&v4, &v6, dom)

	eb := eyeballs(dom, 250) // RFC 8305 默认 Connection Attempt Delay 250ms
	code := topCode(v4, v6)

	values := map[string]any{
		"v4": v4, "v6": v6, "domain": dom, "eyeballs": eb,
	}
	return ots.Verdict{Code: code, Values: values,
		Note: noteZH(code, v4, v6, eb)}, nil
}

// fillFamilyStatic 把地址和默认路由填进两族结果（不发流量）。
func fillFamilyStatic(nics []netif.NIC, routes []netif.DefaultRoute, v4, v6 *familyResult) {
	for _, n := range nics {
		if n.Loop {
			continue
		}
		for _, ad := range n.Addrs {
			switch {
			case ad.Is4():
				if s := usableScope(ad); s {
					v4.HasAddress = true
					v4.Addresses = append(v4.Addresses, ad.CIDR())
				}
			case ad.Is6():
				// v6：全局/ULA 才算「能出本网」；链路本地单独不当 HasAddress，
				// 但只要有链路本地也说明这族在设备上活着，present() 还会看路由。
				if ad.Scope() == netaddr.ScopeGlobal || ad.Scope() == netaddr.ScopePrivate {
					v6.HasAddress = true
					v6.Addresses = append(v6.Addresses, ad.CIDR())
				}
			}
		}
	}
	for _, r := range routes {
		switch r.Family {
		case "ipv4":
			v4.RouteCount++
			if !v4.HasRoute {
				v4.HasRoute, v4.Gateway, v4.RouteIface = true, r.Gateway, r.Iface
			}
		case "ipv6":
			v6.RouteCount++
			if !v6.HasRoute {
				v6.HasRoute, v6.Gateway, v6.RouteIface = true, r.Gateway, r.Iface
			}
		}
	}
}

func usableScope(ad netaddr.Addr) bool {
	s := ad.Scope()
	return s == netaddr.ScopePrivate || s == netaddr.ScopeGlobal
}

// resolveDomain 把域名的 A 和 AAAA 分别查出来（还没连）。
func resolveDomain(ctx context.Context, domain string, port int, timeout time.Duration) domainResult {
	d := domainResult{Name: domain, Port: port, A: []addrAttempt{}, AAAA: []addrAttempt{}}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	var a4, a6 []netip.Addr
	var e4, e6 error
	wg.Add(2)
	go func() { defer wg.Done(); a4, e4 = net.DefaultResolver.LookupNetIP(c, "ip4", domain) }()
	go func() { defer wg.Done(); a6, e6 = net.DefaultResolver.LookupNetIP(c, "ip6", domain) }()
	wg.Wait()
	d.LookupMs = time.Since(start).Milliseconds()
	for _, ip := range a4 {
		d.A = append(d.A, addrAttempt{Addr: ip.String(), Code: egressPending})
	}
	for _, ip := range a6 {
		d.AAAA = append(d.AAAA, addrAttempt{Addr: ip.String(), Code: egressPending})
	}
	// 两族都查不出来才算解析失败；一族没有记录是正常信息（很多域名只有 A）
	if e4 != nil && e6 != nil {
		d.Err = e4.Error()
	}
	return d
}

// connectDomain 对解析出来的 A / AAAA 各连一次（每族最多 2 个地址），记耗时。
func connectDomain(ctx context.Context, d *domainResult, timeout time.Duration) {
	if d.Err != "" {
		for i := range d.A {
			d.A[i].Code = egressError
		}
		for i := range d.AAAA {
			d.AAAA[i].Code = egressError
		}
		return
	}
	dial := func(list []addrAttempt) {
		n := len(list)
		if n > 2 {
			n = 2
		}
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				target := net.JoinHostPort(list[i].Addr, itoa(d.Port))
				code, rtt := dialTCP(ctx, target, timeout)
				list[i].Code, list[i].RTTMs = code, rtt
			}(i)
		}
		wg.Wait()
		// 没连的（超过 2 个的部分）标 skipped，不留 pending
		for i := n; i < len(list); i++ {
			list[i].Code = egressSkipped
		}
	}
	dial(d.A)
	dial(d.AAAA)
}

// dialTCP 连一个 host:port，给出判定码和耗时。
func dialTCP(ctx context.Context, target string, timeout time.Duration) (string, int64) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(c, "tcp", target)
	rtt := time.Since(start).Milliseconds()
	if err == nil {
		conn.Close()
		return verdictOpen, rtt
	}
	switch classify(err) {
	case verdictClosed:
		return verdictClosed, rtt
	case verdictFiltered:
		return verdictFiltered, rtt
	}
	return egressError, rtt
}

// probeEgress 测「出得了外网吗」：往一个公网上一定开着的 TCP 端口连一下。
//
// ★ 用 TCP 不用 ICMP：很多网络禁 ICMP，ping 不通不代表上不了网；
//
//	而 TCP 连上 443 才是应用眼里的「能上网」。
func probeEgress(ctx context.Context, f *familyResult, target string, timeout time.Duration) {
	if !f.present() {
		f.Egress = egressSkipped
		return
	}
	if !f.HasRoute {
		// 没有默认路由 = 出不了本网，直接判定，不必白等一个超时
		f.Egress, f.EgressTarget = egressNoRoute, target
		return
	}
	f.EgressTarget = target
	code, rtt := dialTCP(ctx, target, timeout)
	f.Egress, f.EgressRTTMs = code, rtt
}

// probeGateway ping 一下默认路由的网关（信息项，通不通都不致命）。
func probeGateway(ctx context.Context, f *familyResult, timeout time.Duration) {
	if f.Gateway == "" {
		if f.HasRoute {
			f.GwReachable = gwNoGateway // 有默认路由但没下一跳（点对点链路，正常）
		}
		return
	}
	addr, err := netaddr.Parse(f.Gateway)
	if err != nil {
		f.GwReachable = egressSkipped
		return
	}
	conn, err := listenICMP(addr)
	if err != nil {
		f.GwReachable = egressSkipped // 多半是没权限发 ICMP，不当致命
		return
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IP(addr.IP.AsSlice())}
	if addr.NeedsZone() {
		dst.Zone = addr.Zone
		if dst.Zone == "" {
			dst.Zone = itoa(addr.ZoneID)
		}
	}
	rtt, kind, perr := pingOnce(conn, addr, dst, 0x4e45, 1, timeout)
	if perr != nil && kind == "" {
		kind = egressSkipped // 发都发不出去（路由都没有），不硬给一个 no-reply
	}
	f.GwReachable = kind
	if kind == verdictReachable {
		f.GwRTTMs = ms(rtt)
	}
}

// markDNS 把域名解析结果落到两族的 dns 字段。
func markDNS(v4, v6 *familyResult, d domainResult) {
	if d.Err != "" {
		if v4.present() {
			v4.DNS = dnsError
		}
		if v6.present() {
			v6.DNS = dnsError
		}
		return
	}
	if v4.present() {
		v4.DNS, v4.DNSRTTMs = dnsNoRecord, d.LookupMs
		if len(d.A) > 0 {
			v4.DNS = dnsOK
		}
	}
	if v6.present() {
		v6.DNS, v6.DNSRTTMs = dnsNoRecord, d.LookupMs
		if len(d.AAAA) > 0 {
			v6.DNS = dnsOK
		}
	}
}

// reconcileEgress 用域名连接的实测证据修出口判定。★ 纯函数，方便钉测试。
//
// ★★ 为什么这一步不能省：出口探测只能挑一个固定地址，而固定地址完全可能被这个网络
//
//	单独拦掉（不少企业网直接丢 1.1.1.1 的包）。只认那一次失败就说「出不了外网」，
//	会把「v6 坏了、v4 好好的」这个招牌场景误判成「两族都坏」—— 现场最要命的一类误诊。
//	而域名解析出来的地址**真连上了**，就是这一族能出外网的直接证据：证据优先于探测点。
func reconcileEgress(v4, v6 *familyResult, d domainResult) {
	promoteEgress(v4, d.A, d.Port)
	promoteEgress(v6, d.AAAA, d.Port)
}

func promoteEgress(f *familyResult, list []addrAttempt, port int) {
	if f.egressOK() || !f.present() {
		return
	}
	best := -1
	for i, at := range list {
		if at.Code != verdictOpen {
			continue
		}
		if best < 0 || at.RTTMs < list[best].RTTMs {
			best = i
		}
	}
	if best < 0 {
		return
	}
	f.Egress, f.EgressRTTMs = verdictOpen, list[best].RTTMs
	f.EgressTarget = net.JoinHostPort(list[best].Addr, itoa(port))
}

// topCode 选顶层判定码。★ 纯函数，方便逐条钉测试。
func topCode(v4, v6 familyResult) string {
	if !v4.present() && !v6.present() {
		return dsNoAddress
	}
	switch {
	case v4.present() && v6.present():
		switch {
		case v4.egressOK() && v6.egressOK():
			return dsDualHealthy
		case v4.egressOK() && !v6.egressOK():
			return dsV6EgressBroken // ★ 招牌场景
		case !v4.egressOK() && v6.egressOK():
			return dsV4EgressBroken
		default:
			return dsBothEgressBroken
		}
	case v4.present():
		if v4.egressOK() {
			return dsV4Only
		}
		return dsSingleNoEgress
	default:
		if v6.egressOK() {
			return dsV6Only
		}
		return dsSingleNoEgress
	}
}

// eyeballs 按 RFC 8305 模拟应用怎么选，指出会不会卡。★ 纯函数，方便钉测试。
//
// 简化的 HE：应用优先 v6，先连 v6；若 connDelayMs 内 v6 没连上，就并行开始连 v4，谁先连上用谁。
// 「卡」发生在 v6 连不上（尤其被静默丢包）而 v4 能连时：
//   - 守 HE 的应用：大约卡 connDelayMs + v4 连接耗时
//   - 不守 HE（串行先把 v6 试到超时）的应用：最坏卡到 v6 超时
func eyeballs(d domainResult, connDelayMs int64) eyeballsResult {
	res := eyeballsResult{ConnDelayMs: connDelayMs}
	best := func(list []addrAttempt) (ok bool, rtt int64, worst int64) {
		worst = 0
		for _, at := range list {
			if at.Code == egressPending || at.Code == egressSkipped {
				continue
			}
			if at.RTTMs > worst {
				worst = at.RTTMs
			}
			if at.Code == verdictOpen && (!ok || at.RTTMs < rtt) {
				ok, rtt = true, at.RTTMs
			}
		}
		return
	}
	a4ok, a4rtt, _ := best(d.A)
	a6ok, a6rtt, a6worst := best(d.AAAA)
	hasA, hasAAAA := len(d.A) > 0, len(d.AAAA) > 0

	switch {
	case !hasA && !hasAAAA:
		res.Code = dsEyeballsFail
	case hasA && hasAAAA:
		switch {
		case a6ok && a6rtt <= connDelayMs:
			// v6 又快又通，应用直接用 v6，不卡
			res.Code, res.Preferred, res.Winner = dsEyeballsOK, "ipv6", "ipv6"
		case a6ok && a4ok:
			// v6 通但比 connDelay 慢：HE 会并行起 v4，谁快用谁
			res.Preferred = "ipv6"
			if a6rtt <= connDelayMs+a4rtt {
				res.Winner, res.Code = "ipv6", dsEyeballsOK
			} else {
				res.Winner, res.Code = "ipv4", dsEyeballsOK
			}
		case !a6ok && a4ok:
			// ★ 招牌场景：v6 连不上、v4 能连 —— 应用会先在 v6 上耗一下再回落 v4
			res.Code, res.Preferred, res.Winner = dsEyeballsStall, "ipv6", "ipv4"
			res.WillStall = true
			res.StallMs = connDelayMs + a4rtt
			res.WorstMs = a6worst
			if res.WorstMs < res.StallMs {
				res.WorstMs = res.StallMs
			}
		default:
			res.Code = dsEyeballsFail // 两族都连不上这个域名
		}
	case hasAAAA: // 只有 v6 记录
		res.Preferred, res.Winner = "ipv6", "ipv6"
		if a6ok {
			res.Code = dsEyeballsSingle
		} else {
			res.Code, res.WillStall, res.WorstMs = dsEyeballsFail, true, a6worst
		}
	default: // 只有 v4 记录
		res.Preferred, res.Winner = "ipv4", "ipv4"
		if a4ok {
			res.Code = dsEyeballsSingle
		} else {
			res.Code = dsEyeballsFail
		}
	}
	return res
}

// noteZH 给命令行 / 日志 / MCP 看的中文附加说明 [OTS-5.4]。
// 界面**不依赖**它（界面按 code 渲染），所以这里写句子不违反「后端只给码」。
func noteZH(code string, v4, v6 familyResult, eb eyeballsResult) string {
	base := map[string]string{
		dsNoAddress:        "两个地址族都没拿到可用地址，也没有默认路由 —— 这台机器现在基本没网。",
		dsDualHealthy:      "IPv4 和 IPv6 都能出外网，双栈正常。",
		dsV6EgressBroken:   "IPv4 正常，但 IPv6 有地址/路由却出不了外网 —— 应用优先走 v6 时会先卡再回落，表现成「网很慢」。建议修上游 v6 或临时关掉 v6。",
		dsV4EgressBroken:   "IPv6 正常，但 IPv4 出不了外网。",
		dsBothEgressBroken: "两族都有地址，但都出不了外网 —— 多半是纯内网，或上游整个断了。",
		dsV4Only:           "只有 IPv4，能正常出外网（这台机器没启用 IPv6，或 v6 没拿到地址）。",
		dsV6Only:           "只有 IPv6，能正常出外网。",
		dsSingleNoEgress:   "只有一族在线，而且出不了外网。",
	}[code]
	if eb.Code == dsEyeballsStall {
		base += "（已确认：访问该域名时应用会先在 IPv6 上卡一下再回落到 IPv4。）"
	}
	return base
}
