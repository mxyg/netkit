package netif

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Route 路由表里的**一条**。
//
// ★ 和 DefaultRoute 的区别要说清：那一型只回答「出不了本网时往哪走」，
//
//	这一型是**整张表**。现场真正要问的是「去往这个地址会从哪块网卡出去」，
//	而多网卡工控机上答案常常**不是**默认路由那条 —— 目标就在某块网卡直连的
//	网段里时，走的是那条 /24。只有全表在手，才可能做最长前缀匹配。
type Route struct {
	Family string `json:"family"` // ipv4 / ipv6
	// Destination 一律归一成 CIDR。各平台原样差很多（macOS 把 v4 网段的主机位省掉、
	// Linux 写 default、Windows 写 0.0.0.0/0），不在这一层归一，上层就得各写一遍。
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Iface       string `json:"iface,omitempty"`
	// Metric 越小越优先。★ 各平台给不给这一栏差别很大：Linux 给；macOS 的 netstat 不给；
	// Windows 给的是 RouteMetric，还差一个没读到的 InterfaceMetric（那里已经拼上了）。
	// 读不到就是 0，SelectRoute 只在两边都有值时才比它，不假装比过。
	Metric int `json:"metric"`
	// Direct 这条不经过网关，是本网段直连的路。界面用它把「本段的路」和「往外的路」分开。
	Direct bool `json:"direct"`
	// Src 表里就带源地址的才填（Linux 的直连路由会带）。
	Src string `json:"src,omitempty"`
}

// Routes 本机路由表（v4 + v6）。
func Routes() ([]Route, error) { return routes() }

// RouteFor 问**系统自己**：去往这个地址会走哪条。
//
// ★★ 为什么不自己按表算就算了：算出来的答案在某些机器上会**合法地错** ——
//
//	Linux 常有策略路由（ip rule 给每块 DHCP 网卡挂一张自己的表），
//	只看主表做最长前缀匹配就会挑到一条系统根本不会用的路由。
//	所以这一栏才是权威答案，自己算的那份留着对拍，两者不一致时**如实报出来**。
//
// 平台命令拿不到时返回错误，调用方降级回按表算的结果。
func RouteFor(ctx context.Context, dst netip.Addr) (Route, error) { return routeFor(ctx, dst) }

// errNoRouteCmd 命令跑通了、但输出我们读不懂。
var errNoRouteCmd = errors.New("路由命令的输出读不懂")

// ── 以下全是各平台输出的**纯解析**，不带 build tag：一台机器上就能把三个平台都测了 ──

// parseNetstatTable 解 BSD/macOS `netstat -rn -f inet|inet6` 的整张表。
//
// ★★ 这里有一个能把结论说反的坑：macOS 打印 v4 网段时**把主机位省掉** ——
//
//	192.168.1     就是 192.168.1.0/24
//	10.0          就是 10.0.0.0/16
//	192.168.1.1   是主机路由（/32）
//
//	直接 netip.ParsePrefix 全部失败。而「到不了某个网段」时最该看一眼的恰好是这类行。
func parseNetstatTable(out, family string) []Route {
	var rs []Route
	// ★ macOS 的 netstat 会把**网络路由树和主机路由树各打印一遍**，同一条件出现两次。
	// 不去重就是虚报条数，人会照着那个数怀疑自己看错了表。
	seen := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		// Flags 那一栏的位置会浮动（有的行带 Expire、有的带 ifscope），
		// 按下标取就会把 "59" 当成网卡名，所以按形状认。
		fi := -1
		for i := 2; i < len(f); i++ {
			if isRouteFlags(f[i]) {
				fi = i
				break
			}
		}
		if fi < 0 {
			continue
		}
		flags := f[fi]
		dest, ok := netstatDest(f[0], family)
		if !ok {
			continue
		}
		r := Route{
			Family:      family,
			Destination: dest.String(),
			Direct:      !strings.Contains(flags, "G"),
			Metric:      0, // macOS 的 netstat 不给度量，见 Route.Metric
		}
		// ★ 只有 Flags 带 G 才有下一跳。netstat 在直连行第二栏填的是**这块网卡自己的地址**
		//   （127.0.0.1 那种主机路由）或 link#4，把它当网关填出去，
		//   界面就会对着一个本网段说「下一跳 127.0.0.1」—— 那是我们编出来的话。
		if !r.Direct {
			r.Gateway = f[1]
		}
		for i := fi + 1; i < len(f); i++ {
			if strings.Trim(f[i], "0123456789") != "" {
				r.Iface = f[i]
				break
			}
		}
		key := r.Destination + "|" + r.Iface + "|" + r.Gateway
		if seen[key] {
			continue
		}
		seen[key] = true
		rs = append(rs, r)
	}
	return rs
}

// isRouteFlags 认 netstat 的 Flags 栏。
//
// ★★ 判据是「整段都是字母、且含大写 U」，**不是**「只由我认识的那些字母组成」：
//
//	BSD 的标志位有一长串，而且**大小写各表一义** —— 实测 macOS 给 v4 默认路由写 `UGSc`、
//	给 v6 的 utun 默认路由写 `UGcIg`。按固定字母表挑，小写那几位直接被拒，
//	结果是**默认路由整批从表里消失**（实机跑出来 72 条里一条默认都没有，只剩直连）。
//	而「有没有默认路由」恰恰是最常被问的那一句 —— 缺了它，答案会从
//	「有路但上游不通」翻成「压根没路」，完全相反。
//
// 网卡名（en0 / lo0 / utun3）一定带数字，所以「纯字母」不会把它误认成标志；
// U 表示这条路由可用，有效行都带它，用它当锚。
func isRouteFlags(s string) bool {
	if len(s) < 2 || !strings.Contains(s, "U") {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// netstatDest 把 netstat 的 Destination 栏归一成前缀。
func netstatDest(d, family string) (netip.Prefix, bool) {
	if d == "default" || d == "default6" {
		if family == "ipv6" {
			return netip.MustParsePrefix("::/0"), true
		}
		return netip.MustParsePrefix("0.0.0.0/0"), true
	}
	d = strings.TrimPrefix(d, "!") // netstat 用 ! 标「排除路由」
	base, bits := d, -1
	if i := strings.Index(d, "/"); i >= 0 {
		base, bits = d[:i], mustAtoi(d[i+1:])
	}
	zone := ""
	if i := strings.Index(base, "%"); i >= 0 {
		base, zone = base[:i], base[i:]
	}
	switch base {
	case "ip6", "inet", "Internet", "Internet6", "Routing":
		return netip.Prefix{}, false
	}
	if family == "ipv6" {
		a, err := netip.ParseAddr(base + zone)
		if err != nil {
			return netip.Prefix{}, false
		}
		if bits < 0 {
			bits = a.BitLen()
		}
		return netip.PrefixFrom(a, bits), true
	}
	// v4：按段数补回被省掉的主机位，并据此推前缀长度
	octets := strings.Count(base, ".") + 1
	if bits < 0 {
		switch octets {
		case 4:
			bits = 32
		case 3:
			bits = 24
		case 2:
			bits = 16
		case 1:
			bits = 8
		default:
			return netip.Prefix{}, false
		}
	}
	if octets < 4 {
		base += strings.Repeat(".0", 4-octets)
	}
	a, err := netip.ParseAddr(base)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, bits), true
}

func mustAtoi(s string) int { n, _ := strconv.Atoi(s); return n }

// parseIPRouteTable 解 Linux `ip route show` / `ip -6 route show` 的整张表。
//
//	default via 192.168.0.1 dev en0 proto dhcp src 192.168.0.101 metric 100
//	192.168.0.0/24 dev en0 proto kernel scope link src 192.168.0.101 metric 100
//
// ★ unreachable / blackhole / prohibit 这三类**不收**：它们表示「到不了」，
// 而本包给出的语义是「会走哪条」。把黑洞当一条可走的路由挑出来比少一条糟糕得多 ——
// 用户会照着它去查那块网卡。
func parseIPRouteTable(out, family string) []Route {
	var rs []Route
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "unreachable", "blackhole", "prohibit":
			continue
		}
		dest, ok := ipRouteDest(f[0], family)
		if !ok {
			continue
		}
		r := Route{Family: family, Destination: dest.String()}
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "via":
				if i+1 < len(f) {
					r.Gateway = f[i+1]
				}
			case "dev":
				if i+1 < len(f) {
					r.Iface = f[i+1]
				}
			case "src":
				if i+1 < len(f) {
					r.Src = f[i+1]
				}
			case "metric":
				if i+1 < len(f) {
					r.Metric = mustAtoi(f[i+1])
				}
			case "scope":
				if i+1 < len(f) && f[i+1] == "link" {
					r.Direct = true
				}
			}
		}
		if r.Gateway == "" {
			r.Direct = true // 不带 via 的就是本网段直连
		}
		rs = append(rs, r)
	}
	return rs
}

func ipRouteDest(d, family string) (netip.Prefix, bool) {
	if d == "default" {
		if family == "ipv6" {
			return netip.MustParsePrefix("::/0"), true
		}
		return netip.MustParsePrefix("0.0.0.0/0"), true
	}
	p, err := netip.ParsePrefix(d)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// parseIPRouteGet 解 `ip route get` 的一行结论。
//
//	192.168.1.10 via 192.168.1.1 dev en0 src 192.168.1.50 uid 1000
//	    cache
//
// ★ 第一栏是**被问的那个地址本身**，不是命中的网段，所以 destination 这一栏
// 对 Linux 的答案不留空 —— 填成问的地址才是实话。
func parseIPRouteGet(s string, dst netip.Addr) (Route, bool) {
	ln := strings.TrimSpace(strings.SplitN(strings.TrimSpace(s), "\n", 2)[0])
	f := strings.Fields(ln)
	if len(f) < 2 {
		return Route{}, false
	}
	switch f[0] {
	case "unreachable", "prohibit", "blackhole":
		return Route{}, false
	}
	r := Route{Family: "ipv4", Destination: dst.String()}
	if dst.Is6() {
		r.Family = "ipv6"
	}
	for i := 1; i < len(f); i++ {
		switch f[i] {
		case "via":
			if i+1 < len(f) {
				r.Gateway = f[i+1]
			}
		case "dev":
			if i+1 < len(f) {
				r.Iface = f[i+1]
			}
		case "src":
			if i+1 < len(f) {
				r.Src = f[i+1]
			}
		}
	}
	if r.Iface == "" {
		return Route{}, false
	}
	r.Direct = r.Gateway == ""
	return r, true
}

// windowsRouteTableJSON 对应 PowerShell Get-NetRoute 选出来的字段（裸数组那种形状）。
//
// ★ RouteMetric 用 any：ConvertTo-Json 在有的系统上把度量写成字符串。
// 按 int 收会让**整批**解析失败 —— 一个字段类型就把整张表丢掉，太亏。
type windowsRouteTableJSON struct {
	DestinationPrefix string `json:"DestinationPrefix"`
	NextHop           string `json:"NextHop"`
	InterfaceAlias    string `json:"InterfaceAlias"`
	RouteMetric       any    `json:"RouteMetric"`
}

// parseGetNetRouteTable 解 `Get-NetRoute | Select ... | ConvertTo-Json` 的裸数组形状。
func parseGetNetRouteTable(out string) []Route {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var many []windowsRouteTableJSON
	if err := json.Unmarshal([]byte(out), &many); err != nil {
		var one windowsRouteTableJSON
		if json.Unmarshal([]byte(out), &one) != nil {
			return nil
		}
		many = []windowsRouteTableJSON{one}
	}
	var rs []Route
	for _, w := range many {
		r, ok := winRoute(w.DestinationPrefix, w.NextHop, w.InterfaceAlias, w.RouteMetric)
		if !ok {
			continue
		}
		rs = append(rs, r)
	}
	return rs
}

// winRoute 把一行 Get-NetRoute 归一成 Route。
//
// ★ Windows 用 0.0.0.0 / :: 表示「没有下一跳」，那不是网关 ——
//
//	照它填进 gateway，界面就会指着「本段直连」说「你的网关是 0.0.0.0」。
func winRoute(dest, nextHop, iface string, metric any) (Route, bool) {
	p, err := netip.ParsePrefix(strings.TrimSpace(dest))
	if err != nil {
		return Route{}, false
	}
	p = p.Masked()
	r := Route{
		Family:      familyOf(p),
		Destination: p.String(),
		Iface:       iface,
		Metric:      jsonInt(metric),
	}
	if nh := strings.TrimSpace(nextHop); nh != "" && nh != "0.0.0.0" && nh != "::" && nh != "127.0.0.1" {
		r.Gateway = nh
	} else {
		r.Direct = true
	}
	return r, true
}

func jsonInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		return mustAtoi(strings.TrimSpace(n))
	}
	return 0
}

func familyOf(p netip.Prefix) string {
	if p.Addr().Is4() || p.Addr().Is4In6() {
		return "ipv4"
	}
	return "ipv6"
}

// winRouteRow 是表里的一行（含拼度量要的 InterfaceIndex）。
type winRouteRow struct {
	DestinationPrefix string  `json:"DestinationPrefix"`
	NextHop           string  `json:"NextHop"`
	InterfaceAlias    string  `json:"InterfaceAlias"`
	RouteMetric       any     `json:"RouteMetric"`
	InterfaceIndex    float64 `json:"InterfaceIndex"`
}

// winIfMetric 一行的网卡度量。★ InterfaceMetric 也走 any，理由同 RouteMetric。
type winIfMetric struct {
	InterfaceIndex  float64 `json:"InterfaceIndex"`
	InterfaceMetric any     `json:"InterfaceMetric"`
}

// parseWinRouteTable 解 {"r":[...],"m":[...]}，把网卡度量并进 Metric。
//
// ★★ 度量在这里是**两段相加**的：RouteMetric（路由自己的）+ InterfaceMetric（网卡整体的）。
//
//	只比前者会挑错默认路由 —— 多网卡机器上「两条都是 0.0.0.0/0，谁优先」就是靠这个和算出来的。
//
// ★ 只有一条时 ConvertTo-Json 给对象不给数组，两种都要认（singleAsArray）。
//
//	这个坑在 parseGetNetRoute 上踩过一次：只认数组的话，
//	单网卡机器上**整张表都读不到**，而那恰恰是最常见的机器。
func parseWinRouteTable(out string) []Route {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var p struct {
		Routes  json.RawMessage `json:"r"`
		Metrics json.RawMessage `json:"m"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil || len(p.Routes) == 0 {
		return parseGetNetRouteTable(out) // 退回裸数组那种形状
	}
	im := map[float64]int{}
	var ms []winIfMetric
	if json.Unmarshal(singleAsArray(p.Metrics), &ms) == nil {
		for _, m := range ms {
			im[m.InterfaceIndex] = jsonInt(m.InterfaceMetric)
		}
	}
	var rows []winRouteRow
	if json.Unmarshal(singleAsArray(p.Routes), &rows) != nil {
		return nil
	}
	var rs []Route
	for _, w := range rows {
		r, ok := winRoute(w.DestinationPrefix, w.NextHop, w.InterfaceAlias, w.RouteMetric)
		if !ok {
			continue
		}
		r.Metric += im[w.InterfaceIndex]
		rs = append(rs, r)
	}
	return rs
}

// singleAsArray 把「只有一条时给对象」包成数组，好让解码只有一条路径。
func singleAsArray(raw json.RawMessage) json.RawMessage {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" || t[0] == '[' {
		return raw
	}
	return json.RawMessage("[" + t + "]")
}

// parseRouteGet 解 macOS `route -n get` 的输出。
//
// ★ 不带 -n 会做**反向解析**：拿网关去查 DNS、把 192.168.1.1 印成
//
//	gw01.example-router.cn。那是从客户内网捞出一个域名，而这张表要发给 AI、进日志。
//	所以命令必须带 -n，这里再兜一层：认出来的地址解不成 IP 就丢掉。
func parseRouteGet(s string, dst netip.Addr) Route {
	r := Route{Family: "ipv4", Destination: dst.String() + "/32"}
	if dst.Is6() {
		r.Family = "ipv6"
		r.Destination = dst.String() + "/128"
	}
	var dest, mask string
	recognized := false
	for _, ln := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "route to":
			dest = dst.String()
			recognized = true
		case "destination":
			if v != "default" {
				dest = v
			}
			recognized = true
		case "mask", "netmask":
			mask = v
			recognized = true
		case "gateway":
			// macOS 对直连路由把这一栏写成 link#4 或本机自己的地址，两种都不是下一跳。
			if !strings.HasPrefix(v, "link#") {
				r.Gateway = v
			}
			recognized = true
		case "interface", "expif":
			if r.Iface == "" || k == "expif" {
				r.Iface = v
			}
			recognized = true
		case "src":
			r.Src = v
		}
	}
	if !recognized {
		return Route{} // 整段读不懂，别留半个答案
	}
	base := dest
	if base == "" {
		base = dst.String()
	}
	// ★★ 目的地一律带前缀长度。`route get` 这些栏给的都是**裸地址**
	//
	//	（destination: 192.168.1.0 / mask: 255.255.255.0），
	//	mask 那一栏还是**点分净掩码**而不是前缀长度。原样拼会得到
	//	192.168.0.0/255.255.255.0 这种解不开的 CIDR，
	//	界面「按哪条路由走」那一栏就直接空掉。
	if n, ok := netmaskBits(mask); ok {
		r.Destination = strings.SplitN(base, "%", 2)[0] + "/" + strconv.Itoa(n)
	} else if d, ok := hostOrCIDR(base); ok {
		r.Destination = d
	}
	r.Direct = r.Gateway == ""
	return r
}

// netmaskBits 把点分净掩码换成前缀长度。
//
// 只认真正的掩码（连续一段 1、后面全 0）。非连续的（255.0.255.0 那种）不当成有效长度 ——
// 我们的答案里不许出现一个说不清网段的路由。
func netmaskBits(v string) (int, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil || !a.Is4() {
		return 0, false
	}
	b := a.As4()
	n := 0
	seenZero := false
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			if x&(1<<i) != 0 {
				if seenZero {
					return 0, false
				}
				n++
			} else {
				seenZero = true
			}
		}
	}
	return n, true
}

// hostOrCIDR 把一栏地址归一成带前缀长度的写法。
//
// 裸地址按主机路由算（/32、/128）—— 系统在这一栏给裸地址时，说的就是「这一台」，
// 不是「这个段」。zone（fe80::1%en0）不进 CIDR。
func hostOrCIDR(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if i := strings.LastIndex(v, "%"); i > 0 {
		v = v[:i]
	}
	if strings.Contains(v, "/") {
		if _, err := netip.ParsePrefix(v); err == nil {
			return v, true
		}
		return "", false
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return "", false
	}
	if a.Is6() {
		return v + "/128", true
	}
	return v + "/32", true
}

// SelectRoute 按**最长前缀匹配**从表里挑出该走哪条 —— 这是各主流系统共同的选路规则。
//
// ★★ 平局的处理必须小心，这里按「先比前缀长度，再比度量，最后按表里的先后」：
//
//   - 前缀更长的那条赢，这是系统本身的规则，没有商量余地
//   - 长度相同才比 metric（小的优先）。★ 两边 metric 都是 0 时不许随机挑 ——
//     macOS 的 netstat 压根不给度量，这时按表里的顺序给答案，
//     并由 TiedRoutes 说出「还有几条并列」，让人自己去查，
//     比我们假装比过了强
//   - 族必须对上：v4 的目的地永远不许匹配到 v6 的路由上，反之也一样。
//     ::/0 和 0.0.0.0/0 谁都能盖住一片，族判断一松，v4 的包会被说成走 v6 出口。
func SelectRoute(routes []Route, dst netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			continue
		}
		if p.Addr().Is4() != dst.Is4() {
			continue
		}
		if !p.Contains(dst) {
			continue
		}
		if !found {
			best, found = r, true
			continue
		}
		bp, _ := netip.ParsePrefix(best.Destination)
		switch {
		case p.Bits() > bp.Bits():
			best, found = r, true
		case p.Bits() == bp.Bits() && r.Metric != 0 && best.Metric != 0 && r.Metric < best.Metric:
			best, found = r, true
		}
	}
	return best, found
}

// TiedRoutes 数一下还有多少条路由和 best 一样长、同样盖得住 dst。
//
// 用途是诚实：并列时给的答案只是表里第一条，必须同时说「还有几条并列的」，
// 不然「选错了网卡」这种现场故障就会被我们这句话盖过去。
func TiedRoutes(routes []Route, dst netip.Addr, best Route) int {
	bp, err := netip.ParsePrefix(best.Destination)
	if err != nil {
		return 0
	}
	n := 0
	for _, r := range routes {
		if r.Destination == best.Destination && r.Iface == best.Iface && r.Gateway == best.Gateway {
			continue // best 自己，以及和它完全同一条的重复项
		}
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil || p.Bits() != bp.Bits() {
			continue
		}
		if p.Addr().Is4() != dst.Is4() || !p.Contains(dst) {
			continue
		}
		n++
	}
	return n
}
