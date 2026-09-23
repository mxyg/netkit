package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.routes ──
//
// 读**整张路由表**，并回答现场最想要的那一句：「去往这个地址，会从哪块网卡出去」。
//
// ★ 为什么这一张卡非做不可：本项目里已经有一堆结论偷偷依赖它 ——
//
//	net.wol 要说「从哪块网卡发的」、net.dualstack.check 要说「有没有默认路由」、
//	net.trace 第一跳就是网关。可用户自己**没有任何地方能看到这张表**。
//	多网卡工控机上「两条默认路由打架」「目标网卡根本没路」这两类病，
//	症状都是「时通时不通」和「换台机器就通」，不看表就只能靠猜。
//
// ★★ 和 net.trace 的分工要说清：这里回答的是**按本机规则该走哪**，
//
//	不回答「走得到走不到」。所以纯读本机、一个包都不发（目的地是域名时才解析一次）。
//	把「该走这条路」说成「能走到」是这类工具最常见的越界。
//
// 凭据：无。这张表里只有地址、网卡名和度量，不读配置文件、不碰任何密钥。
const (
	verdictRoutesListed    = "routes-listed"       // 只列了表，没问目的地
	verdictRouteFound      = "route-found"         // 该走哪条，答出来了
	verdictNoRoute         = "no-route"            // 表里没有任何一条盖得住这个目的地
	verdictRouteMismatch   = "route-mismatch"      // 我们按表算的 ≠ 系统自己选的
	verdictRouteSplit      = "route-split"         // 一个名字解出多个地址、走的路不一样
	verdictRouteLocal      = "route-local"         // 目的地就是本机自己的地址
	verdictMultiDefault    = "multi-default-route" // 同族有多条默认路由（只列表时也要顶出来）
	verdictTableUnreadable = "table-unreadable"    // 这台机器上读不到路由表
)

// 三个读取口都走变量，测试才能在任何机器上把全表、选路、对拍都跑满。
//
// ★ 为什么非得换得掉：这台机器上真表里有什么、系统自己怎么选路，
//
//	都不该让测试结果跟着变 —— 否则 CI 在一台挂着 VPN 的机器上就红了，
//	而红的那一条和这次改动毫无关系。
var (
	routesTable = netif.Routes
	routesAskOS = netif.RouteFor
	routesLocal = isLocalAddr
)

var routesTool = ots.Tool{
	Name:  "net.routes",
	Class: ots.ClassRead,
	Summary: "读本机完整路由表，并回答「去往某个地址会从哪块网卡、哪个网关出去」。" +
		"★ 纯读本机，不发探测包。多网卡机器上这是查「时通时不通」的第一步：" +
		"同一个目的地被两条路由盖住、或者某一族压根没路，都只在这张表里看得见。" +
		"给了 dest 时按最长前缀匹配算，并和系统自己给的答案对拍，不一致会直说。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "dest": {"type": "string",
	      "description": "要问目的地的地址或域名，如 192.168.1.100、fd00::1、camera.local。不填就只给全表。"},
	    "family": {"type": "string", "enum": ["ipv4", "ipv6", "both"],
	      "description": "表里只看哪一族，默认 both。"}
	  }
	}`),
	Invoke: readRoutes,
}

type routesArgs struct {
	Dest   string `json:"dest,omitempty"`
	Family string `json:"family,omitempty"`
}

func readRoutes(ctx context.Context, raw json.RawMessage) (any, error) {
	var a routesArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	switch a.Family {
	case "", "both", "ipv4", "ipv6":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "family 只能是 ipv4 / ipv6 / both，给的是 %q", a.Family)
	}

	table, err := routesTable()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "读路由表失败：%s", err)
	}
	if a.Family != "" && a.Family != "both" {
		var f []netif.Route
		for _, r := range table {
			if r.Family == a.Family {
				f = append(f, r)
			}
		}
		table = f
	}
	if len(table) == 0 {
		// ★ 空表和「这台机器没有路由」是两件事。前者多半是这个平台读不到
		//   （或这一族压根没启用），得说成读不到，不能把人指去加路由。
		return ots.Verdict{
			Code:   verdictTableUnreadable,
			Values: map[string]any{"routes": []netif.Route{}, "count": 0, "family": a.Family},
			Note:   "这台机器上读不到路由表（这一族没启用，或这个平台的读取方式还没实现）—— 不是「没有路由」",
		}, nil
	}

	// 默认路由单独抽一份：多网卡机器上「同族两条默认路由」是最要命的一类配置，
	// 埋在几十行表里等于没有。
	var defaults []netif.Route
	for _, r := range table {
		if isDefaultRoute(r) {
			defaults = append(defaults, r)
		}
	}
	perFam := map[string]int{}
	for _, r := range defaults {
		perFam[r.Family]++
	}
	multiDefault := perFam["ipv4"] > 1 || perFam["ipv6"] > 1

	base := map[string]any{
		"routes":       sortedRoutes(table),
		"count":        len(table),
		"defaults":     defaults,
		"defaultCount": perFam,
		"multiDefault": multiDefault,
	}

	if a.Dest == "" {
		code := verdictRoutesListed
		note := fmt.Sprintf("读到 %d 条路由", len(table))
		if multiDefault {
			// 只列表的时候也要把这件事顶到眼前
			code = verdictMultiDefault
			note = fmt.Sprintf("读到 %d 条路由；★ 同一族有多条默认路由，出外网走哪条取决于度量，不是看表顺序", len(table))
		}
		return ots.Verdict{Code: code, Values: base, Note: note}, nil
	}

	addrs, resolved, rerr := routesTarget(ctx, a.Dest)
	if len(addrs) == 0 {
		if rerr == nil {
			rerr = errors.New("没有解出地址")
		}
		// ★ 这一句是这一档的全部价值：不写「.local 走 mDNS」，
		//   人会以为设备不在线，接着去 ping —— 而 ping 同样解不开这个名字。
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%q 既不是地址也解析不出地址：%s。★ 域名走的是系统解析器，.local 这类 mDNS 名字它多半解不开 —— 换成 IP",
			a.Dest, rerr)
	}

	var answers []routeAnswer
	dests := make([]string, 0, len(addrs))
	for _, ad := range addrs {
		dests = append(dests, ad.String())
		tr, ok := netif.SelectRoute(table, ad)
		var a1 *netif.Route
		if ok {
			a1 = &tr
		}
		var a2 *netif.Route
		if or, err := routesAskOS(ctx, ad); err == nil {
			a2 = &or
		}
		answers = append(answers, routeAnswer{byTable: a1, byOS: a2})
	}

	// 先分开「一个名字解出多个地址、走的路不一样」：这不是错误，是必须让人看见的事实
	keys := map[string]bool{}
	for _, an := range answers {
		if k := answerKey(an); k != "" {
			keys[k] = true
		}
	}
	if len(keys) > 1 {
		var paths []map[string]any
		for i, an := range answers {
			paths = append(paths, answerMap(addrs[i], an))
		}
		return ots.Verdict{
			Code:   verdictRouteSplit,
			Values: merge(base, map[string]any{"dest": a.Dest, "destAddrs": dests, "resolved": resolved, "paths": paths}),
			Note: fmt.Sprintf("%s 解出 %d 个地址，走的路不一样（%d 种）—— 具体走哪条由应用挑哪个地址决定",
				a.Dest, len(addrs), len(keys)),
		}, nil
	}

	an := answers[0]

	// ★★ 目的地是**本机自己的地址**时单独出一档，而且不许走到「对拍不一致」那去。
	//
	//	实测踩到的：问 192.168.0.101（本机网卡上的地址），表里给的是 en0，
	//	系统自己给的是 lo0 —— 这是**对的**，BSD/Linux 都把自己的地址收回环。
	//	按对拍逻辑报成「这台机器有策略路由，别只看表」，等于把人往装错东西的方向上推。
	//	反过来这一档本身是有用的信息：他要去的「那台设备」其实就是这台机器
	//	（现场最常见的是 IP 撞了，或者设备的地址被误配到了自己网卡上）。
	if routesLocal(addrs[0]) {
		return ots.Verdict{
			Code: verdictRouteLocal,
			Values: merge(base, map[string]any{
				"dest": a.Dest, "destAddr": addrs[0].String(), "resolved": resolved, "local": true,
			}),
			Note: fmt.Sprintf("%s 是**本机自己的地址** —— 发往它会走回环，不会出网卡。"+
				"如果你以为这是另一台设备，那就是地址撞了", addrs[0]),
		}, nil
	}

	switch {
	case an.byTable == nil && an.byOS == nil:
		fam := "ipv4"
		if addrs[0].Is6() {
			fam = "ipv6"
		}
		n := 0
		for _, r := range table {
			if r.Family == fam {
				n++
			}
		}
		vals := merge(base, map[string]any{
			"dest": a.Dest, "destAddr": addrs[0].String(), "resolved": resolved,
			"family": fam, "familyRoutes": n,
		})
		if n == 0 {
			// ★ 「这一族一条路由都没有」是**没启用这一族**，和「有 v6 但去不了这台」
			//   是完全不同的两件事，必须分开说，否则人会去查防火墙。
			return ots.Verdict{Code: verdictNoRoute, Values: vals,
				Note: fmt.Sprintf("%s 是 %s 地址，可这张表里 %s 一条路由都没有 —— 这台机器这一族没启用", a.Dest, fam, fam)}, nil
		}
		return ots.Verdict{Code: verdictNoRoute, Values: vals,
			Note: fmt.Sprintf("表里 %d 条 %s 路由，没有一条盖得住 %s —— 到不了它是**没路**，不是对端不理",
				n, fam, addrs[0])}, nil
	case an.byTable != nil && an.byOS != nil && answerDiff(*an.byTable, *an.byOS):
		// ★★ 不一致单独出一档，不许偷偷只报一个：Linux 上这多半是策略路由
		//   （ip rule 给每块网卡挂一张表），按主表算的那个人为答案是**错的**。
		//   这一档本身就是有价值的信息：这台机器的路由不能靠看表判断。
		return ots.Verdict{
			Code: verdictRouteMismatch,
			Values: merge(base, map[string]any{
				"dest": a.Dest, "destAddr": addrs[0].String(), "resolved": resolved,
				"decision": decisionMap(addrs[0], an.byOS, "os"),
				"byOS":     decisionMap(addrs[0], an.byOS, "os"),
				"byTable":  decisionMap(addrs[0], an.byTable, "table"),
				"ties":     netif.TiedRoutes(table, addrs[0], *an.byTable),
			}),
			Note: fmt.Sprintf("★ 按表算是从 %s 走，可系统自己选的是 %s —— 这台机器有策略路由或多张表，别只看表判断出口",
				an.byTable.Iface, an.byOS.Iface),
		}, nil
	default:
		from := "table"
		pick := an.byTable
		if an.byOS != nil {
			from = "os"
			pick = an.byOS
		}
		ties := 0
		vals := merge(base, map[string]any{
			"dest": a.Dest, "destAddr": addrs[0].String(), "resolved": resolved,
			"decision": decisionMap(addrs[0], pick, from),
		})
		if an.byTable != nil {
			// ★ 只在真算出来过的时候才给「并列几条」—— 按表算那一步失败时
			//   这里没有可比的基准，硬塞一个 0 会被读成「确认没有并列」。
			ties = netif.TiedRoutes(table, addrs[0], *an.byTable)
			vals["ties"] = ties
		}
		if an.byOS == nil {
			vals["osUnavailable"] = true
		}
		r := *pick
		note := fmt.Sprintf("去往 %s 从 %s 出去", addrs[0], r.Iface)
		if r.Gateway != "" {
			note += "，下一跳 " + r.Gateway
		} else {
			note += "，是本网段直连，不经过网关"
		}
		if from == "table" {
			note += "（按表算的，系统那边问不到）"
		}
		if ties > 0 {
			// ★ 并列必须说：macOS 的表不带度量，我们**没有依据**在并列里挑一条，
			//   给的第一条只是打印顺序里的第一个。不说这句，
			//   「两条默认路由打架」这种真故障就会被这一句盖过去。
			note += fmt.Sprintf("；★ 还有 %d 条同样匹配，本机没有可比依据（表里不带度量），给出的只是其中一条", ties)
		}
		return ots.Verdict{Code: verdictRouteFound, Values: vals, Note: note}, nil
	}
}

// routesTarget 把 dest 变成地址。★ 是 IP 就一个都不问；是域名才解析，
// 并且最多看前 4 个答案 —— 一个名字解出上百个地址时，逐条算路由没有意义，
// 而且会把「走哪条」这个问题稀释成一张长表。
var routesTarget = func(ctx context.Context, dest string) ([]netip.Addr, bool, error) {
	if a, err := netaddr.Parse(dest); err == nil && a.IsValid() {
		return []netip.Addr{a.IP}, false, nil
	}
	host := dest
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := lookupIP(cctx, host)
	if err != nil {
		return nil, true, err
	}
	if len(list) > 4 {
		list = list[:4]
	}
	return list, true, nil
}

// lookupIP 抽成变量：测试里换成编出来的地址，绝不去碰真的 DNS。
var lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func isDefaultRoute(r netif.Route) bool {
	p, err := netip.ParsePrefix(r.Destination)
	if err != nil {
		return false
	}
	return p.Bits() == 0
}

// answerKey 用于「多个地址是不是走同一条路」。空串表示这一条压根没答案。
func answerKey(a routeAnswer) string {
	pick := a.byOS
	if pick == nil {
		pick = a.byTable
	}
	if pick == nil {
		return ""
	}
	return pick.Iface + "|" + pick.Gateway
}

func answerMap(ad netip.Addr, a routeAnswer) map[string]any {
	pick := a.byOS
	from := "os"
	if pick == nil {
		pick, from = a.byTable, "table"
	}
	if pick == nil {
		return map[string]any{"addr": ad.String(), "noRoute": true}
	}
	return decisionMap(ad, pick, from)
}

func decisionMap(ad netip.Addr, r *netif.Route, from string) map[string]any {
	m := map[string]any{
		"addr":        ad.String(),
		"iface":       r.Iface,
		"destination": r.Destination,
		"from":        from,
		"direct":      r.Direct,
	}
	if r.Gateway != "" {
		m["gateway"] = r.Gateway
	}
	if r.Src != "" {
		m["src"] = r.Src
	}
	if r.Metric != 0 {
		m["metric"] = r.Metric
	}
	return m
}

// answerDiff 比较两个答案是不是同一个出口。
//
// ★ 只比「网卡 + 下一跳」，不比 destination：按表算拿到的是网段（192.168.0.0/24），
//
//	系统给常是那条路由自己（甚至带 host 路由 /32），比这个字段会产生一堆假不一致。
//	假不一致比不比对更糟 —— 人查半天，其实是我们的对拍太粗。
func answerDiff(a, b netif.Route) bool {
	return a.Iface != b.Iface || a.Gateway != b.Gateway
}

// sortedRoutes 按「先族、再前缀长度从长到短、最后度量」排。
//
// ★ 这个顺序**就是系统选路时的优先级**：把最可能真正生效的路由摆在最前面，
//
//	人才不会在几十行里从头翻到尾才发现默认路由上面还压着一条 /24。
//	解不出前缀的行不猜长度，按「读不懂」沉到底部，但照样留在结果里 ——
//	少一行表内容比给一个错的排序好，可一行都不该悄悄丢。
func sortedRoutes(in []netif.Route) []netif.Route {
	out := append([]netif.Route(nil), in...)
	bits := func(r netif.Route) (int, bool) {
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			return -1, false
		}
		return p.Bits(), true
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		bi, oki := bits(out[i])
		bj, okj := bits(out[j])
		if oki != okj {
			return oki // 读得懂的排前面
		}
		if !oki {
			return out[i].Destination < out[j].Destination
		}
		if bi != bj {
			return bi > bj
		}
		return out[i].Metric < out[j].Metric
	})
	return out
}

// routeAnswer 一个目的地的两种答案：我们按表算的、系统自己给的。
//
// ★ 两个都留着是**有意的**：不一致时这一档要同时摆出两句话，
//
//	只留一个就等于替用户藏起来「这台机器的路由不能只看表」。
type routeAnswer struct {
	byTable *netif.Route
	byOS    *netif.Route
}

// merge 合两层 facts。★ 不覆盖已有键之外没什么技巧，图的是调用点别再手写一遍表。
func merge(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// localPrefixes 环回段，配合网卡上实际配的地址一起构成「本机地址」集合。
var localPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// isLocalAddr 这个地址是不是本机自己的。
//
// ★ 判据取**网卡上实际配着的地址**，不取路由表里那些 /32：表里的本机主机路由
//
//	各平台写法不一（macOS 在 lo0 上也放一条），拿它判会飘。
func isLocalAddr(ad netip.Addr) bool {
	for _, p := range localPrefixes {
		if p.Contains(ad) {
			return true
		}
	}
	nics, err := netif.Interfaces()
	if err != nil {
		return false
	}
	for _, n := range nics {
		for _, a := range n.Addrs {
			if a.IP == ad {
				return true
			}
		}
	}
	return false
}
