package tools

// 六棵症状树。★ 这里**只写走法**：每一步问谁、看哪个判定码、往哪儿拐。
//
// 引擎在 tree.go，它一概不懂网络 —— 所以审一棵树就是读下面这张表，
// 而表里每一个判定码都是对应工具自己那份常量（不是重打的字符串）：
// 那个工具哪天改了码，这里必须编译不过。

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultProbeDomain / defaultEgressAddr 是「人什么也没填」时的对照组。
//
// ★ 和 net.checkup 用的是同一对，这是刻意的：两张卡给出互相矛盾的结论，
//
//	人就不知道该信谁，最后谁都不信。
const (
	defaultProbeDomain = "www.cloudflare.com"
	defaultEgressAddr  = "1.1.1.1"
	defaultCamPorts    = "554,80,8000"
)

// ── 节点 ──

var (
	nCheckup = &treeNode{id: "checkup", name: "本机过一遍", tool: "net.checkup",
		shows: []string{"values.first"},
		// ★ 「第一项坏了」不够：网卡那一步有四种坏法，处置各不相同
		//	（没网卡 → 查配置、有卡没链路 → 查线、有链路没地址 → 查 DHCP）。
		//	分开它们要靠 items 里那一行自己的码，所以在这里把它取出来存着。
		take: func(st *treeState, vals map[string]any) {
			if c, ok := checkItemCode(vals, stepIface); ok {
				st.set("ifaceCode", c)
			}
		}}

	// nRouteList 整张表顺带读出默认路由的下一跳和出接口：
	// 后面「到网关连发几发」那一步要拿它当地址，没有它就只能落 not-asked。
	nRouteList = &treeNode{id: "route-list", name: "本机路由表", tool: "net.routes",
		shows: []string{"values.count", "values.multiDefault"},
		take:  takeDefaultRoute}

	nRoutesTo = &treeNode{id: "route-target", name: "去往目标走哪条路", tool: "net.routes",
		need: []string{"addr"},
		args: func(st *treeState) (map[string]any, error) {
			return map[string]any{"dest": st.str("addr")}, nil
		},
		shows: []string{"values.decision.iface", "values.decision.destination",
			"values.decision.direct", "values.decision.from"},
		take: takeRouteDecision}

	nGWWatch = &treeNode{id: "gw-watch", name: "到网关稳不稳", tool: "net.ping.watch", need: []string{"gateway"},
		args: func(st *treeState) (map[string]any, error) {
			return watchArgs(st, st.str("gateway")), nil
		},
		shows: []string{"values.lossPercent", "values.sent", "values.recv",
			"values.jitterAvgMs", "values.rttMaxMs", "values.spikes"}}

	nDNS = &treeNode{id: "dns", name: "域名解析", tool: "net.dns.query",
		// 点名的是 IP 时这一步不必问（★ 但必须留下「没问」那一格，不许空着）。
		when:   func(st *treeState) bool { return st.str("ip") == "" },
		unless: "目标本来就是地址，不必再解析一次",
		args: func(st *treeState) (map[string]any, error) {
			name := st.str("host")
			if name == "" {
				name = defaultProbeDomain
			}
			return map[string]any{"name": name, "type": "A"}, nil
		},
		shows: []string{"values.rcode", "values.server", "values.elapsedMs"},
		take: func(st *treeState, vals map[string]any) {
			// ★ 我们问的是谁，就得把的名字留在事实里：证书那一步要拿它当 serverName。
			//	少了这一格，用对照组域名解出的地址去做 TLS 校验，
			//	必然报「名字对不上」—— 那是我们自己造的假案。
			if st.str("host") == "" && st.str("ip") == "" {
				st.set("host", defaultProbeDomain)
			}
			takeAnswer(st, vals)
		}}

	nDual = &treeNode{id: "dualstack", name: "双栈体检", tool: "net.dualstack.check",
		args: func(st *treeState) (map[string]any, error) {
			if h := st.str("host"); h != "" {
				return map[string]any{"domain": h}, nil
			}
			return nil, nil
		},
		shows: []string{"values.eyeballs"}}

	nTrace = &treeNode{id: "trace", name: "路径追踪", tool: "net.trace",
		args: func(st *treeState) (map[string]any, error) {
			return map[string]any{"host": traceHost(st), "maxHops": 12, "perHop": 2}, nil
		},
		shows: []string{"values.traces[0].family", "values.traces[0].hopsSeen", "values.engine"}}

	nMtr = &treeNode{id: "mtr", name: "逐跳质量", tool: "net.mtr",
		args: func(st *treeState) (map[string]any, error) {
			rounds := 5
			if st.args.Quick {
				rounds = 2
			}
			return map[string]any{"host": traceHost(st), "rounds": rounds, "maxHops": 12}, nil
		},
		// ★ 丢包从第几跳起、往返从第几跳起 —— 这两栏才是「断在哪儿」的证据，
		//	光给一个「有丢包」等于让人自己再跑一遍。
		shows: []string{"values.reports[0].lossHop", "values.reports[0].latencyHop",
			"values.reports[0].goalSeen", "values.reports[0].roundsDone"}}

	nPing = &treeNode{id: "ping", name: "ping 一下", tool: "net.ping", need: []string{"addr"},
		args: func(st *treeState) (map[string]any, error) {
			n := 4
			if st.args.Quick {
				n = 2
			}
			return map[string]any{"addr": st.str("addr"), "count": n}, nil
		},
		shows: []string{"values.sent", "values.received", "values.lossPercent", "values.rttAvgMs"}}

	nWatch = &treeNode{id: "watch", name: "连续 ping", tool: "net.ping.watch", need: []string{"addr"},
		args: func(st *treeState) (map[string]any, error) {
			return watchArgs(st, st.str("addr")), nil
		},
		shows: []string{"values.lossPercent", "values.sent", "values.recv",
			"values.jitterAvgMs", "values.spikes", "values.lostAt"}}

	nTCP = &treeNode{id: "tcp", name: "探一个端口", tool: "net.tcp.probe", need: []string{"addr"},
		args: func(st *treeState) (map[string]any, error) {
			return map[string]any{"addr": st.str("addr"), "port": treePort(st)}, nil
		},
		shows: []string{"values.elapsedMs", "values.target"}}

	nPorts = &treeNode{id: "ports", name: "扫一片端口", tool: "net.ports.scan", need: []string{"addr"},
		args: func(st *treeState) (map[string]any, error) {
			m := map[string]any{"addr": st.str("addr")}
			switch {
			case st.str("ports") != "": // 人点名了几个口，就只看这几个
				m["ports"] = st.str("ports")
			case st.args.Port > 0: // ★ 点了一个口，不许拿默认清单交差
				m["ports"] = strconv.Itoa(st.args.Port)
			case st.args.Symptom == symDeviceDown:
				m["ports"] = defaultCamPorts
			}
			return m, nil
		},
		shows: []string{"values.open", "values.closed", "values.filtered",
			"values.scanned", "values.openPorts"}}

	nOnLink = &treeNode{id: "on-link", name: "本网段有没有它", tool: "net.subnet.scan", need: []string{"addr"},
		// ★ 这一棵只问 v4：v6 没有 ARP，「同网段有没有它」要用邻居发现去问，
		//	那是另一棵树的事。这里硬扫会一句「二层没有它」把 v6 的人往错的机房送。
		when:   func(st *treeState) bool { return st.str("family") != "ipv6" },
		unless: "本网段有没有它这一问只认 IPv4；v6 要去问邻居发现",
		args: func(st *treeState) (map[string]any, error) {
			// ★★ 参数里没有「/32」这一档：net.subnet.scan 明确拒绝掩码长过 /30，
			//	因为一个地址的段里除了它自己没别人可问，扫完必然报「一个信号都没收到」，
			//	而那会被读成「这段是空的」。所以要问就问**它所在的那一段**，
			//	段从路由那一步拿来（去它是直连，才谈得上二层）；拿不到段就只报网卡，
			//	让工具去扫本机自己在的段。
			m := map[string]any{"waitMs": 1500}
			if net := st.str("linkNet"); net != "" {
				m["cidr"] = net
			} else if i := st.str("iface"); i != "" {
				m["iface"] = i
			}
			return m, nil
		},
		shows: []string{"values.subnets", "values.alive", "values.asked", "values.hosts"},
		take:  takeOnLink}

	nTLS = &treeNode{id: "tls", name: "证书检查", tool: "net.tls.check", need: []string{"addr"},
		args: func(st *treeState) (map[string]any, error) {
			m := map[string]any{"addr": st.str("addr"), "port": treePort(st)}
			if h := st.str("host"); h != "" {
				m["serverName"] = h // ★ 用 IP 连、用名字验：不填这个，设备证书上的名字必然对不上
			}
			return m, nil
		},
		shows: []string{"values.notAfter", "values.notBefore", "values.issuer",
			"values.subject", "values.protocol", "values.daysLeft"},
		take: func(st *treeState, vals map[string]any) {
			if c, ok := digStr(vals, "verdict"); ok {
				st.set("certCode", c)
			}
			// ★ 「还没生效」有两种：真没到点，和本机钟慢过头。分开要靠证书上那两个
			//	时刻去比 —— 那一步后面要翻案问时间，这里先把时刻存着。
			if s, ok := digStr(vals, "values.notBefore"); ok {
				st.set("certNotBefore", s)
			}
			if s, ok := digStr(vals, "values.notAfter"); ok {
				st.set("certNotAfter", s)
			}
		}}

	// nHTTP 不硬要人填网址：只给了个名字时，就按 https://名字/ 去问一次。
	//	★ 猜错前缀是问得出来的 —— net.http.probe 自己会说「这是明文口」，
	//	那一分支正好翻成「改个前缀就好」，比「缺参数，没问」有用得多。
	nHTTP = &treeNode{id: "http", name: "网页 / 接口探测", tool: "net.http.probe",
		args: func(st *treeState) (map[string]any, error) {
			u := st.str("url")
			if u == "" {
				h := st.str("host")
				if h == "" {
					h = st.str("ip")
				}
				if h == "" {
					h = defaultProbeDomain
				}
				u = "https://" + h + "/"
			}
			return map[string]any{"url": u}, nil
		},
		shows: []string{"values.status", "values.timings", "values.url"}}

	nTime = &treeNode{id: "clock", name: "对一下时间", tool: "net.time.check",
		args: func(st *treeState) (map[string]any, error) {
			return map[string]any{"samples": samples(st)}, nil
		},
		shows: []string{"values.offsetMs", "values.checkedWith", "values.agreeSources", "values.attribution"}}

	// nOnvif 只在**手里没有取流地址**时问一次。现场卡的常常不是「流不通」，
	// 而是「我只有这台设备的网页后台，地址是多少」—— ONVIF 问得出来，问出来就喂给下一步。
	nOnvif = &treeNode{id: "onvif", name: "向设备问取流地址", tool: "media.onvif.info",
		need:   []string{"addr"},
		when:   func(st *treeState) bool { return st.str("url") == "" },
		unless: "已经有取流地址了，不必再向设备问一次",
		args: func(st *treeState) (map[string]any, error) {
			host := st.str("addr")
			if strings.ContainsRune(host, ':') {
				host = "[" + host + "]" // IPv6 不包一层方括号，拼出来的地址谁都解不开
			}
			m := map[string]any{"url": "http://" + host}
			// 账号只在发出去的那份参数里，进结果前由 redactTreeArgs 洗掉。
			if u := st.args.Username; u != "" {
				m["username"] = u
			}
			if pw := st.args.Password; pw != "" {
				m["password"] = pw
			}
			return m, nil
		},
		take: func(st *treeState, vals map[string]any) {
			if s, ok := digStr(vals, "values.mediaUri"); ok {
				if u := onvifStreamFor(s); u != "" {
					st.set("url", u)
				}
			}
		},
		shows: []string{"values.manufacturer", "values.model", "values.profileCount", "values.mediaUri"}}

	nRTSP = &treeNode{id: "stream", name: "问它肯不肯给流", tool: "media.rtsp.probe", need: []string{"url"},
		args: func(st *treeState) (map[string]any, error) {
			m := map[string]any{"url": st.str("url")}
			// 账号只在发出去的那份参数里，进结果前由 redactTreeArgs 洗掉。
			if u := st.args.Username; u != "" {
				m["username"] = u
			}
			if p := st.args.Password; p != "" {
				m["password"] = p
			}
			return m, nil
		},
		shows: []string{"values.status", "values.codec", "values.width",
			"values.height", "values.trackCount"}}
)

// onvifStreamFor 把 ONVIF 问出来的取流地址翻译成下一步能直接发出去的那一句。
//
// ★ 结果里的地址是**抹过口令**的（凭据不进结果是硬规矩），照原样喂给 RTSP
//
//	就等于拿「admin（口令已隐去）」当用户名去敲门 —— 设备回 401，
//	我们把它读成「密码不对」，而密码本来就是调用方填对的那一份。
//	所以这里把用户名整段摘掉，让下一步用调用方给的账号重问。
func onvifStreamFor(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "rtsp" {
		return ""
	}
	u.User = nil
	return u.String()
}

// ── 取值小工具 ──

func watchArgs(st *treeState, addr string) map[string]any {
	ms := 10000
	if st.args.Quick {
		ms = 4000
	}
	return map[string]any{
		"addr": addr, "intervalMs": 200, "durationMs": ms,
		"timeoutMs": st.args.TimeoutMS,
	}
}

func samples(st *treeState) int {
	if st.args.Quick {
		return 2
	}
	return 3
}

func treePort(st *treeState) int {
	if st.args.Port > 0 {
		return st.args.Port
	}
	if st.args.Symptom == symCert {
		return 443
	}
	return 80
}

func traceHost(st *treeState) string {
	for _, k := range []string{"addr", "host", "target"} {
		if v := st.str(k); v != "" {
			return v
		}
	}
	return defaultEgressAddr
}

// takeDefaultRoute 从整张路由表里拿走 v4 默认路由的下一跳和出接口。
//
// ★ 优先 v4：这张树后面要拿这个地址去发包，而现场「出不了外网」九成是 v4 那一路；
//
//	v6 那一族的毛病由 net.dualstack.check 那一步专门问，不在这里混。
func takeDefaultRoute(st *treeState, vals map[string]any) {
	defs, ok := dig(vals, "values.defaults")
	if !ok {
		return
	}
	arr, ok := defs.([]any)
	if !ok {
		return
	}
	pick := func(fam string) {
		for _, d := range arr {
			m, ok := d.(map[string]any)
			if !ok {
				continue
			}
			if s, _ := m["family"].(string); s != fam {
				continue
			}
			if gw, _ := m["gateway"].(string); gw != "" {
				st.set("gateway", gw)
			}
			if i, _ := m["iface"].(string); i != "" {
				st.set("iface", i)
			}
			return
		}
	}
	pick("ipv4")
	if st.str("gateway") == "" {
		pick("ipv6")
	}
}

// takeAnswer 拿走解析出来的第一个地址，并把「有地址了」这件事记下来。
func takeAnswer(st *treeState, vals map[string]any) {
	answers, ok := dig(vals, "values.answers")
	if !ok {
		return
	}
	arr, ok := answers.([]any)
	if !ok || len(arr) == 0 {
		return
	}
	for _, a := range arr {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if v, _ := m["value"].(string); v != "" {
			st.set("ip", v)
			st.set("addr", v)
			if n, _ := m["type"].(string); n == "AAAA" {
				st.set("family", "ipv6")
			} else {
				st.set("family", "ipv4")
			}
			return
		}
	}
}

// takeOnLink 记下二层问到的证据是什么级别的（应 ARP / 应 ICMP / 只在缓存里）。
//
// ★ 这条决定了后面那句「它活着但不回 ping」能不能说：
//
//	只有 arp-cache 这一种证据时不能说 —— 那可能是很久以前留下的。
//
// takeRouteDecision 从「去往它走哪条路」那一步拿走后面要用的事实。
//
// ★ 只在这一条路是直连时才把段记下来：二层那一句「这段里有没有它」只有在同一段里才问得出来，
//
//	要过网关的目标拿自己这段的扫结果去说它「不在」，是凭空定罪。
func takeRouteDecision(st *treeState, vals map[string]any) {
	if i, ok := digStr(vals, "values.decision.iface"); ok && st.str("iface") == "" {
		st.set("iface", i)
	}
	d, ok := dig(vals, "values.decision.direct")
	if !ok {
		return
	}
	if direct, _ := d.(bool); !direct {
		return
	}
	dest, ok := digStr(vals, "values.decision.destination")
	if !ok {
		return
	}
	pfx, err := netip.ParsePrefix(dest)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() > 30 {
		return // 不是能扫的段（v6、点线路、host 路由），这一段就别提「扫这段」
	}
	target, err := netip.ParseAddr(strings.Trim(st.str("addr"), "[]"))
	if err != nil || !pfx.Contains(target) {
		return
	}
	st.set("linkNet", pfx.String())
}

// takeOnLink 只看**人点的那一台**在不在清单里。
//
// ★★ 整段有没有活人是另一件事：这一段里别人都吭了、就它没吭，才是「二层没有它」；
//
//	反过来「清单是空的」既可能是这段没人，也可能是我们压根没问到这段（段不对）。
//	所以这里落成两格：见没见过它、以及这次扫的段盖不盖得住它。
func takeOnLink(st *treeState, vals map[string]any) {
	addr := st.str("addr")
	target, err := netip.ParseAddr(strings.Trim(addr, "[]"))
	if err != nil {
		return
	}
	if subs, ok := dig(vals, "values.subnets"); ok {
		if arr, ok := subs.([]any); ok {
			for _, s := range arr {
				cs, _ := s.(string)
				pfx, err := netip.ParsePrefix(cs)
				if err == nil && pfx.Contains(target) {
					st.set("linkCovered", "yes")
					break
				}
			}
		}
	}
	hosts, ok := dig(vals, "values.hosts")
	if !ok {
		return
	}
	arr, ok := hosts.([]any)
	if !ok {
		return
	}
	for _, h := range arr {
		m, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if a, _ := m["addr"].(string); a != addr {
			continue
		}
		st.set("onLinkSeen", "yes")
		if e, _ := m["evidence"].(string); e != "" {
			st.set("onLinkEvidence", e)
		}
		if mac, _ := m["mac"].(string); mac != "" {
			st.set("mac", mac)
		}
		return
	}
}

// onLinkMove 「这一问到底说明了什么」。★ offLink 是给这棵树用的那一条根因码。
//
//	看不到「扫的段里有它」就绝不许说二层没有它 —— 那一格没填等于这次没问到，
//	而不是「问到了、它不在」。
func onLinkMove(offLink string) func(*treeState, string, map[string]any) move {
	return func(st *treeState, _ string, _ map[string]any) move {
		if st.str("onLinkSeen") == "yes" {
			return to("ping")
		}
		if st.str("linkCovered") == "yes" {
			return stop(offLink)
		}
		return to("ping")
	}
}

// strongOnLink 有没有「它刚才亲自吭过一声」这种级别的证据。
func strongOnLink(st *treeState) bool {
	switch st.str("onLinkEvidence") {
	case evICMP, evARP, evTCP:
		return true
	}
	return false
}

// checkItemCode 取体检里某一项自己的判定码。
//
// ★ 顶层码只说「第一项坏在网卡」，坏法是哪种却在那一行里：没网卡（查配置）、
//
//	有卡没链路（查线）、有链路没地址（查 DHCP）是三件完全不同的事。
//	不取出来就只能三件一起说，那等于没说。
func checkItemCode(vals map[string]any, step string) (string, bool) {
	items, ok := dig(vals, "values.items")
	if !ok {
		return "", false
	}
	arr, ok := items.([]any)
	if !ok {
		return "", false
	}
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if s, _ := m["step"].(string); s != step {
			continue
		}
		c, ok := m["code"].(string)
		return c, ok
	}
	return "", false
}

// ── 六棵树 ──

// end 是「这条路走完了，没定位到根因」。★ 它和 no-cause-found 是同一件事，
// 区别只在于走没走完 —— 引擎会按 asked 数落顶层码。
func end() move { return move{end: true} }

func stop(cause string) move { return move{cause: cause} }

func to(id string) move { return move{next: id} }

// planNoInternet 以体检打头。
//
// ★★ 不是偷懒：体检那八项的顺序正是「第一个坏掉的是哪一步」，
//
//	而它已经保证「走到 DNS 就说明网关那段是好的」。树里再问一遍前几项，
//	等于花两倍的时间重测同一件事，还可能两次结果不一致。
//	所以这棵树做的事是：**拿到那一步之后，只往那一步里挖**。
var planNoInternet = &treePlan{symptom: symNoInternet, steps: []planStep{
	{node: nCheckup,
		by: map[string]move{
			topBrokenRoute:   to("route-list"),
			topBrokenGateway: to("route-list"),
			topBrokenDNS:     to("dns"),
			topBrokenEgress:  to("dualstack"),
			topBrokenClock:   to("clock"),
			topAllGood:       end(),
		},
		// 网卡那一步刻意不放 by：它有几种坏法，处置相反（查配置 vs 查线 vs 查 DHCP），
		// 分开要靠 items 里那一行自己的码，所以统一走 decide。
		decide: func(st *treeState, code string, vals map[string]any) move {
			first, _ := digStr(vals, "values.first")
			if first == "" {
				return end()
			}
			switch first {
			case stepIface:
				switch st.str("ifaceCode") {
				case "no-link": // 卡在链路上：卡是好的，线/无线没接上
					return stop("cause-link-down")
				case "no-address": // 链路通了却没地址：DHCP / RA 那一头没给
					return stop("cause-no-address")
				}
				return stop("cause-no-interface")
			case stepRoute:
				return to("route-list")
			case stepGateway:
				return to("route-list")
			case stepDNS:
				return to("dns")
			case stepEgress:
				return to("dualstack")
			case stepClock:
				return to("clock")
			case stepMTU:
				return to("trace")
			case stepProxy:
				return stop("cause-proxy-in-the-way")
			}
			return to("route-list")
		}},
	{node: nRouteList,
		by: map[string]move{
			verdictNoRoute:         stop("cause-no-default-route"),
			verdictTableUnreadable: end(), // 读不到表是我们的事，不许顺推成「那就是没路由」
			verdictMultiDefault:    stop("cause-multi-default"),
		},
		// 路由这一步通常没问题（体检已经这么判了），它的价值是把网关地址拿到手。
		other: to("gw-watch")},
	{node: nGWWatch,
		by: map[string]move{
			watchLoss:        stop("cause-gateway-loss"),
			watchUnreachable: stop("cause-gateway-unreachable"),
			watchNoReply:     stop("cause-gateway-silent"),
			watchNoRoute:     stop("cause-no-default-route"),
			watchJitter:      to("dns"), // 抖但没丢：继续往上看别处
		}},
	{node: nDNS,
		by: map[string]move{
			dnsTimeout:     stop("cause-dns-server-dead"),
			dnsUnreachable: stop("cause-dns-server-dead"),
			dnsServFail:    stop("cause-dns-upstream"),
			dnsRefused:     stop("cause-dns-refused"),
			dnsBadResponse: stop("cause-dns-bad-response"),
			dnsNXDomain:    stop("cause-name-missing"),
		},
		other: to("dualstack")}, // 解析利索，那问题在上面一层
	{node: nDual,
		by: map[string]move{
			dsV6EgressBroken:   stop("cause-v6-egress-broken"),
			dsEyeballsStall:    stop("cause-v6-stall"),
			dsNoAddress:        stop("cause-no-address"),
			dsBothEgressBroken: to("trace"),
			dsV4EgressBroken:   to("trace"),
			dsSingleNoEgress:   to("trace"),
		},
		other: end()},
	{node: nTrace,
		by: map[string]move{
			traceNoRoute:    stop("cause-no-route-to-target"),
			traceStalled:    stop("cause-path-stalled"),
			traceNoResponse: stop("cause-path-silent"),
			traceReached:    stop("cause-egress-blocked"), // 路到得了出口机器，却连不上那个口 —— 拦在上面
			traceMaxHops:    end(),
			traceNoCommand:  end(),
			tracePrivileged: end(),
			traceTimedOut:   end(),
		},
		other: end()},
	{node: nTime,
		by: map[string]move{
			timeWayOff:     stop("cause-clock-way-off"),
			timeSkewed:     stop("cause-clock-skewed"),
			timeDisagree:   stop("cause-clock-disagree"),
			timeNoResponse: end(), // 问不到时间源在内网天天如此，不能据此说钟好、也不能说坏
			timeKissed:     end(),
			timeBadFormat:  end(),
		},
		other: end()},
}}

// planHostDown 点名一台机器。
var planHostDown = &treePlan{symptom: symHostDown, steps: []planStep{
	{node: nDNS,
		by: map[string]move{
			dnsNXDomain:    stop("cause-name-missing"),
			dnsTimeout:     stop("cause-dns-server-dead"),
			dnsUnreachable: stop("cause-dns-server-dead"),
			dnsServFail:    stop("cause-dns-upstream"),
			dnsRefused:     stop("cause-dns-refused"),
			dnsBadResponse: stop("cause-dns-bad-response"),
		},
		other: to("route-target")},
	{node: nRoutesTo,
		by: map[string]move{
			verdictNoRoute:      stop("cause-no-route-to-target"),
			verdictRouteLocal:   end(), // 目的地就是本机自己，这棵树上问不出东西
			verdictMultiDefault: to("on-link"),
		},
		other: to("on-link")},
	{node: nOnLink,
		// ★ 不在 by 里写 scanNetEmpty→「二层没有它」：那个码说的是整段，
		//	人点的这一台在不在要看它自己那一行 —— 走 onLinkMove。
		decide: onLinkMove("cause-target-off-link"),
		other:  to("ping")},
	{node: nPing,
		by: map[string]move{
			verdictUnreachable: stop("cause-target-unreachable"),
			verdictReachable:   to("ports"),
		},
		// no-reply 要分两种：二层问过、它吭过（那就是它不理 ICMP）；什么都没拿到（真不知道）。
		decide: func(st *treeState, code string, vals map[string]any) move {
			switch code {
			case verdictNoReply:
				if strongOnLink(st) {
					return stop("cause-target-alive-noicmp")
				}
				return to("trace")
			case verdictReachable:
				return to("ports")
			case verdictUnreachable:
				return stop("cause-target-unreachable")
			}
			return end()
		}},
	{node: nTrace,
		by: map[string]move{
			traceStalled:    stop("cause-path-stalled"),
			traceNoRoute:    stop("cause-no-route-to-target"),
			traceReached:    stop("cause-target-alive-noicmp"), // 追得到终点 = 它在，只是不理 ping
			traceNoResponse: stop("cause-target-no-reply"),
		},
		other: stop("cause-target-no-reply")},
	{node: nPorts,
		by: map[string]move{
			scanSomeOpen:   stop("cause-host-alive"),
			scanAllClosed:  stop("cause-service-closed"),
			scanNoResponse: stop("cause-service-filtered"),
			scanNoRoute:    stop("cause-no-route-to-target"),
		},
		other: end()},
}}

// planSlow 通是通，但慢。
//
// ★ 顺序是「先看链路、再看选路、最后看应用各段占了多少」：
//
//	链路在丢包时重传会把每一段都拖慢，那时候读 HTTP 的分段耗时毫无意义 ——
//	会得出「服务端慢」这种把网线的账算到应用头上的结论。
var planSlow = &treePlan{symptom: symSlow, steps: []planStep{
	{node: nDNS, other: to("watch")},
	{node: nWatch,
		by: map[string]move{
			watchLoss:        stop("cause-link-loss"),
			watchJitter:      stop("cause-link-jitter"),
			watchUnreachable: stop("cause-target-unreachable"),
			watchNoRoute:     stop("cause-no-route-to-target"),
			watchStable:      to("http"),
		},
		other: to("http")}, // 不通也归到「慢」的症状里问过的人：继续往下，让分段耗时说话
	{node: nHTTP,
		by: map[string]move{
			httpWrongScheme: stop("cause-wrong-scheme"), // ★ 明文口写成 https：不是慢，是先撞了再重试
		},
		decide: slowBySegment,
		other:  to("dualstack")},
	{node: nDual,
		by: map[string]move{
			dsEyeballsStall:  stop("cause-v6-stall"),
			dsV6EgressBroken: stop("cause-v6-egress-broken"),
		},
		other: to("mtr")},
	{node: nMtr,
		by: map[string]move{
			qualityLatency:   stop("cause-path-latency"),
			qualityLoss:      stop("cause-link-loss"),
			qualityPathMoved: stop("cause-path-moved"),
		},
		other: to("mtu")},
	{node: mtuNode,
		by:    map[string]move{mtuCodePath: stop("cause-mtu-too-small")},
		other: end()},
}}

// slowBySegment 把 HTTP 的分段耗时翻成「慢在哪一段」。
//
// ★★ 阈值写在这里是有代价的：换了网络这个数就不对。所以它只做**归因**
//
//	（哪一段占的大头），不做人话里的「算慢」判断 —— 那一栏 net.http.probe 自己有。
func slowBySegment(st *treeState, code string, vals map[string]any) move {
	lookup, _ := num(vals, "values.timings.lookupMs")
	connect, _ := num(vals, "values.timings.connectMs")
	tls, _ := num(vals, "values.timings.tlsMs")
	total, _ := num(vals, "values.timings.totalMs")
	server, _ := num(vals, "values.timings.serverMs")
	switch {
	case code == dnsTimeout || code == dnsUnreachable:
		return stop("cause-dns-server-dead")
	case lookup >= 300 && lookup >= total*0.25:
		return stop("cause-dns-slow")
	case connect >= 300 && connect >= total*0.25:
		return stop("cause-connect-slow")
	case tls >= 500 && tls >= total*0.25:
		return stop("cause-tls-slow")
	case server >= 500 && total > 0 && server >= total*0.5:
		return stop("cause-app-slow") // 网络各段都利索，慢在服务自己想
	}
	return to("dualstack")
}

// planFlaky 偶尔卡一下 / 时好时坏。
var planFlaky = &treePlan{symptom: symFlaky, steps: []planStep{
	{node: nDNS, other: to("watch")},
	{node: nWatch,
		by: map[string]move{
			watchLoss:        stop("cause-intermittent-loss"),
			watchJitter:      stop("cause-link-jitter"),
			watchNoReply:     stop("cause-gateway-silent"),
			watchUnreachable: stop("cause-target-unreachable"),
		},
		other: to("route-list")},
	{node: nRouteList,
		by:    map[string]move{verdictMultiDefault: stop("cause-multi-default")},
		other: to("mtr")},
	{node: nMtr,
		by: map[string]move{
			qualityPathMoved: stop("cause-path-moved"),
			qualityLoss:      stop("cause-intermittent-loss"),
			qualitySilent:    to("dns-multi"), // 中段静默是设备不爱回 ICMP，不是故障：先看名字后面有没有几台
		},
		other: to("dns-multi")},
	{node: dnsMulti, // 同一个名字解出多台，其中一台是坏的 —— 时好时坏最省钱的解释
		by: map[string]move{dnsNXDomain: stop("cause-name-missing")},
		decide: func(st *treeState, code string, vals map[string]any) move {
			if code != dnsResolved {
				return to("clock")
			}
			arr, ok := dig(vals, "values.answers")
			if a, ok2 := arr.([]any); ok && ok2 && len(a) > 1 {
				return stop("cause-round-robin-bad")
			}
			return to("clock")
		}},
	{node: nTime,
		by: map[string]move{
			timeDisagree: stop("cause-clock-disagree"),
			timeWayOff:   stop("cause-clock-way-off"),
		},
		other: end()},
}}

// planCert 证书报错 / HTTPS 打不开。
//
// ★★ 这棵树里最值钱的一步是「先问时间再下结论」：证书报「已过期」时，
//
//	真凶常常是本机钟偏了（没联网的工控机、CMOS 电池耗尽的盒子）。
//	直接说「证书过期了，去续」会让人白跑一趟 CA，而毛病在自己主机的任务栏上。
var planCert = &treePlan{symptom: symCert, steps: []planStep{
	{node: nDNS, other: to("tcp")},
	{node: nTCP,
		by: map[string]move{
			verdictClosed:   stop("cause-service-closed"),
			verdictFiltered: stop("cause-service-filtered"),
			verdictOpen:     to("tls"),
		},
		other: end()},
	{node: nTLS,
		by: map[string]move{
			certNameMismatch:     stop("cause-cert-name-mismatch"),
			certSelfSigned:       stop("cause-cert-untrusted"),
			certUnknownAuthority: stop("cause-cert-untrusted"),
			certWeakProtocol:     stop("cause-cert-weak-protocol"),
			tlsNotTLS:            stop("cause-not-tls"),
			tlsNoCert:            stop("cause-cert-untrusted"),
			certOK:               end(), // 证书没毛病：这条路上问不出更多，别硬编一个根因
			certExpiringSoon:     end(), // warn，不是「打不开」的原因
			tlsNameUnresolved:    to("dns-multi"),
		},
		// 过期类判定先别下结论 —— 去问时间。
		decide: func(st *treeState, code string, vals map[string]any) move {
			switch code {
			case certExpired, certNotYetValid:
				return to("clock")
			case tlsHandshakeFailed:
				return stop("cause-cert-weak-protocol") // 十有八九是老设备只肯谈 TLS1.0
			}
			return end()
		}},
	{node: dnsMulti,
		by:    map[string]move{dnsNXDomain: stop("cause-name-missing")},
		other: end()},
	{node: nTime,
		decide: func(st *treeState, code string, vals map[string]any) move {
			// 问不到时间源、或者读不出偏移：没有第二把尺子了，只能按证书自己说的下结论。
			off, ok := num(vals, "values.offsetMs")
			if !ok {
				return stop(certOwnWords(st))
			}
			// 偏得离谱，不管证书窗口在哪儿都是钟的锅。
			if code == timeWayOff || (code == timeSkewed && abs(off) > 24*3600*1000) {
				return stop("cause-clock-made-cert-bad")
			}
			if clockMadeCertWindow(st, vals, off) {
				return stop("cause-clock-made-cert-bad")
			}
			return stop(certOwnWords(st))
		}},
}}

// certOwnWords 「那就信证书自己说的」：没生效报没生效，过期报过期。
func certOwnWords(st *treeState) string {
	if st.str("certCode") == certNotYetValid {
		return "cause-cert-not-yet-valid"
	}
	return "cause-cert-expired"
}

// clockMadeCertWindow 判「证书那个时间窗到底是谁不对」。
//
// ★ 必须拿「校准后的此刻」去比证书上写的那个时刻，不能拿本机钟比 ——
//
//	正在被查的那把尺子不能拿来量自己。
//	钟慢到把 notBefore 推过去了、或钟快得越过了 notAfter，都是钟的锅；
//	按时间源算出来的此刻仍在窗口外，那证书说的就是实话。
func clockMadeCertWindow(st *treeState, vals map[string]any, off float64) bool {
	var edge string
	switch st.str("certCode") {
	case certNotYetValid:
		edge = st.str("certNotBefore")
	case certExpired:
		edge = st.str("certNotAfter")
	default:
		return false
	}
	local, ok := digStr(vals, "values.localTime")
	if !ok {
		return false
	}
	t0, err := time.Parse(time.RFC3339, local)
	if err != nil {
		return false
	}
	got, err := time.Parse(time.RFC3339, edge)
	if err != nil {
		return false
	}
	trueNow := t0.Add(time.Duration(off * float64(time.Millisecond)))
	if st.str("certCode") == certNotYetValid {
		return t0.Before(got) && !trueNow.Before(got)
	}
	return t0.After(got) && !trueNow.After(got)
}

// planDeviceDown 一台设备不在线 / 没画面。
var planDeviceDown = &treePlan{symptom: symDeviceDown, steps: []planStep{
	{node: nDNS, other: to("route-target")},
	// ★ 先问「去它走哪条路」：段是从这里来的，没有它就问不出「二层有没有它」。
	{node: nRoutesTo,
		by: map[string]move{
			verdictNoRoute:      stop("cause-no-route-to-target"),
			verdictRouteLocal:   end(), // 那台设备的地址就是本机自己，这棵树上问不出东西
			verdictMultiDefault: to("on-link"),
		},
		other: to("on-link")},
	{node: nOnLink,
		decide: onLinkMove("cause-device-off-link"), // 这段里别的设备都在、就它一个信号没发过：查线、查供电、查它是不是关了
		other:  to("ping")},
	{node: nPing,
		by: map[string]move{verdictUnreachable: stop("cause-target-unreachable")},
		decide: func(st *treeState, code string, vals map[string]any) move {
			switch code {
			case verdictReachable:
				return to("ports")
			case verdictNoReply:
				// 二层问过并且它吭过 —— 设备活着，只是不理 ping（摄像头、NVR 十台九台这样）。
				if strongOnLink(st) {
					return stop("cause-device-no-icmp")
				}
				return to("trace")
			}
			return end()
		}},
	{node: nTrace, other: to("ports")},
	{node: nPorts,
		by: map[string]move{
			scanAllClosed:  stop("cause-device-no-service"),
			scanNoResponse: stop("cause-service-filtered"),
			scanNoRoute:    stop("cause-no-route-to-target"),
			scanSomeOpen:   to("onvif"),
		},
		other: to("onvif")},
	// ★ 地址问不出来，下一步就没东西可问 —— 所以每一档都停在**这一问自己**给的
	//	判定上，而不是走到「缺参数，没问出去」再落一句「每一步都正常」。
	{node: nOnvif,
		by: map[string]move{
			verdictONVIFNoProfile: stop("cause-onvif-no-profile"),
			verdictONVIFAuth:      stop("cause-onvif-auth"),
			verdictONVIFNotOnvif:  stop("cause-port-not-onvif"),
			verdictONVIFFault:     stop("cause-onvif-unsupported"),
			verdictONVIFPartial:   stop("cause-onvif-no-media"),
			verdictONVIFNoRepl:    stop("cause-onvif-silent"),
			verdictONVIFUnreach:   stop("cause-onvif-unreachable"),
		},
		// 问到了身份不等于下一步问得出去：ONVIF 也回 http 那一路的（各家都有），
		//	而下一步只会说 RTSP。放它走过去只会得到「缺参数，没问出去」，
		//	再落一句「每一步都正常」—— 那是把我们问不出来的那一格算成没毛病。
		decide: func(st *treeState, code string, vals map[string]any) move {
			if code == verdictONVIFOK && st.str("url") == "" {
				return stop("cause-onvif-no-media")
			}
			return to("stream")
		},
		other: to("stream")},
	{node: nRTSP,
		by: map[string]move{
			verdictStreamOK:     stop("cause-stream-ok"), // ★ 流在播：那「没画面」是那头的显示侧，不是这台设备
			verdictStreamNoMed:  stop("cause-stream-broken"),
			verdictAuthRequired: stop("cause-stream-auth"),
			verdictNotFound:     stop("cause-stream-missing"),
			// 到这一步前面已经问过「这台活着吗」和「那个口静默还是有声」，所以这两个码各有归属：
			// 连不上 = 那个口不接（和端口扫描看到的静默对上）；接了却不回 RTSP = 端口号 / 协议不对。
			verdictNoResponse:  stop("cause-port-not-rtsp"),
			verdictRTSPUnreach: stop("cause-service-filtered"),
		},
		other: end()},
}}

// dnsMulti 与 nDNS 同一棵树上的第二次解析：★ 这第二次是有目的的 ——
//
//	第一次只想知道「解不解得出」，这次要数**解出几个**，
//	一个好几个地址轮转的名字（DNS 轮询的负载均衡）里混一台坏的，就是「时好时坏」。
var dnsMulti = &treeNode{id: "dns-multi", name: "这个名字解出几台", tool: "net.dns.query",
	args: func(st *treeState) (map[string]any, error) {
		name := st.str("host")
		if name == "" {
			name = defaultProbeDomain
		}
		return map[string]any{"name": name, "type": "A"}, nil
	},
	shows: []string{"values.answers", "values.elapsedMs", "values.server"}}

var mtuNode = &treeNode{id: "mtu", name: "路径 MTU", tool: "net.mtu.path", need: []string{"addr"},
	args: func(st *treeState) (map[string]any, error) {
		return map[string]any{"addr": st.str("addr")}, nil
	},
	shows: []string{"values.pathMtu", "values.suggestion", "values.egress.iface", "values.egress.mtu"}}

func treePlanFor(symptom string) (*treePlan, bool) {
	switch symptom {
	case symNoInternet:
		return planNoInternet, true
	case symHostDown:
		return planHostDown, true
	case symSlow:
		return planSlow, true
	case symFlaky:
		return planFlaky, true
	case symCert:
		return planCert, true
	case symDeviceDown:
		return planDeviceDown, true
	}
	return nil, false
}

// TreePlans 给测试和界面用：六棵树的入口。
func TreePlans() []*treePlan {
	return []*treePlan{planNoInternet, planHostDown, planSlow, planFlaky, planCert, planDeviceDown}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
