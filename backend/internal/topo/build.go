package topo

// 合成逻辑。★ 这一整个文件只有一个入口 Build(in Inputs) Graph，
// 里面全是**对已经拿到的事实做归类**，没有一处去问系统、问网络、开线程。
//
// 画法（每一条都点得出探测名）：
//
//	local ──l2── iface ──l3(v4)── segment(v4 前缀) ──l3(v4)── host/gateway/switch
//	             │
//	             └─l3(v6)─ segment(v6 前缀) ─l3(v6)─ …        ← 同一块双栈网卡是**两条**线
//	iface ──l2── switch                                        ← 只有 LLDP 给得出这种线
//	switch ──l2── host                                         ← 　（它对端是谁写在邻居行里）
//	gateway ─l3/tunnel─ 远处的对端                                ← 只有路由表给得出这种线
//
// ★★ 全程只有一条主线：图上多一个方块、多一根线，都得有人答得出「哪个探测看见的」。
//
//	答不出就不画，改成 blind 里的一句话。这一层最容易写的不是「少画」，
//	是「顺手补一个看起来合理的」：ARP 里有 30 个地址就画台交换机、
//	v6 没路由就拿 v4 的网关凑一条线 —— 那 30 个人里就有一个人会去登那台不存在的交换机。

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"net.yuhox.com/netkit/internal/netaddr"
)

// Build 把事实合成图。★ 输入的顺序**不影响**输出：所有切片进门先按内容排一遍，
// 所有 map 都只在排序之后才参与拼字符串。图上任何一处变化都必须是「事实变了」，
// 不能是「这次 map 转出来的顺序不一样」—— 界面对拍的就是这个。
func Build(in Inputs) Graph {
	hub := in.HubThreshold
	if hub <= 0 {
		hub = DefaultHubThreshold
	}
	b := &builder{
		in:            in,
		hub:           hub,
		nodes:         map[string]*nodeAcc{},
		edges:         map[string]*edgeAcc{},
		byMAC:         map[string]string{},
		byAddr:        map[string]string{},
		ifaces:        sortedIfaces(in.Ifaces),
		neighbors:     sortedNeighbors(in.Neighbors),
		routes:        sortedRoutes(in.Routes),
		ifaceByName:   map[string]Iface{},
		localAddrs:    map[string]string{},
		localPrefixes: map[string]localSeg{},
		ifaceByPrefix: map[string][]string{},
		segEdge:       map[string]*edgeAcc{},
		neighKeys:     map[string]map[string]bool{},
		l2Touch:       map[string]bool{},
		macsPerAddr:   map[string]map[string]bool{},
		defaultGW:     map[string]string{},
		stats:         newStats(),
	}
	for _, ifa := range b.ifaces {
		b.ifaceByName[ifa.Name] = ifa
	}
	b.stats.HubThreshold = hub

	b.local()
	b.ifacesPass()
	b.neighborsPass()
	b.routesPass()
	b.lldpPass()
	b.judge()
	return b.seal()
}

// ── 累加器 ──

// localSeg 本机的一个网段，以及挂在这段上的网卡。
type localSeg struct {
	prefix string
	ifaces []string
	v6     bool
}

type nodeAcc struct {
	id      string
	kind    string
	label   string
	addrs   map[string]bool
	macs    map[string]bool
	ifaces  map[string]bool
	sources map[string]bool
	why     []string
	mtus    []int
	state   string
}

type edgeAcc struct {
	id       string
	from     string
	to       string
	layer    string
	stack    string
	ports    map[string]bool
	evidence []string
	state    string
}

type builder struct {
	in  Inputs
	hub int

	nodes map[string]*nodeAcc
	edges map[string]*edgeAcc

	// 身份索引：MAC 优先、地址退其次。★ 同一台设备被 ARP、路由表、LLDP 各看见一次时，
	// 图上必须是**一个**方块 —— 拆成三个，人就以为网里多了两台设备，
	// 而「两台设备」在这行当里是要去现场数一数的那种结论。
	byMAC  map[string]string
	byAddr map[string]string

	ifaces    []Iface
	neighbors []Neighbor
	routes    []Route

	ifaceByName   map[string]Iface
	localAddrs    map[string]string // 本机地址 → 网卡名
	localPrefixes map[string]localSeg
	ifaceByPrefix map[string][]string // 前缀 → 网卡名
	segEdge       map[string]*edgeAcc // "网卡|前缀|栈" → iface→segment 那根线（路由来补证据用）

	neighKeys   map[string]map[string]bool // 网卡 → 这块口上听见的不同对端
	l2Touch     map[string]bool            // 有 LLDP 二层证据接着的网卡
	macsPerAddr map[string]map[string]bool // 对端地址 → 见过的 MAC（地址冲突用）
	conflicts   []string

	defaultGW map[string]string // 栈 → 默认路由的下一跳
	gwIDs     []string

	codes  []string
	blinds []string
	stats  *Stats
}

func newStats() *Stats {
	return &Stats{
		KindCounts:       map[string]int{},
		LayerCounts:      map[string]int{},
		StackCounts:      map[string]int{},
		NeighborsByIface: map[string]int{},
	}
}

// ── 节点与线 ──

// node 取（或建）一个节点。★ 已存在时不重置 kind/label：类型只往**证据更强**的那一档升
// （host → gateway → switch），名字只在原来是空的时候才补。
func (b *builder) node(id, kind, label string) *nodeAcc {
	n := b.nodes[id]
	if n == nil {
		n = &nodeAcc{id: id, kind: kind, label: label,
			addrs: map[string]bool{}, macs: map[string]bool{}, ifaces: map[string]bool{},
			sources: map[string]bool{}}
		b.nodes[id] = n
		return n
	}
	if kindRank[kind] > kindRank[n.kind] {
		n.kind = kind
	}
	if n.label == "" || n.label == "未命名" {
		n.label = label
	}
	return n
}

func (b *builder) has(id string) bool { return b.nodes[id] != nil }

func (n *nodeAcc) add(src string) {
	if s := strings.TrimSpace(src); s != "" {
		n.sources[s] = true
	}
}

func (n *nodeAcc) whyf(format string, a ...any) {
	n.why = append(n.why, fmt.Sprintf(format, a...))
}

// blindf 记一句「图上这一块是空的，以及为什么空」。
//
// ★★ 这是这个包唯一允许的「什么都没画」的出口。凡是探测看不见、而图上那一格看起来
//
//	像正常（空白 = 那里没有东西）的地方，都必须在这里留一句话，
//	否则读图的人会把「没证据」当成「没设备」——那种错法是查不出来的，
//	因为他会顺着我们的沉默去查一个根本不存在的东西。
func (b *builder) blindf(format string, a ...any) {
	b.blinds = append(b.blinds, fmt.Sprintf(format, a...))
}

// conflictf 记一处「两个探测说的对不上」。
//
// ★ 矛盾只有一份（b.conflicts），stats.conflicts 在收口时从它生成 ——
//
//	两处各存一遍迟早对不上，而对不上的表现是「blind 里说了三条、计数那一格写 2」。
func (b *builder) conflictf(format string, a ...any) {
	b.conflicts = append(b.conflicts, fmt.Sprintf(format, a...))
}

func (n *nodeAcc) setState(s string) {
	if stateRank(s) >= stateRank(n.state) {
		n.state = s
	}
}

// link 连一根线。★ 两端必须已经在图上 —— 一根连着不存在节点的线，
// 画布要么画歪、要么直接画不出来，那种错比少画一根线难查得多。
// 端口/网段名这类「我们只知道字符串、没有节点」的一端，一律先落成节点再连。
func (b *builder) link(from, to, layer, stack string, ports []string, evidence []string, state string) *edgeAcc {
	if from == "" || to == "" || from == to {
		return nil
	}
	if !b.has(from) || !b.has(to) {
		b.blindf("有一条 %s 线本该连 %s ↔ %s，可图上没有这一端 —— 这条线没画（宁可少一根线，也不画一个悬空的端点）",
			layer, from, to)
		return nil
	}
	ps := sortedSet(nil, ports)
	id := fmt.Sprintf("%s|%s|%s|%s|%s", layer, stack, from, to, strings.Join(ps, ","))
	e := b.edges[id]
	if e == nil {
		e = &edgeAcc{id: id, from: from, to: to, layer: layer, stack: stack,
			ports: map[string]bool{}, evidence: nil}
		for _, p := range ps {
			e.ports[p] = true
		}
		b.edges[id] = e
	}
	e.addEvidence(evidence...)
	e.setState(state)
	return e
}

func (e *edgeAcc) addEvidence(list ...string) {
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" && !containsStr(e.evidence, s) {
			e.evidence = append(e.evidence, s)
		}
	}
	sort.Strings(e.evidence)
}

func (e *edgeAcc) setState(s string) {
	if s == "" {
		return
	}
	if stateRank(s) >= stateRank(e.state) {
		e.state = s
	}
}

// ifaceEnd 把「某个网卡」换成图上真实存在的那个端点。
//
// ★ 网卡名对不上任何一块读到的网卡是**常事**（Windows 的路由表给的是 InterfaceAlias、
//
//	邻居表给的是另一种写法，或者这块口在两次探测之间被拔了）。
//	这时候不许凭空造一个 iface 节点（那是我们编的口），退到本机这一头，并把这件事写进线里。
func (b *builder) ifaceEnd(name string) (string, string) {
	if name == "" {
		return "local", ""
	}
	if id := "iface:" + name; b.has(id) {
		return id, name
	}
	return "local", name
}

// ── 本机与网卡 ──

func (b *builder) local() {
	label := strings.TrimSpace(b.in.LocalName)
	if label == "" {
		// ★ 没问到名字就退成「本机」这个**角色**词。不许拿网卡上某个地址当名字：
		// 那台机器改地址之后，图上这个方块的名字就跟着变了，而它一直是同一台机器。
		label = "本机"
	}
	n := b.node("local", KindLocal, label)
	n.add(srcInterfaces)
	n.whyf("这台机器本身：net.interfaces 枚举出来的 %d 块网卡都挂在它身上", len(b.ifaces))
}

func (b *builder) ifacesPass() {
	byName := make(map[string]Iface, len(b.ifaces))
	for _, ifa := range b.ifaces {
		byName[ifa.Name] = ifa
	}
	for _, ifa := range b.ifaces {
		if ifa.Loop {
			// ★ 回环不是拓扑：它没有对端、不接任何网。画出来就是一个谁都认不出来的方块，
			//	还正好踩中 topo-island 的判据（没邻居、没路由）。
			//	但「图上少了一块网卡」不能悄悄发生，所以记一笔。
			b.stats.LoopbackSkipped = append(b.stats.LoopbackSkipped, ifa.Name)
			b.blindf("net.interfaces 里的回环网卡 %s 没画：回环不在拓扑上（127.0.0.1、::1 都不是对端）", ifa.Name)
			continue
		}
		// ★★ 桥的成员口折进桥那一头（macOS 上那三块 en1/en2/en3 挂在 bridge0 下面，
		//	自己一个地址都没有，单独立方块就是「这台机器怎么有三个没接线的口」）。
		//	三条硬条件，少一条都不折：
		//	  ① parent 探测给了（问不到 = 不折，Windows 那条现在就没实现）；
		//	  ② 父设备自己也在 net.interfaces 里（不许替我们没见过的东西造一个方块）；
		//	  ③ 这块成员口**没有可用地址**（有地址就说明它还在独立干活，
		//	     比如 Internet Sharing 那块共享出来的口 —— 折掉它就等于把人正在用的口藏了）。
		if p, ok := byName[ifa.Parent]; ok && ifa.Parent != "" && !hasUsableAddr(ifa) {
			b.foldMember(ifa, p)
			continue
		}
		id := "iface:" + ifa.Name
		n := b.node(id, KindIface, orNone3(ifa.Name, "#"+strconv.Itoa(ifa.Index), ""))
		if ifa.Parent != "" {
			if _, ok := byName[ifa.Parent]; ok {
				n.whyf("这块口同时是 %s 的成员口（net.interfaces 的 parent 字段）"+
					"，但它自己带着可用地址，所以没有折进去 —— 它还独立收发", ifa.Parent)
			}
		}
		n.ifaces[ifa.Name] = true
		n.mtus = append(n.mtus, ifa.MTU)
		n.state = ifaceState(ifa)
		n.add(srcInterfaces)
		n.whyf("net.interfaces 读到的一块网卡：%s（%s，%s）", orNone(ifa.Name), mediaWord(ifa), n.state)
		if mac := normalizeMAC(ifa.MAC); mac != "" {
			n.macs[mac] = true
			if prev, ok := b.byMAC[mac]; ok && prev != id {
				// ★ 两块网卡一个 MAC：可能是绑定/bond/虚拟化（正常），也可能是读重了。
				//	两种都不许我们替人挑一块，所以点出来。
				b.conflictf("MAC %s 同时出现在 %s 与 %s 上（net.interfaces）—— 这两块口是不是同一个东西要人核",
					mac, prev, id)
			}
			b.byMAC[mac] = id
		}
		for _, a := range ifa.Addrs {
			ip := bareIP(a.IP)
			if ip == "" {
				continue
			}
			n.addrs[showAddr(ip, a.Zone)] = true
			if own, seen := b.localAddrs[ip]; seen && own != ifa.Name {
				b.conflictf("地址 %s 同时配在 %s 与 %s 上（net.interfaces）—— 同一个地址被探测到属于两块网卡，"+
					"经过这一段的线到底走哪块口说不准", ip, own, ifa.Name)
			}
			b.localAddrs[ip] = ifa.Name
			p, ok := prefixOfAddr(a.CIDR)
			if !ok || !usableScope(a.Scope) {
				continue
			}
			b.segment(ifa, p)
		}
		b.link("local", id, LayerL2, "", []string{ifa.Name},
			[]string{fmt.Sprintf("net.interfaces: %s（index %d，%s）挂在这台机器上",
				orNone(ifa.Name), ifa.Index, mediaWord(ifa))},
			n.state)
	}
}

// segment 建出（或补上）一个网段节点，并连上 iface→segment 那根三层线。
//
// ★★ 一块**双栈**网卡在这里天然生成两根线（栈不同、网段节点也不同），
//
//	这正是 docs/设计.md:255 那一行要的：「一个节点可以同时挂 v4 和 v6 的边，
//	线上要能看出这条走的是哪一栈」。合成一根线的代价很具体：
//	v6 半条链路坏掉（有地址、没路由、RA 是别人发的）在图上和 v4 一模一样，
//	而现场那种病的表现是「网很慢」不是「网不通」，人根本不会想到去查 v6。
//
// ★ 链路本地（fe80::/64、169.254/16）**不建节点**：每块网卡都是 fe80::/64，
//
//	拿它当网段会把两块毫不相干的口合成同一个方块。
//	地址本身照样留在网卡节点上（那是有用的事实，见 docs/设计.md「不许藏 fe80」），
//	只是不拿它当拓扑容器。
func (b *builder) segment(ifa Iface, p netip.Prefix) {
	key := p.String()
	stack := StackV4
	if p.Addr().Is6() {
		stack = StackV6
	}
	id := "segment:" + key
	seg := b.node(id, KindSegment, key)
	seg.addrs[key] = true
	seg.ifaces[ifa.Name] = true
	seg.mtus = append(seg.mtus, ifa.MTU)
	seg.add(srcInterfaces)
	seg.whyf("本机网卡 %s 上的地址带这个前缀（net.interfaces）", orNone(ifa.Name))

	cidrs := make([]string, 0, 2)
	for _, a := range ifa.Addrs {
		if pp, ok := prefixOfAddr(a.CIDR); ok && pp.String() == key {
			cidrs = append(cidrs, a.CIDR)
		}
	}
	e := b.link("iface:"+ifa.Name, id, LayerL3, stack, []string{ifa.Name},
		[]string{fmt.Sprintf("net.interfaces: %s 上的 %s 落在 %s",
			orNone(ifa.Name), strings.Join(cidrs, "、"), key)},
		ifaceState(ifa))
	if e != nil {
		b.segEdge[ifa.Name+"|"+key+"|"+stack] = e
	}
	b.ifaceByPrefix[key] = appendUnique(b.ifaceByPrefix[key], ifa.Name)
	ls := b.localPrefixes[key]
	ls.prefix = key
	ls.ifaces = appendUnique(ls.ifaces, ifa.Name)
	ls.v6 = p.Addr().Is6()
	b.localPrefixes[key] = ls
}

// ── 邻居表：这个网里都有谁 ──

// foldMember 把一块**没有可用地址**的成员口折进它父设备（桥）那一个方块。
//
// ★ 折的是方块，不是事实：这块口的 MAC 照样进身份索引（否则邻居表里认到它 MAC 的
//
//	那一行会被画成一台陌生设备）、它那几个 fe80 照样挂在父口节点上写明是哪块口的、
//	MTU 与来源照记，而「en1→bridge0」单独进 stats.membersFolded 给界面列一遍 ——
//	现场要查的正是「线到底插在 en1 还是 en2」，折进桥不等于这块口不存在。
//
// ★ 和父口同 MAC **不算冲突**：桥/VLAN 就是把父口的以太网地址复制给成员
//
//	（macOS ifconfig 手册 vlandev 那一节明写 assigned a copy of the parent's
//	ethernet address），为这个弹一句「要人核」是纯噪音。
func (b *builder) foldMember(ifa, parent Iface) {
	p := b.node("iface:"+parent.Name, KindIface,
		orNone3(parent.Name, "#"+strconv.Itoa(parent.Index), ""))
	p.ifaces[ifa.Name] = true
	p.mtus = append(p.mtus, ifa.MTU)
	p.add(srcInterfaces)
	p.whyf("%s 折在 %s 下面（net.interfaces 给的桥成员关系）：%s，%s",
		orNone(ifa.Name), orNone(parent.Name), mediaWord(ifa), ifaceState(ifa))
	b.stats.MembersFolded = append(b.stats.MembersFolded, orNone(ifa.Name)+"→"+orNone(parent.Name))
	for _, a := range ifa.Addrs {
		ip := bareIP(a.IP)
		if ip == "" {
			continue
		}
		p.addrs[showAddr(ip, a.Zone)] = true
		if own, seen := b.localAddrs[ip]; !seen || own == ifa.Name {
			b.localAddrs[ip] = ifa.Name
		}
	}
	if mac := normalizeMAC(ifa.MAC); mac != "" {
		p.macs[mac] = true
		if prev, ok := b.byMAC[mac]; ok && prev != p.id && mac != normalizeMAC(parent.MAC) {
			b.conflictf("MAC %s 同时出现在 %s 与 %s 上（net.interfaces）—— 这两块口是不是同一个东西要人核",
				mac, prev, orNone(ifa.Name))
		}
		if _, ok := b.byMAC[mac]; !ok {
			b.byMAC[mac] = p.id
		}
	}
}

// ── 邻居表：这个网里都有谁 ──

// neighborsPass 把 ARP / NDP 的表项变成对端节点与三层线。
//
// ★★ ARP 能证明的是「这个地址在这块口上被听到过」，**证明不了线怎么接的**。
//
//	所以这里只生成 l3 线，一根 l2 都不生成 —— 一根 l2 线要有 LLDP 才画得出来。
//	把「同网段」画成「直接连线」就是把一台不存在的设备从图上抹掉了。
func (b *builder) neighborsPass() {
	for _, nb := range b.neighbors {
		src := orNone2(nb.Source, srcNeighbors)
		ip := bareIP(nb.Addr)
		if ip == "" {
			b.blindf("%s 里有一条 %q 解不出地址（在 %s 上），这一条没画进图 —— 是**我们读不懂**，不是它不存在",
				src, nb.Addr, orNone(nb.Iface))
			continue
		}
		mac := normalizeMAC(nb.MAC)
		if mac != "" {
			m := b.macsPerAddr[ip]
			if m == nil {
				m = map[string]bool{}
				b.macsPerAddr[ip] = m
			}
			m[mac] = true
		}
		stack := StackV4
		if nb.Family == "ipv6" || strings.Contains(ip, ":") {
			stack = StackV6
		}

		if own, isOwn := b.localAddrs[ip]; isOwn {
			// ★ 邻居表里出现**本机自己的地址**：要么有别的设备在跟本机抢这个地址（现场最要命
			//	的一类，两台设备同一个管理地址），要么是本机自己在应答。两种都不许画成对端 ——
			//	画了就是凭空多一台设备，而人会去登它。
			if mac != "" && b.ifaceMAC(own) != "" && b.ifaceMAC(own) != mac {
				b.conflictf("地址 %s 配在本机 %s 上，可 %s 上听见它对应 MAC %s（本机 MAC 是 %s）—— "+
					"另一个 MAC 也在应答同一个地址，这是地址冲突", ip, own, orNone(nb.Iface), mac, b.ifaceMAC(own))
			} else {
				b.blindf("%s 上看见本机自己的地址 %s（%s）—— 没画成对端：这多半是地址冲突或本机在应答自己",
					orNone(nb.Iface), ip, src)
			}
			continue
		}
		if mac != "" {
			if id, ok := b.byMAC[mac]; ok && strings.HasPrefix(id, "iface:") {
				// 同一个 MAC 是别处的**本机网卡**（bond、虚拟化）：不画对端，只记一句。
				b.blindf("%s 上听见的 MAC %s 就是本机网卡 %s 自己（%s）—— 没画成对端设备",
					orNone(nb.Iface), mac, strings.TrimPrefix(id, "iface:"), src)
				continue
			}
		}

		key := ip
		if mac != "" {
			key = mac
		}
		if nb.Iface != "" {
			m := b.neighKeys[nb.Iface]
			if m == nil {
				m = map[string]bool{}
				b.neighKeys[nb.Iface] = m
			}
			m[key] = true // ★ 按 MAC 去重：一台设备可能有三个地址，按行数会把一台数成三台
		}

		_, segPrefix := b.segmentFor(ip)
		if mac == "" && segPrefix == "" {
			// ★ 没有 MAC 的表项（incomplete、或者这个平台读不到 MAC），又不在本机任何网段里：
			//	只知道「有人说过这个地址」，是哪台设备、在哪段都不知道。画出去是一根悬空
			//	且认不出的线，所以只坦白、不画。
			b.blindf("%s 上有一条 %s 没有 MAC（%s，状态 %s），也不在本机任何网段里 —— 这一条没画成对端：连是哪台设备都不知道",
				orNone(nb.Iface), ip, src, orNone(nb.State))
			continue
		}

		p := b.peer(mac, ip, nb.Iface, KindHost, src)
		p.addrs[ip] = true
		if mac != "" {
			p.macs[mac] = true
		}
		p.setState(neighState(nb.State))
		ev := []string{fmt.Sprintf("%s: %s 在 %s 上被听见（MAC %s，状态 %s）",
			src, ip, orNone(nb.Iface), orNone(mac), orNone(nb.State))}
		switch {
		case segPrefix != "":
			b.link("segment:"+segPrefix, p.id, LayerL3, stack, []string{nb.Iface}, ev, p.state)
		case nb.Iface != "":
			// ★ 这个邻居**不在本机任何网段里**（代理 ARP、路由式网关、表里留下的老表项都这样）。
			//	不许给它造一个网段 —— 那个段是我们编的。线只连到「从哪块口听见的」这一头，
			//	并且把越段这件事写进证据里。
			from, _ := b.ifaceEnd(nb.Iface)
			b.link(from, p.id, LayerL3, stack, []string{nb.Iface},
				append(ev, "★ 这个地址不在本机任何网段里（net.interfaces 的前缀没有一条盖住它），所以没挂进网段"),
				p.state)
		default:
			b.blindf("%s 上听见的 %s 没给出网卡，也不在本机任何网段里 —— 这根线不知道该从哪一头连，没画", src, ip)
		}
	}

	for _, ip := range sortedAddrKeys(b.macsPerAddr) {
		macs := sortedKeysBool(b.macsPerAddr[ip])
		if len(macs) > 1 {
			b.conflictf("地址 %s 在邻居表里对应过 %d 个不同的 MAC（%s）—— 有两台设备在用同一个地址，"+
				"图上把它合成一个方块是不对的", ip, len(macs), strings.Join(macs, "、"))
		}
	}
}

// peer 取（或建）一个对端节点。
func (b *builder) peer(mac, ip, iface, kind, src string) *nodeAcc {
	m := normalizeMAC(mac)
	ip = bareIP(ip)
	id := ""
	if m != "" {
		id = b.byMAC[m]
	}
	if id == "" && ip != "" {
		id = b.byAddr[ip]
	}
	if id == "" {
		switch {
		case m != "":
			id = "mac:" + m
		case ip != "":
			id = "addr:" + ip
		default:
			id = "peer:unknown:" + iface
		}
	}
	n := b.node(id, kind, orNone3(ip, m, "一台设备"))
	if m != "" {
		b.byMAC[m] = n.id
	}
	if ip != "" {
		b.byAddr[ip] = n.id
	}
	if iface != "" {
		n.ifaces[iface] = true
	}
	n.add(src)
	return n
}

// ── 路由表：上游与去路 ──

// routesPass 把路由表变成「上游」方块与去往外部的线。
//
// ★★ 路由表证明的是**这台机器打算怎么走**，一个字都没证明走得到。
//
//	所以这一段生成的线状态一律 unknown：表里有一条默认路由就在图上画一根绿线，
//	是这类工具最顺手也最要命的错 —— 网关换了、上游黑洞、下一跳早就不在了，
//	在路由表里都长得一模一样。
func (b *builder) routesPass() {
	for _, r := range b.routes {
		gw := bareIP(r.Gateway)
		p, ok := prefixOfAddr(r.Destination)
		stack := StackV4
		switch {
		case ok && p.Addr().Is6():
			stack = StackV6
		case r.Family == "ipv6":
			stack = StackV6
		}
		if gw == "" {
			// 直连路由：它证明的正是「这段在本机上」，那根线 iface→segment 已经画过了。
			// 这里只做一件事：把 net.routes 也加成它的证据 ——
			// 两个独立探测（网卡地址 / 路由表）说同一件事，这根线就更硬。
			if ok && r.Iface != "" {
				key := r.Iface + "|" + p.String() + "|" + stack
				if e := b.segEdge[key]; e != nil {
					e.addEvidence(fmt.Sprintf("net.routes: %s 直连在 %s 上（本段的路由，不出本网）",
						p.String(), r.Iface))
				}
			}
			continue
		}
		layer := LayerL3
		if isTunnelIface(r.Iface) {
			// ★ 同一句「去往 X 走 G」，从 utun/wg 出去和从网线出去是两种画法
			//	（一根是封装出来的）。判据是出接口的名字，而 netif 那一栏在问不到系统时
			//	是按名字猜的（KindSrc=name）—— 所以这里只改**线型**，不据它说
			//	「这条隧道是通的」，那要另外探测。
			layer = LayerTunnel
		}
		n := b.peer("", gw, r.Iface, KindGateway, srcRoutes)
		n.addrs[gw] = true
		n.whyf("net.routes 里 %s 的下一跳是它（dev %s，metric %d）",
			orNone(r.Destination), orNone(r.Iface), r.Metric)
		if !containsStr(b.gwIDs, n.id) {
			b.gwIDs = append(b.gwIDs, n.id)
		}
		if ok && p.Bits() == 0 {
			b.defaultGW[stack] = gw
			n.whyf("它是 %s 默认路由的下一跳", stack)
		}
		// ★ 只有默认路由的下一跳才填 defaultGW：有一条去 10.0.0.0/8 的静态路由
		//	不等于「这台出得去」，拿它当网关会把 topo-no-gateway 这个真故障压掉。
		from, used := b.ifaceEnd(r.Iface)
		ev := []string{fmt.Sprintf("net.routes: 去往 %s 走下一跳 %s（dev %s，%s 族，metric %d）",
			orNone(r.Destination), gw, orNone(r.Iface), orNone(r.Family), r.Metric)}
		if _, segPrefix := b.segmentFor(gw); segPrefix != "" {
			from = "segment:" + segPrefix
		}
		if used != "" && !b.has("iface:"+used) {
			ev = append(ev, fmt.Sprintf("net.routes 给的接口 %s 在 net.interfaces 里没有对应网卡，"+
				"所以这一头连到本机（不替它编一块口）", used))
		}
		b.link(from, n.id, layer, stack, []string{r.Iface}, ev, StateUnknown)
	}
}

// ── LLDP：唯一画得出二层的探测 ──

// lldpPass 把一台设备的 LLDP 本地系统数据 + 邻居表变成「交换机方块 + 二层的线」。
//
// ★ 为什么只有它能画 l2：lldpRemTable 每一行都是「我（这台设备）的某个口上
//
//	听见了它（对端自报的身份）」—— 这是**设备自己交代的**相邻关系。
//	ARP、路由、ping 全都在这件事的上层，谁都给不出「这根线另一头是谁」。
//	（另有一条纪律：这棵树里没有 CDP，只发 CDP 的设备在这里就是不存在。
//	所以「LLDP 没读到」永远翻不成「没有对端」，只翻成「看不见」。）
func (b *builder) lldpPass() {
	l := b.in.LLDP
	if l.Unavailable != "" {
		b.blindf("二层看不见：%s", l.Unavailable)
		return
	}
	rows := append([]LLDPNeighbor(nil), l.Neighbors...)
	sort.Slice(rows, func(i, j int) bool { return lldpRowLess(rows[i], rows[j]) })

	dev := l.Device
	devID, devOK := b.deviceNode(dev, len(rows))
	if len(rows) == 0 {
		b.blindf("问了 %s 的 LLDP 邻居表（net.snmp.lldp），它一条邻居都没给。"+
			"★ 这一条不等于「那些口上没接东西」：对端可能只发 CDP、可能把 LLDP 关了、也可能真没接。"+
			"三种下一步完全不同，图上因此仍然没有二层的线。", orNone(dev.SysName))
		return
	}
	if !devOK {
		return
	}
	for _, row := range rows {
		mac := normalizeMAC(row.ChassisID)
		addrs := make([]string, 0, len(row.Addrs))
		for _, a := range row.Addrs {
			if ip := bareIP(a); ip != "" {
				addrs = append(addrs, ip)
			}
		}
		sort.Strings(addrs)

		// 这一行说的是**谁**：先按 MAC、再按管理地址、最后才按自述名字对。
		target, ours := b.resolveNeighbor(mac, addrs, row.SysName)
		if target == nil {
			id := ""
			switch {
			case mac != "":
				id = "mac:" + mac
			case len(addrs) > 0:
				id = "addr:" + addrs[0]
			default:
				// ★ 这行只有「哪个口 + 它自己说的名字」：那就把这个身份绑在 LLDP 那一行上。
				//	不是编的 —— 界面上点开这根线看见的还是这一条原始记录。
				id = "lldp:" + orNone(dev.SysName) + ":" + strconv.Itoa(row.PortNum) + ":" +
					orNone(row.ChassisID) + ":" + orNone(row.SysName)
			}
			target = b.node(id, kindForCaps(row.Caps), lldpLabel(row.SysName, row.ChassisID, addrs))
			if mac != "" {
				target.macs[mac] = true
				b.byMAC[mac] = target.id
			}
			for _, a := range addrs {
				target.addrs[a] = true
				b.byAddr[a] = target.id
			}
			target.whyf("net.snmp.lldp 在 %s 的口 %s 上听见了它：机箱标识 %s、自述 %s、能力 %s",
				orNone(dev.SysName), orNone(row.LocalPort), orNone(row.ChassisID),
				orNone(row.SysName), orNone(joinCaps(row.Caps)))
		}
		if ours != "" {
			// 这一行说的是**我们自己**：这根二层的线就从这块网卡连到那台设备的这个口。
			// （resolveNeighbor 只在图上真有这块网卡时才返回 ours。）
			if !b.has("iface:" + ours) {
				b.blindf("net.snmp.lldp 有一条邻居对上了本机网卡 %s，可 net.interfaces 里没有这块口 "+
					"（两次探测之间它被拔了，或者名字写法不一致）—— 这根二层的线没画", ours)
				ours = ""
			} else {
				target.ifaces[ours] = true
				b.l2Touch[ours] = true
			}
		}
		state := StateUp
		note := ""
		if row.Aging {
			// ★ 这一趟观测里这个口的邻居老化过 —— 这一行**会消失**。画成 up
			//	就是把一根在抖的线画成好的；这种线正是「偶尔卡一下」那种故障的现场。
			state = StateUnknown
			note = "；★ 这个口的邻居在刚才那段观测里老化过，这一行会消失（对端停发 LLDP / TTL 太短 / 链路在抖）"
		}
		ports := []string{row.LocalPort, row.PortID}
		if ours != "" {
			ports = append(ports, ours)
		}
		ev := []string{fmt.Sprintf("net.snmp.lldp: %s 的口 %s（lldpRemLocalPortNum %d）上报了这条邻居：%s%s",
			orNone(dev.SysName), orNone(row.LocalPort), row.PortNum, rowBrief(row), note)}
		from, to := target.id, devID
		if ours != "" {
			from, to = "iface:"+ours, devID // 本机这一头排在前面：图上从左到右就是本机 → 交换机
		}
		if from == to {
			b.blindf("net.snmp.lldp 在 %s 的口 %s 上报的邻居对上了它自己（%s）—— 这根自环线没画，"+
				"去现场看一眼这个口接的是什么", orNone(dev.SysName), orNone(row.LocalPort), orNone(row.ChassisID))
			continue
		}
		b.link(from, to, LayerL2, "", ports, ev, state)
	}
}

// deviceNode 被问的那台设备自己的方块。
//
// ★ 类型是 switch 不是 host：这台设备**自己**在 lldpLocSysName / lldpLocChassisId
//
//	里交代了身份，而且它维护着 LLDP-MIB —— 这是「它是网络设备」的直接证据。
func (b *builder) deviceNode(dev LLDPDevice, rows int) (string, bool) {
	addrs := make([]string, 0, len(dev.Addrs))
	for _, a := range dev.Addrs {
		if ip := bareIP(a); ip != "" {
			addrs = append(addrs, ip)
		}
	}
	sort.Strings(addrs)
	mac := normalizeMAC(dev.ChassisID)
	id := ""
	switch {
	case mac != "":
		id = "mac:" + mac
	case len(addrs) > 0:
		id = "addr:" + addrs[0]
	case dev.SysName != "":
		id = "lldp:dev:" + dev.SysName
	default:
		b.blindf("net.snmp.lldp 回了话，可 lldpLocSysName / lldpLocChassisId 都没给 —— "+
			"这台设备在图上没有身份，不画方块（一个没有任何标识的方块就是装饰）。"+
			"它的 %d 条邻居行因此也连不出去，只记在这里", rows)
		return "", false
	}
	n := b.node(id, KindSwitch, lldpLabel(dev.SysName, dev.ChassisID, addrs))
	n.add(srcSNMPLLDP)
	if mac != "" {
		n.macs[mac] = true
		b.byMAC[mac] = n.id
	}
	for _, a := range addrs {
		n.addrs[a] = true
		b.byAddr[a] = n.id
	}
	n.whyf("net.snmp.lldp 读它的 lldpLocSysName / lldpLocChassisId：这台设备自己说它是网络设备（能力 %s）",
		orNone(joinCaps(dev.Caps)))
	if len(dev.PortNames) > 0 {
		ports := append([]string(nil), dev.PortNames...)
		sort.Strings(ports)
		n.whyf("它自己写在 lldpLocPortTable 里的口名：%s", strings.Join(ports, "、"))
	}
	if len(addrs) > 0 {
		b.linkReachable(n, addrs[0])
	}
	return id, true
}

// linkReachable 把一个只有管理地址的对端挂到三层上去。
//
// ★★ 挂在哪一头是由**本机路由表**算的（纯计算，不再发探测）：
//
//	地址在我们某个前缀里 → 挂网段；要经过下一跳 → 挂那个下一跳。
//	后者这一条最容易写错：跨网段的管理地址被顺手连到本机网卡上，
//	图上就变成「这台交换机插在我的口上」，而它可能在城域另一头。
func (b *builder) linkReachable(n *nodeAcc, ip string) {
	stack := StackV4
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() {
		stack = StackV6
	}
	_, segPrefix := b.segmentFor(ip)
	r, ok := b.routeFor(ip)
	iface := r.Iface
	if ok && r.Gateway != "" && bareIP(r.Gateway) != ip {
		g := b.peer("", r.Gateway, iface, KindGateway, srcRoutes)
		g.addrs[bareIP(r.Gateway)] = true
		b.link(g.id, n.id, layerForIface(iface), stack, []string{iface},
			[]string{
				fmt.Sprintf("net.routes: 去往 %s 要先交给下一跳 %s（dev %s）", ip, r.Gateway, orNone(iface)),
				n.srcNote("net.snmp.lldp"),
			}, StateUnknown)
		return
	}
	ev := []string{fmt.Sprintf("net.snmp.lldp: 这次就是问它的 %s 读到的（lldpLoc*）", ip)}
	if ok && iface != "" {
		ev = append(ev, fmt.Sprintf("net.routes: 去往 %s 从 %s 出去，是本网直连", ip, iface))
	}
	from := "local"
	switch {
	case segPrefix != "":
		from = "segment:" + segPrefix
	case iface != "" && b.has("iface:"+iface):
		from = "iface:" + iface
	}
	b.link(from, n.id, layerForIface(iface), stack, []string{iface}, ev, StateUnknown)
}

// routeFor 按表算「去往这个地址该走哪条」（最长前缀匹配 —— 纯计算，不发探测）。
//
// ★ 规则和各平台一致，也因此和 net.routes 那一张卡的算法同构；
//
//	并列时**不假装比过**：macOS 的表不带度量，这里就按表里的第一条给，
//	而这张图不写「一定走这条」那句话（那是 net.routes 带 dest 时才回答的问题）。
func (b *builder) routeFor(ip string) (Route, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return Route{}, false
	}
	var best Route
	found := false
	for _, r := range b.routes {
		p, err := netip.ParsePrefix(strings.TrimSpace(r.Destination))
		if err != nil {
			continue
		}
		if p.Addr().Is4() != a.Is4() {
			continue // 族必须对上：v4 的目的地永远不许匹配到 v6 的路由上
		}
		if !p.Contains(a) {
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

// resolveNeighbor 一条 LLDP 行对上图上已有的哪个节点。
// 返回 (节点, 本机网卡名)：后者非空表示这一行说的**就是本机**。
func (b *builder) resolveNeighbor(mac string, addrs []string, sysName string) (*nodeAcc, string) {
	if mac != "" {
		if own := b.ifaceByMAC(mac); own != "" {
			if n := b.nodes["iface:"+own]; n != nil {
				return n, own
			}
		}
		if id, ok := b.byMAC[mac]; ok {
			return b.nodes[id], ""
		}
	}
	for _, a := range addrs {
		if own, ok := b.localAddrs[a]; ok {
			if n := b.nodes["iface:"+own]; n != nil {
				return n, own
			}
		}
		if id, ok := b.byAddr[a]; ok {
			return b.nodes[id], ""
		}
	}
	if s := strings.TrimSpace(sysName); s != "" && s == strings.TrimSpace(b.in.LocalName) {
		// ★ 按名字对上本机是**最弱**的一条依据（名字谁都能配，LLDP 里还有个 sysName
		//	是本机的 mDNS 名而不是 hostname 这种情况）。所以只在 MAC 和管理地址都对不上时才用，
		//	并且证据里会写明这一行是靠名字认的。
		if own := b.singleUsableIface(); own != "" {
			if n := b.nodes["iface:"+own]; n != nil {
				// Source 里只放探测名（界面上它是「哪个工具产出了这个方块」的标签），
				// 「靠名字认的」这层可疑写进 why —— 点开节点看得见，标签里不掺假。
				n.add(srcSNMPLLDP)
				n.whyf("net.snmp.lldp 有一条邻居自述 %s，和本机名一样；MAC 和管理地址都对不上，"+
					"所以这一行是**按名字**认成本机的（最弱的一条依据，名字谁都能配）", orNone(sysName))
				return n, own
			}
		}
	}
	return nil, ""
}

// ── 判定 ──

func (b *builder) judge() {
	st := b.stats
	if len(b.nonLoopIfaces()) == 0 {
		// ★ 第一个判，且**只判这一个**：其余七条全建立在「至少有一块口」上，
		// 没口的时候说「没有网关」「没有邻居」都是空话，还会把人指去查路由配置。
		b.codes = append(b.codes, CodeNoIfaces)
		b.blindf("这台机器上没有可画的网卡（只有回环，或者 net.interfaces 一条都没读到）—— " +
			"图上不该有任何方块：每一块网卡、每一根线都没有依据。")
		// ★★ 方块**全部撤掉**，连那台「本机」也撤。留着它的代价很具体：
		//	画布上会出现一个孤零零的方块，人读成「这台机器是好的，只是没测到别的」，
		//	而真实情况是连网卡都没读到（这个平台的读取方式挂了，或者这台压根没插线）。
		//	一张空图 + 一句坦白，胜过一个看起来合理的空图。
		b.nodes = map[string]*nodeAcc{}
		b.edges = map[string]*edgeAcc{}
		for _, g := range b.in.Gaps {
			b.blindf("%s 没做成：%s", orNone(g.Probe), orNone(g.Reason))
		}
		return
	}
	for _, g := range b.in.Gaps {
		b.blindf("%s 没做成：%s —— 图上这一块是**空的**，不是「那里没有东西」", orNone(g.Probe), orNone(g.Reason))
	}
	b.missingProbes()

	// ① 二层看得见吗：只有 LLDP 的邻居行算证据。
	st.L2Confirmed = b.in.LLDP.Unavailable == "" && len(b.in.LLDP.Neighbors) > 0
	if !st.L2Confirmed {
		b.codes = append(b.codes, CodeL2Blind)
		if b.in.LLDP.Unavailable == "" {
			b.blindf("这次没跑 net.snmp.lldp（没给设备地址/团体名，或者压根没问）—— " +
				"图上所有跨设备的连线都是**三层**的：谁用哪根线插在哪个口上，没有任何探测证据。")
		}
	}

	// ② 一块口上邻居太多 → hub 怀疑（**不画交换机**）。
	for _, name := range sortedIfaceNeighborKeys(b.neighKeys) {
		n := len(b.neighKeys[name])
		st.NeighborsByIface[name] = n
		if n > st.MaxNeighbors {
			st.MaxNeighbors = n
		}
		if n >= b.hub && !b.l2Touch[name] {
			b.codes = append(b.codes, CodeHubSuspect)
			st.HubIfaces = append(st.HubIfaces, fmt.Sprintf("%s(%d)", name, n))
			b.blindf("%s 上听见了 %d 个不同邻居（net.neighbors），而这块口没有任何 LLDP 证据 —— "+
				"中间多半有一台非网管交换机、或者一台老 hub。★ 图上**没有画它**：没有任何探测见过它，"+
				"画出来人就去找那台不存在的设备。要坐实就顺着这根线拿 net.snmp.lldp 或 net.snmp.probe "+
				"问那台设备（或者去现场看这个口下面的线到底接到哪儿）。", name, n)
		}
	}

	// ③ 孤岛：链路上是活的、地址也配了，可它什么都够不着。
	for _, ifa := range b.ifaces {
		if ifa.Loop || !hasUsableAddr(ifa) {
			continue // 没配到地址的口不算孤岛：那是「还没配上」，另一件事、另一张卡
		}
		if len(b.neighKeys[ifa.Name]) > 0 || b.reachableVia(ifa.Name) || b.l2Touch[ifa.Name] {
			continue
		}
		st.IslandIfaces = append(st.IslandIfaces, ifa.Name)
		b.codes = append(b.codes, CodeIsland)
		b.blindf("%s 是一块孤岛：net.interfaces 说它是活的、地址也配上了，"+
			"可 net.neighbors 在它上一个邻居都没听见、net.routes 里没有一条经由它出去的非直连路由、"+
			"net.snmp.lldp 也没在任何设备上报告过它 —— 图上它就是一根悬空的线。"+
			"★ 这不是「还没测」：三层能看见的两条路都问过了，都空。查对端有没有上电、线是不是只接了一头。",
			ifa.Name)
	}

	// ④ 上游：图上没有任何一个「下一跳」。
	if len(b.defaultGW) == 0 && len(b.gwIDs) == 0 {
		b.codes = append(b.codes, CodeNoGateway)
		b.blindf("net.routes 里没有任何一条带下一跳的路由 —— 图上没有「上游」这个方块。" +
			"★ 这一条说的不是「上游坏了」，是这台机器压根没往外交：本网打得通、出不了本网，" +
			"查的是这台的路由配置（或它拿到的 DHCP 选项），不是查线。")
	}

	// ⑤ 双栈偏斜：两层各有各的图，合成一张就看不见病了。
	var v4iface, v6iface []string
	for _, ifa := range b.ifaces {
		if ifa.Loop {
			continue
		}
		if hasUsable(ifa, "ipv4") {
			v4iface = append(v4iface, ifa.Name)
		}
		if hasUsable(ifa, "ipv6") {
			v6iface = append(v6iface, ifa.Name)
		}
		if hasUsable(ifa, "ipv4") && hasUsable(ifa, "ipv6") {
			st.DualStack = append(st.DualStack, ifa.Name)
		}
	}
	if len(v4iface) > 0 && len(v6iface) > 0 {
		g4, g6 := b.defaultGW[StackV4], b.defaultGW[StackV6]
		switch {
		case g4 != "" && g6 == "":
			b.skew("v4 有默认路由（下一跳 %s，dev %s），v6 一条默认路由都没有 —— 而两族都有可用地址。"+
				"应用会先试 v6 再回落，表现成「慢」而不是「不通」", g4, b.ifaceOfGW(g4))
		case g6 != "" && g4 == "":
			b.skew("v6 有默认路由（下一跳 %s，dev %s），v4 一条默认路由都没有 —— 而两族都有可用地址",
				g6, b.ifaceOfGW(g6))
		case g4 != "" && g6 != "":
			i4, i6 := b.ifaceOfGW(g4), b.ifaceOfGW(g6)
			if i4 != "" && i6 != "" && i4 != i6 {
				b.skew("v4 的下一跳 %s 从 %s 出去，v6 的下一跳 %s 从 %s 出去 —— 两层走的是不同的口，"+
					"图不能画成同一根上游线", g4, i4, g6, i6)
			}
		}
	}

	// ⑥ 地址/网段矛盾：这块网画不成一个方块。
	if len(b.conflicts) > 0 {
		b.codes = append(b.codes, CodeSegmentConflict)
		for _, c := range b.conflicts {
			b.blindf("网段/地址矛盾：%s", c)
		}
	}

	if len(b.codes) == 0 {
		b.codes = append(b.codes, CodeOK)
	}
}

// missingProbes 把「这次根本没跑的探测」也写成 blind。
//
// ★ 只有收集层明确交代了跑成哪些（Inputs.Probes 非空）才判这一条。
//
//	Probes 空着不判是故意的：拿「没填这个字段」当「什么都没跑」，
//	图上会凭空多出三条坦白 —— 坦白太多和坦白太少一样，会让人不再读 blind。
//	（跑挂了但不算跑成的那些走 Gaps，那条路更准，因为原因带过来了。）
func (b *builder) missingProbes() {
	if len(b.in.Probes) == 0 {
		return
	}
	ran := map[string]bool{}
	for _, p := range b.in.Probes {
		if s := strings.TrimSpace(p); s != "" {
			ran[s] = true
		}
	}
	for _, g := range b.in.Gaps {
		if s := strings.TrimSpace(g.Probe); s != "" {
			ran[s] = true // 报了 Gap 的已经在那儿坦白了，不重复说
		}
	}
	for _, p := range baselineProbes {
		if ran[p] {
			continue
		}
		b.blindf("%s 这次没跑（收集层说跑成的探测里没有它，也没报失败）—— 图上这一块是**空的**，"+
			"不是「那里没有东西」", p)
	}
}

func (b *builder) skew(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	b.stats.Skew = append(b.stats.Skew, msg)
	b.codes = append(b.codes, CodeDualStackSkew)
	b.blindf("双栈拓扑不一致：%s", msg)
}

// ── 判定的辅助查询 ──

func (b *builder) nonLoopIfaces() []Iface {
	var out []Iface
	for _, ifa := range b.ifaces {
		if !ifa.Loop {
			out = append(out, ifa)
		}
	}
	return out
}

// reachableVia 这块口上有没有**非直连**的路由。
//
// ★ 判据里必须把「自己那段」剔掉：每台机器的路由表里都有一条指向自己网段的直连路由，
// 拿它当「有路」等于这一档永远不成立（孤岛那一格永远是绿的）。
func (b *builder) reachableVia(name string) bool {
	for _, r := range b.routes {
		if r.Iface != name {
			continue
		}
		if r.Gateway == "" {
			if p, ok := prefixOfAddr(r.Destination); ok {
				if containsStr(b.ifaceByPrefix[p.String()], name) {
					continue // 本机自己那段
				}
			}
		}
		return true
	}
	return false
}

func (b *builder) ifaceOfGW(gw string) string {
	for _, r := range b.routes {
		if bareIP(r.Gateway) != gw {
			continue
		}
		if p, ok := prefixOfAddr(r.Destination); ok && p.Bits() == 0 {
			return r.Iface
		}
	}
	for _, r := range b.routes {
		if bareIP(r.Gateway) == gw {
			return r.Iface
		}
	}
	return ""
}

func (b *builder) ifaceMAC(name string) string {
	for _, ifa := range b.ifaces {
		if ifa.Name == name {
			return normalizeMAC(ifa.MAC)
		}
	}
	return ""
}

func (b *builder) ifaceByMAC(mac string) string {
	m := normalizeMAC(mac)
	if m == "" {
		return ""
	}
	for _, ifa := range b.ifaces {
		if normalizeMAC(ifa.MAC) == m {
			return ifa.Name
		}
	}
	return ""
}

// singleUsableIface 只有一块口、并且它是活的时候才敢按名字把 LLDP 行认成本机。
func (b *builder) singleUsableIface() string {
	var got []string
	for _, ifa := range b.ifaces {
		if ifa.Loop || !ifa.Up {
			continue
		}
		got = append(got, ifa.Name)
	}
	if len(got) == 1 {
		return got[0]
	}
	return ""
}

// segmentFor 这个地址落在本机哪个网段里；没有就返回空前缀。
func (b *builder) segmentFor(ip string) (localSeg, string) {
	a, err := netip.ParseAddr(bareIP(ip))
	if err != nil {
		return localSeg{}, ""
	}
	a = a.WithZone("")
	for _, key := range sortedSegKeys(b.localPrefixes) {
		p, err := netip.ParsePrefix(key)
		if err != nil {
			continue
		}
		if p.Contains(a) {
			return b.localPrefixes[key], key
		}
	}
	return localSeg{}, ""
}

// ── 收口 ──

func (b *builder) seal() Graph {
	st := b.stats
	nodes := make([]Node, 0, len(b.nodes))
	for _, id := range sortedNodeKeys(b.nodes) {
		n := b.nodes[id]
		st.KindCounts[n.kind]++
		nodes = append(nodes, n.finish(b))
	}
	edges := make([]Edge, 0, len(b.edges))
	for _, id := range sortedEdgeKeys(b.edges) {
		e := b.edges[id]
		st.LayerCounts[e.layer]++
		if e.stack != "" {
			st.StackCounts[e.stack]++
		}
		edges = append(edges, e.finish())
	}
	sort.Strings(st.LoopbackSkipped)
	sort.Strings(st.IslandIfaces)
	sort.Strings(st.HubIfaces)
	sort.Strings(st.DualStack)
	sort.Strings(b.gwIDs)
	st.Conflicts = sortedUnique(b.conflicts)
	st.GatewayIDs = append([]string(nil), b.gwIDs...)
	for _, list := range []*[]string{&st.IslandIfaces, &st.HubIfaces, &st.DualStack,
		&st.LoopbackSkipped, &st.GatewayIDs, &st.Conflicts, &st.Skew} {
		if *list == nil {
			*list = []string{}
		}
	}

	g := Graph{
		Nodes: nodes, Edges: edges,
		Codes: orderCodes(b.codes), Blind: sortedUnique(b.blinds),
		Stats:  *st,
		Ifaces: b.ifaces, Neighbors: b.neighbors, Routes: b.routes,
	}
	if g.Blind == nil {
		g.Blind = []string{}
	}
	if g.Codes == nil {
		g.Codes = []string{CodeOK}
	}
	return g
}

// finish 把累加器收成合同里那个 Node。
//
// ★ stack / state / mtu 全部在这里**算**出来，不在各处手填 ——
// 手填的那份迟早和 addrs / ifaces 对不上，而对不上的表现是界面上一个绿点配一根灰线。
func (n *nodeAcc) finish(b *builder) Node {
	addrs := sortedKeysBool(n.addrs)
	macs := sortedKeysBool(n.macs)
	ifaces := sortedKeysBool(n.ifaces)
	srcs := sortedKeysBool(n.sources)
	if len(srcs) == 0 {
		// ★ Source 空着就等于这个方块没人产出过，那它不该在图上。真到这一步是 bug，
		//	宁可写明来源缺失也别留一个看起来正常的空节点。
		srcs = []string{"unknown"}
	}
	out := Node{
		ID: n.id, Kind: n.kind, Label: orNone3(n.label, n.id, "未命名"),
		Addrs: addrs, MACs: macs, Ifaces: ifaces, Source: srcs,
		Stack: stackOf(addrs), State: n.state, MTU: commonMTU(n.mtus),
	}
	if out.Addrs == nil {
		out.Addrs = []string{}
	}
	if out.MACs == nil {
		out.MACs = []string{}
	}
	if out.Ifaces == nil {
		out.Ifaces = []string{}
	}
	// 状态与 MTU 的推算（只在没被直接填过时才做）。
	switch n.kind {
	case KindSegment, KindLocal:
		if out.State == "" {
			out.State = stateOfIfaces(ifaces, b)
		}
	case KindHost, KindGateway, KindSwitch:
		if out.State == "" {
			// ★ 一个对端一点状态证据都没有时是 unknown，不是 up：
			// 「图上有这个方块」只说明**某个探测听见了它一次**，不说明它现在在。
			out.State = StateUnknown
		}
	}
	if out.State == "" {
		out.State = StateUnknown
	}
	var why []string
	for _, w := range n.why {
		if w = strings.TrimSpace(w); w != "" {
			why = append(why, w)
		}
	}
	if len(why) == 0 {
		why = []string{"这个节点没有任何产出它的说明 —— 见 blind，图上本来不该有它"}
	}
	sort.Strings(why)
	out.Why = strings.Join(why, "；")
	return out
}

func (e *edgeAcc) finish() Edge {
	ports := sortedKeysBool(e.ports)
	out := Edge{
		ID: e.id, From: e.from, To: e.to, Layer: e.layer, Stack: e.stack,
		Ports: ports, Evidence: sortedUnique(e.evidence), State: orNone2(e.state, StateUnknown),
	}
	if out.Ports == nil {
		out.Ports = []string{}
	}
	// ★ Evidence 非空是**合同**，不是风格：一根说不出成分的线就是那张设计稿里
	// 被禁止的「手画示意图」。真到这一步说明上面哪里漏了，宁可写得难看也要留痕。
	if len(out.Evidence) == 0 {
		out.Evidence = []string{"缺少证据（实现缺陷：这条线本不该被画出来）"}
	}
	return out
}

// srcNote 节点上「哪个探测产出了它」那一句。
func (n *nodeAcc) srcNote(src string) string {
	return fmt.Sprintf("%s: %s 是被这个探测读到的对端", src, n.label)
}

// ── 纯函数小工具 ──

const (
	srcInterfaces = "net.interfaces"
	srcNeighbors  = "net.neighbors"
	srcRoutes     = "net.routes"
	srcSNMPLLDP   = "net.snmp.lldp"
)

// ifaceState 从系统给的两个标志位推。
//
// ★ up = 已启用**且**有载波；管理员关着、或者开着但没插线，都算 down。
// 这里没有 unknown 可退：netif 给的就是这两位数，问到什么就是什么。
func ifaceState(ifa Iface) string {
	switch {
	case ifa.Up && ifa.Running:
		return StateUp
	default:
		return StateDown
	}
}

// neighState 邻居表项的状态翻成上/下/不知道。
//
// ★★ 只有「最近真的通过信」的那几种才敢画成 up。
//
//	STALE 是「上次通过信、现在不知道」（v6 的表项放一天也算 STALE）；
//	PERMANENT / 静态是**配置**，配置一条不说明对端活着；
//	FAILED / INCOMPLETE 是「刚问过没人应」→ down。
//	把 STALE 一律当 up，图上就永远是一片绿，而「设备偶尔掉线」这类病恰好在里面。
func neighState(s string) string {
	v := strings.ToUpper(strings.TrimSpace(s))
	switch {
	case v == "":
		return StateUnknown
	case strings.Contains(v, "REACHABLE"), strings.Contains(v, "DELAY"), strings.Contains(v, "PROBE"):
		return StateUp
	case strings.Contains(v, "FAILED"), strings.Contains(v, "INCOMPLETE"), strings.Contains(v, "NO-RESPONSE"):
		return StateDown
	default:
		return StateUnknown // 动态/静态/陈旧/未识别：不猜
	}
}

func stateRank(s string) int {
	switch s {
	case StateUp:
		return 2
	case StateDown:
		return 1
	default:
		return 0
	}
}

// stateOfIfaces 网段/本机这一类「容器」节点的状态：
// 成员口里有一个是 up 就是 up（这段真的在通），全是 down 才是 down，混合算不知道。
func stateOfIfaces(names []string, b *builder) string {
	if len(names) == 0 {
		return StateUnknown
	}
	up, down := 0, 0
	for _, nm := range names {
		ifa, ok := b.ifaceByName[nm]
		if !ok {
			continue
		}
		switch ifaceState(ifa) {
		case StateUp:
			up++
		case StateDown:
			down++
		}
	}
	switch {
	case up > 0:
		return StateUp
	case down == len(names):
		return StateDown
	default:
		return StateUnknown
	}
}

// commonMTU 一组网卡的 MTU：只有一个值才给，不然给 0。
//
// ★ 一个网段/一台设备上填「最大值」或「第一个」都是假数 ——
// 图上那一格人是要拿去算分片和 jumbo 的。
func commonMTU(list []int) int {
	v := 0
	for _, m := range list {
		if m <= 0 {
			continue
		}
		if v == 0 {
			v = m
			continue
		}
		if v != m {
			return 0
		}
	}
	return v
}

// stackOf 从地址列表推栈标记。★ 只看地址本身有什么，不看「大概能通什么」。
func stackOf(addrs []string) string {
	var v4, v6 bool
	for _, a := range addrs {
		ip := bareIP(a)
		if ip == "" {
			continue
		}
		if strings.Contains(ip, ":") {
			v6 = true
		} else {
			v4 = true
		}
	}
	switch {
	case v4 && v6:
		return StackBoth
	case v4:
		return StackV4
	case v6:
		return StackV6
	}
	return ""
}

func hasUsableAddr(ifa Iface) bool { return hasUsable(ifa, "") }

// hasUsable 有没有**能拿跟别人通信**的地址（fam 空 = 任一族）。
//
// ★ 链路本地不算可用：v4 的 169.254 恰恰是「DHCP 没要到地址」的故障信号，
// v6 的 fe80:: 是每块网卡必有、但只能在本链路上用。这一条口径跟 netif 完全一致。
func hasUsable(ifa Iface, fam string) bool {
	for _, a := range ifa.Addrs {
		if fam != "" && a.Family != fam {
			continue
		}
		if usableScope(a.Scope) {
			return true
		}
	}
	return false
}

func usableScope(scope string) bool {
	switch strings.TrimSpace(scope) {
	case "private", "global":
		return true
	}
	return false
}

// isTunnelIface 名字像隧道口。★ 按名字认，而且要承认是按名字认（见 tunnelIfacePrefixes）。
func isTunnelIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, p := range tunnelIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func layerForIface(name string) string {
	if isTunnelIface(name) {
		return LayerTunnel
	}
	return LayerL3
}

// kindForCaps 对端自称是什么。
//
// ★ 按 LLDP 的 **enabled**（开着的）能力分类，不按 supported：
// 按 supported 会把一台「自称路由器但路由功能没关着」的纯二层设备写进路由那一栏，
// 然后人就去找它的路由表了（同一条纪律见 net.snmp.lldp 那一段的⑦）。
func kindForCaps(caps []string) string {
	for _, c := range caps {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "bridge", "router", "wlanap", "repeater":
			return KindSwitch
		}
	}
	return KindHost
}

func joinCaps(caps []string) string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "、")
}

func lldpLabel(sysName, chassisID string, addrs []string) string {
	if s := strings.TrimSpace(sysName); s != "" {
		return s
	}
	if s := strings.TrimSpace(chassisID); s != "" {
		return s
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return "一台说了 LLDP 的设备"
}

func orNone3(a, bb, c string) string {
	if s := strings.TrimSpace(a); s != "" {
		return s
	}
	if s := strings.TrimSpace(bb); s != "" {
		return s
	}
	return c
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "没给"
	}
	return s
}

func orNone2(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func mediaWord(ifa Iface) string {
	kind := orNone2(ifa.Kind, "网卡")
	src := ""
	switch ifa.KindSrc {
	case "name":
		src = "，介质是按名字猜的"
	case "os":
		src = "，介质是问系统问到的"
	}
	flag := "admin=" + strconv.FormatBool(ifa.Up) + " carrier=" + strconv.FormatBool(ifa.Running)
	if ifa.MTU > 0 {
		flag += " mtu=" + strconv.Itoa(ifa.MTU)
	}
	return kind + src + " " + flag
}

// rowBrief 一条 LLDP 行的原始内容（直接进证据）。
func rowBrief(row LLDPNeighbor) string {
	parts := []string{}
	if s := strings.TrimSpace(row.ChassisID); s != "" {
		parts = append(parts, "机箱标识 "+s)
	}
	if s := strings.TrimSpace(row.SysName); s != "" {
		parts = append(parts, "自述 "+s)
	}
	if s := strings.TrimSpace(row.PortID); s != "" {
		parts = append(parts, "插在它的 "+s)
	}
	if len(row.Addrs) > 0 {
		a := append([]string(nil), row.Addrs...)
		sort.Strings(a)
		parts = append(parts, "管理地址 "+strings.Join(a, "、"))
	}
	if c := joinCaps(row.Caps); c != "" {
		parts = append(parts, "能力 "+c)
	}
	if len(parts) == 0 {
		return "这行只给了口号，什么都没交代"
	}
	return strings.Join(parts, "，")
}

// ── 地址与字符串 ──

// normalizeMAC 统一成小写冒号写法。★ 各探测给的写法三种都有：
// ARP 是 aa:bb:cc:dd:ee:ff、LLDP 那栏被打成大写冒号、Windows 是 aa-bb-cc-dd-ee-ff、
// 华为/H3C 的 CLI 还会写 aabb.ccdd.eeff。不去归一，同一块网卡在图上就是三个 MAC，
// 于是「这台设备在不在我们网里」这种问题要人自己对着字符串比大小写。
func normalizeMAC(s string) string { return netaddr.CanonicalMAC(s) }

// bareIP 剥掉 zone、方括号、前缀，只留纯地址。认不出来返回空串。
//
// ★ 空串是**信号**：邻居表里一条解不出地址的东西（Windows 的接口标题行、
//
//	设备自己塞的描述文本）不能进图 —— 它既不是节点也不是线，只能是一句「我们读不懂」。
func bareIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "[")
	if i := strings.Index(s, "]"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "%"); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.WithZone("").String()
}

func showAddr(ip, zone string) string {
	if z := strings.TrimSpace(zone); z != "" && strings.Contains(ip, ":") {
		return ip + "%" + z
	}
	return ip
}

// prefixOfAddr 从 "192.168.1.10/24" 或 "192.168.1.0/24" 取出**归一后的网段**。
//
// ★ 一律 Masked()：网卡上配的是主机地址、路由表里写的是网段，
// 不归一就会给同一个段建两个节点（192.168.1.10/24 和 192.168.1.0/24 各一个方块）。
func prefixOfAddr(cidr string) (netip.Prefix, bool) {
	s := strings.TrimSpace(cidr)
	if i := strings.LastIndex(s, "%"); i >= 0 {
		if j := strings.Index(s[i:], "/"); j >= 0 {
			s = s[:i] + s[i+j:]
		} else {
			s = s[:i]
		}
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false // 没带前缀长度就不猜网段（那是编的）
	}
	return p.Masked(), true
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func appendUnique(list []string, s string) []string {
	if s == "" || containsStr(list, s) {
		return list
	}
	return append(list, s)
}

func sortedSet(seen map[string]bool, in []string) []string {
	m := seen
	if m == nil {
		m = map[string]bool{}
	}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return sortedKeysBool(m)
}

func sortedUnique(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return sortedKeysBool(m)
}

func sortedKeysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAddrKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNodeKeys(m map[string]*nodeAcc) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedEdgeKeys(m map[string]*edgeAcc) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSegKeys(m map[string]localSeg) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIfaceNeighborKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// orderCodes 去重 + 按优先级排。★ Values["codes"] 是**全量**：界面对每个命中的码
// 都要渲染一句话，只给一个就把「同时是孤岛又没有二层证据」压成了半句。
func orderCodes(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range codePriority {
		for _, got := range in {
			if got == c && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	if len(out) == 0 {
		out = []string{CodeOK}
	}
	return out
}

// ── 输入排序（成图的确定性全靠这几段）──

func sortedIfaces(in []Iface) []Iface {
	out := append([]Iface(nil), in...)
	for i := range out {
		addrs := append([]Addr(nil), out[i].Addrs...)
		sort.Slice(addrs, func(a, b int) bool {
			if addrs[a].IP != addrs[b].IP {
				return addrs[a].IP < addrs[b].IP
			}
			return addrs[a].CIDR < addrs[b].CIDR
		})
		out[i].Addrs = addrs
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Index < out[j].Index
	})
	return out
}

func sortedNeighbors(in []Neighbor) []Neighbor {
	out := append([]Neighbor(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		a, bb := out[i], out[j]
		if a.Iface != bb.Iface {
			return a.Iface < bb.Iface
		}
		if a.Addr != bb.Addr {
			return a.Addr < bb.Addr
		}
		if a.MAC != bb.MAC {
			return a.MAC < bb.MAC
		}
		if a.Family != bb.Family {
			return a.Family < bb.Family
		}
		return a.State < bb.State
	})
	return out
}

func sortedRoutes(in []Route) []Route {
	out := append([]Route(nil), in...)
	bits := func(r Route) int {
		if p, ok := prefixOfAddr(r.Destination); ok {
			return p.Bits()
		}
		return -1
	}
	fam := func(r Route) string {
		if p, err := netip.ParsePrefix(strings.TrimSpace(r.Destination)); err == nil {
			if p.Addr().Is6() {
				return "ipv6"
			}
			return "ipv4"
		}
		return r.Family
	}
	sort.Slice(out, func(i, j int) bool {
		a, bb := out[i], out[j]
		if fam(a) != fam(bb) {
			return fam(a) < fam(bb)
		}
		if bits(a) != bits(bb) {
			return bits(a) < bits(bb) // 前缀短的在前：默认路由、大段先建节点
		}
		if a.Metric != bb.Metric {
			return a.Metric < bb.Metric
		}
		if a.Gateway != bb.Gateway {
			return a.Gateway < bb.Gateway
		}
		if a.Iface != bb.Iface {
			return a.Iface < bb.Iface
		}
		return a.Destination < bb.Destination
	})
	return out
}

func lldpRowLess(a, b LLDPNeighbor) bool {
	if a.PortNum != b.PortNum {
		return a.PortNum < b.PortNum
	}
	if a.LocalPort != b.LocalPort {
		return a.LocalPort < b.LocalPort
	}
	if a.ChassisID != b.ChassisID {
		return a.ChassisID < b.ChassisID
	}
	if a.SysName != b.SysName {
		return a.SysName < b.SysName
	}
	return strings.Join(a.Addrs, ",") < strings.Join(b.Addrs, ",")
}
