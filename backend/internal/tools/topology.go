package tools

// ── net.topology.build ──
//
// 把这台机器**已经探测得到**的事实合成一张拓扑图（节点 + 端口 + 线），
// 给画布直接画。这一张卡不新增任何探测：四项输入全是别的卡已经在读的东西
// （net.interfaces、net.neighbors、net.routes、net.snmp.lldp），
// 这里只把它们**换成同一台设备的同一个方块、同一根线上的同一根线**。
//
// ★★ 唯一的硬规矩是 docs/设计.md:940 那一句：「别把拓扑图做成装饰 ——
//
//	看得见的必须是真实探测出来的，不许手画示意图」。
//	落成两条，都在 internal/topo 那两层里用类型保证：
//	  ① 每个节点带 source（哪个探测产出的它）、每根线带 evidence（哪条原始事实支撑它），
//	    界面上点开任何东西都点得回到事实；
//	  ② 探测看不见的地方写 blind（「这一块是空的，以及为什么空」），
//	    绝不补一个看着合理的方块或一根看着合理的线。
//
// ★ 这一张卡最容易写坏的三处，全都在①②上：
//
//	① ARP 表里有 30 个地址 → 顺手画一台交换机。那 30 台机器里就有人拿着我们
//	   给的这个「不存在的设备」去登管理地址。所以只报 topo-hub-suspect（怀疑 + 怎么坐实），
//	   交换机不上图。
//	② 把同网段画成直接连线。二层（谁插在哪个口上）只有 LLDP-MIB 给得出证据，
//	   ARP/路由/连通性全在它的上层 —— 没有 LLDP 时图上跨设备的线一律是三层线，
//	   并明确标 topo-l2-blind。
//	③ 一块双栈网卡合成一根线。v6 半条链路坏掉（有地址、RA 是别人发的、没有 v6 路由）
//	   的表现是「网很慢」而不是「网不通」，合并画就永远看不见这种病。
//	   所以每块双栈网卡天然是两根线（v4/v6 各一根，栈标在线上）。
//
// ★ 合成逻辑一律不在这里：全在 internal/topo（纯函数、不开线程、不碰系统）。
//
//	分成两层是因为「交换机没有 LLDP agent」「ARP 表是空的」「v6 没路由」这三种病
//	没法在 CI 里等出来，只能用夹具跑。这里只负责「把事实取回来」。
//
// ★ 取事实的方式是**复用那些卡自己的代码路径**，不是重新实现一遍读法：
//
//	net.interfaces 用 netif.Interfaces、邻居用 neighborsV4/V6、路由用 netif.Routes、
//	LLDP 直接调 net.snmp.lldp 那张卡的 Invoke。各平台 ARP 的写法差异、
//	windows 的 MAC 用短横、链路本地地址的 zone 怎么写，都在那些地方已经踩过坑修好了，
//	在这儿再手搓一遍只会把修过的坑重新踩开 —— 而且两张卡会对不上数。
//
// 凭据：只有 lldpCommunity（读团体名）是凭据，且只透传给 net.snmp.lldp，
// 不出现在结果里（这台机器自己的四项读法全是只读本机，不需要任何凭据）。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/topo"
)

// 四个取事实的口子都走变量：测试在任何机器上都要能把「读不到」「读回来是空的」
// 这两种病跑满 —— 真机上的 ARP 表里有什么、这台机器挂着几条路由，
// 不该让一张图的测试结果跟着变（否则 CI 在一台连着 VPN 的机器上就红了）。
var (
	topoInterfaces  = netif.Interfaces
	topoRoutes      = netif.Routes
	topoNeighborsV4 = neighborsV4
	topoNeighborsV6 = neighborsV6
	topoLLDPInvoke  = snmpLldpTool.Invoke
	topoHostname    = os.Hostname
)

type topologyArgs struct {
	// LLDP 那一段是**可选**的。不填就完全不问设备 ——
	// 这张图照样建，只是二层那一层明确标成看不见（topo-l2-blind）。
	LldpAddr      string `json:"lldpAddr,omitempty"`
	LldpCommunity string `json:"lldpCommunity,omitempty"`
	LldpIface     string `json:"lldpIface,omitempty"`
	LldpPort      int    `json:"lldpPort,omitempty"`
	LldpVersion   string `json:"lldpVersion,omitempty"`
	LldpTimeoutMS int    `json:"lldpTimeoutMs,omitempty"`
	LldpRetries   int    `json:"lldpRetries,omitempty"`
	// LldpPortNum 点名问某一个 LLDP 口号。★ 只筛「报哪几行邻居」，
	// 不改图的形状：问某一个口时其余口的线我们没见过，所以不能画也不能说它不存在。
	LldpPortNum  int  `json:"lldpPortNum,omitempty"`
	LldpIfIndex  int  `json:"lldpIfIndex,omitempty"`
	HubThreshold int  `json:"hubThreshold,omitempty"`
	NoLLDP       bool `json:"noLldp,omitempty"`
}

var topologyTool = ots.Tool{
	Name:  "net.topology.build",
	Class: ots.ClassRead,
	Summary: "把这台机器已经探测到的事实合成一张网络拓扑图（节点 + 端口 + 连线），" +
		"全部 backed 在真实测量上：net.interfaces（网卡与地址）、net.neighbors（ARP/NDP 表）、" +
		"net.routes（路由表）、可选的 net.snmp.lldp（设备的 LLDP 邻居）。★ 本工具不新发任何探测包，" +
		"前三项都是纯读本机。" +
		"每个节点带 source（哪个探测产出的它）、每根线带 evidence（哪条原始事实支撑它），" +
		"看不见的地方一律写进 blind，不补一个看着合理的方块或一根看着合理的线。" +
		"★ 二层的线（谁用哪根线插在哪个口上）只有 LLDP 给得出证据：没问 LLDP 时" +
		"图上跨设备的线全是三层线，并判 topo-l2-blind —— 同网段不等于直接相连，" +
		"ARP 表里 30 个地址中间那台非网管交换机在 ARP 眼里是不存在的。" +
		"一块双栈网卡画成**两根**线（v4、v6 各一根，栈标在线上），绝不合成一根。" +
		"判定：topo-ok（这张图我们没有理由怀疑它，**不是**网络是好的）、" +
		"topo-no-ifaces（没有可画的网卡）、topo-l2-blind（二层没有任何证据）、" +
		"topo-hub-suspect（一块口上邻居多到中间大概还有一台不说话的交换机，只怀疑、不画出来，" +
		"要坐实就顺着这根线问那台设备的 LLDP/SNMP）、topo-island（链路活着、地址配了，可它什么都够不着）、" +
		"topo-no-gateway（本网够得着、没有任何一条带下一跳的路由，查的是这台的路由配置不是查线）、" +
		"topo-dualstack-skew（两族都有地址但拓扑不是同一张图，应用会先试 v6 再回落，表现成慢而不是不通）、" +
		"topo-segment-conflict（同一个地址被探测到同时属于两处：地址冲突或两块网卡同址，这块网段画不成一个方块）。" +
		"节点和线都按 id 排好序，同一次改动前后的输出可以逐字节对拍。" +
		"要画完整的图就填 lldpAddr + lldpCommunity 问一下上联交换机（先跑 net.snmp.probe 确认 SNMP 通不通）。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "lldpAddr": {"type": "string",
	      "description": "要问 LLDP 的那台设备（通常是上联交换机）的地址。★ 不填就**完全不问**：图照样建，但二层那一层会标成看不见（topo-l2-blind）。域名先用 net.dns.query 查出地址。"},
	    "lldpCommunity": {"type": "string",
	      "description": "那台设备的读团体名。★ 没有默认值：团体名不对时设备压根不答，和没开 SNMP、防火墙丢包在报文上同形。它只透传给 net.snmp.lldp，不会出现在结果里。只给了 lldpAddr 不给这一项时，这次不问 LLDP（当作没问，不是当作设备不回话）。"},
	    "lldpIface": {"type": "string",
	      "description": "问那台设备时从本机哪块网卡出去（en0 / eth0 / 以太网 2）。多网卡机器上管理 VLAN 只放行一个口，走错口就等于没回话。"},
	    "lldpPort": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "那台设备的 SNMP UDP 端口，不填按 161。"},
	    "lldpVersion": {"type": "string", "enum": ["v2c", "v1"],
	      "description": "SNMP 版本，不填按 v2c。只认 v1 的老交换机填 v1（走表会退成一栏一栏问，慢很多）。"},
	    "lldpTimeoutMs": {"type": "integer", "minimum": 200, "maximum": 20000,
	      "description": "问那台设备时单个请求等多久，默认 2000。"},
	    "lldpRetries": {"type": "integer", "minimum": 2, "maximum": 6,
	      "description": "没回话时一共问几次（含首发），默认 3。"},
	    "lldpPortNum": {"type": "integer", "minimum": 1, "maximum": 4096,
	      "description": "点名问那台设备的某一个 LLDP 口（lldpRemLocalPortNum）。★ 这只影响「报哪几行邻居」，不改图的形状：没报的那些口我们这回没见过，既不画也不说那里没有线。"},
	    "lldpIfIndex": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "按接口编号点名（结果里会写清这个号是怎么对上的：设备给的 dot1dBasePortIfIndex 硬映射，还是按编号相等猜的）。"},
	    "hubThreshold": {"type": "integer", "minimum": 1, "maximum": 1024,
	      "description": "一块网卡上听见多少个**不同**邻居就该怀疑中间还有一台不说话的交换机，默认 5。★ 调这个数不会让图变准，只会让那一档更早/更晚响：真实的接入 VLAN 里十几台是常态，没有 LLDP 时我们分不清「一个口下挂 30 台」和「中间还有一台非网管交换机」。"},
	    "noLldp": {"type": "boolean",
	      "description": "什么都不问，只按本机事实（网卡 + 邻居 + 路由）建图。填了 lldpAddr 但只想看三层图时用这一项；它比「忘了填」诚实，blind 里会写明是这次没问。"}
	  }
	}`),
	Invoke: buildTopology,
}

func buildTopology(ctx context.Context, raw json.RawMessage) (any, error) {
	var a topologyArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.HubThreshold < 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "hubThreshold 不能是负数，给的是 %d", a.HubThreshold)
	}
	if a.LldpPortNum > 0 && a.LldpIfIndex > 0 {
		// ★ 这一条必须报错而不是「以其中一个为准」：net.snmp.lldp 自己两个都收、
		//   按顺序挑一个，透传下去的话图上少几根线，人却以为是那里真的没接线。
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"lldpPortNum 和 lldpIfIndex 只能给一个（它们说的是「点哪个口」，给两个就不知道按哪个筛）")
	}

	in := topo.Inputs{HubThreshold: a.HubThreshold}
	if name, err := topoHostname(); err == nil {
		in.LocalName = strings.TrimSpace(name)
	}

	// ── ① 网卡：图上每一块口、每一个本机地址都从这儿来 ──
	nics, err := topoInterfaces()
	if err != nil {
		// ★ 读不到网卡**不是错误**：这张卡的工作是「据我们已经知道的画图」，
		//   而「我们什么都不知道」正是一个要说出来的结论（topo-no-ifaces）。
		//   把它报成工具失败，界面上就只剩一句报错，人看不到「这台读不到网卡」这句有用的话。
		in.Gaps = append(in.Gaps, topo.Gap{Probe: "net.interfaces", Reason: err.Error()})
	} else {
		in.Probes = append(in.Probes, "net.interfaces")
	}
	for _, n := range nics {
		in.Ifaces = append(in.Ifaces, topoIfaceOf(n))
	}

	// ── ② 邻居表：这个网里都有谁（ARP 与 NDP 是两张表，一族读不到不拖累另一族）──
	var gotNeigh []string
	n4, err4 := topoNeighborsV4(ctx)
	if err4 != nil {
		in.Gaps = append(in.Gaps, topo.Gap{Probe: "net.neighbors",
			Reason: "IPv4（ARP）读不到：" + err4.Error()})
	} else {
		gotNeigh = append(gotNeigh, "net.neighbors.v4")
	}
	n6, err6 := topoNeighborsV6(ctx)
	if err6 != nil {
		in.Gaps = append(in.Gaps, topo.Gap{Probe: "net.neighbors",
			Reason: "IPv6（NDP）读不到：" + err6.Error()})
	} else {
		gotNeigh = append(gotNeigh, "net.neighbors.v6")
	}
	if len(gotNeigh) > 0 {
		in.Probes = append(in.Probes, "net.neighbors")
	}
	for _, nb := range n4 {
		in.Neighbors = append(in.Neighbors, topoNeighborOf(nb, "net.neighbors.v4"))
	}
	for _, nb := range n6 {
		in.Neighbors = append(in.Neighbors, topoNeighborOf(nb, "net.neighbors.v6"))
	}

	// ── ③ 路由表：这台往外交走哪、上游是谁 ──
	rt, err := topoRoutes()
	if err != nil {
		in.Gaps = append(in.Gaps, topo.Gap{Probe: "net.routes", Reason: err.Error()})
	} else {
		in.Probes = append(in.Probes, "net.routes")
	}
	for _, r := range rt {
		in.Routes = append(in.Routes, topo.Route{
			Family: r.Family, Destination: r.Destination, Gateway: r.Gateway,
			Iface: r.Iface, Direct: r.Direct, Metric: r.Metric,
		})
	}

	// ── ④ LLDP：唯一画得出「这根线另一头是谁」的探测，可选 ──
	in.LLDP = collectLLDP(ctx, a)

	g := topo.Build(in)
	return ots.Verdict{Code: g.Code(), Values: g.Values(), Note: g.Note()}, nil
}

// ── 把探测结果换成 topo 的输入类型 ──

// topoIfaceOf 复用 net.interfaces 那张卡自己的输出形状（toNICOut），
// 不在这儿重新拼地址、族、作用域、zone —— 那些字段各平台的坑已经在那张卡里踩过。
func topoIfaceOf(n netif.NIC) topo.Iface {
	out := toNICOut(n)
	ifa := topo.Iface{
		Name: out.Name, Index: out.Index, MAC: out.MAC, MTU: out.MTU,
		Up: out.Up, Running: out.Running, Loop: out.Loop, Virtual: out.Virtual,
		Kind: out.Kind, KindSrc: out.KindSrc, Parent: n.Parent,
	}
	for _, a := range out.Addrs {
		ifa.Addrs = append(ifa.Addrs, topo.Addr{
			IP: a.Addr, Zone: a.Zone, CIDR: a.CIDR, Family: a.Family, Scope: a.Scope,
		})
	}
	return ifa
}

func topoNeighborOf(nb neighbor, src string) topo.Neighbor {
	return topo.Neighbor{Addr: nb.Addr, MAC: nb.MAC, Iface: nb.Iface,
		Family: nb.Family, State: nb.State, Source: src}
}

// ── LLDP：调那张卡本身，然后把它回的事实翻成 topo 的输入 ──

// collectLLDP 问一次 net.snmp.lldp，问不到就把**为什么问不到**原样带回去。
//
// ★★ 失败绝不能变成「这层没有邻居」：lldpEmptyTable / lldpUnsupported 那一段说得很清楚，
//
//	「邻居表是空的」在这棵树里是五种病（这台没这棵、口只发不存、口被关、对端不说 LLDP、
//	表没走全），下一步完全相反。所以这里把那张卡的判定码和 note 一起塞进 Unavailable，
//	让图上那句 blind 带上真正的答案，而不是我们重新猜一句「大概没接东西」。
func collectLLDP(ctx context.Context, a topologyArgs) topo.LLDP {
	switch {
	case a.NoLLDP:
		return topo.LLDP{Unavailable: "这次明确没问 LLDP（noLldp=true）—— 二层的线（谁插在哪个口上）没有任何证据"}
	case strings.TrimSpace(a.LldpAddr) == "":
		return topo.LLDP{Unavailable: "没给 lldpAddr，这次没问任何设备的 LLDP —— " +
			"二层的线（谁插在哪个口上）没有任何证据。要坐实就填上联交换机的地址再问一次"}
	case strings.TrimSpace(a.LldpCommunity) == "":
		return topo.LLDP{Unavailable: "给了 lldpAddr 但没给 lldpCommunity（读团体名，这里故意没有默认值）—— " +
			"这次没问 LLDP。★ 这一条**不是**「设备不回话」：我们压根没问它"}
	}
	args := map[string]any{"addr": strings.TrimSpace(a.LldpAddr), "community": a.LldpCommunity}
	if a.LldpPort > 0 {
		args["port"] = a.LldpPort
	}
	if s := strings.TrimSpace(a.LldpVersion); s != "" {
		args["version"] = s
	}
	if s := strings.TrimSpace(a.LldpIface); s != "" {
		args["iface"] = s
	}
	if a.LldpTimeoutMS > 0 {
		args["timeoutMs"] = a.LldpTimeoutMS
	}
	if a.LldpRetries > 0 {
		args["retries"] = a.LldpRetries
	}
	if a.LldpPortNum > 0 {
		args["portNum"] = a.LldpPortNum
	}
	if a.LldpIfIndex > 0 {
		args["ifIndex"] = a.LldpIfIndex
	}
	packed, err := json.Marshal(args)
	if err != nil {
		return topo.LLDP{Unavailable: "拼 LLDP 参数失败（是我们的问题，不是设备的）：" + err.Error()}
	}

	res, err := topoLLDPInvoke(ctx, packed)
	if err != nil {
		return topo.LLDP{Unavailable: "net.snmp.lldp 没跑成：" + err.Error()}
	}
	var snap lldpSnapshot
	b, merr := json.Marshal(res)
	if merr != nil {
		return topo.LLDP{Unavailable: "net.snmp.lldp 回了话，但结果读不出形状（是我们的问题）：" + merr.Error()}
	}
	if uerr := json.Unmarshal(b, &snap); uerr != nil {
		return topo.LLDP{Unavailable: "net.snmp.lldp 回了话，但结果读不出形状（是我们的问题）：" + uerr.Error()}
	}

	l := topo.LLDP{
		Device: topo.LLDPDevice{
			SysName:   snap.Values.Local.SysName,
			ChassisID: snap.Values.Local.ChassisID,
			Caps:      topoCapTokens(snap.Values.Local.CapabilitiesEnabled, snap.Values.Local.Capabilities),
		},
	}
	for _, row := range snap.Values.Neighbors {
		local := strings.TrimSpace(row.LocalPortName)
		if local == "" {
			// ★ 口号原样留着，不许猜它叫什么、也不许留空：留空的话这根线在图上
			//   就说不清接在哪个口上，而这一栏正是现场拿去报名字的那一句。
			local = fmt.Sprintf("口号 %d", row.PortNum)
		}
		l.Neighbors = append(l.Neighbors, topo.LLDPNeighbor{
			PortNum:   row.PortNum,
			LocalPort: local,
			ChassisID: row.ChassisID,
			SysName:   row.SysName,
			PortID:    firstNonBlank(row.RemotePortID, row.RemotePortDesc),
			Addrs:     row.MgmtAddresses,
			Caps:      topoCapTokens(row.CapabilitiesEnabled, row.Capabilities),
			Aging:     row.AgedOut,
		})
	}
	// ★ watchSeconds 没用上（这里没有这个参数），所以不处理 newNeighbors 那几行 ——
	//   那张卡在收口时已经把只在第二遍读到的行并进 neighbors 了，这里读一遍就够。
	if len(l.Neighbors) == 0 {
		// 问过了、这行就是空的：把那张卡自己的判定和 note 带上来（五种病的区别在那儿）。
		why := strings.TrimSpace(snap.Note)
		if why == "" {
			why = "没给说明"
		}
		l.Unavailable = fmt.Sprintf("net.snmp.lldp（判定 %s）：%s", snap.Verdict, why)
		return l
	}
	// ★ 问成功且有邻居行：设备身份那一栏即使缺也照实留空，让 topo 的 blind 去说
	//   「这台没给 lldpLocSysName / ChassisId，所以图上没有它的方块」，
	//   不在这里替它编一个名字。
	//   管理地址就是**我们问它用的那个地址**（探测事实，所以带上）——
	//   它让 topo 能算出「这台在不在本机某个网段里」，从而决定那根线挂在哪一头。
	if ip := onlyIP(strings.TrimSpace(a.LldpAddr)); ip != "" {
		l.Device.Addrs = []string{ip}
	}
	return l
}

// onlyIP 把 addr（可带端口、可写 [fd00::1]:80）收成纯地址。
// 解不出来返回空串 —— ★ 不猜：拿一个看着像地址的字符串当节点身份，
// 图上就会出现一个谁都不认识的方块。
func onlyIP(s string) string {
	if s == "" {
		return ""
	}
	addr, _, err := netaddr.SplitHostPort(s)
	if err != nil {
		return ""
	}
	return addr.IP.String()
}

// topoCapTokens 把 LLDP 的能力词翻成 ASCII 词：bridge / router / wlanAP / stationOnly…
//
// ★ net.snmp.lldp 给的是「交换（bridge）」这种**给人看的**写法（中文界面要能渲染），
//
//	这里取括号里那个标准里的词，不取中文：拿中文当枚举值，
//	将来换一种语言这个判断就整段失效，图上所有交换机方块都会跟着消失。
//	★ 只用 enabled（开着的），supported 只当兜底 —— 见那张卡的注释⑦：
//	按 supported 分类会把一台「自称路由器但功能没开」的纯二层设备写进路由那一栏。
func topoCapTokens(enabled, supported []string) []string {
	if got := capWords(enabled); len(got) > 0 {
		return got
	}
	return capWords(supported)
}

func capWords(in []string) []string {
	var out []string
	for _, s := range in {
		for _, w := range lldpCapWordRe.FindAllString(s, -1) {
			out = append(out, strings.ToLower(w))
		}
	}
	return out
}

// lldpCapWordRe 取括号里的那个英文词（LLDP-MIB 的 capability 名）。
var lldpCapWordRe = regexp.MustCompile(`[（(]\s*([A-Za-z][A-Za-z0-9]*)`)

func firstNonBlank(list ...string) string {
	for _, s := range list {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}

// lldpSnapshot 是 net.snmp.lldp 返回值里 topo 要用的那几栏。
//
// ★ 只声明用得到的字段，不复制那张卡的整个形状：它加栏不用改这里，
//
//	而这里读不到某栏时 topo 会说「这一栏没给」—— 而不是我们假装读到了。
type lldpSnapshot struct {
	Verdict string `json:"verdict"`
	Note    string `json:"note"`
	Values  struct {
		Local struct {
			SysName             string   `json:"sysName"`
			ChassisID           string   `json:"chassisId"`
			Capabilities        []string `json:"capabilities"`
			CapabilitiesEnabled []string `json:"capabilitiesEnabled"`
		} `json:"local"`
		Neighbors []lldpSnapRow `json:"neighbors"`
	} `json:"values"`
}

type lldpSnapRow struct {
	PortNum             int      `json:"portNum"`
	LocalPortName       string   `json:"localPortName"`
	ChassisID           string   `json:"chassisId"`
	SysName             string   `json:"sysName"`
	RemotePortID        string   `json:"remotePortId"`
	RemotePortDesc      string   `json:"remotePortDesc"`
	MgmtAddresses       []string `json:"mgmtAddresses"`
	Capabilities        []string `json:"capabilities"`
	CapabilitiesEnabled []string `json:"capabilitiesEnabled"`
	AgedOut             bool     `json:"agedOut"`
}
