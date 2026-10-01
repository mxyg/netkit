// Package topo 把 NetKit **已经探测到**的事实合成一张拓扑图（节点 + 端口 + 线）。
//
// ★★ 这个包存在的唯一理由是 docs/设计.md:940 那一句：
//
//	「别把拓扑图做成装饰 —— 看得见的必须是真实探测出来的，不许手画示意图」。
//	落成两条硬的：
//	  ① 每一个节点、每一条线都点名**是哪一个探测产出它的**
//	    （Node.Source / Edge.Evidence），点开图上任何东西都能看到原始事实；
//	  ② 探测看不见的地方就写「看不见」（Graph.Blind + topo-l2-blind），
//	    绝不补一条看着很合理的线。图上多一根没有依据的线，比图上少一根线糟得多 ——
//	    人会照着那根线去查一个根本没接的端口。
//
// ★ 为什么最要紧的一条是「不画没见过的交换机」：现场十有八九中间有一台非网管交换机，
//
//	而 ARP 表**看不出**它的存在（它不占 IP、不回 ARP）。一个会自动「把图连起来」的实现
//	一定会在那儿画一个方块，人就会去登那个不存在的方块的管理地址。
//	所以这一层只报「怀疑」（topo-hub-suspect）并且写明要坐实该问谁。
//
// ★ 这个包**一概不探测**：没有 syscall、没有网络、不起 goroutine、不读文件。
//
//	输入是收集层已经拿好的事实（下面那几个 typed 输入），输出是图 + 证据 + 判定。
//	分成两层就是为了让「合成」这件事能用夹具跑满：真机上「交换机没有 LLDP agent」
//	「ARP 表是空的」「v6 没路由」这三种病，没法在 CI 里等出来。
package topo

import (
	"fmt"
	"strings"
)

// ── 判定码 ──
//
// ★ 每个码都是「图上有一种画法会让人做错事」，界面对每个码渲染一句话。
//
//	码的集合是封闭的（八个），加一个就得同时想清楚它在图上对应哪一种画法。
const (
	// topo-ok：图上有节点有线，且上面七种病一条都没犯。**不是**「网络是好的」——
	// 这一张卡压根不判通不通，只说「这张图我们没有理由怀疑它」。
	CodeOK = "topo-ok"
	// topo-no-ifaces：一块能画的网卡都没有（只有回环，或者 net.interfaces 直接失败）。
	// ★ 它必须是**第一个**判：下面七条全都建立在「至少有个口」上，
	//
	//	没口的时候「没有网关」「没有邻居」都是废话，一句都成立也一句都不该说。
	//	写错这一条的下一步会让人去查路由，而那台机器压根没插线。
	CodeNoIfaces = "topo-no-ifaces"
	// topo-l2-blind：二层（谁用哪根线插在哪个口上）**没有任何探测证据**。
	// ★ 判据只有一条：这次没有 net.snmp.lldp 读回来的邻居行。
	//
	//	ARP/NDP 只能证明「三层在同一个广播域」，它证明不了线怎么接的 ——
	//	一台非网管交换机就能让 30 台机器互相 ARP 到，而它们中间那台设备在 ARP 眼里不存在。
	//	这一档的存在就是为了不许把「同网段」画成「直接连线」。
	CodeL2Blind = "topo-l2-blind"
	// topo-hub-suspect：一块网卡上听见的邻居数超过了单个广播域的正常值。
	// ★ 这是**怀疑不是结论**：常见的解释是「这个口下面还有一台非网管交换机 / 一台老 hub」，
	//
	//	也可能是它真的接了一堆设备（接入 VLAN、机柜口）。两种下一步完全不同，
	//	所以这一档只报数、只说「要坐实就拿 net.snmp.lldp 或 net.snmp.probe 问那台设备」，
	//	**不画交换机**（见上面那条硬规矩）。
	CodeHubSuspect = "topo-hub-suspect"
	// topo-island：一块网卡在链路层是活的、地址也配上了，可是它上面既没听见邻居、
	//
	//	也没有任何一条**经由它出去的非直连路由**。图上它就是一根悬空的线 ——
	//	这是真的孤岛（设备没上电、线只接了一头、对端交换机没起端口），
	//	不是「我们没测到」。★ 它排在 topo-no-gateway 前面：一台只有这一块网卡、
	//	什么都没测到的机器，说它是孤岛比说它「没网关」更贴近现场要查的东西。
	CodeIsland = "topo-island"
	// topo-no-gateway：邻居表或地址都说明这台机器在某个网里，可**没有任何一条**
	//
	//	带下一跳的默认路由。图上就没有「上游」这个方块。
	//	★ 和 topo-island 分开是必须的：孤岛是「这块口什么都够不着」，
	//
	//	没网关是「本网够得着、出不了本网」—— 前者查线，后者查配置。
	CodeNoGateway = "topo-no-gateway"
	// topo-dualstack-skew：v4 与 v6 **都有地址**，但两层的拓扑不是同一张图
	//
	//	（一族有默认路由另一族没有，或两族的下一跳落在不同的网卡上）。
	//	★ 这一条是 docs/设计.md 双栈那一段的直接落点：「有 v6 地址却没 v6 路由 / v6 走的是
	//
	//	另一条路」在图上必须看得出来，因为应用会先试 v6 再回落 ——
	//	表现成「网很慢」而不是「网不通」。合成一张合并的图就是把这种病藏起来。
	CodeDualStackSkew = "topo-dualstack-skew"
	// topo-segment-conflict：同一个地址被探测到**同时**属于两处（同一个 IP 配在两块网卡上、
	//
	//	同一个 IP 在邻居表里对应两个 MAC、或邻居表里出现了本机自己的地址/MAC）。
	//	★ 这时候这块网段画不成一个方块：图上任何一条经过它的线都可能是错的。
	//	地址冲突是现场最难查也最要命的一类（两台设备抢一个管理地址），
	//	宁可把网段标成矛盾，也不许挑一个 MAC 画出去。
	CodeSegmentConflict = "topo-segment-conflict"
)

// codePriority 是这些码在「顶层只出一个码」时的先后。★ 顺序就是**哪一个会先骗到人**：
// 没口 → 一切都没有；图建在矛盾事实上 → 后面的结论都不作数；
// 然后是图上少画的东西（孤岛、没上游），最后才是「二层的线我们本来就没测」这种全图级的坦白。
var codePriority = []string{
	CodeNoIfaces,
	CodeSegmentConflict,
	CodeIsland,
	CodeNoGateway,
	CodeHubSuspect,
	CodeDualStackSkew,
	CodeL2Blind,
	CodeOK,
}

// ── 枚举 ──

// 节点类型。
const (
	KindLocal   = "local"   // 这台机器本身
	KindIface   = "iface"   // 一块网卡（画布上的一个端口）
	KindSegment = "segment" // 一个网段（前缀），三层意义上的广播域
	KindHost    = "host"    // 对端：只知道它在某块网卡上被听见了（ARP/NDP/LLDP 自述）
	KindSwitch  = "switch"  // 设备**自己**说它是网络设备（LLDP 本地系统数据）
	KindGateway = "gateway" // 路由表里某条路的下一跳
)

// kindRank 一台设备同时被好几个探测认识时，节点该画成哪一类。
//
// ★ 交换机排在网关前面是想过现场的：LLDP 里那台设备自称 bridge+router、
//
//	管理地址也正好是默认网关，这是同一台东西。图标该画成**它是什么设备**
//	（人要在图上找到它、要登它），而「它是网关」这件事在它连出去的那条线上、
//	在 why 里、在 Values.gateways 里都有；画成网关方块反而让人在图上认不出第二次的它。
var kindRank = map[string]int{
	KindHost: 1, KindGateway: 2, KindSwitch: 3,
	KindSegment: 4, KindIface: 5, KindLocal: 6,
}

// 线的层次。
const (
	LayerL2     = "l2"     // 设备自己报的二层相邻（只有 LLDP 给得了）
	LayerL3     = "l3"     // 三层：本网段的地址、路由算得出来的下一跳
	LayerTunnel = "tunnel" // 出接口是隧道口（utun/tun/wg/ppp/gre…）：线是封装出来的
)

// 状态。★ 只从探测字段推，推不出来就是 unknown，不许按「大概插着线」猜。
const (
	StateUp      = "up"
	StateDown    = "down"
	StateUnknown = "unknown"
)

// 双栈标记。Node.Stack 允许空串（一个地址都没有）；
// Edge.Stack 对**纯二层**的线也是空串 —— 一根网线不分 v4/v6，
// 给它填一个值就是编的（宁可留空，界面上写「二层，不分栈」）。
const (
	StackV4   = "v4"
	StackV6   = "v6"
	StackBoth = "both"
)

// ── 输出形状（★ JSON 标签是与画布层的合同，一个字节都不许改）──

// Node 图上的一个节点。
type Node struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Label  string   `json:"label"`
	Addrs  []string `json:"addrs"`
	MACs   []string `json:"macs"`
	Ifaces []string `json:"ifaces"`
	Stack  string   `json:"stack"`
	State  string   `json:"state"`
	MTU    int      `json:"mtu"`
	Source []string `json:"source"`
	Why    string   `json:"why"`
}

// Edge 图上的一条线。
type Edge struct {
	ID       string   `json:"id"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Layer    string   `json:"layer"`
	Stack    string   `json:"stack"`
	Ports    []string `json:"ports"`
	Evidence []string `json:"evidence"`
	State    string   `json:"state"`
}

// ── 输入形状（收集层把探测结果换成这些类型，本包只看它们）──

// Addr 一个配在本机网卡上的地址。
type Addr struct {
	IP     string // 不带 zone 的地址本身，如 fe80::1
	Zone   string // 链路本地地址挂的网卡名（有就带，只影响显示）
	CIDR   string // 带前缀长度的写法，如 192.168.1.10/24；前缀未知时等于 IP
	Family string // ipv4 / ipv6
	Scope  string // 取自 netaddr：private / global / link-local / loopback / multicast
}

// Iface net.interfaces 读到的一块网卡。
type Iface struct {
	Name    string
	Index   int
	MAC     string
	MTU     int
	Up      bool
	Running bool
	Loop    bool
	Virtual bool
	Kind    string // ethernet / wifi / virtual / loopback…（探测给的）
	KindSrc string // os = 问系统问到的；name = 按名字猜的
	Addrs   []Addr

	// Parent 这块口是哪个设备的成员口（桥 → 桥名）。
	// ★ 空**不等于**「它是独立口」：Windows 这一路还没实现查法，问不到也是空。
	//   所以只有非空才允许折叠端口，见 build.go 的 ifacesPass。
	Parent string
}

// Neighbor net.neighbors 读到的一条邻居表项。
type Neighbor struct {
	Addr   string // 可能带 zone（NDP 的 fe80::1%en0）
	MAC    string
	Iface  string
	Family string
	State  string // 系统原样：REACHABLE / STALE / FAILED / 动态 / incomplete…
	Source string // 哪个探测给的："net.neighbors.v4"（ARP）/ "net.neighbors.v6"（NDP）
}

// Route net.routes 读到的一条路由。
type Route struct {
	Family      string
	Destination string // CIDR
	Gateway     string
	Iface       string
	Direct      bool
	Metric      int
}

// LLDPDevice 被问的那台设备的**本地**系统数据（lldpLoc*）。
type LLDPDevice struct {
	SysName   string   // lldpLocSysName
	ChassisID string   // lldpLocChassisId（是 MAC 时就是 MAC）
	Addrs     []string // 它的管理地址（我们问它用的那个地址也是探测事实，所以带着）
	Caps      []string // 归一后的能力词：bridge / router / wlanAP / stationOnly…
	PortNames []string // 它自己写在 lldpLocPortTable 里的口名
}

// LLDPNeighbor 那台设备邻居表（lldpRemTable）里的一行。
type LLDPNeighbor struct {
	PortNum   int      // lldpRemLocalPortNum
	LocalPort string   // 那个口在它本机上叫什么
	ChassisID string   // 对端是哪台（MAC 或别的标识）
	SysName   string   // 对端自称叫什么
	PortID    string   // 插在它对端哪个口上
	Addrs     []string // 对端留的管理地址
	Caps      []string // 对端开着的 capability
	Aging     bool     // 这一趟观测里这个口的邻居老化过（这一行会消失，不是常驻）
}

// LLDP 一次 net.snmp.lldp 的结果。
//
// ★ Unavailable 非空表示**没有**二层证据，而且把原因带过来了：
// 没给设备地址/团体名、SNMP 没回话、这台没有 LLDP-MIB 这一棵、只发 CDP……
// 「没跑这个探测」和「跑了而这台不说 LLDP」在图上是一样的（都画不出线），
// 但人要看的下一句话完全不同，所以这一栏要如实传上来，它直接进 blind。
type LLDP struct {
	Device      LLDPDevice
	Neighbors   []LLDPNeighbor
	Unavailable string
}

// Gap 收集层如实报上来的「这一项没做成」。
//
// ★ 为什么非要这一项：图空着有两种原因 —— 「这个网里真的没有」和「这个探测读不到」，
//
//	成图逻辑自己分不清。ARP 表为空 vs 这个平台的 arp 命令跑挂了，
//	在数据结构上长得一模一样，而下一步完全相反。
type Gap struct {
	Probe  string // 哪个探测，如 "net.neighbors"
	Reason string // 为什么没做成（原样抄工具给的说明）
}

// Inputs 一次成图需要的全部事实。
type Inputs struct {
	LocalName string // 这台机器自称什么（探测来的，不是我们编的）
	// Probes 这一次**跑成了**哪些探测（工具名，如 net.interfaces）。
	//
	// ★ 收集层愿意交代时才用来兜「这一格为什么是空的」：跑挂了会报 Gap，
	//	但「这次压根没问邻居表」（调用方只给了网卡和路由）也是一种空。
	//	不填就等于不交代，成图逻辑不据此说任何话（见 build.go 的 missingProbes）。
	Probes    []string
	Ifaces    []Iface
	Neighbors []Neighbor
	Routes    []Route
	LLDP      LLDP
	Gaps      []Gap
	// HubThreshold 一块网卡上听见多少个不同邻居就算「中间大概有台交换机」。
	// 0 = 用 DefaultHubThreshold。
	HubThreshold int
}

// baselineProbes 这张图的默认底线：这几项探测跑齐了，图才说得清「谁在哪个网里」。
// net.snmp.lldp 不在这里 —— 它十有八九问不到（要设备地址、要团体名），
// 问不到是 topo-l2-blind 那一档的事，不是「漏跑了一项基础探测」。
var baselineProbes = []string{srcInterfaces, srcNeighbors, srcRoutes}

// DefaultHubThreshold 的取法：★ 这个数不是为了「准」，是为了「值得多看一眼」。
// 一个真实的接入 VLAN 里十几台是常态，但**没有 LLDP 时我们分不清**
// 「一个口下挂 30 台」和「中间还有一台不说话的交换机」——
// 5 台以下按直连带过（现场一个口上接 PC+打印机+摄像头+AP+电话很常见），
// 再多就该问一句「这个口下面是不是还有东西」。要改就改 Inputs.HubThreshold。
const DefaultHubThreshold = 5

// tunnelIfacePrefixes 名字像隧道口的网卡名前缀（小写比）。
//
// ★ 只按名字认，而且要承认是按名字：netif 给的 Kind 在 Windows 上是「按问到的介质」，
//
//	问不到时是猜的（KindSrc=name）。所以隧道的判定只用来决定**线画成 l3 还是 tunnel**，
//	不用来说「这条隧道通不通」—— 那要另外探测。
var tunnelIfacePrefixes = []string{
	"utun", "tun", "tap", "wg", "ipsec", "gre", "gretap", "ipip",
	"ip6tnl", "sit", "ppp", "slip", "ovpn", "wintun", "dtap", "dvp",
}

// ── 图 ──

// Stats 判定的依据，全部放进 Values 给人对着看。
type Stats struct {
	KindCounts       map[string]int `json:"kindCounts"`
	LayerCounts      map[string]int `json:"layerCounts"`
	StackCounts      map[string]int `json:"stackCounts"`
	L2Confirmed      bool           `json:"l2Confirmed"`
	NeighborsByIface map[string]int `json:"neighborsByIface"`
	IslandIfaces     []string       `json:"islandIfaces"`
	HubIfaces        []string       `json:"hubIfaces"`
	GatewayIDs       []string       `json:"gateways"`
	DualStack        []string       `json:"dualStackIfaces"`
	Skew             []string       `json:"skew"`
	Conflicts        []string       `json:"conflicts"`
	LoopbackSkipped  []string       `json:"loopbackSkipped"`
	// MembersFolded 被折进父设备（桥）而没有单独立方块的成员口，形状 `en1→bridge0`。
	// ★ 单列出来是因为「图上少了一块网卡」绝不能悄悄发生（同 LoopbackSkipped 那条理由），
	//   而且现场要查的常常正是「线插在 en1 还是 en2」——折进桥不等于这块口不存在。
	MembersFolded []string `json:"membersFolded"`
	MaxNeighbors  int      `json:"maxNeighborsPerIface"`
	HubThreshold  int      `json:"hubThreshold"`
}

// Graph 成图结果。
type Graph struct {
	Nodes []Node   `json:"nodes"`
	Edges []Edge   `json:"edges"`
	Codes []string `json:"codes"`
	Blind []string `json:"blind"`
	Stats Stats    `json:"stats"`

	// 规范化过的输入（排序后原样带回去，界面上「点进去看原始事实」的就是这几张表）。
	Ifaces    []Iface    `json:"ifaces"`
	Neighbors []Neighbor `json:"neighbors"`
	Routes    []Route    `json:"routes"`
}

// Code 顶层那一个码。★ Values["codes"] 里是全量 —— 界面对**每一个**命中的码
// 都要渲染一句话，只给一个就把「同时是孤岛又没有二层证据」这种事实压成了一句。
func (g Graph) Code() string {
	for _, c := range codePriority {
		for _, got := range g.Codes {
			if got == c {
				return c
			}
		}
	}
	return CodeOK
}

// Values 出参的 Values。★ 键名是与画布层的合同，跟着这个包一起放，
// 免得合同长在收集层里、改了键没人知道另一头在读什么。
func (g Graph) Values() map[string]any {
	return map[string]any{
		"nodes":                g.Nodes,
		"edges":                g.Edges,
		"nodeCount":            len(g.Nodes),
		"edgeCount":            len(g.Edges),
		"blind":                g.Blind,
		"ifaces":               g.Ifaces,
		"neighbors":            g.Neighbors,
		"routes":               g.Routes,
		"codes":                g.Codes,
		"kindCounts":           g.Stats.KindCounts,
		"layerCounts":          g.Stats.LayerCounts,
		"stackCounts":          g.Stats.StackCounts,
		"l2Confirmed":          g.Stats.L2Confirmed,
		"neighborsByIface":     g.Stats.NeighborsByIface,
		"maxNeighborsPerIface": g.Stats.MaxNeighbors,
		"islandIfaces":         g.Stats.IslandIfaces,
		"hubIfaces":            g.Stats.HubIfaces,
		"gateways":             g.Stats.GatewayIDs,
		"dualStackIfaces":      g.Stats.DualStack,
		"skew":                 g.Stats.Skew,
		"conflicts":            g.Stats.Conflicts,
		"loopbackSkipped":      g.Stats.LoopbackSkipped,
		"membersFolded":        g.Stats.MembersFolded,
		"hubThreshold":         g.Stats.HubThreshold,
	}
}

// Note 给日志和命令行的人话。★ 界面不看它（它按 Code 渲染），所以这里可以写得具体。
func (g Graph) Note() string {
	if len(g.Blind) > 0 {
		return fmt.Sprintf("%d 个节点 %d 条线；%s；★ 看不见的有 %d 处（见 blind）",
			len(g.Nodes), len(g.Edges), strings.Join(g.Codes, "、"), len(g.Blind))
	}
	return fmt.Sprintf("%d 个节点 %d 条线；%s", len(g.Nodes), len(g.Edges), strings.Join(g.Codes, "、"))
}
