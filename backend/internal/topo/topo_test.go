package topo

// 这一整套夹具跑的是「合成」这一层：不碰系统、不碰网络，
// 每一块网卡、每一条邻居、每一路由、每一行 LLDP 都是**手填的事实**。
//
// ★★ 为什么必须是夹具：真机上「交换机没有 LLDP agent」「ARP 表是空的」
//
//	「v6 没路由」这三种病等不出来，CI 里更跑不出。而它们正是这张图最容易画错的地方 ——
//	画错了在真机上看不出来（图看着挺完整），只在现场把人指去查一个没接的端口。
//	分成两层（topo 纯函数 + tools 收集）就是为了让这些病能用夹具跑满。
//
// 每个用例都跑一遍**通用不变量**（testInvariants）：合同里写死的那些
// （evidence 非空、source 非空、id 唯一且有序、枚举值合法、双栈不合线）
// 不是某一个用例的期望，是每一个用例都必须成立的东西。

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── 夹具 ──

func mustAddr(ip, cidr, family, scope string) Addr {
	return Addr{IP: ip, CIDR: cidr, Family: family, Scope: scope}
}

func v4Iface(name string, index int, mac string, addrs ...Addr) Iface {
	return Iface{Name: name, Index: index, MAC: mac, MTU: 1500,
		Up: true, Running: true, Kind: "ethernet", KindSrc: "os", Addrs: addrs}
}

func nb(ip, mac, iface, family, state string) Neighbor {
	src := "net.neighbors.v4"
	if family == "ipv6" {
		src = "net.neighbors.v6"
	}
	return Neighbor{Addr: ip, MAC: mac, Iface: iface, Family: family, State: state, Source: src}
}

func route(fam, dest, gw, iface string, metric int) Route {
	return Route{Family: fam, Destination: dest, Gateway: gw, Iface: iface,
		Direct: gw == "", Metric: metric}
}

// lanIn 一台最普通的机器：一块双栈网卡、网关在段里、有默认路由、没问 LLDP。
func lanIn() Inputs {
	return Inputs{
		LocalName: "workstation",
		Probes:    []string{"net.interfaces", "net.neighbors", "net.routes"},
		Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:01",
			mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"),
			mustAddr("fd00::10", "fd00::10/64", "ipv6", "global"),
			mustAddr("fe80::1", "fe80::1/64", "ipv6", "link-local"))},
		Neighbors: []Neighbor{
			nb("192.168.1.1", "aa:bb:cc:dd:11:22", "en0", "ipv4", "REACHABLE"),
			nb("192.168.1.20", "aa:bb:cc:dd:33:44", "en0", "ipv4", "STALE"),
			nb("fd00::1", "aa:bb:cc:dd:11:22", "en0", "ipv6", "REACHABLE"),
		},
		Routes: []Route{
			route("ipv4", "0.0.0.0/0", "192.168.1.1", "en0", 0),
			route("ipv4", "192.168.1.0/24", "", "en0", 0),
			route("ipv6", "::/0", "fd00::1", "en0", 0),
			route("ipv6", "fd00::/64", "", "en0", 0),
		},
	}
}

// ── 用例 ──

func TestBuild判定(t *testing.T) {
	cases := []struct {
		name  string
		in    Inputs
		want  string   // Code() —— 顶层那一个
		also  []string // codes 里还必须出现的
		check func(*testing.T, Graph)
	}{{
		// ① 单机、没有网关：本网打得通、一条带下一跳的路由都没有。
		name: "单主机没有网关",
		in: Inputs{
			LocalName: "cam-box",
			Ifaces: []Iface{v4Iface("eth0", 2, "aa:bb:cc:dd:ee:02",
				mustAddr("10.0.0.5", "10.0.0.5/24", "ipv4", "private"))},
			Neighbors: []Neighbor{nb("10.0.0.9", "aa:bb:cc:dd:55:66", "eth0", "ipv4", "REACHABLE")},
			Routes:    []Route{route("ipv4", "10.0.0.0/24", "", "eth0", 0)},
		},
		want: CodeNoGateway,
		also: []string{CodeL2Blind},
		check: func(t *testing.T, g Graph) {
			if n := countKind(g, KindSwitch); n != 0 {
				t.Errorf("凭空画了 %d 个交换机方块", n)
			}
			// 邻居那台设备要上图，且挂在网段上（不是挂在网卡上当直连线）。
			if countKind(g, KindHost) != 1 {
				t.Errorf("对端设备 %d 个，应该是 1 个", countKind(g, KindHost))
			}
		},
	}, {
		// ② 一块双栈网卡 = 两根线（★ 合成一根就把 v6 半条链路的病藏起来）。
		name: "双栈网卡画两根线",
		in:   lanIn(),
		want: CodeL2Blind,
		check: func(t *testing.T, g Graph) {
			var got []string
			for _, e := range g.Edges {
				if e.From == "iface:en0" && strings.HasPrefix(e.To, "segment:") {
					got = append(got, e.Stack+"→"+e.To)
				}
			}
			if len(got) != 2 {
				t.Fatalf("en0 挂出的三层线是 %d 根，应该是 2 根（v4、v6 各一根）：%v", len(got), got)
			}
			if got[0] == got[1] {
				t.Errorf("两根线一模一样，栈没分开：%v", got)
			}
			// ★ 两根线分别要能看出走哪一栈（不是「两个不同的网段」就算过关）。
			var stacks []string
			for _, e := range g.Edges {
				if e.From == "iface:en0" && strings.HasPrefix(e.To, "segment:") {
					stacks = append(stacks, e.Stack)
				}
			}
			if !containsStr(stacks, StackV4) || !containsStr(stacks, StackV6) {
				t.Errorf("双栈网卡挂出的三层线没有分开两栈：%v", stacks)
			}
			if countKind(g, KindSegment) != 2 {
				t.Errorf("网段方块 %d 个，双栈应该是 2 个（192.168.1.0/24 与 fd00::/64）",
					countKind(g, KindSegment))
			}
			// fe80::/64 不许当网段：每块网卡都是它，会毫不相干的口合成同一个方块。
			for _, n := range g.Nodes {
				if n.Kind == KindSegment && strings.HasPrefix(n.ID, "segment:fe80") {
					t.Errorf("把链路本地前缀当成了网段节点：%s", n.ID)
				}
				if n.Kind == KindSegment && strings.HasPrefix(n.ID, "segment:169.254") {
					t.Errorf("把 169.254 当成了网段节点：%s", n.ID)
				}
			}
			// 链路本地地址本身要留在网卡节点上（「不许藏 fe80」）。
			ifa, ok := nodeByID(g, "iface:en0")
			if !ok {
				t.Fatal("网卡节点不在图上")
			}
			if !hasStr(ifa.Addrs, "fe80::1") {
				t.Errorf("网卡节点上没有 fe80 地址：%v", ifa.Addrs)
			}
		},
	}, {
		// ③ ARP 30 个邻居：只报怀疑，**不画交换机**。
		name: "一块口上三十个邻居（hub 怀疑）",
		in: Inputs{
			LocalName: "core-pc",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:03",
				mustAddr("192.168.9.10", "192.168.9.10/24", "ipv4", "private"))},
			Neighbors: thirtyNeighbors("en0", "192.168.9."),
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "192.168.9.1", "en0", 0),
				route("ipv4", "192.168.9.0/24", "", "en0", 0),
			},
			HubThreshold: 5,
		},
		want: CodeHubSuspect,
		also: []string{CodeL2Blind},
		check: func(t *testing.T, g Graph) {
			if k := countKind(g, KindSwitch); k != 0 {
				t.Errorf("画了 %d 个交换机方块 —— ARP 表看不见它，一个都不许画", k)
			}
			if g.Stats.MaxNeighbors != 30 {
				t.Errorf("maxNeighborsPerIface = %d，应该 30", g.Stats.MaxNeighbors)
			}
			if len(g.Stats.HubIfaces) != 1 || !strings.HasPrefix(g.Stats.HubIfaces[0], "en0(") {
				t.Errorf("hubIfaces = %v", g.Stats.HubIfaces)
			}
			// 怀疑那句必须写清「怎么坐实」，否则这一档等于没说。
			if !anyContains(g.Blind, "net.snmp.lldp") {
				t.Error("hub 怀疑没写明要拿什么探测坐实")
			}
			if countKind(g, KindHost) != 30 {
				t.Errorf("对端设备 %d 台，应该 30 台（按 MAC 去重后）", countKind(g, KindHost))
			}
		},
	}, {
		// ④ LLDP 确认的上联：这一档才允许出现交换机方块 + 二层的线。
		name: "LLDP 确认的上联",
		in: Inputs{
			LocalName: "workstation",
			Probes:    []string{"net.interfaces", "net.neighbors", "net.routes", "net.snmp.lldp"},
			Ifaces: []Iface{v4Iface("en0", 4, "AA:BB:CC:DD:EE:01",
				mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"))},
			Neighbors: []Neighbor{nb("192.168.1.1", "aa:bb:cc:dd:11:22", "en0", "ipv4", "REACHABLE")},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "192.168.1.1", "en0", 0),
				route("ipv4", "192.168.1.0/24", "", "en0", 0),
			},
			LLDP: LLDP{
				Device: LLDPDevice{
					SysName:   "sw-floor3",
					ChassisID: "AA:BB:CC:DD:11:22", // LLDP 那栏是大写
					Addrs:     []string{"192.168.1.1（它本机的 ifIndex 3）"},
					Caps:      []string{"bridge", "router"},
					PortNames: []string{"GE1/0/5", "GE1/0/6"},
				},
				// 这一行说的是**我们**：对端机箱标识 = 本机网卡的 MAC。
				Neighbors: []LLDPNeighbor{
					{PortNum: 5, LocalPort: "GE1/0/5", ChassisID: "AA:BB:CC:DD:EE:01",
						SysName: "workstation", PortID: "en0",
						Addrs: []string{"192.168.1.10"}, Caps: []string{"stationOnly"}},
				},
			},
		},
		want: CodeOK,
		check: func(t *testing.T, g Graph) {
			if !g.Stats.L2Confirmed {
				t.Error("有 LLDP 邻居行却没确认到二层")
			}
			sw := countKind(g, KindSwitch)
			if sw != 1 {
				t.Fatalf("交换机方块 %d 个，应该 1 个", sw)
			}
			var l2 []Edge
			for _, e := range g.Edges {
				if e.Layer == LayerL2 && strings.HasPrefix(e.From, "iface:") {
					l2 = append(l2, e)
				}
			}
			if len(l2) == 0 {
				t.Fatal("没有 iface↔交换机 的二层线")
			}
			for _, e := range l2 {
				if !anyContains(e.Evidence, "net.snmp.lldp") {
					t.Errorf("二层线 %s 的证据里没有 net.snmp.lldp：%v", e.ID, e.Evidence)
				}
				if e.State != StateUp {
					t.Errorf("LLDP 直报的相邻线状态是 %s，应该是 up", e.State)
				}
			}
			// 二层线不分栈：填一个值就是编的。
			for _, e := range g.Edges {
				if e.Layer == LayerL2 && e.Stack != "" {
					t.Errorf("二层线 %s 标了栈 %s", e.ID, e.Stack)
				}
			}
			// 大写 MAC 要归一，否则同一块网卡在图上是两个 MAC。
			ifa, _ := nodeByID(g, "iface:en0")
			if len(ifa.MACs) != 1 || ifa.MACs[0] != "aa:bb:cc:dd:ee:01" {
				t.Errorf("网卡 MAC 没归一：%v", ifa.MACs)
			}
		},
	}, {
		// ⑤ 孤岛：链路活着、地址配了，可它什么都够不着。
		name: "孤岛网卡",
		in: Inputs{
			LocalName: "box",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:04",
				mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"))},
			Routes: []Route{route("ipv4", "192.168.1.0/24", "", "en0", 0)},
		},
		want: CodeIsland,
		also: []string{CodeNoGateway, CodeL2Blind},
		check: func(t *testing.T, g Graph) {
			if len(g.Stats.IslandIfaces) != 1 || g.Stats.IslandIfaces[0] != "en0" {
				t.Errorf("islandIfaces = %v", g.Stats.IslandIfaces)
			}
			if !anyContains(g.Blind, "孤岛") {
				t.Error("blind 里没有孤岛那一句")
			}
		},
	}, {
		// ⑤b 只有链路的本地地址（169.254）不算孤岛：那是「还没配上地址」，另一件事。
		name: "没拿到地址的口不判孤岛",
		in: Inputs{
			LocalName: "box",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:05",
				mustAddr("169.254.1.2", "169.254.1.2/16", "ipv4", "link-local"))},
			Routes: []Route{route("ipv4", "169.254.0.0/16", "", "en0", 0)},
		},
		want: CodeNoGateway,
		check: func(t *testing.T, g Graph) {
			if len(g.Stats.IslandIfaces) != 0 {
				t.Errorf("169.254 的口被判成孤岛：%v", g.Stats.IslandIfaces)
			}
			if countKind(g, KindSegment) != 0 {
				t.Error("链路本地前缀被建成了网段节点")
			}
		},
	}, {
		// ⑥ 同一个地址配在两块网卡上：这块网段画不成一个方块。
		name: "同一地址两块网卡",
		in: Inputs{
			LocalName: "dual-nic",
			Ifaces: []Iface{
				v4Iface("en0", 4, "aa:bb:cc:dd:ee:06",
					mustAddr("10.10.0.5", "10.10.0.5/24", "ipv4", "private")),
				v4Iface("en1", 5, "aa:bb:cc:dd:ee:07",
					mustAddr("10.10.0.5", "10.10.0.5/24", "ipv4", "private")),
			},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "10.10.0.1", "en0", 0),
				route("ipv4", "10.10.0.0/24", "", "en0", 0),
			},
		},
		want: CodeSegmentConflict,
		check: func(t *testing.T, g Graph) {
			if len(g.Stats.Conflicts) == 0 {
				t.Fatal("矛盾一处都没记")
			}
			if !anyContains(g.Stats.Conflicts, "10.10.0.5") {
				t.Errorf("conflicts 里没提到那个地址：%v", g.Stats.Conflicts)
			}
		},
	}, {
		// ⑥b 邻居表里出现本机自己的地址、且 MAC 不是本机的 —— 地址冲突。
		name: "邻居表里有人用本机的地址",
		in: Inputs{
			LocalName: "cam",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:08",
				mustAddr("10.20.0.5", "10.20.0.5/24", "ipv4", "private"))},
			Neighbors: []Neighbor{
				nb("10.20.0.5", "aa:bb:cc:11:22:33", "en0", "ipv4", "REACHABLE"),
				nb("10.20.0.1", "aa:bb:cc:dd:ee:99", "en0", "ipv4", "REACHABLE"),
			},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "10.20.0.1", "en0", 0),
				route("ipv4", "10.20.0.0/24", "", "en0", 0),
			},
		},
		want: CodeSegmentConflict,
		check: func(t *testing.T, g Graph) {
			// ★ 不许把抢地址的那台画成第二个「本机」方块。
			if n := nodeByAddr(g, "10.20.0.5"); n.Kind != KindIface {
				t.Errorf("本机地址落到了 %s 节点上，应该是网卡节点", n.Kind)
			}
		},
	}, {
		// ⑦ 什么都没有：一块网卡都没读到。
		name:  "全空",
		in:    Inputs{},
		want:  CodeNoIfaces,
		check: func(t *testing.T, g Graph) {},
	}, {
		// ⑦b 只有回环：同样没有可画的口。
		name: "只有回环",
		in: Inputs{LocalName: "box", Ifaces: []Iface{{
			Name: "lo0", Index: 1, Loop: true, Up: true, Running: true, MTU: 16384,
			Addrs: []Addr{mustAddr("127.0.0.1", "127.0.0.1/8", "ipv4", "loopback"),
				mustAddr("::1", "::1/128", "ipv6", "loopback")},
		}}},
		want: CodeNoIfaces,
		check: func(t *testing.T, g Graph) {
			if len(g.Stats.LoopbackSkipped) != 1 {
				t.Errorf("少画的回环没记：%v", g.Stats.LoopbackSkipped)
			}
		},
	}, {
		// ⑧ 双栈偏斜：两族都有地址，v6 却没有默认路由。
		name: "v6 没有默认路由",
		in: Inputs{
			LocalName: "dual",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:09",
				mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"),
				mustAddr("fd00::10", "fd00::10/64", "ipv6", "global"))},
			Neighbors: []Neighbor{nb("192.168.1.1", "aa:bb:cc:dd:11:22", "en0", "ipv4", "REACHABLE")},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "192.168.1.1", "en0", 0),
				route("ipv4", "192.168.1.0/24", "", "en0", 0),
				route("ipv6", "fd00::/64", "", "en0", 0),
			},
		},
		want: CodeDualStackSkew,
		also: []string{CodeL2Blind},
		check: func(t *testing.T, g Graph) {
			if len(g.Stats.Skew) == 0 {
				t.Fatal("偏斜一句都没记")
			}
			if !anyContains(g.Stats.Skew, "v6") {
				t.Errorf("偏斜那句没说是哪一层： %v", g.Stats.Skew)
			}
		},
	}, {
		// ⑨ LLDP 问了而这台不说：blind 里要带**原因**，不能只说「看不见」。
		name: "问了 LLDP 而这台不给",
		in: Inputs{
			LocalName: "pc",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:0a",
				mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"))},
			Neighbors: []Neighbor{nb("192.168.1.1", "aa:bb:cc:dd:11:22", "en0", "ipv4", "REACHABLE")},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "192.168.1.1", "en0", 0),
				route("ipv4", "192.168.1.0/24", "", "en0", 0),
			},
			LLDP: LLDP{Unavailable: "net.snmp.lldp（判定 snmp-lldp-unsupported）：这台没有 LLDP-MIB 这一棵"},
		},
		want: CodeL2Blind,
		check: func(t *testing.T, g Graph) {
			if !anyContains(g.Blind, "snmp-lldp-unsupported") {
				t.Errorf("把探测给的原因丢了，只说「看不见」：%v", g.Blind)
			}
			// ★ 「这台不说 LLDP」永远翻不成「那里没有线」。
			if anyContains(g.Blind, "没有交换机") {
				t.Error("把看不见说成了不存在")
			}
		},
	}, {
		// ⑩ 邻居老化过的那一行：线要画成 unknown，不许画成 up。
		name: "LLDP 邻居在老化",
		in: Inputs{
			LocalName: "pc",
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:0b",
				mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"))},
			Neighbors: []Neighbor{nb("192.168.1.1", "aa:bb:cc:dd:11:22", "en0", "ipv4", "REACHABLE")},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "192.168.1.1", "en0", 0),
				route("ipv4", "192.168.1.0/24", "", "en0", 0),
			},
			LLDP: LLDP{
				Device: LLDPDevice{SysName: "sw-1", ChassisID: "aa:bb:cc:dd:11:22", Caps: []string{"bridge"}},
				Neighbors: []LLDPNeighbor{{PortNum: 1, LocalPort: "Gi1", ChassisID: "aa:bb:cc:dd:ee:0b",
					SysName: "pc", Aging: true}},
			},
		},
		want: CodeOK,
		check: func(t *testing.T, g Graph) {
			var lldpEdges int
			for _, e := range g.Edges {
				if e.Layer != LayerL2 || !anyContains(e.Evidence, "net.snmp.lldp") {
					continue
				}
				lldpEdges++
				if e.State == StateUp {
					t.Errorf("LLDP 报的线画成 up：%s", e.ID)
				}
			}
			if lldpEdges == 0 {
				t.Fatal("没有 LLDP 报出来的二层线，这一条没在测东西")
			}
		},
	}, {
		// ⑪ 隧道口：同一句「去往 X 走 G」，从 utun 出去和从网线出去是两种画法。
		name: "走隧道的上游线",
		in: Inputs{
			LocalName: "vpn-box",
			Ifaces: []Iface{v4Iface("utun5", 9, "",
				mustAddr("10.99.0.6", "10.99.0.6/32", "ipv4", "private"))},
			Routes: []Route{route("ipv4", "0.0.0.0/0", "10.99.0.1", "utun5", 0)},
		},
		want: CodeL2Blind,
		check: func(t *testing.T, g Graph) {
			var tun int
			for _, e := range g.Edges {
				if e.Layer == LayerTunnel {
					tun++
				}
				if e.Layer == LayerL2 && strings.HasPrefix(e.From, "iface:utun") {
					t.Errorf("隧道口被画成二层直连：%s", e.ID)
				}
			}
			if tun == 0 {
				t.Error("去往隧道路线的线没有标成 tunnel")
			}
			// ★ 路由给的线一律 unknown：表证明的是「打算怎么走」，一个字都没证明走得到。
			for _, e := range g.Edges {
				if e.Layer == LayerTunnel && e.State != StateUnknown {
					t.Errorf("隧道线 %s 状态是 %s，路由表推不出状态", e.ID, e.State)
				}
			}
		},
	}, {
		// ⑫ 探测读不到 ≠ 那里没有东西：Gap 必须逐条进 blind。
		name: "邻居表读不到（不是空表）",
		in: Inputs{
			LocalName: "server",
			Gaps:      []Gap{{Probe: "net.neighbors", Reason: "这个平台的 arp 命令跑挂了"}},
			Ifaces: []Iface{v4Iface("en0", 4, "aa:bb:cc:dd:ee:0c",
				mustAddr("192.168.1.10", "192.168.1.10/24", "ipv4", "private"))},
			Routes: []Route{
				route("ipv4", "0.0.0.0/0", "192.168.1.1", "en0", 0),
				route("ipv4", "192.168.1.0/24", "", "en0", 0),
			},
		},
		want: CodeL2Blind,
		check: func(t *testing.T, g Graph) {
			if !anyContains(g.Blind, "跑挂") {
				t.Errorf("没把「读不到」原样带进 blind：%v", g.Blind)
			}
			// ★ 读不到邻居时不能判孤岛（那是「我们没测到」，不是「这块口什么都够不着」）。
			if len(g.Stats.IslandIfaces) != 0 {
				t.Errorf("邻居表没读回来就判了孤岛：%v", g.Stats.IslandIfaces)
			}
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := Build(tc.in)
			if got := g.Code(); got != tc.want {
				t.Errorf("顶层判定 = %s，想要 %s（codes = %v）", got, tc.want, g.Codes)
			}
			for _, c := range tc.also {
				if !containsStr(g.Codes, c) {
					t.Errorf("codes 里少了 %s：%v", c, g.Codes)
				}
			}
			testInvariants(t, g)
			tc.check(t, g)
		})
	}
}

// ── 合同级不变量：每个用例都要成立 ──

var (
	allKinds  = []string{KindLocal, KindIface, KindSegment, KindHost, KindSwitch, KindGateway}
	allLayers = []string{LayerL2, LayerL3, LayerTunnel}
	allStates = []string{StateUp, StateDown, StateUnknown}
	allStacks = []string{"", StackV4, StackV6, StackBoth}
	allCodes  = []string{CodeOK, CodeNoIfaces, CodeL2Blind, CodeHubSuspect,
		CodeIsland, CodeNoGateway, CodeDualStackSkew, CodeSegmentConflict}
)

func testInvariants(t *testing.T, g Graph) {
	t.Helper()

	seen := map[string]bool{}
	for _, n := range g.Nodes {
		if n.ID == "" {
			t.Error("有个节点没有 id")
		}
		if seen[n.ID] {
			t.Errorf("节点 id 重复：%s", n.ID)
		}
		seen[n.ID] = true
		if !containsStr(allKinds, n.Kind) {
			t.Errorf("节点 %s 的 kind %q 不在合同枚举里", n.ID, n.Kind)
		}
		if !containsStr(allStates, n.State) {
			t.Errorf("节点 %s 的 state %q 不在合同枚举里", n.ID, n.State)
		}
		if !containsStr(allStacks, n.Stack) {
			t.Errorf("节点 %s 的 stack %q 不在合同枚举里", n.ID, n.Stack)
		}
		if n.Why == "" {
			t.Errorf("节点 %s 没说清它是被谁、按什么事实画上来的", n.ID)
		}
		if len(n.Source) == 0 {
			t.Errorf("节点 %s 没有 source —— 它就是凭空出现的", n.ID)
		}
		for _, s := range n.Source {
			if !strings.HasPrefix(s, "net.") {
				t.Errorf("节点 %s 的 source %q 不是一个探测名（合同要求它点得出哪张卡产出了这个方块）", n.ID, s)
			}
		}
	}
	if !sortedBy(g.Nodes, func(n Node) string { return n.ID }) {
		t.Error("nodes 没有按 id 排序 —— 界面对拍不了两次运行")
	}

	ids := map[string]bool{}
	for _, e := range g.Edges {
		if ids[e.ID] {
			t.Errorf("线 id 重复：%s", e.ID)
		}
		ids[e.ID] = true
		if !containsStr(allLayers, e.Layer) {
			t.Errorf("线 %s 的 layer %q 不在合同枚举里", e.ID, e.Layer)
		}
		if !containsStr(allStates, e.State) {
			t.Errorf("线 %s 的 state %q 不在合同枚举里", e.ID, e.State)
		}
		if !containsStr(allStacks, e.Stack) {
			t.Errorf("线 %s 的 stack %q 不在合同枚举里", e.ID, e.Stack)
		}
		// ★★ 三层/隧道线**必须**标出是哪一栈（docs/设计.md:255：「线上要能看出这条走的是
		//	哪一栈」）。合并成一栈或干脆不标，表现都在这同一行上：
		//	v6 半条链路坏掉（有地址、没路由）在图上和 v4 一模一样，
		//	而那种病的症状是「网很慢」，人根本不会想到去查 v6。
		if e.Layer != LayerL2 && e.Stack != StackV4 && e.Stack != StackV6 {
			t.Errorf("线 %s 是 %s 层却没有标栈（%q）—— 双栈被合成一根线了", e.ID, e.Layer, e.Stack)
		}
		if len(e.Evidence) == 0 {
			t.Errorf("线 %s 没有证据 —— 这就是那张设计稿禁止的手画示意图", e.ID)
		}
		for _, ev := range e.Evidence {
			if strings.TrimSpace(ev) == "" {
				t.Errorf("线 %s 的证据里有一句空白", e.ID)
			}
		}
		// ★ 证据必须点得出**是哪张卡说的**：光一句「它们连着」等于没有证据。
		if !anyContains(e.Evidence, "net.") {
			t.Errorf("线 %s 的证据里没有探测名：%v", e.ID, e.Evidence)
		}
		// ★★ 跨设备的二层线只许由 LLDP 画出来（local→本机网卡那一根除外：
		//	那是 net.interfaces 自己证明的，不涉及别人）。
		//	这一条就是「不许把同网段画成直接相连」在合同层的落点。
		if e.Layer == LayerL2 && e.From != "local" && !anyContains(e.Evidence, "net.snmp.lldp") {
			t.Errorf("二层线 %s 没有 LLDP 证据：%v", e.ID, e.Evidence)
		}
		// ★ 两端必须都在图上：悬空的端点画布画不出来，比少一根线难查得多。
		if !seen[e.From] {
			t.Errorf("线 %s 的 from %s 不在节点里", e.ID, e.From)
		}
		if !seen[e.To] {
			t.Errorf("线 %s 的 to %s 不在节点里", e.ID, e.To)
		}
	}
	if !sortedBy(g.Edges, func(e Edge) string { return e.ID }) {
		t.Error("edges 没有按 id 排序")
	}

	for _, c := range g.Codes {
		if !containsStr(allCodes, c) {
			t.Errorf("判定码 %q 不在这一张卡的码集里", c)
		}
	}
	if !sortedCodes(g.Codes) {
		t.Errorf("codes 没按优先级排：%v", g.Codes)
	}
	if len(g.Codes) == 0 {
		t.Error("codes 是空的：界面对每个命中都要渲染一句话")
	}
	if g.Blind == nil {
		t.Error("blind 是 nil（合同要求数组，界面上 .length 会炸）")
	}

	// 每个方块都得点得出「哪个探测产出的它」，每根线都点得出「哪条事实支撑它」。
	v := g.Values()
	for _, k := range []string{"nodes", "edges", "nodeCount", "edgeCount", "blind",
		"ifaces", "neighbors", "routes", "codes"} {
		if _, ok := v[k]; !ok {
			t.Errorf("Values 少了合同里的键 %s", k)
		}
	}
	if n, ok := v["nodeCount"].(int); !ok || n != len(g.Nodes) {
		t.Errorf("nodeCount = %v，实际 %d", v["nodeCount"], len(g.Nodes))
	}
	if n, ok := v["edgeCount"].(int); !ok || n != len(g.Edges) {
		t.Errorf("edgeCount = %v，实际 %d", v["edgeCount"], len(g.Edges))
	}

	// ★ JSON 标签是与画布层的合同：翻一遍再看键名，改了标签这里就会红。
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("图不能序列化：%v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("图不能反序列化：%v", err)
	}
	for _, k := range []string{"nodes", "edges", "codes", "blind", "stats", "ifaces", "neighbors", "routes"} {
		if _, ok := back[k]; !ok {
			t.Errorf("Graph 的 JSON 里没有 %s 这一栏（标签被改了？）", k)
		}
	}
	if len(g.Nodes) > 0 {
		first := g.Nodes[0]
		for _, k := range []string{"id", "kind", "label", "addrs", "macs", "ifaces",
			"stack", "state", "mtu", "source", "why"} {
			if !hasJSONKey(t, first, k) {
				t.Errorf("Node 的 JSON 里没有 %s —— 画布那边按这个键在读", k)
			}
		}
	}
	if len(g.Edges) > 0 {
		for _, k := range []string{"id", "from", "to", "layer", "stack", "ports", "evidence", "state"} {
			if !hasJSONKey(t, g.Edges[0], k) {
				t.Errorf("Edge 的 JSON 里没有 %s", k)
			}
		}
	}
}

func hasJSONKey(t *testing.T, v any, key string) bool {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("反序列化失败：%v", err)
	}
	_, ok := m[key]
	return ok
}

// ── 确定性 ──

// 界面对拍的就是「同一次改动前后的输出」，所以顺序**绝不能**来自 map 迭代。
func TestBuild确定性(t *testing.T) {
	base := lanIn()
	g1 := Build(base)
	g2 := Build(base)
	if a, b := dump(t, g1), dump(t, g2); a != b {
		t.Errorf("同一份事实两次输出不一样：\n%s\n---\n%s", a, b)
	}

	// 把输入切片的顺序整个反过来（真实系统里枚举顺序本来就不保证）。
	shuf := lanIn()
	shuf.Ifaces = reverseIfaces(shuf.Ifaces)
	shuf.Neighbors = reverseNeighbors(shuf.Neighbors)
	shuf.Routes = reverseRoutes(shuf.Routes)
	if a, b := dump(t, g1), dump(t, Build(shuf)); a != b {
		t.Errorf("输入顺序变了输出就变了（排序没做到位）：\n%s\n---\n%s", a, b)
	}
}

// ★ 这一条是专门冲「map 迭代顺序」去的：
//
//	邻居与网卡从 map 里取出来（Go 的 map 顺序每次都不一样），
//	只要合成里有哪一处直接拼了未排序的 map key，两次跑就会不一样。
func TestBuild不依赖map顺序(t *testing.T) {
	var out []string
	for i := 0; i < 12; i++ {
		in := lanIn()
		m := map[string]Iface{}
		for _, ifa := range in.Ifaces {
			m[ifa.Name] = ifa
		}
		nm := map[string]Neighbor{}
		for _, n := range in.Neighbors {
			nm[n.Addr] = n
		}
		var ifaces []Iface
		var neighs []Neighbor
		for _, ifa := range m {
			ifaces = append(ifaces, ifa)
		}
		for _, n := range nm {
			neighs = append(neighs, n)
		}
		in.Ifaces = ifaces
		in.Neighbors = neighs
		// 上面的 map 只有一个键，多轮取出来的顺序看不出来 —— 再加一块口、三条邻居。
		in.Ifaces = append(in.Ifaces, v4Iface("en1", 5, "aa:bb:cc:dd:ee:11",
			mustAddr("10.7.0.5", "10.7.0.5/24", "ipv4", "private")))
		in.Neighbors = append(in.Neighbors,
			nb("10.7.0.1", "aa:bb:cc:dd:ee:12", "en1", "ipv4", "REACHABLE"),
			nb("10.7.0.2", "aa:bb:cc:dd:ee:13", "en1", "ipv4", "STALE"),
			nb("10.7.0.3", "aa:bb:cc:dd:ee:14", "en1", "ipv4", "FAILED"))
		out = append(out, dump(t, Build(in)))
	}
	for i := 1; i < len(out); i++ {
		if out[i] != out[0] {
			t.Fatalf("第 %d 次和第 0 次输出不一样：\n%s\n---\n%s", i, out[i], out[0])
		}
	}
}

// ── 小助手 ──

func thirtyNeighbors(iface, prefix string) []Neighbor {
	var out []Neighbor
	for i := 1; i <= 30; i++ {
		out = append(out, nb(
			prefix+itoa(20+i),
			macOf(i), iface, "ipv4", "REACHABLE"))
	}
	return out
}

func macOf(i int) string {
	return "aa:bb:cc:00:00:" + hexByte(i)
}

func hexByte(i int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(i/16)%16], digits[i%16]})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func countKind(g Graph, kind string) int {
	n := 0
	for _, x := range g.Nodes {
		if x.Kind == kind {
			n++
		}
	}
	return n
}

func nodeByID(g Graph, id string) (Node, bool) {
	for _, x := range g.Nodes {
		if x.ID == id {
			return x, true
		}
	}
	return Node{}, false
}

func nodeByAddr(g Graph, ip string) Node {
	for _, x := range g.Nodes {
		for _, a := range x.Addrs {
			if a == ip || strings.HasPrefix(a, ip+"/") || strings.HasPrefix(a, ip+"%") {
				return x
			}
		}
	}
	return Node{}
}

func hasStr(list []string, s string) bool { return containsStr(list, s) }

func anyContains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func sortedBy[T any](list []T, key func(T) string) bool {
	for i := 1; i < len(list); i++ {
		if key(list[i-1]) > key(list[i]) {
			return false
		}
	}
	return true
}

func sortedCodes(codes []string) bool {
	rank := map[string]int{}
	for i, c := range codePriority {
		rank[c] = i
	}
	for i := 1; i < len(codes); i++ {
		if rank[codes[i-1]] > rank[codes[i]] {
			return false
		}
	}
	return true
}

func dump(t *testing.T, g Graph) string {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	return string(b)
}

func reverseIfaces(in []Iface) []Iface {
	out := append([]Iface(nil), in...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func reverseNeighbors(in []Neighbor) []Neighbor {
	out := append([]Neighbor(nil), in...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func reverseRoutes(in []Route) []Route {
	out := append([]Route(nil), in...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
