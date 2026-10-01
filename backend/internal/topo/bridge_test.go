package topo

// 桥的成员口折叠。真机形状是从这台 Mac 上抄的：bridge0 下面挂着 en1/en2/en3，
// 那三块自己一个可用地址都没有（地址都在 bridge0 / en0 上）。
//
// ★★ 这一组用例钉的是两种相反的错，两种都会把人带偏：
//   ① 不折 —— 图上凭空多出三个「没接线的口」，人以为机器有三块空闲网卡；
//   ② 折得太狠（连 MAC 一起丢）—— 邻居表里认到 en1 那个 MAC 的一行会被画成
//     **一台陌生设备**，人去登那个根本不存在的对端。

import (
	"strings"
	"testing"
)

func bridgeIn(members ...Iface) Inputs {
	in := Inputs{
		LocalName: "mac-mini",
		Probes:    []string{"net.interfaces", "net.neighbors", "net.routes"},
		Ifaces: []Iface{v4Iface("bridge0", 12, "36:c2:40:ea:c0:00",
			mustAddr("192.168.0.1", "192.168.0.1/24", "ipv4", "private"))},
		Routes: []Route{route("ipv4", "192.168.0.0/24", "", "bridge0", 0)},
	}
	in.Ifaces = append(in.Ifaces, members...)
	return in
}

func member(name string, index int, mac string) Iface {
	return Iface{Name: name, Index: index, MAC: mac, MTU: 1500,
		Up: true, Running: true, Kind: "ethernet", KindSrc: "os",
		Parent: "bridge0"}
}

func TestBuild成员口折进桥(t *testing.T) {
	g := Build(bridgeIn(
		member("en1", 10, "aa:bb:cc:dd:ee:11"),
		member("en2", 11, "aa:bb:cc:dd:ee:22"),
	))

	for _, id := range []string{"iface:en1", "iface:en2"} {
		if _, ok := nodeByID(g, id); ok {
			t.Errorf("%s 还单独立着方块：没地址的成员口应该折进桥", id)
		}
	}
	br, ok := nodeByID(g, "iface:bridge0")
	if !ok {
		t.Fatalf("桥那一头的方块没画出来，折叠无处可折")
	}
	for _, want := range []string{"en1", "en2"} {
		if !containsStr(br.Ifaces, want) {
			t.Errorf("bridge0 那格没有列出成员口 %s：%v", want, br.Ifaces)
		}
	}
	for _, want := range []string{"en1→bridge0", "en2→bridge0"} {
		if !containsStr(g.Stats.MembersFolded, want) {
			t.Errorf("stats.membersFolded 里少一条 %s：%v", want, g.Stats.MembersFolded)
		}
	}
	// ★ 折了方块不许丢身份：en1 的 MAC 必须在桥那一格的 MAC 列表里，
	//   否则邻居表认到它时会凭空造一台设备。
	if !containsStr(br.MACs, "aa:bb:cc:dd:ee:11") {
		t.Errorf("en1 的 MAC 被折掉了：%v", br.MACs)
	}
	// 证据得写明这个折叠是探测给的，不是我们按名字猜的。
	if !strings.Contains(br.Why, "net.interfaces") {
		t.Errorf("桥那一格的 why 没点名来源：%s", br.Why)
	}
}

// ★★ 最关键的一条：邻居表里出现成员口自己的 MAC 时，**不许画成对端设备**。
func TestBuild成员口MAC不会被画成陌生设备(t *testing.T) {
	in := bridgeIn(member("en1", 10, "aa:bb:cc:dd:ee:11"))
	// en1 的 MAC 在 bridge0 那一段上被听见（桥转发时源 MAC 就是成员口的）
	in.Neighbors = []Neighbor{nb("192.168.0.50", "aa:bb:cc:dd:ee:11", "bridge0", "ipv4", "REACHABLE")}
	g := Build(in)
	if n := countKind(g, KindHost); n != 0 {
		t.Errorf("把自己家 en1 的 MAC 画成了 %d 台对端设备", n)
	}
}

// 成员口自己带着可用地址（Internet Sharing 那种共享出来的口）：**不折**，
// 折了就是把人正在用的那块口藏起来。
func TestBuild有地址的成员口不折(t *testing.T) {
	en0 := v4Iface("en0", 6, "ae:bb:cc:dd:ee:ff",
		mustAddr("192.168.1.30", "192.168.1.30/24", "ipv4", "private"))
	en0.Parent = "bridge0"
	in := bridgeIn(en0)
	g := Build(in)
	if _, ok := nodeByID(g, "iface:en0"); !ok {
		t.Fatalf("有可用地址的成员口被折掉了 —— 图上少了一块真在干活的口")
	}
	n, _ := nodeByID(g, "iface:en0")
	if !strings.Contains(n.Why, "bridge0") {
		t.Errorf("没在图上写明它同时是 bridge0 的成员口：%s", n.Why)
	}
	if containsStr(g.Stats.MembersFolded, "en0→bridge0") {
		t.Errorf("没折却记进了折叠账：%v", g.Stats.MembersFolded)
	}
}

// 父设备不在 net.interfaces 里（桥被关了、或者两块探测读岔了）：**不替没见过的东西造方块**。
func TestBuild父口没见过就不折(t *testing.T) {
	orphan := member("en7", 20, "aa:bb:cc:dd:ee:77")
	orphan.Parent = "bridge9"
	in := bridgeIn(orphan)
	g := Build(in)
	if _, ok := nodeByID(g, "iface:en7"); !ok {
		t.Errorf("父口 bridge9 压根没被探测到，en7 却被折进了一个不存在的方块")
	}
	if _, ok := nodeByID(g, "iface:bridge9"); ok {
		t.Errorf("凭空造出了 iface:bridge9")
	}
}

// 这个平台没实现查法（parent 全空）：一口不变，谁都不折。
func TestBuild没有parent信息时一口不折(t *testing.T) {
	in := bridgeIn()
	in.Ifaces = append(in.Ifaces, Iface{Name: "en1", Index: 10, MAC: "aa:bb:cc:dd:ee:11",
		MTU: 1500, Up: true, Running: true, Kind: "ethernet", KindSrc: "os"})
	g := Build(in)
	if _, ok := nodeByID(g, "iface:en1"); !ok {
		t.Errorf("没拿到父子关系却折掉了端口（Windows 那条现在就是这个形状）")
	}
	if len(g.Stats.MembersFolded) != 0 {
		t.Errorf("parent 全空却记了折叠账：%v", g.Stats.MembersFolded)
	}
}

// 桥套桥：只按**直接**父口折一层，不许把孙子一路吸到最顶上。
func TestBuild桥套桥只折一层(t *testing.T) {
	in := Inputs{LocalName: "nest", Probes: []string{"net.interfaces"},
		Ifaces: []Iface{
			v4Iface("bridge1", 30, "36:c2:40:ea:c0:01",
				mustAddr("10.10.0.1", "10.10.0.1/24", "ipv4", "private")),
			{Name: "bridge0", Index: 12, MAC: "36:c2:40:ea:c0:00", MTU: 1500,
				Up: true, Running: true, Kind: "virtual", KindSrc: "os", Parent: "bridge1"},
			member("en1", 10, "aa:bb:cc:dd:ee:11"),
		}}
	g := Build(in)
	if _, ok := nodeByID(g, "iface:bridge0"); !ok {
		t.Errorf("bridge0 被折进了 bridge1 —— 它自己还是个桥，端口关系要看得清")
	}
	if !containsStr(g.Stats.MembersFolded, "en1→bridge0") {
		t.Errorf("en1 该折到直接父口 bridge0：%v", g.Stats.MembersFolded)
	}
	b1, _ := nodeByID(g, "iface:bridge1")
	if containsStr(b1.Ifaces, "en1") {
		t.Errorf("en1 被隔代吸到了 bridge1 上：%v", b1.Ifaces)
	}
}
