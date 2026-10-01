package tools

// net.topology.build 的收集层测试。
//
// ★ 这一层只测两件事：
//
//	① 四个取事实的口子有没有**如实**翻成 topo 的输入 —— 特别是「读不到」必须翻成
//	  Gap（进 blind），不许翻成「那里没有东西」；
//	② 这张卡的声明是它的样子（read 类、schema 合法、注册进了表和排查路线）。
//
//	图本身对不对归 internal/topo 那套夹具管，在这儿重复测一遍形状没有意义；
//	而在这儿碰真的系统更没意义：这台机器上有几条路由、ARP 表里是谁，
//	不该决定测试结果（CI 在一台挂着 VPN 的机器上就红了，而红的那一条和这次改动无关）。

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/topo"
)

// stubFacts 是这一层的夹具：四个口子换成编出来的事实，测试结束换回来。
type stubFacts struct {
	nics   []netif.NIC
	nicErr error
	n4     []neighbor
	e4     error
	n6     []neighbor
	e6     error
	rt     []netif.Route
	rtErr  error
	lldp   any
	lldpEr error
}

func (f stubFacts) install(t *testing.T) *int {
	t.Helper()
	calls := 0
	oi, on4, on6, orr, ol, oh := topoInterfaces, topoNeighborsV4, topoNeighborsV6,
		topoRoutes, topoLLDPInvoke, topoHostname
	t.Cleanup(func() {
		topoInterfaces, topoNeighborsV4, topoNeighborsV6 = oi, on4, on6
		topoRoutes, topoLLDPInvoke, topoHostname = orr, ol, oh
	})
	topoInterfaces = func() ([]netif.NIC, error) { return f.nics, f.nicErr }
	topoNeighborsV4 = func(context.Context) ([]neighbor, error) { return f.n4, f.e4 }
	topoNeighborsV6 = func(context.Context) ([]neighbor, error) { return f.n6, f.e6 }
	topoRoutes = func() ([]netif.Route, error) { return f.rt, f.rtErr }
	topoLLDPInvoke = func(ctx context.Context, raw json.RawMessage) (any, error) {
		calls++
		// ★ 顺手验一下参数真的透传下去了：团体名不能被我们吃掉，
		//   否则「参数填了却没生效」会表现成「这台设备不回话」。
		if f.lldp != nil {
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Errorf("透传给 net.snmp.lldp 的参数不是合法 JSON：%s", raw)
			} else if got["community"] == "" {
				t.Errorf("透传的参数里没有团体名：%s", raw)
			}
		}
		return f.lldp, f.lldpEr
	}
	topoHostname = func() (string, error) { return "test-box", nil }
	return &calls
}

func mustAddrs(t *testing.T, cidrs ...string) []netaddr.Addr {
	t.Helper()
	var out []netaddr.Addr
	for _, s := range cidrs {
		a, err := netaddr.Parse(s)
		if err != nil {
			t.Fatalf("%s 解不开：%v", s, err)
		}
		out = append(out, a)
	}
	return out
}

// oneLAN 一台最普通的机器：一块网卡、网关在段里、有默认路由。
func oneLAN(t *testing.T) stubFacts {
	return stubFacts{
		nics: []netif.NIC{{Name: "en0", Index: 4, MAC: "aa:bb:cc:dd:ee:01", MTU: 1500,
			Up: true, Running: true, Kind: "ethernet", KindSrc: "os",
			Addrs: mustAddrs(t, "192.168.1.10/24")}},
		n4: []neighbor{{Addr: "192.168.1.1", MAC: "aa:bb:cc:dd:11:22", Iface: "en0",
			Family: "ipv4", State: "REACHABLE"}},
		rt: []netif.Route{
			{Family: "ipv4", Destination: "192.168.1.0/24", Iface: "en0", Direct: true},
			{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"},
		},
	}
}

func Test拓扑卡声明(t *testing.T) {
	if topologyTool.Name != "net.topology.build" {
		t.Errorf("名字是 %s", topologyTool.Name)
	}
	// ★ read：这张卡只是把已经读到的东西合起来，自己一个包都不发。
	if topologyTool.Class != ots.ClassRead {
		t.Errorf("只是读本机，类别却是 %s", topologyTool.Class)
	}
	if topologyTool.Invoke == nil {
		t.Fatal("没有 Invoke")
	}
	if !json.Valid(topologyTool.Schema) {
		t.Error("Schema 不是合法 JSON")
	}
	var m map[string]any
	if err := json.Unmarshal(topologyTool.Schema, &m); err != nil {
		t.Fatalf("Schema 解不开：%v", err)
	}
	if m["additionalProperties"] != false {
		t.Error("必须明确拒收多余字段")
	}
	props, _ := m["properties"].(map[string]any)
	for _, k := range []string{"lldpAddr", "lldpCommunity", "hubThreshold", "noLldp"} {
		if _, ok := props[k]; !ok {
			t.Errorf("参数 %s 没声明 —— 调用方只能猜，猜错了就是一串莫名其妙的失败", k)
		}
	}
	if req, _ := m["required"].([]any); len(req) != 0 {
		t.Errorf("声明了必填参数 %v：这张卡不填任何参数也要能出图（二层标成看不见）", req)
	}
	// 摘要里必须把「不许画没见过的东西」写出来，否则调用方（AI）以为它会自动补线。
	for _, need := range []string{"blind", "evidence", "topo-l2-blind", "topo-hub-suspect"} {
		if !strings.Contains(topologyTool.Summary, need) {
			t.Errorf("摘要里没提 %s", need)
		}
	}
	r := ots.NewRegistry(true)
	Register(r)
	if _, ok := r.Lookup("net.topology.build"); !ok {
		t.Error("net.topology.build 没注册进注册表")
	}
}

func Test拓扑卡参数校验(t *testing.T) {
	stubFacts{}.install(t)
	ctx := context.Background()

	res, err := buildTopology(ctx, json.RawMessage(`{"hubThreshold":-1}`))
	if err == nil || !strings.Contains(errText(err), "hubThreshold") {
		t.Errorf("hubThreshold 负数没拦住：%v / %v", res, err)
	}
	if _, err := buildTopology(ctx, json.RawMessage(`{"lldpPortNum":3,"lldpIfIndex":3}`)); err == nil ||
		!strings.Contains(errText(err), "只能给一个") {
		t.Errorf("点名的口号和接口号同时给了却没拦：%v", err)
	}
	// 多余字段这一层不拦：本包的通行做法是「schema 声明 additionalProperties:false，
	// Go 侧宽松解码」（net.neighbors / net.routes / net.snmp.* 都是这样，全仓库没有一处
	// 用 DisallowUnknownFields）。在这里单独改成报错，只会让这张卡比别的卡更难用。
	if _, err := buildTopology(ctx, json.RawMessage(`{"nope":1}`)); err != nil {
		t.Errorf("多一个字段就失败，和同包的卡不一样：%v", err)
	}
}

// ★ 最要紧的一条：**没问 LLDP 时图照样出**，而且二层那一层明确标成看不见。
//
//	现场绝大多数调用就是「先看看这台机器连着什么」，手边没有交换机的地址和团体名。
//	那种情况整体失败，这张卡在真实使用里等于不存在。
func Test拓扑卡不依赖LLDP(t *testing.T) {
	calls := oneLAN(t).install(t)

	res, err := buildTopology(context.Background(), nil)
	if err != nil {
		t.Fatalf("没给 LLDP 参数就失败了：%v", err)
	}
	v, ok := res.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定，是 %T", res)
	}
	if v.Code != topo.CodeL2Blind {
		t.Errorf("顶层判定 = %s，没问 LLDP 时应该是 %s（codes = %v）",
			v.Code, topo.CodeL2Blind, v.Values["codes"])
	}
	for _, k := range []string{"nodes", "edges", "nodeCount", "edgeCount", "blind",
		"ifaces", "neighbors", "routes", "gateways", "hubThreshold"} {
		if _, ok := v.Values[k]; !ok {
			t.Errorf("Values 少了合同里的键 %s", k)
		}
	}
	if cnt, _ := v.Values["nodeCount"].(int); cnt < 3 {
		t.Errorf("nodeCount = %d，网卡 + 网段 + 网关至少三个方块", cnt)
	}
	b, _ := json.Marshal(v.Values["blind"])
	if !strings.Contains(string(b), "没问") {
		t.Errorf("blind 没写明是「这次没问」，只说看不见：%s", b)
	}
	if *calls != 0 {
		t.Errorf("没给地址却问了 %d 次 LLDP", *calls)
	}
	// ★ 跨设备的二层线一根都不许出现（没问 LLDP 就没有证据）。
	//	唯一的例外是 local→iface：那是「这块网卡挂在这台机器上」，
	//	net.interfaces 自己就证明了这件事，不涉及别人。
	raw, _ := json.Marshal(v.Values["edges"])
	if strings.Contains(string(raw), `"layer":"l2"`) {
		var edges []topo.Edge
		if err := json.Unmarshal(raw, &edges); err == nil {
			for _, e := range edges {
				if e.Layer == topo.LayerL2 && e.From != "local" &&
					!strings.Contains(strings.Join(e.Evidence, "|"), "net.snmp.lldp") {
					t.Errorf("二层线 %s 没有 LLDP 证据：%v", e.ID, e.Evidence)
				}
			}
		}
	}
}

// 问了 LLDP：那张卡回的事实要变成图上的交换机方块 + 二层的线。
func Test拓扑卡带LLDP(t *testing.T) {
	f := oneLAN(t)
	f.lldp = ots.Verdict{Code: snmpOk, Note: "读到 1 条邻居行", Values: map[string]any{
		"local": map[string]any{
			"sysName": "sw-floor3", "chassisId": "AA:BB:CC:DD:11:22",
			"capabilities":        []string{"交换（bridge）", "路由（router）"},
			"capabilitiesEnabled": []string{"交换（bridge）", "路由（router）"},
		},
		"neighbors": []map[string]any{{
			"portNum": 5, "localPortName": "GE1/0/5",
			"chassisId": "AA:BB:CC:DD:EE:01", "sysName": "test-box",
			"remotePortId": "en0", "mgmtAddresses": []string{"192.168.1.10（它没说挂在哪个接口上）"},
		}},
	}}
	calls := f.install(t)

	res, err := buildTopology(context.Background(),
		json.RawMessage(`{"lldpAddr":"192.168.1.1","lldpCommunity":"public"}`))
	if err != nil {
		t.Fatalf("%v", err)
	}
	v := res.(ots.Verdict)
	if v.Code != topo.CodeOK {
		t.Errorf("顶层判定 = %s， LLDP 都确认了应该是 %s（codes = %v）", v.Code, topo.CodeOK, v.Values["codes"])
	}
	if *calls != 1 {
		t.Errorf("问了 %d 次 LLDP，应该 1 次", *calls)
	}
	nb, _ := json.Marshal(v.Values["nodes"])
	if !strings.Contains(string(nb), `"kind":"switch"`) {
		t.Errorf("图上没有交换机方块：%s", nb)
	}
	eb, _ := json.Marshal(v.Values["edges"])
	if !strings.Contains(string(eb), "net.snmp.lldp") {
		t.Errorf("没有任何一根线引用 LLDP：%s", eb)
	}
	if got := v.Values["l2Confirmed"]; got != true {
		t.Errorf("l2Confirmed = %v", got)
	}
}

// LLDP 那张卡明确回了「这台不说 LLDP」：原因要原样进 blind，
// ★ 不许被我们翻成「那里没有接线」，也不许翻成「没有交换机」。
func Test拓扑卡带上LLDP失败原因(t *testing.T) {
	f := oneLAN(t)
	f.lldp = ots.Verdict{Code: snmpLldpUnsupported,
		Note: "问了 LLDP-MIB 下面的四组，一条都没给"}
	f.install(t)

	res, err := buildTopology(context.Background(),
		json.RawMessage(`{"lldpAddr":"192.168.1.1","lldpCommunity":"public"}`))
	if err != nil {
		t.Fatalf("%v", err)
	}
	v := res.(ots.Verdict)
	b, _ := json.Marshal(v.Values["blind"])
	if !strings.Contains(string(b), "snmp-lldp-unsupported") {
		t.Errorf("把那张卡的判定码丢了：%s", b)
	}
	if strings.Contains(string(b), "没有交换机") {
		t.Errorf("把看不见说成了不存在：%s", b)
	}
	if v.Code != topo.CodeL2Blind {
		t.Errorf("顶层判定 = %s，应该是 %s", v.Code, topo.CodeL2Blind)
	}
}

// 只给了地址、没给团体名：这是「我们没问」，不是「设备不回话」。
func Test拓扑卡缺团体名(t *testing.T) {
	calls := oneLAN(t).install(t)
	res, err := buildTopology(context.Background(), json.RawMessage(`{"lldpAddr":"192.168.1.1"}`))
	if err != nil {
		t.Fatalf("%v", err)
	}
	v := res.(ots.Verdict)
	b, _ := json.Marshal(v.Values["blind"])
	if !strings.Contains(string(b), "不是") || !strings.Contains(string(b), "没问它") {
		t.Errorf("没把「压根没问」和「设备不回话」分开：%s", b)
	}
	if *calls != 0 {
		t.Errorf("缺团体名还是问了 %d 次 LLDP", *calls)
	}
}

// ★ 探测挂了 ≠ 那里没有东西：三项读本机的口子全失败时，
//
//	图必须空着、并且把每一条失败原样写进 blind（topo-no-ifaces 那一档）。
func Test拓扑卡如实报告读不到(t *testing.T) {
	f := stubFacts{
		nicErr: errors.New("这个平台的枚举方式挂了"),
		e4:     errors.New("arp: command not found"),
		e6:     errors.New("ndp: command not found"),
		rtErr:  errors.New("读路由表失败"),
	}
	f.install(t)

	res, err := buildTopology(context.Background(), nil)
	if err != nil {
		t.Fatalf("读本机失败应该出一个判定，不是错误：%v", err)
	}
	v := res.(ots.Verdict)
	if v.Code != topo.CodeNoIfaces {
		t.Errorf("顶层判定 = %s，读不到网卡应该是 %s", v.Code, topo.CodeNoIfaces)
	}
	b, _ := json.Marshal(v.Values["blind"])
	for _, want := range []string{"枚举方式挂了", "arp", "路由表"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("blind 里少了「%s」这一句失败原因：%s", want, b)
		}
	}
	if cnt, _ := v.Values["nodeCount"].(int); cnt != 0 {
		t.Errorf("什么都没读到还画了 %d 个方块", cnt)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
