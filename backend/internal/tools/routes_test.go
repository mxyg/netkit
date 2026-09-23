package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// 这套测试一律不碰真的网络，也不读真机的路由表：
// 三个读取口（全表 / 问系统 / 是不是本机地址）和解析都能换，
// 所以在挂着 VPN 的机器上和干净机器上跑出来必须一模一样。

func fixRouteTable(rs []netif.Route, err error) func() {
	old := routesTable
	routesTable = func() ([]netif.Route, error) { return rs, err }
	return func() { routesTable = old }
}

func fixAskOS(r netif.Route, err error) func() {
	old := routesAskOS
	routesAskOS = func(context.Context, netip.Addr) (netif.Route, error) { return r, err }
	return func() { routesAskOS = old }
}

func fixLocal(ok bool) func() {
	old := routesLocal
	routesLocal = func(netip.Addr) bool { return ok }
	return func() { routesLocal = old }
}

func fixTarget(addrs []netip.Addr, resolved bool, err error) func() {
	old := routesTarget
	routesTarget = func(context.Context, string) ([]netip.Addr, bool, error) { return addrs, resolved, err }
	return func() { routesTarget = old }
}

func invokeRoutes(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, _ := json.Marshal(args)
	out, err := routesTool.Invoke(context.Background(), raw)
	if err != nil {
		t.Fatalf("调用失败：%v", err)
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", out)
	}
	return v
}

// 一张两网卡 + 一 v6 的表：现场最难查的就是这种。
func sampleTable() []netif.Route {
	return []netif.Route{
		{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"},
		{Family: "ipv4", Destination: "192.168.1.0/24", Iface: "en0", Direct: true},
		{Family: "ipv4", Destination: "10.2.3.0/24", Iface: "eth1", Direct: true},
		{Family: "ipv4", Destination: "10.0.0.0/8", Gateway: "10.9.9.1", Iface: "eth1"},
		{Family: "ipv6", Destination: "::/0", Gateway: "fe80::1%en0", Iface: "en0"},
		{Family: "ipv6", Destination: "fd00:1::/64", Iface: "eth1", Direct: true},
	}
}

func Test只列表时给全表(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, nil)
	if v.Code != "routes-listed" {
		t.Fatalf("该是 routes-listed，拿到 %s", v.Code)
	}
	if got := v.Values["count"]; got != 6 {
		t.Errorf("count 不对：%v", got)
	}
	// 一条默认路由不该顶出 multi-default-route
	if v.Code == "multi-default-route" {
		t.Error("只有一条默认路由，不该报并列")
	}
}

func Test两条默认路由要顶出来(t *testing.T) {
	tbl := append(sampleTable(),
		netif.Route{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "10.9.9.1", Iface: "eth1"})
	defer fixRouteTable(tbl, nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, nil)
	if v.Code != "multi-default-route" {
		t.Fatalf("同族两条默认路由是最要命的一类配置，得顶到判定上，拿到 %s", v.Code)
	}
	if !strings.Contains(v.Note, "度量") {
		t.Errorf("结论里要说清「走哪条由度量决定」：%s", v.Note)
	}
	if v.Values["multiDefault"] != true {
		t.Error("multiDefault 要为真，界面靠它上色")
	}
}

func Test目的地按最长前缀匹配不是照默认路由(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixAskOS(netif.Route{}, errors.New("问不到"))()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "10.2.3.7"})
	if v.Code != "route-found" {
		t.Fatalf("拿到 %s", v.Code)
	}
	d := v.Values["decision"].(map[string]any)
	if d["iface"] != "eth1" || d["from"] != "table" {
		t.Errorf("10.2.3.7 在 eth1 直连段里，该走 eth1：%v", d)
	}
	if d["direct"] != true {
		t.Errorf("直连要说直连，不许编一个下一跳：%v", d)
	}
	// 问不到系统时必须**明说**这是算出来的，不能让人以为是系统给的
	if v.Values["osUnavailable"] != true {
		t.Error("要标 osUnavailable，界面据此说「按表算的」")
	}
	if !strings.Contains(v.Note, "按表算") {
		t.Errorf("Note 里要说清答案从哪来：%s", v.Note)
	}
}

func Test出本网才走默认路由(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixAskOS(netif.Route{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"}, nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "8.8.8.8"})
	d := v.Values["decision"].(map[string]any)
	if d["gateway"] != "192.168.1.1" || d["from"] != "os" {
		t.Fatalf("%v", d)
	}
	if !strings.Contains(v.Note, "下一跳") {
		t.Errorf("走网关的结论要带下一跳：%s", v.Note)
	}
}

func Test算的和系统给的不一样要单独出一档(t *testing.T) {
	// Linux 策略路由的真实形状：主表说 eth0，系统实际从另一块网卡走
	defer fixRouteTable(sampleTable(), nil)()
	defer fixAskOS(netif.Route{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "10.9.9.1", Iface: "eth1"}, nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "8.8.8.8"})
	if v.Code != "route-mismatch" {
		t.Fatalf("不一致必须单独一档，拿到 %s", v.Code)
	}
	if _, ok := v.Values["byTable"]; !ok {
		t.Error("两份都要留着，只报一个等于替人藏起来")
	}
	if v.Values["decision"].(map[string]any)["iface"] != "eth1" {
		t.Error("结论要以系统给的为准，答案不能是算出来的那个")
	}
	if !strings.Contains(v.Note, "策略路由") {
		t.Errorf("要说清为什么不一致：%s", v.Note)
	}
}

func Test目的地是自己时不许报成策略路由(t *testing.T) {
	// 实机踩到的：BSD/Linux 都把本机地址收回 lo，对拍必然「不一致」，
	// 而那是正确行为。照对拍逻辑报一句，就把人推去查路由策略了。
	defer fixRouteTable(sampleTable(), nil)()
	defer fixAskOS(netif.Route{Family: "ipv4", Destination: "192.168.1.5/32", Iface: "lo0", Direct: true}, nil)()
	defer fixLocal(true)()
	v := invokeRoutes(t, map[string]any{"dest": "192.168.1.5"})
	if v.Code != "route-local" {
		t.Fatalf("该是 route-local，拿到 %s", v.Code)
	}
	if !strings.Contains(v.Note, "撞") {
		t.Errorf("这一档最有用的下一步是查地址冲突：%s", v.Note)
	}
}

func Test这一族压根没启用(t *testing.T) {
	tbl := []netif.Route{
		{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.168.1.1", Iface: "en0"},
	}
	defer fixRouteTable(tbl, nil)()
	defer fixAskOS(netif.Route{}, errors.New("问不到"))()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "fd00::1"})
	if v.Code != "no-route" {
		t.Fatalf("拿到 %s", v.Code)
	}
	if !strings.Contains(v.Note, "没启用") {
		t.Errorf("「这一族没路由」要说成没启用，不是让人去查防火墙：%s", v.Note)
	}
	if v.Values["familyRoutes"] != 0 {
		t.Errorf("familyRoutes 要为 0：%v", v.Values["familyRoutes"])
	}
}

func Test有这一族但盖不住目的地(t *testing.T) {
	// ★ 这一族**有**路由、只是没有一条盖住目的地 —— 和上一档「没启用」要分开。
	// 样例表带 0.0.0.0/0，任何目的地都走得通，所以这里换一张只有本网段的小表。
	defer fixRouteTable([]netif.Route{
		{Family: "ipv4", Destination: "192.168.1.0/24", Iface: "en0", Direct: true},
		{Family: "ipv6", Destination: "fd00:1::/64", Iface: "eth1", Direct: true},
	}, nil)()
	defer fixAskOS(netif.Route{}, errors.New("问不到"))()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "172.16.5.5"})
	if v.Code != "no-route" {
		t.Fatalf("拿到 %s", v.Code)
	}
	// ★ 这一句是这一档的全部价值：把「没路」和「对端不理」分开
	if !strings.Contains(v.Note, "没路") || !strings.Contains(v.Note, "对端") {
		t.Errorf("要分开「没路」和「对端不理」：%s", v.Note)
	}
}

func Test读不到表不许说成没有路由(t *testing.T) {
	defer fixRouteTable(nil, nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "8.8.8.8"})
	if v.Code != "table-unreadable" {
		t.Fatalf("拿到 %s", v.Code)
	}
	if !strings.Contains(v.Note, "不是「没有路由」") {
		t.Errorf("必须明说这不是「没路由」这个诊断结论：%s", v.Note)
	}
}

func Test并列要在结论里点名(t *testing.T) {
	tbl := []netif.Route{
		{Family: "ipv6", Destination: "::/0", Gateway: "fe80::1%utun0", Iface: "utun0"},
		{Family: "ipv6", Destination: "::/0", Gateway: "fe80::1%utun1", Iface: "utun1"},
		{Family: "ipv6", Destination: "::/0", Gateway: "fe80::1%utun2", Iface: "utun2"},
	}
	defer fixRouteTable(tbl, nil)()
	defer fixAskOS(netif.Route{}, errors.New("问不到"))()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"dest": "2001:4860::8888"})
	if v.Values["ties"] != 2 {
		t.Fatalf("并列条数要报出来，拿到 %v", v.Values["ties"])
	}
	if !strings.Contains(v.Note, "2 条同样匹配") {
		t.Errorf("并列必须写进结论，不许给一条就当定论：%s", v.Note)
	}
}

func Test一个名字解出多个地址走不同的路(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixAskOS(netif.Route{}, errors.New("问不到"))()
	defer fixLocal(false)()
	defer fixTarget([]netip.Addr{
		netip.MustParseAddr("192.168.1.9"),
		netip.MustParseAddr("10.2.3.9"),
	}, true, nil)()
	v := invokeRoutes(t, map[string]any{"dest": "camera.local"})
	if v.Code != "route-split" {
		t.Fatalf("拿到 %s", v.Code)
	}
	paths, ok := v.Values["paths"].([]map[string]any)
	if !ok || len(paths) != 2 {
		t.Fatalf("paths 要给全两个地址各自的路：%v", v.Values["paths"])
	}
	if paths[0]["iface"] != "en0" || paths[1]["iface"] != "eth1" {
		t.Errorf("路径对不上：%v", paths)
	}
	// ★ 不许替人选：走哪条由应用挑哪个地址决定，这句话必须在结论里
	if !strings.Contains(v.Note, "由应用") {
		t.Errorf("%s", v.Note)
	}
}

func Test给IP时一个DNS都不问(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixAskOS(netif.Route{}, errors.New("问不到"))()
	defer fixLocal(false)()
	old := lookupIP
	lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("目的地已经是地址了，不许再解析")
		return nil, nil
	}
	defer func() { lookupIP = old }()
	if v := invokeRoutes(t, map[string]any{"dest": "8.8.8.8"}); v.Code != "route-found" {
		t.Fatalf("拿到 %s", v.Code)
	}
}

func Test解不开时点名mDNS这个坑(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixLocal(false)()
	defer fixTarget(nil, true, errors.New("no such host"))()
	raw, _ := json.Marshal(map[string]any{"dest": "gate.example"})
	if _, err := routesTool.Invoke(context.Background(), raw); err == nil {
		t.Fatal("该报错")
	} else {
		// ★ .local 走 mDNS，系统解析器解不开。不写这句，人会以为设备不在线。
		if !strings.Contains(err.Error(), "mDNS") {
			t.Errorf("要说清 .local 这类名字解不开：%v", err)
		}
	}
}

func Test按族过滤只留一族(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, map[string]any{"family": "ipv6"})
	rs := v.Values["routes"].([]netif.Route)
	for _, r := range rs {
		if r.Family != "ipv6" {
			t.Fatalf("过滤没生效：%+v", r)
		}
	}
	if len(rs) != 2 {
		t.Errorf("v6 该有 2 条，拿到 %d", len(rs))
	}
}

func Test参数校验(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"坏 JSON", `{"family"`},
		{"family 不认识", `{"family":"ipv7"}`},
	}
	defer fixRouteTable(sampleTable(), nil)()
	for _, c := range cases {
		if _, err := routesTool.Invoke(context.Background(), json.RawMessage(c.raw)); err == nil {
			t.Errorf("%s 该报错", c.name)
		}
	}
}

func Test表按选路的优先级排序(t *testing.T) {
	defer fixRouteTable(sampleTable(), nil)()
	defer fixLocal(false)()
	v := invokeRoutes(t, nil)
	rs := v.Values["routes"].([]netif.Route)
	// ★ 越具体的越前面：这个顺序就是系统选路时的优先级，
	//   默认路由排在最前面会让人以为「出口就是它」，而它常常被一条 /24 压住。
	var first4 string
	for _, r := range rs {
		if r.Family == "ipv4" {
			first4 = r.Destination
			break
		}
	}
	if first4 != "192.168.1.0/24" {
		t.Errorf("v4 第一行该是最具体的那条：%v", first4)
	}
	// 前缀长度只在**同一族内**可比（v6 的 /64 不比 v4 的 /24 更不具体），
	// 所以按族各记一个 prev。
	prev := map[string]int{}
	for _, r := range rs {
		if _, ok := prev[r.Family]; !ok {
			prev[r.Family] = -1
		}
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			t.Fatalf("表里出现解不开的目的地址：%q", r.Destination)
		}
		if prev[r.Family] >= 0 && p.Bits() > prev[r.Family] {
			t.Errorf("排序不对：%v 排在 %d 之后", p, prev[r.Family])
		}
		prev[r.Family] = p.Bits()
	}
}

func Test路由每个判定都有人话(t *testing.T) {
	// 少一个码，客户界面上就是一个裸的 route-mismatch。
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Skipf("读不到界面源码：%v", err)
	}
	js := string(b)
	for _, code := range []string{
		verdictRoutesListed, verdictRouteFound, verdictNoRoute,
		verdictRouteMismatch, verdictRouteSplit, verdictRouteLocal,
		verdictMultiDefault, verdictTableUnreadable,
	} {
		if !strings.Contains(js, `"`+code+`"`) && !strings.Contains(js, `'`+code+`'`) {
			t.Errorf("界面里没有 %s 的说法", code)
		}
	}
}

func Test判定码格式(t *testing.T) {
	for _, code := range []string{
		verdictRoutesListed, verdictRouteFound, verdictNoRoute,
		verdictRouteMismatch, verdictRouteSplit, verdictRouteLocal,
		verdictMultiDefault, verdictTableUnreadable,
	} {
		if !ots.ValidVerdictCode(code) {
			t.Errorf("%s 不是合法判定码", code)
		}
	}
}
