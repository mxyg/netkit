package tools

// 这一张借用文件共享那套测试助手（账本、调用口、空闲端口、网卡样本）：
// 两边同一条口径 —— 判定从 Invoke 出来都该是一个 ots.Verdict，
// 抄第二份只会让两份各自烂掉。
//
// ★ 为什么端到端只走 127.0.0.1：这一张会真的收发字节。让它去绑本机某块真实网卡，
//
//	等于在测试里把这台机器变成别人手里的对测靶子，跑完才撤 —— 那是拿别人当测试床。
//	按网卡挑地址那一条线用注入的假网卡表来验，不去碰真网卡。
//
// ★ 为什么快慢那几档（ok / 缓冲膨胀 / 忽快忽慢 / 窗口顶到头）在这里是纯函数测试：
//
//	它们判的是「一本账长成什么形状」，而一台机器给不出「对面是别人」这个事实。
//	这里用手工造的账本把每一档钉住；两端真的对跑由 internal/throughput 那 24 条覆盖，
//	这一层再加一条回环上的真对跑，证明工具层把那本账原样带了出来。

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
	"net.yuhox.com/netkit/internal/throughput"
)

// fixThruNICs 换掉「本机有哪些网卡」这一层。
func fixThruNICs(nics []netif.NIC, err error) func() {
	old := thruNICs
	thruNICs = func() ([]netif.NIC, error) { return nics, err }
	return func() { thruNICs = old }
}

// fixThruLocalAddrs 换掉「哪些地址就是本机」。
//
// ★ 判「这一发打在自己身上」靠的是这台机器的地址表，测试要能把它清空，
//
//	不然任何一条想走「对面是别人」那条路的测试都得先找一台真机器。
func fixThruLocalAddrs(as []string) func() {
	old := thruLocalAddrs
	thruLocalAddrs = func() []string { return as }
	return func() { thruLocalAddrs = old }
}

// thruReset 保证下一个测试看到的「当前对测口」是空的。
//
// ★ 这个槽是全局的（全场只允许一个口），忘了清的话后面每条测试都会撞上
//
//	「已经有一个对测口在跑」，而那条报错看着像是被测代码的毛病。
func thruReset(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		thru.mu.Lock()
		defer thru.mu.Unlock()
		if thru.srv != nil {
			thru.srv.Stop()
			thru.srv = nil
		}
		thru.entryID = ""
		thru.plan = throughputPlan{}
	})
}

// serveThruLocal 起一个只在回环上的对测口（显式给地址这条路不经网卡，
// 所以挂着 VPN 的机器和干净机器上跑出来一模一样）。
func serveThruLocal(t *testing.T, extra map[string]any) ots.Verdict {
	t.Helper()
	args := map[string]any{"addrs": []string{"127.0.0.1"}, "port": freePort(t)}
	for k, v := range extra {
		args[k] = v
	}
	v, err := callShare(t, throughputServeTool, args)
	if err != nil {
		t.Fatalf("起对测口失败：%v", err)
	}
	return v
}

func mustJSON(t *testing.T, args map[string]any) json.RawMessage {
	t.Helper()
	if args == nil {
		return nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// thruErr 这一组参数必须被挡在门外，而且报错要说清缺的是哪一栏。
func thruErr(t *testing.T, tool ots.Tool, args map[string]any, want string) {
	t.Helper()
	_, err := tool.Invoke(context.Background(), mustJSON(t, args))
	if err == nil {
		t.Fatalf("%s 收下了 %v，这一条本该挡在门外", tool.Name, args)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%v 的报错里没提 %q：%s", args, want, err)
	}
}

// thruStatusSnapshot 走一遍 status，把结构体转成 JSON 形状再看（界面拿到的就是这一份）。
func thruStatusSnapshot(t *testing.T) map[string]any {
	t.Helper()
	v, err := callShare(t, throughputStatusTool, map[string]any{})
	if err != nil {
		t.Fatalf("看状态失败：%v", err)
	}
	b, _ := json.Marshal(v.Values["status"])
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("状态解不开：%v", err)
	}
	return m
}

func thruEntries(j *state.Journal, kind string) []state.Entry {
	var out []state.Entry
	for _, e := range j.All() {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// fakePeer 起一个「端口上有人，但说的不是这套协议」的对端，端口号还回来。
// serve 自己决定回什么、什么时候把线断了；函数返回即断线。
func fakePeer(t *testing.T, serve func(c net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// ── 参数界限：Invoke 不查 schema，所以夹取必须在这里被验到 ──

func Test对测口的参数界限全在代码里夹住(t *testing.T) {
	shareJournal(t)
	// 端口。★ 0 是「让内核挑一个」，这里不收：两端必须报同一个号，内核挑完对面不知道。
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"127.0.0.1"}, "port": -1}, "端口只认")
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"127.0.0.1"}, "port": 70000}, "端口只认")
	// 字节闸。太小会把一条健康链路判成「被对面截了」，太大这一口就成了放大器。
	thruErr(t, throughputServeTool, map[string]any{"maxBytes": 1024}, "maxBytes 只认")
	thruErr(t, throughputServeTool, map[string]any{"maxBytes": int64(1) << 40}, "maxBytes 只认")
	thruErr(t, throughputServeTool, map[string]any{"maxBytes": -1}, "maxBytes 只认")
	// 路数。
	thruErr(t, throughputServeTool, map[string]any{"maxSessions": 9}, "maxSessions 只认")
	thruErr(t, throughputServeTool, map[string]any{"maxSessions": -2}, "maxSessions 只认")
	// ★ 通配地址不是「忘了填」，是要绕开按网卡挑地址那一条线。
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"0.0.0.0"}}, "不接受 0.0.0.0")
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"::"}}, "不接受 ::")
	// 地址这一栏要的是 IP，不是网卡名 —— 填错了别将就去 bind。
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"en0"}}, "这个地址看不懂")
	// 一格都不对时不许「绑零个地址」然后报成功。★ 这里把网卡表清空，
	// 否则它会退回去挑这台机器真实的网卡 —— 测试不许在别人的网络上开接口。
	defer fixThruNICs(nil, nil)()
	defer fixShareRoutes(nil, nil)()
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"  ", ""}}, "没有一块带可用 IPv4")
}

func Test默认值就是那道闸(t *testing.T) {
	defer fixThruNICs([]netif.NIC{upNIC(t, "en0", "192.168.1.20/24")}, nil)()
	defer fixShareRoutes([]netif.DefaultRoute{{Family: "ipv4", Iface: "en0", Gateway: "192.168.1.1"}}, nil)()
	p, err := planThroughputServe(throughputArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if p.port != thruDefaultPort {
		t.Errorf("默认端口 %d，和 iperf 同号这条约定就断了", p.port)
	}
	if p.maxBytes != thruMaxBytes {
		t.Errorf("默认字节闸 %d，应为 %d", p.maxBytes, thruMaxBytes)
	}
	if p.maxSessions != 4 {
		t.Errorf("默认路数 %d", p.maxSessions)
	}
}

// ── 按网卡挑地址：绝不 0.0.0.0，也不许猜错口 ──

func Test按网卡挑对测口(t *testing.T) {
	shareJournal(t)
	t.Run("默认路由那块优先", func(t *testing.T) {
		defer fixThruNICs([]netif.NIC{
			upNIC(t, "en0", "10.0.0.5/24"),
			upNIC(t, "en5", "192.168.1.20/24"),
		}, nil)()
		defer fixShareRoutes([]netif.DefaultRoute{{Family: "ipv4", Iface: "en5", Gateway: "192.168.1.1"}}, nil)()
		p, err := planThroughputServe(throughputArgs{Port: 5299})
		if err != nil {
			t.Fatal(err)
		}
		if p.iface != "en5" {
			t.Errorf("挑了 %q，默认路由那块才是现场对测的出口", p.iface)
		}
		if !strings.Contains(p.ifaceWhy, "默认路由") {
			t.Errorf("没说清是怎么挑出来的：%s", p.ifaceWhy)
		}
	})
	t.Run("只有一块就用它并说清理由", func(t *testing.T) {
		defer fixThruNICs([]netif.NIC{upNIC(t, "en0", "192.168.1.20/24")}, nil)()
		defer fixShareRoutes(nil, nil)()
		p, err := planThroughputServe(throughputArgs{})
		if err != nil {
			t.Fatal(err)
		}
		if p.iface != "en0" || !strings.Contains(p.ifaceWhy, "只有一块") {
			t.Errorf("挑成 %s / %s", p.iface, p.ifaceWhy)
		}
	})
	t.Run("多块又没默认路由就让人填", func(t *testing.T) {
		defer fixThruNICs([]netif.NIC{
			upNIC(t, "en0", "10.0.0.5/24"),
			upNIC(t, "en5", "192.168.1.20/24"),
		}, nil)()
		defer fixShareRoutes(nil, nil)()
		_, err := planThroughputServe(throughputArgs{})
		if err == nil {
			t.Fatal("两块口猜一块开了：猜错口就是「对面连得上却慢得离谱」")
		}
		for _, want := range []string{"en0", "en5", "iface"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("报错里没给出 %s（要让人照着改）：%s", want, err)
			}
		}
	})
	t.Run("人指定的网卡", func(t *testing.T) {
		nics := []netif.NIC{upNIC(t, "en0", "10.0.0.5/24"), upNIC(t, "en5", "192.168.1.20/24")}
		defer fixThruNICs(nics, nil)()
		p, err := planThroughputServe(throughputArgs{Iface: "en0"})
		if err != nil {
			t.Fatal(err)
		}
		if p.iface != "en0" || !strings.Contains(p.ifaceWhy, "人指定") {
			t.Errorf("指定的没接住：%+v", p)
		}
		if len(p.addrs) != 1 || p.addrs[0] != "10.0.0.5" {
			t.Errorf("地址 %v", p.addrs)
		}
		if _, err := planThroughputServe(throughputArgs{Iface: "en9"}); err == nil ||
			!strings.Contains(err.Error(), "没有叫 en9 的网卡") {
			t.Errorf("不存在的网卡：%v", err)
		}
	})
	t.Run("那块口上没有可用地址", func(t *testing.T) {
		// 只有链路本地地址：不能「开是开了，但对面连不上」。
		defer fixThruNICs([]netif.NIC{
			upNIC(t, "en0", "10.0.0.5/24"),
			{Name: "awdl0", Up: true, Running: true},
		}, nil)()
		if _, err := planThroughputServe(throughputArgs{Iface: "awdl0"}); err == nil ||
			!strings.Contains(err.Error(), "没有一个能用来对测的地址") {
			t.Errorf("空口也接下这个网卡：%v", err)
		}
	})
	t.Run("一块都没有", func(t *testing.T) {
		defer fixThruNICs(nil, nil)()
		defer fixShareRoutes(nil, nil)()
		if _, err := planThroughputServe(throughputArgs{}); err == nil ||
			!strings.Contains(err.Error(), "没有一块带可用 IPv4") {
			t.Errorf("没网卡时：%v", err)
		}
	})
	t.Run("读网卡这件事本身失败", func(t *testing.T) {
		defer fixThruNICs(nil, errors.New("权限不够"))()
		if _, err := planThroughputServe(throughputArgs{}); err == nil ||
			!strings.Contains(err.Error(), "读网卡列表失败") {
			t.Errorf("读不到网卡却说没网卡：%v", err)
		}
	})
}

// ── 账本 [OTS-7.5]：没有账本就别动手 ──

func Test没有账本就拒绝开口与打流(t *testing.T) {
	old := journal
	journal = nil
	t.Cleanup(func() { journal = old })
	for _, tc := range []struct {
		tool ots.Tool
		args map[string]any
	}{
		{throughputServeTool, map[string]any{"addrs": []string{"127.0.0.1"}}},
		{throughputTestTool, map[string]any{"host": "127.0.0.1", "seconds": 1}},
	} {
		_, err := tc.tool.Invoke(context.Background(), mustJSON(t, tc.args))
		if err == nil || !strings.Contains(err.Error(), "账本") {
			t.Errorf("%s 没账本也做了：%v", tc.tool.Name, err)
		}
	}
}

func Test开口与停口各留一笔账(t *testing.T) {
	j := shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	thruReset(t)

	v := serveThruLocal(t, map[string]any{"maxBytes": 1 << 20})
	if v.Code != verdictThruServing {
		t.Fatalf("开口判定 %s", v.Code)
	}
	ents := thruEntries(j, "throughput-serve")
	if len(ents) != 1 {
		t.Fatalf("账本里 %d 笔开口，应为 1", len(ents))
	}
	if ents[0].Status != state.StatusApplied {
		t.Errorf("开口这笔停在 %s，做完就该是已生效", ents[0].Status)
	}
	// 批准说明要说到人能拍板 [OTS-7.2]：地址、端口、闸开多大都得在里面。
	for _, want := range []string{"127.0.0.1", "端口", "不鉴权", "三道闸"} {
		if !strings.Contains(ents[0].What, want) {
			t.Errorf("批准说明里没提 %q：%s", want, ents[0].What)
		}
	}

	if _, err := callShare(t, throughputStopTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	ents = thruEntries(j, "throughput-serve")
	if ents[0].Status != state.StatusReverted {
		t.Errorf("停口之后这笔还是 %s，账本里就永远挂着一个不存在的口", ents[0].Status)
	}
	if left := j.Outstanding(); len(left) != 0 {
		t.Errorf("还有没走完的账：%+v", left)
	}
}

// 打流那一发不管成没成都要留痕：人查的就是「刚才有没有人往这条链路上打过流」。
func Test打一次流留一笔账哪怕没跑成(t *testing.T) {
	j := shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	thruReset(t)
	// 没人听这个端口：这一发一定跑不成。
	if _, err := callShare(t, throughputTestTool, map[string]any{
		"host": "127.0.0.1", "port": freePort(t), "mode": "up", "seconds": 1}); err != nil {
		t.Fatal(err)
	}
	ents := thruEntries(j, "throughput-test")
	if len(ents) != 1 {
		t.Fatalf("跑了没成却一笔账没有：%d 笔", len(ents))
	}
	for _, want := range []string{"127.0.0.1", "摄像头"} {
		if !strings.Contains(ents[0].What, want) {
			t.Errorf("批准说明里没提 %q：%s", want, ents[0].What)
		}
	}
	// ★ 这一张没有「还原」这一步：打完就完了，链路上不留东西。
	if ents[0].Status != state.StatusApplied {
		t.Errorf("这一笔停在 %s", ents[0].Status)
	}
}

// 进程被杀掉时那一笔「还开着口」的账：新进程里这个口其实早就空了，
// 但账必须了结 —— 挂着的话下一个看账的人去查一个不存在的口。
func Test重启后遗留的开口账就地了结(t *testing.T) {
	j := shareJournal(t)
	thruReset(t)
	id, err := j.Register("throughput-serve", "上一次进程留下的：口已随进程一起没了",
		map[string]any{"serving": false}, map[string]any{"port": 5201})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.MarkApplied(id); err != nil {
		t.Fatal(err)
	}
	if len(j.Outstanding()) != 1 {
		t.Fatalf("前置条件坏了：%+v", j.Outstanding())
	}
	v, err := callShare(t, throughputStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != verdictThruIdle {
		t.Errorf("判定 %s，本进程没在开就该是「没在开」", v.Code)
	}
	if len(j.Outstanding()) != 0 {
		t.Errorf("那笔账还挂着：%+v", j.Outstanding())
	}
	// ★ 也不自动重开：那等于人不在场就把一个能收发字节的口开到网上去。
	if thru.srv != nil {
		t.Error("看个状态就把口重新开起来了")
	}
}

// ── 口：开 / 看 / 停 ──

func Test开一口看一眼再停掉(t *testing.T) {
	shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	thruReset(t)

	// 没开的时候看状态：那是一条判定，不是错误 [OTS-6.2]。
	v, err := callShare(t, throughputStatusTool, map[string]any{})
	if err != nil {
		t.Fatalf("没开口时看状态报错了：%v", err)
	}
	if v.Code != verdictThruIdle || v.Values["serving"] != false {
		t.Errorf("判定 %+v", v)
	}
	if !strings.Contains(v.Note, "net.throughput.serve") {
		t.Errorf("没在开那一句要指下一步：%s", v.Note)
	}
	if sv, err := callShare(t, throughputStopTool, map[string]any{}); err != nil {
		t.Errorf("停一个本来就没开的口成了失败：%v", err)
	} else if sv.Code != verdictThruIdle {
		t.Errorf("停一个没开的口判成 %s，那不该是「停了」", sv.Code)
	}

	got := serveThruLocal(t, map[string]any{"maxBytes": 1 << 20})
	if got.Code != verdictThruServing {
		t.Fatalf("开口判定 %s", got.Code)
	}
	if got.Values["serving"] != true {
		t.Errorf("serving = %v", got.Values["serving"])
	}
	addrs, _ := got.Values["addrs"].([]string)
	if len(addrs) != 1 || addrs[0] != "127.0.0.1" {
		t.Errorf("绑在 %v", addrs)
	}
	port, _ := got.Values["port"].(int)
	if port == 0 {
		t.Error("没把端口报回来：对面那台无从填起")
	}
	// ★ 界面要把「对面怎么填」当场说给人，省掉一次来回问。
	help, _ := got.Values["peerHelp"].(string)
	if !strings.Contains(help, "127.0.0.1") || !strings.Contains(help, fmt.Sprint(port)) {
		t.Errorf("peerHelp = %q", help)
	}
	if !strings.Contains(got.Note, "net.throughput.test") {
		t.Errorf("开口那句没指下一步：%s", got.Note)
	}
	if got.Values["maxBytes"].(int64) != 1<<20 {
		t.Errorf("闸开在多大没报回来：%v", got.Values["maxBytes"])
	}

	// 第二个口必须先停掉旧的：两个口的界面分不清「停的是哪个」。
	thruErr(t, throughputServeTool, map[string]any{"addrs": []string{"127.0.0.1"}, "port": freePort(t)},
		"net.throughput.stop")

	st := thruStatusSnapshot(t)
	if st["serving"] != true {
		t.Error("状态说没在开")
	}
	if st["port"] != float64(port) {
		t.Errorf("状态和开口时报的端口不一致：%v vs %d", st["port"], port)
	}
	if _, ok := st["recent"]; !ok {
		t.Error("状态里没有「最近跑过哪几路」，排查连不上时没话说")
	}
	sv, err := callShare(t, throughputStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(sv.Values), "serving") && sv.Code != verdictThruServing {
		t.Errorf("状态判定 %s", sv.Code)
	}
	if fmt.Sprint(sv.Values["maxSessions"]) != "4" {
		t.Errorf("没把路数闸报回来：%v", sv.Values["maxSessions"])
	}

	stop, err := callShare(t, throughputStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if stop.Code != verdictThruStopped {
		t.Errorf("停口判定 %s", stop.Code)
	}
	// ★ 要说清放掉了哪几个地址上的哪个口：现场最怕「以为停了，其实还开着」。
	if !strings.Contains(stop.Note, "127.0.0.1") || !strings.Contains(stop.Note, fmt.Sprint(port)) {
		t.Errorf("停口那句没报到地址与端口：%s", stop.Note)
	}
	if v, _ := callShare(t, throughputStatusTool, map[string]any{}); v.Code != verdictThruIdle {
		t.Errorf("停了之后状态还是 %s", v.Code)
	}
	// ★ 停口不清账：那几本账要跟着这一份结果走 —— 界面只在「还开着」的时候画台账，
	//   人停下来的那一刻最想看的正是刚跑砸的那一路，账不在这一份里就等于没留。
	//   （没人连过的时候这一格是空的，那也是「问过、没有」，键必须在。）
	if _, ok := stop.Values["recent"].([]throughput.Session); !ok {
		t.Errorf("停口那一份结果里没带上台账：%+v", stop.Values)
	}
}

// bind 那一步只能演「这块地址不是本机的」：地址不属于本机就该整个失败，
// 不许「几块里起来一块」然后报成功 —— 那会让人以为对端连不上是防火墙的事。
func Test一块地址bind不起来就整个失败(t *testing.T) {
	shareJournal(t)
	thruReset(t)
	_, err := throughputServeTool.Invoke(context.Background(),
		mustJSON(t, map[string]any{"addrs": []string{"203.0.113.77"}, "port": freePort(t)}))
	if err == nil {
		t.Fatal("在一个不属于本机的地址上「开成功了」")
	}
	if !strings.Contains(err.Error(), "203.0.113.77") {
		t.Errorf("报错没说是哪块地址绑不上：%s", err)
	}
	if thru.srv != nil {
		t.Error("失败了却把半开的口留在槽里")
	}
}

// ── 测：参数与判定 ──

func Test拆对端地址认现场抄的那几种写法(t *testing.T) {
	cases := []struct {
		in   string
		port int
		host string
		p    int
	}{
		{"192.168.1.30", 0, "192.168.1.30", thruDefaultPort},
		{"192.168.1.30", 5300, "192.168.1.30", 5300},
		{"192.168.1.30:5300", 0, "192.168.1.30", 5300},
		{"192.168.1.30:5300", 5300, "192.168.1.30", 5300},
		{"[fe80::1%en0]:5300", 0, "fe80::1%en0", 5300},
		{"fe80::1%en0", 5300, "fe80::1%en0", 5300},
		{"cam-01.local", 0, "cam-01.local", thruDefaultPort},
	}
	for _, c := range cases {
		h, p, err := splitTarget(c.in, c.port)
		if err != nil {
			t.Errorf("%q(+%d) 被拒了：%v", c.in, c.port, err)
			continue
		}
		if h != c.host || p != c.p {
			t.Errorf("%q(+%d) 拆成 %s:%d，应为 %s:%d", c.in, c.port, h, p, c.host, c.p)
		}
	}
	for _, bad := range []struct {
		in   string
		port int
		why  string
	}{
		{"", 0, "没给地址"},
		{"192.168.1.30:5300", 5201, "两处端口不一致：不能挑一个装作没事"},
		{"192.168.1.30:abc", 0, "地址里的端口不是数"},
		{"192.168.1.30:99999", 0, "地址里的端口越界"},
		{"本机", 0, "既不是 IP 也不像个主机名"},
	} {
		if _, _, err := splitTarget(bad.in, bad.port); err == nil {
			t.Errorf("%q / %d 被收下了（%s）", bad.in, bad.port, bad.why)
		}
	}
}

func Test测那一步的参数界限(t *testing.T) {
	shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	// ★ 短于 1 秒问不出稳态却会给出一个看着合理的低数；长于 10 秒在现场按住链路太久。
	for _, secs := range []int{-1, 11, 999} {
		thruErr(t, throughputTestTool, map[string]any{
			"host": "127.0.0.1", "port": freePort(t), "seconds": secs}, "seconds 只认")
	}
	thruErr(t, throughputTestTool, map[string]any{"host": "127.0.0.1", "mode": "udp"}, "mode 只认")
	thruErr(t, throughputTestTool, map[string]any{"host": "127.0.0.1", "port": 70000}, "端口只认")
	thruErr(t, throughputTestTool, map[string]any{"seconds": 1}, "没给对面地址")
	// seconds 不填就是默认 3 秒：不填不该等于「不测」。
	if thruDefaultSecs != 3 {
		t.Errorf("默认 %d 秒：短了看不出稳态，长了占链路", thruDefaultSecs)
	}
}

// ── 两端真的对跑一次：证明工具层把底座那本账原样带了回来 ──

func Test两端对跑一次带回四样账(t *testing.T) {
	j := shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	thruReset(t)
	got := serveThruLocal(t, nil)
	port, _ := got.Values["port"].(int)

	v, err := callShare(t, throughputTestTool, map[string]any{
		"host": "127.0.0.1", "port": port, "mode": "up", "seconds": 1})
	if err != nil {
		t.Fatalf("两端对跑失败：%v", err)
	}
	// 地址就是本机 —— 这一发量到的是协议栈，绝不当「链路很快」报出去。
	if v.Code != verdictThruLoopback {
		t.Errorf("判定 %s，应为 %s：%s", v.Code, verdictThruLoopback, v.Note)
	}
	if v.Values["loopback"] != true {
		t.Errorf("loopback = %v", v.Values["loopback"])
	}
	up, ok := v.Values["up"].(map[string]any)
	if !ok {
		t.Fatalf("没有往外打那一向的账：%v", v.Values["up"])
	}
	if b, _ := up["bytes"].(int64); b <= 0 {
		t.Errorf("字节账没带回来：%v", up["bytes"])
	}
	// 曲线：只有跑得够久才有第二个点，快机器上撞了闸也算带回来了。
	samples, _ := up["samples"].([]throughput.Sample)
	if ms, _ := up["elapsedMs"].(int64); len(samples) == 0 && ms > 250 {
		t.Errorf("跑了 %d ms 却一个点都没有：平均值会骗人，靠的就是这一列", ms)
	}
	if _, ok := up["tcp"]; !ok {
		t.Error("内核那本账没带回来（这台给不给由底座说，但这一栏必须在）")
	}
	if up["peerBytes"] == nil || up["peerElapsedMs"] == nil {
		t.Error("对面那句账没带回来：只有本机侧的数就只能说「我发出去多少」")
	}
	if _, ok := v.Values["idle"]; !ok {
		t.Error("少了空载往返：缺了它，带载那个数没有对照")
	}
	if _, ok := v.Values["verdictReason"]; !ok {
		t.Error("判定与它的账不同源：界面没法把这句话对上数")
	}
	st := thruStatusSnapshot(t)
	recent, _ := st["recent"].([]any)
	if len(recent) == 0 {
		t.Error("这一路没进「最近跑过哪几路」：排查「连上就断」时没话说")
	}
	if served, _ := st["served"].(float64); served <= 0 {
		t.Errorf("served = %v，这一口一共过了多少字节必须记得住", st["served"])
	}
	if len(thruEntries(j, "throughput-test")) != 1 {
		t.Error("真跑了一发却没记账")
	}
}

// ── 连上了却说不上话：每一种收场都要落在一档上 ──

func Test对面不是一套协议就说不是(t *testing.T) {
	cases := []struct {
		name  string
		serve func(c net.Conn)
		want  string
		in    string // 那句话里必须出现的词
	}{
		{"回一句 http", func(c net.Conn) {
			r := bufio.NewReader(c)
			_, _ = r.ReadString('\n')
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			time.Sleep(200 * time.Millisecond)
		}, verdictThruProto, "iperf3"},
		{"一句话不说就关线", func(c net.Conn) {}, verdictThruProto, "一句话没说"},
		{"说口满了", func(c net.Conn) {
			r := bufio.NewReader(c)
			_, _ = r.ReadString('\n')
			_, _ = c.Write([]byte("NETKIT-THRU/1 BUSY\n"))
			time.Sleep(200 * time.Millisecond)
		}, verdictThruBusy, "满"},
		{"说了半句就没下文", func(c net.Conn) {
			r := bufio.NewReader(c)
			_, _ = r.ReadString('\n')
			_, _ = c.Write([]byte("NETKIT-THRU/1 OK 100")) // 少一个换行
			time.Sleep(thruDialTo + time.Second)
		}, verdictThruTimeout, "问到一半"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shareJournal(t)
			defer fixThruLocalAddrs(nil)()
			port := fakePeer(t, tc.serve)
			v, err := callShare(t, throughputTestTool, map[string]any{
				"host": "127.0.0.1", "port": port, "mode": "up", "seconds": 1})
			if err != nil {
				t.Fatalf("跑成错误了（判定不是错误 [OTS-6.2]）：%v", err)
			}
			if v.Code != tc.want {
				t.Errorf("判定 %s，应为 %s：%s", v.Code, tc.want, v.Note)
			}
			if v.Values["fault"] == nil {
				t.Error("档位给了却没留证据：落不到档的那些要能看出断在哪")
			}
			if !strings.Contains(v.Note+fmt.Sprint(v.Values["fault"]), tc.in) {
				t.Errorf("这一档既没说 %q 也没留下证据：%s / %v", tc.in, v.Note, v.Values["fault"])
			}
			if !strings.Contains(v.Note, "127.0.0.1") {
				t.Errorf("那句里没报到对端地址：%s", v.Note)
			}
		})
	}
}

func Test连不上分得清是拒绝还是沉默(t *testing.T) {
	shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	// 端口上没人：RST = 那台机器活着，只是没开对测口。
	v, err := callShare(t, throughputTestTool, map[string]any{
		"host": "127.0.0.1", "port": freePort(t), "mode": "up", "seconds": 1})
	if err != nil {
		t.Fatalf("连不上跑成错误了：%v", err)
	}
	if v.Code != verdictThruClosed {
		t.Errorf("判定 %s，应为 %s：%s", v.Code, verdictThruClosed, v.Note)
	}
	// ★ closed 与 filtered 是两件事：下一步完全不同，所以两句话也完全不同。
	if !strings.Contains(v.Note, "net.throughput.serve") {
		t.Errorf("closed 那句必须给下一步（去那台上开个口）：%s", v.Note)
	}
	mute := &throughput.Error{Kind: "dial", Stage: "connect",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}}
	code, note := faultCode(mute, "10.0.0.9:5201")
	if code != verdictThruFiltered {
		t.Errorf("dial 超时归成 %s（%s）", code, note)
	} else {
		if strings.Contains(note, "net.throughput.serve") {
			t.Errorf("沉默那种不该照抄拒绝那一句的下一步：%s", note)
		}
		if !strings.Contains(note, "防火墙") {
			t.Errorf("filtered 那句没指向防火墙：%s", note)
		}
	}
	if c, _ := faultCode(&throughput.Error{Kind: "timeout"}, "x"); c != verdictThruFiltered {
		t.Errorf("对面一直不接归成 %s", c)
	}
	if c, _ := faultCode(&throughput.Error{Kind: "busy"}, "x"); c != verdictThruBusy {
		t.Errorf("口满归成 %s", c)
	}
	if c, _ := faultCode(errors.New("别的"), "x"); c != "" {
		t.Errorf("认不出来的错误硬归了档：%s", c)
	}
	if c, _ := faultCode(&throughput.Error{Kind: "no-such-kind"}, "x"); c != "" {
		t.Errorf("没听过的错误种类硬归了档：%s", c)
	}
}

// ── 数值判读：一台机器给不出的形状，用手工账本把每一档钉住 ──

func Test判定挑的是下一步不一样的那件事(t *testing.T) {
	sample := func(mbps ...float64) []throughput.Sample {
		out := make([]throughput.Sample, 0, len(mbps))
		for i, m := range mbps {
			out = append(out, throughput.Sample{AtMs: int64(i) * 200, MBps: m})
		}
		return out
	}
	steady := func(mbps float64, bytes int64) *throughput.Direction {
		return &throughput.Direction{
			Bytes: bytes, PeerBytes: bytes, ElapsedMs: 1000, PeerMs: 1000, MBps: mbps,
			Samples: sample(mbps, mbps, mbps),
		}
	}
	cases := []struct {
		name string
		res  throughput.Result
		loop bool
		want string
		in   []string // 那句话里必须出现的词
	}{
		{
			name: "两本账对不上先说吞数据",
			res: throughput.Result{
				Up:   &throughput.Direction{Bytes: 1 << 30, PeerBytes: 1 << 28, MBps: 8000, ElapsedMs: 100, Samples: sample(8000, 8000, 8000)},
				Down: steady(900, 1<<29),
			},
			want: verdictThruDropped,
			in:   []string{"吞数据", "1073741824", "268435456"},
		},
		{
			name: "撞闸不等于慢",
			res: throughput.Result{
				Up:           &throughput.Direction{Bytes: 1 << 20, PeerBytes: 1 << 20, Truncated: true, MBps: 8000, ElapsedMs: 100},
				Down:         steady(900, 1<<29),
				PeerMaxBytes: 1 << 20,
			},
			want: verdictThruTruncated,
			in:   []string{"字节闸", "maxBytes"},
		},
		{
			name: "对自己打流量的是协议栈",
			res:  throughput.Result{Up: steady(60000, 1<<33)},
			loop: true,
			want: verdictThruLoopback,
			in:   []string{"协议栈", "另一台"},
		},
		{
			name: "撞了闸也先说自己打自己",
			res:  throughput.Result{Up: &throughput.Direction{Bytes: 1 << 20, PeerBytes: 1 << 20, Truncated: true, MBps: 8000}},
			loop: true,
			want: verdictThruLoopback,
		},
		{
			name: "吞吐上得去而往返翻几倍是缓冲膨胀",
			res: throughput.Result{
				Up:     steady(940, 1<<29),
				Down:   steady(930, 1<<29),
				Idle:   throughput.RTT{Count: 10, AvgMs: 2},
				Loaded: throughput.RTT{Count: 10, AvgMs: 60},
			},
			want: verdictThruBufferbloat,
			in:   []string{"囤包", "队列"},
		},
		{
			name: "少了空载对照就不下缓冲膨胀",
			res: throughput.Result{
				Up:     steady(940, 1<<29),
				Loaded: throughput.RTT{Count: 10, AvgMs: 60},
			},
			want: verdictThruOK,
		},
		{
			name: "涨得不够多就不算缓冲膨胀",
			res: throughput.Result{
				Up:     steady(940, 1<<29),
				Idle:   throughput.RTT{Count: 10, AvgMs: 20},
				Loaded: throughput.RTT{Count: 10, AvgMs: 25},
			},
			want: verdictThruOK,
		},
		{
			name: "平均数藏住的断流",
			res: throughput.Result{
				Up:   &throughput.Direction{Bytes: 1 << 29, PeerBytes: 1 << 29, MBps: 900, ElapsedMs: 1000, Samples: sample(900, 0, 900, 0)},
				Idle: throughput.RTT{Count: 10, AvgMs: 2},
			},
			want: verdictThruUnstable,
			in:   []string{"200 毫秒完全没动", "一阵一阵"},
		},
		{
			name: "忽快忽慢",
			res: throughput.Result{
				Down: &throughput.Direction{Bytes: 1 << 29, PeerBytes: 1 << 29, MBps: 600, ElapsedMs: 1000, Samples: sample(1800, 300, 1500, 600)},
				Idle: throughput.RTT{Count: 10, AvgMs: 2},
			},
			want: verdictThruUnstable,
			in:   []string{"忽快忽慢", "抢这一条路"},
		},
		{
			name: "点太少不下忽快忽慢",
			res: throughput.Result{
				Up:   &throughput.Direction{Bytes: 1 << 29, PeerBytes: 1 << 29, MBps: 600, ElapsedMs: 1000, Samples: sample(1800, 3)},
				Idle: throughput.RTT{Count: 10, AvgMs: 2},
			},
			want: verdictThruOK,
		},
		{
			name: "顶到自己那条连接的天花板",
			res: throughput.Result{
				Up: &throughput.Direction{
					Bytes: 1 << 29, PeerBytes: 1 << 29, MBps: 148, ElapsedMs: 1000,
					Samples: sample(150, 148, 149),
					TCP:     throughput.TCPInfo{Given: true, SrttMs: 20, SndCwndBytes: 65536},
				},
				Idle: throughput.RTT{Count: 10, AvgMs: 20},
			},
			want: verdictThruWindowLimited,
			in:   []string{"天花板", "多路并发"},
		},
		{
			name: "远没到天花板就不怪窗口",
			res: throughput.Result{
				Up: &throughput.Direction{
					Bytes: 1 << 29, PeerBytes: 1 << 29, MBps: 300, ElapsedMs: 1000,
					Samples: sample(300, 300, 300),
					TCP:     throughput.TCPInfo{Given: true, SrttMs: 20, SndCwndBytes: 2 << 20},
				},
				Idle: throughput.RTT{Count: 10, AvgMs: 20},
			},
			want: verdictThruOK,
		},
		{
			name: "都正常就是正常",
			res: throughput.Result{
				Up:     steady(930, 1<<29),
				Down:   steady(920, 1<<29),
				Idle:   throughput.RTT{Count: 10, AvgMs: 1.2},
				Loaded: throughput.RTT{Count: 10, AvgMs: 3},
			},
			want: verdictThruOK,
			in:   []string{"空载往返", "3 个点"},
		},
		{
			name: "两向都没账就交回 unknown",
			res:  throughput.Result{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, note := measureCode(tc.res, tc.loop)
			if code != tc.want {
				t.Fatalf("判定 %s，应为 %s（%s）", code, tc.want, note)
			}
			if tc.want == "" {
				if note != "" {
					t.Errorf("没有账却编出了一句：%s", note)
				}
				return
			}
			if note == "" {
				t.Fatal("判定档没有那句话")
			}
			for _, w := range tc.in {
				if !strings.Contains(note, w) {
					t.Errorf("%s 那句里没提 %q：%s", tc.want, w, note)
				}
			}
			if strings.Contains(note, "\n") {
				t.Errorf("判定句子分成好几行了，界面上一展示就散：%s", note)
			}
		})
	}
}

// ★ 一次都没问到，和量到 0 毫秒，是两件完全不同的事。
func Test没问到的往返不许写成0(t *testing.T) {
	if got := rttWord(throughput.RTT{}); got != "没问到" {
		t.Errorf("空往返写成 %q", got)
	}
	if got := rttWord(throughput.RTT{Count: 3, AvgMs: 1.5}); got != "1.5 ms" {
		t.Errorf("往返 = %q", got)
	}
	code, note := measureCode(throughput.Result{Up: &throughput.Direction{
		Bytes: 1 << 29, PeerBytes: 1 << 29, MBps: 900, ElapsedMs: 1000,
		Samples: []throughput.Sample{{MBps: 900}, {MBps: 900}, {MBps: 900}},
	}}, false)
	if code != verdictThruOK {
		t.Fatalf("判定 %s", code)
	}
	for _, want := range []string{"空载往返 没问到", "带载往返 没问到"} {
		if !strings.Contains(note, want) {
			t.Errorf("%s：那一句里没有 %q（%s）", want, want, note)
		}
	}
	if got := samplesWord([]thruDir{{"往外打", &throughput.Direction{}}}); got != "一个点都没取到" {
		t.Errorf("曲线一栏 = %q", got)
	}
}

func Test判定码都合法且各说一件事(t *testing.T) {
	codes := []string{
		verdictThruServing, verdictThruIdle, verdictThruStopped,
		verdictThruOK, verdictThruLoopback, verdictThruBufferbloat, verdictThruUnstable,
		verdictThruWindowLimited, verdictThruTruncated, verdictThruDropped, verdictThruBusy,
		verdictThruProto, verdictThruClosed, verdictThruFiltered, verdictThruTimeout,
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("判定码 %s 重复：两档同一句话，界面就得分两次写", c)
		}
		seen[c] = true
		for _, r := range c {
			// [OTS-5.5] 只能小写字母、数字、连字符
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				t.Errorf("判定码 %q 里有 %q", c, r)
			}
		}
	}
}

// ── 界面与注册表对得上 ──

func Test四个对测工具都注册上且口径对(t *testing.T) {
	r := ots.NewRegistry(true)
	Register(r)
	want := map[string]ots.Class{
		"net.throughput.serve":  ots.ClassMutate,
		"net.throughput.test":   ots.ClassMutate,
		"net.throughput.stop":   ots.ClassMutate,
		"net.throughput.status": ots.ClassRead,
	}
	for name, class := range want {
		tool, ok := r.Lookup(name)
		if !ok {
			t.Errorf("%s 没注册上", name)
			continue
		}
		if tool.Class != class {
			t.Errorf("%s 类别 %s，应为 %s", name, tool.Class, class)
		}
		if class == ots.ClassMutate && tool.Describe == nil {
			t.Errorf("%s 是 mutate 却没有批准说明 [OTS-7.2]", name)
		}
	}
	off := ots.NewRegistry(false)
	Register(off)
	var sawStatus bool
	for _, v := range off.Visible() {
		if !strings.HasPrefix(v.Name, "net.throughput.") {
			continue
		}
		if v.Class == ots.ClassMutate {
			t.Errorf("mutations=false 时 %s 还在对外提供", v.Name)
		} else {
			sawStatus = true
		}
	}
	if !sawStatus {
		t.Error("看状态这一张也跟着关掉了：界面刷新时没得问")
	}
}

// 排障树里的每一步都只是「看一眼」：树会连着问好几步，中途没人批准就往现场打一轮流，
// 是我们自己变成事故。所以这一张不进树。
func Test对测不进排障树(t *testing.T) {
	for _, p := range TreePlans() {
		for _, s := range p.steps {
			if strings.HasPrefix(s.node.tool, "net.throughput.") {
				t.Errorf("「%s」的步子里放了 %s：树里没有点头这一步", p.symptom, s.node.tool)
			}
		}
	}
}

// jsBlock 截出界面里那张常量表：从 head 那一句到它后面第一个单独成行的 `};`。
// 只在这一个文件里用，所以不搬进 wol_test.go 的 inJS 那一堆。
func jsBlock(js, head string) string {
	i := strings.Index(js, head)
	if i < 0 {
		return ""
	}
	j := strings.Index(js[i:], "\n};")
	if j < 0 {
		return ""
	}
	return js[i : i+j]
}

func Test对测的判定码界面上都有人话(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面文件：%v", err)
	}
	js := string(b)
	codes := []string{
		verdictThruServing, verdictThruIdle, verdictThruStopped,
		verdictThruOK, verdictThruLoopback, verdictThruBufferbloat, verdictThruUnstable,
		verdictThruWindowLimited, verdictThruTruncated, verdictThruDropped, verdictThruBusy,
		verdictThruProto, verdictThruClosed, verdictThruFiltered, verdictThruTimeout,
	}
	// ★ 光「文件里出现过这个码」不算数：跑砸那几档在「下一步」那张表里也各出现一次，
	//   于是把码表里那一行删掉，界面上只会剩一句「这里还没认得的判定」，测试却是绿的。
	//   要钉的是**那张码表**：每一档都得配一句人话。
	table := jsBlock(js, "const THRU_CODE = {")
	if table == "" {
		t.Fatal("界面里找不到对测的判定码表（THRU_CODE）")
	}
	for _, code := range codes {
		if !strings.Contains(table, "'"+code+"'") {
			t.Errorf("码表里没有判定码 %s —— 后端只出码，中文得有人写 [OTS-4.5]", code)
		} else if m := regexp.MustCompile(`'` + code + `': \[(?:t\()?'([^']*)'`).FindStringSubmatch(table); m == nil || m[1] == "" {
			t.Errorf("判定码 %s 在码表里没配人话（或那句是空的）", code)
		}
	}
	// 界面拆页口径：新工具要有归宿，不许往已经满页的卡里再塞一张。
	if !strings.Contains(js, "两台机器对测") {
		t.Error("界面里没有「两台机器对测」这一页")
	}
}

// ── 凭据纪律：结果会被发给 AI，也可能被打进诊断包 ──

func Test对测结果里没有凭据形状的东西(t *testing.T) {
	shareJournal(t)
	defer fixThruLocalAddrs(nil)()
	thruReset(t)
	got := serveThruLocal(t, map[string]any{"maxBytes": 1 << 20})
	if _, ok := got.Values["port"].(int); !ok {
		t.Error("开口没把端口报回来")
	}
	// 打给一个没人的端口：这一发立刻回来，带去的是地址与端口，别的什么都没有。
	closed, err := callShare(t, throughputTestTool, map[string]any{
		"host": "127.0.0.1", "port": freePort(t), "mode": "up", "seconds": 1})
	if err != nil {
		t.Fatal(err)
	}
	sv, err := callShare(t, throughputStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range []ots.Verdict{got, closed, sv} {
		b, jerr := json.Marshal(one)
		if jerr != nil {
			t.Fatal(jerr)
		}
		var tree any
		if jerr := json.Unmarshal(b, &tree); jerr != nil {
			t.Fatal(jerr)
		}
		var walk func(path string, node any)
		walk = func(path string, node any) {
			switch n := node.(type) {
			case map[string]any:
				for k, val := range n {
					if credKey(k) {
						t.Errorf("%s 判定里出现了凭据形状的键 %s/%s", one.Code, path, k)
					}
					walk(path+"."+k, val)
				}
			case []any:
				for i, val := range n {
					walk(fmt.Sprintf("%s[%d]", path, i), val)
				}
			case string:
				for _, bad := range []string{"password=", "passwd:", "community=", "token=", "-----BEGIN", "/Users/"} {
					if strings.Contains(strings.ToLower(n), bad) {
						t.Errorf("%s 判定里带出了 %q", one.Code, bad)
					}
				}
			}
		}
		walk("", tree)
	}
}

func credKey(k string) bool {
	switch strings.ToLower(k) {
	case "password", "passwd", "pwd", "token", "secret", "community", "privatekey", "key", "credential":
		return true
	}
	return false
}
