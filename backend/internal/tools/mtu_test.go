package tools

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.mtu.path 的测试 ──
//
// ★ 这一栏给的是一个**推出来的数**，所以测试重点不是「发出去的包对不对」（那要真网络），
//   而是推的过程：二分收不收得住、中途断信时不许硬给结论、以及**归属判错的方向**。
//   归属判错的后果不是报错，是人照着设一个错的网卡 MTU。

// scriptedProber 按脚本回探测结果。
//
//	wall>0    —— 从这个尺寸开始「过大被挡」；0 表示全都过得去
//	reached>0 —— 探到不小于这个尺寸就回 outcome（模拟「测到一半没回执」）
//	count     —— 记下探了几个尺寸，二分的意义就在这儿
func scriptedProber(wall int, count *int, reached int, outcome string) mtuProbe {
	return func(size int) mtuStep {
		*count++
		switch {
		case wall > 0 && size >= wall:
			return mtuStep{Size: size, Outcome: mtuTooBig, Detail: "message too long"}
		case reached > 0 && size >= reached:
			return mtuStep{Size: size, Outcome: outcome}
		default:
			return mtuStep{Size: size, Outcome: mtuThrough}
		}
	}
}

// 二分要探到能过的最大尺寸，而且**不许一路试上去**：500 到 1500 逐个试要发一千个包。
// 那在现场不是慢，是把自己变成攻击流量 —— 摄像头的防爆破会锁掉这台机器，交换机也可能直接限速。
func Test二分按对数探而不是逐个试(t *testing.T) {
	var calls int
	probe := scriptedProber(1400, &calls, 0, "")
	var steps []mtuStep
	res := mtuSearch(probe, &steps, 500, 1500)
	if res.through != 1399 {
		t.Errorf("判成 %d 能过，应该是 1399（1400 开始过不去）", res.through)
	}
	if res.stopped != mtuTooBig {
		t.Errorf("stopped = %s，应该撞到墙", res.stopped)
	}
	// log2(1000) ≈ 10 步，加上先试上限那一步。留点余量，但绝不是几百步。
	if calls > 14 {
		t.Errorf("探了 %d 次，二分一千个尺寸不该超过十几次", calls)
	}
	if calls < 5 {
		t.Errorf("只探了 %d 次就下结论，步数太少（可能没真二分）", calls)
	}
}

func Test二分上限本身能过时说到上限为止(t *testing.T) {
	var calls int
	var steps []mtuStep
	probe := scriptedProber(0, &calls, 0, "")
	res := mtuSearch(probe, &steps, 500, 1500)
	if res.stopped != mtuThrough || res.through != 1500 {
		t.Errorf("%+v，应该是「到 1500 还过得去」", res)
	}
	if calls != 1 {
		t.Errorf("上限一次就过了还探了 %d 次", calls)
	}
}

// ★★ 中途开始收不到回执时，**不许**把「已经过的那个尺寸」报成路径 MTU。
//
//	那只是「测到这儿测不动了」。报成 MTU 的话，人会照着把网卡 MTU 设小 ——
//	一个凭空的结论比没有结论坏得多。
func Test二分中途断信只说测到哪儿(t *testing.T) {
	var calls int
	var steps []mtuStep
	probe := scriptedProber(0, &calls, 1200, mtuSilent)
	res := mtuSearch(probe, &steps, 500, 1500)
	if res.stopped != mtuSilent {
		t.Errorf("stopped = %s，应该是「没回执」", res.stopped)
	}
	if res.through < 500 {
		t.Errorf("已经过的那个尺寸丢了：%+v", res)
	}
	if calls == 0 {
		t.Error("一次都没探")
	}
}

// ── 归属：谁把这个尺寸挡住的 ──

func Test归属判的是本机还是路上(t *testing.T) {
	cases := []struct {
		name                       string
		localMTU, through, blocked int
		want                       string
	}{
		// 被挡的尺寸还没到本机网卡的上限 → 只能是路上某台设备回的「需要分片但不许分片」
		{"没到本机上限就被挡：路上", 1500, 1399, 1400, "path"},
		// 超过本机网卡的 MTU → 包根本没出过本机，说不上路径 MTU
		{"超过本机网卡：本机", 1500, 1600, 1700, "local"},
		{"正好等于本机 MTU：是本机发出去的", 1500, 1499, 1500, "path"},
		{"没读到本机 MTU：不知道", 0, 1399, 1400, "unknown"},
	}
	for _, c := range cases {
		if got := mtuBlockedBy(c.localMTU, c.through, c.blocked); got != c.want {
			t.Errorf("%s：本机 %d / 过 %d / 挡 %d 判成 %s，应该 %s",
				c.name, c.localMTU, c.through, c.blocked, got, c.want)
		}
	}
}

// 从逐步记录里找「第一个过不去」的尺寸：二分不一定正好测到 through+1。
func Test找第一个过不去的尺寸(t *testing.T) {
	steps := []mtuStep{
		{Size: 500, Outcome: mtuThrough},
		{Size: 1500, Outcome: mtuTooBig},
		{Size: 1000, Outcome: mtuThrough},
		{Size: 1250, Outcome: mtuTooBig},
		{Size: 1375, Outcome: mtuThrough},
		{Size: 1438, Outcome: mtuTooBig},
	}
	if got := valuesBlockedSize(steps, 1375); got != 1438 {
		t.Errorf("找到 %d，应该是 1438（比 1375 大的那些里最小的）", got)
	}
	// 一条都没记下时只能按 through+1 说，不许报 0
	if got := valuesBlockedSize(nil, 1375); got != 1376 {
		t.Errorf("没有记录时找到 %d", got)
	}
	// 比 through 小的那些 too-big 是起手就被挡的历史记录，不能拿来当「第一个过不去」
	early := []mtuStep{{Size: 400, Outcome: mtuTooBig}, {Size: 900, Outcome: mtuThrough}}
	if got := valuesBlockedSize(early, 900); got != 901 {
		t.Errorf("把 %d 当成了被挡的尺寸（那是 through 之前的历史）", got)
	}
}

// ── 判定 ──

func runFinish(t *testing.T, res mtuSearchResult, egress mtuEgress, ceiling int, v6 bool) (ots.Verdict, map[string]any) {
	t.Helper()
	steps := []mtuStep{{Size: res.through, Outcome: mtuThrough}}
	if res.stopped == mtuTooBig {
		steps = append(steps, mtuStep{Size: valuesBlockedSize(nil, res.through), Outcome: mtuTooBig})
	}
	values := map[string]any{}
	addr, _ := netaddr.Parse("192.168.1.64")
	if v6 {
		addr, _ = netaddr.Parse("2408:4003::1")
	}
	v, err := mtuFinish(values, steps, res, egress, ceiling, addr, v6)
	if err != nil {
		t.Fatalf("报错：%v", err)
	}
	ver, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", v)
	}
	return ver, values
}

// 路上一台设备把尺寸压小了：这是这一栏要买的那个结论，必须给数、给建议。
func Test路上被挡时给出路径MTU和设多少(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 1399, stopped: mtuTooBig},
		mtuEgress{Iface: "en0", MTU: 1500}, 1500, false)
	if ver.Code != mtuCodePath {
		t.Fatalf("判成 %s，应该 %s（%s）", ver.Code, mtuCodePath, ver.Note)
	}
	if vals["pathMtu"] != 1399 || vals["suggestion"] != 1399 {
		t.Errorf("pathMtu/suggestion = %v / %v", vals["pathMtu"], vals["suggestion"])
	}
	if _, has := vals["localMtuLimited"]; has {
		t.Error("路上挡的不许标成本机限制")
	}
	for _, want := range []string{"1399", "1400", "en0"} {
		if !strings.Contains(ver.Note, want) {
			t.Errorf("备注里没有 %s：%s", want, ver.Note)
		}
	}
}

// ★ 反过来那档：被本机网卡挡住时**不许**报成路径 MTU，也不许让人去改路上根本没坏的东西。
func Test本机挡住的不能报成路径MTU(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 1600, stopped: mtuTooBig},
		mtuEgress{Iface: "en7", MTU: 1500}, 2000, false)
	if ver.Code != mtuCodeLocal {
		t.Fatalf("判成 %s，应该 %s", ver.Code, mtuCodeLocal)
	}
	if vals["localMtuLimited"] != true {
		t.Errorf("没标 localMtuLimited：%v", vals)
	}
	if _, has := vals["pathMtu"]; has {
		t.Errorf("包没出过本机，不许给路径 MTU：%v", vals)
	}
	if !strings.Contains(ver.Note, "en7") || !strings.Contains(ver.Note, "1500") {
		t.Errorf("备注没说是哪块网卡挡的：%s", ver.Note)
	}
}

// 读不到本机 MTU 时不许硬指认是谁挡的 —— 报「先去看网卡 MTU 再说」，但数照样给。
func Test不知道本机MTU时不指认(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 1399, stopped: mtuTooBig}, mtuEgress{}, 1500, false)
	if ver.Code != mtuCodePath {
		t.Fatalf("判成 %s", ver.Code)
	}
	if !strings.Contains(ver.Note, "分不清") {
		t.Errorf("备注没交代这份不确定：%s", ver.Note)
	}
	if vals["pathMtu"] != 1399 {
		t.Errorf("数还是得给：%v", vals["pathMtu"])
	}
	if _, has := vals["suggestion"]; has {
		t.Errorf("归属都没判出来，不许给「照着设」的建议：%v", vals["suggestion"])
	}
}

// 一个字节都没被挡：结论只能是「至少这么大」，并且要指出去调大上限。
func Test测到上限没被挡时不编MTU(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 900, stopped: mtuThrough},
		mtuEgress{Iface: "en0", MTU: 1500}, 900, false)
	if ver.Code != mtuCodeNoLimit {
		t.Fatalf("判成 %s，应该 %s", ver.Code, mtuCodeNoLimit)
	}
	if vals["carriesAtLeast"] != 900 {
		t.Errorf("carriesAtLeast = %v", vals["carriesAtLeast"])
	}
	if _, has := vals["pathMtu"]; has {
		t.Errorf("没撞到墙就不许给路径 MTU：%v", vals)
	}
	if !strings.Contains(ver.Note, "maxSize") {
		t.Errorf("备注没指下一步（调大上限）：%s", ver.Note)
	}
}

// 本机网卡 MTU 都过得去：这条路没有更小的限制，指人往别的方向查。
func Test连本机MTU都过得去时说路没限制(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 1500, stopped: mtuThrough},
		mtuEgress{Iface: "en0", MTU: 1500}, 1500, false)
	if ver.Code != mtuCodeLocal {
		t.Fatalf("判成 %s，应该 %s", ver.Code, mtuCodeLocal)
	}
	if !strings.Contains(ver.Note, "没有更小的限制") {
		t.Errorf("备注：%s", ver.Note)
	}
	if vals["carriesAtLeast"] != 1500 {
		t.Errorf("carriesAtLeast = %v", vals["carriesAtLeast"])
	}
}

// ★★ 「小包收了、大包没回执」和「大包被挡」长得一样，含义完全不同：
//
//	前者什么都测不出来，后者才是一个 MTU 结论。把这档报成 MTU 是这一栏最坏的错。
func Test大包没回执时报测不出来而不是MTU(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 1400, stopped: mtuSilent},
		mtuEgress{Iface: "en0", MTU: 1500}, 1500, false)
	if ver.Code != mtuCodeNoAnswer {
		t.Fatalf("判成 %s，应该 %s", ver.Code, mtuCodeNoAnswer)
	}
	if _, has := vals["pathMtu"]; has {
		t.Errorf("这一档不许给路径 MTU：%v", vals)
	}
	if !strings.Contains(ver.Note, "不能当成") {
		t.Errorf("备注没把「这不是 MTU 结论」说出口：%s", ver.Note)
	}
}

// 测到一半没路了：那是本机的问题，和路径 MTU 无关。
func Test测到一半没路时报没路(t *testing.T) {
	ver, vals := runFinish(t, mtuSearchResult{through: 1000, stopped: mtuNoRoute},
		mtuEgress{Iface: "en0", MTU: 1500}, 1500, false)
	if ver.Code != mtuCodeNoRoute {
		t.Fatalf("判成 %s，应该 %s", ver.Code, mtuCodeNoRoute)
	}
	if _, has := vals["pathMtu"]; has {
		t.Errorf("没路不许给 MTU：%v", vals)
	}
}

// IPv6 链路上至少该能过 1280（RFC 8200）。测出比这还小说明中间有人在乱来，得标出来。
func TestV6测出小于1280要标警告(t *testing.T) {
	_, vals := runFinish(t, mtuSearchResult{through: 1220, stopped: mtuTooBig},
		mtuEgress{Iface: "en0", MTU: 1400}, 1400, true)
	if vals["warning"] != "below-ipv6-min" {
		t.Errorf("没标 below-ipv6-min：%v", vals)
	}
	_, vals2 := runFinish(t, mtuSearchResult{through: 1280, stopped: mtuTooBig},
		mtuEgress{Iface: "en0", MTU: 1400}, 1400, true)
	if _, has := vals2["warning"]; has {
		t.Errorf("1280 是合法下限，不该报警：%v", vals2["warning"])
	}
	// v4 上没有这条下限，1220 就是正常的路径 MTU
	_, vals3 := runFinish(t, mtuSearchResult{through: 1220, stopped: mtuTooBig},
		mtuEgress{Iface: "en0", MTU: 1400}, 1400, false)
	if _, has := vals3["warning"]; has {
		t.Errorf("v4 不该套 v6 的下限：%v", vals3["warning"])
	}
}

// ── 尺寸口径 ──

// ★ 结果里的尺寸一律是 **IP 包总长**，因为 MTU 本来就是按 IP 包算的。
//
//	按载荷报会把每个数都说大 28/48 字节，人拿去设网卡就设错了。
func Test尺寸是IP包总长不是载荷(t *testing.T) {
	cases := []struct {
		size        int
		v6          bool
		wantPayload int
	}{
		{1500, false, 1472},
		{1400, false, 1372},
		{1500, true, 1452},
		{1280, true, 1232},
		{49, false, 21}, // v4 最小探测包往上一点
		{69, true, 21},
	}
	for _, c := range cases {
		if got := mtuPayloadLen(c.size, c.v6); got != c.wantPayload {
			t.Errorf("%d（v6=%v）载荷算成 %d，应该 %d", c.size, c.v6, got, c.wantPayload)
		}
	}
	if mtuMinPacket(false) != 29 || mtuMinPacket(true) != 49 {
		t.Errorf("最小包 v4=%d v6=%d，应该是 29 / 49（IP 头 + UDP 头 + 1 字节）",
			mtuMinPacket(false), mtuMinPacket(true))
	}
	// 换算回去必须闭合：载荷 + 头 = 报出来的尺寸，不然每一步都在悄悄改口径
	for _, v6 := range []bool{false, true} {
		h := 20 + mtuUDPHeader
		if v6 {
			h = 40 + mtuUDPHeader
		}
		for _, size := range []int{mtuMinPacket(v6), 800, 1500} {
			if got := mtuPayloadLen(size, v6) + h; got != size {
				t.Errorf("%d 换算回来成了 %d", size, got)
			}
		}
	}
}

// ── 参数与真发（打在回环与保留地址上）──

func freeUDPPort(t *testing.T) int {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := p.LocalAddr().(*net.UDPAddr).Port
	p.Close() // 关掉了才没人认领：发到它必然吃 ICMP 端口不可达，那正是「这个尺寸过得去」的证据
	return port
}

func mtuRun(t *testing.T, args map[string]any) (ots.Verdict, error) {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doMTUPath(context.Background(), b)
	if err != nil {
		return ots.Verdict{}, err
	}
	ver, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", v)
	}
	return ver, nil
}

func Test探本机回环给出结论(t *testing.T) {
	ver, err := mtuRun(t, map[string]any{"addr": "127.0.0.1", "port": freeUDPPort(t),
		"maxSize": 900, "timeoutMs": 500})
	if err != nil {
		t.Fatalf("报错：%v", err)
	}
	// 回环上不会被路上压小，所以只能是「至少这么大」或「本机网卡就是上限」。
	// ★ DF 这一层不干活时必须如实停下（no-df），不许硬给数 —— 那也算通过本测试。
	switch ver.Code {
	case mtuCodeNoLimit, mtuCodeLocal, mtuCodeNoDF, mtuCodeNoAnswer:
	case mtuCodePath:
		t.Logf("回环上判出了路径 MTU（出口网卡 MTU 比 900 还小？%s）", ver.Note)
	default:
		t.Fatalf("判成 %s（%s）", ver.Code, ver.Note)
	}
	if ver.Values["target"] != "127.0.0.1" {
		t.Errorf("target = %v", ver.Values["target"])
	}
	if ver.Values["engine"] != dfEngine {
		t.Errorf("engine 没带上：%v", ver.Values["engine"])
	}
	if _, has := ver.Values["port"]; !has {
		t.Error("结果里没写探测打在哪个端口")
	}
	if steps, ok := ver.Values["steps"].([]mtuStep); !ok || len(steps) == 0 {
		t.Errorf("没给逐步记录：%#v", ver.Values["steps"])
	} else {
		for _, s := range steps {
			if s.Size < 29 || s.Size > 65535 {
				t.Errorf("步骤尺寸越界：%+v", s)
			}
		}
	}
}

// ★ 起手的小包都没回执时什么都测不出来 —— 这不能算成 MTU 有问题。
//
//	240.0.0.0/4 是保留段：发出去真的没人答（实测 i/o timeout）。
func Test不回话的主机不许编MTU(t *testing.T) {
	ver, err := mtuRun(t, map[string]any{"addr": "240.0.0.1", "maxSize": 1400, "timeoutMs": 300})
	if err != nil {
		t.Fatalf("没回执是判定不是错误：%v", err)
	}
	if ver.Code != mtuCodeNoAnswer {
		t.Fatalf("判成 %s，应该 %s（本机若没到保留段的路，这条会成 no-route：%s）",
			ver.Code, mtuCodeNoAnswer, ver.Note)
	}
	if _, has := ver.Values["pathMtu"]; has {
		t.Errorf("一个回执都没收到，不许给路径 MTU：%v", ver.Values)
	}
	if !strings.Contains(ver.Note, "net.ping") {
		t.Errorf("该指一步下一步去 ping：%s", ver.Note)
	}
}

func Test域名先让它去查DNS(t *testing.T) {
	for _, a := range []string{"cam.local", "hub.example.com"} {
		b, _ := json.Marshal(map[string]any{"addr": a})
		if _, err := doMTUPath(context.Background(), b); err == nil {
			t.Errorf("%q 收下了", a)
		} else if !strings.Contains(err.Error(), "net.dns.query") {
			t.Errorf("%q 的报错没指下一步：%v", a, err)
		}
	}
}

func Test缺参数与过小上限(t *testing.T) {
	if _, err := doMTUPath(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Error("没给 addr 该拒")
	}
	// 上限比起手的探测尺寸还小：这一趟什么都测不出来，直接拒而不是跑一堆没意义的步
	b, _ := json.Marshal(map[string]any{"addr": "127.0.0.1", "maxSize": 400})
	if _, err := doMTUPath(context.Background(), b); err == nil {
		t.Error("maxSize 小于起手尺寸该拒")
	} else if !strings.Contains(err.Error(), "maxSize") {
		t.Errorf("报错没点明是哪个参数：%v", err)
	}
}

// 探测被打断时不许拖满每一步的超时（人在界面上点了停就得停）。
func Test取消时立刻收摊(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()
	addr, _ := netaddr.Parse("240.0.0.1")
	probe := mtuRealProber(ctx, addr, defaultMTUPort, 5*time.Second, false)
	start := time.Now()
	st := probe(1400)
	if time.Since(start) > 4*time.Second {
		t.Fatalf("取消了还等了 %v", time.Since(start))
	}
	if st.Outcome == mtuThrough {
		t.Errorf("保留地址上的探测居然「过得去」：%+v", st)
	}
}

// DF 自检：明显超过本机网卡 MTU 的尺寸必须被内核当场拒；
// 万一这台机器「不许分片」设上了却不干活，工具会走 df-unsupported，所以这里不判失败。
func Test超MTU的包在内核这一层什么反应(t *testing.T) {
	addr, _ := netaddr.Parse("127.0.0.1")
	probe := mtuRealProber(context.Background(), addr, freeUDPPort(t), time.Second, false)
	st := probe(20000)
	switch st.Outcome {
	case mtuThrough:
		t.Skip("这台机器上 DF 没生效（超 MTU 的大包发出去了）—— 工具会如实报 df-unsupported")
	case mtuTooBig, mtuProbeErr, mtuSilent, mtuNoRoute:
		t.Logf("20000 字节这一档：%s（%s）", st.Outcome, st.Detail)
	default:
		t.Errorf("没见过的口径 %q", st.Outcome)
	}
}

// 每一步都得留痕：人不看到「哪一步开始过不去」就没法信这个推出来的数。
func Test每一步都记进结果(t *testing.T) {
	var steps []mtuStep
	record(&steps, mtuStep{Size: 500, Outcome: mtuThrough, ElapsedMS: 3})
	record(&steps, mtuStep{Size: 1500, Outcome: mtuTooBig, Detail: "EMSGSIZE"})
	if len(steps) != 2 || steps[1].Size != 1500 {
		t.Fatalf("记录丢了：%+v", steps)
	}
	raw, _ := json.Marshal(steps)
	s := string(raw)
	for _, want := range []string{`"size":1500`, `"outcome":"too-big"`, `"elapsedMs":3`} {
		if !strings.Contains(s, want) {
			t.Errorf("序列化后没有 %s：%s", want, s)
		}
	}
}

// 工具本身：分类必须是 read（发流量去观察 [OTS-4.3]），且每个判定码都要在说明里交代。
func TestMTU工具声明(t *testing.T) {
	if mtuPathTool.Class != ots.ClassRead {
		t.Errorf("分类是 %v，探 MTU 只是发流量观察，不该是 mutate", mtuPathTool.Class)
	}
	for _, code := range []string{mtuCodePath, mtuCodeLocal, mtuCodeNoAnswer, mtuCodeNoRoute, mtuCodeNoDF, mtuCodeNoLimit} {
		if !strings.Contains(string(mtuPathTool.Summary), code) {
			t.Errorf("工具说明里没列 %s —— 调用方（AI）靠它选工具和读结果", code)
		}
	}
	if dfEngine == "" {
		t.Error("engine 空着，结果里这一栏就没法说明是靠哪一层测的")
	}
}
