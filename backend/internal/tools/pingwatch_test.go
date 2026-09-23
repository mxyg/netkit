package tools

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// ── net.ping.watch 的测试 ──
//
// ★ 这一栏卖的是一张曲线和「抖在哪一发」，所以测试的重点全在**计时和算术**上：
//
//	计时错了，曲线会自己长出斜线，然后人去查一个不存在的网络问题；
//	算术错了（拿平均值当基线、丢包里混进不可达），点名的那一发就不是现场要对的那一刻。
//	真网络的抖动没法在 CI 里造，所以这里一律喂脚本样本。

func msSample(seq int, atMs int64, rtt float64) pingSample {
	return pingSample{Seq: seq, AtMS: atMs, RTTMS: rtt, Kind: verdictReachable}
}

func lostSample(seq int, atMs int64) pingSample {
	return pingSample{Seq: seq, AtMS: atMs, Kind: verdictNoReply}
}

func unreachSample(seq int, atMs int64) pingSample {
	return pingSample{Seq: seq, AtMS: atMs, Kind: verdictUnreachable}
}

// ── 计时 ──

// 发数由「间隔 + 时长」算出来，不多发也不少发。
// ★ 少发会被读成「这一段没丢」，多发会把这一栏变成洪泛。
func Test发数按间隔和时长算(t *testing.T) {
	samples, noRoute := sweep(context.Background(), 20*time.Millisecond, 100*time.Millisecond,
		func(int) (time.Duration, string, error) { return time.Millisecond, verdictReachable, nil })
	if noRoute != "" {
		t.Fatalf("noRoute = %q，不该判成没路", noRoute)
	}
	if len(samples) < 4 || len(samples) > 7 {
		t.Errorf("发了 %d 发（100ms / 20ms 应该是 5 发上下）", len(samples))
	}
	for i, s := range samples {
		if s.Seq != i+1 {
			t.Errorf("第 %d 条的 seq 是 %d，序号必须连着，否则人对不上「第几发」", i+1, s.Seq)
		}
	}
}

// ★★ 每一发的耗时不能累进间隔里。
// 用「发完再睡一个间隔」的写法，probe 睡 15ms、间隔 20ms，第五发就落到 175ms 处 ——
// 曲线自己长出一条斜线，而它反映的是工具的睡法，不是网络的。
func Test探测耗时不许把曲线拖成斜线(t *testing.T) {
	interval := 25 * time.Millisecond
	cost := 12 * time.Millisecond
	samples, _ := sweep(context.Background(), interval, 125*time.Millisecond,
		func(int) (time.Duration, string, error) {
			time.Sleep(cost)
			return cost, verdictReachable, nil
		})
	if len(samples) < 4 {
		t.Fatalf("只发了 %d 发，样本太少验不出斜率", len(samples))
	}
	last := samples[len(samples)-1]
	// 第 N 发应该落在 (N-1)*interval 附近，而不是 (N-1)*(interval+cost)。
	want := time.Duration(last.Seq-1) * interval
	got := time.Duration(last.AtMS) * time.Millisecond
	if math.Abs(float64(got-want)) > float64(interval) {
		t.Errorf("第 %d 发落在 %v，应该在 %v 附近（差得远说明把探测耗时累进了间隔）",
			last.Seq, got, want)
	}
}

// 本机没路时第一发就该停下：继续发只会得到一条「全丢」的曲线，
// 而那条曲线会把人支去查对端的防火墙。
func Test发不出去时立刻停下不刷全丢曲线(t *testing.T) {
	var calls int
	samples, noRoute := sweep(context.Background(), 10*time.Millisecond, 2*time.Second,
		func(int) (time.Duration, string, error) {
			calls++
			return 0, "error", errors.New("connect: no route to host")
		})
	if noRoute == "" {
		t.Fatal("noRoute 为空：本机没路必须单独说，不能混进丢包")
	}
	if calls > 2 {
		t.Errorf("发了 %d 发才发现没路，第一发就该停", calls)
	}
	if len(samples) != calls {
		t.Errorf("留痕 %d 条但发了 %d 发，发出去的每一发都要有记录", len(samples), calls)
	}
	code, _ := watchVerdict(statsOf(samples), noRoute)
	if code != watchNoRoute {
		t.Errorf("判定是 %s，应该是 %s", code, watchNoRoute)
	}
}

// 取消要立刻收摊，并且把已经发过的留下来 —— 人按了「停」也要看到前面那几秒。
func Test取消时立刻收摊且留下已发的(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	done := make(chan []pingSample, 1)
	go func() {
		samples, _ := sweep(ctx, 15*time.Millisecond, 10*time.Second,
			func(int) (time.Duration, string, error) {
				calls++
				if calls == 3 {
					cancel()
				}
				return time.Millisecond, verdictReachable, nil
			})
		done <- samples
	}()
	select {
	case samples := <-done:
		if len(samples) > 6 {
			t.Errorf("取消后又发了 %d 发（前 3 发之后就该收）", len(samples))
		}
		if len(samples) < 3 {
			t.Errorf("只留下 %d 发，取消前发过的都要留痕", len(samples))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("取消后 sweep 没回来")
	}
}

// ★ 要的间隔不等于跑得起来的间隔：每发都等满 timeout 时，发序会被自己的超时拖稀。
// 这必须说出来 —— 只有两点的曲线在图上看着像「这两秒都稳」，真相是这两秒里每一发都没回。
func Test实际发序被超时拖稀时要讲明(t *testing.T) {
	sparse := []pingSample{lostSample(1, 0), lostSample(2, 1001)}
	span, actual, tooSparse := paceOf(sparse, 250*time.Millisecond)
	if span != 1001 || actual != 1001 {
		t.Errorf("span/actual = %d/%d，应该是 1001/1001", span, actual)
	}
	if !tooSparse {
		t.Error("要 250ms 实际 1001ms，判成不稀 —— 时间轴会被读成等距的")
	}
	tight := []pingSample{msSample(1, 0, 10), msSample(2, 301, 11), msSample(3, 601, 10)}
	if _, _, too := paceOf(tight, 300*time.Millisecond); too {
		t.Error("正常等距的发序被判成拖稀了")
	}
	if _, _, too := paceOf([]pingSample{msSample(1, 0, 10)}, time.Second); too {
		t.Error("只有一发谈不上稀不稀")
	}
}

// ── 汇总算术 ──

func Test丢包率按发数算且不可达单独记(t *testing.T) {
	st := statsOf([]pingSample{
		msSample(1, 0, 10), lostSample(2, 500), unreachSample(3, 1000), msSample(4, 1500, 12),
	})
	if st.Sent != 4 || st.Recv != 2 {
		t.Errorf("sent/recv = %d/%d，应该是 4/2", st.Sent, st.Recv)
	}
	if st.Unreachable != 1 {
		t.Errorf("unreachable = %d，明确回「到不了」的那一发要单独记", st.Unreachable)
	}
	if st.LossPercent != 50 {
		t.Errorf("丢包率 %d%%，应该是 50", st.LossPercent)
	}
}

// 抖动是「上一发和这一发差多少」，必须按发送先后算。
// 排过序再算，一条「稳—抖—稳—抖」的曲线会显得比实际温和得多。
func Test抖动按发送顺序算而不是排序后(t *testing.T) {
	st := statsOf([]pingSample{
		msSample(1, 0, 10), msSample(2, 500, 500), msSample(3, 1000, 10), msSample(4, 1500, 500),
	})
	if st.Jitter != 490 {
		t.Errorf("抖动 = %v，按先后算应该是 490（排序后算会得 %v 这种偏小的数）",
			st.Jitter, (0+490+0)/3.0)
	}
}

// 分位数取实际存在的那一发，不插值。★ 这里要的是「第 95 分位那发实际多少毫秒」，
// 一个算出来的小数会被当成实测值抄进工单。
func Test分位数用最近秩不插值(t *testing.T) {
	var samples []pingSample
	for i := 1; i <= 10; i++ {
		samples = append(samples, msSample(i, int64(i)*100, float64(i)))
	}
	st := statsOf(samples)
	if st.P95 != 10 {
		t.Errorf("P95 = %v，十个样本应该是第 10 个（10）", st.P95)
	}
	if st.Median != 5 {
		t.Errorf("中位数 = %v，应该是第 5 个（5），不许报 5.5", st.Median)
	}
	even := statsOf([]pingSample{
		msSample(1, 0, 1), msSample(2, 1, 2), msSample(3, 2, 3), msSample(4, 3, 4),
	})
	if even.Median != 2 {
		t.Errorf("四个样本的中位数 = %v，应该是第 2 个（2）", even.Median)
	}
}

// 一个回执都没有时不许编 RTT：那些字段干脆不在结果里，
// 免得 UI 把 0 当实测值画成一条贴着底的好看的线。
func Test全没收时不给RTT数(t *testing.T) {
	st := statsOf([]pingSample{lostSample(1, 0), lostSample(2, 500)})
	if st.Recv != 0 || st.LossPercent != 100 {
		t.Fatalf("%+v", st)
	}
	values := map[string]any{}
	mergeStats(values, st, "")
	for _, k := range []string{"rttMedianMs", "rttP95Ms", "jitterAvgMs", "rttMaxMs"} {
		if _, ok := values[k]; ok {
			t.Errorf("一个回执都没有，结果里却出现了 %s", k)
		}
	}
	for _, k := range []string{"sent", "recv", "unreachable", "lossPercent"} {
		if _, ok := values[k]; !ok {
			t.Errorf("%s 丢了：发数、收数、不可达数在「全没收」时同样要给人看", k)
		}
	}
}

// ── 尖峰 ──

// ★★ 挑尖峰必须拿中位数当基线。这一条是这一栏能不能拿去干活的分界：
// 一次 2000ms 的卡顿会把平均值抬到 300 多，之后 300ms 那一发就「不算尖峰」了 ——
// 而用户问的「有时候卡一下」恰恰是那一下。
func Test尖峰拿中位数当基线不用平均值(t *testing.T) {
	samples := []pingSample{
		msSample(1, 0, 10), msSample(2, 500, 11), msSample(3, 1000, 10),
		msSample(4, 1500, 2000), msSample(5, 2000, 10), msSample(6, 2500, 11),
		msSample(7, 3000, 300),
	}
	var sum float64
	for _, s := range samples {
		sum += s.RTTMS
	}
	avg := sum / float64(len(samples))
	if avg < 100 {
		t.Fatalf("构造得不对，平均值 %v 没被卡顿带起来，这组样本验不出问题", avg)
	}
	got := spikeIndexes(samples)
	if len(got) != 2 || got[0] != 4 || got[1] != 7 {
		t.Errorf("尖峰挑成 %v，应该是第 4 发和第 7 发（拿平均值当基线就会漏掉第 7 发）", got)
	}
}

// 两三发谈不上「偏离」，硬挑只会挑出噪音 —— 宁可不指。
func Test样本太少不挑尖峰(t *testing.T) {
	got := spikeIndexes([]pingSample{msSample(1, 0, 10), msSample(2, 500, 900), msSample(3, 1000, 10)})
	if got != nil {
		t.Errorf("三发就挑出尖峰 %v，样本不够应该不指", got)
	}
}

func Test尖峰只列前几条不刷屏(t *testing.T) {
	var samples []pingSample
	for i := 1; i <= 20; i++ {
		samples = append(samples, msSample(i, int64(i)*500, 900))
	}
	samples = append(samples, msSample(21, 10500, 0.5)) // 拉一个低值进来当分母
	if n := len(spikeIndexes(samples)); n > watchMaxSpikes {
		t.Errorf("列了 %d 个尖峰，上限是 %d", n, watchMaxSpikes)
	}
}

// 丢的每一次都要给「第几发 + 第几秒」：人要拿那个时刻去对现场发生了什么
// （是不是刚好起流、是不是刚好有人插拔网线）。
func Test丢包留痕带序号时刻和类型(t *testing.T) {
	samples := []pingSample{msSample(1, 0, 10), lostSample(2, 500), unreachSample(3, 1000)}
	lost := lostAt(samples)
	if len(lost) != 2 {
		t.Fatalf("留痕 %d 条，应该是 2 条", len(lost))
	}
	first, ok := lost[0]["seq"].(int)
	if !ok || first != 2 {
		t.Errorf("seq = %v，应该是 2", lost[0]["seq"])
	}
	if at, ok := lost[0]["atMs"].(int64); !ok || at != 500 {
		t.Errorf("atMs = %v，应该是 500", lost[0]["atMs"])
	}
	if lost[1]["kind"] != verdictUnreachable {
		t.Errorf("第二条 kind = %v，不可达和超时得分开", lost[1]["kind"])
	}
	if _, ok := lost[0]["kind"]; !ok {
		t.Error("每条都得带 kind")
	}
}

func Test全丢时留痕有条数上限(t *testing.T) {
	var samples []pingSample
	for i := 1; i <= 200; i++ {
		samples = append(samples, lostSample(i, int64(i)*500))
	}
	if n := len(lostAt(samples)); n != watchMaxSpikes*4 {
		t.Errorf("留痕 %d 条，应该截到 %d 条", n, watchMaxSpikes*4)
	}
}

// ── 判定 ──

func Test判定六档各归各位(t *testing.T) {
	cases := []struct {
		name    string
		samples []pingSample
		noRoute string
		want    string
	}{
		{"全程稳", []pingSample{msSample(1, 0, 10), msSample(2, 500, 11), msSample(3, 1000, 10), msSample(4, 1500, 12)}, "", watchStable},
		{"没丢但抖", []pingSample{msSample(1, 0, 10), msSample(2, 500, 90), msSample(3, 1000, 10), msSample(4, 1500, 90)}, "", watchJitter},
		{"丢几个", []pingSample{msSample(1, 0, 10), lostSample(2, 500), msSample(3, 1000, 11), msSample(4, 1500, 10)}, "", watchLoss},
		{"一个都没回", []pingSample{lostSample(1, 0), lostSample(2, 500)}, "", watchNoReply},
		{"全是明确不可达", []pingSample{unreachSample(1, 0), unreachSample(2, 500)}, "", watchUnreachable},
		{"包没出去", []pingSample{{Seq: 1, Kind: "error", Detail: "no route to host"}}, "这个地址本机没有路由", watchNoRoute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _ := watchVerdict(statsOf(c.samples), c.noRoute)
			if code != c.want {
				t.Errorf("判成 %s，应该是 %s", code, c.want)
			}
		})
	}
}

// ★「每发都是明确的不可达」和「一个都没吭声」必须分成两档：
// 前者有人回话、路是通的，要查的是终点/路由；后者连是不是有这台机器都不知道。
// 合成一档，人会去 ping 一个根本不该 ping 的地方。
func Test不可达和超时不混成一档(t *testing.T) {
	all := statsOf([]pingSample{unreachSample(1, 0), unreachSample(2, 500), unreachSample(3, 1000)})
	if code, _ := watchVerdict(all, ""); code != watchUnreachable {
		t.Errorf("全不可达判成 %s", code)
	}
	mixed := statsOf([]pingSample{unreachSample(1, 0), lostSample(2, 500), lostSample(3, 1000), lostSample(4, 1500)})
	if code, _ := watchVerdict(mixed, ""); code != watchNoReply {
		t.Errorf("一个回执都没有时判成 %s，应该是 no-reply（不能因为有不可达就谎称路是通的）", code)
	}
	some := statsOf([]pingSample{msSample(1, 0, 10), unreachSample(2, 500), msSample(3, 1000, 11), msSample(4, 1500, 10)})
	if code, _ := watchVerdict(some, ""); code != watchLoss {
		t.Errorf("有回执也有不可达时判成 %s，应该是 loss", code)
	}
}

// 判定说「抖」之外还必须点名哪一发 —— 光一句「不稳」没人能拿去干活。
func Test判定话里点名哪一发(t *testing.T) {
	jit := []pingSample{msSample(1, 0, 10), msSample(2, 500, 90), msSample(3, 1000, 10), msSample(4, 1500, 90)}
	n := watchNote("192.168.0.1", statsOf(jit), watchJitter, jit)
	if !strings.Contains(n, "抖在第 2 发（0.5s 时 90.0ms）") {
		t.Errorf("抖动的话没点到那一发（要序号、时刻、值三样）：%s", n)
	}

	ls := []pingSample{msSample(1, 0, 10), lostSample(2, 500), msSample(3, 1000, 11), msSample(4, 1500, 10)}
	n = watchNote("192.168.0.1", statsOf(ls), watchLoss, ls)
	if !strings.Contains(n, "第 2 发") || !strings.Contains(n, "0.5s") {
		t.Errorf("丢包的话没点到那一发：%s", n)
	}

	un := []pingSample{msSample(1, 0, 10), unreachSample(2, 500), msSample(3, 1000, 11), msSample(4, 1500, 10)}
	n = watchNote("192.168.0.1", statsOf(un), watchLoss, un)
	if !strings.Contains(n, "不可达") {
		t.Errorf("丢的里面混着明确不可达时话里没分开：%s", n)
	}

	// ★ 抖但挑不出单发：那是「整条线在晃」，跟「那一下卡」是两个处理方向，
	//   话里必须分得出来，否则人会把力气花在翻日志找那一刻上。
	ramp := []pingSample{msSample(1, 0, 60), msSample(2, 500, 63), msSample(3, 1000, 61), msSample(4, 1500, 64)}
	n = watchNote("192.168.0.1", statsOf(ramp), watchJitter, ramp)
	if !strings.Contains(n, "整条线都在晃") {
		t.Errorf("没有单发尖峰时的话术：%s", n)
	}
}

// ── 对照组 ──

func sampleLine(rtt ...float64) []pingSample {
	var out []pingSample
	for i, v := range rtt {
		if v < 0 {
			out = append(out, lostSample(i+1, int64(i)*500))
			continue
		}
		out = append(out, msSample(i+1, int64(i)*500, v))
	}
	return out
}

// 「到这台慢」和「整段都在抖」是两件事，光打一个目标分不出来。
func Test对照组分谁不干净(t *testing.T) {
	calm := sampleLine(10, 11, 10, 11)
	jit := sampleLine(10, 90, 10, 90)
	loss := sampleLine(10, -1, 10, 11)

	cases := []struct {
		base, target []pingSample
		want         string
	}{
		{calm, calm, "neither"},
		{calm, jit, "target-only"},
		{jit, calm, "baseline-only"},
		{jit, loss, "both"},
	}
	for i, c := range cases {
		if got := compareWho(c.base, c.target); got != c.want {
			t.Errorf("第 %d 组判成 %s，应该是 %s", i+1, got, c.want)
		}
	}
}

// ★ 两边都不干净时，只在同一种病上比大小。
// 「丢 5%」和「抖 40ms」不是同一个量纲，硬换算会得出「丢包的那边更稳」这种话 ——
// 这里按现场的处理顺序排（丢包先于抖动），并且绝不假装两边可比。
func Test两边都不干净时不跨量纲比(t *testing.T) {
	baseJitterOnly := sampleLine(10, 90, 10, 90)
	targetLoss := sampleLine(10, -1, 10, -1)
	if got := worseSide(baseJitterOnly, targetLoss); got != "target" {
		t.Errorf("worse = %s，一边丢包一边只是抖，应该点出丢包那台", got)
	}
	baseWorse := sampleLine(10, -1, -1, -1)
	targetLight := sampleLine(10, -1, 10, 11)
	if got := worseSide(baseWorse, targetLight); got != "baseline" {
		t.Errorf("worse = %s，同为丢包时该比丢包数", got)
	}
	if got := worseSide(targetLight, targetLight); got != "similar" {
		t.Errorf("worse = %s，一样重要说 similar，不许硬分胜负", got)
	}
	// 一边只抖、一边丢包：按现场处理顺序，丢包那台才是先要查的。
	onlyJitter := sampleLine(10, 90, 10, 90)
	if got := worseSide(targetLight, onlyJitter); got != "baseline" {
		t.Errorf("worse = %s，对照组丢包而目标只抖时该点出对照组", got)
	}
}

func Test对照组话术跟着判定走(t *testing.T) {
	if s := compareSuffix("target-only", nil); !strings.Contains(s, "只在这台") {
		t.Errorf("target-only 话术：%s", s)
	}
	if s := compareSuffix("baseline-only", nil); !strings.Contains(s, "对照组") {
		t.Errorf("baseline-only 话术：%s", s)
	}
	s := compareSuffix("both", "target")
	if !strings.Contains(s, "这一段链路") || !strings.Contains(s, "更难看的是这一台") {
		t.Errorf("both 话术：%s", s)
	}
	if s := compareSuffix("neither", nil); s != "" {
		t.Errorf("neither 不该加话：%s", s)
	}
}

// ── 参数校验 ──

func Test持续ping参数校验(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"没给地址", `{}`, "addr"},
		{"地址看不懂", `{"addr":"999.1.1.1"}`, "看不"},
		{"时间太长", `{"addr":"127.0.0.1","durationMs":600000}`, "太长"},
		{"间隔配时长发不到四发", `{"addr":"127.0.0.1","intervalMs":5000,"durationMs":10000}`, "不到 4 发"},
		{"对照组地址看不懂", `{"addr":"127.0.0.1","baseline":"不是个地址"}`, "baseline"},
		{"参数不是JSON", `[{`, "JSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := doPingWatch(context.Background(), json.RawMessage(c.raw))
			if err == nil {
				t.Fatalf("%s 竟然过了", c.raw)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("报错 %q，话里该有 %q", err, c.want)
			}
		})
	}
}

// 「间隔配时长发不到四发」这条不许反过来把人挡死：给足时间就该放行。
func Test够发就不拦(t *testing.T) {
	_, err := doPingWatch(context.Background(), json.RawMessage(`{"addr":"240.0.0.1","intervalMs":200,"durationMs":1000}`))
	if err != nil && strings.Contains(err.Error(), "不到 4 发") {
		t.Errorf("五发被拦了：%s", err)
	}
}

func Test持续ping工具声明(t *testing.T) {
	if pingWatchTool.Name != "net.ping.watch" {
		t.Errorf("名字是 %s", pingWatchTool.Name)
	}
	if pingWatchTool.Class != ots.ClassRead {
		t.Errorf("分类是 %v，连发只是发流量观察，不算改动 [OTS-4.3]", pingWatchTool.Class)
	}
	for _, code := range []string{watchStable, watchJitter, watchLoss, watchNoReply, watchUnreachable, watchNoRoute} {
		if !strings.Contains(string(pingWatchTool.Summary), code) {
			t.Errorf("说明里没交代判定 %s —— 调用方（AI）拿到这个码不知道下一步", code)
		}
	}
	var schema map[string]any
	if err := json.Unmarshal(pingWatchTool.Schema, &schema); err != nil {
		t.Fatalf("Schema 不是合法 JSON：%s", err)
	}
	if req, _ := schema["required"].([]any); len(req) != 1 || req[0] != "addr" {
		t.Errorf("required = %v，应该只强制 addr", schema["required"])
	}
	if schema["additionalProperties"] != false {
		t.Error("Schema 不许放过没写的参数：写错字段名应该当场报错，而不是静默按默认值跑 10 秒")
	}
}
