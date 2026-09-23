package tools

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.ping.watch ──
//
// ★★ 这一栏答的不是「通不通」，而是「通的时候稳不稳」。
//
//	现场的原话通常是「有时候卡一下」——那恰恰是 net.ping 四发问不出来的：
//	四发全通，因为那一下没赶上。所以这里按时间连发，把每一发的结果都留下来。
//
// 最要紧的一条纪律：**曲线之外必须指出「哪一次、什么时候、抖成什么样」**。
// 只给一张图和一句「抖动偏大」等于没答 —— 人要拿那个时刻去对
// （是不是刚好在录像机起流、是不是刚好有人插拔网线）。
//
// 判定分六档，前两档是「问不到」和「问到了但不稳」的区别，绝不能混：
//
//	watch-stable      全程有回执、RTT 平稳
//	watch-jitter      没丢，但抖（给出抖在哪一发）
//	watch-loss        丢了几个（给出丢在哪几发）—— ★ 丢和抖是两种病，处理方向不同
//	watch-no-reply    一个都没回：分不清主机不在还是 ICMP 被拦，先去 net.ping
//	watch-unreachable 每一发都收到明确的不可达：路是通的，问题在终点或路由
//	watch-no-route    包根本没出去：本机没路（网卡没起来 / 不在同一个网段），要查的是自己这边
//
// ★ 可选的对照组（baseline）：同一轮里顺手打一个别的目标（一般是网关或本机另一块网卡）。
//
//	「到这台慢」和「整段都在抖」是两件不同的事，光打一个目标分不出来 ——
//	这一步不用「猜」，两组的丢包和抖动摆在一起，谁在抖一目了然。
const (
	watchStable      = "stable"
	watchJitter      = "jitter"
	watchLoss        = "loss"
	watchNoReply     = "no-reply"
	watchUnreachable = "unreachable"
	watchNoRoute     = "no-route"
)

const (
	watchDefaultInterval = 500 * time.Millisecond
	watchDefaultDuration = 10 * time.Second
	watchMaxDuration     = 60 * time.Second
	watchMaxSpikes       = 5
	// 抖动算「大」的两条线：相邻两发的变化量、以及单发相对中位数的偏离。
	// ★ 用中位数而不是平均值：丢包和尖峰本身会把平均值带高，
	//   拿被污染的那个数当基线，等于自己造出一堆假尖峰。
	watchJitterMS = 30.0
	watchSpikeAdd = 50.0
)

var pingWatchTool = ots.Tool{
	Name:  "net.ping.watch",
	Class: ots.ClassRead,
	Summary: "按时间连续 ping 一个地址，给出 RTT 曲线、丢包在哪几发、抖在哪一发。" +
		"★ 答的是「有时候卡一下」这种 net.ping 四发问不出来的毛病 —— 四发全通往往只是没赶上那一下。\n" +
		"除了汇总（发数、丢包率、最小/中位/平均/95 分位/最大、相邻两发的平均抖动），" +
		"结果里还逐发留痕（seq / atMs / rttMs / kind），并把明显偏离中位数的那几发单独列成 spikes —— " +
		"人要拿那个时刻去对现场发生了什么。\n" +
		"判定：stable（全程稳）、jitter（没丢但抖）、loss（丢了几个，★ 丢和抖是两种病）、" +
		"no-reply（一个都没回，分不清不在还是被拦）、unreachable（每发都是明确的不可达，路是通的）、" +
		"no-route（包根本没出去，本机没路）。\n" +
		"可选 baseline：同一轮里再打一个对照地址（一般是网关），用来分「只有这台慢」和「整段都在抖」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string", "description": "目标地址，IPv4 或 IPv6。链路本地地址（fe80::）必须带 zone。"},
	    "intervalMs": {"type": "integer", "minimum": 200, "maximum": 5000,
	      "description": "每隔多久发一发，默认 500。再小就成洪泛了，而且无线上自己就会抖。"},
	    "durationMs": {"type": "integer", "minimum": 1000, "maximum": 60000,
	      "description": "一共看多久，默认 10000（10 秒）。要长时间留痕监测的是「持续质量」那一栏，不是这里。"},
	    "timeoutMs": {"type": "integer", "minimum": 100, "maximum": 5000,
	      "description": "每一发等多久算丢，默认 1000。跨洋或者走 VPN 时调大，不然会把慢算成丢。"},
	    "baseline": {"type": "string",
	      "description": "可选：同一轮里顺带打的对照地址（建议填网关）。填了才会给「只有这台抖 / 整段都在抖」。"}
	  }
	}`),
	Invoke: doPingWatch,
}

type pingWatchArgs struct {
	Addr       string `json:"addr"`
	IntervalMS int    `json:"intervalMs,omitempty"`
	DurationMS int    `json:"durationMs,omitempty"`
	TimeoutMS  int    `json:"timeoutMs,omitempty"`
	Baseline   string `json:"baseline,omitempty"`
}

// pingSample 是一发的结果。★ 没有回执的那一发同样要占一行：
// 曲线里少一格，看的人就会以为那一时刻是「好」的。
type pingSample struct {
	Seq    int     `json:"seq"`
	AtMS   int64   `json:"atMs"`
	RTTMS  float64 `json:"rttMs,omitempty"`
	Kind   string  `json:"kind"` // reachable / no-reply / unreachable / error
	Detail string  `json:"detail,omitempty"`
}

// watchStats 一堆样本的汇总。★ 分位数用最近秩，不插值：
// 这里要的是「第 95 分位那一发实际是多少毫秒」，不是一个算出来的小数。
type watchStats struct {
	Sent        int
	Recv        int
	Unreachable int // 收到明确不可达的发数（★ 它不是「超时」，含义完全不同）
	LossPercent int
	Min         float64
	Median      float64
	Avg         float64
	P95         float64
	Max         float64
	Jitter      float64
}

func doPingWatch(ctx context.Context, raw json.RawMessage) (any, error) {
	var a pingWatchArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	interval := watchDefaultInterval
	if a.IntervalMS > 0 {
		interval = time.Duration(a.IntervalMS) * time.Millisecond
	}
	dur := watchDefaultDuration
	if a.DurationMS > 0 {
		dur = time.Duration(a.DurationMS) * time.Millisecond
	}
	if dur > watchMaxDuration {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"durationMs %d 太长了（最多 %d）—— 这一栏是一次性看一小段，要长跑留痕的是「持续质量监测」",
			a.DurationMS, int(watchMaxDuration/time.Millisecond))
	}
	if int64(dur/interval) < 4 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"intervalMs %d 配 durationMs %d 只够发不到 4 发 —— 看不出抖不抖。把间隔调小或者时间调长",
			int(interval/time.Millisecond), int(dur/time.Millisecond))
	}
	timeout := time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}

	target, err := netaddr.Parse(a.Addr)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	watcher, err := newICMPWatcher(target, timeout)
	if err != nil {
		return nil, err
	}
	defer watcher.Close()

	var base *icmpWatcher
	if s := strings.TrimSpace(a.Baseline); s != "" {
		baddr, berr := netaddr.Parse(s)
		if berr != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "baseline %s 看不懂：%s", s, berr)
		}
		base, berr = newICMPWatcher(baddr, timeout)
		if berr != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "对照组 %s 发不出去：%s", s, berr)
		}
		defer base.Close()
	}

	samples, noRoute := watcher.run(ctx, interval, dur)
	var baseSamples []pingSample
	if base != nil {
		// ★ 对照组晚一点开始没关系（同一轮里跑的），但要跑同样长的时间、
		//   同样的发数 —— 两组发的次数不一样，丢包率就没有可比性了。
		baseSamples, _ = base.run(ctx, interval, dur)
	}

	values := map[string]any{
		"target":     target.String(),
		"family":     familyOf(target),
		"intervalMs": int(interval / time.Millisecond),
		"durationMs": int(dur / time.Millisecond),
		"samples":    samples,
		"spikes":     spikeIndexes(samples),
		"lostAt":     lostAt(samples),
	}
	st := statsOf(samples)
	mergeStats(values, st, "")
	spanMS, actualMS, sparse := paceOf(samples, interval)
	values["spanMs"] = spanMS
	values["actualIntervalMs"] = actualMS
	pace := ""
	if sparse {
		pace = "；★ 实际每发隔 " + itoa(actualMS) + "ms，比要的 " + itoa(int(interval/time.Millisecond)) +
			"ms 稀 —— 每一发都等到超时才走下一发（把 timeoutMs 调小或 intervalMs 调大），" +
			"这条曲线的时间轴不是等距的"
	}

	if base != nil {
		values["baselineSamples"] = baseSamples
		mergeStats(values, statsOf(baseSamples), "baseline")
		bSpan, _, _ := paceOf(baseSamples, interval)
		values["baselineSpanMs"] = bSpan
		values["baseline"] = strings.TrimSpace(a.Baseline)
		who := compareWho(baseSamples, samples)
		values["compare"] = who
		if who == "both" {
			values["compareWorse"] = worseSide(baseSamples, samples)
		}
	}

	code, note := watchVerdict(st, noRoute)
	switch code {
	case watchNoRoute:
		return ots.Verdict{Code: code, Values: values,
			Note: "包根本没出去：" + note + " —— 这跟对端没关系，查自己这边（网卡、路由、是不是同一个网段）"}, nil
	case watchNoReply:
		extra := ""
		if st.Unreachable > 0 {
			// ★ 一档里也要把这条证据留住：有几发是明确回了「到不了」的，
			//   那说明这台机器在、也有人收到 —— 只是它把回显拦了。
			//   一句「一个都没回」会让人以为连主机都不存在，那是两个结论。
			extra = "（其中有 " + itoa(st.Unreachable) + " 发是明确的不可达，不是没吭声 —— " +
				"至少这台在，回显被挡了）"
		}
		return ots.Verdict{Code: code, Values: values,
			Note: target.String() + " 一个回显都没给 —— 分不清是主机不在还是 ICMP 被拦了，这一栏测不出稳定性" + extra + pace}, nil
	case watchUnreachable:
		return ots.Verdict{Code: code, Values: values,
			Note: target.String() + " 每发都回了明确的不可达 —— 中间的路是通的，问题在终点或路由" + pace}, nil
	}
	suffix := ""
	if v, ok := values["compare"].(string); ok {
		suffix = compareSuffix(v, values["compareWorse"])
	}
	return ots.Verdict{Code: code, Values: values,
		Note: watchNote(target.String(), st, code, samples) + suffix + pace}, nil
}

// paceOf 算「实际每发隔多久」。★ 要的间隔不等于跑得起来的间隔：
// 一跳等满 timeout、间隔又要得比它小，发序会被自己的超时拖稀。
// 那件事必须说出口 —— 一条只有两点的曲线在图上看着像「这两秒都稳」，
// 而真相是这两秒里每一发都没回。
func paceOf(samples []pingSample, interval time.Duration) (spanMS, actualMS int, sparse bool) {
	if len(samples) < 2 {
		return 0, 0, false
	}
	spanMS = int(samples[len(samples)-1].AtMS - samples[0].AtMS)
	actualMS = spanMS / (len(samples) - 1)
	return spanMS, actualMS, actualMS > int(interval/time.Millisecond)*3/2
}

// watchNote 给 CLI 和日志看的一句话。★ 抖和丢分别说，而且把「哪一发、在第几秒」带上 ——
// 光说「不稳」没人能拿去干活。
func watchNote(target string, st watchStats, code string, samples []pingSample) string {
	base := ""
	if st.Recv > 0 {
		base = "中位 " + fms(st.Median) + "、最慢 " + fms(st.Max) +
			"、相邻两发的平均抖动 " + fms(st.Jitter)
	}
	switch code {
	case watchLoss:
		un := ""
		if st.Unreachable > 0 {
			// ★ 丢的里面有一部分是「明确回了不可达」，这句话必须说：
			//   它把「偶发丢失」和「路由时不时指不到这台」分开，处理方向不同。
			un = "（其中 " + itoa(st.Unreachable) + " 发是明确的不可达，不是超时）"
		}
		return target + " 连续 " + itoa(st.Sent) + " 发里丢了 " + itoa(st.Sent-st.Recv) +
			" 发" + un + "（丢包率 " + itoa(st.LossPercent) + "%），" + base +
			"；丢在" + whenList(samples)
	case watchJitter:
		return target + " 没丢包，但抖：" + base + spikeClause(samples, st.Median)
	default:
		return target + " 全程 " + itoa(st.Recv) + " 发都有回执且不抖：" + base
	}
}

// spikeClause 把尖峰那几发写成「；抖在第 5 发（2.5s 时 320ms）」——
// ★ 时刻和值都要给：人拿时刻去对现场发生了什么，拿值判断严不严重，少一个都得再翻原始样本。
//
//	一发都没挑出来时不能含糊过去：抖是**整条线在晃**还是**那一下卡**，处理方向不一样。
//	前者查链路质量（信号、拥塞、AP 争用），后者查有没有谁在那一刻干了什么。
func spikeClause(samples []pingSample, med float64) string {
	var parts []string
	for _, seq := range spikeIndexes(samples) {
		for _, s := range samples {
			if s.Seq != seq {
				continue
			}
			parts = append(parts, "第 "+itoa(seq)+" 发（"+secs(s.AtMS)+" 时 "+fms(s.RTTMS)+"）")
			break
		}
	}
	if len(parts) == 0 {
		return "；没有哪一发明显高出中位数（" + fms(med) + "）—— 是整条线都在晃，不是那一下卡"
	}
	return "；抖在" + joinCJK(parts, "、")
}

// whenList 丢包那几发：给序号 + 时刻 + 是超时还是不可达。
func whenList(samples []pingSample) string {
	var parts []string
	for _, m := range lostAt(samples) {
		seq, _ := m["seq"].(int)
		at, _ := m["atMs"].(int64)
		kind, _ := m["kind"].(string)
		s := "第 " + itoa(seq) + " 发（" + secs(at) + "）"
		if w := kindWord(kind); w != "" {
			s += "（" + w + "）"
		}
		parts = append(parts, s)
	}
	if len(parts) == 0 {
		return "无"
	}
	return joinCJK(parts, "、")
}

// kindWord 把「没回执」的三种来路写成中文。★ 超时和不吭声不用标：
// 没回执默认就是超时，标出来反而是噪音。
func kindWord(kind string) string {
	switch kind {
	case verdictUnreachable:
		return "明确不可达"
	case "error":
		return "包没出去"
	}
	return ""
}

func joinCJK(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// secs 毫秒写成秒，一位小数就够对时刻了。
func secs(ms int64) string {
	return strconv.FormatFloat(float64(ms)/1000, 'f', 1, 64) + "s"
}

func compareSuffix(who string, worse any) string {
	switch who {
	case "target-only":
		return "；同一轮里对照组是干净的 —— 毛病只在这台"
	case "baseline-only":
		return "；反倒是对照组不干净，目标这台没问题"
	case "both":
		tail := ""
		if s, ok := worse.(string); ok && s != "" && s != "similar" {
			if s == "target" {
				tail = "，更难看的是这一台"
			} else {
				tail = "，更难看的是对照组"
			}
		}
		return "；同一轮里对照组也不干净 —— 先查这一段链路（网段、AP、出口），别只盯这一台" + tail
	}
	return ""
}

// ── 一路 ICMP：开套接字 + 按时间连发 ──

// icmpWatcher 是一个能连发的 ICMP 套接字。
// ★ 一整个 watch 只开一个套接字：每发都重开一个的话，慢的是建套接字而不是网络，
//
//	曲线会被自己污染。
type icmpWatcher struct {
	conn    icmpConn
	addr    netaddr.Addr
	dst     net.Addr
	id      int
	timeout time.Duration
}

func newICMPWatcher(a netaddr.Addr, timeout time.Duration) (*icmpWatcher, error) {
	dst, err := echoDst(a)
	if err != nil {
		return nil, err
	}
	conn, err := listenICMP(a)
	if err != nil {
		return nil, err
	}
	return &icmpWatcher{
		conn: conn, addr: a, dst: dst,
		id: os.Getpid() & 0xffff, timeout: timeout,
	}, nil
}

func (w *icmpWatcher) Close() error { return w.conn.Close() }

// run 用真的套接字连发。
func (w *icmpWatcher) run(ctx context.Context, interval, dur time.Duration) ([]pingSample, string) {
	return sweep(ctx, interval, dur, func(seq int) (time.Duration, string, error) {
		return pingOnce(w.conn, w.addr, w.dst, w.id, seq, w.timeout)
	})
}

// watchProbe 发一发的动作。★ 抽出来是为了能测：
// 「丢在哪一发、抖在哪一发、什么时候该停下」这些判断，
// 不该只能靠真等十几秒、还得碰上一个恰好会抖的网络才验得着。
type watchProbe func(seq int) (time.Duration, string, error)

// sweep 按间隔连发到时间为止，返回每一发的结果，以及「包是不是根本没出去」的原因。
//
// ★ 发不出去（比如本机没有路由）和发了没回是两件事：前者从第一发就该停下 ——
//
//	继续发只会得到一条「全丢」的曲线，而那条曲线会让人去查对端的防火墙。
func sweep(ctx context.Context, interval, dur time.Duration, probe watchProbe) ([]pingSample, string) {
	var out []pingSample
	start := time.Now()
	deadline := start.Add(dur)
	seq := 1
	for {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
		at := time.Since(start)
		rtt, kind, err := probe(seq)
		s := pingSample{Seq: seq, AtMS: at.Milliseconds(), Kind: kind}
		if rtt > 0 {
			s.RTTMS = roundMS(rtt)
		}
		if err != nil {
			s.Detail = err.Error()
			s.Kind = "error"
			out = append(out, s)
			// ★ 「网络不可达」这类是**本机没有路**：一发出不去就该停，
			//   别让人拿一条全丢的曲线去查对端的防火墙。
			if isNoRoute(err) {
				return out, "这个地址本机没有路由（" + err.Error() + "）"
			}
		} else {
			out = append(out, s)
		}
		seq++
		// 等到下一发的点。★ 用「下一发的绝对时刻」而不是「再睡一个间隔」：
		// 后者会把每一发的耗时累进间隔里，越往后越慢，曲线就成了斜线 —— 那是工具的错，不是网络的。
		next := start.Add(time.Duration(seq-1) * interval)
		if d := time.Until(next); d > 0 {
			select {
			case <-ctx.Done():
				return out, ""
			case <-time.After(d):
			}
		}
	}
	return out, ""
}

// ── 纯算术：汇总、尖峰、对照 ──

// statsOf 汇总一路样本。
func statsOf(samples []pingSample) watchStats {
	st := watchStats{Sent: len(samples)}
	var rtts []float64
	for _, s := range samples {
		switch s.Kind {
		case verdictReachable:
			st.Recv++
			rtts = append(rtts, s.RTTMS)
		case verdictUnreachable:
			// ★ 单独记一档：对方明说「到不了」，和「没吭声」是两种病。
			//   混进超时里，就会把人支去查对端防火墙，而路其实是通的。
			st.Unreachable++
		}
	}
	if st.Sent > 0 {
		st.LossPercent = int(math.Round(float64(st.Sent-st.Recv) * 100 / float64(st.Sent)))
	}
	if len(rtts) == 0 {
		return st
	}
	sorted := append([]float64(nil), rtts...)
	sort.Float64s(sorted)
	st.Min = sorted[0]
	st.Max = sorted[len(sorted)-1]
	st.Median = nearestRank(sorted, 50)
	st.P95 = nearestRank(sorted, 95)
	var sum float64
	for _, v := range rtts {
		sum += v
	}
	st.Avg = roundMS2(sum / float64(len(rtts)))
	// ★ 抖动按**发的先后顺序**算，不按大小：要的是「上一发和这一发差多少」，
	//   排过序之后那个差值就没有意义了。
	var jit float64
	for i := 1; i < len(rtts); i++ {
		jit += math.Abs(rtts[i] - rtts[i-1])
	}
	if len(rtts) > 1 {
		st.Jitter = roundMS2(jit / float64(len(rtts)-1))
	}
	return st
}

// nearestRank 最近秩：小样本下不插值，取实际存在的那一发。
func nearestRank(sorted []float64, pct float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	r := math.Ceil(pct / 100 * float64(len(sorted)))
	if r < 1 {
		r = 1
	}
	if int(r) > len(sorted) {
		r = float64(len(sorted))
	}
	return sorted[int(r)-1]
}

// spikeIndexes 挑出明显偏离中位数的那几发，返回它们的序号。
//
// ★★ 判尖峰用中位数不用平均值：平均值会被尖峰自己带高 ——
//
//	一次 2000ms 的卡顿把平均抬上去之后，接下来 200ms 的那一发就不算尖峰了，
//	而它恰恰是用户要问的「那一下」。
func spikeIndexes(samples []pingSample) []int {
	var rtts []float64
	for _, s := range samples {
		if s.Kind == verdictReachable {
			rtts = append(rtts, s.RTTMS)
		}
	}
	if len(rtts) < 4 {
		return nil // 两三发谈不上「偏离」，硬挑只会挑出噪音
	}
	sorted := append([]float64(nil), rtts...)
	sort.Float64s(sorted)
	med := nearestRank(sorted, 50)
	var out []int
	for _, s := range samples {
		if s.Kind != verdictReachable {
			continue
		}
		if s.RTTMS >= math.Max(med*3, med+watchSpikeAdd) {
			out = append(out, s.Seq)
			if len(out) >= watchMaxSpikes {
				break
			}
		}
	}
	return out
}

// lostAt 丢的是哪几发（序号 + 相对时刻）。★ 时刻比序号有用：
// 人要拿它去对「那一下发生了什么」。
func lostAt(samples []pingSample) []map[string]any {
	var out []map[string]any
	for _, s := range samples {
		if s.Kind == verdictReachable {
			continue
		}
		m := map[string]any{"seq": s.Seq, "atMs": s.AtMS, "kind": s.Kind}
		if s.Detail != "" {
			m["detail"] = s.Detail
		}
		out = append(out, m)
		if len(out) >= watchMaxSpikes*4 {
			break // 全丢的时候不该刷出一屏
		}
	}
	return out
}

// watchVerdict 决定说哪一档。★ 顺序是有讲究的：先排除「问不到」的三种，
// 再分「丢」和「抖」——因为丢了样本之后再算抖动就是拿一份残缺的曲线算，
// 那个数不能和「没丢」时的抖动放在同一个尺度上看。
func watchVerdict(st watchStats, noRoute string) (string, string) {
	switch {
	case noRoute != "":
		return watchNoRoute, noRoute
	case st.Recv == 0 && st.Unreachable == st.Sent && st.Unreachable > 0:
		// ★ 每一发都拿到了明确的「到不了」：包出得去、也有人回话，只是回的不是应答。
		//   只要掺进没吭声的那几发就不算 —— 那种情况连「有人收到」都没问实。
		return watchUnreachable, ""
	case st.Recv == 0:
		return watchNoReply, ""
	case st.Recv < st.Sent:
		return watchLoss, ""
	case st.Jitter >= watchJitterMS:
		return watchJitter, ""
	default:
		return watchStable, ""
	}
}

// compareWho 把目标和对照组摆在一起，判「谁不干净」。
// ★ 纯算术，不猜：丢包率、抖动各是多少都另留在结果里，这里只出四档之一。
func compareWho(base, target []pingSample) string {
	b, t := statsOf(base), statsOf(target)
	bad := func(s watchStats) bool {
		return s.Sent == 0 || s.LossPercent > 0 || s.Jitter >= watchJitterMS
	}
	switch {
	case !bad(t) && !bad(b):
		return "neither"
	case !bad(t) && bad(b):
		return "baseline-only"
	case bad(t) && !bad(b):
		return "target-only"
	}
	return "both"
}

// worseSide 两边都不干净时说清谁更难看。
// ★ 同一种病直接比数；各有一种病时按「丢包比抖动更难看」排 ——
//
//	不是把两个量纲换算成同一个数比大小（那会算出「丢包的那边更稳」这种话），
//	而是现场处理顺序本来就如此：丢了要查链路质量，抖只是_margin_偏大。
func worseSide(base, target []pingSample) string {
	b, t := statsOf(base), statsOf(target)
	if t.LossPercent > 0 && b.LossPercent > 0 {
		switch {
		case t.LossPercent > b.LossPercent:
			return "target"
		case t.LossPercent < b.LossPercent:
			return "baseline"
		}
		return "similar"
	}
	if t.LossPercent > 0 || b.LossPercent > 0 {
		// 只有一边丢包：不用比第二个量纲了。
		if t.LossPercent > 0 {
			return "target"
		}
		return "baseline"
	}
	if t.Jitter == b.Jitter {
		return "similar"
	}
	if t.Jitter > b.Jitter {
		return "target"
	}
	return "baseline"
}

func mergeStats(values map[string]any, st watchStats, prefix string) {
	k := func(s string) string {
		if prefix == "" {
			return s
		}
		return prefix + upper1(s)
	}
	values[k("sent")] = st.Sent
	values[k("recv")] = st.Recv
	values[k("unreachable")] = st.Unreachable
	values[k("lossPercent")] = st.LossPercent
	if st.Recv == 0 {
		return
	}
	values[k("rttMinMs")] = st.Min
	values[k("rttMedianMs")] = st.Median
	values[k("rttAvgMs")] = st.Avg
	values[k("rttP95Ms")] = st.P95
	values[k("rttMaxMs")] = st.Max
	values[k("jitterAvgMs")] = st.Jitter
}

func upper1(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return string(r[0]-32) + string(r[1:])
}

// fms 把毫秒数写成一句人话。★ 大于 100ms 就不要再带三位小数 ——
// 「123.456ms」在现场读起来比「123ms」费劲，而多出来的那位既不精确也不影响判断。
func fms(v float64) string {
	if v >= 100 {
		return itoa(int(math.Round(v))) + "ms"
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + "ms"
}

func roundMS(d time.Duration) float64 { return roundMS2(float64(d.Microseconds()) / 1000) }
func roundMS2(v float64) float64      { return math.Round(v*1000) / 1000 }
