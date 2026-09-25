package tools

// ── net.quality.watch / .status / .report / .stop ──
//
// 持续质量监测：本机按窗连续 ping 一个地址，每一窗的 RTT / 丢包 / 抖动画完就**落一行账**，
// 人回到电脑前问「刚才那半小时到底什么样」答得出来。
//
// ★★ 为什么要单独一栏，net.ping.watch 不够用：
//
//	watch 是一次性看十秒，「有时候卡一下」正好在那十秒之外。毛病不在场的时候，
//	唯一能问出真相的办法是让它一直记着 —— 所以这一栏的产物不是曲线，是一本账。
//
// ★★ 为什么 mutate + 点头 + 记账：
//
//	它会在这台机器上后台连续发包（默认每一秒一发，一直到你停），还会往配置目录里写文件。
//	这两件事在人不在场的时候一直发生 —— 不点头就不能开始，点了头就要留下「谁开的、开着干什么」。
//
// ★ 最要紧的一条纪律：**断档必须问得出来**。
//
//	机器睡过去、进程被杀掉、留痕写到上限被滚掉 —— 这三种情况在图上都是一段没有数据，
//	看的人默认会读成「那段时间没出事」。所以每一段空洞、每一次跳号、每一回截断
//	都单独算、单独说，并且在「其他啥毛病都没找到」的时候把它顶成判定 ——
//	因为那时它正是唯一那句实话。
//
// ★ 采不到数据的那几种情况各归各的账，不合并：
//   包根本没出去（本机没路，采集器自己停下）/ 连着全丢（那台关机了）/
//   通断交替（一会儿全断一会儿又通）/ 有窗丢包 / 只有 RTT 抬升 —— 处理方向完全不同。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/quality"
)

// 状态那两问的判定。
const (
	verdictQualityRunning = "quality-running" // 这一路在跑
	verdictQualityIdle    = "quality-idle"    // 本机没有在跑的监测
	verdictQualityStopped = "quality-stopped" // 刚停掉
	verdictQualityBarred  = "quality-barred"  // 包发不出去：本机没有路，采下去只会得到一条假曲线
	// ★ 自己收手有两种病，下一步在两个不同的地方，所以是两个码：
	//
	//	包发不出去 → 查这台机器的路由与网卡；
	//	账写不下去 → 查磁盘、权限和那个目录还在不在。
	verdictQualityLedgerBlocked = "quality-ledger-blocked"
)

// 报表的判定。★ 每一档都对应一个不同的下一步动作，不然不该单开一档。
const (
	verdictQualityStable    = "quality-stable"    // 留着的这些窗全程有回执且不抖
	verdictQualityLoss      = "quality-loss"      // 有窗丢包（点名最差那一窗：什么时候、丢几发）
	verdictQualityFlapping  = "quality-flapping"  // 通断交替：连着全丢的窗之间还恢复过
	verdictQualityRTTRise   = "quality-rtt-rise"  // 没丢，但往返自己往上走了
	verdictQualityGap       = "quality-gap"       // ★ 留痕有断档：那段没采到，不等于没发生
	verdictQualityTruncated = "quality-truncated" // ★ 留痕被截：最早那几窗已经滚出文件了
)

const (
	qualityDefaultIntervalMS = 1000
	qualityMinIntervalMS     = 500
	qualityMaxIntervalMS     = 60000
	qualityDefaultWindowMS   = 30000
	qualityMinWindowMS       = 5000
	qualityMaxWindowMS       = 600000
	qualityMinProbes         = 4    // 一窗里连 4 发都排不下，那本账没有统计意义
	qualityWarmupProbes      = 3    // 开跑前先打三发，只为分清「本机没路」和「那台不吭声」
	qualityReportTail        = 120  // 报表默认看最近多少窗（默认窗口 30s → 一小时）
	qualityReportMaxTail     = 2000 // 一次最多搬回界面多少窗，再多界面画不动也没意义
	qualityRiseFactor        = 1.5  // 后段中位数是前段的几倍算抬升
	qualityRiseFloorMS       = 20   // ★ 且至少差这么多毫秒：5ms 变 8ms 是 1.6 倍，那不是毛病
)

// 留痕落在哪个目录。没装（找不到用户配置目录）就不许开监测 ——
// 一句话说：记不下来的监测不是监测，是给人一个「我盯着呢」的错觉。
var qualityDir string

func SetQualityDir(dir string) { qualityDir = dir }

// qualityProber 开一路探测。★ 走变量是为了能测：
// 「什么时候该自己停下、断档怎么算、被截过看不看得出来」这些判断，
// 不该只能靠真等几十秒、还得碰上一个恰好会抖的网络才验得着。
var qualityProber = newQualityProber

// newQualityProber 真的去开一条 ICMP 套接字。
//
// ★ 一整个采集期只开一条（和 net.ping.watch 同一条理由）：每发都重开一个的话，
// 慢的是建套接字而不是网络，那本账会被自己污染。
func newQualityProber(p qualityPlan) (watchProbe, func() error, error) {
	addr, err := netaddr.Parse(p.target)
	if err != nil {
		return nil, nil, err
	}
	w, err := newICMPWatcher(addr, p.timeout())
	if err != nil {
		return nil, nil, err
	}
	return w.probe(), w.Close, nil
}

// live 当前在跑的这一路。全场只允许一路，和文件共享、对测口同一个理由：
// 界面上那颗「停」必须只对应一件事，两路在现场一定停错。
var live = struct {
	mu      sync.Mutex
	smp     *qualitySampler
	entryID string
}{mu: sync.Mutex{}}

type qualityWatchArgs struct {
	Addr       string `json:"addr"`
	IntervalMS int    `json:"intervalMs,omitempty"`
	WindowMS   int    `json:"windowMs,omitempty"`
}

type qualityReportArgs struct {
	Addr    string `json:"addr"`
	Windows int    `json:"windows,omitempty"`
}

type qualityPlan struct {
	target   string
	interval time.Duration
	window   time.Duration
}

// timeout 每一发等多久算丢。★ 就取一个间隔：窗口是按绝对时刻排的，
// 一发等超过一个间隔就会把后面所有发都拖稀，那条曲线的时间轴不再是等距的 ——
// 而「按窗统计丢包率」的前提正是这些发是等距的。
func (p qualityPlan) timeout() time.Duration {
	d := p.interval
	if d < time.Second {
		d = time.Second
	}
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

var qualityWatchTool = ots.Tool{
	Name:  "net.quality.watch",
	Class: ots.ClassMutate,
	Summary: "在本机开一路**持续质量监测**：按一个固定间隔连续 ping 你指定的地址，每满一窗（默认 30 秒）" +
		"就把这一窗的发数、丢包、中位/95 分位/最大往返、抖动记成一行账落到磁盘上，一直记到你停或者这个后端退出。\n" +
		"★ 它答的是「刚才那一段时间什么样」，不是「现在通不通」—— 后者用 net.ping，看十秒用 net.ping.watch。\n" +
		"开之前先打三发：只为了分清「本机根本没路过去」（这种当场就不开，因为再记下去只会得到一条全丢的假曲线）" +
		"和「这台现在不吭声」（这种照开 —— 它可能过二十分钟才回来，那正是你要看的）。\n" +
		"一路只允许一个在跑；留痕文件有上限（默认 5000 窗），到上限滚掉最早的窗，" +
		"但**序号保留**，所以报表永远问得出「这份账被截过、前面还有多少窗」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string", "description": "盯哪个地址（IPv4/IPv6，链路本地地址要带 zone）。建议填网关或者那台一直在抖的设备 —— 一路只看一个目标，要看两台就开两趟（先停掉这一路）。"},
	    "intervalMs": {"type": "integer", "minimum": 500, "maximum": 60000,
	      "description": "每隔多久发一发，默认 1000。★ 这是**长跑**，不是十秒的看热闹：500ms 以下连跑几小时就是一场小型洪泛，所以不接。"},
	    "windowMs": {"type": "integer", "minimum": 5000, "maximum": 600000,
	      "description": "多久记一窗，默认 30000。窗口要排得下至少 4 发：一窗里只有两三发，那个丢包率是窗口的刻度不是链路的。想看得细就把窗口调小，代价是账变多变密。"}
	  }
	}`),
	Describe: describeQualityWatch,
	Invoke:   startQualityWatch,
}

var qualityStatusTool = ots.Tool{
	Name:  "net.quality.status",
	Class: ots.ClassRead,
	Summary: "本机现在有没有在跑持续质量监测：盯的是谁、多久一发多久一窗、已经记了几窗、" +
		"账落在哪个文件、最新一窗到没到点。\n" +
		"★ 没在跑的时候它同样要说清上一次留下的账还在不在（哪个文件、多少窗、最后一条距今多久）—— " +
		"「采集停了」和「连账都没了」是两件事，前者回去看报表就行，后者才是真丢了现场。\n" +
		"如果这一路是自己停的（包发不出去、账写不下去），这里会点名说为什么停，不会让你对着一个「没在跑」猜。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: statusQualityWatch,
}

var qualityReportTool = ots.Tool{
	Name:  "net.quality.report",
	Class: ots.ClassRead,
	Summary: "读一路持续质量监测留下的账，给出按窗的曲线和判定：稳定 / 有窗丢包 / 通断交替 / 只有往返抬升。\n" +
		"★ 除了「有没有毛病」，它必须同时报**这份账本身缺了什么**：哪一段时间整个没采到（机器睡了、进程被停过）、" +
		"跳了几号窗、最早那几窗是不是被上限滚掉了。这一段没数据不等于那一段没出事 —— " +
		"什么毛病都没找到而账上有洞时，判定就是 quality-gap，不会给你一句「全程稳定」。\n" +
		"每一窗给的是账上的原始数（发数、收回执数、丢包率、中位/95/最大、抖动、抖在哪几发），" +
		"界面上画的线和这句判定读的是同一份，不会两处各算一遍。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string", "description": "哪个目标的账（就是 net.quality.watch 里填的那个地址，写法要一致，账是按目标分文件存的）。"},
	    "windows": {"type": "integer", "minimum": 2, "maximum": 2000,
	      "description": "看最近多少窗，默认 120。★ 它只是**窗口宽度**，不是「这段时间一定采到了」：报表会另外说清这段里有几段断档。"}
	  }
	}`),
	Invoke: reportQualityWatch,
}

var qualityStopTool = ots.Tool{
	Name:     "net.quality.stop",
	Class:    ots.ClassMutate,
	Summary:  "停掉本机的持续质量监测：采集器停下、不再往账里写窗。★ 留下的账**不会删** —— 那本账就是开这一路的目的，停了才有得看。",
	Schema:   json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string { return "停掉本机在跑的持续质量监测（留痕文件保留）" },
	Invoke:   stopQualityWatch,
}

// ── 批准说明 [OTS-7.2] ──

// describeQualityWatch 说到人能拍板：盯谁、多久一发、多久一窗、账写到哪个文件、什么时候停。
// ★ 「一直跑到你停」这句必须在批准框里就出现 —— 不然人以为点是「测一下」，
//
//	实际同意的是这台机器后台每秒一发跑一整夜，并且一直往盘上写。
func describeQualityWatch(raw json.RawMessage) string {
	var a qualityWatchArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	s := fmt.Sprintf("在本机开一路持续质量监测：盯 %s", strings.TrimSpace(a.Addr))
	interval, window, err := qualityTiming(a)
	if err != nil {
		s += "（时间参数没定下来：" + err.Error() + "）"
		return s
	}
	s += fmt.Sprintf("，每 %s 发一发，每 %s 记一窗", humanDur(interval), humanDur(window))
	if qualityDir == "" {
		s += "。★ 找不到用户配置目录，账没地方落 —— 这一路开不起来"
		return s
	}
	s += fmt.Sprintf("。账落在 %s，一直跑到你调 net.quality.stop 停或者这个后端退出为止",
		quality.PathFor(qualityDir, strings.TrimSpace(a.Addr)))
	s += "；停掉不会删这本账。★ 它是后台持续发包，不在同一个网段的目标请按出口策略确认不会被当成扫描"
	return s
}

// ── 一路监测的开关 ──

func qualityTiming(a qualityWatchArgs) (time.Duration, time.Duration, error) {
	interval := qualityDefaultIntervalMS * time.Millisecond
	if a.IntervalMS > 0 {
		interval = time.Duration(a.IntervalMS) * time.Millisecond
	}
	if interval < qualityMinIntervalMS*time.Millisecond || interval > qualityMaxIntervalMS*time.Millisecond {
		return 0, 0, fmt.Errorf("intervalMs 只能在 %d–%d 之间（长跑不要打太密）",
			qualityMinIntervalMS, qualityMaxIntervalMS)
	}
	window := qualityDefaultWindowMS * time.Millisecond
	if a.WindowMS > 0 {
		window = time.Duration(a.WindowMS) * time.Millisecond
	}
	if window < qualityMinWindowMS*time.Millisecond || window > qualityMaxWindowMS*time.Millisecond {
		return 0, 0, fmt.Errorf("windowMs 只能在 %d–%d 之间", qualityMinWindowMS, qualityMaxWindowMS)
	}
	if window/interval < qualityMinProbes {
		return 0, 0, fmt.Errorf("窗口 %v 配间隔 %v 一窗排不下 %d 发 —— 把窗口调大或者间隔调小，"+
			"不然那本账里每一窗都只是两三发，丢包率是刻度的粗细不是链路的", window, interval, qualityMinProbes)
	}
	return interval, window, nil
}

func startQualityWatch(ctx context.Context, raw json.RawMessage) (any, error) {
	var a qualityWatchArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	target := strings.TrimSpace(a.Addr)
	if target == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	interval, window, err := qualityTiming(a)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if qualityDir == "" {
		// ★ 记不下来的监测不是监测：那只是给人一个「我盯着呢」的错觉。
		return nil, ots.Errf(ots.ErrInternal, "找不到用户配置目录，留痕没地方存，拒绝开监测")
	}
	if journal == nil {
		// ★ 和文件共享同一条线：会一直发后台包、一直写文件的改动记不下来，就不许开始。
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝开监测")
	}
	plan := qualityPlan{target: target, interval: interval, window: window}

	live.mu.Lock()
	if s := live.smp; s != nil && s.alive() {
		live.mu.Unlock()
		st := s.snapshot()
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"已经有一路监测在跑了（盯 %s，每 %s 一发）。先 net.quality.stop 停掉再开新的",
			st.plan.target, humanDur(st.plan.interval))
	}
	live.mu.Unlock()

	// 先打三发。★ 这一趟**不是**「先验一下能不能通」——那台现在不吭声也照样该开监测，
	// 它可能二十分钟后才回来，而那正是现场要看的东西。这里只拦一种情况：
	// 包在本机就没出去（没有路）。那种账记一夜也记不出任何东西，
	// 只会留下一条 100% 丢包的线，把人支去查对端的防火墙。
	probe, warmClose, err := qualityProber(plan)
	if err != nil {
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}
	defer func() { _ = warmClose() }()
	warm, warmNoRoute := sweepN(ctx, plan.interval, qualityWarmupProbes, probe)
	if warmNoRoute != "" {
		return ots.Verdict{Code: verdictQualityBarred, Values: map[string]any{
			"target": target, "barred": warmNoRoute, "samples": warm,
			"intervalMs": int(interval / time.Millisecond),
			"windowMs":   int(window / time.Millisecond),
		}, Note: fmt.Sprintf("没有开这一路监测：%s 这个地址本机现在发不出去包 —— "+
			"%s。这不是对端不响，是路由/网卡这边的事，查自己这台（net.routes、net.interfaces）；"+
			"照开的话记一夜也只会得到一条全丢的假曲线",
			target, warmNoRoute)}, nil
	}
	_ = warmClose()

	store, err := quality.Open(quality.PathFor(qualityDir, target), quality.DefaultLimit)
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "%s", err)
	}
	// 采集器自己再开一条套接字：预热那条归这个函数，返回时就该关掉。
	probe, closeProbe, err := qualityProber(plan)
	if err != nil {
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}
	smp := newQualitySampler(plan, store, probe, closeProbe)

	id, err := journal.Register("quality-watch", describeQualityWatch(raw),
		map[string]any{"watching": false},
		map[string]any{"target": target, "intervalMs": int(interval / time.Millisecond),
			"windowMs": int(window / time.Millisecond), "file": store.Path()})
	if err != nil {
		_ = closeProbe()
		return nil, ots.Errf(ots.ErrInternal, "这一路监测记不进改动账本，拒绝开：%s", err)
	}
	_ = journal.MarkApplied(id)

	// ★ 先对外可见、再放 goroutine：反过来的话，采集器可能已经写完一窗而界面上
	// 还查不到「有一路在跑」，那颗「停」按钮就慢一拍 —— 而这一栏的停是唯一能收手的口子。
	live.mu.Lock()
	live.smp, live.entryID = smp, id
	live.mu.Unlock()
	smp.start()

	have := store.Count()
	next := smp.nextSeq()
	note := fmt.Sprintf("已开始盯 %s：每 %s 一发，每 %s 记一窗，账落在 %s。",
		target, humanDur(interval), humanDur(window), store.Path())
	if have > 0 {
		note += fmt.Sprintf("这本账上原来就有 %d 窗（上一次留下的，没动它），"+
			"从现在起往第 %d 窗接着写。", have, next)
	} else {
		note += fmt.Sprintf("第一窗要等满 %s 才落账（第 %d 窗），现在能看到的是开跑前那 %d 发（%s）。",
			humanDur(window), next, len(warm), warmClause(warm))
	}
	note += "★ 它会一直跑到你调 net.quality.stop 停或者这个后端退出；停掉不删账"

	return ots.Verdict{Code: verdictQualityRunning, Values: map[string]any{
		"target":     target,
		"intervalMs": int(interval / time.Millisecond),
		"windowMs":   int(window / time.Millisecond),
		"file":       store.Path(),
		"windows":    have,
		"nextSeq":    next,
		"warmup":     warmRTT(warm),
		"startedAt":  smp.startedAt.Format(time.RFC3339),
		"firstAt":    smp.startedAt.Add(window).Format(time.RFC3339),
		"barred":     "",
	}, Note: note}, nil
}

// warmRTT 预热那几发的往返（没回的明说是几发没回，不拿 0 冒充）。
func warmRTT(samples []pingSample) []any {
	out := make([]any, 0, len(samples))
	for _, s := range samples {
		v := map[string]any{"seq": s.Seq, "kind": s.Kind}
		if s.Kind == verdictReachable {
			v["rttMs"] = s.RTTMS
		}
		if s.Detail != "" {
			v["detail"] = s.Detail
		}
		out = append(out, v)
	}
	return out
}

func warmClause(samples []pingSample) string {
	var got []string
	lost := 0
	for _, s := range samples {
		if s.Kind == verdictReachable {
			got = append(got, fms(s.RTTMS))
		} else {
			lost++
		}
	}
	switch {
	case lost == 0:
		return "往返 " + joinCJK(got, "、")
	case len(got) == 0:
		return fmt.Sprintf("%d 发一个都没回（照开：这一路要看的正是它什么时候回来）", lost)
	}
	return fmt.Sprintf("%s 有回、%d 发没回", joinCJK(got, "、"), lost)
}

// ── 采集器 ──

type qualitySampler struct {
	plan    qualityPlan
	store   *quality.Store
	probe   watchProbe
	cleanup func() error
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}

	startedAt time.Time

	mu      sync.Mutex
	seq     int    // 已经落账的最后一窗序号（0 = 这本账上还没有窗）
	base    int    // 开这一路时已有的序号，用来算「这一路新写了几窗」
	blocked string // 自己停下的原因（空 = 还在跑，或者压根不是自己停的）
	// blockedKind 是自己停下那件事的「哪一种」："route"（包发不出去）或 "ledger"（账写不下去）。
	// ★ 光有 blocked 那句话不够分：那句是人读的，这一格是判定读的 —— 两者的下一步不在同一个地方。
	blockedKind string
}

func newQualitySampler(plan qualityPlan, store *quality.Store, probe watchProbe, cleanup func() error) *qualitySampler {
	// ★ ctx 在这里就建好，不在 start 里：采集器一被挂到 live 上就可能有人调 stop，
	//   到那时才写 cancel 字段就有一次「停的时候读到 nil」的窗口。
	ctx, cancel := context.WithCancel(context.Background())
	s := &qualitySampler{
		plan: plan, store: store, probe: probe, cleanup: cleanup,
		ctx: ctx, cancel: cancel,
		done: make(chan struct{}), startedAt: time.Now(),
	}
	// ★ 序号接着已有的账排：同一本文件里从 1 重排会把「上一次那一路」的窗
	// 变成这一次的窗，截断和跳号就全都对不上了。
	if last, ok := store.Last(); ok {
		s.seq, s.base = last.Seq, last.Seq
	}
	return s
}

// nextSeq 下一窗是第几窗。★ 报给人看的「第 N 窗」必须和落到文件里那个数一模一样。
func (s *qualitySampler) nextSeq() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq + 1
}

// start 把采集器放出去。★ 它用的是自己那份 ctx（构造时就建好，脱离开请求的那个人），
// 这次 HTTP 返回之后采集还得继续 —— 停的时候由 stop 调 cancel 收。
func (s *qualitySampler) start() { go s.loop(s.ctx) }

// stop 收手，并且等采集器真的走完 —— 没等就返回的话，界面上「停了」而账还在长。
func (s *qualitySampler) stop() {
	s.cancel()
	<-s.done
}

func (s *qualitySampler) loop(ctx context.Context) {
	defer close(s.done)
	defer func() {
		if s.cleanup != nil {
			_ = s.cleanup()
		}
	}()
	seq := s.nextSeq()
	for {
		start := time.Now()
		samples, blocked := sweepFor(ctx, s.plan.interval, s.probe,
			func(_ int, elapsed time.Duration) bool { return elapsed < s.plan.window })
		if ctx.Err() != nil {
			// ★ 人停的（或者进程要退了）：这一窗没跑满，不记账。
			//   半窗记进去，图上就会多一格「丢包 40%」，而真相是「那一刻被停了」。
			return
		}
		rec := recordOf(seq, start, time.Now(), s.plan, samples, blocked)
		if err := s.store.Append(rec); err != nil {
			s.markStopped("留痕写不下去了："+err.Error(), blockedLedger)
			return
		}
		s.commitSeq(seq)
		seq++
		if blocked != "" {
			// ★ 本机没路这种事不会自己好。再记下去得到的只是一条全丢的曲线，
			//   而那条曲线每一次都会把人支去查对端的防火墙。
			s.markStopped(blocked, blockedRoute)
			return
		}
	}
}

// commitSeq 写盘成功才把序号推进。★ 写失败的窗不算数：不然文件里的序号会跳，
// 而跳号在这本账里是会被读成断档的 —— 那是我们造的假现场。
func (s *qualitySampler) commitSeq(n int) {
	s.mu.Lock()
	s.seq = n
	s.mu.Unlock()
}

// recordOf 把一窗的样本收成账上的一行。
// ★ 统计口径整个项目只有一份：这里走的是 net.ping.watch 那套 statsOf / spikeIndexes，
//
//	所以「同一时间在 watch 上看到的抖动」和「报表里这一窗的抖动」是同一个算法算的。
func recordOf(seq int, start, end time.Time, plan qualityPlan, samples []pingSample, blocked string) quality.Record {
	st := statsOf(samples)
	r := quality.Record{
		Seq: seq, StartAt: start, EndAt: end, Target: plan.target,
		IntervalMS: int(plan.interval / time.Millisecond),
		WindowMS:   int(plan.window / time.Millisecond),
		Sent:       st.Sent, Recv: st.Recv, Unreachable: st.Unreachable,
		LossPercent: st.LossPercent,
		MinMS:       st.Min, MedianMS: st.Median, P95MS: st.P95,
		MaxMS: st.Max, JitterMS: st.Jitter,
		Blocked: blocked,
	}
	if sp := spikeIndexes(samples); len(sp) > 0 {
		r.Spikes = sp
	}
	return r
}

// 自己收手的两种病。★ 分开的理由不是好看：这两种的下一步不在同一台机器上 ——
// 包发不出去要看的是路由和网卡，账写不下去要看的是磁盘、权限和那个目录。
const (
	blockedRoute  = "route"
	blockedLedger = "ledger"
)

func (s *qualitySampler) markStopped(why, kind string) {
	s.mu.Lock()
	s.blocked, s.blockedKind = why, kind
	s.mu.Unlock()
	s.cancel()
}

// alive 这一路还活着吗。★ 读 done 而不是读一个 bool 标志：
// 「采集器以为自己还在跑」是这一栏最坏的一种错 —— 它会让人盯着一行数字不动却以为在采。
func (s *qualitySampler) alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

type qualitySnapshot struct {
	plan    qualityPlan
	file    string
	windows int // 这本账上现在有多少窗（含上一次留下的）
	mine    int // 这一路新写了几窗
	last    quality.Record
	hasLast bool
	blocked string
	kind    string // blocked 是哪一种（blockedRoute / blockedLedger）
	started time.Time
}

func (s *qualitySampler) snapshot() qualitySnapshot {
	s.mu.Lock()
	blocked, kind, mine := s.blocked, s.blockedKind, s.seq-s.base
	s.mu.Unlock()
	snap := qualitySnapshot{
		plan: s.plan, file: s.store.Path(), windows: s.store.Count(),
		mine: mine, blocked: blocked, kind: kind, started: s.startedAt,
	}
	snap.last, snap.hasLast = s.store.Last()
	return snap
}

// ── 两问读取 ──

func statusQualityWatch(ctx context.Context, raw json.RawMessage) (any, error) {
	live.mu.Lock()
	s := live.smp
	live.mu.Unlock()
	if s == nil || !s.alive() {
		return idleStatus(s)
	}
	snap := s.snapshot()
	vals := map[string]any{
		"running":    true,
		"target":     snap.plan.target,
		"intervalMs": int(snap.plan.interval / time.Millisecond),
		"windowMs":   int(snap.plan.window / time.Millisecond),
		"file":       snap.file,
		"windows":    snap.windows,
		"startedAt":  snap.started.Format(time.RFC3339),
		"blocked":    snap.blocked,
	}
	if snap.hasLast {
		vals["last"] = snap.last
		// 下一窗的估计点：从最新那窗接着排；但这一路刚开、文件里还是上一次的旧窗时，
		// 拿旧窗算出来的「下一窗」是过去的时刻，界面上会读成「已经晚了」。
		next := snap.started.Add(snap.plan.window)
		if snap.last.EndAt.After(snap.started) {
			next = snap.last.EndAt.Add(snap.plan.window)
		}
		vals["nextAt"] = next.Format(time.RFC3339)
		if d := time.Until(next); d > 0 {
			vals["nextInMs"] = d.Milliseconds()
		}
	}
	note := fmt.Sprintf("正在盯 %s：每 %s 一发、每 %s 一窗，这本账上现在有 %d 窗（文件在 %s）",
		snap.plan.target, humanDur(snap.plan.interval), humanDur(snap.plan.window),
		snap.windows, snap.file)
	switch {
	case !snap.hasLast:
		note += "；第一窗还没到点，账上还空着 —— 这不是没数据，是还没到记的时候"
	case snap.last.EndAt.Before(snap.started):
		note += fmt.Sprintf("；这一路还没写新窗（最新那窗 %s 是上一次留下的），第一窗要到 %s 才落",
			snap.last.EndAt.Format("15:04:05"), snap.started.Add(snap.plan.window).Format("15:04:05"))
	default:
		l := snap.last
		note += fmt.Sprintf("；最新一窗 %s：发了 %d 发回了 %d 发（丢包 %d%%），中位 %s",
			l.EndAt.Format("15:04:05"), l.Sent, l.Recv, l.LossPercent, fms(l.MedianMS))
	}
	return ots.Verdict{Code: verdictQualityRunning, Values: vals, Note: note}, nil
}

// idleStatus 没在跑的时候要说清三件事：上一次是自己停的还是被停的、
// 上一本账还在不在、以及这个后端在配置目录里到底有没有账可看。
func idleStatus(s *qualitySampler) (any, error) {
	if s != nil {
		snap := s.snapshot()
		if snap.blocked != "" {
			code, where, next := verdictQualityBarred, "包发不出去",
				"下一步在包的路上：看这块网卡的链路，以及本机现在还有没有去那个地址的路（net.routes、net.interfaces）"
			if snap.kind == blockedLedger {
				code = verdictQualityLedgerBlocked
				where = "账写不下去"
				next = "下一步不在包的路上：看那个目录还在不在、盘满没满、这个账号对它有没有写的权力"
			}
			vals := map[string]any{
				"running": false, "target": snap.plan.target, "selfStopped": true,
				"barred": snap.blocked, "blockedKind": snap.kind,
				"file": snap.file, "windows": snap.windows,
				"intervalMs": int(snap.plan.interval / time.Millisecond),
				"windowMs":   int(snap.plan.window / time.Millisecond),
			}
			if snap.hasLast {
				vals["last"] = snap.last
			}
			// ★ 自己停了也要给「读这本账」：停掉之前那几十窗正是现场，
			//   光说「账还在 + 一个路径」等于让人自己去找文件。
			if ls, err := qualityLedgers(qualityDir); err == nil {
				vals["ledgers"] = ls
			}
			return ots.Verdict{Code: code, Values: vals,
				Note: fmt.Sprintf("这一路监测自己停了（盯的是 %s，已经记了 %d 窗，账还在 %s）：%s。"+
					"★ 它不是被谁停的 —— 这一段之后没有新窗，是因为%s，"+
					"不是「那段时间一切正常」。%s；已经记下的窗都在，修好接着开就是。",
					snap.plan.target, snap.windows, snap.file, snap.blocked,
					where, next)}, nil
		}
	}
	if qualityDir == "" {
		return ots.Verdict{Code: verdictQualityIdle, Values: map[string]any{"running": false},
			Note: "本机没有在跑的持续质量监测（而且找不到用户配置目录，账没地方存）"}, nil
	}
	// 没在跑，但上一本账（以及更早的）还在盘上 —— 界面上要给「去看报表」的入口，
	// 不然人只知道「没在跑」，不知道现场那本账还没丢。
	ledgers, err := qualityLedgers(qualityDir)
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "%s", err)
	}
	return ots.Verdict{Code: verdictQualityIdle, Values: map[string]any{
		"running": false, "dir": qualityDir, "ledgers": ledgers,
	}, Note: idleNote(ledgers)}, nil
}

func idleNote(ledgers []map[string]any) string {
	if len(ledgers) == 0 {
		return "本机没有在跑的持续质量监测，配置目录里也还没有任何留痕 —— 要盯一段时间先开一路（net.quality.watch）"
	}
	names := make([]string, 0, len(ledgers))
	for _, l := range ledgers {
		t, _ := l["target"].(string)
		n, _ := l["windows"].(int)
		names = append(names, fmt.Sprintf("%s（%d 窗）", t, n))
	}
	return fmt.Sprintf("本机没有在跑的持续质量监测，但盘上还留着 %d 本账：%s —— "+
		"要看那一段时间用 net.quality.report（填对应的地址）",
		len(ledgers), joinCJK(names, "、"))
}

// qualityLedgers 扫一遍留痕目录，每本账给一句现状。
// 只报「有多少窗、最后一条什么时候」——曲线留给 report，这里不搬数据。
func qualityLedgers(dir string) ([]map[string]any, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, ots.Errf(ots.ErrInternal, "看不了留痕目录 %s：%s", dir, err)
	}
	var out []map[string]any
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "quality-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		st, err := quality.Open(filepath.Join(dir, e.Name()), quality.DefaultLimit)
		if err != nil {
			out = append(out, map[string]any{"file": filepath.Join(dir, e.Name()), "error": err.Error()})
			continue
		}
		r := map[string]any{
			"file":       st.Path(),
			"windows":    st.Count(),
			"tailBroken": st.TailBroken(),
		}
		target := ""
		if last, ok := st.Last(); ok {
			target = last.Target
			r["lastAt"] = last.EndAt.Format(time.RFC3339)
			r["lastLossPercent"] = last.LossPercent
			r["lastMedianMs"] = last.MedianMS
		}
		if first, ok := st.First(); ok {
			if target == "" {
				target = first.Target
			}
			r["firstAt"] = first.StartAt.Format(time.RFC3339)
			r["firstSeq"] = first.Seq
		}
		r["target"] = target
		out = append(out, r)
	}
	return out, nil
}

func reportQualityWatch(ctx context.Context, raw json.RawMessage) (any, error) {
	var a qualityReportArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	target := strings.TrimSpace(a.Addr)
	if target == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr（要看哪个目标的账）")
	}
	if qualityDir == "" {
		return nil, ots.Errf(ots.ErrInternal, "找不到用户配置目录，没有留痕可看")
	}
	tail := a.Windows
	if tail <= 0 {
		tail = qualityReportTail
	}
	if tail > qualityReportMaxTail {
		return nil, ots.Errf(ots.ErrInvalidArgument, "windows 最多 %d（一次搬太多界面画不动，也没意义）",
			qualityReportMaxTail)
	}
	path := quality.PathFor(qualityDir, target)
	store, err := quality.Open(path, quality.DefaultLimit)
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "%s", err)
	}
	recs := store.Tail(tail)
	// 采集器活着的时候才把「最新一窗距今多久」当断档看；
	// 已经停了的账，尾部那段间隔只是「停掉之后过了多久」，不是洞。
	live.mu.Lock()
	running := live.smp != nil && live.smp.alive() && live.smp.plan.target == target
	live.mu.Unlock()

	if len(recs) == 0 {
		// ★ 「没在跑」和「在跑但第一窗还没到点」在这一栏都读成同一句：没有账。
		//   但绝不该读成「没问题」——所以这一档的 note 要把「一窗都没记到」说死。
		note := fmt.Sprintf("%s 在 %s 上没有留痕 —— 这一段时间根本没采过，"+
			"「没出事」这三个字从这里问不出来", target, path)
		if running {
			note = fmt.Sprintf("%s 这一路正在跑，但还没有任何一窗落账（第一窗要等满一个窗口）"+
				"—— 现在什么都不知道，别读成「目前一切正常」", target)
		}
		return ots.Verdict{Code: verdictQualityIdle, Values: map[string]any{
			"target": target, "file": path, "windows": []quality.Record{}, "running": running,
		}, Note: note}, nil
	}

	now := time.Now()
	if !running {
		now = time.Time{}
	}
	aud := quality.AuditOf(recs, now)
	vals := map[string]any{
		"target": target, "file": path, "running": running,
		"windows": recs, "askedWindows": tail,
		"totalWindows": store.Count(), "truncated": aud.Truncated,
		"droppedWindows": aud.Dropped, "audit": aud,
		// ★ 上次没写干净：进程被杀/断电留下的半行。它不算一窗，但它是
		//   「这一段之后为什么没有账」的答案，得让界面说得出这句话。
		"tailBroken": store.TailBroken(), "skippedLines": store.Skipped(),
		"spanMs": aud.SpanMS, "from": aud.From.Format(time.RFC3339),
		"to": aud.To.Format(time.RFC3339),
	}
	code, note := qualityReportVerdict(recs, aud, running, store.TailBroken())
	return ots.Verdict{Code: code, Values: vals, Note: note}, nil
}

// ── 判定 ──

// qualityReportVerdict 从一本账里出结论。
//
// ★ 顺序就是证据的先后，而且有一条压倒性的规矩：
//
//	账上有洞的时候，绝不能因为「洞以外都没发现问题」就说成稳定 ——
//	那等于把「没问到」写成「问了没问题」。所以毛病先按链路排（发不出去 > 通断交替 > 丢包 > 抬升），
//	一条都没有才轮到账本身的洞（断档 > 被截），那时候洞就是唯一那句实话。
func qualityReportVerdict(recs []quality.Record, aud quality.Audit, running, tailBroken bool) (string, string) {
	head := reportHead(recs, aud)

	if all := allBlocked(recs); all != "" {
		return verdictQualityBarred, head + "；★ 这些窗里包根本没出去（" + all +
			"）—— 这是一条本机没路留下的线，不是对端不响。查自己这台：net.routes、net.interfaces"
	}
	if s := silentClause(recs); s != "" {
		return verdictQualityFlapping, head + "；" + s
	}
	if l := lossClause(recs); l != "" {
		return verdictQualityLoss, head + "；" + l
	}
	if r := riseClause(recs); r != "" {
		return verdictQualityRTTRise, head + "；" + r
	}
	// 链路这一头没毛病了 —— 这时候账本身的洞就是最该说的那句话。
	if h := gapClause(recs, aud, running); h != "" {
		return verdictQualityGap, head + "；" + h + truncClause(aud, tailBroken)
	}
	// ★ truncClause 自己带「；」开头，这里不许再加一个 —— 加了的 note 读起来像打字机卡了。
	if t := truncClause(aud, tailBroken); t != "" {
		return verdictQualityTruncated, head + t
	}
	if len(recs) < 2 {
		// 一窗是一段时间的平均。拿一窗说「没毛病」，说的是「这一段时间里没抓到丢包」，
		// 而「在抖」「在变慢」「断过」这三样在这里根本还没被问过。
		return verdictQualityStable, head + "；★ 只有这一窗 —— 丢包这里问得出，" +
			"「在抖」「在变慢」「中间断过」至少要两窗才问得出。别把这一窗读成「这一路一直很好」"
	}
	return verdictQualityStable, head + "；这些窗里没丢包、不抖、往返也没往上走"
}

// reportHead 先交代这份账的口径：哪台、多长一段、多少窗、怎么个采法。
// ★ 判定之前先把「我们看到的是哪一段」说清楚，不然后面对不上现场的时间。
func reportHead(recs []quality.Record, aud quality.Audit) string {
	first, last := recs[0], recs[len(recs)-1]
	window := time.Duration(first.WindowMS) * time.Millisecond
	s := fmt.Sprintf("%s 的账：%d 窗（每 %s 一窗、每 %s 一发），%s 到 %s，共 %s",
		first.Target, len(recs), humanDur(window), humanDur(time.Duration(first.IntervalMS)*time.Millisecond),
		first.StartAt.Format("15:04:05"), last.EndAt.Format("15:04:05"), humanDur(time.Duration(aud.SpanMS)*time.Millisecond))
	if st := statsOfRecords(recs); st.Recv > 0 {
		s += fmt.Sprintf("；总体中位 %s、最慢 %s、平均抖动 %s", fms(st.Median), fms(st.Max), fms(st.Jitter))
	}
	return s
}

// statsOfRecords 把整本账按发数合并成一份汇总。
// ★ 分位数不能拿各窗的中位数再平均：那是「中位数的中位数」，跟真实分位没关系。
//
//	所以这里能给的只有中位/最大/抖动这一级别的数，95 分位要按窗看（图上那条线就是）。
func statsOfRecords(recs []quality.Record) watchStats {
	st := watchStats{}
	var jitSum float64
	var jitN int
	for _, r := range recs {
		st.Sent += r.Sent
		st.Recv += r.Recv
		st.Unreachable += r.Unreachable
	}
	if st.Sent > 0 {
		st.LossPercent = int(math.Round(float64(st.Sent-st.Recv) * 100 / float64(st.Sent)))
	}
	var med float64
	var medN int
	for _, r := range recs {
		if r.Recv == 0 {
			continue
		}
		if r.MinMS > 0 && (st.Min == 0 || r.MinMS < st.Min) {
			st.Min = r.MinMS
		}
		if r.MaxMS > st.Max {
			st.Max = r.MaxMS
		}
		med += r.MedianMS
		medN++
		if r.JitterMS > 0 {
			jitSum += r.JitterMS
			jitN++
		}
	}
	if medN > 0 {
		st.Median = roundMS2(med / float64(medN))
	}
	if jitN > 0 {
		st.Jitter = roundMS2(jitSum / float64(jitN))
	}
	return st
}

// allBlocked 这些窗里是不是全都发不出去。★ 只在全都发不出去时才判这一档：
// 偶尔一窗blocked 是那一刻网卡没起来，属于链路现象，不该整本账改口。
func allBlocked(recs []quality.Record) string {
	n := 0
	why := ""
	for _, r := range recs {
		if r.Blocked != "" {
			n++
			why = r.Blocked
		}
	}
	if n == len(recs) && n > 0 {
		return why
	}
	return ""
}

// silentClause 连着全丢的窗 —— 而且中间还恢复过，所以是「通断交替」不是「断了」。
func silentClause(recs []quality.Record) string {
	var runs [][]quality.Record
	var cur []quality.Record
	for _, r := range recs {
		if r.Sent > 0 && r.Recv == 0 && r.Blocked == "" {
			cur = append(cur, r)
			continue
		}
		if len(cur) >= 2 {
			runs = append(runs, cur)
		}
		cur = nil
	}
	if len(cur) >= 2 {
		runs = append(runs, cur)
	}
	if len(runs) < 2 {
		return ""
	}
	parts := make([]string, 0, len(runs))
	for _, rn := range runs {
		parts = append(parts, fmt.Sprintf("%s–%s（连 %d 窗全丢）",
			rn[0].StartAt.Format("15:04:05"), rn[len(rn)-1].EndAt.Format("15:04:05"), len(rn)))
	}
	return fmt.Sprintf("通断交替：有 %d 段连着全丢，中间还恢复过 —— %s。"+
		"这一档跟「偶尔丢一发」不是一回事：那台在反复消失（掉电、掉线重连、ARP 被抢、路由在动）",
		len(runs), joinCJK(parts, "、"))
}

// lossClause 有窗丢包：点名最差的那一窗，并把「总共有几窗不干净」带上。
func lossClause(recs []quality.Record) string {
	var dirty int
	var lost int
	worst := quality.Record{}
	for _, r := range recs {
		if r.Recv == r.Sent {
			continue
		}
		dirty++
		lost += r.Sent - r.Recv
		if r.LossPercent > worst.LossPercent {
			worst = r
		}
	}
	if dirty == 0 {
		return ""
	}
	un := ""
	if worst.Unreachable > 0 {
		un = fmt.Sprintf("，其中 %d 发是明确的不可达（不是超时 —— 路是通的，有人在答「到不了」）", worst.Unreachable)
	}
	return fmt.Sprintf("有 %d 窗不干净，一共 %d 发没回；最差的是第 %d 窗（%s 那 %d 发里丢了 %d 发，丢包 %d%%%s）",
		dirty, lost, worst.Seq, worst.StartAt.Format("15:04:05"),
		worst.Sent, worst.Sent-worst.Recv, worst.LossPercent, un)
}

// riseClause 只看往返：没丢包但整段在往上走，是拥塞或链路降速的前兆。
// ★ 前段/后段各取一半的中位数比，并要求**同时**满足倍数和毫秒差两个条件：
//
//	只看倍数会把 5ms 变 8ms 报成毛病，只看绝对值会把本来就有 40ms 的跨洋线报成毛病。
func riseClause(recs []quality.Record) string {
	var ok []quality.Record
	for _, r := range recs {
		if r.Recv > 0 && r.MedianMS > 0 {
			ok = append(ok, r)
		}
	}
	if len(ok) < 4 {
		return ""
	}
	half := len(ok) / 2
	early := medianOfRecords(ok[:half])
	late := medianOfRecords(ok[half:])
	if late-early < qualityRiseFloorMS || early <= 0 || late/early < qualityRiseFactor {
		return ""
	}
	return fmt.Sprintf("往返在往上走：前半段中位 %s，后半段中位 %s（涨到 %.1f 倍）—— "+
		"没丢包不等于没问题，这种形状一般是有人在挤这一段，或者链路自己降了速",
		fms(early), fms(late), late/early)
}

func medianOfRecords(rs []quality.Record) float64 {
	v := make([]float64, 0, len(rs))
	for _, r := range rs {
		v = append(v, r.MedianMS)
	}
	sort.Float64s(v)
	return nearestRank(v, 50)
}

// gapClause 留痕本身有洞：段内空洞、跳号、以及（在跑的话）尾部多久没新窗了。
func gapClause(recs []quality.Record, aud quality.Audit, running bool) string {
	var parts []string
	for _, h := range aud.Holes {
		parts = append(parts, fmt.Sprintf("%s–%s（这一段长 %s，一个窗都没有）",
			h.From.Format("15:04:05"), h.To.Format("15:04:05"), humanDur(time.Duration(h.MS)*time.Millisecond)))
	}
	if aud.Missing > 0 {
		parts = append(parts, fmt.Sprintf("序号跳掉 %d 窗", aud.Missing))
	}
	if running && aud.StaleMS > staleToleranceMS(recs) {
		parts = append(parts, fmt.Sprintf("最新一窗已经结束 %s 还没新窗 —— 这一路看着在跑，但账已经不长了",
			humanDur(time.Duration(aud.StaleMS)*time.Millisecond)))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("★ 留痕有断档：%s。这段时间**没采到**，不等于没出事；"+
		"除了这一段之外的窗里没找到毛病 —— 别把它读成「全程稳定」", joinCJK(parts, "、"))
}

// staleToleranceMS 在跑的这一路「多久没新窗」才算不正常：一个窗口的宽度，再加两发的余量。
// ★ 只有活着的时候才算这条 —— 停了的账尾部当然一直「没新窗」，那不是洞。
func staleToleranceMS(recs []quality.Record) int64 {
	last := recs[len(recs)-1]
	return int64(last.WindowMS) + 2*int64(last.IntervalMS)
}

// truncClause 这份账本身被滚掉/写坏过 —— 和「链路上有没有毛病」无关的另一种缺证据。
func truncClause(aud quality.Audit, tailBroken bool) string {
	var parts []string
	if aud.Truncated {
		parts = append(parts, fmt.Sprintf("最早还留着的是第 %d 窗，前面 %d 窗已经被滚掉（留痕有上限）",
			aud.Dropped+1, aud.Dropped))
	}
	if tailBroken {
		parts = append(parts, "文件尾部有一条没写完的窗，已经丢掉（上一次这个后端不是干净退出的）")
	}
	if len(parts) == 0 {
		return ""
	}
	return "；★ 这份账不完整：" + joinCJK(parts, "、") + "。你现在看到的不是全程"
}

// ── 停 ──

func stopQualityWatch(ctx context.Context, raw json.RawMessage) (any, error) {
	live.mu.Lock()
	s := live.smp
	id := live.entryID
	live.smp, live.entryID = nil, ""
	live.mu.Unlock()
	if s == nil || !s.alive() {
		if s != nil {
			snap := s.snapshot()
			return ots.Verdict{Code: verdictQualityIdle, Values: map[string]any{
				"target": snap.plan.target, "file": snap.file, "windows": snap.windows,
			}, Note: fmt.Sprintf("没有在跑的监测（盯 %s 的那一路已经停了，账还在 %s，%d 窗）",
				snap.plan.target, snap.file, snap.windows)}, nil
		}
		return idleStatus(nil)
	}
	s.stop()
	snap := s.snapshot()
	if journal != nil && id != "" {
		_ = journal.MarkReverted(id, fmt.Sprintf("用户停掉了监测（盯 %s，这一路记了 %d 窗，账保留在 %s）",
			snap.plan.target, snap.mine, snap.file))
	}
	return ots.Verdict{Code: verdictQualityStopped, Values: map[string]any{
		"target": snap.plan.target, "file": snap.file,
		"windows": snap.mine, "totalWindows": snap.windows,
		"intervalMs": int(snap.plan.interval / time.Millisecond),
		"windowMs":   int(snap.plan.window / time.Millisecond),
	}, Note: fmt.Sprintf("监测已停：不再往 %s 写窗（这一路跑了 %s，记了 %d 窗；这本账现在一共 %d 窗）。"+
		"★ 账**没有删** —— 那本账就是开这一路的目的，现在拿 net.quality.report 读它；"+
		"要腾地方就自己删那个文件，我们不动手删现场留下的东西",
		snap.file, humanDur(time.Since(snap.started)), snap.mine, snap.windows)}, nil
}

// restoreQualityWatch 收上次没停的监测账。
//
// ★★ 采集器是本进程持有的，进程退了它就不在了 —— 没有要还原的东西。
//
//	但这笔账必须了结：挂着不管，下次看账本的人会去查一个早就不跑的监测。
//	也不自动重开：那等于人不在场就又开始持续对外发包。
//	留痕文件一律不动：那是现场数据，删了才是不可逆的。
func restoreQualityWatch(log *slog.Logger) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind != "quality-watch" {
			continue
		}
		log.Warn("上次退出时持续质量监测没有正常停止 —— 本次启动不会自动重开（留痕文件保留）",
			"改动", e.What, "时间", e.At.Format(time.RFC3339))
		_ = journal.MarkReverted(e.ID, "进程重启：采集器已随上次进程退出而停，留痕文件保留")
	}
}

// ── 小工具 ──

// humanDur 把 30 秒、1 秒这种长度写成人话。★ 批准框和 note 都用它：
// 「windowMs 30000」人不读，「每 30 秒一窗」人才知道自己同意的是什么刻度。
//
// 除了整刻度，这里还必须接住「不满整秒/整分」的那一段 —— 一段盯了 3 分 45 秒的账，
// 它的总长就是 225063 毫秒。直接把这个大数写进 note，等于把「这段时间有多长」
// 变成一道心算题，而读 note 的人正在现场。
func humanDur(d time.Duration) string {
	ms := int(d / time.Millisecond)
	switch {
	case ms < 1000:
		return itoa(ms) + " 毫秒"
	case ms < 60000:
		if t := ms % 1000 / 100; t > 0 {
			return itoa(ms/1000) + "." + itoa(t) + " 秒"
		}
		return itoa(ms/1000) + " 秒"
	case ms < 3600000:
		if s := ms % 60000 / 1000; s > 0 {
			return itoa(ms/60000) + " 分 " + itoa(s) + " 秒"
		}
		return itoa(ms/60000) + " 分钟"
	default:
		if m := ms % 3600000 / 60000; m > 0 {
			return itoa(ms/3600000) + " 小时 " + itoa(m) + " 分"
		}
		return itoa(ms/3600000) + " 小时"
	}
}
