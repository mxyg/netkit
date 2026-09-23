package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// net.mtr —— 持续路径质量：同一批跳**连着问几十次**，看每一跳的丢包、抖动和最差值。
//
// ★★ 一次性的 traceroute 回答「现在路通不通」，回答不了「这条路是不是一直在丢」。
//
//	现场拿到「偶尔卡一下 / 画面隔十几秒花一格」这种主诉，单跑一次 traceroute 全绿，
//	于是有人说「网络没问题」—— 而那正是这一栏要拦住的误判。
//
// ★ 这一栏真正的价值不是把每一跳的丢包率列出来，而是**读出哪一行的丢包是真的**：
//
//	中间设备常常对 TTL 超时的 ICMP 做限速（不响应不丢转发），在表上就是一行 100% 丢包，
//	可它后面的每一跳都收得到 —— 那说明它根本没丢转发流量，只是自己不爱回话。
//	把这一行报成「第 6 跳拥塞」，人就会去提单查一台正常工作的骨干路由。
//	所以判定看的是**丢包有没有一路延续到终点**，不是单跳的丢包率。
var mtrTool = ots.Tool{
	Name:  "net.mtr",
	Class: ots.ClassRead,
	Summary: "对目标做**持续**逐跳探测（MTR 式），每跳给出发送数、丢包率、最好/平均/最差往返。" +
		"★ 判定看丢包是否一路延续到终点：中间某跳丢但后面每跳都收得到，判为「这台设备只是不回应探测」，" +
		"不算故障；从某跳起一路丢到终点才算真正的拥塞点，并给出那一跳。默认 IPv4、IPv6 各测一遍并排给结果。属于只读。",
	Schema: json.RawMessage(`{
		  "type": "object",
		  "additionalProperties": false,
		  "required": ["host"],
		  "properties": {
		    "host": {"type": "string", "description": "目标：域名或 IP。"},
		    "family": {"type": "string", "enum": ["auto", "v4", "v6"],
		      "description": "默认 auto：两族各测一遍（目标只有一种记录时只测那一种）。"},
		    "rounds": {"type": "integer", "minimum": 1, "maximum": 50,
		      "description": "整条路径重复几轮，默认 8。要抓偶发丢包就调大。"},
		    "perHop": {"type": "integer", "minimum": 1, "maximum": 5,
		      "description": "每轮每跳发几个探测，默认 3。每跳样本数 ≈ rounds × perHop。"},
		    "maxHops": {"type": "integer", "minimum": 1, "maximum": 40,
		      "description": "最多追到第几跳，默认 30。"},
		    "timeoutMs": {"type": "integer", "minimum": 5000, "maximum": 300000,
		      "description": "整轮测量（含两族）最多花多久，默认 60000。时间不够会按已完成的轮出结果。"}
		  }
		}`),
	Invoke: doMtr,
}

// 质量判定码。★ 全部来自**测到的样本**，不是工具失败（[OTS-6.2]）。
const (
	qualityOK         = "quality-ok"
	qualitySilent     = "quality-silent-loss"  // 中段丢，但下游收得到：那台设备不爱回 ICMP，不是故障
	qualityPathMoved  = "quality-path-changed" // 同一跳见过多个地址：等价路径在翻动（负载分担 / 路由在动）
	qualityNoResponse = "quality-no-response"  // 一轮样本都没拿到：说不清质量
	qualityLatency    = "quality-latency-jump" // 从某跳起往返明显抬升并延续到终点
	qualityTargetLoss = "quality-target-loss"  // 只有终点丢：路是通的，终点自己不吭声（限速 / 防火墙 / 它坏了）
	qualityLoss       = "quality-loss"         // 从某跳起一路丢到终点 —— 拥塞点在那一跳之前

	// 每跳行上的注记，界面按这些挑颜色和挑话术。
	flagSilent  = "silent"
	flagSource  = "loss-source" // 真实丢包的起点
	flagSlow    = "latency-start"
	flagMoved   = "path-moved"
	flagTarget  = "target"
	flagHealthy = "healthy"
)

// 判定门槛。★ 写死成常量并说明，不许散在代码里各处凭感觉比。
const (
	// 少于这么多探测就不给丢包结论：3 个样本丢 1 个是 33%，说出来只会误导
	mtrMinProbes = 3
	// 丢包率超过这个百分比才算「在丢」（与 mtr 的 0.x% 噪声区分开）
	mtrLossPct = 5.0
	// ★ 至少要真丢这么多发才算。8 个探测里丢 1 个是 12.5%，够得上上面那条线，
	//   但任何一条正常工作的局域网都会偶尔这么干（第一发的 ARP、对端的 ICMP 限速）——
	//   真机第一次跑就把一台好好的网关报成了「终点在丢包」。一发不算证据，两发起才算。
	mtrMinLost = 2
	// 往返比上一跳高出这么多毫秒才算抬升（链路上 5ms 的差别是常态）
	mtrLatencyJumpMs = 30.0
)

type mtrArgs struct {
	Host      string `json:"host"`
	Family    string `json:"family,omitempty"`
	Rounds    int    `json:"rounds,omitempty"`
	PerHop    int    `json:"perHop,omitempty"`
	MaxHops   int    `json:"maxHops,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// mtrHop 是一跳的统计。★ 丢包率必须带着分母（snt）一起给：
// 3 个探测丢 1 个和 30 个探测丢 1 个是两个数量级的事，只看百分数会把噪声当故障。
type mtrHop struct {
	Hop     int      `json:"hop"`
	Addr    string   `json:"addr,omitempty"`  // 见得最多的那个地址
	Addrs   []string `json:"addrs,omitempty"` // 全部见过的地址，多于一个就是路径在动
	Snt     int      `json:"snt"`             // 分到的探测数（含丢的）
	Lost    int      `json:"lost"`
	LossPct float64  `json:"lossPct"`
	BestMs  float64  `json:"bestMs,omitempty"`
	AvgMs   float64  `json:"avgMs,omitempty"`
	WorstMs float64  `json:"worstMs,omitempty"`
	LastMs  float64  `json:"lastMs,omitempty"`
	Spread  float64  `json:"spreadMs,omitempty"` // 最差减最好：抖动的直白说法，不编公式
	Rounds  int      `json:"roundsSeen"`         // 出现在几轮里（总轮数见 family.rounds）
	Mark    string   `json:"mark,omitempty"`
	IsGoal  bool     `json:"isGoal,omitempty"`
	Flag    string   `json:"flag,omitempty"`
}

type mtrFamily struct {
	Family     string   `json:"family"`
	Code       string   `json:"code"`
	Goals      []string `json:"goals,omitempty"`
	GoalSeen   bool     `json:"goalSeen"` // 一轮都没走到终点时，下面的统计是「截止处」的统计
	Rounds     int      `json:"rounds"`
	RoundsDone int      `json:"roundsDone"`
	Hops       []mtrHop `json:"hops,omitempty"`
	StartHop   int      `json:"lossHop,omitempty"`    // 真实丢包从第几跳开始
	SlowHop    int      `json:"latencyHop,omitempty"` // 往返抬升从第几跳开始
	Engine     string   `json:"engine"`
	Command    string   `json:"command,omitempty"`
	Tried      string   `json:"tried,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Partial    bool     `json:"partial,omitempty"`
}

func doMtr(ctx context.Context, raw json.RawMessage) (any, error) {
	var a mtrArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	host := strings.TrimSpace(a.Host)
	if host == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给目标地址")
	}
	// ★ 目标要交给外部命令当参数：以 - 开头或带空白一律拒（同 net.trace 的理由）。
	if strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n") {
		return nil, ots.Errf(ots.ErrInvalidArgument, "目标写法不对（不能有空白，也不能以 - 开头）")
	}
	rounds := a.Rounds
	if rounds == 0 {
		rounds = 8
	}
	perHop := a.PerHop
	if perHop == 0 {
		perHop = 3
	}
	maxHops := a.MaxHops
	if maxHops == 0 {
		maxHops = 30
	}
	timeout := 60 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	want := a.Family
	if want == "" {
		want = "auto"
	}
	goals, families, early := traceTargets(ctx, host, want)
	if early != nil {
		return *early, nil
	}

	// 两族分预算，理由同 net.trace：v6 卡住时不能把 v4 的样本一起拖没。
	budget := timeout / time.Duration(len(families))
	if budget < 5*time.Second {
		budget = timeout
	}
	out := make([]mtrFamily, 0, len(families))
	for _, fam := range families {
		fctx, cancel := context.WithTimeout(ctx, budget)
		r := measureFamily(fctx, host, fam, goals[fam], maxHops, perHop, rounds)
		cancel()
		out = append(out, r)
	}

	values := map[string]any{
		"host":     host,
		"reports":  out,
		"families": families,
	}
	code := topMtrCode(out)
	return ots.Verdict{Code: code, Values: values, Note: mtrNote(code, out)}, nil
}

// measureFamily 拿到一族的质量样本。有 mtr 就用它（同样的时间里每跳多出一个量级的探测），
// 没有就跑多轮 traceroute —— ★ 两条路的输出汇成同一个形状，判定的规矩只写一遍。
func measureFamily(ctx context.Context, host, family string, goals []netaddr.Addr, maxHops, perHop, rounds int) mtrFamily {
	res := mtrFamily{Family: "ipv" + strings.TrimPrefix(family, "v"), Rounds: rounds}
	want := make([]string, 0, len(goals))
	for _, g := range goals {
		want = append(want, g.String())
	}
	res.Goals = want

	// ★ 给 mtr 只留六成预算：它要是卡住（要 root 却不回话、或者在等一个不回的探测），
	//   把整族的时间吃光就一轮 traceroute 都跑不了，那时拿回 0 个样本，
	//   报出来像「这条路没质量」，其实只是这一支命令没跑成。
	hops, cmd, why, ok := func() ([]mtrHop, string, string, bool) {
		left := time.Until(deadlineOf(ctx))
		sub, cancel := context.WithTimeout(ctx, left*6/10)
		defer cancel()
		return runMtr(sub, host, family, maxHops, perHop, rounds)
	}()
	if ok {
		res.Engine = "mtr"
		res.Command = cmd
		absorbMtrHops(&res, hops, want)
		judgeMtr(&res)
		return res
	} else if why != "" {
		res.Tried = why
	}
	// 多轮 traceroute。★ 每轮分到的时间 = 剩余时间 / 剩余轮数：跑一轮就吃掉全部预算的话，
	// 后面几轮一行样本都没有，而「多轮」正是这一栏存在的理由。
	var tried []string
	aggs := map[int]*hopAgg{}
	done := 0
	for i := 0; i < rounds; i++ {
		left := rounds - i
		budget := time.Until(deadlineOf(ctx)) / time.Duration(left)
		if budget < 1500*time.Millisecond {
			res.Partial = true
			break
		}
		rctx, cancel := context.WithTimeout(ctx, budget)
		r := runTrace(rctx, host, family, goals, maxHops, perHop)
		cancel()
		if r.Code == traceNoCommand || r.Code == tracePrivileged {
			// 工具问题不会因为多跑几轮而变好，早点说
			res.Engine = "traceroute 多轮"
			res.Code, res.Detail, res.Tried = r.Code, r.Detail, strings.Join(append(tried, r.Tried), "；")
			return res
		}
		absorbRound(aggs, r, want)
		done++
		if r.Command != "" {
			res.Command = r.Command
		}
		if r.Tried != "" {
			tried = append(tried, r.Tried)
		}
		if r.Partial {
			res.Partial = true
		}
		if r.Code == traceNoRoute {
			// 本机这一族没路：再跑七轮也是没路，别把时间花完
			res.Engine = "traceroute 多轮"
			res.RoundsDone = done
			res.Code = traceNoRoute
			res.Detail = r.Detail
			res.Tried = strings.Join(tried, "；")
			return res
		}
		if ctx.Err() != nil {
			res.Partial = true
			break
		}
	}
	res.Engine = "traceroute 多轮"
	res.RoundsDone = done
	res.Tried = strings.Join(tried, "；")
	buildHops(&res, aggs, want)
	judgeMtr(&res)
	return res
}

func deadlineOf(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(5 * time.Second)
}

// ---------- 多轮 traceroute → 每跳统计 ----------

type hopAgg struct {
	byAddr map[string]int
	rtts   []float64
	lost   int
	prints int // 出现在几轮里（这一跳被印出来了）
	probes int // 印出来时带了多少个探测（回了几发 + 丢了几发）
	goal   bool
	mark   string
}

// absorbRound 把一轮的结果并进去。
//
// ★★ 分母只算**这一轮真的印到了这一跳**的次数：某一轮在第 6 跳就断了，
//
//	后面那几跳根本没被问过，把它们记成「丢了」等于把「没问」当成「问了三回都没吭声」。
//	这种虚高的丢包率会让人去查一条根本没走过的路。
func absorbRound(aggs map[int]*hopAgg, r traceFamily, goals []string) {
	goal := map[string]bool{}
	for _, g := range goals {
		goal[g] = true
	}
	for _, h := range r.Hops {
		a := aggs[h.Hop]
		if a == nil {
			a = &hopAgg{byAddr: map[string]int{}}
			aggs[h.Hop] = a
		}
		a.prints++
		a.probes += len(h.RTTMs) + h.Lost
		a.lost += h.Lost
		if h.Addr != "" {
			a.byAddr[h.Addr]++
			a.rtts = append(a.rtts, h.RTTMs...)
			if goal[h.Addr] {
				a.goal = true
			}
		}
		if h.Mark != "" && a.mark == "" {
			a.mark = h.Mark
		}
	}
}

func buildHops(res *mtrFamily, aggs map[int]*hopAgg, goals []string) {
	nums := make([]int, 0, len(aggs))
	for n := range aggs {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	goal := map[string]bool{}
	for _, g := range goals {
		goal[g] = true
	}
	for _, n := range nums {
		a := aggs[n]
		h := mtrHop{Hop: n, Snt: a.probes, Lost: a.lost, Rounds: a.prints, Mark: a.mark}
		h.Addr, h.Addrs = topAddr(a.byAddr)
		if a.probes > 0 {
			h.LossPct = round1(float64(a.lost) / float64(a.probes) * 100)
		}
		if len(a.rtts) > 0 {
			var sum float64
			h.BestMs = a.rtts[0]
			for _, v := range a.rtts {
				if v < h.BestMs {
					h.BestMs = v
				}
				if v > h.WorstMs {
					h.WorstMs = v
				}
				sum += v
			}
			h.LastMs = a.rtts[len(a.rtts)-1]
			h.AvgMs = round1(sum / float64(len(a.rtts)))
			h.BestMs = round1(h.BestMs)
			h.WorstMs = round1(h.WorstMs)
			h.LastMs = round1(h.LastMs)
			h.Spread = round1(h.WorstMs - h.BestMs)
		}
		if a.goal {
			h.IsGoal = true
			res.GoalSeen = true
		}
		res.Hops = append(res.Hops, h)
	}
	// ★ 终点那一跳的「一次都没被印出来」要算成丢：中间跳没印出来可能是路径变短了，
	//   终点没印出来只有一个意思 —— 那一轮没走到终点。
	for i := range res.Hops {
		if !res.Hops[i].IsGoal {
			continue
		}
		if miss := res.RoundsDone - res.Hops[i].Rounds; miss > 0 {
			lost := miss * perHopProbes(res.Hops[i])
			res.Hops[i].Snt += lost
			res.Hops[i].Lost += lost
			res.Hops[i].LossPct = round1(float64(res.Hops[i].Lost) / float64(res.Hops[i].Snt) * 100)
		}
	}
}

// perHopProbes 一轮里该跳本该有几个探测：拿它自己的历史猜最稳（有的实现只印一发）。
func perHopProbes(h mtrHop) int {
	if h.Snt/h.Rounds > 0 {
		return h.Snt / h.Rounds
	}
	return 1
}

func topAddr(byAddr map[string]int) (string, []string) {
	if len(byAddr) == 0 {
		return "", nil
	}
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(byAddr))
	for k, v := range byAddr {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	addrs := make([]string, 0, len(list))
	for _, x := range list {
		addrs = append(addrs, x.k)
	}
	return list[0].k, addrs
}

// ---------- mtr（装了就用）----------

// mtrCommands 给出 mtr 的报告模式命令。目标里没有 mtr 时返回 false 走多轮 traceroute。
func mtrCommands(family string, probes, maxHops int, host string) []string {
	fam := "-4"
	if family == "v6" {
		fam = "-6"
	}
	// ★ --json 而不是 --report：文本报告的分列宽随版本和域名长度变，列对齐一错就整行错列；
	//   JSON 每跳自带 sent/rcv/loss/best/avg/worst，字段名写死比数字位置写死可靠得多。
	return []string{"mtr", "--json", "--report-wide", fam, "-c", strconv.Itoa(probes),
		"-m", strconv.Itoa(maxHops), host}
}

// mtrHopDoc 是 mtr --json 报告里一跳的形状。
//
// ★ 各版本对「同一跳多个地址」的写法不一样（有的把 tier 重复给，有的给 IPs 数组），
//
//	所以这里按**能宽容就宽容**处理：认不出的形状当成解析失败，退回多轮 traceroute，
//	绝不照着半懂不懂的字段编统计。
type mtrHopDoc struct {
	Tier   any      `json:"tier"`
	Loss   *float64 `json:"loss"`
	Rcv    any      `json:"rcv"`
	Sent   any      `json:"sent"`
	Best   *float64 `json:"best"`
	Avg    *float64 `json:"avg"`
	Worst  *float64 `json:"worst"`
	Last   *float64 `json:"last"`
	IPs    []string `json:"IPs"`
	IPsLow []string `json:"ips"`
	Name   string   `json:"name"`
}

func runMtr(ctx context.Context, host, family string, maxHops, perHop, rounds int) ([]mtrHop, string, string, bool) {
	argv := mtrCommands(family, rounds*perHop, maxHops, host)
	if _, err := exec.LookPath(argv[0]); err != nil {
		return nil, "", "", false
	}
	var so, se bytes.Buffer
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	text := so.String()
	cmdStr := strings.Join(argv, " ")
	if hops, ok := parseMtrJSON(text); ok {
		return hops, cmdStr, "", true
	}
	// 没跑成 / 形状不认识：把原因带回给调用方，但**不报成故障**（多轮 traceroute 接着干）。
	why := ""
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		why = cmdStr + "：超时"
	case err != nil:
		why = cmdStr + "：" + firstTraceLine(se.String()+text)
	default:
		why = cmdStr + "：输出形状不认识"
	}
	return nil, cmdStr, why, false
}

// mtrDocAgg 把同一跳的多条记录并成一个统计。
//
// ★ 平均按 sent 加权（一个 tier 被拆成几条时，探测多的那条说话更响），
//
//	最好取最小、最差取最大 —— 这三条都是 mtr 自己算出来的数，这里只做合并；
//	不去假装自己能从平均值算出抖动。
type mtrDocAgg struct {
	addrs  map[string]int
	sent   int
	lost   int
	avgSum float64
	best   float64
	worst  float64
	last   float64
}

func (a *mtrDocAgg) absorb(d mtrHopDoc) {
	sent := asInt(d.Sent)
	if sent <= 0 {
		// 拿不到分母就不并。编一个分母出来，等于给这一跳编一个置信度。
		return
	}
	a.sent += sent
	rcv := asInt(d.Rcv)
	if d.Rcv == nil && d.Loss != nil {
		rcv = int(math.Round(float64(sent) * (1 - *d.Loss/100)))
	}
	if lost := sent - rcv; lost > 0 {
		a.lost += lost
	}
	if d.Avg != nil {
		a.avgSum += *d.Avg * float64(sent)
	}
	for _, ip := range append(append([]string{}, d.IPs...), d.IPsLow...) {
		if v, e := netip.ParseAddr(trimZone(ip)); e == nil {
			a.addrs[v.String()]++
		}
	}
	if d.Best != nil && (a.best == 0 || *d.Best < a.best) {
		a.best = *d.Best
	}
	if d.Worst != nil && *d.Worst > a.worst {
		a.worst = *d.Worst
	}
	if d.Last != nil {
		a.last = *d.Last
	}
}

func parseMtrJSON(text string) ([]mtrHop, bool) {
	var doc struct {
		Report struct {
			Hops json.RawMessage `json:"report"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil || len(doc.Report.Hops) == 0 {
		return nil, false
	}
	// 两种形状都见过：一跳一个对象的平铺数组，以及按轮分组的嵌套数组。
	var flat []mtrHopDoc
	if err := json.Unmarshal(doc.Report.Hops, &flat); err != nil {
		var nested [][]mtrHopDoc
		if err := json.Unmarshal(doc.Report.Hops, &nested); err != nil {
			return nil, false
		}
		for _, group := range nested {
			flat = append(flat, group...)
		}
	}
	aggs := map[int]*mtrDocAgg{}
	for _, d := range flat {
		n := asInt(d.Tier)
		if n <= 0 {
			continue
		}
		a := aggs[n]
		if a == nil {
			a = &mtrDocAgg{addrs: map[string]int{}}
			aggs[n] = a
		}
		a.absorb(d)
	}
	nums := make([]int, 0, len(aggs))
	for n, a := range aggs {
		if a.sent > 0 {
			nums = append(nums, n)
		}
	}
	if len(nums) == 0 {
		return nil, false
	}
	sort.Ints(nums)
	out := make([]mtrHop, 0, len(nums))
	for _, n := range nums {
		a := aggs[n]
		h := mtrHop{
			Hop: n, Snt: a.sent, Lost: a.lost, Rounds: 1,
			LossPct: round1(float64(a.lost) / float64(a.sent) * 100),
			BestMs:  round1(a.best), WorstMs: round1(a.worst), LastMs: round1(a.last),
			AvgMs: round1(a.avgSum / float64(a.sent)),
		}
		if h.WorstMs > h.BestMs {
			h.Spread = round1(h.WorstMs - h.BestMs)
		}
		h.Addr, h.Addrs = topAddr(a.addrs)
		out = append(out, h)
	}
	return out, true
}

func asInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(math.Round(x))
	case string:
		n, _ := strconv.Atoi(x)
		return n
	case int:
		return x
	}
	return 0
}

func round1(f float64) float64 {
	return math.Round(f*10) / 10
}

// ---------- 判定：这一路的丢包到底是不是真的 ----------

// absorbMtrHops 把 mtr 出的统计并进结果（mtr 每跳自带地址与丢包，不再自己聚合）。
func absorbMtrHops(res *mtrFamily, hops []mtrHop, goals []string) {
	goal := map[string]bool{}
	for _, g := range goals {
		goal[g] = true
	}
	for _, h := range hops {
		for _, a := range append([]string{h.Addr}, h.Addrs...) {
			if goal[a] {
				h.IsGoal = true
				res.GoalSeen = true
			}
		}
		res.Hops = append(res.Hops, h)
	}
	res.RoundsDone = res.Rounds
}

// judgeMtr 出这一族的判定。★ 顺序是有意的：先看真丢包，再看只有终点丢，
// 然后才是抬升和路径翻动 ——「中段某跳丢得厉害」在最前面，因为它最容易是假的。
func judgeMtr(res *mtrFamily) {
	if res.Code != "" {
		return
	}
	if len(res.Hops) == 0 {
		res.Code = qualityNoResponse
		return
	}
	// 有分母的跳才参与判定
	valid := func(h mtrHop) bool { return h.Snt >= mtrMinProbes }
	// ★ 三个条件一起够才算「在丢」：样本够、真丢了至少两发、比例过线。
	losing := func(h mtrHop) bool {
		return valid(h) && h.Lost >= mtrMinLost && h.LossPct >= mtrLossPct
	}
	tail := -1 // 最后一个有足够样本的跳 —— 它的丢包决定「下游干不干净」
	for i, h := range res.Hops {
		if valid(h) {
			tail = i
		}
	}
	if tail < 0 {
		res.Code = qualityNoResponse
		return
	}
	tailDirty := losing(res.Hops[tail])
	realFrom := -1 // 真实丢包的起点
	targetOnly := false
	slowFrom := -1
	silent := false
	moved := false

	// setFlag 只在还没有注记时写。★ 丢包类注记的优先级高于「路径翻动」：
	// 同一跳既换了地址又在丢，说「它在丢」更有用，被翻动盖掉就等于把故障说成了稀奇。
	setFlag := func(i int, f string) {
		if res.Hops[i].Flag == "" {
			res.Hops[i].Flag = f
		}
	}
	for i, h := range res.Hops {
		if len(h.Addrs) > 1 {
			moved = true
		}
		if !losing(h) {
			continue
		}
		switch {
		case i == tail && h.IsGoal:
			targetOnly = true
			setFlag(i, flagTarget)
		case i == tail:
			// 截止处就在丢，下面没有跳可以作证「下游干净」：算一路延续到可测处
			if realFrom < 0 {
				realFrom = i
			}
			setFlag(i, flagSource)
		case !tailDirty:
			// ★★ 下游收得到：这一跳丢的是**它自己的回应**，不是被它丢掉的转发流量。
			//   报成故障就是这一栏最贵的误判。
			setFlag(i, flagSilent)
			silent = true
		default:
			if realFrom < 0 {
				realFrom = i
			}
			setFlag(i, flagSource)
		}
	}
	// 往返抬升：比上一跳明显变慢，而且**到了终点还是慢** ——
	// 单跳慢 50ms 而下一跳 recovered，多半是那台设备的 ICMP 优先级低，不是链路。
	prev := -1
	for i, h := range res.Hops {
		if !valid(h) || h.AvgMs == 0 {
			continue
		}
		if prev >= 0 && slowFrom < 0 &&
			h.AvgMs >= res.Hops[prev].AvgMs+mtrLatencyJumpMs &&
			res.Hops[tail].AvgMs >= res.Hops[prev].AvgMs+mtrLatencyJumpMs {
			slowFrom = i
			setFlag(i, flagSlow)
		}
		prev = i
	}
	if realFrom >= 0 {
		res.StartHop = res.Hops[realFrom].Hop
		res.Code = qualityLoss
	} else if targetOnly {
		res.Code = qualityTargetLoss
	} else if slowFrom >= 0 {
		res.SlowHop = res.Hops[slowFrom].Hop
		res.Code = qualityLatency
	} else if silent {
		// ★ 这一条不给 quality-ok：那一行 100% 丢包的数字还挂在那儿，
		//   顶层却说「好」，人就会不信这一栏。给它一个自己的码，把「看着丢、其实不丢」说破。
		res.Code = qualitySilent
	} else if moved {
		res.Code = qualityPathMoved
	} else if !tailDirty && !res.GoalSeen {
		// 一次都没走到终点、可测的那几跳又不丢：质量没法给结论，
		// 但也不许说「好」—— 终点压根没回答过。
		res.Code = qualityNoResponse
	} else {
		for i := range res.Hops {
			if valid(res.Hops[i]) && res.Hops[i].Flag == "" {
				res.Hops[i].Flag = flagHealthy
			}
		}
		res.Code = qualityOK
	}
}

// mtrSeverity 只干一件事：两族并排时挑出**更该先看**的那一个结论。
// 顺序按「要不要人去干活」排，不按吓人程度排。
var mtrSeverity = map[string]int{
	qualityOK: 0, qualityPathMoved: 1, qualitySilent: 2, qualityLatency: 3,
	traceTimedOut: 3, tlsNameUnresolved: 4, qualityNoResponse: 4,
	qualityTargetLoss: 5, qualityLoss: 6, traceNoRoute: 6,
}

// mtrNoConclusion：这一族压根没测出东西，原因是工具而不是网络。
func mtrNoConclusion(code string) bool {
	return code == traceNoCommand || code == tracePrivileged || code == ots.CodeUnknown
}

// topMtrCode 两族并排时的顶层判定：**谁坏说谁**，但没结论的不算坏。
// 理由和 net.trace 完全一样 —— 不许把「这台机器缺工具」报成「这条路是坏的」，
// 也不许把没测过的那族当成好的。
func topMtrCode(fs []mtrFamily) string {
	if len(fs) == 1 {
		return fs[0].Code
	}
	ran, worst := 0, ""
	for _, f := range fs {
		if mtrNoConclusion(f.Code) {
			continue
		}
		ran++
		if worst == "" || mtrSeverity[f.Code] > mtrSeverity[worst] {
			worst = f.Code
		}
	}
	switch {
	case ran == 0:
		return traceNoCommand
	case ran < len(fs):
		return pathIncomplete
	default:
		return worst
	}
}

// mtrNote 只给码和已经拿到的事实，不拼中文句子。
func mtrNote(code string, fs []mtrFamily) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		s := f.Family + "=" + f.Code +
			" rounds=" + strconv.Itoa(f.RoundsDone) + "/" + strconv.Itoa(f.Rounds)
		if f.StartHop > 0 {
			s += " lossFromHop=" + strconv.Itoa(f.StartHop)
		}
		if f.SlowHop > 0 {
			s += " slowFromHop=" + strconv.Itoa(f.SlowHop)
		}
		if f.Engine != "" {
			s += " engine=" + f.Engine
		}
		parts = append(parts, s)
	}
	return code + " " + strings.Join(parts, " ")
}
