package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.bandwidth.top ──
//
// ★★ 「带宽被谁吃了」在现场有两个人问的东西，而它们不是一个数：
//
//	一个问「这条路满了没有」—— 那要看**网卡**在窗口里过了多少字节；
//	一个问「是谁在吃」—— 那要看**进程**的套接字收发计数。
//	只有把这两份口径一起摆出来，才问得出第三种毛病：
//	网卡上过得很忙、本机进程加起来却对不上 —— 那些包不是这台机器自己要的
//	（它在转发、或者别人正把它当出口打、或者是容器另一个命名空间里的流量）。
//	拿一个数去推另一个数，这三种病会被合并成「没问题」或者「是 XX 进程干的」。
//
// ★★ 两份口径不许相减、也不许换算成百分比：网卡计数器是链路层（含包头、含广播），
//
//	套接字计数是传输层，回环流量一边算一次另一边算两次。所以这里只在**差出一个
//	量级**时下结论（见 bwNotMineFactor），其余情况一律只报数、不报「还剩多少」。
//
// ★ 只给进程名与 PID。★ 不给命令行，也不给对端地址：命令行里常有口令与 token，
//
//	对端地址会把内网结构原样写进一份要发给 AI 的结果里。要更细，人拿 PID 自己去查。

const (
	bwBusy     = "bandwidth-busy"      // 数到了在吃的进程，点名
	bwIdle     = "bandwidth-idle"      // 网卡和进程都没量：此刻不忙
	bwNotMine  = "bandwidth-not-mine"  // 网卡很忙、本机进程对不上 —— 那些包不是这台机器要发的
	bwLinkOnly = "bandwidth-link-only" // 只数得到网卡，数不到进程（平台的本事就到这）
	bwPartial  = "bandwidth-partial"   // 只数到一部分进程，而网卡上的量没人认领 —— 不许说没人吃
	bwNoSource = "bandwidth-no-source" // 连网卡的字节计数都读不到
)

// 进程归属能数到哪一层。★ 三种必须分开：「这个平台压根没这种读法」和
// 「有读法但权限不够只看到一半」下一步完全不同 —— 一个是要不要换工具，
// 一个是要不要用管理员再问一次。
const (
	bwAttribFull = "full"
	bwAttribPart = "partial"
	bwAttribNone = "none"
)

// 网卡按名字分成三类，决定它进不进「出网口总量」。
const (
	bwKindLoopback = "loopback" // 回环：不经过任何网卡，别的机器看不见
	bwKindTunnel   = "tunnel"   // 隧道：同一份包还会从物理口再走一遍，加总就会算两遍
	bwKindLink     = "link"     // 其余（物理口、网桥、虚拟交换机口）
)

// bwQuietBytesPerSec ≈ 1 Mbps 以下算「这一路基本没动」。
//
// ★ 为什么拿 1 Mbps 切：现场来问「谁在吃带宽」的人，卡住时看到的都是几十 Mbps
// 以上；1 Mbps 以下是心跳、DNS、时间同步这一类背景噪音，谁都指不出是它干的。
// 把背景噪音说成「有人在吃」是制造假案，比不说更坏。
const bwQuietBytesPerSec = 125 * 1000

// bwNotMineFactor 网卡过的字节要超过进程总和这么多倍，才敢说「不是这台机器自己要发的」。
//
// ★ 3 倍是刻意的粗：两份口径天然对不齐（见上面那段），差 20% 不是一条结论；
// 只有差出一个量级，才值得让人去查「这台机器是不是被人当网关了」。
const bwNotMineFactor = 3

// bwDefaultWindowSeconds 默认数 3 秒。★ 再短就被背景抖动主导（一两发突发就能
// 把 1 秒的均值抬起来），再长会把「刚才那一下」摊平看不见 —— 所以给人自己调。
const bwDefaultWindowSeconds = 3

const (
	bwMaxWindowSeconds = 30
	bwDefaultTop       = 10
	bwMaxTop           = 50
)

var bandwidthTopTool = ots.Tool{
	Name:  "net.bandwidth.top",
	Class: ots.ClassRead,
	Summary: "看这几十秒里本机带宽被谁吃了：数一会儿（默认 3 秒），同时给出两份口径 —— " +
		"每块网卡在窗口里过了多少（链路层，回答「这条路满没满」）和每个进程收发多少（套接字层，" +
		"回答「是谁在吃」），进程按收发合计排 Top N。★ 顶层判定分六种：bandwidth-busy（点名在吃的进程）、" +
		"bandwidth-idle（网卡和进程都没量）、bandwidth-not-mine（网卡很忙但本机进程对不上，" +
		"说明那些包不是这台机器自己要发的：在转发 / 被人当出口打 / 容器的另一个命名空间）、" +
		"bandwidth-link-only（这个平台只数得到网卡，数不到进程）、bandwidth-partial" +
		"（只数到一部分进程，网卡上的量没人认领，不能当成没人吃）、bandwidth-no-source（连字节计数都读不到）。" +
		"★ 两份口径不相减不换算：网卡含包头与广播、套接字按连接各算，回环两边算法还不同。" +
		"★ 只给进程名与 PID，不给命令行和对端地址。纯读本机计数，不发任何包。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "windowSeconds": {"type": "integer", "minimum": 1, "maximum": 30,
	      "description": "数多长时间，默认 3 秒。★ 要抓「偶尔冒一下」的那股流量就把它调长（10~30 秒），窗口越长越不会被背景抖动骗到，但也会把那一下摊薄。"},
	    "top": {"type": "integer", "minimum": 1, "maximum": 50,
	      "description": "进程列表最多给几条，默认 10。★ 只按收发合计排序，不合并同名进程：同一个软件开了几个进程是常见的，合并就看不出是哪一路。"}
	  }
	}`),
	Invoke: doBandwidthTop,
}

type bandwidthTopArgs struct {
	WindowSeconds int `json:"windowSeconds,omitempty"`
	Top           int `json:"top,omitempty"`
}

// linkCount 一块网卡在某一时刻的累计收发字节（内核计数器原样，还没做差）。
type linkCount struct {
	Name string
	Rx   uint64
	Tx   uint64
}

// procBytes 一个进程在采样窗口里收发的字节。
type procBytes struct {
	Pid     int
	Process string
	Rx      uint64
	Tx      uint64
}

// linkDelta 窗口里这块网卡过了多少。
//
// ★ Reset：两次读数之间计数被清零或者接口被重建（插拔网卡、VPN 重连、虚拟机重启）。
// 这时差值是**假**的，按 0 处理并留这个标记 —— 绝不能让它显示成「这块口一秒没动」。
type linkDelta struct {
	Name  string
	Rx    uint64
	Tx    uint64
	Reset bool
}

// procsRead 的返回：进程字节 + 数到了哪一层 + 只数到这一层的原因 + 在这台机器上
// 要把进程点出来的下一步。
//
// ★ reason 与 next 分开是必要的：「非管理员看不到别人的进程」下一步是提权，
// 「UDP 这一路压根没有字节计数」下一步是抓包 —— 合成一句，人就只会白提一次权。
type procSample struct {
	procs       []procBytes
	attribution string
	reason      string
	next        string
}

// linkRead / procsRead 是本机实际的读法。★ 做成包级变量只有一个理由：判定层要用
// 一段固定的采样结果钉住每一种判定，而不是依赖跑测试这台机器此刻在传什么。
type (
	linkRead  func(ctx context.Context) ([]linkCount, error)
	procsRead func(ctx context.Context, window time.Duration) (procSample, error)
)

var (
	localLink  linkRead  = readLinkCounters
	localProcs procsRead = readProcBytes
	// egressIface 问系统「往外走是哪块网卡」。同样是测试钩子。
	egressIface = defaultEgressIface
)

// errBandwidthSource 这个平台读不到网卡的字节计数时由 OS 层返回。
//
// ★ 判定层按 errors.Is 认，不按错误文本认：靠文字认，改一句文案就让判定悄悄失效。
var errBandwidthSource = errors.New("读不到网卡的字节计数")

func defaultEgressIface() string {
	rs, err := netif.DefaultRoutes()
	if err != nil {
		return ""
	}
	for _, r := range rs { // v4 优先：现场说的「带宽」几乎都是 v4 那条路
		if strings.TrimSpace(r.Iface) != "" && r.Family != "ipv6" {
			return strings.TrimSpace(r.Iface)
		}
	}
	for _, r := range rs {
		if strings.TrimSpace(r.Iface) != "" {
			return strings.TrimSpace(r.Iface)
		}
	}
	return ""
}

func doBandwidthTop(ctx context.Context, raw json.RawMessage) (any, error) {
	var a bandwidthTopArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	// ★ 0 当「没填」：Go 的 int 分不出「没给这个字段」和「给了 0」，而 schema 的
	// minimum 本来就是 1，正经客户端不会给 0。负数不一样 —— 那是明确要一个不可能的
	// 窗口，必须当场拒；悄悄换成默认值会把「参数写错了」演成「这台机器就这样」。
	if a.WindowSeconds < 0 || a.Top < 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"windowSeconds 与 top 都不能是负数（给的是 %d / %d）", a.WindowSeconds, a.Top)
	}
	window := bwDefaultWindowSeconds * time.Second
	if a.WindowSeconds > 0 {
		if a.WindowSeconds > bwMaxWindowSeconds {
			return nil, ots.Errf(ots.ErrInvalidArgument, "windowSeconds 最多 %d 秒（要数更久就分几次问）",
				bwMaxWindowSeconds)
		}
		window = time.Duration(a.WindowSeconds) * time.Second
	}
	top := bwDefaultTop
	if a.Top > 0 {
		if a.Top > bwMaxTop {
			return nil, ots.Errf(ots.ErrInvalidArgument, "top 最多 %d 条（要全盘看就分几次、或者按进程名去问 net.port.process）", bwMaxTop)
		}
		top = a.Top
	}

	// ★ 顺序就是口径：先取网卡计数的起点，再跑那一段窗口（进程的读法自己吃掉
	// 窗口那么久），窗口结束立刻取终点。这样「网卡过了多少」和「进程收发了多少」
	// 落在同一段时间上 —— 错开取，两份数对不上的时候就分不清是转发还是取数取晚了。
	first, err := localLink(ctx)
	if err != nil {
		if errors.Is(err, errBandwidthSource) {
			return ots.Verdict{Code: bwNoSource, Values: map[string]any{
				"reason":    err.Error(),
				"windowSec": int(window / time.Second),
			}, Note: "这台机器上连每块网卡过了多少字节都读不到：" + err.Error() +
				"。★ 这一栏什么都不结论 —— 不是「没人在吃」，是「数不了」。要查请先用系统自带的工具看着。"}, nil
		}
		return nil, err
	}
	t0 := time.Now()
	ps, err := localProcs(ctx, window)
	if err != nil {
		return nil, err
	}
	second, err := localLink(ctx)
	if err != nil {
		return nil, err
	}
	// ★ 折算速率用实测的这段，不用名义窗口：跑一次 netstat 也要几十毫秒，
	// 窗口越短这个差占比越大。两份口径共用同一个分母，它们之间的比较才成立。
	span := time.Since(t0)
	if span <= 0 {
		span = window
	}
	return bandwidthReport(ps, diffLinkCounts(first, second), egressIface(), window, span, top), nil
}

// diffLinkCounts 两次累计计数做一次差，得到窗口里每块网卡过了多少。
//
// ★ 只在后一次不小于前一次时才认这个差：计数被清零（接口重建、机器重启过）时
// 差值会变成一个巨大的正数或者绕回的负数，两种都会把「数错了」演成「有人在猛吃」。
func diffLinkCounts(first, second []linkCount) []linkDelta {
	before := make(map[string]linkCount, len(first))
	for _, c := range first {
		before[c.Name] = c
	}
	var out []linkDelta
	for _, c := range second {
		b, ok := before[c.Name]
		d := linkDelta{Name: c.Name}
		switch {
		case !ok:
			d.Reset = true // 窗口中途才出现的口（VPN 刚连上、网卡刚插上）：这一段没法算
		case c.Rx < b.Rx || c.Tx < b.Tx:
			d.Reset = true
		default:
			d.Rx, d.Tx = c.Rx-b.Rx, c.Tx-b.Tx
		}
		out = append(out, d)
	}
	for _, c := range first { // 窗口中途消失的口：留下名字，别说成「它一秒没动」
		if _, ok := findDelta(out, c.Name); !ok {
			out = append(out, linkDelta{Name: c.Name, Reset: true})
		}
	}
	return out
}

func findDelta(ds []linkDelta, name string) (linkDelta, bool) {
	for _, d := range ds {
		if d.Name == name {
			return d, true
		}
	}
	return linkDelta{}, false
}

// bandwidthReport 判定层。★ 输入是两次采样的结果而不是真机器，所以六种判定
// 在任何一台机器上都能各测一遍 —— 否则跨平台那三种永远只在对应平台上才走得到。
// window 是人要的那段，span 是实际量到的那段：折算速率只用 span，
// 窗口那一栏给名义值 —— 读得快的时候 span 只有几毫秒，拿它当窗口会算出天文数字。
func bandwidthReport(ps procSample, deltas []linkDelta, egress string, window, span time.Duration, top int) ots.Verdict {
	secs := span.Seconds()
	if secs <= 0 {
		secs = window.Seconds()
	}
	if secs <= 0 {
		secs = 1
	}
	ifaceRows := make([]map[string]any, 0, len(deltas))
	type ifaceAgg struct {
		row    map[string]any
		total  uint64
		counts bool // 进不进「出网侧总量」
	}
	aggs := make([]ifaceAgg, 0, len(deltas))
	var linkRx, linkTx uint64 // 出网侧总量（不含回环、不含隧道）
	var loopRx, loopTx uint64
	var tunRx, tunTx uint64
	var tunnelNames, loopNames []string
	for _, d := range deltas {
		kind := bwLinkKind(d.Name)
		if d.Reset {
			kind = "unreadable" // ★ 在表里点名，不让它躲在「这个口没过东西」后面
		}
		counts := !d.Reset && kind != bwKindLoopback && kind != bwKindTunnel
		row := map[string]any{
			"name": d.Name, "kind": kind, "counts": counts,
			"rxBytes": d.Rx, "txBytes": d.Tx,
			"rxMbps": round4(toMbps(d.Rx, secs)), "txMbps": round4(toMbps(d.Tx, secs)),
		}
		// ★ 「是不是出口」这一标记在后面按 anchor 统一打，这里只按种类归账：
		// 系统说出口是 lo0 的机器也有（某些容器里默认路由指向回环），
		// 那种时候回环的量还是得单独列出来，不能因为被当成了出口就从表里蒸发。
		switch {
		case d.Reset:
		case kind == bwKindLoopback:
			loopRx, loopTx = loopRx+d.Rx, loopTx+d.Tx
			loopNames = append(loopNames, d.Name)
		case kind == bwKindTunnel:
			tunRx, tunTx = tunRx+d.Rx, tunTx+d.Tx
			tunnelNames = append(tunnelNames, d.Name)
		}
		if counts {
			linkRx, linkTx = linkRx+d.Rx, linkTx+d.Tx
		}
		aggs = append(aggs, ifaceAgg{row: row, total: d.Rx + d.Tx, counts: counts})
	}
	sort.SliceStable(aggs, func(i, j int) bool {
		if aggs[i].total != aggs[j].total {
			return aggs[i].total > aggs[j].total
		}
		return aggs[i].row["name"].(string) < aggs[j].row["name"].(string)
	})
	anchor := egress
	if !countsInLink(deltas, egress) { // 没有默认路由、或者那块口这一段读不到 → 换成最忙的那块出网口
		anchor = ""
		for _, a := range aggs { // aggs 已按字节数从大到小排好，第一个进总量的口就是最忙的
			if a.counts {
				anchor = a.row["name"].(string)
				break
			}
		}
		if anchor == "" {
			anchor = egress // 一块出网口都没认出来：至少把人问的那块留在结论里，别空着
		}
	}
	for _, a := range aggs {
		// ★ 表里标的是**这一栏实际按哪块口算的**，不是系统说出口是哪块：
		// 两者不一致时（没有默认路由、或者出口那块口这一段被清零了），
		// 界面拿这个名字去指行，指着的必须就是算进结论的那一行。
		name, _ := a.row["name"].(string)
		if name == anchor {
			a.row["egress"] = true
		}
		if name == egress && egress != anchor {
			a.row["defaultRoute"] = true
		}
		ifaceRows = append(ifaceRows, a.row)
	}

	procs := append([]procBytes(nil), ps.procs...)
	sort.SliceStable(procs, func(i, j int) bool {
		if procs[i].Rx+procs[i].Tx != procs[j].Rx+procs[j].Tx {
			return procs[i].Rx+procs[i].Tx > procs[j].Rx+procs[j].Tx
		}
		return procs[i].Process < procs[j].Process
	})
	var procRx, procTx uint64
	for _, p := range procs {
		procRx += p.Rx
		procTx += p.Tx
	}
	rows := make([]map[string]any, 0, len(procs))
	for _, p := range procs {
		rows = append(rows, map[string]any{
			"process": p.Process, "pid": p.Pid,
			"rxBytes": p.Rx, "txBytes": p.Tx,
			"rxMbps": round4(toMbps(p.Rx, secs)), "txMbps": round4(toMbps(p.Tx, secs)),
		})
	}
	truncated := len(rows) > top
	if truncated {
		rows = rows[:top]
	}

	linkBps := bytesPerSec(linkRx+linkTx, secs)
	procBps := bytesPerSec(procRx+procTx, secs)
	linkBusy := linkBps >= bwQuietBytesPerSec
	procBusy := procBps >= bwQuietBytesPerSec
	if ps.attribution == "" {
		ps.attribution = bwAttribNone
	}

	code := pickBandwidthVerdict(ps.attribution, procBusy, linkBusy, linkRx+linkTx, procRx+procTx)

	values := map[string]any{
		"windowSec":           int(window / time.Second),
		"measuredMs":          span.Milliseconds(),
		"attribution":         ps.attribution,
		"interfaces":          ifaceRows,
		"egress":              anchor,
		"linkRxMbps":          round4(toMbps(linkRx, secs)),
		"linkTxMbps":          round4(toMbps(linkTx, secs)),
		"linkTotalBytes":      linkRx + linkTx,
		"processTotalBytes":   procRx + procTx,
		"processRxMbps":       round4(toMbps(procRx, secs)),
		"processTxMbps":       round4(toMbps(procTx, secs)),
		"processes":           rows,
		"processCount":        len(procs),
		"processCountShown":   len(rows),
		"truncated":           truncated,
		"loopbackTotalBytes":  loopRx + loopTx,
		"tunnelTotalBytes":    tunRx + tunTx,
		"loopbackInterfaces":  loopNames,
		"tunnelInterfaces":    tunnelNames,
		"quietBytesPerSecond": bwQuietBytesPerSec,
	}
	if ps.reason != "" {
		values["attributionNote"] = ps.reason
	}
	if ps.next != "" {
		values["attributionNext"] = ps.next
	}
	return ots.Verdict{Code: code, Values: values, Note: bandwidthNote(code, rows, values, ps, anchor, window)}
}

// pickBandwidthVerdict 六种判定的先后。★ 顺序是有讲究的：先问「能不能数」，
// 再问「数到了谁」，最后才问「数到的这些对不对得上网卡的量」——
// 反过来就会把「这个平台数不到进程」说成「没人吃」。
func pickBandwidthVerdict(attribution string, procBusy, linkBusy bool, linkBytes, procBytesTotal uint64) string {
	switch {
	case attribution == bwAttribNone:
		return bwLinkOnly
	case procBusy:
		return bwBusy
	case !linkBusy:
		// 网卡也没什么量：这时候「没人在吃」问得出来，而且不用管进程看不看得全 ——
		// 出网口自己就没过东西，别人家的进程再怎么藏也变不出字节来。
		return bwIdle
	case attribution == bwAttribPart:
		// ★ 关键的一档：网卡在动、看得见的那些不动。这时说「没人吃」是把
		// 「我看不见」当成「没有」，正是现场最容易被带走的一次。
		return bwPartial
	case linkBytes >= bwNotMineFactor*procBytesTotal:
		return bwNotMine
	default:
		// 网卡有量、进程这边也有量但没到「忙」的刻度：能点名，就按点名报。
		return bwBusy
	}
}

// countsInLink 这块口进不进「出网侧总量」，也就是它读得到、又不是回环或隧道。
func countsInLink(deltas []linkDelta, name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	for _, d := range deltas {
		if d.Name != name {
			continue
		}
		k := bwLinkKind(d.Name)
		return !d.Reset && k != bwKindLoopback && k != bwKindTunnel
	}
	return false
}

// bandwidthNote 每种判定都要留一句「这两个数不是一个口径，别相减」，
// 因为界面上一眼看到的两个 Mbps 太容易被读成「还剩多少」。
func bandwidthNote(code string, rows []map[string]any, values map[string]any, ps procSample, anchor string, window time.Duration) string {
	who := func() string {
		if len(rows) == 0 {
			return "一个都没有"
		}
		p, _ := rows[0]["process"].(string)
		pid, _ := rows[0]["pid"].(int)
		return fmt.Sprintf("%s（PID %d，下 %s Mbps / 上 %s Mbps）", p, pid,
			mbpsText(rows[0], "rxMbps"), mbpsText(rows[0], "txMbps"))
	}
	win := humanDur(window) // ★ 说的是人要的那段，不是实测的那点零头
	link := fmt.Sprintf("%s / %s Mbps", mbpsText(values, "linkRxMbps"), mbpsText(values, "linkTxMbps"))
	procTotal := strconv.FormatUint(orZeroU(values["processTotalBytes"]), 10)
	where := strings.TrimSpace(anchor)
	if where == "" {
		where = "（认不出哪块是出网口，按所有非回环非隧道口合计算）"
	}
	switch code {
	case bwBusy:
		n := "这 " + win + "里本机收发最多的是 " + who() +
			"。★ 进程那一栏是套接字口径（这个进程自己收发了多少），网卡那一栏是链路口径" +
			"（这块口过了多少，含包头与广播），两个数不相减也不换算成百分比 —— " +
			"要判断「链路被吃满没有」看网卡那栏对上下行速率，要判断「该停谁」看进程那栏。"
		if ps.attribution == bwAttribPart {
			n += "另外这次只数到一部分进程（" + ps.reason + "）：排在前面的这些确实在吃，" +
				"但「最忙的就是它」这句在别的机器上不一定成立。"
		}
		return n
	case bwIdle:
		return "这 " + win + "里本机进程加起来才 " + procTotal + " 字节，出网口 " + where +
			" 上下行 " + link + " —— 现在没有任何东西在吃带宽。" +
			"★ 这只说明这一段：那次「卡一下」如果不是这会儿发生的，这一栏推不出当时也不忙。" +
			"要抓偶发的那一下，把窗口调到 10~30 秒再问，或者用 net.quality.watch 长期留痕。"
	case bwNotMine:
		return "出网口 " + where + " 这 " + win + "过了 " + link +
			"，而本机所有进程加起来只有 " + procTotal + " 字节 —— 差出一个量级，" +
			"这些包不是这台机器自己要发的。★ 三种可能，逐个排：这台机器在给别人转发" +
			"（开了共享上网 / NAT / 桥接）、别人正往它身上打（广播风暴或攻击）、" +
			"或者是另一个网络命名空间里的流量（容器、虚拟机自己的桥）。" +
			"下一步不在「本机哪个进程」上，先问「谁在借这台机器走」（net.routes 看路由，net.interfaces 看口）。"
	case bwLinkOnly:
		return "这台机器只数得到网卡过了多少（出网口 " + where + " 上下行 " + link +
			"），数不到是哪个进程在吃" + reasonOf(ps.reason) + "。★ 数不到不等于没人在吃，" +
			"这一栏不许读成「没问题」。" + nextOf(ps.next)
	case bwPartial:
		return "只数到一部分进程的字节" + reasonOf(ps.reason) + "，数到的这些都不忙，" +
			"可出网口 " + where + " 这 " + win + "实实在在过了 " + link +
			"。★ 这栏不能读成「没人吃」：看不见的那些里才可能藏着主角。" + nextOf(ps.next)
	}
	return ""
}

func nextOf(next string) string {
	if strings.TrimSpace(next) == "" {
		return ""
	}
	return "下一步：" + strings.TrimSpace(next) + "。"
}

func mbpsText(m map[string]any, key string) string {
	f, _ := m[key].(float64)
	return strconv.FormatFloat(f, 'f', 2, 64)
}

func orZeroU(v any) uint64 {
	n, _ := v.(uint64)
	return n
}

func reasonOf(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	return "：" + strings.TrimSpace(reason)
}

// bwLinkKind 只看名字。★ 为什么不看 IFF_LOOPBACK 之类的标志位：三个平台把标志
// 传出来的形式全不一样（netstat 用名字后缀、/proc 只有名字、Windows 给别名），
// 而这三家的回环口反倒都认得出「lo/loopback」这个词。
//
// ★★ Windows 的口名是给人看的整句话（"Loopback Pseudo-Interface 1"、
//
//	"Teredo Tunneling Pseudo-Interface"），只按前缀匹配会把它们当成普通网卡 ——
//	回环那一份被加进出网总量，「本机没在吃」就成了「不知道谁在吃」，
//	而 Teredo/ISATAP 的包本来就是套在真网卡上发的，加了就是双倍。
//	所以短名按前缀（unix 的 lo/tun/wg…），这类长别名按词匹配。
func bwLinkKind(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	base := strings.TrimRight(n, "0123456789")
	switch base {
	case "lo", "loop":
		return bwKindLoopback
	case "utun", "tun", "ppp", "ipsec", "wg", "gif", "stf", "gre", "gretap", "ipip", "sit", "vti", "ip_vti", "tunl", "ip6tnl", "ip_gre", "ipip6":
		return bwKindTunnel
	}
	if strings.Contains(n, "loopback") {
		return bwKindLoopback
	}
	for _, w := range []string{"teredo", "isatap", "tunnel", "pseudo-interface", "wan miniport"} {
		if strings.Contains(n, w) {
			return bwKindTunnel
		}
	}
	if strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "docker") {
		return bwKindLink // 容器口子不算隧道：它自己就是那份流量的终点，不会重复计一遍
	}
	return bwKindLink
}

// bytesPerSec 窗口里的平均每秒字节数 —— 判定用它的量（安静线就是按字节/秒定的）。
func bytesPerSec(n uint64, secs float64) float64 {
	if secs <= 0 {
		return 0
	}
	return float64(n) / secs
}

// toMbps 同样这段窗口的速率换成 Mbps，给界面和 AI 看。
//
// ★ 和 bytesPerSec 分开写而不是就地乘 8：判定线是按字节/秒定的，界面按 Mbps 说人话，
//
//	两处共用一个乘算最容易哪天把 1e6 漏在一边 —— 漏了就是「1 秒差 100 万倍」那种错。
func toMbps(n uint64, secs float64) float64 {
	return bytesPerSec(n, secs) * 8 / 1e6
}
