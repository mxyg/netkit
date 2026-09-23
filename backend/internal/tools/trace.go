package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// net.trace —— 路径追踪：到不到得了，以及**走到第几跳停的、停在哪台设备上**。
//
// ★★ 和双栈体检是两件互补的事：体检答「这一族出不出得了外网」，
//
//	追踪答「出得去的话路有多长、断在哪一跳」。现场拿到「上不去」之后，
//	下一步问的几乎都是这个。
//
// ★ 为什么调系统命令、不自己发 TTL 递增的包：要拿到**中间路由器回给你的 ICMP 超时**
//
//	（这才叫得出"第几跳是谁"），得能读原始套接字 —— 那要 root。
//	非特权套接字只能知道「报错了」，不知道是谁报的，等于没有路径。
//	所以这里做的是解析与判定，不重造发包器；用哪条命令如实写进结果（engine 字段），
//	换一台没装 traceroute 的精简 Linux，结论的可信度不一样，这点不许藏。
var traceTool = ots.Tool{
	Name:  "net.trace",
	Class: ots.ClassRead,
	Summary: "追踪到目标走的路径，逐跳给出地址与往返时间。★ 默认 IPv4、IPv6 **各追一遍并排给结果**（不是二选一）：" +
		"现场最常见正是「一族到、另一族断在半路」。判定区分 到达终点 / 断在中间某跳 / " +
		"第一跳就没回应（说不清断没断，多半是 ICMP 被限速）/ 跳数用尽 / 本机这一族压根没路由。" +
		"★ 中途个别跳不回是常态，不会据此说断在那里。属于只读。",
	Schema: json.RawMessage(`{
		  "type": "object",
		  "additionalProperties": false,
		  "required": ["host"],
		  "properties": {
		    "host": {"type": "string",
		      "description": "目标：域名或 IP。填域名时按各族自己的记录追。"},
		    "family": {"type": "string", "enum": ["auto", "v4", "v6"],
		      "description": "默认 auto：两族都追（目标只有一种记录时只追那一种）。"},
		    "maxHops": {"type": "integer", "minimum": 1, "maximum": 40,
		      "description": "最多追几跳，默认 30。"},
		    "perHop": {"type": "integer", "minimum": 1, "maximum": 5,
		      "description": "每跳发几个探测，默认 1（快）。要看抖动或丢包再调大。"},
		    "timeoutMs": {"type": "integer", "minimum": 2000, "maximum": 180000,
		      "description": "整条追踪（含两族）最多花多久，默认 60000。超时会把已经走到的跳带回来。"}
		  }
		}`),
	Invoke: doTrace,
}

// 路径追踪的判定码。★ 全部是**观察到的状态**，不是工具失败（[OTS-6.2]）。
const (
	traceReached    = "reached"         // 走到了目标
	traceStalled    = "stalled"         // 后面全无回应，最后一跳有回应
	traceNoResponse = "no-response"     // 连第一跳都没回：说不通路断没断
	traceMaxHops    = "max-hops"        // 一路都有回应但跳数用完 —— 加大 maxHops 再看
	traceNoRoute    = "no-route"        // 本机这一族没有去目标的路由（v6 被关的招牌表现）
	traceNoCommand  = "no-command"      // 这台机器上没有可用的追踪命令
	tracePrivileged = "needs-privilege" // 命令要 root/管理员，非特权跑不动
	traceTimedOut   = "trace-timeout"

	pathOK      = "path-ok"      // 顶层：跑到结论的族**全部**到终点
	pathPartial = "path-partial" // 顶层：一族到、另一族确定没到 —— 双栈现场最常见
	pathBroken  = "path-broken"  // 顶层：没有一族到，且至少一族确定断在半路/没路
	// pathIncomplete：结论不完整。两种来源：有一族**没跑成**（缺命令 / 要权限），
	// 或跑成了但**谁都没给出结论**（跳数用完、第一跳就不回、整条超时）。
	// ★ 不许把「这台机器缺工具 / 这次没看出来」报成「这条路是坏的」，
	//   也不许反过来报成「这条路是好的」—— 那是两种完全不同的活。
	pathIncomplete = "path-incomplete"
)

type traceArgs struct {
	Host      string `json:"host"`
	Family    string `json:"family,omitempty"`
	MaxHops   int    `json:"maxHops,omitempty"`
	PerHop    int    `json:"perHop,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// traceHop 是一跳。★ 回的时间与丢的个数分开记：只报「回了的那几个」，
// 人看不出这一跳其实三个探测里丢了两个。
type traceHop struct {
	Hop    int       `json:"hop"`
	Addr   string    `json:"addr,omitempty"` // 空 = 这一跳一个都没回
	RTTMs  []float64 `json:"rttMs,omitempty"`
	Lost   int       `json:"lost,omitempty"`
	Mark   string    `json:"mark,omitempty"` // traceroute 的 `!X`/`!H` 一类附注
	IsGoal bool      `json:"isGoal,omitempty"`
}

// mergeHops 按跳号合并。
//
// ★ tracepath 会把本机那一跳印两遍（`1?: [LOCALHOST] pmtu 1500` 和 `1:  192.168.1.1`），
//
//	不合并的话「第一跳没回」会被那条说明行冒充 —— 判成 no-response。
func mergeHops(in []traceHop) []traceHop {
	byNo := map[int]*traceHop{}
	var order []int
	for _, h := range in {
		cur, ok := byNo[h.Hop]
		if !ok {
			cp := h
			cp.RTTMs = append([]float64(nil), h.RTTMs...)
			byNo[h.Hop] = &cp
			order = append(order, h.Hop)
			continue
		}
		if cur.Addr == "" {
			cur.Addr = h.Addr
		}
		cur.RTTMs = append(cur.RTTMs, h.RTTMs...)
		cur.Lost += h.Lost
		if cur.Mark == "" {
			cur.Mark = h.Mark
		}
	}
	out := make([]traceHop, 0, len(order))
	for _, n := range order {
		out = append(out, *byNo[n])
	}
	return out
}

// traceFamily 是**一个地址族**的结果。两族并排，不合并且不互相污染。
type traceFamily struct {
	Family   string     `json:"family"` // ipv4 / ipv6
	Code     string     `json:"code"`
	Goals    []string   `json:"goals,omitempty"` // 目标这一族的地址（判断到没到终点依据它）
	Hops     []traceHop `json:"hops,omitempty"`
	HopsSeen int        `json:"hopsSeen"` // 有回应的最大跳号
	LastAddr string     `json:"lastAddr,omitempty"`
	Command  string     `json:"command,omitempty"` // ★ 用的哪条命令，如实写
	Tried    string     `json:"tried,omitempty"`   // 试过的命令各自的报错
	Detail   string     `json:"detail,omitempty"`  // 命令自己吐的、认不出来的原文
	Partial  bool       `json:"partial,omitempty"` // 超时截断，跳数不全
}

func doTrace(ctx context.Context, raw json.RawMessage) (any, error) {
	var a traceArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	host := strings.TrimSpace(a.Host)
	if host == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给目标地址")
	}
	// ★★ 目标要作为参数交给外部命令，所以不许以 - 开头、不许带空白：
	// 否则 `-f`、`--back` 这种会被 traceroute 当成自己的选项吃掉 —— 参数注入。
	// 域名和 IP 本来都不含空白，这里拒掉的没有一个是正常输入。
	if strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n") {
		return nil, ots.Errf(ots.ErrInvalidArgument, "目标写法不对（不能有空白，也不能以 - 开头）")
	}
	maxHops := a.MaxHops
	if maxHops == 0 {
		maxHops = 30
	}
	perHop := a.PerHop
	if perHop == 0 {
		perHop = 1
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
	// 先定目标各族的地址：填 IP 就直接用，填域名就查一次。
	// ★ 只有一种记录的目标只追那一种 —— 给只有 A 记录的域名追 v6，
	//   拿回来的 no-route 会被误读成「v6 坏了」，而它压根没被要求过有 v6。
	goals, families, early := traceTargets(ctx, host, want)
	if early != nil {
		return *early, nil
	}

	// 两族分预算：否则 v6 卡满 60s，v4 一行结果都没有，而「v6 卡住」正是这里要查的东西。
	budget := timeout / time.Duration(len(families))
	if budget < 3*time.Second {
		budget = timeout
	}
	out := make([]traceFamily, 0, len(families))
	for _, fam := range families {
		fctx, cancel := context.WithTimeout(ctx, budget)
		r := runTrace(fctx, host, fam, goals[fam], maxHops, perHop)
		cancel()
		out = append(out, r)
	}

	values := map[string]any{
		"host":     host,
		"traces":   out,
		"engine":   traceEngineName(runtime.GOOS),
		"families": families,
	}
	code := topTraceCode(out)
	return ots.Verdict{Code: code, Values: values, Note: traceNote(code, out)}, nil
}

// traceTargets 定「目标各族有哪些地址」和「这一次要跑哪几族」。
// ★ 路径追踪和持续路径质量必须共用这一段：两处各写一遍的话，
//
//	迟早有一处会偷偷改变「域名只有一种记录时跑不跑另一族」的规矩 ——
//	那正是「v6 到底测没测」这个问题的答案。
//
// 第三个返回值非空时，调用方直接把它当结果返回（解析不到、指定的族没记录）。
func traceTargets(ctx context.Context, host, want string) (map[string][]netaddr.Addr, []string, *ots.Verdict) {
	goals := map[string][]netaddr.Addr{}
	if ip, err := netip.ParseAddr(host); err == nil {
		fam := "v4"
		if !ip.Is4() {
			fam = "v6"
		}
		goals[fam] = []netaddr.Addr{{IP: ip}}
	} else {
		all, why := resolveTLSHost(ctx, host)
		if len(all) == 0 {
			return nil, nil, &ots.Verdict{Code: tlsNameUnresolved, Values: map[string]any{"host": host},
				Note: host + " 解析不到地址，还没到追路径这一步" + whyOf(why)}
		}
		for _, x := range all {
			fam := "v4"
			if !x.IP.Is4() {
				fam = "v6"
			}
			goals[fam] = append(goals[fam], x)
		}
	}
	families := []string{}
	for _, fam := range []string{"v4", "v6"} {
		if want != "auto" && want != fam {
			continue
		}
		if len(goals[fam]) > 0 {
			families = append(families, fam)
		}
	}
	if len(families) == 0 {
		// 指定了这一族但目标没这一族的记录：如实说，不偷偷改成一族去追
		return nil, nil, &ots.Verdict{Code: tlsNameUnresolved,
			Values: map[string]any{"host": host, "askedFamily": want},
			Note:   host + " 没有 " + want + " 记录，追不了这一族"}
	}
	return goals, families, nil
}

func whyOf(s string) string {
	if s == "" {
		return ""
	}
	return "（" + s + "）"
}

// traceEngineName 说清楚用的是系统里现成的哪个命令。
func traceEngineName(goos string) string {
	if goos == "windows" {
		return "tracert"
	}
	return "traceroute（没有则退到 tracepath）"
}

// traceCommands 给出本平台这一族要试的命令，按优先级排。
//
// 纯函数（goos 作参数），这样三个平台的分支在 mac 上也测得到。
func traceCommands(goos, family string, maxHops, perHop int, host string) [][]string {
	v6 := family == "v6"
	if goos == "windows" {
		// ★ -d：不把地址反解成域名。反解既慢又会超时，而超时的字样是**本地化**的
		//   （中文系统「请求超时。」），没法拿去解析 —— 只认地址和 * 两种形状。
		fam := "-4"
		if v6 {
			fam = "-6"
		}
		return [][]string{{"tracert", "-d", fam, "-h", strconv.Itoa(maxHops), "-w", "1000", host}}
	}
	var v6flag []string
	if v6 {
		v6flag = []string{"-6"}
	}
	tp := "tracepath"
	if v6 {
		tp = "tracepath6"
	}
	// ★ macOS/BSD 的 v6 是**另一个程序**：`traceroute` 不认 -6（打一行用法就退出），
	//   有单独的 `traceroute6`。Linux 的 traceroute 认 -6。
	//   不区分的表现是「v6 什么跳都没有」，看着像这条路是空的，其实是命令用错了 ——
	//   真机第一次跑双栈就撞上这个。
	name := "traceroute"
	if v6 && goos == "darwin" {
		name, v6flag = "traceroute6", nil
	}
	// traceroute 在前：它三个平台的输出形状最接近，且 -q 能控制每跳探测数。
	return [][]string{
		append([]string{name, "-n", "-m", strconv.Itoa(maxHops), "-q", strconv.Itoa(perHop)},
			append(v6flag, host)...),
		{tp, "-n", "-l", strconv.Itoa(maxHops), host},
	}
}

// runTrace 跑一族。命令本身跑不起来（没装、要 root）也是**判定**，不是错误。
func runTrace(ctx context.Context, host, family string, goals []netaddr.Addr, maxHops, perHop int) traceFamily {
	res := traceFamily{Family: "ipv" + strings.TrimPrefix(family, "v")}
	want := make([]string, 0, len(goals))
	for _, g := range goals {
		want = append(want, g.String())
	}
	res.Goals = want

	cmds := traceCommands(runtime.GOOS, family, maxHops, perHop, host)
	var tried []string
	for _, argv := range cmds {
		if _, err := exec.LookPath(argv[0]); err != nil {
			tried = append(tried, argv[0]+" 不在机器上")
			continue
		}
		var so, se bytes.Buffer
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		// ★ 超时被杀也要解析：已经走到的那几跳在缓冲区里，扔掉就等于把线索丢了
		res.Partial = errors.Is(ctx.Err(), context.DeadlineExceeded)
		text := so.String() + "\n" + se.String()
		res.Command = strings.Join(argv, " ")
		hops := parseTraceOutput(text, argv[0])
		if code, detail := classifyTraceRun(ctx, err, text); code != "" && len(hops) == 0 {
			res.Code, res.Detail = code, detail
			if res.Detail == "" {
				res.Detail = firstTraceLine(text)
			}
			res.Tried = strings.Join(tried, "；")
			return res
		}
		// 产不出跳就试退路。★ 每条命令各自的报错都要留着：只留最后一条的话，
		// 「traceroute 用法不对 + tracepath 没装」会报成「tracepath 不在机器上」，
		// 而真正的原因是前者 —— 现场看到的是「明明装了却说没有」。
		if len(hops) == 0 && !res.Partial {
			tried = append(tried, strings.Join(argv, " ")+"："+firstTraceLine(text))
			continue
		}
		res.Tried = strings.Join(tried, "；")
		judgeTrace(&res, hops, want, maxHops)
		return res
	}
	// 两条命令都不行：没装 / 跑不出东西。★ 这是**工具跑不了**，不是「路上没设备」——
	// 混起来的后果是让人去查一条根本没坏的路，而真实情况只是这台机器缺命令。
	if res.Code == "" {
		res.Code = traceNoCommand
		res.Detail = strings.Join(tried, "；")
	}
	return res
}

// classifyTraceRun 认「命令压根没跑出路径」的几种情况。认不出来回空串。
//
// ★★ 「No route to host」和「Operation not permitted」必须分开：前者是**本机这一族没路**
//
//	（v6 被关了，是现场要的那个结论），后者是权限不够（结论是「换台机器或加权限」）。
//	混成一类的代价是人去改网络设置，而真正的事是没给权限。
func classifyTraceRun(ctx context.Context, err error, text string) (string, string) {
	s := strings.ToLower(text)
	switch {
	case strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"),
		strings.Contains(s, "no route to destination"), strings.Contains(s, "general failure"):
		return traceNoRoute, "本机这一族没有通向目标的路由：先确认网卡上有没有这一族的地址、有没有默认路由"
	case strings.Contains(s, "operation not permitted"), strings.Contains(s, "permission denied"),
		strings.Contains(s, "cap_net_raw"):
		return tracePrivileged, "追踪要发原始探测包，这条命令在这台机器上要 root/管理员权限 —— 换 tracepath，或提权再跑"
	case strings.Contains(s, "cannot assign requested address"):
		return traceNoRoute, "本机没有这一族的地址，发不出去"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return traceTimedOut, "整条追踪超时 —— 已经走到的跳见 hops"
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "no such host") {
		return tlsNameUnresolved, ""
	}
	return "", ""
}

func firstTraceLine(text string) string {
	for _, ln := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return ""
}

// judgeTrace 从跳表里出判定。
func judgeTrace(res *traceFamily, hops []traceHop, goals []string, maxHops int) {
	res.Hops = hops
	goal := map[string]bool{}
	for _, g := range goals {
		goal[g] = true
	}
	last := -1
	reached := false
	for i := range hops {
		if hops[i].Addr == "" {
			continue
		}
		last = i
		if goal[hops[i].Addr] {
			hops[i].IsGoal = true
			reached = true
		}
	}
	if last >= 0 {
		res.HopsSeen = hops[last].Hop
		res.LastAddr = hops[last].Addr
	}
	switch {
	case reached:
		res.Code = traceReached
	case last < 0:
		// 一个回应都没有：这条路**说不清**。第一跳（通常是家用路由器）就不回 ICMP 超时的情况很常见，
		// 这时候目标可能是好的 —— 拿它当「断在第一跳」会让人去查一个没坏的设备。
		res.Code = traceNoResponse
	case res.Partial:
		// 被超时截断 —— 不能说「跳数用完」，那是让人去调大 maxHops，而该调的是超时
		res.Code = traceTimedOut
	case res.HopsSeen >= maxHops:
		// 一路都有回应、只是跳数用完：不能算断。★ 这条单独给码，因为它要的动作是「把 maxHops 调大」
		res.Code = traceMaxHops
	default:
		res.Code = traceStalled
	}
}

// parseTraceOutput 按命令认输出形状。tracert 和 traceroute 的行都带跳号，
// tracepath 的形完全不同（`1:  地址  0.512ms`），所以分开解析。
func parseTraceOutput(out, cmdName string) []traceHop {
	if strings.Contains(cmdName, "tracepath") {
		return parseTracepath(out)
	}
	// BSD/Linux traceroute 与 Windows tracert 在这一行上够像：跳号打头，
	// 中间是若干个 `N ms` 或 `*`，地址在行里任意位置 —— 一套切法两用。
	return parseNumberedHops(out)
}

// parseNumberedHops 解析 `1  192.168.1.1  2.69 ms`、`4  *`、
// `  8     *        *     <1 ms  10.0.0.1` 这些形状。
//
// ★ 地址用 netip.ParseAddr 认，不用正则：v6 的地址里带冒号，
//
//	而 traceroute 会在同一个位置写 `1.2.3.4 (host.name)`、`<1 ms`、`ms` 等 token，
//	正则很容易把 `fe80::1%eth0` 这类切一半。认不出地址的行就整行跳过 ——
//	头部说明行（`traceroute to ...`）和空行都是这么被滤掉的。
func parseNumberedHops(out string) []traceHop {
	var hops []traceHop
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimRight(f[0], ".:"))
		if err != nil || n <= 0 {
			continue
		}
		h := traceHop{Hop: n}
		for i := 1; i < len(f); i++ {
			tok := f[i]
			if tok == "*" {
				h.Lost++
				continue
			}
			if a, err := netip.ParseAddr(trimZone(strings.Trim(tok, "()"))); err == nil {
				if h.Addr == "" {
					h.Addr = a.String()
				}
				continue
			}
			// `<1 ms`、`0.512` + `ms`：数值在前一个 token 里
			if tok == "ms" && i > 0 {
				continue
			}
			if ms, ok := parseTraceMs(tok); ok {
				h.RTTMs = append(h.RTTMs, ms)
				if i+1 < len(f) && f[i+1] == "ms" {
					i++
				}
				continue
			}
			// `!X`（禁止转发）、`!H`（禁止主机）这类附注：traceroute 用它说
			// 「这一跳明确拒了」，和「这一跳没回」是两件事，丢掉就分不开了。
			if strings.HasPrefix(tok, "!") && h.Mark == "" {
				h.Mark = tok
			}
		}
		hops = append(hops, h)
	}
	return hops
}

// trimZone 去掉 `fe80::1%en0` 里的 %en0。
//
// ★ zone 是本机网卡名，每台不一样；留着它，「这一跳是不是目标」的字符串比对
//
//	永远对不上 —— 目标是 `fe80::1`，跳上写的是 `fe80::1%en0`，到了终点也报没到。
func trimZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

// parseTraceMs 认 `2.69`、`<1`、`0.512ms` 三种写法。
//
// ★ `<1` 是 macOS/Windows 对亚毫秒的写法（不是坏数据），按 0.5 记 ——
//
//	界面只关心量级，不许因为它不是数字就把这一跳丢掉。
func parseTraceMs(tok string) (float64, bool) {
	tok = strings.TrimSuffix(tok, "ms")
	if v, err := strconv.ParseFloat(tok, 64); err == nil {
		return v, true
	}
	if strings.HasPrefix(tok, "<") {
		if v, err := strconv.ParseFloat(strings.TrimPrefix(tok, "<"), 64); err == nil {
			return v / 2, true
		}
	}
	return 0, false
}

// parseTracepath 解析 Linux tracepath 的输出：
//
//	1?: [LOCALHOST]                      pmtu 1500
//	1:  192.168.1.1         	0.512ms
//	8:  8.8.8.8             	55.581ms reached
//
// 它的跳号在冒号左边，地址在冒号右边第一个能 parse 成地址的 token 上。
func parseTracepath(out string) []traceHop {
	var hops []traceHop
	for _, ln := range strings.Split(out, "\n") {
		left, right, found := strings.Cut(ln, ":")
		if !found {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(left), "?")))
		if err != nil || n <= 0 {
			continue
		}
		h := traceHop{Hop: n}
		f := strings.Fields(right)
		for _, tok := range f {
			if a, err := netip.ParseAddr(trimZone(strings.Trim(tok, "[]"))); err == nil {
				if h.Addr == "" {
					h.Addr = a.String()
				}
				continue
			}
			if ms, ok := parseTracepathMs(tok); ok {
				h.RTTMs = append(h.RTTMs, ms)
			}
		}
		// 既没地址又没时间的行是说明行（`1?: [LOCALHOST]  pmtu 1500`、结尾的 Resume 行），
		// 不是丢包的跳 —— 丢掉它，否则「第一跳没回」会被它冒充。
		if h.Addr == "" && len(h.RTTMs) == 0 {
			continue
		}
		hops = append(hops, h)
	}
	return mergeHops(hops)
}

// parseTracepathMs 认 tracepath 的 `0.512ms`（数值和单位粘在一起，中间没空格）。
func parseTracepathMs(tok string) (float64, bool) {
	if !strings.HasSuffix(tok, "ms") {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(tok, "ms"), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// topTraceCode 合两族的结论。★ 谁坏说谁：不许因为 v4 是好的就把 v6 的断点抹平，
// 那是双栈机器上最贵的一类漏报（应用优先走 v6，就先卡在那里）。
func topTraceCode(fs []traceFamily) string {
	if len(fs) == 1 {
		return codeForTop(fs[0].Code)
	}
	// 三类证据分开数：**到了** / **确定没到** / **没给出结论**。
	//
	// ★★ 第三类绝不能算进第二类。跳数用完、第一跳就不回（ICMP 被限速时整条路都是这样）、
	//   整条超时 —— 这些都只是「这次没看出来」，把它们当成「路断了」的证据，
	//   人就会去查一台根本没坏的路由器；而 max-hops 真正该做的动作是把 maxHops 调大。
	//   同理，这台机器缺命令也不算路坏。
	reached, broken, ran := 0, 0, 0
	for _, f := range fs {
		if f.Code == traceNoCommand || f.Code == tracePrivileged || f.Code == ots.CodeUnknown {
			continue
		}
		ran++
		switch f.Code {
		case traceReached:
			reached++
		case traceStalled, traceNoRoute:
			broken++
		}
	}
	switch {
	case ran == 0:
		return traceNoCommand
	// ★ 有一族压根没跑成：不管跑成的那族结论如何，顶层都是「结论不全」——
	//   报 path-ok 会把没测过的 v6 当成好的，报 path-broken 会让人去查没坏的路。
	case ran < len(fs):
		return pathIncomplete
	case reached == ran:
		return pathOK
	case reached > 0 && broken > 0:
		return pathPartial
	case broken > 0:
		return pathBroken
	default:
		// 都跑成了，但谁都没给出结论（全说不清，或到的那族之外只剩说不清的）
		return pathIncomplete
	}
}

func codeForTop(c string) string {
	if c == traceReached {
		return pathOK
	}
	return c
}

// traceNote 只给码 + 已拿到的事实，不拼中文句子（界面按语言渲染）。
func traceNote(code string, fs []traceFamily) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		s := f.Family + "=" + f.Code
		if f.Code == traceReached || f.Code == traceStalled || f.Code == traceMaxHops {
			s += " hops=" + strconv.Itoa(f.HopsSeen)
		}
		if f.Code == traceStalled && f.LastAddr != "" {
			s += " last=" + f.LastAddr
		}
		parts = append(parts, s)
	}
	return code + " " + strings.Join(parts, " ")
}
