// ── net.troubleshoot 排障决策树 ──
//
// ★★ 这张卡和「一键体检」的区别是**问法**：体检是「不管三七二十一全过一遍」，
//
//	这一张是「人先说一句症状，我按工程师的顺序只查那一条路，并且把为什么往这走记下来」。
//	体检给出八个结果，人要自己判断从哪一条开始看；这里给出一个根因，
//	和一条能拿去跟二线对质的推理路径（第几步问了什么、答了什么、所以接下来问什么）。
//
// ★ 树里每一步都是**已经存在的工具**，不另造一套口径。
//
//	理由很实际：这些判定码每一个都是拿真设备和真网络磨出来的（探端口要分「主机在但没服务」
//	和「静默丢包」，追踪要分清「中段静默」和「真断了」）。树里再实现一遍，
//	就等于给同一件事造两套会各自腐烂的判断。
//
// ★★ 三条不许破的纪律：
//
//  1. **没问的不许读成问过**。每一步都要落一个状态：问了 / 想问但问不成（缺什么）/
//     因为停在前面所以没问 / 问了但读不到要的那个取值 / 工具自己出错。
//     「没去问」和「问了没有」差一次跑错机房。
//  2. **判定码全部引用工具自己那份常量**，不在这张卡里重打一遍字符串。
//     那些码改名，这张卡必须编译不过 —— 靠字符串对上号，改的那一侧看不见，
//     分支就会永远走不到，而界面上一切正常。
//  3. **凭据不进结果**。要问一个带账号的取流地址、带团体名的设备，
//     参数得记进推理路径（不然人看不出我们问的是哪台），但记的是**脱敏之后**那份。
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// 每一步的状态。★ 五个状态就是上面第 1 条纪律的全部内容。
const (
	treeAsked      = "asked"      // 问了，拿到了判定
	treeNotAsked   = "not-asked"  // 缺事实（前面没问出地址/网关来），这一步压根没发出去
	treeSkipped    = "skipped"    // 停在前面了，按顺序不必问
	treeUnreadable = "unreadable" // 问了，但结果里没有我们依赖的那个取值 —— 是**我们**读不到，不是网络没答
	treeFailed     = "failed"     // 工具自己报错（参数、权限、内部错），不能当成「网络查过了没问题」
)

// treeStepOut 推理路径上的一步。★ raw 不进结果，只在内存里给 decide 看数字用。
type treeStepOut struct {
	Step     string         `json:"step"`
	StepName string         `json:"stepName"` // 那一步的中文名。★ 名字只有一个主人：树（见 treeNode.name）
	Tool     string         `json:"tool"`
	Args     map[string]any `json:"args,omitempty"`
	Status   string         `json:"status"`
	Code     string         `json:"code,omitempty"`
	// ToolNote 是那一步工具自己给的一句话（日志口径，不是顶层结论）。
	//
	// ★ 必须带上：很多「这一步其实有话要说」只活在 note 里 ——
	//	比如路由按表算和一个口不一样、邻居那一行是猜的。不带上，人对着一个判定码猜我们看到了什么。
	ToolNote string         `json:"toolNote,omitempty"`
	Facts    map[string]any `json:"facts,omitempty"`
	Note     string         `json:"note,omitempty"` // 只写日志口径的补充（为什么没问成），不写结论

	raw map[string]any
}

// 顶层判定。★ 根因另有一批 cause-* 码，见下面 treeCauses。
const (
	treeNoCause = "no-cause-found" // 这条路走完了，每一步都正常 —— 症状不在我们问的这些里面
	treeStopped = "stopped"        // 中途被取消，这份路径只到第几步，不能当成整条结论
	treeNothing = "nothing-asked"  // 一步都没问出去（缺的目标信息太多），不能读成「查过了都没事」
)

// 症状。界面用中文渲染，这里的名字是给 AI 和剧本用的稳定标识。
const (
	symNoInternet = "no-internet" // 这台机器上不去网
	symHostDown   = "host-down"   // 点名一台机器连不上
	symSlow       = "slow"        // 通是通，但很慢
	symFlaky      = "flaky"       // 偶尔卡一下 / 时好时坏
	symCert       = "cert-error"  // 证书报错 / HTTPS 打不开
	symDeviceDown = "device-down" // 一台设备（摄像头 / NVR / 打印机）不在线、没画面
)

var treeSymptoms = []string{symNoInternet, symHostDown, symSlow, symFlaky, symCert, symDeviceDown}

// treeCauses 是根因码的登记处。★ 这里只登记「有哪些」，不写人话 ——
//
//	句子在界面那侧按码渲染（[OTS-5.1]），这张表存在的意义是让测试能逐条问
//	「树里出现的每个根因码，界面都译了吗」。
var treeCauses = map[string]bool{
	// 出不了外网
	"cause-no-interface":        true, // 一块在用的网卡都没有
	"cause-link-down":           true, // 网卡启用了但没连接（线没插 / 无线没关联）
	"cause-no-address":          true, // 有链路却没地址：DHCP / RA 没给
	"cause-no-default-route":    true, // 有地址却没有默认路由
	"cause-gateway-loss":        true, // 到网关就丢包，后面的测量都不可信
	"cause-gateway-unreachable": true, // 网关明确回了不可达
	"cause-gateway-silent":      true, // 网关一个不吭（也可能是它拦 ICMP）
	"cause-dns-server-dead":     true, // 配了 DNS 服务器却问不到
	"cause-dns-upstream":        true, // 服务器回 SERVFAIL：它自己查不到
	"cause-dns-refused":         true, // 服务器不给递归
	"cause-dns-bad-response":    true, // 回了，但不是能解的 DNS 报文
	"cause-name-missing":        true, // 域名不存在（这台机器上或这个服务器上）
	"cause-v6-egress-broken":    true, // ★ 招牌：v4 正常、v6 有路却出不了外网，应用先卡在 v6
	"cause-path-stalled":        true, // 追到第 N 跳之后全无回应
	"cause-path-silent":         true, // 第一跳就不回，说不通路断没断
	"cause-no-route-to-target":  true, // 本机没有去往目标的路由
	"cause-clock-way-off":       true, // 本机钟偏得会让证书校验和日志都对不上
	"cause-clock-skewed":        true, // 偏一点，还没到出事的地步
	"cause-proxy-in-the-way":    true, // 系统代理指着一台连不上的机器

	// 点名一台机器
	"cause-target-off-link":     true, // 同网段，二层都没有它：查线、查供电、查它自己关机
	"cause-target-alive-noicmp": true, // 二层有它（应 ARP）却不回 ICMP
	"cause-target-unreachable":  true, // 有设备明确回了不可达
	"cause-target-no-reply":     true, // 一路都没回，且二层证据也没拿到
	"cause-service-closed":      true, // 主机在，那个端口明确拒绝（服务没起 / 起在别的口）
	"cause-service-filtered":    true, // 那个端口静默：多半是防火墙
	"cause-host-alive":          true, // 走到这儿网络和服务都没问题，症状不在这条路上

	// 慢
	"cause-link-jitter":   true, // 链路本身在抖
	"cause-link-loss":     true, // 链路上有丢包，重传把一切拖慢
	"cause-v6-stall":      true, // ★ 应用先卡在 v6 上再回落
	"cause-dns-slow":      true, // 解析这一段就慢
	"cause-app-slow":      true, // 网络各段都利索，慢在服务自己想
	"cause-tls-slow":      true, // 慢在 TLS 那一段（常见于设备证书链长或握手要回落）
	"cause-connect-slow":  true, // 慢在 TCP 连接那一段
	"cause-path-latency":  true, // 从某一跳起往返抬升并延续到终点
	"cause-mtu-too-small": true, // 路上有一个更小的 MTU，大包被挡或被迫分片

	// 时好时坏
	"cause-intermittent-loss": true, // 有一段在突发丢包
	"cause-path-moved":        true, // 等价路径在翻动（负载分担 / 路由在动）
	"cause-multi-default":     true, // 同族多条默认路由，选路在换
	"cause-round-robin-bad":   true, // 一个名字解出多台，其中一台是坏的
	"cause-clock-disagree":    true, // 两台机器钟不一致，日志对不上号

	// 证书
	"cause-cert-expired":        true,
	"cause-cert-not-yet-valid":  true,
	"cause-cert-name-mismatch":  true,
	"cause-cert-untrusted":      true,
	"cause-cert-weak-protocol":  true,
	"cause-clock-made-cert-bad": true, // ★ 证书没过期，是本机钟偏了 —— 这条翻案必须问时间才问得出来
	"cause-not-tls":             true, // 那个端口回的不是 TLS（明文服务写成了 https）

	// 设备不在线 / 没画面
	"cause-device-off-link":   true,
	"cause-device-no-icmp":    true,
	"cause-device-no-service": true,
	"cause-stream-auth":       true, // 问到了、只是不让看
	"cause-port-not-rtsp":     true, // 那个口接了 TCP 却不说 RTSP：端口号或协议不对
	"cause-stream-missing":    true, // 设备答了，但这个通道上没有这路流
	"cause-stream-broken":     true, // 认证都过了，应答里却没一条媒体轨：那路流在设备上没配出来
	"cause-stream-ok":         true, // 流在播 —— 「没画面」是那头的显示侧
	"cause-egress-blocked":    true, // 路到得了出口那台机器，却连不上它那个口：拦在中间
	"cause-wrong-scheme":      true, // 明文口写成 https（或反过来），改个前缀就好
}

// IsTreeCause 问一个码是不是登记过的根因码（测试用）。
func IsTreeCause(code string) bool { return treeCauses[code] }

// TreeCauses 返回登记过的根因码，排序好，给测试和界面比对用。
func TreeCauses() []string {
	out := make([]string, 0, len(treeCauses))
	for c := range treeCauses {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// ── 引擎 ──

// move 是「这一步答完之后往哪儿走」。
//
// ★ 三个字段互斥得靠写树的人自己守：给了 Cause 就是停，Next 再写也不看
//
//	（测试 TestTreeMovesAreSane 会盯这条）。
type move struct {
	cause string // 非空 = 停在这儿，这就是根因
	next  string // 下一个步骤的 id；空 = 按表的顺序往下走
	end   bool   // 明确走到头（不再往下问），但没定位到根因
}

// treeNode 一个「问哪个工具、怎么问、从结果里看什么」。多棵症状树共用。
type treeNode struct {
	id string
	// name 是这一步的人话名字。★★ 推理路径里「停在哪儿了」那句话是后端写的，
	//	用内部 id 写就等于把 dualstack 这种人不会读的词塞进结果。
	name string
	tool string
	// codeKey 顶层判定不在 verdict 那一栏时写它在哪儿（比如 net.neighbors 本来没有判定）。
	codeKey string
	need    []string // 缺了这些事实就拼不出参数，直接落 not-asked
	args    func(st *treeState) (map[string]any, error)
	// when 这一步这次到底该不该问（比如已经有 IP 了就不必再解析）。
	//	★ 不问要留下「为什么没问」，不许留空着的那一格 —— 空栏会被读成「问了，没问题」。
	when   func(st *treeState) bool
	unless string                                   // when 为 false 时记进 note 的那句原因（日志口径，不是结论）
	shows  []string                                 // 从结果里挑给人看的取值（点路径）
	take   func(st *treeState, vals map[string]any) // 把后面几步要用的事实拿走
}

// planStep 树里的一个节点 + 它的走法。
type planStep struct {
	// node 的 id 在一棵树里必须唯一（两棵树之间不必）：引擎按 id 找下一步，
	//	同 id 出现两次等于有一步永远走不到。测试 TestTreeStepIDsAreUnique 钉这条。
	node *treeNode
	// by 这一步的判定码 → 往哪儿走。★ 键全部用工具那边的常量写，不许重打字符串。
	//	命中就用它，**不再问 decide** —— 能一句话说清的走法就写在明面上。
	by map[string]move
	// other 一条都没命中时的走法。★ 必须显式给：
	//	漏一条新判定码就走错，比报错坏 —— 界面看起来一切正常。
	other move
	// decide 只在 by 里没有这一条码时问它：看数字（丢包率、第几跳）、看别的步的判定，
	//	或者兜住「这一码我们没预料到」。所以它必须自己带回退，不许返回空走法蒙混。
	decide func(st *treeState, code string, vals map[string]any) move
}

// treePlan 一棵症状树。
type treePlan struct {
	symptom string
	steps   []planStep
}

func (st *treeState) stepList() []*treeStepOut {
	out := make([]*treeStepOut, 0, len(st.order))
	for _, id := range st.order {
		out = append(out, st.step[id])
	}
	return out
}

type treeState struct {
	facts map[string]any
	args  treeArgs
	step  map[string]*treeStepOut
	order []string
}

func (st *treeState) set(k string, v any) {
	if v == nil || v == "" {
		return
	}
	st.facts[k] = v
}

func (st *treeState) str(k string) string {
	if v, ok := st.facts[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (st *treeState) missing(need []string) []string {
	var out []string
	for _, k := range need {
		if st.str(k) == "" {
			out = append(out, k)
		}
	}
	return out
}

// treeCall 是「按名字调一个已经注册的工具」。
//
// ★ 单独抽出来只为了测得动：一棵树的每一条分支，不该只能靠把真网络搞坏来验。
type treeCall func(ctx context.Context, args json.RawMessage) (any, error)

var treeCalls = map[string]treeCall{}

// installTreeCalls 从**注册用的那一份工具表**里装出树能调的东西。
//
// ★★ 只装 ClassRead 的。树要是哪天指向一个改系统的工具，它就在人以为「只是在排查」的时候
//
//	把系统改了 —— 那正是这张卡最不能干的事。所以这里不是过滤，是闸：
//	非只读的一律进不来，指过去就是「没有这个工具」。
func installTreeCalls(ts []ots.Tool) {
	for _, t := range ts {
		if t.Class != ots.ClassRead {
			continue
		}
		treeCalls[t.Name] = t.Invoke
	}
}

func lookupTreeCall(name string) (treeCall, bool) {
	f, ok := treeCalls[name]
	return f, ok && f != nil
}

// ── 工具层 ──

type treeArgs struct {
	Symptom    string `json:"symptom"`
	Target     string `json:"target,omitempty"` // 要点名的地址或域名
	Port       int    `json:"port,omitempty"`
	Ports      string `json:"ports,omitempty"`
	URL        string `json:"url,omitempty"`
	Iface      string `json:"iface,omitempty"`
	Quick      bool   `json:"quick,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Community  string `json:"community,omitempty"`
	TimeoutMS  int    `json:"timeoutMs,omitempty"`
	MaxSeconds int    `json:"maxSeconds,omitempty"`
}

var troubleshootTool = ots.Tool{
	Name:  "net.troubleshoot",
	Class: ots.ClassRead,
	Summary: "给一个症状，按工程师的排查顺序只走那一条路，逐步记下「问了什么 / 答了什么 / 为什么往这走」，" +
		"停在第一个能解释症状的判定上。symptom 六种：" +
		"no-internet（这台机器出不了外网）、host-down（点名一台机器连不上）、" +
		"slow（通是通，但很慢）、flaky（偶尔卡一下）、cert-error（证书报错）、" +
		"device-down（一台设备不在线 / 没画面）。" +
		"★ 顶层判定：cause-*（定位到根因那一条）、no-cause-found（这条路每步都正常，症状不在我们问的里面）、" +
		"stopped（中途停了，这份路径只到第几步）、nothing-asked（一步都没问出去，不能读成「查过了都没事」）。" +
		"每一步带 status：asked / not-asked（缺信息没问）/ skipped（停在前面没问）/ " +
		"unreadable（问了但读不到要的取值）/ failed（工具自己报错）。" +
		"★ 树里每一步都是本产品已有的只读工具，不另造一套判定口径；全程不改任何东西。" +
		"带账号或团名时只填在本卡里，结果和日志里都不出现它们。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["symptom"],
	  "properties": {
	    "symptom": {"type": "string", "enum": ["no-internet","host-down","slow","flaky","cert-error","device-down"],
	      "description": "人那一句话说的是哪种。★ 选错症状等于走错树，结论会「看起来合理但没用」。"},
	    "target": {"type": "string",
	      "description": "要点名的那台机器：IP、域名都收（host-down / slow / flaky / device-down 用）。不填就用默认对照组。"},
	    "port": {"type": "integer","minimum":1,"maximum":65535, "description": "关心哪个端口（比如摄像头 554、网站 443）。"},
	    "ports": {"type": "string","description": "要看好几个端口时给逗号分隔的清单，如 554,80,8000。"},
	    "url": {"type": "string", "description": "慢 / 证书报错时给具体网址；设备取流给 rtsp 地址。带账号的 rtsp 地址里的账号密码不会出现在结果里。"},
	    "iface": {"type": "string", "description": "只在某块网卡上找（device-down 常用：知道设备插在哪个口）。"},
	    "quick": {"type": "boolean", "description": "少发几发，先要个方向。默认 false。"},
	    "username": {"type": "string"}, "password": {"type": "string"},
	    "community": {"type": "string", "description": "问 SNMP 时用哪个团体名。★ 不会进结果、不会进日志。"},
	    "timeoutMs": {"type": "integer","minimum":500,"maximum":8000,"description": "单个探测的等待上限，默认 2000。"},
	    "maxSeconds": {"type": "integer","minimum":10,"maximum":300,"description": "这棵树最长跑多久，默认 120 秒。"}
	  }
	}`),
	Invoke: doTroubleshoot,
}

func doTroubleshoot(ctx context.Context, raw json.RawMessage) (any, error) {
	var a treeArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	plan, ok := treePlanFor(a.Symptom)
	if !ok {
		return nil, ots.Errf(ots.ErrInvalidArgument, "症状 %q 没有对应的排查路线，可选：%s",
			a.Symptom, strings.Join(treeSymptoms, " / "))
	}
	if a.TimeoutMS == 0 {
		a.TimeoutMS = 2000
	}
	if a.TimeoutMS < 500 || a.TimeoutMS > 8000 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "timeoutMs %d 不在 500 到 8000 之间", a.TimeoutMS)
	}
	secs := a.MaxSeconds
	if secs == 0 {
		secs = 120
	}
	if secs < 10 || secs > 300 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "maxSeconds %d 不在 10 到 300 之间 —— 再多就不是排查是扫描了", secs)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second)
	defer cancel()

	st := newTreeState(a)
	v, err := runTreePlan(ctx, plan, st, lookupTreeCall)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// newTreeState 把调用方给的东西先归一成事实。
//
// ★ 地址和域名在这里就分好家：后面每一步都拿 ip 去发包、拿 host 去解析，
//
//	现场最常见的错法是「把一个域名当地址填进 ping 的参数里」，症状是「说不清是没解析还是不通」。
func newTreeState(a treeArgs) *treeState {
	st := &treeState{facts: map[string]any{}, args: a, step: map[string]*treeStepOut{}}
	st.set("symptom", a.Symptom)
	if a.Iface != "" {
		st.set("iface", a.Iface)
	}
	if a.URL != "" {
		st.set("url", a.URL)
		if u, err := url.Parse(a.URL); err == nil && u.Hostname() != "" {
			setTargetFact(st, u.Hostname())
			if u.Port() != "" {
				st.set("portStr", u.Port())
			}
			st.set("scheme", u.Scheme)
		}
	}
	if a.Target != "" {
		setTargetFact(st, a.Target)
	}
	if a.Port > 0 {
		st.set("portStr", strconv.Itoa(a.Port))
	}
	if a.Ports != "" {
		st.set("ports", a.Ports)
	}
	return st
}

// setTargetFact 把一个名字或地址归成事实。
//
// ★★ 地址必须同时落下 ip 和 addr：树里后面每一步都拿 addr 去发包，
//
//	只填 ip 的话，人明明点了 192.0.2.7，路径上却是一片「缺地址，没问成」——
//	那是我们把它弄丢的，不是网络没答，最坏的一种读数。
//
// 域名走另一条：先问解析，解析出来的地址由 takeAnswer 补进 addr。
func setTargetFact(st *treeState, raw string) {
	s := strings.TrimSuffix(strings.Trim(strings.TrimSpace(raw), "[]"), ".")
	if s == "" {
		return
	}
	if addr, err := netaddr.Parse(s); err == nil {
		st.set("ip", s)
		st.set("addr", s)
		fam := "ipv4"
		if addr.Is6() {
			fam = "ipv6"
		}
		st.set("family", fam)
		return
	}
	st.set("host", s)
}

// runTreePlan 走一棵树。★ 引擎只做三件事：按 id 找步、把状态记全、决定停不停。
//
//	所有「往哪儿走」的判断都留在表里（treePlans），这样审一棵树只需要读那张表。
func runTreePlan(ctx context.Context, plan *treePlan, st *treeState, lookup func(string) (treeCall, bool)) (ots.Verdict, error) {
	byID := map[string]planStep{}
	for _, s := range plan.steps {
		byID[s.node.id] = s
	}
	visited := map[string]bool{}
	cur := plan.steps[0].node.id
	cause := ""
	causeFacts := map[string]any{}
	stopped := false

	for cur != "" {
		if visited[cur] { // ★ 表写错了会成环；宁可停下来报错，也不要转圈转到人以为在跑
			return ots.Verdict{}, ots.Errf(ots.ErrInternal, "排查路线成了环：第 %s 步走过一次了", cur)
		}
		if err := ctx.Err(); err != nil {
			stopped = true
			break
		}
		ps, ok := byID[cur]
		if !ok {
			return ots.Verdict{}, ots.Errf(ots.ErrInternal, "排查路线指到一个不存在的步骤 %q", cur)
		}
		visited[cur] = true
		out := askStep(ctx, st, ps, lookup)
		cur = ""

		// ★ 问不成的那一步**不许当成一次正常的判定**：拿它的「其它」分支往下走，
		//	等于把「我们没问出来」读成「网络这么答」。所以这一档只往前走、不定根因。
		if out.Status != treeAsked {
			if !ps.other.end {
				cur = nextID(plan, ps, ps.other)
			}
			continue
		}
		mv := ps.other
		if m, ok := ps.by[out.Code]; ok {
			mv = m
		} else if ps.decide != nil {
			mv = ps.decide(st, out.Code, out.raw)
		}
		if mv.cause != "" {
			cause, causeFacts = mv.cause, out.Facts
			st.set("causeStep", ps.node.id)
			st.set("causeName", ps.node.name)
			break
		}
		if !mv.end {
			cur = nextID(plan, ps, mv)
		}
	}

	// 没走到的步骤一律记 skipped。★ 不是记「没这个步骤」：
	// 人要看的是「你们本来打算问但停在前面了没问」，那正是这份路径下一步该从哪儿接上。
	for _, s := range plan.steps {
		if _, ok := st.step[s.node.id]; !ok {
			st.step[s.node.id] = &treeStepOut{Step: s.node.id, StepName: s.node.name,
				Tool: s.node.tool, Status: treeSkipped, Note: skipReason(st, cause)}
			st.order = append(st.order, s.node.id)
		}
	}

	asked := 0
	for _, id := range st.order {
		if st.step[id].Status == treeAsked {
			asked++
		}
	}
	top := treeNoCause
	switch {
	case cause != "":
		top = cause
	case stopped:
		top = treeStopped
	case asked == 0:
		top = treeNothing
	}
	values := map[string]any{
		"symptom": plan.symptom, "steps": st.stepList(), "asked": asked,
	}
	if cause != "" {
		values["cause"] = cause
		if len(causeFacts) > 0 {
			values["causeFacts"] = causeFacts
		}
	}
	if s := st.str("causeStep"); s != "" {
		values["causeStep"] = s
		// ★ 中文名跟着一起给：界面不必再存一份步骤表（名字只有一个主人，见 treeNode.name）。
		if n := st.str("causeName"); n != "" {
			values["causeName"] = n
		}
	}
	return ots.Verdict{Code: top, Values: values, Note: treeNote(top, asked, stopped, st.str("causeName"))}, nil
}

// askStep 问一步，把五种状态该记的都记上。
func askStep(ctx context.Context, st *treeState, ps planStep, lookup func(string) (treeCall, bool)) *treeStepOut {
	node := ps.node
	out := &treeStepOut{Step: node.id, StepName: node.name, Tool: node.tool}
	st.step[node.id] = out
	st.order = append(st.order, node.id)

	if node.when != nil && !node.when(st) {
		out.Status = treeNotAsked
		out.Note = node.unless
		if out.Note == "" {
			out.Note = "这次不必问这一步"
		}
		return out
	}
	if gap := st.missing(node.need); len(gap) > 0 {
		out.Status = treeNotAsked
		out.Note = "缺这些事实才问得出去：" + strings.Join(gap, "、")
		return out
	}
	call, ok := lookup(node.tool)
	if !ok { // ★ 表指到一个不存在（或不只读）的工具：这是我们的表写错了，不是网络的问题
		out.Status = treeFailed
		out.Code = "tool-missing"
		out.Note = "路线里写了 " + node.tool + "，但它没有注册或不是只读工具"
		return out
	}
	var args map[string]any
	if node.args != nil {
		m, err := node.args(st)
		if err != nil {
			out.Status = treeNotAsked
			out.Note = "参数拼不出来：" + err.Error()
			return out
		}
		args = m
	}
	sent := redactTreeArgs(args)
	if len(sent) > 0 {
		out.Args = sent
	}
	raw, err := json.Marshal(args)
	if err != nil {
		out.Status = treeNotAsked
		out.Note = "参数编不出来：" + err.Error()
		return out
	}
	res, err := call(ctx, raw)
	if err != nil {
		out.Status = treeFailed
		out.Code = errCodeOf(err)
		out.Note = "这一步的工具报错了：" + truncate(err.Error(), 200)
		return out
	}
	vals, ok := asMap(res)
	if !ok {
		out.Status = treeUnreadable
		out.Note = node.tool + " 给回来的东西不是一个对象 —— 是我们读不到，不是网络没答"
		return out
	}
	code, ok := digStr(vals, codePaths(node))
	if !ok || code == "" {
		out.Status = treeUnreadable
		out.Note = node.tool + " 的结果里没有 " + codePaths(node) + " 这一栏 —— 是我们读不到，不是网络没答"
		return out
	}
	out.Status = treeAsked
	out.Code = code
	out.raw = vals
	if n, ok := digStr(vals, "note"); ok && n != "" {
		out.ToolNote = truncate(n, 300) // 工具自己那句话：是日志口径，不许当顶层结论用
	}
	facts := map[string]any{}
	for _, p := range node.shows {
		if v, ok := dig(vals, p); ok {
			facts[lastKey(p)] = v
		}
	}
	if len(facts) > 0 {
		out.Facts = facts
	}
	if node.take != nil {
		node.take(st, vals)
	}
	return out
}

// codePaths 一个节点从哪里读判定码。
//
// ★ 绝大多数工具都是 verdict 一栏（ots.Verdict 的形状），少数几个（net.neighbors）
//
//	本来没有顶层判定，节点里自己写死读哪一栏。
func codePaths(node *treeNode) string {
	if node.codeKey != "" {
		return node.codeKey
	}
	return "verdict"
}

// nextID 这一步之后去哪儿：分支自己说了算，没说就按表的顺序走下一步。
//
// ★ 「按表的顺序」是有意留给线性路线的偷懒口子，但**成环由引擎那一道兜住**，
//
//	而指到不存在的步骤同样报错 —— 表写错要在启动第一次跑时就炸出来，不许默默少问一步。
func nextID(plan *treePlan, ps planStep, mv move) string {
	if mv.next != "" {
		return mv.next
	}
	for i, s := range plan.steps {
		if s.node.id == ps.node.id && i+1 < len(plan.steps) {
			return plan.steps[i+1].node.id
		}
	}
	return ""
}

func skipReason(st *treeState, cause string) string {
	if c := st.str("causeName"); c != "" {
		return "停在「" + c + "」那一步了，按顺序不必问"
	}
	if cause != "" {
		return "停在更早的一步"
	}
	return "这条路没走到这一步"
}

func treeNote(top string, asked int, stopped bool, causeName string) string {
	switch top {
	case treeStopped:
		return "中途停下，一共问了 " + strconv.Itoa(asked) + " 步；这份路径只覆盖到这里，不能当成整条结论"
	case treeNothing:
		return "一步都没问出去（多半是缺目标信息），这不等于「查过了都没事」"
	case treeNoCause:
		return "问了 " + strconv.Itoa(asked) + " 步，每一步都正常 —— 症状不在这一条路线问的范围内"
	}
	if causeName != "" {
		return "问了 " + strconv.Itoa(asked) + " 步，停在「" + causeName + "」那一步 —— 那一步的判定就是根因"
	}
	return "问了 " + strconv.Itoa(asked) + " 步"
}

// ── 取值 ──

// asMap 把一个工具的结果当成 JSON 对象看。
//
// ★ 走一遍 marshal：树里要问的是**别的工具**，它们各自返回自己的 struct 或 map，
//
//	只有过一遍 JSON 才有一致的形状可读。副作用是改名不会编译报错 ——
//	所以读不到时落 unreadable 而不是落「判定为空」，并给每条路径配形状测试。
func asMap(v any) (map[string]any, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return m, true
}

// dig 按 a.b[0].c 这样的路径取值。支持 [last]。
func dig(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, seg := range strings.Split(path, ".") {
		key := seg
		var idx []string
		if i := strings.Index(seg, "["); i >= 0 {
			key = seg[:i]
			idx = strings.Split(strings.TrimSuffix(seg[i+1:], "]"), "][")
		}
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[key]
		if !ok {
			return nil, false
		}
		for _, k := range idx {
			arr, ok := cur.([]any)
			if !ok {
				return nil, false
			}
			n := 0
			switch {
			case k == "last":
				n = len(arr) - 1
			default:
				n = atoi(k)
			}
			if n < 0 || n >= len(arr) {
				return nil, false
			}
			cur = arr[n]
		}
	}
	return cur, true
}

func digStr(m map[string]any, path string) (string, bool) {
	v, ok := dig(m, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func lastKey(path string) string {
	if i := strings.LastIndexAny(path, ".["); i >= 0 {
		p := strings.Trim(path[i+1:], "]")
		if p != "" && p != "last" {
			return p
		}
	}
	return path
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func num(vals map[string]any, path string) (float64, bool) {
	v, ok := dig(vals, path)
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	return f, ok
}

// errCodeOf 把工具报的错归成 ots 的错误码。
//
// ★ 这一步是「failed 不是 ok」那条纪律的另一半：不记码的话，
//
//	界面上只看得见「这一步没结果」，读的人会以为那一步查过了、没问题。
func errCodeOf(err error) string {
	var oe *ots.Error
	if errors.As(err, &oe) {
		return string(oe.Code)
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "error"
}

// redactTreeArgs 把要记进结果的那份参数洗一遍。
//
// ★★ 这一步不能省：推理路径要能拿去发群里、进诊断包、发给 AI。
//
//	rtsp 地址天生带账号（rtsp://user:pass@host/cam），SNMP 团体名等同于设备口令，
//	界面上「你们到底问了什么」那一栏要是照抄参数，每一次排查都在往外发凭据。
func redactTreeArgs(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch strings.ToLower(k) {
		case "password", "community", "token", "secret":
			out[k] = "（已隐去）"
		case "url":
			out[k] = redactTreeURL(v)
		default:
			out[k] = v
		}
	}
	return out
}

func redactTreeURL(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	user := u.User.Username()
	if user == "" {
		user = "?"
	}
	u.User = url.User(user + "（口令已隐去）")
	return u.String()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
