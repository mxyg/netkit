package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"net.yuhox.com/netkit/internal/ots"
)

// ── net.port.process ─
//
// ★★ 「这个端口被谁占了」是现场问得最多、最难一次答准的一句。
//
//	`net.tcp.probe` 只能从外面问「连不连得上」，而连不上有三种完全不同的原因：
//	本机根本没在听（服务没起来）、被别的进程占着（起不来）、还有那种 ——
//	**根本没人占，那条连接是本机自己刚刚连出去留下的**。最后这一种最坑：
//	人看到 554 上有东西就把服务停了，结果停掉的是自己那条客户端连接。
//
// ★★ 所以顶层判定的分法不是「有/没有」，是「要不要动手」：
//
//	occupied（有进程在听，要腾口就得停它） / outbound-only（那是本机当客户端留下的口，
//	不是占用） / free（真没人用） / partial（**只读到一部分，不许说 free**）。
//
// ★ 只取进程名和 PID，**不取命令行**。命令行里经常有口令、token、数据库连接串，
//
//	而结果会原样发给 AI、以后还要进诊断包。要看得更细，人拿 PID 自己去查。

const (
	ppOccupied    = "occupied"      // 有进程在这个口上监听
	ppOutbound    = "outbound-only" // 只有本机连出去的连接用了这个本地端口，不是监听
	ppFree        = "free"          // 读全了，确实在没有任何东西用它
	ppListed      = "listening"     // 没指定端口：列出了本机在听的端口
	ppNoListen    = "no-listener"   // 没指定端口：一个监听都没有（裸机/精简系统上会遇到）
	ppPartial     = "partial"       // 权限不够，只看得到一部分 —— 不能据此说「没人用」
	ppUnsupported = "unsupported"   // 这个平台没有可靠的读法
)

// 结果里最多带多少条监听记录。★ 不填端口时本机轻松上百条，
// 全发给调用方（AI）既没人在看、又会把上下文挤掉——截断要如实标出来。
const maxPPRows = 120

// 监听的几种状态。★ UDP 没有「监听」这个状态位，绑上就算，
//
//	所以 UDP 那条的 state 是空的 —— 空不代表未知，代表这个协议本来就没有。
const (
	ppStateListen  = "listen"
	ppStateSynRecv = "syn-recv"
)

var portProcTool = ots.Tool{
	Name:  "net.port.process",
	Class: ots.ClassRead,
	Summary: "查本机端口被哪个进程用着：给一个端口号，返回在听的进程（协议、地址、PID、进程名、属主）；" +
		"不填端口就列出本机全部在听的端口。★ 顶层判定分四种，分的是「要不要动手」：" +
		"occupied（有进程在听，要腾口就得停它）、outbound-only（那是本机当客户端连出去留下的端口，" +
		"不是占用，别去停它）、free（确实没人用）、partial（权限不够只看得到一部分，" +
		"不能当成 free）。★ 只给进程名和 PID，不给命令行 —— 命令行里常有口令和 token，" +
		"而结果会发给 AI。纯读本机内核表，不发任何包。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "要查的本地端口，如 554。留空则列出本机全部在听的端口。★ 只有「在听」才算占用：本机当客户端连出去时内核也会占住一个本地端口，那种会判成 outbound-only 并提醒别去停它。"},
	    "proto": {"type": "string", "enum": ["tcp", "udp", "both"],
	      "description": "只看哪个协议，默认 both。★ 查 UDP 要单独问：很多服务的口在 TCP 上没有，而 UDP 没有「监听」状态位，绑上就算。"}
	  }
	}`),
	Invoke: doPortProc,
}

type portProcArgs struct {
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
}

// portUse 一条「本机正用着这个端口」的记录。
//
// ★ Family 必须留着：同一个口 v4 与 v6 各听一遍是两种不同的毛病
// （只听在 :: 上的服务，v4 那边可能让给了另一个进程），合成一条就看不见了。
type portUse struct {
	Proto   string `json:"proto"` // tcp / udp
	Family  string `json:"family,omitempty"`
	State   string `json:"state,omitempty"`
	Local   string `json:"local"` // 本机侧地址；* 表示所有地址
	Port    int    `json:"port"`
	Foreign string `json:"foreign,omitempty"` // 已建立连接的对端
	Pid     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	User    string `json:"user,omitempty"`
}

// listening 这条算不算「在听」。★ syn-recv 也算被占着 —— 那是半开的监听队列，
//
//	去起服务照样会撞口。
func (u portUse) listening() bool {
	if u.Proto == "udp" {
		return u.State == "" || u.State == ppStateListen
	}
	return u.State == ppStateListen || u.State == ppStateSynRecv
}

// portRead 读本机全部在用端口的动作。★ 是个类型而不是直接调函数：
// 真机上它要跑外部命令、读 /proc，测试里换成一段固定输出才能钉住判定，
// 而不是依赖跑测试的这台机器现在开着什么。
type portRead func(ctx context.Context) (uses []portUse, partial bool, err error)

// localPorts 本机实际的读法。包级变量只有一个理由：让测试能换掉它。
var localPorts portRead = readLocalPorts

// errPortSource 这个平台没有可靠读法时由 OS 层返回。
//
// ★ 判定层按 errors.Is 认，不按错误文本里的词认：改文案就让判定偷偷失效，
// 那种错只有等到有人在一台不支持的机器上跑到假结论才会被发现。
var errPortSource = errors.New("没有可靠的读法")

func doPortProc(ctx context.Context, raw json.RawMessage) (any, error) {
	var a portProcArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	switch a.Proto {
	case "", "tcp", "udp", "both":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "proto 只能是 tcp / udp / both，给的是 %q", a.Proto)
	}
	if a.Port < 0 || a.Port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "port %d 不在 1 到 65535 之间", a.Port)
	}
	// ★ 0 当「没填」处理：Go 的 int 分不出「根本没给这个字段」和「给了 0」，
	// 为了区分把 port 换成 *int 不值得 —— schema 里 minimum 就是 1，
	// 正经客户端不会给 0，给了就按「列全部」走，比报一个错更靠近人想问的东西。

	uses, partial, err := localPorts(ctx)
	if err != nil {
		if errors.Is(err, errPortSource) {
			return ots.Verdict{Code: ppUnsupported, Values: map[string]any{
				"reason": err.Error(),
			}, Note: "这个平台没有可靠的「端口 → 进程」读法。★ 没有读法不等于没人占用，" +
				"不去猜一个答案是负责任的；要查请在这台机器上用系统自带的工具。"}, nil
		}
		return nil, err
	}

	wantProto := a.Proto
	if wantProto == "" {
		wantProto = "both"
	}
	var hit []portUse
	for _, u := range uses {
		// ★ 端口 0 是「内核还没给它分配端口」—— 一个开着却没绑的套接字，
		// 本机实测有十几条（identityservicesd、微信那些）。它们不算占用任何口：
		// UDP 又没有监听状态位，留着会在列表里显示成「在听 0 端口」，把真在听的淹掉。
		if u.Port == 0 {
			continue
		}
		if wantProto != "both" && u.Proto != wantProto {
			continue
		}
		if a.Port != 0 && u.Port != a.Port {
			continue
		}
		hit = append(hit, u)
	}
	sortPortUses(hit)

	code, listeners := portVerdict(hit, a.Port, partial, wantProto)
	// ★ 列全部时条数能上百（本机实测 227 条监听）。这份结果会整份发给 AI，
	// 所以给行数设顶：截了多少如实说，不假装这就是全部。
	total := len(listeners)
	truncated := false
	if total > maxPPRows {
		listeners = listeners[:maxPPRows]
		truncated = true
	}
	values := map[string]any{
		"listening":     listeners,
		"listenerCount": total,
		"count":         len(hit),
		"partial":       partial,
		"truncated":     truncated,
	}
	if a.Port != 0 {
		values["port"] = a.Port
		// 查一个具体端口时，那些「不监听但确实占着这个本地口」的连接要给出去：
		// 判成 outbound-only 时界面必须指着行说清是哪几条，不能只给一个词。
		conns := make([]portUse, 0, len(hit))
		for _, u := range hit {
			if !u.listening() {
				conns = append(conns, u)
			}
		}
		if len(conns) > 0 {
			values["connections"] = conns
		}
	}
	if wantProto != "both" {
		values["proto"] = wantProto
	}
	// ★ 只指定协议时，被筛掉的另一半要说清楚是多少条里剩多少 ——
	// 不然「tcp 没找到」会被读成「这台机器只有这些口」。
	if a.Port == 0 {
		values["totalRead"] = len(uses)
	}
	return ots.Verdict{
		Code:   code,
		Values: values,
		Note:   portNote(code, listeners, total, a.Port, partial, truncated),
	}, nil
}

// portVerdict 挑顶层判定，顺带把「在听的那些」分出来给界面。
//
// 返回值里的 listeners 只含在听的条目：界面既要拿它决定贴哪种标签，
// 又要把「虽然不在听、但确实占着这个本地端口」的那几条一起显示出来。
func portVerdict(hit []portUse, port int, partial bool, proto string) (string, []portUse) {
	var listeners []portUse
	for _, u := range hit {
		if u.listening() {
			listeners = append(listeners, u)
		}
	}
	switch {
	case port != 0 && len(listeners) > 0:
		return ppOccupied, listeners
	case port != 0 && len(hit) > 0:
		// 有记录但一条都不算监听：本机当客户端连出去时内核也会占住这个本地端口
		return ppOutbound, listeners
	case port != 0 && partial:
		// ★ 这一支是整个判定的关键：看不全的时候说「没人用」，
		// 人就会去起服务，然后撞上「地址已在使用」，回头再骂工具。
		return ppPartial, listeners
	case port != 0:
		return ppFree, listeners
	case len(listeners) > 0:
		return ppListed, listeners
	case len(hit) > 0:
		// 没指定端口、又只有外发连接：本机确实没在听任何东西
		return ppNoListen, listeners
	case partial:
		return ppPartial, listeners
	}
	return ppNoListen, listeners
}

func portNote(code string, listeners []portUse, total, port int, partial, truncated bool) string {
	// ★ 带上协议族（tcp4 / tcp6）：同一个进程常常 v4、v6 各听一遍，只写名字会重复成
	// 「tcp/rapportd:505、tcp/rapportd:505」，人看了以为有两个进程。
	who := func() string {
		var s []string
		for _, u := range listeners {
			s = append(s, fmt.Sprintf("%s%s/%s:%d", u.Proto,
				strings.TrimPrefix(u.Family, "ipv"), u.Process, u.Pid))
		}
		return strings.Join(s, "、")
	}
	switch code {
	case ppOccupied:
		n := "在听的是 " + who() + "。★ 要腾这个口就得停掉它；停之前先确认它是不是那个服务的守护进程" +
			"（有的服务由守护进程拉起，停父的没用）。"
		if partial {
			n += "另外这次只读到一部分，可能还有别的进程也占着这个口。"
		}
		return n
	case ppOutbound:
		return "这个本地端口上没有监听，列出来的那些是本机**连出去**的连接占用的临时端口 —— " +
			"不是谁占着你的服务，去停它反而会把正在跑的会话掐断。要起的服务起不来，再看是不是 " +
			"IPv6 的同一个口被占了（v6only 与双栈绑定不是一回事）。"
	case ppFree:
		return "端口 " + strconv.Itoa(port) + " 上确实没有任何进程在听，也没有本机发起的连接在用它。" +
			"★ 这只说明本机的情况 —— 服务起不来如果报「地址已在使用」，多半是另一个用户或容器命名空间的口，" +
			"那要用管理员权限再问一次。"
	case ppPartial:
		return "只读到一部分：看不到那些进程**不等于没在听**。★ 用管理员权限再问一次才算数，" +
			"别把这一栏的结论当「没人用」。"
	case ppListed:
		n := "本机在听 " + strconv.Itoa(total) + " 个端口，明细在 listening 那一栏"
		if truncated {
			n += "（只列出前 " + strconv.Itoa(len(listeners)) + " 条，其余按端口排序留在内核表里，" +
				"要看得再填具体端口号）"
		}
		return n + "。★ 这里只列监听，本机连出去占用的临时端口没算进来。"
	case ppNoListen:
		return "本机一个监听端口都没有 —— 这台机器现在不对外提供任何服务。"
	}
	return ""
}

func sortPortUses(uses []portUse) {
	sort.SliceStable(uses, func(i, j int) bool {
		if uses[i].Port != uses[j].Port {
			return uses[i].Port < uses[j].Port
		}
		if uses[i].Proto != uses[j].Proto {
			return uses[i].Proto < uses[j].Proto
		}
		return uses[i].Local < uses[j].Local
	})
}
