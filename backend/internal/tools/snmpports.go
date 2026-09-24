package tools

// ── net.snmp.ports ──
//
// 这张卡回答的是「这个口现在到底怎么样」：开着没有、链路起来没有、跑多快、
// 这一会儿流了多少、有没有在丢包错包。
//
// ★★ 四件最容易混、而下一步完全不同的事：
//
//	① **admin 和 oper 是两个数**。admin down + oper down 是「有人关掉了」，
//	  admin up + oper down 才是「链路断了」。只看 oper 会把同事为维护关掉的口
//	  报成故障，让人去查一根好着的线。
//	② **速率优先读 ifHighSpeed**。ifSpeed 是 Gauge32，RFC 2863 写明带宽超过
//	  4294967295 时它**就报这个顶格值** —— 于是 10G 的口在界面上是 4.29G。
//	  只拿到顶格值时不能说速率是 4.29G，只能说「至少 4.29G，这一栏问不出准数」。
//	③ **计数器是回绕的**。ifInOctets 是 32 位：千兆口 34 秒绕一圈、万兆 3.4 秒。
//	  有 64 位（ifHCInOctets）就用 64 位；只有 32 位时按模 2^32 求差，
//	  差出来的速率超过这个口的线速，说明**绕了不止一圈**，这时如实不给速率。
//	④ **两次读之间设备重启过，差值全是假的**。所以比一眼 sysUpTime：
//	  倒退了就是重启过，这一趟不报速率，只报累计值。
//	⑤ **计数器按方向、按栏分开**。64 位那一档（ifHCInOctets）不少设备只做入向，
//	  出向仍然只有 32 位 —— 当成一档相减会算出错位的数；而错包/丢包到今天
//	  仍然只有 Counter32，永远按 32 位取模。
//	⑥ **「不给读」不写成 0**。设备没给某一栏（或者选了 noCounters）时，
//	  那一栏整个不出现，速率那格另外给一句原因 ——
//	  「一个错包都没有」和「这台不给读错包数」在现场要查的是两件事。
//
// ★ 整张表里有口 down 着**不是**故障：没插线的空口本来就该是 down。
//   所以 down 那两个判定码只在「点名问某一个口」时给 —— 不然这张卡永远红着，
//   红就成了噪音，而噪音会让人在真出事那一次跳过它。

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
)

// ifTable / ifXTable 里这一张卡用到的栏。列号按 RFC 2863 抄（已对过原文）。
const (
	oidIfIndex       = "1.3.6.1.2.1.2.2.1.1"
	oidIfType        = "1.3.6.1.2.1.2.2.1.3"
	oidIfMtu         = "1.3.6.1.2.1.2.2.1.4"
	oidIfSpeed       = "1.3.6.1.2.1.2.2.1.5" // Gauge32，bits/s，超 4.29G 顶格
	oidIfPhysAddress = "1.3.6.1.2.1.2.2.1.6" // OctetString，MAC
	oidIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfLastChange  = "1.3.6.1.2.1.2.2.1.9" // TimeTicks：最后一次换状态那一刻的 sysUpTime
	oidIfInOctets    = "1.3.6.1.2.1.2.2.1.10"
	oidIfInDiscards  = "1.3.6.1.2.1.2.2.1.13"
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutOctets   = "1.3.6.1.2.1.2.2.1.16"
	oidIfOutDiscards = "1.3.6.1.2.1.2.2.1.19"
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"

	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"  // Counter64
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10" // Counter64
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15" // Gauge32，单位 Mbps
	oidIfAlias       = "1.3.6.1.2.1.31.1.1.1.18" // 口上写的备注（这根线去哪）
)

// ifAdminStatus 的取值（RFC 2863：up(1) down(2) testing(3)）。
func adminStatusName(n int) string {
	switch n {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	}
	return ""
}

// ifOperStatus 的取值。★ 值域比 admin 宽，界面上不能拿 admin 那三个字对上。
func operStatusName(n int) string {
	switch n {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	}
	return ""
}

// operMeaning 把 oper 那一格翻成「下一步查什么」。
//
// ★ dormant 和 lowerLayerDown 是最容易被当成「断了」的两种：前者是物理层好了
//
//	但还没进转发（802.1X 没放行、STP 还在监听），后者是底下的成员口没起。
//	这两种都不该去查线。
func operMeaning(n int) string {
	switch n {
	case 1:
		return "在转发"
	case 2:
		return "没链路"
	case 3:
		return "在测试模式"
	case 4:
		return "状态问不出来"
	case 5:
		return "等外部动作（物理层好了，还没进转发）"
	case 6:
		return "部件不在位（模块没插或不支持）"
	case 7:
		return "底下的层没起（看成员口）"
	}
	return "设备给了一个没听过的值"
}

// downAdvice 是「oper 不是 up」那一条判定最后一句话：这一步该往哪儿查。
//
// ★ 不能拿一句「去查线」打包七种 oper：dormant 的物理层早就好了（查线白跑一趟），
//
//	lowerLayerDown 要看的是底下的成员口，notPresent 是模块压根没插。
//	写成一笼统的查线，界面那颗「链路没起来」的红灯就把三种下一步相反的病按成一种。
func downAdvice(oper int) string {
	switch oper {
	case 2:
		return "这和「有人关了」不是一回事：要查的是对端开没开机、这根线、对端的口、光模块型号波长对不对。"
	case 3:
		return "设备在做线测，这一趟的状态不代表正常转发时的状态。"
	case 4:
		// ★ unknown 是 RFC 2863 里的标准值，不能说成「设备给了个没听过的值」；
		//   它的意思是设备自己答不出这个口 —— 这时候给人一条查线的话就是瞎指。
		return "★ 这一条不能说它是通的还是断的：设备自己答不出这个口的链路状态" +
			"（驱动/固件没往上送）。先换一种问法确认它在不在（整张表列一遍、或者去 ARP 里看），别照这句话去机房。"
	case 5:
		// ★「不该去查线」这五个字要连在一起：整张卡的其它地方都按这个口径写，
		//   测试也按这个抓 —— 中间插进「这根」两个字就抓不到了。
		return "★ 这一条不该去查线：物理层已经起来了，是被上面卡住的 —— 802.1X 没放行、" +
			"STP 还在监听/学习、或者这个口没划进 VLAN。查那三样，不是查这根线。"
	case 6:
		return "★ 这不是故障：部件不在位（模块没插，或者这台不支持这个口），换一个在位的口再看。"
	case 7:
		return "★ 这一条不该去查线（查这个口的线是白跑）：它是聚合口/子接口，成员口没起来它才起不来 —— " +
			"把「口名或编号」留空列一遍整张表，看是哪几个成员 down。"
	default:
		return "oper 这一栏设备给的不是标准值，这一条不能说它是通的还是断的，只当参照。"
	}
}

// ifTypeName 只认这一张卡会碰到的几种。★ 认不出来就只报编号：
// 虚拟接口/聚合口的 down 和物理口的 down 是两个结论，猜错方向就全错了。
func ifTypeName(n int) string {
	switch n {
	case 6:
		return "物理网口"
	case 24:
		return "环回"
	case 53:
		return "虚拟接口"
	case 71:
		return "无线"
	case 136:
		return "二层 VLAN 接口"
	case 137:
		return "三层 VLAN 接口"
	case 161:
		return "聚合口（LACP）"
	case 162:
		return "三层聚合接口"
	}
	return ""
}

// 这一张卡独有的判定。★ down 的两种必须分开：一种是「去查线和模块」，
// 一种是「去问是谁关的、要不要开回来」。
const (
	snmpPortDown     = "snmp-port-down"
	snmpPortDisabled = "snmp-port-disabled"
	snmpPortNotFound = "snmp-port-not-found"
	// snmpPortErrors：口是 up 的，但这一段在错包 —— 这是「链路能用但在烂」，
	// 和「不通」的下一步完全不同（查线、模块、双工不匹配）。
	snmpPortErrors = "snmp-port-errors"
)

const (
	portsDefault = 512  // 一次最多列几个口
	portsMax     = 8192 // 框式设备堆满板卡也就这个量级
	// ifSpeed 顶格值：见到它就只知道「至少 4.29G」。
	speedMaxIfSpeed = 4294967295
	// errorsBits 是错包/丢包那四栏的位宽。**不能**跟着字节数那一档走：
	// ifXTable 只给 ifHCInOctets 这类字节数的 64 位版本，
	// ifInErrors / ifInDiscards 到 2026 年仍然是 Counter32 ——
	// 拿 64 位去相减的话，回绕那一次不是「绕回来」而是一个天文数字。
	errorsBits = 32
)

type snmpPortArgs struct {
	snmpArgs
	IfIndex int    `json:"ifIndex,omitempty"`
	Name    string `json:"name,omitempty"`
	State   string `json:"state,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	// WatchSeconds > 0 时读两遍，中间等这么久，用差值算速率和「这一段错了多少包」。
	WatchSeconds int  `json:"watchSeconds,omitempty"`
	NoCounters   bool `json:"noCounters,omitempty"`
}

var snmpPortsTool = ots.Tool{
	Name:  "net.snmp.ports",
	Class: ots.ClassRead,
	Summary: "读一台设备的端口表：开着没有、链路起来没有、跑多快、这一会儿流了多少、有没有在丢包错包。" +
		"填 ifIndex 或 name 就是点名问某一个口，这时判定才有意义：" +
		"snmp-port-down（admin 是 up、oper 是 down —— 链路真断了）、" +
		"snmp-port-disabled（admin 是 down —— 有人关着的，不是故障）、" +
		"snmp-port-errors（口是 up 但在错包）、" +
		"snmp-port-not-found（表读全了，没有点名的那个口）。" +
		"★ 不点名只列表时一律给 snmp-ok：整张表里有口 down 不是故障，没插线的空口本来就该 down。" +
		"watchSeconds 填了就读两遍算速率（32 位计数器按回绕处理，绕了不止一圈时如实不给速率）。" +
		"★ 这台不给读的那几栏整栏不出现，不是写成 0 —— 「一个错包都没有」和「读不到错包数」是两个结论。" +
		"先跑 net.snmp.probe 确认 SNMP 通不通。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr", "community"],
	  "properties": {
	    ` + snmpSchemaProps + `,
	    "ifIndex": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "点名问一个口（ifIndex）。填了就只问这一个口，不把整张表走一遍。★ 面板上的「第 5 口」不一定等于 ifIndex 5，不确定就先不填、把表列一遍对着 name 认。"},
	    "name": {"type": "string",
	      "description": "按口名点名，认面板上的写法：GE1/0/5、Gi1/0/5、GigabitEthernet1/0/5 算同一个口（字母前缀取全名的开头，数字部分必须一模一样）。★ 匹配到几个就报几个，不挑「最像的那个」—— 挑错那一次是让人去查别人的链路。"},
	    "state": {"type": "string", "enum": ["up", "down"],
	      "description": "只列这个 oper 状态的口。★ 筛选是在读回来之后筛，不减读的量；countTotal 记的是筛掉之前有几个。"},
	    "limit": {"type": "integer", "minimum": 1, "maximum": 8192,
	      "description": "最多列几个口，默认 512。撞到限量会如实写明，并且不会给「其余口都还好」这种结论。"},
	    "watchSeconds": {"type": "integer", "minimum": 0, "maximum": 300,
	      "description": "读两遍之间等几秒，用来算速率和这段时间内的丢包/错包；0 = 只读一遍，只给累计值不给速率。★ 千兆口上 32 位计数器 34 秒就绕一圈，间隔别拉太长。"},
	    "noCounters": {"type": "boolean",
	      "description": "只问状态、不问流量计数器。几百口的设备上这一档省掉大半报文（代价是没有速率那一栏）。"}
	  }
	}`),
	Invoke: doSnmpPorts,
}

// portRow 是一个口的读数（还没翻成结果形状）。
type portRow struct {
	ifIndex      int
	name         string
	descr        string
	alias        string
	ifType       int
	mtu          int
	admin        int
	oper         int
	lastChange   uint64
	upSeconds    uint64 // 距离最后一次换状态多久（sysUpTime 读到了才算得出来）
	upSecondsSet bool
	speedBps     uint64 // 最终采用的速率；0 = 不知道
	speedCapped  bool   // 只有 ifSpeed 顶格值这一个依据
	phys         []byte

	inOctets, outOctets     uint64
	inErrors, outErrors     uint64
	inDiscards, outDiscards uint64
	// ★ 有没有 64 位那一栏是**按方向**说的：不少设备只实现了 ifHCInOctets，
	//   出向仍然只给 32 位。当成一档处理的话，出向会被按错位的模数相减。
	inHC, outHC bool
	// 这一向的字节数**读到了没有**。★ 没读到不写成 0：
	//   「这个口一个字节都没跑」和「这台不给读这一栏」在现场是两个结论。
	inHas, outHas bool
	// got 记「设备真的给了哪几栏」。★ 没给的栏**不写成 0**：
	//   「一个错包都没有」和「这台不给读错包数」在现场是两个结论。
	got map[string]bool
	// haveDelta 记「这一栏真的做过两次读数相减」。★ 有累计值不等于有增量：
	//   第二遍没读到、或者这一栏是第二遍才出现的，都给不出增量。
	haveDelta map[string]bool

	// 采样之后才有：
	sampled  bool
	seconds  float64
	inBps    float64
	outBps   float64
	inRate   rateStatus // 这一向的速率算得算不得，以及**为什么**算不得
	outRate  rateStatus
	dInErr   uint64
	dOutErr  uint64
	dInDisc  uint64
	dOutDisc uint64
}

// rateStatus 是一个方向上的速率结论。
//
// ★ 三种「没有速率」必须分开：设备不给读这一栏、计数器绕得算不出来、以及
//
//	两遍用的不是同一档。前一种现场要的是「换台设备/换一栏读」，
//	后两种要的是「别信这个数」，合成一个 0 的话界面只会把人往错的方向带。
type rateStatus int

const (
	rateOK rateStatus = iota
	rateNoCounter
	rateUnreliable
)

func (s rateStatus) String() string {
	switch s {
	case rateOK:
		return "ok"
	case rateNoCounter:
		return "no-counter"
	case rateUnreliable:
		return "unreliable"
	}
	return "?"
}

func doSnmpPorts(ctx context.Context, raw json.RawMessage) (any, error) {
	var a snmpPortArgs
	if err := snmpArgsFrom(raw, &a); err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(a.State)) {
	case "", "up", "down":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "state %q 看不懂，要 up 或 down", a.State)
	}
	if a.IfIndex > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "ifIndex %d 超出 1-65535", a.IfIndex)
	}
	if a.WatchSeconds > 300 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"watchSeconds %d 太长（上限 300）—— 间隔越长，32 位计数器绕圈的概率越大，速率就越不可信",
			a.WatchSeconds)
	}
	limit := a.Limit
	if limit <= 0 {
		limit = portsDefault
	}
	if limit > portsMax {
		limit = portsMax
	}

	t, err := snmpDial(a.snmpArgs)
	if err != nil {
		return nil, err
	}
	defer t.close()

	values := t.values()
	counters := !a.NoCounters
	asked := a.IfIndex
	named := strings.TrimSpace(a.Name) != ""
	start := time.Now()

	// ── 第一步：定下来要问哪几个口 ──
	indexes, total, truncated, err := t.portTargets(ctx, asked, a.Name, limit)
	if err != nil {
		verdict, done := snmpFail(err, values)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	// ★ 点名 ifIndex 时不走表，所以「一共有几个口」是**不知道**的 ——
	//   不写这一栏，而不是写一个 0：写 0 会被看成「这台一个口都没有」。
	if asked == 0 {
		values["countTotal"] = total
	}
	values["truncated"] = truncated
	values["readLimit"] = limit
	// ★ 走到这一步设备一定答过话了：定下要问哪几个口那一步就是走表走出来的。
	//   不在这儿写，撞限量的那一次界面会变成「回话：没有」，而它明明答了 3 个口。
	values["answered"] = true
	if len(indexes) == 0 {
		// 一个都没定下来：要么是空的（设备没填 ifTable），要么是点名的没找到。
		values["read"] = total
		// ★ 这一条路上表已经走过一遍了，「等了多久」是真的 —— 不写的话界面上
		//   这一格凭空消失，看着像什么都没发生过。
		values["elapsedMs"] = time.Since(start).Milliseconds()
		if total == 0 && asked == 0 && !named {
			return portsNoData(values), nil
		}
		return portsNotFound(values, asked, a.Name, truncated), nil
	}

	// ── 第二步：读第一遍 ──
	first, err := t.getPortSet(ctx, indexes, counters)
	if err != nil {
		verdict, done := snmpFail(err, values)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	rows := assemblePorts(first, counters)
	sysUp, upErr := t.sysUpTime(ctx)
	applyUpSeconds(rows, sysUp)
	firstAt := time.Now()

	if counters {
		// ★ 一个字节数都没读到时不写这一栏：写 0 会被读成「这台用 0 位计数器」，
		//   该说的是「这台不给读流量」，而那已经在每行的 inRateWhy 里了。
		if bits := counterBits(rows); bits > 0 {
			values["counterBits"] = bits
		}
	}

	// ── 第三步：要测速率就等一下读第二遍 ──
	if a.WatchSeconds > 0 && counters {
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(a.WatchSeconds) * time.Second):
		}
		// ★ 中途被取消：第二遍必然问不通，这时候**不给速率**，
		//   而不是让 applyRates 拿一个空样本去跟第一遍相减。
		if ctx.Err() != nil {
			values["aborted"] = true
			values["sampleAborted"] = "第二次读之前这趟观测被取消了，没测到速率"
		} else {
			second, serr := t.getPortSet(ctx, indexes, true)
			seconds := time.Since(firstAt).Seconds()
			sysDown, downErr := t.sysUpTime(ctx)
			switch {
			case serr != nil:
				// 第二遍没读通：没有第二个样本就没有速率，但累计值是真的，别一起丢掉。
				values["rateUnsure"] = "第二次读没读通，这一趟算不出速率（上面那些累计值是第一次读到的）"
			case upErr != nil || downErr != nil || sysUp == 0:
				// 问不到 sysUpTime 就**不知道**设备中途重启过没有 —— 不假装没重启。
				values["rateUnsure"] = "问不到 sysUpTime，没法确认这台设备中途有没有重启，速率仅供参考"
				applyRates(rows, second, seconds)
			case sysDown < sysUp:
				values["rebooted"] = true
				values["rateUnsure"] = "这台设备在两次读之间重启过（sysUpTime 倒退），速率和增量都是假的，只给累计值"
			default:
				applyRates(rows, second, seconds)
			}
			values["sampleSeconds"] = round1(seconds)
		}
	}

	// ── 第四步：筛选 ──
	all := len(rows)
	rows = filterPortState(rows, a.State)
	if a.State != "" {
		values["stateFilter"] = a.State
	}
	values["read"] = all
	values["count"] = len(rows)
	values["ports"] = buildPortEntries(rows)
	values["elapsedMs"] = time.Since(start).Milliseconds()

	// ── 第五步：定性 ──
	switch {
	case len(rows) == 0 && (asked > 0 || named):
		// 点名了却没读到：筛掉的那种另说（那是「它不是这个状态」，不是「没这个口」）。
		if a.State != "" && all > 0 {
			return portsFilteredOut(values, total), nil
		}
		return portsNotFound(values, asked, a.Name, truncated), nil
	case (asked > 0 || named) && len(rows) == 1:
		return portsVerdict(values, rows[0]), nil
	case truncated:
		// ★ 列到一半撞限量：「这些口都还好」不成立，「别的口没问题」也不成立。
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("列到 %v 个口撞到 limit 停了，这台设备的口没有全列出来。"+
				"这一条不是「其余口都还好」：把 limit 提到 %d 再看一次才算看完这张表",
				all, portsMax)}, nil
	}
	return portsSummary(values, rows, all, a.State != ""), nil
}

// portTargets 定下来这一趟要读哪几个口，返回：要读的口、表里一共有几个口、有没有截断。
//
// ★ 点名一个口时**不走全表**：框式设备几千口，走一遍是上千个报文，
//
//	而现场问的往往就是「5 口起来了没有」。
func (t *snmpTarget) portTargets(ctx context.Context, asked int, name string,
	limit int) ([]int, int, bool, error) {
	if asked > 0 {
		return []int{asked}, 0, false, nil
	}
	indexes, total, truncated, err := t.portIndexes(ctx, limit)
	if err != nil {
		return nil, total, truncated, err
	}
	if s := strings.TrimSpace(name); s != "" {
		byName := t.portNames(ctx, indexes)
		var hit []int
		for _, n := range indexes {
			if portNameMatches(s, byName[n]) {
				hit = append(hit, n)
			}
		}
		return hit, total, truncated, nil
	}
	return indexes, total, truncated, nil
}

// portIndexes 走 ifIndex 那一列，拿到表里有哪些口（按编号升序）。
func (t *snmpTarget) portIndexes(ctx context.Context, limit int) ([]int, int, bool, error) {
	vs, truncated, err := t.client.WalkLimit(ctx, oidIfIndex, limit)
	if err != nil && len(vs) == 0 {
		return nil, 0, truncated, err
	}
	out := make([]int, 0, len(vs))
	for _, v := range vs {
		i := indexAfter(v.OID, oidIfIndex)
		if i == "" || v.Missing() || v.EndOfMib() {
			continue
		}
		n, e := strconv.Atoi(i)
		if e != nil || n <= 0 {
			continue
		}
		out = append(out, n)
	}
	sort.Ints(out)
	return out, len(out), truncated, nil
}

// portNameHit 是一个口上能用来认它的名字，外加这一条是从哪一栏来的。
//
// ★ 来源要留着：口名和备注**不能**用同一套匹配规则（见 portNameMatches）——
//
//	ifName 是有规矩的面板写法，ifAlias 是运维随手写的一句话。
type portNameHit struct {
	s     string
	alias bool
}

// portNames 按已定下来的 ifIndex 批量取名字，外加 ifAlias。
//
// ★ ifName 和 ifDescr 要**都**当候选，不能「有 ifName 就不看 ifDescr」：
//
//	思科的 ifName 写 Gi1/0/1、ifDescr 写 GigabitEthernet1/0/1，华为/H3C 反过来
//	（ifDescr 是 GE1/0/1 这种短写法）。现场抄的是哪一句都有可能，只认一句
//	就等于把另一种写法判成「没这个口」。
func (t *snmpTarget) portNames(ctx context.Context, indexes []int) map[int][]portNameHit {
	out := make(map[int][]portNameHit, len(indexes))
	add := func(column string, alias bool) {
		for n, s := range t.columnStrings(ctx, column, indexes) {
			dup := false
			for _, h := range out[n] {
				if strings.EqualFold(h.s, s) {
					dup = true
					break
				}
			}
			if !dup {
				out[n] = append(out[n], portNameHit{s: s, alias: alias})
			}
		}
	}
	add(oidIfName, false)
	add(oidIfDescr, false)
	// ★ 再补 ifAlias：运维把备注写成「配线架12-到NVR-3」时，现场抄的就是这一段。
	//   备注不能跟口名用同一套匹配规则（见 portNameMatches）。
	add(oidIfAlias, true)
	return out
}

// columnStrings 按 ifIndex 批量取一列的字符串（.1 / .2 …），给不了的口不出现。
func (t *snmpTarget) columnStrings(ctx context.Context, column string, indexes []int) map[int]string {
	out := map[int]string{}
	oids := make([]string, 0, len(indexes))
	for _, n := range indexes {
		oids = append(oids, column+"."+strconv.Itoa(n))
	}
	vbs, err := t.multiGet(ctx, oids)
	if err != nil {
		return out
	}
	for _, v := range vbs {
		i := indexAfter(v.OID, column)
		if i == "" || v.Missing() || v.EndOfMib() {
			continue
		}
		n, e := strconv.Atoi(i)
		if e != nil {
			continue
		}
		if s := printable(v.Str()); s != "" {
			out[n] = s
		}
	}
	return out
}

// portNameMatches 认面板上的写法：字母前缀可以是全名的开头，数字部分必须一模一样。
//
//	Gi1/0/5、GE1/0/5、GigabitEthernet1/0/5 都指同一个口（短写法见 portFamilies）。
//	★ 数字部分不相同的那种不放：1/0/5 和 1/0/50 是两个口，
//	  含糊匹配会把人送到别人的链路上去。
//	★ ifAlias 走另一套：那是运维随手写的一句话（「配线架12-到NVR-3」），
//	  按面板那套「编号必须一模一样」去卡它，等于这一栏白读。
//	  备注里容得下模糊匹配，是因为**匹配到的口会整排列出来**，人看得见自己挑错了；
//	  口名那边不行，因为 1/0/5 和 1/0/50 长得几乎一样，扫一眼分不出来。
func portNameMatches(want string, have []portNameHit) bool {
	w := strings.TrimSpace(want)
	wl, wn := splitPortName(w)
	if wl == "" && wn == "" {
		return false
	}
	for _, h := range have {
		if h.alias {
			if strings.Contains(strings.ToLower(h.s), strings.ToLower(w)) {
				return true
			}
			continue
		}
		hl, hn := splitPortName(h.s)
		if hl == "" && hn == "" {
			continue
		}
		if wn != "" && wn != hn {
			continue
		}
		if wn == "" {
			// 只给了字母（例如 "vlan"）：那就当成按前缀整类匹配。
			if strings.HasPrefix(hl, wl) || samePortFamily(wl, hl) {
				return true
			}
			continue
		}
		if strings.HasPrefix(hl, wl) || wl == hl || samePortFamily(wl, hl) {
			return true
		}
	}
	return false
}

// portFamilies 把面板上那些简写归到同一个全称上：Gi / GE / GigabitEthernet
// 在设备上就是同一类口，人抄哪一句的都有（思科的短写在 ifName、华为/H3C 的短写在
// ifDescr，也有整台只给长写法的）。
//
// ★ 只归一这张表里点到的写法；认不出的照样走前缀规则。猜错家族等于把人送到
//
//	另一个口上去，而编号那一段始终要一模一样，所以这里宁可少收几条。
var portFamilies = map[string]string{
	"gi": "gigabitethernet", "ge": "gigabitethernet", "gig": "gigabitethernet",
	"giga": "gigabitethernet", "gigabit": "gigabitethernet",
	"gigabiteth": "gigabitethernet", "gigabitethernet": "gigabitethernet",

	"te": "ethernet10g", "xe": "ethernet10g", "xge": "ethernet10g",
	"10ge": "ethernet10g", "10gig": "ethernet10g", "tengig": "ethernet10g",
	"tengigabit": "ethernet10g", "tengigabitethernet": "ethernet10g",

	"ce": "ethernet100g", "100ge": "ethernet100g", "100gig": "ethernet100g",
	"hundredge": "ethernet100g",

	"fa": "fastethernet", "fast": "fastethernet", "fasteth": "fastethernet",
	"fastethernet": "fastethernet",

	"eth": "ethernet", "ethernet": "ethernet",
	"mgmt": "management", "management": "management",
	"vl": "vlan", "vlan": "vlan", "vlanif": "vlan",

	"ag": "aggregation", "bagg": "aggregation", "bridge-aggregation": "aggregation",
	"po": "aggregation", "port-channel": "aggregation", "portchannel": "aggregation",
}

// samePortFamily 两种写法是不是同一类口。★ 两边都得在这张表里点过才作数 ——
//
//	只有一边认得出时宁可说不等，「GE 是 GigabitEthernet 的简写」这条知识
//	反过来用（want 是全名、have 是简写）也照样成立。
func samePortFamily(a, b string) bool {
	fa, ok1 := portFamilies[a]
	fb, ok2 := portFamilies[b]
	if !ok1 || !ok2 || fa == "" || fb == "" {
		return false
	}
	return fa == fb
}

// splitPortName 把口名拆成「字母段（小写）」和「后面的编号段」。
func splitPortName(s string) (letters, tail string) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c == '/' || c == '.' || c == ':' {
			return strings.ToLower(s[:i]), s[i:]
		}
	}
	return strings.ToLower(s), ""
}

// getPortSet 按 ifIndex 直取这一张表关心的那几栏。
//
// ★ 走 multiGet 而不是 walk：走表会把整张表都拉回来，而这里只需要点名的那几个口。
func (t *snmpTarget) getPortSet(ctx context.Context, indexes []int,
	counters bool) (map[int]map[string]snmp.VarBind, error) {
	cols := []string{oidIfDescr, oidIfType, oidIfMtu, oidIfSpeed, oidIfPhysAddress,
		oidIfAdminStatus, oidIfOperStatus, oidIfLastChange, oidIfName,
		oidIfHighSpeed, oidIfAlias}
	if counters {
		cols = append(cols, oidIfHCInOctets, oidIfHCOutOctets,
			oidIfInOctets, oidIfOutOctets, oidIfInErrors, oidIfOutErrors,
			oidIfInDiscards, oidIfOutDiscards)
	}
	oids := make([]string, 0, len(indexes)*len(cols))
	for _, c := range cols {
		for _, n := range indexes {
			oids = append(oids, c+"."+strconv.Itoa(n))
		}
	}
	out := make(map[int]map[string]snmp.VarBind, len(indexes))
	vbs, err := t.multiGet(ctx, oids)
	// ★ 错误一律往上交给 snmpFail 定性，这里不吞：
	//   点名一个口时这是这趟观测的**第一次**报文往返 —— 团体名错了也走到这里，
	//   吞掉的话界面会变成「这台没有这个接口号」，而该说的是「你给的团体名不对」。
	if err != nil {
		return out, err
	}
	for _, v := range vbs {
		if v.Missing() || v.EndOfMib() {
			continue
		}
		col, idx, ok := splitColumnOID(v.OID)
		if !ok {
			continue
		}
		n, e := strconv.Atoi(idx)
		if e != nil {
			continue
		}
		if out[n] == nil {
			out[n] = map[string]snmp.VarBind{}
		}
		out[n][col] = v
	}
	return out, nil
}

// splitColumnOID 把「列 OID.行索引」拆成列和行。★ 只用在这里的定长数字索引上；
// ifTable 的行索引就是 ifIndex 一个数，不像转发表那样多节。
func splitColumnOID(oid string) (column, index string, ok bool) {
	o := strings.TrimPrefix(oid, ".")
	i := strings.LastIndexByte(o, '.')
	if i < 0 {
		return "", "", false
	}
	return o[:i], o[i+1:], true
}

// assemblePorts 把「栏 → 值」拼成一个口的读数。
func assemblePorts(byIdx map[int]map[string]snmp.VarBind, counters bool) []portRow {
	indexes := make([]int, 0, len(byIdx))
	for n := range byIdx {
		indexes = append(indexes, n)
	}
	sort.Ints(indexes)
	out := make([]portRow, 0, len(indexes))
	for _, n := range indexes {
		cols := byIdx[n]
		r := portRow{ifIndex: n, got: make(map[string]bool, len(cols)),
			haveDelta: make(map[string]bool, 4)}
		for c := range cols {
			r.got[c] = true // getPortSet 已经把 noSuchInstance / endOfMib 那几类丢掉了，剩下的都是真给了值的
		}
		// multiGet 回来的键就是列 OID（splitColumnOID 只砍掉最后那段行索引），
		// 所以直接按列取，不做「差不多是这个后缀」那种模糊匹配 ——
		// 模糊匹配会把 ifSpeed(5) 和 ifInOctets(10) 这类尾巴相同的栏配错行。
		get := func(col string) (snmp.VarBind, bool) {
			v, ok := cols[col]
			return v, ok
		}
		if v, ok := get(oidIfName); ok {
			r.name = printable(v.Str())
		}
		if v, ok := get(oidIfDescr); ok {
			r.descr = printable(v.Str())
		}
		if v, ok := get(oidIfAlias); ok {
			r.alias = printable(v.Str())
		}
		if v, ok := get(oidIfType); ok {
			r.ifType = int(v.IntOr0())
		}
		if v, ok := get(oidIfMtu); ok {
			r.mtu = int(v.IntOr0())
		}
		if v, ok := get(oidIfAdminStatus); ok {
			r.admin = int(v.IntOr0())
		}
		if v, ok := get(oidIfOperStatus); ok {
			r.oper = int(v.IntOr0())
		}
		if v, ok := get(oidIfLastChange); ok {
			r.lastChange = v.UintOr0()
		}
		if v, ok := get(oidIfPhysAddress); ok {
			r.phys = append([]byte(nil), v.Val...)
		}
		// 速率：ifHighSpeed（单位 Mbps）优先。★ ifSpeed 是 Gauge32，
		// RFC 2863 写明带宽超过 4294967295 时它**就报这个顶格值**，
		// 所以只有顶格值那一个依据时，这一栏是「至少 4.29G」而不是「4.29G」。
		if v, ok := get(oidIfHighSpeed); ok {
			if h := v.UintOr0(); h > 0 {
				r.speedBps = h * 1000000
			}
		}
		if v, ok := get(oidIfSpeed); ok {
			s := v.UintOr0()
			switch {
			case r.speedBps > 0:
				// ifHighSpeed 已经给了准数，这一栏只是互相印证，不覆盖它。
			case s == speedMaxIfSpeed:
				r.speedCapped = true
			case s > 0:
				r.speedBps = s
			}
		}
		if counters {
			in, inHC, haveIn := counterOf(cols, oidIfHCInOctets, oidIfInOctets)
			outv, outHC, haveOut := counterOf(cols, oidIfHCOutOctets, oidIfOutOctets)
			r.inOctets, r.outOctets = in, outv
			r.inHC, r.outHC = inHC, outHC
			r.inHas, r.outHas = haveIn, haveOut
			if v, ok := cols[oidIfInErrors]; ok {
				r.inErrors = v.UintOr0()
			}
			if v, ok := cols[oidIfOutErrors]; ok {
				r.outErrors = v.UintOr0()
			}
			if v, ok := cols[oidIfInDiscards]; ok {
				r.inDiscards = v.UintOr0()
			}
			if v, ok := cols[oidIfOutDiscards]; ok {
				r.outDiscards = v.UintOr0()
			}
		}
		out = append(out, r)
	}
	return out
}

// counterOf 取字节数的累计量：优先 64 位那一栏，没有再退 32 位。
// 第三个返回值是「这一向到底读到没有」—— 一个都没读到时不能当成 0。
// ★ 两栏都给时**必须固定用同一栏做差** —— 拿 64 位的现在值减 32 位的历史值
//
//	会算出一个巨大的假速率。
func counterOf(cols map[string]snmp.VarBind, hcCol, col32 string) (uint64, bool, bool) {
	if v, ok := cols[hcCol]; ok && !v.Missing() && v.Tag == snmp.TagCounter64 {
		return v.UintOr0(), true, true
	}
	if v, ok := cols[col32]; ok && !v.Missing() {
		return v.UintOr0(), false, true
	}
	return 0, false, false
}

// sysUpTime 问一眼设备开了多久（TimeTicks，1/100 秒）。
//
// ★ 两个用处：一是「这个口起来了多久」（ifLastChange 是同一把尺子上的时刻），
//
//	二是测速率时判断**中途有没有重启**（倒退就是重启过）。
func (t *snmpTarget) sysUpTime(ctx context.Context) (uint64, error) {
	v, err := t.client.GetOne(ctx, oidSysUpTime)
	if err != nil {
		return 0, err
	}
	if v.Missing() {
		return 0, nil
	}
	return v.UintOr0(), nil
}

// applyUpSeconds 给每个口算「最后一次换状态是多久以前」。
//
// ★ 这是查**口在翻**（flapping）最省事的一格：刚起来 40 秒 和 起来 30 天
//
//	是两个完全不同的结论，而设备不会主动告诉你它刚才翻过。
//	sysUpTime 的刻度是 497 天绕一圈，绕过的话不给这个数（不给一个看着合理的错数）。
func applyUpSeconds(rows []portRow, sysUp uint64) {
	if sysUp == 0 {
		return
	}
	for i := range rows {
		if rows[i].lastChange == 0 || rows[i].lastChange > sysUp {
			continue
		}
		secs := (sysUp - rows[i].lastChange) / 100
		rows[i].upSecondsSet = true
		rows[i].upSeconds = secs
	}
}

// applyRates 用第二遍读回来的值算速率与增量。
func applyRates(rows []portRow, second map[int]map[string]snmp.VarBind, seconds float64) {
	if seconds <= 0 {
		return
	}
	for i := range rows {
		r := &rows[i]
		cols, ok := second[r.ifIndex]
		if !ok {
			continue
		}
		r.sampled = true
		r.seconds = seconds
		// ★ 速率按方向各算各的：不少设备只实现 ifHCInOctets，出向仍然只有 32 位，
		//   当成一档处理就会拿错位的模数去相减。
		r.inBps, r.inRate = dirRate(r.inOctets, r.inHC, r.inHas, cols,
			oidIfHCInOctets, oidIfInOctets, seconds, r.speedBps)
		r.outBps, r.outRate = dirRate(r.outOctets, r.outHC, r.outHas, cols,
			oidIfHCOutOctets, oidIfOutOctets, seconds, r.speedBps)
		// ★ 错包/丢包那四栏永远按 32 位算：ifXTable 只把字节数做成了 64 位
		//   （ifHCInOctets），错误和丢弃的计数器到今天仍然是 Counter32。
		//   跟着字节数那一档走的话，回绕那一次算出来是 1.8×10¹⁹ 个错包。
		//   另一条：只有第一遍读到过这一栏才算得出增量。第一遍没读到就没有起点，
		//   这时候报「涨了 N 个」是把「不知道」说成了结论。
		countDelta := func(col string, prev, delta *uint64) {
			v, ok := cols[col]
			if !ok || v.Missing() {
				return
			}
			if r.got[col] {
				*delta = wrapDelta(*prev, v.UintOr0(), errorsBits)
				r.haveDelta[col] = true
			}
			*prev = v.UintOr0()
			r.got[col] = true
		}
		countDelta(oidIfInErrors, &r.inErrors, &r.dInErr)
		countDelta(oidIfOutErrors, &r.outErrors, &r.dOutErr)
		countDelta(oidIfInDiscards, &r.inDiscards, &r.dInDisc)
		countDelta(oidIfOutDiscards, &r.outDiscards, &r.dOutDisc)
		// 累计值换成后一遍的：界面上「一共跑了多少」要的是现在的数。
		if in, hc, have := counterOf(cols, oidIfHCInOctets, oidIfInOctets); have {
			r.inOctets, r.inHC = in, hc
		}
		if out, hc, have := counterOf(cols, oidIfHCOutOctets, oidIfOutOctets); have {
			r.outOctets, r.outHC = out, hc
		}
	}
}

// dirRate 算一个方向的速率。
func dirRate(prev uint64, prevHC, prevHas bool, cols map[string]snmp.VarBind, hcCol, col32 string,
	seconds float64, speedBps uint64) (float64, rateStatus) {
	cur, curHC, have := counterOf(cols, hcCol, col32)
	if !prevHas || !have {
		return 0, rateNoCounter
	}
	// ★ 两遍用的必须同一档：跨档相减（64 位的现在值减 32 位的历史值）算出来是假数。
	if curHC != prevHC {
		return 0, rateUnreliable
	}
	bits := 32
	if curHC {
		bits = 64
	}
	// ★ 64 位那一档不可能在人对着屏幕的这段时间里绕回（万兆要 48 年，400G 也要 4.8 年）：
	//   它变小了就是计数器被重置过（不是设备重启，重启那条路看 sysUpTime）。
	//   让它减下去会得到一个 1.8e20 的「速率」——uint64 自己绕了一圈。
	//   32 位那一档相反，变小常常正是绕了一圈，所以只有 64 位这条路判「算不准」。
	if curHC && cur < prev {
		return 0, rateUnreliable
	}
	bps := octetRate(prev, cur, bits, seconds)
	// 32 位那一档：算出来的速率超过线速，说明绕了不止一圈 ——
	// 一圈和两圈在计数器上看不出区别，那就不能说速率是 X。
	if bits == 32 && speedBps > 0 && bps > 1.2*float64(speedBps) {
		return 0, rateUnreliable
	}
	return bps, rateOK
}

// wrapDelta 算两个计数器读数之间走了多少（按 bits 位取模）。
//
// ★ 直接相减遇到回绕会变成一个大得离谱的无符号数，
//
//	取模之后正好是「绕了一小段」的真实增量 —— 这是 Counter32 唯一正确的算法。
func wrapDelta(prev, cur uint64, bits int) uint64 {
	if bits >= 64 {
		return cur - prev // uint64 自己就会绕，正好是模 2^64
	}
	m := uint64(1) << uint(bits)
	return (cur + m - prev) % m
}

func octetRate(prev, cur uint64, bits int, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return float64(wrapDelta(prev, cur, bits)) * 8 / seconds
}

// filterPortState 按 oper 筛。★ up 只认 up(1)，其余（含 dormant、lowerLayerDown）都算 down：
// 这一档要回答的是「这个口现在能不能正常转发」。
func filterPortState(rows []portRow, state string) []portRow {
	s := strings.ToLower(strings.TrimSpace(state))
	if s == "" {
		return rows
	}
	out := make([]portRow, 0, len(rows))
	for _, r := range rows {
		up := r.oper == 1
		if (s == "up") == up {
			out = append(out, r)
		}
	}
	return out
}

func buildPortEntries(rows []portRow) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		e := map[string]any{"ifIndex": r.ifIndex}
		name := r.displayName()
		if name != "" {
			e["name"] = name
		}
		if r.descr != "" && r.descr != name {
			e["descr"] = r.descr
		}
		if r.alias != "" {
			e["alias"] = r.alias
		}
		if r.ifType > 0 {
			e["type"] = r.ifType
			if k := ifTypeName(r.ifType); k != "" {
				e["kind"] = k
			}
		}
		if r.mtu > 0 {
			e["mtu"] = r.mtu
		}
		if a := adminStatusName(r.admin); a != "" {
			e["admin"] = a
		}
		if o := operStatusName(r.oper); o != "" {
			e["oper"] = o
			e["operMeaning"] = operMeaning(r.oper)
		}
		switch {
		case r.speedCapped:
			e["speedAtLeast"] = uint64(speedMaxIfSpeed)
			e["speedText"] = "至少 4.29G（ifSpeed 顶格，这台没给 ifHighSpeed）"
		case r.speedBps > 0:
			e["speedMbps"] = r.speedBps / 1000000
		}
		if len(r.phys) > 0 {
			e["mac"] = formatMAC(r.phys, ":")
		}
		if r.upSecondsSet {
			e["sinceChangeSeconds"] = r.upSeconds
			e["sinceChange"] = humanUptime(r.upSeconds)
		}
		// 字节数：读到哪一向写哪一向，而且按档位分开叫法。
		// ★ 32 位那一栏的名字带 32 —— 混在 inOctets 一个键里，界面会拿 64 位的
		//   口径去显示一个随时会绕回的数。
		if r.inHas {
			octetKey(r.inHC, "inOctets", "inOctets32", r.inOctets, e)
		}
		if r.outHas {
			octetKey(r.outHC, "outOctets", "outOctets32", r.outOctets, e)
		}
		for _, c := range counterList {
			if r.got[c.col] {
				e[c.key] = c.of(r)
			}
		}
		if r.sampled {
			// ★ 这一档同时给出去：界面要按它分「不给读 / 算不准」两个短标签。
			//   不给人话以外的档，界面就只能去正则那句人话 —— 文案改一个字，
			//   两种下一步相反的病就会被分到一个标签里。
			e["inRateStatus"] = r.inRate.String()
			e["outRateStatus"] = r.outRate.String()
			if r.inRate == rateOK {
				e["inMbps"] = round4(r.inBps / 1e6)
			} else {
				e["inRateWhy"] = rateWhy(r.inRate)
			}
			if r.outRate == rateOK {
				e["outMbps"] = round4(r.outBps / 1e6)
			} else {
				e["outRateWhy"] = rateWhy(r.outRate)
			}
			for _, c := range deltaList {
				if r.haveDelta[c.col] {
					e[c.key] = c.of(r)
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// octetKey 按计数器档位选键名。
func octetKey(hc bool, key64, key32 string, v uint64, e map[string]any) {
	if hc {
		e[key64] = v
		return
	}
	e[key32] = v
}

// counterList / deltaList：累计值和增量各写哪几个键。
// ★ 分开两份是因为「读到了」和「算得出增量」是两件事（见 portRow.haveDelta）。
type counterKey struct {
	col string
	key string
	of  func(portRow) uint64
}

var (
	counterList = []counterKey{
		{oidIfInErrors, "inErrors", func(r portRow) uint64 { return r.inErrors }},
		{oidIfOutErrors, "outErrors", func(r portRow) uint64 { return r.outErrors }},
		{oidIfInDiscards, "inDiscards", func(r portRow) uint64 { return r.inDiscards }},
		{oidIfOutDiscards, "outDiscards", func(r portRow) uint64 { return r.outDiscards }},
	}
	deltaList = []counterKey{
		{oidIfInErrors, "inErrorsDelta", func(r portRow) uint64 { return r.dInErr }},
		{oidIfOutErrors, "outErrorsDelta", func(r portRow) uint64 { return r.dOutErr }},
		{oidIfInDiscards, "inDiscardsDelta", func(r portRow) uint64 { return r.dInDisc }},
		{oidIfOutDiscards, "outDiscardsDelta", func(r portRow) uint64 { return r.dOutDisc }},
	}
)

// rateWhy 是「这一向为什么没有速率」的人话。界面直接显示，不再猜。
func rateWhy(s rateStatus) string {
	switch s {
	case rateNoCounter:
		return "这台不给读这一向的字节数"
	case rateUnreliable:
		return "计数器对不上（绕了不止一圈、被重置过，或者两遍用的不是同一档），这个数不敢给"
	}
	return ""
}

// displayName 优先给人家面板上那个写法。★ ifName 在不少设备上就是空的，
// 这时 ifDescr 才是「GE1/0/5」，反过来则要用 ifName —— 两个都给，界面不用猜。
func (r portRow) displayName() string {
	if r.name != "" {
		return r.name
	}
	return r.descr
}

func (r portRow) errorDelta() uint64 {
	return r.dInErr + r.dOutErr
}

func (r portRow) discardDelta() uint64 {
	return r.dInDisc + r.dOutDisc
}

// counterBits 报这一张表用的是几位计数器。
//
// ★ 短板口径：只要有一向只读到 32 位就报 32 —— 混用的设备很常见（只实现
//
//	ifHCInOctets，出向仍是 Counter32），报 64 会让人以为哪一向都不会绕回。
//	一个字节数都没读到时报 0：那是「不知道用几位」，不是「用 32 位」。
func counterBits(rows []portRow) int {
	seen := false
	for _, r := range rows {
		for _, d := range []struct {
			has bool
			hc  bool
		}{{r.inHas, r.inHC}, {r.outHas, r.outHC}} {
			if !d.has {
				continue
			}
			seen = true
			if !d.hc {
				return 32
			}
		}
	}
	if !seen {
		return 0
	}
	return 64
}

// portsVerdict 点名一个口时的定性。
//
// ★ 只有点名才给 down 码：整张表里本来就该有空口是 down 的。
func portsVerdict(values map[string]any, r portRow) ots.Verdict {
	switch {
	case r.admin != 0 && r.admin != 1:
		return ots.Verdict{Code: snmpPortDisabled, Values: values,
			Note: fmt.Sprintf("%s 在管理上是 %s —— 这是有人关掉的，不是链路故障。"+
				"要恢复得去设备上开回来（本工具只读，不改配置）。",
				r.displayName(), adminStatusName(r.admin))}
	case r.oper == 0:
		// 状态那一栏压根没读到：不给「它是 up/down」的任何结论。
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("%s 读到了，但 admin/oper 这两栏设备没给 —— "+
				"这一条不能说它是通的还是断的，只看结果里读到的那几栏。", r.displayName())}
	case r.oper != 1:
		return ots.Verdict{Code: snmpPortDown, Values: values,
			Note: fmt.Sprintf("%s 管理上是开着的（admin %s），链路上是 %s —— %s。%s",
				r.displayName(), adminStatusName(r.admin), operStatusName(r.oper),
				operMeaning(r.oper), downAdvice(r.oper))}
	case r.sampled && r.errorDelta() > 0:
		return ots.Verdict{Code: snmpPortErrors, Values: values,
			Note: fmt.Sprintf("%s 是 up 的，可这一段（%.0f 秒）错了 %v 个包、丢了 %v 个 —— "+
				"链路能用但在烂。最常见的是线或模块在坏、两端双工/速率不匹配（一头自协商一头强制最容易出这个）。",
				r.displayName(), r.seconds, r.errorDelta(), r.discardDelta())}
	default:
		extra := ""
		if r.upSecondsSet && r.upSeconds < 300 {
			extra = fmt.Sprintf("★ 它是 %s前才换的状态 —— 刚翻过，这种要接着看它还会不会再翻。",
				r.sinceChangeText())
		}
		// ★ 「这一趟为什么没有速率」要写进这一句话里：note 是人家复制走的那一行，
		//   只写「up、速率 1000M」而没提「没测到速率」，看着就像真的测过而且是 0。
		extra += sampleLost(values)
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("%s：admin %s / oper %s，速率 %s。%s",
				r.displayName(), adminStatusName(r.admin), operStatusName(r.oper),
				r.speedText(), extra)}
	}
}

// portsFilteredOut 点名 + 按状态筛，把筛到的那个口筛掉了：这本身就是答案。
//
// tableTotal 是「这趟顺带知不知道整张表有几个口」：按 ifIndex 直取时不知道（0），
// 按名字查走的是整张索引表，知道。
//
//	★ 不知道就不许报数 ——「一共 1 个」看着像在说这台只有一个口，那是另一种结论。
func portsFilteredOut(values map[string]any, tableTotal int) ots.Verdict {
	scope := ""
	if tableTotal > 1 {
		scope = fmt.Sprintf("（这张表一共 %v 个口）", tableTotal)
	}
	return ots.Verdict{Code: snmpOk, Values: values,
		Note: fmt.Sprintf("这个口读到了%s，但它现在的 oper 状态不是 %v 那一档，所以列表是空的。"+
			"★ 「被筛掉」不等于「没有这个口」，也不等于「设备不通」。",
			scope, values["stateFilter"])}
}

func (r portRow) speedText() string {
	switch {
	case r.speedCapped:
		return "至少 4.29G（问不出准数）"
	case r.speedBps > 0:
		return fmt.Sprintf("%dM", r.speedBps/1000000)
	}
	return "没读到"
}

func (r portRow) sinceChangeText() string {
	if r.upSecondsSet {
		return humanUptime(r.upSeconds)
	}
	return "很久以前"
}

// portsNotFound：点名要的那个口没读到。★ 「没读到」的三种口径不能揉成一句：
//
//	按 ifIndex 直取（没走表，所以不知道一共有几个口）、
//	走表筛名字（走全了 ⇒ 这台确实没这个名字的口）、
//	走表撞到 limit（没走全 ⇒ 「没这个口」这句话不成立）。
func portsNotFound(values map[string]any, asked int, name string, truncated bool) ots.Verdict {
	which := "点名的这个口"
	switch {
	case asked > 0:
		which = "ifIndex " + strconv.Itoa(asked)
	case strings.TrimSpace(name) != "":
		which = "叫 " + strings.TrimSpace(name) + " 的口（按面板写法认前缀和编号）"
	}
	values["ports"] = []map[string]any{}
	if asked > 0 {
		return ots.Verdict{Code: snmpPortNotFound, Values: values,
			Note: fmt.Sprintf("按索引直取 ifIndex %d，设备一栏都没给 —— 这台没有这个接口号。"+
				"★ 面板上的「第 %d 口」在很多设备上并不等于 ifIndex %d（编号按槽位排，还有子接口插号）。"+
				"不带 ifIndex 把整张表列一遍，对着 name 认那个口真正的编号。", asked, asked, asked)}
	}
	if truncated {
		values["truncated"] = true
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("读了 %v 个口撞到 limit 就停了，里面没有%s —— 这不是「这台没这个口」。"+
				"把 limit 提到 %d 再看一次才算看完这张表", values["read"], which, portsMax)}
	}
	return ots.Verdict{Code: snmpPortNotFound, Values: values,
		Note: fmt.Sprintf("表读全了（%v 个口），里面没有%s。两件要一起看："+
			"ifIndex 和面板编号在不少设备上就是不相等的（编号按槽位排），"+
			"其次是这个口可能被设备藏进了别的视图（同一台设备上不同团体名能看见的表可以不一样）。",
			values["read"], which)}
}

// portsNoData：设备活着但 ifTable 是空的。
func portsNoData(values map[string]any) ots.Verdict {
	values["answered"] = true // 这一条是走表走出来的：设备确实答过话，只是这张表没填
	return ots.Verdict{Code: snmpNoData, Values: values,
		Note: "ifTable 一条都没给（走的是一栏一栏问，不是一棵子树）。" +
			"要么这台设备的视图/权限没放行接口组（这时 net.snmp.probe 照样能读通系统组），" +
			"要么它压根不按 IF-MIB 填接口（有些私有 MIB 的实现会这样，得按厂商那棵去读）。" +
			"★ 这不是「设备不通」：它答过话了。"}
}

// portsSummary 整张表的收口：给多少个口、多少个 down、多少个被关着。
//
// ★ 判定一律给 snmp-ok：表里有 down 的口不是故障（空口本来就该 down）。
//
//	把 down 数写进 note，让人自己判断哪个 down 是他没想到的。
func portsSummary(values map[string]any, rows []portRow, all int, filtered bool) ots.Verdict {
	var up, down, shut int
	var errPorts, flapPorts []string
	for _, r := range rows {
		switch {
		case r.admin != 0 && r.admin != 1:
			shut++
		case r.oper == 1:
			up++
		case r.oper != 0:
			down++
		}
		if r.errorDelta() > 0 {
			errPorts = append(errPorts, r.displayName())
		}
		// ★ 五分钟内换过状态的口单独列出来：这是查「偶尔断一下」最省事的一格，
		//   而设备不会主动告诉你它刚才翻过 —— 只能拿 ifLastChange 跟 sysUpTime 比。
		if r.upSecondsSet && r.upSeconds < 300 {
			flapPorts = append(flapPorts, fmt.Sprintf("%s（%s前）", r.displayName(), r.sinceChangeText()))
		}
	}
	values["up"] = up
	values["down"] = down
	values["adminDown"] = shut
	if len(errPorts) > 0 {
		values["errorPorts"] = errPorts
	}
	if len(flapPorts) > 0 {
		values["recentlyChanged"] = flapPorts
	}
	say := fmt.Sprintf("%d 个口：%d 个在转发、%d 个没链路、%d 个是被关着的。",
		len(rows), up, down, shut)
	switch {
	case filtered:
		say += fmt.Sprintf("（这是按 state 筛过的，筛之前一共 %d 个）", all)
	case down > 0:
		say += "★ 「没链路」这一栏里含没插线的空口，它不是故障清单 —— 要判断哪一个，点名再问一次。"
	}
	if len(errPorts) > 0 {
		say += fmt.Sprintf(" 这一段在错包的口：%s。", strings.Join(errPorts, "、"))
	}
	if len(flapPorts) > 0 {
		say += fmt.Sprintf(" 五分钟内换过状态的口：%s —— 「偶尔断一下」先看这几个。",
			strings.Join(flapPorts, "、"))
	}
	say += " " + sampleLost(values)
	return ots.Verdict{Code: snmpOk, Values: values, Note: strings.TrimSpace(say)}
}

// sampleLost 说清这一趟「测了速率却没有速率」是为什么。
//
// ★ 三种情况必须分开：这台重启过（数要重新攒）、第二遍没读通（要问为什么不通）、
//
//	这趟观测中途被取消（重问一次就行）。写成一句「没测到」会让人去查一条好着的线。
func sampleLost(values map[string]any) string {
	switch s, _ := values["rateUnsure"].(string); {
	case values["rebooted"] == true:
		return "两次读之间这台重启过（sysUpTime 倒退），计数器被清零了，所以这一趟没有速率和增量。"
	case s != "":
		return s + "。"
	case values["sampleAborted"] != nil:
		return "第二次读之前这趟观测被取消了，没测到速率 —— 重问一次就有。"
	}
	return ""
}

// round4 留给速率：Mbps 下面还要看到小数点后四位（0.0012 Mbps 是一个真的在喘的口）。
// round1 在 mtr.go 里已经有一份，这里不重复声明。
func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
