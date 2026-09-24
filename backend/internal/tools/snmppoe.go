package tools

// ── net.snmp.poe ──
//
// 这一张卡回答的是「这个口给不给供电、现在给着没有、整台的电源池还剩多少」。
// 现场问它的那一句通常是：「摄像头插上去不亮 —— 是我这台交换机没给电，还是它没来要电？」
//
// ★★ 栏位、单位、枚举全部照 RFC 3621（POWER-ETHERNET-MIB）原文抄过。
//	五件最容易混、而下一步完全不同的事：
//
//	① **PoE 在这棵树里有两个层级**：整台的电源池（pethMainPseTable：额定功率、
//	  实测在耗多少、总开关）和单个口（pethPsePortTable）。池子是 off/faulty 时，
//	  口那一栏写什么都不是这个口自己的事 —— 所以池子先读、而且压过口。
//	② **adminEnable 和 detectionStatus 是两个数**。前者是「这个口允不允许供电」
//	  （有人把它关了），后者是「它现在在不在供」。两者都指向「没供」时下一步查的
//	  配置还不一样：前者去问是谁关的，后者是设备自己把它排除在 PoE 之外的。
//	③ **行索引是两段：{group, port}**。group 是堆叠里的机箱 / 机架里的模块，
//	  RFC 规定非模块化设备必须用 1。★ RFC 3621 里**没有** ifIndex ↔
//	  pethPsePortIndex 的映射，所以「按接口编号问 PoE」只能是猜：
//	  界面上要写成猜的，并把这一行自己的组号/口号一并给出，让人能核对。
//	④ **等级（class）只在供电中有效**，这是 RFC 原文写明的（valid only while
//	  pethPsePortDetectionStatus is reporting deliveringPower）。口不在供电时
//	  给它挂一句「class2 ≈ 7W」，是把一个未定义的值当成这个 PD 的功率。
//	⑤ **那五个计数器是从开机攒到现在的**（MPS 消失 / 非法签名 / 拒绝供电 /
//	  过载 / 短路）。要说「刚才那一下被踢了」必须连读两遍看增量 ——
//	  所以有 watchSeconds，而且两遍之间比 sysUpTime：倒退了就是重启过，
//	  计数器被清零过，相减得到的是一个看着合理的假数。
//
// ★ 这一张卡**给不出「某个口现在用了几瓦」**：RFC 3621 只有整台电源池的实测值，
//   单个口只有等级档，而等级档换算成瓦还要看 802.3 的版本（af 和 at 同号不同功率）。
//   界面上不许造这个数。同理这棵树里没有 class5-8（at/bt 的等级），
//   设备在 class 那一栏给出五档以外的值时只报编号、不换算。

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
)

// POWER-ETHERNET-MIB。pethPsePortTable 的索引是 {pethPsePortGroupIndex,
// pethPsePortIndex} 两段，pethMainPseTable 只有一段 {pethMainPseGroupIndex}。
const (
	pethArc          = "1.3.6.1.2.1.105" // powerEthernetMIB ::= { mib-2 105 }
	pethPsePortEntry = "1.3.6.1.2.1.105.1.1.1"
	pethMainPseEntry = "1.3.6.1.2.1.105.1.3.1.1"

	oidPethAdminEnable  = pethPsePortEntry + ".3"  // TruthValue：true=允许供
	oidPethPairsControl = pethPsePortEntry + ".4"  // TruthValue：能不能切线对
	oidPethPowerPairs   = pethPsePortEntry + ".5"  // signal(1) / spare(2)
	oidPethDetectStatus = pethPsePortEntry + ".6"  // 这张表的主干：RFC 要求必给
	oidPethPriority     = pethPsePortEntry + ".7"  // critical(1)/high(2)/low(3)
	oidPethMPSAbsent    = pethPsePortEntry + ".8"  // 供着供着掉电（tmpdo_timer_done）
	oidPethPortType     = pethPsePortEntry + ".9"  // 运维手写的「这口上挂的什么」
	oidPethClass        = pethPsePortEntry + ".10" // class0(1)..class4(5)
	oidPethBadSignature = pethPsePortEntry + ".11"
	oidPethDenied       = pethPsePortEntry + ".12"
	oidPethOverLoad     = pethPsePortEntry + ".13"
	oidPethShort        = pethPsePortEntry + ".14"

	oidPethMainPower       = pethMainPseEntry + ".2" // Gauge32，单位**瓦**
	oidPethMainOperStatus  = pethMainPseEntry + ".3" // on(1)/off(2)/faulty(3)
	oidPethMainConsumption = pethMainPseEntry + ".4" // Gauge32，实测瓦
	oidPethMainThreshold   = pethMainPseEntry + ".5" // Integer32 1..99，%
)

// pethColumnName 在「这棵子树没按我们要的方式给」时用：把设备给回来的栏翻回名字，
// 好把「它一个口都没供着」和「它只放行了其中几栏」分开说。
var pethColumnName = map[string]string{
	oidPethAdminEnable:     "pethPsePortAdminEnable（这个口允不允许供电）",
	oidPethPairsControl:    "pethPsePortPowerPairsControlAbility（能不能切线对）",
	oidPethPowerPairs:      "pethPsePortPowerPairs（用哪一对线供）",
	oidPethDetectStatus:    "pethPsePortDetectionStatus（现在在不在供）",
	oidPethPriority:        "pethPsePortPowerPriority（预算不够时先断谁）",
	oidPethMPSAbsent:       "pethPsePortMPSAbsentCounter（供电中掉了几次）",
	oidPethPortType:        "pethPsePortType（这口上挂的什么，运维手写）",
	oidPethClass:           "pethPsePortPowerClassifications（等级）",
	oidPethBadSignature:    "pethPsePortInvalidSignatureCounter",
	oidPethDenied:          "pethPsePortPowerDeniedCounter（插上来被拒了几次）",
	oidPethOverLoad:        "pethPsePortOverLoadCounter",
	oidPethShort:           "pethPsePortShortCounter",
	oidPethMainPower:       "pethMainPsePower（额定功率）",
	oidPethMainOperStatus:  "pethMainPseOperStatus（总开关）",
	oidPethMainConsumption: "pethMainPseConsumptionPower（实测在耗）",
	oidPethMainThreshold:   "pethMainPseUsageThreshold（告警阈值）",
}

// 这一张卡独有的判定。★ 每一条的下一步都不一样，能揉成「PoE 不行」的话就白做了。
const (
	// 电源池的总开关关着：整台的口都不会供电，不用逐个看。
	snmpPoeOff = "snmp-poe-off"
	// 使能栏是 false（有人关的），或者使能开着而设备自己把它排除在 PoE 之外。
	// 两种都不该去查线，但查的配置不一样 —— 分开写在 note 里，不合成一句。
	snmpPoeDisabled = "snmp-poe-disabled"
	// 在检测、没供上：没插 / PD 不合规 / 要的电超档，三种同形，靠计数器分。
	snmpPoeSearching = "snmp-poe-searching"
	snmpPoeFault     = "snmp-poe-fault"
	// 电源池自己报 faulty：这是电源模块/硬件的事，和「某个口测出错」两码。
	snmpPoePseFault = "snmp-poe-pse-fault"
	// 余量已经紧了：下一个 PD 插上来会被拒绝。
	snmpPoeBudget   = "snmp-poe-budget"
	snmpPoeNotFound = "snmp-poe-not-found"
)

const (
	poeDefault = portsDefault // 一次最多列几个 PoE 口
	poeMax     = portsMax     // 和端口表同一档限量口径，不另立一个数
	// 这棵子树探测用的限量：只为看清「它给了哪几栏」，读到几十条就够说清了。
	poeProbeLimit = 64
)

type snmpPoeArgs struct {
	snmpArgs
	// ★ 这一对是 PoE 表自己的两段索引，跟上面那个「port」（SNMP 的 UDP 端口）
	//   不是一回事，所以键名刻意带上 Index：两个都叫 port 的话，JSON 解码时
	//   外层赢，用户填的 UDP 端口会被当成 PoE 口编号 —— 一个说不出口的错。
	GroupIndex int `json:"groupIndex,omitempty"`
	PortIndex  int `json:"portIndex,omitempty"`
	IfIndex    int `json:"ifIndex,omitempty"`
	// 按 pethPsePortType 那一栏找（那一栏本来是运维手写的「这口上挂的什么」）。
	Name         string `json:"name,omitempty"`
	State        string `json:"state,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	WatchSeconds int    `json:"watchSeconds,omitempty"`
	NoCounters   bool   `json:"noCounters,omitempty"`
}

var snmpPoeTool = ots.Tool{
	Name:  "net.snmp.poe",
	Class: ots.ClassRead,
	Summary: "读一台设备的 PoE 供电情况（RFC 3621 / POWER-ETHERNET-MIB）：整台的电源池额定多少瓦、" +
		"实测在耗多少、总开关开没开；某一个口允不允许供电、现在在不在供、检测卡在哪一步、" +
		"被拒绝/掉电/过载/短路各攒了几次。" +
		"★ 判定按下一步怎么查来分：snmp-poe-pse-fault（电源池自己报故障，是硬件的事）、" +
		"snmp-poe-off（电源池总开关关着，这时候逐个看口是白跑）、" +
		"snmp-poe-budget（余量紧了，下一个 PD 插上来会被拒）、" +
		"snmp-poe-disabled（这个口是被关着的 / 被设备排除在 PoE 之外）、" +
		"snmp-poe-searching（在检测但没供上：没插、PD 不合规、或要的电超档）、" +
		"snmp-poe-fault（这个口自己报故障）、snmp-poe-not-found（表读全了没有这一行）。" +
		"★ PoE 表的行索引是 {组号, 口号} 两段，RFC 3621 里**没有** ifIndex 到口号的映射，" +
		"填 ifIndex 时结果是按编号猜的，会写明怎么猜的、以及这一行自己的组号口号。" +
		"★ 这棵树给不出「某个口用了几瓦」（只有整台的实测值），也不含 class5-8。" +
		"先跑 net.snmp.probe 确认 SNMP 通不通。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr", "community"],
	  "properties": {
	    ` + snmpSchemaProps + `,
	    "groupIndex": {"type": "integer", "minimum": 1, "maximum": 2147483647,
	      "description": "PoE 分组号（pethPsePortGroupIndex）：堆叠里的哪一台机箱 / 机架里的哪一块模块。RFC 规定非模块化设备必须是 1，所以一般不用填。★ 和上面那个「端口」不是一回事，那一个是 SNMP 的 UDP 端口。"},
	    "portIndex": {"type": "integer", "minimum": 1, "maximum": 2147483647,
	      "description": "点名问一个 PoE 口（pethPsePortIndex）。只填这个、不填组号时，会把每一组里编号相同的行**都**列出来（堆叠设备上每箱都有一个 5 号口，挑一个可能挑错机箱）。★ 这个编号和面板上的第几口、和 ifIndex 都不一定相等 —— 不确定就把表列一遍，对着 pethPsePortType 那一栏认。"},
	    "ifIndex": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "按接口编号问这个口的供电。★ RFC 3621 没规定 ifIndex 和 PoE 口编号的关系，所以这一条是**猜**：结果里的 ifIndexMapping 会写清是「编号正好相等猜的」还是「设备在 pethPsePortType 里写了口名、对上的」；两条指着不同行时两行都列出来，不挑一个。"},
	    "name": {"type": "string",
	      "description": "在 pethPsePortType 那一栏里找这几个字（那一栏是运维手写的「这口上挂的什么」，如「AP-3F」「NVR-12」）。★ 很多设备上这一栏是空的，空着不代表设备坏；它也不是口名。"},
	    "state": {"type": "string", "enum": ["on", "off"],
	      "description": "只列在供电的（on）或没在供电的（off）。★ 筛选在读回来之后做，不减读的量；「读了多少」记的是筛掉之前有几个。detectionStatus 没给读的行算进 off —— 那是「说不清」，不是「确定没供」。"},
	    "limit": {"type": "integer", "minimum": 1, "maximum": 8192,
	      "description": "最多列几个 PoE 口，默认 512。撞到限量时不会给「其余口都还好」这种结论。"},
	    "watchSeconds": {"type": "integer", "minimum": 0, "maximum": 300,
	      "description": "读两遍之间等几秒，用来看那几个计数器**这一段**涨没涨（掉电、被拒、过载、短路）。0 = 只读一遍，只给从开机攒到现在的累计值。★ 两遍之间会比 sysUpTime，倒退了说明这台重启过、计数器被清零，那就不给增量。"},
	    "noCounters": {"type": "boolean",
	      "description": "只问状态、不问那几个计数器（口多时省报文，代价是看不出「刚才又踢了一次」）。"}
	  }
	}`),
	Invoke: doSnmpPoe,
}

// poeKey 是 pethPsePortTable 的一行。★ 两段索引必须两段都带上：
// 堆叠设备上「1 组的 5 口」和「2 组的 5 口」是两个物理口，
// 合成一个数就挑错了机箱 —— 而这一趟的结论是照着它去机房的。
type poeKey struct{ group, port int }

func (k poeKey) String() string { return strconv.Itoa(k.group) + "." + strconv.Itoa(k.port) }

func sortPoeKeys(ks []poeKey) {
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].group != ks[j].group {
			return ks[i].group < ks[j].group
		}
		return ks[i].port < ks[j].port
	})
}

// samePoeKeys 两组行是不是同一批（不看顺序：两边都是排好序走出来的）。
func samePoeKeys(a, b []poeKey) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[poeKey]bool, len(a))
	for _, k := range a {
		seen[k] = true
	}
	for _, k := range b {
		if !seen[k] {
			return false
		}
	}
	return true
}

// parsePoeKey 把 OID 尾巴上那两段拆成 {group, port}。
//
// ★ 不是正好两段就不认。把「1.2.3」按前两段读成一行的话，另一张表
//
//	（或者厂商自己加的列）就被当成了这个口的读数。
func parsePoeKey(rest string) (poeKey, bool) {
	g, p, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(p, ".") {
		return poeKey{}, false
	}
	gn, err := strconv.Atoi(g)
	if err != nil || gn <= 0 {
		return poeKey{}, false
	}
	pn, err := strconv.Atoi(p)
	if err != nil || pn <= 0 {
		return poeKey{}, false
	}
	return poeKey{gn, pn}, true
}

// poeRow 是一个 PoE 口的读数（还没翻成结果形状）。
type poeRow struct {
	key poeKey
	// matched 记「这行是靠哪条路子被认成点名要的那个口」。★ 不标的话，
	// 按 ifIndex 猜出来的结果和按组号口号直问的结果长得一模一样，
	// 人就分不清哪一条是猜的。
	matched string

	// 每一栏「设备给没给」单独记。★ 没给的不写成 false / 0 ——
	//   「这个口不允许供电」和「这台不给读使能栏」是两个相反的结论。
	got          map[string]bool
	admin        bool
	pairsControl bool
	pairs        int // 1 signal / 2 spare，0 = 没读到
	status       int // 1..6，0 = 没读到
	priority     int
	class        int
	pdType       string

	// 五个累计计数器 + 各自报回来的位宽。
	counters map[string]uint64
	bits     map[string]int
	// sampled / deltas 只有走了第二遍才有。★ 有累计值不等于有增量。
	sampled    bool
	deltas     map[string]uint64
	unreliable string // 增量给不出的原因（位宽两遍不一致、计数器倒退…）
}

func newPoeRow(k poeKey) poeRow {
	return poeRow{key: k, got: map[string]bool{},
		counters: map[string]uint64{}, bits: map[string]int{}, deltas: map[string]uint64{}}
}

// pseRow 是一个电源池（pethMainPseTable 的一行）。
type pseRow struct {
	group       int
	got         map[string]bool
	power       uint64
	consumption uint64
	oper        int // 1 on / 2 off / 3 faulty，0 = 没读到
	threshold   int // 1..99，0 = 没读到
}

// computable 是「余量算不算得出来」。★ 额定没读到、或者读到一个 0，
//
//	都算不出来 —— 算不出来的那一档**没有资格**说「余量够」。
func (r pseRow) computable() bool {
	return r.got[oidPethMainPower] && r.got[oidPethMainConsumption] && r.power > 0
}

// budgetState 是余量结论，三档。
type budgetState int

const (
	budgetUnknown budgetState = iota
	budgetOK
	budgetTight
)

func (s budgetState) String() string {
	switch s {
	case budgetOK:
		return "ok"
	case budgetTight:
		return "tight"
	}
	return "unknown"
}

// budget 算余量。算不出来时 usedPct / remaining 是零值，调用方看 state。
func (r pseRow) budget() (state budgetState, usedPct float64, remaining int64) {
	if !r.computable() {
		return budgetUnknown, 0, 0
	}
	usedPct = float64(r.consumption) * 100 / float64(r.power)
	remaining = int64(r.power) - int64(r.consumption)
	if remaining < 0 {
		remaining = 0
	}
	// ★ 实测比额定还大 = 这一栏的口径不对（有些设备报的不是瓦）。
	//   但「池子已经顶满了」这句仍然成立，所以按紧处理，另外标出来。
	if r.consumption > r.power {
		return budgetTight, usedPct, remaining
	}
	switch {
	// 阈值是设备自己定的告警线（RFC 里它就是拿来触发告警的），照它判。
	case r.threshold > 0:
		if usedPct >= float64(r.threshold) {
			return budgetTight, usedPct, remaining
		}
		return budgetOK, usedPct, remaining
	default:
		// 没给阈值就只按「有没有顶到额定」判，并且说清口径，
		// 不假装知道设备想在哪一线报警。
		if usedPct >= 100 {
			return budgetTight, usedPct, remaining
		}
		return budgetOK, usedPct, remaining
	}
}

func doSnmpPoe(ctx context.Context, raw json.RawMessage) (any, error) {
	var a snmpPoeArgs
	if err := snmpArgsFrom(raw, &a); err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(a.State)) {
	case "", "on", "off":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "state %q 看不懂，要 on 或 off", a.State)
	}
	if a.GroupIndex < 0 || a.PortIndex < 0 || a.IfIndex < 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "groupIndex / portIndex / ifIndex 不能是负数")
	}
	if a.IfIndex > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "ifIndex %d 超出 1-65535", a.IfIndex)
	}
	if a.WatchSeconds > 300 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"watchSeconds %d 太长（上限 300）—— 这一档是「看几个计数器涨没涨」，等那么久不如重新问一次",
			a.WatchSeconds)
	}
	limit := a.Limit
	if limit <= 0 {
		limit = poeDefault
	}
	if limit > poeMax {
		limit = poeMax
	}

	t, err := snmpDial(a.snmpArgs)
	if err != nil {
		return nil, err
	}
	defer t.close()

	values := t.values()
	start := time.Now()

	// ── ① 整台的电源池：它压过一切单口的结论，所以先读它 ──
	pse, err := t.pseRows(ctx)
	if err != nil {
		verdict, done := snmpFail(err, values)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	// 走到这一步设备一定答过话了（池子那一趟就是走表走出来的）。
	answered := true
	values["answered"] = true
	// 那几个计数器是「从开机攒到现在」的，不带上开机多久就不知道那个数攒了多久。
	sysUp, upErr := t.sysUpTime(ctx)
	if upErr == nil && sysUp > 0 {
		values["uptimeSeconds"] = sysUp / 100
		values["uptime"] = humanUptime(sysUp / 100)
	}

	// ── ② 定下来要问哪几行 PoE 口 ──
	set, err := t.pickPoeTargets(ctx, a, limit, values)
	if err != nil {
		verdict, done := poeFail(err, values, answered)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	// ★ 按 {组, 口} 直取时没走表，「一共有几个口」是**不知道**的 ——
	//   不写这一栏，而不是写 0：写 0 会被看成「这台一个 PoE 口都没有」。
	if !set.direct {
		values["countTotal"] = set.total
	}
	values["truncated"] = set.truncated
	values["readLimit"] = limit
	values["pse"] = buildPseEntries(pse)
	if len(set.keys) == 0 {
		values["read"] = 0
		values["count"] = 0
		values["poePorts"] = []map[string]any{}
		values["elapsedMs"] = time.Since(start).Milliseconds()
		if set.total == 0 && !set.named {
			return t.poeNoData(ctx, values), nil
		}
		return poeNotFound(values, a, set.truncated), nil
	}

	// ── ③ 读这些行的各栏 ──
	counters := !a.NoCounters
	rows, err := t.getPoeRows(ctx, set.keys, counters)
	if err != nil {
		verdict, done := poeFail(err, values, answered)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	for i := range rows {
		rows[i].matched = set.match[rows[i].key]
	}
	firstAt := time.Now()

	// ── ④ 要看守没涨，就读第二遍 ──
	if a.WatchSeconds > 0 && counters {
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(a.WatchSeconds) * time.Second):
		}
		if ctx.Err() != nil {
			values["sampleAborted"] = "第二次读之前这趟观测被取消了，没测到增量"
		} else {
			second, serr := t.getPoeRows(ctx, set.keys, true)
			seconds := time.Since(firstAt).Seconds()
			sysDown, downErr := t.sysUpTime(ctx)
			switch {
			case serr != nil:
				values["sampleUnsure"] = "第二次没读通，这一趟算不出增量（上面那些累计值是第一次读到的）"
			case upErr != nil || downErr != nil || sysUp == 0:
				values["sampleUnsure"] = "问不到 sysUpTime，没法确认这台设备中途有没有重启，增量仅供参考"
				applyPoeDeltas(rows, second, false)
			case sysDown < sysUp:
				values["rebooted"] = true
				values["sampleUnsure"] = "这台设备在两次读之间重启过（sysUpTime 倒退），计数器被清零了，" +
					"增量是假的，只给累计值"
			default:
				applyPoeDeltas(rows, second, true)
			}
			values["sampleSeconds"] = round1(seconds)
		}
	}

	// ── ⑤ 筛选、计数、收口 ──
	all := len(rows)
	rows = filterPoeState(rows, a.State)
	if a.State != "" {
		values["stateFilter"] = a.State
	}
	values["read"] = all
	values["count"] = len(rows)
	values["poePorts"] = buildPoeEntries(rows)
	values["elapsedMs"] = time.Since(start).Milliseconds()

	switch {
	case len(rows) == 0 && set.named:
		// 点名了却没读到：被筛掉的那种另说（那是「它不在这个状态」，不是「没这一行」）。
		if a.State != "" && all > 0 {
			return poeFilteredOut(values, set.total, a.State), nil
		}
		return poeNotFound(values, a, set.truncated), nil
	case len(rows) == 1 && set.named:
		return poeVerdict(values, rows[0], pse), nil
	case set.truncated:
		// ★ 列到一半撞限量：「其余口都还好」不成立，「别的口没问题」也不成立。
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("列到 %v 个 PoE 口撞到 limit 停了，这台的口没有全列出来。"+
				"这一条不是「其余口都还好」：把 limit 提到 %d 再看一次才算看完这张表", all, poeMax)}, nil
	}
	return poeSummary(values, rows, all, pse, a.State != "", set.named), nil
}

// poeFail 是 snmpFail 的一层补丁：这台设备在**前面一步已经答过话**了
// （电源池那一趟走通），所以「这一步没读回来」不该翻成「设备没回话」——
// 那两种病的下一步完全相反（查这棵子树的视图 / 查防火墙和团体名）。
func poeFail(err error, values map[string]any, answered bool) (ots.Verdict, bool) {
	verdict, done := snmpFail(err, values)
	if done && answered {
		values["answered"] = true
		values["answeredEarlier"] = "整台的电源池那一栏已经读通了：设备是活的、团体名也是对的。" +
			"这一步没读回来，要查的是这棵子树的视图/权限，不是网络"
	}
	return verdict, done
}

// poeTargetSet 是「这一趟要问哪几行」，外加几条必须带到收口处的信息。
type poeTargetSet struct {
	keys      []poeKey
	total     int // 表里一共有几行（直取时不知道 = 0）
	truncated bool
	direct    bool // 按 {组, 口} 直取，没走表
	named     bool // 点名了（填了组号 / 口号 / 接口号 / 标签任意一个）
	// match 记每一行是被哪条路子认出来的（只有按 ifIndex 问时才有）。
	match map[poeKey]string
}

// pickPoeTargets 定下要问哪些行。
//
// ★ 只有「组号和口号都填了」时才不走表直取：少填一个就不能直取 ——
//
//	堆叠设备上每箱都有一个 5 号口，只填 5 就按「1 组 5」去猜，
//	等于把别的机箱漏掉，而这正是最容易查错的那一次。
func (t *snmpTarget) pickPoeTargets(ctx context.Context, a snmpPoeArgs, limit int,
	values map[string]any) (poeTargetSet, error) {
	if a.GroupIndex > 0 && a.PortIndex > 0 {
		return poeTargetSet{keys: []poeKey{{a.GroupIndex, a.PortIndex}},
			direct: true, named: true}, nil
	}
	keys, total, truncated, err := t.poeIndexKeys(ctx, limit)
	set := poeTargetSet{total: total, truncated: truncated}
	if err != nil {
		return set, err
	}
	switch {
	case a.PortIndex > 0:
		set.named = true
		for _, k := range keys {
			if k.port == a.PortIndex {
				set.keys = append(set.keys, k)
			}
		}
		return set, nil
	case a.GroupIndex > 0:
		set.named = true
		for _, k := range keys {
			if k.group == a.GroupIndex {
				set.keys = append(set.keys, k)
			}
		}
		return set, nil
	case a.IfIndex > 0:
		set.named = true
		set.keys, set.match = t.poeByIfIndex(ctx, keys, a.IfIndex, values)
		return set, nil
	case strings.TrimSpace(a.Name) != "":
		set.named = true
		want := strings.ToLower(strings.TrimSpace(a.Name))
		types := t.poeColumnStrings(ctx, oidPethPortType, keys)
		for _, k := range keys {
			if strings.Contains(strings.ToLower(types[k]), want) {
				set.keys = append(set.keys, k)
			}
		}
		if len(set.keys) == 0 && len(types) == 0 {
			// 一行标签都没给：这一条要说出来，不然「没找到」看着像「这台没这种东西」。
			values["labelEmpty"] = "这台的 pethPsePortType 一栏是空的（那一栏本来就要人手写，" +
				"多数设备没写）—— 「按标签没找着」不等于「没有这个口」，按组号/口号点名或者把表列一遍"
		}
		return set, nil
	}
	set.keys = keys
	return set, nil
}

// poeIndexKeys 走 detectionStatus 那一栏当行的主干，问出这张表有几行。
//
// ★ 为什么拿这一栏当主干：它是这张表里 RFC 要求每一行都得给的一栏
//
//	（口的供电状态本身就是这棵树要回答的东西）。整棵子树走一遍的条数是
//	「口数 × 栏数」，48 口的设备就是六百多条，而这里要的只是「有几行」。
func (t *snmpTarget) poeIndexKeys(ctx context.Context, limit int) ([]poeKey, int, bool, error) {
	vs, truncated, err := t.client.WalkLimit(ctx, oidPethDetectStatus, limit)
	if err != nil && len(vs) == 0 {
		return nil, 0, truncated, err
	}
	seen := map[poeKey]bool{}
	out := make([]poeKey, 0, len(vs))
	for _, v := range vs {
		rest := indexAfter(v.OID, oidPethDetectStatus)
		if rest == "" || v.Missing() || v.EndOfMib() {
			continue
		}
		k, ok := parsePoeKey(rest)
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sortPoeKeys(out)
	return out, len(out), truncated, nil
}

// poeByIfIndex 把接口编号换成 PoE 表的行。**两条路各走一遍，一条都不藏**：
//
//	A. pethPsePortIndex 正好等于 ifIndex —— 这只是编号相同。★ RFC 3621 里
//	   没有任何 ifIndex ↔ 口号的映射规定，所以这是**猜**。
//	B. 某一行的 pethPsePortType 里正好写着这个口的名字（ifName / ifDescr）。
//	   那一栏本来是「运维手写的 PD 类型」，有厂商拿它写口名 —— 对上了就是
//	   这台设备自己给出的证据，比 A 硬。
//
// 两条指着不同的行时两行都列出来，并且写明「有两个候选」：宁可多给一行，
// 也不挑一个 —— 挑错那一次是让人去查另一个口的供电。
func (t *snmpTarget) poeByIfIndex(ctx context.Context, keys []poeKey, ifIndex int,
	values map[string]any) ([]poeKey, map[poeKey]string) {
	values["ifIndex"] = ifIndex
	match := map[poeKey]string{}
	var byIndex, byType []poeKey
	names := t.ifaceNames(ctx, ifIndex)
	if len(names) > 0 {
		types := t.poeColumnStrings(ctx, oidPethPortType, keys)
		for _, k := range keys {
			s := types[k]
			if s == "" {
				continue
			}
			for _, n := range names {
				if portNameMatches(n, []portNameHit{{s: s}}) {
					byType = append(byType, k)
					break
				}
			}
		}
	}
	for _, k := range keys {
		if k.port == ifIndex {
			byIndex = append(byIndex, k)
		}
	}
	out := []poeKey{}
	add := func(list []poeKey, how string) {
		for _, k := range list {
			if prev, ok := match[k]; ok {
				if prev != how {
					match[k] = poeMatchBoth
				}
				continue
			}
			match[k] = how
			out = append(out, k)
		}
	}
	add(byIndex, poeMatchIndex)
	add(byType, poeMatchType)
	sortPoeKeys(out)
	values["ifIndexMapping"] = poeMappingNote(len(out), byIndex, byType, len(names) > 0)
	if len(byIndex) > 0 && len(byType) > 0 && !samePoeKeys(byIndex, byType) {
		values["ifIndexAmbiguous"] = true
	}
	return out, match
}

// ifaceNames 取一个口上能用来认它的两种写法（ifName 和 ifDescr 都给，
// 理由见 portNames：思科的短写在 ifName、华为/H3C 的短写在 ifDescr）。
func (t *snmpTarget) ifaceNames(ctx context.Context, ifIndex int) []string {
	var out []string
	for _, col := range []string{oidIfName, oidIfDescr} {
		for _, s := range t.columnStrings(ctx, col, []int{ifIndex}) {
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// poeMappingNote 说清这次「接口编号 → PoE 口」是怎么对上的。
func poeMappingNote(got int, byIndex, byType []poeKey, haveNames bool) string {
	switch {
	case got == 0:
		if haveNames {
			return "没对上：这台设备既没有编号等于这个 ifIndex 的 PoE 口，" +
				"也没有哪一行的 pethPsePortType 写着这个口的名字"
		}
		return "没对上：这台不给读 ifName/ifDescr，也没有编号等于这个 ifIndex 的 PoE 口"
	case len(byIndex) > 0 && len(byType) > 0 && !samePoeKeys(byIndex, byType):
		return "★ 有两个候选：一行的编号正好等于这个接口号（按猜的算），" +
			"另一行是设备自己在 pethPsePortType 里写了这个口名（对上的）—— 两者指着不同的行，" +
			"两行都列出来了，别当成同一个口"
	case len(byIndex) > 0 && len(byType) > 0:
		return "两条独立的路子都对上了（编号正好相等，而且这一行的标签写着这个口名）—— 这一条可以当准"
	case len(byType) > 0:
		return "按设备自己写在 pethPsePortType 那一栏的口名对上的（那一栏本来是运维手写的 PD 类型，" +
			"它写着口名就说明这台给了映射）"
	default:
		return "★ 按「pethPsePortIndex 正好等于 ifIndex」猜的：RFC 3621 没有规定 ifIndex " +
			"和 PoE 口编号的关系。结果里每一行都带着它自己的组号和口号，请核一下是不是同一个口"
	}
}

// pseRows 读整台的电源池。
//
// ★ 走 entry 整棵子树、而不是拿某一栏当主干：这张表每组只有四栏，
//
//	而「每一栏都在」这个假设一旦破了，池子那一档就会整个空掉 ——
//	界面上变成「这台不给读电源池」，实际上它给了额定和实测、只少了总开关。
func (t *snmpTarget) pseRows(ctx context.Context) ([]pseRow, error) {
	vs, _, err := t.client.WalkLimit(ctx, pethMainPseEntry, 256)
	if err != nil && len(vs) == 0 {
		return nil, err
	}
	byGroup := map[int]*pseRow{}
	for _, v := range vs {
		rest := indexAfter(v.OID, pethMainPseEntry)
		if rest == "" || v.Missing() || v.EndOfMib() {
			continue
		}
		col, idx, ok := strings.Cut(rest, ".")
		if !ok || strings.Contains(idx, ".") {
			continue
		}
		column, g, ok := splitPseColumn(col, idx)
		if !ok {
			continue // 认不出的列（厂商自己加的）：宁可丢掉，不许当成额定功率
		}
		r := byGroup[g]
		if r == nil {
			r = &pseRow{group: g, got: map[string]bool{}}
			byGroup[g] = r
		}
		r.got[column] = true
		switch column {
		case oidPethMainPower:
			r.power = v.UintOr0()
		case oidPethMainConsumption:
			r.consumption = v.UintOr0()
		case oidPethMainOperStatus:
			r.oper = int(v.IntOr0())
		case oidPethMainThreshold:
			r.threshold = int(v.IntOr0())
		}
	}
	out := make([]pseRow, 0, len(byGroup))
	for _, r := range byGroup {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].group < out[j].group })
	return out, nil
}

// splitPseColumn 把「列号.组号」对回完整的列 OID。
func splitPseColumn(col, idx string) (column string, group int, ok bool) {
	candidate := pethMainPseEntry + "." + col
	if _, known := pethColumnName[candidate]; !known {
		return "", 0, false
	}
	n, err := strconv.Atoi(idx)
	if err != nil || n <= 0 {
		return "", 0, false
	}
	return candidate, n, true
}

// poeColumns 是一次读要问的栏。
func poeColumns(counters bool) []string {
	cols := []string{oidPethAdminEnable, oidPethPairsControl, oidPethPowerPairs,
		oidPethDetectStatus, oidPethPriority, oidPethPortType, oidPethClass}
	if counters {
		cols = append(cols, oidPethMPSAbsent, oidPethBadSignature,
			oidPethDenied, oidPethOverLoad, oidPethShort)
	}
	return cols
}

// poeCounterColumns 是那五个累计计数器。
var poeCounterColumns = []string{oidPethMPSAbsent, oidPethBadSignature,
	oidPethDenied, oidPethOverLoad, oidPethShort}

// getPoeRows 按 {组, 口} 批量取这几栏。
//
// ★ 用 multiGet 而不是走整棵子树：走表会把这台所有行都拉回来，
//
//	而这里要的只是已经定下来的那几行。
//	错误一律往上交给 poeFail 定性，这里不吞 —— 吞掉的话团体名错会变成
//	「这台没有这个口」，而该说的是「你给的团体名不对」。
func (t *snmpTarget) getPoeRows(ctx context.Context, keys []poeKey,
	counters bool) ([]poeRow, error) {
	cols := poeColumns(counters)
	oids := make([]string, 0, len(keys)*len(cols))
	for _, c := range cols {
		for _, k := range keys {
			oids = append(oids, c+"."+k.String())
		}
	}
	vbs, err := t.multiGet(ctx, oids)
	if err != nil {
		return nil, err
	}
	byKey := map[poeKey]map[string]snmp.VarBind{}
	for _, v := range vbs {
		if v.Missing() || v.EndOfMib() {
			continue
		}
		for _, c := range cols {
			rest := indexAfter(v.OID, c)
			if rest == "" {
				continue
			}
			k, ok := parsePoeKey(rest)
			if !ok {
				continue
			}
			if byKey[k] == nil {
				byKey[k] = map[string]snmp.VarBind{}
			}
			byKey[k][c] = v
		}
	}
	out := make([]poeRow, 0, len(byKey))
	for _, k := range keys {
		cols := byKey[k]
		if cols == nil {
			continue // 这一行设备一栏都没给：不编出一行「全是空」的读数
		}
		out = appendPoeRow(out, k, cols)
	}
	return out, nil
}

func appendPoeRow(out []poeRow, k poeKey, cols map[string]snmp.VarBind) []poeRow {
	r := newPoeRow(k)
	for c := range cols {
		r.got[c] = true
	}
	if v, ok := cols[oidPethAdminEnable]; ok {
		r.admin = truth(v)
	}
	if v, ok := cols[oidPethPairsControl]; ok {
		r.pairsControl = truth(v)
	}
	if v, ok := cols[oidPethPowerPairs]; ok {
		r.pairs = int(v.IntOr0())
	}
	if v, ok := cols[oidPethDetectStatus]; ok {
		r.status = int(v.IntOr0())
	}
	if v, ok := cols[oidPethPriority]; ok {
		r.priority = int(v.IntOr0())
	}
	if v, ok := cols[oidPethClass]; ok {
		r.class = int(v.IntOr0())
	}
	if v, ok := cols[oidPethPortType]; ok {
		r.pdType = printable(v.Str())
	}
	for _, c := range poeCounterColumns {
		v, ok := cols[c]
		if !ok {
			continue
		}
		r.counters[c] = v.UintOr0()
		r.bits[c] = counterWidth(v)
	}
	return append(out, r)
}

// counterWidth 是一个计数器报回来的位宽。★ 默认按 32 位：RFC 3621 里这五个
//
//	都是 Counter32，而设备偶尔会用 Counter64 报回来（厂商扩展）。
//	拿 64 位的模去相减一个 32 位的计数器，回绕那一次得到的是 1.8×10¹⁹。
func counterWidth(v snmp.VarBind) int {
	if v.Tag == snmp.TagCounter64 {
		return 64
	}
	return 32
}

// truth 读 TruthValue。★ 只认 1 是 true：MIB 里 true=1、false=2，
//
//	「非零即真」会把一个读不懂的值当成「允许供电」。
func truth(v snmp.VarBind) bool { return v.IntOr0() == 1 }

// poeColumnStrings 按行取一栏的字符串（认口用）。
func (t *snmpTarget) poeColumnStrings(ctx context.Context, column string,
	keys []poeKey) map[poeKey]string {
	out := map[poeKey]string{}
	oids := make([]string, 0, len(keys))
	for _, k := range keys {
		oids = append(oids, column+"."+k.String())
	}
	vbs, err := t.multiGet(ctx, oids)
	if err != nil {
		return out
	}
	for _, v := range vbs {
		rest := indexAfter(v.OID, column)
		if rest == "" || v.Missing() || v.EndOfMib() {
			continue
		}
		k, ok := parsePoeKey(rest)
		if !ok {
			continue
		}
		if s := printable(v.Str()); s != "" {
			out[k] = s
		}
	}
	return out
}

// applyPoeDeltas 用第二遍的读数算「这一段涨了几次」。
//
// ★ 增量要三件事都成立才算：这一栏两遍都读到过、两遍报回来的是同一个位宽、
//
//	以及两遍之间这台没重启（checked 那一路已经比过 sysUpTime）。
//	任何一件不成立就不给增量 ——「刚才又被踢了一次」这句话是要动手的，
//	给一个看着合理的假数比不给更坏。
func applyPoeDeltas(rows []poeRow, second []poeRow, checked bool) {
	byKey := make(map[poeKey]poeRow, len(second))
	for _, r := range second {
		byKey[r.key] = r
	}
	for i := range rows {
		r := &rows[i]
		s, ok := byKey[r.key]
		if !ok {
			continue
		}
		r.sampled = true
		for _, c := range poeCounterColumns {
			if !r.got[c] || !s.got[c] {
				continue // 有一遍没读到这一栏 = 没有起点，报「涨了 N」是把不知道说成结论
			}
			switch {
			case !checked:
				r.unreliable = "问不到 sysUpTime，不知道这台中途重启过没有，增量不给"
			case r.bits[c] != s.bits[c]:
				r.unreliable = "这一栏两遍报回来的位宽不一样（32 位和 64 位混了），增量不给"
			// ★ 32 位那一档倒退常常正是绕了一圈，所以取模；
			//   64 位那一档不可能在人对着屏幕的这几秒里绕完，倒退就是被重置过。
			case r.bits[c] == 64 && s.counters[c] < r.counters[c]:
				r.unreliable = "计数器倒退（被重置过），增量不给"
			default:
				r.deltas[c] = wrapDelta(r.counters[c], s.counters[c], r.bits[c])
			}
		}
		// 累计值换成后一遍的：界面上「一共几次」要的是现在的数。
		for _, c := range poeCounterColumns {
			if s.got[c] {
				r.counters[c] = s.counters[c]
				r.bits[c] = s.bits[c]
				r.got[c] = true
			}
		}
	}
}

// filterPoeState 按「在不在供电」筛。★ 只有 deliveringPower(3) 算 on：
// 使能开着、状态读不到、在检测中，都属于「现在没在给电」，现场要的就是这一刀。
func filterPoeState(rows []poeRow, state string) []poeRow {
	s := strings.ToLower(strings.TrimSpace(state))
	if s == "" {
		return rows
	}
	out := make([]poeRow, 0, len(rows))
	for _, r := range rows {
		on := r.status == 3
		if (s == "on") == on {
			out = append(out, r)
		}
	}
	return out
}

// ── 翻译：把枚举翻成「这一档在说什么、下一步查什么」 ──

func poeStatusName(n int) string {
	switch n {
	case 1:
		return "disabled"
	case 2:
		return "searching"
	case 3:
		return "deliveringPower"
	case 4:
		return "fault"
	case 5:
		return "test"
	case 6:
		return "otherFault"
	}
	return ""
}

// poeStatusWord 是 note 里用的中文词。★ note 是现场整句复制进工单的那一行，
//
//	只写 MIB 原文等于让看的人再去查一遍枚举表；枚举名另起括号留着，供对报文的人核。
func poeStatusWord(n int) string {
	switch n {
	case 1:
		return "没在供"
	case 2:
		return "在检测"
	case 3:
		return "在供电"
	case 4, 6:
		return "报故障"
	case 5:
		return "在测试"
	}
	return ""
}

// poeStatusNamed 给「中文词（MIB 原文）」这一对；认不出来时原样带出编号，不编一个词。
func poeStatusNamed(n int) string {
	w, raw := poeStatusWord(n), poeStatusName(n)
	switch {
	case w == "" && raw == "":
		return "状态没读到"
	case w == "":
		return "状态 " + raw
	case raw == "":
		return w
	}
	return w + "（" + raw + "）"
}

// poeStatusMeaning 按 RFC 3621 对 PSE 状态机的说明翻。★ fault(4) 是 TEST_ERROR、
//
//	otherFault(6) 是因 error_conditions 回到 IDLE，两个都不是一句「坏了」能打发的。
func poeStatusMeaning(n int) string {
	switch n {
	case 1:
		return "这个口不在 PoE 状态机里（设备没把它当供电口）"
	case 2:
		return "在检测，还没供上电（也可能压根没插受电设备）"
	case 3:
		return "正在供电"
	case 4:
		return "检测阶段出错（TEST_ERROR）"
	case 5:
		return "在测试模式（TEST_MODE），不代表正常供电"
	case 6:
		return "因为出错条件被停供（error_conditions）"
	}
	return "设备给了一个没听过的值"
}

// poeStatusAdvice 是点名一个口时最后一句话：这一步该往哪儿查。
//
// ★ searching 那一档最容易白跑一趟：48 口交换机上大部分口本来就在 searching
//
//	（没插东西），所以那句里必须给出「怎么把『没插』和『插了但不要电』分开」——
//	看两个计数器，不是把同一句状态再问一次。
func poeStatusAdvice(n int) string {
	switch n {
	case 1:
		return "★ 这一步不用查线：使能是开着的，可设备自己把这个口排除在 PoE 之外了" +
			"（有些设备上这一档的意思是这个口不在 PoE 组里，或者被策略挡住了）。去设备的 PoE 配置里看。"
	case 2:
		return "在检测、没供上电，三种可能分不开：① 这个口压根没插受电设备（正常现象）；" +
			"② 插的东西不合规（非 PoE 的分离器、劣质线）；③ 它要的电超过这台给的档。" +
			"拿计数器分：invalidSignature 在涨是②，powerDenied 在涨是③，都没涨就是①。" +
			"★ 分辨的办法是读两遍看增量（watchSeconds），不是把同一句状态再问一次。"
	case 3:
		return "★ 「在供电」不等于「它在工作」：PD 拿到电之后自己起不来、" +
			"或者网线太差带不动链路，都得另问（链路状态和流量看 net.snmp.ports）。"
	case 4:
		return "这个口自己报「检测阶段出错」（TEST_ERROR）。把 PD 换到别的口试：换了就好是 PD 的事，" +
			"还是坏就是这个口 / 这台的电源。再看 overLoad、shortCircuit 有没有涨。"
	case 5:
		return "这个口在测试模式，这一趟读到的不代表正常供电时的状态。"
	case 6:
		return "设备因为它报错把这个口停供了（error_conditions）。和 fault 一样两头分：先换 PD、再换口。" +
			"★ 别把它当成「有人关掉了」—— 那种是 adminEnable=false。"
	default:
		return "detectionStatus 这一栏设备给的不是标准值，这一条不能说它在供还是没在供，只当参照。"
	}
}

func poePairsName(n int) string {
	switch n {
	case 1:
		return "signal"
	case 2:
		return "spare"
	}
	return ""
}

// poePairsWhy 说清这一栏能说什么、不能说什么。
//
// ★ 别拿它判断是不是 4 对供电：这一栏只有「用哪一对」，
//
//	802.3at/bt 是两对一起供的，那一档在这棵树里根本表达不出来。
//	拿 signal/spare 去说「这是 Mode A / 是 4-pair」是编出来的。
const poePairsWhy = "这一栏只说用哪一对线送电（signal=信号线对，spare=空闲线对）。" +
	"★ 别拿它判断是不是 4 对供电：RFC 3621 里没这一档，802.3at/bt 是两对一起供的。"

// poePriorityWhy：优先级只在预算不够时才有意义，这一句要连着给，
// 不然人以为它是「供电快慢」的档。
const poePriorityWhy = "这个优先级只在电源池不够分时起作用：预算顶到阈值时先断优先级低的那几个。" +
	"网络运行不能断的那一路（如应急电话）该是 critical。"

// poeClassWhy 是一次结果里只写一遍的那句「等级不是瓦数」。
const poeClassWhy = "等级只是设备对「这口要多少电」的分类档，这一棵树不给瓦数：" +
	"af 和 at 同号不同功率，而单个口的实测值 RFC 3621 里根本没有。"

// ── 结果形状 ──

func buildPseEntries(pse []pseRow) []map[string]any {
	out := make([]map[string]any, 0, len(pse))
	for _, r := range pse {
		e := map[string]any{"group": r.group}
		if o := mainPseStatusName(r.oper); o != "" {
			e["oper"] = o
			e["operMeaning"] = mainPseStatusMeaning(r.oper)
		}
		if r.got[oidPethMainPower] {
			e["powerW"] = r.power
		}
		if r.got[oidPethMainConsumption] {
			e["consumptionW"] = r.consumption
		}
		if r.got[oidPethMainThreshold] {
			e["thresholdPct"] = r.threshold
		}
		state, used, remaining := r.budget()
		e["budget"] = state.String()
		if state == budgetUnknown {
			e["budgetWhy"] = "额定或实测这两栏这台没给（或者额定读回来是 0），余量算不出来 " +
				"—— ★ 这不能读成「余量够」"
		} else {
			e["usedPct"] = round1(used)
			e["remainingW"] = remaining
			if r.consumption > r.power {
				e["pseInconsistent"] = fmt.Sprintf(
					"实测（%v W）比额定（%v W）还大：这一栏的口径不对（有些设备报的不是瓦），余量按顶满处理",
					r.consumption, r.power)
			}
			if r.threshold == 0 {
				e["budgetBasis"] = "这台没给告警阈值，只按「有没有顶到额定」判紧不紧"
			}
		}
		out = append(out, e)
	}
	return out
}

func mainPseStatusName(n int) string {
	switch n {
	case 1:
		return "on"
	case 2:
		return "off"
	case 3:
		return "faulty"
	}
	return ""
}

// mainPseStatusWord 是收口那句里用的中文词。★ 认出来的值不冒充「没读到」：
// 「这一栏缺」和「给了个没听见的值」下一步不一样，所以后者原样带出编号。
func mainPseStatusWord(n int) string {
	switch n {
	case 1:
		return "开着"
	case 2:
		return "关着"
	case 3:
		return "报故障"
	case 0:
		return ""
	}
	return "给了个没听过的值 " + strconv.Itoa(n)
}

func mainPseStatusMeaning(n int) string {
	switch n {
	case 1:
		return "整台的 PoE 电源开着"
	case 2:
		return "整台的 PoE 电源被关着 —— 这时候逐个口看状态没有意义"
	case 3:
		return "电源池自己报故障：这是电源模块/整机供电的事，不是哪一根线的事"
	}
	return "设备给了一个没听过的值"
}

func buildPoeEntries(rows []poeRow) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		e := map[string]any{"group": r.key.group, "port": r.key.port}
		if r.matched != "" {
			e["matchedBy"] = r.matched
			e["matchedByWhy"] = poeMatchWhy(r.matched)
		}
		if r.got[oidPethAdminEnable] {
			e["admin"] = "enabled"
			if !r.admin {
				e["admin"] = "disabled"
				e["adminWhy"] = "有人把这个口的供电关掉了（pethPsePortAdminEnable=false）。" +
					"★ 这不是故障，也不该去查线；要恢复得在设备上开回来（本工具只读，不改配置）"
			}
		}
		if r.got[oidPethDetectStatus] {
			e["status"] = poeStatusName(r.status)
			e["statusMeaning"] = poeStatusMeaning(r.status)
		} else {
			// ★ 「没读到」和「读到了、值是 disabled」是两个结论，界面上要分得开。
			e["statusMissing"] = "detectionStatus 这一栏这台不给读：这一条不能说它在供还是没在供"
		}
		if r.got[oidPethPairsControl] {
			e["pairsControllable"] = r.pairsControl
		}
		if p := poePairsName(r.pairs); p != "" {
			e["pairs"] = p
			e["pairsNote"] = poePairsWhy
		}
		if r.got[oidPethPriority] {
			if n := poePriorityName(r.priority); n != "" {
				e["priority"] = n
			} else {
				e["priority"] = r.priority // 认不出来就原样给编号，不猜一个档
			}
			e["priorityNote"] = poePriorityWhy
		}
		// 等级：★ 只在供电中才写（RFC 3621 原文），其余情况说明它为什么不写。
		if r.got[oidPethClass] {
			switch {
			case r.status == 3 && r.class >= 1 && r.class <= 5:
				e["class"] = poeClassName(r.class)
				e["classNote"] = poeClassWhy
			case r.status == 3:
				e["classUnknown"] = r.class
				e["classNote"] = "等级这一栏设备给的是标准五档以外的值（厂商自己的写法，" +
					"802.3at/bt 的 class5-8 不在这棵树里），只报编号、不换算成瓦"
			default:
				which := poeStatusWord(r.status)
				if which == "" {
					if raw := poeStatusName(r.status); raw != "" {
						which = "「" + raw + "」那一档"
					} else {
						which = "状态这一栏这台没给、或给的是标准以外的值"
					}
				} else {
					which = "「" + which + "」那一档"
				}
				e["classSkipped"] = fmt.Sprintf("设备给了等级这一栏，但 RFC 3621 写明它只在供电中有效"+
					"（这个口现在是%s），所以不报等级 —— 那是一个未定义的值", which)
			}
		}
		if r.pdType != "" {
			e["pdType"] = r.pdType
		}
		for _, c := range poeCounterColumns {
			if r.got[c] {
				e[poeCounterKey(c)] = r.counters[c]
			}
			if d, ok := r.deltas[c]; ok {
				e[poeCounterKey(c)+"Delta"] = d
			}
		}
		if r.unreliable != "" {
			e["countersUnreliable"] = r.unreliable
		}
		out = append(out, e)
	}
	return out
}

const (
	poeMatchIndex = "portIndex-equals-ifIndex"
	poeMatchType  = "pethPsePortType-names-the-port"
	poeMatchBoth  = "both-mappings"
)

func poeMatchWhy(how string) string {
	switch how {
	case poeMatchIndex:
		return "这一行是靠「PoE 口编号正好等于填的 ifIndex」认出来的 —— ★ 这是猜的映射，" +
			"RFC 3621 没规定 ifIndex 和 PoE 口编号的关系"
	case poeMatchType:
		return "这一行是设备自己给出的：它把接口名字写在 pethPsePortType 那一栏里，和填的那个口的名字对上了"
	case poeMatchBoth:
		return "两条独立的路子都对上了（编号正好相等，而且这一行的标签写着这个口名）"
	}
	return ""
}

// poePriorityName 认 RFC 3621 那三档。
func poePriorityName(n int) string {
	switch n {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "low"
	}
	return ""
}

// poePriorityWord 是 note 里用的中文词（预算不够时先断谁，现场要说「关键口」）。
func poePriorityWord(n int) string {
	switch n {
	case 1:
		return "关键"
	case 2:
		return "高"
	case 3:
		return "低"
	}
	return ""
}

// poeClassName 认那五档。★ 认不出来时只把编号原样带出来，**不换算成瓦**：
//
//	class5-8 是 802.3at/bt 的东西，这棵树里没有；而 af 和 at 同号不同功率，
//	拿一个表去换必然是错的。
func poeClassName(n int) string {
	if n >= 1 && n <= 5 {
		return "class" + strconv.Itoa(n-1)
	}
	return ""
}

// poeCounterKey 是计数器在结果里的键名。
func poeCounterKey(col string) string {
	switch col {
	case oidPethMPSAbsent:
		return "mpsAbsent"
	case oidPethBadSignature:
		return "invalidSignature"
	case oidPethDenied:
		return "powerDenied"
	case oidPethOverLoad:
		return "overLoad"
	case oidPethShort:
		return "shortCircuit"
	}
	return col
}

// poeCounterText 给收口那一句用：每个计数器在数什么。
var poeCounterText = map[string]string{
	"mpsAbsent":        "供电中掉回去（检测不到 PD 的维持签名）",
	"invalidSignature": "插上来的东西签名不合规（不是标准 PD，或者线不行）",
	"powerDenied":      "插上来要电、被这台拒绝",
	"overLoad":         "过载保护跳过",
	"shortCircuit":     "短路保护跳过",
}

// ── 定性 ──

// pseFaulty / pseOff 返回第一个报故障 / 关着的池子，没有则 nil。
//
// ★ 池子级的问题压住一切单口结论：池子塌了的时候口那一栏写什么都不是那个口的事。
func pseFaulty(pse []pseRow) *pseRow {
	for i := range pse {
		if pse[i].oper == 3 {
			return &pse[i]
		}
	}
	return nil
}

func pseOff(pse []pseRow) *pseRow {
	for i := range pse {
		if pse[i].oper == 2 {
			return &pse[i]
		}
	}
	return nil
}

// pseTight 返回第一个「余量紧」的池子。★ 算不出来的那些（没给额定）跳过 ——
// 它们交给 poePoolLine 去说「这一条本结果没回答」，不冒充结论。
func pseTight(pse []pseRow) *pseRow {
	for i := range pse {
		if s, _, _ := pse[i].budget(); s == budgetTight {
			return &pse[i]
		}
	}
	return nil
}

// groupText 说清是哪一个电源池。堆叠设备上「第 2 组」和「整台」不是一回事。
func groupText(p *pseRow) string {
	if p == nil {
		return "这台设备"
	}
	return fmt.Sprintf("%d 组（这台设备的电源池按组分：堆叠里的机箱 / 机架里的模块）", p.group)
}

// poePoolLine 是收口那句里的「整台的电源池怎么样」一段。
//
// ★ 池子压根没读到时，这一句必须是「没回答」而不是「正常」：
//
//	现场最容易出的事故就是把「问不出来」当成「没问题」抄进工单。
func poePoolLine(pse []pseRow) string {
	if len(pse) == 0 {
		return "★ 整台的电源池那一档（额定功率、实测在耗、总开关）这台不给读，" +
			"所以「余量够不够」本结果没有回答 —— 别把它读成「余量充足」。"
	}
	var parts []string
	for _, r := range pse {
		one := fmt.Sprintf("第 %d 组：", r.group)
		if o := mainPseStatusWord(r.oper); o != "" {
			one += "总开关 " + o
		} else {
			one += "总开关没读到"
		}
		if r.computable() {
			state, used, remaining := r.budget()
			one += fmt.Sprintf("，额定 %vW / 实测 %vW（已用 %.0f%%，还剩 %vW）",
				r.power, r.consumption, used, remaining)
			if r.threshold > 0 {
				one += fmt.Sprintf("，阈值 %v%%", r.threshold)
			}
			if state == budgetTight {
				one += " — 紧"
			}
		} else {
			one += "，额定/实测没给全（余量算不出来）"
		}
		parts = append(parts, one)
	}
	return strings.Join(parts, "；") + "。"
}

// poeStatusLine 是一个口现在供电情况的一句话（点名那条路上给 snmp-ok 用）。
func poeStatusLine(r poeRow) string {
	s := poeStatusNamed(r.status)
	if n := poeClassName(r.class); r.status == 3 && n != "" {
		if strings.HasSuffix(s, "）") {
			s = strings.TrimSuffix(s, "）") + "，" + n + "）"
		} else {
			s += "（" + n + "）"
		}
	}
	if r.got[oidPethPriority] {
		if p := poePriorityWord(r.priority); p != "" {
			s += "，优先级 " + p
		}
	}
	return s
}

// poeCounterDeltaLine 说「这一段又涨了几次」。★ 只在真的涨了的时候出现。
func poeCounterDeltaLine(r poeRow) string {
	var bits []string
	for _, c := range poeCounterColumns {
		d, ok := r.deltas[c]
		if !ok || d == 0 {
			continue
		}
		key := poeCounterKey(c)
		bits = append(bits, fmt.Sprintf("%s 涨了 %v 次（%s）", key, d, poeCounterText[key]))
	}
	if len(bits) == 0 {
		return ""
	}
	return "这一段：" + strings.Join(bits, "、") + " —— 在涨才是要动手的那一个。"
}

// poeVerdict 点名一个口时的定性。★ 电源池的问题压在上面（见 pseFaulty）。
//
// 每一句末尾都带上 tail（映射是猜的 / 这一趟没测到增量）：note 是现场唯一
// 复制进工单的那一行，这些限定只写在 values 里等于没写。
func poeVerdict(values map[string]any, r poeRow, pse []pseRow) ots.Verdict {
	who := fmt.Sprintf("%d 组的 %d 号 PoE 口", r.key.group, r.key.port)
	if r.pdType != "" {
		who += fmt.Sprintf("（标签写着「%s」）", r.pdType)
	}
	tail := mappingWarning(values) + sampleWarning(values)
	advice := ""
	if r.status == 3 {
		// 「在供电」这一档最容易被人读成「那台设备在工作」。
		advice = " " + poeStatusAdvice(3)
	}
	switch {
	case pseFaulty(pse) != nil:
		return ots.Verdict{Code: snmpPoePseFault, Values: values,
			Note: fmt.Sprintf("%s的电源池自己报故障（pethMainPseOperStatus=faulty）—— "+
				"这是电源模块 / 整机供电的事，不是这个口、也不是这根线的事：%s%s%s",
				groupText(pseFaulty(pse)), poePoolLine(pse), poeStatusAdvice(r.status), tail)}
	case pseOff(pse) != nil:
		return ots.Verdict{Code: snmpPoeOff, Values: values,
			Note: fmt.Sprintf("%s的 PoE 总开关是关着的（pethMainPseOperStatus=off）—— "+
				"整台的口都不会供电，这时候逐个看口是白跑：%s%s",
				groupText(pseOff(pse)), poePoolLine(pse), tail)}
	case r.got[oidPethAdminEnable] && !r.admin:
		extra := ""
		if r.status == 3 {
			extra = " ★ 可它的 detectionStatus 写着「正在供电」：这两栏对不上 —— " +
				"有些设备关掉之后不清状态。配置那一栏（使能）为准。"
		}
		return ots.Verdict{Code: snmpPoeDisabled, Values: values,
			Note: fmt.Sprintf("%s的供电被人关掉了（pethPsePortAdminEnable=false）。"+
				"★ 这不是故障，也不该去查线：要恢复得在设备上开回来（本工具只读，一行配置都不改）。%s%s%s",
				who, extra, poePoolLine(pse), tail)}
	case r.status == 0:
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("%s读到了，但 detectionStatus 这一栏设备没给 —— "+
				"这一条不能说它在供还是没在供，只看结果里读到的那几栏。%s%s",
				who, poePoolLine(pse), tail)}
	case r.status == 1:
		// 使能栏没读到时也要能报这一条：detectionStatus=disabled 这句是设备自己说的，
		// 缺了使能栏只少了「是谁关的」这一半，不该整条结论都不给。
		why := "★ 使能那一栏这台没给，所以分不清「是人关的」还是「设备自己把它排除在 PoE 之外」——" +
			"上一段说的两种下一步不一样，先确认这一栏能不能读。"
		if r.got[oidPethAdminEnable] && r.admin {
			why = "使能是开着的，可设备自己把它排除在 PoE 之外 —— 这种不是有人关的。"
		}
		return ots.Verdict{Code: snmpPoeDisabled, Values: values,
			Note: fmt.Sprintf("%s不在供电，detectionStatus 写着 disabled。%s %s %s%s",
				who, why, poeStatusAdvice(1), poePoolLine(pse), tail)}
	case r.status == 2:
		return ots.Verdict{Code: snmpPoeSearching, Values: values,
			Note: fmt.Sprintf("%s：%s %s%s%s", who, poeStatusAdvice(2),
				poePoolLine(pse), poeCounterDeltaLine(r), tail)}
	case r.status == 4 || r.status == 5 || r.status == 6:
		return ots.Verdict{Code: snmpPoeFault, Values: values,
			Note: fmt.Sprintf("%s报故障（detectionStatus=%s）。%s %s%s%s", who, poeStatusName(r.status),
				poeStatusAdvice(r.status), poePoolLine(pse), poeCounterDeltaLine(r), tail)}
	case r.deltas[oidPethDenied] > 0:
		return ots.Verdict{Code: snmpPoeBudget, Values: values,
			Note: fmt.Sprintf("%s这一段又被拒绝了 %v 次要电（powerDenied 在涨）—— 插得上、要不到电。%s%s%s",
				who, r.deltas[oidPethDenied], budgetAdvice(pseTight(pse), pse),
				poeCounterDeltaLine(r), tail)}
	case pseTight(pse) != nil:
		return ots.Verdict{Code: snmpPoeBudget, Values: values,
			Note: fmt.Sprintf("%s：%s。★ 但这台的余量已经紧了 —— %s%s%s",
				who, poeStatusLine(r), budgetAdvice(pseTight(pse), pse), poeCounterDeltaLine(r), tail)}
	default:
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("%s：%s。%s%s%s%s", who, poeStatusLine(r), poePoolLine(pse),
				poeCounterDeltaLine(r), advice, tail)}
	}
}

// sampleWarning 把「这一趟到底测没测到增量」带进复制得走的那一句。
//
// ★ 不写的话，界面是「供着电、计数器一个没涨」，看着像真的读两遍而且增量为 0 ——
//
//	那是另一种结论。
func sampleWarning(values map[string]any) string {
	for _, k := range []string{"sampleUnsure", "sampleAborted"} {
		if s, ok := values[k].(string); ok && s != "" {
			return " ★ " + s
		}
	}
	return ""
}

// budgetAdvice 是「余量紧了」那一条的下一步。
func budgetAdvice(tight *pseRow, pse []pseRow) string {
	if tight == nil {
		return poePoolLine(pse)
	}
	_, used, remaining := tight.budget()
	why := "顶到额定"
	switch {
	case tight.consumption > tight.power:
		// ★ 这一句要说破：数字本身不可信，但「池子顶满了」这个结论仍然成立。
		why = fmt.Sprintf("而且实测（%vW）比额定（%vW）还大 —— 这一栏的口径不对（有些设备报的不是瓦），"+
			"余量按顶满处理", tight.consumption, tight.power)
	case tight.threshold > 0:
		why = fmt.Sprintf("过了设备自己定的告警阈值 %v%%", tight.threshold)
	}
	return fmt.Sprintf("%d 组的电源池已经用到 %.0f%%（额定 %vW、实测 %vW、还剩 %vW），%s —— "+
		"下一个 PD 插上来很可能直接被拒绝（powerDenied 那个计数器就是在记这件事）。"+
		"两条路：把不重要的口按优先级排开（预算不够时设备先断 low 的那几个），或者减掉一些负载。",
		tight.group, used, tight.power, tight.consumption, remaining, why)
}

// mappingWarning 在点名一条路的收口里，把「这次是按编号猜的口」再顶一次。
//
// ★ note 常常被人整句复制进工单：只在 values 里写映射方式，复制走的那句就没有了。
func mappingWarning(values map[string]any) string {
	if _, ok := values["ifIndex"]; !ok {
		return ""
	}
	m, _ := values["ifIndexMapping"].(string)
	if m == "" {
		return ""
	}
	// 映射那几句自己带星号时不再加一颗：「★ ★」读起来像排版坏了，不像提醒。
	if strings.HasPrefix(m, "★") {
		return " " + m
	}
	return " ★ " + m
}

// poeFilteredOut 点名 + 按状态筛，把点到的那一行筛掉了：这本身就是答案。
func poeFilteredOut(values map[string]any, tableTotal int, state string) ots.Verdict {
	scope := ""
	if tableTotal > 1 {
		scope = fmt.Sprintf("（这张表一共 %v 个 PoE 口）", tableTotal)
	}
	what := "没在供电"
	if state == "on" {
		what = "在供电"
	}
	return ots.Verdict{Code: snmpOk, Values: values,
		Note: fmt.Sprintf("这一行读到了%s，但它现在的供电状态不是「%s」那一档，所以列表是空的。"+
			"★ 「被筛掉」不等于「没有这个口」，也不等于「设备不通」。", scope, what)}
}

// poeNotFound：点名要的那一行没读到。★ 「没读到」的几种口径不能揉成一句：
//
//	按 {组,口} 直取（没走表，不知道一共有几行）、走表筛（走全了才敢说没有）、
//	走表撞限量（没走全 ⇒ 「没这一行」不成立）、按 ifIndex 猜（连映射都不一定存在）。
func poeNotFound(values map[string]any, a snmpPoeArgs, truncated bool) ots.Verdict {
	which := "点名的这一行"
	switch {
	case a.GroupIndex > 0 && a.PortIndex > 0:
		which = fmt.Sprintf("%d 组的 %d 号 PoE 口", a.GroupIndex, a.PortIndex)
	case a.PortIndex > 0:
		which = fmt.Sprintf("编号为 %d 的 PoE 口（任何一组里都没有）", a.PortIndex)
	case a.GroupIndex > 0:
		which = fmt.Sprintf("%d 组里的任何一个 PoE 口", a.GroupIndex)
	case a.IfIndex > 0:
		which = fmt.Sprintf("ifIndex %d 对应的 PoE 口", a.IfIndex)
	case strings.TrimSpace(a.Name) != "":
		which = fmt.Sprintf("标签里含「%s」的 PoE 口", strings.TrimSpace(a.Name))
	}
	if a.IfIndex > 0 {
		values["ifIndex"] = a.IfIndex
		if m, _ := values["ifIndexMapping"].(string); m != "" {
			which += "（" + m + "）"
		}
	}
	if truncated {
		values["truncated"] = true
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("读了 %v 个 PoE 口撞到 limit 就停了，里面没有 %s —— 这不是「这台没这个口」。"+
				"把 limit 提到 %d 再看一次才算看完这张表", values["read"], which, poeMax)}
	}
	values["poePorts"] = []map[string]any{}
	// ★ 「没这一行」这句话的底气从哪来，要分开说：直取那一趟压根没走表，
	//   说「表读全了」是替设备撒的谎。
	basis := fmt.Sprintf("PoE 表读全了（%v 行）", values["countTotal"])
	if a.GroupIndex > 0 && a.PortIndex > 0 {
		basis = "这一行设备一栏都没给（这一条是按「组号 + 口号」直取的，没走整张表，" +
			"所以「这台一共有几个 PoE 口」本结果没有回答）"
	}
	return ots.Verdict{Code: snmpPoeNotFound, Values: values,
		Note: fmt.Sprintf("%s，里面没有 %s。★ 三件要一起看："+
			"pethPsePortIndex 和面板上的第几口在很多设备上并不相等；"+
			"RFC 3621 也没有 ifIndex 到口号的映射；"+
			"其次这个口可能在这台不给读的那棵子树里（同一台设备不同团体名能看见的表可以不一样）。"+
			"把「组号 / 口号」都留空列一遍整张表，对着 pethPsePortType 那一栏认。",
			basis, which)}
}

// poeNoData：设备活着，但这棵 PoE 子树没按我们要的方式给。
//
// ★ 「读不到」和「一个口都没供电」是两件相反的事：前者的下一步是换团体名/换设备问，
//
//	后者的下一步是去查这台设备的供电配置。合成一句「没有 PoE 信息」必然有一半人是白跑。
func (t *snmpTarget) poeNoData(ctx context.Context, values map[string]any) ots.Verdict {
	values["answered"] = true
	gave := t.poeSubtreeColumns(ctx)
	note := "这台的 PoE 那棵子树（" + pethArc + "）一条都没给。" +
		"★ 这不是「设备不通」：它答过话了。也不是「一个口都没供电」：那两句下一步完全相反。"
	switch {
	case len(gave) > 0:
		note += "它给了这些栏：" + strings.Join(gave, "、") +
			" —— 检测状态那一栏不给读，所以认不出有几行。这一条要去设备的 SNMP 视图/权限里看，不是查线。"
	default:
		note += "整棵子树都是空的，两种可能分不开：① 这台不是供电端（PSE）—— 不支持 PoE 的交换机、" +
			"以及受电设备本来就没有这棵树；② 这一棵被藏进了别的视图（换个团体名问 net.snmp.probe 看看）。"
	}
	return ots.Verdict{Code: snmpNoData, Values: values, Note: note}
}

// poeSubtreeColumns 在「什么都没读到」时再探一次：这棵子树里到底有没有东西、
// 给的是哪几栏。★ 只探一次、有限量，不在正常通路上多花报文。
func (t *snmpTarget) poeSubtreeColumns(ctx context.Context) []string {
	vs, _, err := t.client.WalkLimit(ctx, pethArc, poeProbeLimit)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range vs {
		if v.Missing() || v.EndOfMib() {
			continue
		}
		for c, name := range pethColumnName {
			if !seen[c] && strings.HasPrefix(strings.TrimPrefix(v.OID, "."), c+".") {
				seen[c] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// poeSummary 整张表的收口。
//
// ★ 表里有口没在供电**不是**故障：没插受电设备的口本来就该在 searching。
//
//	所以列表那一趟只在「池子级的问题」和「口报错」这两种事上给坏颜色 ——
//	fault 不是空口的正常样子，而池子级的问题会让整张表的结论都失效。
func poeSummary(values map[string]any, rows []poeRow, all int, pse []pseRow,
	filtered, named bool) ots.Verdict {
	var powering, searching, disabled, adminOff, faulty, unknown int
	var faultPorts, deniedPorts []string
	var deniedTotal uint64
	for _, r := range rows {
		switch r.status {
		case 1:
			disabled++
			// ★ 「没在供」有两种来路：admin 被人关了，和 admin 开着但设备自己不供
			//   （非 PoE 口、池子满了被排除）。前者去问是谁关的，后者去看池子预算，
			//   合成一个数就分不出该问谁。
			if r.got[oidPethAdminEnable] && !r.admin {
				adminOff++
			}
		case 2:
			searching++
		case 3:
			powering++
		case 4, 5, 6:
			faulty++
			faultPorts = append(faultPorts, fmt.Sprintf("%d组%d口", r.key.group, r.key.port))
		default:
			unknown++
		}
		if r.got[oidPethDenied] && r.counters[oidPethDenied] > 0 {
			deniedTotal += r.counters[oidPethDenied]
			deniedPorts = append(deniedPorts, fmt.Sprintf("%d组%d口（%v 次）",
				r.key.group, r.key.port, r.counters[oidPethDenied]))
		}
	}
	values["powering"] = powering
	values["searching"] = searching
	values["disabled"] = disabled
	if adminOff > 0 {
		values["adminOff"] = adminOff
	}
	values["faulty"] = faulty
	if unknown > 0 {
		values["statusUnknown"] = unknown
	}
	if len(faultPorts) > 0 {
		values["faultPorts"] = faultPorts
	}
	if len(deniedPorts) > 0 {
		values["powerDeniedPorts"] = deniedPorts
	}
	// ★ 那五个计数器是开机到现在攒的：不带上这一句，「3 次」看着像「刚才 3 次」。
	if since, ok := values["uptime"].(string); ok && since != "" {
		values["countersSince"] = "下面那些计数器是这台开机（" + since + "）到现在一共攒的次数，不是这一会儿的"
	}

	say := fmt.Sprintf("%d 个 PoE 口：%d 个在供电、%d 个在检测（多半没插受电设备）、"+
		"%d 个没在供、%d 个报错。",
		len(rows), powering, searching, disabled, faulty)
	if adminOff > 0 {
		say += fmt.Sprintf("「没在供」那 %d 个里，%d 个是 admin 被人关着的，其余 %d 个 admin 开着但设备自己不供（非 PoE 口，或者池子不够）。",
			disabled, adminOff, disabled-adminOff)
	}
	switch {
	case filtered:
		say += fmt.Sprintf("（这是按 state 筛过的，筛之前一共 %d 个）", all)
	case searching > 0:
		say += "★ 「在检测」这一栏里大部分是没插东西的空口，它不是故障清单 —— 要判断哪一个，点名再问一次。"
	}
	if unknown > 0 {
		say += fmt.Sprintf(" 另有 %d 行 detectionStatus 不给读，这一条没说它们供没供。", unknown)
	}
	if len(faultPorts) > 0 {
		say += fmt.Sprintf(" 报故障的口：%s。", strings.Join(faultPorts, "、"))
	}
	if deniedTotal > 0 {
		say += fmt.Sprintf(" 累计被拒绝要电：%s（★ 这是从开机攒到现在的，要看是不是「刚才还在拒」，填 watchSeconds 读两遍）。",
			strings.Join(deniedPorts, "、"))
	}
	if named && len(rows) > 1 {
		say += fmt.Sprintf(" ★ 点名的条件对上了 %d 行（堆叠设备上每箱都有一个同号口，或者 ifIndex 的两条映射路子指着不同行），一个都没挑。", len(rows))
	}
	say += " " + poePoolLine(pse)
	say += " " + poeClassWhy

	// 定性顺序：池子级 > 口报错 > 其余（其余一律 snmp-ok，见上面那段）。
	tail := mappingWarning(values) + sampleWarning(values)
	switch {
	case pseFaulty(pse) != nil:
		return ots.Verdict{Code: snmpPoePseFault, Values: values,
			Note: fmt.Sprintf("%s的电源池自己报故障（pethMainPseOperStatus=faulty）—— 这是电源模块/整机供电的事，"+
				"不是哪个口、哪根线的事。%s%s", groupText(pseFaulty(pse)), say, tail)}
	case pseOff(pse) != nil:
		return ots.Verdict{Code: snmpPoeOff, Values: values,
			Note: fmt.Sprintf("%s的 PoE 总开关是关着的（pethMainPseOperStatus=off）—— 整台的口都不会供电，"+
				"这时候逐个看口是白跑。%s%s", groupText(pseOff(pse)), say, tail)}
	case pseTight(pse) != nil:
		return ots.Verdict{Code: snmpPoeBudget, Values: values,
			Note: fmt.Sprintf("★ %s%s%s", budgetAdvice(pseTight(pse), pse), say, tail)}
	case faulty > 0:
		return ots.Verdict{Code: snmpPoeFault, Values: values,
			Note: fmt.Sprintf("%d 个口在报故障：%s。%s %s%s", faulty, strings.Join(faultPorts, "、"),
				poeStatusAdvice(4), say, tail)}
	}
	return ots.Verdict{Code: snmpOk, Values: values, Note: strings.TrimSpace(say) + tail}
}
