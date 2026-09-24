package tools

// ── net.snmp.lldp ──
//
// 这一张卡回答的是「这台设备从邻居那里听见了谁」：每一根线对端是哪台机器、
// 插在它哪个口上、它自己说它是干什么的、要管它该去哪个地址。
// 现场问它的那一句通常是：「这个口上的线另一头接到哪台交换机了？」
//
// ★★ 栏位、单位、枚举全部照 IEEE 802.1AB 的 LLDP-MIB 原文抄过
//
//	（lldpMIB ::= { iso std(0) iso8802(8802) ieee802dot1(1) ieee802dot1mibs(1) 2 }）。
//	八件最容易混、而下一步完全不同的事：
//
//	① **「邻居表是空的」在这棵树里是五种病**，下一步各不相同：这台压根没有
//	  LLDP-MIB 这一棵（本地那一组直接回「没有这个对象」）、有这一棵树但一行邻居
//	  都没有（对端没在说 LLDP）、这个口被配成 txOnly（只发不存，那空是必然的）、
//	  这个口 LLDP 被关了、以及表读到一半撞到限量。合成一句「没读到邻居」，
//	  这个工具就白做了。
//	② **本地口号（lldpRemLocalPortNum）不等于 ifIndex**。MIB 原文：桥设备按
//	  dot1dBasePort 编号，非桥设备才按 ifIndex。所以按接口号问邻居要走三条路对：
//	  dot1dBasePortIfIndex 是设备给的硬映射、编号正好相等是猜、
//	  lldpLocPortTable 里设备自己写的口名对上 ifName/ifDescr 是它自己交代的证据。
//	③ **chassisId / portId 是 OctetString，不是文本**。subtype=4 时它是 6 个原始
//	  字节（MAC），subtype=5 时第一个字节是地址族、后面才是地址。直接 .Str()
//	  会得到一屏乱码 —— 而这一栏正是拿去向对端机房报名字的那一句。
//	④ **timeMark 有两种填法**：填 0 的意思是「这就是当前值」，填 sysUpTime 的
//	  设备才能算出「这条邻居多久没刷新」。拿 sysUpTime 减它，倒挂（这台重启过、
//	  或者两个号根本不是同一把尺）时不给这个数。
//	⑤ **一个口上两行不是错**：MIB 允许一个本地口存多条邻居记录（索引里有
//	  lldpRemIndex）。现实里这就是「这个口下面接了台非网管交换机 / 分光器」，
//	  而设备不会主动把这件事说出来。
//	⑥ **邻居「一会儿有一会儿没有」只能看老化计数器**。lldpStatsRxPortAgeoutsTotal
//	  在涨 = 存进去的邻居过期被删掉了 = 对端停发 LLDP、或者 TTL 比它的发包间隔短、
//	  或者链路在抖。所以有 watchSeconds，而且两遍之间比 sysUpTime ——
//	  重启会把计数器清零，相减得到一个看着合理的假数。
//	⑦ **capSupported 和 capEnabled 是两个位图**。enabled 是空的而 supported 有位，
//	  意思是「它自称路由器但路由功能没开」—— 按 supported 分类会把一台纯二层的
//	  设备写进路由那一栏，然后人就去查它的路由表了。
//	⑧ **这棵树里没有 CDP**。老 Cisco 设备、以及大部分消费级设备只发 CDP，
//	  在 LLDP-MIB 里就是不存在。读不到邻居不等于对端不存在，只等于它没在说 LLDP。
//	⑨ **adminStatus 那一栏在标准里是 read-write，这一张卡只读它**。
//	  要改哪个口开不开 LLDP，得去设备上改（本工具不改任何配置）。
//
// ★ 判定只在「点名问某一个口 / 某一条线」时才有红的可能：整台设备列邻居时，
//   接了台不支持 LLDP 的老设备是常态，每次都红就等于不红。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
)

// LLDP-MIB。lldpRemTable 的索引是 {timeMark, localPortNum, remIndex} 三段，
// lldpLocPortTable 一段，lldpPortConfigTable 一段，lldpStatsRxPortTable 一段。
const (
	lldpArc        = "1.0.8802.1.1.2.1" // lldpObjects
	lldpConfGroup  = lldpArc + ".1"     // lldpConfiguration
	lldpStatGroup  = lldpArc + ".2"     // lldpStatistics
	lldpLocGroup   = lldpArc + ".3"     // lldpLocalSystemData
	lldpRemGroup   = lldpArc + ".4"     // lldpRemoteSystemsData
	lldpRemEntry   = lldpArc + ".4.1.1"
	lldpLocPortEnt = lldpArc + ".3.7.1"
	lldpPortCfgEnt = lldpConfGroup + ".6.1"
	lldpRxStatEnt  = lldpStatGroup + ".7.1"

	// 本地系统那一组（标量，实例都是 .0）。这几栏是「这台有没有这棵树」的探针。
	oidLldpLocChassisIDSubtype = lldpLocGroup + ".1"
	oidLldpLocChassisID        = lldpLocGroup + ".2"
	oidLldpLocSysName          = lldpLocGroup + ".3"
	oidLldpLocSysDesc          = lldpLocGroup + ".4"
	oidLldpLocSysCapSupported  = lldpLocGroup + ".5"
	oidLldpLocSysCapEnabled    = lldpLocGroup + ".6"

	// 本地口号表：这台设备自己怎么给它那些口编号（口号 → ID / 描述）。
	oidLldpLocPortIDSubtype = lldpLocPortEnt + ".2"
	oidLldpLocPortID        = lldpLocPortEnt + ".3"
	oidLldpLocPortDesc      = lldpLocPortEnt + ".4"

	// 邻居表（这一张卡的主干）。
	oidLldpRemChassisIDSubtype = lldpRemEntry + ".4"
	oidLldpRemChassisID        = lldpRemEntry + ".5"
	oidLldpRemPortIDSubtype    = lldpRemEntry + ".6"
	oidLldpRemPortID           = lldpRemEntry + ".7"
	oidLldpRemPortDesc         = lldpRemEntry + ".8"
	oidLldpRemSysName          = lldpRemEntry + ".9"
	oidLldpRemSysDesc          = lldpRemEntry + ".10"
	oidLldpRemSysCapSupported  = lldpRemEntry + ".11"
	oidLldpRemSysCapEnabled    = lldpRemEntry + ".12"

	// 邻居的管理地址：索引是 {timeMark, port, index, addrSubtype, addr...} 五段。
	lldpRemManAddrEnt      = lldpArc + ".4.2.1"
	oidLldpRemManAddrIfSub = lldpRemManAddrEnt + ".3" // 这个地址在它的哪个接口上（按哪种号数）
	oidLldpRemManAddrIfID  = lldpRemManAddrEnt + ".4" // 　‖ 那个接口的编号

	// 每个口的 LLDP 开关（txOnly / rxOnly / txAndRx / disabled）。
	// ★ 「邻居表为什么是空的」最省事的一条答案就在这一栏里。
	oidLldpPortConfigAdminStatus = lldpPortCfgEnt + ".2"

	// 收方向的分口统计。
	oidLldpRxPortFramesDiscarded = lldpRxStatEnt + ".2"
	oidLldpRxPortFramesErrors    = lldpRxStatEnt + ".3"
	oidLldpRxPortTLVUnrecognized = lldpRxStatEnt + ".6"
	oidLldpRxPortAgeouts         = lldpRxStatEnt + ".7"

	// 整张邻居表的变动计数（标量）。
	oidLldpStatsRemLastChange = lldpStatGroup + ".1"
	oidLldpStatsRemInserts    = lldpStatGroup + ".2"
	oidLldpStatsRemDeletes    = lldpStatGroup + ".3"
	oidLldpStatsRemDrops      = lldpStatGroup + ".4"
	oidLldpStatsRemAgeouts    = lldpStatGroup + ".5"
)

// lldpColumnName：这棵子树没按要的方式给时，把设备回过来的栏翻回名字，
// 好把「一个邻居都没有」和「它只放行了其中几栏」分开说。
var lldpColumnName = map[string]string{
	oidLldpRemChassisIDSubtype:   "lldpRemChassisIdSubtype（机箱标识是哪种编号）",
	oidLldpRemChassisID:          "lldpRemChassisId（对端是哪台）",
	oidLldpRemPortIDSubtype:      "lldpRemPortIdSubtype（端口标识是哪种编号）",
	oidLldpRemPortID:             "lldpRemPortId（对端哪个口）",
	oidLldpRemPortDesc:           "lldpRemPortDesc（对端那个口的描述）",
	oidLldpRemSysName:            "lldpRemSysName（对端自称叫什么）",
	oidLldpRemSysDesc:            "lldpRemSysDesc（对端的自述）",
	oidLldpRemSysCapSupported:    "lldpRemSysCapSupported（对端自称会的）",
	oidLldpRemSysCapEnabled:      "lldpRemSysCapEnabled（对端开着的）",
	oidLldpPortConfigAdminStatus: "lldpPortConfigAdminStatus（这个口 LLDP 开到哪一档）",
	oidLldpRxPortAgeouts:         "lldpStatsRxPortAgeoutsTotal（这个口的邻居老化过几次）",
	oidLldpLocPortDesc:           "lldpLocPortDesc（这个口号在本机上叫什么）",
	oidLldpLocPortID:             "lldpLocPortId",
}

// 这一张卡独有的判定。★ 每一条的下一步都不一样：
// 「这台没这棵树」要去问厂商，「这个口只发不收」要去改设备配置，
// 「邻居在老化」要去查对端为什么停发，「表没走全」什么都不用查、把限量提上去就行。
const (
	// 本地那一组设备明确回了「没有这个对象」，邻居子树也走不出东西：
	// 这台不按 LLDP-MIB 填（没开 LLDP 服务、只做 CDP、或者整棵被藏进别的视图）。
	snmpLldpUnsupported = "snmp-lldp-unsupported"
	// 树是有的，邻居一行都没有，而且没有哪个口的配置能解释这件事。
	snmpLldpNoNeighbor = "snmp-lldp-no-neighbor"
	// 这个口是 txOnly：这台只发不存，所以它的邻居行必然一条都没有 —— 不是故障。
	snmpLldpTxOnly = "snmp-lldp-tx-only"
	// 这个口的 LLDP 整个关着（disabled）：收发都没有，邻居表当然空。
	snmpLldpPortOff = "snmp-lldp-port-off"
	// 点名要的那个口没有邻居行（别的口有 ⇒ 这台的 LLDP 是开着的，只有这一条线上没人说话）。
	snmpLldpNotFound = "snmp-lldp-not-found"
	// 一个本地口上听见了不止一个邻居：下面接了非网管交换机 / hub / 分光器。
	snmpLldpMulti = "snmp-lldp-multi"
	// 两次读之间这个口的邻居老化过：邻居会消失，不是「没有邻居」。
	snmpLldpAging = "snmp-lldp-aging"
)

const (
	lldpDefault = portsDefault // 一次最多列几条邻居行
	lldpMax     = portsMax
	// 探测子树用的限量：只为看清「它给了哪几栏」，读到几十条就够说清。
	lldpProbeLimit = 64
	// timeMark 大于这个就当它不是「当前值」的标记，而是设备打的时间戳（百分秒）。
	// ★ 判据只能是这样：MIB 只说这是 TimeFilter，没规定填法。
	lldpMarkIsTime = 100
)

type snmpLldpArgs struct {
	snmpArgs
	// PortNum 是 LLDP 自己的口号（lldpRemLocalPortNum）。★ 它和 SNMP 的 UDP
	//   端口（snmpArgs.Port）不是一回事，所以键名带上 Num：两个都叫 port 的话
	//   JSON 解码时外层赢，用户填的 161 会被当成 LLDP 口号 —— 一个说不出口的错。
	PortNum      int    `json:"portNum,omitempty"`
	IfIndex      int    `json:"ifIndex,omitempty"`
	Name         string `json:"name,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	WatchSeconds int    `json:"watchSeconds,omitempty"`
	NoStats      bool   `json:"noStats,omitempty"`
}

var snmpLldpTool = ots.Tool{
	Name:  "net.snmp.lldp",
	Class: ots.ClassRead,
	Summary: "读一台设备的 LLDP 邻居（IEEE 802.1AB 的 LLDP-MIB）：本机哪一个口上听见了对端" +
		"哪台设备、它在对端的哪个口、对端自称是什么（交换/路由/无线 AP/电话/终端）、" +
		"以及它留下的管理地址。外加每个口的 LLDP 开关（只发 / 只听 / 收发 / 关着）和邻居老化次数。" +
		"★ 「邻居表是空的」在这棵树里是五种病，判定按下一步怎么查来分：" +
		"snmp-lldp-unsupported（这台没有 LLDP-MIB 这一棵：没开、只做 CDP、或被藏进别的视图）、" +
		"snmp-lldp-tx-only（这个口只发不存，空是必然的）、snmp-lldp-port-off（这个口 LLDP 关着）、" +
		"snmp-lldp-no-neighbor（树有、口在收，但没人说话）、snmp-lldp-not-found（点名的那个口没有邻居行，别的口有）。" +
		"另外两条：snmp-lldp-multi（一个口上听见好几个邻居 = 下面接了非网管交换机）、" +
		"snmp-lldp-aging（watchSeconds 期间邻居老化过 = 它会消失，不是没有）。" +
		"★ 本地口号（lldpRemLocalPortNum）不等于 ifIndex：MIB 规定桥设备按 dot1dBasePort 编号。" +
		"填 ifIndex 时结果会写明这次是靠设备的 dot1dBasePortIfIndex 硬映射对上的、还是按编号相等猜的。" +
		"★ 这棵树里没有 CDP：只发 CDP 的设备在这儿就是不存在，读不到邻居不等于对端不存在。" +
		"lldpPortConfigAdminStatus 在标准里可写，这一张卡只读，不改任何配置。先跑 net.snmp.probe 确认 SNMP 通不通。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr", "community"],
	  "properties": {
	    ` + snmpSchemaProps + `,
	    "portNum": {"type": "integer", "minimum": 1, "maximum": 4096,
	      "description": "点名问一个本地口（lldpRemLocalPortNum，LLDP 自己的口号）。★ 这个号和面板上的第几口、和 ifIndex 都不一定相等（MIB 规定桥设备按 dot1dBasePort 编号）—— 不确定就填 ifIndex 或者直接不填、把邻居列一遍对着 localPortName 认。"},
	    "ifIndex": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "按接口编号问「这根线另一头是谁」。★ 结果里的 portMapping 会写清这一条是怎么对上的：设备的 dot1dBasePortIfIndex 给的硬映射（可以当准）、还是「编号正好相等」猜的（要核）。几条路指着不同口号时全列出来，不挑一个 —— 挑错那一次是让人去查另一根线。"},
	    "name": {"type": "string",
	      "description": "按口名点名，认面板上的写法：GE1/0/5、Gi1/0/5、GigabitEthernet1/0/5 算同一个口。同时在设备的 lldpLocPortDesc/lldpLocPortId 和 ifName/ifDescr 里找。★ 匹配到几个口号就报几个，不挑「最像的那个」。"},
	    "limit": {"type": "integer", "minimum": 1, "maximum": 8192,
	      "description": "最多列几条邻居行，默认 512。撞到限量会给 snmp-not-walked，并且不会给「其余线都还好」这种结论。"},
	    "watchSeconds": {"type": "integer", "minimum": 0, "maximum": 300,
	      "description": "读两遍之间等几秒，用来看邻居表和老化计数器**这一段**动没动：新出现一个邻居、或者某个口的邻居老化掉了（对端停发 LLDP / TTL 比发包间隔短 / 链路在抖）。0 = 只读一遍，只给累计值。★ 第二遍才出现的那些邻居也照样报出来（neighbors 里标着 newNeighbor，一共几行记在 newNeighborRows），第二遍不见了的标 gone。两遍之间会比 sysUpTime，这台重启过就不给增量。"},
	    "noStats": {"type": "boolean",
	      "description": "不读那几个统计计数器（分口收包/错包/老化，以及整张邻居表的插入/删除/丢弃计数）。邻居本身照读；代价是看不出「邻居在老化」这一条。"}
	  }
	}`),
	Invoke: doSnmpLldp,
}

// lldpRemKey 是 lldpRemTable 的一行。★ 三段索引都要带上：同一个本地口可以先存
// 一条邻居、旧的那条还没老化掉就并存第二行（timeMark / remIndex 区分），
// 只按口号去重的话会把「邻居在换」显示成「一个邻居」。
type lldpRemKey struct{ mark, port, index int }

func (k lldpRemKey) String() string {
	return strconv.Itoa(k.port) + "." + strconv.Itoa(k.index)
}

func lldpKeyLess(a, b lldpRemKey) bool {
	if a.port != b.port {
		return a.port < b.port
	}
	if a.index != b.index {
		return a.index < b.index
	}
	return a.mark < b.mark
}

func sortLldpKeys(ks []lldpRemKey) {
	sort.Slice(ks, func(i, j int) bool { return lldpKeyLess(ks[i], ks[j]) })
}

// lldpRow 是一条邻居记录（还没翻成结果形状）。
type lldpRow struct {
	key        lldpRemKey
	got        map[string]bool
	chassisSub int
	chassisID  []byte
	portSub    int
	portID     []byte
	portDesc   string
	sysName    string
	sysDesc    string
	capSup     []byte
	capEn      []byte
	manAddrs   []string

	// 这条邻居多久没刷新（timeMark 是设备打的 sysUpTime 时才算得出来）。
	ageSeconds uint64
	ageSet     bool
	// 这个本地口上的邻居老化次数（读了统计才有）。
	ageouts     uint64
	ageoutsSet  bool
	ageoutDelta uint64
	agedOut     bool // 这一次观测期间这个口的老化计数涨了
	// 这个口号是被哪条路子认出来的（只有按 ifIndex 问时才有）。
	matched string
	// 第二遍读时这一行不见了 / 这一行的口上多了一行（watchSeconds 才有）。
	gone bool
	grew bool
	// 这个本地口的 LLDP 开关（txOnly 那一档能解释「这口为什么没有邻居」）。
	admin int
	// 设备在邻居表里给了哪几栏（只给了 sysName 没给 chassisId 这种，要说得清）。
	cols []string
}

// lldpLocPort 是 lldpLocPortTable 的一行：这台设备自己怎么给它那些口编号。
// ★ 这是「口号 → 口名」的权威来源（PoE 那张卡没有这个，只能猜）。
type lldpLocPort struct {
	num   int
	idSub int
	id    []byte
	desc  string
}

// lldpLocal 是本地系统那一组标量。missingAll 是「这台没有这棵树」的主要证据。
type lldpLocal struct {
	chassisSub int
	chassisID  []byte
	sysName    string
	sysDesc    string
	capSup     []byte
	capEn      []byte
	got        int  // 读到了几栏（0 = 一栏都没给）
	answered   bool // 设备对这几栏明确回了话（含回了「没有这一栏」）
}

// lldpStats 是那几个计数器：整张表一组、每个口一组。
type lldpStats struct {
	inserts, deletes, drops, ageouts uint64
	perPortAgeout                    map[int]uint64
	perPortError                     map[int]uint64
	perPortTLVUnknown                map[int]uint64
	any                              bool
}

func doSnmpLldp(ctx context.Context, raw json.RawMessage) (any, error) {
	var a snmpLldpArgs
	if err := snmpArgsFrom(raw, &a); err != nil {
		return nil, err
	}
	if a.PortNum < 0 || a.IfIndex < 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "portNum / ifIndex 不能是负数")
	}
	if a.PortNum > 4096 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"portNum %d 超出 1-4096 —— LLDP 的口号（LldpPortNumber）就规定在这个范围里", a.PortNum)
	}
	if a.IfIndex > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "ifIndex %d 超出 1-65535", a.IfIndex)
	}
	if a.WatchSeconds > 300 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"watchSeconds %d 太长（上限 300）—— 这一档是「看邻居有没有消失」，LLDP 的 TTL 一般是 120 秒",
			a.WatchSeconds)
	}
	limit := a.Limit
	if limit <= 0 {
		limit = lldpDefault
	}
	if limit > lldpMax {
		limit = lldpMax
	}

	t, err := snmpDial(a.snmpArgs)
	if err != nil {
		return nil, err
	}
	defer t.close()

	values := t.values()
	start := time.Now()

	// ── ① 本地那一组：先确认这台有没有 LLDP-MIB 这棵树 ──
	loc, err := t.lldpLocalInfo(ctx)
	if err != nil {
		verdict, done := snmpFail(err, values)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	// 走到这一步设备一定答过话了（这一趟要么读了标量、要么明确回了「没有这一栏」）。
	values["answered"] = true
	if loc.got > 0 {
		values["local"] = buildLldpLocal(loc)
	}

	sysUp, upErr := t.sysUpTime(ctx)
	if upErr == nil && sysUp > 0 {
		values["uptimeSeconds"] = sysUp / 100
		// 这一条是拿来判「邻居那几行有多新」的参照，光给秒数要人心算 —— 顺手带上能读的那一句。
		values["uptime"] = humanUptime(sysUp / 100)
	}

	// ── ② 邻居表：一次走完整棵子树，按三段索引分桶 ──
	rows, total, truncated, err := t.lldpRemRows(ctx, limit)
	if err != nil {
		verdict, done := lldpFail(err, values, true)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	for i := range rows {
		if sysUp > 0 && rows[i].key.mark >= lldpMarkIsTime && sysUp >= uint64(rows[i].key.mark) {
			rows[i].ageSeconds = (sysUp - uint64(rows[i].key.mark)) / 100
			rows[i].ageSet = true
		}
	}
	values["truncated"] = truncated
	values["readLimit"] = limit
	// 这张表没有「按索引直取」那条路（三段索引是走出来的），所以一共有几条**一直知道**。
	values["countTotal"] = total
	// ★ 整棵子树都是空的、而且本地那一组也没给 —— 先判「这台没有这棵树」，
	//   不能直接说「没人跟它说话」：前者要去问厂商，后者要去查对端。
	if len(rows) == 0 && loc.got == 0 && !truncated {
		if !t.lldpAnyLLDPOID(ctx) {
			return t.lldpUnsupported(ctx, values), nil
		}
	}

	// ── ③ 每个口的 LLDP 开关：这一栏能解释「为什么这个口没有邻居」 ──
	cfg, cfgErr := t.lldpPortConfig(ctx, limit)
	if cfgErr == nil && len(cfg) > 0 {
		values["portAdminCounts"] = lldpAdminCounts(cfg)
	}
	for i := range rows {
		rows[i].admin = cfg[rows[i].key.port]
	}
	// 口号 → 口名（lldpLocPortTable 是这台设备自己给的映射）。
	locPorts, _ := t.lldpLocPorts(ctx, limit)
	nameByPort := lldpPortNames(locPorts)
	mgmt := t.lldpManAddrs(ctx, rows)
	for i := range rows {
		rows[i].manAddrs = mgmt[rows[i].key]
	}

	// ── ④ 统计计数器（读了才知道邻居会不会消失；noStats 时整块跳过） ──
	var stats lldpStats
	if !a.NoStats {
		stats, _ = t.lldpStatsRead(ctx, limit)
		applyLldpStats(rows, stats)
	}
	var stats2 lldpStats // 第二遍读到的那一组（watchSeconds 才有）
	firstAt := time.Now()

	// ── ⑤ 定下来这一趟要报哪几行（点名 ifIndex / 口号 / 口名） ──
	set, err := t.pickLldpTargets(ctx, a, rows, locPorts, values)
	if err != nil {
		verdict, done := lldpFail(err, values, true)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return verdict, nil
	}
	named := set.named
	if named {
		// ★ 点名时比的是「要报哪几个口号」，不是「哪几行」：一个口上两行都要报出来，
		//   少了哪一行都可能正好是要找的那台。
		rows = filterLldpPorts(rows, set.ports)
	}
	// ★ read 记的是「读回来几条」，count 记的是「要报几条」：点名筛掉的那些不是不存在，
	//   写成 read=count 会把「这台一共 4 个邻居」显示成 1 个。
	all := total

	// ── ⑥ 要看邻居动没动，就读第二遍 ──
	var added []lldpRow
	if a.WatchSeconds > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(a.WatchSeconds) * time.Second):
		}
		if ctx.Err() != nil {
			values["sampleAborted"] = "第二次读之前这趟观测被取消了，没测到邻居有没有变"
		} else {
			second, _, _, serr := t.lldpRemRows(ctx, limit)
			sysDown, downErr := t.sysUpTime(ctx)
			if !a.NoStats {
				stats2, _ = t.lldpStatsRead(ctx, limit)
			}
			seconds := time.Since(firstAt).Seconds()
			values["sampleSeconds"] = round1(seconds)
			switch {
			case serr != nil:
				values["sampleUnsure"] = "第二次没读通，这一趟算不出邻居有没有变（上面那些是第一次读到的）"
			case upErr != nil || downErr != nil || sysUp == 0:
				values["sampleUnsure"] = "问不到 sysUpTime，没法确认这台设备中途有没有重启，增量仅供参考"
				added = applyLldpWatch(rows, second, stats, stats2)
			case sysDown < sysUp:
				values["rebooted"] = true
				values["sampleUnsure"] = "这台设备在两次读之间重启过（sysUpTime 倒退），计数器被清零了，" +
					"邻居的变动只按两遍的行数比，增量不给"
				added = applyLldpWatch(rows, second, lldpStats{}, stats2)
			default:
				added = applyLldpWatch(rows, second, stats, stats2)
			}
		}
	}
	// ★ 只在第二遍才出现的那些行也要报出来：问 watch 的人要找的就是「这一段里新插进来的
	//   那台」，而那一行的一切（对端叫什么、什么标识）只有第二遍读得到。第一遍它还不存在，
	//   所以口号开关、多久以前刷新、老化次数得从别处补齐，不然界面上是一行空。
	if len(added) > 0 {
		if named {
			added = filterLldpPorts(added, set.ports)
		}
		for i := range added {
			// 口名沿用第一遍那份（lldpLocPortTable 这一趟只读一次）。
			added[i].admin = cfg[added[i].key.port]
			if sysUp > 0 && added[i].key.mark >= lldpMarkIsTime && sysUp >= uint64(added[i].key.mark) {
				added[i].ageSeconds = (sysUp - uint64(added[i].key.mark)) / 100
				added[i].ageSet = true
			}
			if n, ok := stats2.perPortAgeout[added[i].key.port]; ok {
				added[i].ageouts, added[i].ageoutsSet = n, true
			}
		}
		if len(added) > 0 {
			mgmt := t.lldpManAddrs(ctx, added)
			for i := range added {
				added[i].manAddrs = mgmt[added[i].key]
			}
			values["newNeighborRows"] = len(added)
			rows = append(rows, added...)
		}
	}
	// ── ⑦ 收口 ──
	values["read"] = all
	values["count"] = len(rows)
	values["neighbors"] = buildLldpEntries(rows, nameByPort, set.match)
	values["elapsedMs"] = time.Since(start).Milliseconds()
	if !a.NoStats {
		shown := stats
		if stats2.any {
			shown = stats2 // ★ 界面上那几个数要是**第二次**读到的，不是半小时前那一趟的
		}
		values["stats"] = buildLldpStats(shown, rows)
	}

	switch {
	case len(rows) == 0 && named:
		if v, ok := lldpNamedButEmpty(values, a, set, cfg, locPorts, total, truncated); ok {
			return v, nil
		}
		if total == 0 && !truncated {
			return t.lldpEmptyTable(values, cfg, loc), nil
		}
		return lldpNotFound(values, a, set, truncated), nil
	case len(rows) == 0 && total == 0 && !truncated:
		return t.lldpEmptyTable(values, cfg, loc), nil
	case truncated:
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("读到 %v 行就撞上限量停了（限量 %v 行；走表是一栏一栏走的，最后那一行多半只读到几栏），"+
				"这台的邻居没有全列出来。这一条不是「其余线都还好」：把 limit 提到 %d 再看一次才算看完这张表",
				all, limit, lldpMax)}, nil
	case len(rows) == 1 && named:
		return lldpVerdict(values, rows[0], nameByPort, loc), nil
	}
	return lldpSummary(values, rows, cfg, all, named), nil
}

// lldpFail 是 snmpFail 的一层补丁：这台设备在前面一步已经答过话了
// （本地那一组那一趟），所以「这一步没读回来」不该翻成「设备没回话」——
// 两种病的下一步完全相反（查这棵子树的视图 / 查防火墙和团体名）。
func lldpFail(err error, values map[string]any, answered bool) (ots.Verdict, bool) {
	verdict, done := snmpFail(err, values)
	if done && answered {
		values["answered"] = true
		values["answeredEarlier"] = "本地那一组已经问过了：设备是活的、团体名也是对的。" +
			"这一步没读回来，要查的是这棵子树的视图/权限，不是网络"
	}
	return verdict, done
}

// ── 读 ──

// lldpLocalInfo 读本地系统那一组标量。
//
// ★ 一次 GET 全问，而不是拿到第一栏就收：这几栏都是标准要求的，
//
//	「一栏都没给」才是「这台没有这棵树」的证据；只缺一两栏是另一件事。
//	v1 问不存在的栏会让整个报文作废，所以那条路上要一栏一栏问（同 systemInfo）。
func (t *snmpTarget) lldpLocalInfo(ctx context.Context) (lldpLocal, error) {
	var loc lldpLocal
	oids := []string{oidLldpLocChassisIDSubtype + ".0", oidLldpLocChassisID + ".0",
		oidLldpLocSysName + ".0", oidLldpLocSysDesc + ".0",
		oidLldpLocSysCapSupported + ".0", oidLldpLocSysCapEnabled + ".0"}
	vs, err := t.multiGet(ctx, oids)
	if err != nil {
		var de *snmp.Error
		if !errors.As(err, &de) {
			return loc, err
		}
		// 设备回了 error-status：它认这个请求、只是这一栏不给。逐栏再问一遍，
		// 好把「一栏都没有」和「只少了其中几栏」分开。
		if vs, err = t.lldpLocalOneByOne(ctx); err != nil {
			return loc, err
		}
	}
	loc.answered = true
	for _, v := range vs {
		base := strings.TrimSuffix(v.OID, ".0")
		if v.Missing() || v.EndOfMib() {
			continue
		}
		switch base {
		case oidLldpLocChassisIDSubtype:
			loc.chassisSub = int(v.IntOr0())
		case oidLldpLocChassisID:
			loc.chassisID = append([]byte(nil), v.Val...)
		case oidLldpLocSysName:
			loc.sysName = printable(v.Str())
		case oidLldpLocSysDesc:
			loc.sysDesc = printable(v.Str())
		case oidLldpLocSysCapSupported:
			loc.capSup = append([]byte(nil), v.Val...)
		case oidLldpLocSysCapEnabled:
			loc.capEn = append([]byte(nil), v.Val...)
		default:
			continue
		}
		loc.got++
	}
	return loc, nil
}

func (t *snmpTarget) lldpLocalOneByOne(ctx context.Context) ([]snmp.VarBind, error) {
	var out []snmp.VarBind
	for _, o := range []string{oidLldpLocChassisIDSubtype, oidLldpLocChassisID,
		oidLldpLocSysName, oidLldpLocSysDesc, oidLldpLocSysCapSupported,
		oidLldpLocSysCapEnabled} {
		v, err := t.client.GetOne(ctx, o+".0")
		if err != nil {
			var de *snmp.Error
			if errors.As(err, &de) {
				continue // 这一栏它不给
			}
			return out, err
		}
		out = append(out, v)
	}
	return out, nil
}

// lldpAnyLLDPOID 再确认一次：本地那一组没给话时，往 lldpRemoteSystemsData 走一步，
// 看这台到底认不认 1.0.8802 这一棵。★ 只认「走得出 LLDP 树里的东西」，
// 不然一判就判死：有些实现邻居表有内容、本地标量却全不给。
func (t *snmpTarget) lldpAnyLLDPOID(ctx context.Context) bool {
	for _, prefix := range []string{lldpLocGroup, lldpRemGroup, lldpConfGroup, lldpStatGroup} {
		vs, _, err := t.client.WalkLimit(ctx, prefix, lldpProbeLimit)
		if err != nil && len(vs) == 0 {
			continue
		}
		for _, v := range vs {
			if v.Missing() || v.EndOfMib() {
				continue
			}
			if strings.HasPrefix(strings.TrimPrefix(v.OID, "."), lldpArc) {
				return true
			}
		}
	}
	return false
}

// lldpRemRows 走 lldpRemEntry 整棵子树，按 {timeMark, port, index} 分桶。
//
// ★ 走整棵子树、而不是拿某一栏当主干：邻居表有九栏，「每一栏都在」这个假设
//
//	一旦破了（只放行 sysName 的视图很常见），拿单栏走出来的表会整个空掉，
//	界面上变成「没人跟你说话」，实际上它给了对端名字、只少了机箱标识。
func (t *snmpTarget) lldpRemRows(ctx context.Context, limit int) ([]lldpRow, int, bool, error) {
	want := limit*len(lldpRemColumns()) + 8
	vs, truncated, err := t.client.WalkLimit(ctx, lldpRemEntry, want)
	if err != nil && len(vs) == 0 {
		return nil, 0, truncated, err
	}
	byKey := map[lldpRemKey]*lldpRow{}
	var keys []lldpRemKey
	for _, v := range vs {
		rest := indexAfter(v.OID, lldpRemEntry)
		col, k, ok := parseLldpRem(rest)
		if !ok {
			continue // 认不出的列（厂商自己加的那几栏）：宁可丢掉，不许当成对端名字
		}
		if v.Missing() || v.EndOfMib() {
			continue
		}
		r := byKey[k]
		if r == nil {
			r = &lldpRow{key: k, got: map[string]bool{}}
			byKey[k] = r
			keys = append(keys, k)
		}
		if !r.got[col] {
			r.cols = append(r.cols, col)
		}
		r.got[col] = true
		switch col {
		case oidLldpRemChassisIDSubtype:
			r.chassisSub = int(v.IntOr0())
		case oidLldpRemChassisID:
			r.chassisID = append([]byte(nil), v.Val...)
		case oidLldpRemPortIDSubtype:
			r.portSub = int(v.IntOr0())
		case oidLldpRemPortID:
			r.portID = append([]byte(nil), v.Val...)
		case oidLldpRemPortDesc:
			r.portDesc = printable(v.Str())
		case oidLldpRemSysName:
			r.sysName = printable(v.Str())
		case oidLldpRemSysDesc:
			r.sysDesc = printable(v.Str())
		case oidLldpRemSysCapSupported:
			r.capSup = append([]byte(nil), v.Val...)
		case oidLldpRemSysCapEnabled:
			r.capEn = append([]byte(nil), v.Val...)
		}
	}
	sortLldpKeys(keys)
	out := make([]lldpRow, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	return out, len(out), truncated, nil
}

func lldpRemColumns() []string {
	return []string{oidLldpRemChassisIDSubtype, oidLldpRemChassisID,
		oidLldpRemPortIDSubtype, oidLldpRemPortID, oidLldpRemPortDesc,
		oidLldpRemSysName, oidLldpRemSysDesc,
		oidLldpRemSysCapSupported, oidLldpRemSysCapEnabled}
}

// parseLldpRem 把「列号.时间点.口号.行号」拆回列和索引。
//
// ★ 四段必须刚好四段：邻居表管理地址那一棵（.4.2.1）的索引更长，
//
//	混进来的话会把地址里的字节当成口号。
func parseLldpRem(rest string) (column string, k lldpRemKey, ok bool) {
	p := strings.Split(rest, ".")
	if len(p) != 4 {
		return "", k, false
	}
	column = lldpRemEntry + "." + p[0]
	if _, known := lldpColumnName[column]; !known {
		return "", k, false
	}
	mark, e1 := strconv.Atoi(p[1])
	port, e2 := strconv.Atoi(p[2])
	index, e3 := strconv.Atoi(p[3])
	if e1 != nil || e2 != nil || e3 != nil || port <= 0 || index <= 0 || mark < 0 {
		return "", k, false
	}
	return column, lldpRemKey{mark, port, index}, true
}

// lldpManAddrs 读邻居留下的管理地址（lldpRemManAddrTable）。
//
// 这一棵的索引是五段：{timeMark, port, index, 地址族, 地址本身}，
// 地址那一段长度按地址族变（IPv4 四段、IPv6 十六段），所以只能按族拆。
// ★ 这一栏是把「找到对端」变成「能去管它」的那一步：现场拿到对端的自述之后，
//
//	下一步就是登它的地址 —— 没有这一栏，人只能拿着 hostname 回去问台账。
func (t *snmpTarget) lldpManAddrs(ctx context.Context, rows []lldpRow) map[lldpRemKey][]string {
	out := map[lldpRemKey][]string{}
	if len(rows) == 0 {
		return out
	}
	vs, _, err := t.client.WalkLimit(ctx, lldpRemManAddrEnt, lldpProbeLimit*8)
	if err != nil && len(vs) == 0 {
		return out
	}
	have := map[lldpRemKey]bool{}
	for _, r := range rows {
		have[r.key] = true
	}
	// 地址 → 它挂在那个接口上（.3/.4 两栏都是同一个索引的附属信息，按地址合起来）。
	type addrIf struct {
		sub, id int
		set     bool
	}
	ifs := map[lldpRemKey]map[string]*addrIf{}
	order := map[lldpRemKey][]string{}
	for _, v := range vs {
		if v.Missing() || v.EndOfMib() {
			continue
		}
		row, ok := parseLldpManAddr(indexAfter(v.OID, lldpRemManAddrEnt))
		if !ok || !have[row.key] {
			continue
		}
		m := ifs[row.key]
		if m == nil {
			m = map[string]*addrIf{}
			ifs[row.key] = m
		}
		one := m[row.addr]
		if one == nil {
			one = &addrIf{}
			m[row.addr] = one
			order[row.key] = append(order[row.key], row.addr)
		}
		if row.col == oidLldpRemManAddrIfSub {
			one.sub, one.set = int(v.IntOr0()), true
		} else if row.col == oidLldpRemManAddrIfID {
			one.id = int(v.IntOr0())
		}
	}
	for _, r := range rows {
		for _, addr := range order[r.key] {
			line := addr
			if x := ifs[r.key][addr]; x != nil && x.set {
				if w := manAddrIfWord(x.sub, x.id); w != "" {
					line += "（" + w + "）"
				}
			}
			out[r.key] = append(out[r.key], line)
		}
	}
	return out
}

// lldpManAddrRow 是管理地址那一棵的一个索引：哪一行、哪个地址、以及是哪一栏。
type lldpManAddrRow struct {
	key  lldpRemKey
	addr string
	col  string
}

// parseLldpManAddr 从索引里拆出「哪一行的哪个地址」。
//
// ★ 地址族以外的长度一律不猜：把 NSAP 的字节按 IPv4 点分十进制打出来，
//
//	等于给人一个看着能 ping 的地址，而它不是任何东西。
func parseLldpManAddr(rest string) (lldpManAddrRow, bool) {
	p := strings.Split(rest, ".")
	// 列号.时间点.口号.行号.地址族.地址长度.地址……：这一棵的索引里带着地址本身，
	// 所以实例 OID 的**开头**是列号、末尾那段是地址的最后一个字节 —— 反过来拆，
	// 一个结尾是 3 的 IPv4 就会被当成「lldpRemManAddrIfSubtype 这一栏」。
	if len(p) < 7 {
		return lldpManAddrRow{}, false
	}
	col := lldpRemManAddrEnt + "." + p[0]
	if col != oidLldpRemManAddrIfSub && col != oidLldpRemManAddrIfID {
		return lldpManAddrRow{}, false // 认不出的栏（厂商加的那几栏）：丢掉，不许当地址
	}
	mark, e1 := strconv.Atoi(p[1])
	port, e2 := strconv.Atoi(p[2])
	index, e3 := strconv.Atoi(p[3])
	afn, e4 := strconv.Atoi(p[4])
	addrLen, e5 := strconv.Atoi(p[5])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil ||
		port <= 0 || index <= 0 || mark < 0 {
		return lldpManAddrRow{}, false
	}
	raw := make([]byte, 0, len(p)-6)
	for _, x := range p[6:] {
		n, err := strconv.Atoi(x)
		if err != nil || n < 0 || n > 255 {
			return lldpManAddrRow{}, false
		}
		raw = append(raw, byte(n))
	}
	// ★ 索引里那个长度字节必须等于地址的实际长度：对不上就说明这一栏不是这么填的
	//   （厂商自己扩的索引、或者走表走歪了），拼出来的地址是个看着能 ping 的假地址。
	if addrLen <= 0 || len(raw) != addrLen {
		return lldpManAddrRow{}, false
	}
	row := lldpManAddrRow{key: lldpRemKey{mark, port, index}, col: col}
	switch {
	case afn == 1 && len(raw) == net.IPv4len:
		row.addr = net.IP(raw).String()
	case afn == 2 && len(raw) == net.IPv6len:
		row.addr = net.IP(raw).String()
	case afn == 18 && len(raw) == 6:
		row.addr = "MAC " + strings.ToUpper(formatMAC(raw, ":"))
	default:
		row.addr = fmt.Sprintf("地址族 %d（这一族没按它翻译，原始字节 %s）",
			afn, strings.ToUpper(hex.EncodeToString(raw)))
	}
	return row, true
}

// manAddrIfWord 把 lldpRemManAddrIfSubtype 那一栏翻成人话：
// 这个管理地址挂在它本机的哪个接口上（按哪种号数）。
func manAddrIfWord(sub, id int) string {
	switch sub {
	case 2:
		return "它本机的 ifIndex " + strconv.Itoa(id)
	case 3:
		return "它本机的系统口号 " + strconv.Itoa(id)
	case 1:
		return "它没说挂在哪个接口上"
	}
	return ""
}

// lldpPortConfig 走每个口的 LLDP 开关。
func (t *snmpTarget) lldpPortConfig(ctx context.Context, limit int) (map[int]int, error) {
	out := map[int]int{}
	vs, _, err := t.client.WalkLimit(ctx, oidLldpPortConfigAdminStatus, limit)
	if err != nil && len(vs) == 0 {
		return out, err
	}
	for _, v := range vs {
		if v.Missing() || v.EndOfMib() {
			continue
		}
		n, ok := atoiTail(indexAfter(v.OID, oidLldpPortConfigAdminStatus))
		if !ok {
			continue
		}
		out[n] = int(v.IntOr0())
	}
	return out, nil
}

// lldpLocPorts 走 lldpLocPortTable：口号 → 这口在本机上叫什么。
//
// ★ 两栏都读（id 和 desc），理由和 portNames 一样：有的厂商把口名写在 desc、
//
//	有的写在 id（id 那一栏本来是「MAC / 接口名」这类编号，写法按 subtype 变）。
func (t *snmpTarget) lldpLocPorts(ctx context.Context, limit int) (map[int]lldpLocPort, bool) {
	out := map[int]lldpLocPort{}
	read := func(column string, wantIDSub bool) {
		vs, _, err := t.client.WalkLimit(ctx, column, limit)
		if err != nil && len(vs) == 0 {
			return
		}
		for _, v := range vs {
			if v.Missing() || v.EndOfMib() {
				continue
			}
			n, ok := atoiTail(indexAfter(v.OID, column))
			if !ok {
				continue
			}
			p := out[n]
			p.num = n
			switch column {
			case oidLldpLocPortDesc:
				if s := printable(v.Str()); s != "" {
					p.desc = s
				}
			case oidLldpLocPortID:
				if len(v.Val) > 0 {
					p.id = append([]byte(nil), v.Val...)
				}
			case oidLldpLocPortIDSubtype:
				p.idSub = int(v.IntOr0())
			}
			out[n] = p
		}
	}
	read(oidLldpLocPortDesc, false)
	read(oidLldpLocPortID, false)
	read(oidLldpLocPortIDSubtype, true)
	return out, len(out) > 0
}

// lldpPortNames 给出「口号 → 能用来认它的那几个名字」。
func lldpPortNames(ports map[int]lldpLocPort) map[int][]portNameHit {
	out := map[int][]portNameHit{}
	for n, p := range ports {
		var hits []portNameHit
		if s := strings.TrimSpace(p.desc); s != "" {
			hits = append(hits, portNameHit{s: s})
		}
		if len(p.id) > 0 {
			// ★ id 那一栏按 subtype 才是文本或二进制：不带上编号就翻不出人话。
			text, _ := portIDText(p.idSub, p.id)
			if s := strings.TrimSpace(text); s != "" && !containsStrHit(hits, s) {
				hits = append(hits, portNameHit{s: s})
			}
		}
		if len(hits) > 0 {
			out[n] = hits
		}
	}
	return out
}

func containsStrHit(hits []portNameHit, s string) bool {
	for _, h := range hits {
		if strings.EqualFold(h.s, s) {
			return true
		}
	}
	return false
}

// lldpStatsRead 读那几个计数器：整张邻居表一组标量，收方向一栏一张表。
func (t *snmpTarget) lldpStatsRead(ctx context.Context, limit int) (lldpStats, error) {
	s := lldpStats{perPortAgeout: map[int]uint64{}, perPortError: map[int]uint64{},
		perPortTLVUnknown: map[int]uint64{}}
	for col, dst := range map[string]*uint64{
		oidLldpStatsRemInserts: &s.inserts, oidLldpStatsRemDeletes: &s.deletes,
		oidLldpStatsRemDrops: &s.drops, oidLldpStatsRemAgeouts: &s.ageouts,
	} {
		v, err := t.client.GetOne(ctx, col+".0")
		if err != nil || v.Missing() || v.EndOfMib() {
			continue
		}
		*dst = v.UintOr0()
		s.any = true
	}
	for col, dst := range map[string]*map[int]uint64{
		oidLldpRxPortAgeouts:         &s.perPortAgeout,
		oidLldpRxPortFramesErrors:    &s.perPortError,
		oidLldpRxPortTLVUnrecognized: &s.perPortTLVUnknown,
	} {
		vs, _, err := t.client.WalkLimit(ctx, col, limit)
		if err != nil && len(vs) == 0 {
			continue
		}
		for _, v := range vs {
			if v.Missing() || v.EndOfMib() {
				continue
			}
			n, ok := atoiTail(indexAfter(v.OID, col))
			if !ok {
				continue
			}
			(*dst)[n] = v.UintOr0()
			s.any = true
		}
	}
	return s, nil
}

func applyLldpStats(rows []lldpRow, s lldpStats) {
	for i := range rows {
		if v, ok := s.perPortAgeout[rows[i].key.port]; ok {
			rows[i].ageouts, rows[i].ageoutsSet = v, true
		}
	}
}

// applyLldpWatch 把第二遍的读数和增量落到第一遍的行上，并带回只在第二遍出现的那些行。
//
// ★ 邻居行本身也参与比较（不只是计数器）：新出现的邻居和对端改了口名，
//
//	都只在行数/内容这一档看得见，而老化计数器不涨也可能只是设备没实现它。
func applyLldpWatch(rows []lldpRow, second []lldpRow, first, last lldpStats) []lldpRow {
	seen := map[lldpRemKey]bool{}
	for _, r := range second {
		seen[r.key] = true
	}
	for i := range rows {
		k := rows[i].key
		if !seen[k] {
			rows[i].gone = true
		}
	}
	// ★ 只在第二遍出现的那些行原样带回去：现场问这一档的人要找的就是
	//
	//	「这一段观察里新插进来的那台」，而那一行的全部内容只有第二遍读得到 ——
	//	把它丢掉，等于恰好把答案扔了；标在第一遍已有的行上也不对，
	//	那几行是老的，只是它们那个口涨了。
	var added []lldpRow
	for _, r := range second {
		if _, ok := lookupLldpRow(rows, r.key); !ok {
			cp := r
			cp.grew = true
			added = append(added, cp)
		}
	}
	sort.Slice(added, func(i, j int) bool { return lldpKeyLess(added[i].key, added[j].key) })

	// 老化：只认「第二遍的号 ≥ 第一遍的号」那一种涨法。★ 这三个计数是
	// ZeroBasedCounter32，设备重启会清零（重启那条路已经按 sysUpTime 拦了），
	// 但两遍之间被人为 clear 也会倒退 —— 倒退时不给增量，别拿减法绕回一个巨大的数。
	if !first.any || !last.any {
		return added
	}
	for i := range rows {
		p := rows[i].key.port
		a, b := first.perPortAgeout[p], last.perPortAgeout[p]
		if a == 0 && b == 0 {
			continue
		}
		if b > a {
			rows[i].ageoutDelta = b - a
			rows[i].agedOut = true
			rows[i].ageouts, rows[i].ageoutsSet = b, true
		}
	}
	return added
}

func lookupLldpRow(rows []lldpRow, k lldpRemKey) (lldpRow, bool) {
	for _, r := range rows {
		if r.key == k {
			return r, true
		}
	}
	return lldpRow{}, false
}

// atoiTail 取实例后缀里最后一段数字（一栏一索引的表就是那个索引）。
func atoiTail(rest string) (int, bool) {
	if rest == "" {
		return 0, false
	}
	if i := strings.LastIndexByte(rest, '.'); i >= 0 {
		rest = rest[i+1:]
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ── 定下要报哪几行 ──

type lldpTargetSet struct {
	ports map[int]bool
	match map[int]string
	named bool
}

// pickLldpTargets 把点名的口号 / 接口号 / 口名换成 lldpRemLocalPortNum。
//
// ★ 按 ifIndex 问时三条路各走一遍，一条都不藏：
//
//	A. dot1dBasePortIfIndex —— 设备给的硬映射（桥设备上口号就是 dot1dBasePort）。
//	   这一条是**证据**，不是猜，界面上要按证据写。
//	B. 口号正好等于 ifIndex —— MIB 说非桥设备就是这样编号的，但这是猜。
//	C. lldpLocPortTable 里设备自己写的口名，和这个接口的 ifName/ifDescr 对上了 ——
//	   它自己交代的，比 B 硬。
//
// 指着不同口号时全留着：宁可多报一根线，也不挑一个 —— 挑错那一次是让人去查
// 别人的链路，而这一趟的结论是照着它去机房的。
func (t *snmpTarget) pickLldpTargets(ctx context.Context, a snmpLldpArgs,
	rows []lldpRow, locPorts map[int]lldpLocPort, values map[string]any) (lldpTargetSet, error) {
	set := lldpTargetSet{ports: map[int]bool{}, match: map[int]string{}, named: true}
	switch {
	case a.PortNum > 0:
		set.ports[a.PortNum] = true
		values["portNum"] = a.PortNum
		return set, nil
	case a.IfIndex > 0:
		return t.lldpByIfIndex(ctx, rows, locPorts, a.IfIndex, values)
	case strings.TrimSpace(a.Name) != "":
		names := lldpPortNames(locPorts)
		for n, hits := range names {
			if portNameMatches(a.Name, hits) {
				set.ports[n] = true
				set.match[n] = lldpMatchName
			}
		}
		// ★ 口名也可能只在 ifName/ifDescr 里写着（有些设备 lldpLocPortTable 是空的）。
		//   这条路上「口号 == ifIndex」这个假设跑不掉，所以匹配上也要标成猜的。
		if len(set.ports) == 0 {
			for n, hits := range t.ifaceNamesByIndex(ctx) {
				if portNameMatches(a.Name, hits) {
					set.ports[n] = true
					set.match[n] = lldpMatchEqual
				}
			}
		}
		values["name"] = strings.TrimSpace(a.Name)
		if len(set.ports) == 0 {
			values["portMapping"] = "没对上：设备的 lldpLocPortTable 和 ifName/ifDescr 里，" +
				"都没有按面板写法认得出「" + strings.TrimSpace(a.Name) + "」的这个口"
		} else {
			values["portMapping"] = "按口名对上的（在设备的 lldpLocPortDesc / lldpLocPortId 里认出来的）"
			if lldpHasGuess(set.match) {
				values["portMapping"] = "★ 有一部分是按「口号正好等于 ifIndex」对上的，不是设备给的映射，要核"
			}
		}
		return set, nil
	}
	set.named = false
	return set, nil
}

// lldpHasGuess 这份候选里有没有「按编号相等猜的」那一条 —— 有就要在界面上标出来。
func lldpHasGuess(match map[int]string) bool {
	for _, m := range match {
		if m == lldpMatchEqual {
			return true
		}
	}
	return false
}

// ifaceNamesByIndex 取整张接口表里能用来认那些口的名字（按 ifIndex 分）。
func (t *snmpTarget) ifaceNamesByIndex(ctx context.Context) map[int][]portNameHit {
	out := map[int][]portNameHit{}
	for _, col := range []string{oidIfName, oidIfDescr} {
		vs, _, err := t.client.WalkLimit(ctx, col, portsMax)
		if err != nil && len(vs) == 0 {
			continue
		}
		for _, v := range vs {
			if v.Missing() || v.EndOfMib() {
				continue
			}
			n, ok := atoiTail(indexAfter(v.OID, col))
			if !ok {
				continue
			}
			s := printable(v.Str())
			if s == "" {
				continue
			}
			dup := false
			for _, h := range out[n] {
				if strings.EqualFold(h.s, s) {
					dup = true
				}
			}
			if !dup {
				out[n] = append(out[n], portNameHit{s: s})
			}
		}
	}
	return out
}

// lldpByIfIndex 把接口编号换成 LLDP 口号，并写清是怎么对的。
func (t *snmpTarget) lldpByIfIndex(ctx context.Context, rows []lldpRow,
	locPorts map[int]lldpLocPort, ifIndex int, values map[string]any) (lldpTargetSet, error) {
	set := lldpTargetSet{ports: map[int]bool{}, match: map[int]string{}, named: true}
	values["ifIndex"] = ifIndex

	// A. 硬映射：dot1dBasePort → ifIndex。
	var byBridge []int
	if vs, _, err := t.client.WalkLimit(ctx, oidDot1dBasePortIfIndex, portsMax); err == nil {
		for _, v := range vs {
			if v.Missing() || v.EndOfMib() {
				continue
			}
			basePort, ok := atoiTail(indexAfter(v.OID, oidDot1dBasePortIfIndex))
			if !ok {
				continue
			}
			if int(v.IntOr0()) == ifIndex {
				byBridge = append(byBridge, basePort)
			}
		}
	}
	// B. 编号正好相等（猜）。
	var byEqual []int
	for n := range locPorts {
		if n == ifIndex {
			byEqual = append(byEqual, n)
		}
	}
	// C. 设备自己写的口名对上这个接口的 ifName/ifDescr。
	var byName []int
	names := t.ifaceNames(ctx, ifIndex)
	if len(names) > 0 {
		hits := lldpPortNames(locPorts)
		for n, cand := range hits {
			for _, nm := range names {
				if portNameMatches(nm, cand) {
					byName = append(byName, n)
					break
				}
			}
		}
	}

	add := func(list []int, how string) {
		for _, n := range list {
			if prev, ok := set.match[n]; ok {
				if prev != how {
					set.match[n] = lldpMatchBothPorts
				}
				continue
			}
			set.match[n] = how
			set.ports[n] = true
		}
	}
	add(byBridge, lldpMatchBridge)
	add(byName, lldpMatchName)
	add(byEqual, lldpMatchEqual)
	values["portMapping"] = lldpMappingNote(len(set.ports), byBridge, byName, byEqual, len(names) > 0)
	if len(byBridge) > 0 && !sameIntSet(byBridge, append(append([]int{}, byName...), byEqual...)) {
		values["portMappingAmbiguous"] = true
	}
	return set, nil
}

// sameIntSet 两组候选是不是指着同一批口号（顺序不看：两边都是按号排过序走出来的）。
func sameIntSet(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]int(nil), a...)
	bs := append([]int(nil), b...)
	sort.Ints(as)
	sort.Ints(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// lldpMappingNote 说清这次「接口编号 → LLDP 口号」是怎么对上的。
//
// ★ 这一条和 PoE 那张卡不一样：这里可能有硬映射（dot1dBasePortIfIndex），
//
//	所以对上了要敢写「这一条可以当准」；只有猜的那一条才要人核。
func lldpMappingNote(got int, byBridge, byName, byEqual []int, haveNames bool) string {
	switch {
	case got == 0:
		if haveNames {
			return "没对上：这台设备既没有在 dot1dBasePortIfIndex 里把这个接口映射到某个 LLDP 口，" +
				"lldpLocPortTable 里也没有哪一行的口名等于这个接口"
		}
		return "没对上：这台不给读 ifName/ifDescr，dot1dBasePortIfIndex 和 lldpLocPortTable 里也认不出这个接口号"
	case len(byBridge) > 0 && len(byName)+len(byEqual) > 0 &&
		!sameIntSet(byBridge, append(append([]int{}, byName...), byEqual...)):
		return "★ 有两个候选：一条是设备的 dot1dBasePortIfIndex 映射，另一条是编号/口名对上的，" +
			"两者指着不同的口号 —— 两个口都问了，邻居行按各自那一行的口号列着" +
			"（没列出来的那个就是真没有邻居），别把它们当成同一根线"
	case len(byBridge) > 0:
		return "按设备的 dot1dBasePortIfIndex 对上的（桥设备上 LLDP 口号就是 dot1dBasePort，" +
			"这一条是设备给的映射，不是猜的）"
	case len(byName) > 0:
		return "按设备自己写在 lldpLocPortDesc / lldpLocPortId 里的口名对上的"
	default:
		return "★ 按「lldpRemLocalPortNum 正好等于 ifIndex」猜的：MIB 只说非桥设备才这么编号。" +
			"结果里每一条都带着它自己的 LLDP 口号，请核一下是不是这根线"
	}
}

func filterLldpPorts(rows []lldpRow, ports map[int]bool) []lldpRow {
	if len(ports) == 0 {
		return nil
	}
	out := make([]lldpRow, 0, len(rows))
	for _, r := range rows {
		if ports[r.key.port] {
			out = append(out, r)
		}
	}
	return out
}

// ── 翻译 ──

// chassisIDText / portIDText：把 chassisId / portId 那一串字节翻成人能读的东西。
//
// ★ 分成两个函数是必须的，不是洁癖：这两栏的 subtype 是**两套枚举**——
//
//	机箱标识的 4 是 MAC、5 是网络地址，而端口标识的 3 才是 MAC、4 是网络地址。
//	共用一张表的话，subtype=4 的端口标识会被当成 MAC 打出来，而它按标准是网络地址
//	—— 这一栏正是拿去向机房报名字的那一句，宁可退到十六进制也不能编一个。
//
// ★ 返回的第二个值「为什么这样翻」要给界面：这一栏是 OctetString，
//
//	subtype 才是那把尺。
func chassisIDText(subtype int, raw []byte) (string, string) {
	return lldpIDText(subtype, raw, 4, 5, []int{1, 2, 3, 6, 7})
}

func portIDText(subtype int, raw []byte) (string, string) {
	return lldpIDText(subtype, raw, 3, 4, []int{1, 2, 5, 6, 7})
}

// lldpIDText 按「MAC 是几号、网络地址是几号、哪几号是文本」翻一栏标识。
func lldpIDText(subtype int, raw []byte, macSub, netSub int, textSubs []int) (text string, why string) {
	if len(raw) == 0 {
		return "", ""
	}
	switch subtype {
	case macSub:
		if len(raw) == 6 {
			return strings.ToUpper(formatMAC(raw, ":")), "标识是 MAC（原始 6 字节，按网络序打出来）"
		}
		return strings.ToUpper(hex.EncodeToString(raw)),
			fmt.Sprintf("标识写着是 MAC，可长度是 %d 不是 6，只按原始字节打", len(raw))
	case netSub:
		if len(raw) >= 5 && raw[0] == 1 {
			return net.IP(raw[1:5]).String(), "标识是一个 IPv4 地址（第一个字节是地址族 1）"
		}
		if len(raw) >= 17 && raw[0] == 2 {
			return net.IP(raw[1:17]).String(), "标识是一个 IPv6 地址（第一个字节是地址族 2）"
		}
		return fmt.Sprintf("地址族 %d：%s", raw[0], strings.ToUpper(hex.EncodeToString(raw[1:]))),
			"标识写着是网络地址，但不是这一张卡认得的地址族，只按原始字节打"
	}
	for _, s := range textSubs {
		if subtype == s {
			// ★ 这几族按标准是 DisplayString（可打印 ASCII）。printable() 会把控制符
			//   换成 □、把非法 UTF-8 换成 U+FFFD，永远「有内容」，于是设备给的二进制
			//   会被打成一片方块 —— 而这一栏是抄进工单的那一行。
			if txt, ok := lldpAsciiText(raw); ok {
				return txt, ""
			}
			return strings.ToUpper(hex.EncodeToString(raw)),
				fmt.Sprintf("这一栏按标准该是文本（编号 %d），设备给的不是能打的字符，只按原始字节打", subtype)
		}
	}
	// ★ 认不出的 subtype + 二进制：给十六进制，并说清楚这是「没按某一族翻」，
	//   不是设备给了乱码 —— 人看到一屏 hex 的第一反应是这台坏了。
	return strings.ToUpper(hex.EncodeToString(raw)),
		fmt.Sprintf("这一栏的编号类型（subtype %d）这一张卡不认得，只按原始字节打", subtype)
}

// lldpAsciiText：整段都是可打印 ASCII 才算文本。
//
// 剔掉首尾空白后什么都不剩的也算「这一栏不是文本」—— 它到底是几个空格还是几个 0x00，
//
//	十六进制看得出来，一个空字符串看不出来。
func lldpAsciiText(raw []byte) (string, bool) {
	for _, c := range raw {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	s := strings.TrimSpace(string(raw))
	return s, s != ""
}

// chassisSubtypeName / portSubtypeName：两套枚举**编号不一样**。
//
// ★ 机箱标识的 1 是 chassisComponent，端口标识的 1 是 interfaceAlias；
//
//	拿一张表去翻两栏，界面上就会出现「这个口的标识是接口备注」这种没影的结论。
func chassisSubtypeName(n int) string {
	switch n {
	case 1:
		return "机箱部件号（chassisComponent）"
	case 2:
		return "接口备注（interfaceAlias）"
	case 3:
		return "端口部件号（portComponent）"
	case 4:
		return "MAC 地址（macAddress）"
	case 5:
		return "网络地址（networkAddress）"
	case 6:
		return "接口名（interfaceName）"
	case 7:
		return "本地定义的值（local）"
	}
	return ""
}

func portSubtypeName(n int) string {
	switch n {
	case 1:
		return "接口备注（interfaceAlias）"
	case 2:
		return "端口部件号（portComponent）"
	case 3:
		return "MAC 地址（macAddress）"
	case 4:
		return "网络地址（networkAddress）"
	case 5:
		return "接口名（interfaceName）"
	case 6:
		return "电路标识（agentCircuitId）"
	case 7:
		return "本地定义的值（local）"
	}
	return ""
}

func chassisSubtypeWord(n int) string {
	switch n {
	case 4:
		return "MAC"
	case 5:
		return "网络地址"
	case 6, 2, 3, 1, 7:
		return "文本"
	}
	return ""
}

// lldpAdminName 是这个口的 LLDP 开关（txOnly(1) rxOnly(2) txAndRx(3) disabled(4)）。
func lldpAdminName(n int) string {
	switch n {
	case 1:
		return "txOnly"
	case 2:
		return "rxOnly"
	case 3:
		return "txAndRx"
	case 4:
		return "disabled"
	}
	return ""
}

func lldpAdminWord(n int) string {
	switch n {
	case 1:
		return "只发不收"
	case 2:
		return "只听不发"
	case 3:
		return "又发又听"
	case 4:
		return "关着"
	}
	return ""
}

// lldpAdminMeaning 把开关那一格翻成「所以这一栏该看到什么」。
//
// ★ txOnly 是「邻居表为什么是空的」最省事的一条答案：这台在这个口发了 LLDP，
//
//	但不把听来的东西存表里（RFC 原文就是这么规定的），所以表空是必然的，
//	不是对端没说话。这一条要敢下结论，因为它的下一步是「去改这一档」，
//	而查线、查对端都是白跑。
func lldpAdminMeaning(n int) string {
	switch n {
	case 1:
		return "这个口只发不存：它的邻居表本来就不会有这一口，跟对端发不发没关系"
	case 2:
		return "这个口只听不发：能看见对端，对端那边看不见这台（查「为什么对面没有我的邻居」时就是这一条）"
	case 3:
		return "正常收发"
	case 4:
		return "这个口 LLDP 整个关掉：不发也不存"
	}
	return "设备给了一个没听过的值"
}

// lldpCapNames 解 LldpSystemCapabilitiesMap 那两位字节图。
//
// ★ 位序是从第一个字节的最高位开始数（other(0) 在 bit0）：按最低位读会把
//
//	「交换机」念成「电缆调制解调器」，而这一栏是界面上「对端是什么」那一格。
func lldpCapNames(v []byte) []string {
	if len(v) == 0 {
		return nil
	}
	var out []string
	for i, name := range lldpCapBits {
		bit := 7 - uint(i%8)
		b := i / 8
		if b >= len(v) {
			break
		}
		if v[b]&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	return out
}

var lldpCapBits = []string{
	"其它（other）", "中继（repeater）", "交换（bridge）", "无线 AP（wlanAP）",
	"路由（router）", "电话（telephone）", "电缆接入设备（docsis）", "只是终端（stationOnly）",
}

// lldpCapNote 处理 supported 和 enabled 不一致那两种情况。
func lldpCapNote(sup, en []byte) string {
	if len(sup) == 0 || len(en) == 0 {
		return ""
	}
	s, e := lldpCapNames(sup), lldpCapNames(en)
	if len(s) > 0 && len(e) == 0 {
		return "★ 自称会这些（" + strings.Join(s, "、") + "）但一个都没启用 —— " +
			"按 enabled 认它，别按 supported 分类"
	}
	for _, x := range e {
		found := false
		for _, y := range s {
			if x == y {
				found = true
			}
		}
		if !found {
			return "★ 它启用了" + x + "，可这一项没写在「会这些」里 —— 这一栏设备自己就对不上，只当参照"
		}
	}
	return ""
}

// ── 结果形状 ──

func buildLldpLocal(loc lldpLocal) map[string]any {
	e := map[string]any{}
	if s, _ := chassisIDText(loc.chassisSub, loc.chassisID); s != "" {
		e["chassisId"] = s
	}
	if n := chassisSubtypeName(loc.chassisSub); n != "" {
		e["chassisIdType"] = n
	}
	if loc.sysName != "" {
		e["sysName"] = loc.sysName
	}
	if loc.sysDesc != "" {
		e["sysDesc"] = loc.sysDesc
	}
	if c := lldpCapNames(loc.capSup); len(c) > 0 {
		e["capabilities"] = c
	}
	if c := lldpCapNames(loc.capEn); len(c) > 0 {
		e["capabilitiesEnabled"] = c
	}
	if n := lldpCapNote(loc.capSup, loc.capEn); n != "" {
		e["capabilityNote"] = n
	}
	return e
}

func buildLldpEntries(rows []lldpRow, names map[int][]portNameHit,
	match map[int]string) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		e := map[string]any{"portNum": r.key.port, "remIndex": r.key.index}
		if r.key.mark > 0 {
			e["timeMark"] = r.key.mark
		}
		if n := lldpPortName(names, r.key.port); n != "" {
			e["localPortName"] = n
		}
		if how := match[r.key.port]; how != "" {
			e["portMatchedBy"] = how
			e["portMatchWhy"] = lldpMatchWhy(how)
		}
		if a := lldpAdminName(r.admin); a != "" {
			e["localLldpAdmin"] = a
			e["localLldpAdminMeaning"] = lldpAdminMeaning(r.admin)
		}
		if t, why := chassisIDText(r.chassisSub, r.chassisID); t != "" {
			e["chassisId"] = t
			if why != "" {
				e["chassisIdWhy"] = why
			}
		}
		if n := chassisSubtypeName(r.chassisSub); n != "" {
			e["chassisIdType"] = n
		}
		if t, why := portIDText(r.portSub, r.portID); t != "" {
			e["remotePortId"] = t
			if why != "" {
				e["remotePortIdWhy"] = why
			}
		}
		if n := portSubtypeName(r.portSub); n != "" {
			e["remotePortIdType"] = n
		}
		if r.portDesc != "" {
			e["remotePortDesc"] = r.portDesc
		}
		if r.sysName != "" {
			e["sysName"] = r.sysName
		}
		if r.sysDesc != "" {
			e["sysDesc"] = r.sysDesc
		}
		if c := lldpCapNames(r.capSup); len(c) > 0 {
			e["capabilities"] = c
		}
		if c := lldpCapNames(r.capEn); len(c) > 0 {
			e["capabilitiesEnabled"] = c
		}
		if n := lldpCapNote(r.capSup, r.capEn); n != "" {
			e["capabilityNote"] = n
		}
		if len(r.manAddrs) > 0 {
			e["mgmtAddresses"] = r.manAddrs
		}
		if r.ageSet {
			e["lastUpdate"] = humanUptime(r.ageSeconds)
			e["lastUpdateSeconds"] = r.ageSeconds
		} else if r.key.mark > 0 {
			// timeMark 给了号、可算不出「多久以前」：这台现在的运行时间比那个号还小
			// （重启过，或者两个号不是同一把尺）。★ 不假装算得出。
			e["lastUpdateWhy"] = "这一条打了时间戳（" + strconv.Itoa(r.key.mark) +
				"），但比这台的运行时间还大，算不出多久以前"
		}
		if r.ageoutsSet {
			e["ageoutsTotal"] = r.ageouts
		}
		if r.ageoutDelta > 0 {
			e["ageoutsDelta"] = r.ageoutDelta
		}
		if r.agedOut {
			e["agedOut"] = true
		}
		if r.gone {
			e["gone"] = true
		}
		if r.grew {
			e["newNeighbor"] = true
		}
		if miss := lldpMissingCols(r); miss != "" {
			e["missingColumns"] = miss
		}
		out = append(out, e)
	}
	return out
}

// lldpMissingCols 说清这一行设备给了哪几栏、少了哪几栏。
//
// ★ 只有「少了认身份的那几栏」才说：一条邻居没给 sysDesc 是常态，
//
//	每一行都挂一句「少了自述」就成了噪音。
func lldpMissingCols(r lldpRow) string {
	var miss []string
	if len(r.chassisID) == 0 {
		miss = append(miss, "lldpRemChassisId（对端是哪台）")
	}
	if r.sysName == "" {
		miss = append(miss, "lldpRemSysName（对端自称叫什么）")
	}
	if len(r.portID) == 0 && r.portDesc == "" {
		miss = append(miss, "lldpRemPortId / PortDesc（对端哪个口）")
	}
	if len(miss) == 0 {
		return ""
	}
	return "这一行设备没给：" + strings.Join(miss, "、") +
		" —— 少了哪一栏，那一栏的结论就不能下（不是「没有」）"
}

func lldpPortName(names map[int][]portNameHit, port int) string {
	if hits := names[port]; len(hits) > 0 {
		return hits[0].s
	}
	return ""
}

const (
	lldpMatchBridge    = "dot1dBasePortIfIndex" // 设备给的硬映射
	lldpMatchName      = "lldpLocPort-names-it" // 设备自己写的口名对上了
	lldpMatchEqual     = "portNum-equals-ifIndex"
	lldpMatchBothPorts = "both-mappings"
)

const lldpMatchBridgeWord = "设备的 dot1dBasePortIfIndex 映射（这一条是设备给的，可以当准）"

func lldpMatchWhy(how string) string {
	switch how {
	case lldpMatchBridge:
		return lldpMatchBridgeWord
	case lldpMatchName:
		return "设备写在 lldpLocPortDesc / lldpLocPortId 里的口名对上的"
	case lldpMatchEqual:
		return "★ 按「LLDP 口号正好等于 ifIndex」猜的，要核"
	case lldpMatchBothPorts:
		return "两条独立的路子都认出了这个口号（设备的映射、口名、编号相等，各算一条）—— 这一条可以当准"
	}
	return ""
}

func buildLldpStats(s lldpStats, rows []lldpRow) map[string]any {
	e := map[string]any{}
	if !s.any {
		e["note"] = "这台不给读 LLDP 的统计计数器（只给了邻居表本身）"
		return e
	}
	if s.inserts > 0 {
		e["tableInserts"] = s.inserts
	}
	if s.deletes > 0 {
		e["tableDeletes"] = s.deletes
	}
	if s.drops > 0 {
		e["tableDrops"] = s.drops
	}
	if s.ageouts > 0 {
		e["tableAgeouts"] = s.ageouts
	}
	var agedPorts, errPorts []string
	for _, r := range rows {
		if r.ageouts > 0 {
			agedPorts = append(agedPorts, strconv.Itoa(r.key.port))
		}
	}
	for p, v := range s.perPortError {
		if v > 0 {
			errPorts = append(errPorts, strconv.Itoa(p))
		}
	}
	sort.Strings(agedPorts)
	sort.Strings(errPorts)
	if len(agedPorts) > 0 {
		e["ageoutPorts"] = agedPorts
	}
	if len(errPorts) > 0 {
		e["rxErrorPorts"] = errPorts
	}
	if len(e) == 0 {
		e["note"] = "计数器都读到了，全是 0（这台到现在没丢过邻居）"
	}
	return e
}

// ── 定性 ──

// lldpVerdict 点名一条邻居时的收口。★ 只有点名才给红：一台设备上接了台
// 不支持 LLDP 的老设备是常态，整张表都红就等于不红。
func lldpVerdict(values map[string]any, r lldpRow, names map[int][]portNameHit, loc lldpLocal) ots.Verdict {
	who := lldpWhoIs(r, names)
	switch {
	case r.agedOut:
		return ots.Verdict{Code: snmpLldpAging, Values: values,
			Note: fmt.Sprintf("%s：这个口的邻居在刚才那一段里老化过 %v 次（对端停发 LLDP、"+
				"或者它给的存活时间比它的发包间隔短、或者链路在抖）。"+
				"★ 这一条不是「没有邻居」，是「邻居会消失」—— 查对端为什么停发，别查这台没配。",
				who, r.ageoutDelta)}
	case r.admin == 2:
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("%s。★ 但这个口的 LLDP 是「只听不发」（rxOnly）：这台能看见对端，"+
				"对端那边永远看不见这台。要两边互相看得见，得去设备上把这个口改成收发（本工具只读，不改配置）。",
				who)}
	case r.admin == 1:
		// ★ 表里有这一行、可这个口写着 txOnly：设备的实现和标准不一致（标准说
		//   只发不存）。这不是好事，是要人去看一眼设备配置到底哪一档生效。
		return ots.Verdict{Code: snmpLldpTxOnly, Values: values,
			Note: fmt.Sprintf("%s。可这个口的 LLDP 开关写的是「只发不收」（txOnly）—— "+
				"这一档按标准就不该存邻居，设备却存了这一行。两栏对不上，先去设备上核这个口到底开到哪一档。",
				who)}
	}
	extra := lldpSampleNote(values)
	if r.ageSet && r.ageSeconds > 600 {
		extra += fmt.Sprintf(" 这一条是 %s前刷新的（LLDP 的存活时间一般是 120 秒，"+
			"这个号比那大得多，说明这台只是把第一次听到的东西留着没清）", humanUptime(r.ageSeconds))
	}
	if note := lldpCapNote(r.capSup, r.capEn); note != "" {
		extra += " " + strings.TrimPrefix(note, "★ ")
	}
	if miss := lldpMissingCols(r); miss != "" {
		extra += " " + miss
	}
	return ots.Verdict{Code: snmpOk, Values: values, Note: who + "。" + extra}
}

// lldpSampleNote 把「这两遍之间发生了什么」那几句搬到复制得走的 note 里。
//
// ★ 两遍之间设备重启过时，计数器被清零、行数是唯一可比的东西；反过来，
//
//	只在第二遍出现的那几行正是有人新插进来的设备。这两句都只写在 values 里的话，
//	人会把界面上那个「涨了 0 次」当成「邻居没动过」。
func lldpSampleNote(values map[string]any) string {
	out := ""
	if values["rebooted"] == true {
		out += " ★ 这台设备在两次读之间重启过（sysUpTime 倒退、计数器被清零），" +
			"所以这一趟只按两遍的行数比邻居，不给增量。"
	}
	if n, ok := values["newNeighborRows"]; ok {
		out += fmt.Sprintf(" ★ 这一趟之间多出 %v 行邻居（只有第二遍才读到）—— "+
			"这一段观察里有人新插了一台，上面标了 newNeighbor 的那几行就是它。", n)
	}
	return out
}

// lldpWhoIs 用一行邻居记录拼出「这根线另一头是谁」那一句。
//
// ★ 缺哪一栏就跳过哪一栏，不许用「未知」占位：note 是人家复制进工单的那一行，
//
//	写一句「对端 未知」比不写更容易被当成结论。
func lldpWhoIs(r lldpRow, names map[int][]portNameHit) string {
	here := "口号 " + strconv.Itoa(r.key.port)
	if n := lldpPortName(names, r.key.port); n != "" {
		here = n
	}
	parts := []string{}
	if r.sysName != "" {
		parts = append(parts, "对端叫 "+r.sysName)
	}
	if t, _ := chassisIDText(r.chassisSub, r.chassisID); t != "" {
		label := "机箱标识"
		if w := chassisSubtypeWord(r.chassisSub); w != "" {
			label = "机箱标识（" + w + "）"
		}
		parts = append(parts, label+" "+t)
	}
	if t, _ := portIDText(r.portSub, r.portID); t != "" {
		parts = append(parts, "插在它的 "+t+" 上")
	} else if r.portDesc != "" {
		parts = append(parts, "插在它的 "+r.portDesc+" 上")
	}
	if c := lldpCapNames(r.capEn); len(c) > 0 {
		parts = append(parts, "它自称是"+strings.Join(c, "+"))
	}
	if len(r.manAddrs) > 0 {
		parts = append(parts, "它留的管理地址 "+strings.Join(r.manAddrs, "、"))
	}
	head := fmt.Sprintf("%s 这根线：", here)
	if len(parts) == 0 {
		return head + "这台的邻居表里有这一行，但机箱标识、名字、端口标识都没给"
	}
	return head + strings.Join(parts, "，")
}

// lldpNamedButEmpty 点名了、那一行却没有邻居：先看这个口的开关能不能解释。
//
// ★ 这一条顺序很重要：「这个口只发不收」和「这根线上没人说话」是两种下一步
//
//	（前者改设备，后者查对端），而它们在这一层的数据里长得一模一样。
func lldpNamedButEmpty(values map[string]any, a snmpLldpArgs, set lldpTargetSet,
	cfg map[int]int, locPorts map[int]lldpLocPort, total int, truncated bool) (ots.Verdict, bool) {
	if truncated || len(set.ports) == 0 {
		return ots.Verdict{}, false
	}
	var ports []int
	for p := range set.ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	names := lldpPortNames(locPorts)
	which := make([]string, 0, len(ports))
	for _, p := range ports {
		w := "口号 " + strconv.Itoa(p)
		if n := lldpPortName(names, p); n != "" {
			w = n
		}
		switch cfg[p] {
		case 1:
			return ots.Verdict{Code: snmpLldpTxOnly, Values: values,
				Note: fmt.Sprintf("%s 的邻居是空的，而且这一条不用去查对端：这个口的 LLDP 开关是"+
					"「只发不收」（txOnly）—— 按标准这一档就是只发不存，表里必然没有它。"+
					"要看见对端得去设备上把这个口改成收发（txAndRx）或只听（本工具只读，不改配置）。"+
					"★ 这一条也不是「线不通」：链路状态看 net.snmp.ports。", w)}, true
		case 4:
			return ots.Verdict{Code: snmpLldpPortOff, Values: values,
				Note: fmt.Sprintf("%s 的邻居是空的，因为这个口的 LLDP 整个关着（disabled）：不发也不收。"+
					"要去设备上把这个口的 LLDP 开回来（本工具只读，不改配置）。"+
					"★ 这一条也不是「线不通」，也不是「对端不支持」。", w)}, true
		}
		which = append(which, w)
	}
	_ = a
	values["queriedPorts"] = which
	return ots.Verdict{}, false
}

// lldpNotFound：点名的那个口没有邻居行，而这台别处是有的（或者表压根没走全）。
func lldpNotFound(values map[string]any, a snmpLldpArgs, set lldpTargetSet, truncated bool) ots.Verdict {
	which := "点名的这个口"
	switch {
	case a.PortNum > 0:
		which = "LLDP 口号 " + strconv.Itoa(a.PortNum)
	case a.IfIndex > 0:
		which = "ifIndex " + strconv.Itoa(a.IfIndex) + " 对应的口"
	case strings.TrimSpace(a.Name) != "":
		which = "叫 " + strings.TrimSpace(a.Name) + " 的口"
	}
	values["neighbors"] = []map[string]any{}
	if set.named && len(set.ports) == 0 {
		if m, ok := values["portMapping"].(string); ok && m != "" {
			return ots.Verdict{Code: snmpLldpNotFound, Values: values,
				Note: "没找到这个口的邻居，因为连「它是哪个 LLDP 口号」都没定下来。" + m +
					" ★ 先把这一条对上：不填口名、把邻居整张列一遍，看设备写的是哪种口名。"}
		}
	}
	if truncated {
		values["truncated"] = true
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("读到 %v 行就撞上限量停了（限量 %v 行；走表是一栏一栏走的，最后那一行多半只读到几栏），"+
				"里面没有%s —— 这不是「这个口没邻居」。"+
				"把 limit 提到 %d 再看一次才算看完这张表",
				values["read"], values["readLimit"], which, lldpMax)}
	}
	return ots.Verdict{Code: snmpLldpNotFound, Values: values,
		Note: fmt.Sprintf("%s 上没有邻居行，而这台设备的邻居表是读得出来的（一共 %v 行）。"+
			"这一条能说的是：这台在说 LLDP，只有这根线的另一头没在说 —— 对端多半是台不支持 LLDP 的设备"+
			"（只发 CDP 的老设备、消费级设备、或者它把 LLDP 关了）。★ 这不代表线不通：链路状态看 net.snmp.ports。",
			which, values["countTotal"])}
}

// lldpEmptyTable：树在、口在收，可一条邻居都没有。
//
// ★ 这一条最容易被写成「没有邻居」，而那三种病的下一步完全相反，
//
//	所以先把开关那一栏看完再定性：有一口在「只发不收」/「关着」就用那两个码。
func (t *snmpTarget) lldpEmptyTable(values map[string]any,
	cfg map[int]int, loc lldpLocal) ots.Verdict {
	values["answered"] = true
	values["countTotal"] = 0
	values["neighbors"] = []map[string]any{}
	txOnly, off, listening := 0, 0, 0
	for _, v := range cfg {
		switch v {
		case 1:
			txOnly++
		case 4:
			off++
		case 2, 3:
			listening++
		}
	}
	switch {
	case listening == 0 && txOnly > 0 && off == 0:
		return ots.Verdict{Code: snmpLldpTxOnly, Values: values,
			Note: fmt.Sprintf("这台设备的 %v 个口 LLDP 全都配成「只发不收」（txOnly）—— "+
				"按标准这一档不存邻居，所以它的邻居表本来就该是空的，不是对端没说话。"+
				"要去设备上把这些口改成收发（本工具只读，不改配置）。", txOnly)}
	case listening == 0 && off > 0 && txOnly == 0:
		return ots.Verdict{Code: snmpLldpPortOff, Values: values,
			Note: fmt.Sprintf("这台设备的 %v 个口 LLDP 都是关着（disabled）的，也没有哪个口在收 —— "+
				"邻居表空是配置的结果，不是网络的事。要去设备上开（本工具只读，不改配置）。", off)}
	case len(cfg) == 0:
		return ots.Verdict{Code: snmpNoData, Values: values,
			Note: "这台设备的邻居表（" + lldpRemGroup + "）一条都没给，而且没读到每个口的 LLDP 开关。" +
				"★ 这不是「设备不通」：它答过话了。也不是「对端都没在说 LLDP」：那两句下一步完全相反。" +
				"两种可能分不开：① 这台的 LLDP 服务没开（很多设备上不开服务时这棵树整个不存在）；" +
				"② 这棵子树被放到了别的 SNMP 视图里（换个团体名问 net.snmp.probe）。"}
	}
	who := "本机"
	if loc.sysName != "" {
		who = loc.sysName
	}
	return ots.Verdict{Code: snmpLldpNoNeighbor, Values: values,
		Note: fmt.Sprintf("%s 的 LLDP 是在收的（有 %v 个口处于只听或收发），可一条邻居都没有。"+
			"这一条能说：这台设备活着、这棵树也在，是没有东西在向它说 LLDP。三件要一起看："+
			"① 对端只发 CDP（老 Cisco、消费级设备，这棵树里读不到）；② 对端把 LLDP 关了；"+
			"③ 链路本身没起来 —— 那不是邻居表的事，用 net.snmp.ports 看 oper。",
			who, listening)}
}

// lldpUnsupported：这台压根没有 LLDP-MIB 这一棵。
func (t *snmpTarget) lldpUnsupported(ctx context.Context, values map[string]any) ots.Verdict {
	values["answered"] = true
	values["countTotal"] = 0
	values["neighbors"] = []map[string]any{}
	return ots.Verdict{Code: snmpLldpUnsupported, Values: values,
		Note: "问了 LLDP-MIB（" + lldpArc + "）下面的四组：本地系统、邻居表、每口开关、统计，" +
			"一条都没给，而且前面问系统组（1.3.6.1.2.1.1）是通的。三种可能分不开：" +
			"① 这台的 LLDP 服务没开（不少设备上不开服务时整棵树就不存在）；" +
			"② 它根本不说 LLDP，只说 CDP（老 Cisco、多数消费级设备）—— 这一棵树读不到 CDP，" +
			"要认对端得换一棵：net.arp.table 看三层、net.snmp.mac 看二层，或者按厂商私有 MIB 问；" +
			"③ 整棵被放到了别的 SNMP 视图里（换个团体名问 net.snmp.probe）。" +
			"★ 这一条不是「设备不通」：它答过话了。也不是「没人跟它说话」：那两种病的下一步完全不同。"}
}

// lldpSummary 整张邻居表的收口。★ 表里有「没邻居的口」不是故障（对端不说 LLDP 是常态），
// 所以这一档只给 snmp-ok；但一个口上听见好几个邻居是拓扑事实，值得单独说一句。
func lldpSummary(values map[string]any, rows []lldpRow, cfg map[int]int, all int, named bool) ots.Verdict {
	byPort := map[int][]lldpRow{}
	for _, r := range rows {
		byPort[r.key.port] = append(byPort[r.key.port], r)
	}
	var multi []string
	for p, list := range byPort {
		if len(list) > 1 {
			names := make([]string, 0, len(list))
			for _, r := range list {
				names = append(names, r.sysName)
			}
			multi = append(multi, fmt.Sprintf("%d 个（口号 %d：%s）", len(list), p,
				strings.Join(cleanNames(names), "、")))
		}
	}
	sort.Strings(multi)
	var aging []string
	for _, r := range rows {
		if r.agedOut {
			aging = append(aging, strconv.Itoa(r.key.port))
		}
	}
	sort.Strings(aging)
	values["ports"] = len(byPort)
	if len(multi) > 0 {
		values["multiNeighborPorts"] = len(multi)
	}
	if len(aging) > 0 {
		values["agingPorts"] = aging
	}
	off, txOnly := 0, 0
	for _, v := range cfg {
		switch v {
		case 4:
			off++
		case 1:
			txOnly++
		}
	}

	sample := lldpSampleNote(values)
	// ★ 那几句话数的是**列出来的**这些行：点名的时候表里一共八行、这里只列两行，
	//   写成「8 条邻居行，涉及 1 个口」就是把两个口径混在一句里。
	listed := len(rows)
	scope := ""
	if listed != all {
		scope = fmt.Sprintf("（这台表里一共 %v 行，这里只列了点名的那几个口）", all)
	}
	switch {
	case len(aging) > 0:
		return ots.Verdict{Code: snmpLldpAging, Values: values,
			Note: strings.TrimSpace(fmt.Sprintf("%v 条邻居行%s，涉及 %v 个口。★ 刚才那一段里口号 %s 的邻居老化过 —— "+
				"这一条说的是「邻居会消失」，不是「没有邻居」：对端停发 LLDP、或者它给的存活时间"+
				"比自己的发包间隔短、或者这条链路在抖。%s",
				listed, scope, values["ports"], strings.Join(aging, "、"), sample))}
	case len(multi) > 0:
		return ots.Verdict{Code: snmpLldpMulti, Values: values,
			Note: fmt.Sprintf("%v 条邻居行%s，涉及 %v 个口。★ 有口上听见了不止一个邻居：%s —— "+
				"这不是故障，是拓扑：这个口下面接了台非网管交换机、hub 或者分光器，"+
				"设备不会主动把这件事说出来。要理拓扑就顺着这几个口去现场看一眼。%s",
				listed, scope, values["ports"], strings.Join(multi, "；"), sample)}
	}
	extra := ""
	if txOnly > 0 || off > 0 {
		extra = fmt.Sprintf("另外这台上有 %v 个口的 LLDP 是「只发不收」、%v 个口是关着的 —— "+
			"这些口的邻居表本来就不会有内容，别看成故障。 ", txOnly, off)
	}
	return ots.Verdict{Code: snmpOk, Values: values,
		Note: fmt.Sprintf("读到 %v 条邻居行%s，涉及 %v 个本地口。%s"+
			"★ 表里没有某个口不等于那根线不通：对端不说 LLDP（只发 CDP、或者把 LLDP 关了）时，"+
			"这个口在这张表里就是不存在。链路状态看 net.snmp.ports。%s",
			listed, scope, values["ports"], extra, sample)}
}

func cleanNames(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			s = "没给名字"
		}
		out = append(out, s)
	}
	return out
}

// lldpAdminCounts 每个口的开关各有多少（给界面那一栏「这台 LLDP 开成什么样」）。
func lldpAdminCounts(cfg map[int]int) map[string]int {
	out := map[string]int{}
	for _, v := range cfg {
		name := lldpAdminName(v)
		if name == "" {
			name = "other"
		}
		out[name]++
	}
	return out
}
