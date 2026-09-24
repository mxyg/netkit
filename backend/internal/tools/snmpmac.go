package tools

// ── net.snmp.mac ──
//
// ★ 为什么先读 Q-BRIDGE 那张表、读不到才退到 BRIDGE-MIB：
//
//	BRIDGE-MIB 的 dot1dTpFdb **不带 VLAN**，而且在多数实现里一个团体名只管一个 VLAN
//	（通常是 VLAN 1），要读别的 VLAN 得用 `public@100` 那种扩展团体名。
//	现场最常见的症状就是「CLI 里表明明有几十条，读回来是空的」——
//	那不是设备坏了，是这个团体名管不到那一层。
//	Q-BRIDGE 的 dot1qTpFdb 一张表带 VLAN，能一次读全，所以放在前面。
//
// ★ 为什么 MAC 要从 OID 索引里解，而不是读 dot1qTpFdbAddress 那一栏：
//
//	走一列（.2 端口号）比走三列（地址+端口+状态）少两倍报文。MAC 就在索引里，
//	不需要再问一遍。状态那一栏只补走一列，用来分清「学来的」和「手工配的」。
//
// ★ 反查（填了 mac）时**不能**把「读到的那些里没有」说成「它不在这台交换机上」：
//
//	表是按 limit 读的，后面的没读；FDB 本身又只记**最近发过帧**的源地址。
//	所以 not-found 要分两种：读全了没有（snmp-mac-not-found），和没读完（snmp-not-walked）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
)

// 桥接与接口相关的 OID。★ 只写这里用到的，别的地方要用了再加，
// 一张全量 OID 表会变成「没人核对过的字典」。
const (
	oidIfDescr = "1.3.6.1.2.1.2.2.1.2" // ifTable：网卡描述（老设备唯一有的一栏）
	oidIfName  = "1.3.6.1.2.1.31.1.1.1.1"

	oidDot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2" // 桥端口号 → ifIndex

	oidDot1dTpFdbPort   = "1.3.6.1.2.1.17.4.3.1.2"     // BRIDGE-MIB：端口
	oidDot1dTpFdbStatus = "1.3.6.1.2.1.17.4.3.1.3"     // 　‖ 状态
	oidDot1qTpFdbPort   = "1.3.6.1.2.1.17.7.1.2.2.1.2" // Q-BRIDGE：端口
	oidDot1qTpFdbStatus = "1.3.6.1.2.1.17.7.1.2.2.1.3" // 　‖ 状态
)

// dot1dTpFdbStatus / dot1qTpFdbStatus 的取值（RFC 1493 / 2674）。
// ★ 这里刻意把 learned 写成「动态」而不是「学到」：界面上要短，
//
//	而「动态」和「静态」摆在一起才看得出是一对。
func fdbStatusName(n int) string {
	switch n {
	case 1:
		return "other"
	case 2:
		return "invalid" // 正在老化掉：口可能已经变了，不能当结论
	case 3:
		return "dynamic"
	case 4:
		return "self" // 交换机自己的 MAC
	case 5:
		return "static"
	}
	return ""
}

// ★ 这里**不新造**「表是空的」那个码：SNMP 分不出「这张表存在但为空」和
//
//	「这棵子树它没实现」，造一个 snmp-mac-none 出来就是把猜的写成结论。
//	两种都落在 snmp-no-data 上，note 里把两种可能一起摆出来。
const snmpMacNotFound = "snmp-mac-not-found" // 表读全了，里面没有这个 MAC

// fdbTable 是一张能读的转发表。
type fdbTable struct {
	name      string // 进结果的表名：qbridge / bridge
	portOid   string
	statusOid string
	withVLAN  bool
}

var (
	fdbQBridge = fdbTable{name: "qbridge", portOid: oidDot1qTpFdbPort,
		statusOid: oidDot1qTpFdbStatus, withVLAN: true}
	fdbBridge = fdbTable{name: "bridge", portOid: oidDot1dTpFdbPort,
		statusOid: oidDot1dTpFdbStatus, withVLAN: false}
)

const (
	macRowsDefault = 2000
	macRowsMax     = 200000
)

type snmpMacArgs struct {
	snmpArgs
	MAC   string `json:"mac,omitempty"`
	VLAN  int    `json:"vlan,omitempty"`
	Limit int    `json:"limit,omitempty"`
	// Table 不填 = 先 Q-BRIDGE 再 BRIDGE-MIB。指定 = 只读那一张：
	// 一台表结构被改过的设备会「一张有、一张也有」，这时得能点名。
	Table string `json:"table,omitempty"`
}

// fdbRow 是一条转发表记录（还没翻成结果形状）。
type fdbRow struct {
	mac     []byte
	vlan    int
	hasVLAN bool
	port    int
	status  int
}

var snmpMacTool = ots.Tool{
	Name:  "net.snmp.mac",
	Class: ots.ClassRead,
	Summary: "读一台交换机（或带桥接的设备）的 MAC 地址表：谁在哪个口、属于哪个 VLAN、是学来的还是手工配的。" +
		"填 mac 就是反查「这个 MAC 插在哪个口」。" +
		"★ 判定分开：snmp-ok（读到了）、snmp-mac-not-found（表读全了，里面没有这个 MAC ——" +
		"它最近没发过帧，或者挂在别的设备上）、" +
		"snmp-not-walked（表只读了一部分：**这时「没有」不算结论**）、" +
		"snmp-no-data（两种转发表都不给读：设备不做交换、表确实空着、或者这张表按 VLAN 分给了别的团体名）、" +
		"以及 snmp-no-reply / snmp-error。" +
		"先跑 net.snmp.probe 确认 SNMP 通不通，再来看这一栏。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr", "community"],
	  "properties": {
	    ` + snmpSchemaProps + `,
	    "mac": {"type": "string",
	      "description": "反查：只关心这一个 MAC。常见写法都认（aa:bb:cc:dd:ee:ff、aa-bb-cc-dd-ee-ff、aabb.ccdd.eeff、连写）。★ 不填就是整张表。"},
	    "vlan": {"type": "integer", "minimum": 1, "maximum": 4094,
	      "description": "只看这个 VLAN。★ Q-BRIDGE 的表本来就带 VLAN，不填会一次读回所有 VLAN；填了是在结果里筛，读的量不变。"},
	    "limit": {"type": "integer", "minimum": 1, "maximum": 200000,
	      "description": "最多读几条，默认 2000。核心交换机的表可能有几万条，全读要等很久，所以到数就停、并在结果里写明「没读完」。★ 反查一个 MAC 时把 limit 提到能盖住整张表：读到一半就下「不在这台」的结论是骗人。"},
	    "table": {"type": "string", "enum": ["qbridge", "bridge"],
	      "description": "只读一张转发表。qbridge = dot1qTpFdb（带 VLAN，优先）；bridge = dot1dTpFdb（不带 VLAN，老设备）。不填两张都试。填这个主要用于「Q-BRIDGE 那张被设备改过结构、读出来是乱的」这种现场。"}
	  }
	}`),
	Invoke: doSnmpMac,
}

func doSnmpMac(ctx context.Context, raw json.RawMessage) (any, error) {
	var a snmpMacArgs
	if err := snmpArgsFrom(raw, &a); err != nil {
		return nil, err
	}
	var wantMAC []byte
	if strings.TrimSpace(a.MAC) != "" {
		mac, err := parseMAC(a.MAC)
		if err != nil {
			// 报错里要带上参数名：这串字符是从设备上抄来的，人第一反应是「设备没这条」，
			// 而不是「我填的那串本身写错了」。
			return nil, ots.Errf(ots.ErrInvalidArgument, "mac %q 认不出来：%v", a.MAC, err)
		}
		wantMAC = mac
	}
	if a.VLAN < 0 || a.VLAN > 4094 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "VLAN %d 不在 1-4094 之间", a.VLAN)
	}
	tables, err := fdbTables(a.Table)
	if err != nil {
		return nil, err
	}
	limit := a.Limit
	if limit <= 0 {
		// ★ 反查一条 MAC 时按「读全整张表」来读：读一半就说「表里没有」是骗人，
		//   而现场最不该拿错的就是这句 —— 拿错就会去查一条本来好好的链路。
		//   显式填了 limit 的人自己收口，那种情况下如实报 truncated。
		if wantMAC != nil {
			limit = macRowsMax
		} else {
			limit = macRowsDefault
		}
	}
	if limit > macRowsMax {
		limit = macRowsMax
	}

	t, err := snmpDial(a.snmpArgs)
	if err != nil {
		return nil, err
	}
	defer t.close()

	values := t.values()
	// ★ 问过哪几张表要写进结果：点名只读一张时，「两张都问过了」那句话就是假的。
	names := make([]string, len(tables))
	for i, tb := range tables {
		names[i] = tb.name
	}
	values["tablesTried"] = names
	start := time.Now()
	got := t.readFdb(ctx, tables, limit, wantMAC, a.VLAN)
	rows, table, truncated := got.rows, got.table, got.truncated
	if got.err != nil && len(rows) == 0 {
		verdict, done := snmpFail(got.err, values)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", got.err)
		}
		return verdict, nil
	}
	if got.skipped > 0 {
		values["skipped"] = got.skipped
	}
	values["fdbTable"] = table.name
	values["read"] = len(rows)
	values["truncated"] = truncated
	values["readLimit"] = limit
	if got.statusKnown {
		values["lookedUp"] = "index" // 按索引直取的：没走过表，别的项目不能把这条当「整张表看过了」
	} else {
		values["lookedUp"] = "walk"
	}

	// 状态那一栏单独补一次走。★ 两次走之间表会变（这正是这张表的性质），
	// 所以按索引去配对，配不上的如实留空，不猜它是「动态」。
	if len(rows) > 0 && !got.statusKnown {
		statuses, stErr := t.readFdbColumn(ctx, table.statusOid, limit)
		if stErr == nil {
			for i := range rows {
				if s, ok := statuses[fdbIndexKey(rows[i], table.withVLAN)]; ok {
					rows[i].status = s
				}
			}
		}
	}
	if wantMAC != nil {
		rows = filterFdbMac(rows, wantMAC)
	}
	if a.VLAN > 0 {
		rows = filterFdbVlan(rows, a.VLAN)
	}
	sortFdbRows(rows)
	values["count"] = len(rows)
	if a.VLAN > 0 {
		values["vlanFilter"] = a.VLAN
	}
	if wantMAC != nil {
		values["queriedMac"] = formatMAC(wantMAC, ":")
	}
	values["elapsedMs"] = time.Since(start).Milliseconds()

	out := t.fdbOut(ctx, rows, values)
	entries, badNames := buildFdbEntries(out, rows)
	values["entries"] = entries
	if badNames > 0 {
		values["unresolved"] = badNames
	}
	return fdbVerdict(values, rows, entries, table, truncated, wantMAC), nil
}

// fdbTables 按 table 参数决定读哪几张、什么顺序。
func fdbTables(s string) ([]fdbTable, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return []fdbTable{fdbQBridge, fdbBridge}, nil
	case "qbridge", "q", "dot1q":
		return []fdbTable{fdbQBridge}, nil
	case "bridge", "dot1d":
		return []fdbTable{fdbBridge}, nil
	}
	return nil, ots.Errf(ots.ErrInvalidArgument, "table %q 看不懂，要 qbridge 或 bridge", s)
}

// fdbRead 是一次「读表」的结果。
type fdbRead struct {
	rows      []fdbRow
	table     fdbTable
	truncated bool
	// statusKnown 为真表示这些行的状态已经拿到了（直取那一条时顺带读回来的），
	// 不用再为补状态走一整列 —— 反查的意义就是少发报文。
	statusKnown bool
	// skipped 是索引写法对不上的行数。★ 必须报出来：
	// 非标实现（长 MAC、802.1ah 那种）会被我们的解析规则丢掉，
	// 不报的话「读到 300 条」看着像读全了，实际少了多少没人知道。
	skipped int
	err     error
}

// readFdb 依次试几张表，第一张读到东西就用它。
//
// ★ 「读到 0 条」和「这一棵子树不存在」在 SNMP 里是同一个样子（walk 走出子树就收口），
//
//	所以一张空表会让它继续往下试 —— 只有两张都空才判「没有数据」，
//	而那一句里会写清两张都问过了。
func (t *snmpTarget) readFdb(ctx context.Context, tables []fdbTable, limit int,
	wantMAC []byte, vlan int) fdbRead {
	var last fdbRead
	for _, tb := range tables {
		// ★ mac 和 VLAN 都知道时先按索引直取：核心交换机三万条表，
		//   走全表是一千多个报文，按索引问两个报文就够，而现场等不了前者。
		//   直取没问着不等于没有（索引编码各家不完全一样），所以下面照旧要走表确认。
		if row, ok := t.directFdbGet(ctx, tb, wantMAC, vlan); ok {
			return fdbRead{rows: []fdbRow{row}, table: tb, statusKnown: true}
		}
		vs, trunc, err := t.client.WalkLimit(ctx, tb.portOid, limit)
		if err != nil && len(vs) == 0 {
			last = fdbRead{table: tb, err: err}
			continue // 这张问不动：换下一张，最后再一起定性
		}
		rows, skipped := decodeFdbRows(vs, tb)
		if len(rows) == 0 && !trunc {
			last = fdbRead{table: tb, err: err, skipped: skipped}
			continue // 这张是空的，再看下一张
		}
		return fdbRead{rows: rows, table: tb, truncated: trunc, skipped: skipped, err: err}
	}
	if last.err != nil {
		return last
	}
	// 两张都问通了但都是空的：报第一张（Q-BRIDGE），判定走「没有数据」那一条。
	return fdbRead{table: last.table}
}

// directFdbGet 按索引直接问一行（端口 + 状态），只在问得准的时候用。
//
// ★ VLAN 在索引里占一节还是两节，各家实现不完全一致（BER 的规矩是「最少字节」，
//
//	但有的实现固定按两字节填零）。这里把两种写法都问一遍，多一个报文换「不猜」，
//	值。反查错了报成「没有」，人就照着这句话去别处找了。
func (t *snmpTarget) directFdbGet(ctx context.Context, tb fdbTable, wantMAC []byte,
	vlan int) (fdbRow, bool) {
	if wantMAC == nil {
		return fdbRow{}, false
	}
	if tb.withVLAN && vlan <= 0 {
		return fdbRow{}, false // 不知道 VLAN 就拼不出索引，只能走表
	}
	indexes := []string{}
	if !tb.withVLAN {
		indexes = append(indexes, macIndex(wantMAC))
	} else {
		indexes = append(indexes, vlanIndex(vlan)+"."+macIndex(wantMAC))
		if vlan > 127 {
			indexes = append(indexes, strconv.Itoa(vlan>>8)+"."+strconv.Itoa(vlan&0xff)+
				"."+macIndex(wantMAC))
		} else {
			indexes = append(indexes, "0."+strconv.Itoa(vlan)+"."+macIndex(wantMAC))
		}
	}
	for _, idx := range indexes {
		vs, err := t.client.Get(ctx, tb.portOid+"."+idx, tb.statusOid+"."+idx)
		if err != nil {
			var de *snmp.Error
			if errors.As(err, &de) {
				continue // v1 上「这一行没有」是整包作废，换下一种写法
			}
			return fdbRow{}, false
		}
		var port, status int
		found := false
		for _, v := range vs {
			if v.Missing() || v.EndOfMib() {
				continue
			}
			if strings.HasPrefix(v.OID, strings.TrimPrefix(tb.statusOid, ".")) {
				status = int(v.IntOr0())
				continue
			}
			port = int(v.IntOr0())
			found = true
		}
		if !found || port <= 0 {
			continue
		}
		return fdbRow{mac: wantMAC, vlan: vlan, hasVLAN: tb.withVLAN, port: port, status: status}, true
	}
	return fdbRow{}, false
}

// macIndex 把 MAC 写成 OID 索引里那六节（十进制，不补零）。
func macIndex(mac []byte) string {
	parts := make([]string, len(mac))
	for i, b := range mac {
		parts[i] = strconv.Itoa(int(b))
	}
	return strings.Join(parts, ".")
}

func vlanIndex(vlan int) string {
	if vlan > 127 {
		return strconv.Itoa(vlan>>8) + "." + strconv.Itoa(vlan&0xff)
	}
	return strconv.Itoa(vlan)
}

// readFdbColumn 走一列「索引 → 整数值」，用来补状态。
func (t *snmpTarget) readFdbColumn(ctx context.Context, oid string, limit int) (map[string]int, error) {
	vs, _, err := t.client.WalkLimit(ctx, oid, limit)
	if err != nil && len(vs) == 0 {
		return nil, err
	}
	out := make(map[string]int, len(vs))
	for _, v := range vs {
		idx := indexAfter(v.OID, oid)
		if idx == "" {
			continue
		}
		out[idx] = int(v.IntOr0())
	}
	return out, nil
}

// decodeFdbRows 从「端口列」的 OID 索引里解出 MAC 和 VLAN。
//
// ★ VLAN 在索引里占**一节或两节**，取决于它有多大：BER 编 INTEGER 用的是
//
//	装下它所需的最少字节，VLAN ≤127 一节、128~4095 两节。
//	写死「索引后面固定 7 节」的话，VLAN 100 全对、VLAN 1000 整段被丢掉，
//	而界面上显示的是「这台交换机没学到这些地址」。
func decodeFdbRows(vs []snmp.VarBind, tb fdbTable) ([]fdbRow, int) {
	rows := make([]fdbRow, 0, len(vs))
	skipped := 0
	for _, v := range vs {
		idx := indexAfter(v.OID, tb.portOid)
		parts := strings.Split(idx, ".")
		mac, vlan, ok := parseFdbIndex(parts, tb.withVLAN)
		if !ok {
			skipped++
			continue
		}
		port := int(v.IntOr0())
		if port <= 0 {
			skipped++
			continue // 端口号是 0 的行不成行（0 在 SMI 里是保留值）
		}
		rows = append(rows, fdbRow{mac: mac, vlan: vlan, hasVLAN: tb.withVLAN, port: port})
	}
	return rows, skipped
}

// parseFdbIndex 解一张表的行索引。
func parseFdbIndex(parts []string, withVLAN bool) ([]byte, int, bool) {
	// 尾部六节是 MAC；Q-BRIDGE 在它前面还有 1~2 节 VLAN。
	want := 6
	if withVLAN {
		want = 7 // 最少：1 节 VLAN + 6 节 MAC
	}
	if len(parts) < want || len(parts) > want+1 {
		return nil, 0, false
	}
	mac := make([]byte, 6)
	for i := 0; i < 6; i++ {
		n, err := strconv.ParseUint(parts[len(parts)-6+i], 10, 8)
		if err != nil {
			return nil, 0, false
		}
		mac[i] = byte(n)
	}
	vlanParts := parts[:len(parts)-6]
	if !withVLAN {
		return mac, 0, true
	}
	var vlan uint64
	switch len(vlanParts) {
	case 1:
		n, err := strconv.ParseUint(vlanParts[0], 10, 32)
		if err != nil {
			return nil, 0, false
		}
		vlan = n
	case 2: // 两节按大端拼（第一节的值本来就在高位，0~15）
		hi, err1 := strconv.ParseUint(vlanParts[0], 10, 32)
		lo, err2 := strconv.ParseUint(vlanParts[1], 10, 32)
		if err1 != nil || err2 != nil {
			return nil, 0, false
		}
		vlan = hi<<8 | lo
	default:
		return nil, 0, false
	}
	return mac, int(vlan), true
}

// indexAfter 切出一栏 OID 里「列前缀之后」的那段索引（含末尾的列号）。
func indexAfter(oid, columnOid string) string {
	o := strings.TrimPrefix(oid, ".")
	c := strings.TrimPrefix(columnOid, ".")
	if !strings.HasPrefix(o, c+".") {
		return ""
	}
	return o[len(c)+1:]
}

// fdbIndexKey 给一行算出配状态列用的键（就是它的索引，不带列号）。
func fdbIndexKey(r fdbRow, withVLAN bool) string {
	var b strings.Builder
	if withVLAN {
		if r.vlan > 127 {
			b.WriteString(strconv.Itoa(r.vlan >> 8))
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(r.vlan & 0xff))
		b.WriteByte('.')
	}
	for i, x := range r.mac {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(int(x)))
	}
	return b.String()
}

func filterFdbMac(rows []fdbRow, mac []byte) []fdbRow {
	out := make([]fdbRow, 0, 1)
	for _, r := range rows {
		if len(r.mac) == len(mac) && string(r.mac) == string(mac) {
			out = append(out, r)
		}
	}
	return out
}

func filterFdbVlan(rows []fdbRow, vlan int) []fdbRow {
	out := make([]fdbRow, 0, len(rows))
	for _, r := range rows {
		if r.hasVLAN && r.vlan == vlan {
			out = append(out, r)
		}
	}
	return out
}

// sortFdbRows 按 VLAN、MAC 排。★ 顺序必须固定：
// 结果会发给 AI、也会进诊断包，同一张表两次读出来的顺序不一样，
// 人就分不清是表变了还是程序在抖。
func sortFdbRows(rows []fdbRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].vlan != rows[j].vlan {
			return rows[i].vlan < rows[j].vlan
		}
		return bytesLess(rows[i].mac, rows[j].mac)
	})
}

func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// fdbOut 把「桥端口号 → ifIndex → 网卡名」一次问回来。
//
// ★ 走 dot1dBasePortIfIndex，而不是把端口号当 ifIndex 用：
//
//	两者在很多设备上恰好相等，所以猜着写能蒙对，
//	但在端口按面板顺序编号的设备上会把「GE0/0/3」报成「GE0/0/1」——
//	现场照着这个去拔线，拔错的就是别人的链路。
//	映射表读不到时**只报端口号**，名字那栏如实留空。
func (t *snmpTarget) fdbOut(ctx context.Context, rows []fdbRow, values map[string]any) map[int]portName {
	out := map[int]portName{}
	if len(rows) == 0 {
		return out
	}
	ports := make([]int, 0, len(rows))
	seen := map[int]bool{}
	for _, r := range rows {
		if !seen[r.port] {
			seen[r.port] = true
			ports = append(ports, r.port)
		}
	}
	sort.Ints(ports)

	idxOf := map[int]int{} // 桥端口号 → ifIndex
	oids := make([]string, 0, len(ports))
	for _, p := range ports {
		oids = append(oids, oidDot1dBasePortIfIndex+"."+strconv.Itoa(p))
	}
	mapped := true
	vbs, err := t.multiGet(ctx, oids)
	if err != nil {
		values["detail"] = err.Error()
		mapped = false // 不是「设备没这一栏」，是这一趟没问成 —— 下面如实分开
	}
	for _, v := range vbs {
		if v.Missing() {
			continue
		}
		n := int(v.IntOr0())
		if n <= 0 {
			continue
		}
		if i := indexAfter(v.OID, oidDot1dBasePortIfIndex); i != "" {
			if p, e := strconv.Atoi(i); e == nil {
				idxOf[p] = n
			}
		}
	}
	if len(idxOf) == 0 {
		values["portNames"] = "unavailable"
		if mapped {
			// 设备确实没实现这张映射表（有的实现直接把 ifIndex 当端口号用）。
			// ★ 这里不去「猜它就是 ifIndex」：猜错一次，这条结论就再没人信了。
			values["portNamesDetail"] = "这台设备没给 dot1dBasePortIfIndex，端口只报桥端口号"
		}
		return out
	}
	if len(idxOf) < len(ports) {
		values["portNames"] = "partial" // 有几栏没映射上
	}

	indexes := make([]int, 0, len(idxOf))
	for _, n := range idxOf {
		indexes = append(indexes, n)
	}
	sort.Ints(indexes)
	names := t.ifNames(ctx, indexes)
	for p, n := range idxOf {
		// ★ 名和描述各来自 ifXTable / ifTable，老设备只有后者；
		//   两个都没有就只报 ifIndex，报「查不到名字」而不是编一个。
		out[p] = portName{ifIndex: n, name: names[n]}
	}
	return out
}

// portName 是一个桥端口对应的网卡。
type portName struct {
	ifIndex int
	name    string
}

// ifNames 按 ifIndex 批量取网卡名：先问 ifName，没答的那几个再问 ifDescr。
func (t *snmpTarget) ifNames(ctx context.Context, indexes []int) map[int]string {
	out := map[int]string{}
	oids := make([]string, 0, len(indexes))
	for _, n := range indexes {
		oids = append(oids, oidIfName+"."+strconv.Itoa(n))
	}
	vbs, err := t.multiGet(ctx, oids)
	if err != nil {
		return out
	}
	var fallback []string
	for _, v := range vbs {
		i := indexAfter(v.OID, oidIfName)
		if v.Missing() || v.EndOfMib() || i == "" {
			if i != "" {
				fallback = append(fallback, oidIfDescr+"."+i)
			}
			continue
		}
		n, e := strconv.Atoi(i)
		if e != nil {
			continue
		}
		if s := printable(v.Str()); s != "" {
			out[n] = s
		} else {
			fallback = append(fallback, oidIfDescr+"."+i)
		}
	}
	if len(fallback) == 0 {
		return out
	}
	vbs, err = t.multiGet(ctx, fallback)
	if err != nil {
		return out
	}
	for _, v := range vbs {
		i := indexAfter(v.OID, oidIfDescr)
		if v.Missing() || v.EndOfMib() || i == "" {
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

// multiGet 一次问一叠 OID，按每包 25 栏分开问。
//
// ★ 单个请求里的某一栏设备没有时：v2c 回该栏 noSuchInstance（其余照给），
//
//	v1 是**整包作废**。所以 v1 见到 noSuchName 就退成一栏一栏问 ——
//	和系统组那一条是同一招，不退的话老设备上有几栏读不到就全都读不到。
func (t *snmpTarget) multiGet(ctx context.Context, oids []string) ([]snmp.VarBind, error) {
	var out []snmp.VarBind
	for start := 0; start < len(oids); start += snmp.MaxRepetitions {
		end := start + snmp.MaxRepetitions
		if end > len(oids) {
			end = len(oids)
		}
		vs, err := t.client.Get(ctx, oids[start:end]...)
		if err != nil {
			var de *snmp.Error
			if t.client.Version == snmp.V1 && errors.As(err, &de) && de.Status == 2 {
				for _, o := range oids[start:end] {
					one, oerr := t.client.Get(ctx, o)
					if oerr != nil {
						var e2 *snmp.Error
						if errors.As(oerr, &e2) && e2.Status == 2 {
							continue // 这一栏它没有
						}
						return out, oerr
					}
					out = append(out, one...)
				}
				continue
			}
			return out, err
		}
		out = append(out, vs...)
	}
	return out, nil
}

// buildFdbEntries 拼成结果里的行。返回的第二个值是「有几行没能配上名字」。
func buildFdbEntries(names map[int]portName, rows []fdbRow) ([]map[string]any, int) {
	out := make([]map[string]any, 0, len(rows))
	unresolved := 0
	for _, r := range rows {
		e := map[string]any{"mac": formatMAC(r.mac, ":")}
		if r.hasVLAN {
			e["vlan"] = r.vlan
		}
		e["basePort"] = r.port
		if s := fdbStatusName(r.status); s != "" {
			e["status"] = s
		}
		pn, ok := names[r.port]
		switch {
		case !ok:
			unresolved++
		case pn.name != "":
			e["ifIndex"] = pn.ifIndex
			e["port"] = pn.name
		default:
			// 映射到了 ifIndex，但名字两栏都没读到：给 ifIndex，不编名字。
			e["ifIndex"] = pn.ifIndex
			unresolved++
		}
		out = append(out, e)
	}
	return out, unresolved
}

// fdbVerdict 定性。★ 三条「没有」是分开的：
//
//	表是空的 / 表里没有这个 MAC / 表没读完 —— 下一步查的东西完全不同，
//	合成一句「没找到」就等于让人去查一条本来就好好的链路。
func fdbVerdict(values map[string]any, rows []fdbRow, entries []map[string]any,
	table fdbTable, truncated bool, wantMAC []byte) ots.Verdict {
	values["answered"] = true
	switch {
	case wantMAC != nil && len(rows) > 0:
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("找到了：%s 在 %s（%s）", formatMAC(wantMAC, ":"),
				fdbRowWhere(rows[0], entries[0]), fdbStatusName(rows[0].status))}
	case wantMAC != nil && truncated:
		// ★ 这一条最容易被写成「不在这台交换机上」—— 而它其实是「没查到」。
		//   读满 limit 的时候后面还有什么谁都不知道，这里给的是下一步，不是结论。
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("读了 %v 条就撞到 limit 停了，里面没有 %s —— 这不是「它不在这台设备上」。"+
				"把 limit 提到 %d 再问一次，那一次才是读全了整张表",
				values["read"], formatMAC(wantMAC, ":"), macRowsMax)}
	case wantMAC != nil:
		return ots.Verdict{Code: snmpMacNotFound, Values: values,
			Note: fmt.Sprintf("表读全了（%s 一张，%v 条），里面没有 %s。两件要一起看："+
				"FDB 只记「最近发过帧」的源地址，静默的终端不在表里；"+
				"其次是它可能挂在另一台设备或另一个 VLAN 上（这次读的是 %s 那张表）。"+
				"先用 net.neighbors 看本机 ARP/NDP 里有没有它，再确认它有没有在发东西。",
				table.name, values["read"], formatMAC(wantMAC, ":"), table.name)}
	case len(rows) == 0 && truncated:
		// 读满一屏却一条都没筛出来：条件太窄，或者表太大没读到那一段 —— 不能判空。
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("读了 %v 条撞到 limit，筛完是空的。这不是「没有」：把 limit 提上去再看",
				values["read"])}
	case len(rows) == 0:
		return ots.Verdict{Code: snmpNoData, Values: values,
			Note: fmt.Sprintf("转发表问过了（%s），这台设备一条都没给。",
				strings.Join(values["tablesTried"].([]string), "、")) +
				"要么它确实没学到东西（口都 down 着、或者链路上没流量），" +
				"要么它不做二层交换（三层设备/透明转发），" +
				"要么这张表按 VLAN 分给了别的团体名 —— BRIDGE-MIB 那张在很多实现里只回默认 VLAN 的内容，" +
				"这种要用 `团体名@VLAN` 那种扩展写法再问一次。"}
	default:
		extra := ""
		if truncated {
			extra = "，没读完"
		}
		return ots.Verdict{Code: snmpOk, Values: values,
			Note: fmt.Sprintf("读到 %v 条（表：%s%s）", values["count"], table.name, extra)}
	}
}

// fdbRowWhere 给一行拼「在哪个口」。★ 名字没解析出来时只报端口号，不硬凑一个名字。
func fdbRowWhere(r fdbRow, entry map[string]any) string {
	where := "桥端口 " + strconv.Itoa(r.port)
	if s, ok := entry["port"].(string); ok && s != "" {
		where = s
	}
	if r.hasVLAN {
		where += " / VLAN " + strconv.Itoa(r.vlan)
	}
	return where
}
