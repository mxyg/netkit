package tools

// net.snmp.ports 的测试。★ 假设备上的每一个毛病都是照着真设备的毛病填的：
//   - 10G 口的 ifSpeed 报顶格值 4294967295（RFC 2863 就是这么规定的），
//     只有 ifHighSpeed 能问出准数；有一台连 ifHighSpeed 都不给，那就只能说「至少 4.29G」。
//   - 有的设备只有 32 位的 ifInOctets（千兆口 34 秒绕一圈）。
//   - 错包/丢包那几栏**没有 64 位版本**，即使在有 ifHCInOctets 的设备上也还是 Counter32。
//   - 管理上是 down（有人关了）和链路上是 down（断了）是两个结论。
//   - oper 的 dormant / lowerLayerDown 最容易被当成「断了」，而这两种都不该去查线。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
)

func snmpPortsRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snmpPortsTool.Invoke(context.Background(), raw)
	if err != nil {
		t.Fatalf("工具直接报错：%v", err)
	}
	v, ok := got.(ots.Verdict)
	if !ok {
		t.Fatalf("回来的不是判定，是 %T", got)
	}
	if !ots.ValidVerdictCode(v.Code) {
		t.Errorf("判定码 %q 不合法", v.Code)
	}
	assertNoCommunity(t, v)
	return v
}

func portsOf(t *testing.T, v ots.Verdict) []map[string]any {
	t.Helper()
	ps, ok := v.Values["ports"].([]map[string]any)
	if !ok {
		t.Fatalf("ports 不是行数组，是 %T", v.Values["ports"])
	}
	return ps
}

// portDeviceEntries 是一台 13 个口的交换机。
//
// ★ sysUpTime = 900000（1/100 秒）= 开了 9000 秒。
//
//	ifLastChange 用的是同一把尺子，所以「这个口起来了多久」= 两者相减。
func portDeviceEntries() map[string]snmptest.Value {
	e := sysEntries()
	type port struct {
		idx         int
		name        string // ifName；空 = 这台不给 ifName，只能靠 ifDescr
		descr       string
		typ         int
		admin, oper int
		lastChange  int64 // 相对 sysUpTime 往回多少秒；0 = 这一栏不给
		mbps        int   // ifHighSpeed；0 = 不给这一栏
		cappedSpeed bool  // 只给 ifSpeed，而且给的是顶格值
		c32         bool  // 只有 32 位的 ifInOctets（没有 ifHCInOctets）
		hcInOnly    bool  // ★ 只有入向做了 64 位，出向仍然只有 Counter32
		noOctets    bool  // 字节数整个不给读（有些虚拟口/老固件就是这样）
	}
	ports := []port{
		{idx: 1, name: "GigabitEthernet1/0/1", descr: "GE1/0/1", typ: 6, admin: 1, oper: 1, lastChange: 9000, mbps: 1000},
		{idx: 2, name: "GigabitEthernet1/0/2", descr: "GE1/0/2", typ: 6, admin: 1, oper: 2, lastChange: 60, mbps: 1000},
		{idx: 3, name: "GigabitEthernet1/0/3", descr: "GE1/0/3", typ: 6, admin: 2, oper: 2, lastChange: 3000, mbps: 1000},
		{idx: 4, name: "10GE1/0/1", descr: "XGE1/0/1", typ: 6, admin: 1, oper: 1, lastChange: 8000, mbps: 10000},
		{idx: 5, name: "10GE1/0/2", descr: "XGE1/0/2", typ: 6, admin: 1, oper: 1, lastChange: 9000, cappedSpeed: true},
		{idx: 6, name: "GigabitEthernet1/0/6", descr: "GE1/0/6", typ: 6, admin: 1, oper: 5, lastChange: 10, mbps: 1000},
		{idx: 7, name: "Bridge-Aggregation1", descr: "BAGG1", typ: 161, admin: 1, oper: 7, lastChange: 100, mbps: 2000},
		// 只有 32 位计数器的一个口（老设备/老实现）
		{idx: 8, name: "GigabitEthernet1/0/8", descr: "GE1/0/8", typ: 6, admin: 1, oper: 1, lastChange: 4000, mbps: 100, c32: true},
		{idx: 9, name: "Vlanif100", descr: "Vlanif100", typ: 136, admin: 1, oper: 1, lastChange: 6000, mbps: 0},
		{idx: 10, name: "GigabitEthernet1/0/10", descr: "GE1/0/10", typ: 6, admin: 1, oper: 1, lastChange: 9000, mbps: 1000},
		{idx: 11, descr: "GigabitEthernet1/0/11（这台没有 ifName）", typ: 6, admin: 1, oper: 2, lastChange: 5, mbps: 1000},
		// ★ 只有入向做了 64 位：这是 ifXTable 最常见的实现残缺，
		//   当成一档处理的话出向会被拿错位的模数相减。
		{idx: 12, name: "GigabitEthernet1/0/12", descr: "GE1/0/12", typ: 6, admin: 1, oper: 1, lastChange: 7000, mbps: 1000, hcInOnly: true},
		// 一个字节数都不给读的口（虚拟接口 / 老固件常这样）
		{idx: 13, name: "Null0", descr: "Null0", typ: 1, admin: 1, oper: 1, lastChange: 9000, noOctets: true},
	}
	put := func(col string, idx int, v snmptest.Value) { e[col+"."+fmt.Sprint(idx)] = v }
	for _, p := range ports {
		if p.name != "" {
			put(oidIfName, p.idx, snmptest.Str(p.name))
		}
		put(oidIfDescr, p.idx, snmptest.Str(p.descr))
		put(oidIfIndex, p.idx, snmptest.Int(int64(p.idx)))
		put(oidIfType, p.idx, snmptest.Int(int64(p.typ)))
		put(oidIfAdminStatus, p.idx, snmptest.Int(int64(p.admin)))
		put(oidIfOperStatus, p.idx, snmptest.Int(int64(p.oper)))
		if p.lastChange > 0 {
			put(oidIfLastChange, p.idx, snmptest.Ticks(uint64((9000-p.lastChange)*100)))
		}
		switch {
		case p.cappedSpeed:
			put(oidIfSpeed, p.idx, snmptest.Gauge(speedMaxIfSpeed))
		case p.mbps > 0:
			put(oidIfSpeed, p.idx, snmptest.Gauge(uint64(p.mbps)*1000000))
			put(oidIfHighSpeed, p.idx, snmptest.Gauge(uint64(p.mbps)))
		}
		switch {
		case p.noOctets:
			// 一个字节数都不给 —— 这一档要的是「不给读」和「0 字节」分开。
		case p.hcInOnly:
			put(oidIfHCInOctets, p.idx, snmptest.Count64(900000000000))
			put(oidIfInOctets, p.idx, snmptest.Count(900000000000%(1<<32)))
			put(oidIfOutOctets, p.idx, snmptest.Count(7654321))
		case p.c32:
			put(oidIfInOctets, p.idx, snmptest.Count(1234567))
			put(oidIfOutOctets, p.idx, snmptest.Count(7654321))
		default:
			put(oidIfHCInOctets, p.idx, snmptest.Count64(900000000000))
			put(oidIfHCOutOctets, p.idx, snmptest.Count64(400000000000))
			put(oidIfInOctets, p.idx, snmptest.Count(900000000000%(1<<32)))
			put(oidIfOutOctets, p.idx, snmptest.Count(400000000000%(1<<32)))
		}
		put(oidIfInErrors, p.idx, snmptest.Count(0))
		put(oidIfOutErrors, p.idx, snmptest.Count(0))
		put(oidIfInDiscards, p.idx, snmptest.Count(0))
		put(oidIfOutDiscards, p.idx, snmptest.Count(0))
	}
	// 口 1 上写了一段备注：现场就是拿这一段来认口的。
	put(oidIfAlias, 1, snmptest.Str("配线架12-到NVR-3"))
	// 口 5 有一块光模块的 MAC；口 9 是 VLAN 接口，没有物理地址（这一栏不给）。
	put(oidIfPhysAddress, 5, snmptest.MAC(mustMAC("aabbccddeeff")))
	// 口 2 链路上断了，而且这一段在错包 —— 这是「查线」那一类。
	put(oidIfInErrors, 2, snmptest.Count(17))
	return e
}

func portsDevice(t *testing.T) *snmptest.Device {
	t.Helper()
	return snmptest.Start(t, probeCommunity, portDeviceEntries())
}

// TestSnmpPortsTable 整张表列回来该有的样子。
//
// ★ 最要紧的一格：判一是 snmp-ok。表里有口 down 着不是故障（空口本来就该 down），
//
//	把这一条判成故障，这张卡就会永远红着，红成了噪音。
func TestSnmpPortsTable(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	ps := portsOf(t, v)
	if len(ps) != 13 {
		t.Fatalf("读到 %d 个口，要 13 个", len(ps))
	}
	if v.Values["up"] != 8 || v.Values["down"] != 4 || v.Values["adminDown"] != 1 {
		t.Errorf("统计 = up %v / down %v / adminDown %v，要 8/4/1",
			v.Values["up"], v.Values["down"], v.Values["adminDown"])
	}
	if ps[0]["ifIndex"] != 1 {
		t.Errorf("第一个口是 %v，表要按 ifIndex 升序", ps[0]["ifIndex"])
	}
	if !strings.Contains(v.Note, "没链路") {
		t.Errorf("note = %q：有 down 就得提醒「这里面含空口，不是故障清单」", v.Note)
	}
}

// TestSnmpPortsNamedDown 点名一个 admin up / oper down 的口 → 链路断了。
func TestSnmpPortsNamedDown(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 2})
	if v.Code != snmpPortDown {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPortDown, v.Note)
	}
	ps := portsOf(t, v)
	if len(ps) != 1 || ps[0]["oper"] != "down" || ps[0]["admin"] != "up" {
		t.Fatalf("行不对：%v", ps)
	}
	for _, want := range []string{"admin", "查的是对端", "光模块"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」—— 这一条的下一步就是这个", v.Note, want)
		}
	}
}

// TestSnmpPortsDisabledIsNotAFault ★★ admin down 和 oper down 必须是两个码。
//
// 把「有人为维护关掉的口」报成「链路断了」，人就跑去机房查一根好着的线。
func TestSnmpPortsDisabledIsNotAFault(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 3})
	if v.Code != snmpPortDisabled {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPortDisabled, v.Note)
	}
	if !strings.Contains(v.Note, "有人关掉的") {
		t.Errorf("note = %q：要说清这是关掉的，不是断的", v.Note)
	}
	if strings.Contains(v.Note, "光模块") {
		t.Errorf("note = %q：这一条**不该**让人去查线查模块", v.Note)
	}
}

// TestSnmpPortsDormantAndLowerLayer 两种最容易被当成「断了」的 oper 值：
// 界面要把「别去查线」说在前面。
func TestSnmpPortsDormantAndLowerLayer(t *testing.T) {
	d := portsDevice(t)
	cases := []struct {
		idx  int
		oper string
		want string
	}{
		{6, "dormant", "802.1X"},
		{7, "lowerLayerDown", "成员口"},
	}
	for _, c := range cases {
		v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": c.idx})
		if v.Code != snmpPortDown {
			t.Errorf("口 %d 判定 = %s，要 %s", c.idx, v.Code, snmpPortDown)
		}
		ps := portsOf(t, v)
		if ps[0]["oper"] != c.oper {
			t.Errorf("口 %d oper = %v，要 %s", c.idx, ps[0]["oper"], c.oper)
		}
		if !strings.Contains(v.Note, c.want) || !strings.Contains(v.Note, "不该去查线") {
			t.Errorf("口 %d note = %q：要说清「不该去查线」并指出该看%s", c.idx, v.Note, c.want)
		}
	}
}

// TestSnmpPortsDownAdviceSplitsByOper ★★ 一句「去查线」不能打包七种 oper。
//
// dormant 的那根线是好的（查完白跑一趟回来），notPresent 压根没有模块可查，
// lowerLayerDown 要往下看成员口 —— 这三种挂同一句建议，就等于把三种
// 下一步相反的病按成一种，界面上那颗红灯还会替这句话背书。
func TestSnmpPortsDownAdviceSplitsByOper(t *testing.T) {
	d := portsDevice(t)
	for _, c := range []struct {
		idx int
		yes string
		no  string
	}{
		{2, "光模块", ""},
		{6, "802.1X", "光模块"},
		{7, "成员口", "这根线"},
	} {
		v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": c.idx})
		if !strings.Contains(v.Note, c.yes) {
			t.Errorf("口 %d note = %q：该指出去看 %s", c.idx, v.Note, c.yes)
		}
		if c.no != "" && strings.Contains(v.Note, c.no) {
			t.Errorf("口 %d note = %q：这一条**不该**让人去查%s", c.idx, v.Note, c.no)
		}
	}
}

// TestDownAdviceEveryOper oper 的整个值域逐个过一遍。
//
// 表里放不下的那几档（在测试模式、设备自己答不出）真机上不多，但一错就是
// 把人支去机房白跑一趟：所以每一档要么给出对的下一步，要么明说「这一条不能
// 当结论」，不许把标准值说成非标准值。
func TestDownAdviceEveryOper(t *testing.T) {
	for _, c := range []struct {
		oper int
		yes  string
		no   string
	}{
		{2, "对端", ""},
		{3, "线测", ""},
		// ★ unknown 是标准值：这一档只许说「设备答不出」，不许说「值不标准」，
		//   也不许顺手给一条查线的话。
		{4, "答不出", "不是标准值"},
		{5, "802.1X", "光模块"},
		{6, "不在位", "对端"},
		{7, "成员口", "光模块"},
		{0, "不是标准值", ""},
		{42, "不是标准值", "光模块"},
	} {
		got := downAdvice(c.oper)
		if got == "" {
			t.Errorf("oper %d 没给下一步", c.oper)
			continue
		}
		if strings.Contains(got, "**") {
			t.Errorf("oper %d 的 note 里有 markdown 星号：%q", c.oper, got)
		}
		if c.yes != "" && !strings.Contains(got, c.yes) {
			t.Errorf("oper %d = %q：该出现「%s」", c.oper, got, c.yes)
		}
		if c.no != "" && strings.Contains(got, c.no) {
			t.Errorf("oper %d = %q：这一条不该出现「%s」", c.oper, got, c.no)
		}
	}
	// 每一档的话都得各不相同：同一个值域里给两句一模一样的，等于合并了两类病。
	seen := map[string]int{}
	for _, op := range []int{2, 3, 4, 5, 6, 7} {
		s := downAdvice(op)
		if n, ok := seen[s]; ok {
			t.Errorf("oper %d 与 oper %d 给了同一句下一步：%q", op, n, s)
		}
		seen[s] = op
	}
}

// TestSnmpPortsHighSpeedWins ★★ 10G 口不能报成 4.29G。
//
// ifSpeed 是 Gauge32，带宽超过 4294967295 时它**就报顶格值**（RFC 2863），
// 所以有 ifHighSpeed 时必须用后者的准数。
func TestSnmpPortsHighSpeedWins(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 4})
	ps := portsOf(t, v)
	if got := ps[0]["speedMbps"]; got != uint64(10000) {
		t.Errorf("speedMbps = %v，要 10000 —— 拿 ifSpeed 的顶格值会写成 4294.97", got)
	}
	if _, ok := ps[0]["speedAtLeast"]; ok {
		t.Errorf("问出准数了还标顶格：%v", ps[0])
	}
}

// TestSnmpPortsCappedSpeedIsNotASpeed 只给 ifSpeed 顶格值的设备：
// ★ 这一栏是「至少 4.29G」，不是一个速率。写成 4.29G 就是把猜的当结论。
func TestSnmpPortsCappedSpeedIsNotASpeed(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 5})
	ps := portsOf(t, v)
	if _, ok := ps[0]["speedMbps"]; ok {
		t.Errorf("顶格值被当成速率给了：%v", ps[0])
	}
	if got := ps[0]["speedAtLeast"]; got != uint64(speedMaxIfSpeed) {
		t.Errorf("speedAtLeast = %v，要 %d", got, speedMaxIfSpeed)
	}
	if !strings.Contains(fmt.Sprint(ps[0]["speedText"]), "至少") {
		t.Errorf("speedText = %v：要写成「至少」", ps[0]["speedText"])
	}
}

// TestSnmpPortsNameMatchesPanel 面板写法：Gi1/0/1 认得出 GigabitEthernet1/0/1，
// 但★ 绝不能顺手把 1/0/10 也算进来 —— 那会把人送到别人的链路上。
func TestSnmpPortsNameMatchesPanel(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "name": "Gi1/0/1"})
	ps := portsOf(t, v)
	if len(ps) != 1 {
		t.Fatalf("按 Gi1/0/1 匹配到 %d 个口：%v —— 1/0/1 和 1/0/10 是两个口", len(ps), namesOf(ps))
	}
	if ps[0]["ifIndex"] != 1 {
		t.Errorf("匹配到 ifIndex %v，要 1", ps[0]["ifIndex"])
	}
	// 整类匹配：只给字母段
	all := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "name": "vlan"})
	if got := namesOf(portsOf(t, all)); len(got) != 1 || got[0] != "Vlanif100" {
		t.Errorf("按 vlan 筛出来是 %v，要只有 Vlanif100", got)
	}
	// 备注里认口：现场抄的就是这一段
	by := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "name": "配线架12"})
	if got := namesOf(portsOf(t, by)); len(got) != 1 || got[0] != "GigabitEthernet1/0/1" {
		t.Errorf("按 ifAlias 找口找出来是 %v，要口 1", got)
	}
}

func namesOf(ps []map[string]any) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprint(p["name"]))
	}
	return out
}

// TestSnmpPortsDescrFallback ifName 缺项的设备：退到 ifDescr，别报成「没有名字」。
func TestSnmpPortsDescrFallback(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 11})
	ps := portsOf(t, v)
	if !strings.HasPrefix(fmt.Sprint(ps[0]["name"]), "GigabitEthernet1/0/11") {
		t.Errorf("name = %v，要用 ifDescr 兜住", ps[0]["name"])
	}
}

// TestSnmpPortsNotFoundReadWhole 表读全了没这个口：★ note 里必须先说
// 「面板编号不一定等于 ifIndex」，否则人会以为设备上没这个口。
func TestSnmpPortsNotFoundReadWhole(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 999})
	if v.Code != snmpPortNotFound {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPortNotFound, v.Note)
	}
	if len(portsOf(t, v)) != 0 {
		t.Error("没找着还给行")
	}
	if !strings.Contains(v.Note, "不等于") && !strings.Contains(v.Note, "不相等") {
		t.Errorf("note = %q：要说清 ifIndex 和面板编号不一定对得上", v.Note)
	}
	if _, ok := v.Values["countTotal"]; ok {
		t.Error("按索引直取时不走表，「一共有几个口」是不知道的，不许写这一栏")
	}
}

// TestSnmpPortsTruncatedIsNotConclusion ★★ 撞限量的那几次都不许说「没这个口」。
func TestSnmpPortsTruncatedIsNotConclusion(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"name": "GE1/0/10", "limit": 3})
	if v.Code != snmpNotWalked {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNotWalked, v.Note)
	}
	if !strings.Contains(v.Note, "不是") {
		t.Errorf("note = %q：要说清「没读到」不等于「这台没这个口」", v.Note)
	}
	// ★ 撞限量那一次设备明明答了话（前面那几个口就是它答的）：这一条不能写成「没回话」，
	//   否则界面会让人以为团体名或防火墙有问题，而该做的是把限量提大。
	if v.Values["answered"] != true {
		t.Errorf("answered = %v：走表走回来了 3 个口，就是答过话", v.Values["answered"])
	}
}

// TestSnmpPortsStateFilter 筛状态不减读量，所以结果里要看得见筛过。
func TestSnmpPortsStateFilter(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "state": "down"})
	ps := portsOf(t, v)
	// down 那一档含「被关着的」口 3：筛的是 oper，admin 只管定性，两件事不能混。
	if len(ps) != 5 {
		t.Fatalf("down 筛出来 %d 个：%v", len(ps), namesOf(ps))
	}
	if v.Values["stateFilter"] != "down" {
		t.Errorf("结果里没记「按状态筛过」：%v", v.Values)
	}
	if v.Values["read"] != 13 {
		t.Errorf("read = %v，要 13 —— 筛选是在读回来之后筛", v.Values["read"])
	}
	if !strings.Contains(v.Note, "筛之前") {
		t.Errorf("note = %q：要说明这是筛过的", v.Note)
	}
}

// TestSnmpPortsNoMACOnVirtual 虚拟接口没有物理地址：这一栏**不出现**，不给空串。
func TestSnmpPortsNoMACOnVirtual(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 9})
	ps := portsOf(t, v)
	if _, ok := ps[0]["mac"]; ok {
		t.Errorf("VLAN 接口给了 mac：%v", ps[0])
	}
	if ps[0]["kind"] != "二层 VLAN 接口" {
		t.Errorf("kind = %v —— 虚拟口的 down 和物理口的 down 是两个结论，类型必须认出来", ps[0]["kind"])
	}
}

// TestSnmpPortsFlapping 刚换过状态的口要单独摆出来：这是查「偶尔断一下」最省事的一格。
func TestSnmpPortsFlapping(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	list, _ := v.Values["recentlyChanged"].([]string)
	got := map[string]bool{}
	for _, s := range list {
		// 每一项是「口名（多久以前）」
		got[strings.SplitN(s, "（", 2)[0]] = true
	}
	want := []string{"GigabitEthernet1/0/2", "GigabitEthernet1/0/6", "Bridge-Aggregation1",
		"GigabitEthernet1/0/11"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("recentlyChanged = %v，少了 %s（它是几十秒前才换的状态）", list, w)
		}
	}
	// ★ 起来了 9000 秒的口不算「刚翻过」。这里刻意查 1/0/1：它和 1/0/10 只差一个字符，
	//   按前缀查会查错，所以必须查「整项等于」。
	for _, n := range []string{"GigabitEthernet1/0/1", "GigabitEthernet1/0/10", "GigabitEthernet1/0/3"} {
		if got[n] {
			t.Errorf("%s 起来了两三个小时，不该出现在刚换过状态的清单里：%v", n, list)
		}
	}
	if len(list) != len(want) {
		t.Errorf("recentlyChanged = %v，要正好 %d 项 —— 多出来的说明「多久以前」算歪了", list, len(want))
	}
}

// TestSnmpPortsNoCounters noCounters 要真的少问：几百口的设备上这是唯一能让这张卡变快的一档。
func TestSnmpPortsNoCounters(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "noCounters": true})
	if _, ok := v.Values["counterBits"]; ok {
		t.Errorf("没问计数器还给 counterBits：%v", v.Values)
	}
	ps := portsOf(t, v)
	if _, ok := ps[0]["inOctets"]; ok {
		t.Errorf("noCounters 了还带累计值：%v", ps[0])
	}
	if ps[0]["oper"] != "up" {
		t.Errorf("状态那一栏被一起省掉了：%v", ps[0])
	}
	// ★ 错包/丢包也一样：没问就是没问，不许写成一串 0（那是「一个错包都没有」）。
	for _, k := range []string{"inErrors", "outErrors", "inDiscards", "outDiscards",
		"inOctets32", "outOctets32"} {
		if _, ok := ps[0][k]; ok {
			t.Errorf("noCounters 了还带 %v：%v", k, ps[0])
		}
	}
}

// TestSnmpPortsPerDirectionCounters ★★ 只有入向做了 64 位的设备（口 12）。
//
// 当成一档处理的话，出向会被拿错位的模数相减 —— 这里要看到两向各按各的档位。
func TestSnmpPortsPerDirectionCounters(t *testing.T) {
	d := portsDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		// 只有入向推进：出向原样不动，那一条要能算出「出向这 1 秒没跑东西」，
		// 而不是被入向的档位带歪。
		d.Set("1.3.6.1.2.1.31.1.1.1.6.12", snmptest.Count64(900000000000+250000))
	})
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"ifIndex": 12, "watchSeconds": 1})
	row := portsOf(t, v)[0]
	if _, ok := row["inOctets"]; !ok {
		t.Errorf("入向没按 64 位那一档写：%v", row)
	}
	if _, ok := row["outOctets32"]; !ok {
		t.Errorf("出向没按 32 位那一档写：%v —— 同一行两向档位不同，键名必须分开", row)
	}
	got, hasIn := row["inMbps"]
	if !hasIn || got.(float64) < 1.0 {
		t.Errorf("inMbps = %v (有=%v)，入向推了 250000 字节，要算得出速率", got, hasIn)
	}
	if got, ok := row["outMbps"]; !ok || got != 0.0 {
		t.Errorf("outMbps = %v (ok=%v)，出向没动过要 0 —— 0 是真数，不是缺项", got, ok)
	}
	if _, ok := row["outRateWhy"]; ok {
		t.Errorf("出向算得出来却记了原因：%v", row["outRateWhy"])
	}
	// 混用的表按短板报：报 64 会让人以为出向也不会绕回。
	if v.Values["counterBits"] != 32 {
		t.Errorf("counterBits = %v，要 32（这一向只有 Counter32）", v.Values["counterBits"])
	}
}

// TestSnmpPortsFilteredOutScope ★★ 点名 + 筛状态把点的那个口筛掉了：
//
//	这要说成「它不是这一档」，不能顺嘴说成「这台只有一个口」——按 ifIndex 点名时
//	这趟根本没读整张表，报一个「一共 1 个」就是凭空给全表下结论。
func TestSnmpPortsFilteredOutScope(t *testing.T) {
	d := portsDevice(t)
	byIdx := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"ifIndex": 2, "state": "up"})
	if byIdx.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", byIdx.Code, snmpOk, byIdx.Note)
	}
	if len(portsOf(t, byIdx)) != 0 {
		t.Errorf("筛掉了还给行：%v", byIdx.Values["ports"])
	}
	if strings.Contains(byIdx.Note, "一共") || strings.Contains(byIdx.Note, "个里面") {
		t.Errorf("note = %q：按编号点名时不知道全表有几个口，不许报数", byIdx.Note)
	}
	if !strings.Contains(byIdx.Note, "被筛掉") {
		t.Errorf("note = %q：要说清「被筛掉」不是「没有这个口」", byIdx.Note)
	}
	// 按名字点名走的是整张表，这时候读到的个数是真知道得，可以提。
	byName := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"name": "GE1/0/2", "state": "up"})
	if byName.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", byName.Code, snmpOk, byName.Note)
	}
	if !strings.Contains(byName.Note, "这张表一共 13 个口") {
		t.Errorf("note = %q：按名字查走的是整张索引表，知道全表几个口就该带上", byName.Note)
	}
}

// TestPortNameMatches 口名那套认法的边界：简写要认得，编号差一位就不许认。
func TestPortNameMatches(t *testing.T) {
	one := func(s string) []portNameHit { return []portNameHit{{s: s}} }
	for _, c := range []struct {
		want string
		have []portNameHit
		ok   bool
	}{
		{"Gi1/0/5", one("GigabitEthernet1/0/5"), true},
		// ★ 反过来也要成：设备上给的是长写法，人抄的是面板上那三个字母。
		{"GE1/0/5", one("GigabitEthernet1/0/5"), true},
		{"GigabitEthernet1/0/5", one("GE1/0/5"), true},
		{"Te1/0/1", one("10GE1/0/1"), false}, // 编号段对不上（10 被算进编号里了）
		{"10GE1/0/1", one("10GE1/0/1"), true},
		// 编号差一位是两个口，含糊不得。
		{"Gi1/0/50", one("GigabitEthernet1/0/5"), false},
		{"Gi1/0/5", one("GigabitEthernet1/0/50"), false},
		// 不同类的口不许被归一族。
		{"Fa0/1", one("GigabitEthernet0/1"), false},
		{"Gi0/1", one("FastEthernet0/1"), false},
		{"Vlanif100", one("Vlanif100"), true},
		{"Vlan100", one("Vlanif100"), true},
		// 表里没点到的写法仍走前缀规则：认不出就该说认不出。
		{"Qx1/0/1", one("GigabitEthernet1/0/1"), false},
		{"Po1", one("Port-channel1"), true},
		// 只给字母 = 整类匹配
		{"vlan", []portNameHit{{s: "Vlanif100"}, {s: "GigabitEthernet1/0/1"}}, true},
		{"ge", one("GigabitEthernet1/0/1"), true},
		// 备注走另一套：那是人写的一句话，按子串认。
		{"配线架12", []portNameHit{{s: "GigabitEthernet1/0/1"}, {s: "配线架12-到NVR-3", alias: true}}, true},
		{"NVR-3", []portNameHit{{s: "配线架12-到NVR-3", alias: true}}, true},
	} {
		if got := portNameMatches(c.want, c.have); got != c.ok {
			t.Errorf("portNameMatches(%q, %v) = %v，要 %v", c.want, c.have, got, c.ok)
		}
	}
}

// TestSnmpPortsDescrAlsoNamesThePort ★ 有 ifName 不等于 ifDescr 白读。
//
// 思科把短写法放在 ifName（Gi1/0/1）、长写法放在 ifDescr，华为/H3C 正好反过来
// （ifDescr 是 GE1/0/1 这种短写法），还有的设备两栏写的是对不上的两套名字。
// 只认一句的那一种，人抄另一句就被判「没这个口」。
func TestSnmpPortsDescrAlsoNamesThePort(t *testing.T) {
	d := portsDevice(t)
	// 故意造一个两栏互推不出来的口：ifName 是 Bridge-Aggregation1，ifDescr 是 Trunk1。
	d.Set(oidIfDescr+".7", snmptest.Str("Trunk1"))
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"name": "Trunk1"})
	// 口 7 是个成员口没起来的聚合口，所以点名它给的是「底下的层没起」——
	// 这一条要的是**找着了它**（判定码不是 snmp-port-not-found）。
	if v.Code != snmpPortDown {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPortDown, v.Note)
	}
	ps := portsOf(t, v)
	if len(ps) != 1 || ps[0]["ifIndex"] != 7 {
		t.Fatalf("按 ifDescr 没找着口：%v", ps)
	}
	// 同一个口的 ifName 照样要能问出来：两栏都是它的名字，不是「后者盖掉前者」。
	byName := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"name": "Bridge-Aggregation1"})
	if got := portsOf(t, byName); len(got) != 1 || got[0]["ifIndex"] != 7 {
		t.Errorf("换了 ifName 反而找不着了：%v", got)
	}
}

// TestSnmpPortsNoOctetColumn ★★ 字节数整个不给读的口（口 13）：
// 「不给读」和「一个字节都没跑」是两个结论，所以既不写 0、也不写速率。
func TestSnmpPortsNoOctetColumn(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"ifIndex": 13, "watchSeconds": 1})
	row := portsOf(t, v)[0]
	for _, k := range []string{"inOctets", "outOctets", "inOctets32", "outOctets32",
		"inMbps", "outMbps"} {
		if _, ok := row[k]; ok {
			t.Errorf("这台不给读字节数，却写了 %v = %v：%v", k, row[k], row)
		}
	}
	why := fmt.Sprint(row["inRateWhy"])
	if !strings.Contains(why, "不给读") {
		t.Errorf("inRateWhy = %q：要说「这台不给读」，不是「数算不准」", why)
	}
	// 错包那一栏它给了，就照写 —— 不能因为没字节数把整行流量都判成没有。
	if _, ok := row["inErrors"]; !ok {
		t.Errorf("设备给了 ifInErrors 却没写出来：%v", row)
	}
	if v.Values["counterBits"] != nil {
		t.Errorf("一个字节数都没读到，counterBits 该整栏不写：%v", v.Values["counterBits"])
	}
}

// TestSnmpPortsDirectGetIsCheap 点名一个口不许走全表。
// ★ 三万口的框式设备走一遍是上千个报文，而现场问的就是「5 口起来了没有」。
func TestSnmpPortsDirectGetIsCheap(t *testing.T) {
	d := portsDevice(t)
	before := d.Reqs()
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 5})
	used := d.Reqs() - before
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if used > 4 {
		t.Errorf("点名叫一个口用了 %d 个报文，要 ≤4（多出来的是走表）", used)
	}
}

// TestSnmpPortsNoData 系统组答得好好的、ifTable 是空的：判「没有数据」，不判「不通」。
func TestSnmpPortsNoData(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpNoData {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNoData, v.Note)
	}
	if v.Values["answered"] != true {
		t.Errorf("answered = %v：设备答过话，这一条不能含糊", v.Values["answered"])
	}
}

// TestSnmpPortsNoReply 团体名不对：走 SNMP 共用那一条收口。
func TestSnmpPortsNoReply(t *testing.T) {
	d := portsDevice(t)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": "wrong",
		"timeoutMs": 200, "retries": 2})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNoReply, v.Note)
	}
}

// TestSnmpPortsBadArgs 参数写错要直接报错，不能变成判定码。
func TestSnmpPortsBadArgs(t *testing.T) {
	d := portsDevice(t)
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"state 不认识", map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"state": "blocked"}, "state"},
		{"ifIndex 超范围", map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"ifIndex": 70000}, "ifIndex"},
		{"watchSeconds 太长", map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"watchSeconds": 9999}, "watchSeconds"},
		{"没给团体名", map[string]any{"addr": d.Addr()}, "community"},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(c.args)
		_, err := snmpPortsTool.Invoke(context.Background(), raw)
		if err == nil {
			t.Errorf("%s：居然跑通了", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：报错 %q 里没提到 %q", c.name, err, c.want)
		}
		if strings.Contains(err.Error(), probeCommunity) {
			t.Errorf("%s：报错里漏出了团体名", c.name)
		}
	}
}

// TestSnmpPortsSampleGivesRates 读两遍要给出速率、增量。
//
// ★ 推计数器的那一下必须落在两次读**中间**：goroutine 立刻推的话往往赶在第一遍之前，
//
//	于是两遍读到同一个值、增量恒为 0 —— 这一条就变成一条永远绿的假测试。
func TestSnmpPortsSampleGivesRates(t *testing.T) {
	d := portsDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set("1.3.6.1.2.1.31.1.1.1.6.1", snmptest.Count64(900000000000+200000))
		d.Set("1.3.6.1.2.1.2.2.1.14.2", snmptest.Count(20)) // 17 → 20
	})
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"ifIndex": 2, "watchSeconds": 1})
	// 口 2 本来就是 down，但这一档要验的是增量算得对。
	ps := portsOf(t, v)
	if got := ps[0]["inErrorsDelta"]; got != uint64(3) {
		t.Errorf("inErrorsDelta = %v，要 3（17 → 20）", got)
	}
	if got := v.Values["sampleSeconds"]; got == nil {
		t.Error("读了两遍却没记采样间隔")
	}
}

// TestSnmpPortsErrorsWhileUp 口是 up 的、这一段在错包 → snmp-port-errors。
// ★ 这一条和「不通」的下一步完全不同（查线/模块 vs 查双工不匹配）。
func TestSnmpPortsErrorsWhileUp(t *testing.T) {
	d := portsDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set("1.3.6.1.2.1.2.2.1.14.1", snmptest.Count(12))
	})
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"ifIndex": 1, "watchSeconds": 1})
	if v.Code != snmpPortErrors {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPortErrors, v.Note)
	}
	for _, want := range []string{"up", "双工"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
}

// TestSnmpPortsRebootBetweenSamples ★ 两次读之间设备重启过：差值全是假的，只给累计值。
func TestSnmpPortsRebootBetweenSamples(t *testing.T) {
	d := portsDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set("1.3.6.1.2.1.1.3.0", snmptest.Ticks(5000)) // sysUpTime 倒退 = 刚重启
		d.Set("1.3.6.1.2.1.31.1.1.1.6.1", snmptest.Count64(1000))
	})
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"ifIndex": 1, "watchSeconds": 1})
	if v.Values["rebooted"] != true {
		t.Errorf("rebooted = %v：sysUpTime 倒退了要如实标出来", v.Values["rebooted"])
	}
	if !strings.Contains(fmt.Sprint(v.Values["rateUnsure"]), "重启") {
		t.Errorf("rateUnsure = %v：要说明速率不可信", v.Values["rateUnsure"])
	}
	ps := portsOf(t, v)
	if _, ok := ps[0]["inMbps"]; ok {
		t.Errorf("重启过还给速率：%v", ps[0])
	}
	// ★ note 是人家唯一复制走的那一行：只写「up、速率 1000M」而没提「这一趟
	//   压根没测到速率」，看着就像真的测过、而且是 0 —— 那是另一种结论。
	if !strings.Contains(v.Note, "重启") {
		t.Errorf("note = %q：这一趟没有速率这件事要写进这一句里", v.Note)
	}
}

// TestSnmpPortsRebootShowsInSummary 整张表那一条也要带上「这一趟没测到速率」。
func TestSnmpPortsRebootShowsInSummary(t *testing.T) {
	d := portsDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set("1.3.6.1.2.1.1.3.0", snmptest.Ticks(5000))
	})
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"watchSeconds": 1})
	if v.Values["rebooted"] != true {
		t.Fatalf("rebooted = %v", v.Values["rebooted"])
	}
	if !strings.Contains(v.Note, "重启") {
		t.Errorf("note = %q：列表那一条也要说清这一趟没有速率", v.Note)
	}
}

// TestSnmpPortsV1Device v1 设备：没有 GETBULK（列 ifIndex 退成 GETNEXT），
// 批量 GET 里少一栏会让整包作废（退成一栏一栏问）。
func TestSnmpPortsV1Device(t *testing.T) {
	d := portsDevice(t)
	d.SetV1Only(true)
	v := snmpPortsRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "version": "v1"})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	if got := len(portsOf(t, v)); got != 13 {
		t.Errorf("v1 读到 %d 个口，要 13 个 —— GETNEXT 那条路走歪了", got)
	}
}

// ── 计数器数学：这部分不碰网络，所以用最坏的数直接算 ──

// hcRow 造一个「第一遍读回来」的口。
//
// 四栏错误/丢弃计数器按「设备给了」初始化 —— 这几条测的是数学，
// 「不给读」那条路有 TestApplyRatesMissingColumn 单独钉。
func hcRow(idx int, in, out uint64, hc bool, speedMbps uint64) portRow {
	r := portRow{ifIndex: idx, inOctets: in, outOctets: out, admin: 1, oper: 1,
		inHC: hc, outHC: hc, inHas: true, outHas: true,
		got:       map[string]bool{},
		haveDelta: map[string]bool{}}
	for _, c := range []string{oidIfInErrors, oidIfOutErrors, oidIfInDiscards, oidIfOutDiscards} {
		r.got[c] = true
	}
	if speedMbps > 0 {
		r.speedBps = speedMbps * 1000000
	}
	return r
}

// secondSample 把「第二遍读回来的那几栏」拼成 getPortSet 的形状。
func secondSample(idx int, vals map[string]snmptest.Value) map[int]map[string]snmp.VarBind {
	cols := map[string]snmp.VarBind{}
	for col, v := range vals {
		cols[col] = snmptest.Bind(col, idx, v)
	}
	return map[int]map[string]snmp.VarBind{idx: cols}
}

// TestApplyRatesCounter32Wrap ★★ 32 位计数器绕一圈：差必须按模算回来。
//
// 千兆口上 ifInOctets 34 秒就绕一圈，直接相减会得到一个负的（无符号下是一个巨大的）数，
// 界面上就是「这个口刚刚跑了 300 Gbps」。
func TestApplyRatesCounter32Wrap(t *testing.T) {
	const nearTop = uint64(1<<32) - 1000 // 差 1000 字节就绕完一圈
	rows := []portRow{hcRow(8, nearTop, nearTop, false, 100)}
	second := secondSample(8, map[string]snmptest.Value{
		oidIfInOctets:  snmptest.Count(500), // 绕过来之后又走了 500
		oidIfOutOctets: snmptest.Count(500),
	})
	applyRates(rows, second, 1.0)
	r := rows[0]
	if r.inRate != rateOK || r.outRate != rateOK {
		t.Fatalf("绕一圈是能算对的，不该拒答：in=%v out=%v", r.inRate, r.outRate)
	}
	// 1000 + 500 = 1500 字节 = 12000 bit / 1 秒 = 0.012 Mbps
	if got := r.inBps; got < 11900 || got > 12100 {
		t.Errorf("inBps = %v，要 ≈12000", got)
	}
}

// TestApplyRatesHCGoesBackwards ★★ 64 位那一栏变小了 = 计数器被重置过，不是绕圈。
//
// 让它相减的话 uint64 自己绕一圈，界面上就是「这个口刚刚跑了 1.8e20 bps」
// ——一个荒谬到没人会怀疑的数，因为它旁边写着 M。sysUpTime 正常前进时
// 重启那条路不会拦下这一种，所以这里必须自己拦。
func TestApplyRatesHCGoesBackwards(t *testing.T) {
	rows := []portRow{hcRow(1, 900000000000, 900000000000, true, 1000)}
	second := secondSample(1, map[string]snmptest.Value{
		oidIfHCInOctets:  snmptest.Count64(12345),
		oidIfHCOutOctets: snmptest.Count64(900000001000),
	})
	applyRates(rows, second, 1.0)
	r := rows[0]
	if r.inRate != rateUnreliable {
		t.Fatalf("64 位计数器倒退还给了速率：%v", r.inRate)
	}
	if r.inBps != 0 {
		t.Errorf("拒答了却留着数：%v", r.inBps)
	}
	if r.outRate != rateOK || r.outBps < 7900 || r.outBps > 8100 {
		t.Errorf("出向正常涨了 1000 字节，要 ≈8000bps，得到 %v / %v", r.outRate, r.outBps)
	}
}

// TestApplyRatesRefusesImpossibleSpeed ★ 绕了不止一圈时，计数器上看不出区别，
// 那就不能说速率是 X —— 算出来的速率超过线速，说明这个差不是「一段」而是「几段」。
func TestApplyRatesRefusesImpossibleSpeed(t *testing.T) {
	rows := []portRow{hcRow(8, 0, 0, false, 100)} // 100M 的口
	second := secondSample(8, map[string]snmptest.Value{
		// 一秒内"走了" 20 MB → 160 Mbps，超过 100M 线速：只能是绕了不止一圈
		oidIfInOctets:  snmptest.Count(20000000),
		oidIfOutOctets: snmptest.Count(0),
	})
	applyRates(rows, second, 1.0)
	if rows[0].inRate != rateUnreliable {
		t.Fatalf("算出 160Mbps 的「100M 口」还给了速率：%v", rows[0].inRate)
	}
	if rows[0].inBps != 0 || rows[0].outBps != 0 {
		t.Errorf("拒答了却留着数：%v / %v", rows[0].inBps, rows[0].outBps)
	}
}

// TestApplyRatesStaysOnOneColumn ★ 两遍必须用同一档计数器：
// 64 位的现在值减 32 位的历史值 = 一个天文数字。
func TestApplyRatesStaysOnOneColumn(t *testing.T) {
	rows := []portRow{hcRow(1, 1000, 1000, true, 1000)}
	second := secondSample(1, map[string]snmptest.Value{
		oidIfInOctets:  snmptest.Count(1060), // 第二遍只读到 32 位那一栏
		oidIfOutOctets: snmptest.Count(1060),
	})
	applyRates(rows, second, 1.0)
	if rows[0].inRate != rateUnreliable || rows[0].outRate != rateUnreliable {
		t.Fatalf("跨档相减没被拦下来：in=%v out=%v", rows[0].inRate, rows[0].outRate)
	}
	if _, ok := second[1][oidIfHCInOctets]; ok {
		t.Fatal("样本里本来就没有 64 位那一栏")
	}
}

// TestApplyRatesErrorsAreAlways32Bit ★★ 即使在有 ifHCInOctets 的设备上，
// ifInErrors / ifInDiscards 也**没有** 64 位版本，回绕必须按 32 位算。
// 跟着字节数那一档走的话，回绕那一次界面会显示「错了 1.8×10¹⁹ 个包」。
func TestApplyRatesErrorsAreAlways32Bit(t *testing.T) {
	rows := []portRow{hcRow(1, 1000, 1000, true, 1000)}
	rows[0].inErrors = uint64(1<<32) - 7 // 快绕完
	rows[0].inDiscards = uint64(1<<32) - 3
	second := secondSample(1, map[string]snmptest.Value{
		oidIfHCInOctets:  snmptest.Count64(2000),
		oidIfHCOutOctets: snmptest.Count64(2000),
		oidIfInErrors:    snmptest.Count(3),
		oidIfOutErrors:   snmptest.Count(0),
		oidIfInDiscards:  snmptest.Count(3),
		oidIfOutDiscards: snmptest.Count(0),
	})
	applyRates(rows, second, 1.0)
	r := rows[0]
	if got := r.dInErr; got != 10 {
		t.Errorf("inErrors 增量 = %v，要 10（按 32 位回绕算）", got)
	}
	if got := r.dInDisc; got != 6 {
		t.Errorf("inDiscards 增量 = %v，要 6", got)
	}
	if got := r.errorDelta(); got > 100 {
		t.Errorf("错包增量被算成 %v —— 这是回绕没按 32 位处理的典型症状", got)
	}
}

// TestWrapDelta 钉住取模那一步。
func TestWrapDelta(t *testing.T) {
	cases := []struct {
		prev, cur uint64
		bits      int
		want      uint64
		why       string
	}{
		{100, 250, 32, 150, "正常前进"},
		{(1 << 32) - 10, 5, 32, 15, "绕一圈"},
		{5, 5, 32, 0, "没动"},
		{(1 << 32) - 1, 0, 32, 1, "刚好在顶格上"},
		{100, 90, 64, ^uint64(0) - 9, "64 位：直接相减，让 uint64 自己绕"},
	}
	for _, c := range cases {
		if got := wrapDelta(c.prev, c.cur, c.bits); got != c.want {
			t.Errorf("%s：wrapDelta(%d,%d,%d) = %d，要 %d", c.why, c.prev, c.cur, c.bits, got, c.want)
		}
	}
}

// TestApplyUpSecondsSaturates 起来了多久 = sysUpTime - ifLastChange。
// ★ TimeTicks 497 天绕一圈，绕过之后这两个数没可比性 —— 不给一个看着合理的错数。
func TestApplyUpSecondsSaturates(t *testing.T) {
	rows := []portRow{
		{ifIndex: 1, lastChange: 900000 - 4000}, // 40 秒前换的状态
		{ifIndex: 2, lastChange: 0},             // 这一栏设备没给
		{ifIndex: 3, lastChange: 1200000},       // ★ 比 sysUpTime 还大：绕过了
	}
	applyUpSeconds(rows, 900000)
	if !rows[0].upSecondsSet || rows[0].upSeconds != 40 {
		t.Errorf("口 1 sinceChange = %v/%v，要 40 秒", rows[0].upSeconds, rows[0].upSecondsSet)
	}
	if rows[1].upSecondsSet {
		t.Error("设备没给 ifLastChange 的口，不该凭空算出「多久以前」")
	}
	if rows[2].upSecondsSet {
		t.Errorf("刻度绕过一圈还算出 %v —— 这一条要说「算不出来」", rows[2].upSeconds)
	}
}

// TestHumanUptime ★「多久以前」这一格查的就是分钟级的差别，写成「0 分」等于没说。
func TestHumanUptime(t *testing.T) {
	for _, c := range []struct {
		secs uint64
		want string
	}{{0, "0 秒"}, {10, "10 秒"}, {59, "59 秒"}, {60, "1 分"}, {90, "1 分30 秒"},
		{300, "5 分"}, {3600, "1 小时"}, {7980, "2 小时13 分"}, {90061, "1 天1 小时1 分"}} {
		if got := humanUptime(c.secs); got != c.want {
			t.Errorf("humanUptime(%d) = %q，要 %q", c.secs, got, c.want)
		}
	}
}
