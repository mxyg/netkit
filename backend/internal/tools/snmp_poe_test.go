package tools

// net.snmp.poe 的测试。★ 假设备上的毛病照真设备填：
//   - PoE 有两个层级：整台的电源池（额定/实测/总开关）和单个口。池子塌了的时候
//     口那一栏写什么都不是那个口的事，所以池子的判定压在上面。
//   - adminEnable 与 detectionStatus 是两个数：前者 false 是有人关的，
//     后者 disabled 是设备自己把它排除在 PoE 之外的。
//   - 等级（class）只在供电中有效（RFC 3621 原文），不供电时给它是未定义值。
//   - 行索引是 {组号, 口号} 两段；RFC 3621 没有 ifIndex 到口号的映射，
//     所以「按接口编号问 PoE」只能是猜，并且要写明怎么猜的。
//   - 那五个计数器是从开机攒到现在的，要看「这一段涨没涨」必须读两遍，
//     而两遍之间设备重启过的话，相减得到的是一个看着合理的假数。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
)

func snmpPoeRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snmpPoeTool.Invoke(context.Background(), raw)
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
	if strings.Contains(v.Note, "**") {
		t.Errorf("note 里有 markdown 加粗记号：%s", v.Note)
	}
	return v
}

func poeRowsOf(t *testing.T, v ots.Verdict) []map[string]any {
	t.Helper()
	ps, ok := v.Values["poePorts"].([]map[string]any)
	if !ok {
		t.Fatalf("poePorts 不是行数组，是 %T", v.Values["poePorts"])
	}
	return ps
}

func pseRowsOf(t *testing.T, v ots.Verdict) []map[string]any {
	t.Helper()
	ps, ok := v.Values["pse"].([]map[string]any)
	if !ok {
		t.Fatalf("pse 不是行数组，是 %T", v.Values["pse"])
	}
	return ps
}

// poeRowBy 从列表里按口号挑一行（列表按 {组,口} 升序，但测试要的是某一行的某一栏，
// 写死下标的话，加一行fixture就得改一遍所有断言）。
func poeRowBy(t *testing.T, v ots.Verdict, port int) map[string]any {
	t.Helper()
	for _, e := range poeRowsOf(t, v) {
		if e["port"] == port {
			return e
		}
	}
	t.Fatalf("列表里没有 %d 号口：%v", port, v.Values["poePorts"])
	return nil
}

// poeDeviceEntries 是一台 370W 电源池、11 个 PoE 口的交换机。
//
// ★ sysUpTime = 900000（1/100 秒）= 开了 9000 秒，那几个计数器的「攒了多久」全靠它。
func poeDeviceEntries() map[string]snmptest.Value {
	e := sysEntries()
	type pd struct {
		port                                       int
		admin                                      int    // 1 true / 2 false，0 = 这一栏不给
		status                                     int    // detectionStatus，0 = 这一栏不给读
		pairs                                      int    // 1 signal / 2 spare，0 = 不给
		prio                                       int    // 1..3，0 = 不给
		class                                      int    // 1..5（这里有一个故意给 7 的），0 = 不给
		pdType                                     string // pethPsePortType（运维手写的标签）
		MpsAbsent, BadSig, Denied, OverLoad, Short uint64
	}
	ports := []pd{
		{port: 1, admin: 1, status: 3, pairs: 1, prio: 2, class: 3, pdType: "AP-3F-01"},
		{port: 2, admin: 1, status: 2, pairs: 1, prio: 3, class: 1, BadSig: 4},
		{port: 3, admin: 2, status: 1, pairs: 1, prio: 2},
		// ★ 这一行的标签写的是自己的口名：ifIndex 映射的第二条路子靠它。
		{port: 4, admin: 1, status: 3, pairs: 2, prio: 2, class: 4, pdType: "Gi1/0/4", MpsAbsent: 2},
		{port: 5, admin: 1, status: 2, prio: 2, Denied: 7},
		{port: 6, admin: 1, status: 3, prio: 3, Short: 1},
		{port: 7, admin: 1, status: 3, prio: 1, class: 4, OverLoad: 3},
		// ★ 等级给到五档以外：这棵树里没有 class5-8，只报编号、不换算成瓦。
		{port: 8, admin: 1, status: 3, prio: 2, class: 7},
		//使能写着 false、状态却写着「正在供电」：两栏对不上，这一档要说出来。
		{port: 9, admin: 2, status: 3, prio: 2, class: 3},
		{port: 10, admin: 1, status: 1},
		// ★ detectionStatus 不给读的一个口：走表认不出它，只有点名直取能读回来。
		{port: 11, admin: 1, prio: 2},
	}
	put := func(col string, idx int, v snmptest.Value) { e[col+"."+fmt.Sprint(idx)] = v }
	for _, p := range ports {
		// 每一行都挂在组 1 上（RFC 3621：非模块化设备必须用 1）。
		key := func(col string, v snmptest.Value) { e[col+".1."+fmt.Sprint(p.port)] = v }
		if p.admin != 0 {
			key(oidPethAdminEnable, snmptest.Int(int64(p.admin)))
		}
		key(oidPethPairsControl, snmptest.Int(1))
		if p.pairs != 0 {
			key(oidPethPowerPairs, snmptest.Int(int64(p.pairs)))
		}
		if p.status != 0 {
			key(oidPethDetectStatus, snmptest.Int(int64(p.status)))
		}
		if p.prio != 0 {
			key(oidPethPriority, snmptest.Int(int64(p.prio)))
		}
		if p.class != 0 {
			key(oidPethClass, snmptest.Int(int64(p.class)))
		}
		if p.pdType != "" {
			key(oidPethPortType, snmptest.Str(p.pdType))
		}
		key(oidPethMPSAbsent, snmptest.Count(p.MpsAbsent))
		key(oidPethBadSignature, snmptest.Count(p.BadSig))
		key(oidPethDenied, snmptest.Count(p.Denied))
		key(oidPethOverLoad, snmptest.Count(p.OverLoad))
		key(oidPethShort, snmptest.Count(p.Short))
		// ifTable：让按 ifIndex 那一条路有名字可对。
		put(oidIfIndex, p.port, snmptest.Int(int64(p.port)))
		put(oidIfName, p.port, snmptest.Str(fmt.Sprintf("GigabitEthernet1/0/%d", p.port)))
		put(oidIfDescr, p.port, snmptest.Str(fmt.Sprintf("GE1/0/%d", p.port)))
	}
	// 电源池：额定 370W、实测 180W、开着、告警线 90%。
	e[oidPethMainPower+".1"] = snmptest.Gauge(370)
	e[oidPethMainOperStatus+".1"] = snmptest.Int(1)
	e[oidPethMainConsumption+".1"] = snmptest.Gauge(180)
	e[oidPethMainThreshold+".1"] = snmptest.Int(90)
	return e
}

func poeDevice(t *testing.T) *snmptest.Device {
	t.Helper()
	return snmptest.Start(t, probeCommunity, poeDeviceEntries())
}

// poeStackedEntries 是一台堆叠设备：两个组，每组各有同号口。
// ★ 刻意让「1 组 5 号」和「2 组 5 号」都存在 —— 只填口号就按一组去猜的话，
//
//	等于把另一台机箱整个漏掉。
func poeStackedEntries() map[string]snmptest.Value {
	e := sysEntries()
	for _, g := range []int{1, 2} {
		for _, p := range []int{1, 5, 6} {
			key := func(col string, v snmptest.Value) {
				e[col+"."+fmt.Sprint(g)+"."+fmt.Sprint(p)] = v
			}
			key(oidPethAdminEnable, snmptest.Int(1))
			key(oidPethDetectStatus, snmptest.Int(3))
			key(oidPethPriority, snmptest.Int(2))
			key(oidPethClass, snmptest.Int(2))
			key(oidPethDenied, snmptest.Count(0))
		}
		e[oidPethMainPower+"."+fmt.Sprint(g)] = snmptest.Gauge(740)
		e[oidPethMainOperStatus+"."+fmt.Sprint(g)] = snmptest.Int(1)
		e[oidPethMainConsumption+"."+fmt.Sprint(g)] = snmptest.Gauge(120)
	}
	return e
}

// TestSnmpPoeTable 整张表列回来该有的样子。
//
// ★ 最要紧的一格：判定是 snmp-ok。表里有口没在供电不是故障（没插受电设备的口
// 本来就在 searching），把这一条判成故障，这张卡就永远红着。
func TestSnmpPoeTable(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	// detectionStatus 不给读的那一行走表认不出来，所以列表是 10 行。
	if got := len(poeRowsOf(t, v)); got != 10 {
		t.Fatalf("读到 %d 行，要 10 行", got)
	}
	if v.Values["countTotal"] != 10 {
		t.Errorf("countTotal = %v，要 10", v.Values["countTotal"])
	}
	// 在供电 6（1/4/6/7/8/9）、在检测 2（2/5）、disabled 2（3/10）、报错 0。
	if v.Values["powering"] != 6 || v.Values["searching"] != 2 ||
		v.Values["disabled"] != 2 || v.Values["faulty"] != 0 {
		t.Errorf("统计 = 供 %v / 检 %v / 未供 %v / 错 %v，要 6/2/2/0",
			v.Values["powering"], v.Values["searching"], v.Values["disabled"], v.Values["faulty"])
	}
	if v.Values["adminOff"] != 1 {
		t.Errorf("adminOff = %v，要 1（只有 3 号口是使能关着的）", v.Values["adminOff"])
	}
	if !strings.Contains(v.Note, "空口") {
		t.Errorf("note = %q：有 searching 就得提醒「这里面大半是没插东西」", v.Note)
	}
	if !strings.Contains(v.Note, "370") || !strings.Contains(v.Note, "180") {
		t.Errorf("note = %q：整台的电源池要一并报出来", v.Note)
	}
	// ★ 计数器是攒出来的，不带上开机多久就不知道那个数攒了多久。
	if _, ok := v.Values["countersSince"]; !ok {
		t.Error("没写「计数器是从开机攒到现在的」")
	}
	if _, ok := v.Values["uptime"]; !ok {
		t.Error("没读到开机时长 —— 那一句增量口径就成了空话")
	}
}

// TestSnmpPoePoolLevels 电源池那一档的三种事：关着、自己报故障、余量紧。
//
// ★ 它们必须压过一切单口结论：池子塌了的时候逐个看口是白跑一趟。
func TestSnmpPoePoolLevels(t *testing.T) {
	cases := []struct {
		name    string
		set     func(*snmptest.Device)
		want    string
		wantStr string
	}{
		{"总开关关着", func(d *snmptest.Device) {
			d.Set(oidPethMainOperStatus+".1", snmptest.Int(2))
		}, snmpPoeOff, "逐个看口是白跑"},
		{"电源池自己报故障", func(d *snmptest.Device) {
			d.Set(oidPethMainOperStatus+".1", snmptest.Int(3))
		}, snmpPoePseFault, "电源模块"},
		{"余量过了告警线", func(d *snmptest.Device) {
			d.Set(oidPethMainConsumption+".1", snmptest.Gauge(340)) // 340/370 = 92% > 90%
		}, snmpPoeBudget, "告警阈值"},
		{"实测比额定还大", func(d *snmptest.Device) {
			d.Set(oidPethMainConsumption+".1", snmptest.Gauge(900))
		}, snmpPoeBudget, "口径不对"},
	}
	for _, c := range cases {
		d := poeDevice(t)
		c.set(d)
		v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
		if v.Code != c.want {
			t.Errorf("%s：判定 = %s，要 %s：%s", c.name, v.Code, c.want, v.Note)
			continue
		}
		if !strings.Contains(v.Note, c.wantStr) {
			t.Errorf("%s：note = %q，少了「%s」", c.name, v.Note, c.wantStr)
		}
	}
}

// TestSnmpPoePoolOffBeatsPortVerdict ★ 池子关着时，点名一个「被人为关掉」的口，
// 报出来的也必须是池子那一条 —— 不然人会去问是谁关了这个口，而真正该问的是整台。
func TestSnmpPoePoolOffBeatsPortVerdict(t *testing.T) {
	d := poeDevice(t)
	d.Set(oidPethMainOperStatus+".1", snmptest.Int(2))
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 3})
	if v.Code != snmpPoeOff {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeOff, v.Note)
	}
}

// TestSnmpPoePoolNotReadIsNotOK 电源池那一整档读不到时，判定不能是绿的「一切正常」：
// 「问不出来」和「余量充足」在现场是两个结论。
func TestSnmpPoePoolNotReadIsNotOK(t *testing.T) {
	d := poeDevice(t)
	for _, col := range []string{oidPethMainPower, oidPethMainOperStatus,
		oidPethMainConsumption, oidPethMainThreshold} {
		d.Del(col + ".1")
	}
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	if !strings.Contains(v.Note, "没有回答") {
		t.Errorf("note = %q：池子没读到必须说「没回答」，不能不吭声", v.Note)
	}
	if len(pseRowsOf(t, v)) != 0 {
		t.Errorf("pse = %v：一栏都没读到还挤出行了", v.Values["pse"])
	}
}

// TestSnmpPoeBudgetUnknownIsNotEnough 额定读回来是 0：余量算不出来，
// 这一条不能算「紧」（那是凭空定罪），也不能算「够」（那是替设备撒谎）。
func TestSnmpPoeBudgetUnknownIsNotEnough(t *testing.T) {
	d := poeDevice(t)
	d.Set(oidPethMainPower+".1", snmptest.Gauge(0))
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	e := pseRowsOf(t, v)[0]
	if e["budget"] != "unknown" {
		t.Errorf("budget = %v，要 unknown：%v", e["budget"], e)
	}
	if _, ok := e["usedPct"]; ok {
		t.Errorf("算不出来还给百分比：%v", e)
	}
	if !strings.Contains(fmt.Sprint(e["budgetWhy"]), "不能读成") {
		t.Errorf("budgetWhy = %v：要写明这一条读不成「余量够」", e["budgetWhy"])
	}
	if v.Code != snmpOk {
		t.Errorf("判定 = %s，算不出余量不该报紧：%s", v.Code, v.Note)
	}
}

// TestSnmpPoeDisabledByAdmin ★★ 使能被人关掉 ≠ 故障。
// 报成「没供上电、去查线」的话，人会跑去查一根本来就好着的线。
func TestSnmpPoeDisabledByAdmin(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 3})
	if v.Code != snmpPoeDisabled {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeDisabled, v.Note)
	}
	for _, want := range []string{"不是故障", "查线", "只读"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
	e := poeRowBy(t, v, 3)
	if e["admin"] != "disabled" {
		t.Errorf("admin = %v，要 disabled", e["admin"])
	}
	if !strings.Contains(fmt.Sprint(e["adminWhy"]), "开回来") {
		t.Errorf("adminWhy = %v：要说清怎么恢复", e["adminWhy"])
	}
}

// TestSnmpPoeAdminStatusDisagree 使能写着 false、状态却写着「正在供电」：
// 这两栏对不上时必须说出来，不能挑一栏当准。
func TestSnmpPoeAdminStatusDisagree(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 9})
	if v.Code != snmpPoeDisabled {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeDisabled, v.Note)
	}
	if !strings.Contains(v.Note, "对不上") {
		t.Errorf("note = %q：两栏矛盾要写明，并且说清以哪一栏为准", v.Note)
	}
}

// TestSnmpPoeDeviceExcluded 使能开着、detectionStatus 却是 disabled：
// 这种不是有人关的，去问「是谁关的」是白跑。
func TestSnmpPoeDeviceExcluded(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 10})
	if v.Code != snmpPoeDisabled {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeDisabled, v.Note)
	}
	if !strings.Contains(v.Note, "使能是开着的") {
		t.Errorf("note = %q：要分清「人关的」和「设备自己排除的」", v.Note)
	}
}

// TestSnmpPoeSearchingTriage 在检测、没供上：三种可能分不开，
// 而分开它们的办法是看计数器涨不涨，不是把同一句状态再问一次。
func TestSnmpPoeSearchingTriage(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 2})
	if v.Code != snmpPoeSearching {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeSearching, v.Note)
	}
	for _, want := range []string{"invalidSignature", "powerDenied", "watchSeconds"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」—— 分不开那三种的话这一条就没用", v.Note, want)
		}
	}
	e := poeRowBy(t, v, 2)
	if e["invalidSignature"] != uint64(4) {
		t.Errorf("invalidSignature = %v，要 4", e["invalidSignature"])
	}
	// ★ 这一行不在供电，等级就不该报出来。
	if _, ok := e["class"]; ok {
		t.Errorf("没在供电还给等级：%v", e)
	}
	if !strings.Contains(fmt.Sprint(e["classSkipped"]), "供电中") {
		t.Errorf("classSkipped = %v：要说明为什么不给等级", e["classSkipped"])
	}
}

// TestSnmpPoeFaultKinds fault / otherFault 两种都不是一句「坏了」能打发的。
func TestSnmpPoeFaultKinds(t *testing.T) {
	cases := []struct {
		port    int
		status  int
		wantStr string
	}{
		{7, 4, "换到别的口"},            // fault(4)：先分是口还是 PD
		{6, 6, "error_conditions"}, // otherFault(6)：别当成有人关掉了
	}
	for _, c := range cases {
		d := poeDevice(t)
		d.Set(oidPethDetectStatus+".1."+fmt.Sprint(c.port), snmptest.Int(int64(c.status)))
		v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"groupIndex": 1, "portIndex": c.port})
		if v.Code != snmpPoeFault {
			t.Errorf("%d 号口：判定 = %s，要 %s：%s", c.port, v.Code, snmpPoeFault, v.Note)
			continue
		}
		if !strings.Contains(v.Note, c.wantStr) {
			t.Errorf("%d 号口：note = %q，少了「%s」", c.port, v.Note, c.wantStr)
		}
	}
}

// TestSnmpPoeTableFaultIsRed ★ 列表那一条什么时候可以给坏颜色：
//
//	「没在供电」不给（空口本来就该那样），但「报错」给 —— fault 不是任何一个口的
//	正常样子，列表里有一个就说明这一趟值得跑一趟机房。
func TestSnmpPoeTableFaultIsRed(t *testing.T) {
	d := poeDevice(t)
	d.Set(oidPethDetectStatus+".1.7", snmptest.Int(4))
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpPoeFault {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeFault, v.Note)
	}
	if !strings.Contains(v.Note, "1组7口") {
		t.Errorf("note = %q：要报出是哪一个口（组号 + 口号），不然不知道去哪儿", v.Note)
	}
	if v.Values["faultPorts"] == nil {
		t.Error("faultPorts 没写：界面上那一栏要点名")
	}
}

// TestSnmpPoeDeliveringIsNotWorking 「在供电」不等于「它在工作」：
// 这一句不写，人会拿着一个绿灯去机房。
func TestSnmpPoeDeliveringIsNotWorking(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 1})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	if !strings.Contains(v.Note, "不等于") {
		t.Errorf("note = %q：要提醒「供着电」不代表那台设备在工作", v.Note)
	}
	e := poeRowBy(t, v, 1)
	if e["class"] != "class2" {
		t.Errorf("class = %v，要 class2（枚举 3 = class2）", e["class"])
	}
	// ★ 等级不是瓦数，这一句得跟着等级一起出现。
	if !strings.Contains(fmt.Sprint(e["classNote"]), "瓦数") {
		t.Errorf("classNote = %v", e["classNote"])
	}
	if e["status"] != "deliveringPower" || e["admin"] != "enabled" {
		t.Errorf("行不对：%v", e)
	}
}

// TestSnmpPoeClassBeyondRFC 五档以外的等级：只报编号，不换算成瓦。
func TestSnmpPoeClassBeyondRFC(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 8})
	e := poeRowBy(t, v, 8)
	if _, ok := e["class"]; ok {
		t.Errorf("认不出的等级还翻成名字：%v", e)
	}
	if e["classUnknown"] != 7 {
		t.Errorf("classUnknown = %v，要原样报编号 7", e["classUnknown"])
	}
	if !strings.Contains(fmt.Sprint(e["classNote"]), "不换算成瓦") {
		t.Errorf("classNote = %v", e["classNote"])
	}
}

// TestSnmpPoeDirectGetHasNoCountTotal ★ 按 {组,口} 直取时没走表，
// 「一共有几个 PoE 口」是不知道的 —— 不写这一栏，而不是写一个 0。
func TestSnmpPoeDirectGetHasNoCountTotal(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 1})
	if _, ok := v.Values["countTotal"]; ok {
		t.Errorf("直取一条却给了 countTotal = %v", v.Values["countTotal"])
	}
	if !strings.Contains(v.Note, "1 组") {
		t.Errorf("note = %q：这一行自己的组号口号要写出来，别人才核对得上", v.Note)
	}
}

// TestSnmpPoeNotFoundDirect ★ 直取那一条没走表，收口那句不能说「PoE 表读全了」。
func TestSnmpPoeNotFoundDirect(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 99})
	if v.Code != snmpPoeNotFound {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeNotFound, v.Note)
	}
	if strings.Contains(v.Note, "读全了") {
		t.Errorf("note = %q：这一条压根没走表，不能说表读全了", v.Note)
	}
	if !strings.Contains(v.Note, "没有回答") {
		t.Errorf("note = %q：要说明「一共有几个口」这一条没回答", v.Note)
	}
}

// TestSnmpPoeStatusMissingOnDirect 走表认不出、直取读得回的一个口：
// detectionStatus 没给读时，这一条不能说它在供还是没在供。
func TestSnmpPoeStatusMissingOnDirect(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 11})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	e := poeRowBy(t, v, 11)
	if !strings.Contains(fmt.Sprint(e["statusMissing"]), "不能说") {
		t.Errorf("statusMissing = %v：「没读到」和「读到了 disabled」要分得开", e["statusMissing"])
	}
	if _, ok := e["status"]; ok {
		t.Errorf("没读到还编出一个状态：%v", e)
	}
	if !strings.Contains(v.Note, "没给") {
		t.Errorf("note = %q：这一条的口径要写进复制得走的那一句", v.Note)
	}
}

// TestSnmpPoePortIndexAcrossGroups ★ 只填口号时，每一组里同号的行都要列出来：
// 堆叠设备上挑一个 = 挑错机箱。
func TestSnmpPoePortIndexAcrossGroups(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, poeStackedEntries())
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "portIndex": 5})
	rows := poeRowsOf(t, v)
	if len(rows) != 2 {
		t.Fatalf("读到 %d 行，要 2 行（1 组和 2 组各一个 5 号口）", len(rows))
	}
	if rows[0]["group"] != 1 || rows[1]["group"] != 2 {
		t.Errorf("组号不对：%v / %v", rows[0]["group"], rows[1]["group"])
	}
	if !strings.Contains(v.Note, "2 行") {
		t.Errorf("note = %q：点了名回来两行，这一句要顶出来", v.Note)
	}
	if len(pseRowsOf(t, v)) != 2 {
		t.Errorf("两个组的电源池都要报出来：%v", v.Values["pse"])
	}
}

// TestSnmpPoeIfIndexIsAGuess ★ RFC 3621 没有 ifIndex → PoE 口号的映射：
// 按接口号问必须写明「这是按编号相等猜的」，并把这一行自己的组号口号带上。
func TestSnmpPoeIfIndexIsAGuess(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 2})
	if v.Code != snmpPoeSearching {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeSearching, v.Note)
	}
	m := fmt.Sprint(v.Values["ifIndexMapping"])
	if !strings.Contains(m, "猜") {
		t.Errorf("ifIndexMapping = %q：这一条是猜的必须写明", m)
	}
	// ★ note 是人家唯一复制走的那一行：只在 values 里写映射方式，工单里就没有了。
	if !strings.Contains(v.Note, "猜") {
		t.Errorf("note = %q：要把「这是猜的映射」带进这一句", v.Note)
	}
	e := poeRowBy(t, v, 2)
	if e["matchedBy"] != poeMatchIndex {
		t.Errorf("matchedBy = %v，要 %s", e["matchedBy"], poeMatchIndex)
	}
}

// TestSnmpPoeIfIndexNamedByDevice 设备把口名写在 pethPsePortType 里：
// 这一条是它自己给的证据，和「编号正好相等」不是一回事。
func TestSnmpPoeIfIndexNamedByDevice(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 4})
	rows := poeRowsOf(t, v)
	if len(rows) != 1 {
		t.Fatalf("读到 %d 行，要 1 行：%v", len(rows), rows)
	}
	if rows[0]["matchedBy"] != poeMatchBoth {
		t.Errorf("matchedBy = %v：编号相等且标签写着这个口名，两条路子都对上了", rows[0]["matchedBy"])
	}
	if !strings.Contains(fmt.Sprint(v.Values["ifIndexMapping"]), "都") {
		t.Errorf("ifIndexMapping = %v", v.Values["ifIndexMapping"])
	}
}

// TestSnmpPoeIfIndexAmbiguous ★ 两条路子指着不同的行：两行都列出来、并说「有候选」。
// 挑一个的话，等于让人去查另一个口的供电。
func TestSnmpPoeIfIndexAmbiguous(t *testing.T) {
	d := poeDevice(t)
	// 让 7 号口的标签写着 5 号口的名字：按编号猜是 5，按设备给的名字对是 7。
	d.Set(oidPethPortType+".1.7", snmptest.Str("GigabitEthernet1/0/5"))
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 5})
	if v.Values["ifIndexAmbiguous"] != true {
		t.Errorf("ifIndexAmbiguous = %v：两条路子指着不同行要标出来", v.Values["ifIndexAmbiguous"])
	}
	rows := poeRowsOf(t, v)
	if len(rows) != 2 {
		t.Fatalf("读到 %d 行，要 2 行：%v", len(rows), rows)
	}
	if !strings.Contains(v.Note, "两个候选") {
		t.Errorf("note = %q：这一句要说清有歧义，不能让人以为问的是一个口", v.Note)
	}
}

// TestSnmpPoeIfIndexUnmapped 两条路子都没对上 → 没找到，并且说明是怎么找的。
func TestSnmpPoeIfIndexUnmapped(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "ifIndex": 77})
	if v.Code != snmpPoeNotFound {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeNotFound, v.Note)
	}
	if !strings.Contains(v.Note, "没对上") {
		t.Errorf("note = %q", v.Note)
	}
}

// TestSnmpPoeByLabel 按运维手写的标签找（那一栏本来就不是口名）。
func TestSnmpPoeByLabel(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "name": "ap-3f"})
	rows := poeRowsOf(t, v)
	if len(rows) != 1 || rows[0]["port"] != 1 {
		t.Fatalf("按标签没找着那台 AP：%v", rows)
	}
	if _, ok := v.Values["labelEmpty"]; ok {
		t.Error("标签明明写了，不该报「这一栏是空的」")
	}
}

// TestSnmpPoeLabelEmpty ★ 按标签没找着、而这台一个标签都没写：
// 这一条必须说出来，不然「没找着」看着像「这台没这种东西」。
func TestSnmpPoeLabelEmpty(t *testing.T) {
	d := poeDevice(t)
	for p := 1; p <= 11; p++ {
		d.Del(oidPethPortType + ".1." + fmt.Sprint(p))
	}
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "name": "NVR-3"})
	if v.Code != snmpPoeNotFound {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeNotFound, v.Note)
	}
	if _, ok := v.Values["labelEmpty"]; !ok {
		t.Errorf("values = %v：那一栏整列都是空的，这一条要单独说", v.Values)
	}
}

// TestSnmpPoeTruncated ★ 撞限量：不能给「其余口都还好」这种结论。
func TestSnmpPoeTruncated(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "limit": 3})
	if v.Code != snmpNotWalked {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNotWalked, v.Note)
	}
	if v.Values["truncated"] != true {
		t.Errorf("truncated = %v", v.Values["truncated"])
	}
	if got := len(poeRowsOf(t, v)); got != 3 {
		t.Errorf("读到 %d 行，限量 3 就该是 3 行", got)
	}
}

// TestSnmpPoeNotFoundWalked 表走全了没这一行 —— 这一句才敢说「没有」。
func TestSnmpPoeNotFoundWalked(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "portIndex": 99})
	if v.Code != snmpPoeNotFound {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpPoeNotFound, v.Note)
	}
	if !strings.Contains(v.Note, "读全了") {
		t.Errorf("note = %q：走全了才敢说没这一行", v.Note)
	}
	if !strings.Contains(v.Note, "面板") {
		t.Errorf("note = %q：要提醒口号和面板上的第几口不一定相等", v.Note)
	}
}

// TestSnmpPoeNoDataTwoKinds ★ 「这棵子树不给读」和「一个口都没供电」是两件相反的事：
// 前者的下一步是换团体名，后者是去查这台设备的供电配置。
func TestSnmpPoeNoDataTwoKinds(t *testing.T) {
	t.Run("整棵子树是空的", func(t *testing.T) {
		d := portsDevice(t) // 一台不做 PoE 的设备
		v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
		if v.Code != snmpNoData {
			t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNoData, v.Note)
		}
		if !strings.Contains(v.Note, "不是「设备不通」") {
			t.Errorf("note = %q：这一条要说清设备是活的", v.Note)
		}
		if !strings.Contains(v.Note, "不是供电端") || !strings.Contains(v.Note, "视图") {
			t.Errorf("note = %q：整棵子树空着有两种可能，都得摆出来", v.Note)
		}
	})
	t.Run("只少了检测状态那一栏", func(t *testing.T) {
		d := poeDevice(t)
		for p := 1; p <= 11; p++ {
			d.Del(oidPethDetectStatus + ".1." + fmt.Sprint(p))
		}
		v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
		if v.Code != snmpNoData {
			t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNoData, v.Note)
		}
		if !strings.Contains(v.Note, "它给了这些栏") {
			t.Errorf("note = %q：设备给了别的栏，就要把栏名列出来", v.Note)
		}
		if !strings.Contains(v.Note, "pethPsePortAdminEnable") {
			t.Errorf("note = %q：要写明它给了哪几栏：%s", v.Note, "")
		}
	})
}

// TestSnmpPoeSampleDeltas 读两遍要给出「这一段涨了几次」。
//
// ★ 推计数器那一下必须落在两次读中间：goroutine 立刻推的话往往赶在第一遍之前，
//
//	两遍读到同一个值，这一条就成了永远绿的假测试。
func TestSnmpPoeSampleDeltas(t *testing.T) {
	d := poeDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set(oidPethDenied+".1.5", snmptest.Count(9)) // 7 → 9
		d.Set(oidPethMPSAbsent+".1.4", snmptest.Count(3))
	})
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 5, "watchSeconds": 1})
	e := poeRowBy(t, v, 5)
	if e["powerDeniedDelta"] != uint64(2) {
		t.Errorf("powerDeniedDelta = %v，要 2（7 → 9）", e["powerDeniedDelta"])
	}
	if e["powerDenied"] != uint64(9) {
		t.Errorf("累计值要换成第二遍读到的：%v", e["powerDenied"])
	}
	if _, ok := v.Values["sampleSeconds"]; !ok {
		t.Error("读了两遍却没记间隔")
	}
	if !strings.Contains(v.Note, "涨了 2 次") {
		t.Errorf("note = %q：「这一段又被拒绝了两次」要写进复制得走的那一句", v.Note)
	}
}

// TestSnmpPoeDeniedDeltaInSearching 5 号口在检测、而且这一段又被拒了两次：
// 「在检测」这一条要带上增量的那句话，才能把「压根没插东西」和「插了、要不到电」分开。
func TestSnmpPoeDeniedDeltaInSearching(t *testing.T) {
	d := poeDevice(t)
	d.Set(oidPethMainConsumption+".1", snmptest.Gauge(345)) // 池子已经紧了
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set(oidPethDenied+".1.5", snmptest.Count(8))
	})
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 5, "watchSeconds": 1})
	if v.Code != snmpPoeSearching {
		t.Fatalf("判定 = %s，要 %s（在检测这一条更具体）：%s", v.Code, snmpPoeSearching, v.Note)
	}
	for _, want := range []string{"第 1 组", "涨了"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
}

// TestSnmpPoeRebootBetweenSamples ★ 两次读之间设备重启过：计数器全被清零，
// 相减得到的是一个看着合理的假数 —— 这一趟不给增量。
func TestSnmpPoeRebootBetweenSamples(t *testing.T) {
	d := poeDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set("1.3.6.1.2.1.1.3.0", snmptest.Ticks(5000)) // sysUpTime 倒退 = 刚重启
		d.Set(oidPethDenied+".1.5", snmptest.Count(1))
	})
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 5, "watchSeconds": 1})
	if v.Values["rebooted"] != true {
		t.Errorf("rebooted = %v：sysUpTime 倒退了要如实标出来", v.Values["rebooted"])
	}
	if !strings.Contains(fmt.Sprint(v.Values["sampleUnsure"]), "重启") {
		t.Errorf("sampleUnsure = %v", v.Values["sampleUnsure"])
	}
	e := poeRowBy(t, v, 5)
	if _, ok := e["powerDeniedDelta"]; ok {
		t.Errorf("重启过还给增量：%v", e)
	}
	if !strings.Contains(v.Note, "重启") {
		t.Errorf("note = %q：「这一趟没测到增量」要写进这一句", v.Note)
	}
}

// TestSnmpPoeNoCounters 只问状态时，计数器那几栏整个不出现 —— 不写成 0。
func TestSnmpPoeNoCounters(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 5, "noCounters": true})
	e := poeRowBy(t, v, 5)
	for _, k := range []string{"powerDenied", "mpsAbsent", "invalidSignature", "overLoad", "shortCircuit"} {
		if _, ok := e[k]; ok {
			t.Errorf("选了 noCounters 还带 %s：%v", k, e)
		}
	}
}

// TestSnmpPoeStateFilter 筛状态是在读回来之后筛：「一共几个口」记筛之前。
func TestSnmpPoeStateFilter(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "state": "on"})
	rows := poeRowsOf(t, v)
	if len(rows) != 6 {
		t.Fatalf("在供电的要 6 行，读到 %d", len(rows))
	}
	if v.Values["read"] != 10 || v.Values["count"] != 6 {
		t.Errorf("read/count = %v/%v，要 10/6（筛掉之前有几个）", v.Values["read"], v.Values["count"])
	}
	if !strings.Contains(v.Note, "10") {
		t.Errorf("note = %q：列表那一条要带上「筛之前读了几个」", v.Note)
	}
}

// TestSnmpPoeFilterNamedAway 点名 + 筛状态把那一行筛掉了：这本身就是答案，
// 不能说成「没这个口」。
func TestSnmpPoeFilterNamedAway(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 1, "state": "off"})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	if !strings.Contains(v.Note, "被筛掉") {
		t.Errorf("note = %q", v.Note)
	}
}

// TestSnmpPoeStackedPoolPerGroup 堆叠设备：每一组的池子都要单独报，
// 「整台多少瓦」在这种设备上是问不出来的。
func TestSnmpPoeStackedPoolPerGroup(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, poeStackedEntries())
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "第 1 组") || !strings.Contains(v.Note, "第 2 组") {
		t.Errorf("note = %q：两组的池子要分开报", v.Note)
	}
}

// TestSnmpPoeBadArgs 参数写错要直接报错，不能变成一个看着像结论的判定。
func TestSnmpPoeBadArgs(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"看不懂的状态", map[string]any{"addr": "192.0.2.9", "community": probeCommunity,
			"state": "powering"}, "state"},
		{"负数索引", map[string]any{"addr": "192.0.2.9", "community": probeCommunity,
			"portIndex": -3}, "负数"},
		{"ifIndex 超范围", map[string]any{"addr": "192.0.2.9", "community": probeCommunity,
			"ifIndex": 70000}, "ifIndex"},
		{"watchSeconds 太长", map[string]any{"addr": "192.0.2.9", "community": probeCommunity,
			"watchSeconds": 9999}, "watchSeconds"},
		{"没给团体名", map[string]any{"addr": "192.0.2.9"}, "community"},
		{"域名", map[string]any{"addr": "sw.example.com", "community": probeCommunity}, "不是 IP"},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(c.args)
		_, err := snmpPoeTool.Invoke(context.Background(), raw)
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

// TestSnmpPoeNoReply 团体名不对 = 设备压根不答，这一条不能变成「这台没有 PoE」。
func TestSnmpPoeNoReply(t *testing.T) {
	d := poeDevice(t)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": "wrong-one"})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNoReply, v.Note)
	}
	if v.Values["answered"] != false {
		t.Errorf("answered = %v：一条包都没回来", v.Values["answered"])
	}
}

// TestSnmpPoeV1Device v1 设备：没有 GETBULK（走表退成 GETNEXT），
// 批量 GET 里少一栏会让整包作废（退成一栏一栏问）。
func TestSnmpPoeV1Device(t *testing.T) {
	d := poeDevice(t)
	d.SetV1Only(true)
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity, "version": "v1"})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	if got := len(poeRowsOf(t, v)); got != 10 {
		t.Errorf("v1 设备读到 %d 行，要 10 行", got)
	}
	if v.Values["version"] != "v1" {
		t.Errorf("version = %v", v.Values["version"])
	}
}

// TestSnmpPoeNoSysUpTime 问不到 sysUpTime 就**不知道**这台中途重启过没有：
// 这一条不给增量，而不是假装没重启。
func TestSnmpPoeNoSysUpTime(t *testing.T) {
	d := poeDevice(t)
	d.Del("1.3.6.1.2.1.1.3.0")
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set(oidPethDenied+".1.5", snmptest.Count(12))
	})
	v := snmpPoeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity,
		"groupIndex": 1, "portIndex": 5, "watchSeconds": 1})
	if !strings.Contains(fmt.Sprint(v.Values["sampleUnsure"]), "sysUpTime") {
		t.Errorf("sampleUnsure = %v：问不到开机时长要说明增量不可信", v.Values["sampleUnsure"])
	}
	e := poeRowBy(t, v, 5)
	if _, ok := e["powerDeniedDelta"]; ok {
		t.Errorf("没比过 sysUpTime 还给增量：%v", e)
	}
	if !strings.Contains(fmt.Sprint(e["countersUnreliable"]), "sysUpTime") {
		t.Errorf("countersUnreliable = %v：行上也要写明为什么不给增量", e["countersUnreliable"])
	}
	if _, ok := v.Values["countersSince"]; ok {
		t.Error("没读到开机时长，不该给「攒了多久」那一句")
	}
}
