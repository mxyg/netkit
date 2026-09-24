package tools

// net.snmp.mac 的测试全部指向 snmptest 那台假交换机，用的是 probe 那台**同一份**表
// （bridgeEntries）—— 两边各搭一套的话，「索引怎么切」「端口怎么映射」
// 这两处最容易错的地方正好各错各的、合起来还绿。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
)

func snmpMacRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snmpMacTool.Invoke(context.Background(), raw)
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

// entriesOf 取结果里的表行。★ 断言前先确认形状，别用类型断言把 panic 当测试失败。
func entriesOf(t *testing.T, v ots.Verdict) []map[string]any {
	t.Helper()
	es, ok := v.Values["entries"].([]map[string]any)
	if !ok {
		t.Fatalf("entries 不是行数组，是 %T", v.Values["entries"])
	}
	return es
}

// TestSnmpMacTable 钉住整张表读回来该有的样子。
//
// ★ 这里最要紧的三件事：VLAN 1000 那一条（索引两节）不能丢、
//
//	端口号必须按 dot1dBasePortIfIndex 映射（1 → ifIndex 5）、
//	设备没给状态的那一行要留着而不是被丢掉。
func TestSnmpMacTable(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	es := entriesOf(t, v)
	if len(es) != 6 {
		t.Fatalf("读到 %d 条，要 6 条：%v", len(es), es)
	}
	if got := fmt.Sprint(v.Values["fdbTable"]); got != "qbridge" {
		t.Errorf("fdbTable = %s，两张表都有时要用带 VLAN 的那张", got)
	}
	// 顺序按 VLAN、MAC 固定：VLAN 100 那五条在前，VLAN 1000 那一条在最后
	if got := es[0]["mac"]; got != "11:22:33:44:55:66" {
		t.Errorf("第一条 = %v，要 VLAN 100 里 MAC 最小的那条", got)
	}
	if got := es[5]["mac"]; got != "00:11:22:33:44:55" {
		t.Errorf("最后一条 = %v，要 VLAN 1000 那条（VLAN 大，排在后面）", got)
	}
	if got := es[5]["vlan"]; got != 1000 {
		t.Errorf("最后一条 vlan = %v，要 1000 —— ★ 索引里 VLAN 占两节（3.232，0x03E8）,"+
			"只按一节解析的话这一整段会被安静丢掉", got)
	}
	for _, e := range es {
		if e["mac"] == "aa:bb:cc:dd:ee:ff" {
			if e["port"] != "GE1/0/1" {
				t.Errorf("端口名 = %v，要 GE1/0/1（桥端口 1 经 dot1dBasePortIfIndex 映射到 ifIndex 5）", e["port"])
			}
			if e["ifIndex"] != 5 {
				t.Errorf("ifIndex = %v，要 5", e["ifIndex"])
			}
			if e["status"] != "dynamic" {
				t.Errorf("status = %v，要 dynamic（3=learned）", e["status"])
			}
		}
		if e["mac"] == "99:88:77:66:55:44" && e["status"] != "static" {
			t.Errorf("手工配死的那条 status = %v，要 static（5=mgmt）—— "+
				"「学来的」和「配死的」在两处故障现场是两个结论", e["status"])
		}
	}
	// 设备没给状态的那一行：留着，只是不带 status
	seen := map[string]bool{}
	for _, e := range es {
		seen[fmt.Sprint(e["mac"])] = true
	}
	if !seen["11:22:33:44:55:66"] {
		t.Error("少了一行：设备没给状态的行不许丢，那只是这一栏没填")
	}
}

// TestSnmpMacReverse 反查：填一个 MAC，只回它那一行。
//
// ★ 输入用**交换机 CLI 的点分写法**（aabb.ccdd.eeff）：现场就是从设备屏幕上
//
//	抄这么一串过来，认不出这种写法等于这个功能在现场用不了。
func TestSnmpMacReverse(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "mac": "AA-BB-CC-DD-EE-01",
	})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	es := entriesOf(t, v)
	if len(es) != 1 {
		t.Fatalf("反查回来 %d 行，要 1 行：%v", len(es), es)
	}
	if es[0]["port"] != "GE1/0/2" {
		t.Errorf("所在口 = %v，要 GE1/0/2", es[0]["port"])
	}
	if !strings.Contains(v.Note, "GE1/0/2") || !strings.Contains(v.Note, "VLAN 100") {
		t.Errorf("note = %q，要把口和 VLAN 一起说 —— 只说口等于让人再问一遍 VLAN", v.Note)
	}
	if got := v.Values["queriedMac"]; got != "aa:bb:cc:dd:ee:01" {
		t.Errorf("queriedMac = %v，结果里要把规范化后的写法记下来", got)
	}
}

// TestSnmpMacNotFoundWholeTable 表读全了、里面没有这个 MAC。
// ★ 这一条必须同时说清「FDB 只记发过帧的源地址」，否则人会把「没有」当成「不在」。
func TestSnmpMacNotFoundWholeTable(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "mac": "de:ad:be:ef:00:01",
	})
	if v.Code != snmpMacNotFound {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpMacNotFound, v.Note)
	}
	if es := entriesOf(t, v); len(es) != 0 {
		t.Errorf("反查没查到还给了 %d 行", len(es))
	}
	for _, want := range []string{"发过帧", "net.neighbors"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」—— 这一条的下一步就是这个", v.Note, want)
		}
	}
}

// TestSnmpMacTruncatedIsNotConclusion ★★ 这批里最重要的一条。
//
// limit 只够读第一条时，「里面没有这个 MAC」这句不许说出口 ——
// 说出口就是让人去查一条本来好好的链路。判成 snmp-not-walked，并给下一步。
func TestSnmpMacTruncatedIsNotConclusion(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity,
		"mac": "aa:bb:cc:dd:ee:ff", "limit": 1,
	})
	if v.Code != snmpNotWalked {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpNotWalked, v.Note)
	}
	if v.Values["truncated"] != true {
		t.Errorf("truncated = %v，读满了 limit 要如实标出来", v.Values["truncated"])
	}
	if !strings.Contains(v.Note, "不是") || !strings.Contains(v.Note, "limit") {
		t.Errorf("note = %q，要说清「没查到」和「没有」不是一回事，并给出下一步", v.Note)
	}
}

// TestSnmpMacReverseReadsWholeTable 不填 limit 的反查要把整张表读完。
// 表有 6 条，反查那条（99:88:77:66:55:44）排在中间偏前 ——
// 按默认的「看一眼」限量读就会判成没有。
func TestSnmpMacReverseReadsWholeTable(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "mac": "99:88:77:66:55:44",
	})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpOk, v.Note)
	}
	if got := v.Values["read"]; got != 6 {
		t.Errorf("read = %v，要 6 —— 反查要读全，不能被默认的 limit 截住", got)
	}
}

// TestSnmpMacVlanFilter 只看一个 VLAN：★ 是在结果里筛，读的量不变，
// 所以结果里要看得见筛过（vlanFilter），不然会以为这台只学了这几条。
func TestSnmpMacVlanFilter(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "vlan": 1000,
	})
	es := entriesOf(t, v)
	if len(es) != 1 || es[0]["mac"] != "00:11:22:33:44:55" {
		t.Fatalf("VLAN 1000 筛出来是 %v", es)
	}
	if v.Values["vlanFilter"] != 1000 {
		t.Errorf("结果里没记「按 VLAN 筛过」：%v", v.Values)
	}
	if got := v.Values["read"]; got != 6 {
		t.Errorf("read = %v，要 6：筛选不减读量", got)
	}
}

// TestSnmpMacBridgeFallback 只有 BRIDGE-MIB 的设备：表名要写 bridge，而且**不给 vlan**。
// ★ 那张表本来就不带 VLAN，硬给一个 0 会被界面渲染成「VLAN 0」。
func TestSnmpMacBridgeFallback(t *testing.T) {
	e := sysEntries()
	e["1.3.6.1.2.1.17.4.3.1.2."+macIdx("aabbccddeeff")] = snmptest.Int(1)
	e["1.3.6.1.2.1.17.4.3.1.3."+macIdx("aabbccddeeff")] = snmptest.Int(3)
	e["1.3.6.1.2.1.17.1.4.1.2.1"] = snmptest.Int(5)
	e["1.3.6.1.2.1.2.2.1.2.5"] = snmptest.Str("GigabitEthernet0/1")
	d := snmptest.Start(t, probeCommunity, e)
	v := snmpMacRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	if got := fmt.Sprint(v.Values["fdbTable"]); got != "bridge" {
		t.Errorf("fdbTable = %s，要 bridge（Q-BRIDGE 那棵它没有，退到老的）", got)
	}
	es := entriesOf(t, v)
	if len(es) != 1 {
		t.Fatalf("读到 %d 条：%v", len(es), es)
	}
	if _, ok := es[0]["vlan"]; ok {
		t.Errorf("BRIDGE-MIB 那张表不该有 vlan：%v —— 给 0 会被当成「VLAN 0」", es[0])
	}
	if es[0]["port"] != "GigabitEthernet0/1" {
		t.Errorf("端口名 = %v（ifName 没有时要用 ifDescr 兜住）", es[0]["port"])
	}
}

// TestSnmpMacForcedTable 点名只读 BRIDGE-MIB：Q-BRIDGE 那张一条都不许问。
func TestSnmpMacForcedTable(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "table": "bridge",
	})
	if got := fmt.Sprint(v.Values["fdbTable"]); got != "bridge" {
		t.Fatalf("fdbTable = %s，点名了还换表：%s", got, v.Note)
	}
	es := entriesOf(t, v)
	if len(es) != 1 {
		t.Fatalf("bridge 那张只有一条，读到 %d 条：%v", len(es), es)
	}
}

// TestSnmpMacNoPortMapping 映射表读不到时**只报桥端口号**，不许把端口号当 ifIndex 猜。
//
// ★ 两者经常恰好相等，所以猜通常能猜对 —— 而错的那一次是把 GE1/0/1 报成 GE1/0/5，
//
//	人照着这句话去机房拔线，拔的是别人的链路。
func TestSnmpMacNoPortMapping(t *testing.T) {
	e := sysEntries()
	q := "1.3.6.1.2.1.17.7.1.2.2.1"
	e[q+".2.100."+macIdx("aabbccddeeff")] = snmptest.Int(1)
	d := snmptest.Start(t, probeCommunity, e)
	v := snmpMacRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	es := entriesOf(t, v)
	if len(es) != 1 {
		t.Fatalf("读到 %d 条", len(es))
	}
	if _, ok := es[0]["port"]; ok {
		t.Errorf("映射表没读到还给出口名：%v", es[0])
	}
	if es[0]["basePort"] != 1 {
		t.Errorf("basePort = %v，端口号本身要保留", es[0]["basePort"])
	}
	if fmt.Sprint(v.Values["portNames"]) != "unavailable" {
		t.Errorf("portNames = %v，要 unavailable —— 让人知道这一栏是问不到，不是没有", v.Values["portNames"])
	}
}

// TestSnmpMacNoData 系统组答得好好的、桥接子树压根没有：判「没有数据」，不判「不通」。
func TestSnmpMacNoData(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := snmpMacRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpNoData {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpNoData, v.Note)
	}
	if v.Values["answered"] != true {
		t.Errorf("answered = %v：设备答过话，团体名是对的，这一条不能含糊", v.Values["answered"])
	}
	for _, want := range []string{"没学到", "团体名"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」这个可能", v.Note, want)
		}
	}
}

// TestSnmpMacEmptyIsNoData 空表和「没实现这棵子树」在 SNMP 里同一个样子，
// 所以两种都不许被报成「设备不通」，也不许编出一个「表存在但为空」的结论。
func TestSnmpMacNoDataNoteNamesBothTables(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := snmpMacRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpNoData {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpNoData, v.Note)
	}
	if !strings.Contains(v.Note, "qbridge") || !strings.Contains(v.Note, "bridge") {
		t.Errorf("note = %q：要说清两张表都问过了，不然人会以为只试了一张", v.Note)
	}
}

// TestSnmpMacNoReply 团体名不对：走 SNMP 共用的那一条收口，不能报成「表是空的」。
func TestSnmpMacNoReply(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": "wrong", "timeoutMs": 200, "retries": 2,
	})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpNoReply, v.Note)
	}
}

// TestSnmpMacDirectGet 知道 VLAN 时按索引直取，不把整张表走一遍。
// ★ 三万条表走全是上千个报文，现场等不了；这条钉住「能直取就别走表」。
func TestSnmpMacDirectGet(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	before := d.Reqs()
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity,
		"mac": "aa:bb:cc:dd:ee:ff", "vlan": 100,
	})
	used := d.Reqs() - before
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	if v.Values["lookedUp"] != "index" {
		t.Errorf("lookedUp = %v，要 index（按索引直取，没走全表）", v.Values["lookedUp"])
	}
	if used > 3 {
		t.Errorf("直取用了 %d 个报文，要 ≤3：多出来的是走表", used)
	}
}

// TestSnmpMacV1 v1 设备：没有 GETBULK（walk 退成 GETNEXT），
// 批量 GET 里有一栏没有会让**整包**作废（退成一栏一栏问）。
func TestSnmpMacV1(t *testing.T) {
	e := bridgeEntries()
	e["1.3.6.1.2.1.1.1.0"] = snmptest.Str("3Com Switch")
	d := snmptest.Start(t, probeCommunity, e)
	d.SetV1Only(true)
	v := snmpMacRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "version": "v1",
	})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	es := entriesOf(t, v)
	if len(es) != 6 {
		t.Fatalf("v1 读到 %d 条，要 6 条：GETNEXT 那一条路走歪了", len(es))
	}
	// 状态问不全的那一行：留着，只是不带 status（v2c 上同样有这一行）
	for _, e := range es {
		if e["mac"] == "11:22:33:44:55:66" {
			if _, ok := e["status"]; ok {
				t.Errorf("设备没给状态还配出 %v：那一栏是问不到，不是学来的", e["status"])
			}
			return
		}
	}
	t.Error("v1 走表把「没给状态」的那一行丢了")
}

// TestSnmpMacBadArgs 参数写错要**直接报错**，不能变成一个判定码。
// ★ 混起来的话，人会在设备上找「为什么提示表里没有」，而真正该改的是他填的那串字符。
func TestSnmpMacBadArgs(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, probeEntries())
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"MAC 写错", map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"mac": "gg:bb:cc:dd:ee:ff"}, "mac"},
		{"VLAN 超范围", map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"vlan": 9000}, "VLAN"},
		{"表名不认识", map[string]any{"addr": d.Addr(), "community": probeCommunity,
			"table": "cisco"}, "qbridge"},
		{"没给团体名", map[string]any{"addr": d.Addr()}, "community"},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(c.args)
		_, err := snmpMacTool.Invoke(context.Background(), raw)
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

// TestParseFdbIndex 钉住索引切法。★ VLAN 段数不固定这一条必须单测：
// 假设备只填了 100 和 1000 两种，真设备上还有 127/128/4094 这些边界，
// 边界上错一次就是「某一整个 VLAN 的地址全不见」。
func TestParseFdbIndex(t *testing.T) {
	cases := []struct {
		name     string
		idx      string // 行索引（不含列号）
		withVLAN bool
		wantMAC  string
		wantVLAN int
		ok       bool
	}{
		{"VLAN 一节", "100.1.2.3.4.5.6", true, "01:02:03:04:05:06", 100, true},
		{"VLAN 两节", "3.232.1.2.3.4.5.6", true, "01:02:03:04:05:06", 1000, true},
		{"边界 127", "127.1.2.3.4.5.6", true, "01:02:03:04:05:06", 127, true},
		{"边界 128", "0.128.1.2.3.4.5.6", true, "01:02:03:04:05:06", 128, true},
		{"边界 4094", "15.254.1.2.3.4.5.6", true, "01:02:03:04:05:06", 4094, true},
		{"BRIDGE 无 VLAN", "1.2.3.4.5.6", false, "01:02:03:04:05:06", 0, true},
		{"Q-BRIDGE 少一节", "1.2.3.4.5.6", true, "", 0, false},
		{"非标多一节", "1.2.3.4.5.6.7.8.9", true, "", 0, false},
		{"MAC 节出范围", "100.300.2.3.4.5.6", true, "", 0, false},
	}
	for _, c := range cases {
		mac, vlan, ok := parseFdbIndex(strings.Split(c.idx, "."), c.withVLAN)
		if ok != c.ok {
			t.Errorf("%s：收不收 = %v，要 %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got := formatMAC(mac, ":"); got != c.wantMAC {
			t.Errorf("%s：MAC = %s，要 %s", c.name, got, c.wantMAC)
		}
		if vlan != c.wantVLAN {
			t.Errorf("%s：VLAN = %d，要 %d", c.name, vlan, c.wantVLAN)
		}
	}
}

// TestVlanIndexMatchesParse 拼索引和拆索引必须互为逆运算。
//
// ★ 直取那一条靠 vlanIndex 拼 OID，走表那一条靠 parseFdbIndex 拆 ——
//
//	两边规则错到一处也测不出来，所以这里逐条把 1~4094 里挑出来的边界拼出来再拆回去。
func TestVlanIndexMatchesParse(t *testing.T) {
	for _, vlan := range []int{1, 99, 100, 127, 128, 255, 256, 1000, 4093, 4094} {
		idx := vlanIndex(vlan) + "." + macIndex(mustMAC("010203040506"))
		mac, got, ok := parseFdbIndex(strings.Split(idx, "."), true)
		if !ok || got != vlan || formatMAC(mac, ":") != "01:02:03:04:05:06" {
			t.Errorf("VLAN %d：拼成 %s 再拆回来是 %d/%v/%v", vlan, idx, got, mac, ok)
		}
	}
}

// TestFdbIndexRoundTrip 索引 → 行 → 再算回索引，必须一模一样。
// ★ 配状态那一栏靠的就是这个键；算歪了不报错，只是**全都配不上**，
//
//	于是界面上整张表都变成「没有状态」，看着像设备不支持这一栏。
func TestFdbIndexRoundTrip(t *testing.T) {
	for _, hex := range []string{"aabbccddeeff", "010203040506", "ffffffffffff"} {
		mac := mustMAC(hex)
		for _, vlan := range []int{1, 100, 127, 128, 255, 256, 1000, 4094} {
			oid := oidDot1qTpFdbPort + "." + vlanIndex(vlan) + "." + macIndex(mac)
			// Val 就是端口号那栏的整数值：给 0 的话 decodeFdbRows 会当无效行跳过（0 在 SMI 里保留）。
			vs := []snmp.VarBind{{OID: strings.TrimPrefix(oid, "."), Tag: snmp.TagInteger,
				Val: []byte{12}}}
			rows, skipped := decodeFdbRows(vs, fdbQBridge)
			if skipped != 0 || len(rows) != 1 {
				t.Fatalf("VLAN %d MAC %s 解出来是 %v（跳过 %d）", vlan, hex, rows, skipped)
			}
			if rows[0].vlan != vlan {
				t.Errorf("VLAN = %d，要 %d", rows[0].vlan, vlan)
			}
			// ★ 配状态那一栏的键必须把 VLAN 一起带上：一张表里不同 VLAN 可以有同一个 MAC，
			//   键不含 VLAN 就会把 VLAN 100 的状态配到 VLAN 1000 那行上。
			want := vlanIndex(vlan) + "." + macIndex(mac)
			if got := fdbIndexKey(rows[0], true); got != want {
				t.Errorf("索引键 = %q，要 %q", got, want)
			}
		}
	}
}
