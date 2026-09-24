package tools

// net.snmp.probe 的测试全部指向 snmptest 那台假交换机 —— 和底座自己的测试共用同一台。
//
// ★ 各写一台的话，「MAC 表怎么拼」「端口状态怎么判」这类最容易错的地方正好测不出来：
//   两边错到一处就绿了。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
)

const probeCommunity = "s3cret-reaonly"

// sysEntries 是一台「正常的 v2c 设备」的系统组。故意不给 sysContact、sysLocation。
func sysEntries() map[string]snmptest.Value {
	return map[string]snmptest.Value{
		"1.3.6.1.2.1.1.1.0": snmptest.Str(
			"HUAWEI Versatile Routing Platform Software\x01\nVRP (R) software, Version 8.180 (S5720-28X-LI-AC)\n"),
		"1.3.6.1.2.1.1.2.0": snmptest.Object("1.3.6.1.4.1.2636.1.1.1.2.89"),
		"1.3.6.1.2.1.1.3.0": snmptest.Ticks(900000), // 1/100 秒 → 9000 秒 = 2 小时 30 分
		"1.3.6.1.2.1.1.5.0": snmptest.Str("core-sw-01"),
		"1.3.6.1.2.1.1.7.0": snmptest.Int(72),
	}
}

func snmpProbeRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snmpProbeTool.Invoke(context.Background(), raw)
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

// TestSnmpProbeOK 钉住正常那一路：设备答了，系统信息读回来。
func TestSnmpProbeOK(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := snmpProbeRun(t, map[string]any{"addr": d.Addr(), "community": probeCommunity})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	// 设备给的控制字节不许原样贴进结果（会把界面顶成一堆乱码），但也不能整段删掉：
	// 换成一个 □，「这里真有个不可打印字节」这件事要留着。
	want := "HUAWEI Versatile Routing Platform Software□\n" +
		"VRP (R) software, Version 8.180 (S5720-28X-LI-AC)"
	if got := v.Values["sysDescr"]; got != want {
		t.Errorf("sysDescr = %q，要 %q", got, want)
	}
	if got := v.Values["vendor"]; got != "Huawei" {
		t.Errorf("vendor = %v，要 Huawei（sysObjectID 的企业号是 2636）", got)
	}
	if got := v.Values["uptime"]; got != "2 小时30 分" {
		t.Errorf("uptime = %v，要「2 小时30 分」（TimeTicks 900000 = 9000 秒）", got)
	}
	if got := v.Values["version"]; got != "v2c" {
		t.Errorf("version = %v，没填版本时结果里要写清用的是 v2c", got)
	}
	// ★ 没读到的栏记成「它没填」，不许悄悄留一个空字符串 ——
	//   空串看上去像「设备填了一个空」，那是两种不同的现场结论。
	// 顺序也要钉：漏了哪几栏是按 sysOIDs 的固定顺序记的，界面照这个顺序摆。
	if got := fmt.Sprint(v.Values["sysMissing"]); got != "[sysContact sysLocation]" {
		t.Errorf("sysMissing = %v，要两条且按问的顺序", got)
	}
	// note 只取第一行：sysDescr 是多行的，整段贴上去界面就没法看了。
	if !strings.Contains(v.Note, "HUAWEI Versatile Routing Platform Software") ||
		strings.Contains(v.Note, "VRP (R) software") {
		t.Errorf("note = %q，要只带 sysDescr 的第一行", v.Note)
	}
	if !strings.Contains(v.Note, "已开机 2 小时30 分") {
		t.Errorf("note = %q，开机时长是现场最常被问的一件事", v.Note)
	}
}

// TestSnmpProbeNoCommunity 钉住「不给团体名时直接报错」。
//
// ★ 这一条看着小，其实是这个工具的立身之本：只要这里松口给了个 "public"，
//
//	界面上「没回话」就永远分不清是团体名错还是防火墙丢包。
func TestSnmpProbeNoCommunity(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	raw, _ := json.Marshal(map[string]any{"addr": d.Addr()})
	if _, err := snmpProbeTool.Invoke(context.Background(), raw); err == nil {
		t.Fatal("没给 community 也跑通了 —— 默认值这条不能开")
	} else if !strings.Contains(err.Error(), "community") {
		t.Errorf("报错没说清是团体名缺失：%v", err)
	}
}

// TestSnmpProbeWrongCommunity 团体名不对时设备**不答**，所以判定还是「没回话」，
// 但要把三种同形的病一起摆出来 —— 其中最常见的那种恰恰是团体名。
func TestSnmpProbeWrongCommunity(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": "public", "timeoutMs": 200, "retries": 2,
	})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s，要 %s", v.Code, snmpNoReply)
	}
	for _, k := range []string{"团体名", "防火墙", "没开 SNMP"} {
		if !strings.Contains(v.Note, k) {
			t.Errorf("没回话这条漏了「%s」：%s", k, v.Note)
		}
	}
}

// TestSnmpProbeV1Only 只认 v1 的老交换机：v2c 问不通，换 v1 就答。
//
// ★ 这一条就是对照探测的全部意义 —— 不做它，这台设备和「防火墙丢包」是同一个码。
func TestSnmpProbeV1Only(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	d.SetV1Only(true)
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "timeoutMs": 200,
	})
	if v.Code != snmpV1Only {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpV1Only, v.Note)
	}
	if !strings.Contains(v.Note, "version 填成 v1") {
		t.Errorf("判定要把下一步写出来（后面几栏都得改版本）：%s", v.Note)
	}
	if got := v.Values["versionProbe"]; got != "v1" {
		t.Errorf("versionProbe = %v，结果里要留下「对照试过 v1」这件事", got)
	}
	// 换版本那次问到的系统信息要留下：这条判定的用户同样想知道这是台什么设备。
	if got := v.Values["sysName"]; got != "core-sw-01" {
		t.Errorf("sysName = %v，对照探测读到的信息不该丢", got)
	}
}

// TestSnmpProbeNoVersionProbe 关掉对照探测后只剩「三种病分不开」这一句，
// 而且不许把没做过的事写进结果。
func TestSnmpProbeNoVersionProbe(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	d.SetV1Only(true)
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "noVersionProbe": true, "timeoutMs": 200,
	})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s，要 %s", v.Code, snmpNoReply)
	}
	if _, ok := v.Values["versionProbe"]; ok {
		t.Error("没跑对照却写了 versionProbe")
	}
	if got := d.Reqs(); got != 3 {
		t.Errorf("设备收到 %d 个请求，默认重传两次应该正好问完一轮", got)
	}
}

// TestSnmpProbeBothVersionsSilent 两档都不答时，要写明「对照做过、也没答」，
// 这样看的人知道版本这一条已经排除了。
func TestSnmpProbeBothVersionsSilent(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	d.SetDropNext(99)
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "timeoutMs": 200, "retries": 2,
	})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s，要 %s", v.Code, snmpNoReply)
	}
	if v.Values["otherVersionSilent"] != true {
		t.Errorf("otherVersionSilent = %v，两档都没答这件事要写进结果", v.Values["otherVersionSilent"])
	}
}

// TestSnmpProbeV1Asked 指定 v1 时按 v1 成功就行，不许顺手改成 v2c 的答案。
func TestSnmpProbeV1Asked(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "version": "v1", "timeoutMs": 200,
	})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	if got := v.Values["version"]; got != "v1" {
		t.Errorf("version = %v，要写明这次用的是 v1", got)
	}
}

// TestSnmpProbeV1MissingColumn 一台只认 v1、并且少填了 sysContact 的设备。
//
// ★ v1 里「这一栏没有」是拿 error-status=noSuchName 把**整个报文**作废的，
//
//	不退成一栏一栏问的话这台设备会读成「什么都没答」——
//	现场表现就是「老交换机一概读不出来」。
func TestSnmpProbeV1MissingColumn(t *testing.T) {
	e := sysEntries()
	delete(e, "1.3.6.1.2.1.1.4.0")
	d := snmptest.Start(t, probeCommunity, e)
	d.SetV1Only(true)
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "version": "v1", "timeoutMs": 200,
	})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpOk, v.Note)
	}
	if got := v.Values["sysName"]; got != "core-sw-01" {
		t.Errorf("sysName = %v，少一栏不该把其余几栏一起带走", got)
	}
}

// TestSnmpProbeTrapOnly 设备答非所问：回的是它主动推的 trap。
// 这不是答案，但也**不是没人答** —— 两件事必须分开，否则人会去查防火墙。
func TestSnmpProbeTrapOnly(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	d.SetTrapOnly(true)
	v := snmpProbeRun(t, map[string]any{
		"addr": d.Addr(), "community": probeCommunity, "timeoutMs": 200, "retries": 2,
	})
	if v.Code != snmpReplyUnmatched {
		t.Fatalf("判定 = %s，要 %s（%s）", v.Code, snmpReplyUnmatched, v.Note)
	}
	if v.Values["answered"] != true {
		t.Error("有回包却写了 answered=false：这条的下一步是核团体名，不是查 ACL")
	}
	if v.Values["sawTrap"] != true {
		t.Errorf("要记下「看到的是 trap」：%v", v.Values)
	}
}

// TestSnmpProbeBadDeviceReply 设备回了 error-status（这里用团体名对不上的 v1 设备模拟）：
// 「有回话但说不行」和「没回话」是两条判定，下一步完全不同。
func TestSnmpProbeErrorStatus(t *testing.T) {
	// 假设备对正常的 v2c 请求不会回 error-status（真实的也不该回，它只是不给某一栏），
	// 所以这里直接验分类器那一层：状态码怎么翻成判定。
	values := map[string]any{"target": "192.0.2.1:161"}
	v, ok := snmpFail(&snmp.Error{Status: 2, Index: 1, OID: "1.3.6.1.2.1.1.1.0"}, values)
	if !ok || v.Code != snmpError {
		t.Fatalf("判定 = %+v，要 %s", v, snmpError)
	}
	if values["answered"] != true {
		t.Error("设备答了，answered 必须是 true —— 这条的意义就是「路是通的」")
	}
	if values["errorStatus"] != 2 {
		t.Errorf("errorStatus = %v，要把设备给的状态码原样带出来", values["errorStatus"])
	}
}

// TestSnmpProbeUnreachableIsUnknown 包根本没出去时不许报成「设备没回话」。
func TestSnmpProbeUnreachableIsUnknown(t *testing.T) {
	values := map[string]any{"target": "x"}
	v, ok := snmpFail(errors.New("snmp: 起不了本地端口：bind: nosuchiface: no such device"), values)
	if !ok {
		t.Fatal("分类器没管住这个错")
	}
	if v.Code != ots.CodeUnknown {
		t.Errorf("判定 = %s，观测没做成要报 unknown，不是「设备不通」", v.Code)
	}
	if !strings.Contains(fmt.Sprint(values["detail"]), "nosuchiface") {
		t.Errorf("detail = %v，要留下原始错文供人查", values["detail"])
	}
}

// TestSnmpProbeBadArgs 参数层面的错要报成错，不许伪装成一次观测结果。
func TestSnmpProbeBadArgs(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"没给地址", map[string]any{"community": probeCommunity}, "addr"},
		{"填了域名", map[string]any{"addr": "sw.core.example.com", "community": probeCommunity}, "net.dns.query"},
		{"版本不认识", map[string]any{"addr": "192.0.2.1", "community": probeCommunity, "version": "v9"}, "v1 或 v2c"},
		{"不支持 v3", map[string]any{"addr": "192.0.2.1", "community": probeCommunity, "version": "v3"}, "v3"},
		{"网卡不存在", map[string]any{"addr": "192.0.2.1", "community": probeCommunity, "iface": "nosuchiface"}, "nosuchiface"},
		{"端口越界", map[string]any{"addr": "192.0.2.1", "community": probeCommunity, "port": 70000}, "1-65535"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, _ := json.Marshal(c.args)
			_, err := snmpProbeTool.Invoke(context.Background(), raw)
			if err == nil {
				t.Fatalf("%v 居然跑通了", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("报错 %q 里没提 %q", err, c.want)
			}
			if strings.Contains(err.Error(), probeCommunity) {
				t.Errorf("报错里回显了团体名：%v", err)
			}
		})
	}
}

// TestSnmpProbePortDefault 端口不填按 161，而且结果里要说清楚发去了哪个端口 ——
// 只写 "192.0.2.1" 的话，人会去查一个我们根本没碰过的端口。
func TestSnmpProbePortDefault(t *testing.T) {
	v := snmpProbeRun(t, map[string]any{
		"addr": "192.0.2.1", "community": probeCommunity,
		"timeoutMs": 200, "retries": 2, "noVersionProbe": true,
	})
	if got := v.Values["port"]; got != 161 {
		t.Errorf("port = %v，要 161", got)
	}
	if got := v.Values["target"]; got != "192.0.2.1:161" {
		t.Errorf("target = %v，要写清补齐端口后的地址", got)
	}
}

// assertNoCommunity 扫一遍整个结果（判定码、所有 values、note），确认团体名没漏出去。
//
// ★ 结果会原样发给 AI，也可能被打进诊断包 —— 团体名漏一次就是长期泄漏。
func assertNoCommunity(t *testing.T, v ots.Verdict) {
	t.Helper()
	blob := fmt.Sprintf("%#v|%s|%s", v.Values, v.Code, v.Note)
	if strings.Contains(blob, probeCommunity) {
		t.Errorf("结果里漏出了团体名：%s", blob)
	}
}
