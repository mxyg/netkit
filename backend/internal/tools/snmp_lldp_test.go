package tools

// net.snmp.lldp 的测试。★ 假设备照现场那几种样子填：
//   - 「邻居表是空的」在这一棵里是五种病（没这棵树 / 只发不存 / 这个口关着 /
//     没人说话 / 表没走全），每一种都要各自钉住一条，揉成一句「没读到邻居」等于白做。
//   - lldpRemLocalPortNum 不等于 ifIndex：设备给了 dot1dBasePortIfIndex 时是硬映射，
//     没给时只能猜，而界面上这两句必须长得不一样。
//   - chassisId / portId 是 OctetString：subtype 那套枚举机箱标识和端口标识**编号不一样**，
//     拿一张表翻两栏会编出一个看着能用的 MAC。
//   - 邻居「一会儿有一会儿没有」只有老化计数器能看见，而两遍之间设备重启过、
//     计数器就被清零了 —— 那时不给增量。
//   - 一个口上两行 = 下面接了台非网管交换机，这是拓扑事实，不是脏数据。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
)

func snmpLldpRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snmpLldpTool.Invoke(context.Background(), raw)
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

// lldpFailRun 断言参数写错时**直接报错**，而不是给一个判定。
//
// ★ 「参数不对」和「设备没回话」的下一步完全相反，混在一起就没人去改参数了。
func lldpFailRun(t *testing.T, args map[string]any, want string) {
	t.Helper()
	raw, _ := json.Marshal(args)
	v, err := snmpLldpTool.Invoke(context.Background(), raw)
	if err == nil {
		t.Fatalf("参数写错却给了判定：%v %+v", v, args)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("报错 %q，要含 %q", err, want)
	}
}

func lldpNeighborsOf(t *testing.T, v ots.Verdict) []map[string]any {
	t.Helper()
	ps, ok := v.Values["neighbors"].([]map[string]any)
	if !ok {
		t.Fatalf("neighbors 不是行数组，是 %T", v.Values["neighbors"])
	}
	return ps
}

// lldpNeighborBy 按 {口号, 行号} 挑一条：一个口上可以有好几行，只按口号挑会拿错。
func lldpNeighborBy(t *testing.T, v ots.Verdict, port, index int) map[string]any {
	t.Helper()
	for _, e := range lldpNeighborsOf(t, v) {
		if e["portNum"] == port && e["remIndex"] == index {
			return e
		}
	}
	t.Fatalf("结果里没有口号 %d 行号 %d：%v", port, index, v.Values["neighbors"])
	return nil
}

func lldpLocalOf(t *testing.T, v ots.Verdict) map[string]any {
	t.Helper()
	m, ok := v.Values["local"].(map[string]any)
	if !ok {
		t.Fatalf("local 不是对象，是 %T", v.Values["local"])
	}
	return m
}

// ── 假设备的表 ──

func lldpOct(b ...byte) snmptest.Value {
	return snmptest.Value{Tag: snmp.TagOctetString, B: append([]byte(nil), b...)}
}

func lldpMAC(s string) []byte {
	b, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return b
}

// lldpCapBytes 按 capability 的位号填那两位字节图（other=0 … stationOnly=7）。
func lldpCapBytes(bits ...int) []byte {
	b := make([]byte, 2)
	for _, x := range bits {
		b[x/8] |= 1 << (7 - uint(x%8))
	}
	return b
}

func lldpV4(s string) []byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		panic("只填 IPv4：" + s)
	}
	return append([]byte(nil), ip...)
}

const (
	capBridge    = 2
	capWlanAP    = 3
	capRouter    = 4
	capTelephone = 5
	capStation   = 7
)

// lldpNeigh 是一条邻居记录（只填非零的那几栏 —— 故意留空的那几栏就是考点）。
type lldpNeigh struct {
	port, index, mark int
	chassisSub        int
	chassis           []byte
	portSub           int
	portID            []byte
	portDesc          string
	sysName           string
	sysDesc           string
	capSup, capEn     []byte
	manAddr           string // 对端留的管理地址（IPv4）
	manAddrIf         int    // 这个地址挂在它本机的哪个 ifIndex 上
}

// 这一台假设备上的口：口号 = LLDP 的 lldpRemLocalPortNum。
//
//	1 交换机（MAC 机箱标识）｜2 无线 AP（网络地址机箱标识 + 管理地址 + 老化过 4 次）
//	3 两行邻居（下面挂了台非网管交换机）｜4 只发不收、没有邻居｜5 LLDP 关着
//	6 只听不发｜7 写着只发不收、表里却有邻居（设备和标准不一致）｜8 机箱标识是认不出的编号
//	9 只给了名字、而且打了时间戳（能算出多久没刷新）｜10 有开关、没有邻居
var (
	lldpSw1 = lldpNeigh{port: 1, index: 1, chassisSub: 4, chassis: lldpMAC("aa:bb:cc:dd:ee:11"),
		portSub: 5, portID: []byte("GigabitEthernet1/0/24"), portDesc: "Uplink to core",
		sysName: "acc-sw-11", sysDesc: "H3C Comware Platform Software, Release 2211",
		capSup: lldpCapBytes(capBridge, capRouter), capEn: lldpCapBytes(capBridge),
		manAddr: "192.0.2.11", manAddrIf: 101}
	lldpAP = lldpNeigh{port: 2, index: 1, chassisSub: 5,
		chassis: append([]byte{1}, lldpV4("192.0.2.5")...),
		portSub: 5, portID: []byte("Gi2/0/3"), sysName: "ap-3f-01",
		capSup: lldpCapBytes(capWlanAP), capEn: lldpCapBytes(capWlanAP),
		manAddr: "192.0.2.5", manAddrIf: 2}
	lldpCam = lldpNeigh{port: 3, index: 1, chassisSub: 4, chassis: lldpMAC("aa:bb:cc:dd:ee:31"),
		portSub: 5, portID: []byte("eth0"), sysName: "cam-3f-02", capSup: lldpCapBytes(capStation),
		capEn: lldpCapBytes(capStation)}
	lldpPhone = lldpNeigh{port: 3, index: 2, chassisSub: 4, chassis: lldpMAC("aa:bb:cc:dd:ee:32"),
		portSub: 5, portID: []byte("1"), sysName: "voip-3f-07", capSup: lldpCapBytes(capTelephone),
		capEn: lldpCapBytes(capTelephone)}
	lldpPrinter = lldpNeigh{port: 6, index: 1, chassisSub: 6, chassis: []byte("printer-3f"),
		portSub: 5, portID: []byte("1"), sysName: "print-3f-01"}
	lldpLegacy = lldpNeigh{port: 7, index: 1, chassisSub: 4, chassis: lldpMAC("aa:bb:cc:dd:ee:71"),
		portSub: 5, portID: []byte("FastEthernet0/1"), sysName: "sw-legacy-01",
		sysDesc: "Cisco Internetwork Operating System Software, 12.2(55)SE"}
	// ★ 机箱标识是一个认不出的编号（99）+ 二进制；enabled 位图给了、里面一位都没置。
	lldpOdd = lldpNeigh{port: 8, index: 1, chassisSub: 99, chassis: []byte{0x0d, 0xad, 0xbe, 0xef},
		sysName: "door-controller-1", capSup: lldpCapBytes(capBridge), capEn: []byte{0, 0}}
	// ★ 只给名字：机箱标识、端口标识都没有，而这一行确实是一条邻居。时间戳 800000
	//
	//	比 sysUpTime(900000) 小，能算出「这条 1000 秒没刷新了」。
	lldpUPS = lldpNeigh{port: 9, index: 1, mark: 800000, sysName: "ups-3f-01"}

	lldpAllRows = []lldpNeigh{lldpSw1, lldpAP, lldpCam, lldpPhone, lldpPrinter, lldpLegacy,
		lldpOdd, lldpUPS}

	lldpCfg = map[int]int{1: 3, 2: 3, 3: 3, 4: 1, 5: 4, 6: 2, 7: 1, 8: 3, 9: 3, 10: 3}
)

// lldpEntries 拼一台完整的 LLDP 设备：本地那一组、口号表、每口开关、邻居表、
// 管理地址、统计计数器，外加 ifTable 和 dot1dBasePortIfIndex。
func lldpEntries(rows []lldpNeigh, cfg map[int]int) map[string]snmptest.Value {
	e := sysEntries()
	put := func(oid string, v snmptest.Value) { e[oid] = v }

	// ── 本地系统那一组 ──
	put(oidLldpLocChassisIDSubtype+".0", snmptest.Int(4))
	put(oidLldpLocChassisID+".0", lldpOct(lldpMAC("aa:bb:cc:dd:ee:01")...))
	put(oidLldpLocSysName+".0", snmptest.Str("core-sw-01"))
	put(oidLldpLocSysDesc+".0", snmptest.Str("HUAWEI S5720-28X-LI, VRP Version 8.180"))
	put(oidLldpLocSysCapSupported+".0", lldpOct(lldpCapBytes(capBridge, capRouter)...))
	put(oidLldpLocSysCapEnabled+".0", lldpOct(lldpCapBytes(capBridge)...))

	// ── 口号表：这台自己怎么给它那些口编号 ──
	for p := range cfg {
		put(oidLldpLocPortIDSubtype+"."+fmt.Sprint(p), snmptest.Int(5))
		put(oidLldpLocPortID+"."+fmt.Sprint(p), snmptest.Str(fmt.Sprintf("GigabitEthernet1/0/%d", p)))
		put(oidLldpLocPortDesc+"."+fmt.Sprint(p), snmptest.Str(fmt.Sprintf("Gi1/0/%d", p)))
	}
	// ── 每个口的 LLDP 开关 ──
	for p, v := range cfg {
		put(oidLldpPortConfigAdminStatus+"."+fmt.Sprint(p), snmptest.Int(int64(v)))
	}
	// ── ifTable：口号 1..10 的接口编号是 101..110（★ 不等于口号）──
	for p := 1; p <= 10; p++ {
		idx := 100 + p
		put(oidIfIndex+"."+fmt.Sprint(idx), snmptest.Int(int64(idx)))
		put(oidIfName+"."+fmt.Sprint(idx), snmptest.Str(fmt.Sprintf("GigabitEthernet1/0/%d", p)))
		put(oidIfDescr+"."+fmt.Sprint(idx), snmptest.Str(fmt.Sprintf("GE1/0/%d", p)))
		put(oidDot1dBasePortIfIndex+"."+fmt.Sprint(p), snmptest.Int(int64(idx)))
	}
	// ★ 现场真有的毛病：一个接口编号被两个桥端口映射上（换过线、老的没删）。
	//   这一条让「按 ifIndex 问」出现两个候选，代码不许替人挑一个。
	put(oidDot1dBasePortIfIndex+".51", snmptest.Int(8))
	// ifIndex 8 上也写着口名：猜和口名两条路都指着口号 8，硬映射那条指着 51。
	put(oidIfIndex+".8", snmptest.Int(8))
	put(oidIfName+".8", snmptest.Str("GigabitEthernet1/0/8"))
	put(oidIfDescr+".8", snmptest.Str("GE1/0/8"))

	// ── 邻居表 ──
	for _, n := range rows {
		row := func(col string, v snmptest.Value) {
			e[fmt.Sprintf("%s.%d.%d.%d", col, n.mark, n.port, n.index)] = v
		}
		if len(n.chassis) > 0 {
			row(oidLldpRemChassisIDSubtype, snmptest.Int(int64(n.chassisSub)))
			row(oidLldpRemChassisID, lldpOct(n.chassis...))
		}
		if len(n.portID) > 0 {
			row(oidLldpRemPortIDSubtype, snmptest.Int(int64(n.portSub)))
			row(oidLldpRemPortID, lldpOct(n.portID...))
		}
		if n.portDesc != "" {
			row(oidLldpRemPortDesc, snmptest.Str(n.portDesc))
		}
		if n.sysName != "" {
			row(oidLldpRemSysName, snmptest.Str(n.sysName))
		}
		if n.sysDesc != "" {
			row(oidLldpRemSysDesc, snmptest.Str(n.sysDesc))
		}
		if len(n.capSup) > 0 {
			row(oidLldpRemSysCapSupported, lldpOct(n.capSup...))
		}
		if len(n.capEn) > 0 {
			row(oidLldpRemSysCapEnabled, lldpOct(n.capEn...))
		}
		if n.manAddr != "" {
			lldpPutManAddr(e, n.mark, n.port, n.index, 1, lldpV4(n.manAddr), 2, n.manAddrIf)
		}
	}

	// ── 统计计数器 ──
	put(oidLldpStatsRemInserts+".0", snmptest.Count(148))
	put(oidLldpStatsRemDeletes+".0", snmptest.Count(37))
	put(oidLldpStatsRemAgeouts+".0", snmptest.Count(21))
	put(oidLldpRxPortAgeouts+".2", snmptest.Count(4))
	put(oidLldpRxPortAgeouts+".6", snmptest.Count(0))
	put(oidLldpRxPortFramesErrors+".2", snmptest.Count(3))
	put(oidLldpRxPortTLVUnrecognized+".8", snmptest.Count(12))
	return e
}

// lldpPutManAddr 按 MIB 的索引写法填一栏管理地址：
// 列号.时间点.口号.行号.地址族.地址长度.地址各字节。
func lldpPutManAddr(e map[string]snmptest.Value, mark, port, index, afn int, addr []byte,
	ifSub, ifID int) {
	idx := fmt.Sprintf("%d.%d.%d.%d.%d", mark, port, index, afn, len(addr))
	for _, x := range addr {
		idx += "." + fmt.Sprint(x)
	}
	e[oidLldpRemManAddrIfSub+"."+idx] = snmptest.Int(int64(ifSub))
	e[oidLldpRemManAddrIfID+"."+idx] = snmptest.Int(int64(ifID))
}

func lldpDevice(t *testing.T) *snmptest.Device {
	t.Helper()
	return snmptest.Start(t, probeCommunity, lldpEntries(lldpAllRows, lldpCfg))
}

func lldpRunAt(t *testing.T, d *snmptest.Device, args map[string]any) ots.Verdict {
	t.Helper()
	a := map[string]any{"addr": d.Addr(), "community": probeCommunity}
	for k, v := range args {
		a[k] = v
	}
	return snmpLldpRun(t, a)
}

// ── 整张表 ──

// TestSnmpLldpTableWalk 整台设备列邻居：行数、口数、每个口的开关统计、以及
// 「一个口上两行」这一条拓扑事实。
func TestSnmpLldpTableWalk(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), nil)
	if v.Code != snmpLldpMulti {
		t.Fatalf("判定 = %s，要 %s：%s", v.Code, snmpLldpMulti, v.Note)
	}
	if v.Values["read"] != 8 || v.Values["count"] != 8 {
		t.Errorf("read=%v count=%v，要 8 条邻居行", v.Values["read"], v.Values["count"])
	}
	if v.Values["ports"] != 7 {
		t.Errorf("ports = %v，要 7 个本地口", v.Values["ports"])
	}
	if v.Values["multiNeighborPorts"] != 1 {
		t.Errorf("multiNeighborPorts = %v", v.Values["multiNeighborPorts"])
	}
	for _, want := range []string{"口号 3", "2 个"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
	want := map[string]int{"txAndRx": 6, "txOnly": 2, "rxOnly": 1, "disabled": 1}
	got, ok := v.Values["portAdminCounts"].(map[string]int)
	if !ok {
		t.Fatalf("portAdminCounts = %T", v.Values["portAdminCounts"])
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("portAdminCounts[%s] = %v，要 %d（全部 %v）", k, got[k], n, got)
		}
	}
	local := lldpLocalOf(t, v)
	if local["sysName"] != "core-sw-01" {
		t.Errorf("local.sysName = %v", local["sysName"])
	}
	if local["chassisId"] != "AA:BB:CC:DD:EE:01" {
		t.Errorf("local.chassisId = %v：本机的机箱标识是 6 个原始字节，要按 MAC 打", local["chassisId"])
	}
	stats, ok := v.Values["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats = %T", v.Values["stats"])
	}
	if stats["tableInserts"] != uint64(148) || stats["tableAgeouts"] != uint64(21) {
		t.Errorf("stats = %v", stats)
	}
	if v.Values["answered"] != true {
		t.Error("设备答过话了却没记 answered")
	}
	if v.Values["uptimeSeconds"] != uint64(9000) {
		t.Errorf("uptimeSeconds = %v", v.Values["uptimeSeconds"])
	}
}

// TestSnmpLldpIdentityDecoding chassisId / portId 是 OctetString：
// 按 subtype 翻，翻不出来给十六进制并说清为什么，绝不硬当字符串。
func TestSnmpLldpIdentityDecoding(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 1})
	e := lldpNeighborBy(t, v, 1, 1)
	if e["chassisId"] != "AA:BB:CC:DD:EE:11" {
		t.Errorf("chassisId = %v，要按 MAC 大写打出来", e["chassisId"])
	}
	if e["chassisIdType"] != "MAC 地址（macAddress）" {
		t.Errorf("chassisIdType = %v", e["chassisIdType"])
	}
	if s, _ := e["chassisIdWhy"].(string); !strings.Contains(s, "MAC") {
		t.Errorf("chassisIdWhy = %v：要写明是按哪一栏翻的", e["chassisIdWhy"])
	}
	if e["remotePortId"] != "GigabitEthernet1/0/24" {
		t.Errorf("remotePortId = %v", e["remotePortId"])
	}
	if e["remotePortIdType"] != "接口名（interfaceName）" {
		t.Errorf("remotePortIdType = %v：端口标识的 5 才是 interfaceName（机箱标识的 5 是网络地址）",
			e["remotePortIdType"])
	}
	if got := e["capabilities"]; fmt.Sprint(got) != "[交换（bridge） 路由（router）]" {
		t.Errorf("capabilities = %v", got)
	}
	if got := e["capabilitiesEnabled"]; fmt.Sprint(got) != "[交换（bridge）]" {
		t.Errorf("capabilitiesEnabled = %v：enabled 是另一张位图，不能跟 supported 混", got)
	}
	if e["localPortName"] != "Gi1/0/1" {
		t.Errorf("localPortName = %v：要用设备自己写的 lldpLocPortDesc", e["localPortName"])
	}
	if e["localLldpAdmin"] != "txAndRx" || e["localLldpAdminMeaning"] != "正常收发" {
		t.Errorf("localLldpAdmin = %v / %v", e["localLldpAdmin"], e["localLldpAdminMeaning"])
	}
	for _, want := range []string{"acc-sw-11", "AA:BB:CC:DD:EE:11", "GigabitEthernet1/0/24"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」：这一句是复制进工单的那一行", v.Note, want)
		}
	}
}

// TestSnmpLldpNetworkAddressChassis 机箱标识是 networkAddress 时，第一个字节是地址族。
// 直接当字符串打会得到一个 \x01 开头的乱码，而这一栏正是要拿去报名字的。
func TestSnmpLldpNetworkAddressChassis(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 2})
	e := lldpNeighborBy(t, v, 2, 1)
	if e["chassisId"] != "192.0.2.5" {
		t.Errorf("chassisId = %v，要翻成 192.0.2.5", e["chassisId"])
	}
	if s, _ := e["chassisIdWhy"].(string); !strings.Contains(s, "IPv4") {
		t.Errorf("chassisIdWhy = %v", s)
	}
	addrs, ok := e["mgmtAddresses"].([]string)
	if !ok || len(addrs) != 1 || !strings.HasPrefix(addrs[0], "192.0.2.5") {
		t.Fatalf("mgmtAddresses = %v，要读到对端留的管理地址", e["mgmtAddresses"])
	}
	if !strings.Contains(addrs[0], "它本机的系统口号") && !strings.Contains(addrs[0], "ifIndex") {
		t.Errorf("mgmtAddresses[0] = %v：要写明这个地址挂在它哪个接口上", addrs[0])
	}
}

// TestSnmpLldpMgmtAddressIfIndex 第一条邻居的管理地址：ifSubtype=2 时那个号是 ifIndex。
func TestSnmpLldpMgmtAddressIfIndex(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 1})
	e := lldpNeighborBy(t, v, 1, 1)
	addrs, _ := e["mgmtAddresses"].([]string)
	if len(addrs) != 1 || addrs[0] != "192.0.2.11（它本机的 ifIndex 101）" {
		t.Errorf("mgmtAddresses = %v", e["mgmtAddresses"])
	}
}

// TestSnmpLldpUnknownSubtypeStaysHex 认不出的 subtype + 二进制：给十六进制 + 一句为什么。
//
// ★ 不能因为长度像 MAC 就当 MAC 打 —— 那一栏会被人抄进工单。
func TestSnmpLldpUnknownSubtypeStaysHex(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 8})
	e := lldpNeighborBy(t, v, 8, 1)
	if e["chassisId"] != "0DADBEEF" {
		t.Errorf("chassisId = %v，要按原始字节打", e["chassisId"])
	}
	if s, _ := e["chassisIdWhy"].(string); !strings.Contains(s, "subtype 99") {
		t.Errorf("chassisIdWhy = %v：要写清是「这一族不认得」，不是设备给了乱码", s)
	}
	note, _ := e["capabilityNote"].(string)
	if !strings.Contains(note, "一个都没启用") {
		t.Errorf("capabilityNote = %v：supported 有 bridge、enabled 空，要点出来", note)
	}
}

// TestSnmpLldpPartialRow 只给了名字的邻居行：算一条邻居，但要写明缺了哪几栏 ——
// 「没读到」和「没有」在这一栏上是两件事。
func TestSnmpLldpPartialRow(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 9})
	e := lldpNeighborBy(t, v, 9, 1)
	miss, _ := e["missingColumns"].(string)
	if !strings.Contains(miss, "lldpRemChassisId") || !strings.Contains(miss, "lldpRemPortId") {
		t.Errorf("missingColumns = %v", miss)
	}
	if e["lastUpdateSeconds"] != uint64(1000) {
		t.Errorf("lastUpdateSeconds = %v，要 1000（sysUpTime 9000 减 timeMark 8000）", e["lastUpdateSeconds"])
	}
	if s, _ := e["lastUpdate"].(string); s == "" {
		t.Error("lastUpdate 要给人能读的那一句")
	}
	if !strings.Contains(v.Note, "1000 秒") && !strings.Contains(v.Note, "16 分") {
		t.Errorf("note = %q：这条比一般 TTL 老得多，要写进那一句", v.Note)
	}
}

// TestSnmpLldpVendorColumnsDiscarded 设备在邻居表里加了自己那几栏（或者索引段数不对）：
// 宁可丢掉，不许把厂商的字节当成对端名字。
func TestSnmpLldpVendorColumnsDiscarded(t *testing.T) {
	d := lldpDevice(t)
	d.Set(lldpRemEntry+".20.0.1.1", snmptest.Str("vendor-junk"))
	d.Set(oidLldpRemSysName+".0.4.1.7", snmptest.Str("不该出现的第五段"))
	v := lldpRunAt(t, d, nil)
	if v.Values["read"] != 8 {
		t.Errorf("read = %v，还是 8 条（认不出的栏不能凭空造一行）", v.Values["read"])
	}
	if strings.Contains(fmt.Sprint(v.Values["neighbors"]), "vendor-junk") {
		t.Error("厂商自己加的栏被当成邻居内容了")
	}
	for _, e := range lldpNeighborsOf(t, v) {
		if e["sysName"] == "不该出现的第五段" {
			t.Error("五段索引（管理地址那一棵的写法）混进了邻居表")
		}
	}
}

// ── 「邻居表是空的」那五种病 ──

func TestSnmpLldpUnsupported(t *testing.T) {
	d := snmptest.Start(t, probeCommunity, sysEntries())
	v := lldpRunAt(t, d, nil)
	if v.Code != snmpLldpUnsupported {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if v.Values["answered"] != true {
		t.Error("系统组答过话了，这一条不能算「设备不通」")
	}
	if len(lldpNeighborsOf(t, v)) != 0 {
		t.Error("没有这棵树却报了邻居")
	}
	if _, ok := v.Values["local"]; ok {
		t.Error("一栏都没给，不该有 local 那一块")
	}
	for _, want := range []string{"CDP", "视图", "net.snmp.probe"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」这条下一步", v.Note, want)
		}
	}
}

func TestSnmpLldpTreeButNoNeighbor(t *testing.T) {
	cfg := map[int]int{1: 3, 2: 3, 3: 3}
	d := snmptest.Start(t, probeCommunity, lldpEntries(nil, cfg))
	v := lldpRunAt(t, d, nil)
	if v.Code != snmpLldpNoNeighbor {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if _, ok := v.Values["local"]; !ok {
		t.Error("这棵树是有的（本地那一组给了话），local 那一块要在")
	}
	for _, want := range []string{"在收", "CDP", "net.snmp.ports"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
}

// TestSnmpLldpAllTxOnly：按标准这一档不存邻居，表空是必然的，不是对端没说话。
func TestSnmpLldpAllTxOnly(t *testing.T) {
	cfg := map[int]int{1: 1, 2: 1, 3: 1, 4: 1}
	d := snmptest.Start(t, probeCommunity, lldpEntries(nil, cfg))
	v := lldpRunAt(t, d, nil)
	if v.Code != snmpLldpTxOnly {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "本来就该是空的") {
		t.Errorf("note = %q：要敢下「这不是故障」这一句", v.Note)
	}
}

func TestSnmpLldpAllDisabled(t *testing.T) {
	cfg := map[int]int{1: 4, 2: 4}
	d := snmptest.Start(t, probeCommunity, lldpEntries(nil, cfg))
	v := lldpRunAt(t, d, nil)
	if v.Code != snmpLldpPortOff {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "配置的结果") {
		t.Errorf("note = %q", v.Note)
	}
}

// TestSnmpLldpNoPortConfig：树在、但没有每口开关那一栏 —— 这时候不能硬说
// 「这个口在收」，只能说「这棵子树没给东西」，并给出两种分不开的可能。
func TestSnmpLldpNoPortConfig(t *testing.T) {
	e := sysEntries()
	e[oidLldpLocSysName+".0"] = snmptest.Str("edge-sw-02")
	d := snmptest.Start(t, probeCommunity, e)
	v := lldpRunAt(t, d, nil)
	if v.Code != snmpNoData {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	for _, want := range []string{"服务没开", "视图"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
}

// TestSnmpLldpNamedTxOnlyEmpty 点名一个「只发不收」的口：这一条不用去查对端。
func TestSnmpLldpNamedTxOnlyEmpty(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 4})
	if v.Code != snmpLldpTxOnly {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	for _, want := range []string{"Gi1/0/4", "只发不收", "不是「线不通」"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
}

func TestSnmpLldpNamedPortOff(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 5})
	if v.Code != snmpLldpPortOff {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "也不是「对端不支持」") {
		t.Errorf("note = %q", v.Note)
	}
}

// TestSnmpLldpNotFound 点名的口没有邻居行、别处有：这台在说 LLDP，只有这根线另一头没说。
func TestSnmpLldpNotFound(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 10})
	if v.Code != snmpLldpNotFound {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "8") || !strings.Contains(v.Note, "net.snmp.ports") {
		t.Errorf("note = %q：要带上「这台一共读出 8 行」和链路状态那一档", v.Note)
	}
	if len(lldpNeighborsOf(t, v)) != 0 {
		t.Error("点名的口没有邻居，却还是报了行")
	}
}

// TestSnmpLldpTxOnlyContradictsRow 表里有这一行、开关却写着 txOnly：
// 设备自己的两栏对不上，这一条要红，因为下一步是去核配置。
func TestSnmpLldpTxOnlyContradictsRow(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 7})
	if v.Code != snmpLldpTxOnly {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "对不上") {
		t.Errorf("note = %q", v.Note)
	}
	if !strings.Contains(v.Note, "sw-legacy-01") {
		t.Errorf("note = %q：邻居是谁那一句不能被开关盖掉", v.Note)
	}
}

// TestSnmpLldpRxOnly 只听不发：能看见对端，对端看不见这台 —— 这不是故障，
// 但「为什么对面没有我的邻居」的答案就是这一条。
func TestSnmpLldpRxOnly(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 6})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "只听不发") {
		t.Errorf("note = %q", v.Note)
	}
	e := lldpNeighborBy(t, v, 6, 1)
	if e["localLldpAdminMeaning"] != "这个口只听不发：能看见对端，对端那边看不见这台（查「为什么对面没有我的邻居」时就是这一条）" {
		t.Errorf("localLldpAdminMeaning = %v", e["localLldpAdminMeaning"])
	}
}

// TestSnmpLldpTruncated 撞到 limit 就停：少的那几行不能当「没有」，也不给「其余都好」。
func TestSnmpLldpTruncated(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"limit": 2})
	if v.Code != snmpNotWalked {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if v.Values["truncated"] != true || v.Values["readLimit"] != 2 {
		t.Errorf("truncated=%v readLimit=%v", v.Values["truncated"], v.Values["readLimit"])
	}
	if !strings.Contains(v.Note, "8192") {
		t.Errorf("note = %q：要给下一步（把限量提到上限再看一次）", v.Note)
	}
	// 走表按栏走，限量按行给，所以「读到 7 行」和「限量 2 行」会同时出现 ——
	// 那一句必须把两个数都写出来，否则界面看着像数错了。
	if !strings.Contains(v.Note, "限量 2 行") {
		t.Errorf("note = %q：撞限量那一句要带上限量是几", v.Note)
	}
}

// ── 接口编号 → LLDP 口号 ──

// TestSnmpLldpIfIndexHardMapping：设备给了 dot1dBasePortIfIndex 时这一条是证据，
// 界面上要按证据写；只按编号相等猜的那一次必须留下「要核」。
func TestSnmpLldpIfIndexHardMapping(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"ifIndex": 101})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if _, ok := v.Values["portMappingAmbiguous"]; ok {
		t.Errorf("portMappingAmbiguous = %v：两条路指着同一个口号，不该报歧义", v.Values["portMappingAmbiguous"])
	}
	mapping, _ := v.Values["portMapping"].(string)
	if !strings.Contains(mapping, "dot1dBasePortIfIndex") {
		t.Errorf("portMapping = %v：要写明是设备给的映射", mapping)
	}
	e := lldpNeighborBy(t, v, 1, 1)
	if e["portMatchedBy"] != lldpMatchBothPorts {
		t.Errorf("portMatchedBy = %v，要两条路都对上", e["portMatchedBy"])
	}
	if why, _ := e["portMatchWhy"].(string); !strings.Contains(why, "可以当准") {
		t.Errorf("portMatchWhy = %v", why)
	}
}

// TestSnmpLldpIfIndexGuess 只有一条「编号正好相等」的路子时，那是猜的，
// 而且要点名说；这一趟点的是 4 号口，它同时是「只发不收」—— 两件事都要说。
func TestSnmpLldpIfIndexGuess(t *testing.T) {
	d := lldpDevice(t)
	d.Del(oidDot1dBasePortIfIndex + ".4")
	v := lldpRunAt(t, d, map[string]any{"ifIndex": 4})
	mapping, _ := v.Values["portMapping"].(string)
	if !strings.Contains(mapping, "猜") {
		t.Errorf("portMapping = %v：这一条只能按编号相等猜，要写明", mapping)
	}
	if v.Code != snmpLldpTxOnly {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
}

// TestSnmpLldpIfIndexAmbiguous 硬映射和口名/编号指着不同口号时，两条都不许藏。
func TestSnmpLldpIfIndexAmbiguous(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"ifIndex": 8})
	if v.Values["portMappingAmbiguous"] != true {
		t.Fatalf("portMappingAmbiguous = %v（%v）", v.Values["portMappingAmbiguous"], v.Values["portMapping"])
	}
	mapping, _ := v.Values["portMapping"].(string)
	if !strings.Contains(mapping, "两个候选") {
		t.Errorf("portMapping = %v", mapping)
	}
	e := lldpNeighborBy(t, v, 8, 1)
	if e["portMatchedBy"] != lldpMatchBothPorts {
		t.Errorf("portMatchedBy = %v", e["portMatchedBy"])
	}
}

// TestSnmpLldpIfIndexNoMatch 连「它是哪个 LLDP 口号」都没定下来时，
// 不能把「没找到邻居」写成结论 —— 那两句下一步完全不同。
func TestSnmpLldpIfIndexNoMatch(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"ifIndex": 4242})
	if v.Code != snmpLldpNotFound {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "没定下来") {
		t.Errorf("note = %q", v.Note)
	}
	mapping, _ := v.Values["portMapping"].(string)
	if !strings.Contains(mapping, "没对上") {
		t.Errorf("portMapping = %v", mapping)
	}
}

// TestSnmpLldpByName 按面板上的口名点名：短写法和全写法算同一个口。
func TestSnmpLldpByName(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"name": "GigabitEthernet1/0/2"})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	e := lldpNeighborBy(t, v, 2, 1)
	if e["portMatchedBy"] != lldpMatchName {
		t.Errorf("portMatchedBy = %v", e["portMatchedBy"])
	}
	if mapping, _ := v.Values["portMapping"].(string); !strings.Contains(mapping, "按口名对上的") {
		t.Errorf("portMapping = %v", mapping)
	}
}

func TestSnmpLldpByNameNotFound(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"name": "TenGigabitEthernet1/0/9"})
	if v.Code != snmpLldpNotFound {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "没定下来") {
		t.Errorf("note = %q：口名没对上时要先让人把整张表列一遍", v.Note)
	}
}

// ── 读两遍 ──

// TestSnmpLldpAging 老化计数器在涨 = 邻居会消失，不是「没有邻居」。
//
// ★ 推计数器那一下必须落在两次读中间（time.AfterFunc，不是立刻 Set）。
func TestSnmpLldpAging(t *testing.T) {
	d := lldpDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set(oidLldpRxPortAgeouts+".2", snmptest.Count(7)) // 4 → 7
	})
	v := lldpRunAt(t, d, map[string]any{"portNum": 2, "watchSeconds": 1})
	if v.Code != snmpLldpAging {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	e := lldpNeighborBy(t, v, 2, 1)
	if e["ageoutsDelta"] != uint64(3) {
		t.Errorf("ageoutsDelta = %v，要 3", e["ageoutsDelta"])
	}
	if e["ageoutsTotal"] != uint64(7) {
		t.Errorf("累计值要换成第二遍读到的：%v", e["ageoutsTotal"])
	}
	if e["agedOut"] != true {
		t.Errorf("agedOut = %v", e["agedOut"])
	}
	for _, want := range []string{"3 次", "不是「没有邻居」"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
	if v.Values["sampleSeconds"] == nil {
		t.Error("读了两遍却没记间隔")
	}
}

// TestSnmpLldpAgeoutsWithoutWatch 不读两遍也要给累计值，只是不给增量。
func TestSnmpLldpAgeoutsWithoutWatch(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 2})
	e := lldpNeighborBy(t, v, 2, 1)
	if e["ageoutsTotal"] != uint64(4) {
		t.Errorf("ageoutsTotal = %v", e["ageoutsTotal"])
	}
	if _, ok := e["ageoutsDelta"]; ok {
		t.Errorf("只读了一遍还给增量：%v", e)
	}
	if v.Code != snmpOk {
		t.Errorf("判定 = %s：%s", v.Code, v.Note)
	}
}

// TestSnmpLldpNewNeighbor 第二遍多出一行 = 有人在这个口下新插了一台（通常是台小交换机），
// 老化计数器不会告诉你这件事。
//
// ★ 标 newNeighbor 的必须是**多出来的那一行**，不是它旁边那条老邻居：那一行第一遍还不存在，
//
//	它的 chassisId / sysName / 管理地址只有第二遍读得到 —— 报错了对象等于没报。
func TestSnmpLldpNewNeighbor(t *testing.T) {
	d := lldpDevice(t)
	extra := lldpEntries([]lldpNeigh{{port: 1, index: 2, chassisSub: 4,
		chassis: lldpMAC("aa:bb:cc:dd:ee:12"), portSub: 5,
		portID: []byte("GigabitEthernet1/0/12"), sysName: "hidden-sw-12",
		capSup: lldpCapBytes(capBridge), capEn: lldpCapBytes(capBridge)}}, lldpCfg)
	time.AfterFunc(300*time.Millisecond, func() {
		for oid, val := range extra {
			// 只搬邻居表里那一行（mark.port.index = 0.1.2），别把整台设备重下一遍。
			if strings.HasPrefix(oid, lldpRemEntry) && strings.HasSuffix(oid, ".0.1.2") {
				d.Set(oid, val)
			}
		}
	})
	v := lldpRunAt(t, d, map[string]any{"portNum": 1, "watchSeconds": 1})
	e := lldpNeighborBy(t, v, 1, 2)
	if e["newNeighbor"] != true {
		t.Errorf("第二遍多出来的那一行没标出来：%v", e)
	}
	if e["sysName"] != "hidden-sw-12" {
		t.Errorf("sysName = %v：这一行的内容只有第二遍读得到，要补齐", e["sysName"])
	}
	if e["chassisId"] != "AA:BB:CC:DD:EE:12" {
		t.Errorf("chassisId = %v", e["chassisId"])
	}
	if e["localPortName"] != "Gi1/0/1" {
		t.Errorf("localPortName = %v：新行也要有本地口名，不然不知道往哪个口去看", e["localPortName"])
	}
	if e["localLldpAdmin"] != "txAndRx" {
		t.Errorf("localLldpAdmin = %v：开关是每个口的，新行该沿用同一个口的", e["localLldpAdmin"])
	}
	old := lldpNeighborBy(t, v, 1, 1)
	if _, ok := old["newNeighbor"]; ok {
		t.Errorf("第一遍就有的那一行被当成了新邻居：%v", old)
	}
	if v.Values["newNeighborRows"] != 1 {
		t.Errorf("newNeighborRows = %v，要 1", v.Values["newNeighborRows"])
	}
	// ★ 那一句数的是列出来的行，不是整张表：这里点名了 1 号口，表里另外六个口的行没列，
	//   写成「8 条邻居行、涉及 1 个口」就是把两个口径混在一句话里。
	if !strings.Contains(v.Note, "2 条邻居行（这台表里一共 8 行") {
		t.Errorf("note = %q：要按列出的行数说，并把表里一共几行另说一句", v.Note)
	}
	if v.Values["count"] != 2 {
		t.Errorf("count = %v，要 2（第一遍 1 行 + 第二遍新出现 1 行都报出来）", v.Values["count"])
	}
	if !strings.Contains(v.Note, "多出 1 行") {
		t.Errorf("note = %q：这一趟之间多了东西，得写进复制得走的那一句", v.Note)
	}
}

// TestSnmpLldpNeighborGone 第二遍这一行没了：这一行要点名说「不在了」，
// 不能安静地按第一遍的样子报 —— 那正是「刚被拔走」那一次的现场。
func TestSnmpLldpNeighborGone(t *testing.T) {
	d := lldpDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		for _, col := range lldpRemColumns() {
			d.Del(fmt.Sprintf("%s.0.6.1", col))
		}
	})
	v := lldpRunAt(t, d, map[string]any{"watchSeconds": 1})
	e := lldpNeighborBy(t, v, 6, 1)
	if e["gone"] != true {
		t.Errorf("gone = %v（这一行第二次读时不在了）", e)
	}
}

// TestSnmpLldpRebootBetweenSamples 两遍之间设备重启过：计数器被清零，
// 相减得到一个看着合理的假数 —— 这一趟不给增量。
func TestSnmpLldpRebootBetweenSamples(t *testing.T) {
	d := lldpDevice(t)
	time.AfterFunc(300*time.Millisecond, func() {
		d.Set("1.3.6.1.2.1.1.3.0", snmptest.Ticks(5000))
		d.Set(oidLldpRxPortAgeouts+".2", snmptest.Count(0))
	})
	v := lldpRunAt(t, d, map[string]any{"portNum": 2, "watchSeconds": 1})
	if v.Values["rebooted"] != true {
		t.Errorf("rebooted = %v：sysUpTime 倒退了要如实标出来", v.Values["rebooted"])
	}
	if !strings.Contains(fmt.Sprint(v.Values["sampleUnsure"]), "重启") {
		t.Errorf("sampleUnsure = %v", v.Values["sampleUnsure"])
	}
	e := lldpNeighborBy(t, v, 2, 1)
	if _, ok := e["ageoutsDelta"]; ok {
		t.Errorf("重启过还给增量：%v", e)
	}
	if !strings.Contains(v.Note, "重启") {
		t.Errorf("note = %q：「这一趟的增量不可信」要写进复制得走的那一句", v.Note)
	}
}

// TestSnmpLldpNoStats 不读计数器时那几栏整个不出现（不写成 0），
// 但管理地址不是计数器 —— 它是身份，不该被这个开关带走。
func TestSnmpLldpNoStats(t *testing.T) {
	v := lldpRunAt(t, lldpDevice(t), map[string]any{"portNum": 1, "noStats": true})
	if _, ok := v.Values["stats"]; ok {
		t.Errorf("noStats 还给了统计：%v", v.Values["stats"])
	}
	e := lldpNeighborBy(t, v, 1, 1)
	if _, ok := e["ageoutsTotal"]; ok {
		t.Errorf("noStats 却还给了老化计数：%v", e)
	}
	if addrs, _ := e["mgmtAddresses"].([]string); len(addrs) != 1 {
		t.Errorf("mgmtAddresses = %v：管理地址是身份，不该跟着计数器一起被跳过", e["mgmtAddresses"])
	}
}

// ── 报文层的那些事 ──

func TestSnmpLldpNoReply(t *testing.T) {
	d := lldpDevice(t)
	v := snmpLldpRun(t, map[string]any{"addr": d.Addr(), "community": "wrong-one",
		"timeoutMs": 200, "retries": 2})
	if v.Code != snmpNoReply {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if v.Values["answered"] != false {
		t.Errorf("answered = %v", v.Values["answered"])
	}
}

// TestSnmpLldpV1OneByOne：v1 问不存在的栏会让**整个报文作废**，所以本地那一组
// 要一栏一栏问一遍，才能把「一栏都没有」和「只少一两栏」分开。
func TestSnmpLldpV1OneByOne(t *testing.T) {
	d := lldpDevice(t)
	d.Del(oidLldpLocSysDesc + ".0")
	d.SetV1Only(true)
	v := lldpRunAt(t, d, map[string]any{"version": "v1", "portNum": 1})
	if v.Values["version"] != "v1" {
		t.Fatalf("version = %v", v.Values["version"])
	}
	local := lldpLocalOf(t, v)
	if local["sysName"] != "core-sw-01" {
		t.Errorf("local = %v：只缺一栏，不该把整组丢掉", local)
	}
	if _, ok := local["sysDesc"]; ok {
		t.Errorf("设备不给 sysDesc，结果里不该出现这一栏：%v", local)
	}
	if v.Code != snmpOk {
		t.Errorf("判定 = %s：%s", v.Code, v.Note)
	}
}

// TestSnmpLldpNoBulk：老设备不认 GETBULK 时走表要退回 GETNEXT，而不是整个失败。
func TestSnmpLldpNoBulk(t *testing.T) {
	d := lldpDevice(t)
	d.SetNoBulk(true)
	v := lldpRunAt(t, d, map[string]any{"portNum": 1})
	if v.Code != snmpOk {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	if v.Values["read"] != 8 {
		t.Errorf("read = %v，退回 GETNEXT 也要走完整张表", v.Values["read"])
	}
}

// TestSnmpLldpHalfWalkFails 本地那一组已经答过话了，邻居这一趟没读回来 ——
// 这时候不能翻成「设备没回话」（那要去查防火墙，这里要查视图）。
func TestSnmpLldpHalfWalkFails(t *testing.T) {
	d := lldpDevice(t)
	d.SetStuck(true)
	v := lldpRunAt(t, d, map[string]any{"portNum": 1})
	if v.Values["answered"] != true {
		t.Errorf("answered = %v：前面已经问过本地那一组了", v.Values["answered"])
	}
	if !strings.Contains(fmt.Sprint(v.Values["answeredEarlier"]), "本地那一组") {
		t.Errorf("answeredEarlier = %v", v.Values["answeredEarlier"])
	}
	// ★ 这一条的判定不能是 unknown、note 更不能是空的：unknown 的下一步是「回来重试」，
	//   而这里的下一步是去核视图 —— 拿不到一句能抄走的话，现场就等于没查。
	if v.Code != snmpNotWalked {
		t.Fatalf("判定 = %s：%s", v.Code, v.Note)
	}
	for _, want := range []string{"不能当「没有」", "视图"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note = %q，少了「%s」", v.Note, want)
		}
	}
	if v.Values["walkStoppedAt"] == nil || v.Values["walkRead"] == nil {
		t.Errorf("卡在哪儿、读回几栏都没带回来：%v", v.Values)
	}
}

// ── 参数 ──

func TestSnmpLldpArgs(t *testing.T) {
	for _, c := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"口号超上限", map[string]any{"portNum": 5000}, "4096"},
		{"口号是负数", map[string]any{"portNum": -1}, "负数"},
		{"ifIndex 超上限", map[string]any{"ifIndex": 70000}, "65535"},
		{"观测太长", map[string]any{"watchSeconds": 9999}, "watchSeconds"},
		{"没给团体名", map[string]any{"addr": "192.0.2.9"}, "community"},
		{"addr 是域名", map[string]any{"addr": "sw.example.com", "community": probeCommunity}, "IP"},
		{"v3 不支持", map[string]any{"addr": "192.0.2.9", "community": probeCommunity,
			"version": "v3"}, "v3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// ★ 只塞 addr，不塞 community：这一档里有一条测的就是「没给团体名」，
			//   默认值替它填上，那条测试就变成了「问一个没人应答的地址」。
			a := map[string]any{"addr": "192.0.2.9"}
			for k, v := range c.args {
				a[k] = v
			}
			lldpFailRun(t, a, c.want)
		})
	}
}

// ── 不经过网络的算法测试 ──

func TestLldpParseRemIndex(t *testing.T) {
	for _, c := range []struct {
		rest string
		ok   bool
		key  lldpRemKey
		col  string
	}{
		{"9.0.1.1", true, lldpRemKey{0, 1, 1}, oidLldpRemSysName},
		{"9.800000.7.2", true, lldpRemKey{800000, 7, 2}, oidLldpRemSysName},
		// 厂商自己加的栏：丢掉，不许当成对端名字。
		{"20.0.1.1", false, lldpRemKey{}, ""},
		// 五段：那是管理地址那一棵的索引写法。
		{"9.0.1.1.7", false, lldpRemKey{}, ""},
		// 口号或行号为 0：索引从 1 起，0 是设备答歪了。
		{"9.0.0.1", false, lldpRemKey{}, ""},
		{"9.0.1.0", false, lldpRemKey{}, ""},
		{"9.-1.1.1", false, lldpRemKey{}, ""},
	} {
		col, k, ok := parseLldpRem(c.rest)
		if ok != c.ok || k != c.key || col != c.col {
			t.Errorf("parseLldpRem(%q) = %q %+v %v，要 %q %+v %v",
				c.rest, col, k, ok, c.col, c.key, c.ok)
		}
	}
}

func TestLldpParseManAddr(t *testing.T) {
	v4 := oidLldpRemManAddrIfSub + ".0.1.1.1.4.192.0.2.11"
	row, ok := parseLldpManAddr(indexAfter(v4, lldpRemManAddrEnt))
	if !ok || row.key != (lldpRemKey{0, 1, 1}) || row.addr != "192.0.2.11" {
		t.Errorf("IPv4 = %+v %v", row, ok)
	}
	// 结尾那个字节是地址的一部分，不是列号：以前按最后一段拆栏，
	// 10.0.0.3 这种地址会被当成「lldpRemManAddrIfSubtype 这一栏」。
	dup := oidLldpRemManAddrIfSub + ".0.2.1.1.4.10.0.0.3"
	row, ok = parseLldpManAddr(indexAfter(dup, lldpRemManAddrEnt))
	if !ok || row.addr != "10.0.0.3" || row.key.port != 2 {
		t.Errorf("结尾是 3 的地址 = %+v %v", row, ok)
	}
	// 长度字节和实际段数对不上：不猜。
	bad := oidLldpRemManAddrIfSub + ".0.1.1.1.4.192.0.2"
	if _, ok := parseLldpManAddr(indexAfter(bad, lldpRemManAddrEnt)); ok {
		t.Error("地址长度对不上还给了地址")
	}
	// 2001:db8::1 逐字节写死：32.1.13.184 = 20 01 0d b8，后面 11 个 0 再加末尾的 1
	v6oid := oidLldpRemManAddrIfSub + ".0.1.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
	if r, ok := parseLldpManAddr(indexAfter(v6oid, lldpRemManAddrEnt)); !ok {
		t.Error("IPv6 管理地址没读出来")
	} else if !strings.HasPrefix(r.addr, "2001:db8") {
		t.Errorf("IPv6 = %v", r.addr)
	}
	// 没按它翻译的地址族：给原始字节，并写明是哪一族。
	nsap := oidLldpRemManAddrIfID + ".0.1.1.3.2.47.0"
	if r, ok := parseLldpManAddr(indexAfter(nsap, lldpRemManAddrEnt)); !ok {
		t.Error("地址族 3 也要给一行")
	} else if !strings.Contains(r.addr, "地址族 3") {
		t.Errorf("NSAP = %v", r.addr)
	}
	// 厂商加的栏（列号 .5）丢掉。
	if _, ok := parseLldpManAddr("5.0.1.1.1.4.192.0.2.11"); ok {
		t.Error("认不出的栏不该被当成地址")
	}
	// MAC 那一族：这一栏给的是 6 个字节。
	if r, ok := parseLldpManAddr(indexAfter(oidLldpRemManAddrIfID+
		".0.1.1.18.6.170.187.204.221.238.239", lldpRemManAddrEnt)); !ok {
		t.Error("MAC 形式的管理地址没读出来")
	} else if r.addr != "MAC AA:BB:CC:DD:EE:EF" {
		t.Errorf("MAC 地址 = %v", r.addr)
	}
	for _, bad := range []string{"", "3", "3.0.1.1.1.4", "4.0.1.1.1.4.192.0.2.11.x"} {
		if _, ok := parseLldpManAddr(bad); ok {
			t.Errorf("parseLldpManAddr(%q) 竟然成功了", bad)
		}
	}
}

// TestLldpIDTextTwoEnums 机箱标识和端口标识的 subtype 是两套枚举：
// 同一个 4 在两边不是一回事，共用一张表会编出一个看着能用的 MAC。
func TestLldpIDTextTwoEnums(t *testing.T) {
	raw := []byte{1, 192, 0, 2, 5}
	if s, why := chassisIDText(4, raw); !strings.Contains(s, "DEADBEEF") &&
		!strings.Contains(s, "C000") {
		t.Errorf("机箱标识 subtype 4 但长度不是 6：%s / %s", s, why)
	} else if !strings.Contains(why, "长度") {
		t.Errorf("why = %s：要说清为什么退到原始字节", why)
	}
	if s, why := portIDText(4, raw); s != "192.0.2.5" {
		t.Errorf("端口标识的 4 是网络地址：%s / %s", s, why)
	}
	if s, why := chassisIDText(5, raw); s != "192.0.2.5" {
		t.Errorf("机箱标识的 5 才是网络地址：%s / %s", s, why)
	}
	if s, _ := portIDText(3, lldpMAC("aa:bb:cc:dd:ee:ff")); s != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("端口标识的 3 是 MAC：%s", s)
	}
	if s, _ := portIDText(5, []byte("Gi2/0/3")); s != "Gi2/0/3" {
		t.Errorf("接口名直接给文本：%s", s)
	}
	if s, why := chassisIDText(77, []byte{2, 3, 4}); !strings.Contains(s, "020304") ||
		!strings.Contains(why, "subtype 77") {
		t.Errorf("认不出的编号：%s / %s", s, why)
	}
	if s, _ := chassisIDText(4, nil); s != "" {
		t.Errorf("空的标识不该有内容：%q", s)
	}
}

func TestLldpCapNamesBitOrder(t *testing.T) {
	for _, c := range []struct {
		v    []byte
		want string
	}{
		{lldpCapBytes(capBridge), "交换（bridge）"},
		{lldpCapBytes(capWlanAP), "无线 AP（wlanAP）"},
		{lldpCapBytes(capStation), "只是终端（stationOnly）"},
		{lldpCapBytes(capBridge, capRouter), "交换（bridge）+路由（router）"},
	} {
		got := strings.Join(lldpCapNames(c.v), "+")
		if got != c.want {
			t.Errorf("位图 % x = %q，要 %q（位序从第一个字节的最高位数）", c.v, got, c.want)
		}
	}
	if n := lldpCapNote(lldpCapBytes(capBridge), []byte{0, 0}); !strings.Contains(n, "一个都没启用") {
		t.Errorf("supported 有位、enabled 空：%s", n)
	}
	if n := lldpCapNote(lldpCapBytes(capBridge), lldpCapBytes(capRouter)); !strings.Contains(n, "对不上") {
		t.Errorf("enabled 里有 supported 没写的项：%s", n)
	}
	if n := lldpCapNote(lldpCapBytes(capBridge), lldpCapBytes(capBridge)); n != "" {
		t.Errorf("两栏一致时不该有提示：%s", n)
	}
}

func TestLldpAdminWords(t *testing.T) {
	for n, want := range map[int]string{1: "只发不收", 2: "只听不发", 3: "又发又听", 4: "关着"} {
		if got := lldpAdminWord(n); got != want {
			t.Errorf("adminStatus %d = %q，要 %q", n, got, want)
		}
	}
	if w := lldpAdminWord(9); w != "" {
		t.Errorf("没听过的值不该有中文名：%q", w)
	}
	if m := lldpAdminMeaning(9); !strings.Contains(m, "没听过") {
		t.Errorf("lldpAdminMeaning(9) = %q", m)
	}
}

func TestLldpMappingNotePaths(t *testing.T) {
	if n := lldpMappingNote(0, nil, nil, nil, false); !strings.Contains(n, "不给读") {
		t.Errorf("没名字可对时：%s", n)
	}
	if n := lldpMappingNote(1, []int{3}, nil, nil, true); !strings.Contains(n, "设备给的映射") {
		t.Errorf("硬映射：%s", n)
	}
	if n := lldpMappingNote(1, nil, []int{3}, nil, true); !strings.Contains(n, "lldpLocPortDesc") {
		t.Errorf("设备自己写的口名：%s", n)
	}
	if n := lldpMappingNote(1, nil, nil, []int{3}, true); !strings.Contains(n, "猜") {
		t.Errorf("只有编号相等：%s", n)
	}
	n := lldpMappingNote(2, []int{5}, nil, []int{8}, true)
	if !strings.Contains(n, "两个候选") {
		t.Errorf("两条路指着不同口号：%s", n)
	}
}
