package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

// net.mac.analyze 的测试钉四类事：
//
//	① 四条岔路各归各位：全零 / 组播 / 本机管理 / 真厂商地址。判错档的后果不是
//	   「少个名字」，是**拿一个软件造的地址当设备唯一标识**，一台数成好几台；
//	② 写法要宽（几种来源的地址都得能粘进来），但**混用分隔符和拿 IP 当 MAC 要拒** ——
//	   这两种都是「两行粘成一行」，接着算只会查错设备；
//	③ 自带的表里**不许有 IEEE 注册表的厂商**（CC BY-NC-SA，不许打进安装包），
//	   软件约定前缀必须标成推测，厂商名只能来自操作者自己挂的表；
//	④ 派生的东西（EUI-64 接口标识、Docker 地址里藏的 IPv4）要算得准，
//	   而组播地址不许派生 —— 推出来像个真的，比推不出来坏得多。

// ── 夹具 ──

func macRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doMACAnalyze(context.Background(), b)
	if err != nil {
		t.Fatalf("跑不动：%v", err)
	}
	return v.(ots.Verdict)
}

func macAsk(t *testing.T, s string) ots.Verdict {
	t.Helper()
	return macRun(t, map[string]any{"mac": s})
}

func macStr(t *testing.T, v ots.Verdict, key string) string {
	t.Helper()
	s, ok := v.Values[key].(string)
	if !ok {
		t.Fatalf("%s 不在或不是字符串（ %+v ）", key, v.Values[key])
	}
	return s
}

func macBool(t *testing.T, v ots.Verdict, key string) bool {
	t.Helper()
	b, ok := v.Values[key].(bool)
	if !ok {
		t.Fatalf("%s 不是布尔（ %+v ）", key, v.Values[key])
	}
	return b
}

// withTable 临时换掉厂商表，测完复原（表是包级缓存，不复原会污染别的测试）。
func withTable(t *testing.T, tbl *ouiTable) {
	t.Helper()
	old := loadOUI
	loadOUI = func() *ouiTable { return tbl }
	t.Cleanup(func() { loadOUI = old })
}

// ── 写法 ──

// 现场地址是从 `arp -a`、交换机 CLI、设备标签、网页上分别抄下来的，写法各不相同。
func Test几种写法都归到同一个地址(t *testing.T) {
	want := "02:42:ac:11:00:02"
	for _, in := range []string{
		"02:42:ac:11:00:02", "02:42:AC:11:00:02", "02-42-ac-11-00-02",
		"0242.ac11.0002", "0242ac110002", "  02:42:ac:11:00:02  ", "\"02:42:ac:11:00:02\"",
	} {
		v := macAsk(t, in)
		if got := macStr(t, v, "canonical"); got != want {
			t.Errorf("%q 归一成 %q，想要 %q", in, got, want)
		}
	}
}

func Test各种输出写法都给全(t *testing.T) {
	v := macAsk(t, "02:42:ac:11:00:02")
	for key, want := range map[string]string{
		"canonical": "02:42:ac:11:00:02", "dashForm": "02-42-ac-11-00-02",
		"dotForm": "0242.ac11.0002", "bareForm": "0242ac110002",
	} {
		if got := macStr(t, v, key); got != want {
			t.Errorf("%s = %q，想要 %q", key, got, want)
		}
	}
}

// ★ 混用分隔符多半是两行地址粘成一行，接着算就会查错设备。
func Test混用分隔符当场拒(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"mac": "02:42-ac:11.0002"})
	if _, err := doMACAnalyze(context.Background(), b); err == nil {
		t.Fatal("混了三种分隔符居然收下了")
	} else if !strings.Contains(err.Error(), "粘") {
		t.Errorf("报错没说清为什么会混： %v", err)
	}
}

// 把 IP 当 MAC 粘进来是高频错，报错必须点名，不能只说「不是十六进制」。
func Test粘进来的是IP地址要说破(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"mac": "192.168.1.1"})
	_, err := doMACAnalyze(context.Background(), b)
	if err == nil {
		t.Fatal("IP 地址被当成 MAC 收了")
	}
	if !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("报错没点破是 IP： %v", err)
	}
}

func Test长度不对时报错列出认得的写法(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"mac": "02:42:ac"})
	_, err := doMACAnalyze(context.Background(), b)
	if err == nil {
		t.Fatal("3 字节被收下了")
	}
	for _, want := range []string{"6 字节", "02:42:ac:11:00:02"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("报错里缺 %q： %v", want, err)
		}
	}
}

func Test非十六进制当场拒(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"mac": "02:42:zz:11:00:02"})
	if _, err := doMACAnalyze(context.Background(), b); err == nil {
		t.Fatal("zz 被当成十六进制收下了")
	}
}

func Test空的和不合法参数当场拒(t *testing.T) {
	if _, err := doMACAnalyze(context.Background(), []byte(`{"mac":"   "}`)); err == nil {
		t.Fatal("空 mac 收下了")
	}
	if _, err := doMACAnalyze(context.Background(), []byte(`{`)); err == nil {
		t.Fatal("半个 JSON 收下了")
	}
}

func Test八字节EUI64也认(t *testing.T) {
	v := macAsk(t, "00:11:22:33:44:55:66:77")
	if got := macStr(t, v, "family"); got != "eui-64" {
		t.Errorf("family = %q", got)
	}
	if n, _ := v.Values["octets"].(int); n != 8 {
		t.Errorf("octets = %v", v.Values["octets"])
	}
}

// ── 位 ──

func Test组播位和管理位分开报(t *testing.T) {
	// 02 = 0000 0010：单播 + 本机管理
	v := macAsk(t, "02:00:00:00:00:01")
	if macBool(t, v, "group") {
		t.Error("02 的最低位是 0，不是组播")
	}
	if got := macStr(t, v, "administered"); got != "local" {
		t.Errorf("管理位 = %q，想要 local", got)
	}
	if got := macStr(t, v, "firstOctetBin"); got != "00000010" {
		t.Errorf("二进制形态 = %q", got)
	}
	// 01 = 0000 0001：组播 + 全局 —— 和上面是两件不相干的事，不许并成一栏
	v = macAsk(t, "01:00:5e:00:00:01")
	if !macBool(t, v, "group") {
		t.Error("01 的最低位是 1，应为组播")
	}
	if got := macStr(t, v, "administered"); got != "global" {
		t.Errorf("管理位 = %q，想要 global", got)
	}
}

func Test第一个字节的二进制形态必须给(t *testing.T) {
	v := macAsk(t, "33:33:00:00:00:01")
	if got := macStr(t, v, "firstOctetBin"); got != "00110011" {
		t.Errorf("got %q", got)
	}
}

// ── 四条岔路 ──

// ★ 全零最容易被当成「厂商库缺这一条」，实际是设备没烧 MAC 或驱动没读上来。
func Test全零说的是没读到而不是查不到(t *testing.T) {
	v := macAsk(t, "00:00:00:00:00:00")
	if v.Code != macUnset {
		t.Fatalf("判定 = %s", v.Code)
	}
	if !strings.Contains(v.Note, "不是库的问题") {
		t.Errorf("人话没把方向掰回来： %s", v.Note)
	}
	if _, ok := v.Values["iid"]; ok {
		t.Error("全零不该推出 IPv6 接口标识")
	}
}

func Test全一是广播不许当源地址(t *testing.T) {
	v := macAsk(t, "ff:ff:ff:ff:ff:ff")
	if v.Code != macBroadcast {
		t.Fatalf("判定 = %s", v.Code)
	}
	if !strings.Contains(v.Note, "源地址") {
		t.Errorf("note = %q", v.Note)
	}
}

func Test协议组播点名到标准出处(t *testing.T) {
	cases := map[string]string{"33:33:ff:aa:bb:cc": "IPv6", "01:00:5e:01:02:03": "IGMP",
		"01:80:c2:00:00:00": "802.1X"}
	for in, want := range cases {
		v := macAsk(t, in)
		if v.Code != macGroup {
			t.Errorf("%s 判定 = %s", in, v.Code)
			continue
		}
		if !strings.Contains(macStr(t, v, "who"), want) {
			t.Errorf("%s 名字/出处里找不到 %q：%v / %v", in, want, v.Values["who"], v.Values["whoSrc"])
		}
		if got := macStr(t, v, "whoBasis"); got != "standard" {
			t.Errorf("%s 协议地址是事实，whoBasis = %q", in, got)
		}
		if _, ok := v.Values["iid"]; ok {
			t.Errorf("%s 是组播，不该推出接口标识", in)
		}
	}
}

// ★ CDP 的地址是 01:00:0c:cc:cc:cc（组播位在那儿），不是「一台 Cisco 设备」。
func TestCDP地址按四位前缀认(t *testing.T) {
	v := macAsk(t, "01:00:0c:cc:cc:cc")
	if v.Code != macGroup {
		t.Fatalf("判定 = %s", v.Code)
	}
	if !strings.Contains(macStr(t, v, "who"), "Cisco") {
		t.Errorf("who = %q", v.Values["who"])
	}
}

func Test虚拟化前缀判成虚机并标明是推测(t *testing.T) {
	for _, in := range []string{"52:54:00:12:34:56", "00:0c:29:ab:cd:ef", "00:16:3e:00:11:22",
		"00:15:5d:00:11:22", "00:50:56:a0:b1:c2"} {
		v := macAsk(t, in)
		if v.Code != macVirtual {
			t.Errorf("%s 判定 = %s，想要 %s", in, v.Code, macVirtual)
			continue
		}
		if got := macStr(t, v, "whoBasis"); got != "guess" {
			t.Errorf("%s 软件约定不是登记信息，whoBasis = %q", in, got)
		}
		if !strings.Contains(v.Note, "推测") {
			t.Errorf("%s 人话没说是推测： %s", in, v.Note)
		}
	}
}

// 手机私有地址 / 随机 MAC：认不出名字，但**必须**判成「别当身份」。
func Test认不出名字的随机地址仍然判成本机管理(t *testing.T) {
	v := macAsk(t, "da:b4:71:3f:9a:2c")
	if v.Code != macLocal {
		t.Fatalf("判定 = %s，想要 %s", v.Code, macLocal)
	}
	for _, want := range []string{"设备唯一标识", "同一台设备"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note 缺 %q： %s", want, v.Note)
		}
	}
	if _, ok := v.Values["who"]; ok {
		t.Error("本机管理地址没有厂商，不许编一个 who")
	}
}

func Test厂商发的单播地址判成可当身份(t *testing.T) {
	v := macAsk(t, "ac:de:48:00:11:22") // AC-DE-48 是 IEEE 留给文档用的，正好当例子
	if v.Code != macDevice {
		t.Fatalf("判定 = %s", v.Code)
	}
	if !strings.Contains(v.Note, "可以当设备身份") {
		t.Errorf("note = %q", v.Note)
	}
}

// ★★ 没挂表时不许留空：要说清「为什么不报厂商名」以及「怎么才能有」。
func Test没挂表时说明许可限制和挂表办法(t *testing.T) {
	withTable(t, &ouiTable{err: "没挂厂商表", by24: map[string]string{}})
	v := macAsk(t, "ac:de:48:00:11:22")
	why := macStr(t, v, "vendorWhy")
	for _, want := range []string{"CC BY-NC-SA", ouiFileEnvVar, "ieee.org"} {
		if !strings.Contains(why, want) {
			t.Errorf("vendorWhy 缺 %q： %q", want, why)
		}
	}
}

// ── 派生 ──

// 两台设备「MAC 很像」时，像在哪半截决定了下一步：前段像是同厂商，后段像才要查克隆。
func Test厂商前缀和设备位分开给(t *testing.T) {
	v := macAsk(t, "ac:de:48:00:11:22")
	if got := macStr(t, v, "oui"); got != "ac:de:48" {
		t.Errorf("oui = %q", got)
	}
	if got := macStr(t, v, "nic"); got != "00:11:22" {
		t.Errorf("nic = %q", got)
	}
}

func TestDocker地址反推出容器IPv4(t *testing.T) {
	v := macAsk(t, "02:42:ac:11:00:02")
	if got := macStr(t, v, "derivedIPv4"); got != "172.17.0.2" {
		t.Fatalf("derivedIPv4 = %q", got)
	}
	if !strings.Contains(macStr(t, v, "who"), "Docker") {
		t.Errorf("who = %q", v.Values["who"])
	}
}

// 别的软件也用本机管理段，硬按「后四字节当地址」推会推出一个像真的假地址。
func Test非Docker前缀不许硬凑出IPv4(t *testing.T) {
	for _, in := range []string{"02:43:ac:11:00:02", "52:54:ac:11:00:02", "02:42:ac:11:00:02:ff:fe"} {
		v := macAsk(t, in)
		if _, ok := v.Values["derivedIPv4"]; ok {
			t.Errorf("%s 被凑出了一个 IPv4", in)
		}
	}
}

func TestEUI64接口标识按RFC4291算(t *testing.T) {
	v := macAsk(t, "00:11:22:33:44:55")
	if got := macStr(t, v, "iid"); got != "0211:22ff:fe33:4455" {
		t.Fatalf("iid = %q", got)
	}
	// ★ 取反不是置位：本机管理地址推出来那一位要变 0
	v = macAsk(t, "02:00:00:00:00:01")
	if got := macStr(t, v, "iid"); got != "0000:00ff:fe00:0001" {
		t.Errorf("iid = %q", got)
	}
}

// ── 前缀表 ──

// ★ 安装包零专有依赖，也包括不许把 CC BY-NC-SA 的 IEEE 表抄进来。
func Test自带表里不许有IEEE注册表的厂商(t *testing.T) {
	for _, p := range macPrefixes {
		if p.kind != "protocol" && p.kind != "convention" {
			t.Errorf("%s 的 kind = %q，只许 protocol / convention", p.name, p.kind)
		}
		if p.src == "" || p.name == "" {
			t.Errorf("%+v 缺出处或名字", p)
		}
	}
}

func Test最长前缀赢(t *testing.T) {
	old := macPrefixes
	macPrefixes = append(append([]macPrefix{}, old...),
		macPrefix{prefix: hx("00:11:22"), name: "宽的", kind: "convention", src: "x"},
		macPrefix{prefix: hx("00:11:22:33"), name: "更窄的", kind: "convention", src: "y"})
	t.Cleanup(func() { macPrefixes = old })
	p, ok := matchPrefix(hx("00:11:22:33:44:55"))
	if !ok || p.name != "更窄的" {
		t.Fatalf("匹配到 %+v", p)
	}
}

// ── 厂商表文件 ──

func TestIEEE格式的行认得(t *testing.T) {
	k, name, ok := parseOUILine("AC-DE-48   (hex)\t\tExample Company Inc.")
	if !ok || k != "ac:de:48" || name != "Example Company Inc." {
		t.Fatalf("got %q %q %v", k, name, ok)
	}
	k, name, ok = parseOUILine("ACDE48 Example Company Inc.")
	if !ok || k != "ac:de:48" || name != "Example Company Inc." {
		t.Fatalf("nmap 格式：got %q %q %v", k, name, ok)
	}
	for _, bad := range []string{"", "# comment", "AC-DE   (hex)\tX", "ZZ-ZZ-ZZ (hex)\tX",
		"AC-DE-48   (hex)\t\t"} {
		if _, _, ok := parseOUILine(bad); ok {
			t.Errorf("不该认这一行： %q", bad)
		}
	}
}

func Test表里的条目数和查找都对上(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oui.txt")
	body := "# comment\nAC-DE-48   (hex)\t\tExample Company Inc.\n" +
		"AC-DE-48   (hex)\t\t重复的一条\n" +
		"00-11-22   (hex)\t\tAnother Co\n nonsense line\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl := readOUIFile(path)
	if tbl.err != "" {
		t.Fatalf("读表报错：%s", tbl.err)
	}
	if tbl.entries != 2 {
		t.Errorf("entries = %d，想要 2（重复前缀只算一条）", tbl.entries)
	}
	withTable(t, tbl)
	v := macAsk(t, "ac:de:48:11:22:33")
	if got := macStr(t, v, "who"); got != "Example Company Inc." {
		t.Errorf("who = %q", got)
	}
	if got := macStr(t, v, "whoBasis"); got != "registry" {
		t.Errorf("whoBasis = %q", got)
	}
	// ★ 按 24 位查就有撞名的一天，note 里不许写成「确定是这家」
	if !strings.Contains(v.Note, "多半") {
		t.Errorf("note 过头了： %s", v.Note)
	}
	if _, ok := v.Values["vendorWhy"]; ok {
		t.Error("查到名字了就不该再给「为什么查不到」")
	}
}

func Test表文件打不开时不影响判定(t *testing.T) {
	withTable(t, readOUIFile(filepath.Join(t.TempDir(), "没有这个文件")))
	v := macAsk(t, "ac:de:48:11:22:33")
	if v.Code != macDevice {
		t.Errorf("判定 = %s", v.Code)
	}
	if !strings.Contains(v.Note, ouiFileEnvVar) {
		t.Errorf("查不到厂商名时该给出挂表的办法： %s", v.Note)
	}
}

func Test没给环境变量时不读任何文件(t *testing.T) {
	t.Setenv(ouiFileEnvVar, "")
	tbl := readOUIFile(os.Getenv(ouiFileEnvVar))
	if tbl.entries != 0 || tbl.err == "" {
		t.Errorf("tbl = %+v", tbl)
	}
}

// ── 声明与判定码 ──

func TestMAC分析工具声明(t *testing.T) {
	if macAnalyzeTool.Name != "net.mac.analyze" {
		t.Errorf("name = %s", macAnalyzeTool.Name)
	}
	if macAnalyzeTool.Class != ots.ClassRead {
		t.Errorf("纯解析必须是 read，class = %s", macAnalyzeTool.Class)
	}
	var sch map[string]any
	if err := json.Unmarshal(macAnalyzeTool.Schema, &sch); err != nil {
		t.Fatal(err)
	}
	if sch["additionalProperties"] != false {
		t.Error("schema 不许放行未知参数")
	}
	for _, code := range []string{macUnset, macBroadcast, macGroup, macVirtual, macLocal, macDevice} {
		if !strings.Contains(macAnalyzeTool.Summary, code) {
			t.Errorf("Summary 里没提判定码 %s —— AI 就选不对这个工具", code)
		}
	}
	if !strings.Contains(macAnalyzeTool.Summary, "NETKIT_OUI_FILE") {
		t.Error("Summary 得说清厂商名从哪来，否则 AI 会以为工具坏了")
	}
}

func TestMAC判定码拼写与人话(t *testing.T) {
	for _, code := range []string{macUnset, macBroadcast, macGroup, macVirtual, macLocal, macDevice} {
		if strings.ToLower(code) != code || strings.ContainsAny(code, " _") {
			t.Errorf("判定码 %q 不合规", code)
		}
	}
	// 每个码都得有人话，且不许把 UI 该做的事写进去（界面按码自己渲染中文）
	for _, in := range []string{"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "33:33:00:00:00:01",
		"52:54:00:00:00:01", "da:b4:71:3f:9a:2c", "ac:de:48:00:11:22"} {
		v := macAsk(t, in)
		if v.Note == "" {
			t.Errorf("%s（%s）没给人话", in, v.Code)
		}
		if len(v.Values) < 5 {
			t.Errorf("%s 取值太少", in)
		}
	}
}
