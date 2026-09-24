package diag

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var when = time.Date(2026, 9, 25, 10, 30, 0, 0, time.Local)

func hdr(label string) Header {
	return Header{
		Label: label, Created: when, HostName: "eng-laptop",
		GOOS: "linux", GOARCH: "amd64", Version: "2026.09.25",
		Rows: []Row{{Item: "iface", Code: "iface-ok"},
			{Item: "gateway", Code: "gateway-loss", Note: "★ 这一段**不能**当「没有」", Missing: true}},
		Warnings: []string{"这台**没有** v6 地址，别按双栈查"},
	}
}

func secs() []Section {
	return []Section{
		{Name: "01 本机/网卡.txt", Text: "eth0 10.0.12.34/22 up mtu 1500\n"},
		{Name: "01 本机/路由表", Text: "default via 10.0.12.1 dev eth0\n"},
		{Name: "02 连通性/到网关.txt", Text: "6 发丢 1，rtt 0.8ms\n"},
	}
}

// Test文件名是UTF8不是GBK 是这个包**最硬的一条要求**：上一版诊断包用 GBK 存名字，
// macOS/Linux 的 unzip 直接报 Illegal byte sequence —— 现场把包发回来却解不开。
//
// ★ 所以这里不看库的说明书，逐字节去查那一位（general purpose bit 11 = 0x800）：
//
//	本地文件头和中心目录头**两处都得置**，只置一处会让某些解压工具走另一条解码路径。
func Test文件名是UTF8不是GBK(t *testing.T) {
	dir := t.TempDir()
	res, err := Build(dir, hdr("金宇建安-盒1"), secs())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	raw, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	names := zipNames(t, raw)
	if len(names) == 0 {
		t.Fatal("一个名字都没读到")
	}
	nonASCII := 0
	for _, n := range names {
		if !utf8.ValidString(n) {
			t.Errorf("名字不是合法 UTF-8：%q", n)
		}
		if !isASCII(n) {
			nonASCII++
		}
	}
	if nonASCII == 0 {
		t.Fatal("这个包里没有中文名字，那这条测试什么都没验")
	}
	// 本地文件头：签名后的偏移 6 是 flags
	var localFlags, centralFlags []uint16
	for i := 0; i+4 <= len(raw); i++ {
		switch binary.LittleEndian.Uint32(raw[i:]) {
		case 0x04034b50: // 本地文件头
			if i+30 <= len(raw) {
				localFlags = append(localFlags, binary.LittleEndian.Uint16(raw[i+6:]))
			}
		case 0x02014b50: // 中心目录头
			if i+46 <= len(raw) {
				centralFlags = append(centralFlags, binary.LittleEndian.Uint16(raw[i+8:]))
			}
		}
	}
	if len(localFlags) != len(centralFlags) {
		t.Fatalf("本地头 %d 个、中心目录头 %d 个，对不上", len(localFlags), len(centralFlags))
	}
	for i, f := range localFlags {
		if f&0x800 == 0 {
			t.Errorf("第 %d 个本地文件头没置 UTF-8 位（flags=0x%04x）：%s", i, f, names[i])
		}
	}
	for i, f := range centralFlags {
		if f&0x800 == 0 {
			t.Errorf("第 %d 个中心目录头没置 UTF-8 位（flags=0x%04x）：%s", i, f, names[i])
		}
	}
	// 反证：名字里不许有 GBK 残留 —— GBK 的「诊」是 0xD5 0xEF，不是合法 UTF-8 起始序列，
	// 上面的 utf8.ValidString 已经挡住；这一条再确认解压出来的中文和写进去的一模一样。
	want := "NetKit 诊断包 金宇建安-盒1/01 本机/网卡.txt"
	found := false
	for _, n := range names {
		if n == want {
			found = true
		}
	}
	if !found {
		t.Errorf("包里没有 %q，实际名字：%#v", want, names)
	}
}

func Test清单排在最前面(t *testing.T) {
	dir := t.TempDir()
	res, err := Build(dir, hdr("x"), secs())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) < 2 {
		t.Fatalf("条目太少：%v", res.Entries)
	}
	first := res.Entries[0]
	if !strings.HasSuffix(first, manifestName) {
		t.Errorf("解压第一眼看到的应该是清单，实际是 %q", first)
	}
	text := readEntry(t, res.Path, first)
	for _, want := range []string{"NetKit 诊断包", "2026-09-25", "机器名：eng-laptop",
		"发出去就等于把这些信息给了对方", "已经抹掉", "这台没有 v6 地址", "gateway-loss", "没读出来"} {
		if !strings.Contains(text, want) {
			t.Errorf("清单里少了 %q：\n%s", want, text)
		}
	}
	if strings.Contains(text, "**") {
		t.Errorf("清单是给人在记事本里看的，不该有手抄记号（工具判定里的 ** 要洗掉）：\n%s", text)
	}
	if !strings.Contains(text, "这一段不能当「没有」") {
		t.Errorf("洗星号把内容也洗掉了：\n%s", text)
	}
	// 判定码那一段要能看出顺序：iface 在 gateway 前面（排查顺序，不是字母序）
	if strings.Index(text, "iface-ok") > strings.Index(text, "gateway-loss") {
		t.Error("清单里项的顺序被打乱了：诊断包也要保住排查顺序")
	}
}

// Test读不到的项也要进包 安静地少一个文件，远程的人会判成「这台没配」；
// 写一行「这项读不到，因为…」，他才知道是没权限、没这个功能、还是真的没有。
func Test读不到的项也要进包(t *testing.T) {
	dir := t.TempDir()
	s := append(secs(), Section{Name: "01 本机/邻居表.txt",
		Text:    "读不到：这台是 Linux，邻居表要 root 才读得出（ip neighbor 需要 CAP_NET_ADMIN）",
		Missing: true})
	res, err := Build(dir, hdr("x"), s)
	if err != nil {
		t.Fatal(err)
	}
	text := readEntryBySuffix(t, res.Path, "邻居表.txt")
	if !strings.Contains(text, "不要把它当成「这台机器上没有」") {
		t.Errorf("缺项没写明这是「没读出来」而不是「没有」：\n%s", text)
	}
	if !strings.Contains(text, "CAP_NET_ADMIN") {
		t.Error("为什么读不出来的原因得留着")
	}
	man := readEntry(t, res.Path, res.Entries[0])
	if !strings.Contains(man, "邻居表.txt（没读出来）") {
		t.Errorf("清单上没标出这一项没读出来：\n%s", man)
	}
}

// Test包里的路径走不出去 段名会进 zip 的名字字段，而 zip 被解开时**名字就是路径**。
// 放一段 "../" 进去，这个包就变成了一次任意路径写入。
func Test包里的路径走不出去(t *testing.T) {
	dir := t.TempDir()
	bad := []string{
		"../../etc/passwd", "/etc/passwd", "..", "a/../../b",
		"C:\\Windows\\test.txt", "C:/Windows/x.txt", "01 本机/../../escape.txt",
		"", "   ", "a/b/c/d.txt",
	}
	for _, name := range bad {
		_, err := Build(dir, hdr("x"), []Section{{Name: name, Text: "x"}})
		if err == nil {
			t.Errorf("段名 %q 被收下了：它能把文件写到包外面去", name)
		}
	}
	// 合法的写法不能被误杀（每段名字都得不同：重名是要报错的，见下一条测试）
	for i, name := range []string{"网卡.txt", "01 本机/网卡.txt", "01 本机/子目录/路由表", "a-b_c.1.txt"} {
		if _, err := Build(filepath.Join(dir, "ok"), hdr("合法"+itoaTest(i)),
			[]Section{{Name: name, Text: "x"}}); err != nil {
			t.Errorf("合法段名 %q 被拒：%v", name, err)
		}
	}
}

// Test段名撞车要报错，不能后一段顶掉前一段 —— 那种丢法在包里看不出来。
func Test段名撞车要报错(t *testing.T) {
	_, err := Build(t.TempDir(), hdr("x"), []Section{
		{Name: "网卡.txt", Text: "第一版"},
		{Name: " 网卡 ", Text: "第二版"}, // 清洗之后与第一条同名
	})
	if err == nil || !strings.Contains(err.Error(), "都叫") {
		t.Errorf("重名没报错：%v", err)
	}
}

// Test空包与超大包 一个内容都没有 / 段数超上限 / 合计超上限：都要拒绝，不要出一个
// 看起来正常但其实什么都没有的包。
func Test空包与超大包(t *testing.T) {
	if _, err := Build(t.TempDir(), hdr("x"), nil); err == nil {
		t.Error("零段也出了包")
	}
	var many []Section
	for i := 0; i <= MaxSections; i++ {
		many = append(many, Section{Name: "s" + itoaTest(i) + ".txt", Text: "x"})
	}
	if _, err := Build(t.TempDir(), hdr("x"), many); err == nil {
		t.Errorf("超过 %d 段还出包", MaxSections)
	}
}

// Test内容太长要写明截断 撞上限时在包里写明白，不许安静地少内容 ——
// 少内容的诊断包会让远程的人照着「没有」下结论。
func Test内容太长要写明截断(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("这是一行中文内容，用来撑长度。\n", 400)
	res, err := Build(dir, hdr("x"), []Section{
		{Name: "转发表.txt", Text: long, TruncateAt: 256},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := readEntry(t, res.Path, res.Entries[1])
	if !strings.Contains(text, "截断") {
		t.Errorf("截断了却没写：\n%s", tail(text))
	}
	if !strings.Contains(text, "原长 "+itoaTest(len(long))+" 字节") {
		t.Errorf("没写原长多少：%s", tail(text))
	}
	if !utf8.ValidString(text) {
		t.Error("截断把多字节字符劈坏了 —— 劈坏之后整个文件在别的机器上是乱码")
	}
	if len(res.Truncated) != 1 || res.Truncated[0] != "转发表.txt" {
		t.Errorf("Result.Truncated = %v", res.Truncated)
	}
	man := readEntry(t, res.Path, res.Entries[0])
	if !strings.Contains(man, "被截断的节") || !strings.Contains(man, "转发表.txt") {
		t.Errorf("清单里看不出这一节截断过：\n%s", man)
	}
}

// Test脱敏在写包时统一跑一遍 不问每一段是谁写的：漏一次就是漏到公网上。
func Test脱敏在写包时统一跑一遍(t *testing.T) {
	dir := t.TempDir()
	res, err := Build(dir, hdr("x"), []Section{
		{Name: "代理.txt", Text: "proxy = 10.0.0.5:3128\nproxy_password: Pr0xy@2026\n"},
		{Name: "snmp.txt", Text: "命令：snmpwalk -v2c -c NetKit-View-RO 10.0.0.1\n"},
		{Name: "空.txt", Text: ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(res.Path)
	all := string(raw) + strings.Join(entryTexts(t, res.Path), "|")
	for _, leak := range []string{"Pr0xy@2026", "NetKit-View-RO"} {
		if strings.Contains(all, leak) {
			t.Errorf("凭据 %q 原样进了包", leak)
		}
	}
	// 键名与「配了什么」要留着，只抹值
	proxy := readEntry(t, res.Path, res.Entries[1])
	if !strings.Contains(proxy, "proxy = 10.0.0.5:3128") {
		t.Errorf("代理地址被顺手抹了：\n%s", proxy)
	}
	if !strings.Contains(proxy, "proxy_password: ***") {
		t.Errorf("口令该抹成 ***，键名要留：\n%s", proxy)
	}
	// 空内容不能留一个 0 字节的文件：解包的人分不清「空」和「坏了」
	if readEntry(t, res.Path, res.Entries[3]) == "" {
		t.Error("空节写成了 0 字节")
	}
	man := readEntry(t, res.Path, res.Entries[0])
	if !strings.Contains(man, "共抹掉 2 处") {
		t.Errorf("清单里的脱敏计数不对：\n%s", man)
	}
	if got := res.Redactions["键值形式的口令/团体名/令牌"]; got != 1 {
		t.Errorf("Redactions 计数 = %v，要 1（Result 也要带，界面要用）", res.Redactions)
	}
}

// Test同一秒两次不覆盖上一次 上一份可能已经发出去了、或者正在被人解压。
func Test同一秒两次不覆盖上一次(t *testing.T) {
	dir := t.TempDir()
	first, err := Build(dir, hdr("现场"), secs())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(dir, hdr("现场"), secs())
	if err != nil {
		t.Fatal(err)
	}
	if first.Path == second.Path {
		t.Fatalf("两次写到同一个文件：%s", first.Path)
	}
	if _, err := os.Stat(first.Path); err != nil {
		t.Errorf("第一份被顶掉了：%v", err)
	}
	if !strings.Contains(filepath.Base(second.Path), "-2") {
		t.Errorf("第二份该带个 -2，实际 %s", filepath.Base(second.Path))
	}
	// 中间态不能留下：包要么是完整的，要么不在
	left, _ := filepath.Glob(filepath.Join(dir, "*.part"))
	if len(left) > 0 {
		t.Errorf("留下了半截的包：%v", left)
	}
}

// Test文件与目录权限 包里有内网拓扑，落在共享机器上不能人人可读。
func Test文件与目录权限(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上这套权限位不成立")
	}
	dir := t.TempDir()
	res, err := Build(filepath.Join(dir, "深一层", "诊断包"), hdr("x"), secs())
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(filepath.Dir(res.Path)); got != "诊断包" {
		t.Errorf("输出目录没建出来：%s", res.Path)
	}
	st, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if m := st.Mode().Perm(); m != 0o600 {
		t.Errorf("包权限 = %o，要 600（里面有内网拓扑）", m)
	}
}

// Test机读结果可解析 另一个 NetKit 或脚本拿它判，不必读中文。
func Test机读结果可解析(t *testing.T) {
	dir := t.TempDir()
	res, err := Build(dir, hdr("x"), secs())
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, e := range res.Entries {
		if strings.HasSuffix(e, machineReadName) {
			name = e
		}
	}
	if name == "" {
		t.Fatal("没有机读结果")
	}
	var doc struct {
		Kind    string `json:"kind"`
		Created string `json:"created"`
		Files   []struct {
			Name   string `json:"name"`
			Bytes  int    `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		Items []struct {
			Item    string `json:"item"`
			Missing bool   `json:"missing"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(readEntry(t, res.Path, name)), &doc); err != nil {
		t.Fatalf("机读结果解不开：%v", err)
	}
	if doc.Kind != "netkit.diag.bundle" {
		t.Errorf("kind = %q", doc.Kind)
	}
	if len(doc.Items) != 2 || !doc.Items[1].Missing {
		t.Errorf("items 丢了缺项标记：%+v", doc.Items)
	}
	for _, f := range doc.Files {
		if strings.HasSuffix(f.Name, machineReadName) {
			continue
		}
		got := sha256.Sum256([]byte(readEntry(t, res.Path, f.Name)))
		if hex.EncodeToString(got[:]) != f.SHA256 {
			t.Errorf("%s 的摘要对不上：收的人就没法验这个包没被改过", f.Name)
		}
	}
}

// Test包名里的标签要洗过 标签来自用户输入，会变成一个真实存在的文件名。
func Test包名里的标签要洗过(t *testing.T) {
	for _, bad := range []string{"../../x", "a/b", `con`, "nul.txt", "带|管道", "结尾的点."} {
		if got := CleanName(bad); got != "" {
			for _, c := range []string{"/", "\\", ":", "|", "*"} {
				if strings.Contains(got, c) {
					t.Errorf("CleanName(%q) = %q，还留着 %q", bad, got, c)
				}
			}
			if strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") {
				t.Errorf("CleanName(%q) = %q：结尾的点或空格会被 Windows 吃掉", bad, got)
			}
		}
	}
	if got := CleanName("金宇建安 盒 1"); got != "金宇建安 盒 1" {
		t.Errorf("正常中文名被改了：%q", got)
	}
	if got := CleanName("con"); got != "" {
		t.Errorf("Windows 保留名没清掉：%q", got)
	}
	// 标签被洗过之后，包名里也就只剩安全字符
	dir := t.TempDir()
	res, err := Build(dir, hdr("../恶意/../标签"), secs())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filepath.Base(res.Path), "..") {
		t.Errorf("包名里有 ..：%s", res.Path)
	}
	if filepath.Dir(res.Path) != dir {
		t.Errorf("包写到指定目录外面去了：%s", res.Path)
	}
}

// Test压缩包能被标准库读回来 用 archive/zip 自己解一遍：解不回来就等于现场解不开。
func Test压缩包能被标准库读回来(t *testing.T) {
	dir := t.TempDir()
	res, err := Build(dir, hdr("x"), secs())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(res.Path)
	if err != nil {
		t.Fatalf("标准库解不开这个包：%v", err)
	}
	defer zr.Close()
	var dirs, files int
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			dirs++
			continue
		}
		files++
	}
	if dirs == 0 {
		t.Error("没有目录条目：老资源管理器会把层级挤平，看起来像少了文件夹")
	}
	if files != len(secs())+2 {
		t.Errorf("文件数 = %d，要 %d", files, len(secs())+2)
	}
}

// TestDefaultDir落在自己的目录里 不覆盖别人、也不落在配置目录根上。
func TestDefaultDir落在自己的目录里(t *testing.T) {
	got, err := DefaultDir()
	if err != nil {
		t.Skipf("这台机器拿不到用户配置目录：%v", err)
	}
	if filepath.Base(got) != "诊断包" || filepath.Base(filepath.Dir(got)) != "yuhox-netkit" {
		t.Errorf("DefaultDir = %q，要在 yuhox-netkit/诊断包", got)
	}
}

func Test摘要函数自己先算对(t *testing.T) {
	// cutAtRune：劈在汉字中间时往后退到字符边界
	s := "中文abc"
	got := cutAtRune(s, 4) // 「中」占 3 字节，第 4 字节是半个「文」
	if got != "中" || !utf8.ValidString(got) {
		t.Errorf("cutAtRune(中文abc, 4) = %q", got)
	}
	if cutAtRune("abc", 10) != "abc" {
		t.Error("没超长时不该动")
	}
}

// ── 小工具 ──

func zipNames(t *testing.T, raw []byte) []string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("解不开：%v", err)
	}
	var out []string
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	return out
}

// readEntryBySuffix 按结尾找条目，不数下标 —— 下标会把「加了个目录条目」这类改动
// 变成一堆假失败。
func readEntryBySuffix(t *testing.T, path, suffix string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, suffix) {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(rc); err != nil {
				t.Fatal(err)
			}
			return buf.String()
		}
	}
	t.Fatalf("包里没有以 %q 结尾的条目", suffix)
	return ""
}

func readEntry(t *testing.T, path, name string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	t.Fatalf("包里没有 %q", name)
	return ""
}

func entryTexts(t *testing.T, path string) []string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var out []string
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		out = append(out, readEntry(t, path, f.Name))
	}
	return out
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func tail(s string) string {
	if len(s) > 120 {
		s = s[len(s)-120:]
	}
	return s
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
