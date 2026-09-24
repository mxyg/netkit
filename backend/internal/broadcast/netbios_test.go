package broadcast

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// ── NetBIOS（RFC 1002）：这一路是唯一能拿到 MAC 的，所以逐字节盯紧 ──

func Test名字编码照RFC的样例(t *testing.T) {
	// RFC 1002 §1 给的样例：NetBIOS 名 "FRED" 加服务编号 0x20（16 字节，右侧空格补齐）
	// 编成 32 个字符 EGFCEFEECACACACACACACACACACACACA。
	got, err := encodeNBName("FRED", 0x20)
	if err != nil {
		t.Fatal(err)
	}
	const want = "EGFCEFEECACACACACACACACACACACACA"
	if string(got[1:]) != want {
		t.Errorf("编码 =\n%s\n要\n%s", got[1:], want)
	}
	if got[0] != 0x20 {
		t.Errorf("长度字节是 %#x，编码名固定 32 个字符", got[0])
	}
	name, suffix, err := decodeNBName(got[1:])
	if err != nil {
		t.Fatal(err)
	}
	if name != "FRED" || suffix != 0x20 {
		t.Errorf("解回 %q %#x", name, suffix)
	}
}

func qtype2(t uint16) []byte {
	var b [4]byte
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], classIN)
	return b[:]
}

func Test通配符问法是星号加十五个空格(t *testing.T) {
	// NODE STATUS 用通配符名（'*' + 15 个空格），这是 nbtstat -A 的问法。
	// 用具体名字问只会拿到那一个名，MAC 也就跟着丢了。
	msg, err := NodeStatusRequest(0x1234)
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 12)
	binary.BigEndian.PutUint16(head[0:2], 0x1234)
	binary.BigEndian.PutUint16(head[4:6], 1)
	if string(msg[:12]) != string(head) {
		t.Errorf("头部：\n% x\n要\n% x", msg[:12], head)
	}
	if msg[12] != 0x20 {
		t.Errorf("长度字节 %#x", msg[12])
	}
	// '*'=0x2A → C(2) K(10)；后面 15 个空格 → 15 段 "CA"
	if string(msg[13:15]) != "CK" {
		t.Errorf("通配符的首段是 %q，要 CK", msg[13:15])
	}
	if string(msg[15:45]) != strings.Repeat("CA", 15) {
		t.Errorf("补齐不对：%q", msg[15:45])
	}
	if string(msg[45:]) != string(qtype2(nbStatus)) {
		t.Errorf("问题尾：% x（类型要 NBSTAT=0x0021）", msg[45:])
	}
	if len(msg) != 49 {
		t.Errorf("整条 %d 字节", len(msg))
	}
}

func Test名字长度与点号要报错(t *testing.T) {
	if _, err := encodeNBName("abcdefghijklmnop", 0); err == nil {
		t.Error("16 个字符超过 15 的上限，要报错")
	}
	// 点号在 DNS 那一层是标签分隔符，编进去就解不回来了：宁可报错，不静默改写。
	if _, err := encodeNBName("PC.一楼", 0); err == nil || !strings.Contains(err.Error(), "有点") {
		t.Errorf("带点的名要说清楚：%v", err)
	}
	if _, _, err := decodeNBName([]byte("0123456789")); err == nil {
		t.Error("长度不对要报错")
	}
	if _, _, err := decodeNBName([]byte(strings.Repeat("z", 32))); err == nil {
		t.Error("不在 A-P 范围内的编码要报错，不许硬解成乱码")
	}
	// 中文名按**字节**算上限（15 字节），不许默默截。
	if _, err := encodeNBName(strings.Repeat("长", 8), 0); err == nil {
		t.Error("超 15 字节的中文名要报错")
	}
}

// nbResp 按 RFC 1002 §4.2.18 的布局拼一条 NODE STATUS 应答。
//
// claim 是写在 RDLENGTH 位置上的 NUM_NAMES：故意让它和 names 里的整条数不一致，
// 才测得出「报数撒谎」与「数组被截断」这两种现场都会碰到的情况。
type nbResp struct {
	question bool // 是否把问题段回声回来（QDCOUNT=1）
	names    []byte
	claim    int
	mac      []byte
	stats    int  // 统计段除 MAC 之外再凑几字节
	noType   bool // 把 RR 类型改写成 A：不是 NBSTAT 应答
}

func (r nbResp) bytes() []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], 0x1234)
	h[2] |= 0x80 // QR=1：这是应答
	h[3] |= 0x10 // RD
	if r.question {
		binary.BigEndian.PutUint16(h[4:6], 1)
	}
	binary.BigEndian.PutUint16(h[6:8], 1) // ANCOUNT=1：一条 NBSTAT RR
	b := append([]byte{}, h...)
	if r.question {
		b = append(b, encName("*", 0x20)...)
		b = append(b, qtype2(nbStatus)...)
	}
	b = append(b, encName("*", 0x20)...)
	var fixed [10]byte
	if r.noType {
		binary.BigEndian.PutUint16(fixed[0:2], typeA)
	} else {
		binary.BigEndian.PutUint16(fixed[0:2], nbStatus)
	}
	binary.BigEndian.PutUint16(fixed[2:4], classIN)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(r.claim))
	b = append(b, fixed[:]...)
	b = append(b, r.names...)
	b = append(b, r.mac...)
	for i := 0; i < r.stats/2; i++ {
		b = append(b, 0, byte(i)) // 往下依次是 JUMPERS、TEST_RESULT…
	}
	return b
}

// encName 带长度字节的 32 字符编码名。
func encName(name string, suffix byte) []byte {
	e, err := encodeNBName(name, suffix)
	if err != nil {
		panic(err)
	}
	return e
}

// nameEntry 一条「32 字符编码名 + 2 字节 NAME_FLAGS」。
func nameEntry(name string, suffix byte, flags uint16) []byte {
	out := append([]byte{}, encName(name, suffix)[1:]...)
	var f [2]byte
	binary.BigEndian.PutUint16(f[:], flags)
	return append(out, f[:]...)
}

func Test节点状态应答把名字和MAC一起带回来(t *testing.T) {
	const active = 0x0400 // ACT 置位、ONT=00（B 节点）、唯一名
	var names []byte
	names = append(names, nameEntry("OFFICE-PC", 0x00, active)...)
	names = append(names, nameEntry("OFFICE-PC", 0x20, active)...)
	names = append(names, nameEntry("WORKGROUP", 0x00, 0x8000|active)...) // 组名
	r := nbResp{names: names, claim: 3,
		mac: []byte{0xa4, 0x5e, 0x60, 0x11, 0x22, 0x33}, stats: 22}

	got, err := ParseNodeStatus(r.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Names) != 3 {
		t.Fatalf("读到 %d 个名：%+v", len(got.Names), got.Names)
	}
	if got.Names[0].Name != "OFFICE-PC" || got.Names[0].Suffix != 0 {
		t.Errorf("第一个名：%+v", got.Names[0])
	}
	if !got.Names[0].Active {
		t.Error("ACT 位在整字第 10 位（RFC 那张图的位号从左边数），没认出来")
	}
	if got.Names[0].Owner != "B" {
		t.Errorf("ONT 两位全 0 是 B 节点，得到 %q", got.Names[0].Owner)
	}
	if got.Names[0].Service != "计算机名（工作站服务）" {
		t.Errorf("服务编号没翻：%q", got.Names[0].Service)
	}
	if got.Names[1].Service != "服务器服务（这台开了文件与打印共享）" {
		t.Errorf("<20> 没翻对：%q", got.Names[1].Service)
	}
	if !got.Names[2].Group || got.Names[2].Service != "这台机器所属的工作组/域名" {
		t.Errorf("组名那条：%+v", got.Names[2])
	}
	// ★ 这一条是整个工具存在的理由：MAC 来自统计段的 UNIT_ID。
	if got.MAC != "a4:5e:60:11:22:33" {
		t.Errorf("MAC = %q，要 a4:5e:60:11:22:33", got.MAC)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\ufffd") {
		t.Error("MAC 是裸字节转成的字符串，进 JSON 会变成一串替换符")
	}
	if got.Jumpers != 0 || got.Tests != 1 {
		t.Errorf("统计段的跳数/测试结果：%d %d", got.Jumpers, got.Tests)
	}
}

func Test三种节点类型翻得出来(t *testing.T) {
	for _, c := range []struct {
		bits uint16
		want string
	}{{0x0000, "B"}, {0x2000, "P"}, {0x4000, "M"}, {0x6000, ""}} {
		if got := ownerNode(c.bits); got != c.want {
			t.Errorf("ONT %#x = %q，要 %q", c.bits, got, c.want)
		}
	}
}

func Test问题段带回来也照样解(t *testing.T) {
	// 有的实现把我们发出去的问题原样回声一遍（QDCOUNT=1）：位置要跟着挪，不然全错。
	r := nbResp{question: true, names: nameEntry("NAS", 0x00, 0x0400), claim: 1,
		mac: []byte{1, 2, 3, 4, 5, 6}}
	ns, err := ParseNodeStatus(r.bytes())
	if err != nil {
		t.Fatalf("带了问题段的解不出来：%v", err)
	}
	if len(ns.Names) != 1 || ns.Names[0].Name != "NAS" {
		t.Errorf("%+v", ns.Names)
	}
	if ns.MAC != "01:02:03:04:05:06" {
		t.Errorf("MAC=%q", ns.MAC)
	}
}

func Test查询与坏应答不许当成一台机器(t *testing.T) {
	req, _ := NodeStatusRequest(1)
	if _, err := ParseNodeStatus(req); err != ErrNotNetBIOS {
		t.Errorf("自己发出去的查询给了 %v，要按不是应答处理", err)
	}
	if _, err := ParseNodeStatus([]byte{1, 2, 3}); err != ErrNotNetBIOS {
		t.Errorf("短报文：%v", err)
	}
	// 名字条数写得离谱（一条应答里 5000 个名）：卡住，不许照着这个数循环。
	lie := nbResp{names: nameEntry("X", 0, 0x0400), claim: 5000, mac: []byte{0, 0, 0, 0, 0, 1}}
	if _, err := ParseNodeStatus(lie.bytes()); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Errorf("名字条数没卡住：%v", err)
	}
	// 一个名都没写：那不是一个能用的结果。
	empty := nbResp{claim: 0, mac: []byte{0, 0, 0, 0, 0, 0}}
	if _, err := ParseNodeStatus(empty.bytes()); err != ErrNotNetBIOS {
		t.Errorf("零个名的应答给了 %v", err)
	}
	// RR 类型不是 NBSTAT：不是我们要解的那种应答。
	wrong := nbResp{names: nameEntry("X", 0, 0x0400), claim: 1, mac: []byte{0, 0, 0, 0, 0, 1}, noType: true}
	if _, err := ParseNodeStatus(wrong.bytes()); err != ErrNotNetBIOS {
		t.Errorf("类型不对的应答给了 %v", err)
	}
}

func Test名字数组被截断时留着已经读到的(t *testing.T) {
	names := nameEntry("A-PC", 0x00, 0x0400)
	names = append(names, nameEntry("B-PC", 0x00, 0x0400)...)
	names = append(names, nameEntry("C-PC", 0x00, 0x0400)[:20]...) // 第三条只写了 20 字节
	r := nbResp{names: names, claim: 3, mac: []byte{9, 9, 9, 9, 9, 9}}
	ns, err := ParseNodeStatus(r.bytes())
	if err != nil {
		t.Fatalf("断在后半个名上不该整条丢：%v", err)
	}
	if len(ns.Names) != 2 {
		t.Fatalf("读到 %d 个名", len(ns.Names))
	}
	// ★ 名数组没读完 → 统计段的位置量不出来。这时候给出去的 MAC 其实是
	//   「半个名的头 6 个字节」，看着像个 MAC，拿去查交换机口就查错端口了，所以必须空着。
	if ns.MAC != "" {
		t.Errorf("位置算不准时 MAC 不许瞎给：%q", ns.MAC)
	}
}

func Test服务编号只翻公开定义过的(t *testing.T) {
	if got := nbServiceName(0x20, false); !strings.Contains(got, "文件与打印共享") {
		t.Errorf("<20>：%q", got)
	}
	if got := nbServiceName(0x1C, true); !strings.Contains(got, "域控制器组") {
		t.Errorf("<1C> 组名：%q", got)
	}
	// 没定义的号不许编一个名字出来：人会因为这个名字去查错的方向。
	got := nbServiceName(0x77, false)
	if !strings.Contains(got, "0x77") || !strings.Contains(got, "没有对得上的公开定义") {
		t.Errorf("未定义的号写成：%q", got)
	}
}

func TestMAC写成小写冒号形式(t *testing.T) {
	if got := macString([]byte{0xFF, 0x0A, 0x00, 0x1B, 0xCD, 0xEF}); got != "ff:0a:00:1b:cd:ef" {
		t.Errorf("%q", got)
	}
	if got := macString([]byte{1, 2, 3}); got != "" {
		t.Errorf("不是六个字节要空，得到 %q", got)
	}
}

func Test名字查询请求也编得出去(t *testing.T) {
	msg, err := NameQueryRequest(0xABCD, "SERVER-01", 0x20)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(msg[0:2]) != 0xABCD {
		t.Error("事务号没写进去（应答要照它配对）")
	}
	name, suffix, err := decodeNBName(msg[13:45])
	if err != nil {
		t.Fatal(err)
	}
	if name != "SERVER-01" || suffix != 0x20 {
		t.Errorf("问出去的名字 round-trip 成了 %q %#x", name, suffix)
	}
	if _, err := NameQueryRequest(1, "名字太长装不下的一台设备", 0); err == nil {
		t.Error("装不下的名字要报错，不许默默截半")
	}
}
