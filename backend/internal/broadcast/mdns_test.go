package broadcast

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// ── 造报文的小工具：偏移一律用 len() 算，不手填数字（手填的错位看不出错）──

func hdr(qd, an, ns, ar int, response bool) []byte {
	h := make([]byte, 12)
	if response {
		h[2] |= 0x80
	}
	binary.BigEndian.PutUint16(h[4:6], uint16(qd))
	binary.BigEndian.PutUint16(h[6:8], uint16(an))
	binary.BigEndian.PutUint16(h[8:10], uint16(ns))
	binary.BigEndian.PutUint16(h[10:12], uint16(ar))
	return h
}

// flat 把名字按标签展开写（不用压缩）。
func flat(name string) []byte {
	var b []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// one 只写一个标签（不带结尾的 0），用来拼「一段展开 + 一段指针」的名字。
func one(label string) []byte {
	return append([]byte{byte(len(label))}, label...)
}

// ptr 写一个指向 off 的压缩指针。
func ptr(off int) []byte { return []byte{0xC0 | byte(off>>8), byte(off)} }

func qtype(t, class uint16) []byte {
	var b [4]byte
	binary.BigEndian.PutUint16(b[0:2], t)
	binary.BigEndian.PutUint16(b[2:4], class)
	return b[:]
}

func rdata(typ, class uint16, ttl uint32, body []byte) []byte {
	var h [10]byte
	binary.BigEndian.PutUint16(h[0:2], typ)
	binary.BigEndian.PutUint16(h[2:4], class)
	binary.BigEndian.PutUint32(h[4:8], ttl)
	binary.BigEndian.PutUint16(h[8:10], uint16(len(body)))
	return append(h[:], body...)
}

func txtRdata(entries ...string) []byte {
	var b []byte
	for _, e := range entries {
		b = append(b, byte(len(e)))
		b = append(b, e...)
	}
	return b
}

func Test查询里问的是PTR并且能要求单播回(t *testing.T) {
	msg, err := MDNSQuery([]string{"_rtsp._tcp.local"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) < 12 {
		t.Fatal("太短")
	}
	if flags := binary.BigEndian.Uint16(msg[2:4]); flags&0x8000 != 0 {
		t.Error("查询不许把 QR 位置成应答")
	}
	if qd := binary.BigEndian.Uint16(msg[4:6]); qd != 1 {
		t.Errorf("QDCOUNT=%d", qd)
	}
	body := msg[12:]
	want := string(flat("_rtsp._tcp.local")) + string(qtype(typePTR, classIN|bitUnicast))
	if string(body) != want {
		t.Errorf("查询体不对：\n% x\n要\n% x", body, want)
	}
	// ★ QU 位没置的话，设备会把应答组播出去，而我们这个临时端口收不收得到看运气。
	if cl := binary.BigEndian.Uint16(msg[len(msg)-2:]); cl&0x8000 == 0 {
		t.Error("要单播回时类的最高位没置")
	}
	m2, err := MDNSQuery([]string{"_smb._tcp.local"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if cl := binary.BigEndian.Uint16(m2[len(m2)-2:]); cl != classIN {
		t.Errorf("不要求单播时类要干净，得到 %#x", cl)
	}
	if _, err := MDNSQuery(nil, true); err == nil {
		t.Error("一个类型都不问，等于什么都没问，要报错")
	}
	// 只带一个类型，但给 100 个：截到上限，不许无限涨。
	many := make([]string, 100)
	for i := range many {
		many[i] = "_t" + strconv.Itoa(i) + "._tcp.local"
	}
	big, err := MDNSQuery(many, true)
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.BigEndian.Uint16(big[4:6]); n != 32 {
		t.Errorf("一次问 %d 个类型，要截到 32", n)
	}
}

func Test名字编码守住标签上限(t *testing.T) {
	got, err := EncodeName("_rtsp._tcp.local.")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(flat("_rtsp._tcp.local")) {
		t.Errorf("编码不对：% x", got)
	}
	if got, err := EncodeName(""); err != nil || string(got) != "\x00" {
		t.Errorf("空名要写成根标签：% x %v", got, err)
	}
	if _, err := EncodeName("a..b"); err == nil {
		t.Error("空标签要报错（写出去就解不回来）")
	}
	if _, err := EncodeName(strings.Repeat("长", 40) + ".local"); err == nil {
		t.Error("超过 63 字节的标签要报错")
	}
}

// 一条真实的设备应答：问题段里写全名，应答段几乎全用指针。
//
// ★ 盯住四件事：指针跟法、跟完指针之后**继续解析的位置**、cache-flush 位、一段里多条记录。
func Test应答里的压缩指针按RFC跟(t *testing.T) {
	m := hdr(1, 2, 0, 1, true)
	qOff := len(m) // 问题段里那个完整名的起始偏移
	m = append(m, flat("_rtsp._tcp.local")...)
	m = append(m, qtype(typePTR, classIN)...)

	// answer 1：实例名「3楼球机」+ 指针指回服务类型。
	// 这一条专盯 resume：跟完指针之后，后面的固定部分必须按「指针占 2 字节」算。
	// 按指针指向的位置算，TTL 与 RDLENGTH 就会读到服务类型名的字节上去。
	m = append(m, one("3楼球机")...)
	m = append(m, ptr(qOff)...)
	m = append(m, rdata(typePTR, classIN, 120, ptr(qOff))...)

	// answer 2：名字整段就是一个指针，类字段最高位是 cache-flush。
	m = append(m, ptr(qOff)...)
	m = append(m, rdata(typePTR, classIN|bitCache, 120, flat("另一台._rtsp._tcp.local"))...)

	// additional：主机名 -> A。
	m = append(m, flat("cam3.local")...)
	m = append(m, rdata(typeA, classIN, 120, []byte{10, 0, 12, 77})...)

	parsed, err := ParseMDNS(m)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Response {
		t.Error("应答的 QR 位没认出来")
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Name != "_rtsp._tcp.local" {
		t.Errorf("问题段：%+v", parsed.Questions)
	}
	if len(parsed.Answers) != 2 {
		t.Fatalf("应答 %d 条", len(parsed.Answers))
	}
	if parsed.Answers[0].Name != "3楼球机._rtsp._tcp.local" {
		t.Errorf("第一条名字：%q", parsed.Answers[0].Name)
	}
	if p, ok := parsed.Answers[0].Data.(PTRName); !ok || p.Target != "_rtsp._tcp.local" {
		t.Errorf("指针指向的目标没跟对：%#v", parsed.Answers[0].Data)
	}
	if parsed.Answers[0].TTL != 120 {
		t.Errorf("跟完指针之后位置错了，TTL 读到 %d", parsed.Answers[0].TTL)
	}
	if parsed.Answers[1].Name != "_rtsp._tcp.local" {
		t.Errorf("第二条用指针的名字：%q", parsed.Answers[1].Name)
	}
	if !parsed.Answers[1].CacheFlush {
		t.Error("cache-flush 位没认出来（那是「之前缓存的这条作废」，不是类型）")
	}
	if parsed.Answers[1].Class != classIN {
		t.Errorf("类要把最高位摘掉，得到 %#x", parsed.Answers[1].Class)
	}
	if len(parsed.Additional) != 1 {
		t.Fatalf("补充段 %d 条", len(parsed.Additional))
	}
	a, ok := parsed.Additional[0].Data.(Addr)
	if !ok || a.Addr != "10.0.12.77" {
		t.Errorf("A 记录：%#v", parsed.Additional[0].Data)
	}
	if parsed.Additional[0].TTL != 120 {
		t.Errorf("TTL=%d", parsed.Additional[0].TTL)
	}
}

func Test指针链两级跳与向前指针(t *testing.T) {
	m := hdr(2, 1, 0, 0, true)
	q1 := len(m)
	m = append(m, flat("_rtsp._tcp.local")...) // q1+1+5 = 18 是 "_tcp" 那一段
	m = append(m, qtype(typePTR, classIN)...)
	q2 := len(m)
	m = append(m, one("printer")...) // 「printer」 + 指针 = 两段拼出来的名字
	tcpOff := q1 + 1 + len("_rtsp")
	m = append(m, ptr(tcpOff)...) // 二段跳：answer -> q2 -> q1 内部
	m = append(m, qtype(typePTR, classIN)...)
	m = append(m, ptr(q2)...)
	m = append(m, rdata(typePTR, classIN, 60, ptr(q1))...)

	parsed, err := ParseMDNS(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Questions[1].Name; got != "printer._tcp.local" {
		t.Errorf("跨了两级指针之后名字不对：%q", got)
	}
	if p, ok := parsed.Answers[0].Data.(PTRName); !ok || p.Target != "_rtsp._tcp.local" {
		t.Errorf("RDATA 里的指针没跟对：%#v", parsed.Answers[0].Data)
	}
	if parsed.Answers[0].Name != "printer._tcp.local" {
		t.Errorf("应答名：%q", parsed.Answers[0].Name)
	}
}

func Test坏指针按坏包处理不转不完(t *testing.T) {
	// 指针指向自己：跟下去就是无限循环，所以必须往回指。
	self := append(hdr(0, 1, 0, 0, true), ptr(12)...)
	self = append(self, rdata(typePTR, classIN, 1, []byte{0})...)
	if _, err := ParseMDNS(self); err != ErrNotMDNS {
		t.Errorf("自指指针给了 %v，要按坏包丢", err)
	}
	// 指针指向另一个指针，另一个再指回来。
	back := hdr(0, 1, 0, 0, true) // 12
	back = append(back, 0xC0, 13) // 指向 13
	back = append(back, 0xC0, 12) // 再指回 12
	if _, err := ParseMDNS(back); err != ErrNotMDNS {
		t.Errorf("互相指给了 %v", err)
	}
	// 指向报文之外。
	out := append(hdr(0, 1, 0, 0, true), ptr(9999)...)
	if _, err := ParseMDNS(out); err != ErrNotMDNS {
		t.Errorf("越界指针给了 %v", err)
	}
	// 保留的标签类型（0x40 开头）。
	reserved := append(hdr(0, 1, 0, 0, true), 0x40, 0x01, 'x')
	if _, err := ParseMDNS(reserved); err == nil || !strings.Contains(err.Error(), "保留") {
		t.Errorf("保留标签类型要说得出来：%v", err)
	}
	// 太短的不算 DNS。
	if _, err := ParseMDNS([]byte{1, 2, 3}); err != ErrNotMDNS {
		t.Errorf("短报文给了 %v", err)
	}
	// 段数写得离谱：不许照着这个数去循环。
	fake := hdr(70000, 0, 0, 0, false)
	if _, err := ParseMDNS(fake); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Errorf("段数没卡住：%v", err)
	}
}

func Test记录读到一半断了前面的仍然有用(t *testing.T) {
	m := hdr(0, 3, 0, 0, true)
	m = append(m, flat("a.local")...)
	m = append(m, rdata(typeA, classIN, 60, []byte{10, 0, 0, 1})...)
	m = append(m, flat("b.local")...)
	// SRV 的 RDATA：优先级 2 字节 + 权重 2 字节 + 端口 2 字节 + 目标名（这里用指针指回第 12 字节的 a.local）
	srvBody := append([]byte{0, 0, 0, 0, 0, 80}, ptr(12)...)
	m = append(m, rdata(typeSRV, classIN, 60, srvBody)...)
	// 第三条只写了一半就断：设备发 MTU 边缘的报文时真会这样。
	m = append(m, flat("c.local")...)
	m = append(m, 0x00, 0x01)

	parsed, err := ParseMDNS(m)
	if err != nil {
		t.Fatalf("后面读不动了不该把前面的丢掉：%v", err)
	}
	if len(parsed.Answers) != 2 {
		t.Fatalf("读到 %d 条：%+v", len(parsed.Answers), parsed.Answers)
	}
	if a, ok := parsed.Answers[0].Data.(Addr); !ok || a.Addr != "10.0.0.1" {
		t.Errorf("第一条：%#v", parsed.Answers[0].Data)
	}
	if s, ok := parsed.Answers[1].Data.(SRV); !ok || s.Port != 80 {
		t.Errorf("第二条：%#v", parsed.Answers[1].Data)
	}
}

func TestSRV与TXT把端口和型号带回来(t *testing.T) {
	m := hdr(0, 2, 0, 0, true)
	m = append(m, flat("cam._rtsp._tcp.local")...)
	srv := []byte{0, 0, 0, 1, 0x1F, 0x90} // 优先级 0、权重 1、端口 8080
	srv = append(srv, flat("cam.local")...)
	m = append(m, rdata(typeSRV, classIN, 120, srv)...)
	m = append(m, flat("cam._rtsp._tcp.local")...)
	m = append(m, rdata(typeTXT, classIN, 120,
		txtRdata("txtvers=1", "model=RST-3200", "备注", "novalue"))...)

	parsed, err := ParseMDNS(m)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := parsed.Answers[0].Data.(SRV)
	if !ok {
		t.Fatalf("SRV 没解出来：%#v", parsed.Answers[0].Data)
	}
	if s.Port != 8080 || s.Weight != 1 || s.Target != "cam.local" {
		t.Errorf("SRV：%+v（目标名要从 RDATA 第 6 个字节起读）", s)
	}
	tx, ok := parsed.Answers[1].Data.(TXT)
	if !ok {
		t.Fatalf("TXT 没解出来：%#v", parsed.Answers[1].Data)
	}
	if tx.Values["model"] != "RST-3200" || tx.Values["txtvers"] != "1" {
		t.Errorf("key=value 没拆开：%v", tx.Values)
	}
	if len(tx.Entries) != 4 {
		t.Errorf("原样留着的条目丢了：%v", tx.Entries)
	}
	if tx.Values["备注"] != "" {
		t.Errorf("没有 = 的条目不该进键值：%v", tx.Values)
	}
	// 声明的长度比报文长：不许 panic，也不许读到别人的字节里去。
	short := hdr(0, 1, 0, 0, true)
	short = append(short, flat("x.local")...)
	var h [10]byte
	binary.BigEndian.PutUint16(h[0:2], typeTXT)
	binary.BigEndian.PutUint16(h[8:10], 900) // 谎报 900 字节
	short = append(short, h[:]...)
	if _, err := ParseMDNS(short); err != nil {
		t.Errorf("谎报长度的要按读不全处理，给了 %v", err)
	}
}

func TestTXT长度字节撒谎时不许越界(t *testing.T) {
	// 第一个条目声明 200 字节，实际只剩 6 个：剩下的内容原样留下一条，不许读出报文。
	got := parseTXT([]byte{200, 'a', 'b', 'c', 'd', 'e', 'f'})
	if len(got.Entries) != 1 || got.Entries[0] != "abcdef" {
		t.Errorf("%v", got.Entries)
	}
}

func Test实例名与服务类型分开取(t *testing.T) {
	inst, svc := ServiceName("3楼球机._rtsp._tcp.local")
	if inst != "3楼球机" || svc != "_rtsp._tcp.local" {
		t.Errorf("拆错：inst=%q svc=%q", inst, svc)
	}
	if i, s := ServiceName("_rtsp._tcp.local"); i != "" || s != "_rtsp._tcp.local" {
		t.Errorf("光有服务类型时：%q %q", i, s)
	}
	if i, s := ServiceName("no-service-name"); i != "no-service-name" || s != "" {
		t.Errorf("没有服务段时要把整段当名字：%q %q", i, s)
	}
	if TypeLabel(typeSRV) != "SRV" || TypeLabel(99) != "类型 99" {
		t.Error("记录类型的词不对")
	}
}

func TestAAAA地址写成压缩形式(t *testing.T) {
	raw := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if got := ipString(raw); got != "2001:db8::1" {
		t.Errorf("v6 写成 %q，要压缩形式（现场要拿去和别的页面对）", got)
	}
	if got := ipString([]byte{1, 2, 3}); got != "" {
		t.Errorf("长度不对要空，得到 %q", got)
	}
}
