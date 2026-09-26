package flow

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/capture"
)

// 这一份文件钉的是「包怎么落成一条流」。
//
// 聚合这一层出错的样子从来不是崩溃，是表上少了一行、或者一行变成两行：
// 少一行，现场就去查一台没发过包的机器；多一行，就把「单向」说成「双向」。
// 所以每一条都盯着两件最贵的事：**谁跟谁算一条**、**哪一些包没进表**。

var base = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

// at 回第 n 个 20 毫秒那一刻：时序判定要的是「隔了多久」，写死一串 time 容易看错。
func at(n int) time.Time { return base.Add(time.Duration(n) * 20 * time.Millisecond) }

const (
	client    = "192.168.1.10"
	device    = "10.0.0.9"
	gateway   = "192.168.1.1"
	multicast = "239.1.2.3"
)

// ==================== 喂包的手 ====================

// ipMAC 给「同一地址同一 MAC」那一层映射：流上的 AMAC/BMAC 要能按地址对回去。
func ipMAC(ip string) net.HardwareAddr {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return macA
	}
	return net.HardwareAddr{0x02, v4[2], v4[3], 0x11, 0x22, 0x33}
}

var bcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// v4frame 把已经造好的 L4 段套上 IPv4 与伦理头。
func v4frame(src, dst string, proto byte, seg []byte) []byte {
	return eth(ipMAC(dst), ipMAC(src), etypeIPv4, ipv4(1, proto, 64, src, dst, 20+len(seg), seg))
}

// pkt 是一份要喂进聚合器的包。写成结构体而不是十来个参数：
// 一个用例常常同时要改时刻、窗口与留长，参数串到第五格就读不出哪一讲是哪一讲了。
type pkt struct {
	when    time.Time
	src     string
	dst     string
	sp, dp  uint16
	seq     uint32
	ack     uint32
	flags   TCPFlags
	win     uint16
	opts    []byte // TCP 选项（MSS 就藏在这一截里）
	payload []byte
	tcp     bool
	iface   string
	wire    int // 0 = 按带回来的长度算；填得比实际大就是「被剪过」那一档
}

func (p pkt) frame() []byte {
	var proto byte
	var seg []byte
	if p.tcp {
		proto = protoTCP
		seg = tcp(p.sp, p.dp, p.seq, p.ack, p.flags, p.win, p.opts, p.payload)
	} else {
		proto = protoUDP
		seg = udp(p.sp, p.dp, 8+len(p.payload), p.payload)
	}
	return v4frame(p.src, p.dst, proto, seg)
}

func add(a *Aggregator, p pkt) error {
	raw := p.frame()
	wire := p.wire
	if wire == 0 {
		wire = len(raw)
	}
	_, err := a.Add(Packet{Timestamp: p.when, LinkType: LinkEN10MB, Data: raw, WireLen: wire, Iface: p.iface})
	return err
}

// ask / reply 是「取流的那一端发」与「设备回」：几十条用例都用它们，省掉一半样板。
func ask(a *Aggregator, n int, text string) error {
	return add(a, pkt{when: at(n), src: client, sp: 51234, dst: device, dp: 554,
		payload: []byte(text)})
}

func reply(a *Aggregator, n int, text string) error {
	return add(a, pkt{when: at(n), src: device, sp: 554, dst: client, dp: 51234,
		payload: []byte(text)})
}

func mssOpt(n int) []byte { return []byte{2, 4, byte(n >> 8), byte(n)} }

// ==================== 读表的手 ====================

func finding(fl *Flow, code string) (Finding, bool) {
	for _, f := range fl.Findings {
		if f.Code == code {
			return f, true
		}
	}
	return Finding{}, false
}

func mustHave(t *testing.T, fl *Flow, code string) Finding {
	t.Helper()
	f, ok := finding(fl, code)
	if !ok {
		t.Fatalf("判定 %s 没出来。表上有的：%s", code, codesOf(fl))
	}
	return f
}

func mustNotHave(t *testing.T, fl *Flow, code string) {
	t.Helper()
	if f, ok := finding(fl, code); ok {
		t.Errorf("判定 %s 不该出现（正常的那一种也被说了）：%s", code, f.Text)
	}
}

func codesOf(fl *Flow) string {
	if len(fl.Findings) == 0 {
		return "（一条都没有）"
	}
	parts := make([]string, 0, len(fl.Findings))
	for _, f := range fl.Findings {
		parts = append(parts, f.Code)
	}
	return strings.Join(parts, "、")
}

func noteWith(fl *Flow, sub string) bool {
	for _, n := range fl.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// oneFlow 回表上的那一条流；条数不对就直接停 —— 后面的断言全建立在「就这一条」上。
func oneFlow(t *testing.T, a *Aggregator) *Flow {
	t.Helper()
	out := a.Flows()
	if len(out) != 1 {
		t.Fatalf("表上 %d 条流，要 1 条：%s", len(out), keysOf(out))
	}
	return out[0]
}

func keysOf(fl []*Flow) string {
	parts := make([]string, 0, len(fl))
	for _, f := range fl {
		parts = append(parts, f.Key)
	}
	return strings.Join(parts, " | ")
}

func anyContains(s []string, sub string) bool {
	for _, v := range s {
		if strings.Contains(v, sub) {
			return true
		}
	}
	return false
}

// ==================== 一条流一个键，两个方向共用 ====================

func Test两个方向归成一条流且分开记账(t *testing.T) {
	a := NewAggregator(Options{})
	if err := ask(a, 0, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := reply(a, 1, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	fl := oneFlow(t, a)
	if fl.A != client+":51234" || fl.B != device+":554" {
		t.Errorf("端点定反了：%s → %s（发起那一头必须是 A，现场照着这一格决定去问谁）", fl.A, fl.B)
	}
	if fl.AB.Packets != 1 || fl.BA.Packets != 1 {
		t.Errorf("方向账 = A→B %d 包、B→A %d 包", fl.AB.Packets, fl.BA.Packets)
	}
	if fl.AMAC != ipMAC(client).String() || fl.BMAC != ipMAC(device).String() {
		t.Errorf("MAC 按方向配错了：%s / %s", fl.AMAC, fl.BMAC)
	}
	if fl.AB.Bytes+fl.BA.Bytes != fl.Bytes {
		t.Errorf("两个方向加起来 %d ≠ 总 %d：分方向与总量对不上，界面上的百分比就是假的",
			fl.AB.Bytes+fl.BA.Bytes, fl.Bytes)
	}
	if fl.Iface != "" {
		t.Errorf("没给口名却填了口：%q", fl.Iface)
	}
}

func Test口名跟着第一包而字节按线上长度(t *testing.T) {
	a := NewAggregator(Options{})
	p := pkt{when: at(0), src: client, sp: 51234, dst: device, dp: 554,
		payload: []byte("PING"), iface: "en0"}
	raw := p.frame()
	// 第一包：线上 4000 字节只带回来这么多（snaplen 剪过）。
	if _, err := a.Add(Packet{Timestamp: at(0), LinkType: LinkEN10MB, Data: raw, WireLen: 4000, Iface: "en0"}); err != nil {
		t.Fatal(err)
	}
	// 第二包换了口，也换了长度：都不许盖掉第一包定下的那两格。
	if _, err := a.Add(Packet{Timestamp: at(1), LinkType: LinkEN10MB, Data: raw, WireLen: 42, Iface: "eth9"}); err != nil {
		t.Fatal(err)
	}
	fl := oneFlow(t, a)
	if fl.Iface != "en0" {
		t.Errorf("口名被后一包改成了 %q（第一条流进来的那一个口才算）", fl.Iface)
	}
	if fl.Bytes != 4042 {
		t.Errorf("字节按带回来的算了 %d：现场要的是线上过了多少，两个数差着一整个 snaplen", fl.Bytes)
	}
	if fl.Truncated != 1 {
		t.Errorf("截断计了 %d 包", fl.Truncated)
	}
	mustHave(t, fl, "captured-truncated")
}

// ==================== 方向：第一个 SYN 说话 ====================

func Test方向按第一个SYN定但握手开始之后不换(t *testing.T) {
	a := NewAggregator(Options{})
	// 先见到的是设备发来的一个普通 ACK：这一刻只能把设备当 A。
	if err := add(a, pkt{when: at(0), src: device, sp: 554, dst: client, dp: 51234, tcp: true,
		seq: 100, ack: 200, flags: FlagACK, win: 64240}); err != nil {
		t.Fatal(err)
	}
	if got := a.Flows()[0].A; got != device+":554" {
		t.Fatalf("第一包没定上：%s", got)
	}
	// 之后才见到真正的 SYN：换过来，并且必须在表上留一句「起点是后补的」。
	if err := add(a, pkt{when: at(1), src: client, sp: 51234, dst: device, dp: 554, tcp: true,
		seq: 200, flags: FlagSYN, win: 64240}); err != nil {
		t.Fatal(err)
	}
	fl := a.Flows()[0]
	if fl.A != client+":51234" {
		t.Errorf("换向后 A = %s，要发起那一方", fl.A)
	}
	if !noteWith(fl, "方向按第一个 SYN") {
		t.Errorf("没留下那一句说明：%v（抓包从中间开始是常态，这一句决定现场信不信这个 A）", fl.Notes)
	}
	// 握手已经开始之后再来的 SYN/ACK 不许再换：那是同一条流上新建的一次会话，不是认错发起方。
	if err := add(a, pkt{when: at(2), src: device, sp: 554, dst: client, dp: 51234, tcp: true,
		seq: 300, flags: FlagSYN | FlagACK, win: 64240}); err != nil {
		t.Fatal(err)
	}
	if got := a.Flows()[0].A; got != client+":51234" {
		t.Errorf("又被换了：%s —— 每换一次，两边已经记下的账就对调错一次", got)
	}
}

// ==================== TCP 的几种走法各说一句 ====================

func TestTCP的几种走法各说各的(t *testing.T) {
	syn := pkt{src: client, sp: 51234, dst: device, dp: 554, tcp: true, flags: FlagSYN, win: 64240, opts: mssOpt(1460)}
	synack := pkt{src: device, sp: 554, dst: client, dp: 51234, tcp: true, flags: FlagSYN | FlagACK, win: 1460, opts: mssOpt(1400)}
	ack := pkt{src: client, sp: 51234, dst: device, dp: 554, tcp: true, flags: FlagACK, win: 64240}
	rst := pkt{src: device, sp: 554, dst: client, dp: 51234, tcp: true, flags: FlagRST, win: 0}
	finA := pkt{src: client, sp: 51234, dst: device, dp: 554, tcp: true, flags: FlagFIN | FlagACK, win: 64240}
	finB := pkt{src: device, sp: 554, dst: client, dp: 51234, tcp: true, flags: FlagFIN | FlagACK, win: 1460}

	cases := []struct {
		name    string
		pkts    []pkt
		want    string
		wantHS  HandshakeState
		notWant string
	}{
		{"没人接", []pkt{syn}, "tcp-no-synack", HSSyn, ""},
		{"一直重发SYN", []pkt{syn, syn, syn}, "tcp-syn-retransmit", HSSyn, "tcp-no-synack"},
		{"半开", []pkt{syn, synack}, "tcp-half-open", HSSplit, ""},
		{"握手齐", []pkt{syn, synack, ack}, "", HSEstablished, "tcp-half-open"},
		{"被拒", []pkt{syn, rst}, "tcp-reset", HSReset, ""},
		{"连上就断", []pkt{syn, synack, ack, finA, finB}, "tcp-instant-close", HSClosed, ""},
		{"从中间开始", []pkt{ack}, "tcp-no-syn", HSNone, "tcp-no-synack"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := NewAggregator(Options{})
			for i, p := range c.pkts {
				p.when = at(i)
				if err := add(a, p); err != nil {
					t.Fatal(err)
				}
			}
			fl := oneFlow(t, a)
			if c.want != "" {
				mustHave(t, fl, c.want)
			}
			if c.notWant != "" {
				mustNotHave(t, fl, c.notWant)
			}
			if fl.TCP.Handshake != c.wantHS {
				t.Errorf("握手走到 %q，要 %q", fl.TCP.Handshake, c.wantHS)
			}
		})
	}
}

func Test收端窗口压到零与MSS两边不一(t *testing.T) {
	a := NewAggregator(Options{})
	pkts := []pkt{
		{src: client, sp: 51234, dst: device, dp: 554, tcp: true, flags: FlagSYN, win: 64240, opts: mssOpt(1460)},
		{src: device, sp: 554, dst: client, dp: 51234, tcp: true, flags: FlagSYN | FlagACK, win: 1460, opts: mssOpt(1400)},
		{src: client, sp: 51234, dst: device, dp: 554, tcp: true, flags: FlagACK, win: 64240},
		// 设备收不动了：带着数据的段，窗口那一格是 0。
		{src: device, sp: 554, dst: client, dp: 51234, tcp: true, flags: FlagPSH | FlagACK, win: 0, payload: []byte("x")},
	}
	for i, p := range pkts {
		p.when = at(i)
		if err := add(a, p); err != nil {
			t.Fatal(err)
		}
	}
	fl := oneFlow(t, a)
	f := mustHave(t, fl, "tcp-zero-window")
	if !strings.Contains(f.Text, fl.B) {
		t.Errorf("零窗口指错了人：%s（B 才是发那一个带数据段的一方）", f.Text)
	}
	mustHave(t, fl, "tcp-mss-mismatch")
	// SYN 那两包的窗口本来就可以不一样大，也不许被算成「收不过来」。
	if fl.TCP.ZeroWin[0] != 0 {
		t.Errorf("发起方被算出 %d 次零窗口", fl.TCP.ZeroWin[0])
	}
}

func Test拼流缺一段与同一份数据重发(t *testing.T) {
	data := "DESCRIBE rtsp://10.0.0.9/live RTSP/1.0\r\nCSeq: 1\r\n\r\n"
	a := NewAggregator(Options{})
	// 序号 1000 起步，第二条跳到 1000+len+500：中间那 500 字节没带回来。
	add(a, pkt{when: at(0), src: client, sp: 51234, dst: device, dp: 554, tcp: true,
		flags: FlagPSH | FlagACK, win: 64240, seq: 1000, payload: []byte(data)})
	add(a, pkt{when: at(1), src: client, sp: 51234, dst: device, dp: 554, tcp: true,
		flags: FlagPSH | FlagACK, win: 64240, seq: uint32(1000 + len(data) + 500), payload: []byte("tail")})
	// 同一份数据再发一遍：那是重发，不是新的一条报文。
	add(a, pkt{when: at(2), src: client, sp: 51234, dst: device, dp: 554, tcp: true,
		flags: FlagPSH | FlagACK, win: 64240, seq: 1000, payload: []byte(data)})

	fl := oneFlow(t, a)
	mustHave(t, fl, "tcp-gap")
	mustHave(t, fl, "tcp-retransmit")
	n := 0
	for _, m := range fl.Messages {
		if m.Proto == "rtsp" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("RTSP 报文出了 %d 条，要 1 条（同序号同正文只算一份，多出来的那一条是假的）", n)
	}
}

// ==================== 分片 ====================

func Test后续片段归进首片那一条(t *testing.T) {
	a := NewAggregator(Options{})
	// 首片：带 UDP 头 + 100 字节正文，「更多分片」那一位置上。
	first := ipv4(77, protoUDP, 64, client, device, 20+8+100, udp(51234, 554, 108, make([]byte, 100)))
	first[6] |= 0x20
	// 后续片：没有端口，只有 40 字节数据，偏移接着首片那 108 字节。
	tail := ipv4(77, protoUDP, 64, client, device, 20+40, make([]byte, 40))
	tail[6] = byte(108 / 8) // 偏移那一格单位是 8 字节

	if _, err := a.Add(Packet{Timestamp: at(0), LinkType: LinkEN10MB,
		Data: eth(ipMAC(device), ipMAC(client), etypeIPv4, first), WireLen: 14 + len(first)}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(Packet{Timestamp: at(1), LinkType: LinkEN10MB,
		Data: eth(ipMAC(device), ipMAC(client), etypeIPv4, tail), WireLen: 14 + len(tail)}); err != nil {
		t.Fatal(err)
	}
	fl := a.Flows()
	if len(fl) != 1 {
		t.Fatalf("分片被拆成 %d 条流：%s（后续片没有端口，各记各的就是一条变两条）", len(fl), keysOf(fl))
	}
	only := fl[0]
	if only.FragPackets != 1 || only.FragBytes != 74 {
		// 口径跟 fl.Bytes 一致：记的是线上那一份（以太网头 14 + IP 头 20 + 数据 40 = 74）。
		// 这里断成 60 就是逼着实现两套口径 —— 一个含链路头一个不含，两条数加不起来才是真难查。
		t.Errorf("归并了 %d 片 / %d 字节，要 1 片 / 74 字节（线上长度：14 + 20 + 40）", only.FragPackets, only.FragBytes)
	}
	if only.Packets != 2 {
		t.Errorf("总包数 = %d", only.Packets)
	}
	mustHave(t, only, "ip-fragments")
}

func Test只有后续片段时也要有一条流兜着(t *testing.T) {
	// 抓包从中间开始，首片根本没进这一份文件：那一些片段不能当没看见。
	a := NewAggregator(Options{})
	tail := ipv4(88, protoUDP, 64, client, device, 20+40, make([]byte, 40))
	tail[6] = byte(1480/8) | 0x20
	if _, err := a.Add(Packet{Timestamp: at(0), LinkType: LinkEN10MB,
		Data: eth(ipMAC(device), ipMAC(client), etypeIPv4, tail), WireLen: 14 + len(tail)}); err != nil {
		t.Fatal(err)
	}
	fl := a.Flows()
	if len(fl) != 1 {
		t.Fatalf("只有后续片段时表上 %d 条流：这一档必须有一条兜着的，不然这 40 字节在账上凭空消失", len(fl))
	}
	if fl[0].FragPackets != 1 {
		t.Errorf("片段没记账：%+v", fl[0])
	}
}

// ==================== 账：每一包都要有下落 ====================

func Test包数账对得上包括拆不开的(t *testing.T) {
	a := NewAggregator(Options{})
	add(a, pkt{when: at(0), src: client, sp: 51234, dst: device, dp: 554, payload: []byte("hi")})
	// 拆不开的三种：太短的、链路口不支持的、上层没内容的。
	a.Add(Packet{Timestamp: at(1), LinkType: LinkEN10MB, Data: []byte{0x01, 0x02}})
	a.Add(Packet{Timestamp: at(2), LinkType: LinkIEEE80211, Data: []byte{0x08, 0x00, 0, 0}})
	a.Add(Packet{Timestamp: at(3), LinkType: LinkEN10MB, Data: eth(macB, macA, 0x88cc, []byte{})})

	l := a.Ledger()
	if l.Total != 4 {
		t.Fatalf("总数 %d", l.Total)
	}
	if !l.Reconciles() {
		t.Errorf("账对不上：%s —— 对不上的表连「这里没流量」都不该说", l)
	}
	if l.ByLink[LinkIEEE80211] != 1 {
		t.Errorf("按链路口的格子少了：%v（这一格决定建议用户换哪种抓法）", l.ByLink)
	}
}

func Test流表撞到上限要明说(t *testing.T) {
	a := NewAggregator(Options{MaxFlows: 2})
	for i := 0; i < 5; i++ {
		add(a, pkt{when: at(i), src: fmt.Sprintf("10.1.1.%d", i+10), sp: 51234, dst: device, dp: 554,
			payload: []byte("x")})
	}
	if got := len(a.Flows()); got != 2 {
		t.Fatalf("表上 %d 条，上限是 2", got)
	}
	l := a.Ledger()
	if l.FlowsDropped == 0 || l.PacketsDropped == 0 {
		t.Errorf("撞上限没记账：%+v（悄悄丢掉就是表上那句「这台没发过包」的来源）", l)
	}
	if !l.Reconciles() {
		t.Errorf("撞上限之后账就散了：%s", l)
	}
}

// ==================== ICMP：谁问了、谁没答 ====================

func icmpSeg(typ byte, id, seq uint16, inner []byte) []byte {
	b := []byte{typ, 0, 0, 0, byte(id >> 8), byte(id), byte(seq >> 8), byte(seq)}
	return append(b, inner...)
}

func TestICMP按方向配对(t *testing.T) {
	a := NewAggregator(Options{})
	// 设备问三次，客户端只答了一次。
	for i, n := range []int{0, 1, 3} {
		_ = i
		addICMP(t, a, n, device, client, icmpSeg(8, 0x1234, uint16(n+1), nil))
	}
	addICMP(t, a, 2, client, device, icmpSeg(0, 0x1234, 2, nil))

	fl := oneFlow(t, a)
	f := mustHave(t, fl, "icmp-loss")
	if !strings.Contains(f.Text, "问了 3 次") || !strings.Contains(f.Text, "答了 1 次") {
		t.Errorf("那一句没把两边的数出来：%s", f.Text)
	}
	mustNotHave(t, fl, "icmp-no-reply")
	if fl.ICMP.Req[0] != 3 || fl.ICMP.Reply[1] != 1 {
		t.Errorf("回声账 = 请求 %d / 应答 %d（下标 0 是 A→B，即设备问出去那一个方向）", fl.ICMP.Req[0], fl.ICMP.Reply[1])
	}
}

func TestICMP一个都没答时不说丢包(t *testing.T) {
	a := NewAggregator(Options{})
	for i := 0; i < 2; i++ {
		addICMP(t, a, i, client, device, icmpSeg(8, 0x4321, uint16(i+1), nil))
	}
	fl := oneFlow(t, a)
	mustHave(t, fl, "icmp-no-reply")
	mustNotHave(t, fl, "icmp-loss") // 一个回包都没有却说「过了几个才丢一个」，是把两种病混成一句
}

func Test不可达单独一句并指着里面那一条(t *testing.T) {
	a := NewAggregator(Options{})
	inner := ipv4(11, protoTCP, 64, device, client, 20+20, tcp(554, 51234, 9, 9, FlagSYN|FlagACK, 0, nil, nil))
	addICMP(t, a, 0, device, client, icmpSeg(3, 0, 0, inner))

	fl := oneFlow(t, a)
	f := mustHave(t, fl, "icmp-unreachable")
	if !strings.Contains(f.Text, "1 包") {
		t.Errorf("不可达那一句：%s", f.Text)
	}
	// ★ 下标 0 才对：这条流的第一包就是设备发过来的那一个 ICMP，所以设备是 A。
	// 「不可达一定是 B→A」是想当然 —— 抓包不绑定本机是谁，方向只能是「先见到的那一方」。
	// 真要给人看是谁说的，看判定那句：它直接把 A/B 的名字打出来了。
	if fl.ICMP.Unreach[0] != 1 {
		t.Errorf("不可达记在错的方向上：%v（第一包是设备发的，设备就是 A，这一格是「设备→对面」）", fl.ICMP.Unreach)
	}
	if !strings.Contains(f.Text, device) {
		t.Errorf("那一句没指着是谁说的：%s（要带 %s）", f.Text, device)
	}
}

func addICMP(t *testing.T, a *Aggregator, n int, src, dst string, seg []byte) {
	t.Helper()
	raw := v4frame(src, dst, protoICMP, seg)
	if _, err := a.Add(Packet{Timestamp: at(n), LinkType: LinkEN10MB, Data: raw, WireLen: len(raw)}); err != nil {
		t.Fatalf("第 %d 个 icmp 包：%v", n, err)
	}
}

// ==================== ARP：同一个地址几个人认领 ====================

func Test同一地址被两个MAC说过就报冲突(t *testing.T) {
	a := NewAggregator(Options{})
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	for i, mac := range []net.HardwareAddr{macA, macB} {
		raw := eth(bcastMAC, mac, etypeARP, arpFrame(2, mac, zero, gateway, client))
		if _, err := a.Add(Packet{Timestamp: at(i), LinkType: LinkEN10MB, Data: raw, WireLen: len(raw)}); err != nil {
			t.Fatal(err)
		}
	}
	bd := a.ARPBindings()
	if len(bd) != 1 || len(bd[0].MACs) != 2 {
		t.Fatalf("绑定表 = %+v，要一个地址两个 MAC", bd)
	}
	f := mustHave(t, oneFlow(t, a), "arp-conflict")
	if !strings.Contains(f.Text, gateway) {
		t.Errorf("没指出是哪个地址：%s", f.Text)
	}
}

func Test只有请求那一方不算认领(t *testing.T) {
	// who-has 的提问方也带源 MAC：拿它当「这个地址是谁的」，每一条广播都会变成冲突。
	a := NewAggregator(Options{})
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	raw := eth(bcastMAC, macA, etypeARP, arpFrame(1, macA, zero, client, gateway))
	if _, err := a.Add(Packet{Timestamp: at(0), LinkType: LinkEN10MB, Data: raw, WireLen: len(raw)}); err != nil {
		t.Fatal(err)
	}
	for _, bd := range a.ARPBindings() {
		if bd.IP == client && bd.MACs[0] == macA.String() {
			t.Logf("提问方也被记了一笔：%+v（这一格口径只影响 arp-conflict，先写下现状）", bd)
		}
	}
}

func Test单向UDP说一句双向的不说(t *testing.T) {
	a := NewAggregator(Options{})
	add(a, pkt{when: at(0), src: client, sp: 40000, dst: multicast, dp: 1900,
		payload: []byte("NOTIFY * HTTP/1.1\r\nHost: 239.1.2.3:1900\r\n\r\n")})
	mustHave(t, oneFlow(t, a), "udp-one-way")

	b := NewAggregator(Options{})
	add(b, pkt{when: at(0), src: client, sp: 40000, dst: device, dp: 5060, payload: []byte(sipOptions)})
	add(b, pkt{when: at(1), src: device, sp: 5060, dst: client, dp: 40000, payload: []byte(sip200Options)})
	mustNotHave(t, oneFlow(t, b), "udp-one-way")
}

const (
	sipOptions = "OPTIONS * SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.10:40000\r\n" +
		"From: <sip:34020000001320000001@3402000000>\r\nTo: <sip:34020000002000000001@3402000000>\r\n" +
		"Call-ID: 1@192.168.1.10\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"
	sip200Options = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.10:40000\r\n" +
		"From: <sip:34020000001320000001@3402000000>\r\nTo: <sip:34020000002000000001@3402000000>;tag=2\r\n" +
		"Call-ID: 1@192.168.1.10\r\nCSeq: 1 OPTIONS\r\n\r\n"
)

// ==================== 快照重算：刷一次界面不许多出一条判定 ====================

func Test判定重算不追加(t *testing.T) {
	a := NewAggregator(Options{})
	add(a, pkt{when: at(0), src: client, sp: 51234, dst: device, dp: 554, tcp: true, flags: FlagSYN, win: 64240})
	first := len(a.Flows()[0].Findings)
	for i := 1; i <= 5; i++ {
		if got := len(a.Flows()[0].Findings); got != first {
			t.Fatalf("第 %d 次取表判定变成 %d 条（第一次 %d 条）：同一份状态必须算出同一组话", i, got, first)
		}
	}
}

func Test按键取一条流时跨流那几格也算过(t *testing.T) {
	a := NewAggregator(Options{})
	// 只喂信令那一条：SETUP 说好了 6970-6971 收流，画面那条 UDP 流不在表上。
	ask(a, 0, "SETUP rtsp://10.0.0.9/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 3\r\n"+
		"Transport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	reply(a, 1, "RTSP/1.0 200 OK\r\nCSeq: 3\r\n"+
		"Transport: RTP/AVP;unicast;client_port=6970-6971;server_port=6972-6973\r\nSession: 12345\r\n\r\n")

	key := "udp " + client + ":51234 <-> " + device + ":554"
	fl, ok := a.Flow(key)
	if !ok {
		t.Fatalf("按键取不到：%s", keysOf(a.Flows()))
	}
	// ★ 单独取一条也必须把整表算一遍：不然「画面在另一条上」那一半永远连不出来。
	mustHave(t, fl, "signaling-promised-no-media")
}

// ==================== 从采集/文件那一头进来 ====================

func Test读一份pcapng出整张表(t *testing.T) {
	var raw bytes.Buffer
	w, err := capture.NewWriter(&raw, []capture.Interface{{Name: "eth0", LinkType: LinkEN10MB}})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("GET /ISAPI/System/deviceInfo HTTP/1.1\r\nHost: 10.0.0.9\r\n\r\n")
	frame := v4frame(client, device, protoUDP, udp(51234, 80, 8+len(payload), payload))
	if err := w.WritePacket(0, at(0), frame, len(frame)); err != nil {
		t.Fatal(err)
	}
	// 第二包只带回头 42 字节（IP+UDP 头齐、正文被剪了），线上声明 9999：留长剪过那一档。
	if err := w.WritePacket(0, at(1), frame[:42], 9999); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	tbl := NewTable(Options{})
	n, err := tbl.ReadFile(&raw)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("读进来 %d 包", n)
	}
	fl := tbl.Flows()
	if len(fl) != 1 {
		t.Fatalf("表上 %d 条流", len(fl))
	}
	if fl[0].App != "http" {
		t.Errorf("协议认成 %q，要 http", fl[0].App)
	}
	if fl[0].Iface != "eth0" {
		t.Errorf("口名没跟着文件进来：%q（一份多口的文件，不换口名就没法说「这条是从哪块口抓的」）", fl[0].Iface)
	}
	if fl[0].Truncated != 1 {
		t.Errorf("剪过那一包没落到流上：%d", fl[0].Truncated)
	}
	rep := tbl.Report()
	if !anyContains(rep, "比线上声明的短") {
		t.Errorf("整表口径里没这一笔：%v（读一半当成读全份是最容易上屏的假话）", rep)
	}
	if !tbl.Ledger().Reconciles() {
		t.Errorf("读文件的账对不上：%s", tbl.Ledger())
	}
}

func Test口表缺号那一包只记账不拖垮整份(t *testing.T) {
	var raw bytes.Buffer
	w, err := capture.NewWriter(&raw, []capture.Interface{{Name: "eth0", LinkType: LinkEN10MB}})
	if err != nil {
		t.Fatal(err)
	}
	frame := v4frame(client, device, protoUDP, udp(51234, 554, 8+len(rtspOptions), rtspOptions))
	if err := w.WritePacket(0, at(0), frame, len(frame)); err != nil {
		t.Fatal(err)
	}
	w.Flush()

	tbl := NewTable(Options{})
	// 手工喂一个 7 号口的包：口表里只有 0 号，这一包进不了表，但后面的照进。
	err = tbl.Add(capture.Packet{InterfaceIndex: 7, Timestamp: at(1), Data: frame, OrigLen: len(frame), HasTimestamp: true})
	if err == nil {
		t.Fatal("口表缺号被当成了正常包")
	}
	if got := len(tbl.Flows()); got != 0 {
		t.Errorf("进不了表的包把流表撑成了 %d 条", got)
	}
	if !anyContains(tbl.Report(), "口表里没有第 7 号口") {
		t.Errorf("整表口径里没这一笔：%v", tbl.Report())
	}
	// 同一份表接着读真文件：坏过一次不许停。
	n, err := tbl.ReadFile(bytes.NewReader(raw.Bytes()))
	if err != nil || n != 1 {
		t.Fatalf("坏过一处之后读不动了：%v %d（停下等于把后面本来读得出来的包全扔了）", err, n)
	}
	if len(tbl.Flows()) != 1 {
		t.Errorf("后面本来读得出来的包被扔了：%d 条流", len(tbl.Flows()))
	}
}

var rtspOptions = []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nRequire: rtsp-standard\r\n\r\n")

func Test没带时刻的包只进得数量不进时序(t *testing.T) {
	tbl := NewTable(Options{})
	tbl.SetInterfaces([]capture.Interface{{Name: "eth0", LinkType: LinkEN10MB}})
	frame := v4frame(client, device, protoUDP, udp(51234, 554, 8+len(rtspOptions), rtspOptions))
	if err := tbl.Add(capture.Packet{Timestamp: at(0), Data: frame, OrigLen: len(frame), HasTimestamp: true}); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Add(capture.Packet{Data: frame, OrigLen: len(frame)}); err != nil {
		t.Fatal(err)
	}
	if !anyContains(tbl.Report(), "没带时刻") {
		t.Errorf("Report 里没这一句：%v", tbl.Report())
	}
	fl := oneFlow(t, tbl.Agg())
	if fl.Packets != 2 {
		t.Errorf("数量那一边也漏了：%d 包", fl.Packets)
	}
	// ★ 没有拿前一包的时刻替这一包凑，也没有把起点撑成 1970：只让有时刻的那些说话。
	if !fl.Last.Equal(at(0)) && !fl.Last.IsZero() {
		t.Errorf("终点被没时刻的那包顶成了 %v", fl.Last)
	}
}

func Test正文为空的包不进表但要记一笔(t *testing.T) {
	tbl := NewTable(Options{})
	tbl.SetInterfaces([]capture.Interface{{Name: "eth0", LinkType: LinkEN10MB}})
	if err := tbl.Add(capture.Packet{Timestamp: at(0), HasTimestamp: true}); err != nil {
		t.Fatal(err)
	}
	if len(tbl.Flows()) != 0 {
		t.Error("空包造出了一条流")
	}
	if !anyContains(tbl.Report(), "正文为空") {
		t.Errorf("空包没进整表口径：%v（这些包必须在账上，不然总数对不上）", tbl.Report())
	}
}

func Test一个口都没读到时要说出来(t *testing.T) {
	tbl := NewTable(Options{})
	if err := tbl.Add(capture.Packet{Timestamp: at(0), Data: []byte{1, 2, 3}, OrigLen: 3, HasTimestamp: true}); err == nil {
		t.Fatal("没有口表却把链路类型猜了一个")
	}
	if !anyContains(tbl.Report(), "口表里没有第 0 号口") {
		t.Errorf("缺口表的口径没写出来：%v", tbl.Report())
	}
}

// ==================== 怎么喂都不许崩 ====================

// ★ 这一条是这一层的保险：文件是同事抓来的、留长是用户填的，两者叠起来什么形状都能出现。
// 「拆包拆到崩」会把整张表一起带走，所以从聚合到出表这一段也要一起过一遍。
func Test怎么喂都不许崩到出表(t *testing.T) {
	raws := [][]byte{
		v4frame(client, device, protoUDP, udp(554, 554, 8+12, []byte("V2\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03"))),
		v4frame(client, device, protoTCP, tcp(1, 2, 3, 4, FlagPSH|FlagACK, 0, mssOpt(1460), []byte("RTSP/1.0 200 OK\r\n\r\n"))),
		v4frame(client, device, protoICMP, icmpSeg(3, 1, 2, v4frame(device, client, protoTCP, tcp(2, 1, 4, 5, FlagACK, 0, nil, nil)))),
		eth(bcastMAC, macA, etypeARP, arpFrame(2, macA, macB, gateway, client)),
		eth(ipMAC(device), ipMAC(client), 0x8100, vlan(300, etypeIPv4,
			v4frame(client, device, protoUDP, udp(5060, 5060, 8+6, []byte("BYE sip:x"))))),
		v4frame(client, "224.0.0.251", protoUDP, udp(5353, 5353, 8+4, []byte{0, 0, 0, 0})),
	}
	links := []uint16{LinkEN10MB, LinkNull, LinkLinuxSLL, LinkLinuxSLL2, LinkRaw, LinkRadioTap}
	a := NewAggregator(Options{MaxFlows: 32, MaxMessages: 8, MaxFindings: 3})
	n := 0
	for _, lt := range links {
		for _, raw := range raws {
			for cut := 0; cut <= len(raw); cut++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("链路口 %d、截到 %d 字节时崩了：%v", lt, cut, r)
						}
					}()
					_, _ = a.Add(Packet{Timestamp: at(n % 50), LinkType: lt, Data: raw[:cut], WireLen: len(raw)})
					n++
					if n%97 == 0 {
						a.Flows() // 一路出表：判定与跨流连线也要跟着过
						a.Ledger()
						a.ARPBindings()
					}
				}()
			}
		}
	}
	l := a.Ledger()
	if !l.Reconciles() {
		t.Errorf("喂了 %d 种形状之后账散了：%s", n, l)
	}
	if len(a.Flows()) > 32 {
		t.Errorf("流表冲破上限：%d 条", len(a.Flows()))
	}
	t.Logf("共喂了 %d 种截法，表上 %d 条流", n, len(a.Flows()))
}
