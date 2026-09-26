package flow

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/gb28181"
	"net.yuhox.com/netkit/internal/snmp"
)

// 这一份钉的是「一条流上的报文解成了什么，跨报文比出了什么」。
//
// 专解这一层最坏的错不是崩，是**解出一句看着像样的假话**：半条报文被当成一条解，
// 界面上就多出一条「200 OK 但 SDP 是空的」；回包没配上它答的那次询问，
// 「SETUP 成了却没画面」就永远不报，现场照着这张表查一整天。
// 所以每条用例都同时钉两头：**解出来的那一条对不对**、**该闭嘴的那一种有没有闭嘴**。

// ==================== 喂 TCP 的手 ====================

// tcpSession 是一条建好的 TCP 会话，两个方向各自把序号往后接。
//
// ★ 序号不能每个用例手写死：frameTCP 只认「拼出来的连续字节」，序号一接不上就永远
// 等不到一条完整的报文 —— 那是最难查的一种假绿：包全喂进去了、一条报文都没解出来，
// 看着像「专解没写」，其实是测试自己把流切断了。
type tcpSession struct {
	a      *Aggregator
	sp, dp uint16
	next   [2]uint32
}

func newTCPSession(t *testing.T, a *Aggregator, sp, dp uint16) *tcpSession {
	t.Helper()
	s := &tcpSession{a: a, sp: sp, dp: dp, next: [2]uint32{1000, 5000}}
	// 握手三包：不先建会话，表上每一格都带「从中间开始抓的」，判定就分不清是谁的锅。
	s.seg(t, 0, 0, FlagSYN, nil)
	s.seg(t, 1, 1, FlagSYN|FlagACK, nil)
	s.seg(t, 2, 0, FlagACK, nil)
	return s
}

func (s *tcpSession) seg(t *testing.T, n, dir int, flags TCPFlags, payload []byte) {
	t.Helper()
	p := pkt{when: at(n), tcp: true, flags: flags, seq: s.next[dir], ack: s.next[dir^1],
		win: 64240, payload: payload}
	if dir == 0 {
		p.src, p.dst, p.sp, p.dp = client, device, s.sp, s.dp
	} else {
		p.src, p.dst, p.sp, p.dp = device, client, s.dp, s.sp
	}
	if err := add(s.a, p); err != nil {
		t.Fatalf("第 %d 个 tcp 包（方向 %d）：%v", n, dir, err)
	}
	// SYN 与 FIN 各占一个序号，哪怕正文是空的。忘了这一条，后面每一段的序号都差一，
	// 拼出来的流里就会处处「差一字节对不上」，而那是最不像错的错。
	if flags&FlagSYN != 0 || flags&FlagFIN != 0 {
		s.next[dir]++
	}
	s.next[dir] += uint32(len(payload))
}

func (s *tcpSession) ask(t *testing.T, n int, text string) {
	t.Helper()
	s.seg(t, n, 0, FlagACK|FlagPSH, []byte(text))
}

func (s *tcpSession) reply(t *testing.T, n int, text string) {
	t.Helper()
	s.seg(t, n, 1, FlagACK|FlagPSH, []byte(text))
}

// ==================== 喂 RTP / RTCP 的手 ====================

// rtpPacket 造一个 RTP 包。cc 给非零时才有「只剩头、正文为零」那一种形状
// （rtpKind 拒绝「恰好停在头尾且 cc=0」的包，那多半是别的协议撞上了这个前缀）。
func rtpPacket(ssrc uint32, seq uint16, ts uint32, pt byte, marker bool, payload []byte) []byte {
	b := make([]byte, 12+len(payload))
	b[0] = 2 << 6
	if marker {
		b[1] |= 0x80
	}
	b[1] |= pt & 0x7f
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], ts)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	copy(b[12:], payload)
	return b
}

// rtcpPacket 造一份 RTCP：pt 是整字节（200=SR、201=RR、202=SDES、203=BYE、205/206=专用）。
// rc 是公共头低 5 位（SR/RR 那里是接收块数，BYE 那里是来源数）。
func rtcpPacket(pt byte, rc int, ssrc uint32, body []byte) []byte {
	b := make([]byte, 8+len(body))
	b[0] = 2<<6 | byte(rc&0x1f)
	b[1] = pt
	binary.BigEndian.PutUint16(b[2:4], uint16((len(body)/4)+1))
	binary.BigEndian.PutUint32(b[4:8], ssrc)
	copy(b[8:], body)
	return b
}

// srBody 是一份 SR 的「发送者信息 20 字节 + 一个接收块 24 字节」。
func srBody(ntpSec, ntpFrac, rtpTS, sentPkts, sentOcts, target uint32, frac byte, cum uint32, extSeq, jitter, lsr, dlsr uint32) []byte {
	b := make([]byte, 0, 44)
	var u [4]byte
	put := func(v uint32) {
		binary.BigEndian.PutUint32(u[:], v)
		b = append(b, u[:]...)
	}
	put(ntpSec)
	put(ntpFrac)
	put(rtpTS)
	put(sentPkts)
	put(sentOcts)
	put(target)
	b = append(b, frac)
	b = append(b, byte(cum>>16), byte(cum>>8), byte(cum))
	put(extSeq)
	put(jitter)
	put(lsr)
	put(dlsr)
	return b
}

// rrp 造一个接收块（RTCP 报告块 24 字节：被报的 SSRC、丢包分数 1、累计丢失 3、
// 最高扩展序号、抖动、LSR、DLSR）。
func rrp(target uint32, frac byte, cum uint32, extSeq, jitter, lsr, dlsr uint32) []byte {
	return srBody(0, 0, 0, 0, 0, target, frac, cum, extSeq, jitter, lsr, dlsr)[20:]
}

// media 从设备往客户端复一路 RTP：这是取流之后最常见的那一个方向。
func media(t *testing.T, a *Aggregator, n int, seq uint16, ssrc uint32, pt byte, payload []byte) {
	t.Helper()
	s := make([]byte, 160)
	copy(s, payload)
	if err := add(a, pkt{when: at(n), src: device, sp: 554, dst: client, dp: 6970,
		payload: rtpPacket(ssrc, seq, uint32(n)*160, pt, false, s)}); err != nil {
		t.Fatalf("第 %d 个 rtp 包：%v", n, err)
	}
}

// ==================== TCP 上的应用层：定口与切报文 ====================

func TestTCP上解出RTSP并按内容定口(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\nTransport: RTP/AVP;destination=192.168.1.10;server_port=6970-6971\r\n\r\n")
	s.ask(t, 5, "PLAY rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 2\r\nSession: 12345\r\nRange: npt=0.000-\r\n\r\n")
	s.reply(t, 6, "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 12345\r\nRTP-Info: url=rtsp://10.0.0.9/live/1;seq=2\r\n\r\n")

	fl := oneFlow(t, a)
	// ★ TCP 上的定口只发生在 frameTCP 那一头（UDP 是靠每个数据报）。这里一旦为空，
	// 整条 TCP 上的 RTSP 一个字都解不出来 —— 而现场九成九的 RTSP 就跑在 TCP 上。
	if fl.App != "rtsp" {
		t.Fatalf("TCP 上的 RTSP 没定出口：App=%q AppBy=%q（解出 %d 条报文）", fl.App, fl.AppBy, len(fl.Messages))
	}
	if fl.AppBy != "内容" {
		t.Errorf("定口来源记成 %q：内容都解出来了还写端口，等于把「按内容认的」冒充成蒙的", fl.AppBy)
	}
	if len(fl.Messages) != 4 {
		t.Fatalf("解出 %d 条报文，要 4 条：%s", len(fl.Messages), msgsOf(fl))
	}
	// 回包的起始行里没有方法名，靠 CSeq 配回请求那一条。不配，setupOK 恒为 0。
	if got := fl.Messages[1].Method; got != "SETUP" {
		t.Errorf("第一条 200 配上的是 %q，要 SETUP（答的是哪一次询问全凭 CSeq）", got)
	}
	if got := fl.Messages[3].Method; got != "PLAY" {
		t.Errorf("第二条 200 配上的是 %q，要 PLAY", got)
	}
	if fl.Messages[1].Dir != 1 || fl.Messages[1].From != device+":554" {
		t.Errorf("回包的方向记错：dir=%d from=%s（Dir 1 才是 B→A）", fl.Messages[1].Dir, fl.Messages[1].From)
	}
	mustNotHave(t, fl, "rtsp-setup-no-play")
	// 协商走 UDP：画面本来就不在这条流上，这一种只许给一句说明，不许给判定。
	if !noteWith(fl, "协商走 UDP") {
		t.Errorf("走 UDP 取流却没给那一句说明，判定 %s 也没写：%v", "rtsp-play-no-rtp", fl.Notes)
	}
	mustNotHave(t, fl, "rtsp-play-no-rtp")
}

func TestTCP上一条报文拆成两段只出一条(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	full := "DESCRIBE rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n"
	s.ask(t, 3, full[:20])

	fl := oneFlow(t, a)
	if len(fl.Messages) != 0 {
		t.Fatalf("半条就出了报文：%s（解出来的是残缺的那一半，头与正文都会少，而看着像设备没发）", msgsOf(fl))
	}
	// 这一段连起始行都没写完（"RTSP/" 还在后面）：此刻什么都不是，也不许按 554 蒙成 rtsp。
	if fl.App != "" {
		t.Errorf("招牌还没露头就定成了 %s（来源 %s）", fl.App, fl.AppBy)
	}
	s.ask(t, 4, full[20:])
	fl = oneFlow(t, a)
	if len(fl.Messages) != 1 {
		t.Fatalf("两段拼完解出 %d 条，要 1 条：%s", len(fl.Messages), msgsOf(fl))
	}
	m := fl.Messages[0]
	if m.Method != "DESCRIBE" || m.Seq != "1" || !strings.Contains(m.URI, "/live/1") {
		t.Errorf("拼出来的那一条：%+v", m)
	}
}

func TestTCP上一条报文分成头部与正文两段(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	sdp := "v=0\r\no=- 1 1 IN IP4 10.0.0.9\r\ns=Live\r\nc=IN IP4 10.0.0.9\r\n" +
		"t=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
	head := "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: " +
		strconv.Itoa(len(sdp)) + "\r\n\r\n"
	s.reply(t, 3, head)             // 只到空行：正文一个字节没来
	s.reply(t, 4, sdp[:len(sdp)/2]) // 正文来了一半
	s.reply(t, 5, sdp[len(sdp)/2:]) // 剩下的那一半
	fl := oneFlow(t, a)
	if len(fl.Messages) != 1 {
		t.Fatalf("三段喂完解出 %d 条，要 1 条：%s", len(fl.Messages), msgsOf(fl))
	}
	m := fl.Messages[0]
	if m.SDP == nil {
		t.Fatalf("按 Content-Length 对齐之后 SDP 还是没解出来：%+v", m.Fields)
	}
	if m.SDP.Port != 0 || !strings.Contains(m.SDP.Summary(), "收流地址 10.0.0.9") {
		t.Errorf("SDP 那几格：%+v", m.SDP)
	}
}

func TestTCP上内容没露头前不许按端口定口(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 443)
	s.ask(t, 3, "GET /mg") // 起始行都没写完：此刻什么都还不是

	fl := oneFlow(t, a)
	// ★ 这一条钉的是「早退」：443 上按端口就是 https，一旦定下来就不许再换
	// （换会把已经解出去的报文作废）。真内容是 HTTP 时，早退等于把这条流永久定错。
	if fl.App != "" {
		t.Fatalf("内容还没露头就按端口定成了 %s（来源 %s）", fl.App, fl.AppBy)
	}
	s.ask(t, 4, "mt/device/info HTTP/1.1\r\nHost: 10.0.0.9\r\n\r\n")
	fl = oneFlow(t, a)
	if fl.App != "http" || fl.AppBy != "内容" {
		t.Fatalf("内容露头之后没换过来：App=%q 来源=%q", fl.App, fl.AppBy)
	}
	if len(fl.Messages) != 1 {
		t.Fatalf("解出 %d 条：%s", len(fl.Messages), msgsOf(fl))
	}
}

func TestTCP上的加密流按端口定口要写明只是像(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 22)
	s.ask(t, 3, "SSH-2.0-OpenSSH_8.9\r\n") // 这一档没有 ssh 的专解：只能按端口说
	fl := oneFlow(t, a)
	if fl.App != "ssh" {
		t.Fatalf("App=%q，要 ssh（端口上认出来的）", fl.App)
	}
	if fl.AppBy != "端口" {
		t.Errorf("来源记成 %q：按端口认的一律不许写成按内容认的", fl.AppBy)
	}
	if !noteWith(fl, "只是端口上像") {
		t.Errorf("没有那一句「只是端口上像」：%v（界面会把 ssh 读成解过了）", fl.Notes)
	}
	if len(fl.Messages) != 0 {
		t.Errorf("没有专解还解出了 %d 条报文：%s", len(fl.Messages), msgsOf(fl))
	}
}

func Test一条流上见过两种内容时按先定下来的解(t *testing.T) {
	a := NewAggregator(Options{})
	if err := ask(a, 0, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	fl0 := oneFlow(t, a)
	_ = fl0
	// 同一个四元组上又发来一份 DNS：拿 rtsp 的刀去切它会解出一句看着像样的假应答。
	if err := ask(a, 1, dnsQuery("cam.local")); err != nil {
		t.Fatal(err)
	}
	fl := oneFlow(t, a)
	if fl.App != "rtsp" {
		t.Errorf("后到的内容把先定下来的协议顶掉了：App=%q", fl.App)
	}
	if !noteWith(fl, "见过两种协议") {
		t.Errorf("没说出这一条上混过两种协议：%v（宁可少解一条，也不能悄悄切错）", fl.Notes)
	}
	if len(fl.Messages) != 1 {
		t.Errorf("解出 %d 条，要 1 条（那一份 DNS 不该被喂进 rtsp 的刀）：%s", len(fl.Messages), msgsOf(fl))
	}
}

// ==================== 跨报文的信令判定 ====================

func TestSETUP成了却没有PLAY要单独一句(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\n\r\n")

	fl := oneFlow(t, a)
	f := mustHave(t, fl, "rtsp-setup-no-play")
	if !strings.Contains(f.Text, "1 次") {
		t.Errorf("那一句没数出 SETUP 次数：%s", f.Text)
	}
}

func TestPLAY成了走TCP复用却没画面(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n")
	s.ask(t, 5, "PLAY rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 2\r\nSession: 12345\r\n\r\n")
	s.reply(t, 6, "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 12345\r\n\r\n")

	fl := oneFlow(t, a)
	f := mustHave(t, fl, "rtsp-play-no-rtp")
	// 走 TCP 复用时画面就该在这条流上：这一句必须写成「设备没复出来」，不能留「去看另一条流」。
	if !strings.Contains(f.Text, "TCP 复用") {
		t.Errorf("走法没说清：%s", f.Text)
	}
	mustNotHave(t, fl, "rtsp-setup-no-play") // SETUP 后面有 PLAY，那一句就不该再说
}

func TestTEARDOWN之后不说SETUP没PLAY(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\n\r\n")
	s.ask(t, 5, "TEARDOWN rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 2\r\nSession: 12345\r\n\r\n")

	fl := oneFlow(t, a)
	// 取流那一端自己收了会话：说「没人要流」是把正常收尾当成病。
	mustNotHave(t, fl, "rtsp-setup-no-play")
}

func Test认证循环说成口令对不上而不是网络不通(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	for i := 0; i < 2; i++ {
		n := 3 + i*2
		s.ask(t, n, fmt.Sprintf("DESCRIBE rtsp://admin:***@10.0.0.9/live/1 RTSP/1.0\r\nCSeq: %d\r\n\r\n", i+1))
		s.reply(t, n+1, fmt.Sprintf("RTSP/1.0 401 Unauthorized\r\nCSeq: %d\r\n"+
			"WWW-Authenticate: Digest realm=\"cam\", nonce=\"abc123\", qop=\"auth\"\r\n\r\n", i+1))
	}
	fl := oneFlow(t, a)
	f := mustHave(t, fl, "auth-loop")
	if !strings.Contains(f.Text, "2 次") {
		t.Errorf("次数没数对：%s", f.Text)
	}
	mustHave(t, fl, "auth-challenge") // 单包那一层也要有：401 至少得说一句
	// ★ 凭据本身不许在表上：这里请求 URI 里的 userinfo 与 nonce 的值都要被打掉。
	for _, m := range fl.Messages {
		if m.Proto != "rtsp" {
			continue
		}
		for _, fd := range m.Fields {
			if strings.Contains(fd.V, "abc123") {
				t.Errorf("nonce 的值漏在表上了：%s=%s", fd.K, fd.V)
			}
		}
	}
}

func Test国标注册连着被拒与一次没回是两句话(t *testing.T) {
	// 401×2：路是通的，病在口令/编号上。
	a := NewAggregator(Options{})
	for i := 0; i < 2; i++ {
		req := sipRequest(t, gb28181.MethodRegister, uint64(i+1))
		if err := sipAsk(t, a, i*2, req); err != nil {
			t.Fatal(err)
		}
		resp := sipResponse(t, req, 401)
		if err := sipReply(t, a, i*2+1, resp); err != nil {
			t.Fatal(err)
		}
	}
	fl := oneFlow(t, a)
	mustHave(t, fl, "gb28181-register-auth-loop")
	mustHave(t, fl, "auth-loop")
	mustNotHave(t, fl, "gb28181-register-no-reply") // 明明回了 401，不能说成「没人接」

	// 一个回包都没有：那是端口没人接，下一步与上面那一种完全不同。
	b := NewAggregator(Options{})
	for i := 0; i < 2; i++ {
		if err := sipAsk(t, b, i, sipRequest(t, gb28181.MethodRegister, uint64(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	fl2 := oneFlow(t, b)
	mustHave(t, fl2, "gb28181-register-no-reply")
	mustNotHave(t, fl2, "gb28181-register-auth-loop")
	mustNotHave(t, fl2, "auth-loop")
}

func Test保活没人答说成平台没收(t *testing.T) {
	a := NewAggregator(Options{})
	req := sipRequest(t, gb28181.MethodMessage, 1)
	req.Body = gb28181.KeepaliveNotify("34020000001320000001", "34020000001110000001", "OK")
	req.Set(gb28181.HContentType, "Application/MANSCDP+xml")
	for i := 0; i < 3; i++ {
		if err := sipAsk(t, a, i, req); err != nil {
			t.Fatal(err)
		}
	}
	fl := oneFlow(t, a)
	f := mustHave(t, fl, "gb28181-keepalive-no-reply")
	if !strings.Contains(f.Text, "3 条") || !strings.Contains(f.Text, device+":5060") {
		t.Errorf("那一句没带上往哪儿喊的：%s", f.Text)
	}
	// 单包那一层认出了 Keepalive：这一格必须解出来，否则「喊了三次」是蒙的。
	if got := fl.Messages[0].CmdType; !strings.EqualFold(got, "keepalive") {
		t.Errorf("MANSCDP 的命令类型解成 %q", got)
	}
}

func TestINVITE一个回包都没有(t *testing.T) {
	a := NewAggregator(Options{})
	if err := sipAsk(t, a, 0, sipRequest(t, gb28181.MethodInvite, 1)); err != nil {
		t.Fatal(err)
	}
	fl := oneFlow(t, a)
	mustHave(t, fl, "sip-invite-no-reply")

	b := NewAggregator(Options{})
	req := sipRequest(t, gb28181.MethodInvite, 1)
	if err := sipAsk(t, b, 0, req); err != nil {
		t.Fatal(err)
	}
	if err := sipReply(t, b, 1, sipResponse(t, req, 100)); err != nil {
		t.Fatal(err)
	}
	mustNotHave(t, oneFlow(t, b), "sip-invite-no-reply") // 连 Trying 都回来了，就不是没人接
}

func TestMQTT连不上与被拒是两句话(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 1883)
	s.ask(t, 3, string(mqttBuildConnect("cam-01", "iot-user", "S3cr3t-MQTT-pw")))
	fl := oneFlow(t, a)
	if fl.App != "mqtt" {
		t.Fatalf("TCP 上的 MQTT 没定出口：App=%q 来源=%q", fl.App, fl.AppBy)
	}
	f := mustHave(t, fl, "mqtt-connect-no-connack")
	if !strings.Contains(f.Text, "1 次") {
		t.Errorf("%s", f.Text)
	}

	// 回了 5：那是口令/授权不对，与「没回」是两种下一步，两句不许混。
	b := NewAggregator(Options{})
	s2 := newTCPSession(t, b, 51234, 1883)
	s2.ask(t, 3, string(mqttBuildConnect("cam-01", "iot-user", "S3cr3t-MQTT-pw")))
	s2.reply(t, 4, string(mqttBuildConnAck(5)))
	fl2 := oneFlow(t, b)
	mustNotHave(t, fl2, "mqtt-connect-no-connack")
	mustHave(t, fl2, "mqtt-connack-5")
}

func TestMQTTCONNECT的几格按标志位读对(t *testing.T) {
	// ★ 这一条是补的一处自己踩过的坑： 构造 CONNECT 的手一度把 body 覆盖了而不是接上去，
	// 于是发出去的包只剩口令一段。解码器照标志位读， 就把口令读成了「协议名」——
	// 表上一格协议名写着密码， 那是错位与泄露凑在一起： 看着解出来了， 其实每一格都错一位，
	// 而「口令」那一格反而显示「没带」。所以这里既钉读对， 也钉没漏。
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 1883)
	s.ask(t, 3, string(mqttBuildConnect("cam-01", "iot-user", "S3cr3t-MQTT-pw")))
	m := oneFlow(t, a).Messages[0]
	got := map[string]string{}
	redacted := map[string]bool{}
	for _, fd := range m.Fields {
		got[fd.K] = fd.V
		redacted[fd.K] = fd.Redacted
	}
	if got["协议名"] != "MQTT" {
		t.Errorf("协议名 = %q，要 MQTT（ 变长头读错位了：后面每一格都跟着错一位）", got["协议名"])
	}
	if got["客户端标识"] != "cam-01" {
		t.Errorf("客户端标识 = %q", got["客户端标识"])
	}
	if got["用户名"] != "iot-user" {
		t.Errorf("用户名 = %q（ 标志位 0xC0 写了带用户名， 这一格必须读出来）", got["用户名"])
	}
	if got["口令"] == "S3cr3t-MQTT-pw" || !redacted["口令"] {
		t.Errorf("口令那格 = %q（redacted=%v），要的是打掉原值只留形状", got["口令"], redacted["口令"])
	}
	if m.Creds == 0 {
		t.Errorf("Creds = 0：糊掉了一格却没数， 界面就不敢说这条已脱敏")
	}
}

func TestRTSP起始行不许被当成头(t *testing.T) {
	// 起始行里全是冒号（ "DESCRIBE rtsp://user:pass@host/live RTSP/1.0"），
	// 拿「有没有冒号」判是不是一行头， 就会凭空多出一格名字为 "DESCRIBE rtsp" 的假头，
	// 而流地址里那份 userinfo 正好跟着它原样上了表 —— URI 那一格是过了脱敏的， 这一格没有。
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "DESCRIBE rtsp://admin:Pass-In-StartLine-6644@10.0.0.9/live/1 RTSP/1.0\r\n"+
		"CSeq: 1\r\n\r\n")
	fl := oneFlow(t, a)
	m := fl.Messages[0]
	if m.URI != "rtsp://***@10.0.0.9/live/1" {
		t.Errorf("URI = %q，要 userinfo 打掉、 主机留着（「流地址写错了」就靠这一段）", m.URI)
	}
	for _, fd := range m.Fields {
		if strings.HasPrefix(strings.ToUpper(fd.K), "DESCRIBE") || strings.HasPrefix(fd.K, "RTSP/") {
			t.Errorf("起始行被当成头了：%s = %q", fd.K, fd.V)
		}
		if strings.Contains(fd.V, "Pass-In-StartLine-6644") {
			t.Errorf("凭据原文漏在 %q 这一格上：%q", fd.K, fd.V)
		}
	}
}

// ==================== RTP 序号账 ====================

func TestRTP按序号估丢包(t *testing.T) {
	a := NewAggregator(Options{})
	// 100 101 102 然后跳到 105：中间两个号没见到。
	for i, seq := range []uint16{100, 101, 102, 105} {
		media(t, a, i, seq, 0x1234abcd, 96, []byte{byte(i)})
	}
	fl := oneFlow(t, a)
	if fl.App != "rtp" {
		t.Errorf("App=%q，一路 RTP 上按内容就该定成 rtp", fl.App)
	}
	if len(fl.RTP) != 1 {
		t.Fatalf("记了 %d 路 SSRC，要 1 路", len(fl.RTP))
	}
	r := fl.RTP[0]
	if r.SSRC != 0x1234abcd || r.Packets != 4 || r.Gaps != 1 || r.Lost != 2 {
		t.Fatalf("序号账：%+v", r)
	}
	// 该有 100..105 = 6 个，实收 4 个。
	if got := r.Expected(); got != 6 {
		t.Errorf("Expected = %d，要 6", got)
	}
	f := mustHave(t, fl, "rtp-loss")
	if !strings.Contains(f.Text, "33.33%") || !strings.Contains(f.Text, "1234abcd") {
		t.Errorf("那一句：%s", f.Text)
	}
	// 句子得指着是谁发的那一路：一条流上两个方向都有画面时，不说清就是两句糊话。
	if !strings.Contains(f.Text, device+":554") {
		t.Errorf("没写发的那一方：%s", f.Text)
	}
}

func TestRTP序号大跳不算进丢包(t *testing.T) {
	a := NewAggregator(Options{})
	// 100 101 然后直接到 5000：跳过的 4898 个号「没见到」不等于「丢了」。
	for i, seq := range []uint16{100, 101, 5000, 5001} {
		media(t, a, i, seq, 0x0a0b0c0d, 96, []byte{byte(i)})
	}
	fl := oneFlow(t, a)
	r := fl.RTP[0]
	if r.Jumps != 1 || r.JumpSpan != 4898 {
		t.Fatalf("大跳记成 %d 处 / 跳过 %d 个号", r.Jumps, r.JumpSpan)
	}
	if r.Lost != 0 {
		t.Errorf("大跳被算进了丢包：Lost=%d（换了源、序号从头来，与真丢一大片在包上长得一样）", r.Lost)
	}
	// ★ 这是那句「没算进丢包数」的凭据：分母里也得把跳过的减掉，
	// 不然一次换源就把丢包率顶到 99%，界面上报的数根本没被证实过。
	if got := r.Expected(); got != 4 {
		t.Errorf("Expected = %d，要 4（该有 100/101/5000/5001，跳过的不算该有）", got)
	}
	mustNotHave(t, fl, "rtp-loss")
	f := mustHave(t, fl, "rtp-seq-jump")
	if !strings.Contains(f.Text, "4898") {
		t.Errorf("跳过的号没写：%s", f.Text)
	}
}

func TestRTP绕圈与迟到和重复各记各的(t *testing.T) {
	a := NewAggregator(Options{})
	// 100 101 101（重复） 106（空位 4） 103（到晚了）
	for i, seq := range []uint16{100, 101, 101, 106, 103} {
		media(t, a, i, seq, 0x77, 96, []byte{byte(i)})
	}
	fl := oneFlow(t, a)
	r := fl.RTP[0]
	if r.Dupes != 1 {
		t.Errorf("重复记成 %d", r.Dupes)
	}
	if r.Reorder != 1 {
		t.Errorf("迟到的记成 %d", r.Reorder)
	}
	if r.Gaps != 1 || r.Lost != 4 {
		t.Errorf("空位记成 %d 处 / %d 个号：%+v", r.Gaps, r.Lost, r)
	}
	mustHave(t, fl, "rtp-dup")
	mustHave(t, fl, "rtp-reorder")
	// 实收按「去掉重复」算：把又投了一遍的包当又收到一份内容，丢包率就被压低了。
	if got := r.Received(); got != 4 {
		t.Errorf("Received = %d，要 4（收了 5 包，其中一包是重复的）", got)
	}
}

func TestRTP账在报文列表到顶之后照样记(t *testing.T) {
	a := NewAggregator(Options{MaxMessages: 10})
	// 第 20 包那一带挖一个空位 —— 早已过了 10 条的上限。
	for i := 0; i < 30; i++ {
		if i == 20 {
			continue
		}
		media(t, a, i, uint16(1000+i), 0x99, 96, []byte{byte(i)})
	}
	fl := oneFlow(t, a)
	if len(fl.Messages) != 10 {
		t.Errorf("报文列表 %d 条，上限 10（这一格归上限管，没到顶就是记账挂错了地方）", len(fl.Messages))
	}
	if !noteWith(fl, "只留前 10 条") {
		t.Errorf("没说报文列表被截到上限：%v（不写出来，界面看着就是「这些就是全部的报文」）", fl.Notes)
	}
	if len(fl.RTP) != 1 {
		t.Fatalf("SSRC 账 %d 路", len(fl.RTP))
	}
	r := fl.RTP[0]
	if r.Packets != 29 {
		t.Fatalf("序号账只数了 %d 包，要 29（整条流都要数，不是前 10 包）", r.Packets)
	}
	// ★ 这一句是这一档存在的全部理由：账挂在 emit 上就会得出「前 10 包没丢，所以这条流没丢包」。
	f := mustHave(t, fl, "rtp-loss")
	if !strings.Contains(f.Text, "空位 1 处") {
		t.Errorf("空位那一句：%s", f.Text)
	}
}

func TestRTP两路SSRC分开记(t *testing.T) {
	a := NewAggregator(Options{})
	for i := 0; i < 4; i++ {
		media(t, a, i, uint16(10+i), 0x1111, 96, []byte{byte(i)})
	}
	// 另一路：号从 500 起，与第一路混在同一条 UDP 流上（同一对端口跑了两个源）。
	for i := 0; i < 3; i++ {
		media(t, a, 4+i, uint16(500+i), 0x2222, 96, []byte{byte(i)})
	}
	fl := oneFlow(t, a)
	if len(fl.RTP) != 2 {
		t.Fatalf("记成 %d 路，要 2 路（混着数会把两路的序号差当成一处大跳）", len(fl.RTP))
	}
	for _, r := range fl.RTP {
		if r.Jumps != 0 || r.Lost != 0 {
			t.Errorf("SSRC %08x 的账串了：%+v", r.SSRC, r)
		}
	}
	mustNotHave(t, fl, "rtp-loss")
	mustNotHave(t, fl, "rtp-seq-jump")
}

func TestRTP的SSRC多到上限要明说没数完(t *testing.T) {
	a := NewAggregator(Options{})
	for i := 0; i < maxRTPSources+8; i++ {
		media(t, a, i, uint16(100+i), uint32(0x10000+i), 96, []byte{byte(i)})
	}
	fl := oneFlow(t, a)
	if len(fl.RTP) != maxRTPSources {
		t.Errorf("记了 %d 路，上限 %d（不设上限就是给脏包留门：每包换一个新 SSRC 能把内存吃没）",
			len(fl.RTP), maxRTPSources)
	}
	if fl.RTPSkipped != 8 {
		t.Errorf("没记账的包数 = %d，要 8", fl.RTPSkipped)
	}
	if !noteWith(fl, "没记账") {
		t.Errorf("没说出来：%v（一张脏表显示「只有一路、一路没丢」是最坏的那种假话）", fl.Notes)
	}
}

func TestRTCP的报告解出那几格(t *testing.T) {
	a := NewAggregator(Options{})
	// RTCP 走的是 RTP 那对口之上的另一对（server_port+1 → client_port+1），
	// 它自己就是一条流：这一档只验「报告里那几格解得对不对」，不牵扯跨流。
	sr := rtcpPacket(200, 1, 0x1234abcd, srBody(
		0xE0000000, 0x80000000, 90000, 1234, 567890,
		0x1234abcd, 12, 3, 199, 450, 0x11223344, 655360))
	if err := add(a, pkt{when: at(0), src: device, sp: 555, dst: client, dp: 6971, payload: sr}); err != nil {
		t.Fatal(err)
	}
	fl := oneFlow(t, a)
	var m *Message
	for i := range fl.Messages {
		if fl.Messages[i].Proto == "rtcp" {
			m = &fl.Messages[i]
		}
	}
	if m == nil {
		t.Fatalf("RTCP 报告没解出来：%s", msgsOf(fl))
	}
	if !strings.Contains(m.Summary, "SR") {
		t.Errorf("类型：%q", m.Summary)
	}
	want := map[string]string{
		"它自己数发了":   "1234 包 / 567890 字节正文",
		"接收端自报丢包":  "这一阵 12/255、累计 3 包",
		"它看到的最高序号": "199",
	}
	for k, v := range want {
		got := ""
		for _, fd := range m.Fields {
			if fd.K == k {
				got = fd.V
			}
		}
		if got != v {
			t.Errorf("%s = %q，要 %q（★SR 的接收块从第 28 字节起，不是 32：多算 4 字节整块挪一位）", k, got, v)
		}
	}
	// DLSR 655360 = 10.0 ms：它是「收到上一份 SR 之后攒了多久」，不是往返时延。
	if !anyContains(fieldsOf(m.Fields), "10.0 ms") || !anyContains(fieldsOf(m.Fields), "不是往返时延") {
		t.Errorf("DLSR 那一句：%v（当成 RTT 报出去，现场会照着几百毫秒说链路慢）", m.Fields)
	}
	// 抖动不换算成毫秒：时钟率只在 SDP 里，这一档没拿到就不编。
	if !anyContains(fieldsOf(m.Fields), "时钟刻度") {
		t.Errorf("抖动那格：%v", m.Fields)
	}
}

// ==================== 其它专解 ====================

func TestONVIF的SOAP调用与WSSE口令(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 80)
	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` +
		`xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` +
		`<s:Header><wsse:Security><wsse:UsernameToken>` +
		`<wsse:Username>admin</wsse:Username>` +
		`<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">Onvif-Pw-Plain-9182</wsse:Password>` +
		`</wsse:UsernameToken></wsse:Security></s:Header>` +
		`<s:Body><trt:GetStreamUri><trt:StreamSetup><tt:Stream xmlns:tt="http://www.onvif.org/ver10/schema">RTP-Unicast</tt:Stream></trt:StreamSetup></trt:GetStreamUri></s:Body></s:Envelope>`
	s.ask(t, 3, "POST /onvif/media_service HTTP/1.1\r\nHost: 10.0.0.9\r\nContent-Type: application/soap+xml\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)

	fl := oneFlow(t, a)
	if fl.App != "onvif" {
		t.Fatalf("App=%q：SOAP 里写着 onvif 的命名空间，不该定成 http/soap", fl.App)
	}
	if len(fl.Messages) != 1 {
		t.Fatalf("解出 %d 条：%s", len(fl.Messages), msgsOf(fl))
	}
	m := fl.Messages[0]
	if m.Soap != "GetStreamUri" {
		t.Errorf("SOAP 方法 = %q", m.Soap)
	}
	if m.Creds == 0 {
		t.Errorf("Creds = 0：WSSE 里那条口令根本没算进脱敏数，界面就不敢说「已脱敏」")
	}
	if !anyContains(fieldsOf(m.Fields), "admin") {
		t.Errorf("用户名被打掉了：%v（口令要糊，用户名留着，不然「哪个账号被拒」这一句答不了）", m.Fields)
	}
}

func TestSNMP的团体名一律不上表(t *testing.T) {
	pk, err := snmp.NewGet("Private-Community-9", "1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pk.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a := NewAggregator(Options{})
	if err := add(a, pkt{when: at(0), src: client, sp: 51234, dst: device, dp: 161, payload: raw}); err != nil {
		t.Fatal(err)
	}
	fl := oneFlow(t, a)
	if fl.App != "snmp" {
		t.Fatalf("App=%q，要 snmp（按内容认的：团体名那一格的位置与长度都在外壳里写着）", fl.App)
	}
	if len(fl.Messages) != 1 {
		t.Fatalf("解出 %d 条：%s", len(fl.Messages), msgsOf(fl))
	}
	m := fl.Messages[0]
	if m.Creds == 0 {
		t.Errorf("Creds = 0：v2c 的团体名就是它的读口令")
	}
	for _, fd := range m.Fields {
		if fd.K == "团体名" && !fd.Redacted {
			t.Errorf("团体名那格没打脱敏标记：%+v", fd)
		}
	}
}

// ==================== 测试用的报文构造 ====================

// dnsQuery 造一份最简的 DNS 查询（只一个问题名），用来在同一个四元组上撞出第二种协议。
func dnsQuery(name string) string {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[4:6], 1) // 一个问题
	for _, part := range strings.Split(name, ".") {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // QTYPE = A
	b = binary.BigEndian.AppendUint16(b, 1) // QCLASS = IN
	return string(b)
}

func fieldsOf(fs []Field) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.K+"="+f.V)
	}
	return out
}

func msgsOf(fl *Flow) string {
	parts := make([]string, 0, len(fl.Messages))
	for _, m := range fl.Messages {
		parts = append(parts, m.String())
	}
	return strings.Join(parts, " | ")
}

// sipRequest 起一条国标的请求：头集中在一处，免得每个用例各写一遍、各错一遍。
func sipRequest(t *testing.T, method string, cseq uint64) *gb28181.Message {
	t.Helper()
	platform := "34020000002000000001"
	deviceID := "34020000001320000001"
	via := gb28181.NewVia(client, "5060")
	uri := gb28181.SIPURI(platform, device, "5060")
	req := gb28181.NewRequest(method, uri,
		"<"+gb28181.SIPURI(deviceID, client, "5060")+">",
		"<"+uri+">",
		"gb-"+strconv.FormatUint(cseq, 10), via.String(), cseq)
	req.Set(gb28181.HContact, "<"+gb28181.SIPURI(deviceID, client, "5060")+">")
	req.Set(gb28181.HUserAgent, "netkit-flow-test")
	if method == gb28181.MethodRegister {
		req.Set(gb28181.HExpires, "3600")
	}
	return req
}

func sipResponse(t *testing.T, req *gb28181.Message, status int) *gb28181.Message {
	t.Helper()
	resp := gb28181.NewResponseFor(req, status, "")
	if status == 401 {
		ch := &gb28181.Challenge{Realm: "3402000000", Nonce: "nonce-flow-test", QOP: []string{"auth"}}
		resp.Set(gb28181.HWWWAuthenticate, ch.Header())
	}
	return resp
}

func sipAsk(t *testing.T, a *Aggregator, n int, msg *gb28181.Message) error {
	t.Helper()
	return add(a, pkt{when: at(n), src: client, sp: 5060, dst: device, dp: 5060, payload: msg.MustBytes()})
}

func sipReply(t *testing.T, a *Aggregator, n int, msg *gb28181.Message) error {
	t.Helper()
	return add(a, pkt{when: at(n), src: device, sp: 5060, dst: client, dp: 5060, payload: msg.MustBytes()})
}

// mqttConnect 造一条 3.1.1 的 CONNECT：带用户名与口令（标志位 0xC0 那两格）。
//
// ★ 剩余长度那一格必须与整包对得上：isMQTTPlausible 认的是「这一份刚好是一条」，
// 长度写错就是定不上口，测试会以「没解出来」收场而看不出是自己造的包坏了。
func mqttBuildConnect(clientID, user, pass string) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, 4)
	body = append(body, "MQTT"...)
	body = append(body, 4, 0xC0, 0, 60) // 版本 3.1.1，用户名 + 口令，保活 60 秒
	body = append(body, mqttStrField(clientID)...)
	body = append(body, mqttStrField(user)...)
	body = append(body, mqttStrField(pass)...)
	return mqttPacket(1, 0, body)
}

// mqttConnAck 造一条 CONNACK：code 0 成了，5 是「用户名或口令不对」。
func mqttBuildConnAck(code byte) []byte {
	return mqttPacket(2, 0, []byte{0, code})
}

func mqttStrField(s string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(s)))
	return append(b, s...)
}

func mqttPacket(typ, flags byte, body []byte) []byte {
	out := []byte{typ<<4 | flags}
	// 剩余长度：这里只用单字节那一档（测试的包都不超过 127 字节）。
	if len(body) > 127 {
		panic("mqttPacket：测试用的剩余长度只写到单字节")
	}
	return append(out, append([]byte{byte(len(body))}, body...)...)
}
