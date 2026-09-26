package flow

// 这一份钉的是「跨流的那根线连得对不对」。
//
// 信令与媒体本来是一件事的两半：SETUP 写在 TCP 那一条上，画面跑在另一条 UDP 上，
// 表上是两行。分开看各自都「正常」，连错了才看得见的病（说好的口上什么都没落、
// 平台点给的 ssrc 与设备推的不是同一个）才有地方说。
//
// 这一层最容易出的两种错，一种是**漏连**（那条媒体流明明在表上，
// 结论却说「什么都没落」，现场被支去查一台没发过包的机器），
// 另一种是**多嘴**（信令里没写明的也照上去说一句）。
// 所以每条用例都同时钉两头：该连的连上了、该闭嘴的没出声。

import (
	"strconv"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/gb28181"
)

// ==================== 喂媒体流的手 ====================

// stream 从设备往客户端复一路 UDP：媒体那条流的两个端点由用例自己定，
// 因为跨流连的正是「端口对不对得上」，把端口写死在helper里就测不到连错了。
func stream(t *testing.T, a *Aggregator, n int, sp, dp uint16, payload []byte) {
	t.Helper()
	streamTo(t, a, n, device, sp, client, dp, payload)
}

// streamTo 是它的两端都放开那一档：destination= 指向第三台机器时要按机器连。
func streamTo(t *testing.T, a *Aggregator, n int, src string, sp uint16, dst string, dp uint16, payload []byte) {
	t.Helper()
	if err := add(a, pkt{when: at(n), src: src, sp: sp, dst: dst, dp: dp, payload: payload}); err != nil {
		t.Fatalf("第 %d 个媒体包（%s:%d→%s:%d）：%v", n, src, sp, dst, dp, err)
	}
}

// rtcpTo 复一路 RTCP：SETUP 说明好的是「RTP 一个口、报告一个口」两对，
// 只复 RTP 不复报告，表上就永远缺两个口 —— 那一种缺是测试自己造的。
func rtcpTo(t *testing.T, a *Aggregator, n int, sp, dp uint16, ssrc uint32) {
	t.Helper()
	stream(t, a, n, sp, dp, rtcpPacket(201, 0, ssrc, nil))
}

// inviteSDP 是一份国标点播正文。★ y= 写在 m= 之后（媒体级）—— 各家实现都这么写，
// 而「只翻会话级那一份」正是这一格以前读不到的原因。
func inviteSDP(target string, port int, ssrc string) string {
	b := "v=0\r\n" +
		"o=34020000001110000001 20250101 1 IN IP4 " + target + "\r\n" +
		"s=Play\r\n" +
		"c=IN IP4 " + target + "\r\n" +
		"t=0 0\r\n" +
		"m=video " + strconv.Itoa(port) + " RTP/AVP 96\r\n" +
		"a=recvonly\r\n"
	if ssrc != "" {
		b += "y=" + ssrc + " 0 0\r\n"
	}
	return b
}

// ==================== 读连线的手 ====================

// flowWith 回端点是这两头的那一条流。★ 不按键写死：键里的端口是测试自己造的，
// 连线读的也正是端口，两边各写一遍就会有一处改漏。
func flowWith(t *testing.T, a *Aggregator, ep1, ep2 string) *Flow {
	t.Helper()
	var hit *Flow
	for _, fl := range a.Flows() {
		if (fl.A == ep1 && fl.B == ep2) || (fl.A == ep2 && fl.B == ep1) {
			if hit != nil {
				t.Fatalf("同样的端点有两条流：%s 与 %s（那等于一次 SETUP 被当成两路画面）", hit.Key, fl.Key)
			}
			hit = fl
		}
	}
	if hit == nil {
		t.Fatalf("表上没有 %s ↔ %s 这一条：%s", ep1, ep2, keysOf(a.Flows()))
	}
	return hit
}

func refKey(refs []FlowRef) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		parts = append(parts, r.Key)
	}
	return strings.Join(parts, "、")
}

func hasRef(t *testing.T, refs []FlowRef, key string) {
	t.Helper()
	for _, r := range refs {
		if r.Key == key {
			return
		}
	}
	t.Fatalf("引用里没有 %s，实际有：%s", key, refKey(refs))
}

// ==================== RTSP：说好的四个口都有流 ====================

func TestSETUP说好的口都有流就把两边连上(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\nTransport: RTP/AVP;unicast;client_port=6970-6971;server_port=6972-6973;destination=192.168.1.10\r\n\r\n")
	s.ask(t, 5, "PLAY rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 2\r\nSession: 12345\r\nRange: npt=0.000-\r\n\r\n")
	s.reply(t, 6, "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 12345\r\n\r\n")
	// 画面与报告各一对口：RTP 6972→6970、RTCP 6973→6971。
	stream(t, a, 7, 6972, 6970, rtpPacket(0x1234abcd, 1, 160, 96, false, make([]byte, 160)))
	rtcpTo(t, a, 8, 6973, 6971, 0x1234abcd)

	sig := flowWith(t, a, "192.168.1.10:51234", "10.0.0.9:554")
	rtp := flowWith(t, a, "10.0.0.9:6972", "192.168.1.10:6970")

	// ★ 两头都要挂上：只挂信令那一头，现场拿着媒体那条流问「这是谁开的」仍然查不到。
	hasRef(t, sig.Media, rtp.Key)
	hasRef(t, rtp.Signaling, sig.Key)
	if len(sig.Missing) != 0 {
		t.Errorf("四个口都有流，还说着缺：%s", strings.Join(sig.Missing, "、"))
	}
	if _, ok := finding(sig, "signaling-promised-no-media"); ok {
		t.Errorf("线连上了还报缺流，判定就变成假警报：%s", codesOf(sig))
	}
	// 引用里的端点是抄来的那一头，不是键本身：拿引用就能说出对端是谁，不用再查一遍表。
	for _, r := range sig.Media {
		if r.Key == rtp.Key && !strings.Contains(r.EPs, "6970") {
			t.Errorf("引用没带上对端端点：%+v", r)
		}
	}
}

// ==================== RTSP：SETUP 成了，表上什么都没有 ====================

func TestSETUP成了却没有流落在说好的口上(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\nTransport: RTP/AVP;unicast;client_port=6970-6971;server_port=6972-6973\r\n\r\n")

	sig := flowWith(t, a, "192.168.1.10:51234", "10.0.0.9:554")
	f, ok := finding(sig, "signaling-promised-no-media")
	if !ok {
		t.Fatalf("SETUP 成了、四个口一条流都没有，这一句却没说：判定只有 %s", codesOf(sig))
	}
	// ★ 四个口要在同一句里报全：判定按码去重，分开发只会剩第一个口，
	// 现场就会以为只有 6970 没落上，查完那一头回来才发现报告口也没人发。
	for _, want := range []string{"192.168.1.10:6970", "192.168.1.10:6971", "10.0.0.9:6972", "10.0.0.9:6973"} {
		if !strings.Contains(f.Text, want) {
			t.Errorf("缺的口里没报 %s：%s", want, f.Text)
		}
	}
	// 措辞的上限是「表上没有」，不是「它没发」：换个口抓、交换机没镜像都看不见那一段。
	if !strings.Contains(f.Text, "表上没有") {
		t.Errorf("这句话越了口径的上限（说成了「它没发」）：%s", f.Text)
	}
	if len(sig.Media) != 0 {
		t.Errorf("一条流都没落上却挂了引用：%s", refKey(sig.Media))
	}
}

// ==================== SETUP 没成：没有资格谈缺流 ====================

func TestSETUP没成不说缺流(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nRequire: www-authenticate\r\nTransport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"cam\", nonce=\"abc123\"\r\n\r\n")

	sig := flowWith(t, a, "192.168.1.10:51234", "10.0.0.9:554")
	// ★ 会话都没建成，没有媒体是正常的。这时候说「说好了发流却没落上」
	// 等于把人支去查一条根本没开过的路。
	if _, ok := finding(sig, "signaling-promised-no-media"); ok {
		t.Errorf("SETUP 被 401 拒了还报缺流：%s", codesOf(sig))
	}
	if len(sig.Missing) != 0 {
		t.Errorf("没成的会话也攒了空口：%s", strings.Join(sig.Missing, "、"))
	}
}

// ==================== 走 TCP 复用的画面不另连 ====================

func Test走TCP复用的画面不另连媒体流(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n")

	sig := flowWith(t, a, "192.168.1.10:51234", "10.0.0.9:554")
	// ★ interleaved 的画面就在这条 TCP 上，压根没有另一个 UDP 口。
	// 按端口去连就会给这一条挂一个「缺流」，而那是设计里根本没有的东西。
	if len(sig.Missing) != 0 || len(sig.Media) != 0 {
		t.Fatalf("TCP 复用被当成 UDP 连线了：缺 %v 引用 %s", sig.Missing, refKey(sig.Media))
	}
	if _, ok := finding(sig, "signaling-promised-no-media"); ok {
		t.Errorf("TCP 复用报出「表上没有 UDP 流」：%s", codesOf(sig))
	}
}

// ==================== 只按信令里写明的 destination 连 ====================

func Test按写明的destination连不按方向推(t *testing.T) {
	const nvr = "192.168.1.20"
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	// 设备在应答里明写「我发给 NVR」：这种转发的案子里收流的不是发 SETUP 的那一端。
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\nTransport: RTP/AVP;destination="+nvr+";client_port=6970\r\n\r\n")
	streamTo(t, a, 5, device, 6974, nvr, 6970, rtpPacket(0xabcd0001, 1, 160, 96, false, make([]byte, 160)))

	sig := flowWith(t, a, "192.168.1.10:51234", "10.0.0.9:554")
	// 媒体流的端点是 device:6974 → nvr:6970，落点地址是 NVR 而不是取流端。
	nvrFlow := flowWith(t, a, "10.0.0.9:6974", nvr+":6970")
	hasRef(t, sig.Media, nvrFlow.Key)
	if !strings.Contains(sig.Missing[0], client+":6970") {
		t.Errorf("destination 之外的另一格没报缺：%v", sig.Missing)
	}
	// ★ 那一头的端点要抄在引用里：拿着引用查不到「发给谁」，还得回头翻表。
	for _, r := range sig.Media {
		if r.Key == nvrFlow.Key && !strings.Contains(r.EPs, nvr) {
			t.Errorf("引用里没写清发给哪台：%+v", r)
		}
	}
}

// ==================== 国标：SDP 说好的口与 ssrc ====================

func Test国标点播说好的口与ssrc都对上就不说话(t *testing.T) {
	a := NewAggregator(Options{})
	inv := sipRequest(t, gb28181.MethodInvite, 1)
	inv.Body = []byte(inviteSDP(client, 20002, "01000068"))
	if err := sipAsk(t, a, 3, inv); err != nil {
		t.Fatal(err)
	}
	resp := sipResponse(t, inv, 200)
	resp.Body = []byte("v=0\r\no=34020000001320000001 1 1 IN IP4 " + device + "\r\ns=Play\r\nc=IN IP4 " + device +
		"\r\nt=0 0\r\nm=video 30000 RTP/AVP 96\r\na=sendonly\r\n")
	if err := sipReply(t, a, 4, resp); err != nil {
		t.Fatal(err)
	}
	stream(t, a, 5, 30000, 20002, rtpPacket(0x01000068, 1, 90, 96, false, make([]byte, 160)))

	sig := flowWith(t, a, client+":5060", device+":5060")
	med := flowWith(t, a, device+":30000", client+":20002")
	hasRef(t, sig.Media, med.Key)
	// ★ y= 写在 m= 之后（媒体级）。只翻会话级那一份就比不到，
	// 于是这一格永远「安静」，看着像查过没问题。
	if noteWith(sig, "没比对") {
		t.Errorf("ssrc 明明读得出来（01000068），却说着没比对：%v", sig.Notes)
	}
	if _, ok := finding(sig, "rtp-ssrc-mismatch"); ok {
		t.Errorf("两边 ssrc 一样还报对不上号：%s", codesOf(sig))
	}
	if _, ok := finding(sig, "signaling-promised-no-media"); ok {
		t.Errorf("流明明落在说好的口上：%s", codesOf(sig))
	}
}

func Test国标点给的ssrc与设备推的不是同一个(t *testing.T) {
	a := NewAggregator(Options{})
	inv := sipRequest(t, gb28181.MethodInvite, 1)
	inv.Body = []byte(inviteSDP(client, 20002, "01000068"))
	if err := sipAsk(t, a, 3, inv); err != nil {
		t.Fatal(err)
	}
	// 平台按 ssrc 白名单收流：对不上号的那一路整个丢掉，网络一个包都没丢。
	stream(t, a, 5, 30000, 20002, rtpPacket(0x02000068, 1, 90, 96, false, make([]byte, 160)))

	sig := flowWith(t, a, client+":5060", device+":5060")
	f, ok := finding(sig, "rtp-ssrc-mismatch")
	if !ok {
		t.Fatalf("说好的 01000068 与实际推的 02000068 对不上，这一句却没说：判定只有 %s", codesOf(sig))
	}
	for _, want := range []string{"01000068", "02000068"} {
		if !strings.Contains(f.Text, want) {
			t.Errorf("这句话里没写出 %s：%s", want, f.Text)
		}
	}
	// ★ 必须说清「与丢包无关」：这一路的包是齐的，看的人第一反应是去查链路。
	if !strings.Contains(f.Text, "与丢包无关") {
		t.Errorf("这句话没挡住「去查链路」那条弯路：%s", f.Text)
	}
}

func Test信令里的ssrc读不出数字要明写没比对(t *testing.T) {
	a := NewAggregator(Options{})
	inv := sipRequest(t, gb28181.MethodInvite, 1)
	// 国标的 y= 各家位数不一（八位、十位都见过），而 RTP 头里那一格只有 32 位。
	inv.Body = []byte(inviteSDP(client, 20002, "0100000000"))
	if err := sipAsk(t, a, 3, inv); err != nil {
		t.Fatal(err)
	}
	stream(t, a, 5, 30000, 20002, rtpPacket(0x01000068, 1, 90, 96, false, make([]byte, 160)))

	sig := flowWith(t, a, client+":5060", device+":5060")
	if _, ok := finding(sig, "rtp-ssrc-mismatch"); ok {
		t.Errorf("读不出数字就当成「对不上」：那是拿工具的口径当设备的口径（%s）", codesOf(sig))
	}
	// ★ 不替厂家猜哪一位才是 SSRC，但「这一格没比对」必须写在表上 ——
	// 默默跳过会被读成「查过了，没问题」，而现场最信的就是这种没出声的地方。
	if !noteWith(sig, "没比对") {
		t.Fatalf("读不出的 ssrc 没在表上留话。说明：%v", sig.Notes)
	}
	if !noteWith(sig, "0100000000") {
		t.Errorf("那句话没写出读的是哪一个值（现场要能指回信令那一格）：%v", sig.Notes)
	}
}

// ==================== 来回几次 SETUP 只留一条引用 ====================

func Test一条信令开两路媒体各挂各的引用(t *testing.T) {
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	// 音视频各一路 SETUP（同一个会话里两次），两路画面落在不同的口上。
	s.ask(t, 3, "SETUP rtsp://10.0.0.9/live/1/trackID=1 RTSP/1.0\r\nCSeq: 1\r\nTransport: RTP/AVP;unicast;client_port=6970\r\n\r\n")
	s.reply(t, 4, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345\r\n\r\n")
	s.ask(t, 5, "SETUP rtsp://10.0.0.9/live/1/trackID=2 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP;unicast;client_port=6972\r\n\r\n")
	s.reply(t, 6, "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 12345\r\n\r\n")
	stream(t, a, 7, 7000, 6970, rtpPacket(0x00001111, 1, 160, 96, false, make([]byte, 160)))
	stream(t, a, 8, 7002, 6972, rtpPacket(0x00002222, 1, 160, 8, false, make([]byte, 160)))

	sig := flowWith(t, a, "192.168.1.10:51234", "10.0.0.9:554")
	v := flowWith(t, a, "10.0.0.9:7000", "192.168.1.10:6970")
	audio := flowWith(t, a, "10.0.0.9:7002", "192.168.1.10:6972")
	hasRef(t, sig.Media, v.Key)
	hasRef(t, sig.Media, audio.Key)
	if len(sig.Media) != 2 {
		t.Fatalf("两路媒体挂出 %d 条引用：%s", len(sig.Media), refKey(sig.Media))
	}
	// 两条媒体流各自知道自己是谁开的：反过来查「这一路是谁开的」要有答案。
	hasRef(t, v.Signaling, sig.Key)
	hasRef(t, audio.Signaling, sig.Key)
}
