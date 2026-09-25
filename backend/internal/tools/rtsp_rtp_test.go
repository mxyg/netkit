package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCam 是一个会真的发码流的假设备。
//
// ★ 收流这一问没法只靠解析函数测：SETUP 的传输谈法、Session 从哪来、
//
//	交织帧的 framing、哪些包该丢掉 —— 全在和这台「设备」对话的那一刻才见分晓。
type fakeCam struct {
	sdp       string
	refuseUDP bool          // SETUP 走 UDP 时回 461
	stray     bool          // 一半的包从另一个地址发（别的会话）
	pace      time.Duration // 两包之间隔多久，默认 20 毫秒
	noData    bool          // PLAY 200 但一个包都不发
	tcp       bool          // 用交织发（refuseUDP 时自动）

	mu   sync.Mutex
	seen []string // 每一问的「方法 地址」
}

func (f *fakeCam) record(s string) {
	f.mu.Lock()
	f.seen = append(f.seen, s)
	f.mu.Unlock()
}

func (f *fakeCam) methods() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.seen, "\n")
}

func (f *fakeCam) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return ln.Addr().String()
}

func (f *fakeCam) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	clientPort := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		method, uri := fields[0], fields[1]
		hdr := map[string]string{}
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			if l == "" {
				break
			}
			if i := strings.Index(l, ":"); i > 0 {
				hdr[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
			}
		}
		cseq := hdr["cseq"]
		f.record(method + " " + uri)
		// 真设备只认会话号本身：把 ;timeout=60 一并带回来的客户端会被回 500。
		if method == "PLAY" && strings.SplitN(hdr["session"], ";", 2)[0] != "987654321" {
			fmt.Fprintf(c, "RTSP/1.0 500 Invalid Session\r\nCSeq: %s\r\n\r\n", cseq)
			continue
		}
		switch method {
		case "SETUP":
			tr := hdr["transport"]
			switch {
			case strings.Contains(tr, "TCP"):
				fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: 987654321;timeout=60\r\n"+
					"Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n", cseq)
				f.tcp = true
			case f.refuseUDP:
				fmt.Fprintf(c, "RTSP/1.0 461 Unsupported Transport\r\nCSeq: %s\r\n\r\n", cseq)
			default:
				clientPort = portAfter(tr, "client_port=")
				fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: 987654321;timeout=60\r\n"+
					"Transport: RTP/AVP;unicast;client_port=%d-%d;server_port=6666-6667\r\n\r\n",
					cseq, clientPort, clientPort+1)
			}
		case "PLAY":
			fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nSession: 987654321\r\nRTP-Info: url=%s;seq=1;rtptime=0\r\n\r\n", cseq, uri)
			if !f.noData {
				f.emit(c, clientPort)
			}
		case "TEARDOWN":
			fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\n\r\n", cseq)
			return
		default: // DESCRIBE / OPTIONS / GET_PARAMETER
			if f.sdp == "" {
				fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Length: 0\r\n\r\n", cseq)
				continue
			}
			fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Type: application/sdp\r\n"+
				"Content-Length: %d\r\n\r\n%s", cseq, len(f.sdp), f.sdp)
		}
	}
}

// emit 发一小段码流，内容见 rtpBurst：UDP 那一路从临时口发给 client_port，
// TCP 那一路把同一批包套上交织帧头写回控制连接。
func (f *fakeCam) emit(tcp net.Conn, clientPort int) {
	burst := rtpBurst()
	if f.tcp {
		// 中间夹一发 RTCP：统计要是认了它，读数会多出「第二个源」。
		for i, pkt := range burst {
			if i == 10 {
				writeInterleaved(tcp, 1, rtcpFake())
			}
			writeInterleaved(tcp, 0, pkt)
			time.Sleep(f.paceMs())
		}
		return
	}
	uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", clientPort))
	if err != nil {
		return
	}
	defer uc.Close()
	// stray 那一档：另一个发源混进来的包（现场就是组播里别人的会话、
	// 或者同机第二路取流）。★ 收流的口是本机随机偶数口，谁都能往里发 ——
	//   不认来源就把别人的码流算成这路的。这里从 ::1 发，控制连接走的是 127.0.0.1。
	var stray *net.UDPConn
	if f.stray {
		b, berr := net.ResolveUDPAddr("udp", fmt.Sprintf("[::1]:%d", clientPort))
		if berr == nil {
			stray, _ = net.DialUDP("udp", nil, b)
		}
	}
	for i, pkt := range burst {
		w := net.Conn(uc)
		if stray != nil && i%2 == 1 {
			w = stray
		}
		_ = w.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = w.Write(pkt)
		time.Sleep(f.paceMs())
	}
}

// paceMs 是发包的节奏。★ 收流窗口要能真的被收满，才有「窗口被掐短」这一问可对。
func (f *fakeCam) paceMs() time.Duration {
	if f.pace > 0 {
		return f.pace
	}
	return 20 * time.Millisecond
}

func writeInterleaved(c net.Conn, channel byte, payload []byte) {
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{'$', channel, byte(len(payload) >> 8), byte(len(payload))})
	_, _ = c.Write(payload)
}

func portAfter(s, key string) int {
	i := strings.Index(s, key)
	if i < 0 {
		return 0
	}
	v := s[i+len(key):]
	if j := strings.IndexAny(v, "-,;"); j >= 0 {
		v = v[:j]
	}
	n, _ := strconv.Atoi(v)
	return n
}

// rtpPkt 造一个 RTP 包（测试用，和 internal/media 里那份同格式）。
func rtpPkt(seq, ts int, marker bool, payload []byte) []byte {
	b := make([]byte, 12+len(payload))
	b[0] = 0x80
	if marker {
		b[1] |= 0x80
	}
	b[1] |= 96
	b[2], b[3] = byte(seq>>8), byte(seq)
	b[4], b[5], b[6], b[7] = byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts)
	b[8], b[9], b[10], b[11] = 0, 0, 4, 7
	copy(b[12:], payload)
	return b
}

func rtcpFake() []byte {
	b := make([]byte, 28)
	b[0] = 0x80
	b[1] = 200 // SR：版本也是 2，只看版本号拦不住它
	return b
}

func rtpBurst() [][]byte {
	var out [][]byte
	for i := 0; i < 40; i++ {
		if i == 5 || i == 6 {
			continue // 这两包在路上没了
		}
		payload := make([]byte, 200)
		if i == 0 || i == 20 {
			payload[0] = 0x65 // IDR
		} else {
			payload[0] = 0x61
		}
		// 每张 IDR 的 RTP 时间戳整整数 270000（= 90kHz 下 3 秒），包内再按帧走
		out = append(out, rtpPkt(i, (i/20)*270000+(i%20)*3600, i%10 == 9, payload))
	}
	return out
}

// ★ 这一条才是这次升级的全部意义：SDP 写着 25fps 是设备的说法，
//
//	几秒里到了多少包、隔多久来一个关键帧，才是盒子里真有的东西。
func Test收一段流量出实际码率与关键帧间隔(t *testing.T) {
	cam := &fakeCam{sdp: sdpH264(sps2K)}
	addr := cam.start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":1500}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q（vals=%v）", code, vals)
	}
	if vals["measured"] != true {
		t.Fatalf("没量到：%v", vals["measureNote"])
	}
	if vals["transport"] != "udp" {
		t.Errorf("传输路子 = %v，期望 udp —— 只有这一路问得出丢包", vals["transport"])
	}
	rtp, _ := vals["rtp"].(map[string]any)
	if rtp == nil {
		t.Fatal("结果里没有 rtp 那一格")
	}
	if got := rtp["packets"]; got != 38.0 {
		t.Errorf("收到包数 = %v，期望 38（40 包缺两包）", got)
	}
	if got := rtp["lostPackets"]; got != 2.0 {
		t.Errorf("丢包数 = %v，期望 2", got)
	}
	if got := rtp["bitrateKbps"]; got == nil || got.(float64) < 55 || got.(float64) > 110 {
		t.Errorf("实际码率 = %v kbps，期望 55~110（38 包 × 200 字节，约 0.8 秒）", got)
	}
	if got := rtp["keyframeEveryMs"]; got == nil || got.(float64) < 2800 || got.(float64) > 3200 {
		t.Errorf("关键帧间隔 = %v ms，期望 3000（两张 IDR 的 RTP 时间戳差）", got)
	}
	if m := cam.methods(); !strings.Contains(m, "TEARDOWN") {
		t.Errorf("收完没走 TEARDOWN，设备的取流档位会被一直占着：%s", m)
	}
}

// SETUP 的地址要用 SDP 给的轨名，不是会话地址 —— 拼错了设备直接回 404。
func TestSETUP用的是SDP里的轨地址(t *testing.T) {
	cam := &fakeCam{sdp: sdpH264(sps2K)}
	addr := cam.start(t)
	probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":600}`)
	found := false
	for _, l := range strings.Split(cam.methods(), "\n") {
		if strings.HasPrefix(l, "SETUP ") {
			found = strings.HasSuffix(l, "/live/track1")
			break
		}
	}
	if !found {
		t.Errorf("SETUP 问的不是视频那一轨：%s", cam.methods())
	}
	// PLAY 问会话地址（聚合控制地址），不是某一轨 —— 反过来不少设备直接回 400。
	// ★ 整行对上：「以 /live 开头」这种查法，把轨地址那一行也算成了对的。
	playOK := false
	for _, l := range strings.Split(cam.methods(), "\n") {
		if l == "PLAY rtsp://"+addr+"/live" {
			playOK = true
		}
	}
	if !playOK {
		t.Errorf("PLAY 问的地址不对：%s", cam.methods())
	}
}

// ★ 收流的 UDP 口是本机随机口，谁都能往里发。不认来源，
//
//	「这台相机 1.9Mbps」里就掺了别人那一路的字节。
func Test只认这台设备发来的包(t *testing.T) {
	cam := &fakeCam{sdp: sdpH264(sps2K), stray: true}
	addr := cam.start(t)
	_, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":1500}`)
	rtp, _ := vals["rtp"].(map[string]any)
	if rtp == nil {
		t.Fatalf("没量到：%v", vals["measureNote"])
	}
	if got := rtp["packets"]; got != 19.0 {
		t.Errorf("收到包数 = %v，期望 19（一半从另一个地址来的不该算）—— 38 就是别人的码流也计进来了", got)
	}
	if got := rtp["rtpSources"]; got != 1.0 {
		t.Errorf("源数量 = %v，期望 1", got)
	}
}

// ★ 一问一答的超时不该把收流掐掉：现场把 timeoutMs 调到 1 秒很常见（设备答得慢，
// 人就想快一点），要是它顺带把三秒的收流窗口也卡成一秒，读数就成了「窗口太短」。
func Test收流的窗口不被一问一答的超时掐掉(t *testing.T) {
	// 40 包 × 70 毫秒 = 2.8 秒的一小段，比 3 秒的窗口短，收得完
	cam := &fakeCam{sdp: sdpH264(sps2K), pace: 70 * time.Millisecond}
	addr := cam.start(t)
	_, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":3000,"timeoutMs":1000}`)
	if vals["measured"] != true {
		t.Fatalf("没量到：%v", vals["measureNote"])
	}
	rtp, _ := vals["rtp"].(map[string]any)
	if got := rtp["measuredMs"]; got == nil || got.(float64) < 2500 {
		t.Errorf("收流窗口 = %v ms，期望 ≥2500 —— 被信号超时掐了就不够折算码率", got)
	}
}

// 设备什么都应了（200），却一个包都不发 —— 这就是「盒子说没画面」最难读的一档。
// ★ 报成 stream-ok 会把人支去看下游；单独一个判定码才把他叫回设备那头。
func TestPLAY成了却没有一个包到(t *testing.T) {
	cam := &fakeCam{sdp: sdpH264(sps2K), noData: true}
	addr := cam.start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":700}`)
	if code != verdictStreamNoData {
		t.Fatalf("判定 = %q，期望 %q", code, verdictStreamNoData)
	}
	if _, has := vals["rtp"]; has {
		t.Error("一个包都没到却给了 RTP 读数")
	}
	if vals["measured"] != false {
		t.Error("没量到却标了 measured=true")
	}
	note := fmt.Sprint(probeFull(t, `{"url":"rtsp://`+addr+`/live","measureMs":700}`)["note"])
	if !strings.Contains(note, "一个 RTP 包都没到") {
		t.Errorf("没在结果里说清是哪一步空的：%q", note)
	}
}

// 有的固件只做 TCP 交织。★ 换过去之后必须留话：这一路 TCP 自己会重传，
// 报「0% 丢包」是假清白。
func Test设备不让走UDP就退回TCP交织(t *testing.T) {
	cam := &fakeCam{sdp: sdpH264(sps2K), refuseUDP: true}
	addr := cam.start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":1500}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q（vals=%v）", code, vals)
	}
	if vals["transport"] != "tcp-interleaved" {
		t.Fatalf("传输路子 = %v，期望 tcp-interleaved（measureNote=%v）", vals["transport"], vals["measureNote"])
	}
	if vals["transportNote"] == nil || vals["transportNote"] == "" {
		t.Error("换了路子这件事没留话 —— 现场会以为设备肯走 UDP")
	}
	if vals["measureNote"] != nil {
		t.Errorf("量到了却还挂着「没量到」那句话：%v", vals["measureNote"])
	}
	rtp, _ := vals["rtp"].(map[string]any)
	if rtp == nil {
		t.Fatal("退回 TCP 那一路却没量到")
	}
	if rtp["lossNote"] == nil || rtp["lossNote"] == "" {
		t.Error("TCP 这一路没写「丢包问不出来」—— 空着会被读成网络很好")
	}
	if rtp["lostPackets"] != nil {
		t.Errorf("TCP 那一路还报了丢包数：%v", rtp["lostPackets"])
	}
	if got := rtp["rtpSources"]; got != 1.0 {
		t.Errorf("源数量 = %v，期望 1 —— 夹进来的那发 RTCP 不该被当成第二个源", got)
	}
}

// 填 0 就是只问参数：不能偷偷多发 SETUP，设备只允许一路取流时那一路会被探测占掉。
func Test填0就只问参数不收流(t *testing.T) {
	cam := &fakeCam{sdp: sdpH264(sps2K)}
	addr := cam.start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":0}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q", code)
	}
	if m := cam.methods(); strings.Contains(m, "SETUP") || strings.Contains(m, "PLAY") {
		t.Errorf("说了不收流还去 SETUP：%s", m)
	}
	if vals["measured"] != false || vals["measureNote"] == "" {
		t.Errorf("跳过了收流这件事得留话：%v", vals)
	}
}

// 设备回了 SETUP 却不给会话号（半答应的固件常见）。★ 这时候不能把整条探测判坏，
// 也不能把「没量到」写成「量到 0」。
func Test设备不给会话号时只出参数并留话(t *testing.T) {
	addr := (&fakeRTSP{sdp: sdpH264(sps2K)}).start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/live","measureMs":500}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q —— 参数那一问是成的", code)
	}
	if vals["measured"] != false {
		t.Errorf("没量到却标了 measured=true：%v", vals)
	}
	if vals["measureNote"] == "" || vals["measureNote"] == nil {
		t.Error("没说清为什么这一格空着")
	}
	if _, has := vals["rtp"]; has {
		t.Error("没量到却给了 rtp 那一格")
	}
	// ★ 它回的是 200，只是没把会话号带回来 —— 那一句不能写成「不让走 UDP」，
	//	否则人跑去改传输配置，毛病其实在设备只回了一半。
	if tn, _ := vals["transportNote"].(string); strings.Contains(tn, "不让走 UDP") {
		t.Errorf("设备应了 200，却说它不让走 UDP：%q", tn)
	}
}

// probeFull 拿整份应答（判定码、values、还有给人看的那句 note）。
func probeFull(t *testing.T, args string) map[string]any {
	t.Helper()
	out, err := probeRTSP(context.Background(), json.RawMessage(args))
	if err != nil {
		t.Fatalf("探测出错：%v", err)
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
