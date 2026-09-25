package tools

// SETUP + PLAY 收一小段 RTP，把「设备说它打算发什么」变成「盒子里真到了什么」。
//
// ★ 这一问值得单独一个文件：DESCRIBE 是一问一答的纯文本，收流要占本机 UDP 口、
//   要在两条传输路子之间退让、还要在设备装死时留一句实话。混在主流程里，
//   最容易被改坏的是「没量到」被写成「量到 0」。

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/media"
)

// rtspMeasureWindow 定这一趟收多久。★ nil（没填）= 默认收 3 秒，
// 特意填 0 = 不收流（设备只允许一路取流、或者不想打断现网播放）。
func rtspMeasureWindow(ms *int) time.Duration {
	if ms == nil {
		return 3 * time.Second
	}
	if *ms <= 0 {
		return 0
	}
	d := time.Duration(*ms) * time.Millisecond
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	return d
}

// rtpMeasure 是一次收流的账。note 非空 = 没量到，原因就写在那一句里。
type rtpMeasure struct {
	reading   media.Reading
	transport string // udp / tcp-interleaved
	note      string // 非空 = 没量到，原因在这一句
	silent    bool   // SETUP、PLAY 都要到了，一段时间里一个包都没来
	// switched 是「本来想走 UDP、设备不让，改了 TCP 交织」那一句。
	// ★ 它和 note 不能合成一格：那是换了路子、照样量到了，
	//   混进 note 就把一份好读数当「没量到」扔掉了。
	switched string
}

// rtpPair 是收流用的一对 UDP 口。★ RTP 那个必须是偶数口，而且 RTCP 必须正好是它 +1 ——
// 这是 SDP 里 client_port=p-p+1 写死的规矩，奇数口设备会直接拒。
type rtpPair struct {
	rtp, rtcp net.PacketConn
	port      int
}

func (p *rtpPair) Close() {
	if p == nil {
		return
	}
	if p.rtp != nil {
		_ = p.rtp.Close()
	}
	if p.rtcp != nil {
		_ = p.rtcp.Close()
	}
}

func bindRTPPair() (*rtpPair, error) {
	for try := 0; try < 24; try++ {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		port := 40000 + (int(b[0])|int(b[1])<<8)%20000
		if port%2 != 0 {
			port++
		}
		rtp, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		rtcp, err := net.ListenPacket("udp", ":"+strconv.Itoa(port+1))
		if err != nil {
			rtp.Close()
			continue
		}
		return &rtpPair{rtp: rtp, rtcp: rtcp, port: port}, nil
	}
	return nil, fmt.Errorf("本机腾不出一对空闲的偶数 UDP 口")
}

// trackURL 拼出这一轨的 SETUP 地址。
//
// ★ a=control 三种写法现场都有：绝对地址、光一个轨名（trackID=1）、
//
//	会话级给父地址 + 轨级给子名。只按一种拼，SETUP 在某些设备上直接 404。
func trackURL(descrURI, sessionCtl, ctl string) string {
	if ctl == "" {
		return descrURI
	}
	if strings.Contains(ctl, "://") {
		return ctl
	}
	if strings.Contains(sessionCtl, "://") {
		return strings.TrimSuffix(sessionCtl, "/") + "/" + ctl
	}
	base := strings.TrimSuffix(descrURI, "/")
	if sessionCtl != "" {
		base += "/" + strings.Trim(sessionCtl, "/")
	}
	return base + "/" + ctl
}

// sessionOf 取 Session 响应头里的会话号（后面可能挂着 ;timeout=60）。
func sessionOf(hdr map[string]string) string {
	v := hdr["session"]
	if i := strings.IndexAny(v, ";,"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// measureStream 走完 SETUP→PLAY→收→TEARDOWN。
// 调用方只在 m.note == "" 时读 m.reading；silent 那一档要单独出判定码。
func measureStream(ctx context.Context, conn net.Conn, br *bufio.Reader,
	descrURI, auth string, seq *int, tr *track, sessionCtl string,
	signal, window time.Duration) rtpMeasure {

	out := rtpMeasure{}
	url := trackURL(descrURI, sessionCtl, tr.ctl)
	arm := func() { _ = conn.SetDeadline(time.Now().Add(signal)) }

	var session string
	var pair *rtpPair

	// 1) 先试 UDP —— 只有这一路问得出丢包。
	pair, bindErr := bindRTPPair()
	if pair != nil {
		arm()
		code, hdr, _, err := rtspDo(conn, br, "SETUP", url, seq, auth,
			fmt.Sprintf("Transport: RTP/AVP;unicast;client_port=%d-%d", pair.port, pair.port+1))
		if err == nil && code == 200 && sessionOf(hdr) != "" {
			session, out.transport = sessionOf(hdr), "udp"
		} else {
			// ★ 设备不肯走 UDP（有的固件只做 TCP 交织，有的直接回 461）不是毛病，
			//   换条路问就是 —— 但这一换必须留话，因为丢包那一格从此问不出来了。
			pair.Close()
			pair = nil
			out.switched = udpRefusedNote(code, err, bindErr)
		}
	} else {
		out.switched = "本机腾不出收流的 UDP 口，改问 TCP 那一路：" + bindErr.Error()
	}

	// 2) TCP 交织兜底。
	if session == "" {
		arm()
		code, hdr, _, err := rtspDo(conn, br, "SETUP", url, seq, auth,
			"Transport: RTP/AVP/TCP;unicast;interleaved=0-1")
		if err != nil {
			out.note = "SETUP 没回话：" + err.Error()
			return out
		}
		if code != 200 {
			out.note = fmt.Sprintf("设备不让这一路收流（SETUP 回了 %d）—— 下面这些只来自流描述", code)
			return out
		}
		if sessionOf(hdr) == "" {
			out.note = "SETUP 回了 200 却没给会话号，PLAY 无从发起"
			return out
		}
		session, out.transport = sessionOf(hdr), "tcp-interleaved"
	}

	// 3) PLAY 问的是会话地址，不是轨地址 —— 多数设备只认前者。
	arm()
	code, _, _, err := rtspDo(conn, br, "PLAY", descrURI, seq, auth,
		"Session: "+session, "Range: npt=0.000-")
	if err != nil {
		out.note = "PLAY 没回话：" + err.Error()
		return out
	}
	if code != 200 {
		out.note = fmt.Sprintf("PLAY 被拒（%d）", code)
		return out
	}

	col := media.NewCollector(tr.Codec, tr.clock)
	col.Transport = out.transport
	until := time.Now().Add(window)
	if dl, ok := ctx.Deadline(); ok && dl.Before(until) {
		until = dl
	}
	if pair != nil {
		collectUDP(col, pair, remoteIP(conn), until)
	} else {
		_ = conn.SetDeadline(until)
		collectTCP(br, col, until)
	}
	// TEARDOWN 尽力而为：等它回话的人不该被这一步拖住。
	_ = conn.SetDeadline(time.Now().Add(700 * time.Millisecond))
	_, _, _, _ = rtspDo(conn, br, "TEARDOWN", descrURI, seq, auth, "Session: "+session)

	out.reading = col.Report()
	if out.reading.Packets == 0 {
		// ★ 这是「盒子说没画面」里最容易被读错的一档：设备什么都应了，
		//   人却会以为「参数都对，那就是下游的事」。
		out.silent = true
		out.note = fmt.Sprintf("SETUP 与 PLAY 都回了 200，%s里一个 RTP 包都没到 —— 参数那一问是对的，码流是没发的",
			humanSpan(window))
		return out
	}
	return out
}

func udpRefusedNote(code int, err error, bindErr error) string {
	switch {
	case err != nil:
		return "问 UDP 收流时没回话：" + err.Error()
	case bindErr != nil:
		return bindErr.Error()
	case code == 200:
		// ★ 应了 UDP 却没给会话号 —— 这不是「不让走 UDP」。
		//	写成不让走 UDP 会把人引去改传输配置，而毛病在固件只回了一半。
		return "设备应了 UDP 却没把会话号带回来，改问 TCP 那一路"
	default:
		return fmt.Sprintf("这台设备不让走 UDP 收流（回了 %d），改用 TCP 交织", code)
	}
}

func humanSpan(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.3g 秒", d.Seconds())
	}
	return fmt.Sprintf("%d 毫秒", d.Milliseconds())
}

func remoteIP(conn net.Conn) net.IP {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// collectUDP 收到 until 为止。★ 只认这个设备发来的包：口是临时的，
// 组播里、别人也在用这台机器的随机口时，混进来的包会把码率凭空抬一截。
func collectUDP(col *media.Collector, pair *rtpPair, from net.IP, until time.Time) {
	buf := make([]byte, 2048)
	for {
		left := time.Until(until)
		if left <= 0 {
			return
		}
		_ = pair.rtp.SetReadDeadline(time.Now().Add(left))
		n, addr, err := pair.rtp.ReadFrom(buf)
		if err != nil {
			return
		}
		if from != nil {
			ua, ok := addr.(*net.UDPAddr)
			if !ok || !ua.IP.Equal(from) {
				continue
			}
		}
		col.Add(buf[:n], time.Now())
	}
}

// collectTCP 读交织在同一条连接上的 RTP（$ + 通道 + 两字节长度 + 那一段）。
// 通道 0 是流，通道 1 是 RTCP —— ★ 后者不能喂给统计：RTCP 的头看着也是版本 2，
// 数进去就成了「两路源」，帧率凭空翻倍。
func collectTCP(br *bufio.Reader, col *media.Collector, until time.Time) {
	for time.Now().Before(until) {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		switch b {
		case '$':
			var head [3]byte
			if _, err := io.ReadFull(br, head[:]); err != nil {
				return
			}
			n := int(head[1])<<8 | int(head[2])
			if n <= 0 || n > 65535 {
				return
			}
			frag := make([]byte, n)
			if _, err := io.ReadFull(br, frag); err != nil {
				return
			}
			if head[0] == 0 {
				col.Add(frag, time.Now())
			}
		case 'R':
			return // 交织之外又来了 RTSP 响应，别再当码流读
		}
	}
}
