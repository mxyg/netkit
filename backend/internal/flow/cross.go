package flow

// 跨流的连线：信令那一条与画面那一条本来是一件事的两半，分开看各自都「正常」。
//
// 为什么非要连：RTSP 的 SETUP 写「6970-6971 收流」，国标 INVITE 的 SDP 写
// 「发给 10.0.0.5:20002、ssrc 01000068」—— 这两句话都在信令流上，
// 而真正跑画面的那条 UDP 流在表上是另一行，上面一个字都没写。
// 于是现场看到的总是「信令全 200，媒体那条一无所有」，
// 或者反过来「媒体丢了 3%」却说不清它是谁开出来的、该不该落在这儿。
//
// ★ 连线只按信令里**写明**的地址与端口连，不靠「时间接近」猜。
//   猜出来的关联会把不相干的两条并成一句结论 —— 那是这张表最容易骗人的地方。

import (
	"fmt"
	"strconv"
	"strings"
)

// 一条流上跨流引用与「说好了没落上」那两格各留这么多：
// 一张全网抓的表里，组播那一条能被几十条信令指到，不设上限就是拿内存换一句好看的话。
const maxRefsPerFlow = 16

// FlowRef 是一条跨流引用：只存键与一句话，不存指针。
//
// 存指针就是把表连成环（信令 ↔ 媒体 互相指着），出 JSON 那一刻才崩，
// 而这一层迟早要交给工具层往外发 —— 现在就用键，别留一颗以后才响的雷。
type FlowRef struct {
	Key string
	Why string
	EPs string // 那一头的两个端点，原样抄一遍：免得拿着键还要回头查表
}

// mediaWant 是「信令里说好的那一路媒体」。
type mediaWant struct {
	ip   string // 该落在哪个地址上
	port int    // 该落在哪个端口上
	ssrc string // 说好的 ssrc，空 = 信令里没写
	how  string // 这句话是从哪一格读出来的：对不上时要能指回去
}

// linkMedia 把信令与媒体连上，并对「说好了却一条媒体流都没落在表上」那一种下判定。
//
// 排在每条流的 conclude 之后：连线只往表上加格子，反过来不行 ——
// 没连之前根本不知道缺哪几个口。
func (a *Aggregator) linkMedia() {
	// UDP 的两个端点先建索引：一条媒体流可能被多个 want 命中（音视频各一路），
	// 反过来一条信令也能开好几路，所以两边都是列表。
	byEP := map[string][]*Flow{}
	for _, fl := range a.order {
		if fl.Proto != "udp" {
			continue
		}
		for _, ep := range []string{fl.A, fl.B} {
			if host, port, ok := splitEP(ep); ok {
				key := host + ":" + port
				if len(byEP[key]) < maxRefsPerFlow {
					byEP[key] = append(byEP[key], fl)
				}
			}
		}
	}

	for _, fl := range a.order {
		for _, w := range mediaWantsOf(fl) {
			hit := false
			for _, cand := range byEP[w.ip+":"+strconv.Itoa(w.port)] {
				if cand == fl {
					continue
				}
				hit = true
				fl.addMediaRef(cand, w.how)
				cand.addSignalingRef(fl, w.how)
				fl.checkSSRC(cand, w)
			}
			if !hit {
				fl.addMissing(w)
			}
		}
		fl.concludeMissing()
	}
}

// mediaWantsOf 读一条流里所有「信令说好了的媒体端口」。
func mediaWantsOf(fl *Flow) []mediaWant {
	var out []mediaWant
	// RTSP 里 client_port 是取流那一头的收流口、server_port 是设备那一头的：
	// 两格都可能出现在请求或应答里（应答常把 client_port 原样抄回来），
	// 所以按「哪一格」定归属，不按「这一条是谁发的」定 ——
	// 后者会把应答里抄来的 client_port 算到设备头上，连线就指错了机器。
	clientEP := fl.A
	for i := range fl.Messages {
		m := &fl.Messages[i]
		if m.Proto == "rtsp" && m.Kind == "request" {
			if m.Dir != 0 {
				clientEP = fl.B
			}
			break
		}
	}
	clientHost, serverHost := hostOf(clientEP), hostOf(fl.B)
	if clientHost == serverHost {
		serverHost = hostOf(fl.A) // 本机自取自（回环那一种）：两边同址时另一端才算设备
	}

	for i := range fl.Messages {
		m := &fl.Messages[i]
		switch m.Proto {
		case "rtsp":
			// 得先「SETUP 成了」才谈缺流：连上都没连上，没有媒体是正常的，
			// 说成缺流就是把人支去查一条根本没开过的路。
			if m.Transport == nil || m.Transport.Kind != "udp" || !fl.rtspMediaPromised() {
				continue // 走 interleaved 的画面就在这条 TCP 上，不另连
			}
			tr := m.Transport
			host := clientHost
			if tr.Dest != "" {
				host = tr.Dest // destination= 是设备明写的收流地址，比按方向推硬
			}
			for _, spec := range []struct {
				ports string
				who   string
			}{
				{tr.ClientPorts, host},
				{tr.ServerPorts, serverHost},
			} {
				p1, p2, ok := portRange(spec.ports)
				if !ok || spec.who == "" {
					continue
				}
				if p2-p1 > 1 {
					p2 = p1 + 1 // 只认「RTP 一个口、报告一个口」那一档；更宽的区间是读错了
				}
				for p := p1; p <= p2; p++ {
					out = append(out, mediaWant{
						ip: spec.who, port: p, ssrc: tr.SSRC,
						how: "RTSP 的 " + spec.ports,
					})
				}
			}
		case "sip":
			// 国标的 SDP 写在 INVITE 里：c= 与 m= 那两格就是「往这儿发」。
			// c= 没写（不合规但常见）就不猜收流地址 —— 猜一个就是把不相干的流连上。
			if m.SDP == nil || m.SDP.Port <= 0 || m.SDP.Target == "" {
				continue
			}
			out = append(out, mediaWant{
				ip: m.SDP.Target, port: m.SDP.Port, ssrc: m.SDP.SSRC,
				how: fmt.Sprintf("SDP 的 %s:%d", m.SDP.Target, m.SDP.Port),
			})
		}
	}
	return out
}

// rtspMediaPromised 只认一个门槛：SETUP 成了。PLAY 在不在另说 ——
// 有的取流端 SETUP 完就挂着不 PLAY，那一句归 rtsp-setup-no-play 说，不在这儿重复。
func (fl *Flow) rtspMediaPromised() bool {
	for i := range fl.Messages {
		m := &fl.Messages[i]
		if m.Proto == "rtsp" && m.Status == 200 && strings.EqualFold(m.Method, "SETUP") {
			return true
		}
	}
	return false
}

// addMediaRef / addSignalingRef 两边各挂一条引用，按键去重。
//
// 去重是必需的：一条流上 SETUP 会来回好几次，不去重就是同一句「画面在那条上」
// 在界面上重复四五遍，看的人反而以为有四条流。
func (fl *Flow) addMediaRef(other *Flow, why string) { fl.addRef(&fl.Media, other, why) }

func (fl *Flow) addSignalingRef(other *Flow, why string) {
	fl.addRef(&fl.Signaling, other, why)
}

func (fl *Flow) addRef(slot *[]FlowRef, other *Flow, why string) {
	eps := other.A + " ↔ " + other.B
	for i := range *slot {
		if (*slot)[i].Key == other.Key {
			(*slot)[i].EPs = eps
			return
		}
	}
	if len(*slot) >= maxRefsPerFlow {
		return
	}
	*slot = append(*slot, FlowRef{Key: other.Key, Why: why, EPs: eps})
}

// checkSSRC 比对「信令说好的 ssrc」与那条媒体流上实际见到的 ssrc。
//
// 这一格值得单比：国标平台点播给的 ssrc 与设备实际推的不是同一个时，
// 平台的收流程序会**按 ssrc 白名单整路丢** —— 网络一切正常、画面死活不出来，
// 现场最容易在这一步耗一整天。
func (fl *Flow) checkSSRC(media *Flow, w mediaWant) {
	if strings.TrimSpace(w.ssrc) == "" {
		return // 信令里没写这一格：没什么可比
	}
	if len(media.RTP) == 0 {
		return // 那条流一个 RTP 都没解出来（那一档归「没落上」那句说）
	}
	want := normSSRC(w.ssrc)
	if want == 0 {
		// ★ 读不出数字不等于「对得上」。国标的 y= 各家位数不一（八位、十位都见过），
		// 而 RTP 头里那一格只有 32 位 —— 不替厂家猜哪一位才是 SSRC，
		// 但必须把「这一格没比对」写在表上：默默跳过会被读成「查过了，没问题」。
		fl.addNote(fmt.Sprintf("信令里写的流标识 %q（%s）读不出 32 位的数，与 %s 上实际见到的没比对："+
			"★这一格是「没查」，不是「查了没问题」；各家 y= 的位数写法不一，要核就对一下两边报文头",
			strings.TrimSpace(w.ssrc), w.how, media.Key))
		return
	}
	for _, r := range media.RTP {
		if r.SSRC == want {
			return
		}
	}
	got := make([]string, 0, len(media.RTP))
	for _, r := range media.RTP {
		got = append(got, fmt.Sprintf("%08x", r.SSRC))
	}
	fl.addFinding("rtp-ssrc-mismatch", media.Last, fmt.Sprintf(
		"信令里说好的是 %08x（%s），%s 上实际见到的是 %s：两边对不上号。"+
			"★这一条与丢包无关（包是齐的），是收流那端按 ssrc 白名单把这一路整个丢了 —— "+
			"查平台点播参数与设备推流参数，谁改了那一位",
		want, w.how, media.Key, strings.Join(got, " / ")))
}

// addMissing 记下「说好了要有、表上没有」的那一个口。
func (fl *Flow) addMissing(w mediaWant) {
	s := fmt.Sprintf("%s:%d（%s）", w.ip, w.port, w.how)
	for _, have := range fl.Missing {
		if have == s {
			return
		}
	}
	if len(fl.Missing) >= maxRefsPerFlow {
		return
	}
	fl.Missing = append(fl.Missing, s)
}

// concludeMissing 把攒下的那几个空口说成一句。
//
// 同一句里把所有缺的口一起报：判定按码去重，一条流上音视频各一路时，
// 分开发只会剩第一路，第二路那句永远出不来。
//
// ★ 措辞的上限是「表上没有」，不是「它没发」：抓包点本来就不保证覆盖那一段
//
//	（Windows 那一档连回环都抓不到，交换机没镜像就看不见别人的流量），
//	说成「没发」就是把工具的口径当成设备的口径。
func (fl *Flow) concludeMissing() {
	if len(fl.Missing) == 0 {
		return
	}
	fl.addFinding("signaling-promised-no-media", fl.Last, fmt.Sprintf(
		"信令里说好了往这些口发流，表上一条对得上的 UDP 流都没有：%s。"+
			"★这一句只到「表上没有」：换个口再抓一遍才能定「它到底发没发」",
		strings.Join(fl.Missing, "、")))
}

// splitEP 拆 "10.0.0.9:554" 或 "[fe80::1]:554"。没有端口那一格时回 ok=false。
func splitEP(ep string) (host, port string, ok bool) {
	i := strings.LastIndexByte(ep, ':')
	if i < 0 {
		return "", "", false
	}
	host, port = ep[:i], ep[i+1:]
	if strings.HasPrefix(host, "[") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if host == "" || port == "" {
		return "", "", false
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", false
	}
	return host, port, true
}

// hostOf 取端点里的地址那一截（icmp 那一格用 '#' 占端口，这里要的就是地址）。
func hostOf(ep string) string {
	if host, _, ok := splitEP(ep); ok {
		return host
	}
	return ipOnly(ep)
}

// portRange 读 "6970-6971" 那一格；单个号也算一段（起止相同）。
func portRange(s string) (int, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false
	}
	a, b, _ := strings.Cut(s, "-")
	n1, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil || n1 <= 0 || n1 > 65535 {
		return 0, 0, false
	}
	if strings.TrimSpace(b) == "" {
		return n1, n1, true
	}
	n2, err := strconv.Atoi(strings.TrimSpace(b))
	if err != nil || n2 <= 0 || n2 > 65535 {
		return 0, 0, false
	}
	if n2 < n1 {
		n1, n2 = n2, n1
	}
	return n1, n2, true
}

// normSSRC 把信令里那几种写法收成数字：0x 前缀、"01000068.1234567890" 这种带后缀的、
// 以及 "ssrc:01000068" 那一档。读不出来回 0 = 不比对，不猜一个看着像的。
func normSSRC(s string) uint32 {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	v = strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 16, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
