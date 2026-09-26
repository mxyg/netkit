package flow

// 认协议的落账与分发。
//
// 定口：一条流的 App 只定一次，之后不再改 —— 中途改会让前面已经切好的报文
// 按新协议重切一遍，表上就会出现「同一条 RTSP 流先是 rtsp 后是 http」。
// 后面的报文内容与已定的不符时，明说一句，不悄悄换。

import (
	"fmt"
	"strings"
	"time"
)

// pickProto 给一个数据报定协议（UDP 一档：每包自己看一眼）。
//
// 回空 = 这一包不喂给专解。已定口之后又见到别的内容时宁可少解一条，
// 也不能拿 RTSP 的刀去切 SIP 的报文——那会解出一句看着像样的假应答。
func (fl *Flow) pickProto(payload []byte) string {
	sniffed := sniffProto(payload)
	if fl.App == "" {
		fl.setApp(sniffed)
		if sniffed == "" {
			return ""
		}
		return fl.App
	}
	if sniffed != "" && sniffed != fl.App {
		fl.addNote(fmt.Sprintf("这一条流上见过两种协议的内容（先 %s，后 %s）：按先定下来的那个解，后者没解",
			fl.App, sniffed))
		return ""
	}
	return fl.App
}

// pickProtoOf 回这一条流已定的协议（TCP 切报文时用，那时没有整包可看）。
func (fl *Flow) pickProtoOf() string { return fl.App }

func (fl *Flow) setApp(sniffed string) {
	if sniffed != "" {
		fl.App, fl.AppBy = sniffed, "内容"
		return
	}
	// 内容说不清才轮到端口。★ 这一档必须写「端口」，不能写成内容认出来的那个样子：
	// 加密流（TLS、SSH）落在 443 上按端口就是 https，界面若不说清，人就真以为解出了证书。
	if p := fl.portProto(); p != "" {
		fl.App, fl.AppBy = p, "端口"
		fl.addNote(fmt.Sprintf("%s 只是端口上像：内容没有解（加密、或这一档没写它的专解）", p))
		return
	}
	fl.App = ""
}

// portProto 从这一条流两端的端口里取协议名。
func (fl *Flow) portProto() string {
	for _, ep := range []string{fl.A, fl.B} {
		if p := portOf(ep); p > 0 {
			if name := protoByPort(uint16(p)); name != "" {
				return name
			}
		}
	}
	return ""
}

func portOf(ep string) int {
	i := strings.LastIndexByte(ep, ':')
	if i < 0 {
		return 0
	}
	// 裸 IPv6（fe80::1 这种没端口的）里也有冒号：那一格不是端口，别拿地址尾巴当端口认协议。
	if strings.Contains(ep, "::") && !strings.Contains(ep, "]:") {
		return 0
	}
	n, err := atoiStrict(ep[i+1:])
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

// ipOnly 从端点里只留地址那一截："10.0.0.9:554" 回 "10.0.0.9"。
//
// 发现类协议要把「谁在喊」填进判定句里，而那一句话给人看的地址带端口是多余的；
// 更要紧的是 broadcast 那几个解包函数收的是地址，带端口的字符串进去就解不出来源。
// 裸 IPv6 里到处是冒号，所以只在「冒号后面确实是数字」那一格切，不数第几个冒号。
func ipOnly(ep string) string {
	s := ep
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			return s[1:i]
		}
	}
	if i := strings.LastIndexByte(s, '#'); i >= 0 {
		s = s[:i] // icmp 那一条用 '#' 占了端口那一格
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if _, err := atoiStrict(s[i+1:]); err == nil {
			return s[:i]
		}
	}
	return s
}

func atoiStrict(s string) (int, error) {
	var n int
	if s == "" {
		return 0, errEmpty
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errNotNumber
		}
		n = n*10 + int(r-'0')
		if n > 1<<20 {
			return 0, errNotNumber // 端口那格不会有这么大的数：脏数据
		}
	}
	return n, nil
}

// hasDecoder 问这一档协议有没有专解。按端口认出来的那一堆（ssh/rdp/telnet/加密的 tls）
// 没有，切报文这一步对它们只会产出噪音。
func hasDecoder(proto string) bool {
	switch proto {
	case "rtsp", "http", "soap", "sip", "onvif", "mqtt", "dns", "dhcp", "snmp",
		"ssdp", "mdns", "ws-discovery", "netbios", "rtp", "rtcp", "dahua":
		return true
	}
	return false
}

// emit 解一条报文并挂到这一条流上。fromStream = 这一条是从拼好的字节流切出来的。
func (fl *Flow) emit(proto string, raw []byte, dir int, at time.Time, fromStream bool) {
	if proto == "" || len(raw) == 0 {
		return
	}
	if len(fl.Messages) >= fl.maxMessages {
		fl.addNote(fmt.Sprintf("应用层报文只留前 %d 条（上限）：后面的没有解，也不假装解过", fl.maxMessages))
		return
	}
	from, to := fl.A, fl.B
	if dir != 0 {
		from, to = fl.B, fl.A
	}
	m, err := decodeApp(proto, raw, ipOnly(from))
	if m == nil {
		if err != nil && fromStream {
			// 拼出来的一条切下去解不动：这一句必须留下。缺口、抓漏、还是没写专解，
			// 现场要能分清，不然「没解出来」会被读成「它没发」。
			fl.addNote("按 " + proto + " 切出来的报文有一段解不动：" + err.Error())
		}
		return
	}
	m.At = at
	// Proto 由专解自己写，这里不覆盖：同一把刀能切出两种协议（RTP 与 RTCP 共用一个头，
	// 靠 PT 分段），覆盖成流上定的那一个，界面上就会把 RTCP 的报告写成 RTP 包。
	m.Dir = dir
	m.From, m.To = from, to
	fl.attributeMethod(m)
	fl.Messages = append(fl.Messages, *m)
}

// attributeMethod 把「这一条回包答的是哪一次询问」补进 Method。
//
// RTSP / HTTP 的回包起始行里没有方法名（"RTSP/1.0 200 OK"），只有 CSeq 能对回请求那一条。
// 不补，流一层就分不清这一条 200 是答 SETUP 还是答 OPTIONS ——
// 而「SETUP 成了却没有画面」那一句判定读的正是它，读不到就永远不报，
// 表上看着一切正常，现场查一整天。SIP 那一头由 decodeSIP 在单条报文里就从 CSeq 补好了。
//
// 键里带方向：CSeq 是每一头各有一套计数器的，A 发的 3 与 B 发的 3 同号是常态，
// 拿序号当唯一键就会把两条不相干的会话连成一句。
func (fl *Flow) attributeMethod(m *Message) {
	switch m.Proto {
	case "rtsp", "http", "soap", "onvif":
	default:
		return
	}
	if m.Seq == "" {
		return
	}
	key := fmt.Sprintf("%d|%s", m.Dir, m.Seq)
	if m.Kind == "request" {
		if m.Method == "" {
			return
		}
		if fl.seqMethod == nil {
			fl.seqMethod = map[string]string{}
		}
		fl.seqMethod[key] = m.Method
		return
	}
	if m.Method == "" {
		// 回包在反方向上：答的是对面那一头发出来的同序号请求。
		m.Method = fl.seqMethod[fmt.Sprintf("%d|%s", m.Dir^1, m.Seq)]
	}
}

// decodeApp 分发给各协议的专解。回 nil 表示「这一条解不动」，不是「没东西可解」。
//
// from 只给发现类那一档用（SSDP/WS-Discovery/NetBIOS 的报告里要写清是谁喊的），
// 其余专解用不上就先不接 —— 多一个没人读的参数比少一个更容易出错。
func decodeApp(proto string, raw []byte, from string) (*Message, error) {
	switch proto {
	case "rtsp", "http", "soap":
		return decodeRTSPish(proto, raw)
	case "sip":
		return decodeSIP(raw)
	case "onvif":
		return decodeONVIF(raw)
	case "mqtt":
		return decodeMQTT(raw)
	case "dns":
		return decodeDNS(raw)
	case "dhcp":
		return decodeDHCP(raw)
	case "snmp":
		return decodeSNMP(raw)
	case "ssdp":
		return decodeSSDP(raw, from)
	case "mdns":
		return decodeMDNS(raw)
	case "ws-discovery":
		return decodeWSD(raw, from)
	case "netbios":
		return decodeNetBIOS(raw, from)
	case "rtp", "rtcp":
		return decodeRTP(raw)
	case "dahua":
		return decodeDahua(raw)
	}
	return nil, fmt.Errorf("flow: %s 这一档没有专解", proto)
}

var (
	errEmpty     = fmt.Errorf("flow: 空的")
	errNotNumber = fmt.Errorf("flow: 不是数字")
)
