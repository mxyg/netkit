package flow

// 发现类（SSDP / WS-Discovery / NetBIOS）与媒体类（RTP / RTCP）。
//
// ★ 这三种自报协议在抓包表上值得单列，因为它们回答的是同一句话：
// 「这个地址上到底有什么设备」。平台侧最常见的死案是
// 「国标平台里看不到这台相机」，而相机一直在链路上喊 WS-Discovery ——
// 那一句「它活着，只是没人登记它」只有解开这几包才说得出。
//
// 报文本身一律是别人喊出来的话，所以值全按原样留（设备自己公开广播的东西不是凭据）；
// 唯一例外是 Location/XAddrs 里带 userinfo 的那种地址，照样过 scrubURI。

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/broadcast"
)

// ==================== SSDP ====================

// decodeSSDP 走文本那一形状（NOTIFY / M-SEARCH / 200 OK 都是 HTTP 壳），
// 再把 UPnP 那几格挑出来。设备自己喊的话按原样留。
func decodeSSDP(raw []byte, from string) (*Message, error) {
	m, err := decodeRTSPish("ssdp", raw)
	if err != nil {
		return nil, err
	}
	var reportedID bool
	if rep, err := broadcast.ParseSSDP(raw, ipOnly(from)); err == nil && rep != nil {
		ssdpApplyReport(m, rep)
		reportedID = rep.UniqueID != ""
	}
	nt := headerValue(parseHeaders(headOf(raw)), "NT")
	st := headerValue(parseHeaders(headOf(raw)), "ST")
	usn := headerValue(parseHeaders(headOf(raw)), "USN")
	if usn != "" && !reportedID {
		// broadcast 那一趟没给出 USN（它对头的要求比这里严）：这一格补上，
		// 不然界面上写成「没自报编号」，人会以为是设备没写 —— 其实是我们的解法没吃到。
		m.Fields = append(m.Fields, field("UDN/USN", usn))
	}
	switch {
	case strings.Contains(nt, "ssdp:byebye") || strings.Contains(m.Method, "byebye"):
		m.Fields = append(m.Fields, field("这一条在说", "它要下线了（ssdp:byebye）：之后一段时间里没人会再答这个地址"))
		m.Findings = append(m.Findings, Finding{Code: "ssdp-byebye",
			Text: "有一台设备在广播「我走了」：" + firstNonEmpty(repName(m), ipOnly(from)) +
				"。搜索端如果只收到这一条，那「搜不到」不是网络问题，是它自己下的"})
	case strings.Contains(m.Method, "ssdp:discover"), strings.HasPrefix(m.Method, "M-SEARCH"):
		m.Kind = "query"
		m.Fields = append(m.Fields, field("在找", firstNonEmpty(st, "（没写 ST：这一条不合规）")))
		m.Findings = append(m.Findings, Finding{Code: "ssdp-search",
			Text: "有人在搜索（M-SEARCH " + firstNonEmpty(st, "目标没写") + "）：" + ipOnly(from) +
				" 在问这一段里谁在。这个不是错，但「突然冒出一堆搜索」常常就是有人在扫"})
	default:
		m.Kind = "notify"
		m.Fields = append(m.Fields, field("自报为", firstNonEmpty(nt, st)))
	}
	if v := headerValue(parseHeaders(headOf(raw)), "LOCATION"); v != "" {
		m.Fields = append(m.Fields, field("描述文件", scrubURI(v)))
	}
	m.Proto = "ssdp"
	m.Summary = ssdpSummary(m, from)
	m.Summary = scrubText(m.Summary)
	return m, nil
}

func ssdpApplyReport(m *Message, rep *broadcast.Report) {
	if rep.Name != "" {
		m.Fields = append(m.Fields, field("设备名", rep.Name))
	}
	if rep.UniqueID != "" {
		m.Fields = append(m.Fields, field("UDN/USN", rep.UniqueID))
	}
	if rep.Type != "" {
		m.Fields = append(m.Fields, field("设备类型", rep.Type))
	}
	if rep.TTL > 0 {
		m.Fields = append(m.Fields, field("还能信多久", strconv.Itoa(rep.TTL)+" 秒"))
	} else {
		m.Fields = append(m.Fields, field("还能信多久", "0 秒（这一条本身就是告退）"))
	}
}

// repName 从已经落好的格里找回设备名（判定句里要用，不想再解一遍报文）。
func repName(m *Message) string {
	for _, f := range m.Fields {
		if f.K == "设备名" {
			return f.V
		}
	}
	return ""
}

func ssdpSummary(m *Message, from string) string {
	s := "SSDP " + firstNonEmpty(m.Method, "一条")
	if n := repName(m); n != "" {
		s += "：" + n
	} else {
		s += "：来自 " + ipOnly(from)
	}
	return s
}

// ==================== WS-Discovery（ONVIF 摄像头靠它喊自己在） ====================

func decodeWSD(raw []byte, from string) (*Message, error) {
	m, err := decodeRTSPish("ws-discovery", raw)
	if err != nil {
		return nil, err
	}
	m.Proto = "ws-discovery"
	if rep, err := broadcast.ParseWSDiscovery(raw, ipOnly(from)); err == nil && rep != nil {
		wsdApply(m, rep)
	}
	m.Summary = wsdSummary(m, from)
	m.Summary = scrubText(m.Summary)
	return m, nil
}

func wsdApply(m *Message, rep *broadcast.Report) {
	m.Kind = "notify"
	switch {
	case strings.Contains(m.Method, "Probe"):
		m.Kind = "query"
	case strings.Contains(m.Method, "Bye"):
		m.Kind = "bye"
	}
	if rep.Name != "" {
		m.Fields = append(m.Fields, field("设备名", rep.Name))
	}
	if rep.Type != "" {
		// dn:NetworkVideoTransmitter 就是「我是一台网络摄像机」的那句话。
		m.Fields = append(m.Fields, field("服务类型", rep.Type))
	}
	if rep.URL != "" {
		m.Fields = append(m.Fields, field("服务地址", scrubURI(rep.URL)))
	}
	if rep.UniqueID != "" {
		m.Fields = append(m.Fields, field("端点（uuid）", rep.UniqueID))
	}
	if strings.Contains(rep.Type, "NetworkVideoTransmitter") {
		m.Findings = append(m.Findings, Finding{Code: "wsd-camera-here",
			Text: "这台在喊自己是网络摄像机（dn:NetworkVideoTransmitter）：" + ipOnly(rep.From) +
				"。它在链路上是活的 —— 平台里看不到它，得往「谁该来收这条 Hello」那一步查，" +
				"而不是「这台是不是坏了」"})
	}
	if m.Kind == "bye" {
		m.Findings = append(m.Findings, Finding{Code: "wsd-bye",
			Text: "有一台在告退（Bye）：" + ipOnly(rep.From) + "。之后搜不到它是应该的"})
	}
}

func wsdSummary(m *Message, from string) string {
	s := "WS-Discovery " + firstNonEmpty(m.Method, "一条")
	if n := repName(m); n != "" {
		s += "：" + n
	} else {
		s += "：来自 " + ipOnly(from)
	}
	return s
}

// ==================== NetBIOS 节点状态 ====================

// decodeNetBIOS 解「这台 Windows 机器报了自己哪些名字」。
// 137 上大部分是名字查询（一问一答），只有节点状态应答这一种带着一串名字。
func decodeNetBIOS(raw []byte, from string) (*Message, error) {
	ns, err := broadcast.ParseNodeStatus(raw)
	if err != nil {
		return nil, err
	}
	m := &Message{Proto: "netbios", Kind: "response", Method: "NodeStatus", Fields: []Field{}}
	if ns.MAC != "" {
		m.Fields = append(m.Fields, field("MAC", ns.MAC))
	}
	var names []string
	var groups int
	for _, n := range ns.Names {
		if len(names) >= 16 {
			names = append(names, fmt.Sprintf("…还有 %d 个没列（上限 16）", len(ns.Names)-len(names)))
			break
		}
		s := n.Name + "<" + strconv.Itoa(n.Suffix) + ">"
		if n.Group {
			s += "（组名）"
			groups++
		}
		if n.Service != "" {
			s += " " + n.Service
		}
		names = append(names, s)
	}
	m.Fields = append(m.Fields, field("它报的名字", strings.Join(names, "、")))
	if ns.Tests != 0 || ns.Jumpers != 0 {
		m.Fields = append(m.Fields, field("测试/跳线", fmt.Sprintf("tests=%d jumpers=%d", ns.Tests, ns.Jumpers)))
	}
	m.Summary = "NetBIOS 节点状态：" + ipOnly(from) + " 报了 " + strconv.Itoa(len(ns.Names)) + " 个名字"
	if len(ns.Names) == 0 {
		m.Summary = "NetBIOS 节点状态应答里一个名字都没有"
		m.Findings = append(m.Findings, Finding{Code: "netbios-no-names",
			Text: "问了节点状态，回来的名字表是空的：这台机器上 Server 服务没起（或被挡），" +
				"共享名当然也出不来 —— 这一句和「网络不通」是两件事"})
	}
	if groups == len(ns.Names) && len(ns.Names) > 0 {
		m.Note = "报回来的全是组名，一个唯一名都没有：这台机器可能没在跑工作站服务"
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

// ==================== RTP / RTCP ====================

// RTP 与 RTCP 共用那一形状（同一个头，PT 号段分开），所以放一起。
//
// ★ 为什么这一档非做不可：昱弘现场「画面卡/有条纹/时有时无」那一批案子，
// 证据全在 RTP 的序号上 —— 而序号只有在一包一层数才知道，事后翻正文翻不出来。
// RTCP 更值钱：Receiver Report 里的 fraction lost 与累计丢失是**接收端自己算的**，
// 和我们在链路上看到的丢包一对照，「谁在丢」这句话就说得出口了。
func decodeRTP(raw []byte) (*Message, error) {
	kind, pt, err := rtpKind(raw)
	if err != nil {
		return nil, err
	}
	var info *RTPInfo
	if kind == "rtp" {
		// 只有 RTP 才挑得出序号那一格：RTCP 的 2:4 是长度、4:8 才是 SSRC，
		// 拿 RTP 的下标去读会得出一串看着像序号的数。
		if info = peekRTP(raw); info == nil {
			return nil, fmt.Errorf("flow: RTP 头看着齐，挑不出序号那一格")
		}
	}
	m := &Message{Proto: kind, Kind: "packet", Fields: []Field{}}
	m.RTP = info
	switch kind {
	case "rtp":
		m.Method = "RTP"
		m.Fields = append(m.Fields,
			field("SSRC", fmt.Sprintf("%08x", info.SSRC)),
			field("序号", strconv.Itoa(int(info.Seq))),
			field("时间戳", strconv.FormatUint(uint64(info.Timestamp), 10)),
			field("载荷类型", rtpPayloadName(info.PayloadType)),
			field("正文", strconv.Itoa(info.PayloadBytes)+" 字节"),
		)
		if info.Marker {
			m.Fields = append(m.Fields, field("标记位", "置上了（一帧的最后一片，或说话的开始）"))
		}
		m.Summary = fmt.Sprintf("RTP ssrc=%08x seq=%d pt=%s %d 字节", info.SSRC, info.Seq, rtpPayloadName(info.PayloadType), info.PayloadBytes)
		if info.PayloadBytes == 0 {
			m.Findings = append(m.Findings, Finding{Code: "rtp-empty-payload",
				Text: "有 RTP 包一个字节载荷都没带：有的实现拿它当保活，有的就是坏了。" +
					"单独几包不算病，整条流都这样就是没在出图"})
		}
	default:
		decodeRTCP(m, raw, pt)
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

// decodeRTCP 解发送者/接收者报告那几种。质量问题的答案大多在这一格里。
//
// ★ pt 传的是公共头那**整字节**（RTCP 的 PT 是 8 位，不像 RTP 拆走了一位标记位）。
// 拿 pt&0x7f 去查表会把 200 查成 72 —— 一句「RTCP 类型 72」就这么上了屏。
func decodeRTCP(m *Message, raw []byte, pt byte) {
	label := rtcpNames[pt]
	if label == "" {
		label = "RTCP 类型 " + strconv.Itoa(int(pt)) + "（这一档没写它的专解，只到这里）"
	}
	m.Proto = "rtcp"
	m.Method = "RTCP " + strconv.Itoa(int(pt))
	m.Kind = "report"
	if len(raw) < 8 {
		m.Note = "RTCP 只带回来 " + strconv.Itoa(len(raw)) + " 字节，公共头都不齐"
		return
	}
	m.Fields = append(m.Fields, field("类型", label))
	m.Summary = label
	switch pt {
	case rtcpSR, rtcpRR:
		ssrc := binary.BigEndian.Uint32(raw[4:8])
		m.Fields = append(m.Fields, field("报告方 SSRC", fmt.Sprintf("%08x", ssrc)))
		base := 8
		if pt == rtcpSR {
			// 发送者信息 20 字节（NTP 时间戳 8 + RTP 时间戳 4 + 包数 4 + 正文字节数 4），
			// 所以接收块从第 28 字节起 —— ★ 不是 32：多算那 4 字节会把第一块整体挪一位，
			// 解出来的「丢包数」会是隔壁字段的数，那种错在最要紧的一格上。
			if len(raw) < 28 {
				m.Fields = append(m.Fields, field("发送者信息", "SR 只带回来 "+strconv.Itoa(len(raw))+" 字节，发送者那 20 字节不齐"))
				return
			}
			ntpSec := binary.BigEndian.Uint32(raw[8:12])
			ntpFrac := binary.BigEndian.Uint32(raw[12:16])
			rtpTS := binary.BigEndian.Uint32(raw[16:20])
			pkts := binary.BigEndian.Uint32(raw[20:24])
			octs := binary.BigEndian.Uint32(raw[24:28])
			m.Fields = append(m.Fields,
				field("它自己数发了", fmt.Sprintf("%d 包 / %d 字节正文", pkts, octs)),
				field("SR 的 RTP 时间戳", strconv.FormatUint(uint64(rtpTS), 10)),
				field("它的 NTP 时间戳", fmt.Sprintf("%d.%010d（它自己的钟，与我们的抓包时刻不同源）",
					ntpSec, uint64(ntpFrac)*1000000000/uint64(1<<32))),
			)
			base = 28
		}
		n := int(raw[0] & 0x1f) // RC：后面跟着几个接收块
		if base+24*n > len(raw) {
			// 声明的块数比包里的字节多：这一份被剪过或坏了。数出来的那一格照样报，
			// 但把「后面的读不到」写在同一格里，不让人以为剩下那几块真的没发。
			m.Fields = append(m.Fields, field("接收块", "声明 "+strconv.Itoa(n)+" 块，正文只够 "+strconv.Itoa((len(raw)-base)/24)+" 块"))
			n = (len(raw) - base) / 24
		}
		for i := 0; i < n; i++ {
			off := base + 24*i
			// 接收块：被报的那路 SSRC(4) 丢包分数(1) 累计丢失(3) 它见的最高扩展序号(4)
			// 抖动(4) 上一份 SR 的时间戳(4) 收到之后攒了多久(4)
			target := binary.BigEndian.Uint32(raw[off : off+4])
			frac := raw[off+4]
			var cum uint32
			for _, c := range raw[off+5 : off+8] {
				cum = cum<<8 | uint32(c)
			}
			extSeq := binary.BigEndian.Uint32(raw[off+8 : off+12])
			jitter := binary.BigEndian.Uint32(raw[off+12 : off+16])
			lsr := binary.BigEndian.Uint32(raw[off+16 : off+20])
			dlsr := binary.BigEndian.Uint32(raw[off+20 : off+24])
			m.Fields = append(m.Fields,
				field("它报给谁 SSRC", fmt.Sprintf("%08x", target)),
				field("接收端自报丢包", fmt.Sprintf("这一阵 %d/255、累计 %d 包", frac, cum)),
				field("它看到的最高序号", strconv.FormatUint(uint64(extSeq), 10)),
				field("抖动", strconv.FormatUint(uint64(jitter), 10)+" 个时钟刻度（换毫秒要 SDP 里那一路的时钟率，这一档不换算）"),
			)
			if lsr != 0 {
				m.Fields = append(m.Fields, field("它引的上一份 SR", fmt.Sprintf("%08x（NTP 中间那 32 位）", lsr)))
			}
			if dlsr != 0 {
				// ★ DLSR 不是往返时延：是「它收到上一份 SR 之后攒了多久才发这份报告」。
				// 真拿它当 RTT 报出去，现场会照着一个几百毫秒的数去说链路慢。
				m.Fields = append(m.Fields, field("它攒报告的间隔", fmt.Sprintf("%.1f ms（DLSR：不是往返时延）", float64(dlsr)/65536)))
			}
			if cum > 0 {
				m.Findings = append(m.Findings, Finding{Code: "rtcp-rr-loss",
					Text: fmt.Sprintf("接收端自己数出累计丢了 %d 包（这一阵 %d/255，被报的那路 SSRC %08x）：这一份丢包是它算的，"+
						"不是我们猜的。与链路上看到的丢包一对照，「丢在谁那一段」就说得出口",
						cum, frac, target)})
			}
		}
	case rtcpSDES:
		// 块从第 8 字节起：先 4 字节这一路的 SSRC，再一串 (项类型, 长度, 值)。
		if len(raw) >= 12 {
			chunk := binary.BigEndian.Uint32(raw[8:12])
			m.Fields = append(m.Fields,
				field("源名", rtpSDESItem(raw[12:], 1)),
				field("这一路（SDES 块）", fmt.Sprintf("%08x", chunk)),
			)
			if tool := rtpSDESItem(raw[12:], 3); tool != "" {
				m.Fields = append(m.Fields, field("工具", tool)) // TOOL = 实现软件名：版本对不对常看这一格
			}
		}
	case rtcpBYE:
		var why []string
		for i := 0; i < int(raw[0]&0x1f); i++ {
			off := 8 + 4*i
			if off+4 > len(raw) {
				break
			}
			why = append(why, fmt.Sprintf("%08x", binary.BigEndian.Uint32(raw[off:off+4])))
		}
		reason := ""
		if n := 8 + 4*len(why); n < len(raw) {
			l := int(raw[n])
			if n+1+l <= len(raw) {
				reason = scrubText(string(raw[n+1 : n+1+l]))
			}
		}
		m.Fields = append(m.Fields, field("离开的源", strings.Join(why, "、")))
		if reason != "" {
			m.Fields = append(m.Fields, field("它给的理由", reason))
		}
		m.Findings = append(m.Findings, Finding{Code: "rtcp-bye",
			Text: "这一路 RTP 的源发了 RTCP BYE（它自己说不发了）：" + strings.Join(why, "、") +
				"。画面停住不是网络断，是那一端主动收的流"})
	case rtcpRTPFB:
		// 传输层反馈：FMT=1 才是 NACK（RFC 4585）。204 在 RFC 3551 里是 APP，别当 NACK 报。
		if raw[0]&0x1f != 1 {
			m.Fields = append(m.Fields, field("反馈类型", "FMT="+strconv.Itoa(int(raw[0]&0x1f))+"（这一档没有专解，只记到这里）"))
			return
		}
		if len(raw) < 16 {
			m.Fields = append(m.Fields, field("NACK", "这一份不够长，读不出要重传的那一段"))
			return
		}
		media := binary.BigEndian.Uint32(raw[8:12])
		pid := binary.BigEndian.Uint16(raw[12:14])
		blpi := binary.BigEndian.Uint16(raw[14:16])
		m.Fields = append(m.Fields,
			field("它在要重传", fmt.Sprintf("媒体源 %08x：从序号 %d 起 %d 个", media, pid, blpi+1)),
		)
		m.Findings = append(m.Findings, Finding{Code: "rtcp-nack",
			Text: fmt.Sprintf("接收端在发 NACK 要重传（媒体源 %08x，从 %d 起 %d 个）：它知道自己漏了包。"+
				"这一格与链路上的丢包一起看，「卡一下」就有了一个能数的口径", media, pid, blpi+1)})
	case rtcpPSFB:
		switch raw[0] & 0x1f {
		case 1: // PLI：它解不出画面了，在要一个关键帧
			media := uint32(0)
			if len(raw) >= 12 {
				media = binary.BigEndian.Uint32(raw[8:12])
			}
			m.Fields = append(m.Fields, field("它在要关键帧", fmt.Sprintf("媒体源 %08x", media)))
			m.Findings = append(m.Findings, Finding{Code: "rtcp-pli",
				Text: "接收端发了 PLI（它在要一个关键帧）：" +
					"这一句的分量是「它已经解不下去了」。偶尔一次是起流出图前的正常动作，" +
					"每隔一两秒一次就是丢包或码流对不上，去看那一路的序号账"})
		case 4: // FIR：强制刷新（大华/海康的协商里常见）
			m.Findings = append(m.Findings, Finding{Code: "rtcp-fir",
				Text: "接收端发了 FIR（要发送端立刻出一个关键帧）：与 PLI 同一类诉求，口径比 PLI 更硬"})
		default:
			m.Fields = append(m.Fields, field("反馈类型", "FMT="+strconv.Itoa(int(raw[0]&0x1f))+"（这一档没有专解，只记到这里）"))
		}
	}
}

// RTCP 的 PT 号段（RFC 3550 + 4585 + 5104）。204 是 APP 不是 NACK ——
// 这一格写错过一次，现场就会对着一份 APP 报告查「谁在要重传」。
const (
	rtcpSR    = 200
	rtcpRR    = 201
	rtcpSDES  = 202
	rtcpBYE   = 203
	rtcpAPP   = 204 // 应用自定义
	rtcpRTPFB = 205 // 传输层反馈：FMT=1 是 NACK
	rtcpPSFB  = 206 // 载荷层反馈：FMT=1 是 PLI，4 是 FIR
	rtcpXR    = 207 // 扩展报告
)

var rtcpNames = map[byte]string{
	rtcpSR:   "SR（发送者报告）",
	rtcpRR:   "RR（接收者报告）",
	rtcpSDES: "SDES（源名）",
	rtcpBYE:  "BYE（它不发了）",
	rtcpAPP:  "APP（应用自定义，这一档不解内容）",
	rtcpXR:   "XR（扩展报告，这一档不解内容）",
}

// rtpSDESItem 从 SDES 项里挑出指定类型那一个的值（1=CNAME，3=TOOL）。
func rtpSDESItem(b []byte, want byte) string {
	for i := 0; i < len(b); {
		kind := b[i]
		if kind == 0 {
			return "" // 结束项
		}
		if i+2 > len(b) {
			return ""
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return ""
		}
		if kind == want {
			return scrubText(string(b[i+2 : i+2+n]))
		}
		i += 2 + n
	}
	return ""
}

// rtpKind 分得清 RTP、RTCP，还是「长得像但不是」。
//
// ★ 这一档必须严格：RTP 没有端口上界（RTSP 的 client_port 给的都是临时口），
// 而临时口上什么都有。V=2 这一条谁都过不了筛选，所以要连头长、载荷类型一起看。
func rtpKind(b []byte) (string, byte, error) {
	if len(b) < 12 {
		return "", 0, fmt.Errorf("flow: RTP 头要 12 字节，这一包只有 %d", len(b))
	}
	if b[0]>>6 != 2 {
		return "", 0, fmt.Errorf("flow: RTP 版本号不是 2")
	}
	cc := int(b[0] & 0x0f)
	hdr := 12 + 4*cc
	if b[0]&0x10 != 0 {
		if hdr+4 > len(b) {
			return "", 0, fmt.Errorf("flow: RTP 说有扩展头，但包不够扩展头那么长")
		}
		hdr += 4 + 4*int(binary.BigEndian.Uint16(b[hdr+2:hdr+4]))
	}
	if hdr > len(b) {
		return "", 0, fmt.Errorf("flow: RTP 头声明 %d 字节，整包只有 %d", hdr, len(b))
	}
	if hdr == len(b) && cc == 0 {
		// 只有头、一个字节正文都没有：这种形状在真 RTP 里极罕见（0 载荷的 RTP 是有的，
		// 但配上「恰好停在头尾」更可能是别的协议撞上了这个前缀），不当 RTP 记账。
		return "", 0, fmt.Errorf("flow: 这一包只剩 RTP 头那么长，不像真流")
	}
	pt := b[1]
	if pt >= 192 && pt <= 207 {
		// RTCP 的 PT 是整字节；200~206 那一段就是 SR/RR/SDES/BYE/NACK。
		return "rtcp", pt, nil
	}
	return "rtp", pt, nil
}

func looksLikeRTP(b []byte) bool {
	_, _, err := rtpKind(b)
	return err == nil
}

// peekRTP 只挑头那几格，不碰正文。
//
// 与 decodeRTP 分开是因为两件事的用量差得远：序号账每一包都要记，
// 而报文列表有上限（一条流可以有几十万包 RTP）。上限之后还去整包解，
// 就是把「省内存」做成了「省了个寂寞」。
func peekRTP(b []byte) *RTPInfo {
	kind, pt, err := rtpKind(b)
	if err != nil || kind != "rtp" {
		return nil
	}
	base := 12 + 4*int(b[0]&0x0f)
	hdr := base
	if b[0]&0x10 != 0 { // 扩展头：再跳 4+4*extLen 字节（rtpKind 已经量过越界）
		hdr = base + 4 + 4*int(binary.BigEndian.Uint16(b[base+2:base+4]))
	}
	return &RTPInfo{
		SSRC:         binary.BigEndian.Uint32(b[8:12]),
		Timestamp:    binary.BigEndian.Uint32(b[4:8]),
		Seq:          binary.BigEndian.Uint16(b[2:4]),
		Marker:       b[1]&0x80 != 0,
		PayloadType:  pt & 0x7f,
		PayloadBytes: len(b) - hdr,
		Padding:      b[0]&0x20 != 0,
	}
}

// RTP 的静态载荷类型（RFC 3551 那一张表）。只列现场真见得到的：
// 摄像头那批基本全在动态段（96 起），而 26/28 是海康/大华的 MJPEG 与私有视频常用号。
var rtpStaticNames = map[byte]string{
	0: "G.711 μlaw", 8: "G.711 Alaw", 18: "G.729",
	26: "MJPEG", 28: "SL26D/私有视频",
}

func rtpPayloadName(pt byte) string {
	if s, ok := rtpStaticNames[pt]; ok {
		return strconv.Itoa(int(pt)) + "（" + s + "）"
	}
	if pt >= 96 {
		return strconv.Itoa(int(pt)) + "（动态：得看 SDP 里 a=rtpmap 那一条）"
	}
	return strconv.Itoa(int(pt))
}

// countRTPFor 在把正文喂给专解之前，先把 RTP 的序号账记了。
//
// ★ 为什么不挂在 emit 上：报文列表有上限，到顶之后 emit 直接返回，
// 而「这一路丢了几包」数的是整条流 —— 挂在 emit 上就成了「前 200 包没丢，所以这条流没丢」。
// 另一个口径：流上已经定了别的内容协议时不当 RTP 记（大华私有协议的头也是 0x80 开头），
// 与 pickProto 一致 —— 认错的协议宁可少记一笔，不要多记一笔假的。
func (a *Aggregator) countRTPFor(fl *Flow, f Frame, dir int, at time.Time) {
	if fl.App != "" && fl.App != "rtp" && fl.App != "rtcp" {
		return
	}
	info := peekRTP(f.Payload)
	if info == nil {
		return
	}
	fl.countRTP(info, dir, len(f.Payload), at)
}

// RTPInfo 是给跨包计数用的那一格。
//
// ★ 序号与 SSRC 必须留在结构上，不能只留在 Fields 里：
// 「丢了几包」要在每一包上比上一个序号，靠翻 Fields 的中文键去比是迟早出错的写法。
type RTPInfo struct {
	SSRC         uint32
	Seq          uint16
	Timestamp    uint32
	PayloadType  byte
	Marker       bool
	PayloadBytes int
	Padding      bool
}

// ==================== 跨包的序号账 ====================

// rtpMaxDropout 借 RFC 3550 的同一个数：正向差超过它就不当「正常丢包」。
const rtpMaxDropout = 3000

// maxRTPSources 是一条流上最多记几个 SSRC。
// 不设上限就是给脏包留门：每一包换一个新 SSRC，光这张表就能把内存吃没。
const maxRTPSources = 32

// RTPAccount 是一个 SSRC 在这一条流上的序号账。
//
// ★ 为什么要单独一张，而不是从 Messages 里翻：报文列表有上限（几百条），
// 而「这一路丢了几个包」要数的是整条流。「前 200 包没丢」被写成「这条流没丢包」
// 是这类工具最容易上屏的那种假话。
type RTPAccount struct {
	SSRC        uint32
	Dir         int // 0 = A→B，1 = B→A（第一个包上看到的方向）
	PayloadType byte
	Packets     int // 见到的包（含重复）
	Bytes       int // RTP 包本身：不含 IP/UDP 头，所以这一格比链路上的数小
	Payload     int // 正文字节：算码率用这一格，含头的数会把音频流算虚高
	Markers     int // 置了标记位的包数（视频里通常等于帧数）
	Lost        int // 正向小跳估出来的空位
	JumpSpan    int // 那几处「大跳」跳过的序号数：没算进 Lost，见 advance
	Jumps       int // 大跳处数
	Gaps        int // 小跳处数
	Reorder     int // 比最高序号小、又不是重复：到晚了
	Dupes       int // 与上一包同号：网络重发、或网卡重复投递
	First       time.Time
	Last        time.Time
	Base        uint32 // 第一包的序号
	MaxExt      uint64 // 最高扩展序号（绕圈的那 16 位补到 32 位以上）

	cycles  uint64
	lastRaw uint16
	started bool
}

// String 给界面上那一格：一句话把「收了几个、该有几个、差在哪」说完。
func (r *RTPAccount) String() string {
	s := fmt.Sprintf("SSRC %08x：%d 包", r.SSRC, r.Packets)
	if n := r.LossPercent(); n > 0 {
		s += fmt.Sprintf("、丢约 %.2f%%（%d 个空位）", n, r.Lost)
	}
	if r.Jumps > 0 {
		s += fmt.Sprintf("、%d 处序号大跳（跳过 %d 个号，没算进丢包）", r.Jumps, r.JumpSpan)
	}
	if r.Reorder > 0 {
		s += fmt.Sprintf("、%d 包到晚了", r.Reorder)
	}
	if r.Dupes > 0 {
		s += fmt.Sprintf("、%d 包重复", r.Dupes)
	}
	return s
}

// Expected 回「按序号该收到几个」（首包与最高扩展序号之间，含两端，扣掉大跳过的那一段）。
//
// ★ 为什么扣 JumpSpan：advance 那一头把大跳排除在 Lost 之外，句子里也写着「没算进丢包数」，
// 但分母如果不跟着扣，一次「换了源、序号从头来」就把 Expected 顶到几千，
// 丢包率立刻变成 99% —— 那一句「没算进丢包」就成了写在表上的假话。
// 扣完之后剩下的正是「小跳（真空位）+ 实收」那一段，与 Lost 那一格对得上。
func (r *RTPAccount) Expected() uint64 {
	if !r.started || r.MaxExt < uint64(r.Base) {
		return 0
	}
	exp := r.MaxExt - uint64(r.Base) + 1 - uint64(r.JumpSpan)
	if r.Received() > exp {
		// 序号绕圈、或者一路里混进了同号不同源的包，能让实收比该有大：
		// 回实收而不是回小数，LossPercent 就稳稳是 0，不报一个凭空的负数。
		return r.Received()
	}
	return exp
}

// Received 回实际收下的包数（重复的那一些不算又收到一份内容）。
func (r *RTPAccount) Received() uint64 {
	n := r.Packets - r.Dupes
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// LossPercent 用 RFC 3550 那个口径：（应有 - 实收）/ 应有。
//
// ★ 它与 Lost 那一格可以不相等：到晚了的那一些补回来会减掉一截，
// 而大跳那一些根本没算进来 —— 两个数都得在，只留一个就是把账混了。
func (r *RTPAccount) LossPercent() float64 {
	exp := r.Expected()
	if exp == 0 {
		return 0
	}
	if got := r.Received(); got < exp {
		return float64(exp-got) * 100 / float64(exp)
	}
	return 0
}

// advance 走一个序号。方向与绕圈都按 int16 差值判，不直接比大小。
func (r *RTPAccount) advance(seq uint16) {
	if !r.started {
		r.started = true
		r.Base = uint32(seq)
		r.MaxExt = uint64(seq)
		r.lastRaw = seq
		return
	}
	d := int32(int16(seq - r.lastRaw))
	switch {
	case d == 0:
		r.Dupes++
	case d > 0:
		switch {
		case int(d) > rtpMaxDropout:
			// 正向跳得超过上限：真丢一大片与「换了源 / 序号从头来」在这一包里长得一模一样。
			// ★ 所以只记一笔，不写进丢包数 —— 把没证实的数算进丢包率，
			// 现场就会照着一个假数去换网线。
			r.Jumps++
			r.JumpSpan += int(d) - 1
		case d > 1:
			r.Gaps++
			r.Lost += int(d) - 1
		}
	default:
		if int(-d) > rtpMaxDropout {
			r.cycles += 1 << 16 // 退得离谱 = 绕了一圈
		} else {
			r.Reorder++
		}
	}
	if ext := r.cycles + uint64(seq); ext > r.MaxExt {
		r.MaxExt = ext
	}
	r.lastRaw = seq
}

// countRTP 落一个 RTP 包的账。wire 传这一包自己有多少字节（含 RTP 头，不含 IP/UDP）。
func (fl *Flow) countRTP(info *RTPInfo, dir, wire int, at time.Time) {
	if info == nil {
		return
	}
	if fl.rtpState == nil {
		fl.rtpState = make(map[uint32]*RTPAccount, 2)
	}
	st := fl.rtpState[info.SSRC]
	if st == nil {
		if len(fl.rtpState) >= maxRTPSources {
			fl.RTPSkipped++
			return
		}
		st = &RTPAccount{SSRC: info.SSRC, Dir: dir, PayloadType: info.PayloadType}
		fl.rtpState[info.SSRC] = st
		fl.RTP = append(fl.RTP, st)
	}
	if st.First.IsZero() {
		st.First = at
	}
	st.Last = at
	st.Packets++
	st.Bytes += wire
	st.Payload += info.PayloadBytes
	if info.Marker {
		st.Markers++
	}
	st.advance(info.Seq)
}
