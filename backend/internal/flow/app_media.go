package flow

// 媒体与信令那几种的专解：RTSP / HTTP / SIP（含国标 MANSCDP 与 SDP）/ ONVIF。
//
// 为什么是这几种：昱弘的客户现场就是摄像头、NVR、平台三方对接，
// 卡住人的永远是信令那几句话 —— 「DESCRIBE 回了 460」「REGISTER 一直 401」
// 「SETUP 的端口没人发流」。这几种不专门解，这张表就只是一份换了排版的包列表。
//
// ★ SIP、SDP、MANSCDP 都用 gb28181 那一包的现成解码器，不在这里重写第二遍：
// 那一份是拿真平台对过互操作测试的（internal/gb28181/interop_test.go），
// 这里再写一份只可能得出两个不一样的结论，而那对现场是最坏的结果。

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"net.yuhox.com/netkit/internal/gb28181"
	"net.yuhox.com/netkit/internal/onvif"
)

// SDPInfo 是一份 SDP 里排查真正要用的那几格。
//
// 单独一格是因为「收流地址」与「本机在不在那个地址上」要对，
// 「SSRC」与平台点播时给的那个要对 —— 这两处都是跨字段比，散在 Fields 里没法比。
type SDPInfo struct {
	Target     string // c= 那个地址
	Multicast  bool   // 收流地址是组播：本机没加组就没画面，这一格是那句话的依据
	Port       int
	Proto      string
	Formats    []string
	SSRC       string   // a=ssrc: 或国标写在 y= 那一行的
	MediaCount int      // 有几段 m=
	Lines      []string // 原样的会话级行（ 只留类型与值， 密钥那几行不留）
}

// TransportInfo 是 RTSP SETUP 那两格抠出来的端口与形态。
type TransportInfo struct {
	ClientPorts string // 客户端收流的端口区间，如 "6970-6971"
	ServerPorts string
	Interleaved string // "0-1"：走 TCP 复用
	Dest        string // destination= 那一格（ 有的设备会写， 写了就说得清它发给谁）
	SSRC        string // SETUP 里也写 ssrc=：与 SDP 那一份对不上号是一类真案
	Kind        string // udp / tcp-interleaved / 空 = 没说
}

// ports 把 "6970-6971" 拆成两个号；拆不出第二个时第二个等于第一个。
func (t *TransportInfo) ports() (int, int, bool) {
	s := t.ClientPorts
	if s == "" {
		s = t.ServerPorts
	}
	if s == "" {
		return 0, 0, false
	}
	a, b, _ := strings.Cut(s, "-")
	n1, err1 := strconv.Atoi(strings.TrimSpace(a))
	if err1 != nil || n1 <= 0 || n1 > 65535 {
		return 0, 0, false
	}
	n2 := n1
	if b != "" {
		v, err := strconv.Atoi(strings.TrimSpace(b))
		if err != nil || v <= 0 || v > 65535 {
			return 0, 0, false
		}
		n2 = v
	}
	if n2 < n1 {
		n1, n2 = n2, n1
	}
	return n1, n2, true
}

// bodyOf 取起始行+头之后的正文。切报文时已按 Content-Length 对齐过，这里只按空行分。
func bodyOf(raw []byte) []byte {
	i := headEnd(raw)
	if i < 0 {
		return nil
	}
	return raw[i:]
}

// ==================== RTSP / HTTP ====================

func decodeRTSPish(proto string, raw []byte) (*Message, error) {
	first, second, third := startLine(raw)
	head := headOf(raw)
	hdrs := parseHeaders(head)
	m := &Message{Proto: proto, Fields: []Field{}}
	switch {
	case strings.HasPrefix(first, "RTSP/"), strings.HasPrefix(first, "HTTP/"), strings.HasPrefix(first, "SIP/"):
		m.Kind = "response"
		if n, err := strconv.Atoi(second); err == nil {
			m.Status = n
		}
		m.Version = first
		m.Reason = scrubText(third)
	default:
		m.Kind = "request"
		m.Method = strings.ToUpper(first)
		m.URI = scrubURI(second)
		m.Version = third
	}
	m.Seq = firstOf(headerValue(hdrs, "CSeq"), headerValue(hdrs, "Seq"))

	for _, h := range hdrs {
		fs, k := headerFields(h.Name, h.Value)
		m.Fields = append(m.Fields, fs...)
		m.Creds += k
	}

	switch proto {
	case "rtsp":
		decorateRTSP(m, hdrs, bodyOf(raw))
	case "http", "soap":
		decorateHTTP(m)
	}
	if m.Kind == "request" {
		m.Summary = strings.TrimSpace(m.Method + " " + m.URI)
	} else {
		m.Summary = strings.TrimSpace(fmt.Sprintf("%d %s", m.Status, m.Reason))
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

// headerFields 落一条头，并回这一条里脱掉了几格凭据。认证那几头的值里有凭据，单独走 digestFields。
//
// 收 name/value 而不是收 Header：SIP 那一条流的头在 gb28181 包上（形状一样、类型不同），
// 为了传参再拷一层结构，不如让两个调用方各自交自己那一份。
func headerFields(name, value string) ([]Field, int) {
	switch localName(name) {
	case "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate":
		return digestFields(name, value)
	}
	return []Field{field(name, scrubText(value))}, 0
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// decorateRTSP 把 RTSP 特有的那几格与判定落下来。
func decorateRTSP(m *Message, hdrs []Header, body []byte) {
	if v := headerValue(hdrs, "Session"); v != "" {
		m.Fields = append(m.Fields, field("Session", strings.TrimSpace(strings.Split(v, ";")[0])))
	}
	tr := headerValue(hdrs, "Transport")
	name := "Transport"
	if tr == "" {
		tr = headerValue(hdrs, "Server-Transport")
		name = "Server-Transport"
	}
	if tr != "" {
		m.Fields = append(m.Fields, field(name, tr))
		m.Transport = parseTransport(tr)
	}
	for _, h := range []string{"Require", "Public", "Range", "Scale", "Speed"} {
		if v := headerValue(hdrs, h); v != "" {
			m.Fields = append(m.Fields, field(h, v))
		}
	}
	if m.Kind == "response" {
		rtspStatusFinding(m)
	}
	if len(body) > 0 {
		if sdp, err := gb28181.ParseSDP(body); err == nil {
			m.SDP = sdpInfo(sdp)
			m.Fields = append(m.Fields, field("SDP", m.SDP.Summary()))
		} else {
			m.Fields = append(m.Fields, field("正文", fmt.Sprintf("%d 字节，不是 SDP（这一档没写它的专解）", len(body))))
		}
	}
}

func (s *SDPInfo) Summary() string {
	if s == nil {
		return ""
	}
	var parts []string
	if s.Port > 0 {
		parts = append(parts, fmt.Sprintf("媒体端口 %d", s.Port))
	}
	if s.Target != "" {
		parts = append(parts, "收流地址 "+s.Target)
		if s.Multicast {
			parts = append(parts, "组播")
		}
	}
	if s.SSRC != "" {
		parts = append(parts, "SSRC "+s.SSRC)
	}
	if len(s.Formats) > 0 {
		parts = append(parts, "格式 "+strings.Join(s.Formats, "/"))
	}
	if s.MediaCount > 1 {
		parts = append(parts, fmt.Sprintf("%d 段媒体", s.MediaCount))
	}
	if len(parts) == 0 {
		return "一份没有可用字段的 SDP（对方给的很省事， 也可能是坏的）"
	}
	return strings.Join(parts, "，")
}

// parseTransport 抠出排查真正要用的那几格：两个端口区间、interleaved、destination。
//
// 「SETUP 成功了但一个 RTP 包都没有」就是靠 client_port 对到 UDP 那条流上去的（见 cross.go）。
func parseTransport(tr string) *TransportInfo {
	out := &TransportInfo{}
	low := strings.ToLower(tr)
	switch {
	case strings.Contains(low, "rtp/tcp"):
		out.Kind = "tcp-interleaved"
	case strings.Contains(low, "rtp/udp"):
		out.Kind = "udp"
	}
	for _, part := range strings.Split(tr, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "client_port":
			out.ClientPorts = v
			out.Kind = "udp"
		case "server_port":
			out.ServerPorts = v
		case "interleaved":
			out.Interleaved = v
			out.Kind = "tcp-interleaved"
		case "destination":
			out.Dest = v
		case "ssrc":
			// SETUP 里也写 SSRC：点播对不上的案，这一格与 SDP 那一份要能互相对。
			out.SSRC = v
		}
	}
	return out
}

// rtspStatusFinding 只对「有明确下一步查法」的那些码说话。
// 其余非 2xx 一律一个通用码加原文，不猜语义：猜出来的原因比没有更害人。
func rtspStatusFinding(m *Message) {
	add := func(code, text string) {
		m.Findings = append(m.Findings, Finding{Code: code, Text: text})
	}
	switch m.Status {
	case 401, 407:
		scheme := "（没写方式）"
		for _, h := range m.Fields {
			// digestFields 把方式单列成了一格 "<头名> 方式"
			if strings.HasSuffix(h.K, " 方式") {
				scheme = h.V
			}
		}
		add("auth-challenge", fmt.Sprintf("要认证（%d，方式 %s）：客户端没带凭据、或带的这一份被拒了 —— 凭据本身不在表上", m.Status, scheme))
	case 404:
		add("rtsp-uri-not-found", fmt.Sprintf("没有这个流地址：%s —— 先核通道号与上下文（不同家的路径写法差很远）", m.URI))
	case 451:
		add("rtsp-parameter-forbidden", "参数合法但服务端不许用（常见于要求鉴权后才允许的 Transport）")
	case 453:
		add("rtsp-method-not-allowed", fmt.Sprintf("%s 在这个资源上不允许 %s：多半是没 SETUP 就 PLAY，或路径给错了", m.URI, m.Method))
	case 454:
		add("rtsp-session-not-found", "Session 号服务端不认：会话超时或被别的客户端顶掉（保活没发、或中间设备清过状态）")
	case 455:
		add("rtsp-method-not-valid", "这个方法在这一版协议里不合法：两端实现版本对不上")
	case 460:
		add("rtsp-unsupported-transport", "传输方式设备不支持（要 RTP/TCP interleaved 而它只给 UDP，或反过来）：这是「播放器不出图、VLC 能出」那类案的那一步")
	case 461:
		add("rtsp-unsupported-parameter", "请求里某个参数设备不支持：看上一条 Transport/Require 写了什么")
	case 462:
		add("rtsp-unsupported-codec", "客户端声明的编码格式设备没有：改播放器或改码流配置，网络这一侧没问题")
	case 500:
		add("rtsp-internal-error", "设备内部错误（500）：它自己的日志才有答案，网络这一层到这里就到头了")
	case 501:
		add("rtsp-not-implemented", "设备没实现这个方法：客户端要求了一个它不支持的能力")
	case 551:
		add("rtsp-not-enough-bandwidth", "设备说带宽不够：先确认是不是走错了口（比如跨了一层窄上联），别急着改码率")
	default:
		if m.Status >= 400 {
			add("rtsp-error-status", fmt.Sprintf("回了 %d %s（这一档没有它的专门说法，原文照抄）", m.Status, m.Reason))
		}
	}
}

// decorateHTTP 记下对排查有用的那几格，并对 4xx/5xx 出一句原文。
func decorateHTTP(m *Message) {
	for _, h := range m.Fields {
		if strings.EqualFold(h.K, "Location") {
			h.V = scrubURI(h.V)
		}
	}
	if m.Kind == "response" && m.Status >= 400 {
		m.Findings = append(m.Findings, Finding{Code: "http-error-status",
			Text: fmt.Sprintf("HTTP %d %s：这台管理页/接口回了错", m.Status, m.Reason)})
	}
}

// ==================== SDP ====================

// sdpInfo 从解好的 SDP 里挑出排查要用的那几格。
//
// ★ 只挑「对得上号」的那些：一条 a=crypto / a=key-param 是密钥材料，
// 原文一行都不许进结果（所以 Lines 里跳掉这几类）。
func sdpInfo(s *gb28181.Session) *SDPInfo {
	out := &SDPInfo{MediaCount: len(s.Media)}
	if len(s.Conns) > 0 {
		out.Target = s.Conns[0].Address
		out.Multicast = s.Conns[0].Multicast()
	}
	if len(s.Media) > 0 {
		md := s.Media[0]
		out.Port = md.Port
		out.Proto = md.Proto
		out.Formats = append([]string(nil), md.Formats...)
		if len(md.Conns) > 0 && out.Target == "" {
			out.Target = md.Conns[0].Address
			out.Multicast = md.Conns[0].Multicast()
		}
		for _, a := range md.Attrs {
			pickSDPAttr(out, a)
		}
	}
	for _, a := range s.Attributes {
		pickSDPAttr(out, a)
	}
	for _, ln := range s.Others {
		switch ln.Type {
		case "y":
			// 国标把 SSRC/组播信息写在 y= 这一行（ 不在 a= 里）， 点播对不上号时看它。
			// 这里只原样留行内容；SSRC 那一格另按 s.SSRC() 取（见下）。
			out.Lines = append(out.Lines, "y="+ln.Value)
		case "s", "t", "b":
			out.Lines = append(out.Lines, ln.Type+"="+ln.Value)
		case "k":
			// 旧式的密钥行：值是凭据， 只留「有这一行」。
			out.Lines = append(out.Lines, "k=（已脱敏）")
		}
	}
	// ★ SSRC 得走 s.SSRC()：标准与各家实现把 y= 写在 m= **之后**（媒体级），
	// 只翻会话级那一份就把最常见的一种写法整个漏掉 ——
	// 于是「平台点播给的 ssrc 与设备推的不是同一个」这一格永远不响，
	// 而现场照着这张表查一整天，因为表上看着「比对过了、没报」。
	if v, ok := s.SSRC(); ok {
		out.SSRC = firstOf(out.SSRC, v)
	}
	return out
}

func pickSDPAttr(out *SDPInfo, a gb28181.Attr) {
	switch strings.ToLower(a.Name) {
	case "ssrc":
		v := strings.TrimSpace(a.Value)
		if i := strings.IndexByte(v, ' '); i > 0 {
			v = v[:i] // "1234567890 msid:..." 这种带后缀的写法
		}
		if out.SSRC == "" {
			out.SSRC = v
		}
	case "recvaddress":
		out.Lines = append(out.Lines, "a=recvaddress="+a.Value)
	case "crypto", "key-param", "key-syst", "fingerprint", "kg", "ike", "gcm", "aes-cm":
		// SDES 密钥材料：值一个字节都不留，只留「有这一行」（ 见包注释那条硬闸门）。
		out.Lines = append(out.Lines, "a="+a.Name+"=（已脱敏）")
	default:
		out.Lines = append(out.Lines, "a="+strings.TrimSpace(a.Raw))
	}
}

// ==================== SIP（国标 GB28181 的信令） ====================

func decodeSIP(raw []byte) (*Message, error) {
	msg, err := gb28181.Parse(raw)
	if err != nil {
		return nil, err
	}
	m := &Message{Proto: "sip", Fields: []Field{}, Method: msg.Method, Status: msg.Status, Reason: msg.Reason}
	if m.Status != 0 {
		m.Kind = "response"
		m.Version = "SIP/2.0"
	} else {
		m.Kind = "request"
		m.URI = scrubURI(msg.URI)
	}
	for _, h := range msg.Headers {
		switch localName(h.Name) {
		case "cseq":
			// CSeq 是「序号 + 方法」两段。回包的起始行里没有方法（方法只写在请求行），
			// 这一条头就是「这条 200/401 答的是哪一次询问」唯一的凭据。不拆出来，
			// 流一层就分不清 401 是答 REGISTER 还是答 MESSAGE，判定会串到别的会话上。
			num, verb, _ := strings.Cut(strings.TrimSpace(h.Value), " ")
			m.Seq = strings.TrimSpace(num)
			if m.Kind == "response" && m.Method == "" {
				m.Method = strings.ToUpper(strings.TrimSpace(verb))
			}
		case "call-id":
			m.CallID = h.Value
		case "contact", "from", "to":
			m.Fields = append(m.Fields, field(h.Name, scrubURI(h.Value)))
			continue
		}
		fs, k := headerFields(h.Name, h.Value)
		m.Fields = append(m.Fields, fs...)
		m.Creds += k
	}
	if body := msg.Body; len(bytes.TrimSpace(body)) > 0 {
		switch {
		case bytes.Contains(body, []byte("MANSCDP")) || bytes.Contains(body, []byte("CmdType")):
			decorateMANSCDP(m, body)
		default:
			if sdp, err := gb28181.ParseSDP(body); err == nil {
				m.SDP = sdpInfo(sdp)
				m.Fields = append(m.Fields, field("SDP", m.SDP.Summary()))
			} else {
				m.Fields = append(m.Fields, field("正文", fmt.Sprintf("%d 字节（不是 MANSCDP 也不是 SDP）", len(body))))
			}
		}
	}
	decorateSIPStatus(m)
	if m.Kind == "request" {
		m.Summary = strings.TrimSpace(m.Method + " " + m.URI)
	} else {
		m.Summary = strings.TrimSpace(fmt.Sprintf("%d %s", m.Status, gb28181.ReasonPhrase(m.Status)))
	}
	if m.CmdType != "" {
		m.Summary = strings.TrimSpace(m.Summary + " " + m.CmdType)
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

// decorateMANSCDP 解国标的 XML 命令。
func decorateMANSCDP(m *Message, body []byte) {
	cmd, err := gb28181.ParseCmd(body)
	if err != nil {
		m.Fields = append(m.Fields, field("MANSCDP", "解不动："+scrubText(err.Error())))
		return
	}
	m.CmdType = cmd.CmdType
	m.Fields = append(m.Fields,
		field("命令类型", cmd.CmdType), field("报文类别", cmd.Root),
		field("SN", cmd.SN), field("设备编号", cmd.DeviceID))
	for _, k := range cmd.Fields.Keys() {
		m.Fields = append(m.Fields, field(k, scrubText(cmd.Fields.Get(k))))
	}
	for name, n := range cmd.Lists {
		m.Fields = append(m.Fields, field("列表 "+name, strconv.Itoa(n)+" 条"))
	}
	if len(cmd.Items) > 0 {
		m.Fields = append(m.Fields, field("条目数", strconv.Itoa(len(cmd.Items))))
	}
	if cmd.NonUTF8 {
		m.Fields = append(m.Fields, field("编码", "正文里有非 UTF-8 字节（中文名可能是乱码， 不是本工具弄坏的）"))
	}
	if len(cmd.Repeated) > 0 {
		m.Fields = append(m.Fields, field("同层重复键", strings.Join(cmd.Repeated, "、")))
	}
	switch strings.ToLower(cmd.CmdType) {
	case "alarm":
		m.Findings = append(m.Findings, Finding{Code: "gb28181-alarm",
			Text: "设备上报了一条告警：" + alarmSummary(cmd)})
	case "keepalive":
		if !strings.EqualFold(cmd.Root, "Response") {
			// 设备侧的 Keepalive 里 Status 那格是它自己报的健康度（ALARM/OK）：
			// 不是 OK 就得当场问一句，别等它掉线了才回头翻这张表。
			if st := cmd.Fields.Get("Status"); st != "" && !strings.EqualFold(st, "OK") {
				m.Findings = append(m.Findings, Finding{Code: "gb28181-keepalive-status",
					Text: "保活里设备自报状态不是 OK：" + scrubText(st)})
			}
			m.Fields = append(m.Fields, field("保活状态", strings.TrimSpace(cmd.Fields.Get("Status"))))
		}
	case "catalog":
		m.Fields = append(m.Fields, field("目录", catalogSummary(cmd)))
	}
}

// alarmSummary 把一条告警里最能定位的那几格拼成一句。
//
// ★ 键是manscdp 解析后落在同一层的小写叶子名（ 它不保留 XML 的嵌套路径），
// 所以这里按平铺的名字取，写成 "Info/AlarmDescription" 那种路径只会永远取到空。
func alarmSummary(cmd *gb28181.Cmd) string {
	var parts []string
	for _, k := range []string{"AlarmMethod", "AlarmType", "AlarmPriority", "AlarmDescription", "StartTime"} {
		if v := cmd.Fields.Get(k); v != "" {
			parts = append(parts, k+"="+scrubText(v))
		}
	}
	if len(parts) == 0 {
		return "设备没说细节（这一条上它只报了有一个告警）"
	}
	return strings.Join(parts, "，")
}

func catalogSummary(cmd *gb28181.Cmd) string {
	s := "没报 SumNum"
	if n, ok := cmd.SumNum(); ok {
		s = strconv.Itoa(n) + " 个通道（它自己报的数）"
	}
	if got := len(cmd.Items); got > 0 {
		s += fmt.Sprintf("，这一份里数到 %d 条", got)
	}
	if len(cmd.Ambiguous) > 0 {
		// 只装了一条的容器分不清是「就一台设备」还是「设备自己带的字段」：
		// 这一句必须原样交给人，不能替他认成通道数。
		s += "；★" + strings.Join(cmd.Ambiguous, "、") + " 只挂了一个子项，分不清是条目还是字段"
	}
	return s
}

func decorateSIPStatus(m *Message) {
	if m.Status == 0 {
		return
	}
	add := func(code, text string) {
		m.Findings = append(m.Findings, Finding{Code: code, Text: text})
	}
	switch m.Status {
	case 401, 407:
		add("sip-auth-challenge", fmt.Sprintf("认证没过（%d）：国标平台要 Digest，设备只发 Basic 或不带 Authorization 就是这一句", m.Status))
	case 403:
		add("sip-forbidden", "平台拒了（403）：设备编号没入库、或不在该平台的域内——凭据对不对得看上一条 401")
	case 404:
		add("sip-not-found", "目标不存在（404）：编号写错，或设备此时不在线（注册已过期）")
	case 408, 481:
		add("sip-timeout", fmt.Sprintf("信令超时/事务不存在（%d）：SIP 走 UDP 时最常见的是中间那一跳没回，先核到那台机器的回程路由", m.Status))
	case 480, 503:
		add("sip-unavailable", fmt.Sprintf("对方说它现在不能服务（%d）：注册/转发那台过载或没起", m.Status))
	case 603:
		add("sip-declined", "被叫明确拒了（603）：这不是网络问题，去问那台设备的策略")
	}
}

// ==================== ONVIF（SOAP over HTTP） ====================

func decodeONVIF(raw []byte) (*Message, error) {
	m, err := decodeRTSPish("http", raw)
	if err != nil {
		return nil, err
	}
	m.Proto = "onvif"
	body := bytes.TrimSpace(bodyOf(raw))
	if len(body) == 0 {
		m.Fields = append(m.Fields, field("SOAP", "没有正文（这一条只是 HTTP 壳，SOAP 在另一个方向）"))
		return m, nil
	}
	root, perr := onvif.Parse(body)
	if perr != nil {
		m.Fields = append(m.Fields, field("SOAP", "解不动："+scrubText(perr.Error())))
		return m, nil
	}
	// Body 下面第一个元素就是方法名（请求）或应答名（响应）。
	if b := root.Find("Body"); b != nil && len(b.Kids) > 0 {
		m.Soap = b.Kids[0].Name
		m.Fields = append(m.Fields, field("SOAP 方法", m.Soap))
	}
	if f := root.Find("Fault"); f != nil {
		reason := firstNonEmpty(f.Get("Reason"), f.Get("Text"), f.Get("faultstring"), f.Get("faultCode"))
		m.Findings = append(m.Findings, Finding{Code: "soap-fault",
			Text: "SOAP 回了 Fault：" + scrubText(reason) + "（设备拒绝了这个调用，不是网络不通）"})
	}
	// 应答里那几格是现场真正要抄走的：服务地址、取流地址、身份、时间。
	for _, name := range []string{"XAddr", "StreamUri", "Uri", "Name", "Hardware", "Firmware", "SerialNumber", "IPAddress"} {
		if v := root.Get(name); v != "" {
			m.Fields = append(m.Fields, field(name, scrubURI(v)))
		}
	}
	if tok := root.Find("UsernameToken"); tok != nil {
		m.Fields = append(m.Fields, field("WSSE 用户名", tok.Get("Username")))
		if pw := tok.Get("Password"); pw != "" {
			m.Fields = append(m.Fields, secretField("WSSE 口令", pw))
			m.Creds++
		}
	}
	if m.Kind == "response" && m.Soap != "" && root.Find("Fault") == nil {
		m.Summary = "SOAP " + m.Soap + " 回了应答"
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "（没给原因）"
}
