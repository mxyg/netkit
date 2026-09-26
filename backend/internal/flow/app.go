package flow

// 应用层：从拼好的字节流里切出报文，认出是什么协议，解成一句人话。
//
// ★ 认协议一律「先看内容，内容说不清才看端口」，而且**只靠端口认出来的一定要标出来**。
// 现场最常见的坑是把 554 上当成 RTSP 来解的一堆字节解出个「DESCRIBE 回了 200」——
// 界面上写着解出来了、实际是猜的，这种产出比不解更坏。
//
// 为什么要在这一层切报文：抓包文件里从来没有人问「这一条流怎么样」，
// 问的是「这台相机为什么起不来」。而那一句的答案在 SETUP 的 Server-Transport 里、
// 在 REGISTER 第二个 401 里、在 CONNACK 那一个 return code 里。

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Message 是一条应用层报文在表上的样子。
//
// ★ 这里没有 Raw：原文里可能整段就是凭据（Authorization、MQTT 的 password、SNMP 的团体名），
// 而这一份结构是要进 JSON、进诊断包、可能被发给 AI 的。要给人看的东西一律写成脱敏后的 Fields。
type Message struct {
	At        time.Time
	Proto     string // rtsp / sip / onvif / mqtt / dns / dhcp / snmp / ssdp / mdns / ws-discovery / netbios / rtp
	From      string
	To        string
	Dir       int    // 0 = A→B，1 = B→A
	Kind      string // request / response / notify / query / report / packet
	Method    string // DESCRIBE / REGISTER / CONNECT / GetStreamUri / NOTIFY ...
	URI       string // 请求的流地址/资源（ userinfo 已脱敏）
	Version   string // RTSP/1.0、SIP/2.0、HTTP/1.1：两端实现版本对不对，看这一格
	Status    int    // 响应码；0 = 请求或没有码的一类
	Reason    string // 响应码后面那句话（协议自己给的）
	Seq       string // CSeq / 事务号 / MQTT packet id：一问一答靠它配对
	CallID    string // SIP 的会话号：同一次点播的几条信令靠它串起来
	CmdType   string // 国标 MANSCDP 的命令类型（Catalog/Keepalive/DeviceInfo/...）
	Soap      string // SOAP Body 里那一个元素名（GetStreamUri / GetCapabilities ...）
	SDP       *SDPInfo
	Transport *TransportInfo // RTSP SETUP 那两格端口与形态：跨流对账（cross.go）要用它
	RTP       *RTPInfo       // RTP/RTCP 那几格的结构值：跨包比序号要用它，不能去翻中文键
	Summary   string         // 一句人话
	Fields    []Field
	Findings  []Finding
	Creds     int // 这一条里有几处凭据被脱敏（数量不是凭据，可以带）
	Note      string
}

// Field 是一个键值对。单独一格而不写进 Summary，是因为界面要能按号筛（比如只看端口区间）。
type Field struct {
	K, V string
	// Redacted：这一格原本是凭据，只剩形状。★ 有这个标记，界面才敢写「已脱敏」，
	// 而不是让人以为这台设备没带认证信息。
	Redacted bool
}

func (m Message) String() string {
	s := m.Proto + " " + m.Kind
	if m.Method != "" {
		s += " " + m.Method
	}
	if m.Status != 0 {
		s += " " + strconv.Itoa(m.Status)
	}
	if m.Summary != "" {
		s += "：" + m.Summary
	}
	return s
}

// Header 是一条文本协议报文（RTSP / SIP / HTTP 同一形状）。
type Header struct {
	Name  string
	Value string
}

// 报文切分的上限：一条 RTSP 应答带一张大 SDP 也就一两 KB，
// 但「Content-Length: 999999999」是合法的字符串，不挡就是把内存交出去。
const (
	maxHeaderBytes = 64 << 10
	maxBodyBytes   = 1 << 20
)

// sniffWindow 是定口时看正文开头看的宽度。
// 协议的招牌都在起始行与前几个头里；给整条缓冲（上限 64KiB）每次都要洗一遍是白烧。
const sniffWindow = 8 << 10

// scanApp 在正文到位之后切报文并解。
//
// TCP 用连续缓冲（分片发的一条报文要能拼出来）；UDP 一个数据报就是一条。
func (fl *Flow) scanApp(f Frame, dir int, payload []byte, at time.Time) {
	if len(payload) == 0 || fl.owner == nil {
		return
	}
	if f.TCP != nil {
		fl.frameTCP(dir, at)
		return
	}
	fl.emit(fl.pickProto(payload), payload, dir, at, false)
}

// frameTCP 从这一方向的连续缓冲里把报文一条条切出来。
func (fl *Flow) frameTCP(dir int, at time.Time) {
	fl.sniffTCP()
	if !hasDecoder(fl.App) {
		return // 只是端口上像（ssh、rdp、加密的 tls）：没有专解就别切，切出来的每一条都是噪音
	}
	st := fl.state(dir)
	buf := st.contiguous()
	for fl.consumed[dir] < len(buf) {
		rest := buf[fl.consumed[dir]:]
		n, ok := cutMessage(fl.pickProtoOf(), rest)
		if !ok {
			break // 还不够一条：等下一段，不许拿半条去解
		}
		fl.consumed[dir] += n
		fl.emit(fl.App, rest[:n], dir, at, true)
	}
	if st.st.Capped && fl.consumed[dir] >= len(buf) {
		fl.addNote(fmt.Sprintf("这一方向的正文只留到 %d 字节（上限）：后面的没有解，也不假装解过", st.Cap()))
	}
}

// sniffTCP 给 TCP 定协议：从两个方向拼好的连续缓冲开头看一眼。
//
// ★ 这一步非做不可，而且只能做在这里：TCP 没有 UDP 那种「一个数据报就是一条报文」的便利，
// 定口的入口（pickProto）挂在 UDP 那一支上，所以不做这一步的话 fl.App 一路是空，
// 整条 TCP 上的 RTSP / HTTP / MQTT 一个字都解不出来 —— 而 RTSP 恰恰九成跑在 TCP 上。
//
// 退到端口那一档必须等：内容还没露头就按 443 定成 https，后面真正的 MQTT 再也换不过来
// （定下来的协议不再改，是为了不拿 rtsp 的刀切 sip）。所以这里只在
// 「凑出一个完整的头」或「头长顶到上限」之后才允许用端口定口。
func (fl *Flow) sniffTCP() {
	if fl.App != "" || fl.tcpSniffed {
		return
	}
	for _, dir := range []int{0, 1} {
		buf := fl.state(dir).contiguous()
		if len(buf) == 0 {
			continue
		}
		head := buf
		if len(head) > sniffWindow {
			head = head[:sniffWindow] // 只看开头那一截：协议的招牌都在起始行与前几个头里
		}
		if p := sniffProto(head); p != "" {
			fl.setApp(p)
			fl.tcpSniffed = true
			return
		}
		// 退到端口那一档的时机：第一行读完（文本协议的招牌就在第一行，读完还没认出来，
		// 就只剩「按端口说一声」和「什么都不说」两种选择，而前一种对现场有用 ——
		// 「443 上这一条是加密的」这句话本身就是答案），或者缓冲顶到了头长上限。
		// ★ 半行不许退：那一会儿真内容还没露头，早退就是把一条还没露头的 MQTT 永久定成 https。
		if firstLineDone(buf) || len(buf) >= maxHeaderBytes {
			fl.setApp("")
			fl.tcpSniffed = true
			return
		}
	}
}

// cutMessage 回这一条报文占了多少字节。ok=false 表示「还没齐，再等」。
func cutMessage(proto string, b []byte) (int, bool) {
	switch proto {
	case "mqtt":
		return cutMQTT(b)
	case "dahua":
		return cutDahua(b)
	case "dns", "mdns":
		// DNS over TCP 用两字节长度前缀分帧（RFC 1035 §4.2.2）：
		// 拿文本协议那套空行去切 TCP 上的 DNS，切出来的每一条都是半条。
		return cutDNSFrame(b)
	}
	// 文本协议（RTSP/SIP/HTTP/ONVIF-Soap 都套在 HTTP 那一形状里）：头以空行结束，正文按 Content-Length。
	head := headEnd(b)
	if head < 0 {
		if len(b) > maxHeaderBytes {
			return len(b), true // 到头了还没空行：这一条废了，别把整条流堵在这
		}
		return 0, false
	}
	cl, ok := contentLength(b[:head])
	if !ok || cl <= 0 {
		return head, true
	}
	if cl > maxBodyBytes {
		return head + cl, true // 上限外的那一些直接跳过：留着只会把缓冲吃光
	}
	if len(b) < head+cl {
		return 0, false
	}
	return head + cl, true
}

// headEnd 回「起始行加头部」结束在第几字节（ 那道空行不算正文）。
//
// ★ 长度不能写死 4：分隔行既可能是 CRLFCRLF，也可能是 LFLF（ 见 indexDoubleCRLF 那一档）。
// 写死的话，LF 分行的固件正文开头会多出两个 `\n` —— 而 SDP 的第一行是 v=，
// 多两个空行就 ParseSDP 说「没有 v= 那一行」，界面上变成「对方给的 SDP 是坏的」。
func headEnd(b []byte) int {
	i := indexDoubleCRLF(b)
	if i < 0 {
		return -1
	}
	if i+4 <= len(b) && b[i] == '\r' {
		return i + 4
	}
	return i + 2
}

// headOf 回「起始行+头部」那一段，切不出空行时把整份交给调用方。
//
// ★ 头必须只从头那一段解：拿整包去 parseHeaders 会把 SDP 与 XML 正文里
// 带冒号的行（"a=rtpmap:96 ..."、"<a:Subject:u=..."）当成头，
// 界面上就多出几格凭空发明的「头字段」，其中一格还可能正是凭据。
func headOf(raw []byte) []byte {
	if i := headEnd(raw); i >= 0 {
		return raw[:i]
	}
	return raw
}

func indexDoubleCRLF(b []byte) int {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i
	}
	// 有固件用单个 LF 分行（廉价栈）：也认，但只在没有 CRLF 形状时退这一步。
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i
	}
	return -1
}

// firstLineDone 问这一份字节里读完第一行了没有（文本协议的招牌就写在起始行那一截上）。
func firstLineDone(b []byte) bool {
	return bytes.IndexByte(b, '\n') >= 0
}

func contentLength(head []byte) (int, bool) {
	for _, h := range parseHeaders(head) {
		if strings.EqualFold(h.Name, "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(h.Value))
			if err != nil || n < 0 {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

// parseHeaders 解起始行之外的头。折行（下一行以空白开头）接回上一条，
// 因为有些平台的 User-Agent 真的会折行，不接就变成一条看不懂的孤儿头。
// parseHeaders 从头那一段里逐行解出键值。
//
// ★ 第一行一律不看：那是起始行（"DESCRIBE rtsp://… RTSP/1.0"），不是头。
// 按「有没有冒号」把它丢掉的写法看着省事，实际是最坏的一处：
// 起始行里到处是冒号（ 协议名、 端口、 版本 都在这一行上），
// "DESCRIBE rtsp://user:pass@host/live RTSP/1.0" 会被解成一格
// 名字 "DESCRIBE rtsp"、 值 "//user:pass@host/live RTSP/1.0" 的假头，
// 而流地址里那份 userinfo 就跟着这一格原样上了表 ——
// 起始行已经由 startLine 单独解过（ URI 那一份过了 scrubURI）， 这里再解一遍纯属凭空发明。
func parseHeaders(head []byte) []Header {
	lines := strings.Split(strings.TrimRight(string(head), "\r\n"), "\n")
	var out []Header
	for i, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" || i == 0 {
			continue
		}
		if (ln[0] == ' ' || ln[0] == '\t') && len(out) > 0 {
			out[len(out)-1].Value += " " + strings.TrimSpace(ln)
			continue
		}
		j := strings.IndexByte(ln, ':')
		if j <= 0 {
			continue // 脏数据里根本没有冒号的行
		}
		out = append(out, Header{Name: strings.TrimSpace(ln[:j]), Value: strings.TrimSpace(ln[j+1:])})
	}
	return out
}

// startLine 回起始行那三段（"DESCRIBE rtsp://… RTSP/1.0" / "SIP/2.0 200 OK" / "HTTP/1.0 200 OK"）。
func startLine(raw []byte) (first, second, third string) {
	line := raw
	if i := bytes.IndexAny(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	parts := strings.SplitN(strings.TrimSpace(string(line)), " ", 3)
	switch len(parts) {
	case 3:
		return parts[0], parts[1], parts[2]
	case 2:
		return parts[0], parts[1], ""
	case 1:
		return parts[0], "", ""
	}
	return "", "", ""
}

func headerValue(hdrs []Header, name string) string {
	for _, h := range hdrs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// ==================== 认协议 ====================

// 端口 → 协议名。★ 只当作「内容说不清时的第二依据」，而且认出来必须带 AppBy=端口。
func protoByPort(port uint16) string {
	switch port {
	case 554, 8554, 8001, 10554:
		return "rtsp"
	case 5060, 5061:
		return "sip"
	case 1883, 8883:
		return "mqtt"
	case 53:
		return "dns"
	case 67, 68:
		return "dhcp"
	case 161, 162:
		return "snmp"
	case 1900:
		return "ssdp"
	case 5353:
		return "mdns"
	case 3702:
		return "ws-discovery"
	case 137, 138:
		return "netbios"
	case 80, 443, 8080, 8000, 8443, 8081:
		return "http"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 3389:
		return "rdp"
	case 5900, 5901:
		return "vnc"
	case 123:
		return "ntp"
	case 3478, 5349:
		return "stun-turn"
	}
	return ""
}

// sniffProto 只看内容。这是第一依据：内容说了算。
func sniffProto(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := string(b)
	switch {
	case strings.HasPrefix(s, "RTSP/"), isRequestMethod(startLineOf(b)) && hasVersionToken(s, "RTSP/"):
		return "rtsp"
	case strings.HasPrefix(s, "SIP/2.0"), hasVersionToken(s, "SIP/2.0"):
		return "sip"
	case strings.HasPrefix(s, "OPTIONS * SIP/2.0"), strings.HasPrefix(s, "BYE "), strings.HasPrefix(s, "REGISTER "),
		strings.HasPrefix(s, "INVITE "), strings.HasPrefix(s, "ACK "), strings.HasPrefix(s, "MESSAGE "),
		strings.HasPrefix(s, "NOTIFY "), strings.HasPrefix(s, "SUBSCRIBE "), strings.HasPrefix(s, "INFO "),
		strings.HasPrefix(s, "PRACK "), strings.HasPrefix(s, "UPDATE "):
		return "sip"
	case hasVersionToken(s, "HTTP/"):
		// ONVIF 与 WS-Discovery 都套在 SOAP/HTTP 里：先看正文顶上来的是谁。
		if bytes.Contains(b[:min(len(b), 4096)], []byte("soap:Envelope")) ||
			bytes.Contains(b[:min(len(b), 4096)], []byte("Envelope xmlns")) {
			if bytes.Contains(b, []byte("Onvif")) || bytes.Contains(b, []byte("ONVIF")) ||
				bytes.Contains(b, []byte("sdp.onvif")) || bytes.Contains(b, []byte("devicemgmt")) ||
				bytes.Contains(b, []byte("media.ws")) || bytes.Contains(b, []byte("onvif.org")) {
				return "onvif"
			}
			if bytes.Contains(b, []byte("ws-dd")) || bytes.Contains(b, []byte("Discovery/Probe")) ||
				bytes.Contains(b, []byte("Discovery/Hello")) || bytes.Contains(b, []byte("Discovery/Resolve")) {
				return "ws-discovery"
			}
			if bytes.Contains(b, []byte("Discovery/Bye")) {
				return "ws-discovery"
			}
			return "soap"
		}
		// SSDP 的 NOTIFY 与 200 OK 都是 HTTP 形状：靠它自己那几个头认（NT/ST/USN/MAN/BOOTID/CACHE-CONTROL）。
		// ★ 不写 "ST: urn" 这种带空格的死串：头与值之间空不空格各家实现不一样，
		// 少一个空格就认不出来，这一档就会把它当普通 HTTP 解 —— 那正好把「谁在喊自己是什么」解没了。
		if looksLikeSSDP(b) {
			return "ssdp"
		}
		return "http"
	case strings.HasPrefix(s, "NOTIFY *"), strings.HasPrefix(s, "M-SEARCH *"):
		return "ssdp"
	case looksLikeDahua(b):
		return "dahua"
	case looksLikeDNS(b):
		return "dns"
	case looksLikeDHCP(b):
		return "dhcp"
	case looksLikeSNMP(b):
		return "snmp"
	// ★ MQTT 排在这几张结构刀之后：它的判据是「类型号 1~15 + 剩余长度正好对上」，
	// 而一份 BER 的 SEQUENCE 天生就满足这一条（0x30 的头是类型 3 = PUBLISH，
	// 第二字节就是它的长度）。反过来 MQTT 不会满足上面任何一条结构判据。
	// 谁先谁后在这里不是风格问题：先跑的那一把会把后面那一种整个认成自己的。
	case isMQTTPlausible(b):
		return "mqtt"
	case looksLikeRTP(b):
		return "rtp"
	}
	return ""
}

// ssdpHeaderNames 是 SSDP 独有、别的 HTTP 形状协议不会同时带的那几个头。
var ssdpHeaderNames = map[string]bool{
	"nt": true, "st": true, "usn": true, "man": true, "bootid": true,
	"configid": true, "searchtarget": true, "cache-control": true, "ext": true,
}

func looksLikeSSDP(b []byte) bool {
	n := 0
	for _, h := range parseHeaders(headOf(b)) {
		name := strings.ToLower(strings.TrimSpace(h.Name))
		if name == "server" && strings.Contains(strings.ToLower(h.Value), "upnp") {
			return true
		}
		if ssdpHeaderNames[name] {
			n++
		}
		if n >= 2 {
			// 两个同时出现才认：光一个 ST 或 Cache-Control 在别的 HTTP 里也见得到。
			return true
		}
	}
	return false
}

func startLineOf(b []byte) string {
	i := bytes.IndexAny(b, " \r\n")
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}

func isRequestMethod(firstWord string) bool {
	switch strings.ToUpper(firstWord) {
	case "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN", "GET_PARAMETER", "PAUSE", "ANNOUNCE", "RECORD", "GET", "POST", "PUT", "DELETE":
		return true
	}
	return false
}

func hasVersionToken(s, tok string) bool {
	i := strings.Index(s, tok)
	if i < 0 {
		return false
	}
	// 版本号要么在行首（响应），要么是这一行的第三个词（请求）。
	// 只这么认，是为了不把正文里引用到的另一句话当成协议自己的版本。
	line := s
	if j := strings.IndexAny(s, "\r\n"); j >= 0 {
		line = s[:j]
	}
	head := line[:min(i, len(line))]
	return strings.HasPrefix(strings.TrimSpace(head), tok) || strings.Count(head, " ") >= 1
}
