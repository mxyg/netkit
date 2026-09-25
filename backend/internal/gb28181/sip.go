package gb28181

// SIP 报文：够用的一份 RFC 3261 子集，专门照着 GB/T 28181 现场的样子写。
//
// ★ 为什么自己解析、不用现成库：探测工具要的从来不是「注册成功了吗」这一句，
//
//	而是「死在哪一步、那一层的账长什么样」。第三方 SIP 栈把 401、超时、
//	报文读不下去、口开着但回的不是 SIP 这几种糊成一个 error，
//	正好把现场要分的那几档抹掉了。
//
// ★ 只做到「收发这几类报文」为止：请求行走、Via/From/To 的 tag 与 branch、
//
//	CSeq、Call-ID、Expires、Contact 这几样 GB28181 真用得着的字段；
//	不碰事务状态机、不碰重定向、不碰 sips 与 TLS —— 那是话机栈的活。
//
// ★ 收的方向一律宽容，发的方向一律严格：行分隔符按 \n 切再吃掉 \r
//
//	（不少设备的固件发出来是裸 \n，只按 \r\n 切就是把能答的设备判成不答）；
//	发出去的必须按 RFC 用 CRLF，Content-Length 跟着正文走。

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// GB28181 用到的这几类方法。★ 这一层只发的那三种：OPTIONS（问它在不在）、
// MESSAGE（问它设备信息与通道表）、REGISTER（本机扮设备走一遍注册）。
// NOTIFY 与 INVITE 只认、不发：INVITE 会真的占住一路码流，属改动，
// 而本软件不解码、不放播放器 —— 但平台发来的那条 INVITE 必须认得出来，
// 那是「这台设备被当真认下了」最硬的一条证据。
const (
	MethodRegister = "REGISTER"
	MethodOptions  = "OPTIONS"
	MethodMessage  = "MESSAGE"
	MethodNotify   = "NOTIFY"
	MethodInvite   = "INVITE"
)

// Message 是一条 SIP 报文，请求与响应合用一个壳。
//
// ★ 合用不是为了省代码：这一层最容易出的错就是「把响应当请求读」，
// 合成一个类型之后，取请求行字段的地方和取状态码的地方在同一条判断上。
type Message struct {
	// 请求：Method + URI；响应：Status + Reason。另一对留着零值。
	Method string
	URI    string
	Status int
	Reason string

	// Headers 按收到的顺序存。Via 允许重复，且「最上面那一条是谁」是有意义的
	// （探测回环时要看第一条的 branch 是不是自己发出去的那个）。
	Headers []Header
	Body    []byte
}

type Header struct {
	Name  string
	Value string
}

// 常用头名。写成常量是因为这几处要跨函数比对，手打错一个字母就成了「没这个头」。
const (
	HVia             = "Via"
	HFrom            = "From"
	HTo              = "To"
	HCallID          = "Call-ID"
	HCSeq            = "CSeq"
	HContact         = "Contact"
	HMaxForwards     = "Max-Forwards"
	HContentLength   = "Content-Length"
	HContentType     = "Content-Type"
	HExpires         = "Expires"
	HUserAgent       = "User-Agent"
	HAuthorization   = "Authorization"
	HWWWAuthenticate = "WWW-Authenticate"
	HAllow           = "Allow"
	HSubject         = "Subject"
)

// 紧凑形式（compact form）。GB28181 的设备极少这么发，但一旦有人这么发，
// 不认就等于把一条答得清清楚楚的回包判成「没答」。只收有把握的几个。
var sipCompactHeaders = map[string]string{
	"v": HVia,
	"f": HFrom,
	"t": HTo,
	"i": HCallID,
	"m": HContact,
	"l": HContentLength,
	"c": HContentType,
	"s": HSubject,
}

func (m *Message) IsRequest() bool  { return m.Status == 0 }
func (m *Message) IsResponse() bool { return m.Status != 0 }

// Get 取某一条头（大小写无关，按紧凑形式展开）。
func (m *Message) Get(name string) string {
	want := canonicalHeader(name)
	for _, h := range m.Headers {
		if canonicalHeader(h.Name) == want {
			return h.Value
		}
	}
	return ""
}

// All 取某一条头的全部出现（Via 用）。
func (m *Message) All(name string) []string {
	want := canonicalHeader(name)
	var out []string
	for _, h := range m.Headers {
		if canonicalHeader(h.Name) == want {
			out = append(out, h.Value)
		}
	}
	return out
}

// Set 覆盖同名头的所有出现，并保持原来第一条的位置 —— 重排 Via 会破坏
// 「Via 自上而下的路径」这一层意思。
func (m *Message) Set(name, value string) {
	want := canonicalHeader(name)
	pos := -1
	for i, h := range m.Headers {
		if canonicalHeader(h.Name) != want {
			continue
		}
		if pos < 0 {
			pos = i
			m.Headers[i] = Header{Name: name, Value: value}
		} else {
			m.Headers = append(m.Headers[:i], m.Headers[i+1:]...)
			i--
		}
	}
	if pos < 0 {
		m.Headers = append(m.Headers, Header{Name: name, Value: value})
	}
}

func (m *Message) Add(name, value string) {
	m.Headers = append(m.Headers, Header{Name: name, Value: value})
}

func (m *Message) CallID() string { return m.Get(HCallID) }

// CSeq 拆出序号与方法。序号给不动或方法为空时返回 ok=false，
// 调用方要的是「这条回包能不能算对上号」，不是「能不能别报错」。
func (m *Message) CSeq() (seq uint64, method string, ok bool) {
	v := m.Get(HCSeq)
	sp := strings.IndexByte(v, ' ')
	if sp < 0 {
		return 0, "", false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(v[:sp]), 10, 64)
	if err != nil {
		return 0, "", false
	}
	method = strings.ToUpper(strings.TrimSpace(v[sp+1:]))
	if method == "" {
		return 0, "", false
	}
	return n, method, true
}

// Expires 读注册有效期。头没有或读不成数字时 ok=false —— 这时值该按平台的口径补，
// 不在这里替人编一个「看着像」的数。
func (m *Message) Expires() (int, bool) {
	v := strings.TrimSpace(m.Get(HExpires))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// From / To 解出地址（含 tag）。解不出来给零值，调用方按「这条报文不像 SIP」处理。
func (m *Message) From() Addr { a, _ := ParseAddr(m.Get(HFrom)); return a }
func (m *Message) To() Addr   { a, _ := ParseAddr(m.Get(HTo)); return a }

// Vias 自上而下的 Via 链。
func (m *Message) Vias() []Via {
	raw := m.All(HVia)
	out := make([]Via, 0, len(raw))
	for _, r := range raw {
		v, err := ParseVia(r)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

// TopViaBranch 是自己发出去的那个 branch，用来认「这条响应是不是回给我这一趟的」。
func (m *Message) TopViaBranch() string {
	vs := m.Vias()
	if len(vs) == 0 {
		return ""
	}
	return vs[0].Param("branch")
}

func (m *Message) StartLine() (string, error) {
	if m.IsRequest() {
		if m.Method == "" || m.URI == "" {
			return "", fmt.Errorf("请求行缺方法或 Request-URI")
		}
		// ★ 请求行里版本号在最后（`OPTIONS sip:h SIP/2.0`），响应行里在最前
		// （`SIP/2.0 200 OK`）。按响应的样子发请求，对端的解析器第一眼就崩。
		return m.Method + " " + m.URI + " SIP/2.0", nil
	}
	if m.Status < 100 || m.Status > 699 {
		return "", fmt.Errorf("状态码 %d 不在 SIP 的范围内", m.Status)
	}
	reason := m.Reason
	if reason == "" {
		reason = ReasonPhrase(m.Status)
	}
	return "SIP/2.0 " + strconv.Itoa(m.Status) + " " + reason, nil
}

// Bytes 序列化。★ 行分隔固定 CRLF；正文非空而 Content-Length 没给时按正文补上，
// 因为 GB28181 的平台收到没有长度的 MESSAGE 就当没正文，那条查询会静默地没人理。
func (m *Message) Bytes() ([]byte, error) {
	start, err := m.StartLine()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(start)
	b.WriteString("\r\n")
	body := m.Body
	hdrs := m.Headers
	if len(body) > 0 && m.Get(HContentLength) == "" {
		hdrs = append(append([]Header{}, hdrs...), Header{Name: HContentLength, Value: strconv.Itoa(len(body))})
	}
	for _, h := range hdrs {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(strings.NewReplacer("\r", " ", "\n", " ").Replace(h.Value))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	out := append([]byte(b.String()), body...)
	return out, nil
}

// MustBytes 给确定编得出去的地方用（自己刚拼出来、还没发出去的那一条）。
func (m *Message) MustBytes() []byte {
	b, err := m.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// Parse 解一条报文。★ 宽容：裸 \n 也认，头名前后空白吃掉，没有头的报文只有一行起始行也收。
func Parse(raw []byte) (*Message, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	head, body, hasBody := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("空报文")
	}
	first := strings.TrimSpace(lines[0])
	up := strings.ToUpper(first)
	switch {
	case strings.HasPrefix(up, "SIP/2.0 "):
	case strings.HasSuffix(up, " SIP/2.0"):
	default:
		return nil, fmt.Errorf("起始行不像 SIP/2.0：%q", first)
	}
	m := &Message{}
	if strings.HasPrefix(up, "SIP/2.0 ") {
		// 响应行：状态码 + 原因短语（短语里可以带空格，所以只按第一个空格切）。
		rest := strings.TrimSpace(first[len("SIP/2.0 "):])
		digits, reason := rest, ""
		if sp := strings.IndexByte(rest, ' '); sp > 0 {
			digits, reason = rest[:sp], strings.TrimSpace(rest[sp+1:])
		}
		if !allDigits(digits) {
			return nil, fmt.Errorf("状态码不像数字：%q", rest)
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return nil, fmt.Errorf("状态码 %q 读不成数字：%v", digits, err)
		}
		m.Status = n
		m.Reason = reason
	} else {
		// 请求行：方法 + Request-URI，版本号在尾巴上切掉。
		rest := strings.TrimSpace(first[:len(first)-len(" SIP/2.0")])
		method, uri, ok := strings.Cut(rest, " ")
		if !ok || method == "" || strings.TrimSpace(uri) == "" {
			return nil, fmt.Errorf("请求行不完整：%q", first)
		}
		m.Method = strings.ToUpper(strings.TrimSpace(method))
		m.URI = strings.TrimSpace(uri)
	}
	for _, ln := range lines[1:] {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if folded := ln[0]; folded == ' ' || folded == '\t' {
			// 折行：整段并到上一条去，别当新头（折行行常常压根没有冒号）。
			if len(m.Headers) == 0 {
				return nil, fmt.Errorf("第一条就是折行")
			}
			last := len(m.Headers) - 1
			m.Headers[last].Value += " " + strings.TrimSpace(ln)
			continue
		}
		name, value, ok := strings.Cut(ln, ":")
		if !ok {
			return nil, fmt.Errorf("头那一行没有冒号：%q", ln)
		}
		m.Headers = append(m.Headers, Header{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value)})
	}
	if hasBody {
		m.Body = []byte(strings.TrimSuffix(strings.ReplaceAll(body, "\n", "\r\n"), "\r\n"))
		// ★ 正文按 Content-Length 截：不少固件在最后多吐一个换行，
		// 拿去当 XML 解就多一个「尾随内容」的报错，而这条回包本来是答对了的。
		if n := strings.TrimSpace(m.Get(HContentLength)); n != "" {
			if want, err := strconv.Atoi(n); err == nil && want >= 0 && want <= len(m.Body) {
				m.Body = m.Body[:want]
			}
		}
	}
	return m, nil
}

// NewRequest 起一条请求，带上 GB28181 一定要的那几条头。
// from/to 给地址串（"sip:user@host"），via 给本机那一跳。
func NewRequest(method, uri, from, to, callID, via string, cseq uint64) *Message {
	m := &Message{Method: method, URI: uri}
	m.Add(HVia, via)
	m.Add(HFrom, from)
	m.Add(HTo, to)
	m.Add(HCallID, callID)
	m.Add(HCSeq, fmt.Sprintf("%d %s", cseq, method))
	m.Add(HMaxForwards, "70")
	return m
}

// NewResponseFor 照着请求起一条响应：Via 全部照抄且保持顺序（多条 Via 时
// 顺序就是路径，倒了中间那一跳会以为回包走错了路），From 照抄，
// To 没有 tag 就在自己这边补一个（缺 tag 的 200 OK 会让设备当成没答，重新发一趟）。
func NewResponseFor(req *Message, status int, reason string) *Message {
	if reason == "" {
		reason = ReasonPhrase(status)
	}
	resp := &Message{Status: status, Reason: reason}
	for _, h := range req.All(HVia) {
		resp.Add(HVia, h)
	}
	resp.Add(HFrom, req.Get(HFrom))
	to := req.Get(HTo)
	if addr, err := ParseAddr(to); err == nil && addr.Param("tag") == "" {
		to += ";tag=" + NewTag()
	}
	resp.Add(HTo, to)
	resp.Add(HCallID, req.CallID())
	if seq, method, ok := req.CSeq(); ok {
		resp.Add(HCSeq, fmt.Sprintf("%d %s", seq, method))
	} else {
		resp.Add(HCSeq, req.Get(HCSeq))
	}
	return resp
}

// ReasonPhrase 只给现场真会见到的那几个。默认回 "Unknown"，
// 因为原因短语只是给人看的，编一个像模像样的短语反而把「标准没这条」这件事藏掉了。
func ReasonPhrase(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 183:
		return "Session Progress"
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 480:
		return "Temporarily Unavailable"
	case 486:
		return "Busy Here"
	case 500:
		return "Server Internal Error"
	case 501:
		return "Not Implemented"
	case 503:
		return "Service Unavailable"
	case 505:
		return "Version Not Supported"
	case 603:
		return "Decline"
	}
	return "Unknown"
}

// Addr 是 From / To / Contact 里那种「地址 + 参数」。
type Addr struct {
	DisplayName string
	Scheme      string // sip / sips
	User        string
	Host        string
	Port        string
	Params      map[string]string
}

func (a Addr) Param(name string) string {
	if a.Params == nil {
		return ""
	}
	return a.Params[strings.ToLower(name)]
}

func (a Addr) String() string {
	uri := a.Scheme + ":"
	if a.User != "" {
		uri += a.User + "@"
	}
	uri += a.Host
	if a.Port != "" {
		uri += ":" + a.Port
	}
	if a.DisplayName != "" {
		uri = `"` + a.DisplayName + `" <` + uri + ">"
	}
	out := uri
	names := make([]string, 0, len(a.Params))
	for k := range a.Params {
		names = append(names, k)
	}
	// 参数顺序在协议里无意义，但这里必须稳定 —— 不然同样的地址每次拼出的报文不同，
	// 「发出去的到底是不是我以为的那一条」就没法用测试钉住了。
	sortStrings(names)
	for _, k := range names {
		out += ";" + k + "=" + a.Params[k]
	}
	return out
}

// SIPURI 起一个请求/地址用的 URI。port 为空就不带冒号（默认口）。
func SIPURI(user, host, port string) string {
	uri := "sip:"
	if user != "" {
		uri += user + "@"
	}
	uri += host
	if port != "" {
		uri += ":" + port
	}
	return uri
}

// ParseAddr 解地址串。容忍三种写法：
//
//	sip:user@host:5060
//	<sip:user@host>;tag=abc
//	"名字" <sip:user@host>;tag=abc
//
// 另外「参数写在 URI 里面」这种不合规但现场常见的写法（<sip:u@h;tag=x>）也照收 ——
// 拒掉它就等于把一条答对了的回包判成没答。
func ParseAddr(v string) (Addr, error) {
	var a Addr
	v = strings.TrimSpace(v)
	if v == "" {
		return a, fmt.Errorf("地址是空的")
	}
	var display, uri, paramPart string
	if lt := strings.IndexByte(v, '<'); lt >= 0 {
		if gt := strings.LastIndexByte(v, '>'); gt > lt {
			display = v[:lt]
			uri = v[lt+1 : gt]
			paramPart = v[gt+1:]
		} else {
			// 只有左尖括号：按没闭合处理，别把后面的参数整段吃掉。
			uri = v[lt+1:]
			display = v[:lt]
		}
	} else {
		uri = v
	}
	if semi := findParamStart(uri); semi >= 0 {
		paramPart = uri[semi+1:] + ";" + paramPart
		uri = uri[:semi]
	}
	a.Params = parseParams(paramPart)
	return fillAddrURI(&a, strings.TrimSpace(uri), display)
}

// fillAddrURI 处理「可能是 "显示名" <...> 也可能就是裸 URI」这两种剩下的形状。
func fillAddrURI(a *Addr, s, display string) (Addr, error) {
	if display == "" {
		// 没有尖括号时，前面那段带引号的算显示名。
		if strings.HasPrefix(s, `"`) {
			if q := strings.IndexByte(s[1:], '"'); q >= 0 {
				a.DisplayName = s[1 : q+1]
				s = strings.TrimSpace(s[q+2:])
			}
		} else if sp := strings.IndexByte(s, ' '); sp > 0 && !strings.Contains(s[:sp], ":") {
			a.DisplayName = strings.TrimSpace(s[:sp])
			s = strings.TrimSpace(s[sp+1:])
		}
	} else {
		a.DisplayName = strings.Trim(strings.TrimSpace(display), `"`)
	}
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok {
		return *a, fmt.Errorf("地址里没有 scheme：%q", s)
	}
	a.Scheme = strings.ToLower(scheme)
	if a.Scheme != "sip" && a.Scheme != "sips" {
		return *a, fmt.Errorf("scheme 不是 sip/sips：%q", scheme)
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		a.User = rest[:at]
		rest = rest[at+1:]
	}
	host, port, ok := strings.Cut(rest, ":")
	a.Host = strings.TrimSpace(host)
	if a.Host == "" {
		return *a, fmt.Errorf("地址里没有主机：%q", s)
	}
	if ok {
		// 端口后面可能还跟着参数（裸写法里 ;user=phone 之类），截掉。
		port, _, _ = strings.Cut(port, ";")
		if !allDigits(port) {
			return *a, fmt.Errorf("端口不像数字：%q", port)
		}
		a.Port = port
	}
	return *a, nil
}

// Via 是一跳。
type Via struct {
	Version   string // SIP/2.0
	Transport string // UDP / TCP / TLS
	Host      string
	Port      string
	Params    map[string]string
}

func (v Via) Param(name string) string {
	if v.Params == nil {
		return ""
	}
	return v.Params[strings.ToLower(name)]
}

// NewVia 起本机那一跳。branch 必须以 z9hG4bK 开头（RFC 3261 的魔术字），
// 不写这个前缀，不少平台直接把这条请求当成不合规报文丢掉。
func NewVia(host, port string) Via {
	return Via{
		Version:   "SIP/2.0",
		Transport: "UDP",
		Host:      host,
		Port:      port,
		Params:    map[string]string{"branch": NewBranch()},
	}
}

// String 把这一跳拼回头的值（SIP/2.0/UDP host:port;branch=…）。
//
// ★ 参数顺序是定死的：branch 在最前，其余按名排序。超时重发要求两条报文
// 字节完全相同，事务才还是同一趟；参数顺序每次漂，现场就成了
// 「设备说发了、平台说收到两趟」这种查不动的账。
func (v Via) String() string {
	s := v.Version + "/" + v.Transport + " " + v.Host
	if v.Port != "" {
		s += ":" + v.Port
	}
	names := make([]string, 0, len(v.Params))
	for k := range v.Params {
		if k == "branch" {
			continue
		}
		names = append(names, k)
	}
	if b := v.Param("branch"); b != "" {
		s += ";branch=" + b
	}
	sortStrings(names)
	for _, k := range names {
		s += ";" + k + "=" + v.Params[k]
	}
	return s
}

func ParseVia(v string) (Via, error) {
	var out Via
	v = strings.TrimSpace(v)
	semi := findParamStart(v)
	paramPart := ""
	if semi >= 0 {
		paramPart = v[semi+1:]
		v = v[:semi]
	}
	out.Params = parseParams(paramPart)
	tok := strings.Fields(v)
	if len(tok) < 2 {
		return out, fmt.Errorf("Via 少了段：%q", v)
	}
	// 形如 SIP/2.0/UDP 10.0.0.1:5060 —— 版本与传输用斜杠连着，中间没有空格。
	head := strings.Split(tok[0], "/")
	if len(head) < 3 {
		return out, fmt.Errorf("Via 的头部不像 SIP/版本/传输：%q", tok[0])
	}
	out.Version = strings.Join(head[:2], "/")
	out.Transport = strings.ToUpper(head[2])
	host, port, hasPort := strings.Cut(tok[1], ":")
	out.Host = host
	if hasPort {
		if !allDigits(port) {
			return out, fmt.Errorf("Via 端口不像数字：%q", port)
		}
		out.Port = port
	}
	if out.Host == "" {
		return out, fmt.Errorf("Via 没有主机")
	}
	return out, nil
}

// Branch / tag：随机串。★ 用 crypto/rand，不用时间戳 —— 时间戳在同一毫秒里
// 发两条注册会撞 branch，回包对不上号就成了「设备没答」。
func NewBranch() string { return "z9hG4bK" + randHex(8) }
func NewTag() string    { return randHex(6) }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 走到这里说明系统随机源出问题，宁可炸也别发一条会撞号的报文。
		panic(err)
	}
	return hex.EncodeToString(b)
}

// parseParams 解 ";k=v;k2;k3=\"a;b\""。分号在引号里不算分隔，
// 因为显示名与 SomeField 里真带分号的例子不少。
func parseParams(s string) map[string]string {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), ";"))
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, p := range splitOutsideQuotes(s, ';') {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		out[k] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// findParamStart 找第一个在引号外的分号。
func findParamStart(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

func splitOutsideQuotes(s string, sep byte) []string {
	var out []string
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case sep:
			if !inQuote {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func canonicalHeader(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if full, ok := sipCompactHeaders[n]; ok {
		return strings.ToLower(full)
	}
	return n
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// sortStrings 是小工具，避免为了排几个键名把 sort 拉进这个文件。
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
