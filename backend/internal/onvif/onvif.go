// Package onvif 只做一件事：把 ONVIF 那套 SOAP 报文对上/对下。
//
// ★ 为什么不用现成 SDK：ONVIF 的 Golang 生成代码要拉一整套 WSDL 生成器，
//
//	而我们要的只是三个读请求 —— 自己拼信封、自己扫应答，安装包依旧零专有依赖。
//
// ★ 扫应答时一律**只按元素的本地名认**，不认前缀。
//
//	各家固件给元素起的前缀千奇百怪（tds:、ttd:、tt:、d:、无前缀都有），
//	照前缀匹配的结果就是「设备明明回了，我们却报它没回」——
//	这种错比报错更坏：人会顺着「没回」去查一个不存在的地方。
package onvif

import (
	"crypto/rand"
	"crypto/sha1" // [WS-Security] PasswordDigest 这一处是规范钉死的，见 passwordDigest
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// 报文里写死的命名空间。市面设备 SOAP 1.1 / 1.2 并存，
// 发的时候按 ONVIF 规范用的 1.2，**收的时候两个都认**（都只按本地名认）。
const (
	EnvNS      = "http://www.w3.org/2003/05/soap-envelope"
	DeviceNS   = "http://www.onvif.org/ver10/device/wsdl"
	MediaNS    = "http://www.onvif.org/ver10/media/wsdl"
	SchemaNS   = "http://www.onvif.org/ver10/schema"
	wsseNS     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	wsuNS      = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	digestType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	nonceEnc   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

// Credential 是 ONVIF 账号。多数相机匿名只回 Fault，得带账号才问得出东西。
type Credential struct {
	Username string
	Password string
}

// Authenticated 是有没有给账号 —— 给了被拒和没给是被要求，两件事得分开。
func (c *Credential) Authenticated() bool { return c != nil && c.Username != "" }

// PasswordDigest = Base64(SHA-1(nonce + created + password))。
//
// ★ 这里出现 SHA-1 **不是我们挑的算法，是 WS-Security UsernameToken 1.0 钉死的**：
//
//	换成 SHA-256 对岸不认，问都问不通。弱在协议不在实现 —— 这也正是
//	「凭据不进结果、不进日志」这一条在 ONVIF 这一路尤其要紧的原因。
func PasswordDigest(nonce []byte, created, password string) string {
	h := sha1.New()
	h.Write(nonce)
	h.Write([]byte(created))
	h.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// SecurityHeader 拼 WS-Security 头。nonce 每次现取（同一份摘要被回放没用，
// 但设备会拿 Created 的时间窗挡旧包，所以时间戳也要跟着走）。
func SecurityHeader(c *Credential) string {
	if !c.Authenticated() {
		return ""
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	created := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	return `<wsse:Security xmlns:wsse="` + wsseNS + `" xmlns:wsu="` + wsuNS +
		`" s:mustUnderstand="1"><wsse:UsernameToken>` +
		`<wsse:Username>` + Esc(c.Username) + `</wsse:Username>` +
		`<wsse:Password Type="` + digestType + `">` +
		PasswordDigest(nonce, created, c.Password) + `</wsse:Password>` +
		`<wsse:Nonce EncodingType="` + nonceEnc + `">` +
		base64.StdEncoding.EncodeToString(nonce) + `</wsse:Nonce>` +
		`<wsu:Created>` + created + `</wsu:Created>` +
		`</wsse:UsernameToken></wsse:Security>`
}

// Request 拼一个 SOAP 1.2 信封。body 是本包内写死的请求片段，
// 唯一可能带外部输入的是 token —— 所以造请求只走 Body()，它会转义。
func Request(header, body string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="` + EnvNS + `"><s:Header>` + header + `</s:Header>` +
		`<s:Body>` + body + `</s:Body></s:Envelope>`
}

// Body 造一个带命名空间的请求元素，extra 是已经拼好的子元素（本包内写死）。
func Body(ns, elem, extra string) string {
	if extra == "" {
		return `<` + elem + ` xmlns="` + ns + `"/>`
	}
	return `<` + elem + ` xmlns="` + ns + `">` + extra + `</` + elem + `>`
}

// Esc 转义要进 XML 的外部文本（账号、profile token 都算）。
func Esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// ── 本包用到的几个请求 ──

func reqDeviceInfo() string { return Body(DeviceNS, "GetDeviceInformation", "") }
func reqTime() string       { return Body(DeviceNS, "GetSystemDateAndTime", "") }
func reqProfiles() string   { return Body(MediaNS, "GetProfiles", "") }
func reqStreamURI(t string) string {
	return Body(MediaNS, "GetStreamUri",
		`<StreamSetup><Transport xmlns="`+SchemaNS+`"><Protocol>RTSP</Protocol></Transport>`+
			`<RtpTransport xmlns="`+SchemaNS+`">RTP/UDP</RtpTransport></StreamSetup>`+
			`<ProfileToken>`+Esc(t)+`</ProfileToken>`)
}

// Call 是一次问话：返回要 POST 的正文与 SOAPAction。
type Call struct {
	Action string
	Body   string
}

// Calls 是这一轮要问的读请求。★ 只有读的：ONVIF 里写的那一半
// （SetSystemDateAndTime、SetNetworkProtocols…）不在本包的能力范围内，
// 也不该被一个探测工具碰到。
func Calls() []Call {
	return []Call{
		{Action: "GetDeviceInformation", Body: reqDeviceInfo()},
		{Action: "GetSystemDateAndTime", Body: reqTime()},
		{Action: "GetCapabilities", Body: Body(DeviceNS, "GetCapabilities", "")},
		{Action: "GetProfiles", Body: reqProfiles()},
	}
}

// StreamURICall 拿到 profile token 之后才问得出，所以单独一次。
func StreamURICall(token string) Call {
	return Call{Action: "GetStreamUri", Body: reqStreamURI(token)}
}

// ── 应答这一侧：扫成一棵树，再按名字取 ──

// Node 是一个元素。只留本地名 —— 见包注释里那条「不认前缀」。
type Node struct {
	Name string
	Attr map[string]string
	Text string
	Kids []*Node
}

// 对岸是我们控制不了的固件：报文多大、多深、文本多长都没有承诺。
// 没有天花板的话，一句探测语可能被一台设备拖死。
const (
	maxNodes  = 20000
	maxDepth  = 40
	maxText   = 4096
	maxKids   = 5000
	errTooBig = "应答太大或太深，没接着解（设备回的 SOAP 不像正常规模）"
)

// Parse 把一段 SOAP 应答扫成树。不要求它是合法 XML —— 真设备的应答常年少个
// 结束标签、多个未声明前缀，Strict=false 加上「按本地名认」才扛得住。
func Parse(data []byte) (*Node, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	root := &Node{Name: "#root"}
	stack := []*Node{root}
	nodes := 0
	for {
		tk, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 解到一半坏了：手里已经解出来的那部分照用 —— 设备回了身份却
			// 在媒体那一段崩掉，比「整条失败」更接近真相。
			break
		}
		switch v := tk.(type) {
		case xml.StartElement:
			nodes++
			if nodes > maxNodes || len(stack) > maxDepth || len(stack[0].Kids) > maxKids {
				return nil, fmt.Errorf("%s", errTooBig)
			}
			n := &Node{Name: local(v.Name.Local), Attr: attrs(v.Attr)}
			parent := stack[len(stack)-1]
			parent.Kids = append(parent.Kids, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if s := strings.TrimSpace(string(v)); s != "" {
				cur := stack[len(stack)-1]
				if len(cur.Text) < maxText {
					if cur.Text != "" {
						cur.Text += " "
					}
					if room := maxText - len(cur.Text); len(s) > room {
						// 一句就能顶穿上限：当场截住，不等下一句再看门。
						s = strings.ToValidUTF8(s[:room], "")
					}
					cur.Text += s
				}
			}
		}
	}
	return root, nil
}

func local(s string) string {
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func attrs(in []xml.Attr) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for _, a := range in {
		out[local(a.Name.Local)] = a.Value
	}
	return out
}

// Find 深度优先找第一个这个名字的后代（不限层）。
//
// ★ 之所以要「不限层」而不是逐层写死路径：各家的嵌套层数并不一致
//
//	（Media 服务地址有的挂在 Capabilities/Media/XAddr，有的挂在 Services 里），
//	写死一条路径等于只认一家的写法。
func (n *Node) Find(name string) *Node {
	if n == nil {
		return nil
	}
	for _, k := range n.Kids {
		if k.Name == name {
			return k
		}
		if d := k.Find(name); d != nil {
			return d
		}
	}
	return nil
}

// All 找全部这个名字的（后代）。profile 列表这种「给几个就要数几个」的走这条。
func (n *Node) All(name string) []*Node {
	var out []*Node
	if n == nil {
		return out
	}
	for _, k := range n.Kids {
		if k.Name == name {
			out = append(out, k)
		}
		out = append(out, k.All(name)...)
	}
	return out
}

// Get 取一个后代的文本；没有就返回空串（不编一个）。
func (n *Node) Get(name string) string {
	if d := n.Find(name); d != nil {
		return d.Text
	}
	return ""
}

func (n *Node) Has(name string) bool { return n != nil && n.Find(name) != nil }

// Fault 是 SOAP 的拒答。
type Fault struct {
	Code   string
	Reason string
}

// FaultOf 从整份应答里取 Fault。没有 Fault 返回 nil。
func FaultOf(root *Node) *Fault {
	f := root.Find("Fault")
	if f == nil {
		return nil
	}
	out := &Fault{}
	// SOAP 1.2 把码与文案各往下挂了一层（Code/Value、Reason/Text）。
	// 只读 Code 这一层读到的是空白 —— 于是「不让你问」被当成「这台不会问」，
	// 人就该去翻一个根本没配错的东西。
	if c := f.Find("Code"); c != nil {
		out.Code = c.Get("Value")
		if out.Code == "" {
			out.Code = c.Text
		}
	}
	if r := f.Find("Reason"); r != nil {
		out.Reason = r.Get("Text")
		if out.Reason == "" {
			out.Reason = r.Text
		}
	}
	if out.Code == "" { // SOAP 1.1 直接挂在 Fault 下
		out.Code = f.Get("faultcode")
	}
	if out.Reason == "" {
		for _, k := range []string{"ReasonText", "faultstring"} {
			if v := f.Get(k); v != "" {
				out.Reason = v
				break
			}
		}
	}
	if out.Reason == "" && out.Code == "" {
		out.Reason = f.Text
	}
	return out
}

// LooksAuthFault 判断这条 Fault 是「不让你问」还是「这个我不会」。
//
// ★ 分不开就会误判：auth-rejected 让人去翻密码，而密码本来就是对的 ——
//
//	真原因是这台没实现媒体服务，那该去翻配置。各家文案不统一，
//	所以这里按关键字认，认不出就当作「不会」而不是「不让」。
func LooksAuthFault(f *Fault) bool {
	if f == nil {
		return false
	}
	s := strings.ToLower(f.Code + " " + f.Reason)
	// ★ 各家文案不统一，这里宽一点：这些词都指向「你不够格问」，不是「这台不会答」。
	// 收得太紧就会把人推去翻密码。不收 sender/access：s:Sender 也用于参数错，会反向误判。
	for _, k := range []string{"auth", "unauthorized", "not authorized", "notauthorized",
		"security", "credential", "password", "username", "token",
		"rights", "permission", "denied", "wsse", "soapenv:sender", "env:sender"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// DeviceInfo 是设备自己报的户口。
type DeviceInfo struct {
	Manufacturer string
	Model        string
	Firmware     string
	Serial       string
	HardwareID   string
}

// DecodeDeviceInfo 取设备信息。★ 空串就是「这台没说」，不填一个像样的值。
func DecodeDeviceInfo(root *Node) DeviceInfo {
	return DeviceInfo{
		Manufacturer: root.Get("Manufacturer"),
		Model:        root.Get("Model"),
		Firmware:     root.Get("FirmwareVersion"),
		Serial:       root.Get("SerialNumber"),
		HardwareID:   root.Get("HardwareId"),
	}
}

// Time 是设备自己说它几点，以及它靠什么对时。
type Time struct {
	UTC         string // 拼成 RFC3339 的 UTC 时刻；解不出来留空
	Local       string
	DateTime    string // 设备给的类型：NTP / Manual / SetManually…
	Timezone    string
	Dst         string // true / false / 空 = 没说
	NTPAddrs    []string
	NTPFromDHCP bool
}

// DecodeTime 取系统时间。
//
// ★ ONVIF 把时刻拆成 Date + Time 两段，有的挂在 UTC 有的挂在 LocalTime，
//
//	也有的固件直接给一个完整 ISO 串 —— 三种写法都要认，
//	只认一种的结果是「设备回了时间，我们报它没说」。
func DecodeTime(root *Node) Time {
	var t Time
	sum := root.Find("SystemDateTime")
	if sum == nil {
		sum = root
	}
	t.DateTime = sum.Get("DateTimeType")
	t.Timezone = sum.Get("TZ")
	if t.Timezone == "" {
		t.Timezone = sum.Get("Timezone")
	}
	t.Dst = sum.Get("DaylightSavings")
	if n := sum.Find("Ntp"); n != nil {
		t.NTPFromDHCP = strings.EqualFold(n.Get("FromDHCP"), "true")
		var addrs []string
		for _, a := range n.All("NtpAddress") {
			if a.Text != "" {
				addrs = append(addrs, a.Text)
			}
		}
		t.NTPAddrs = addrs
	}
	t.UTC = isoOf(sum.Find("UTC"))
	t.Local = isoOf(sum.Find("LocalTime"))
	return t
}

// isoOf 把一个时刻节点拼成 RFC3339。拿不准就不拿：解不出就留空，不编一个时刻。
func isoOf(n *Node) string {
	if n == nil {
		return ""
	}
	// 写法三：整串给好了
	if s := n.Text; strings.Contains(s, "T") {
		if _, err := time.Parse(time.RFC3339, s); err == nil {
			return s
		}
	}
	d := n.Get("Date")
	if d == "" {
		return ""
	}
	clock := ""
	// 时刻有三种挂法：<Time>03:04:05</Time>、<Time><Hour>..</Hour>..</Time>，
	// 还有规范里 <Time><Date>…</Date><Time>…</Time></Time> 这种套娃。
	// 套娃时外层 <Time> 是空的，只认第一个找到的就读成零点 ——
	// 设备明明回了时间，我们报「它说是 00:00」，这一格错得比留白更坏。
	for _, t := range n.All("Time") {
		if h := t.Get("Hour"); h != "" {
			clock = h + ":" + def(t.Get("Minute"), "00") + ":" + def(t.Get("Second"), "00")
			break
		}
		if c := clockText(t.Text); c != "" {
			clock = c
			break
		}
	}
	if clock == "" {
		clock = "00:00:00"
	}
	out := d + "T" + clock + "Z"
	if _, err := time.Parse(time.RFC3339, out); err != nil {
		return ""
	}
	return out
}

// clockText 把「hh:mm:ss」这类文本规成秒；不是这个形状就返回空。
func clockText(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, ":") {
		return ""
	}
	f := strings.Split(s, ":")
	if len(f) == 2 {
		f = append(f, "00")
	}
	if len(f) != 3 {
		return ""
	}
	for _, x := range f {
		if x == "" || len(x) > 2 {
			return ""
		}
		for _, r := range x {
			if r < '0' || r > '9' {
				return ""
			}
		}
	}
	return strings.Join(f, ":")
}

func def(s, when string) string {
	if s == "" {
		return when
	}
	return s
}

// LocalOnly 说这台只报了本地时间、没给出可当 UTC 用的时刻。
// ★ 这种时刻不能拿去算偏移：时区一差就是几小时，「它时间不对」会被我们算成假的。
func (t Time) LocalOnly() bool { return t.UTC == "" && t.Local != "" }

// MediaXAddr 从 GetCapabilities 的应答里取媒体服务挂在哪。没给就返回空串。
func MediaXAddr(root *Node) string {
	for _, s := range DecodeServices(root) {
		if s.Name == "Media" {
			return s.XAddr
		}
	}
	return ""
}

// Service 是一个服务挂在哪。
type Service struct {
	Name  string
	XAddr string
}

// DecodeServices 取服务地址表。媒体服务常在另一个端口上，
// 所以拿到 XAddr 才能问 profile —— 照设备自己的说法去问，不猜。
func DecodeServices(root *Node) []Service {
	var out []Service
	seen := map[string]bool{}
	for _, n := range root.All("XAddr") {
		if n.Text == "" {
			continue
		}
		name := ""
		for _, p := range []string{"Media", "Device", "Events", "Imaging", "PTZ", "Analytics", "Recipient"} {
			if hasAncestorName(root, n, p) {
				name = p
				break
			}
		}
		key := name + " " + n.Text
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Service{Name: name, XAddr: n.Text})
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// hasAncestorName 看这个节点是不是挂在某个名字的元素底下。
//
// ★ 不能写成「整棵树里有没有这个名」：GetCapabilities 一次报了设备与媒体两个服务地址，
//
//	只要树里出现过 Media，两条就都被认成媒体 —— 于是去敲错的那个端口，
//	再把「媒体服务没起来」报出去，而它其实活得好好的。得沿 root 到 target 那一条链看。
func hasAncestorName(root, target *Node, name string) bool {
	var chain []*Node
	if root == nil || target == nil || !pathTo(root, target, &chain) {
		return false
	}
	for _, n := range chain[:len(chain)-1] { // 最后一个是 target 自己，它不是自己的父
		if n.Name == name {
			return true
		}
	}
	return false
}

// pathTo 记一条从 n 走到 target 的链；走不通就不留。
func pathTo(n, target *Node, chain *[]*Node) bool {
	if n == nil {
		return false
	}
	*chain = append(*chain, n)
	if n == target {
		return true
	}
	for _, k := range n.Kids {
		if pathTo(k, target, chain) {
			return true
		}
	}
	*chain = (*chain)[:len(*chain)-1]
	return false
}

// Profile 是一路码流的自报。
type Profile struct {
	Token     string
	Name      string
	Encoding  string
	Width     string
	Height    string
	Framerate string
	Bitrate   string
	Audio     string
	StreamURI string // GetStreamUri 才有；单独问
}

// DecodeProfiles 取码流列表。★ 这里问不到取流 URI：ONVIF 把 URI 放在
// GetStreamUri 里单独一答 —— 所以拿到 token 还要再问一次，
// 不能拿 profile 的名字冒充地址。
func DecodeProfiles(root *Node) []Profile {
	var out []Profile
	for _, n := range root.All("Profiles") {
		p := Profile{Token: n.Attr["token"]}
		if p.Token == "" {
			p.Token = n.Attr["Token"]
		}
		if enc := n.Find("VideoEncoderConfiguration"); enc != nil {
			p.Encoding = enc.Get("Encoding")
			if r := enc.Find("Resolution"); r != nil {
				p.Width, p.Height = r.Get("Width"), r.Get("Height")
			}
			if rc := enc.Find("RateControl"); rc != nil {
				p.Bitrate = rc.Get("BitrateLimit")
			}
		}
		if src := n.Find("VideoSourceConfiguration"); src != nil {
			p.Framerate = src.Get("Framerate")
		}
		if au := n.Find("AudioEncoderConfiguration"); au != nil {
			p.Audio = au.Get("Encoding")
		}
		// Profile 自己那个 Name 挂在直接子层；里面的配置块也各自有 Name，
		// 所以只取第一个「就挂在 Profiles 下」的。
		for _, k := range n.Kids {
			if k.Name == "Name" {
				p.Name = k.Text
				break
			}
		}
		out = append(out, p)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

// DecodeStreamURI 取一次 GetStreamUri 的应答。
func DecodeStreamURI(root *Node) string {
	m := root.Find("MediaUri")
	if m == nil {
		return root.Get("Uri")
	}
	return m.Get("Uri")
}
