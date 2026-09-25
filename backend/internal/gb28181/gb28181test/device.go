package gb28181test

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 假设备的模式：每一种就是现场一种毛病。
const (
	ModeOK        = "ok"        // 规规矩矩答：OPTIONS 200 + 三类查询都应答
	ModeSilent    = "silent"    // 口开着，一个字节都不回（防火墙吃了 / 它不理这句）
	ModeNotSIP    = "not-sip"   // 同一个口上跑着别的东西（HTTP、TLS…）
	ModeNoBody    = "nobody"    // 接了查询，200 但不带正文
	ModeNoCatalog = "nocatalog" // 只自述，通道表那句不答（能力缺，不是不通）
	ModeBadXML    = "badxml"    // 答了，可 XML 是坏的（标签没闭合）
	ModeGBK       = "gbk"       // 中文名按非 UTF-8 发（现场那类老固件）
	ModeBusy      = "busy"      // 503：它在，但这一刻不肯答
	// ModeBadSIP 是「回话的确实是 SIP 那一套，可这一条报文读不成句」——
	// 现场对应 SIP 网关/ALG 改了包，或固件发的换行不对。下一步是找中间那台，不是查网络。
	ModeBadSIP = "bad-sip"
	// ModeAuth 是「这个口认 SIP，但 OPTIONS 也要先看凭据」——
	// 现场那一头是平台（或按平台配的网关），下一步是走注册，不是去查防火墙。
	ModeAuth = "auth"
)

// Channel 是假设备回的一条通道。
type Channel struct {
	DeviceID string
	Name     string
	Status   string
}

// DeviceOptions 配一台假设备。
type DeviceOptions struct {
	Mode     string
	DeviceID string
	// MessageStatus 非 0 时，这台设备对每一条 MESSAGE 查询都只回那个状态码、不给正文
	// —— 现场「同一个信令口，403 是没授权、404 是编号不存在、405 是压根不接这句」
	// 是三种不同的下一步，判定端必须分得开。
	MessageStatus int
	Info          map[string]string // DeviceInfo 应答里的那几样
	Channels      []Channel
	// AllowList 是 OPTIONS 回的能力（有的设备只列 REGISTER，不列 MESSAGE）。
	AllowList []string
	// PeerAddress 非空时，这台设备会主动往那个地址发一条 MESSAGE 查询
	// —— 用来验「本机当平台」那一路。
	PeerAddress *net.UDPAddr
}

// Device 是一台在 127.0.0.1 上收 SIP 的假设备。
type Device struct {
	conn *net.UDPConn
	opts DeviceOptions

	mu       sync.Mutex
	queries  []string // 收到的 CmdType，按顺序
	requests int
	stop     chan struct{}
	done     chan struct{}
}

// StartDevice 起一台假设备。★ 用 t.Cleanup 收口：测试里忘了关就是端口泄漏，
// 而这类泄漏在这套测试里会以「下一个测试拿到一个陌生口的回包」的形式咬人。
func StartDevice(t *testing.T, opts DeviceOptions) *Device {
	t.Helper()
	if opts.Mode == "" {
		opts.Mode = ModeOK
	}
	if opts.DeviceID == "" {
		opts.DeviceID = "34020000001110000001"
	}
	if opts.Info == nil {
		opts.Info = map[string]string{
			"DeviceName":   "测试枪机",
			"Manufacturer": "测试厂",
			"Model":        "ZX-100",
			"Firmware":     "1.0.4",
		}
	}
	if opts.Channels == nil {
		opts.Channels = []Channel{{DeviceID: "34020000001320000001", Name: "东门", Status: "ON"}}
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("起假设备失败：%v", err)
	}
	d := &Device{conn: conn, opts: opts, stop: make(chan struct{}), done: make(chan struct{})}
	go d.serve()
	t.Cleanup(d.Close)
	return d
}

func (d *Device) Port() int { return d.conn.LocalAddr().(*net.UDPAddr).Port }

func (d *Device) Addr() *net.UDPAddr { return d.conn.LocalAddr().(*net.UDPAddr) }

// Queries 是这台设备收到过的 MESSAGE 查询（按顺序），用于断言「探测端确实问了那一句」。
func (d *Device) Queries() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string{}, d.queries...)
}

// Requests 收到过多少条请求（OPTIONS + MESSAGE）。
func (d *Device) Requests() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.requests
}

func (d *Device) Close() {
	select {
	case <-d.stop:
		return
	default:
		close(d.stop)
	}
	_ = d.conn.Close()
	<-d.done
}

func (d *Device) serve() {
	defer close(d.done)
	buf := make([]byte, 65536)
	for {
		_ = d.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.stop:
				return
			default:
				continue // 只是这一轮没读到东西，接着等
			}
		}
		d.handle(buf[:n], from)
	}
}

func (d *Device) handle(raw []byte, from *net.UDPAddr) {
	m, err := parse(raw)
	if err != nil || !m.IsRequest {
		return
	}
	d.mu.Lock()
	d.requests++
	d.mu.Unlock()

	switch d.opts.Mode {
	case ModeSilent, ModeNoCatalog:
		// ModeNoCatalog 只不答通道表那一句，其它照常 —— 所以这里按内容分流。
		if d.opts.Mode == ModeSilent {
			return
		}
	case ModeNotSIP:
		_, _ = d.conn.WriteToUDP([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"), from)
		return
	case ModeBadSIP:
		// 起始行是 SIP，头那一行却没有冒号：读得下起始行，读不下去这一条。
		_, _ = d.conn.WriteToUDP([]byte("SIP/2.0 200 OK\r\nthis line was rewritten somewhere\r\n\r\n"), from)
		return
	case ModeBusy:
		d.respond(m, from, 503, "Service Unavailable", nil)
		return
	case ModeAuth:
		// 连 OPTIONS 都要先认证：这一档在现场只有一句话可说——它是收设备的那一头。
		d.respond(m, from, 401, "Unauthorized", nil,
			`WWW-Authenticate: Digest realm="3402000000", nonce="fakes nonce", qop="auth", algorithm=MD5`)
		return
	}

	switch m.Method {
	case "OPTIONS":
		allow := d.opts.AllowList
		if allow == nil {
			allow = []string{"REGISTER", "MESSAGE", "NOTIFY"}
		}
		d.respond(m, from, 200, "OK", nil, "Allow: "+strings.Join(allow, ", "))
	case "MESSAGE":
		// ★ 不用 Split(...)[1]：正文里根本没有 <CmdType> 的 MESSAGE 现场天天有
		//	（有些平台先发一条空正文的探活），那样写会把整个测试进程弄崩，
		//	报出来的错和「设备答不答这句」一点关系都没有。
		cmdType := ""
		if _, rest, found := strings.Cut(string(m.Body), "<CmdType>"); found {
			if i := strings.Index(rest, "<"); i >= 0 {
				cmdType = strings.TrimSpace(rest[:i])
			}
		}
		d.mu.Lock()
		d.queries = append(d.queries, cmdType)
		d.mu.Unlock()
		d.answerQuery(m, from, cmdType)
	case "NOTIFY":
		d.respond(m, from, 200, "OK", nil)
	default:
		d.respond(m, from, 405, "Method Not Allowed", nil)
	}
}

// answerQuery 按 CmdType 回对应的 MANSCDP 应答。
func (d *Device) answerQuery(m msg, from *net.UDPAddr, cmdType string) {
	// ★ 这一条要排在所有正文之前：只回状态码的那一档，「不给正文」是它的病，不是漏写。
	if d.opts.MessageStatus != 0 {
		d.respond(m, from, d.opts.MessageStatus, statusReason(d.opts.MessageStatus), nil)
		return
	}
	// 「接了这句、200、但一个字正文都不给」对三类查询是同一种病，
	// ★ 所以按模式统一分流，不是只挑 Catalog 来演 —— 判定端要能不管问的是哪句
	//	都把「空正文」和「正文读坏了」分清楚。
	if d.opts.Mode == ModeNoBody {
		d.respond(m, from, 200, "OK", nil)
		return
	}
	sn := leafValue(m.Body, "SN")
	switch cmdType {
	case "DeviceInfo":
		var b strings.Builder
		b.WriteString(rootOpen("Response") + "<CmdType>DeviceInfo</CmdType><SN>" + sn + "</SN><DeviceID>" + d.opts.DeviceID + "</DeviceID><Result>OK</Result>")
		_ = sn
		keys := make([]string, 0, len(d.opts.Info))
		for k := range d.opts.Info {
			keys = append(keys, k)
		}
		// 顺序稳定：同一份配置两次发出去的正文字节要一样，否则测试会随机抖。
		sortStrings(keys)
		for _, k := range keys {
			b.WriteString("<" + k + ">" + escape(d.opts.Info[k]) + "</" + k + ">")
		}
		b.WriteString(rootClose("Response"))
		d.respond(m, from, 200, "OK", []byte(b.String()), "Content-Type: Application/MANSCDP+xml")
	case "DeviceStatus":
		body := rootOpen("Response") + "<CmdType>DeviceStatus</CmdType><SN>" + sn +
			"</SN><DeviceID>" + d.opts.DeviceID + "</DeviceID><Result>OK</Result><Status>ON</Status></Response>"
		d.respond(m, from, 200, "OK", []byte(body), "Content-Type: Application/MANSCDP+xml")
	case "Catalog":
		if d.opts.Mode == ModeNoCatalog {
			return // 它接了这句，但就是不答内容
		}
		var b strings.Builder
		b.WriteString(rootOpen("Response") + "<CmdType>Catalog</CmdType><SN>" + sn + "</SN><DeviceID>" +
			d.opts.DeviceID + "</DeviceID><SumNum>" + strconv.Itoa(len(d.opts.Channels)) + "</SumNum><DeviceList>")
		for _, c := range d.opts.Channels {
			name := escape(c.Name)
			if d.opts.Mode == ModeGBK {
				name = gbkBytes(c.Name)
			}
			b.WriteString("<Item><DeviceID>" + c.DeviceID + "</DeviceID><Name>" + name +
				"</Name><Status>" + defaultString(c.Status, "ON") + "</Status><Parental>0</Parental></Item>")
		}
		b.WriteString("</DeviceList>" + rootClose("Response"))
		switch d.opts.Mode {
		case ModeBadXML:
			// 截一半：现场那种正文按 1400 切、最后一条通道只发出去半截的固件。
			half := []byte(b.String())
			d.respond(m, from, 200, "OK", half[:len(half)/2], "Content-Type: Application/MANSCDP+xml")
		default:
			d.respond(m, from, 200, "OK", []byte(b.String()), "Content-Type: Application/MANSCDP+xml")
		}
	default:
		// 认不出的 CmdType：回 200 但正文里 Result 写 ERROR（有些设备就这么处理）。
		body := rootOpen("Response") + "<CmdType>" + cmdType + "</CmdType><SN>" + sn + "</SN><DeviceID>" +
			d.opts.DeviceID + "</DeviceID><Result>ERROR</Result></Response>"
		d.respond(m, from, 200, "OK", []byte(body), "Content-Type: Application/MANSCDP+xml")
	}
}

// statusReason 给假设备回的状态码配一句行当里惯用的原因短语。
// ★ 各家写的文案不一样，判定端不许读这一栏 —— 这里只是为了报文像真的。
func statusReason(status int) string {
	switch status {
	case 401, 407:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405, 501:
		return "Method Not Allowed"
	case 480:
		return "Temporarily Unavailable"
	case 486:
		return "Busy Here"
	case 500:
		return "Internal Server Error"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Server Timeout"
	}
	return "SIP/2.0"
}

func (d *Device) respond(m msg, from *net.UDPAddr, status int, reason string, body []byte, extra ...string) {
	seq, method := cseqOf(m)
	hdrs := [][2]string{{"Via", m.header("Via")}, {"From", m.header("From")}, {"To", withTag(m.header("To"))},
		{"Call-ID", m.header("Call-ID")}, {"CSeq", strconv.FormatUint(seq, 10) + " " + method}}
	for _, e := range extra {
		k, v, _ := strings.Cut(e, ":")
		hdrs = append(hdrs, [2]string{k, strings.TrimSpace(v)})
	}
	var raw []byte
	if len(body) > 0 {
		raw = withCL(fmt.Sprintf("SIP/2.0 %d %s", status, reason), hdrs, body)
	} else {
		raw = build(fmt.Sprintf("SIP/2.0 %d %s", status, reason), hdrs, nil)
	}
	_, _ = d.conn.WriteToUDP(raw, from)
}

// withTag 照抄 To；没有 tag 就补一个（缺 tag 的响应会让设备以为没答，重发一趟）。
func withTag(to string) string {
	if strings.Contains(to, "tag=") {
		return to
	}
	return to + ";tag=" + randHex(5)
}

func rootOpen(root string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\r\n<" + root + ">"
}

func rootClose(root string) string { return "</" + root + ">" }

func leafValue(body []byte, name string) string {
	s := string(body)
	open := "<" + name + ">"
	i := strings.Index(s, open)
	if i < 0 {
		return "0"
	}
	rest := s[i+len(open):]
	if j := strings.Index(rest, "<"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func escape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// gbkBytes 把一个中文名换成「按 GBK 编码的那几个字节」。
// ★ 只用于造样本：这里按一张两字节的对照写死，不引任何编码库 ——
// 我们要验的是解析端碰到非 UTF-8 会不会崩，不是要做一个转换器。
func gbkBytes(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > 0x7f {
			b.Write([]byte{0xC4, 0xE3}) // 一段按 UTF-8 解不出来的字节
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
