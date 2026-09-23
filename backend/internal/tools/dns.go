package tools

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// net.dns.query —— 直接问某一台 DNS 服务器，看它回什么。
//
// ★★ 为什么这算一个独立工具而不是 ping 的附属：现场有一大类问题是
//
//	「网络是好的，就是解析不对」，而「解析不对」又分三种，处理办法完全不同：
//	  1) 服务器压根没回        —— 出网被拦 / 服务器挂了 / 配错了
//	  2) 服务器回了 SERVFAIL   —— 服务器自己查不到（转发环、DNSSEC 校验失败）
//	  3) 回了，但答案是错的    —— 劫持 / 污染 / 这台机器配了内网 DNS 却在查公网
//	ping 与 hosts 都分不清这三层，只有「点名问一台服务器、看它的 rcode 和答案」才分得开。
//
// ★ 支持指定服务器，就是为了第 3 种：同一个域名分别问系统配的那台和 223.5.5.5，
//
//	答案不一样就抓到问题了 —— 这也是为什么结果里要把系统 DNS 一并报出来。
//
// ★ 只做查询、不改任何配置，所以是 read（[OTS-4.3]）。
var dnsQueryTool = ots.Tool{
	Name:  "net.dns.query",
	Class: ots.ClassRead,
	Summary: "向一台 DNS 服务器查询指定域名/地址，给出答案、TTL、rcode 与耗时。支持 A / AAAA / CNAME / MX / TXT / NS / SOA / PTR" +
		"（查 PTR 时直接给 IP，自动转成 arpa 名字）。server 不填就用系统配置的 DNS，并且结果里会把系统配了哪几台一并报出来。" +
		"★ 用来分清「服务器没回」「服务器说查不到」「答案不对（劫持/污染）」这三类问题 —— 处理办法完全不同。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["name"],
	  "properties": {
	    "name": {"type": "string",
	      "description": "要查的名字。查 PTR 时填 IP 地址（IPv4 或 IPv6，链路本地要带 zone）。"},
	    "type": {"type": "string", "enum": ["A","AAAA","CNAME","MX","TXT","NS","SOA","PTR"],
	      "description": "记录类型，默认 A。"},
	    "server": {"type": "string",
	      "description": "问哪台 DNS 服务器。可以不带端口（默认 53）。不填就用系统配的那台。"},
	    "timeoutMs": {"type": "integer", "minimum": 200, "maximum": 15000,
	      "description": "单次查询等多久，默认 3000。"}
	  }
	}`),
	Invoke: doDNSQuery,
}

// DNS 查询的判定码。★ 区分的就是注释里说的那三类问题。
const (
	dnsResolved    = "resolved"       // 问到了答案
	dnsNXDomain    = "nxdomain"       // 服务器明确说这个域名不存在
	dnsServFail    = "server-failure" // 服务器自己查不到（转发环、上游挂了）
	dnsRefused     = "refused"        // 服务器拒绝查询（多半是不给递归的公网解析器）
	dnsTimeout     = "timeout"        // 什么都没回 —— 「DNS 坏了」最常见的样子
	dnsUnreachable = "unreachable"    // 连服务器都连不上（路由没有 / 端口不可达）
	dnsBadResponse = "bad-response"   // 回了，但不是能解析的 DNS 报文
)

type dnsArgs struct {
	Name      string `json:"name"`
	Type      string `json:"type,omitempty"`
	Server    string `json:"server,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// dnsAnswer 一条答案，翻成人好读的形态。
type dnsAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

func doDNSQuery(ctx context.Context, raw json.RawMessage) (any, error) {
	var a dnsArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if strings.TrimSpace(a.Name) == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 name")
	}
	qtype, err := dnsMessageType(a.Type)
	if err != nil {
		return nil, err
	}
	qname := a.Name
	if strings.EqualFold(a.Type, "PTR") {
		if qname, err = reverseName(a.Name); err != nil {
			return nil, err
		}
	}

	// 问谁：显式给的优先，否则用系统配的第一台（并把系统配的几台一起报出来）
	sys, _ := netif.SystemDNSServers()
	server := a.Server
	if server == "" {
		if len(sys) == 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"这台机器上读不到系统配置的 DNS 服务器，请在参数里显式给一个 server")
		}
		server = sys[0].Addr
	}
	server = withDNSPort(server)

	timeout := 3 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout*2) // 截断时要走一次 TCP，留出两倍
	defer cancel()

	target, err := dnsServerDialAddr(server)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}

	values := map[string]any{
		"name": qname, "type": dnsMessageTypeName(qtype), "server": target,
		"systemServers": sys,
	}
	msg, id, err := buildDNSQuery(qname, qtype)
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "构造查询报文失败：%s", err)
	}

	start := time.Now()
	resp, truncatedByTCP, derr := exchangeDNS(ctx, target, msg, timeout)
	values["elapsedMs"] = time.Since(start).Milliseconds()
	if derr != nil {
		return dnsFailValues(values, derr)
	}

	hdr, answers, err := parseDNSResponse(resp, id, qname)
	if err != nil {
		if errors.Is(err, errTruncated) {
			// 回包被截断：改用 TCP 重问一次。不做的症状是「大 TXT / 多记录的域名查不全」，
			// 而调用方完全看不出来 —— 只会以为自己拿到的就是全部答案。
			resp, err = exchangeDNSTCP(ctx, target, msg, timeout)
			truncatedByTCP = true
			values["via"] = "tcp"
			if err == nil {
				hdr, answers, err = parseDNSResponse(resp, id, qname)
			}
		}
		if err != nil {
			return dnsFailValues(values, err)
		}
	}
	values["rcode"] = hdr.RCode.String()
	values["authoritative"] = hdr.Authoritative
	values["elapsedMs"] = time.Since(start).Milliseconds()
	values["answers"] = answers
	// CNAME 链单独列出来：一个域名 CNAME 到谁家，直接说明了它走没走 CDN、被没被指到别处
	var cnames []string
	for _, an := range answers {
		if an.Type == "CNAME" {
			cnames = append(cnames, an.Name+" → "+an.Value)
		}
	}
	if len(cnames) > 0 {
		values["cnameChain"] = cnames
	}

	code := dnsVerdict(hdr.RCode, len(answersOfType(answers, dnsMessageTypeName(qtype))))
	if truncatedByTCP {
		values["truncated"] = true
	}
	return ots.Verdict{Code: code, Values: values, Note: dnsNote(code, qname, target, answers)}, nil
}

// dnsFailValues 把「问不出结果」归成判定码，而不是甩一个错误。
//
// ★ [OTS-6.2]：对方没回、拒绝、连不上都是**查出来的状态**，是判定不是错误。
//
//	只有参数不对、报文构造失败才算错误。
func dnsFailValues(values map[string]any, err error) (any, error) {
	var dserr *net.DNSError
	if errors.As(err, &dserr) {
		values["detail"] = dserr.Err
		if dserr.IsTimeout {
			return ots.Verdict{Code: dnsTimeout, Values: values,
				Note: "DNS 服务器没有任何回应 —— 分不清是它挂了、端口被拦了，还是路由不通"}, nil
		}
	}
	if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
		return ots.Verdict{Code: dnsTimeout, Values: values,
			Note: "DNS 服务器没有任何回应 —— 分不清是它挂了、端口被拦了，还是路由不通"}, nil
	}
	if isUnreachable(err) {
		values["detail"] = err.Error()
		return ots.Verdict{Code: dnsUnreachable, Values: values,
			Note: "连这台 DNS 服务器都连不上 —— 先确认这台服务器在不在本网、有没有路由"}, nil
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errShortDNS) || errors.Is(err, errBadDNS) {
		values["detail"] = err.Error()
		return ots.Verdict{Code: dnsBadResponse, Values: values,
			Note: "服务器回了东西，但不是能解析的 DNS 报文 —— 这个端口后面可能不是 DNS 服务"}, nil
	}
	return nil, ots.Errf(ots.ErrInternal, "DNS 查询失败：%s", err)
}

// dnsVerdict 把 rcode + 答案条数翻成判定码。★ 纯函数，方便钉测试。
//
// ★ NOERROR 但这一类没有记录（NODATA）要单独分出来：域名存在、只是没有你要的那种记录，
//
//	和「域名不存在」「服务器查不到」是三件不同的事。
func dnsVerdict(rcode dnsmessage.RCode, n int) string {
	switch rcode {
	case dnsmessage.RCodeSuccess:
		if n == 0 {
			return dnsNoRecord
		}
		return dnsResolved
	case dnsmessage.RCodeNameError:
		return dnsNXDomain
	case dnsmessage.RCodeServerFailure:
		return dnsServFail
	case dnsmessage.RCodeRefused:
		return dnsRefused
	default:
		return dnsBadResponse
	}
}

func dnsNote(code, qname, server string, answers []dnsAnswer) string {
	switch code {
	case dnsResolved:
		var vs []string
		for _, a := range answers {
			if len(vs) >= 4 {
				vs = append(vs, "…")
				break
			}
			vs = append(vs, a.Value)
		}
		return qname + " 由 " + server + " 解析到：" + strings.Join(vs, "、")
	case dnsNoRecord:
		return qname + " 这个域名存在，但没有 " + "所查类型的记录（NODATA）"
	case dnsNXDomain:
		return "服务器明确说 " + qname + " 不存在（NXDOMAIN）"
	case dnsServFail:
		return server + " 自己查不到 " + qname + "（SERVFAIL）—— 多半是它的上游或转发出了问题"
	case dnsRefused:
		return server + " 拒绝了这个查询（REFUSED）—— 它可能不对外提供递归"
	}
	return ""
}

// ── 报文收发 ──

// buildDNSQuery 造一个查询报文。返回报文和里面用的查询 ID（回包要核对）。
//
// ★ 带 EDNS0（UDP 载荷 1232）：不带的话服务器只肯回 512 字节，
//
//	多记录的域名（比如一堆 MX/TXT）几乎必被截断，症状是「答案莫名其妙少了」。
func buildDNSQuery(qname string, qtype dnsmessage.Type) ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])

	name, err := dnsmessage.NewName(fqdn(qname))
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 0, 512)
	b := dnsmessage.NewBuilder(buf, dnsmessage.Header{
		ID: id, RecursionDesired: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, 0, err
	}
	// EDNS0：显式声明我们能收多大的 UDP 报文。不带的症状是「答案莫名其妙少了」——
	// 老式服务器按 512 字节截断，多记录的域名（一堆 A/MX/TXT）就查不全。
	if err := b.OPTResource(dnsmessage.ResourceHeader{
		Name:  rootName(),
		Class: dnsmessage.ClassINET,
		TTL:   1232, // UDP 载荷上限，写在 OPT 的 TTL 字段里（EDNS0 的格式如此）
	}, dnsmessage.OPTResource{Options: []dnsmessage.Option{}}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, 0, err
	}
	return msg, id, nil
}

var errTruncated = errors.New("回包被截断")
var errShortDNS = errors.New("回包比声明的长度短")
var errBadDNS = errors.New("不是一份 DNS 应答")

// exchangeDNS 走 UDP 问一次。回包截断时返回 errTruncated，由调用方改走 TCP。
func exchangeDNS(ctx context.Context, server string, msg []byte, timeout time.Duration) ([]byte, bool, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, false, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	resp := buf[:n]
	var hp dnsmessage.Parser
	hdr, perr := hp.Start(resp)
	if perr != nil {
		return nil, false, perr
	}
	if hdr.Truncated {
		return nil, true, errTruncated
	}
	return resp, false, nil
}

// exchangeDNSTCP 走 TCP 重问（DNS over TCP 前两个字节是报文长度）。
func exchangeDNSTCP(ctx context.Context, server string, msg []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed, uint16(len(msg)))
	copy(framed[2:], msg)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenb[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, errShortDNS
	}
	return resp, nil
}

// parseDNSResponse 解出报头与答案，并核对查询 ID 和问的名字。
//
// ★ 核对 ID 不是洁癖：DNS 是无连接的 UDP 服务，收来什么就信什么，
//
//	等于把「谁都能伪造一个应答」的门开着。对不上就当这份不算。
func parseDNSResponse(msg []byte, id uint16, qname string) (dnsmessage.Header, []dnsAnswer, error) {
	if len(msg) < 12 {
		return dnsmessage.Header{}, nil, errBadDNS
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return hdr, nil, err
	}
	if !hdr.Response || hdr.ID != id {
		// 不是我们问的那份应答（或者被人随手塞了一个），不认
		return hdr, nil, errBadDNS
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return hdr, nil, err
	}
	if len(qs) > 0 && !sameDNSName(qs[0].Name.String(), qname) {
		return hdr, nil, errBadDNS
	}
	res, err := p.AllAnswers()
	if err != nil {
		return hdr, nil, err
	}
	return hdr, formatAnswers(res), nil
}

// formatAnswers 把资源记录翻成人好读的形态。
func formatAnswers(res []dnsmessage.Resource) []dnsAnswer {
	out := make([]dnsAnswer, 0, len(res))
	for _, r := range res {
		h := r.Header
		a := dnsAnswer{Name: unFQDN(h.Name.String()), Type: dnsMessageTypeName(h.Type), TTL: h.TTL}
		switch b := r.Body.(type) {
		case *dnsmessage.AResource:
			a.Value = net.IP(b.A[:]).String()
		case *dnsmessage.AAAAResource:
			a.Value = net.IP(b.AAAA[:]).String()
		case *dnsmessage.CNAMEResource:
			a.Value = unFQDN(b.CNAME.String())
		case *dnsmessage.NSResource:
			a.Value = unFQDN(b.NS.String())
		case *dnsmessage.PTRResource:
			a.Value = unFQDN(b.PTR.String())
		case *dnsmessage.MXResource:
			a.Value = itoa(int(b.Pref)) + " " + unFQDN(b.MX.String())
		case *dnsmessage.TXTResource:
			a.Value = strings.Join(b.TXT, "")
		case *dnsmessage.SOAResource:
			a.Value = strings.Join([]string{unFQDN(b.NS.String()), unFQDN(b.MBox.String()),
				itoa(int(b.Serial)), itoa(int(b.Refresh)), itoa(int(b.Retry)),
				itoa(int(b.Expire)), itoa(int(b.MinTTL))}, " ")
		case *dnsmessage.SRVResource:
			a.Value = itoa(int(b.Priority)) + " " + itoa(int(b.Weight)) + " " +
				itoa(int(b.Port)) + " " + unFQDN(b.Target.String())
		case *dnsmessage.OPTResource:
			continue // EDNS0 的伪记录，不是答案
		case *dnsmessage.UnknownResource:
			a.Value = "<" + itoa(len(b.Data)) + " 字节，本版本不解析这个类型>"
		}
		out = append(out, a)
	}
	return out
}

func answersOfType(answers []dnsAnswer, typeName string) []dnsAnswer {
	var out []dnsAnswer
	for _, a := range answers {
		// 查 A 时中间那串 CNAME 也在答案里，但不算「A 记录条数」
		if a.Type == typeName {
			out = append(out, a)
		}
	}
	return out
}

// ── 参数与地址处理 ──

// dnsMessageType 把参数里的类型名翻成 DNS 类型；空当 A。
func dnsMessageType(s string) (dnsmessage.Type, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "A":
		return dnsmessage.TypeA, nil
	case "AAAA":
		return dnsmessage.TypeAAAA, nil
	case "CNAME":
		return dnsmessage.TypeCNAME, nil
	case "MX":
		return dnsmessage.TypeMX, nil
	case "TXT":
		return dnsmessage.TypeTXT, nil
	case "NS":
		return dnsmessage.TypeNS, nil
	case "SOA":
		return dnsmessage.TypeSOA, nil
	case "PTR":
		return dnsmessage.TypePTR, nil
	case "SRV":
		return dnsmessage.TypeSRV, nil
	}
	return 0, ots.Errf(ots.ErrInvalidArgument,
		"不认识 DNS 记录类型 %s（支持 A / AAAA / CNAME / MX / TXT / NS / SOA / PTR / SRV）", s)
}

func dnsMessageTypeName(t dnsmessage.Type) string {
	for _, c := range []struct {
		name string
		t    dnsmessage.Type
	}{{"A", dnsmessage.TypeA}, {"AAAA", dnsmessage.TypeAAAA}, {"CNAME", dnsmessage.TypeCNAME},
		{"MX", dnsmessage.TypeMX}, {"TXT", dnsmessage.TypeTXT}, {"NS", dnsmessage.TypeNS},
		{"SOA", dnsmessage.TypeSOA}, {"PTR", dnsmessage.TypePTR}, {"SRV", dnsmessage.TypeSRV}} {
		if c.t == t {
			return c.name
		}
	}
	return "TYPE" + itoa(int(t))
}

// reverseName 把 IP 翻成 PTR 要问的 arpa 名字。★ 纯函数，钉了测试。
//
// 让用户直接填 192.168.1.1 而不是背 1.1.168.192.in-addr.arpa —— 现场没人记得住反写规则，
// 而写错了不会报错，只会查到一条「没这个记录」，把人往错方向引。
func reverseName(ip string) (string, error) {
	addr, err := netaddr.Parse(ip)
	if err != nil {
		return "", ots.Errf(ots.ErrInvalidArgument, "查 PTR 要填 IP，填的是「%s」：%s", ip, err)
	}
	if addr.Is4() {
		b := addr.IP.AsSlice()
		return itoa(int(b[3])) + "." + itoa(int(b[2])) + "." +
			itoa(int(b[1])) + "." + itoa(int(b[0])) + ".in-addr.arpa", nil
	}
	// ip6.arpa：逐**半字节**反写。少反一位、多算一位，症状都是查不到还看不出哪错了。
	full := addr.IP.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		// ★ 先低位再高位：整个名字的 32 个半字节是**倒着**排的，
		// 按字节内高低顺序写的症状是「查不到还看不出哪错了」
		sb.WriteString(hexNibble(full[i] & 0x0f))
		sb.WriteByte('.')
		sb.WriteString(hexNibble(full[i] >> 4))
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

// fqdn 补成 DNS 报文里要的绝对名字（带根点）。库要这个格式，
// 但用户填的、界面显示的都是不带尾点的样子，所以两头各转一次。
func fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// rootName DNS 的根名字「.」。★ 这个库要的是带尾点的绝对形式，
// 传空 Name 会被判成"不是规范格式"，报一个看不懂的错。
func rootName() dnsmessage.Name {
	var n dnsmessage.Name
	n.Data[0] = '.'
	n.Length = 1
	return n
}

// unFQDN 把报文里的绝对名字还原成给人看的样子。
func unFQDN(s string) string { return strings.TrimSuffix(s, ".") }

// sameDNSName 比两个域名：忽略尾点与大小写（DNS 名字本来大小写不敏感）。
func sameDNSName(a, b string) bool {
	return strings.EqualFold(unFQDN(a), unFQDN(b))
}

func hexNibble(b byte) string {
	const digits = "0123456789abcdef"
	return string(digits[b&0x0f])
}

// withDNSPort 没写端口就补 53。★ 不能直接当 host:port 交给 SplitHostPort ——
// 裸 IPv6 地址没有方括号时它是解析不了的，得走 netaddr。
func withDNSPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// dnsServerDialAddr 把「服务器地址[:端口]」拼成本平台能拨的形态（v6 带方括号、
// 链路本地带 zone）。这一步拼错了不报错，只会超时 —— 和连不上分不清。
func dnsServerDialAddr(server string) (string, error) {
	addr, port, err := netaddr.SplitHostPort(server)
	if err != nil {
		return "", err
	}
	if port == 0 {
		port = 53
	}
	return addr.HostPort(port, runtime.GOOS)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isUnreachable 「连这个地址本身就失败」：没有路由、网络不可达、连接被拒。
func isUnreachable(err error) bool {
	var ie *net.OpError
	if !errors.As(err, &ie) {
		return false
	}
	s := ie.Err.Error()
	return strings.Contains(s, "unreachable") || strings.Contains(s, "no route to host") ||
		strings.Contains(s, "connection refused")
}
