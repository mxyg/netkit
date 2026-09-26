package flow

// DNS 与 mDNS 共用这一份读者（mDNS 就是 5353 上的 DNS 报文形状）。
//
// ★ 为什么在 flow 里另写一份，而不复用 internal/tools 里那一份：
// 方向反了 —— tools 是这一层的调用方，让 flow 去 import tools 会成一个环。
// 而「解析到内网地址了」「NXDOMAIN」「回包被截了」这三句是抓包表上最常看的，
// 少了 DNS 专解，这张表在「设备为什么连不上平台域名」那一案上就是瞎的。
//
// ★ 每一处读字节都带长度检查，而且名字里的压缩指针有跳数与方向限制：
// 一份把指针指回自己的脏包，能让不设限的读者在环里转到天荒地老。

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	maxDNSRecords = 64  // 一条 DNS 回包正常十几条，上百条是要拿内存换界面
	maxDNSJumps   = 8   // 压缩指针链的长度上限
	maxNameBytes  = 512 // 一个名字的上限（协议本身是 255，留一倍余量给多问题）
)

type dnsMsg struct {
	id        uint16
	response  bool
	opcode    byte
	flagAA    bool
	flagTC    bool
	rcode     byte
	questions []dnsQuestion
	answers   []dnsRecord
	nRecords  int
}

type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type dnsRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

func (q dnsQuestion) String() string { return q.Name + " " + dnsTypeName(q.Type) }
func (r dnsRecord) String() string {
	return fmt.Sprintf("%s %s ttl=%d %s", r.Name, dnsTypeName(r.Type), r.TTL, r.Data)
}

// DNS 的 rcode：只把有明确下一步查法的几句写成人话，其余照号说。
var dnsRcodeText = map[byte]string{
	0:  "没有错",
	1:  "格式不对（对方没看懂这一问）",
	2:  "服务器拒了（策略上不许给它解）",
	3:  "这个名字不存在（NXDOMAIN）：域名写错、或者压根没登记",
	4:  "服务器不支持这个类型",
	5:  "拒绝服务",
	6:  "这个名字本该存在却没有（YXDOMAIN）",
	7:  "名字不在该区里",
	8:  "记录不在（但名字在）",
	9:  "服务器状态不对",
	10: "名字冲突（推上去的那条已经有主）",
	11: "记录冲突",
	12: "没授权",
	13: "该区没这一条",
	16: "签名不对",
	17: "签名缺失",
	23: "这个键没配好",
	24: "策略不允许",
}

func describeRcode(r byte) string {
	if s, ok := dnsRcodeText[r]; ok {
		return s
	}
	return "这一档没定义"
}

// 类型名只列「解得出内容」的那些；其余按号说，不猜。
var dnsTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 8: "MD", 11: "WKS", 12: "PTR",
	13: "HINFO", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25",
	20: "ISDN", 21: "RT", 22: "NSAP", 24: "SIG", 25: "KEY", 26: "AAAA",
	27: "LOC", 29: "NXT", 30: "EID", 31: "NIMLOC", 32: "SRV", 33: "ATMA",
	34: "NAPTR", 35: "KX", 36: "CERT", 37: "A6", 38: "DNAME", 39: "OPT",
	40: "APL", 41: "DS", 42: "SSHFP", 43: "RRSIG", 44: "NSEC", 45: "DNSKEY",
	46: "DHCPv4", 47: "NXNAME", 48: "DNSSEC", 49: "DHCID", 50: "NSEC3",
	51: "NSEC3PARAM", 52: "TLSA", 55: "HIP", 59: "CDS", 60: "CDNSKEY",
	61: "OPENPGPKEY", 62: "CSYNC", 65: "HTTPS", 99: "SPF", 108: "HTTPS2",
	257: "CAA", 32769: "DLV",
}

func dnsTypeName(t uint16) string {
	if s, ok := dnsTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

// parseDNS 解一条 DNS 报文。回的是结构，句子与判定由调用方组（dns 与 mdns 两处说法不同）。
func parseDNS(b []byte) (*dnsMsg, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("flow: DNS 头要 12 字节，这一包只有 %d", len(b))
	}
	m := &dnsMsg{
		id:       binary.BigEndian.Uint16(b[0:2]),
		response: b[0]&0x80 != 0,
		opcode:   b[1] >> 3,
		flagAA:   b[1]&0x04 != 0,
		flagTC:   b[1]&0x02 != 0,
		rcode:    b[3] & 0x0f,
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	if qd <= 0 || qd > 8 {
		// 一问一答是常态；0 个问题的「DNS 报文」多半是别的协议撞上了这个形状。
		return nil, fmt.Errorf("flow: 这一段里问题数 = %d，不像是 DNS", qd)
	}
	off := 12
	for i := 0; i < qd; i++ {
		name, next, err := dnsName(b, off, false)
		if err != nil {
			return nil, err
		}
		if next+4 > len(b) {
			return nil, fmt.Errorf("flow: DNS 问题段在第 %d 字节断了", next)
		}
		q := dnsQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[next : next+2]),
			Class: binary.BigEndian.Uint16(b[next+2 : next+4]),
		}
		m.questions = append(m.questions, q)
		off = next + 4
	}
	if !m.response {
		return m, nil
	}
	for i := 0; i < an && i < maxDNSRecords; i++ {
		r, next, err := dnsRecordAt(b, off)
		if err != nil {
			// 前半截已经解出来了：把已有的交出去，别把整条丢掉 ——
			// 「回包里有 3 条 A，第 4 条坏了」在现场就是「解到一半」。
			m.nRecords = i
			return m, err
		}
		m.answers = append(m.answers, r)
		off = next
	}
	m.nRecords = len(m.answers)
	return m, nil
}

// dnsName 展开一个名字，并回「这一段名字之后第几字节」。
//
// follow=false 用于问题段：那儿出现压缩指针不合规（RFC 1035 之后才有人这么干），
// 直接报错比解出一个假名字好。
func dnsName(b []byte, off int, follow bool) (string, int, error) {
	var (
		sb    strings.Builder
		cur   = off
		end   = -1 // 「不跟指针」时名字结束在哪；跟了就取第一次跳转之后的位置
		jumps int
	)
	for {
		if cur >= len(b) {
			return "", 0, fmt.Errorf("flow: DNS 名字在第 %d 字节出了包尾", cur)
		}
		n := int(b[cur])
		switch {
		case n == 0:
			cur++
			if end < 0 {
				end = cur
			}
			if sb.Len() == 0 {
				return ".", end, nil
			}
			return sb.String(), end, nil
		case n&0xC0 == 0xC0:
			if !follow {
				return "", 0, fmt.Errorf("flow: 问题段的名字里用了压缩指针（不合规则）")
			}
			if cur+2 > len(b) {
				return "", 0, fmt.Errorf("flow: DNS 压缩指针在第 %d 字节只剩一字节", cur)
			}
			ptr := int(binary.BigEndian.Uint16(b[cur:cur+2]) & 0x3fff)
			if ptr >= cur {
				// ★ 只许往后跳：往前或原地指是造环最省事的写法，
				// 而这一层吃的正是别人递进来的文件。
				return "", 0, fmt.Errorf("flow: DNS 压缩指针指回第 %d 字节（往前或原地，是个环）", ptr)
			}
			if end < 0 {
				end = cur + 2
			}
			jumps++
			if jumps > maxDNSJumps {
				return "", 0, fmt.Errorf("flow: DNS 压缩指针跳了 %d 次还没到底（上限 %d）", jumps, maxDNSJumps)
			}
			cur = ptr
		case n > 63:
			return "", 0, fmt.Errorf("flow: DNS 标签长度 %d 超过 63（而且不是指针的形状）", n)
		default:
			cur++
			if cur+n > len(b) {
				return "", 0, fmt.Errorf("flow: DNS 标签声明 %d 字节，包尾只剩 %d", n, len(b)-cur)
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.WriteString(escapeLabel(b[cur : cur+n]))
			cur += n
			if sb.Len() > maxNameBytes {
				return "", 0, fmt.Errorf("flow: DNS 名字超过 %d 字节（脏数据）", maxNameBytes)
			}
		}
	}
}

// escapeLabel 把名字里的不可打印字节写成 \NNN。
//
// ★ 不能原样递出去：DNS 标签里放换行与 ANSI 转义是做得出来的，
// 而这张表要在终端与网页上打 —— 一条报文把界面重画了，就不是排查工具了。
func escapeLabel(label []byte) string {
	need := false
	for _, c := range label {
		if c < 0x20 || c == 0x7f || c == '\\' {
			need = true
			break
		}
	}
	if !need {
		return string(label)
	}
	var b strings.Builder
	for _, c := range label {
		if c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, "\\%03d", c)
			continue
		}
		if c == '\\' {
			b.WriteString("\\\\")
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func dnsRecordAt(b []byte, off int) (dnsRecord, int, error) {
	name, next, err := dnsName(b, off, true)
	if err != nil {
		return dnsRecord{}, 0, err
	}
	if next+10 > len(b) {
		return dnsRecord{}, 0, fmt.Errorf("flow: DNS 记录头在第 %d 字节断了", next)
	}
	r := dnsRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[next : next+2]),
		Class: binary.BigEndian.Uint16(b[next+2 : next+4]),
		TTL:   binary.BigEndian.Uint32(b[next+4 : next+8]),
	}
	rdlen := int(binary.BigEndian.Uint16(b[next+8 : next+10]))
	data := next + 10
	if data+rdlen > len(b) {
		return dnsRecord{}, 0, fmt.Errorf("flow: DNS 记录数据声明 %d 字节，只剩 %d", rdlen, len(b)-data)
	}
	r.Data = dnsRData(r.Type, b[data:data+rdlen], b, data)
	return r, data + rdlen, nil
}

// dnsRData 按类型解数据段。指回整包是为了 CNAME/NS 这类里套着名字的记录。
func dnsRData(typ uint16, rd, full []byte, base int) string {
	switch typ {
	case 1: // A
		if len(rd) != 4 {
			return fmt.Sprintf("A 数据段 %d 字节（不是 4）", len(rd))
		}
		return net.IPv4(rd[0], rd[1], rd[2], rd[3]).String()
	case 28: // AAAA
		if len(rd) != 16 {
			return fmt.Sprintf("AAAA 数据段 %d 字节（不是 16）", len(rd))
		}
		return net.IP(rd).String()
	case 2, 5, 12, 39: // NS / CNAME / PTR / DNAME
		name, _, err := dnsName(full, base, true)
		if err != nil {
			return fmt.Sprintf("%s：名字解不动（%v）", dnsTypeName(typ), err)
		}
		return dnsTypeName(typ) + " " + name
	case 15: // MX
		if len(rd) < 4 {
			return "MX 数据段太短"
		}
		pri := binary.BigEndian.Uint16(rd[0:2])
		name, _, err := dnsName(full, base+2, true)
		if err != nil {
			return fmt.Sprintf("MX 优先 %d，后面的名字解不动", pri)
		}
		return fmt.Sprintf("MX 优先 %d → %s", pri, name)
	case 16, 99: // TXT / SPF
		var parts []string
		for i := 0; i < len(rd); {
			n := int(rd[i])
			i++
			if i+n > len(rd) {
				parts = append(parts, fmt.Sprintf("（第 %d 段声明 %d 字节，超出）", i-1, n))
				break
			}
			parts = append(parts, strconv.Quote(decodeTxtBytes(rd[i:i+n])))
			i += n
		}
		return "TXT " + strings.Join(parts, " ")
	case 33: // SRV
		if len(rd) < 7 {
			return "SRV 数据段太短"
		}
		target, _, err := dnsName(full, base+7, true)
		if err != nil {
			target = "（名字解不动）"
		}
		return fmt.Sprintf("SRV 优先 %d 权重 %d 端口 %d → %s",
			binary.BigEndian.Uint16(rd[0:2]), binary.BigEndian.Uint16(rd[2:4]),
			binary.BigEndian.Uint16(rd[4:6]), target)
	case 6: // SOA
		mname, next, err := dnsName(full, base, true)
		if err != nil {
			return "SOA 名字解不动"
		}
		rname, next, err := dnsName(full, next, true)
		if err != nil {
			return "SOA 第二名字解不动"
		}
		_ = rname
		return "SOA 主 " + mname
	case 41: // OPT（EDNS）：只报 UDP 载荷上限，那一格才和「回包被截」有关
		return fmt.Sprintf("OPT/EDNS（数据段 %d 字节）", len(rd))
	}
	return fmt.Sprintf("%s：%d 字节（这一档没解）", dnsTypeName(typ), len(rd))
}

// decodeTxtBytes 把 TXT 里的字节变成能上屏的串：非 UTF-8 与不可打印的都走 \NNN。
func decodeTxtBytes(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		switch {
		case c >= 0x20 && c < 0x7f:
			s.WriteByte(c)
		case c >= 0x80 && utf8Valid(b):
			s.WriteByte(c) // 整段是合法 UTF-8：中文实例名照原样给
		default:
			fmt.Fprintf(&s, "\\%03d", c)
		}
	}
	return s.String()
}

func utf8Valid(b []byte) bool {
	for i := 0; i < len(b); {
		switch c := b[i]; {
		case c < 0x80:
			i++
		case c&0xE0 == 0xC0:
			if i+2 > len(b) || b[i+1]&0xC0 != 0x80 {
				return false
			}
			i += 2
		case c&0xF0 == 0xE0:
			if i+3 > len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 {
				return false
			}
			i += 3
		case c&0xF8 == 0xF0:
			if i+4 > len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 || b[i+3]&0xC0 != 0x80 {
				return false
			}
			i += 4
		default:
			return false
		}
	}
	return true
}

// cutDNSFrame 按 DNS-over-TCP 的两字节长度前缀切一条。
//
// ★ 这一档必须存在：TCP 上的 DNS 拿文本协议那套「找空行」去切，
// 十有八九一条也切不出来（DNS 正文里根本没有 \r\n\r\n），
// 于是「53 端口上的 TCP」这一栏永远是空的，而它正是「DNS 被截了改走 TCP」那一案的证据。
func cutDNSFrame(b []byte) (int, bool) {
	if len(b) < 2 {
		if len(b) > maxBodyBytes {
			return len(b), true
		}
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if n <= 0 || n > maxBodyBytes {
		return len(b), true // 长度那一格本身坏了：这一段作废，不把这条流堵在这
	}
	if 2+n > len(b) {
		return 0, false
	}
	return 2 + n, true
}

// looksLikeDNS 只看形状，不猜语义：过不了这一关的不会按 DNS 解。
//
// TCP 上的 DNS 多两字节长度前缀（RFC 1035 §4.2.2），认不认得出来由调用方给的方向定；
// 这里两种都放行，真正剥前缀在 decodeDNS 里，而且只在「前缀与剩下的长度正好对上」时剥。
func looksLikeDNS(b []byte) bool {
	m, err := parseDNS(dnsStripPrefix(b))
	return err == nil && m != nil && len(m.questions) > 0
}

// decodeDNS 把解好的报文组成表上那一格。
//
// mdns 走同一个读者：两者的差别在「谁在听」（5353、组播、cache-flush 位），
// 不在字节形状，所以差别只体现在这里说的那句话上。
func decodeDNS(raw []byte) (*Message, error)  { return decodeDNSish("dns", raw) }
func decodeMDNS(raw []byte) (*Message, error) { return decodeDNSish("mdns", raw) }

func decodeDNSish(proto string, raw []byte) (*Message, error) {
	b := dnsStripPrefix(raw)
	m, err := parseDNS(b)
	if m == nil {
		return nil, err
	}
	out := &Message{Proto: proto, Fields: []Field{}, Note: ""}
	if m.response {
		out.Kind = "response"
	} else {
		out.Kind = "query"
	}
	out.Seq = strconv.Itoa(int(m.id))
	out.Method = dnsTypeName(m.qtype0())
	if len(m.questions) > 0 {
		out.URI = m.questions[0].Name
		out.Fields = append(out.Fields, field("查询", m.questions[0].String()))
	}
	for _, q := range m.questions[1:] {
		out.Fields = append(out.Fields, field("还问了", q.String()))
	}
	if m.response {
		out.Fields = append(out.Fields, field("应答数", strconv.Itoa(len(m.answers))))
	}
	for i, r := range m.answers {
		if i >= maxDNSRecords {
			out.Fields = append(out.Fields, field("答案", fmt.Sprintf("还有 %d 条没列（上限 %d）", len(m.answers)-i, maxDNSRecords)))
			break
		}
		out.Fields = append(out.Fields, field("答案 "+r.Name, r.String()))
	}
	if m.flagTC {
		out.Findings = append(out.Findings, Finding{Code: "dns-truncated",
			Text: "回包被标了 TC：这一份装不下，完整答案在 TCP 那一侧（53 上的两字节长度前缀那条路）"})
	}
	if m.response {
		if m.rcode != 0 {
			out.Findings = append(out.Findings, Finding{Code: "dns-rcode-" + strconv.Itoa(int(m.rcode)),
				Text: fmt.Sprintf("域名解析回了 rcode=%d：%s（问的是 %s）", m.rcode, describeRcode(m.rcode), out.URI)})
		} else if len(m.answers) == 0 {
			out.Findings = append(out.Findings, Finding{Code: "dns-no-answer",
				Text: "解成功了但答案一条都没有（NOERROR、空应答）：这个名字没配地址记录，" +
					"不是「DNS 服务器不通」——那一档长得完全不一样"})
		}
		for _, r := range m.answers {
			if r.Type == 1 && isSiteLocal(net.ParseIP(r.Data)) {
				out.Findings = append(out.Findings, Finding{Code: "dns-answer-private",
					Text: "这个域名解到了内网地址 " + r.Data + "：设备在本地 hosts 或内网 DNS 上指了另一台，" +
						"「到公网平台」那一案里这一格能翻转结论"})
				break
			}
		}
	}
	if err != nil {
		out.Note = "后半段解不动：" + err.Error()
	}
	if proto == "mdns" && !m.response {
		// mDNS 里没有「服务器」，每个应答者都是权威：问与答在同一个组播组上。
		out.Note = firstNonEmptyStr(out.Note, "mDNS 的查询与应答都走 224.0.0.251:5353，没有「DNS 服务器」这一说")
	}
	out.Summary = dnsSummary(proto, m, out)
	out.Summary = scrubText(out.Summary)
	return out, nil
}

func dnsSummary(proto string, m *dnsMsg, out *Message) string {
	if m.response {
		s := fmt.Sprintf("%s 答 %s：%d 条", proto, out.URI, len(m.answers))
		if m.rcode != 0 {
			s += "，rcode=" + strconv.Itoa(int(m.rcode))
		}
		return s
	}
	return fmt.Sprintf("%s 问 %s", proto, out.URI)
}

// qtype0 回第一个问题的类型（界面上「问了个什么类型」那一格）。
func (m *dnsMsg) qtype0() uint16 {
	if len(m.questions) == 0 {
		return 0
	}
	return m.questions[0].Type
}

func isSiteLocal(ip net.IP) bool {
	return ip != nil && ip.IsPrivate()
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// dnsStripPrefix 剥 DNS-over-TCP 那两字节长度前缀。
//
// ★ 只在「声明的长度 == 剩下的字节数」时剥：这是唯一分得清「这是前缀」与
// 「这报文开头两字节刚好像前缀」的条件。不满足就原样交回去，让 parseDNS 按 UDP 形状读。
func dnsStripPrefix(b []byte) []byte {
	if len(b) < 14 {
		return b
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if n == len(b)-2 {
		return b[2:]
	}
	return b
}
