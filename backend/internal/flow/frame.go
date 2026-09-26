// Package flow 把「一堆包」拆成「一张能看的表」：链路口 → IP → TCP/UDP → 应用层会话。
//
// 为什么要单独一层：抓包文件里从来没有人问「这一条流怎么样」，问的都是
// 「这台相机为什么起不来」——那一句的答案在流这一层（DESCRIBE 回了 460、
// SETUP 的 Transport 里那个端口没人接、REGISTER 一直 401）。所以这一层的产出
// 必须是**带判定的人话**，不是把包换个排版再列一遍。
//
// ★ 拆不下去的包一律留下一条带原因的账，不许静悄悄丢掉。
// 静悄悄丢的下游症状是「表上没有这条流」，而现场据此得出的结论是「它没发过包」——
// 这两件事差得远，后者会把人送去查错的那台机器。
package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// 链路类型照 capture 那一份表（同一个数在两头必须是一个意思）。
const (
	LinkNull      uint16 = 0   // BSD 环回（macOS 的 lo0）
	LinkEN10MB    uint16 = 1   // 以太网
	LinkRaw       uint16 = 12  // 裸 IP
	LinkIEEE80211 uint16 = 23  // 802.11（不拆，见 ErrLink）
	LinkLinuxSLL  uint16 = 113 // Linux cooked v1（-i any）
	LinkRadioTap  uint16 = 127
	LinkPFSync    uint16 = 117
	LinkLinuxSLL2 uint16 = 276
	LinkIPv4      uint16 = 228
	LinkIPv6      uint16 = 229
)

// ErrLink 是「这一档不拆这种链路口」。
//
// 802.11 与 Radiotap 单独拒而不硬拆：那里头有 A-MSDU 嵌套、有 WEP/WPA 加密、
// 还有三个地址字段（客户端 ↔ AP ↔ 网关）。按以太网那两格地址拆，
// 得到的是「三个 MAC 里挑两个」的假数 —— 错得比不拆更坏。
var ErrLink = errors.New("flow: 这一档不拆这种链路口")

// 链路口上那几种我们真要看的类型编号。
const (
	etypeIPv4 = 0x0800
	etypeARP  = 0x0806
	etypeIPv6 = 0x86DD
)

// IP 协议号。
const (
	protoHopByHop = 0
	protoICMP     = 1
	protoTCP      = 6
	protoUDP      = 17
	protoRoute    = 43
	protoFrag     = 44
	protoGRE      = 47
	protoESP      = 50
	protoAH       = 51
	protoICMPv6   = 58
	protoNoNext   = 59
	protoDstOpts  = 60
	protoMobility = 135
)

// Frame 是一个包拆到底之后的样子。
type Frame struct {
	SrcMAC, DstMAC net.HardwareAddr // 没有二层的那几档就是 nil
	VLANs          []int            // 由外向内；QinQ 就两格
	LinkName       string
	EtherType      uint16 // 剥完标签之后那个类型编号；没有二层就是 IP 自己
	IPVersion      byte   // 4 / 6， 没到 IP 层为 0

	SrcIP, DstIP net.IP
	IPProto      byte // IPv4 的 protocol / IPv6 走到底之后那个头
	Src, Dst     string
	SrcPort      uint16 // 非首片没有端口，就是 0（配合 Frag）
	DstPort      uint16
	Transport    string // "tcp" / "udp" / "icmp" / "icmpv6" / "arp" / ""

	TCP  *TCP
	UDP  *UDP
	ICMP *ICMP
	ARP  *ARP

	// Payload 是应用层正文。★ 非首片不给（那一格里压根没有 L4 正文），
	// 被截断的包给截到的那一份，同时把 Truncated 标上。
	Payload []byte

	Frag       bool // 这一包是 IP 分片（含首片）
	FirstFrag  bool // 首片，或压根没分
	FragOffset int  // 字节偏移（已经把那个 8 字节的单位换算掉）
	MoreFrags  bool
	FragID     uint32 // IPv4 的标识那一格（v6 分片头里也是同名的一格）
	TTL        int
	TypeOfSvc  byte
	IPID       uint16 // IPv4 的标识那一格
	WireLen    int    // 线上那份声明的总长
	Truncated  bool   // 带回来的比声明的短（留长剪过 / 文件本身截过）

	Unrecognized bool // 拆到底了但认不出里面是什么（记账，不猜）
	Note         string
}

// TCP 是 TCP 头里看得懂的那几格。
type TCP struct {
	SrcPort   uint16
	DstPort   uint16
	Seq       uint32
	Ack       uint32
	Flags     TCPFlags
	Window    uint16
	Options   []byte // 原始选项串（含 0xE1 这类厂商项），MSS/SACK 由上面按号取
	HeaderLen int
}

// TCPFlags 照线上的 bit 位存，不翻成字符串：判定要按位问（「有 SYN 没 ACK」）。
type TCPFlags uint8

const (
	FlagFIN TCPFlags = 1 << 0
	FlagSYN TCPFlags = 1 << 1
	FlagRST TCPFlags = 1 << 2
	FlagPSH TCPFlags = 1 << 3
	FlagACK TCPFlags = 1 << 4
	FlagECE TCPFlags = 1 << 5
	FlagCWR TCPFlags = 1 << 6
)

func (f TCPFlags) String() string {
	var s []string
	for _, c := range []struct {
		bit  TCPFlags
		name string
	}{{FlagCWR, "CWR"}, {FlagECE, "ECE"}, {FlagACK, "ACK"}, {FlagPSH, "PSH"},
		{FlagRST, "RST"}, {FlagSYN, "SYN"}, {FlagFIN, "FIN"}} {
		if f&c.bit != 0 {
			s = append(s, c.name)
		}
	}
	return strings.Join(s, ",")
}

func (t *TCP) Get(flag TCPFlags) bool { return t != nil && t.Flags&flag != 0 }

// Option 按号取 TCP 选项里那一段（ kind 1/0 这种单字节的取不到， 也不该取）。
//
// 选项串是按 4 字节对齐的， 结尾可能是 NOP/Padding：走到 kind==0 就该停，
// 不然后面那份填充会被当成一个「长度为 0 的选项」一直往前啃。
func (t *TCP) Option(kind byte) []byte {
	if t == nil {
		return nil
	}
	for i := 0; i+1 < len(t.Options); {
		k := t.Options[i]
		if k == 0 {
			return nil
		}
		if k == 1 {
			i++
			continue
		}
		l := int(t.Options[i+1])
		if l < 2 || i+l > len(t.Options) {
			return nil // 长度撒谎： 后面不猜
		}
		if k == kind {
			return t.Options[i+2 : i+l]
		}
		i += l
	}
	return nil
}

// MSS 回 TCP 选项里那格声明的段大小（ 没有该选项回 0）。
// 这一格是「改小 MTU 就能通的相机」案发现场：中间设备偷偷 clamp 过， 表上就能看出来。
func (t *TCP) MSS() int {
	b := t.Option(2)
	if len(b) != 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

// WindowScale 回窗口缩放因子（ 左右移的位数） 与「有没有带这个选项」。
func (t *TCP) WindowScale() (int, bool) {
	b := t.Option(3)
	if len(b) != 1 {
		return 0, false
	}
	return int(b[0]), true
}

// UDP 只留长度那一格：它和「实际带回来多少」可以不相等，而那是不一致的证据。
type UDP struct {
	Len uint16 // 线上写的那一份（含 8 字节头）；0 = 发送方没填
}

// ICMP 是 ICMP/ICMPv6。id/seq 只有回声用得上，但它是「没有端口的日子」里
// 唯一能把两条 ping 分开的东西。
type ICMP struct {
	Type   byte
	Code   byte
	ID     uint16
	Seq    uint16
	Inside *Frame // 不可达/超时这类回包里嵌着的那一条原始流；可能为 nil
}

// 回声那一对编号在两头不是一套（v4 是 8/0，v6 是 128/129）——
// 同一句话两套号，写在调用方迟早出错，所以留在这儿。
func (i *ICMP) IsEchoReply(v6 bool) bool {
	if i == nil {
		return false
	}
	if v6 {
		return i.Type == 129
	}
	return i.Type == 0
}

func (i *ICMP) IsEchoRequest(v6 bool) bool {
	if i == nil {
		return false
	}
	if v6 {
		return i.Type == 128
	}
	return i.Type == 8
}

// ARP 单列一张：它没有 IP 层，而现场问的「谁在 ARP 谁」「这台地址被谁占了」全在这儿。
type ARP struct {
	Op         uint16
	SenderMAC  net.HardwareAddr
	SenderIP   net.IP
	TargetMAC  net.HardwareAddr
	TargetIP   net.IP
	Gratuitous bool // 请求里源==目标：白送的一条「这台地址我占了」

	// ★ 「同一个地址两个 MAC」（地址冲突）不在这一格：那是两包之间的事，
	// 拿单包判必错 —— 一条正常应答的目标 MAC 就是请求方的 MAC， 与源 MAC 天然不同。
	// 这一条留在 Aggregator 里按历史判。
}

func (a *ARP) String() string {
	if a == nil {
		return ""
	}
	kind := fmt.Sprintf("ARP op %d", a.Op)
	switch {
	case a.Gratuitous:
		kind = "免费 ARP（谁占了这台地址）"
	case a.Op == 1:
		kind = "ARP 请求"
	case a.Op == 2:
		kind = "ARP 应答"
	}
	return fmt.Sprintf("%s：%s（%s）说 %s 是 %s 的", kind, a.SenderIP, a.SenderMAC, a.TargetIP, a.TargetMAC)
}

// Decode 按链路口把一份包拆到底。
//
// 出错时返回的 Frame 不一定空：能拆到哪儿就填到哪儿，错在 err 里 ——
// 界面上要能说出「拆到 IPv6 扩展头就走不动了」，而不是只说「拆不开」。
func Decode(linkType uint16, data []byte) (Frame, error) {
	f := Frame{}
	var (
		rest []byte
		typ  uint16
		err  error
	)
	switch linkType {
	case LinkEN10MB:
		rest, typ, err = decodeEthernet(data, &f)
	case LinkNull:
		rest, typ, err = decodeNull(data, &f)
	case LinkLinuxSLL:
		rest, typ, err = decodeSLL(data, &f)
	case LinkLinuxSLL2:
		rest, typ, err = decodeSLL2(data, &f)
	case LinkIPv4:
		f.LinkName, rest, typ = "裸 IPv4", data, etypeIPv4
	case LinkIPv6:
		f.LinkName, rest, typ = "裸 IPv6", data, etypeIPv6
	case LinkRaw:
		// DLT_RAW 只说「前面没有链路口」，不说 4 还是 6：按版本号那半字节判。
		if len(data) == 0 {
			return f, errors.New("flow: 裸 IP 这一包是空的")
		}
		f.LinkName = "裸 IP"
		switch data[0] >> 4 {
		case 4:
			typ = etypeIPv4
		case 6:
			typ = etypeIPv6
		default:
			return f, fmt.Errorf("flow: 裸 IP 里版本号是 %d， 既不 4 也不 6", data[0]>>4)
		}
		rest = data
	case LinkIEEE80211, LinkRadioTap:
		return f, fmt.Errorf("%w：802.11 帧（三个地址字段， 而且可能加密）", ErrLink)
	case LinkPFSync:
		return f, fmt.Errorf("%w：pflog（它没有源目这一说）", ErrLink)
	default:
		return f, fmt.Errorf("%w：编号 %d", ErrLink, linkType)
	}
	if err != nil {
		return f, err
	}
	f.EtherType = typ
	switch typ {
	case etypeARP:
		err = decodeARPFrame(rest, &f)
	case etypeIPv4, etypeIPv6:
		_, err = decodeIP(rest, &f)
	default:
		f.Unrecognized = true
		f.Note = fmt.Sprintf("链路口类型 %s 不拆（%d 字节没动）", ethTypeName(typ), len(rest))
	}
	return f, err
}

func ethTypeName(typ uint16) string {
	switch typ {
	case etypeIPv4:
		return "IPv4"
	case etypeIPv6:
		return "IPv6"
	case etypeARP:
		return "ARP"
	case 0x88CC:
		return "LLDP"
	case 0x8863, 0x8864:
		return "PPPoE"
	case 0x888E:
		return "802.1X"
	case 0x88F7:
		return "PTP"
	}
	return fmt.Sprintf("0x%04x", typ)
}

// decodeEthernet 拆以太网头，顺带把 VLAN 一层层剥掉；回正文与链路口类型编号。
func decodeEthernet(b []byte, f *Frame) ([]byte, uint16, error) {
	f.LinkName = "以太网"
	if len(b) < 14 {
		return nil, 0, fmt.Errorf("flow: 以太网头要 14 字节， 这一包只有 %d", len(b))
	}
	f.DstMAC = append(net.HardwareAddr(nil), b[0:6]...)
	f.SrcMAC = append(net.HardwareAddr(nil), b[6:12]...)
	typ := binary.BigEndian.Uint16(b[12:14])
	rest := b[14:]
	// ★ 上限两层：QinQ 就是外层一个加内层一个。不给上限，
	// 一份把标签类型一路自填到底的脏包能把这里转成死循环。
	for i := 0; i < 2 && (typ == 0x8100 || typ == 0x88A8 || typ == 0x9100); i++ {
		if len(rest) < 4 {
			return nil, 0, fmt.Errorf("flow: VLAN 标签断在半路（还剩 %d 字节）", len(rest))
		}
		f.VLANs = append(f.VLANs, int(binary.BigEndian.Uint16(rest[0:2])&0x0fff))
		typ = binary.BigEndian.Uint16(rest[2:4])
		rest = rest[4:]
	}
	return rest, typ, nil
}

// AF 那一族编号在 BSD 上各不一样；这几个是从这台机器的 <sys/socket.h> 量的。
const (
	afInet        = 2
	afInet6Darwin = 30
	afInet6Free   = 28
	afInet6Open   = 24
)

func decodeNull(b []byte, f *Frame) ([]byte, uint16, error) {
	f.LinkName = "BSD 环回"
	if len(b) < 4 {
		return nil, 0, fmt.Errorf("flow: 环回头要 4 字节， 这一包只有 %d", len(b))
	}
	// 地址族那格是**本机字节序**的 int（按大端读，IPv4 就成了 0x02000000 一类认不出的数）。
	switch fam := binary.NativeEndian.Uint32(b[0:4]); fam {
	case afInet:
		return b[4:], etypeIPv4, nil
	case afInet6Darwin, afInet6Free, afInet6Open:
		return b[4:], etypeIPv6, nil
	default:
		return nil, 0, fmt.Errorf("flow: 环回地址族 %d 认不出", fam)
	}
}

func decodeSLL(b []byte, f *Frame) ([]byte, uint16, error) {
	f.LinkName = "Linux cooked v1"
	if len(b) < 16 {
		return nil, 0, fmt.Errorf("flow: Linux cooked v1 头要 16 字节， 这一包只有 %d", len(b))
	}
	// 那里头的「地址」只是发送方，且长度可变；-i any 根本没有「从哪块口进」这一说，
	// 所以这一档不把 cooked 的地址当成源 MAC —— 填了就是造出来的。
	return b[16:], binary.BigEndian.Uint16(b[14:16]), nil
}

func decodeSLL2(b []byte, f *Frame) ([]byte, uint16, error) {
	f.LinkName = "Linux cooked v2"
	if len(b) < 20 {
		return nil, 0, fmt.Errorf("flow: Linux cooked v2 头要 20 字节， 这一包只有 %d", len(b))
	}
	return b[20:], binary.BigEndian.Uint16(b[2:4]), nil
}

func decodeARPFrame(b []byte, f *Frame) error {
	a, rest, err := parseARP(b)
	if err != nil {
		return err
	}
	f.ARP = a
	f.Transport = "arp"
	f.SrcIP, f.DstIP = a.SenderIP, a.TargetIP
	f.Src, f.Dst = a.SenderIP.String(), a.TargetIP.String()
	f.SrcMAC, f.DstMAC = a.SenderMAC, a.TargetMAC
	f.Payload = rest
	return nil
}

func parseARP(b []byte) (*ARP, []byte, error) {
	if len(b) < 28 {
		return nil, nil, fmt.Errorf("flow: ARP 头要 28 字节， 这一包只有 %d", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != 1 || binary.BigEndian.Uint16(b[2:4]) != etypeIPv4 {
		return nil, nil, fmt.Errorf("flow: 只拆「以太网 ＋ IPv4」的 ARP（硬件类型 %d， 协议类型 %#x）",
			binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]))
	}
	if b[4] != 6 || b[5] != 4 {
		return nil, nil, fmt.Errorf("flow: 只拆「6 字节 MAC ＋ 4 字节 IPv4」的 ARP， 量到 %d/%d", b[4], b[5])
	}
	a := &ARP{
		Op:        binary.BigEndian.Uint16(b[6:8]),
		SenderMAC: append(net.HardwareAddr(nil), b[8:14]...),
		SenderIP:  append(net.IP(nil), b[14:18]...),
		TargetMAC: append(net.HardwareAddr(nil), b[18:24]...),
		TargetIP:  append(net.IP(nil), b[24:28]...),
	}
	a.Gratuitous = a.Op == 1 && a.SenderIP.Equal(a.TargetIP)
	return a, b[28:], nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// decodeIP 拆网络层加传输层，回 L4 正文（非首片回 nil）。
func decodeIP(b []byte, f *Frame) ([]byte, error) {
	body, err := decodeNetwork(b, f)
	if err != nil {
		return nil, err
	}
	// ★ 网络层回 nil 是「这一层已经说完了」：加密的、非首片的、只到地址的。
	// 再往下走一层会把已经写下的那句 Note 盖成「协议号不拆」， 现场就看不懂了。
	if body == nil {
		return nil, nil
	}
	return body, decodeTransport(body, f)
}

// decodeNetwork 拆 IPv4/IPv6，回 L4 头开始的正文。
func decodeNetwork(b []byte, f *Frame) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("flow: 网络层是空的")
	}
	switch b[0] >> 4 {
	case 4:
		return decodeIPv4(b, f)
	case 6:
		return decodeIPv6(b, f)
	}
	return nil, fmt.Errorf("flow: 网络层版本号是 %d（既不 4 也不 6）， 前 %d 字节 %# x", b[0]>>4, len(first(b, 8)), first(b, 8))
}

func decodeIPv4(b []byte, f *Frame) ([]byte, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("flow: IPv4 头最少 20 字节， 这一包只有 %d", len(b))
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 {
		return nil, fmt.Errorf("flow: IPv4 头长声明 %d 字节， 少于 20", ihl)
	}
	if len(b) < ihl {
		return nil, fmt.Errorf("flow: IPv4 头长声明 %d 字节， 而这一包只有 %d", ihl, len(b))
	}
	f.TypeOfSvc = b[1]
	f.TTL = int(b[8])
	f.IPProto = b[9]
	f.IPVersion = 4
	f.IPID = binary.BigEndian.Uint16(b[4:6])
	f.FragID = uint32(f.IPID)
	flags := binary.BigEndian.Uint16(b[6:8])
	f.MoreFrags = flags&0x2000 != 0
	f.FragOffset = int(flags&0x1fff) * 8
	f.Frag = f.MoreFrags || f.FragOffset > 0
	f.FirstFrag = f.FragOffset == 0
	f.SrcIP = append(net.IP(nil), b[12:16]...)
	f.DstIP = append(net.IP(nil), b[16:20]...)
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl {
		return nil, fmt.Errorf("flow: IPv4 总长 %d 比头长 %d 还小", total, ihl)
	}
	f.WireLen = total
	// ★ 线上那一格不许拿去做切片：它可能比带回来的长（截过），也可能脏。
	// 按「这一份实际有什么」走，声明得多了就记一句被截过。
	want, avail := total-ihl, len(b)-ihl
	body := b[ihl:]
	if want < avail {
		body = body[:want] // 文件里多出来的那一份不是正文（填充/别人写的脏数）
	}
	if want > avail {
		f.Truncated = true
	}
	if f.Frag && !f.FirstFrag {
		f.Transport = transportName(f.IPProto)
		f.Src, f.Dst = f.SrcIP.String(), f.DstIP.String()
		f.Note = fmt.Sprintf("IP 分片的后续片段（偏移 %d， 端口在这一片里没有）", f.FragOffset)
		return nil, nil
	}
	return body, nil
}

func transportName(proto byte) string {
	switch proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	case protoICMPv6:
		return "icmpv6"
	}
	return ""
}

func decodeIPv6(b []byte, f *Frame) ([]byte, error) {
	if len(b) < 40 {
		return nil, fmt.Errorf("flow: IPv6 头固定 40 字节， 这一包只有 %d", len(b))
	}
	payload := int(binary.BigEndian.Uint16(b[4:6]))
	f.IPProto = b[6]
	f.IPVersion = 6
	f.TTL = int(b[7]) // 这一格线上叫 Hop Limit， 表上跟 v4 说同一句话
	f.SrcIP = append(net.IP(nil), b[8:24]...)
	f.DstIP = append(net.IP(nil), b[24:40]...)
	body := b[40:]
	if payload < len(body) {
		body = body[:payload]
	}
	if payload > len(body) {
		f.Truncated = true
	}
	f.WireLen = 40 + payload
	proto := f.IPProto
	// ★ 走的次数必须有上限：一份把「下一个头」自指的脏包能在这里转到机器卡住。
	for hop := 0; ; hop++ {
		if hop > 7 {
			return nil, errors.New("flow: IPv6 扩展头套了 8 层以上， 停在这里")
		}
		switch proto {
		case protoHopByHop, protoRoute, protoDstOpts, protoMobility:
			if len(body) < 2 {
				return nil, fmt.Errorf("flow: IPv6 扩展头断在半路（还剩 %d 字节）", len(body))
			}
			n := (int(body[1]) + 1) * 8
			if len(body) < n {
				return nil, fmt.Errorf("flow: IPv6 扩展头声明 %d 字节， 只剩 %d", n, len(body))
			}
			proto, body = body[0], body[n:]
		case protoAH:
			if len(body) < 2 {
				return nil, errors.New("flow: AH 头断在半路")
			}
			n := (int(body[1]) + 2) * 4
			if len(body) < n {
				return nil, fmt.Errorf("flow: AH 头声明 %d 字节， 只剩 %d", n, len(body))
			}
			proto, body = body[0], body[n:]
		case protoESP:
			// 加密的：没有密钥就到此为止。把密文当正文往下拆是最坏的一种错。
			f.IPProto = proto
			f.Note = "ESP（加密）—— 这一档不拆内容"
			f.Src, f.Dst = f.SrcIP.String(), f.DstIP.String()
			return nil, nil
		case protoFrag:
			if len(body) < 8 {
				return nil, fmt.Errorf("flow: IPv6 分片头要 8 字节， 只剩 %d", len(body))
			}
			next := body[0]
			// 那一个 16 位字（第 2~3 字节）：偏移 13 位（单位 8 字节）＋ 保留 2 位 ＋ M 1 位。
			// ★ 单位是 8 字节：不乘回去， 表上的偏移差 8 倍， 分片重组对不上首片。
			word := uint32(binary.BigEndian.Uint16(body[2:4]))
			f.FragOffset = int(word>>3) * 8
			f.MoreFrags = word&1 != 0
			f.Frag = f.MoreFrags || f.FragOffset > 0
			f.FirstFrag = f.FragOffset == 0
			f.FragID = binary.BigEndian.Uint32(body[4:8])
			if resv := (word >> 1) & 0x3; resv != 0 {
				f.Note = fmt.Sprintf("IPv6 分片头里那两位保留位非零（%d）", resv)
			}
			proto, body = next, body[8:]
			f.IPProto = proto
			if f.Frag && !f.FirstFrag {
				f.Transport = transportName(proto)
				f.Src, f.Dst = f.SrcIP.String(), f.DstIP.String()
				return nil, nil
			}
			return body, nil
		default:
			f.IPProto = proto
			return body, nil
		}
	}
}

// decodeTransport 拆 TCP/UDP/ICMP，填端口与正文。
func decodeTransport(b []byte, f *Frame) error {
	switch f.IPProto {
	case protoTCP:
		t, rest, err := parseTCP(b)
		if err != nil {
			return err
		}
		f.TCP, f.Transport, f.Payload = t, "tcp", rest
		f.SrcPort, f.DstPort = t.SrcPort, t.DstPort
		f.Src, f.Dst = addrPort(f.SrcIP, t.SrcPort), addrPort(f.DstIP, t.DstPort)
		return nil
	case protoUDP:
		if len(b) < 8 {
			return fmt.Errorf("flow: UDP 头要 8 字节， 这一包只有 %d", len(b))
		}
		sp, dp := binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4])
		ulen := int(binary.BigEndian.Uint16(b[4:6]))
		f.SrcPort, f.DstPort, f.Transport = sp, dp, "udp"
		f.Src, f.Dst = addrPort(f.SrcIP, sp), addrPort(f.DstIP, dp)
		f.UDP = &UDP{Len: uint16(ulen)}
		rest := b[8:]
		// ★ 长度那一格不许信：Linux 只在校验和里带它时写 0，有的栈脏。
		// 正文一律按「带回来的这一份」给，不一致只记一句 —— 别拿声明长度去切界外。
		switch {
		case ulen == 0:
			f.Note = "UDP 长度那格是 0（发送方没填， 常见于校验和卸载）"
			f.Payload = rest
		case ulen < 8:
			f.Note = fmt.Sprintf("UDP 长度 %d 比头还短", ulen)
			f.Payload = rest
		case ulen-8 < len(rest):
			f.Payload = rest[:ulen-8]
			f.Note = fmt.Sprintf("UDP 长度 %d 比带回来的短：末尾 %d 字节是填充", ulen, len(rest)-(ulen-8))
		default:
			if ulen-8 > len(rest) {
				f.Truncated = true
			}
			f.Payload = rest
		}
		return nil
	case protoICMP, protoICMPv6:
		return decodeICMP(b, f)
	case protoGRE:
		f.Unrecognized = true
		f.Note = "GRE 隧道：这一档不拆里面（拆了会把隧道两端的账算成两台机器的）"
		return nil
	case protoNoNext:
		f.Unrecognized = true
		f.Note = "IPv6 说「后面没有了」"
		return nil
	}
	f.Unrecognized = true
	f.Note = fmt.Sprintf("协议号 %d 这一档不拆", f.IPProto)
	return nil
}

func parseTCP(b []byte) (*TCP, []byte, error) {
	if len(b) < 20 {
		return nil, nil, fmt.Errorf("flow: TCP 头最少 20 字节， 这一包只有 %d", len(b))
	}
	hl := int(b[12]>>4) * 4
	if hl < 20 {
		return nil, nil, fmt.Errorf("flow: TCP 头长声明 %d 字节， 少于 20", hl)
	}
	if len(b) < hl {
		return nil, nil, fmt.Errorf("flow: TCP 头长声明 %d 字节， 而这一包只有 %d", hl, len(b))
	}
	t := &TCP{
		SrcPort:   binary.BigEndian.Uint16(b[0:2]),
		DstPort:   binary.BigEndian.Uint16(b[2:4]),
		Seq:       binary.BigEndian.Uint32(b[4:8]),
		Ack:       binary.BigEndian.Uint32(b[8:12]),
		Flags:     TCPFlags(b[13] & 0x3f),
		Window:    binary.BigEndian.Uint16(b[14:16]),
		HeaderLen: hl,
	}
	if hl > 20 {
		t.Options = b[20:hl]
	}
	return t, b[hl:], nil
}

func decodeICMP(b []byte, f *Frame) error {
	if len(b) < 4 {
		return fmt.Errorf("flow: ICMP 头最少 4 字节， 这一包只有 %d", len(b))
	}
	v6 := f.IPProto == protoICMPv6
	i := &ICMP{Type: b[0], Code: b[1]}
	if v6 {
		f.Transport = "icmpv6"
	} else {
		f.Transport = "icmp"
	}
	echoT, replyT := byte(8), byte(0)
	if v6 {
		echoT, replyT = 128, 129
	}
	switch i.Type {
	case echoT, replyT:
		if len(b) < 8 {
			return fmt.Errorf("flow: ICMP 回声要 8 字节， 这一包只有 %d", len(b))
		}
		i.ID, i.Seq = binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8])
		f.Payload = b[8:]
	default:
		// 目的不可达 / 超时 / 需要分片：里面嵌着原来那一条的头 —— 那一份才是现场要看的。
		// ★ 拆里面那一包用的是另一个 Frame， 不许把外面这一包的地址盖掉。
		inner := &Frame{}
		if _, err := decodeIP(b[4:], inner); err == nil && inner.Transport != "" {
			i.Inside = inner // 关联留给聚合那一步做， 不在这里改这一包自己的账
		}
		f.Payload = b[4:]
	}
	f.ICMP = i
	if i.ID != 0 || i.Seq != 0 {
		f.Src, f.Dst = fmt.Sprintf("%s:id%d", f.SrcIP, i.ID), fmt.Sprintf("%s:id%d", f.DstIP, i.ID)
	} else {
		f.Src, f.Dst = f.SrcIP.String(), f.DstIP.String()
	}
	return nil
}

// addrPort 把「IP:端口」写成一句人话，v6 要按 RFC 4007 那样用方括号，
// 否则地址里那些冒号会把端口挤成看不出来。
func addrPort(ip net.IP, port uint16) string {
	if ip == nil {
		return fmt.Sprintf("%d", port)
	}
	if ip.To4() != nil {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return fmt.Sprintf("[%s]:%d", ip, port)
}

func first(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}
