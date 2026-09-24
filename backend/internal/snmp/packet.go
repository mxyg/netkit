package snmp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 版本。现场还活着的老交换机有一批只认 v1，所以两个都要能发。
const (
	Version1  = 0
	Version2c = 1
)

// VarBind 是一对「OID + 值」。
//
// ★ 值刻意停在**原始字节 + 标签**这一层：Counter64、IpAddress、Opaque 这些
//
//	各自的解法不一样，而 MIB 那一侧才知道该按哪种读。
//	提前统一成 string 的话，「一个二进制描述串」会被改得看不出原样。
type VarBind struct {
	OID string
	Tag byte
	Val []byte
}

func (v VarBind) Int() (int64, error)   { return AsInt(v.Val) }
func (v VarBind) Uint() (uint64, error) { return AsUint(v.Val) }

func (v VarBind) Str() string { return string(v.Val) }

// IntOr0 给「这一栏读不出来就当没有」的统计用：
// 一台设备不支持某个计数器时，界面要少一栏，而不是一整页报错。
func (v VarBind) IntOr0() int64 {
	n, err := AsInt(v.Val)
	if err != nil {
		return 0
	}
	return n
}

func (v VarBind) UintOr0() uint64 {
	n, err := AsUint(v.Val)
	if err != nil {
		return 0
	}
	return n
}

// IP 把 IpAddress 这一类（4 字节）读成地址；不是 4 字节时退回字符串表示，
// 因为有些实现会把 IPv6 塞进 Opaque 里回来。
func (v VarBind) IP() net.IP {
	if len(v.Val) == net.IPv4len || len(v.Val) == net.IPv6len {
		return net.IP(append([]byte(nil), v.Val...))
	}
	return nil
}

// EndOfMib 是不是 walk 收口的「没有下一条了」。
func (v VarBind) EndOfMib() bool { return v.Tag == TagEndOfMibView }

// Missing 是「这个 OID 这台设备没有」：跟走到树末尾不是一回事。
func (v VarBind) Missing() bool {
	return v.Tag == TagNoSuchObject || v.Tag == TagNoSuchInstance
}

func (v VarBind) TypeName() string {
	switch v.Tag {
	case TagInteger:
		return "整数"
	case TagOctetString:
		return "字符串"
	case TagOID:
		return "OID"
	case TagIPAddress:
		return "IP 地址"
	case TagCounter32:
		return "计数器(32)"
	case TagGauge32:
		return "瞬时值"
	case TagTimeTicks:
		return "时间(1/100 秒)"
	case TagOpaque:
		return "不透明数据"
	case TagCounter64:
		return "计数器(64)"
	case TagNoSuchObject:
		return "没有这个对象"
	case TagNoSuchInstance:
		return "这个设备没有这一栏"
	case TagEndOfMibView:
		return "走到头了"
	}
	return fmt.Sprintf("标签 0x%02x", v.Tag)
}

// Packet 是一个 SNMP 报文。同一格数字在 GET 和 GETBULK 里两个意思，
// 这是协议自己定的（RFC 3416 4.2.2 / 4.2.3），字段名按 GET 那侧叫，
// GETBULK 的用法在 NewBulk 里注释清楚。
type Packet struct {
	Version   int
	Community string
	PDU       byte
	ID        int32
	ErrStatus int
	ErrIndex  int
	VarBinds  []VarBind
}

// Marshal 拼成一个可发的报文。
func (p Packet) Marshal() ([]byte, error) {
	var vb []byte
	for _, v := range p.VarBinds {
		oid, err := appendOID(nil, v.OID)
		if err != nil {
			return nil, err
		}
		body := append(oid, valueTLV(v)...)
		vb = appendTLV(vb, TagSequence, body)
	}
	var pduBody []byte
	pduBody = appendInt(pduBody, TagInteger, int64(p.ID))
	pduBody = appendInt(pduBody, TagInteger, int64(p.ErrStatus))
	pduBody = appendInt(pduBody, TagInteger, int64(p.ErrIndex))
	pduBody = appendTLV(pduBody, TagSequence, vb)
	pdu := appendTLV(nil, p.PDU, pduBody)

	var msg []byte
	msg = appendInt(msg, TagInteger, int64(p.Version))
	msg = appendStr(msg, p.Community)
	msg = append(msg, pdu...)
	return appendTLV(nil, TagSequence, msg), nil
}

// valueTLV 把一个 VarBind 的值写成对应的标签。
//
// ★ 请求里值一律是 NULL：这是 SNMP 的写法，问「下一条是什么」时
//
//	带一个猜的值过去，个别实现会照那个值比而不是照 OID 比。
//
// Val 一律按**已经编好的内容**处理：OID 值也一样（内容是 base-128 那串，
// 不是点分字符串），不然「值恰好是一个 OID」的栏（sysServices 之外还有
// ifValueType 那些）会被编成变量的名字。
func valueTLV(v VarBind) []byte {
	if v.Tag == 0 || v.Tag == TagNull {
		return appendTLV(nil, TagNull, nil)
	}
	return appendTLV(nil, v.Tag, v.Val)
}

// Parse 解一个报文。对端是设备，不是我们自己，所以每一步都当输入是坏的来对待。
func Parse(b []byte) (Packet, error) {
	var p Packet
	outer, rest, err := Read(b)
	if err != nil {
		return p, err
	}
	if len(rest) != 0 {
		return p, fmt.Errorf("snmp: 报文尾巴上多了 %d 字节", len(rest))
	}
	if outer.Tag != TagSequence {
		return p, fmt.Errorf("%w: 最外层不是序列", ErrBadTag)
	}
	items, err := ReadAll(outer.Val)
	if err != nil {
		return p, err
	}
	if len(items) != 3 {
		return p, fmt.Errorf("snmp: 顶层要有 版本/团体名/报文 三项，实际 %d 项", len(items))
	}
	if items[0].Tag != TagInteger || items[1].Tag != TagOctetString {
		return p, fmt.Errorf("%w: 版本或团体名类型不对", ErrBadTag)
	}
	ver, err := AsInt(items[0].Val)
	if err != nil || ver < 0 || ver > 3 {
		return p, fmt.Errorf("snmp: 看不懂这个版本号 %d", ver)
	}
	p.Version = int(ver)
	p.Community = string(items[1].Val)

	// PDU 已经是 ReadAll 拆出来的一个元素了，直接看它的标签和内容。
	// （这里再 Read 一次会把整段 PDU 当成 TLV 去剥，真设备的包一个都解不开。）
	if items[2].Tag&0xe0 != 0xa0 {
		return p, fmt.Errorf("%w: 报文段不是一个 PDU", ErrBadTag)
	}
	p.PDU = items[2].Tag
	fields, err := ReadAll(items[2].Val)
	if err != nil {
		return p, err
	}
	if len(fields) != 4 || fields[3].Tag != TagSequence {
		return p, fmt.Errorf("snmp: PDU 里要有 标识/状态/下标/变量表 四段")
	}
	id, err := AsInt(fields[0].Val)
	if err != nil {
		return p, err
	}
	p.ID = int32(id)
	if p.ErrStatus, err = intOf(fields[1].Val); err != nil {
		return p, err
	}
	if p.ErrIndex, err = intOf(fields[2].Val); err != nil {
		return p, err
	}
	binds, err := ReadAll(fields[3].Val)
	if err != nil {
		return p, err
	}
	for _, one := range binds {
		if one.Tag != TagSequence {
			return p, fmt.Errorf("%w: 变量表里有一项不是序列", ErrBadTag)
		}
		pair, err := ReadAll(one.Val)
		if err != nil {
			return p, err
		}
		if len(pair) != 2 || pair[0].Tag != TagOID {
			return p, fmt.Errorf("snmp: 变量表里有一对不是「OID + 值」")
		}
		oid, err := AsOID(pair[0].Val)
		if err != nil {
			return p, err
		}
		p.VarBinds = append(p.VarBinds, VarBind{OID: oid, Tag: pair[1].Tag, Val: pair[1].Val})
	}
	return p, nil
}

func intOf(b []byte) (int, error) {
	n, err := AsInt(b)
	return int(n), err
}

// Error 是设备**答了但答的是「不行」**：状态码非 0。
//
// ★ 这一类必须和「没回话」分开：没回话要查防火墙和团体名，
//
//	而 noAccess / wrongType 是设备在告诉我们它认这个请求、只是这一栏不给或给不了。
type Error struct {
	Status int
	Index  int
	OID    string // 出错的是变量表里第 Index 个，把它带出来好查
}

func (e *Error) Error() string {
	s := StatusText(e.Status)
	if e.OID != "" {
		return fmt.Sprintf("设备回了一句「%s」（第 %d 栏 %s）", s, e.Index, e.OID)
	}
	return fmt.Sprintf("设备回了一句「%s」", s)
}

// StatusText 把 error-status 翻成人话。这几个词在现场是有用的：
// 比如 wrongEncoding 多半是那台设备只认 v1，把版本降一档就好。
func StatusText(n int) string {
	switch n {
	case 0:
		return "没有错"
	case 1:
		return "报文太大（一次问太多了，少问几栏）"
	case 2:
		return "这一栏不给读（团体名权限不够）"
	case 3:
		return "值的类型不对"
	case 4:
		return "值的长度不对"
	case 5:
		return "值的编码不对（多半是这台只认 v1，把版本改成 v1 再试）"
	case 6:
		return "值本身不对"
	case 7:
		return "不允许新建"
	case 8:
		return "只读，改不了"
	case 9:
		return "写不进去"
	case 10:
		return "名字不一致"
	}
	return "状态码 " + strconv.Itoa(n)
}

// NewGet / NewGetNext / NewBulk 拼三种请求。
func NewGet(community string, oids ...string) (Packet, error) {
	return newRequest(Version2c, community, PDUGetRequest, 0, 0, oids)
}

// NewGetNext 问「每个 OID 的下一个是哪一栏」—— walk 就是靠它一步一步走。
func NewGetNext(community string, oids ...string) (Packet, error) {
	return newRequest(Version2c, community, PDUGetNextRequest, 0, 0, oids)
}

// NewBulk 是 GETBULK：一次多要几轮，走一棵大树比 GETNEXT 省几十倍往返。
//
// nonRepeaters 是前面几栏「只要一个值」（通常是表的列数那些标量），
// maxRep 是剩下的列各重复几轮。★ maxRep 不许无脑给大：
// 一个报文超过对端的 max-pdu-size 时它会直接丢，症状是「有的设备 walk 不动」。
func NewBulk(community string, nonRepeaters, maxRep int, oids ...string) (Packet, error) {
	return newRequest(Version2c, community, PDUGetBulkRequest, nonRepeaters, maxRep, oids)
}

func newRequest(version int, community string, pdu byte, a, b int, oids []string) (Packet, error) {
	if strings.TrimSpace(community) == "" {
		return Packet{}, fmt.Errorf("snmp: 没给团体名（community）")
	}
	if len(oids) == 0 {
		return Packet{}, fmt.Errorf("snmp: 一个 OID 都没给")
	}
	p := Packet{
		Version:   version,
		Community: community,
		PDU:       pdu,
		ErrStatus: a, // GETBULK 里这一格是 non-repeaters
		ErrIndex:  b, // GETBULK 里这一格是 max-repetitions
	}
	for _, o := range oids {
		o = strings.TrimPrefix(strings.TrimSpace(o), ".")
		if o == "" {
			return Packet{}, fmt.Errorf("%w: 空的 OID", ErrBadOID)
		}
		if _, err := OIDContent(o); err != nil {
			return Packet{}, err
		}
		p.VarBinds = append(p.VarBinds, VarBind{OID: o})
	}
	return p, nil
}
