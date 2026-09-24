// Package snmp 是一个自己写的 SNMPv2c 客户端（以及一点点 v1 的兼容）。
//
// ★★ 为什么自己写：现场查交换机绕不开这一层（MAC 表、端口状态、PoE、LLDP 邻居），
//
//	而装包里不许塞第三方二进制；纯 Go 一份代码，五个平台一起走。
//
// 这一层只到「报文编得对、发得出去、回得来」，MIB 的语义在 tools 那一侧。
package snmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BER 标签：通用类型 + SMIv2 的应用类型 + 异常值。
// 这几个号是协议里写死的，注释掉任何一个都会变成「有的设备答、有的设备不答」。
const (
	TagInteger     byte = 0x02
	TagOctetString byte = 0x04
	TagNull        byte = 0x05
	TagOID         byte = 0x06
	TagSequence    byte = 0x30

	TagIPAddress byte = 0x40
	TagCounter32 byte = 0x41
	TagGauge32   byte = 0x42
	TagTimeTicks byte = 0x43
	TagOpaque    byte = 0x44
	TagCounter64 byte = 0x46

	TagNoSuchObject   byte = 0x80
	TagNoSuchInstance byte = 0x81
	TagEndOfMibView   byte = 0x82
)

// PDU 类型。
const (
	PDUGetRequest     byte = 0xa0
	PDUGetNextRequest byte = 0xa1
	PDUGetResponse    byte = 0xa2
	PDUSetRequest     byte = 0xa3
	PDUGetBulkRequest byte = 0xa5
	PDUInformRequest  byte = 0xa6
	PDUTrapV2         byte = 0xa7 // 设备主动推的那一条：不是我们要的答案，但它是「设备活着」的证据
)

// maxPDULen 是一个报文允许的最大长度。SNMP 跑在 UDP 上，理论上能拼到 65535；
// 超过这个数的一定是坏包，而解析坏包的代价必须是**当场报错**，不是把内存吃下去。
const maxPDULen = 65535

var (
	ErrShort    = errors.New("snmp: 报文比声明的长度短")
	ErrTooLarge = errors.New("snmp: 报文长度超出允许范围")
	ErrBadTag   = errors.New("snmp: 标签不对")
	ErrBadOID   = errors.New("snmp: OID 编不开")
	ErrBadInt   = errors.New("snmp: 整数域不对")
)

// ── 编码 ──

// appendLength 写 BER 的长度域：短格式（<128）一字节，长格式先带一个「后面几字节」。
func appendLength(dst []byte, n int) []byte {
	switch {
	case n < 128:
		return append(dst, byte(n))
	case n <= 0xff:
		return append(dst, 0x81, byte(n))
	case n <= 0xffff:
		return append(dst, 0x82, byte(n>>8), byte(n))
	default:
		return append(dst, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
}

// appendTLV 写一个「标签 + 长度 + 内容」。
func appendTLV(dst []byte, tag byte, content []byte) []byte {
	dst = append(dst, tag)
	dst = appendLength(dst, len(content))
	return append(dst, content...)
}

// appendInt 写一个有符号整数，用的是 BER 的**最少字节**补码。
//
// ★ 最少字节不是省流量：多写一个 0x00 前缀，个别实现比长度就比不过去。
func appendInt(dst []byte, tag byte, v int64) []byte {
	return appendTLV(dst, tag, intContent(v))
}

// intContent 把一个有符号整数缩成最少字节的补码。
func intContent(v int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	i := 0
	// 去掉冗余的符号扩展字节，但至少要留一字节。
	for i < 7 {
		cur, next := buf[i], buf[i+1]
		if (cur == 0x00 && next&0x80 == 0) || (cur == 0xff && next&0x80 != 0) {
			i++
			continue
		}
		break
	}
	return append([]byte(nil), buf[i:]...)
}

// uintContent 把一个无符号数写成最少字节。
//
// ★ 最高位是 1 时要补一个前导 0x00：Counter32 / Gauge32 / Counter64 / TimeTicks
//
//	在 BER 里仍按 INTEGER 编码，不补的话一个 42 亿字节的计数器会被读成负数 ——
//	现场表现是「流量统计是负的」。
func uintContent(v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	content := append([]byte(nil), buf[i:]...)
	if content[0]&0x80 != 0 {
		content = append([]byte{0x00}, content...)
	}
	return content
}

// appendOID 把点分十进制的 OID 编成 BER 内容。
//
// 前两节合成一字节（40*a+b），后面每节按 128 进制、高位续位。
func appendOID(dst []byte, oid string) ([]byte, error) {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: %q 至少要有两节", ErrBadOID, oid)
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %q 里的 %q 不是数", ErrBadOID, oid, p)
		}
		nums[i] = v
	}
	if nums[0] > 2 || nums[1] > 39 {
		// 第一字节是 40*a+b，a 只能 0..2、b 只能 0..39，越界就编不出可还原的字节。
		return nil, fmt.Errorf("%w: %q 的头两节超出 40 进制能装下的范围", ErrBadOID, oid)
	}
	content := []byte{byte(40*nums[0] + nums[1])}
	var tmp [10]byte
	for _, v := range nums[2:] {
		n := 0
		for {
			tmp[len(tmp)-1-n] = byte(v & 0x7f)
			v >>= 7
			if v == 0 {
				break
			}
			n++
		}
		start := len(tmp) - 1 - n
		// 除最后一段外都置续位
		for i := start; i < len(tmp)-1; i++ {
			tmp[i] |= 0x80
		}
		content = append(content, tmp[start:]...)
	}
	return appendTLV(dst, TagOID, content), nil
}

// OIDContent 只编 OID 的内容部分，给测试和拼包用。
func OIDContent(oid string) ([]byte, error) {
	full, err := appendOID(nil, oid)
	if err != nil {
		return nil, err
	}
	// 跳过标签和长度域：长度域占几字节要看内容多长，按第一字节的续位判。
	skip := 1 // 标签
	if full[skip]&0x80 == 0 {
		skip++ // 短格式：一字节长度
	} else {
		skip += 1 + int(full[skip]&0x7f) // 长格式：一字节说明后面跟几字节
	}
	return full[skip:], nil
}

// appendStr 写一个 OCTET STRING。设备名、sysDescr 这些都是这一类。
func appendStr(dst []byte, s string) []byte {
	return appendTLV(dst, TagOctetString, []byte(s))
}

// ── 解码 ──

// Element 是一个已经拆开的 TLV。
type Element struct {
	Tag byte
	Val []byte // 指向输入缓冲区，不复制
}

// Read 拆出下一个 TLV，返回它和剩下的字节。
//
// ★ 每一步都查边界：对端是一台来路不明的设备，
//
//	一个长度写飞的包不许变成 panic，也不许让我们按它说的长度去切片。
func Read(b []byte) (Element, []byte, error) {
	if len(b) < 2 {
		return Element{}, nil, ErrShort
	}
	tag := b[0]
	l, n, err := readLength(b[1:])
	if err != nil {
		return Element{}, nil, err
	}
	body := b[1+n:]
	if l < 0 || l > maxPDULen || len(body) < l {
		if l > maxPDULen {
			return Element{}, nil, ErrTooLarge
		}
		return Element{}, nil, ErrShort
	}
	return Element{Tag: tag, Val: body[:l]}, body[l:], nil
}

// readLength 解长度域，返回长度和它自己占了几字节。
func readLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrShort
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, nil
	}
	n := int(first & 0x7f)
	// 0x80 是「不定长」：DER 里不许出现，SNMP 实现也不该发，看到了就按坏的算。
	if n == 0 || n > 4 || len(b) < 1+n {
		return 0, 0, ErrTooLarge
	}
	l := 0
	for i := 0; i < n; i++ {
		l = l<<8 | int(b[1+i])
	}
	return l, 1 + n, nil
}

// ReadAll 把一个序列的**内容**拆成逐个元素，并且要求正好拆完。
func ReadAll(b []byte) ([]Element, error) {
	var out []Element
	for len(b) > 0 {
		e, rest, err := Read(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

// AsInt 按有符号整数读一个元素的内容。
func AsInt(val []byte) (int64, error) {
	if len(val) == 0 || len(val) > 8 {
		return 0, ErrBadInt
	}
	v := int64(0)
	if val[0]&0x80 != 0 {
		v = -1 // 负数先按全 1 铺开再覆盖，省掉一次补码运算
	}
	for _, b := range val {
		v = v<<8 | int64(b)
	}
	return v, nil
}

// AsUint 按无符号整数读（Counter32 / Gauge32 / Counter64 / TimeTicks）。
//
// 有些实现会把高位置一个 0x00 前缀，这里都按无符号处理，不看符号位。
//
// ★ 允许 9 字节：Counter64 满值（一个 64 位计数器绕满）编出来就是
//
//	00 + 八个 ff —— 自家编码器也这么编。不认的话现场表现是
//	「跑了很久的设备那一栏读不出来」，而它偏偏是最需要看的那台。
func AsUint(val []byte) (uint64, error) {
	if len(val) == 9 {
		// 九字节只认「一个 0x00 前缀 + 最高位为 1 的八字节」这一种：
		// 那是补码规则下唯一的写法，多一个前导零就是长度域没人守。
		if val[0] != 0x00 || val[1]&0x80 == 0 {
			return 0, ErrBadInt
		}
		val = val[1:]
	}
	if len(val) == 0 || len(val) > 8 {
		return 0, ErrBadInt
	}
	var v uint64
	for _, b := range val {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// AsOID 把内容解回点分十进制。
func AsOID(val []byte) (string, error) {
	if len(val) == 0 {
		return "", ErrBadOID
	}
	out := make([]string, 0, 8)
	out = append(out, strconv.FormatUint(uint64(val[0])/40, 10))
	out = append(out, strconv.FormatUint(uint64(val[0])%40, 10))
	var v uint64
	for i, b := range val[1:] {
		if b&0x80 != 0 {
			v = v<<7 | uint64(b&0x7f)
			// 最后一节不许带续位：带了就是被截断的 OID。
			if i == len(val)-2 {
				return "", ErrBadOID
			}
			continue
		}
		v = v<<7 | uint64(b)
		out = append(out, strconv.FormatUint(v, 10))
		v = 0
	}
	return strings.Join(out, "."), nil
}

// IsException 判断这个标签是不是 SNMP 的三种「没有」之一。
//
// ★ 三种要分开看：走到 MIB 末尾（endOfMibView）是 walk 的正常收口，
//
//	而 noSuchInstance 是「这个 OID 这台设备没有」—— 该换 OID，不该停。
func IsException(tag byte) bool {
	return tag == TagNoSuchObject || tag == TagNoSuchInstance || tag == TagEndOfMibView
}

// ── OID 比较 ──

// oidParts 拆 OID；非数字的节按 0 处理并且不参与「相等」判断，
// 因为调用方给的 OID 都来自协议或常量表。
func oidParts(oid string) []uint64 {
	s := strings.TrimPrefix(oid, ".")
	if s == "" {
		return nil
	}
	as := strings.Split(s, ".")
	out := make([]uint64, len(as))
	for i, p := range as {
		v, _ := strconv.ParseUint(p, 10, 64)
		out[i] = v
	}
	return out
}

// CmpOID 按 SNMP 的字典序（逐节比数值，短的在前）比两个 OID。
//
// ★ 不能按字符串比：".10" 在字符串序里排在 ".9" 前面，
//
//	而 walk 靠的就是「下一个 OID」的顺序，比错一次就会漏一整棵子树。
func CmpOID(a, b string) int {
	pa, pb := oidParts(a), oidParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// OIDUnder 判断 oid 是不是在 prefix 这棵子树里（prefix 本身不算）。
func OIDUnder(oid, prefix string) bool {
	p := strings.TrimPrefix(prefix, ".")
	if p == "" {
		return true
	}
	o := strings.TrimPrefix(oid, ".")
	return strings.HasPrefix(o, p+".")
}
