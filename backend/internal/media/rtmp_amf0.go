package media

// AMF0 编解码 —— RTMP 的命令（connect / createStream / play / onStatus）用的就是它。
//
// ★ 只实现 RTMP 命令通道真会用到的那几种类型：number / boolean / string /
//
//	long string / object / ecma array / null / undefined / strict array。
//	AMF3 与 XML-document 一律照实报错，不猜。
//
// ★★ 解码有硬上限（长度、深度、属性条数）：对端是一个我们控制不了的服务器，
//
//	一个自称 40 亿字节的字符串必须先挡住，不然第一口分配就把这台机器顶穿。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

const (
	amf0Number      = 0x00
	amf0Boolean     = 0x01
	amf0String      = 0x02
	amf0Object      = 0x03
	amf0Null        = 0x05
	amf0Undefined   = 0x06
	amf0Reference   = 0x07
	amf0ECMAArray   = 0x08
	amf0ObjectEnd   = 0x09
	amf0StrictArray = 0x0a
	amf0LongString  = 0x0c

	amf0MaxDepth   = 8       // 对象嵌套层数上限
	amf0MaxProps   = 4096    // 一个对象里的属性条数上限
	amf0MaxStrLen  = 1 << 20 // 单个字符串上限 1 MiB
	amf0MaxElem    = 1 << 16 // 数组元素上限
	amf0MaxCmdArgs = 12      // 一条命令最多解几个参数
	// 属性名的长度字段只有两字节：过 65535 写不出去（会回绕成别的数），
	// 所以这一格是报错而不是换成长字符串 —— AMF0 没有长属性名这回事。
	amf0MaxKeyLen = 0xffff
)

// AMFValue 是一个 AMF0 值。对象用 map[string]any 表示，数组用 []any。
type AMFValue = any

// AMF0Encode 把若干个值编成一条命令消息的正文。
//
// 支持的 Go 类型：float64 / int / int64 / bool / string / nil /
// map[string]any（按 key 排序写，同一份输入编出的字节固定）/ []any。
func AMF0Encode(vals ...any) ([]byte, error) {
	var out []byte
	for _, v := range vals {
		b, err := amf0EncodeOne(v, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func amf0EncodeOne(v any, depth int) ([]byte, error) {
	if depth > amf0MaxDepth {
		return nil, fmt.Errorf("AMF0 嵌套超过 %d 层", amf0MaxDepth)
	}
	switch x := v.(type) {
	case nil:
		return []byte{amf0Null}, nil
	case bool:
		b := byte(0)
		if x {
			b = 1
		}
		return []byte{amf0Boolean, b}, nil
	case float64:
		out := make([]byte, 9)
		out[0] = amf0Number
		binary.BigEndian.PutUint64(out[1:], math.Float64bits(x))
		return out, nil
	case float32:
		return amf0EncodeOne(float64(x), depth)
	case int:
		return amf0EncodeOne(float64(x), depth)
	case int32:
		return amf0EncodeOne(float64(x), depth)
	case int64:
		return amf0EncodeOne(float64(x), depth)
	case string:
		return amf0EncodeString(x), nil
	case map[string]any:
		out := []byte{amf0Object}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(k) > amf0MaxKeyLen {
				return nil, errors.New("AMF0 属性名过长")
			}
			out = append(out, amf0RawString(k)...)
			b, err := amf0EncodeOne(x[k], depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return append(out, 0x00, 0x00, amf0ObjectEnd), nil
	case []any:
		out := []byte{amf0StrictArray}
		n := make([]byte, 4)
		binary.BigEndian.PutUint32(n, uint32(len(x)))
		out = append(out, n...)
		for _, e := range x {
			b, err := amf0EncodeOne(e, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("不支持编成 AMF0 的类型 %T", v)
	}
}

func amf0EncodeString(s string) []byte {
	// ★ 门槛是 0xffff 而不是 0xffffff：普通 string 的长度只有两字节，
	//   过 65535 还按它写，长度字段就回绕成别的数，整条命令从这儿开始错位。
	if len(s) > 0xffff {
		out := make([]byte, 5)
		out[0] = amf0LongString
		binary.BigEndian.PutUint32(out[1:], uint32(len(s)))
		return append(out, s...)
	}
	return append([]byte{amf0String}, amf0RawString(s)...)
}

// amf0RawString = 两字节长度 + 正文（不带类型标记）。
func amf0RawString(s string) []byte {
	out := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(out, uint16(len(s)))
	copy(out[2:], s)
	return out
}

// AMF0DecodeArgs 解出一条命令消息里的所有参数。
//
// ★ RTMP 命令消息有个历史包袱：紧跟在命令名后面的 transaction id 常常不带
//
//	类型标记（只有 8 个裸 double 字节）。所以那一个位置先认标记，认不出来才按
//	裸 double 读 —— 两种写法都吃得下，也不会把后面的对象当成数字吞掉。
func AMF0DecodeArgs(b []byte) ([]AMFValue, error) {
	var out []AMFValue
	for len(b) > 0 {
		if len(out) >= amf0MaxCmdArgs {
			return out, fmt.Errorf("一条命令的参数超过 %d 个，后面的没读", amf0MaxCmdArgs)
		}
		if len(out) == 1 && !amf0KnownMarker(b[0]) {
			if len(b) < 8 {
				return out, errors.New("命令名后面那一格既不是 AMF0 标记、也不够 8 字节")
			}
			out = append(out, math.Float64frombits(binary.BigEndian.Uint64(b)))
			b = b[8:]
			continue
		}
		v, rest, err := amf0DecodeOne(b, 0)
		if err != nil {
			return out, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

func amf0KnownMarker(m byte) bool {
	switch m {
	case amf0Number, amf0Boolean, amf0String, amf0Object, amf0Null,
		amf0Undefined, amf0Reference, amf0ECMAArray, amf0StrictArray, amf0LongString:
		return true
	}
	return false
}

func amf0DecodeOne(b []byte, depth int) (any, []byte, error) {
	if depth > amf0MaxDepth {
		return nil, nil, fmt.Errorf("AMF0 嵌套超过 %d 层", amf0MaxDepth)
	}
	if len(b) == 0 {
		return nil, nil, errors.New("AMF0 读到结尾，值还没读完")
	}
	marker := b[0]
	b = b[1:]
	switch marker {
	case amf0Number:
		if len(b) < 8 {
			return nil, nil, errors.New("AMF0 number 不足 8 字节")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), b[8:], nil
	case amf0Boolean:
		if len(b) < 1 {
			return nil, nil, errors.New("AMF0 boolean 缺正文")
		}
		return b[0] != 0, b[1:], nil
	case amf0String:
		if len(b) < 2 {
			return nil, nil, errors.New("AMF0 string 缺长度")
		}
		n := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if n > amf0MaxStrLen {
			return nil, nil, fmt.Errorf("AMF0 字符串自称 %d 字节，超过上限", n)
		}
		if len(b) < n {
			return nil, nil, errors.New("AMF0 string 正文不够")
		}
		return string(b[:n]), b[n:], nil
	case amf0LongString:
		if len(b) < 4 {
			return nil, nil, errors.New("AMF0 long string 缺长度")
		}
		n := int(binary.BigEndian.Uint32(b))
		b = b[4:]
		if n < 0 || n > amf0MaxStrLen {
			return nil, nil, fmt.Errorf("AMF0 字符串自称 %d 字节，超过上限", n)
		}
		if len(b) < n {
			return nil, nil, errors.New("AMF0 long string 正文不够")
		}
		return string(b[:n]), b[n:], nil
	case amf0Null:
		return nil, b, nil
	case amf0Undefined:
		return nil, b, nil
	case amf0Reference:
		if len(b) < 2 {
			return nil, nil, errors.New("AMF0 reference 缺句柄")
		}
		return map[string]any{"__ref": float64(binary.BigEndian.Uint16(b))}, b[2:], nil
	case amf0Object, amf0ECMAArray:
		if marker == amf0ECMAArray {
			if len(b) < 4 {
				return nil, nil, errors.New("AMF0 ecma array 缺元素数")
			}
			b = b[4:] // 这个计数各家写法不一，读不读得到结尾以 end marker 为准
		}
		obj := map[string]any{}
		for {
			if len(b) < 3 {
				return nil, nil, errors.New("AMF0 对象没写完就到底了")
			}
			if len(obj) >= amf0MaxProps {
				return obj, nil, fmt.Errorf("AMF0 对象属性超过 %d 条，后面的没读", amf0MaxProps)
			}
			klen := int(binary.BigEndian.Uint16(b))
			if klen == 0 && b[2] == amf0ObjectEnd {
				b = b[3:]
				break
			}
			if klen > amf0MaxStrLen || len(b) < 3+klen {
				return nil, nil, errors.New("AMF0 属性名长度不对")
			}
			key := string(b[2 : 2+klen])
			v, rest, err := amf0DecodeOne(b[2+klen:], depth+1)
			if err != nil {
				return obj, rest, fmt.Errorf("属性 %q：%w", key, err)
			}
			obj[key] = v
			b = rest
		}
		return obj, b, nil
	case amf0StrictArray:
		if len(b) < 4 {
			return nil, nil, errors.New("AMF0 array 缺元素数")
		}
		n := int(binary.BigEndian.Uint32(b))
		b = b[4:]
		if n < 0 || n > amf0MaxElem {
			return nil, nil, fmt.Errorf("AMF0 数组自称 %d 个元素，超过上限", n)
		}
		arr := make([]any, 0, amf0SliceCap(n))
		for i := 0; i < n; i++ {
			v, rest, err := amf0DecodeOne(b, depth+1)
			if err != nil {
				return arr, rest, err
			}
			arr = append(arr, v)
			b = rest
		}
		return arr, b, nil
	default:
		return nil, b, fmt.Errorf("认不出的 AMF0 类型标记 0x%02x", marker)
	}
}

// 自称几万个元素的数组先按 64 格预留：剩下的边读边长，
// 免得一个假计数直接换一次巨量分配。
func amf0SliceCap(n int) int {
	if n > 64 {
		return 64
	}
	return n
}
