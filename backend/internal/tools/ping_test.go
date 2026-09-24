package tools

import "testing"

// echoErr 拼一条「目的不可达」的原始报文，内层带上我们发出去的那一发回显请求。
//
// 非特权数据报套接字读到的就是这一层：8 字节 ICMP 头 + 被投诉的原包（原 IP 头 + 原 ICMP 头）。
func echoErr(is6 bool, seq int, innerType byte) []byte {
	pkt := []byte{3, 0, 0, 0, 0, 0, 0, 0} // v6 也用同样的头长度（类型/代码/校验和/未使用）
	if is6 {
		pkt[0] = 1
	}
	icmpInner := []byte{innerType, 0, 0, 0, 0x12, 0x34, byte(seq >> 8), byte(seq)}
	if is6 {
		// 内层 IPv6 头：只看版本 nibble 和下一个首部（58=ICMPv6），后面 33 字节是填充。
		v6 := append([]byte{0x60}, make([]byte, 39)...)
		v6[6] = 58
		pkt = append(pkt, v6...)
	} else {
		// 内层 IPv4 头：版本 4、IHL 5（20 字节）、协议 1=ICMP，后面只是走到 ICMP 头为止。
		v4 := append([]byte{0x45}, make([]byte, 19)...)
		v4[9] = 1
		pkt = append(pkt, v4...)
	}
	return append(pkt, icmpInner...)
}

// udpPortUnreachable 本机自己产生的那条「端口不可达」：内层是一个 UDP 包。
// 这是实测踩过的假阳性来源 —— 同一进程里往没人听的 UDP 端口发过一个包，
// 网关 ping 的套接字就可能读到它。
//
// ★ 这个包故意拼成「除了协议号，别处都像我们的回显请求」：源端口高八位 0x08
//
//	正好落在内层 type 那一格，校验和两字节落在那一发序号那一格。
//	只看这两格就会收下它，拦住它的只能是「内层协议是 17，不是 1」。
func udpPortUnreachable() []byte {
	inner := append([]byte{0x45}, make([]byte, 19)...)
	inner[9] = 17 // UDP
	inner = append(inner,
		0x08, 0x02, // 源端口 2050
		0x30, 0x39, // 目的端口
		0x00, 0x1c, // 长度
		0x12, 0x34) // 校验和 —— 正好是 4660，和下面测试传的序号一样
	return append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, inner...)
}

func TestUnreachableForOnlyAcceptsOurOwnProbe(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		is6  bool
		seq  int
		want bool
	}{
		{"v4 说的是这一发", echoErr(false, 1234, 8), false, 1234, true},
		{"v6 说的是这一发", echoErr(true, 4321, 128), true, 4321, true},
		{"v4 说的是别的那一发", echoErr(false, 1234, 8), false, 99, false},
		{"v6 说的是别的那一发", echoErr(true, 4321, 128), true, 7, false},
		{"内层不是回显请求", echoErr(false, 1234, 11), false, 1234, false},
		{"本机 UDP 的端口不可达", udpPortUnreachable(), false, 4660, false},
		{"只有包头，没带原包", []byte{3, 0, 0, 0, 0, 0, 0, 0}, false, 1234, false},
		{"原包不是 IP", append([]byte{3, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 28)...), false, 1234, false},
	}
	for _, c := range cases {
		if got := unreachableFor(c.is6, c.pkt, c.seq); got != c.want {
			t.Errorf("%s: unreachableFor = %v，要 %v", c.name, got, c.want)
		}
	}
}
