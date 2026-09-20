// Package dhcp 是一个够用的 DHCPv4 服务端与探测器（RFC 2131 / 2132）。
//
// ★★ 起因（老板 2026-09-20）：
//
//	「我所有设备都在交换机里，但是没有人能自动分 IP，
//	  所以一个电脑开启 DHCP 后，能给所有设备自动分 IP。」
//
//	现场太常见了：一堆设备插在一台哑交换机上，没有路由器、没人发地址，
//	于是每台设备都要手工设静态 IP —— 40 台摄像机就是 40 次。
//
// ★★★ 但这件事**有一个能把整个网搞瘫的前提**，必须先验：
//
//	如果这个网里**已经有**一个 DHCP（路由器、别人的电脑、某台带 DHCP 的设备），
//	再起一个就是两个人同时发地址 —— 地址冲突、设备拿到错的网关、
//	有的能通有的不通，而且故障是间歇的，极难查。
//
//	所以「没有人能自动分 IP」这句话**必须实测**，不能听说。
//	Probe() 就是干这个的，而且 Serve 之前会强制先探一遍。
//
// 自研而不用现成库：DHCP 报文结构简单（固定头 + TLV 选项），
// 而我们要的判断（有没有别的 DHCP、它发的是什么网段）恰恰是通用库不直接给的。
package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// 报文类型（选项 53）。
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

// 常用选项码。
const (
	OptSubnetMask  = 1
	OptRouter      = 3
	OptDNS         = 6
	OptHostName    = 12
	OptRequestedIP = 50
	OptLeaseTime   = 51
	OptMessageType = 53
	OptServerID    = 54
	OptParamList   = 55
	OptClientID    = 61
	OptEnd         = 255
)

const (
	opRequest = 1
	opReply   = 2
	// magicCookie 是 DHCP 报文的固定标记（RFC 2132）。没有它的就不是 DHCP。
	magicCookie = 0x63825363
	// ServerPort / ClientPort 是 DHCP 的固定端口。
	ServerPort = 67
	ClientPort = 68
)

// Packet 一个 DHCP 报文。
//
// ★ 只保留我们真正要用的字段。完整的 BOOTP 头还有 sname/file 等，
// 那些是 PXE 网络引导用的，这里用不到 —— 留着反而让人以为该填。
type Packet struct {
	Op      byte
	XID     uint32 // 事务号：一问一答靠它配对
	Flags   uint16
	CIAddr  net.IP // 客户端已有地址（续租时用）
	YIAddr  net.IP // 我们分给它的地址
	SIAddr  net.IP // 下一跳服务器
	GIAddr  net.IP // 中继网关；非 0 表示这个请求是被中继过来的
	CHAddr  net.HardwareAddr
	Options map[byte][]byte
}

// MessageType 取报文类型（选项 53）。取不到返回 0。
func (p *Packet) MessageType() byte {
	if v, ok := p.Options[OptMessageType]; ok && len(v) > 0 {
		return v[0]
	}
	return 0
}

// OptionIP 把某个选项按 IPv4 读出来。
func (p *Packet) OptionIP(code byte) net.IP {
	if v, ok := p.Options[code]; ok && len(v) >= 4 {
		return net.IPv4(v[0], v[1], v[2], v[3])
	}
	return nil
}

// Parse 解一个 DHCP 报文。
func Parse(b []byte) (*Packet, error) {
	// 固定头 236 字节 + 4 字节 magic cookie
	if len(b) < 240 {
		return nil, fmt.Errorf("报文太短（%d 字节），不是 DHCP", len(b))
	}
	if binary.BigEndian.Uint32(b[236:240]) != magicCookie {
		return nil, fmt.Errorf("没有 DHCP 标记，这不是 DHCP 报文")
	}
	p := &Packet{
		Op:      b[0],
		XID:     binary.BigEndian.Uint32(b[4:8]),
		Flags:   binary.BigEndian.Uint16(b[10:12]),
		CIAddr:  net.IPv4(b[12], b[13], b[14], b[15]),
		YIAddr:  net.IPv4(b[16], b[17], b[18], b[19]),
		SIAddr:  net.IPv4(b[20], b[21], b[22], b[23]),
		GIAddr:  net.IPv4(b[24], b[25], b[26], b[27]),
		Options: map[byte][]byte{},
	}
	hlen := int(b[2])
	if hlen > 16 {
		hlen = 16
	}
	p.CHAddr = net.HardwareAddr(append([]byte(nil), b[28:28+hlen]...))

	// TLV 选项。★ 边界要一条条查：现场真见过畸形报文，
	//   不查的话一个越界就是服务进程崩掉，而它正管着整网的地址。
	for i := 240; i < len(b); {
		code := b[i]
		if code == OptEnd {
			break
		}
		if code == 0 { // 填充
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		p.Options[code] = append([]byte(nil), b[i+2:i+2+l]...)
		i += 2 + l
	}
	return p, nil
}

// Marshal 把报文编成字节。
func (p *Packet) Marshal() []byte {
	b := make([]byte, 240, 576)
	b[0] = p.Op
	b[1] = 1 // htype：以太网
	b[2] = 6 // hlen
	binary.BigEndian.PutUint32(b[4:8], p.XID)
	binary.BigEndian.PutUint16(b[10:12], p.Flags)
	copy(b[12:16], to4(p.CIAddr))
	copy(b[16:20], to4(p.YIAddr))
	copy(b[20:24], to4(p.SIAddr))
	copy(b[24:28], to4(p.GIAddr))
	copy(b[28:34], p.CHAddr)
	binary.BigEndian.PutUint32(b[236:240], magicCookie)

	// ★ 选项 53（报文类型）必须排第一：有些老设备就认这个顺序。
	//   规范没这么要求，但现场设备不都按规范写。
	if v, ok := p.Options[OptMessageType]; ok {
		b = append(b, OptMessageType, byte(len(v)))
		b = append(b, v...)
	}
	for code, v := range p.Options {
		if code == OptMessageType || code == OptEnd {
			continue
		}
		if len(v) > 255 {
			continue
		}
		b = append(b, code, byte(len(v)))
		b = append(b, v...)
	}
	b = append(b, OptEnd)
	// 补齐到 300 字节：有些设备对过短的报文不理睬
	for len(b) < 300 {
		b = append(b, 0)
	}
	return b
}

func to4(ip net.IP) []byte {
	if ip == nil {
		return []byte{0, 0, 0, 0}
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return []byte{0, 0, 0, 0}
}

// ipOpt 把一个 IP 编成选项值。
func ipOpt(ip net.IP) []byte {
	v := to4(ip)
	return append([]byte(nil), v...)
}

// durOpt 把租期编成 4 字节秒数。
func durOpt(d time.Duration) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(d/time.Second))
	return b
}
