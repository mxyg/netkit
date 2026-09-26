package flow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/capture"
)

// 这一份文件里的每一条都写着「不这么做会怎样」：拆包这一层出错的方式不是崩溃，
// 是把一份包算到错的那条流上、或者干脆算不出来 —— 后者在表上的样子恰好是
// 「这台机器没发过包」，而现场会照着这句话去查错的那台机器。

// ==================== 造包的手 ====================

func eth(dst, src net.HardwareAddr, typ uint16, body []byte) []byte {
	b := make([]byte, 0, 14+len(body))
	b = append(b, dst...)
	b = append(b, src...)
	b = binary.BigEndian.AppendUint16(b, typ)
	return append(b, body...)
}

func vlan(tag uint16, typ uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, tag&0x0fff)
	b = binary.BigEndian.AppendUint16(b, typ)
	return append(b, body...)
}

// ipv4 造一条头加正文；total 故意可以填错， 因为「线上那一格与带回来的不符」
// 正是这一层必须处理对的两件事之一。
func ipv4(id int, proto byte, ttl int, src, dst string, total int, body []byte) []byte {
	sip, dip := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if sip == nil || dip == nil {
		panic("测试造的地址不是 IPv4：" + src + " / " + dst)
	}
	b := make([]byte, 20)
	b[0] = 4<<4 | 5
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], uint16(id))
	b[8] = byte(ttl)
	b[9] = proto
	copy(b[12:16], sip)
	copy(b[16:20], dip)
	return append(b, body...)
}

func ipv6(next byte, hop int, src, dst string, body []byte) []byte {
	sip, dip := net.ParseIP(src), net.ParseIP(dst)
	b := make([]byte, 40)
	b[0] = 6 << 4
	b[6] = next
	b[7] = byte(hop)
	copy(b[8:24], sip.To16())
	copy(b[24:40], dip.To16())
	binary.BigEndian.PutUint16(b[4:6], uint16(len(body)))
	return append(b, body...)
}

func tcp(sp, dp uint16, seq, ack uint32, flags TCPFlags, win uint16, opts, payload []byte) []byte {
	hl := 20 + len(opts)
	b := make([]byte, hl)
	binary.BigEndian.PutUint16(b[0:2], sp)
	binary.BigEndian.PutUint16(b[2:4], dp)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12] = byte(hl/4) << 4
	b[13] = byte(flags)
	binary.BigEndian.PutUint16(b[14:16], win)
	copy(b[20:], opts)
	return append(b, payload...)
}

func udp(sp, dp uint16, lenField int, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], sp)
	binary.BigEndian.PutUint16(b[2:4], dp)
	binary.BigEndian.PutUint16(b[4:6], uint16(lenField))
	binary.BigEndian.PutUint16(b[6:8], 0)
	return append(b, payload...)
}

var (
	macA = net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	macB = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
)

// ==================== 以太网 ＋ IPv4 ＋ TCP ====================

func Test拆一条普通的TCP包(t *testing.T) {
	payload := []byte("DESCRIBE rtsp://10.0.0.9/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\n\r\n")
	pkt := eth(macB, macA, etypeIPv4,
		ipv4(7, protoTCP, 64, "192.168.1.10", "10.0.0.9", 20+20+len(payload),
			tcp(51234, 554, 1001, 0, FlagSYN|FlagPSH, 64240, nil, payload)))
	f, err := Decode(LinkEN10MB, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if f.Src != "192.168.1.10:51234" || f.Dst != "10.0.0.9:554" {
		t.Errorf("地址写成了 %s → %s", f.Src, f.Dst)
	}
	if !bytes.Equal(f.SrcMAC, macA) || !bytes.Equal(f.DstMAC, macB) {
		t.Errorf("MAC 反了：%s → %s", f.SrcMAC, f.DstMAC)
	}
	if f.Transport != "tcp" || f.TTL != 64 || f.IPID != 7 {
		t.Errorf("传输层/生存时间/标识 = %q %d %d", f.Transport, f.TTL, f.IPID)
	}
	if !f.TCP.Get(FlagSYN) || !f.TCP.Get(FlagPSH) || f.TCP.Get(FlagACK) {
		t.Errorf("标志位解错：%s", f.TCP.Flags)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("正文不是那一份 RTSP 请求：%q", f.Payload)
	}
	if f.Unrecognized || f.Note != "" {
		t.Errorf("一条正常的包被记成了有话要说：%v %q", f.Unrecognized, f.Note)
	}
}

func TestVLAN一层层剥到里面(t *testing.T) {
	inner := ipv4(1, protoUDP, 64, "1.1.1.1", "2.2.2.2", 20+8+3, udp(5060, 5060, 11, []byte("BYE")))
	// 外层 0x88A8（服务商标签）套内层 0x8100， 再是 IPv4。
	tagged := vlan(300, 0x8100, vlan(20, etypeIPv4, inner))
	f, err := Decode(LinkEN10MB, eth(macB, macA, 0x8100, tagged))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.VLANs) != 2 || f.VLANs[0] != 300 || f.VLANs[1] != 20 {
		t.Errorf("两层标签量到 %v（顺序必须由外到内， 现场要照这个去配 trunk）", f.VLANs)
	}
	if f.SrcPort != 5060 || f.Transport != "udp" {
		t.Errorf("剥完标签没走到里面：%s %q", f.Src, f.Transport)
	}
}

func Test自指的VLAN标签不许转死(t *testing.T) {
	// 一份把 0x8100 一路填到底的脏包：没有上限就是死循环（这一档必须自己挡住，
	// 因为文件是同事抓来的， 谁都不知道中间被什么工具改过）。
	body := []byte{}
	for i := 0; i < 40; i++ {
		body = vlan(1, 0x8100, body)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f, _ := Decode(LinkEN10MB, eth(macB, macA, 0x8100, body))
		if !f.Unrecognized {
			t.Error("第三层标签该停在「不拆」这一格上， 不能继续往里猜")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("自指标签转死了")
	}
}

// ==================== 分片 ====================

func Test非首片不许冒充有端口(t *testing.T) {
	// 偏移 1480 的那一片：头里没有端口， 正文也不该当成「L4 正文」递出去。
	frag := ipv4(9, protoUDP, 64, "10.0.0.2", "10.0.0.1", 20+10, []byte("0123456789"))
	binary.BigEndian.PutUint16(frag[6:8], uint16(1480/8)) // 偏移那一格单位是 8 字节
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv4, frag))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Frag || f.FirstFrag {
		t.Errorf("这一片没被判成非首片：Frag=%v First=%v", f.Frag, f.FirstFrag)
	}
	if f.FragOffset != 1480 {
		t.Errorf("偏移量成了 %d（ 那一格的单位是 8 字节， 不换算就差 8 倍）", f.FragOffset)
	}
	if f.SrcPort != 0 || f.DstPort != 0 || f.Payload != nil {
		t.Errorf("非首片被造出了端口或正文：%d %d %q", f.SrcPort, f.DstPort, f.Payload)
	}
	if f.Note == "" {
		t.Error("没记下「这一片没有端口」—— 上层要据此去和首片对账")
	}
}

func Test总长比带回来的大就只记截断不崩(t *testing.T) {
	// 留长 96 抓的包， 线上那一格照抄 65535：拿它去切片就直接越界。
	hdr := ipv4(3, protoTCP, 64, "10.0.0.2", "10.0.0.1", 65535, tcp(1, 2, 3, 4, FlagACK, 0, nil, nil)[:20])
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv4, hdr))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Truncated {
		t.Error("没标截断：这份文件里的包是剪过的， 表上必须看得出来")
	}
	if f.SrcPort != 1 || f.DstPort != 2 {
		t.Errorf("截断不该妨碍拆头：%d %d", f.SrcPort, f.DstPort)
	}
}

func Test头长声明撒谎时说的是那一句(t *testing.T) {
	cases := []struct {
		name   string
		pkt    []byte
		wantLn string
	}{
		{"IPv4 头长小于 20", eth(macB, macA, etypeIPv4, func() []byte {
			b := ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 40, nil)
			b[0] = 4<<4 | 4
			return b
		}()), "少于 20"},
		{"IPv4 头长超过整包", eth(macB, macA, etypeIPv4, func() []byte {
			b := ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 60, make([]byte, 4))
			b[0] = 4<<4 | 15
			return b
		}()), "而这一包只有"},
		{"IPv4 总长比头还小", eth(macB, macA, etypeIPv4, ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 10, nil)), "比头长"},
		{"TCP 头长小于 20", eth(macB, macA, etypeIPv4, func() []byte {
			b := ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 40, tcp(1, 2, 3, 4, FlagACK, 0, nil, nil))
			b[20+12] = 4 << 4
			return b
		}()), "TCP 头长"},
		{"版本号不是 4 也不是 6", eth(macB, macA, etypeIPv4, []byte{0x50, 0, 0, 0}), "版本号是 5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(LinkEN10MB, c.pkt)
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(c.wantLn)) {
				t.Errorf("回的是 %v， 要句里带 %q", err, c.wantLn)
			}
		})
	}
}

// ==================== IPv6 ====================

func TestIPv6扩展头一路走到TCP(t *testing.T) {
	hbh := append([]byte{protoRoute, 0}, make([]byte, 6)...)      // (0+1)*8 = 8 字节
	route := append([]byte{protoDstOpts, 1}, make([]byte, 14)...) // (1+1)*8 = 16 字节
	opts := append([]byte{protoTCP, 1}, make([]byte, 14)...)      // (1+1)*8 = 16 字节
	seg := tcp(8080, 554, 1, 1, FlagACK, 0, nil, []byte("OPTIONS *"))
	body := append(append(append([]byte{}, hbh...), route...), opts...)
	body = append(body, seg...)
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv6, ipv6(protoHopByHop, 63, "fe80::1", "ff02::1", body)))
	if err != nil {
		t.Fatal(err)
	}
	if f.IPProto != protoTCP || f.SrcPort != 8080 {
		t.Errorf("扩展头走完后停在协议号 %d：%v", f.IPProto, err)
	}
	if f.Src != "[fe80::1]:8080" {
		t.Errorf("v6 的地址没加方括号：%s（ 地址里全是冒号， 不加就把端口挤没了）", f.Src)
	}
}

func TestIPv6自指的扩展头停在八层(t *testing.T) {
	// 每一层都声明「下一个头还是路由头」， 长度 8 字节：没上限就转不完。
	var body []byte
	for i := 0; i < 30; i++ {
		body = append(body, append([]byte{protoRoute, 0}, make([]byte, 6)...)...)
	}
	pkt := eth(macB, macA, etypeIPv6, ipv6(protoRoute, 63, "fe80::1", "fe80::2", body))
	done := make(chan error, 1)
	go func() { _, err := Decode(LinkEN10MB, pkt); done <- err }()
	select {
	case err := <-done:
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("8 层")) {
			t.Errorf("撞上限时回的是 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("扩展头转死了")
	}
}

func TestESP只说加密不拆内容(t *testing.T) {
	secret := []byte{protoESP, 0, 1, 2, 3, 4, 5, 6, 9, 9, 9, 9}
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv6, ipv6(protoESP, 63, "fe80::1", "fe80::2", secret)))
	if err != nil {
		t.Fatal(err)
	}
	if f.Transport != "" || len(f.Payload) != 0 {
		t.Errorf("ESP 的密文被当成正文递出去了：%q", f.Payload)
	}
	if !bytes.Contains([]byte(f.Note), []byte("ESP")) {
		t.Errorf("没记下是加密的：%q", f.Note)
	}
}

func TestIPv6分片头那一位换算(t *testing.T) {
	// 分片头：下一个头、保留、偏移(29)+保留(2)+M(1)、标识 4 字节。
	fh := make([]byte, 8)
	fh[0] = protoUDP
	binary.BigEndian.PutUint16(fh[2:4], uint16(1232/8*8|1)) // 偏移 1232 字节（ 单位 8 字节） 、M 置上
	binary.BigEndian.PutUint32(fh[4:8], 0xdeadbeef)
	fh = append(fh, []byte("tail")...)
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv6, ipv6(protoFrag, 63, "fe80::1", "fe80::2", fh)))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Frag || f.FirstFrag || !f.MoreFrags {
		t.Errorf("v6 分片判错：Frag=%v First=%v M=%v", f.Frag, f.FirstFrag, f.MoreFrags)
	}
	if f.FragOffset != 1232 {
		t.Errorf("偏移 = %d， 要 1232（ 单位 8 字节没换算）", f.FragOffset)
	}
	if f.FragID != 0xdeadbeef {
		t.Errorf("标识 = %x", f.FragID)
	}
}

// ==================== UDP 长度那一格 ====================

func TestUDP长度那一格不许信(t *testing.T) {
	cases := []struct {
		name     string
		lenField int
		payload  int
		wantNote string
		wantPl   int
	}{
		{"发送方没填（ 校验和卸载）", 0, 12, "长度那格是 0", 12},
		{"比头还短", 4, 8, "比头还短", 8},
		{"比带回来的短", 12, 20, "是填充", 4},
		{"比带回来的长", 100, 8, "", 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			seg := udp(5060, 5060, c.lenField, make([]byte, c.payload))
			f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv4,
				ipv4(1, protoUDP, 64, "10.0.0.2", "10.0.0.1", 20+len(seg), seg)))
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Payload) != c.wantPl {
				t.Errorf("正文给了 %d 字节， 要 %d", len(f.Payload), c.wantPl)
			}
			if c.wantNote != "" && !bytes.Contains([]byte(f.Note), []byte(c.wantNote)) {
				t.Errorf("没记下那一格：%q", f.Note)
			}
			if c.name == "比带回来的长" && !f.Truncated {
				t.Error("声明比带回来的长却没标截断")
			}
		})
	}
}

// ==================== ICMP ====================

func TestICMP两套编号各认各的(t *testing.T) {
	v4 := func(typ byte) Frame {
		seg := []byte{typ, 0, 0, 0, 0x12, 0x34, 0, 7}
		f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv4,
			ipv4(1, protoICMP, 64, "10.0.0.2", "10.0.0.1", 20+len(seg), seg)))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if got := v4(8); !got.ICMP.IsEchoRequest(false) || got.Transport != "icmp" {
		t.Errorf("v4 请求 8 认错了：%v", got.ICMP)
	}
	if got := v4(0); !got.ICMP.IsEchoReply(false) {
		t.Error("v4 应答 0 认错了")
	}
	if got := v4(8); got.ICMP.ID != 0x1234 || got.ICMP.Seq != 7 {
		t.Errorf("id/seq = %x/%d", got.ICMP.ID, got.ICMP.Seq)
	}
	seg := []byte{128, 0, 0, 0, 0x00, 0x01, 0, 2}
	f6, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv6, ipv6(protoICMPv6, 64, "fe80::1", "fe80::2", seg)))
	if err != nil {
		t.Fatal(err)
	}
	if !f6.ICMP.IsEchoRequest(true) || f6.Transport != "icmpv6" {
		t.Errorf("v6 用 128 这一套：Transport=%q", f6.Transport)
	}
}

func Test不可达回包里那一条要指得回去(t *testing.T) {
	// 里面嵌的是原来的那一包（ 10.0.0.1:554 → 10.0.0.2:51234 的一条 TCP）。
	inner := ipv4(11, protoTCP, 64, "10.0.0.1", "10.0.0.2", 20+20, tcp(554, 51234, 9, 9, FlagSYN|FlagACK, 0, nil, nil))
	seg := append([]byte{3, 3, 0, 0}, inner...) // 类型 3 代码 3 = 端口不可达
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv4,
		ipv4(12, protoICMP, 64, "10.0.0.2", "10.0.0.1", 20+len(seg), seg)))
	if err != nil {
		t.Fatal(err)
	}
	if f.ICMP.Inside == nil {
		t.Fatal("没把嵌着的那一条拆出来：这一句判定就只能说「收到了一个 ICMP」， 说不到是哪个端口")
	}
	in := f.ICMP.Inside
	if in.Src != "10.0.0.1:554" || in.Dst != "10.0.0.2:51234" {
		t.Errorf("里面那一条的地址 = %s → %s", in.Src, in.Dst)
	}
	// ★ 外面这一包自己的账不许被里面那条盖掉。
	if f.SrcIP.String() != "10.0.0.2" || f.SrcPort != 0 {
		t.Errorf("外面那一包自己的地址被改了：%s 端口 %d", f.Src, f.SrcPort)
	}
}

// ==================== ARP ====================

func arpFrame(op uint16, smac, tmac net.HardwareAddr, sip, tip string) []byte {
	b := make([]byte, 0, 28)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, etypeIPv4)
	b = append(b, 6, 4)
	b = binary.BigEndian.AppendUint16(b, op)
	b = append(b, smac...)
	b = append(b, net.ParseIP(sip).To4()...)
	b = append(b, tmac...)
	b = append(b, net.ParseIP(tip).To4()...)
	return b
}

func TestARP那几种说法各是一句(t *testing.T) {
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	t.Run("请求", func(t *testing.T) {
		f, err := Decode(LinkEN10MB, eth(macB, macA, etypeARP, arpFrame(1, macA, zero, "10.0.0.5", "10.0.0.1")))
		if err != nil {
			t.Fatal(err)
		}
		if f.ARP.Gratuitous {
			t.Error("一次正常的问话被判成「谁占了这台地址」")
		}
		if f.Transport != "arp" || f.Src != "10.0.0.5" {
			t.Errorf("ARP 那一格：%q %s", f.Transport, f.Src)
		}
	})
	t.Run("免费 ARP", func(t *testing.T) {
		// 请求里源==目标：这是白送的一条「这台地址我占了」（ 地址冲突排查的第一手证据）。
		f, err := Decode(LinkEN10MB, eth(macB, macA, etypeARP, arpFrame(1, macA, zero, "10.0.0.5", "10.0.0.5")))
		if err != nil {
			t.Fatal(err)
		}
		if !f.ARP.Gratuitous {
			t.Error("免费 ARP 没认出来")
		}
	})
	t.Run("应答里目标 MAC 与源 MAC 不同是常态", func(t *testing.T) {
		// ★ 这条钉的是「不许拿单包判地址冲突」：应答的目标 MAC 就是当初那个请求方，
		// 与源 MAC 天然不一样。拿它当冲突， 表上每一条 ARP 应答都是病。
		f, err := Decode(LinkEN10MB, eth(macB, macA, etypeARP, arpFrame(2, macA, macB, "10.0.0.5", "192.168.1.1")))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.ARP.TargetMAC, macB) || !bytes.Equal(f.ARP.SenderMAC, macA) {
			t.Errorf("应答里两个 MAC 记反了或丢了：%s %s", f.ARP.SenderMAC, f.ARP.TargetMAC)
		}
	})
}

// decodeARPIntoTest 已经删掉了：它把生产逻辑在测试里抄了一遍，
// 那种测试只会自证自洽， 量不到真代码。

func TestARP只拆6字节MAC加IPv4(t *testing.T) {
	bad := arpFrame(1, macA, macB, "10.0.0.5", "10.0.0.1")
	bad[4] = 20 // 把长度那一格改成 InfiniBand 之类的
	if _, err := Decode(LinkEN10MB, eth(macB, macA, etypeARP, bad)); err == nil {
		t.Error("形状不对的 ARP 被照拆了")
	}
	if _, err := Decode(LinkEN10MB, eth(macB, macA, etypeARP, bad[:20])); err == nil {
		t.Error("断在半路的 ARP 被照拆了")
	}
}

// ==================== 链路口 ====================

func Test每种链路口各走各的头(t *testing.T) {
	seg := tcp(1, 2, 3, 4, FlagSYN, 0, nil, []byte("x"))
	ip := ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 20+len(seg), seg)
	t.Run("BSD 环回", func(t *testing.T) {
		b := binary.NativeEndian.AppendUint32(nil, afInet)
		f, err := Decode(LinkNull, append(b, ip...))
		if err != nil {
			t.Fatal(err)
		}
		if f.SrcMAC != nil {
			t.Error("环回没有 MAC， 造出来就是假数")
		}
		if f.Src != "1.1.1.1:1" {
			t.Errorf("环回里没拆出地址：%s", f.Src)
		}
	})
	t.Run("cooked v1", func(t *testing.T) {
		b := make([]byte, 16)
		binary.BigEndian.PutUint16(b[14:16], etypeIPv4)
		f, err := Decode(LinkLinuxSLL, append(b, ip...))
		if err != nil {
			t.Fatal(err)
		}
		if f.SrcMAC != nil {
			t.Error("cooked 那个地址字段不是「源 MAC」（-i any 没有口这一说）")
		}
	})
	t.Run("cooked v2", func(t *testing.T) {
		b := make([]byte, 20)
		binary.BigEndian.PutUint16(b[2:4], etypeIPv4)
		f, err := Decode(LinkLinuxSLL2, append(b, ip...))
		if err != nil {
			t.Fatal(err)
		}
		if f.Src != "1.1.1.1:1" {
			t.Errorf("v2 的头长走错了吗：%s", f.Src)
		}
	})
	t.Run("裸 IP 按版本号判", func(t *testing.T) {
		if f, err := Decode(LinkRaw, ip); err != nil || f.SrcPort != 1 {
			t.Errorf("v4：%v", err)
		}
		v6 := ipv6(protoTCP, 64, "fe80::1", "fe80::2", seg)
		if f, err := Decode(LinkRaw, v6); err != nil || f.SrcPort != 1 {
			t.Errorf("v6：%v", err)
		}
		if _, err := Decode(LinkRaw, []byte{0x50, 0, 0, 0}); err == nil {
			t.Error("版本号 5 也照拆了")
		}
	})
	t.Run("无线那几档拒而不硬拆", func(t *testing.T) {
		for _, lt := range []uint16{LinkIEEE80211, LinkRadioTap, LinkPFSync, 9999} {
			if _, err := Decode(lt, ip); !errors.Is(err, ErrLink) {
				t.Errorf("链路口 %d：回的是 %v， 要 ErrLink", lt, err)
			}
		}
	})
}

func TestTCP选项那一格不许吃进正文(t *testing.T) {
	// 20 字节头 ＋ 4 字节选项（MSS）， 正文从 24 开始。
	opts := []byte{2, 4, 5, 0x40} // MSS 1280
	seg := tcp(1, 2, 3, 4, FlagSYN, 0, opts, []byte("BODY"))
	f, err := Decode(LinkEN10MB, eth(macB, macA, etypeIPv4,
		ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 20+len(seg), seg)))
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Payload) != "BODY" {
		t.Errorf("正文里混进了选项：%q", f.Payload)
	}
	if !bytes.Equal(f.TCP.Options, opts) || f.TCP.HeaderLen != 24 {
		t.Errorf("选项没留在该留的地方：% x 头长 %d", f.TCP.Options, f.TCP.HeaderLen)
	}
}

// ==================== 真产物与「怎么截都不许 panic」 ====================

// 这一台机器之外抓来的两份真文件（Linux 的 dumpcap 与 Windows pktmon 转出来的那一份）
// 走的是同一套拆包手， 所以把它们当用例：手搭的包只会按我们的想法错。
func Test真文件里的每一包都拆得动(t *testing.T) {
	for _, name := range []string{"dumpcap-lo.pcapng", "pktmon-nics.pcapng"} {
		t.Run(name, func(t *testing.T) {
			fh, err := os.Open("../capture/testdata/" + name)
			if err != nil {
				t.Skipf("拿不到那份真产物：%v", err)
			}
			defer fh.Close()
			rd, err := capture.Open(fh)
			if err != nil {
				t.Fatal(err)
			}
			ifaces := rd.Ifaces()
			n, ok := 0, 0
			for {
				p, err := rd.Read()
				if errors.Is(err, os.ErrClosed) {
					break
				}
				if err != nil {
					break
				}
				lt := ifaces[p.InterfaceIndex].LinkType
				n++
				f, err := Decode(lt, p.Data)
				if err != nil {
					t.Errorf("第 %d 包拆不动：%v", n, err)
					continue
				}
				if f.SrcIP == nil && f.ARP == nil {
					t.Errorf("第 %d 包连地址都没有：%+v", n, f)
					continue
				}
				ok++
			}
			if n == 0 {
				t.Fatal("一份包都没有")
			}
			if ok != n {
				t.Errorf("%d 包里只有 %d 包拆出了地址", n, ok)
			}
		})
	}
}

// ★ 每一份包都从 0 字节截到整包， 一路喂进去：这一层不许 panic。
// 抓包文件是别人给的， 留长是用户填的， 两者叠起来什么形状都能出现，
// 而「拆包拆到崩」会把整张表一起带走。
func Test怎么截都不会崩(t *testing.T) {
	seg := tcp(1, 2, 3, 4, FlagSYN, 0, []byte{2, 4, 5, 0x40}, []byte("PAYLOAD"))
	v6ext := append([]byte{protoFrag, 0, 0, 0x13, 0x11, 0xde, 0xad, 0xbe, 0xef}, tcp(1, 2, 3, 4, FlagACK, 0, nil, nil)...)
	// 注意上面那条故意把分片头写成 9 字节（ 多一字节）， 让它成为最难拆的那一种。
	frames := [][]byte{
		eth(macB, macA, etypeIPv4, ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 20+len(seg), seg)),
		eth(macB, macA, etypeIPv4, ipv4(1, protoUDP, 64, "1.1.1.1", "2.2.2.2", 65535, udp(1, 2, 0, []byte("abc")))),
		eth(macB, macA, etypeIPv4, ipv4(1, protoICMP, 64, "1.1.1.1", "2.2.2.2", 20+4+20+20,
			append([]byte{3, 3, 0, 0}, ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 20+20, seg)...))),
		eth(macB, macA, etypeIPv6, ipv6(protoHopByHop, 64, "fe80::1", "fe80::2", v6ext)),
		eth(macB, macA, etypeARP, arpFrame(2, macA, macB, "10.0.0.5", "10.0.0.1")),
		eth(macB, macA, 0x8100, vlan(1, 0x8100, vlan(2, 0x8100, ipv4(1, protoTCP, 64, "1.1.1.1", "2.2.2.2", 20+20, seg)))),
	}
	links := []uint16{LinkEN10MB, LinkNull, LinkLinuxSLL, LinkLinuxSLL2, LinkRaw, LinkIPv4, LinkIPv6, LinkRadioTap}
	n := 0
	for _, lt := range links {
		for _, raw := range frames {
			for cut := 0; cut <= len(raw); cut++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("链路口 %d、 截到 %d 字节时崩了：%v", lt, cut, r)
						}
					}()
					_, _ = Decode(lt, raw[:cut])
					n++
				}()
			}
		}
	}
	if n == 0 {
		t.Error("一次都没跑")
	}
	t.Logf("共喂了 %d 种截法", n)
}
