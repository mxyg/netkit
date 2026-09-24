package tools

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"sort"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// ping 的判定码。
//
// ★★ 这三个的区分是这个工具**最要紧的地方**，现场判断全靠它：
//
//	reachable    收到了回显应答 —— 对方在，通
//	unreachable  收到了 ICMP 不可达 —— **有人明确告诉我们到不了**（路由没有 / 主机不在 / 端口不通），
//	             这说明中间的路是通的，只是终点有问题
//	no-reply     什么都没收到 —— **分不清是主机不在、还是 ICMP 被拦了**
//
// 很多工具把后两种混成一个"不通"，那正是现场最容易走错方向的地方：
// unreachable 说明网络路径是通的，no-reply 连这个都不知道。
const (
	verdictReachable   = "reachable"
	verdictUnreachable = "unreachable"
	verdictNoReply     = "no-reply"
)

var pingTool = ots.Tool{
	Name:  "net.ping",
	Class: ots.ClassRead,
	Summary: "对一个地址发 ICMP 回显请求（ping），给出是否可达、往返时延与丢包率。" +
		"IPv4 走 ICMP、IPv6 走 ICMPv6，按地址自动选。" +
		"★ 结果区分三种：reachable（通）、unreachable（收到了明确的不可达，说明路是通的、终点有问题）、" +
		"no-reply（什么都没收到，分不清是主机不在还是 ICMP 被拦了）。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string",
	      "description": "目标地址。IPv4 或 IPv6；链路本地地址（fe80::）必须带 zone，如 fe80::1%en0。"},
	    "count": {"type": "integer", "minimum": 1, "maximum": 20,
	      "description": "发几个包，默认 4。"},
	    "timeoutMs": {"type": "integer", "minimum": 100, "maximum": 30000,
	      "description": "每个包等多久，默认 1000。"}
	  }
	}`),
	Invoke: doPing,
}

type pingArgs struct {
	Addr      string `json:"addr"`
	Count     int    `json:"count,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

func doPing(ctx context.Context, raw json.RawMessage) (any, error) {
	var a pingArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	addr, err := netaddr.Parse(a.Addr)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	count := a.Count
	if count <= 0 {
		count = 4
	}
	timeout := time.Duration(a.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Second
	}

	conn, err := listenICMP(addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// ★ 链路本地地址要带 zone 才知道从哪块网卡发。netaddr 已经存了接口名和索引，
	//   这里按本平台取用（见 netaddr.Addr.DialString 里那段说明）。
	dst := &net.UDPAddr{IP: net.IP(addr.IP.AsSlice())}
	if addr.NeedsZone() {
		if addr.Zone == "" && addr.ZoneID == 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"链路本地地址 %s 必须说清楚走哪块网卡（zone），否则不知道从哪个口发出去", addr.IP)
		}
		dst.Zone = addr.Zone
		if dst.Zone == "" {
			dst.Zone = itoa(addr.ZoneID)
		}
	}

	id := os.Getpid() & 0xffff
	// ★ 序号从随机点起，不从 1 开始，原因见 seqBase。
	base := seqBase()
	var rtts []time.Duration
	var gotUnreachable bool
	sent, recv := 0, 0

	for seq := 1; seq <= count; seq++ {
		if err := ctx.Err(); err != nil {
			break
		}
		rtt, kind, err := pingOnce(conn, addr, dst, id, base+seq, timeout)
		sent++
		switch {
		case err != nil:
			// 发不出去（比如网络不可达）也算一次没回应，继续下一个
		case kind == verdictReachable:
			recv++
			rtts = append(rtts, rtt)
		case kind == verdictUnreachable:
			gotUnreachable = true
		}
		if seq < count {
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	values := map[string]any{
		"target": addr.String(), "family": familyOf(addr),
		"sent": sent, "received": recv,
	}
	if sent > 0 {
		values["lossPercent"] = (sent - recv) * 100 / sent
	}
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		var sum time.Duration
		for _, d := range rtts {
			sum += d
		}
		values["rttMinMs"] = ms(rtts[0])
		values["rttMaxMs"] = ms(rtts[len(rtts)-1])
		values["rttAvgMs"] = ms(sum / time.Duration(len(rtts)))
	}

	switch {
	case recv > 0:
		return ots.Verdict{Code: verdictReachable, Values: values,
			Note: addr.String() + " 可达"}, nil
	case gotUnreachable:
		return ots.Verdict{Code: verdictUnreachable, Values: values,
			Note: addr.String() + " 返回了明确的不可达 —— 中间的路是通的，问题在终点或路由"}, nil
	}
	return ots.Verdict{Code: verdictNoReply, Values: values,
		Note: addr.String() + " 没有任何回应 —— 分不清是主机不在，还是 ICMP 被拦了"}, nil
}

// listenICMP 开一个 ICMP 套接字。
//
// ★ 优先用**非特权**的数据报 ICMP（macOS 默认允许；Linux 看 net.ipv4.ping_group_range）。
// 不行再退回需要 root 的原始套接字。两条都不行时要回 permission-required 并**说清楚怎么办** ——
// [OTS-6.3] 的精神：能事先知道要权限的，就别让用户撞一鼻子灰再猜。
func listenICMP(a netaddr.Addr) (*icmp.PacketConn, error) {
	dgram, raw := "udp4", "ip4:icmp"
	if a.Is6() {
		dgram, raw = "udp6", "ip6:ipv6-icmp"
	}
	listen := "0.0.0.0"
	if a.Is6() {
		listen = "::"
	}
	if c, err := icmp.ListenPacket(dgram, listen); err == nil {
		return c, nil
	}
	c, err := icmp.ListenPacket(raw, listen)
	if err == nil {
		return c, nil
	}
	if errors.Is(err, os.ErrPermission) || isPermission(err) {
		hint := "需要管理员权限才能发 ICMP。"
		switch runtime.GOOS {
		case "linux":
			hint += "或者让内核允许非特权 ping：sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
		case "windows":
			hint += "请以管理员身份运行。"
		}
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", hint)
	}
	return nil, ots.Errf(ots.ErrInternal, "开 ICMP 套接字失败：%s", err)
}

// icmpConn 是 ping 一族工具用到的那几件套：读、写、设读deadline、关。
//
// ★ 抽成接口的原因是 net.ping.watch 要能换实现（真套接字 / 编出来的样本序列），
//
//	不然测「丢在哪一发、抖在哪一发」就得真等上十几秒。
//	*icmp.PacketConn 天然满足它，两边都不用包一层。
type icmpConn interface {
	ReadFrom(b []byte) (int, net.Addr, error)
	WriteTo(b []byte, dst net.Addr) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// echoDst 拼出发包要用的目的地址。
//
// ★ 链路本地地址必须带 zone 才知道从哪块网卡发 —— netaddr 里已经存了接口名和索引，
//
//	这里按本平台取用（见 netaddr.Addr.DialString 里那段说明）。
func echoDst(a netaddr.Addr) (net.Addr, error) {
	dst := &net.UDPAddr{IP: net.IP(a.IP.AsSlice())}
	if !a.NeedsZone() {
		return dst, nil
	}
	if a.Zone == "" && a.ZoneID == 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"链路本地地址 %s 必须说清楚走哪块网卡（zone），否则不知道从哪个口发出去", a.IP)
	}
	dst.Zone = a.Zone
	if dst.Zone == "" {
		dst.Zone = itoa(a.ZoneID)
	}
	return dst, nil
}

func pingOnce(conn icmpConn, a netaddr.Addr, dst net.Addr, id, seq int, timeout time.Duration) (time.Duration, string, error) {
	typ := icmp.Type(ipv4.ICMPTypeEcho)
	errTyp := icmp.Type(ipv4.ICMPTypeDestinationUnreachable)
	proto := 1 // ICMPv4
	if a.Is6() {
		typ = ipv6.ICMPTypeEchoRequest
		errTyp = ipv6.ICMPTypeDestinationUnreachable
		proto = 58
	}
	msg := icmp.Message{Type: typ, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("yuhox-netkit")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, "", err
	}
	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, "", err
	}

	deadline := start.Add(timeout)
	buf := make([]byte, 1500)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return 0, "", err
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, verdictNoReply, nil // 超时或读失败：当没回应
		}
		rm, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		switch body := rm.Body.(type) {
		case *icmp.Echo:
			// ★ 非特权数据报 ICMP 下，内核会改写 ID，所以**不能按 ID 过滤**，
			//   只认 Seq。按 ID 过滤会导致在 macOS 上一个包都收不到。
			if body.Seq != seq {
				continue
			}
			return time.Since(start), verdictReachable, nil
		default:
			// ★ 不可达必须对上「说的是我们这一发」才算数，见 unreachableFor。
			//   对不上就接着等真回音 —— 宁可报「没回应」，也不许把别处的失败记在这台机器头上。
			if rm.Type != errTyp || !unreachableFor(a.Is6(), buf[:n], seq) {
				continue
			}
			return 0, verdictUnreachable, nil
		}
	}
}

// seqBase 一轮探测的线上序号起点。
//
// ★★ 随机、不从 1 开始，是为了同一进程里同时跑几路 ping 时不互摘回包：
//
//	非特权 ICMP 的 ID 会被内核改写，收包时只能按 Seq 认（见 pingOnce），
//	两路都从 1 开始编号时，A 路的回包会被 B 路当成自己的 —— A 看到「丢包」，
//	B 看到不知道哪来的数，而网络什么都没丢。体检里同时有到网关、对照组和出口探测，
//	正是会撞上这件事的地方。
func seqBase() int { return rand.IntN(40000) + 1 }

// unreachableFor 判断一条 ICMP 不可达是不是在说我们刚发出去的那一发。
//
// ★ 不可达报文里会带一段原包的头部（至少带到原 ICMP 头），拿它比对序号才知道是谁的。
//
//	不对这段就收下，等于把同一个套接字上任何一条不相干的错误算到被 ping 的那台机器头上 ——
//	实测过这种错法：同一进程里往一个没人听的 UDP 端口发包，本机自己产生的
//	「端口不可达」被记成了「网关回了明确不可达」，体检因此指出一条根本不存在的根因。
func unreachableFor(is6 bool, pkt []byte, seq int) bool {
	// 不可达报文的固定头是 8 字节（类型/代码/校验和 4 字节 + 未使用 4 字节），
	// 往后就是被投诉的那个原包。
	const icmpHdr = 8
	if len(pkt) < icmpHdr {
		return false
	}
	raw := pkt[icmpHdr:]
	off := 40
	if !is6 {
		if len(raw) < 20 || raw[0]>>4 != 4 {
			return false
		}
		// v4 头第 10 字节是上层协议。不先看它，一条 UDP 的端口不可达（内层第 21 字节
		// 恰好是源端口高八位）也有机会被读成「像我们的回显请求」。
		if raw[9] != 1 {
			return false
		}
		off = int(raw[0]&0x0f) * 4
	} else {
		if len(raw) < 40 || raw[0]>>4 != 6 || raw[6] != 58 {
			return false
		}
	}
	// 内层至少要有 type/code/checksum/id/seq 这 8 字节才认得出是谁的。
	if len(raw) < off+8 {
		return false
	}
	echo := byte(8) // ICMPv4 Echo Request
	if is6 {
		echo = 128 // ICMPv6 Echo Request
	}
	if raw[off] != echo {
		return false
	}
	return int(binary.BigEndian.Uint16(raw[off+6:off+8])) == seq
}

func familyOf(a netaddr.Addr) string {
	if a.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func isPermission(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) {
		return errors.Is(oe.Err, os.ErrPermission)
	}
	return false
}
