package tools

import (
	"context"
	"encoding/json"
	"errors"
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
	var rtts []time.Duration
	var gotUnreachable bool
	sent, recv := 0, 0

	for seq := 1; seq <= count; seq++ {
		if err := ctx.Err(); err != nil {
			break
		}
		rtt, kind, err := pingOnce(conn, addr, dst, id, seq, timeout)
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
	if a.Is6() {
		typ = ipv6.ICMPTypeEchoRequest
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
		proto := 1 // ICMPv4
		if a.Is6() {
			proto = 58
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
		case *icmp.DstUnreach:
			return 0, verdictUnreachable, nil
		}
		if time.Now().After(deadline) {
			return 0, verdictNoReply, nil
		}
	}
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
