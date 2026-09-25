package gb28181

// UDP 上的一问一答。
//
// ★ 为什么连「发一条、等一条」也要单独一层：GB28181 现场最难分的两件事是
//
//	「这个口根本没开」与「口开着、没人答这一句」—— 前者要去看设备配没配对地址，
//	后者多半是被防火墙或平台的白名单挡了。这两条只有用**连好的** UDP 套接字
//	才分得开：连好的套接字会把对端回来的 ICMP 端口不通变成一次读错误，
//	没连的套接字只会一直等到超时。
//
// ★ 代价写在这儿，免得以后有人当 bug 改：连好的套接字只收这一对地址端口来的包。
//
//	有些平台会从另一个端口回话 —— 那时候的表现是「发出去了、超时」，
//	所以 timeout 这一档的下一步必须先包含「核对平台侧源端口/换个端口再问」。
//	服务端那一头（本机当平台开口）反过来用未连的套接字，谁都能打进来。

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// 错误的种类（封闭集合）。★ 工具层按 Kind 选判定码，不靠中文文本匹配 ——
// 文案要改，判定不能跟着漂。
const (
	KindDial       = "dial"        // 本机这一头就没起来（解析地址、起套接字、发不出去）
	KindRefused    = "refused"     // 对端明确回了不可达（ICMP 端口不通）：口是关的
	KindTimeout    = "timeout"     // 发出去了，到点没有任何回音：中间有东西吃掉，或者它不答这句
	KindNotSIP     = "not-sip"     // 有回包，但内容不像 SIP 报文
	KindBadMessage = "bad-message" // 看着是 SIP，但起始行/头读不下去
	KindStatus     = "status"      // 收到了最终响应，不是 2xx（Status 里带着码）
	KindAuth       = "auth"        // 认证这一关没过（Detail 里说哪一关）
	KindNoBody     = "no-body"     // 答了，可正文是空的（查询它接了但没答内容）
	KindBadBody    = "bad-body"    // 正文不是 MANSCDP，或读不出那四种根
	KindLocal      = "local"       // 本机自己的事没办成（参数、编码、内部状态）
)

// Error 带着「死在哪一步」。
type Error struct {
	Stage  string // dial / options / register / message / keepalive / listen …
	Kind   string
	Detail string
	Status int   // KindStatus 时给状态码
	Err    error // 底层 errno，工具层用 errors.Is 认
}

func (e *Error) Error() string {
	switch {
	case e.Status > 0:
		return fmt.Sprintf("%s 这一步收到 %d（%s）：%s", e.Stage, e.Status, e.Kind, e.Detail)
	case e.Detail != "":
		return fmt.Sprintf("%s 这一步失败（%s）：%s", e.Stage, e.Kind, e.Detail)
	case e.Err != nil:
		return fmt.Sprintf("%s 这一步失败（%s）：%s", e.Stage, e.Kind, e.Err)
	default:
		return fmt.Sprintf("%s 这一步失败（%s）", e.Stage, e.Kind)
	}
}

// Unwrap 把底层 errno 透出去：「refused 还是 timeout」靠 errors.Is(syscall.ECONNREFUSED)
// 认，不靠中文。
func (e *Error) Unwrap() error { return e.Err }

// KindOf 从 error 里取 Kind；不是 *Error 给空串。
func KindOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// StatusOf 取状态码（没有给 0）。
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// isRefused 认「对端不可达」这一类错误。
// ★ 三个平台写法不同（Linux/macOS 是 ECONNREFUSED，Windows 上是 WSAECONNRESET 10054，
// 而且 Go 在 Windows 上有时只给一条包起来的 os 错误），认不全就是把
// 「口是关的」报成「没人答」—— 正好抹掉这一层最想说的那句话。
func isRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, m := range refusedMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// refusedMarkers 是 errno 名字之外那点文本线索。★ 只在确认不是超时之后才用，
// 不然一条恰好带 "unreachable" 的报文会把 timeout 抢走。
var refusedMarkers = []string{"connection refused", "wsaconnectionreset", "10054", "no route to host", "network is unreachable"}

// Client 是一个连到对端的 UDP 套接字。
type Client struct {
	conn  *net.UDPConn
	peer  *net.UDPAddr
	local *net.UDPAddr

	// OnMessage 收到「不是回给我正在等的这一条」的报文时叫这里 ——
	// 注册之后平台发来的 Catalog 查询就走这条路进来。
	// ★ 不能默默丢掉：它来问本机通道表，正是「这台平台认下这个设备了」的最硬证据。
	OnMessage func(msg *Message, from *net.UDPAddr)

	cseq uint64
}

// DialClient 连到 host:port 发 SIP。★ 用 DialUDP 而不是 ListenUDP+WriteTo：
// 上面说的那层「关着的口 vs 没人答」的分辨全靠它。
func DialClient(host, port string) (*Client, error) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, &Error{Stage: "dial", Kind: KindDial,
			Detail: fmt.Sprintf("对端地址 %s:%s 解析不了", host, port), Err: err}
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, &Error{Stage: "dial", Kind: KindDial, Detail: "本机起这个 UDP 套接字没成", Err: err}
	}
	l, _ := conn.LocalAddr().(*net.UDPAddr)
	return &Client{conn: conn, peer: raddr, local: l}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// LocalHost / LocalPort 是本机这一头**实际用到**的地址与口。
// Via 与 Contact 按它写，不按配置里那个：绑在通配地址上时，
// 配置的口和内核真用的口经常不是一回事，写错了平台回包就发给一个没人听的口。
func (c *Client) LocalHost() string {
	if c.local == nil {
		return ""
	}
	return c.local.IP.String()
}

func (c *Client) LocalPort() string {
	if c.local == nil {
		return ""
	}
	return fmt.Sprint(c.local.Port)
}

// Peer 是对端地址。
func (c *Client) Peer() *net.UDPAddr { return c.peer }

// NextCSeq 给下一个 CSeq。★ 只增不减、不回绕：序号退回去，
// 平台会当这是重复请求，然后什么都不回，现场就成了「设备说发了、平台说没收到」。
func (c *Client) NextCSeq() uint64 {
	c.cseq++
	return c.cseq
}

// Send 发一条已经编好字节、且确定发给这个对端的报文。
func (c *Client) Send(raw []byte) error {
	if _, err := c.conn.Write(raw); err != nil {
		return &Error{Stage: "send", Kind: KindDial, Detail: "本机发不出去", Err: err}
	}
	return nil
}

// Reply 是一次问答的账。
type Reply struct {
	Final *Message
	// Interims 是那些 1xx。★ 留着是因为「一句 100 都没收到」与
	// 「收到 100 Trying 之后最终响应超时」下一步完全不同：前者是它压根没理这一句。
	Interims []*Message
	Sent     int
	Elapsed  time.Duration
	Started  time.Time
}

// Request 发一条请求并等最终响应。
//
// timeout 是这一问的总预算；预算内按 500ms 起、每次翻倍重发**同一串字节**
// （★ branch、CSeq、Call-ID 必须一字不差，改了就成新的一趟事务，
// 平台会把前一趟挂着不放）。匹配不上号的报文交给 OnMessage，不算这一问的答案。
func (c *Client) Request(req *Message, stage string, timeout time.Duration) (*Reply, error) {
	raw, err := req.Bytes()
	if err != nil {
		return nil, &Error{Stage: stage, Kind: KindLocal, Detail: "这条报文自己就编不出去", Err: err}
	}
	callID := req.CallID()
	seq, method, hasSeq := req.CSeq()
	branch := req.TopViaBranch()
	if !hasSeq {
		return nil, &Error{Stage: stage, Kind: KindLocal, Detail: "这条请求没带能用的 CSeq"}
	}
	started := time.Now()
	if err := c.Send(raw); err != nil {
		return nil, err
	}
	reply := &Reply{Sent: 1, Started: started}
	wait := 500 * time.Millisecond
	deadline := started.Add(timeout)
	for {
		leg := time.Now().Add(wait)
		if leg.After(deadline) {
			leg = deadline
		}
		msg, rerr := c.readAt(leg)
		for rerr == nil && msg != nil {
			if msg.IsRequest() || !matches(msg, callID, seq, method, branch) {
				c.dispatch(msg)
				// 不是这一问的答：剩下的预算继续等，但不重发（发过了）。
				if time.Now().After(deadline) {
					break
				}
				msg, rerr = c.readAt(deadline)
				continue
			}
			if msg.Status < 200 {
				reply.Interims = append(reply.Interims, msg)
				if time.Now().After(deadline) {
					break
				}
				msg, rerr = c.readAt(deadline)
				continue
			}
			reply.Final = msg
			reply.Elapsed = time.Since(started)
			if msg.Status >= 400 {
				return reply, &Error{Stage: stage, Kind: KindStatus, Status: msg.Status,
					Detail: fmt.Sprintf("%s 回了 %d %s", method, msg.Status, msg.Reason)}
			}
			return reply, nil
		}
		if rerr != nil && !isTimeoutErr(rerr) {
			kind := KindDial
			detail := "本机这个 UDP 套接字读不下去了"
			switch {
			case isRefused(rerr):
				kind = KindRefused
				detail = "对端回了不可达（这个口上是关的）"
			case KindOf(rerr) == KindNotSIP:
				kind = KindNotSIP
				detail = rerr.Error()
			case KindOf(rerr) == KindBadMessage:
				kind = KindBadMessage
				detail = rerr.Error()
			}
			return reply, &Error{Stage: stage, Kind: kind, Detail: detail, Err: unwrapOf(rerr)}
		}
		if time.Now().After(deadline) {
			return reply, &Error{Stage: stage, Kind: KindTimeout,
				Detail: fmt.Sprintf("发了 %d 次，%s 之内没有任何回音", reply.Sent, timeout)}
		}
		if err := c.Send(raw); err != nil {
			return reply, err
		}
		reply.Sent++
		wait *= 2
	}
}

// WaitFor 在一段时间里继续读：匹配的收进来说话，其余交给 OnMessage。
// 用于「注册成功之后，看平台有没有回头来问本机通道表」那一段。
func (c *Client) WaitFor(d time.Duration, match func(*Message) bool) []*Message {
	var out []*Message
	deadline := time.Now().Add(d)
	for {
		msg, err := c.readAt(deadline)
		if isTimeoutErr(err) {
			return out
		}
		if err != nil {
			// 不像 SIP / 读坏了：这一条不结束整个窗口，但也不能原样吞掉 ——
			// 交给 OnMessage，由它记账（否则「有人在往这个口上打东西」就成了看不见的洞）。
			if msg != nil {
				c.dispatch(msg)
			}
			if KindOf(err) == KindTimeout || time.Now().After(deadline) {
				return out
			}
			continue
		}
		if msg == nil {
			if time.Now().After(deadline) {
				return out
			}
			continue
		}
		if match != nil && !match(msg) {
			c.dispatch(msg)
			continue
		}
		out = append(out, msg)
	}
}

// Respond 回一条应答（本机扮设备时回平台的查询，或本机当平台时回设备的注册）。
// ★ 目的地址用这一条报文的**实际来路**，不用配置里那个：平台常从它自己的另一个口
// 发查询，照配置回去就是发给一个没在等的地址，表现成「答了，它还是说没收到」。
//
// 连好的套接字只能写给对端，所以这里必须分流：来路就是那个对端时直接 Write
// （★ 不能用 WriteToUDP —— 内核当场拒成 "use of WriteTo with pre-connected
// connection"，这条路径一跑就死）；来路不是对端时如实报错，不许默默发出去。
// 反过来「谁的包都能答」的是服务端那一头，它用未连的套接字（见 listen.go）。
func (c *Client) Respond(resp *Message, to *net.UDPAddr) error {
	raw, err := resp.Bytes()
	if err != nil {
		return &Error{Stage: "respond", Kind: KindLocal, Detail: "这条应答编不出去", Err: err}
	}
	if to == nil || sameUDPAddr(to, c.peer) {
		if _, err := c.conn.Write(raw); err != nil {
			return &Error{Stage: "respond", Kind: KindDial, Detail: "本机发不出去这条应答", Err: err}
		}
		return nil
	}
	return &Error{Stage: "respond", Kind: KindLocal, Detail: fmt.Sprintf(
		"这个套接字连在 %s 上，答不回 %s —— 这条报文不是从它连的那个地址来的",
		c.peer, to)}
}

// sameUDPAddr 比地址与口。IP 一边写成 127.0.0.1 一边写成 ::ffff:127.0.0.1
// 是同一处（net 包两头都可能给成这种形状），所以比的是 16 字节形态。
func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	if a.IP.Equal(b.IP) {
		return true
	}
	return a.IP.To16() != nil && b.IP.To16() != nil && a.IP.To16().Equal(b.IP.To16())
}

func (c *Client) dispatch(msg *Message) {
	if c.OnMessage != nil {
		c.OnMessage(msg, c.peer)
	}
}

// readAt 在 deadline 之前读一条报文。到点给带 timeout 的 error。
func (c *Client) readAt(deadline time.Time) (*Message, error) {
	left := time.Until(deadline)
	if left <= 0 {
		return nil, errReadTimeout
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(left)); err != nil {
		return nil, err
	}
	buf := make([]byte, sipMaxDatagram)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	raw := buf[:n]
	if !looksLikeSIP(raw) {
		return nil, &Error{Stage: "read", Kind: KindNotSIP,
			Detail: "来的内容不像 SIP：" + peekText(raw)}
	}
	msg, err := Parse(raw)
	if err != nil {
		return nil, &Error{Stage: "read", Kind: KindBadMessage, Detail: err.Error(), Err: err}
	}
	return msg, nil
}

const sipMaxDatagram = 65536

// errReadTimeout 自己造一条，免得每轮都去问 net 包「这算不算超时」。
var errReadTimeout = &net.OpError{Op: "read", Net: "udp", Err: timeoutError{}}

type timeoutError struct{}

func (timeoutError) Error() string   { return "gb28181: 读这条 UDP 套接字到点了" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// looksLikeSIP 只看起始行像不像 SIP/2.0。★ 不用「能不能解析完整」当判据：
// 同一个口上开着 HTTP 时，那句 "HTTP/1.1 400 Bad Request" 也读得动半截，
// 那一条要报成「这不是 SIP」，不是「SIP 报文读坏了」。
func looksLikeSIP(raw []byte) bool {
	s := string(raw)
	if i := indexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.Contains(strings.ToUpper(strings.TrimSpace(s)), "SIP/2.0")
}

func indexAny(s, chars string) int {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return i
			}
		}
	}
	return -1
}

// peekText 给一段可打印的头部，够认出「这是 HTTP、TLS 还是别的」。
// ★ 截断并且过滤控制字符：这一段会进结果、进日志，
// 不能把对端随便吐出来的字节原样带出去。
func peekText(raw []byte) string {
	const max = 48
	var b []rune
	for _, r := range string(raw) {
		if len(b) >= max {
			return string(b) + "…"
		}
		switch {
		case r == '\r' || r == '\n':
			b = append(b, '␍', '␊')
		case r < 0x20 || r == 0x7f:
			b = append(b, '·')
		default:
			b = append(b, r)
		}
	}
	return string(b)
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// unwrapOf 从 *Error 里把底层 errno 拿出来，避免套两层 Error。
func unwrapOf(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return e.Err
	}
	return err
}

// matches 认这条响应是不是正在等的这一条：Call-ID、CSeq 的方法与序号、
// 第一条 Via 的 branch 三条都对上才算。
//
// ★ branch 不能省：超时重发之后平台对**上一趟**的回包才到，
// 不核 branch 就把「它答得慢」记成了「这一趟它答得快」。
func matches(resp *Message, callID string, seq uint64, method, branch string) bool {
	if resp.IsRequest() || callID == "" {
		return false
	}
	if resp.CallID() != callID {
		return false
	}
	rseq, rmethod, ok := resp.CSeq()
	if !ok || rmethod != method || rseq != seq {
		return false
	}
	if branch != "" {
		return resp.TopViaBranch() == branch
	}
	return true
}
