package snmp

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPort 是 SNMP 的公认端口（161）。设备的 SNMP 栏很多写死了它。
const DefaultPort = 161

// ErrNoReply 是「问了没回」。
//
// ★★ 这一条的话必须把三种病一起摆出来，因为它们在报文层面**长得一模一样**：
//
//	团体名不对（v2c 不报错，直接丢）、防火墙/ACL 没放行、设备压根没开 SNMP。
//	只说「超时」的话，现场会去查第三和第二种，而最常见的其实是第一种。
var ErrNoReply = errors.New("snmp: 没有回话")

// Unmatched 是「收到了东西，但没算成答案」的条数。
type Unmatched struct {
	WrongID   int // 回包里的请求标识对不上：路上有第二台在答，或者这台实现有问题
	WrongHost int // 不是我们点名的那台答的
	NotReply  int // 是报文但不是响应（设备上往我们这台推 trap 时最常见）
}

// Any 有没有收到过任何东西。
func (u Unmatched) Any() bool { return u.WrongID+u.WrongHost+u.NotReply > 0 }

// NoReplyError 是「没回话」这一类失败的完整形状。
//
// ★★ 为什么不直接返回 ErrNoReply 就完了：「一条包都没回来」和「回来几条但对不上号」
//
//	在「超时」两个字上一样，可查的方向相反 —— 前者查防火墙、团体名、设备没开 SNMP，
//	后者说明路上有东西在答话（第二台冒充，或者这台在往我们推 trap）。
//	不把这个分出来，界面上就只能说「三种可能都有」，而现场其实已经能排除一种。
//
// Unwrap 到 ErrNoReply，所以 errors.Is 那条老写法照旧成立。
type NoReplyError struct {
	Addr  string // 实际发去了哪儿（端口补齐后的）
	Tries int    // 一共问了几次
	Seen  Unmatched
}

func (e *NoReplyError) Error() string {
	return fmt.Sprintf("%v（%s，问了 %d 次）%s", ErrNoReply, e.Addr, e.Tries, e.Seen.Note())
}

func (e *NoReplyError) Unwrap() error { return ErrNoReply }

// ClientVersion 是客户端这一侧的版本选择。
//
// ★★ 这里的编号和报文里的**不一样**，是故意反过来的：
//
//	报文里 v1 = 0、v2c = 1，而 Go 的零值也是 0 —— 照搬的话
//	「忘了填版本」就等于「用 v1」，可现场绝大多数设备是 v2c。
//	少填一个字段就全体问不通，这种默认不能留。
//	所以：零值 = v2c，要 v1 得显式写。发出去的号由 wire() 换算。
type ClientVersion int

const (
	V2c ClientVersion = iota // 不填就是 v2c
	V1                       // 只认 v1 的老交换机，以及 SNMPv1 的 trap
)

func (v ClientVersion) wire() int {
	if v == V1 {
		return Version1
	}
	return Version2c
}

// Client 是一个 SNMPv2c 客户端。
//
// ★ 一个 Client 一条连接：walk 一棵树要发几十上百个请求，
//
//	每次重新拨号的话，源端口一变，某些设备的会话表会把它当成新的管理器反复登记。
type Client struct {
	Addr      string // host 或 host:port；不给端口按 161
	Community string
	Version   ClientVersion
	LocalAddr string // 从本机哪个地址出去（多网卡机器上这一条决定设备答不答）
	Timeout   time.Duration
	Retries   int

	mu   sync.Mutex
	conn net.PacketConn
	addr *net.UDPAddr

	id   int32
	done bool
}

// 默认值：超时 1 秒、重传 2 次。这是 SNMP 管理器的常规量级 ——
// 太短会让跨广域网的设备「有时答有时不答」，太长会让现场干等。
func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return time.Second
}

func (c *Client) retries() int {
	if c.Retries > 0 {
		return c.Retries
	}
	return 2
}

func (c *Client) version() int { return c.Version.wire() }

// resolve 把地址补齐并按 LocalAddr 拨一条连接。
//
// ★ LocalAddr 解不开要**当场失败**，不许退化成「不绑」：
//
//	退化的意思是这台机器其余每一块网卡都可能成为出口，
//	而指定网卡的意义正是「别从办公口/公网口出去」。filesrv 那边踩过同一条。
func (c *Client) dialLocked() (net.PacketConn, *net.UDPAddr, error) {
	if c.done {
		return nil, nil, errors.New("snmp: 这个客户端已经关掉了")
	}
	host := strings.TrimSpace(c.Addr)
	if host == "" {
		return nil, nil, fmt.Errorf("snmp: 没给设备地址")
	}
	if c.addr == nil {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, strconv.Itoa(DefaultPort))
		}
		ra, err := net.ResolveUDPAddr("udp", host)
		if err != nil {
			return nil, nil, fmt.Errorf("snmp: 设备地址 %q 解不开：%w", c.Addr, err)
		}
		c.addr = ra
	}
	if c.conn != nil {
		return c.conn, c.addr, nil
	}
	la := &net.UDPAddr{}
	if c.LocalAddr != "" {
		var err error
		la, err = net.ResolveUDPAddr("udp", net.JoinHostPort(c.LocalAddr, "0"))
		if err != nil {
			return nil, nil, fmt.Errorf("snmp: 本机没有 %s 这个地址（%v）", c.LocalAddr, err)
		}
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, nil, fmt.Errorf("snmp: 起不了本地端口：%w", err)
	}
	c.conn = conn
	return conn, c.addr, nil
}

// Close 放掉连接。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done = true
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	return nil
}

// nextID 取一个正的请求标识。
//
// ★ 两条都要守：
//
//	必须正 —— BER 的 INTEGER 是补码，最高位给 1 设备读回来是负数，
//	对不上我们记的那个号，表现成「每次请求都超时」，最难查的一种；
//	起点要随机 —— 请求标识是这台机器上**唯一**能区分「这条回包是回给我这次问的」的号，
//	固定从 1 开始的话，隔壁一个进程同一秒问的报文能互相串上。
func (c *Client) nextID() int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.id == 0 {
		var b [4]byte
		if _, err := crand.Read(b[:]); err != nil {
			c.id = int32(time.Now().UnixNano()&0x3fffffff) + 1
		} else {
			c.id = int32(binary.BigEndian.Uint32(b[:])&0x3fffffff) + 1
		}
	} else {
		c.id++
	}
	return c.id
}

// Do 发一个请求并等回话（含重传）。
func (c *Client) Do(ctx context.Context, p Packet) (Packet, error) {
	c.mu.Lock()
	conn, ra, err := c.dialLocked()
	c.mu.Unlock()
	if err != nil {
		return Packet{}, err
	}
	p.Version = c.version()
	if p.Community == "" {
		p.Community = c.Community
	}
	if p.ID == 0 {
		p.ID = c.nextID()
	}
	b, err := p.Marshal()
	if err != nil {
		return Packet{}, err
	}

	tries := c.retries() + 1
	var lastErr error
	var dropped miss
	for i := 0; i < tries; i++ {
		if err := ctx.Err(); err != nil {
			return Packet{}, err
		}
		deadline := time.Now().Add(c.timeout())
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return Packet{}, err
		}
		if _, err := conn.WriteTo(b, ra); err != nil {
			lastErr = fmt.Errorf("snmp: 发不出去：%w", err)
			continue
		}
		// ★ 等回包这段时间里 ctx 也可能被取消（界面上按了「停止」）。
		//   挂一个看门狗把读截止时间推到当下，让 ReadFrom 立刻回来 ——
		//   否则一次 walk 还剩几十趟，停止按钮要等最后一个超时才管用。
		stop := watchCancel(ctx, conn)
		got, lost, err := c.readMatch(conn, ra, p.ID, deadline)
		stop()
		dropped.add(lost)
		if cerr := ctx.Err(); cerr != nil {
			return Packet{}, cerr
		}
		if err == nil {
			return got, nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Packet{}, err
		}
		lastErr = err
		if errors.Is(err, ErrNoReply) {
			// 没回话才重传；设备答了一句但答得不对，重传只是把同一个错再要一遍。
			continue
		}
		return got, err
	}
	// 一次都没答 和 答了但读不懂 是两件事：前者要查防火墙和团体名，
	// 后者是我们这边的解析要修，别把两种并成一句「超时」。
	// 地址报的是**补齐端口之后**那个：只写 "192.168.1.1" 的话，
	// 人不知道我们其实发去了 161，会去查一个根本没碰过的端口。
	if lastErr != nil && !errors.Is(lastErr, ErrNoReply) {
		return Packet{}, fmt.Errorf("snmp: 问了 %d 次都没成（%s）：%w", tries, ra.String(), lastErr)
	}
	return Packet{}, &NoReplyError{Addr: ra.String(), Tries: tries, Seen: dropped.seen()}
}

// watchCancel 在 ctx 取消的那一瞬间把连接的读截止时间推到当下。
//
// 返回的函数必须调用（defer 或紧跟其后），否则 goroutine 会留到下一次读超时。
// 推到当下是安全的：readMatch 每次进循环都自己设截止时间，
// 就算这条晚了一步，也会被下一次设的覆盖掉。
func watchCancel(ctx context.Context, conn net.PacketConn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

// miss 记下「收到了回包但没算数」的几种原因，读的时候汇成 Unmatched 给外面。
type miss struct {
	wrongID   int
	wrongHost int
	notReply  int
}

func (m *miss) add(o miss) {
	m.wrongID += o.wrongID
	m.wrongHost += o.wrongHost
	m.notReply += o.notReply
}

func (m miss) seen() Unmatched {
	return Unmatched{WrongID: m.wrongID, WrongHost: m.wrongHost, NotReply: m.notReply}
}

// Note 把「对不上号」那几条说成人话，给上面拼判定用。
func (u Unmatched) Note() string {
	var why []string
	if u.WrongID > 0 {
		why = append(why, fmt.Sprintf("%d 条回包的请求标识对不上", u.WrongID))
	}
	if u.WrongHost > 0 {
		why = append(why, fmt.Sprintf("%d 条不是这台设备答的", u.WrongHost))
	}
	if u.NotReply > 0 {
		why = append(why, fmt.Sprintf("%d 条不是响应报文", u.NotReply))
	}
	if len(why) == 0 {
		return ""
	}
	return "；" + strings.Join(why, "、") + "，都没有算数（有回包，但对不上号）"
}

// readMatch 读到一条**标识对得上**的响应为止，顺带记下丢掉了多少条对不上的。
//
// ★ 标识对不上就丢掉继续读，不能直接返回：重传之后旧请求的迟到回包
//
//	会从同一个口进来，认了它等于把 A 栏的值报成 B 栏 —— 界面上完全看不出来。
func (c *Client) readMatch(conn net.PacketConn, from net.Addr, id int32, deadline time.Time) (Packet, miss, error) {
	var lost miss
	buf := make([]byte, maxPDULen)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return Packet{}, lost, err
		}
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return Packet{}, lost, ErrNoReply
			}
			return Packet{}, lost, err
		}
		if !sameHostPort(peer, from) {
			// 不是我们要的那台设备答的：丢掉。冒充的响应不能算数。
			lost.wrongHost++
			continue
		}
		p, perr := Parse(buf[:n])
		if perr != nil {
			return Packet{}, lost, perr
		}
		if p.PDU != PDUGetResponse {
			// _trap 报文会从同一个口进来（设备上配了 trap 目标是我们这台时尤其常见）。
			// 它不是我们要的答案，但是**设备活着**的证据 —— 所以记一笔，别当成没回话。
			lost.notReply++
			continue
		}
		if p.ID != id {
			lost.wrongID++
			continue
		}
		if p.ErrStatus != 0 {
			bad := ""
			if p.ErrIndex > 0 && p.ErrIndex <= len(p.VarBinds) {
				bad = p.VarBinds[p.ErrIndex-1].OID
			}
			return p, lost, &Error{Status: p.ErrStatus, Index: p.ErrIndex, OID: bad}
		}
		return p, lost, nil
	}
}

func sameHostPort(a, b net.Addr) bool {
	ah, ap, aerr := net.SplitHostPort(a.String())
	bh, bp, berr := net.SplitHostPort(b.String())
	if aerr != nil || berr != nil {
		return false
	}
	return ah == bh && ap == bp
}

// Get 一次问几栏。
func (c *Client) Get(ctx context.Context, oids ...string) ([]VarBind, error) {
	p, err := NewGet(c.Community, oids...)
	if err != nil {
		return nil, err
	}
	r, err := c.Do(ctx, p)
	if err != nil {
		return nil, err
	}
	return r.VarBinds, nil
}

// GetOne 问一栏，直接给那一栏的值。
func (c *Client) GetOne(ctx context.Context, oid string) (VarBind, error) {
	vs, err := c.Get(ctx, oid)
	if err != nil {
		return VarBind{}, err
	}
	if len(vs) != 1 {
		return VarBind{}, fmt.Errorf("snmp: 问了一栏，回来 %d 栏", len(vs))
	}
	return vs[0], nil
}

// GetNext 问「这些 OID 的下一栏是谁」。walk 一步一步走用的就是它，
// 不是 Get —— Get 问的是精确那一栏，拿它走表会把第一行读成「没有这一栏」。
func (c *Client) GetNext(ctx context.Context, oids ...string) ([]VarBind, error) {
	p, err := NewGetNext(c.Community, oids...)
	if err != nil {
		return nil, err
	}
	r, err := c.Do(ctx, p)
	if err != nil {
		return nil, err
	}
	return r.VarBinds, nil
}

// MaxRepetitions 是 GETBULK 一轮要几行。
//
// ★ 25 是个折中：再大就有一批老设备的 max-pdu-size 装不下，它会**直接丢包**，
//
//	症状是「walk 到某一张表就没反应」，而人只会以为那张表是空的。
const MaxRepetitions = 25

// Walk 沿着一棵子树把每一栏读回来（读到底）。
//
// 表大到只关心前若干行时用 WalkLimit：一次完整的 MAC 表可能是几万行，
// 那会让「看一眼」变成几分钟的请求。
func (c *Client) Walk(ctx context.Context, prefix string) ([]VarBind, error) {
	out, _, err := c.walk(ctx, prefix, 0)
	return out, err
}

// WalkLimit 读到 want 栏就收口（want <= 0 = 不限量），第二个返回值表示**确实还有剩下的没读**。
//
// ★ 到了量之后要多问一次 GETNEXT 才敢报「被截断」：
//
//	刚好停在表末尾时说「后面还有」是谎话，而调用方会照着这句话去查一台没毛病的管理进程。
//	这一条请求只在撞上限时才发，正常路径不多花时间。
func (c *Client) WalkLimit(ctx context.Context, prefix string, want int) ([]VarBind, bool, error) {
	return c.walk(ctx, prefix, want)
}

func (c *Client) walk(ctx context.Context, prefix string, want int) ([]VarBind, bool, error) {
	prefix = strings.TrimPrefix(strings.TrimSpace(prefix), ".")
	if prefix == "" {
		return nil, false, fmt.Errorf("snmp: walk 要给一个子树前缀")
	}
	if c.version() == Version1 {
		return c.walkNext(ctx, prefix, want)
	}
	var out []VarBind
	cur := prefix
	for {
		if err := ctx.Err(); err != nil {
			return out, false, err
		}
		p, err := NewBulk(c.Community, 0, MaxRepetitions, cur)
		if err != nil {
			return out, false, err
		}
		r, err := c.Do(ctx, p)
		if err != nil {
			// 设备不认 GETBULK（回 tooBig 或者干脆没辙）时退回 GETNEXT，
			// 而不是让整个 walk 失败：树还是要走完。
			if isTooBig(err) {
				return c.walkNext(ctx, prefix, want)
			}
			return out, false, err
		}
		if len(r.VarBinds) == 0 {
			break
		}
		progressed := false
		for _, v := range r.VarBinds {
			if v.EndOfMib() {
				return out, false, nil
			}
			// ★ 先看有没有往前走，再看还在不在树里：
			//   「原地不动」和「走到树外面」都是收口，但只有前者是设备的毛病，
			//   当成正常结束的话 walk 会安静地少一整张表，而界面上是「这台设备没有端口」。
			if CmpOID(v.OID, cur) <= 0 {
				return out, false, fmt.Errorf("snmp: 设备在 %s 处没有往前走（下一栏它给的是 %s），walk 停在这里", cur, v.OID)
			}
			if !OIDUnder(v.OID, prefix) {
				return out, false, nil
			}
			out = append(out, v)
			cur = v.OID
			progressed = true
			if want > 0 && len(out) >= want {
				trunc, err := c.hasMore(ctx, prefix, cur)
				return out, trunc, err
			}
		}
		if !progressed {
			return c.walkNext(ctx, prefix, want)
		}
	}
	return out, false, nil
}

// hasMore 问一栏「cur 后面树里还有东西吗」。问不动就算没探到，
// 宁可少报一次截断，也不拿一个查不出原因的失败让整个 walk 作废。
func (c *Client) hasMore(ctx context.Context, prefix, cur string) (bool, error) {
	vs, err := c.GetNext(ctx, cur)
	if err != nil || len(vs) == 0 {
		return false, nil
	}
	return OIDUnder(vs[0].OID, prefix) && !vs[0].EndOfMib(), nil
}

func isTooBig(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == 1
}

// walkNext 用 GETNEXT 一步一步走：v1 设备和不肯配合 GETBULK 的设备走这条。
func (c *Client) walkNext(ctx context.Context, prefix string, want int) ([]VarBind, bool, error) {
	var out []VarBind
	cur := prefix
	for {
		if err := ctx.Err(); err != nil {
			return out, false, err
		}
		vs, err := c.GetNext(ctx, cur)
		if err != nil {
			// GETNEXT 在 v1 里「走到头」是用 error-status=noSuchName 表达的，
			// 这一条要当收口，不能当失败 —— 否则每张表末尾都白报一次错。
			var e *Error
			if errors.As(err, &e) && e.Status == 2 && len(out) > 0 {
				return out, false, nil
			}
			return out, false, err
		}
		if len(vs) == 0 {
			return out, false, nil
		}
		v := vs[0]
		if v.EndOfMib() {
			return out, false, nil
		}
		// 和 GETBULK 那条同样的顺序：先确认它往前走了，再判断还在不在树里。
		if CmpOID(v.OID, cur) <= 0 {
			return out, false, fmt.Errorf("snmp: 设备在 %s 处没有往前走（下一栏它给的是 %s），walk 停在这里", cur, v.OID)
		}
		if !OIDUnder(v.OID, prefix) {
			return out, false, nil
		}
		out = append(out, v)
		cur = v.OID
		if want > 0 && len(out) >= want {
			trunc, err := c.hasMore(ctx, prefix, cur)
			return out, trunc, err
		}
	}
}
