package throughput

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Options 是一次对测要定的事。
type Options struct {
	Host    string
	Port    int
	Mode    string        // up / down / both
	Seconds int           // 每个方向跑多久
	Timeout time.Duration // 连接与握手那一步的超时
	Chunk   int           // 一帧多少字节，0 用默认
}

// Sample 是曲线上一个点。★ 平均数会骗人：稳定 900 Mbps，与 1800/0 交替两秒，
//
//	平均值一模一样 —— 而现场要看的正是「它是稳的还是一阵一阵」。
type Sample struct {
	AtMs int64   `json:"atMs"`
	MBps float64 `json:"mbps"`
}

// Direction 是一个方向上问出来的东西。
type Direction struct {
	Bytes     int64    `json:"bytes"`
	ElapsedMs int64    `json:"elapsedMs"`
	MBps      float64  `json:"mbps"`
	PeerBytes int64    `json:"peerBytes"`     // 对面那侧数到/写出多少
	PeerMs    int64    `json:"peerElapsedMs"` // 对面那侧花了多久
	Truncated bool     `json:"truncated"`     // 撞到对面的上限，没跑满要说的量
	Samples   []Sample `json:"samples"`
	Fault     string   `json:"fault,omitempty"`
	// TCP 是这条连接在自己那条向上的内核账。★ 只在这条连接还开着的时候取：
	// 传完就关掉再另连一条，问回来的是另一条连接的空闲状态，与刚才那一段无关。
	TCP TCPInfo `json:"tcpInfo"`
}

// RTT 是若干次往返的账。★ 空载与带载分开量：只看带载那一个数，
//
//	分不清「链路本来就慢」还是「一打流队列就囤起来」。
type RTT struct {
	Count    int     `json:"count"`
	MinMs    float64 `json:"minMs"`
	AvgMs    float64 `json:"avgMs"`
	MaxMs    float64 `json:"maxMs"`
	JitterMs float64 `json:"jitterMs"`
	Fault    string  `json:"fault,omitempty"`
}

// Result 是一次对测问出来的全部东西。
type Result struct {
	Addr         string     `json:"addr"`
	Mode         string     `json:"mode"`
	Seconds      int        `json:"seconds"`
	PeerMaxBytes int64      `json:"peerMaxBytes"`
	Up           *Direction `json:"up,omitempty"`
	Down         *Direction `json:"down,omitempty"`
	Idle         RTT        `json:"rttIdle"`
	Loaded       RTT        `json:"rttLoaded"`
}

// Error 带着「死在哪一步」：同样是超时，握手不回和跑到一半断，下一步完全不同。
type Error struct {
	Kind  string // dial / handshake / proto / busy / io / timeout
	Stage string
	Err   error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Kind + "：" + e.Stage
	}
	return e.Kind + "（" + e.Stage + "）：" + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

const (
	defaultChunk  = 256 << 10 // 256 KiB：够摊薄每帧刷新的开销，又不至于让采样点之间差一整秒
	sampleEvery   = 200 * time.Millisecond
	pingFrameSize = 8
	idlePings     = 10
	loadPingEvery = 100 * time.Millisecond
	// pingIOTimeout 是往返那一次读写的兜底：对面不回话时别把整次对测挂死。
	pingIOTimeout = 2 * time.Second
	statsWait     = 3 * time.Second
)

// Run 打一次对测。★ ctx 到点时正在跑的传输会带着「已经走了多少」退出来，
//
//	而不是什么数都拿不到 —— 半截的账也是账，只要明说是半截。
func Run(ctx context.Context, o Options) (Result, error) {
	if o.Host == "" {
		return Result{}, &Error{Kind: "dial", Stage: "参数", Err: errors.New("没给对端地址")}
	}
	if o.Seconds <= 0 {
		o.Seconds = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Chunk <= 0 || o.Chunk > maxFrame {
		o.Chunk = defaultChunk
	}
	if o.Mode == "" {
		o.Mode = "both"
	}
	addr := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	res := Result{Addr: addr, Mode: o.Mode, Seconds: o.Seconds}

	// 空载往返先量：带载那一次要拿它当对照。
	pingConn, pingBr, err := dialPing(ctx, addr, o.Timeout)
	if err == nil {
		res.Idle = measureRTT(pingConn, pingBr, idlePings, 50*time.Millisecond)
		_ = pingConn.Close()
	} else {
		return res, err
	}

	var loadPing *RTT
	switch o.Mode {
	case "up":
		res.Up, res.PeerMaxBytes, loadPing = runUp(ctx, addr, o)
	case "down":
		res.Down, res.PeerMaxBytes, loadPing = runDown(ctx, addr, o)
	case "both":
		up, upMax, upPing := runUp(ctx, addr, o)
		down, downMax, downPing := runDown(ctx, addr, o)
		res.Up, res.Down = up, down
		res.PeerMaxBytes = upMax
		if downMax > 0 && (res.PeerMaxBytes == 0 || downMax < res.PeerMaxBytes) {
			res.PeerMaxBytes = downMax
		}
		loadPing = worseRTT(upPing, downPing)
	default:
		return res, &Error{Kind: "handshake", Stage: "参数",
			Err: fmt.Errorf("只认 up / down / both，给的是 %q", o.Mode)}
	}
	if loadPing != nil {
		res.Loaded = *loadPing
	}
	return res, firstFault(res.Up, res.Down)
}

func firstFault(up, down *Direction) error {
	for _, d := range []*Direction{up, down} {
		if d != nil && d.Fault != "" {
			return &Error{Kind: "io", Stage: d.Fault, Err: errors.New(d.Fault)}
		}
	}
	return nil
}

func worseRTT(a, b *RTT) *RTT {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.AvgMs > a.AvgMs {
		return b
	}
	return a
}

// newNonce 给一个会话编号。★ 用 crypto/rand：这一格的作用是「把晚到的上一轮回执
//
//	认出来」，编号可猜就等于这一道闸没关上。
func newNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return strconv.FormatUint(binary.BigEndian.Uint64(b[:]), 36)
}

// dialPing 连一条只做往返的线，并走完 ping 握手。
//
// ★ 每次测都新连一条：复用旧线会把上一轮的内核缓冲余温算进这一轮的往返里。
//
// ★ 握手那个读缓冲要一起交回去，别为后面另起一个：对面提前吐过字节的话，
// 那些字节就永远留在没人再看的旧缓冲里。
//
// ★ 这一条不是修 bug —— 回音弹不回来的真正毛病在对面的 flush（见 sink.go 的
// echo），把 reader 换成新的实测照样全绿；留着它是免得日后有人在这里另起一个。
func dialPing(ctx context.Context, addr string, to time.Duration) (net.Conn, *bufio.Reader, error) {
	c, err := dial(ctx, addr, to)
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReader(c)
	nonce := newNonce()
	// ★ 握手这一步必须有截止时间：对面光是把连接接着却不回话（口被别的程序占着），
	// 没有这一条就把整次对测挂在那里。
	_ = c.SetDeadline(time.Now().Add(to))
	if _, err := c.Write([]byte(requestLine(ModePing, 0, nonce))); err != nil {
		_ = c.Close()
		return nil, nil, &Error{Kind: "handshake", Stage: "ping", Err: err}
	}
	r, err := readReply(br, nonce)
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	_ = r
	// ★ 交还出去之前把截止清掉：留着的话，量到一半的往返会把这条线在半路上掐了。
	_ = c.SetDeadline(time.Time{})
	return c, br, nil
}

// measureRTT 打 count 次 8 字节往返。★ 一次都没回来不算「0 毫秒」，那是没问到。
func measureRTT(c net.Conn, br *bufio.Reader, count int, gap time.Duration) RTT {
	buf := make([]byte, pingFrameSize)
	echo := make([]byte, pingFrameSize+8)
	var samples []float64
	start := time.Now()
	for i := 0; i < count; i++ {
		for j := range buf {
			buf[j] = byte(i + j)
		}
		if err := c.SetDeadline(time.Now().Add(pingIOTimeout)); err != nil {
			return RTT{Fault: err.Error()}
		}
		if err := writeFrameBuf(c, buf); err != nil {
			return partial(samples, "发不出去："+err.Error())
		}
		if _, err := io.ReadFull(br, echo[:4]); err != nil {
			return partial(samples, "没等到回音："+err.Error())
		}
		n := int(uint32(echo[0])<<24 | uint32(echo[1])<<16 | uint32(echo[2])<<8 | uint32(echo[3]))
		if n != len(buf) {
			return partial(samples, fmt.Sprintf("弹回来的长度是 %d，不是 %d", n, len(buf)))
		}
		if _, err := io.ReadFull(br, echo[:n]); err != nil {
			return partial(samples, "回音读不全："+err.Error())
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000)
		start = time.Now()
		time.Sleep(gap)
	}
	_ = c.SetDeadline(time.Now().Add(pingIOTimeout))
	_ = writeFrameBuf(c, nil) // 说到结束，让对面那一路干净地收尾
	return summarizeRTT(samples)
}

// partial 把已经量到的那几次连同「断在哪」一起交出去。
//
// ★ 量到第 3 次断了不等于一次没量到；也别把平均值塞进最小值那一格。
func partial(samples []float64, fault string) RTT {
	r := summarizeRTT(samples)
	if r.Fault != "" {
		r.Fault = fault + "（" + r.Fault + "）"
		return r
	}
	r.Fault = fault
	return r
}

// writeFrameBuf 是不带缓冲的一帧写出（往返那一路用，图的是「现在就发」）。
func writeFrameBuf(w io.Writer, p []byte) error {
	var h [4]byte
	n := len(p)
	h[0] = byte(n >> 24)
	h[1] = byte(n >> 16)
	h[2] = byte(n >> 8)
	h[3] = byte(n)
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err := w.Write(p)
	return err
}

func summarizeRTT(samples []float64) RTT {
	if len(samples) == 0 {
		return RTT{Fault: "一次都没回来"}
	}
	r := RTT{Count: len(samples), MinMs: samples[0], MaxMs: samples[0]}
	var sum, prev float64
	for i, s := range samples {
		sum += s
		if s < r.MinMs {
			r.MinMs = s
		}
		if s > r.MaxMs {
			r.MaxMs = s
		}
		if i > 0 {
			d := s - prev
			if d < 0 {
				d = -d
			}
			r.JitterMs += d
		}
		prev = s
	}
	r.AvgMs = sum / float64(len(samples))
	if len(samples) > 1 {
		r.JitterMs /= float64(len(samples) - 1)
	}
	return r
}

// runUp 往上打。返回这一向、对面给的上限、以及带载往返。
func runUp(ctx context.Context, addr string, o Options) (*Direction, int64, *RTT) {
	d := &Direction{}
	c, err := dial(ctx, addr, o.Timeout)
	if err != nil {
		d.Fault = err.Error()
		return d, 0, nil
	}
	defer c.Close()
	br := bufio.NewReader(c)
	nonce := newNonce()
	_ = c.SetDeadline(time.Now().Add(o.Timeout))
	if _, err := c.Write([]byte(requestLine(ModeUp, 0, nonce))); err != nil {
		d.Fault = (&Error{Kind: "handshake", Stage: "up", Err: err}).Error()
		return d, 0, nil
	}
	r, err := readReply(br, nonce)
	if err != nil {
		d.Fault = err.Error()
		return d, 0, nil
	}
	payload := pattern(o.Chunk)
	deadline := time.Now().Add(time.Duration(o.Seconds) * time.Second)
	start := time.Now()
	sampleAt := start.Add(sampleEvery)
	var written int64
	load := newPingRunner(addr, o.Timeout)
	load.start()
	for {
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		if capped(r.maxBytes, written) {
			// ★ 对面在回执里就说了它最多收多少 —— 数到了我们自己收手，
			// 而不是等它把连接剪了：剪了之后那句「它数到多少」就再也问不到了。
			break
		}
		// 一帧最多等到「这一向该结束之后再三秒」：对面把窗口关死时，
		// 我们要带着已经写出去的那部分退出来，不是挂在这条线上。
		_ = c.SetWriteDeadline(deadline.Add(statsWait))
		if err := writeFrameBuf(c, payload); err != nil {
			if !capped(r.maxBytes, written) {
				d.Fault = (&Error{Kind: "io", Stage: "up", Err: err}).Error()
			}
			break
		}
		written += int64(len(payload))
		if !time.Now().Before(sampleAt) {
			appendSample(d, start, written)
			sampleAt = sampleAt.Add(sampleEvery)
		}
	}
	d.Truncated = capped(r.maxBytes, written)
	d.TCP = tcpInfoOf(c) // ★ 还开着的时候取：另连一条问回来的是另一条的账
	_ = c.SetDeadline(time.Now().Add(statsWait))
	_ = writeFrameBuf(c, nil)
	d.Bytes = written
	d.ElapsedMs = time.Since(start).Milliseconds()
	d.MBps = mbpsInt(written, d.ElapsedMs)
	// 先说我们这侧的账，再听对面的 —— 对面那句才是「链路上真到了多少」。
	if _, err := c.Write([]byte(statsLine(written, time.Since(start)))); err != nil {
		if d.Fault == "" && !d.Truncated {
			// 被上限截断的那一路，对面说完「到此为止」就可能先走：这一步失败不是毛病
			d.Fault = err.Error()
		}
	}
	if line, err := readLine(br); err == nil {
		if n, el, perr := parseStatsLine(line); perr == nil {
			d.PeerBytes, d.PeerMs = n, el.Milliseconds()
		}
	}
	ping := load.stop()
	return d, r.maxBytes, ping
}

// capped 说这一向是不是已经写到对面答应的上限了。
func capped(maxBytes, written int64) bool {
	return maxBytes > 0 && written >= maxBytes
}

// runDown 往下收。★ 到了时长由发起方喊停（同一条连接的反向写一个 STOP），
//
//	不然「跑多久」这件事只能变成「先猜一个字节数」—— 猜小了测不出稳态，猜大了白等。
func runDown(ctx context.Context, addr string, o Options) (*Direction, int64, *RTT) {
	d := &Direction{}
	c, err := dial(ctx, addr, o.Timeout)
	if err != nil {
		d.Fault = err.Error()
		return d, 0, nil
	}
	defer c.Close()
	br := bufio.NewReaderSize(c, maxFrame+16)
	nonce := newNonce()
	// 要的量先给一个大到没人能用完的数，真正的两个闸是「对面的上限」和「我们的 STOP」。
	// 给小了的话，本机回环上零点几秒就把这个数发完，测出来的是「要多少给多少」，
	// 而不是「这一条链路一秒能吃下多少」。
	want := int64(1) << 44
	_ = c.SetDeadline(time.Now().Add(o.Timeout))
	if _, err := c.Write([]byte(requestLine(ModeDown, want, nonce))); err != nil {
		d.Fault = (&Error{Kind: "handshake", Stage: "down", Err: err}).Error()
		return d, 0, nil
	}
	r, err := readReply(br, nonce)
	if err != nil {
		d.Fault = err.Error()
		return d, 0, nil
	}
	buf := make([]byte, maxFrame)
	deadline := time.Now().Add(time.Duration(o.Seconds) * time.Second)
	start := time.Now()
	sampleAt := start.Add(sampleEvery)
	var got int64
	stopping := false
	load := newPingRunner(addr, o.Timeout)
	load.start()
	for {
		// 对面中途不再发（或被防火墙把连接晾在半路）时，这一条保证我们带半截账退出来。
		_ = c.SetReadDeadline(deadline.Add(statsWait))
		frame, end, ferr := readFrame(br, buf)
		if ferr != nil {
			if errors.Is(ferr, io.EOF) && got > 0 {
				// 对面在我们喊停之前就把线断了：这是半截账，不是「收到 0」。
				d.Fault = (&Error{Kind: "io", Stage: "down",
					Err: fmt.Errorf("跑到一半对面断了（已收到 %d 字节）", got)}).Error()
			} else {
				d.Fault = (&Error{Kind: "io", Stage: "down", Err: ferr}).Error()
			}
			break
		}
		if end {
			break
		}
		got += int64(len(frame))
		if !stopping && !time.Now().Before(sampleAt) {
			appendSample(d, start, got)
			sampleAt = sampleAt.Add(sampleEvery)
		}
		if !stopping && (time.Now().After(deadline) || ctx.Err() != nil) {
			_, _ = c.Write([]byte("STOP\n"))
			stopping = true
			// ★ 喊完停不能转身就走：对面手里还有一帧在路上，它说完「到此为止」
			// 才会有那句账。现在去读，读到的是帧的字节，不是 STATS。
		}
	}
	d.TCP = tcpInfoOf(c)
	d.Bytes = got
	d.ElapsedMs = time.Since(start).Milliseconds()
	d.MBps = mbpsInt(got, d.ElapsedMs)
	// 收到对面截在自己上限上，与「跑满了我们说好的时长」是两件事：只有前者算截断。
	d.Truncated = r.maxBytes > 0 && got >= r.maxBytes
	_ = c.SetDeadline(time.Now().Add(statsWait))
	_, _ = c.Write([]byte(statsLine(got, time.Since(start))))
	if line, err := readLine(br); err == nil {
		if n, el, perr := parseStatsLine(line); perr == nil {
			d.PeerBytes, d.PeerMs = n, el.Milliseconds()
		}
	}
	ping := load.stop()
	return d, r.maxBytes, ping
}

// appendSample 记的是**这一段**的速率，不是「从开始到现在的平均」。
//
// ★ 平均速率的曲线永远是平的 —— 那样一条线看不出「稳定 900」与「1800/0 交替」。
func appendSample(d *Direction, start time.Time, count int64) {
	ms := time.Since(start).Milliseconds()
	if ms <= 0 || len(d.Samples) >= 600 {
		return
	}
	var prevAt int64
	var prevCount int64
	if n := len(d.Samples); n > 0 {
		prevAt = d.Samples[n-1].AtMs
		// 上一段的速率乘上一段时长就是当时的累计值，不必为它另留一格字段
		prevCount = int64(d.Samples[n-1].MBps*1e6/8*float64(ms-prevAt)/1000) + cumulative(d)
	}
	span := float64(ms-prevAt) / 1000
	if span <= 0 {
		return
	}
	rate := float64(count-prevCount) * 8 / span / 1e6
	d.Samples = append(d.Samples, Sample{AtMs: ms, MBps: round1(rate)})
}

// cumulative 把已记的区间速率还原成「到最后一个点为止一共走了多少字节」。
func cumulative(d *Direction) int64 {
	var total int64
	for i, s := range d.Samples {
		var at int64
		if i > 0 {
			at = d.Samples[i-1].AtMs
		}
		total += int64(s.MBps * 1e6 / 8 * float64(s.AtMs-at) / 1000)
	}
	return total
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}

func mbpsInt(count int64, ms int64) float64 {
	if ms <= 0 || count <= 0 {
		return 0
	}
	return round1(float64(count) * 8 / (float64(ms) / 1000) / 1e6)
}

func dial(ctx context.Context, addr string, to time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: to}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		kind := "dial"
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
			(errors.As(err, &ne) && ne.Timeout()) {
			kind = "timeout"
		}
		var ae *net.AddrError
		if errors.As(err, &ae) {
			kind = "dial" // 地址本身不成话（端口越界这类），别记成网络问题
		}
		return nil, &Error{Kind: kind, Stage: "connect", Err: err}
	}
	return c, nil
}

func readReply(br *bufio.Reader, nonce string) (reply, error) {
	line, err := readLine(br)
	if err != nil {
		// 等对面那一句时没读到，只有两种收场，下一步完全不同：
		// ① 表走到点了它还没回话 —— 归「连上了，问到一半」；
		// ② 连接被对面关掉了（EOF、或者被重置）—— 它根本不说这一套，归「不是一套协议」。
		// ★ 原先 ② 里那句 "connection reset by peer" 被算进了 ①，界面就写成「问到一半超时」——
		//   一个字节都没等到，超时钟根本没响过，那句话是假话。
		var ne net.Error
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
			(errors.As(err, &ne) && ne.Timeout()) {
			return reply{}, &Error{Kind: "handshake", Stage: "read", Err: err}
		}
		if s := strings.TrimSpace(trimLine(line)); s != "" {
			return reply{}, &Error{Kind: "proto", Stage: "handshake",
				Err: fmt.Errorf("连上了，可它开口的第一句就不是对测该说的话（收到 %q / %v）：%w", s, err, ErrProto)}
		}
		return reply{}, &Error{Kind: "proto", Stage: "handshake",
			Err: fmt.Errorf("连上了，可它一句话没说就把连接关了（%v）：%w", err, ErrProto)}
	}
	r, perr := parseReply(line)
	if perr != nil {
		return reply{}, &Error{Kind: "proto", Stage: "handshake",
			Err: fmt.Errorf("%w（它回的那一句：%q）", ErrProto, trimLine(line))}
	}
	switch r.code {
	case "OK":
		if r.nonce != nonce {
			return r, &Error{Kind: "proto", Stage: "handshake",
				Err: fmt.Errorf("回执里的编号对不上（要 %s，回 %s）—— 这一口上可能同时有别人在测", nonce, r.nonce)}
		}
		return r, nil
	case "BUSY":
		return r, &Error{Kind: "busy", Stage: "handshake", Err: errors.New("对端对测口同时在测的路数已满")}
	}
	return r, &Error{Kind: "proto", Stage: "handshake", Err: errors.New("对面说：" + trimLine(line))}
}

func trimLine(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// pingRunner 在打流的同时另开一条线量往返。
//
// ★ 复用正在传数据的那条连接量 RTT 是量不出缓冲膨胀的 —— 那 8 个字节排在
//
//	几万个字节后面，量到的是队列深度本身，不是链路往返。
type pingRunner struct {
	addr string
	to   time.Duration
	done chan struct{}
	out  chan *RTT
}

func newPingRunner(addr string, to time.Duration) *pingRunner {
	return &pingRunner{addr: addr, to: to, done: make(chan struct{}), out: make(chan *RTT, 1)}
}

func (p *pingRunner) start() {
	go func() {
		c, br, err := dialPing(context.Background(), p.addr, p.to)
		if err != nil {
			p.out <- &RTT{Fault: err.Error()}
			return
		}
		defer func() {
			// 说到结束再走：不然对面那一路把「连接没了」记成一次毛病，
			// 界面里「最近跑过哪几路」就会挂着几条不存在的错。
			_ = writeFrameBuf(c, nil)
			_ = c.Close()
		}()
		var samples []float64
		buf := make([]byte, pingFrameSize)
		echo := make([]byte, pingFrameSize+4)
		for {
			select {
			case <-p.done:
				p.finish(samples)
				return
			default:
			}
			t := time.Now()
			_ = c.SetDeadline(t.Add(pingIOTimeout))
			if err := writeFrameBuf(c, buf); err != nil {
				p.finish(samples)
				return
			}
			if _, err := io.ReadFull(br, echo[:4]); err != nil {
				p.finish(samples)
				return
			}
			n := int(uint32(echo[0])<<24 | uint32(echo[1])<<16 | uint32(echo[2])<<8 | uint32(echo[3]))
			if n != pingFrameSize {
				p.finish(samples)
				return
			}
			if _, err := io.ReadFull(br, echo[:n]); err != nil {
				p.finish(samples)
				return
			}
			samples = append(samples, float64(time.Since(t).Microseconds())/1000)
			time.Sleep(loadPingEvery)
		}
	}()
}

// finish 交的是「到目前为止」的账。★ 半途断掉也要交：只跑了 3 次的往返仍然是往返，
//
//	把它报成「一次都没回来」就等于把已经问到的证据丢了。
func (p *pingRunner) finish(samples []float64) {
	r := summarizeRTT(samples)
	p.out <- &r
}

func (p *pingRunner) stop() *RTT {
	close(p.done)
	select {
	case r := <-p.out:
		return r
	case <-time.After(3 * time.Second):
		return &RTT{Fault: "带载往返那一路到点没交账"}
	}
}
