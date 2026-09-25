package throughput

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config 是开一个对测口要定的几件事。
type Config struct {
	// Addrs 是绑哪几个地址。★ 不许图省事绑 0.0.0.0：多网卡工控机上另一块口
	// 连着办公网甚至公网，绑法一错就等于把对测口开到了那边。
	Addrs []string
	// Port 是口开在哪个端口。0 = 让内核挑一个（只有测试这么用；
	// 界面上必须写明端口，两边要对得上同一个数，工具层会夹住不给 0）。
	Port int
	// MaxBytes 是**一次会话**最多收发多少字节（对面要得再多也只给这么多）。
	// 0 用默认值。这一格是下行方向的闸：不设限的话，任何人连上一句
	// 「给我 100G」就把这台机器的出口占满 —— 那是一台现成的放大器。
	MaxBytes int64
	// MaxSessions 是同时接几路。0 用默认值。
	MaxSessions int
	// SessionLimit 是一路会话最长活多久（含握手后的沉默）。
	SessionLimit time.Duration
}

const (
	// defaultMaxBytes 是一路会话的字节闸。★ 这一格拦的是「连上就不停手的那一路」，
	// 不是正常测试：万兆网上跑满工具允许的最长十秒就要 12.5 GB，
	// 闸设得比这还小，一条健健康康的万兆链路会被报成「被对面截了」——那是假毛病。
	defaultMaxBytes    = int64(16) << 30
	defaultMaxSessions = 4
	defaultIdle        = 15 * time.Second
	defaultSessionDur  = 5 * time.Minute
)

// Session 是一路跑完（或跑砸）的对测记录。
type Session struct {
	Peer      string    `json:"peer"`
	Mode      string    `json:"mode"`
	Bytes     int64     `json:"bytes"`
	Elapsed   string    `json:"elapsed"`
	MBps      float64   `json:"mbps"`
	EndedAt   time.Time `json:"endedAt"`
	Fault     string    `json:"fault,omitempty"`
	PeerStats bool      `json:"peerStats"` // 对面那句 STATS 听到了没
}

// Status 是「这个口现在开着吗、在跑第几路、最近跑过哪几路」。
type Status struct {
	Serving    bool      `json:"serving"`
	Addrs      []string  `json:"addrs"`
	Port       int       `json:"port"`
	MaxBytes   int64     `json:"maxBytes"`
	MaxSession int       `json:"maxSessions"`
	Active     int       `json:"active"`
	Served     int64     `json:"served"`
	Recent     []Session `json:"recent"`
}

// Server 是对测口。每一台只允许开一个（和文件共享同一个道理：
//
//	界面上要让人分清「停的是哪个」，两个口在现场一定出错）。
type Server struct {
	cfg    Config
	lns    []net.Listener
	closed atomic.Bool
	active atomic.Int32
	served atomic.Int64
	mu     sync.Mutex
	recent []Session
}

// Start 在每一个给定地址上各起一个监听器。★ 一个都起不来就直接失败，
//
//	不许「起了两块里的一块」—— 那会让人以为对端连不上是防火墙的事。
func Start(cfg Config) (*Server, error) {
	if len(cfg.Addrs) == 0 {
		return nil, errors.New("没给要绑的地址")
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("端口 %d 不是可用的端口", cfg.Port)
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultMaxSessions
	}
	if cfg.SessionLimit <= 0 {
		cfg.SessionLimit = defaultSessionDur
	}
	s := &Server{cfg: cfg}
	for _, a := range cfg.Addrs {
		ln, err := net.Listen("tcp", net.JoinHostPort(a, strconv.Itoa(cfg.Port)))
		if err != nil {
			s.Stop()
			return nil, bindErr(a, cfg.Port, err)
		}
		s.lns = append(s.lns, ln)
	}
	for _, ln := range s.lns {
		go s.accept(ln)
	}
	return s, nil
}

func bindErr(addr string, port int, err error) error {
	return fmt.Errorf("在 %s:%d 上开不起来：%s", addr, port, err)
}

// Stop 关掉所有监听器。★ 已经在线上的会话不打断：现场那一测跑到一半，
//
//	拔了它只会得到一个说不清的数。
func (s *Server) Stop() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	for _, ln := range s.lns {
		_ = ln.Close()
	}
}

// Port 是这个口实际落在哪个端口上 —— 给 0 让内核挑时要靠它把端口报回界面。
func (s *Server) Port() int {
	for _, ln := range s.lns {
		if a, ok := ln.Addr().(*net.TCPAddr); ok {
			return a.Port
		}
	}
	return s.cfg.Port
}

// Stopping 说这一口是不是已经关了。正在发的每一帧看一眼：
//
// 人点了「停止对测」之后还把人家的出口占着，那一口就不是他的了。
func (s *Server) Stopping() bool { return s.closed.Load() }

func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Status{
		Serving:    !s.closed.Load(),
		Addrs:      append([]string(nil), s.cfg.Addrs...),
		Port:       s.Port(),
		MaxBytes:   s.cfg.MaxBytes,
		MaxSession: s.cfg.MaxSessions,
		Active:     int(s.active.Load()),
		Served:     s.served.Load(),
	}
	out.Recent = append(out.Recent, s.recent...)
	return out
}

func (s *Server) note(se Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recent = append([]Session{se}, s.recent...)
	if len(s.recent) > 20 {
		s.recent = s.recent[:20]
	}
}

func (s *Server) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // 口已关（或这块地址出了毛病）：不再接新的，已在跑的会话不打断
		}
		if int(s.active.Add(1)) > s.cfg.MaxSessions {
			s.active.Add(-1)
			_ = writeReply(c, replyLine("BUSY", 0, ""))
			_ = c.Close()
			continue
		}
		go s.serve(c)
	}
}

// serve 处理一路会话。★ 每一处提前退出都要留下一个 Session 记录：
//
//	「谁连过、要了多少、为什么拒」只有在这里说得清，界面上那句「最近跑过哪几路」靠它。
func (s *Server) serve(c net.Conn) {
	defer func() {
		s.active.Add(-1)
		_ = c.Close()
	}()
	endAt := time.Now().Add(s.cfg.SessionLimit)
	_ = c.SetDeadline(endAt)
	br := bufio.NewReaderSize(c, maxFrame+16)
	bw := bufio.NewWriterSize(c, maxFrame+16)

	line, err := readLine(br)
	if err != nil {
		s.fail(c, "读不到第一句："+err.Error())
		return
	}
	mode, want, nonce, err := parseRequest(line)
	if err != nil {
		_ = writeReply(c, "ERR "+err.Error()+"\n")
		s.fail(c, err.Error())
		return
	}
	if want > s.cfg.MaxBytes {
		// ★ 要得比上限多：直接给上限，并在回执里写清楚 —— 对面据此知道自己被截了。
		want = s.cfg.MaxBytes
	}
	if err := writeReply(c, replyLine("OK", s.cfg.MaxBytes, nonce)); err != nil {
		s.fail(c, "回执没送出去："+err.Error())
		return
	}
	switch mode {
	case ModeUp:
		s.sink(c, br, bw, endAt)
	case ModeDown:
		s.source(c, br, bw, want, endAt)
	case ModePing:
		s.echo(c, br, bw, endAt)
	default:
		s.fail(c, "不认识的模式 "+mode)
	}
}

// readWait 定下一次的读截止：先按「沉默多久算断」来，但绝不越过这一路的总时限。
//
// ★ 只用总时限的话，有人连上不说话就把四个位子占满五分钟；只用沉默时限的话，
// 一路慢慢吞吞不停的数据能把这一路永远挂着。
func (s *Server) readWait(c net.Conn, endAt time.Time) {
	to := time.Now().Add(defaultIdle)
	if to.After(endAt) {
		to = endAt
	}
	_ = c.SetReadDeadline(to)
}

func (s *Server) fail(c net.Conn, why string) {
	s.note(Session{Peer: c.RemoteAddr().String(), Fault: why, EndedAt: time.Now()})
}

// sink 收流（对端说 up）。★ 收满上限就停：不设这一道的话，对面连着一直灌，
//
//	这台就成了别人手里的黑洞 —— 上限拦的是「有人拿这一口当炮使」，不是「正常测不完」。
//	收到结束帧后，两边各说一句 STATS。
func (s *Server) sink(c net.Conn, br *bufio.Reader, bw *bufio.Writer, endAt time.Time) {
	host := c.RemoteAddr().String()
	buf := make([]byte, maxFrame)
	var got int64
	start := time.Now()
	err := readUntilEnd(s, c, br, buf, &got, s.cfg.MaxBytes, endAt)
	recv := time.Since(start)
	s.served.Add(got) // ★ 数到了就先记账：对面回执一到就会去问「一共过了多少」
	if err != nil {
		s.note(Session{Peer: host, Mode: ModeUp, Bytes: got, Fault: err.Error(), EndedAt: time.Now()})
		return
	}
	// 先听对面那句（它写出用了多久），再说我们这句。★ 先听后说能保证两端看到的
	// 「这一路一共多少字节」是同一份，界面上不会出现两个数各说各的。
	s.readWait(c, endAt)
	peerCount, _, perr := readStats(br)
	se := Session{Peer: host, Mode: ModeUp, Bytes: got, Elapsed: recv.String(),
		MBps: mbps(got, recv), PeerStats: perr == nil, EndedAt: time.Now()}
	if peerCount > 0 && peerCount != got {
		// 对面写出的字节数与收到的应当一致；不一致本身就是这一路的毛病，留在 Fault 里说
		se.Fault = fmt.Sprintf("对面写出 %d 字节，我这边只数到 %d", peerCount, got)
	}
	// ★ 这一笔必须在回执发出去之前记好：对面拿到回执就回来问状态，
	//   晚一步界面上就是「刚跑过一路，可最近那列是空的」。
	s.note(se)
	if perr == nil {
		// 回执发不出去时对面自己会报「没等到那句账」，这一路该记的账已经记牢了。
		_ = writeStats(bw, got, recv)
	}
}

// source 发流（对端说 down）。★ 只发到 want 为止，want 在进门时已经被上限夹过。
//
// 反向那一侧只可能说两句话：STOP（对面跑够时长了，别再发了）和 STATS（它数到多少）。
// 这两句必须边发边听 —— 只听 STATS 的话，对面喊停等于对着耳罩喊，
// 我们会把「跑三秒」执行成「把这台上限那一整 GiB 都推过去」。
func (s *Server) source(c net.Conn, br *bufio.Reader, bw *bufio.Writer, want int64, endAt time.Time) {
	host := c.RemoteAddr().String()
	stop := make(chan struct{})
	var closeStop sync.Once
	peerStats := make(chan string, 1)
	go func() {
		for {
			s.readWait(c, endAt)
			line, err := readLine(br)
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "STOP") {
				closeStop.Do(func() { close(stop) })
				continue
			}
			select {
			case peerStats <- line:
			default:
			}
			return
		}
	}()

	payload := pattern(maxFrame)
	var sent int64
	start := time.Now()
	err := writeUntil(bw, payload, want, stop, s.Stopping, &sent)
	send := time.Since(start)
	s.served.Add(sent) // ★ 数过了就先记账，理由同 sink
	if err != nil {
		s.note(Session{Peer: host, Mode: ModeDown, Bytes: sent, Fault: err.Error(), EndedAt: time.Now()})
		return
	}
	var peerCount int64
	var perr error
	select {
	case line := <-peerStats:
		peerCount, _, perr = parseStatsLine(line)
	case <-time.After(defaultIdle):
		perr = errors.New("等对面那句账没等到")
	}
	se := Session{Peer: host, Mode: ModeDown, Bytes: sent, Elapsed: send.String(),
		MBps: mbps(sent, send), PeerStats: perr == nil, EndedAt: time.Now()}
	if perr != nil {
		se.Fault = perr.Error()
	} else if peerCount > 0 && peerCount != sent {
		// 我们写出的与对面数到的不一致 —— 这一路本身就有毛病，留在账里说
		se.Fault = fmt.Sprintf("这边写出 %d 字节，对面只数到 %d", sent, peerCount)
	}
	// ★ 先记账再发回执：对面拿到回执就回来问状态，晚一步界面上就是空的。
	s.note(se)
	_ = writeStats(bw, sent, send)
}

// echo 把每一帧原样弹回去，用于量往返。
func (s *Server) echo(c net.Conn, br *bufio.Reader, bw *bufio.Writer, endAt time.Time) {
	host := c.RemoteAddr().String()
	buf := make([]byte, 64)
	var n int64
	start := time.Now()
	for {
		s.readWait(c, endAt)
		frame, end, err := readFrame(br, buf)
		if err != nil {
			// 对面收完最后一帧就把连接关了（客户端量完就是这个动作），不是它说错了话：
			// 只有读到一个不像帧的东西才算毛病。
			if errors.Is(err, io.EOF) {
				break
			}
			s.note(Session{Peer: host, Mode: ModePing, Bytes: n,
				Fault: err.Error(), EndedAt: time.Now()})
			return
		}
		if end {
			break
		}
		if err := writeFrame(bw, frame); err != nil {
			s.note(Session{Peer: host, Mode: ModePing, Bytes: n, Fault: err.Error(), EndedAt: time.Now()})
			return
		}
		// ★ 每一帧都要当场_flush_：写进 1 MiB 的缓冲里就等于没发出去，
		// 对面那一次往返会一直等到超时 —— 量出来的不是往返，是攒够一缓冲要多久。
		if err := bw.Flush(); err != nil {
			s.note(Session{Peer: host, Mode: ModePing, Bytes: n, Fault: err.Error(), EndedAt: time.Now()})
			return
		}
		n += int64(len(frame))
	}
	_ = bw.Flush()
	s.note(Session{Peer: host, Mode: ModePing, Bytes: n, Elapsed: time.Since(start).String(),
		EndedAt: time.Now()})
}

// parseRequest 认第一句。★ 认不出来就说「不是这套协议」，不去猜：
//
//	把 http 的一行 GET 当成 up 来读，接下来读到的每个字节都是垃圾。
func parseRequest(line string) (mode string, want int64, nonce string, err error) {
	f := strings.Fields(line)
	if len(f) < 4 || f[0] != protoMagic {
		return "", 0, "", ErrProto
	}
	switch f[1] {
	case ModeUp, ModeDown, ModePing:
	default:
		return "", 0, "", fmt.Errorf("不认识的模式 %q", f[1])
	}
	n, cerr := strconv.ParseInt(f[2], 10, 64)
	if cerr != nil || n < 0 {
		return "", 0, "", fmt.Errorf("要的那个数不像数：%q", f[2])
	}
	return f[1], n, f[3], nil
}

func writeReply(c net.Conn, line string) error {
	_, err := c.Write([]byte(line))
	return err
}

func writeStats(w *bufio.Writer, count int64, elapsed time.Duration) error {
	_, err := w.WriteString(statsLine(count, elapsed))
	if err != nil {
		return err
	}
	return w.Flush()
}

func readStats(br *bufio.Reader) (int64, time.Duration, error) {
	line, err := readLine(br)
	if err != nil {
		return 0, 0, err
	}
	return parseStatsLine(line)
}

func readUntilEnd(s *Server, c net.Conn, br *bufio.Reader, buf []byte, got *int64, limit int64, endAt time.Time) error {
	for {
		s.readWait(c, endAt)
		frame, end, err := readFrame(br, buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("还没说到结束就断了（已数到 %d 字节）", *got)
			}
			return err
		}
		if end {
			return nil
		}
		*got += int64(len(frame))
		if *got > limit {
			return fmt.Errorf("对面灌过了上限（%d 字节 > %d），这一路就地断开", *got, limit)
		}
	}
}

// writeUntil 按帧写到 want 为止；对面喊停（stop 关了）或这一口被关掉时就收住。
//
// ★ 无论怎么收场，最后都要补一个结束帧 —— 对面是靠这一帧才对齐的：少了它，
//
//	它会把下一句（STATS）的头四个字节当成帧长去读。
func writeUntil(w *bufio.Writer, payload []byte, want int64, stop <-chan struct{},
	stopping func() bool, counter *int64) error {
	var left int64 = want
	for left > 0 {
		select {
		case <-stop:
			left = 0
		default:
			if stopping != nil && stopping() {
				return errors.New("这一口已经关了")
			}
		}
		if left <= 0 {
			break
		}
		n := int64(len(payload))
		if n > left {
			n = left
		}
		if err := writeFrame(w, payload[:n]); err != nil {
			return err
		}
		// ★ 每帧都刷：不刷的话这个数测的是「本机内核缓冲吃下了多少」，
		//   而不是「链路上真走了多少」—— 千兆网上测出 8G 就是这么来的。
		if err := w.Flush(); err != nil {
			return err
		}
		left -= n
		*counter += n
	}
	return writeFrame(w, nil)
}

// pattern 给一段不全是 0 的数据：全零的载荷会让某些网卡与压缩链路把吞吐虚报出来。
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*1103515245 + 12345) >> 13)
	}
	return b
}

func mbps(count int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(count) * 8 / d.Seconds() / 1e6
}
