package media

// RTMP 客户端探测：握手 → connect（问应用认不认） → createStream → play
// （问这路名上到底有没有流） → 数一段时间里的媒体字节。
//
// ★ 为什么要自己实现、还非得把这五步拆开报：现场那句「推流没到平台」在这五步上
//
//	各有各的样子 —— 口没开 / 端口开着但不是 RTMP / 握手不回 / 应用被拒 /
//	这路名上没有流 / 服务器说有流可一个媒体字节都没到 / 在推（那顺手把码率量出来）。
//	第三方库把它们糊成一次「连接成功或失败」，正好把要区分的那几档抹掉了。
//
// ★ 只发读命令：connect + createStream + play。绝不发 publish / FCPublish /
//
//	releaseStream / deleteStream —— 那是往别人服务器上挂流，属于改动，不是探测。

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

// RTMPError 的 Kind 集合（封闭）：工具层按这个选判定码，不靠文本匹配。
const (
	RTMPKindDial     = "dial"     // TCP 就没连上（拒绝 / 超时 / 没路由）
	RTMPKindTimeout  = "timeout"  // 连上了，到点没回该回的那一句
	RTMPKindNotRTMP  = "not-rtmp" // 端口开着，回的内容不像 RTMP 握手
	RTMPKindClosed   = "closed"   // 对端把连接关了（有些服务器用它表示拒绝）
	RTMPKindProtocol = "protocol" // 报文本身读不下去（长度对不上、块大小离谱）
)

// RTMPError 带着「死在哪一步」。★ 阶段和类型分开报：同样是超时，握手不回和
// connect 不回下一步完全不同 —— 前者多半是这台只肯收推流，后者多半是中间有东西吃掉。
type RTMPError struct {
	Stage  string // dial / handshake / connect / createStream / play / read
	Kind   string
	Detail string
	Err    error
}

func (e *RTMPError) Error() string {
	switch {
	case e.Detail != "":
		return fmt.Sprintf("%s 这一步失败（%s）：%s", e.Stage, e.Kind, e.Detail)
	case e.Err != nil:
		return fmt.Sprintf("%s 这一步失败（%s）：%s", e.Stage, e.Kind, e.Err)
	default:
		return fmt.Sprintf("%s 这一步失败（%s）", e.Stage, e.Kind)
	}
}

// Unwrap 把底层网络错误透出去：工具层那些「拒绝=closed、超时=filtered」的判断
// 靠 errors.Is / errors.As 认 errno，不看中文文本。
func (e *RTMPError) Unwrap() error { return e.Err }

// RTMPHandshake 是一次握手问出来的东西。
type RTMPHandshake struct {
	Version    byte          // S0：握手协议版本，正常是 3
	ServerTime uint32        // S1 前 4 字节：服务器自己报的那个毫秒数
	Elapsed    time.Duration // C1 发出去到 S0 回来
	Sig        string        // 不像 RTMP 时：内容看着像什么
	Peek       string        // 前若干字节的十六进制，够认协议就行
}

// RTMPStats 是一条连接上读到的账。
//
// ★ 记账点在读到每一条消息的地方，包括那些我们没在等的答案 —— 不然
//
//	「等 connect 回包的那一小会儿里到没过媒体」就成了一个看不见的洞。
type RTMPStats struct {
	Messages     int  `json:"messages"`
	AudioBytes   int  `json:"audioBytes"`
	VideoBytes   int  `json:"videoBytes"`
	OtherMedia   int  `json:"otherMediaBytes"` // aggregate 这类混在一起的
	MediaBytes   int  `json:"mediaBytes"`
	MetadataSeen bool `json:"metadataSeen"`
	KeyFrames    int  `json:"keyFrames"`
	Acks         int  `json:"acks"`
	UserControls int  `json:"userControls"`
	Aborts       int  `json:"aborts"`
	PeerChunkSet int  `json:"peerChunkSet"`
	// LastMediaTS 是最后一条媒体消息自带的 RTMP 时间戳（毫秒）。
	// 单独留这一格，是因为「字节到了」与「头读对了」是两件事：
	// 四字节扩展时间戳要是没读，字节照样到，时间戳却停在 0xffffff。
	LastMediaTS  uint32   `json:"lastMediaTs,omitempty"`
	FirstMediaMs int64    `json:"firstMediaMs,omitempty"`
	LastMediaMs  int64    `json:"lastMediaMs,omitempty"`
	StatusCodes  []string `json:"statusCodes,omitempty"`
}

// RTMPCommand 是一条解开了的命令消息。
type RTMPCommand struct {
	Name string
	Tx   float64
	Args []any
}

// Info 取命令里那个携带信息的对象（onStatus 的 info、_result 的 properties）。
func (c RTMPCommand) Info() map[string]any {
	for _, a := range c.Args {
		if m, ok := a.(map[string]any); ok {
			return m
		}
	}
	return nil
}

// Code 取 onStatus 那个信息对象里的 code（NetStream.Play.Start 一类的原文）。
func (c RTMPCommand) Code() string {
	info := c.Info()
	if info == nil {
		return ""
	}
	if s, ok := info["code"].(string); ok {
		return s
	}
	return ""
}

// Session 是一条握完手、可以发命令的 RTMP 连接。
type Session struct {
	conn net.Conn
	cr   *chunkReader
	cw   *chunkWriter

	Handshake RTMPHandshake
	Stats     RTMPStats
	PeerChunk int
	StreamID  uint32

	started time.Time
}

// 探测用的三个块流号。协议消息、命令消息分开走，各家都这样。
const (
	rtmpCsidProtocol = 2
	rtmpCsidCommand  = 3
)

// RTMPDial 拨号并做完握手。
//
// timeout 管的是「这一段该等的都等不到」：TCP、S0、S1、S2 各自到点都算超时。
// 握手做完后连接上的读超时由后面每一次等待自己设，不留全局死线 ——
// 观测窗口要按调用方给的秒数走。
func RTMPDial(ctx context.Context, host string, port int, timeout time.Duration) (*Session, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, &RTMPError{Stage: "dial", Kind: RTMPKindDial, Err: err}
	}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < timeout {
			timeout = left
		}
	}
	c1 := make([]byte, rtmpHandshakeSize)
	if _, err := rand.Read(c1[8:]); err != nil { // 前 8 字节是时间戳+保留，后面全随机
		_ = conn.Close()
		return nil, &RTMPError{Stage: "handshake", Kind: RTMPKindProtocol, Err: err}
	}
	binary.BigEndian.PutUint32(c1, uint32(time.Now().UnixNano()/int64(time.Millisecond)&0x7fffffff))

	_ = conn.SetDeadline(time.Now().Add(timeout))
	out := make([]byte, 0, 1+rtmpHandshakeSize)
	out = append(out, 0x03)
	out = append(out, c1...)
	sent := time.Now()
	if _, err := conn.Write(out); err != nil {
		_ = conn.Close()
		return nil, &RTMPError{Stage: "handshake", Kind: RTMPKindClosed, Err: err}
	}

	s0, err := readByte(conn)
	if err != nil {
		return nil, handshakeGone(conn, err)
	}
	info := RTMPHandshake{Version: s0, Elapsed: time.Since(sent)}
	if s0 != 0x03 {
		// ★ 第一个字节就不是 3：这个端口回的多半压根不是 RTMP。趁连接还在，
		//   把前面那一小截原文捞出来认个协议 —— 「1935 上跑的是 HTTPS」这种
		//   配错，只说「不是 RTMP」等于让人再去猜一遍。
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		peek, _ := readN(conn, 24)
		info.Peek = hex.EncodeToString(peek)
		info.Sig = sniffProtocol(append([]byte{s0}, peek...))
		_ = conn.Close()
		return nil, &RTMPError{Stage: "handshake", Kind: RTMPKindNotRTMP,
			Detail: fmt.Sprintf("第一个字节是 0x%02x，不是 RTMP 的 0x03", s0), Err: &RTMPHangError{Info: info}}
	}
	s1, err := readN(conn, rtmpHandshakeSize)
	if err != nil {
		return nil, handshakeGone(conn, err)
	}
	info.ServerTime = binary.BigEndian.Uint32(s1)
	// C2 = 把 S1 原样回去（简单握手），1536 字节，前面不再带版本字节。
	//
	// ★ 顺序是先回 C2 再等 S2：SRS 与 nginx-rtmp 是 S0S1S2 一口气发完，
	//   可也有服务器要看到 C2 才发 S2 —— 反过来等就成死锁，
	//   而那会被我们误判成「这台不回握手」。
	if _, err := conn.Write(s1); err != nil {
		_ = conn.Close()
		return nil, &RTMPError{Stage: "handshake", Kind: closedKind(err), Err: err}
	}
	s2, err := readN(conn, rtmpHandshakeSize)
	if err != nil {
		return nil, handshakeGone(conn, err)
	}
	_ = s2
	// 复杂握手要按 Flash 密钥算摘要，现场这几家服务器都收简单握手；真遇到只认
	// 复杂握手的，它会关连接 —— 那一档照实报「握手没做完」，不假装成功。
	_ = conn.SetDeadline(time.Time{})

	br := bufio.NewReaderSize(conn, 32*1024)
	return &Session{conn: conn, cr: newChunkReader(br), cw: newChunkWriter(conn),
		Handshake: info, PeerChunk: 128, started: time.Now()}, nil
}

// RTMPHangError 把已经问到的握手信息带回去：not-rtmp 那一档要写的正是
// 「它回的这段像什么协议」，只回一个错误码就把已经看到的扔了。
type RTMPHangError struct{ Info RTMPHandshake }

func (e *RTMPHangError) Error() string { return "回的不是 RTMP 握手" }

// handshakeGone 分「到点没回」与「它把连接关了」—— 这两句在现场是两个毛病。
func handshakeGone(conn net.Conn, err error) error {
	_ = conn.Close()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &RTMPError{Stage: "handshake", Kind: RTMPKindTimeout, Err: err}
	}
	return &RTMPError{Stage: "handshake", Kind: RTMPKindClosed, Err: err}
}

// Close 关掉连接。探测自己负责收尾，不留半开的连接。
func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// Elapsed 给出「这条消息离握手完成多少毫秒」。
func (s *Session) Elapsed() time.Duration { return time.Since(s.started) }

// sendProtocol 发一条协议消息（窗口大小、块大小这一类）。
func (s *Session) sendProtocol(typeID uint8, value uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	return s.cw.WriteMessage(rtmpCsidProtocol, typeID, 0, 0, b[:])
}

// Begin 发探测方该发的三条开场协议消息：窗口应答、对端带宽、我方块大小。
//
// ★ 块大小一定要先声明：不声明就按默认 128 字节切，一条 connect 命令会被切成
//
//	一堆续块，而有些只收推流的服务器对续块的处理很马虎。
func (s *Session) Begin(timeout time.Duration) error {
	_ = s.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	for _, m := range []struct {
		id    uint8
		value uint32
	}{{TypeWindowAckSize, 2500000}, {TypeSetPeerBW, 2500000}, {TypeSetChunkSize, 4096}} {
		if err := s.sendProtocol(m.id, m.value); err != nil {
			return &RTMPError{Stage: "connect", Kind: closedKind(err), Err: err}
		}
	}
	s.cw.ourChunk = 4096
	return nil
}

// Connect 发 connect 命令并等回包。extra 是给某些服务器要求的额外参数
// （vhost、key、token 这类）——★ 这些值只上线路，不进结果、不进日志。
func (s *Session) Connect(app, tcURL string, extra map[string]any, timeout time.Duration) (RTMPCommand, error) {
	cmd := map[string]any{
		"app":            app,
		"tcUrl":          tcURL,
		"flashVer":       "FML / 34,0,0,0",
		"type":           "nonprivate",
		"fpad":           false,
		"capabilities":   15.0,
		"audioCodecs":    1024.0,
		"videoCodecs":    252.0,
		"videoFunction":  1.0,
		"pageUrl":        "http://" + strings.TrimPrefix(tcURL, "rtmp://"),
		"objectEncoding": 0.0,
	}
	for k, v := range extra {
		if k == "app" || k == "tcUrl" { // 这两个由探测方自己算，不许覆盖
			continue
		}
		cmd[k] = v
	}
	body, err := AMF0Encode("connect", 1.0, cmd)
	if err != nil {
		return RTMPCommand{}, &RTMPError{Stage: "connect", Kind: RTMPKindProtocol, Err: err}
	}
	_ = s.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	if err := s.cw.WriteMessage(rtmpCsidCommand, TypeCommandAMF0, 0, 0, body); err != nil {
		return RTMPCommand{}, &RTMPError{Stage: "connect", Kind: closedKind(err), Err: err}
	}
	// connect 的答案可能是 _result（成）、onStatus（多数服务器用它报拒绝）、
	// _error（少数用它报参数错）。只认这三个，别的照实报错，不猜成成功。
	c, err := s.waitFor(timeout, func(cm RTMPCommand) bool {
		switch cm.Name {
		case "_result", "onStatus", "_error":
			return cm.Tx == 1 || cm.Tx == 0
		}
		return false
	})
	if err != nil {
		return c, wrapWait("connect", err)
	}
	return c, nil
}

// CreateStream 发 createStream，拿回一个可以 play 的流号。
func (s *Session) CreateStream(tx float64, timeout time.Duration) (uint32, error) {
	body, err := AMF0Encode("createStream", tx, nil)
	if err != nil {
		return 0, &RTMPError{Stage: "createStream", Kind: RTMPKindProtocol, Err: err}
	}
	_ = s.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	if err := s.cw.WriteMessage(rtmpCsidCommand, TypeCommandAMF0, 0, 0, body); err != nil {
		return 0, &RTMPError{Stage: "createStream", Kind: closedKind(err), Err: err}
	}
	c, err := s.waitFor(timeout, func(cm RTMPCommand) bool {
		return (cm.Name == "_result" || cm.Name == "onStatus") && cm.Tx == tx
	})
	if err != nil {
		return 0, wrapWait("createStream", err)
	}
	if c.Name != "_result" {
		return 0, &RTMPError{Stage: "createStream", Kind: RTMPKindClosed,
			Detail: "回的是 " + c.Name + " " + c.Code()}
	}
	for _, a := range c.Args {
		if n, ok := a.(float64); ok && n >= 1 && n < 1<<20 {
			s.StreamID = uint32(n)
			return s.StreamID, nil
		}
	}
	return 0, &RTMPError{Stage: "createStream", Kind: RTMPKindProtocol,
		Detail: "_result 里没找到流号"}
}

// Play 在那一路流上发 play。★ 这一步不等答案：答案和媒体消息是同一条路上
// 陆续到的，分开等会把已经到手的媒体字节挡在外面 —— 用 Watch 一次收全。
func (s *Session) Play(stream string, tx float64, timeout time.Duration) error {
	body, err := AMF0Encode("play", tx, nil, stream, -2.0, -1.0, true)
	if err != nil {
		return &RTMPError{Stage: "play", Kind: RTMPKindProtocol, Err: err}
	}
	_ = s.conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	if err := s.cw.WriteMessage(rtmpCsidCommand, TypeCommandAMF0, s.StreamID, 0, body); err != nil {
		return &RTMPError{Stage: "play", Kind: closedKind(err), Err: err}
	}
	return nil
}

// Watch 读一段时间，把这段时间里到的消息全记进账，并盯第一个符合要求的答案。
//
// 窗口到点不算错误（返回 ok=false, err=nil）；对端提前关连接会带一个
// closed 类的错误 —— 那一档也是证据，不能和「没答上来」混成一句。
func (s *Session) Watch(window time.Duration, isWant func(RTMPCommand) bool) (RTMPCommand, bool, error) {
	_ = s.conn.SetDeadline(time.Now().Add(window))
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	for {
		msg, err := s.cr.ReadMessage()
		if err != nil {
			if isTimeoutErr(err) {
				return RTMPCommand{}, false, nil
			}
			return RTMPCommand{}, false, err
		}
		s.note(msg)
		if s.dispatch(msg) {
			continue
		}
		if msg.TypeID != TypeCommandAMF0 && msg.TypeID != TypeCommandAMF3 &&
			msg.TypeID != TypeDataAMF0 && msg.TypeID != TypeDataAMF3 {
			continue
		}
		c, ok := decodeCommand(msg)
		if !ok {
			continue
		}
		if c.Name != "" {
			s.recordStatus(c)
		}
		if isWant != nil && isWant(c) {
			return c, true, nil
		}
	}
}

// Observation 是一次「把整段窗口读完」的结果。
type Observation struct {
	// Status 是等到的那一条命令答案（play 的回包），StatusSeen 说它到没到。
	Status     RTMPCommand
	StatusSeen bool
	// Elapsed 是真读了多久。★ 码率要按这个除，不按「想要读的那几秒」除：
	// 对端提前断线时按想要的秒数除，会给出一个偏低的假码率。
	Elapsed time.Duration
	// Closed 是窗口没读满就结束的原因：nil 表示读满了整个窗口。
	Closed error
	// 窗口内的那份账。★ 单独给一份，是因为底下那份是从握手起累计的 ——
	// 码率的分子必须只算这段窗口里到的字节，不然是拿两段不同的数在除。
	MediaBytes   int
	AudioBytes   int
	VideoBytes   int
	MetadataSeen bool
	Messages     int
	// Stats 是整条连接的累计账（含窗口外的协议消息）。
	Stats RTMPStats
	// Meta 是窗口里第一条元数据（@setDataFrame / onMetaData 里那个对象）。
	// ★ 单独给一格而不是塞进 Status：那是推流端「打算发多大、多快」的声明，
	//
	//	和实测码率是两回事 —— 对得上是好消息，对不上本身就是毛病。
	Meta map[string]any
}

// Observe 在整段窗口里连续读：等到 play 的回包之后**不提前收工**，
// 把剩下的窗口继续读完。
//
// ★ 这一步不能省：回包和媒体消息走的是同一条读循环，「等到回包就返回」等于
//
//	把窗口里后面那些字节全挡在外面，码率就成了 0 —— 那是量的方法错了，不是没在推。
func (s *Session) Observe(window time.Duration, isWant func(RTMPCommand) bool) Observation {
	deadline := time.Now().Add(window)
	_ = s.conn.SetDeadline(deadline)
	defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	ob := Observation{}
	before := s.Stats
	beforeMeta := s.Stats.MetadataSeen
	for time.Now().Before(deadline) {
		msg, err := s.cr.ReadMessage()
		if err != nil {
			if isTimeoutErr(err) {
				break // 窗口读满了
			}
			ob.Closed = err
			break
		}
		s.note(msg)
		if s.dispatch(msg) {
			continue
		}
		if msg.TypeID != TypeCommandAMF0 && msg.TypeID != TypeCommandAMF3 &&
			msg.TypeID != TypeDataAMF0 && msg.TypeID != TypeDataAMF3 {
			continue
		}
		c, ok := decodeCommand(msg)
		if !ok {
			continue
		}
		if c.Name != "" {
			s.recordStatus(c)
		}
		// 元数据不是命令，但它身上有「声明的那份分辨率与码率」—— 别丢
		if (msg.TypeID == TypeDataAMF0 || msg.TypeID == TypeDataAMF3) && ob.Meta == nil {
			if m := c.Info(); m != nil {
				ob.Meta = m
			}
		}
		if !ob.StatusSeen && isWant != nil && isWant(c) {
			ob.Status = c
			ob.StatusSeen = true
		}
	}
	ob.Elapsed = window - time.Until(deadline)
	if ob.Elapsed < 0 {
		ob.Elapsed = 0
	}
	after := s.Stats
	ob.Messages = after.Messages - before.Messages
	ob.MediaBytes = after.MediaBytes - before.MediaBytes
	ob.AudioBytes = after.AudioBytes - before.AudioBytes
	ob.VideoBytes = after.VideoBytes - before.VideoBytes
	ob.MetadataSeen = after.MetadataSeen && !beforeMeta
	ob.Stats = after
	return ob
}

// note 把一条消息记进账。★ 媒体字节按「消息正文长度」算，不含块头：
// 探测问的是「这路流真带过来多少码流」，把我们的协议开销算进去会虚高。
func (s *Session) note(msg *RTMPMessage) {
	s.Stats.Messages++
	switch msg.TypeID {
	case TypeAudio:
		s.Stats.AudioBytes += len(msg.Payload)
		s.Stats.MediaBytes += len(msg.Payload)
		s.markMedia(msg)
	case TypeVideo:
		s.Stats.VideoBytes += len(msg.Payload)
		s.Stats.MediaBytes += len(msg.Payload)
		if len(msg.Payload) > 0 && msg.Payload[0]>>4 == 1 {
			s.Stats.KeyFrames++
		}
		s.markMedia(msg)
	case TypeAggregate:
		s.Stats.OtherMedia += len(msg.Payload)
		s.Stats.MediaBytes += len(msg.Payload)
		s.markMedia(msg)
	case TypeDataAMF0, TypeDataAMF3:
		s.Stats.MetadataSeen = true
	case TypeAck:
		s.Stats.Acks++
	case TypeUserControl:
		s.Stats.UserControls++
	case TypeAbort:
		s.Stats.Aborts++
	case TypeSetChunkSize:
		s.Stats.PeerChunkSet++
	}
}

func (s *Session) markMedia(msg *RTMPMessage) {
	s.Stats.LastMediaTS = msg.Timestamp
	ms := s.Elapsed().Milliseconds()
	if s.Stats.FirstMediaMs == 0 {
		s.Stats.FirstMediaMs = ms
	}
	s.Stats.LastMediaMs = ms
}

// dispatch 处理协议层消息（改块大小、丢块流），返回 true 表示这条已经用掉了。
func (s *Session) dispatch(msg *RTMPMessage) bool {
	switch msg.TypeID {
	case TypeSetChunkSize:
		if len(msg.Payload) < 4 {
			return true
		}
		n := int(int32(binary.BigEndian.Uint32(msg.Payload)))
		if err := s.cr.setPeerChunkSize(n); err != nil {
			return true
		}
		s.PeerChunk = n
		return true
	case TypeAbort:
		if len(msg.Payload) >= 4 {
			s.cr.dropCsid(binary.BigEndian.Uint32(msg.Payload))
		}
		return true
	case TypeWindowAckSize, TypeSetPeerBW, TypeAck, TypeUserControl:
		return true
	}
	return false
}

func (s *Session) recordStatus(c RTMPCommand) {
	code := c.Code()
	if code == "" {
		return
	}
	for _, have := range s.Stats.StatusCodes {
		if have == code {
			return
		}
	}
	s.Stats.StatusCodes = append(s.Stats.StatusCodes, code)
}

// waitFor 在超时内等一条符合要求的命令消息。
func (s *Session) waitFor(timeout time.Duration, isWant func(RTMPCommand) bool) (RTMPCommand, error) {
	c, ok, err := s.Watch(timeout, isWant)
	if err != nil {
		return c, err
	}
	if !ok {
		return c, &RTMPError{Stage: "read", Kind: RTMPKindTimeout}
	}
	return c, nil
}

// decodeCommand 把命令消息正文解成 AMF0 参数。
//
// ★ AMF3 壳（类型 17/15）的第一个值前面多两字节（一个长度前缀），跳掉再解；
// 里面的参数实际仍是 AMF0 —— 各家都这么写，照做。
func decodeCommand(msg *RTMPMessage) (RTMPCommand, bool) {
	b := msg.Payload
	if msg.TypeID == TypeCommandAMF3 || msg.TypeID == TypeDataAMF3 {
		if len(b) < 2 {
			return RTMPCommand{}, false
		}
		b = b[2:]
	}
	args, err := AMF0DecodeArgs(b)
	if err != nil || len(args) == 0 {
		return RTMPCommand{}, false
	}
	c := RTMPCommand{}
	if name, ok := args[0].(string); ok {
		c.Name = name
	}
	if len(args) > 1 {
		if f, ok := args[1].(float64); ok {
			c.Tx = f
		}
	}
	c.Args = args[2:]
	return c, c.Name != ""
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// closedKind：读写报错时区分「它关了连接」与「到点了」。
func closedKind(err error) string {
	if isTimeoutErr(err) {
		return RTMPKindTimeout
	}
	return RTMPKindClosed
}

func wrapWait(stage string, err error) error {
	var re *RTMPError
	if errors.As(err, &re) {
		if re.Stage == "read" {
			re.Stage = stage
		}
		return re
	}
	return &RTMPError{Stage: stage, Kind: closedKind(err), Err: err}
}

// sniffProtocol 认一下「这个端口回的那一截像什么协议」。只认形状，不解析。
func sniffProtocol(b []byte) string {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "HTTP/1."), strings.HasPrefix(s, "GET "), strings.HasPrefix(s, "POST "):
		return "http"
	case strings.HasPrefix(s, "RTSP/"), strings.HasPrefix(s, "OPTIONS "):
		return "rtsp"
	case strings.HasPrefix(s, "<"), strings.Contains(s, "<html"):
		return "html"
	case len(b) >= 3 && b[0] == 'F' && b[1] == 'L' && b[2] == 'V':
		return "flv"
	case len(b) >= 8 && string(b[4:8]) == "ftyp":
		return "mp4"
	case len(b) >= 2 && (b[0] == 0x14 || b[0] == 0x15 || b[0] == 0x16 || b[0] == 0x17) && b[1] == 0x03:
		return "tls"
	case len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0:
		return "mpeg-ts?"
	}
	return ""
}

// AmfNumber 是个小助手：AMF0 里所有数字都是 double，取出来总要转一下。
func AmfNumber(v any) (float64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
