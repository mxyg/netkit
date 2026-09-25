// Package rtmptest 是一个只用于测试的假 RTMP 服务器。
//
// ★ 它刻意不复用 internal/media 里那套编解码：假的这一台如果和探测端共用
//
//	同一个编码器，两边一起写错的地方就永远测不出来。这里按规范另写一份，
//	只实现探测会碰到的那几种报文。
//
// ★ 每一种模式对应的就是现场一种毛病，模式名和判定码一一对得上，
//
//	看测试文件名就能知道哪一档是谁在验。
package rtmptest

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// 模式：每一种都是一种现场毛病。
const (
	ModeOK          = "ok"          // 一路在推，媒体按节奏发
	ModeNoMedia     = "nomedia"     // 说有这路，可一个媒体字节都不发
	ModeStreamGone  = "streamgone"  // play 回 NetStream.Play.Failed
	ModeNotFound    = "notfound"    // play 回 NetStream.Play.StreamNotFound
	ModeRejected    = "rejected"    // connect 被拒（应用不存在那一类）
	ModeAuth        = "auth"        // connect 被拒，理由是没带 key
	ModeSilent      = "silent"      // 握手做完就一句命令不回
	ModeJunk        = "junk"        // 端口开着，回的不是 RTMP
	ModeHang        = "hang"        // 连上就一句话不说
	ModeCloseOnPlay = "closeonplay" // 刚 play 完就把连接断了
	ModeTinyChunks  = "tinychunks"  // 块大小切成 16 字节，验探测端会不会读串
	ModeExtendedTS  = "extendedts"  // 时间戳走 4 字节扩展形式
	ModeChunkMidway = "chunkmidway" // 中途改一次块大小（各家真会这么干）
	ModeAMF3Command = "amf3command" // 命令装在 AMF3 壳里
	ModePublishOnly = "publishonly" // 只肯收推流：connect 回拒绝并说清为什么
	ModeBareTx      = "baretx"      // 命令里的 transactionId 不带 0x00 标记（各家真这么写）
	// ModeCloseAfterMedia 发完那一阵媒体就把连接断了。★ 专门用来验「码率除以的是
	// 真读了多久」：窗口给 3 秒、字节只在前 0.4 秒到，按 3 秒除会给出一个低得离谱的假码率。
	ModeCloseAfterMedia = "closeaftermedia"
)

// Server 是一台监听在随机端口上的假 RTMP 服务器。
type Server struct {
	Mode string

	// MediaEvery 媒体消息之间的间隔，MediaBurst 一次探测里发几条。
	MediaEvery time.Duration
	MediaBurst int
	// MediaSize 每条媒体消息的正文长度（码率好不好算就看这个）。
	MediaSize int

	// PeerChunk 服务器声明的自己那侧块大小。
	PeerChunk int

	// RejectText 覆盖 connect 被拒时那句描述（现场各家写的都不一样）。
	// ★ 和上面几项一样，要在 StartConfigured 的 tweak 里定好，起了服务再改就是抢跑。
	RejectText string

	// PlayText 覆盖 play 答应时那句描述 —— 有些服务器把整条 tcUrl 抄回这里，
	//   口令就跟着回来了：验「进结果的那一句打没打码」只能用这一格。
	PlayText string

	ln   net.Listener
	conn net.Conn

	mu       sync.Mutex
	commands []string
	connect  map[string]any
	// playStream 是 play 命令里那一格原文（含 ?key=… 这类挂在流名上的参数）。
	playStream string
	err        error
	served     int
}

// Start 起一台假服务器。mode 是上面那几种之一。
func Start(mode string) (*Server, error) { return StartConfigured(mode, nil) }

// StartConfigured 起一台假服务器，并在它开始接单之前先把节奏与文案改掉。
//
// ★ 一定要有这个入口：那几个字段没有锁，起了服务再改会被 -race 抓，
//
//	更麻烦的是「改没赶上这一轮发送」会悄悄给出一个假绿。
func StartConfigured(mode string, tweak func(*Server)) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{Mode: mode, MediaEvery: 50 * time.Millisecond, MediaBurst: 8,
		MediaSize: 1000, PeerChunk: 4096, ln: ln}
	if s.PeerChunk == 0 {
		s.PeerChunk = 4096
	}
	if tweak != nil {
		tweak(s)
	}
	go s.accept()
	return s, nil
}

// Port 是这台假服务器实际占用的端口。
func (s *Server) Port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

// Host 是监听地址的主机部分。
func (s *Server) Host() string { return "127.0.0.1" }

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.served++
		s.mu.Unlock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.conn = c
		go s.serve(c)
	}
}

// Close 关掉监听与当前连接。
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// Commands 返回收到的命令名，按到达顺序。
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

// PlayStream 返回 play 命令里那个流名的**原文**。
//
// ★ 结果里那份是打过码的；要证明「?key= 真的一并发了出去」只能看线路上这一份。
func (s *Server) PlayStream() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.playStream
}

// ConnectParams 返回 connect 命令里那个参数对象。
func (s *Server) ConnectParams() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connect
}

// Err 记录服务过程中遇到的底层错误（测试用来确认不是假服务器自己先垮了）。
func (s *Server) Err() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		return ""
	}
	return s.err.Error()
}

func (s *Server) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

// serve 跑一条连接。
func (s *Server) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	switch s.Mode {
	case ModeJunk:
		// 探测端会先写 C0C1；这里当作一个 HTTP 口回它一句，然后关掉。
		buf := make([]byte, 1537)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\ncontent-type: text/html\r\n\r\n"))
		return
	case ModeHang:
		time.Sleep(20 * time.Second)
		return
	}

	c0, err := read1(c)
	if err != nil {
		s.setErr(err)
		return
	}
	if c0 != 0x03 {
		s.setErr(fmt.Errorf("客户端 C0 写的是 0x%02x", c0))
		return
	}
	if _, err := readN(c, 1536); err != nil { // C1：长度对得上就行，内容不看
		s.setErr(err)
		return
	}
	s1 := make([]byte, 1536)
	binary.BigEndian.PutUint32(s1, 12345)
	if _, err := c.Write(append([]byte{0x03}, s1...)); err != nil { // S0 + S1
		s.setErr(err)
		return
	}
	c2, err := readN(c, 1536) // 等 C2 再发 S2：验探测端没有把顺序等反
	if err != nil {
		s.setErr(err)
		return
	}
	if err := writeAll(c, pad(c2)); err != nil { // S2 = 把 C2 原样回去
		s.setErr(err)
		return
	}

	if s.Mode == ModeSilent {
		time.Sleep(20 * time.Second) // 握手做完了，后面一句不答
		return
	}

	cr := newChunkReader(c)
	cw := newChunkWriter(c, s.PeerChunk)
	if s.Mode == ModeAMF3Command {
		cw.amf3 = true // 命令装在 AMF3 壳里：探测端要跳掉那两个前缀字节
	}
	if s.Mode == ModeBareTx {
		cw.bareTx = true
	}
	// ★ 宣告我方写正文用的块大小。真实的服务器都会在开场发这条（4096 或 2048），
	//   假服务器要是不发，探测端就还按默认 128 去切 —— 第一条媒体就散了，
	//   而那看起来像是探测端的错。
	if err := cw.protocol(1, uint32(s.PeerChunk)); err != nil {
		s.setErr(err)
		return
	}
	if s.Mode == ModeTinyChunks {
		// 先把块大小改成 16：探测端要是按 4096 读，第一条回包就散了。
		if err := cw.protocol(1, 16); err != nil {
			s.setErr(err)
			return
		}
		cw.chunk = 16
	}

	for {
		msg, err := cr.read()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed") {
				return
			}
			s.setErr(err)
			return
		}
		// 客户端也会改块大小（探测方开场就声明 4096），这边必须跟着改，
		// 不然第一条命令的正文就被按 128 字节截断了。
		switch msg.typ {
		case 1:
			if len(msg.body) >= 4 {
				cr.chunk = int(binary.BigEndian.Uint32(msg.body)) & 0x7fffffff
			}
			continue
		case 2:
			if len(msg.body) >= 4 {
				delete(cr.hdrs, binary.BigEndian.Uint32(msg.body))
			}
			continue
		case 5, 6, 3, 4:
			continue
		}
		if msg.typ == 20 || msg.typ == 17 {
			name, tx, args := decodeCommand(msg.body)
			s.note(name, args)
			if done, err := s.reply(cw, name, tx, args); done {
				if err != nil {
					s.setErr(err)
					return
				}
				// ★ 只在 play 那一条答完之后才断：这一档演的是「刚说要开始播，
				//   连接就没了」，在 connect 后面就断演的是另一回事。
				//   closeaftermedia 走的是另一档：媒体在 reply 里已经同步发完了，
				//   这儿断只是把「窗口没读满」这件事变成确定的。
				if (s.Mode == ModeCloseOnPlay || s.Mode == ModeCloseAfterMedia) && name == "play" {
					return
				}
				continue
			}
		}
	}
}

func (s *Server) note(name string, args []any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, name)
	if name == "connect" {
		for _, a := range args {
			if m, ok := a.(map[string]any); ok {
				cp := map[string]any{}
				for k, v := range m {
					cp[k] = v
				}
				s.connect = cp
			}
		}
	}
	if name == "play" {
		// play 的参数按规范是 (stream, start, duration, reset)；流名是第一格字符串。
		for _, a := range args {
			if st, ok := a.(string); ok {
				s.playStream = st
				break
			}
		}
	}
}

// reply 处理一条命令。返回「是不是已经把这条答完了」。
func (s *Server) reply(cw *chunkWriter, name string, tx float64, args []any) (bool, error) {
	switch name {
	case "connect":
		switch s.Mode {
		case ModeRejected, ModePublishOnly:
			info := map[string]any{
				"level":       "error",
				"code":        "NetConnection.Connect.Rejected",
				"description": s.rejectText(defaultRejectText(s.Mode)),
			}
			return true, cw.command(0, 5, "onStatus", tx, nil, info)
		case ModeAuth:
			info := map[string]any{
				"level":       "error",
				"code":        "NetConnection.Connect.Rejected",
				"description": s.rejectText("auth failed: invalid key in tcUrl"),
			}
			return true, cw.command(0, 5, "onStatus", tx, nil, info)
		}
		props := map[string]any{"caption": "Fake RTMP", "server": "FakeRTMP/0,1,0,1", "type": "nonprivate"}
		return true, cw.command(0, 3, "_result", tx, nil, props)
	case "releaseStream", "FCPublish", "publish":
		// 探测不该发这些；真发上来了就照实记一笔（测试会断言没收到）。
		return true, nil
	case "createStream":
		return true, cw.command(0, 3, "_result", tx, nil, 1.0)
	case "play":
		switch s.Mode {
		case ModeStreamGone:
			info := map[string]any{"level": "error", "code": "NetStream.Play.Failed",
				"description": "stream is not publishing"}
			return true, cw.command(1, 5, "onStatus", 0, nil, info)
		case ModeNotFound:
			info := map[string]any{"level": "status", "code": "NetStream.Play.StreamNotFound",
				"description": "stream not found"}
			return true, cw.command(1, 5, "onStatus", 0, nil, info)
		}
		start := map[string]any{"level": "status", "code": "NetStream.Play.Start",
			"description": s.playText(), "clientID": 1.0}
		if err := cw.command(1, 5, "onStatus", 0, nil, start); err != nil {
			return true, err
		}
		if s.Mode == ModeNoMedia || s.Mode == ModeCloseOnPlay {
			return true, nil
		}
		return true, s.feed(cw)
	}
	return false, nil
}

// defaultRejectText 两档拒绝各有一句现成文案。
//
// ★ 措辞里刻意不互相串味：ModeRejected 那句不带「key」这类词，
//
//	不然「应用不对」与「缺凭据」两档在测试里就没法分开了。
func defaultRejectText(mode string) string {
	if mode == ModePublishOnly {
		return "this server only accepts publishers"
	}
	return "application 'live' not found"
}

// rejectText 用测试指定的那句拒绝理由，没指定就用默认的。
//
// ★ 各家写的文案千奇百怪，工具层的判断（是不是缺凭据、要不要打码）不能只对着一种措辞验。
func (s *Server) rejectText(def string) string {
	if s.RejectText != "" {
		return s.RejectText
	}
	return def
}

// playText 用测试指定的那一句，没指定就说「Started playing」。
func (s *Server) playText() string {
	if s.PlayText != "" {
		return s.PlayText
	}
	return "Started playing"
}

// feed 按节奏发几条音视频消息，让码率是一个能算准的数。
func (s *Server) feed(cw *chunkWriter) error {
	if s.Mode == ModeChunkMidway {
		if err := cw.protocol(1, 128); err != nil {
			return err
		}
		cw.chunk = 128
	}
	var ts uint32
	// 元数据排在媒体前面：真实现场就是这个顺序（推流端先报「我打算发这么大」，
	// 再开始发字节）。
	if err := cw.data(4, 1, "@setDataFrame", "onMetaData", map[string]any{
		"width": 1920.0, "height": 1080.0, "framerate": 25.0,
		"videodatarate": 2000.0, "audiodatarate": 64.0,
		"videocodecid": 7.0, "audiocodecid": 10.0,
	}); err != nil {
		return err
	}
	for i := 0; i < s.MediaBurst; i++ {
		var payload []byte
		if i%2 == 1 { // audio：1 字节 tag header + 正文
			payload = make([]byte, s.MediaSize)
			payload[0] = 0xaf
			for j := 1; j < len(payload); j++ {
				payload[j] = byte(j)
			}
		} else { // video：关键帧要能数出来，第一个字节高 4 位是 1
			payload = make([]byte, s.MediaSize)
			payload[0] = 0x17
			for j := 1; j < len(payload); j++ {
				payload[j] = byte(j)
			}
		}
		if s.Mode == ModeExtendedTS && i == s.MediaBurst-1 {
			ts = 0x01000000 // 超过 3 字节能写的范围，必须走扩展时间戳
		}
		typ := byte(9)
		if i%2 == 1 {
			typ = 8
		}
		if err := cw.message(6, typ, 1, ts, payload); err != nil {
			return err
		}
		ts += uint32(s.MediaEvery / time.Millisecond)
		time.Sleep(s.MediaEvery)
	}
	return nil
}

// pad 保证长度是 1536（客户端可能写得不一样长）。
func pad(b []byte) []byte {
	if len(b) >= 1536 {
		return b[:1536]
	}
	out := make([]byte, 1536)
	copy(out, b)
	return out
}

// ── 下面这一小截是假服务器自己的分块与 AMF0 实现 ──

type message struct {
	csid     uint32
	typ      byte
	streamID uint32
	ts       uint32
	body     []byte
}

type chunkReader struct {
	r     io.Reader
	chunk int
	hdrs  map[uint32]*chState
}

type chState struct {
	ts, len uint32
	typ     byte
	sid     uint32
	ext     bool
	got     []byte
}

func newChunkReader(r io.Reader) *chunkReader {
	return &chunkReader{r: r, chunk: 128, hdrs: map[uint32]*chState{}}
}

func (cr *chunkReader) read() (*message, error) {
	for {
		b, err := read1(cr.r)
		if err != nil {
			return nil, err
		}
		fmtBits := b >> 6
		csid := uint32(b & 0x3f)
		if csid == 0 {
			x, err := read1(cr.r)
			if err != nil {
				return nil, err
			}
			csid = uint32(x) + 64
		} else if csid == 1 {
			xs, err := readN(cr.r, 2)
			if err != nil {
				return nil, err
			}
			csid = uint32(xs[0]) + uint32(xs[1])*256 + 64
		}
		st := cr.hdrs[csid]
		if st == nil {
			st = &chState{}
			cr.hdrs[csid] = st
		}
		switch fmtBits {
		case 0:
			h, err := readN(cr.r, 11)
			if err != nil {
				return nil, err
			}
			st.ts = uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])
			st.len = uint32(h[3])<<16 | uint32(h[4])<<8 | uint32(h[5])
			st.typ = h[6]
			st.sid = binary.LittleEndian.Uint32(h[7:11])
			st.ext = st.ts == 0xffffff
			if st.ext {
				e, err := readN(cr.r, 4)
				if err != nil {
					return nil, err
				}
				st.ts = binary.BigEndian.Uint32(e)
			}
			st.got = st.got[:0]
		case 1:
			h, err := readN(cr.r, 7)
			if err != nil {
				return nil, err
			}
			d := uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])
			st.len = uint32(h[3])<<16 | uint32(h[4])<<8 | uint32(h[5])
			st.typ = h[6]
			st.ext = d == 0xffffff
			if st.ext {
				e, err := readN(cr.r, 4)
				if err != nil {
					return nil, err
				}
				d = binary.BigEndian.Uint32(e)
			}
			st.ts += d
			st.got = st.got[:0]
		case 2:
			h, err := readN(cr.r, 3)
			if err != nil {
				return nil, err
			}
			d := uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])
			st.ext = d == 0xffffff
			if st.ext {
				e, err := readN(cr.r, 4)
				if err != nil {
					return nil, err
				}
				d = binary.BigEndian.Uint32(e)
			}
			st.ts += d
			st.got = st.got[:0]
		default:
			if st.ext {
				if _, err := readN(cr.r, 4); err != nil {
					return nil, err
				}
			}
		}
		need := int(st.len) - len(st.got)
		if need <= 0 {
			return &message{csid: csid, typ: st.typ, streamID: st.sid, ts: st.ts, body: st.got}, nil
		}
		take := cr.chunk
		if take > need {
			take = need
		}
		chunk, err := readN(cr.r, take)
		if err != nil {
			return nil, err
		}
		st.got = append(st.got, chunk...)
		if len(st.got) < int(st.len) {
			continue
		}
		body := append([]byte(nil), st.got...)
		st.got = st.got[:0]
		return &message{csid: csid, typ: st.typ, streamID: st.sid, ts: st.ts, body: body}, nil
	}
}

type chunkWriter struct {
	w     io.Writer
	chunk int
	// amf3 打开时命令消息用类型 17（AMF3 壳），正文前面多写两字节前缀。
	amf3 bool
	// bareTx 打开时，命令名后面那格 transaction id 只写 8 个裸 double 字节，
	// 不带 0x00 标记 —— 不少服务器就是这么写的。
	bareTx bool
}

func newChunkWriter(w io.Writer, chunk int) *chunkWriter {
	return &chunkWriter{w: w, chunk: chunk}
}

func (cw *chunkWriter) message(csid byte, typ byte, sid, ts uint32, body []byte) error {
	basic := csid & 0x3f
	ext := ts >= 0xffffff
	head := make([]byte, 1, 16)
	head[0] = basic // fmt 0
	if ext {
		head = append(head, 0xff, 0xff, 0xff)
	} else {
		head = append(head, byte(ts>>16), byte(ts>>8), byte(ts))
	}
	n := len(body)
	head = append(head, byte(n>>16), byte(n>>8), byte(n))
	head = append(head, typ)
	var sidb [4]byte
	binary.LittleEndian.PutUint32(sidb[:], sid)
	head = append(head, sidb[:]...)
	if ext {
		var e [4]byte
		binary.BigEndian.PutUint32(e[:], ts)
		head = append(head, e[:]...)
	}
	for off := 0; ; off += cw.chunk {
		end := off + cw.chunk
		if end > n {
			end = n
		}
		if err := writeAll(cw.w, append(head, body[off:end]...)); err != nil {
			return err
		}
		if end == n {
			return nil
		}
		head = []byte{0xc0 | basic} // fmt 3 续块
	}
}

func (cw *chunkWriter) protocol(typ byte, value uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	return cw.message(2, typ, 0, 0, b[:])
}

func (cw *chunkWriter) command(sid uint32, csid byte, name string, tx float64, rest ...any) error {
	var body []byte
	if cw.bareTx {
		body = amf0One(name)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(tx))
		body = append(body, b[:]...)
		body = append(body, amf0Encode(rest...)...)
	} else {
		body = amf0Encode(append([]any{name, tx}, rest...)...)
	}
	typ := byte(20)
	if cw.amf3 {
		// AMF3 壳：类型 17，正文最前面是两个字节（AMF3 字符串的长度前缀），
		// 后面照旧是 AMF0 序列 —— 各家实现都这么写。
		typ = 17
		body = append([]byte{0x00, 0x00}, body...)
	}
	return cw.message(csid, typ, sid, 0, body)
}

// data 发一条元数据（类型 18：不是命令，是 @setDataFrame / onMetaData）。
//
// ★ 现场推流端（OBS、摄像头、NVR 转推）几乎都先带这一条，里面写着它「打算发多大、
//
//	多快」—— 探测端要能把它和媒体字节分开数，不然声明分辨率就成了凭空多出来的数。
func (cw *chunkWriter) data(csid byte, sid uint32, vals ...any) error {
	return cw.message(csid, 18, sid, 0, amf0Encode(vals...))
}

// read1 / readN：定长小段逐段读。
func read1(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

// amf0Encode 是假服务器自己那一份 AMF0 编码器（字符串 / 数字 / 对象 / null）。
func amf0Encode(vals ...any) []byte {
	var out []byte
	for _, v := range vals {
		out = append(out, amf0One(v)...)
	}
	return out
}

func amf0One(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte{0x05}
	case string:
		return append([]byte{0x02, byte(len(x) >> 8), byte(len(x))}, x...)
	case float64:
		var b [9]byte
		b[0] = 0x00
		binary.BigEndian.PutUint64(b[1:], math.Float64bits(x))
		return b[:]
	case bool:
		if x {
			return []byte{0x01, 1}
		}
		return []byte{0x01, 0}
	case map[string]any:
		out := []byte{0x03}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, byte(len(k)>>8), byte(len(k)))
			out = append(out, k...)
			out = append(out, amf0One(x[k])...)
		}
		return append(out, 0x00, 0x00, 0x09)
	}
	return []byte{0x05}
}

func bitsFloat(b []byte) float64 {
	return math.Float64frombits(binary.BigEndian.Uint64(b))
}

// decodeCommand 只解假服务器需要认的那几种值。
func decodeCommand(b []byte) (string, float64, []any) {
	name, rest := decString(b)
	tx, rest := decNumberRest(rest)
	var args []any
	for len(rest) > 0 {
		if len(rest) < 2 {
			break
		}
		switch {
		case rest[0] == 0x02:
			var s string
			s, rest = decString(rest)
			args = append(args, s)
		case rest[0] == 0x00:
			var f float64
			f, rest = decNumber(rest)
			args = append(args, f)
		case rest[0] == 0x05 || rest[0] == 0x06:
			rest = rest[1:]
			args = append(args, nil)
		case rest[0] == 0x03:
			var m map[string]any
			m, rest = decObject(rest)
			args = append(args, m)
		default:
			rest = nil
		}
	}
	return name, tx, args
}

func decString(b []byte) (string, []byte) {
	if len(b) < 3 || b[0] != 0x02 {
		return "", b
	}
	n := int(b[1])<<8 | int(b[2])
	if len(b) < 3+n {
		return "", nil
	}
	return string(b[3 : 3+n]), b[3+n:]
}

func decNumber(b []byte) (float64, []byte) {
	if len(b) < 9 || b[0] != 0x00 {
		// 命令名后面那一格常常没有类型标记，直接是 8 字节裸 double。
		if len(b) >= 8 {
			return bitsFloat(b[:8]), b[8:]
		}
		return 0, b
	}
	return bitsFloat(b[1:9]), b[9:]
}

func decNumberRest(b []byte) (float64, []byte) {
	if len(b) == 0 {
		return 0, b
	}
	if b[0] == 0x00 {
		return decNumber(b)
	}
	if len(b) >= 8 {
		return bitsFloat(b[:8]), b[8:]
	}
	return 0, b
}

func decObject(b []byte) (map[string]any, []byte) {
	if len(b) < 1 {
		return nil, b
	}
	b = b[1:]
	out := map[string]any{}
	for {
		if len(b) < 3 {
			return out, nil
		}
		n := int(b[0])<<8 | int(b[1])
		if n == 0 && b[2] == 0x09 {
			return out, b[3:]
		}
		if len(b) < 3+n {
			return out, nil
		}
		key := string(b[2 : 2+n])
		b = b[2+n:]
		switch {
		case len(b) > 0 && b[0] == 0x02:
			var s string
			s, b = decString(b)
			out[key] = s
		case len(b) > 0 && b[0] == 0x00:
			var f float64
			f, b = decNumber(b)
			out[key] = f
		case len(b) > 0 && b[0] == 0x01:
			if len(b) > 1 {
				out[key] = b[1] != 0
				b = b[2:]
			}
		default:
			if len(b) > 0 {
				out[key] = nil
				b = b[1:]
			}
		}
	}
}
