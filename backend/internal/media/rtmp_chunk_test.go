package media

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// 分块（chunk）这一层的单元测试。★ 这里全部是手拼字节，不走探测端自己的写头函数：
// 假服务器那一份是另一套实现，端到端测的是「两套能不能对上」；
// 这一层要测的是「对端这么写的时候我们该怎么读」，所以把字节一条条钉死在纸面上。

// chunkFmt0 = fmt 0 起头的一个块：1 字节 csid + 3 时间戳 + 3 长度 + 1 类型 + 4 流号（小端）。
func chunkFmt0(csid byte, ts, length uint32, typeID byte, streamID uint32, body []byte) []byte {
	out := []byte{csid & 0x3f, byte(ts >> 16), byte(ts >> 8), byte(ts),
		byte(length >> 16), byte(length >> 8), byte(length), typeID}
	var sid [4]byte
	binary.LittleEndian.PutUint32(sid[:], streamID)
	return append(append(out, sid[:]...), body...)
}

// chunkFmt0Ext = fmt 0 + 4 字节扩展时间戳（3 字节那位写成 0xffffff）。
func chunkFmt0Ext(csid byte, ts, length uint32, typeID byte, streamID uint32, body []byte) []byte {
	out := chunkFmt0(csid, 0xffffff, length, typeID, streamID, nil)
	var ext [4]byte
	binary.BigEndian.PutUint32(ext[:], ts)
	out = append(out, ext[:]...)
	return append(out, body...)
}

func chunkFmt1(csid byte, delta, length uint32, typeID byte, body []byte) []byte {
	out := []byte{1<<6 | (csid & 0x3f), byte(delta >> 16), byte(delta >> 8), byte(delta),
		byte(length >> 16), byte(length >> 8), byte(length), typeID}
	return append(out, body...)
}

func chunkFmt2(csid byte, delta uint32, body []byte) []byte {
	out := []byte{2<<6 | (csid & 0x3f), byte(delta >> 16), byte(delta >> 8), byte(delta)}
	return append(out, body...)
}

func chunkFmt3(csid byte, body []byte) []byte {
	return append([]byte{0xc0 | (csid & 0x3f)}, body...)
}

func readAllMessages(t *testing.T, b []byte, peerChunk int) []*RTMPMessage {
	t.Helper()
	cr := newChunkReader(bytes.NewReader(b))
	if peerChunk > 0 {
		if err := cr.setPeerChunkSize(peerChunk); err != nil {
			t.Fatal(err)
		}
	}
	var out []*RTMPMessage
	for {
		m, err := cr.ReadMessage()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "EOF") {
				return out
			}
			t.Fatalf("读到第 %d 条就错了：%v", len(out), err)
		}
		out = append(out, m)
	}
}

// 一条消息切成 fmt0 + 两个 fmt3 续块：正文必须按原样拼回来，一条不多一条不少。
func Test一条消息三个块拼回来一字不差(t *testing.T) {
	body := make([]byte, 300)
	for i := range body {
		body[i] = byte(i % 251)
	}
	wire := chunkFmt0(5, 120, 300, TypeVideo, 1, body[:128])
	wire = append(wire, chunkFmt3(5, body[128:256])...)
	wire = append(wire, chunkFmt3(5, body[256:])...)

	got := readAllMessages(t, wire, 128)
	if len(got) != 1 {
		t.Fatalf("该只有一条消息，读到 %d 条", len(got))
	}
	m := got[0]
	if !bytes.Equal(m.Payload, body) {
		t.Errorf("正文拼错了：%d 字节 vs %d 字节", len(m.Payload), len(body))
	}
	if m.TypeID != TypeVideo || m.StreamID != 1 || m.Timestamp != 120 || m.Csid != 5 {
		t.Errorf("头读歪了：类型 %d 流号 %d 时间戳 %d 块流 %d",
			m.TypeID, m.StreamID, m.Timestamp, m.Csid)
	}
}

// ★ 流号是小端写的（这一层别处全是大端）：读反了的话 play 就落在另一条流上。
func Test流号按小端读(t *testing.T) {
	const want = uint32(0x01020304)
	wire := chunkFmt0(4, 0, 1, TypeCommandAMF0, want, []byte{0x14})
	got := readAllMessages(t, wire, 128)
	if len(got) != 1 {
		t.Fatalf("一条都没读到")
	}
	if got[0].StreamID != want {
		t.Errorf("流号读成 0x%08x 了", got[0].StreamID)
	}
	// 挑的数必须「大端读出来不一样」，不然这个用例什么都没验
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], want)
	if binary.BigEndian.Uint32(raw[:]) == want {
		t.Fatal("这个数大端小端一样，换个数再验")
	}
}

// 两条块流交错着写（真服务器就是这样：命令在 3，媒体在 4/5/6）。
func Test两条块流交错各归各(t *testing.T) {
	a := bytes.Repeat([]byte("A"), 200)
	b := bytes.Repeat([]byte("B"), 50)
	wire := chunkFmt0(3, 0, uint32(len(a)), TypeCommandAMF0, 0, a[:128])
	wire = append(wire, chunkFmt0(4, 10, uint32(len(b)), TypeAudio, 1, b)...)
	wire = append(wire, chunkFmt3(3, a[128:])...)

	got := readAllMessages(t, wire, 128)
	if len(got) != 2 {
		t.Fatalf("该读到 2 条：%d", len(got))
	}
	if !bytes.Equal(got[0].Payload, b) || got[0].TypeID != TypeAudio || got[0].Timestamp != 10 {
		t.Errorf("先到的那条读歪了：%+v", got[0])
	}
	if !bytes.Equal(got[1].Payload, a) || got[1].Csid != 3 {
		t.Errorf("续块那条读歪了：%d 字节", len(got[1].Payload))
	}
}

// 块流号 64 以上的两种扩展写法：低 6 位是 0 → 后跟 1 字节；是 1 → 后跟 2 字节。
func Test块流号的两种扩展写法(t *testing.T) {
	// 头部固定 11 字节：时间戳 3 + 长度 3 + 类型 1 + 流号 4，接在 csid（含扩展字节）后面
	head := []byte{0, 0, 0, 0, 0, 1, TypeVideo, 0, 0, 0, 0}
	mk := func(first byte, ext []byte, body []byte) []byte {
		out := append([]byte{first}, ext...)
		out = append(out, head...)
		return append(out, body...)
	}

	// 低 6 位 0（fmt 0）+ 一个扩展字节 36 → 36+64 = 100
	wire := mk(0x00, []byte{100 - 64}, []byte{9})
	got := readAllMessages(t, wire, 128)
	if len(got) != 1 || got[0].Csid != 100 {
		t.Fatalf("单字节扩展的块流号读错了：%+v", got)
	}

	// 低 6 位 1 + 两个扩展字节（低字节在前）→ 236+64 = 300
	wire = mk(0x01, []byte{byte((300 - 64) & 0xff), byte((300 - 64) >> 8)}, []byte{9})
	got = readAllMessages(t, wire, 128)
	if len(got) != 1 || got[0].Csid != 300 {
		t.Fatalf("两字节扩展的块流号读错了：%+v", got)
	}
}

// fmt 0 的 3 字节时间戳写成 0xffffff 时，后面跟 4 字节扩展值。
func Test扩展时间戳读的是后四字节(t *testing.T) {
	wire := chunkFmt0Ext(6, 0x01234567, 1, TypeVideo, 1, []byte{1})
	got := readAllMessages(t, wire, 128)
	if len(got) != 1 {
		t.Fatalf("一条都没读到")
	}
	if got[0].Timestamp != 0x01234567 {
		t.Errorf("扩展时间戳读成 0x%x", got[0].Timestamp)
	}
	if !bytes.Equal(got[0].Payload, []byte{1}) {
		t.Errorf("那 4 字节要是没读走，正文就成 %v 了", got[0].Payload)
	}
}

// fmt 1：换一条消息，时间戳给的是增量，长度与类型重新写。
func TestFMT1的时间戳按增量累加(t *testing.T) {
	wire := chunkFmt0(6, 1000, 1, TypeVideo, 1, []byte{1})
	wire = append(wire, chunkFmt1(6, 32, 1, TypeAudio, []byte{2})...)
	got := readAllMessages(t, wire, 128)
	if len(got) != 2 {
		t.Fatalf("fmt1 那条没读出来：%d", len(got))
	}
	if got[1].Timestamp != 1032 {
		t.Errorf("时间戳没累加：%d", got[1].Timestamp)
	}
	if got[1].TypeID != TypeAudio || !bytes.Equal(got[1].Payload, []byte{2}) {
		t.Errorf("fmt1 的类型或正文读歪了：%+v", got[1])
	}
}

// fmt 2：只带增量，长度与类型沿用上一条。
func TestFMT2沿用上一条的长度与类型(t *testing.T) {
	wire := chunkFmt0(6, 500, 1, TypeVideo, 1, []byte{1})
	wire = append(wire, chunkFmt2(6, 0x100, []byte{7})...)
	got := readAllMessages(t, wire, 128)
	if len(got) != 2 {
		t.Fatalf("fmt2 那条没读出来：%d", len(got))
	}
	if got[1].Timestamp != 500+0x100 || got[1].TypeID != TypeVideo {
		t.Errorf("fmt2 读得不一样：%+v", got[1])
	}
}

// fmt 1/2 的增量也能走扩展形式（长录像上时间戳过 3 字节是常事）。
func TestFMT1与FMT2的扩展增量(t *testing.T) {
	var ext [4]byte
	binary.BigEndian.PutUint32(ext[:], 0x00010000)
	wire := chunkFmt0(6, 0, 1, TypeVideo, 1, []byte{1})
	// fmt1：delta 写 0xffffff 再跟 4 字节
	f1 := []byte{1<<6 | 6, 0xff, 0xff, 0xff, 0, 0, 1, TypeVideo}
	wire = append(append(append(wire, f1...), ext[:]...), []byte{2}...)
	// fmt2：同样
	f2 := []byte{2<<6 | 6, 0xff, 0xff, 0xff}
	wire = append(append(append(wire, f2...), ext[:]...), []byte{3}...)

	got := readAllMessages(t, wire, 128)
	if len(got) != 3 {
		t.Fatalf("读到 %d 条：%+v", len(got), got)
	}
	if got[1].Timestamp != 0x10000 || got[2].Timestamp != 0x20000 {
		t.Errorf("扩展增量没加对：%d %d", got[1].Timestamp, got[2].Timestamp)
	}
}

// 0 字节的一条消息：有的服务器用它回 ACK，照实给出去，不算读错。
func Test零字节的消息照样返回(t *testing.T) {
	wire := chunkFmt0(2, 0, 0, TypeAck, 0, nil)
	got := readAllMessages(t, wire, 128)
	if len(got) != 1 || len(got[0].Payload) != 0 || got[0].TypeID != TypeAck {
		t.Fatalf("空消息没读出来：%d 条 %+v", len(got), got)
	}
}

// ★ 对端自称的长度必须先过上界：一个 42 亿字节的长度字段不挡的话，
//
//	下一口分配就把这台机器顶穿了。
func Test自称超长的消息直接被拒(t *testing.T) {
	wire := chunkFmt0(3, 0, maxRTMPMessage+1, TypeVideo, 0, []byte{1})
	cr := newChunkReader(bytes.NewReader(wire))
	if _, err := cr.ReadMessage(); err == nil || !strings.Contains(err.Error(), "上界") {
		t.Errorf("超长消息没被挡住：%v", err)
	}
}

// 块大小的上界与生效范围：报了错的不许改状态；改成功的只影响之后新读的块。
func Test块大小只影响之后的块(t *testing.T) {
	body := bytes.Repeat([]byte("z"), 200)
	wire := chunkFmt0(4, 0, 200, TypeVideo, 1, body[:128])
	wire = append(wire, chunkFmt3(4, body[128:])...)
	cr := newChunkReader(bytes.NewReader(wire))
	if err := cr.setPeerChunkSize(1 << 24); err == nil {
		t.Error("自称 1600 万的块大小没挡住")
	}
	if err := cr.setPeerChunkSize(0); err == nil {
		t.Error("块大小 0 没挡住（那样每次只读 0 字节，会死循环）")
	}
	if cr.peerChunk != 128 {
		t.Errorf("报错的块大小把状态改了：%d", cr.peerChunk)
	}
	m, err := cr.ReadMessage() // 仍然按 128 切
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Payload, body) {
		t.Errorf("按旧块大小没读全：%d", len(m.Payload))
	}

	// 换成 16 之后再写一条 40 字节的：仍按 128 读的话第一条就把后面的块头当正文吞掉
	next := bytes.Repeat([]byte("q"), 40)
	wire2 := chunkFmt0(4, 1, 40, TypeVideo, 1, next[:16])
	wire2 = append(wire2, chunkFmt3(4, next[16:32])...)
	wire2 = append(wire2, chunkFmt3(4, next[32:])...)
	cr2 := newChunkReader(bytes.NewReader(wire2))
	if err := cr2.setPeerChunkSize(16); err != nil {
		t.Fatal(err)
	}
	m2, err := cr2.ReadMessage()
	if err != nil || !bytes.Equal(m2.Payload, next) {
		t.Errorf("16 字节块没读全：%v %+v", err, m2)
	}
}

// Abort Message：正在攒的那条作废，之后同一块流重新起头必须还能读。
func Test中途被中止的块流重新起头还能读(t *testing.T) {
	half := chunkFmt0(6, 0, 300, TypeVideo, 1, bytes.Repeat([]byte("x"), 128))
	cr := newChunkReader(bytes.NewReader(half))
	if _, err := cr.ReadMessage(); err != io.EOF {
		t.Fatalf("先读到一半断了才对，得到：%v", err)
	}
	if len(cr.states[6].got) == 0 {
		t.Fatal("用例前提不成立：那条半截消息没攒上东西")
	}
	cr.dropCsid(6)
	if _, ok := cr.states[6]; ok {
		t.Fatal("dropCsid 没把那条块流清掉")
	}
	// 半截不清的话，这条 40 字节的会被补成 300 字节的怪东西
	cr.r = bytes.NewReader(chunkFmt0(6, 9, 40, TypeAudio, 1, bytes.Repeat([]byte("y"), 40)))
	m, err := cr.ReadMessage()
	if err != nil {
		t.Fatalf("清掉之后读不回来了：%v", err)
	}
	if len(m.Payload) != 40 || m.TypeID != TypeAudio || m.Timestamp != 9 {
		t.Errorf("重新起头的这条读得不干净：%+v", m)
	}
}

// 写出去的一条消息，用读的那一份回来必须一模一样（含被切成几段、扩展时间戳）。
func Test写出去再读回来一模一样(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chunk int
		ts    uint32
		size  int
	}{
		{"默认 4096 一条一块", 4096, 1234, 100},
		{"128 切成四块", 128, 7, 400},
		{"扩展时间戳", 4096, 0xffffff, 60},
		{"扩展时间戳还要切块", 128, 0x12345678, 300},
		{"正文为空", 128, 0, 0},
	} {
		var buf bytes.Buffer
		cw := newChunkWriter(&buf)
		cw.ourChunk = tc.chunk
		payload := make([]byte, tc.size)
		for i := range payload {
			payload[i] = byte(i * 7 % 256)
		}
		if err := cw.WriteMessage(4, TypeVideo, 1, tc.ts, payload); err != nil {
			t.Fatalf("%s：%v", tc.name, err)
		}
		got := readAllMessages(t, buf.Bytes(), tc.chunk)
		if len(got) != 1 {
			t.Fatalf("%s：写出 %d 字节读出 %d 条", tc.name, len(payload), len(got))
		}
		if !bytes.Equal(got[0].Payload, payload) {
			t.Errorf("%s：正文回来了但不是那一份", tc.name)
		}
		if got[0].Timestamp != tc.ts {
			t.Errorf("%s：时间戳 0x%x → 0x%x", tc.name, tc.ts, got[0].Timestamp)
		}
		if got[0].StreamID != 1 || got[0].TypeID != TypeVideo || got[0].Csid != 4 {
			t.Errorf("%s：头写歪了 %+v", tc.name, *got[0])
		}
	}
}

// 块流号越界要报错：0/1 是保留的（协议消息），64 以上得走扩展字节，探测端不写那些。
func Test块流号越界报错(t *testing.T) {
	var buf bytes.Buffer
	cw := newChunkWriter(&buf)
	for _, bad := range []uint32{0, 1, 64, 9999} {
		if err := cw.WriteMessage(bad, TypeCommandAMF0, 0, 0, []byte{20}); err == nil {
			t.Errorf("块流号 %d 居然写出去了", bad)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("报错之前还是写了 %d 字节", buf.Len())
	}
}

// 读到一半对端把连接断了：报的是读错，不是返回半条消息。
func Test读到一半就断了不返回半条(t *testing.T) {
	wire := chunkFmt0(4, 0, 300, TypeVideo, 1, bytes.Repeat([]byte("w"), 128))
	cr := newChunkReader(bytes.NewReader(wire))
	if m, err := cr.ReadMessage(); err == nil {
		t.Errorf("正文不够却返回了消息：%+v", m)
	}
}

// 扩展时间戳的续块也带着那 4 字节：少读一格，整条连接的块边界全乱。
func Test扩展时间戳的续块也带四字节(t *testing.T) {
	var ext [4]byte
	binary.BigEndian.PutUint32(ext[:], 0x01000000)
	wire := chunkFmt0Ext(5, 0x01000000, 40, TypeVideo, 1, bytes.Repeat([]byte("a"), 20))
	wire = append(wire, 0xc0|5)
	wire = append(wire, ext[:]...)
	wire = append(wire, bytes.Repeat([]byte("b"), 20)...)
	got := readAllMessages(t, wire, 20)
	if len(got) != 1 {
		t.Fatalf("读到 %d 条", len(got))
	}
	if len(got[0].Payload) != 40 {
		t.Fatalf("正文只有 %d 字节：续块那 4 字节没跟着读", len(got[0].Payload))
	}
	if string(got[0].Payload[20:]) != strings.Repeat("b", 20) {
		t.Errorf("正文后半截错位了：%q", string(got[0].Payload[20:]))
	}
	if got[0].Timestamp != 0x01000000 {
		t.Errorf("时间戳 %x", got[0].Timestamp)
	}
}

// 每条消息读完必须正好停在下一个块的边界上：错一格，后面每一条都歪。
func Test每条消息读完后正好停在边界上(t *testing.T) {
	body := bytes.Repeat([]byte("m"), 260)
	wire := chunkFmt0(6, 1, uint32(len(body)), TypeAudio, 1, body[:128])
	wire = append(wire, chunkFmt3(6, body[128:256])...)
	wire = append(wire, chunkFmt3(6, body[256:])...)
	wire = append(wire, chunkFmt0(6, 2, 3, TypeCommandAMF0, 1, []byte("hi!"))...)

	br := bytes.NewReader(wire)
	cr := newChunkReader(br)
	for i := 0; i < 2; i++ {
		if _, err := cr.ReadMessage(); err != nil {
			t.Fatalf("第 %d 条：%v", i+1, err)
		}
	}
	if br.Len() != 0 {
		t.Errorf("还剩 %d 字节没读走：块边界算错了", br.Len())
	}
}

// slowReader 一次只给一个字节：重组不该依赖「一整块正好到位」。
type slowReader struct {
	r   io.Reader
	buf []byte
}

func (s *slowReader) Read(p []byte) (int, error) {
	if len(s.buf) == 0 {
		b := make([]byte, 1)
		if _, err := io.ReadFull(s.r, b); err != nil {
			return 0, err
		}
		s.buf = b
	}
	p[0] = s.buf[0]
	s.buf = nil
	return 1, nil
}

func Test一次只给一个字节也读得对(t *testing.T) {
	body := bytes.Repeat([]byte("s"), 300)
	wire := chunkFmt0(7, 3, uint32(len(body)), TypeVideo, 1, body[:128])
	wire = append(wire, chunkFmt3(7, body[128:256])...)
	wire = append(wire, chunkFmt3(7, body[256:])...)
	cr := newChunkReader(&slowReader{r: bytes.NewReader(wire)})
	m, err := cr.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Payload, body) {
		t.Errorf("逐字节喂就散了：%d 字节", len(m.Payload))
	}
}

// IsMedia 只认能算进码率的那几类：命令、元数据、协议消息一律不算。
func Test只有音视频与聚合算媒体(t *testing.T) {
	for _, typ := range []uint8{TypeAudio, TypeVideo, TypeAggregate} {
		if !(&RTMPMessage{TypeID: typ}).IsMedia() {
			t.Errorf("类型 %d 该算媒体", typ)
		}
	}
	for _, typ := range []uint8{TypeSetChunkSize, TypeAbort, TypeAck, TypeUserControl,
		TypeWindowAckSize, TypeSetPeerBW, TypeDataAMF3, TypeCommandAMF3, TypeDataAMF0} {
		if (&RTMPMessage{TypeID: typ}).IsMedia() {
			t.Errorf("类型 %d 不该算媒体（会把码率算虚高）", typ)
		}
	}
}
