package media

// RTMP 分块（chunk）编解码 —— 协议本身：一条消息被切成若干块，每块前面带一个
// 越来越省的头（fmt 0→3 复用上一个块的字段）。
//
// ★ 为什么要自己实现：现场那句「推流没到平台」中间隔着三层，逐层要问的东西不一样
//
//	（端口开没开 → 是不是 RTMP 握手 → 应用认不认 → 这路名上有没有流 →
//	有没有真的媒体字节过来）。第三方库把这几层糊成一次「连接成功/失败」，
//	正好把要区分的那几档抹掉了。
//
// ★ 所有从对端读到的长度都要过上界：消息长度、块大小、字符串长度都是对端说了算。
//
//	「自称 42 亿字节的一条消息」必须先挡住，不然大头还没到，内存先没了。

import (
	"encoding/binary"
	"fmt"
	"io"
)

// RTMP 消息类型里探测用得上的那几种。
const (
	TypeSetChunkSize  uint8 = 1
	TypeAbort         uint8 = 2
	TypeAck           uint8 = 3
	TypeUserControl   uint8 = 4
	TypeWindowAckSize uint8 = 5
	TypeSetPeerBW     uint8 = 6
	TypeAudio         uint8 = 8
	TypeVideo         uint8 = 9
	TypeDataAMF3      uint8 = 15 // @setDataFrame / onMetaData（AMF3 壳里的 AMF0）
	TypeCommandAMF3   uint8 = 17
	TypeDataAMF0      uint8 = 18
	TypeCommandAMF0   uint8 = 20
	TypeAggregate     uint8 = 19

	rtmpHandshakeSize = 1536
	// 一条消息最多攒这么多。真正的关键帧没这么长，超了多半是长度字段被写坏，
	// 或者对端根本不是 RTMP —— 那就照实说「这条没读完」，不要继续攒。
	maxRTMPMessage = 8 << 20
	// 对端声明的块大小上界。同理，一个自称 4G 的块大小会让下一块的正文读不完。
	maxChunkSize = 1 << 20
)

// RTMPMessage 是一条重组完成的 RTMP 消息。
type RTMPMessage struct {
	Csid      uint32
	TypeID    uint8
	StreamID  uint32
	Timestamp uint32 // 绝对时间戳（毫秒）
	Payload   []byte
	// Truncated 正文超出上界、被丢掉一截。
	Truncated bool
}

// IsMedia 音频 / 视频 / 聚合 —— 真正能算进码率的那几类。
func (m *RTMPMessage) IsMedia() bool {
	switch m.TypeID {
	case TypeAudio, TypeVideo, TypeAggregate:
		return true
	}
	return false
}

// chunkHeader 是一个块流（chunk stream）的头部状态，fmt 1/2/3 要复用它。
type chunkHeader struct {
	timestamp uint32
	length    uint32
	typeID    uint8
	streamID  uint32
	// extended 这一路是否用 4 字节扩展时间戳。一旦某块用了，后续 fmt3 也带着走。
	extended bool
	// have 是否已经收到过这个块流的第一个块。
	have bool
}

// chunkReader 把字节流重组成消息。
type chunkReader struct {
	r         io.Reader
	peerChunk int
	states    map[uint32]*chunkState
}

type chunkState struct {
	hdr chunkHeader
	// got 正在攒的那条消息已收到的正文。
	got []byte
}

func newChunkReader(r io.Reader) *chunkReader {
	return &chunkReader{r: r, peerChunk: 128, states: map[uint32]*chunkState{}}
}

// readByte / readN：这条连接上的头都是定长小段，逐段读最省事。
func readByte(r io.Reader) (byte, error) {
	var one [1]byte
	if _, err := io.ReadFull(r, one[:]); err != nil {
		return 0, err
	}
	return one[0], nil
}

func readN(r io.Reader, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// setPeerChunkSize 收到 Set Chunk Size 时更新。★ 只影响之后新读的块：
// 已经在攒的那条消息仍按旧块大小切 —— 各家实现都这样，跟着做才不会读串。
func (cr *chunkReader) setPeerChunkSize(n int) error {
	if n < 1 || n > maxChunkSize {
		return fmt.Errorf("对端声明的块大小 %d 不合理", n)
	}
	cr.peerChunk = n
	return nil
}

// ReadMessage 读出一条完整消息。
//
// ★ 循环体是「读一个块 → 攒进对应块流 → 攒够一条消息才返回」：一条消息可能被
//
//	切成好几个块，也可能几条消息的块交错在同一条连接上，所以没攒够时继续读下一个
//	块，而不是报错。
//
// ★ 块与块之间靠对端声明的长度对齐。一旦对端写的正文比它自己声明的还长，
//
//	后面所有块都会读串 —— 这种只能报错断开，绝不能继续攒。
func (cr *chunkReader) ReadMessage() (*RTMPMessage, error) {
	for {
		first, err := readByte(cr.r)
		if err != nil {
			return nil, err
		}
		fmtBits := first >> 6
		csid, err := cr.readCsid(first & 0x3f)
		if err != nil {
			return nil, err
		}
		st, ok := cr.states[csid]
		if !ok {
			st = &chunkState{}
			cr.states[csid] = st
		}
		if err := cr.readHeader(st, csid, fmtBits); err != nil {
			return nil, err
		}

		remaining := int(st.hdr.length) - len(st.got)
		if remaining <= 0 {
			// 头里说这条消息 0 字节：那就是一条空消息，照实给出去（有的服务器
			// 用它回 ACK），别当成读错了。
			msg := st.message(csid)
			st.got = st.got[:0]
			return msg, nil
		}
		take := cr.peerChunk
		if take > remaining {
			take = remaining
		}
		body, err := readN(cr.r, take)
		if err != nil {
			return nil, err
		}
		st.got = append(st.got, body...)
		if len(st.got) < int(st.hdr.length) {
			continue // 这条消息还没攒完，继续读下一个块（fmt 3 续块）
		}
		msg := st.message(csid)
		st.got = st.got[:0]
		return msg, nil
	}
}

// readCsid 还原块流号：低 6 位是 0/1 时后面还跟着扩展字节。
func (cr *chunkReader) readCsid(low byte) (uint32, error) {
	switch low {
	case 0:
		b, err := readByte(cr.r)
		if err != nil {
			return 0, err
		}
		return uint32(b) + 64, nil
	case 1:
		bs, err := readN(cr.r, 2)
		if err != nil {
			return 0, err
		}
		return uint32(bs[0]) + uint32(bs[1])*256 + 64, nil
	default:
		return uint32(low), nil
	}
}

// readHeader 按 fmt 读消息头，更新块流状态。
func (cr *chunkReader) readHeader(st *chunkState, csid uint32, fmtBits byte) error {
	switch fmtBits {
	case 0:
		b, err := readN(cr.r, 11)
		if err != nil {
			return err
		}
		ts := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		st.hdr.length = uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
		st.hdr.typeID = b[6]
		// 流号是小端写的 —— 这是 RTMP 里最容易读反的一处。
		st.hdr.streamID = binary.LittleEndian.Uint32(b[7:11])
		st.hdr.extended = ts == 0xffffff
		if st.hdr.extended {
			b4, err := readN(cr.r, 4)
			if err != nil {
				return err
			}
			st.hdr.timestamp = binary.BigEndian.Uint32(b4)
		} else {
			st.hdr.timestamp = ts
		}
		st.got = st.got[:0] // 新的一条消息，从头攒
	case 1:
		b, err := readN(cr.r, 7)
		if err != nil {
			return err
		}
		delta := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		st.hdr.length = uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
		st.hdr.typeID = b[6]
		st.hdr.extended = delta == 0xffffff
		if st.hdr.extended {
			b4, err := readN(cr.r, 4)
			if err != nil {
				return err
			}
			delta = binary.BigEndian.Uint32(b4)
		}
		st.hdr.timestamp += delta
		st.got = st.got[:0]
	case 2:
		b, err := readN(cr.r, 3)
		if err != nil {
			return err
		}
		delta := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		st.hdr.extended = delta == 0xffffff
		if st.hdr.extended {
			b4, err := readN(cr.r, 4)
			if err != nil {
				return err
			}
			delta = binary.BigEndian.Uint32(b4)
		}
		st.hdr.timestamp += delta
		st.got = st.got[:0]
	default: // fmt 3：全复用 —— 要么是同一条消息的续块，要么是同一头的下一条。
		// 续块不改时间戳。这里不区分两者：探测只按类型数字节、认命令名，
		// 时间戳差这一格不影响任何一个判定。
		if st.hdr.extended {
			if _, err := readN(cr.r, 4); err != nil {
				return err
			}
		}
	}
	st.hdr.have = true
	if st.hdr.length > maxRTMPMessage {
		return fmt.Errorf("对端自称一条消息 %d 字节，超过 %d 的上界", st.hdr.length, maxRTMPMessage)
	}
	return nil
}

// dropCsid 丢掉一条块流的状态：收到 Abort Message 时，那条正在攒的消息作废。
func (cr *chunkReader) dropCsid(csid uint32) {
	delete(cr.states, csid)
}

func (st *chunkState) message(csid uint32) *RTMPMessage {
	payload := make([]byte, len(st.got))
	copy(payload, st.got)
	return &RTMPMessage{
		Csid:      csid,
		TypeID:    st.hdr.typeID,
		StreamID:  st.hdr.streamID,
		Timestamp: st.hdr.timestamp,
		Payload:   payload,
	}
}

// chunkWriter 把消息切成块写出去。
type chunkWriter struct {
	w        io.Writer
	ourChunk int
	hdr      [16]byte
}

func newChunkWriter(w io.Writer) *chunkWriter {
	return &chunkWriter{w: w, ourChunk: 4096}
}

// WriteMessage 用 fmt 0 起头（必要时后面接 fmt 3 续块）写一条消息。
//
// ★ 每条命令都重新起完整头：探测一共就发四五条命令，
//
//	省那几字节换不来什么，头写错却会把整条连接读乱。
func (cw *chunkWriter) WriteMessage(csid uint32, typeID uint8, streamID, timestamp uint32, payload []byte) error {
	if csid >= 2 && csid <= 63 {
		cw.hdr[0] = byte(csid & 0x3f)
	} else {
		return fmt.Errorf("探测用的块流号要在 2 到 63 之间，给的是 %d", csid)
	}
	extended := timestamp >= 0xffffff
	ts := timestamp
	if extended {
		ts = 0xffffff
	}
	cw.hdr[1] = byte(ts >> 16)
	cw.hdr[2] = byte(ts >> 8)
	cw.hdr[3] = byte(ts)
	n := len(payload)
	cw.hdr[4] = byte(n >> 16)
	cw.hdr[5] = byte(n >> 8)
	cw.hdr[6] = byte(n)
	cw.hdr[7] = typeID
	binary.LittleEndian.PutUint32(cw.hdr[8:12], streamID)
	at := 12
	if extended {
		binary.BigEndian.PutUint32(cw.hdr[12:16], timestamp)
		at = 16
	}
	for off := 0; ; off += cw.ourChunk {
		end := off + cw.ourChunk
		if end > n {
			end = n
		}
		if _, err := cw.w.Write(cw.hdr[:at]); err != nil {
			return err
		}
		if _, err := cw.w.Write(payload[off:end]); err != nil {
			return err
		}
		if end == n {
			return nil
		}
		// 续块：fmt 3 + 同一个块流号，没有消息头。
		cw.hdr[0] = 0xc0 | byte(csid&0x3f)
		at = 1
		if extended {
			binary.BigEndian.PutUint32(cw.hdr[1:5], timestamp)
			at = 5
		}
	}
}
