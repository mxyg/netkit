package flow

// 按 seq 拼一条 TCP 方向上的字节流。
//
// 为什么单独一格：应用层的报文是分片发的 —— 一条 RTSP 的 SETUP 应答可以落在三个包里，
// 直接拿单包正文去解，得到的就是「解不出来」，而现场看到的表上写着「这台相机没回话」。
//
// ★ 缺口不造假：序号跳了就把跳过的字节数记进 Lost，然后把游标挪到新到的那一段上。
// 这里最坏的做法是「拿零填充把洞补上再交给上层解」——上层解出来的是**一份看着像样的假报文**，
// 比一句「拼不上」坏得多：它会让人照着假内容去改配置。
//
// 序号会绕圈（32 位回绕），所以比大小一律用 int32 差值，不许直接 <。

import (
	"fmt"
	"time"
)

// DefaultStreamCap 是每个方向最多留多少连续正文交给上层解。
//
// 为什么要有这一格：一条流可以吃掉几 GB（下载、录像回放），
// 不设上限就是「看一张表把机器内存看没了」。
const DefaultStreamCap = 64 << 10

// seqLt 按回绕比大小：a 在 b 前面。
func seqLt(a, b uint32) bool { return int32(a-b) < 0 }

// seqGte 按回绕比大小：a 不在 b 前面。
func seqGte(a, b uint32) bool { return int32(a-b) >= 0 }

// Stream 是一个方向上拼出来的字节流与它的账。
type Stream struct {
	Bytes   int       // 接进连续流的字节数（不含缺的那些）
	Lost    int       // 跳号时估出来的缺口合计（字节）
	Gaps    int       // 空洞处数（不是字节数）
	Retrans int       // 序号落在已覆盖区间内的带数据段：重传或零窗探测的重复
	Kept    int       // 缓冲里留着多少字节（不超过这一方向的上限）
	Capped  bool      // 撞到上限：后面的正文不再留，账照记
	LastAt  time.Time // 最后一个带数据的段
}

func (s Stream) String() string {
	t := fmt.Sprintf("%d 字节", s.Bytes)
	if s.Lost > 0 {
		t += fmt.Sprintf("（缺 %d 字节 / %d 处）", s.Lost, s.Gaps)
	}
	if s.Retrans > 0 {
		t += fmt.Sprintf("，重传 %d 段", s.Retrans)
	}
	if s.Capped {
		t += "，正文只留到上限"
	}
	return t
}

// streamState 是一个方向上的拼接状态。buf 只从连续的那一段往后长。
type streamState struct {
	next    uint32
	started bool
	cap     int
	buf     []byte
	st      Stream
}

func newStreamState(capn int) *streamState {
	if capn <= 0 {
		capn = DefaultStreamCap
	}
	return &streamState{cap: capn, buf: make([]byte, 0, 256)}
}

// add 收一个 TCP 段，回本次接进连续流的那一段（纯 ACK 与重复段回 nil）。
//
// payload 为空也要调：上层用它更新 LastAt 之外的状态时不许拿它当「有正文」。
func (s *streamState) add(seq uint32, payload []byte, at time.Time) []byte {
	if len(payload) == 0 {
		return nil
	}
	s.st.LastAt = at
	end := seq + uint32(len(payload))
	if !s.started {
		s.started = true
		s.next = seq
	}

	switch {
	case seq == s.next || seqLt(s.next, seq):
		// 正常那一种（seq == next），或跳号那一种。
		if seqGte(seq, s.next) && seq != s.next {
			// ★ 跳号：中间那段没见到。只记账，不拿零补。
			s.st.Gaps++
			s.st.Lost += int(seq - s.next)
		}
		s.st.Bytes += len(payload)
		s.next = end
		s.keep(payload)
		return payload
	case seqLt(seq, s.next) && seqGte(end, s.next):
		// 比游标早、又超出了一截：迟到的一段正好补洞，只接超出的那一部分。
		n := int(end - s.next)
		s.st.Bytes += n
		s.next = end
		tail := payload[len(payload)-n:]
		s.keep(tail)
		return tail
	default:
		// 整段都在已覆盖区间里：同一份又发了一遍。
		s.st.Retrans++
		return nil
	}
}

func (s *streamState) keep(b []byte) {
	if len(s.buf) >= s.cap {
		s.st.Capped = true
		return
	}
	room := s.cap - len(s.buf)
	if len(b) > room {
		s.buf = append(s.buf, b[:room]...)
		s.st.Capped = true
	} else {
		s.buf = append(s.buf, b...)
	}
	s.st.Kept = len(s.buf)
}

// contiguous 回缓冲里那一份连续正文（上层只在它变长之后重新切报文）。
func (s *streamState) contiguous() []byte { return s.buf }

// Cap 回这一方向的正文书上限，判定句子要说「只留到多少字节」。
func (s *streamState) Cap() int { return s.cap }
