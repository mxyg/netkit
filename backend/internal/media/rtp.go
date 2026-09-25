package media

// RTP 这一路的到达统计。★ 这个包存在的另一半天在这里：
//
// 「SDP 里写着 25fps 1080p」说的是设备**打算**发什么，
// 「3 秒里到了多少包、隔多久来一个关键帧」说的才是盒子**收到**什么。
// 现场那句「它回了 200 却没有画面」正卡在两者中间 —— 而 ffprobe 也不答这三个数。
//
// ★ 口径写死在实现里：码率算的是**载荷字节**（不含 RTP 头与 UDP 头），
//   帧率数的是 **marker 位**（一帧的最后一包），关键帧间隔拿 **RTP 时间戳**算。
//   三个数各有各的算法，混着说一句就会在别的工具前对不上号。

import (
	"fmt"
	"time"
)

// 一路 RTP 里最多认几个源。★ 真会有第二个：换过一次 SETUP、NAT 后面两台设备
// 都在答，或者被人拿组播灌了一路。只认第一个会把「谁在发」读错。
const (
	maxSources = 8
	noteCap    = 8
	keyTSCap   = 64
)

// 序号与时间戳的回绕半程。
const (
	seqRange = int64(1) << 16
	tsRange  = int64(1) << 31
	tsFull   = int64(1) << 32
)

// 比这个窗口还短就不出码率与帧率：几个包折算出来的「2.4Mbps」是噪声。
const minSpan = 200 * time.Millisecond

// 序号一次跳超过这个数就不当连续的账来算 —— 那是重新起了一路流。
// ★ 一路流三秒也就三百来个包；拿「跳了一截」去算丢包，读数会是「丢了六万包」，
//
//	现场照着这个数字去查网络，查一辈子也查不出来。
const restartGap = 1 << 10

// 逐个记序号的上限。防的是被一个坏号段撑爆内存；到顶就退回按包数折算。
const seenCap = 1 << 14

// Collector 数一路 RTP 的到达情况。零值不可用，请走 NewCollector。
type Collector struct {
	codec     string // h264 / h265 / 空 = 说不出关键帧
	clock     int    // RTP 时钟；视频基本是 90000
	Transport string // udp / tcp-interleaved —— 决定丢包问不问得出来
	started   bool
	sources   []*source
	bySSRC    map[uint32]*source
	notes     []string
}

// source 是一个 SSRC 那一档的账。
type source struct {
	ssrc    uint32
	packets int
	payload int // 载荷字节，不含 RTP 头、扩展与 CSRC
	frames  int // marker 位计数 = 到了几帧的最后一包
	dupes   int
	reorder int

	haveSeq   bool
	lastRaw   int // 上一次见到的 16 位序号原值
	cycles    int64
	firstSeq  int64
	lastSeq   int64
	seen      map[int64]bool // 这一段里数过的序号；丢包按「几个号真到过」折算
	seenFull  bool           // 号记到上限了，退回按包数折算
	restarts  int            // 号段凭空跳了几次（重新起流）
	lastRawTS int
	tsCycles  int64
	keyTS     []int64 // 关键帧的 RTP 时间戳（已拆回绕）

	firstAt time.Time
	lastAt  time.Time
}

// NewCollector 起一份统计。codec 留空就只数包、不说关键帧；
// clock 不合理（0 或负）时退回视频惯用的 90kHz，并把这一格记进 notes ——
// 拿错的时钟折算出来的「关键帧隔 5 秒」比不给更坏。
func NewCollector(codec string, clockRate int) *Collector {
	c := &Collector{codec: codec, bySSRC: map[uint32]*source{}}
	switch {
	case clockRate > 0:
		c.clock = clockRate
	default:
		c.clock = 90000
		c.note("SDP 没给时钟频率，按视频惯用的 90kHz 折算时间戳")
	}
	return c
}

func (c *Collector) note(s string) {
	if len(c.notes) < noteCap {
		c.notes = append(c.notes, s)
	}
}

// Add 记一个报文（整个 UDP 数据报，或 TCP 交织帧去掉 4 字节前缀后的那一段）。
// 返回 false 表示这一包不是可认的 RTP（版本不对、太短），一个数都不计入。
func (c *Collector) Add(b []byte, at time.Time) bool {
	h, ok := rtpHeader(b)
	if !ok {
		return false
	}
	s := c.sourceFor(h.ssrc)
	if !c.started {
		c.started = true
	}
	if s.firstAt.IsZero() {
		s.firstAt = at
	}
	s.lastAt = at
	s.packets++
	s.payload += len(h.payload)
	first := !s.haveSeq // 这一档刚开：序号与时间戳都只记基线，不比差
	isNew := s.addSeq(h.seq, first)
	if !isNew {
		return true // 重复的那一包：字节到了线上，计进码率；但不再计一帧、一个关键帧
	}
	if h.marker {
		s.frames++
	}
	if c.handlesKeyframes() && keyframeStart(h.payload, c.codec) {
		s.keyTS = append(s.keyTS, s.addTS(h.timestamp, first))
		if len(s.keyTS) > keyTSCap {
			s.keyTS = s.keyTS[:keyTSCap] // 三秒用不了这么多，纯防设备发疯
		}
	}
	return true
}

// addSeq 拆 16 位序号的回绕，并回答「这个号是不是头一回到」。
//
// ★ 直接拿原值相减会在跨过 65535 时算出「丢了六万个包」—— 而那正是现场最容易
//
//	撞上的位置（一秒 90 个包，十几分钟一绕）。
//
// ★ 「到过的号」和「收到的包」是两笔账：TCP 重传、组播里两路并一份，都会把同一个
//
//	号送来两次。重复包要是也算收到，丢包那一格就退成「一个没丢」。
func (s *source) addSeq(raw int, first bool) bool {
	if first {
		s.haveSeq = true
		s.lastRaw = raw
		s.firstSeq = int64(raw)
		s.lastSeq = int64(raw)
		s.markSeen(s.firstSeq)
		return true
	}
	d := int64(raw) - int64(s.lastRaw)
	switch {
	case d <= -seqRange/2:
		s.cycles += seqRange // 正向跨过 65535
	case d >= seqRange/2:
		s.cycles -= seqRange // 上一圈里迟到的那一包
	}
	s.lastRaw = raw
	unw := s.cycles + int64(raw)
	if s.spanBreak(unw) {
		// 号段凭空跳了一大截：那是重新起了一路流，不是中间丢了上千包。
		s.restarts++
		s.firstSeq, s.lastSeq = unw, unw
		s.seen = nil
		s.markSeen(unw)
		return true
	}
	if unw > s.lastSeq {
		s.lastSeq = unw
	}
	if s.markSeen(unw) {
		if unw < s.lastSeq {
			s.reorder++ // 补上了一个缺号：迟到，不算丢
		}
		return true
	}
	s.dupes++
	return false
}

// spanBreak 前后向跳出这个距离的号，不接着上账算。
func (s *source) spanBreak(unw int64) bool {
	if unw-s.lastSeq > restartGap {
		return true
	}
	return s.firstSeq-unw > restartGap
}

// markSeen 记一个到过的号，返回它是不是新号。★ 记满了就不再逐个记，
// 由 Report 退回按包数折算 —— 那一档宁可粗一点，也不能把内存吃穿。
func (s *source) markSeen(unw int64) bool {
	if s.seenFull {
		return true
	}
	if s.seen == nil {
		s.seen = make(map[int64]bool)
	}
	if s.seen[unw] {
		return false
	}
	if len(s.seen) >= seenCap {
		s.seenFull = true
		return true
	}
	s.seen[unw] = true
	return true
}

// addTS 拆 32 位时间戳的回绕，思路同 addSeq。
func (s *source) addTS(raw int, first bool) int64 {
	if first {
		s.lastRawTS = raw
		return int64(raw)
	}
	d := int64(raw) - int64(s.lastRawTS)
	switch {
	case d <= -tsRange:
		s.tsCycles += tsFull
	case d >= tsRange:
		s.tsCycles -= tsFull
	}
	s.lastRawTS = raw
	return s.tsCycles + int64(raw)
}

func (c *Collector) sourceFor(ssrc uint32) *source {
	if s, ok := c.bySSRC[ssrc]; ok {
		return s
	}
	if len(c.sources) >= maxSources {
		c.note("来的 SSRC 多过 " + fmt.Sprint(maxSources) + " 个，后到的没再单开一档")
		return c.sources[0]
	}
	s := &source{ssrc: ssrc}
	c.sources = append(c.sources, s)
	c.bySSRC[ssrc] = s
	if len(c.sources) > 1 {
		c.note("中途来了第二个源（SSRC 换成 " + fmt.Sprintf("%x", ssrc) + "）—— 给人看的那一路是包最多的")
	}
	return s
}

func (c *Collector) handlesKeyframes() bool {
	return c.codec == "h264" || c.codec == "h265"
}

// Reading 是给人看的那一份。★★ 量不出来的数一律**不给**，不填一个像样的 0：
// 「没量到」和「量到是 0」在现场是两个完全不同的动作 —— 前者去看为什么没量到，
// 后者直接去查设备发疯了。哪一格没给，都在对应的 *Note 里写原因。
type Reading struct {
	Transport    string `json:"transport,omitempty"`
	MeasuredMs   int64  `json:"measuredMs,omitempty"`
	Packets      int    `json:"packets,omitempty"`
	PayloadBytes int    `json:"payloadBytes,omitempty"`

	BitrateKbps     int     `json:"bitrateKbps,omitempty"`
	ReceivedFps     float64 `json:"receivedFps,omitempty"`
	LostPackets     int     `json:"lostPackets,omitempty"`
	LossPercent     float64 `json:"lossPercent,omitempty"`
	Reordered       int     `json:"reordered,omitempty"`
	Duplicates      int     `json:"duplicates,omitempty"`
	Keyframes       int     `json:"keyframes,omitempty"`
	KeyframeEveryMs int     `json:"keyframeEveryMs,omitempty"`
	Sources         int     `json:"rtpSources,omitempty"`

	// 为什么哪一格没有数。界面上有内容才现身。
	LossNote string   `json:"lossNote,omitempty"`
	RateNote string   `json:"rateNote,omitempty"`
	Other    []string `json:"measureNotes,omitempty"`
}

// Report 汇总。给人看的那一路取包最多的那个源 —— 第二路一般是混进来的
// （组播里别人的会话、换过 SETUP 的旧档），两路加一起算帧率会凭空多一倍。
func (c *Collector) Report() Reading {
	r := Reading{Transport: c.Transport, Sources: len(c.sources)}
	s := c.mainSource()
	if s == nil {
		r.Other = append(r.Other, c.notes...)
		return r
	}
	r.Packets = s.packets
	r.PayloadBytes = s.payload
	r.Reordered = s.reorder
	r.Duplicates = s.dupes
	if !s.firstAt.IsZero() && !s.lastAt.IsZero() {
		r.MeasuredMs = s.lastAt.Sub(s.firstAt).Milliseconds()
	}
	if expected := s.lastSeq - s.firstSeq + 1; expected > 0 {
		distinct := int64(len(s.seen))
		if s.seenFull {
			distinct = int64(s.packets - s.dupes)
		}
		if lost := expected - distinct; lost > 0 {
			r.LostPackets = int(lost)
			r.LossPercent = round1(float64(lost) / float64(expected) * 100)
		}
	}
	if s.restarts > 0 {
		r.Other = append(r.Other,
			fmt.Sprintf("这几秒里号段凭空跳了 %d 次（多半是中间重新起了流）—— 丢包只按最后那一段算", s.restarts))
	}
	if c.Transport == "tcp-interleaved" {
		// ★ 这一句比数字要紧：TCP 自己会重传，报「0% 丢包」是假清白。
		r.LostPackets, r.LossPercent = 0, 0
		r.LossNote = "丢包问不出来：这一路是走 TCP 交织收的，TCP 自己会重传"
	}
	secs := float64(r.MeasuredMs) / 1000
	switch {
	case r.MeasuredMs >= minSpan.Milliseconds() && r.Packets >= 2:
		r.BitrateKbps = int(float64(r.PayloadBytes) * 8 / 1000 / secs)
		if s.frames >= 2 {
			r.ReceivedFps = round1(float64(s.frames) / secs)
		} else {
			r.RateNote = "一个 marker 位都没见到（一帧都没收全），到达帧率不算"
		}
	case r.Packets > 0:
		r.RateNote = "窗口太短（不到 0.2 秒），码率与到达帧率不算"
	}
	if c.handlesKeyframes() {
		r.Keyframes = len(s.keyTS)
		var gaps []int64
		for i := 1; i < len(s.keyTS); i++ {
			if d := s.keyTS[i] - s.keyTS[i-1]; d > 0 {
				gaps = append(gaps, d*1000/int64(c.clock))
			}
		}
		if len(gaps) > 0 {
			// 取中位数：一两个被网络挤在一起的间隔不该把「GOP 多大」整个带偏。
			r.KeyframeEveryMs = int(median(gaps))
		} else if r.Keyframes < 2 {
			r.Other = append(r.Other, "这几秒里没认出第二个关键帧，间隔算不出（只认 H.264 / H.265 的 IDR）")
		}
	} else {
		r.Other = append(r.Other, "关键帧间隔只认 H.264 / H.265，这路编码认不出，只数了包")
	}
	r.Other = append(r.Other, c.notes...)
	return r
}

func (c *Collector) mainSource() *source {
	var best *source
	for _, s := range c.sources {
		if best == nil || s.packets > best.packets {
			best = s
		}
	}
	return best
}

func median(xs []int64) int64 {
	cp := append([]int64(nil), xs...)
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j] < cp[j-1]; j-- {
			cp[j], cp[j-1] = cp[j-1], cp[j]
		}
	}
	return cp[len(cp)/2]
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

// rtp 是一个 RTP 头的可见部分。
type rtp struct {
	marker    bool
	pt        int
	seq       int
	timestamp int
	ssrc      uint32
	payload   []byte
}

// rtpHeader 剥掉定长头、CSRC 列表和扩展头。
//
// ★ 版本号必须验：不验的话，一个恰好以 0x80 开头的杂包会被算成一包，
//
//	码率凭空多一节，而现场一点都看不出来。
func rtpHeader(b []byte) (rtp, bool) {
	var h rtp
	if len(b) < 12 {
		return h, false
	}
	if b[0]>>6 != 2 {
		return h, false
	}
	csrc := int(b[0] & 0x0F)
	hasExt := b[0]&0x10 != 0
	pad := b[0]&0x20 != 0
	h.marker = b[1]&0x80 != 0
	h.pt = int(b[1] & 0x7F)
	h.seq = int(b[2])<<8 | int(b[3])
	// ★ 用 int64 拼：windows/386 那一份的 int 是 32 位，直接左移 24 位会溢出成负数
	h.timestamp = int(int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7]))
	h.ssrc = uint32(b[8])<<24 | uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11])
	off := 12 + 4*csrc
	if off > len(b) {
		return h, false
	}
	if hasExt {
		if off+4 > len(b) {
			return h, false
		}
		off += 4 + int(int(b[off+2])<<8|int(b[off+3]))*4
		if off > len(b) || off < 0 {
			return h, false
		}
	}
	end := len(b)
	if pad && end > off {
		if n := int(b[end-1]); n > 0 && end-n >= off {
			end -= n
		}
	}
	h.payload = b[off:end]
	return h, true
}

// keyframeStart 看这一包的载荷**开头**是不是一张关键帧的第一包。
//
// ★ 只看载荷开头，不看 SDP 说什么：一条流里混着两种打包方式是常态
//
//	（有的设备把 SPS/PPS 单发一包，有的塞在 IDR 前面）。
func keyframeStart(payload []byte, codec string) bool {
	if len(payload) == 0 {
		return false
	}
	switch codec {
	case "h264":
		t := payload[0] & 0x1F
		if t == 5 { // IDR
			return true
		}
		if t == 28 && len(payload) >= 2 { // FU-A：取分段里的类型和起始位
			fu := payload[1]
			return fu&0x80 != 0 && fu&0x1F == 5
		}
	case "h265":
		t := (payload[0] >> 1) & 0x3F
		if t == 19 || t == 20 { // IDR_W_RADL / IDR_N_LP
			return true
		}
		if (t == 48 || t == 49) && len(payload) >= 4 { // 分段：内层 NAL 头在第 3、4 字节
			inner := (payload[2] >> 1) & 0x3F
			return (inner == 19 || inner == 20) && payload[3]&0x40 != 0
		}
	}
	return false
}
