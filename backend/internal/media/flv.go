package media

// FLV 容器探测（rtmp 家族的文件/HTTP-FLV 形态）：头校验 + 一路走标签，
// 回答「这个容器里到底有什么」。
//
// ★ 为什么自己写：现场那句「flv 地址打不开 / 没画面」在容器这一层各有各的样子 ——
//
//	回的根本不是 FLV（网页、mp4、还是裸 h264）、头是好的可一个标签都没有、
//	容器里只有音频没有视频、视频是老 7 号 AVC 还是 12 号 HEVC 草案、
//	还是那两种靠 FourCC 认门的扩展序列头（Enhanced RTMP）、时间戳在 24 位里回绕。
//	第三方库把它们糊成一次「解析失败」，正好把要分开的档抹掉了。
//	分辨率不在这重写：解出来的 SPS 交给本包既有的 ParseH264SPS / ParseH265SPS。
//
// ★ 凡是流上读来的长度都不许信：标签数据长度是 24 位（最大 16 MiB-1），
//
//	读多少永远拿「总预算 − 已读」和「这一标签声称还剩」里小的那个兜底；
//	截断的流、永不到头的直播流、灌垃圾的流，都要在有限的字节数与有限的时间内
//	给出答案或给出带证据的错误 —— 不许 panic，也不许挂着不走。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// FLVError 的 Kind 集合（封闭）：工具层按这个选判定码，不靠文本匹配。
const (
	FLVKindNotFLV = "not-flv" // 开头压根不是 FLV（带「它像什么」的证据）
	FLVKindHeader = "header"  // FLV 签名对，可头那 9 个字节读不成（版本离谱 / 字节不够）
	FLVKindTag    = "tag"     // 标签声称的长度与实际到手的对不上 —— 断在标签中间
	FLVKindIO     = "io"      // 读通道自己坏了（连接被断 / 超时）
)

// 停下来的原因（封闭集）：读到哪儿为止，是判定与那句账的共同出处。
const (
	FLVStopEnded  = "ended"   // 干净地读到流末尾（点播文件本来的样子）
	FLVStopByte   = "bytecap" // 到了字节预算：只读了前 MaxBody 个字节
	FLVStopTag    = "tagcap"  // 到了标签数预算
	FLVStopWindow = "window"  // 到了时间预算（直播流永不到头，靠这一档收口）
)

const (
	flvHeaderSize    = 9
	flvTagHeaderSize = 11
	// 音视频标签只需要开头一小截来解容器头；正文多大都不进内存。
	flvPeekMax = 512
	// 脚本标签（onMetaData）整段进内存来跑 AMF0，超了这个数的不碰：
	// 正常的元数据没有几十 KB 的，那种多半是有人把码流灌进了脚本标签。
	flvScriptMax = 64 << 10
	// 单个标签声明的长度超过这个数就不往里读了：FLV 的 24 位长度最大约 16 MiB，
	// 真关键帧没这么长，超了多半是长度字段被写坏，接着读只是陪它浪费预算。
	flvHugeTag = 12 << 20

	// ★ 探测的默认上界：一次 FLV 探测最多读这么多字节、走这么多标签、
	// 花这么长时间。8 MiB 按 2 Mbps 也有 32 秒内容，足够回答容器里有什么。
	FLVDefaultMaxBody int64         = 8 << 20
	FLVDefaultMaxTags int64         = 4000
	FLVDefaultWindow  time.Duration = 5 * time.Second
)

// FLVError 带着「读到哪儿停的」。
// Seen 是出错之前已经走到的那一份账 —— ★ 问到一半断了，问到的照样是证据，
// 与 RTMP 那边「断之前问到的都留着」同一条规矩。
type FLVError struct {
	Stage  string // header / tag / body
	Kind   string
	Detail string
	Err    error
	// Head 是流上最先到手的那一小截，工具层拿它去认「那一段像什么」。
	Head []byte
	Seen *FLVReport
}

func (e *FLVError) Error() string {
	switch {
	case e.Detail != "":
		return fmt.Sprintf("FLV 在 %s 这一步停住（%s）：%s", e.Stage, e.Kind, e.Detail)
	case e.Err != nil:
		return fmt.Sprintf("FLV 在 %s 这一步停住（%s）：%s", e.Stage, e.Kind, e.Err)
	default:
		return fmt.Sprintf("FLV 在 %s 这一步停住（%s）", e.Stage, e.Kind)
	}
}

// Unwrap 让调用方用 errors.Is 认底层网络错误（超时/断开），不看中文文本。
func (e *FLVError) Unwrap() error { return e.Err }

// FLVReport 是一次 FLV 走查的账。所有字段都是「这一趟真读到的」，读不到的留零值。
type FLVReport struct {
	// 头（9 字节）那一份
	Version      byte
	FlagAudio    bool // 头声明有音频（TypeFlags bit0）
	FlagVideo    bool // 头声明有视频（TypeFlags bit2）
	DataOffset   uint32
	HeaderErrors []string // 头看着像 FLV 可哪里不对，照实记，不猜

	// 标签账
	Tags       int64
	AudioTags  int64
	VideoTags  int64
	ScriptTags int64
	OtherTags  int64 // 聚合/未知类型，数到了但没解析里面
	BodyBytes  int64 // 读掉的标签正文字节（含跳过的）
	AudioBytes int64
	VideoBytes int64
	// PrevTagSizeBad：上一个标签长度字段与实际对不上的次数。
	// ★ 单独一格：直播平台上这一项常见的很，非零不等于流坏了，
	// 但「整段长度账都对不上」是 muxer 有毛病的证据。
	PrevTagSizeBad int64

	// 容器里有什么
	AudioFormats []string // 出现过的音频编码名（按出现顺序，去重）
	VideoFormats []string // 出现过的视频编码名（含 FourCC），同上
	HasAudio     bool
	HasVideo     bool
	// AAC 详情（第一份能解出来的序列头）；解不出采样率就是 0，不编。
	AAC *FLVAudioInfo
	// Video 是第一份解得开的序列头给出的参数（分辨率走本包的 SPS 解析）。
	Video *FLVVideoInfo
	// MultiTrack：碰到 Enhanced RTMP 的多轨封装。这一版认得它、不解析内部，
	// 账上如实写「多轨」，分辨率就不报了 —— 报「没解出来」比猜一路强。
	MultiTrack bool

	// 时间戳（毫秒）。★ FLV 的时间戳是 24 位 + 1 字节的扩展高位：
	// 超过 0xFFFFFF（约 4.66 小时）的必须把扩展位拼回去，
	// 拼错或没拼的症状是时间戳永远停在 16777215 —— 静默的错，最难查的那种。
	// 下面这几个都是拼好、且按各自的码种解过 32 位回绕的值。
	FirstMediaTS uint64
	LastMediaTS  uint64
	FirstKeyTS   uint64 // 第一个关键帧在哪；HasKeyframe 为假就是没见到
	HasKeyframe  bool
	Keyframes    int64
	MediaTSSeen  bool
	MetadataSeen bool
	MetaErrCount int
	ScriptTooBig int            // 声明长度超过 flvScriptMax、没进内存解析的脚本标签数
	Metadata     map[string]any // 第一个 onMetaData / @setDataFrame 里那个对象

	StopReason string // FLVStop* 之一；空串表示还没走到头（只在出错时有意义）
}

// FLVAudioInfo 是 AAC（或 FourCC 音频）序列头里解出来的那几样。
type FLVAudioInfo struct {
	FourCC       string // 扩展头的 FourCC，老式 AAC 为空
	Format       int    // FLV SoundFormat 编号
	SampleRateHz int
	Channels     int
}

// FLVVideoInfo 是从序列头解出来的视频参数。Codec 认门：
// h264 / h265 / 以及认不出内容的 FourCC 原样带引号报出来。
type FLVVideoInfo struct {
	CodecID int
	FourCC  string
	Codec   string // h264 / h265 / av1 / vp9 / vvc / "fourcc 'xxxx'"
	Width   int
	Height  int
	// ParamsNote：为什么没解出分辨率。与 RTSP 那边同一条口径 ——
	// 解不出不等于探测失败，可也不许编一个数。
	ParamsNote string
}

// FLVLimits 一次走查的上界。零值字段用默认值。
type FLVLimits struct {
	MaxBody  int64     // 最多读进多少标签正文
	MaxTags  int64     // 最多走多少个标签
	Deadline time.Time // 到点收口（直播流永不到头，必须有这一档）
}

func (l FLVLimits) norm() FLVLimits {
	if l.MaxBody <= 0 {
		l.MaxBody = FLVDefaultMaxBody
	}
	if l.MaxTags <= 0 {
		l.MaxTags = FLVDefaultMaxTags
	}
	return l
	// Deadline 不填表示不计时（测试里喂内存字节串用）
}

// ProbeFLV 走一段 FLV 字节流并给出那一份账。错误一律带证据：
// 返回 *FLVError 时它的 Seen 里是停下来之前走到的东西。
//
// ★ 时间戳的回绕是按码种各自解的：同一容器里音视频各自单调前进，
// 但互相之间会倒挂 —— 拿一个全局游标解回绕，音频标签会把视频解歪。
func ProbeFLV(r io.Reader, lim FLVLimits) (*FLVReport, error) {
	lim = lim.norm()
	br := bufio.NewReaderSize(r, 16<<10)
	rep := &FLVReport{}

	head, headAll := peekSome(br, flvHeaderSize)
	if head == nil {
		// ★ 连 9 个字节都没凑齐：到手的都留着给「它像什么」那一格。
		if len(headAll) == 0 {
			return rep, &FLVError{Stage: "header", Kind: FLVKindHeader,
				Detail: "连 9 字节的 FLV 头都没读到，一个字节都没来", Head: headAll, Seen: rep}
		}
		return rep, &FLVError{Stage: "header", Kind: FLVKindHeader,
			Detail: "只读到 " + strconv.Itoa(len(headAll)) + " 字节，凑不齐 9 字节的 FLV 头",
			Head:   headAll,
			Seen:   rep}
	}
	if string(head[:3]) != "FLV" {
		return rep, &FLVError{Stage: "header", Kind: FLVKindNotFLV,
			Detail: "前三个字节是 " + hexHead(head[:3]) + "，不是 “FLV”",
			Head:   peekAllForSniff(br, head), Seen: rep}
	}
	rep.Version = head[3]
	// 版本：规格写 0x01，现场见过 0x00 的 muxer；别的一律当成不是 FLV。
	if rep.Version > 1 {
		return rep, &FLVError{Stage: "header", Kind: FLVKindNotFLV,
			Detail: "FLV 版本号是 " + strconv.Itoa(int(rep.Version)) + "，只认 0/1",
			Head:   peekAllForSniff(br, head), Seen: rep}
	}
	rep.FlagAudio = head[4]&0x01 != 0
	rep.FlagVideo = head[4]&0x04 != 0
	if head[4]&0xFA != 0 { // 保留位该是 0；非 0 常见于把音频标志写成 bit1 的怪 muxer
		rep.HeaderErrors = append(rep.HeaderErrors,
			fmt.Sprintf("头的保留标志位非零（0x%02x）", head[4]))
	}
	off := int64(be32(head[5:9]))
	rep.DataOffset = uint32(off)
	switch {
	case off < flvHeaderSize:
		return rep, &FLVError{Stage: "header", Kind: FLVKindNotFLV,
			Detail: "头声明的数据起始偏移 " + strconv.FormatInt(off, 10) + " 比 9 还小",
			Head:   peekAllForSniff(br, head),
			Seen:   rep}
	case off > 64:
		return rep, &FLVError{Stage: "header", Kind: FLVKindNotFLV,
			Detail: "头声明的数据起始偏移 " + strconv.FormatInt(off, 10) + " 离谱",
			Head:   peekAllForSniff(br, head),
			Seen:   rep}
	}
	// 吃掉「头 + 扩展头 + PreviousTagSize0」。
	// ★ 上面那 9 个字节是 Peek 来看的，Peek **不**推进读位置，所以这里得从流首算起：
	//
	//	规格是「9 字节头 + (DataOffset-9) 字节扩展头 + 4 字节 PreviousTagSize0」，
	//	一共 DataOffset+4 个字节。少算这 9 字节的症状是整条流从头的第 4 字节起错位，
	//	标签类型、长度、时间戳全是拿旗字节 —— 报错会写成「标签正文没读全」，
	//	看上去像流的毛病，其实是探测端的毛病。
	//
	// PreviousTagSize0 规范规定必须是 4 字节的 0，可对不上也只记账不判死 ——
	// 现场有 muxer 在这写别的数而流照样能播。
	if skip := off + 4; skip > 0 {
		n, err := discardN(br, skip)
		if err != nil {
			return rep, &FLVError{Stage: "header", Kind: FLVKindTag,
				Detail: "头之后声明 " + strconv.FormatInt(off, 10) +
					" 字节，实际只读到 " + strconv.FormatInt(n, 10) + " 字节就没了",
				Seen: rep}
		}
	}

	tsv := &flvTSUnwrap{} // 按码种各自解回绕，见类型注释
	for {
		if !lim.Deadline.IsZero() && time.Now().After(lim.Deadline) {
			rep.StopReason = FLVStopWindow
			break
		}
		if rep.Tags >= lim.MaxTags {
			rep.StopReason = FLVStopTag
			break
		}
		var th [flvTagHeaderSize]byte
		got, err := io.ReadFull(br, th[:])
		if err != nil {
			if errors.Is(err, io.EOF) && got == 0 {
				rep.StopReason = FLVStopEnded // 干净的流末尾
				break
			}
			return rep, &FLVError{Stage: "tag", Kind: flvReadKind(err),
				Detail: "最后一个标签的 " + strconv.Itoa(flvTagHeaderSize) +
					" 字节头只读到 " + strconv.Itoa(got) + " 字节",
				Err: err, Seen: rep}
		}
		typ := th[0]
		size := int64(be24(th[1:4]))
		// ★ 时间戳：字节 4-6 是低 24 位（大端），字节 7 才是高 8 位（扩展位）。
		// 常见错法是把 4-7 当成一个连续 32 位大端字读 —— 那样扩展位会跑到最低 8 位，
		// 时间戳 > 0xFFFFFF（约 4.66 小时）的流就会静默错位。照规格拼：
		raw := uint32(th[7])<<24 | uint32(th[4])<<16 | uint32(th[5])<<8 | uint32(th[6])

		if size > lim.MaxBody-rep.BodyBytes || size > flvHugeTag {
			rep.StopReason = FLVStopByte
			break
		}

		peekN := size
		if typ == 8 || typ == 9 {
			if peekN > flvPeekMax {
				peekN = flvPeekMax
			}
		} else if typ == 18 || typ == 15 {
			if peekN > flvScriptMax {
				peekN = flvScriptMax
			}
		} else {
			peekN = 0
		}
		body, err := readBounded(br, peekN)
		if err != nil {
			return rep, &FLVError{Stage: "body", Kind: flvReadKind(err),
				Detail: "标签（类型 " + strconv.Itoa(int(typ)) + "，声明 " +
					strconv.FormatInt(size, 10) + " 字节）正文没读全",
				Err: err, Seen: rep}
		}
		if size > peekN {
			if _, err := discardN(br, size-peekN); err != nil {
				return rep, &FLVError{Stage: "body", Kind: flvReadKind(err),
					Detail: "标签（类型 " + strconv.Itoa(int(typ)) + "）正文读到一半流就断了",
					Err:    err, Seen: rep}
			}
		}
		rep.BodyBytes += size
		rep.Tags++
		ms := tsv.note(typ, raw)
		switch typ {
		case 8:
			rep.noteAudio(body, ms, size)
		case 9:
			rep.noteVideo(body, ms, size)
		case 18, 15:
			rep.noteScript(body)
		default:
			rep.OtherTags++
		}

		var pts [4]byte
		if _, err := io.ReadFull(br, pts[:]); err != nil {
			return rep, &FLVError{Stage: "tag", Kind: flvReadKind(err),
				Detail: "最后一个标签之后的 PreviousTagSize 没读全",
				Err:    err, Seen: rep}
		}
		if int64(be32(pts[:])) != size+flvTagHeaderSize {
			rep.PrevTagSizeBad++
		}
	}
	return rep, nil
}

// hexHead 给错误里那一小截字节留个可认的样子。
func hexHead(b []byte) string {
	const max = 8
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, []byte(fmt.Sprintf("%02x", c))...)
	}
	return string(out)
}

// ── 时间戳：24 位 + 8 位扩展，以及 32 位回绕 ──

// flvTSUnwrap 把每个码种（音频/视频各自一条）的 32 位时间戳解成单调的 64 位毫秒。
//
// ★ 为什么必须解：muxer 播过 49.7 天后 32 位会回绕，此时「最后时间戳」
// 比第一个还小，时长就成了负数。解法与 RTMP 那边同一口径：
// 同一码种上大幅往回跳（超过半程）就当是绕了一圈。
type flvTSUnwrap struct {
	audio, video flvTSSeries
}

type flvTSSeries struct {
	base uint64 // 累计的高 32 位（每绕一圈 +2^32）；用 uint64，别在 uint32 上加 1<<32
	last uint32
	have bool
}

func (s *flvTSSeries) unwrap(raw uint32) uint64 {
	if s.have && raw < s.last && s.last-raw > 1<<31 {
		s.base += 1 << 32
	}
	s.have = true
	s.last = raw
	return s.base + uint64(raw)
}

func (t *flvTSUnwrap) note(typ byte, raw uint32) uint64 {
	switch typ {
	case 8:
		return t.audio.unwrap(raw)
	case 9:
		return t.video.unwrap(raw)
	default:
		// 脚本/聚合标签的时间戳不进音视频任何一条序列 —— 否则一条 ts=0 的
		// onMetaData 会把视频的回绕解算起点带歪。原样返回，不参与解回绕。
		return uint64(raw)
	}
}

// ── 读的小工具：每一处都在预算内 ──

func be24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// peekSome 试着凑齐 n 字节；凑不齐时返回 (nil, 到手的)。
func peekSome(br *bufio.Reader, n int) ([]byte, []byte) {
	buf, err := br.Peek(n)
	if err == nil {
		return buf, buf
	}
	if len(buf) == 0 {
		// Peek 一个字节看是不是真没数据了（还是那种「一个都没来」）
		if b, perr := br.Peek(1); perr == nil {
			return nil, b
		}
		return nil, nil
	}
	return nil, append([]byte(nil), buf...)
}

// peekAllForSniff 把头段加上后面最多 24 字节攒给「认它像什么」用。
func peekAllForSniff(br *bufio.Reader, head []byte) []byte {
	more, _ := br.Peek(24)
	out := append([]byte{}, head...)
	return append(out, more...)
}

func readBounded(br io.Reader, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	b := make([]byte, int(n)) // n 已被上界夹过（peekN ≤ 512 / 64KiB），转 int 安全
	if _, err := io.ReadFull(br, b); err != nil {
		return nil, err
	}
	return b, nil
}

func discardN(br io.Reader, n int64) (int64, error) {
	c, err := io.CopyN(io.Discard, br, n)
	return c, err
}

// flvReadKind 分「读通道自己坏了」与「流断在标签里」。
// 到点/被取消算 io（是我们主动收口，不是容器的锅）；
// EOF/读半截（io.ErrUnexpectedEOF）算 tag —— 那才是「声称的长度对不上」。
// 与 RTMP 那边同一手法：错误分层靠类型，不靠中文文本匹配。
func flvReadKind(err error) string {
	if isTimeoutErr(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return FLVKindIO
	}
	return FLVKindTag
}

// ── 标签内容 ──

// audioFormatNames：FLV SoundFormat 的编号表。认不出的报编号，不猜。
func audioFormatName(f int, fourCC string) string {
	switch f {
	case 0:
		return "lpcm"
	case 1:
		return "adpcm"
	case 2:
		return "mp3"
	case 3:
		return "pcm-s16le"
	case 4:
		return "nellymoser-16k"
	case 5:
		return "nellymoser-8k"
	case 6:
		return "nellymoser"
	case 7:
		return "g711a"
	case 8:
		return "g711u"
	case 9:
		if fourCC != "" {
			return "fourcc " + strconv.Quote(fourCC)
		}
		return "编号 9（保留位）"
	case 10:
		return "aac"
	case 11:
		return "speex"
	case 14:
		return "mp3-8k"
	case 15:
		return "设备私有"
	}
	return "编号 " + strconv.Itoa(f)
}

func videoCodecName(id int) string {
	switch id {
	case 2:
		return "sorenson-h263"
	case 3:
		return "screen"
	case 4:
		return "vp6"
	case 5:
		return "vp6a"
	case 6:
		return "screen-v2"
	case 7:
		return "h264"
	case 8:
		return "h265(保留位写法)"
	case 12, 13:
		return "h265(老草案 12 号)"
	}
	return "编号 " + strconv.Itoa(id)
}

// knownFourCC 认扩展序列头/头信息里那几种 FourCC；认不出返回空串。
// 两种 HEVC 写法都收：hvc1（参数集内联在流里）与 hev1（参数集只当解码器配置）。
var fourCCNames = map[string]string{
	"avc1": "h264", "hvc1": "h265", "hev1": "h265",
	"vvc1": "vvc", "av01": "av1", "vp09": "vp9", "vp08": "vp8",
}

func knownVideoFourCC(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	s := string(b[:4])
	for c := 0; c < 4; c++ {
		if b[c] < 0x20 || b[c] > 0x7e {
			return ""
		}
	}
	if _, ok := fourCCNames[s]; ok {
		return s
	}
	return ""
}

// noteAudio 解一个音频标签的容器头。body 是最多前 512 字节，可能比声明的短；
// size 是这个标签真正从流上消耗掉的正文字节数 —— 每种码流的字节账按真数记，
// 才不会把「只 peek 了 512 字节」当成「这路音频就这么点」。
func (rep *FLVReport) noteAudio(body []byte, ms uint64, size int64) {
	rep.AudioTags++
	rep.AudioBytes += size
	rep.HasAudio = true
	rep.markMedia(ms)
	if len(body) == 0 {
		rep.addAudio("空标签")
		return
	}
	b0 := body[0]
	format := int(b0 >> 4)
	switch {
	case format == 9 && len(body) >= 5:
		// ExAudioTagHeader：低 4 位是包类型，FourCC 在字节 1-4。
		fc := ""
		if printable(body[1:5]) {
			fc = string(body[1:5])
		}
		pt := int(b0 & 0x0F)
		if len(fc) >= 2 && fc[0] == 'F' && fc[1] >= '0' && fc[1] <= '5' {
			rep.MultiTrack = true // 多轨封装（FourCC 以 'F'+轨数起手）：这一版只点名不解析
		}
		name := audioFormatName(9, fc)
		rep.addAudio(name)
		if fc == "mp4a" && pt == 0 && rep.AAC == nil && len(body) > 5 {
			rep.AAC = parseASC(10, fc, body[5:])
		}
	case format == 10 && len(body) >= 2:
		// 老式 AAC：字节 1 是 AACPacketType，0 就是后面跟着 AudioSpecificConfig。
		rep.addAudio("aac")
		if body[1] == 0 && rep.AAC == nil && len(body) > 2 {
			rep.AAC = parseASC(10, "", body[2:])
		}
	case format == 0 || format == 1 || format == 2 || format == 3 || format == 14:
		names := map[int]string{0: "lpcm", 1: "adpcm", 2: "mp3", 3: "pcm-s16le", 14: "mp3-8k"}
		rep.addAudio(names[format])
		if format == 0 || format == 1 || format == 3 {
			if rep.AAC == nil {
				// PCM/ADPCM 的采样率就在头的 2 个比特里（这是老规矩，不是猜的）
				rate := [4]int{5512, 11025, 22050, 44100}[(b0>>2)&3]
				ch := 2
				if b0&0x01 != 0 {
					ch = 1
				}
				rep.AAC = &FLVAudioInfo{Format: format, SampleRateHz: rate, Channels: ch}
			}
		}
	case format == 7 || format == 8:
		rep.addAudio(audioFormatName(format, ""))
		if rep.AAC == nil {
			rep.AAC = &FLVAudioInfo{Format: format, SampleRateHz: 8000, Channels: 1}
		}
	default:
		rep.addAudio(audioFormatName(format, ""))
	}
}

// parseASC 解 ISO/IEC 14496-3 的 AudioSpecificConfig：
// 对象类型 5 位、采样率索引 4 位、声道配置 4 位，中间有扩展频率那些岔路。
// 解不成返回 nil 而不是半成品 —— 拿错声道数去下结论比没有更坏。
func parseASC(format int, fourCC string, b []byte) *FLVAudioInfo {
	x := &byteBits{b: b}
	aot, ok := x.u(5)
	if !ok {
		return nil
	}
	if aot == 31 {
		e, ok := x.u(6)
		if !ok {
			return nil
		}
		aot += e
	}
	if aot == 5 || aot == 6 { // SBR/PS：先跳过扩展频率与扩展对象类型
		idx, ok := x.u(4)
		if !ok {
			return nil
		}
		if idx == 15 {
			if _, ok := x.u(24); !ok {
				return nil
			}
		}
		ext, ok := x.u(5)
		if !ok {
			return nil
		}
		if ext == 6 {
			if _, ok := x.u(6); !ok {
				return nil
			}
		}
	}
	info := &FLVAudioInfo{Format: format, FourCC: fourCC}
	idx, ok := x.u(4)
	if !ok {
		return nil
	}
	switch {
	case idx <= 12:
		info.SampleRateHz = mpeg4Rates[idx]
	case idx == 15:
		v, ok := x.u(24)
		if !ok || v == 0 || v > 960000 {
			return nil
		}
		info.SampleRateHz = int(v)
	default: // 13/14 是保留值：解到这儿说明后面全错位了
		return nil
	}
	ch, ok := x.u(4)
	if !ok || ch > 8 {
		return nil
	}
	info.Channels = int(ch)
	if info.SampleRateHz == 0 && info.Channels == 0 {
		return nil
	}
	return info
}

var mpeg4Rates = [13]int{96000, 88200, 64000, 48000, 44100, 32000, 24000, 16000,
	12000, 11025, 8000, 7350, 0}

// noteVideo 解一个视频标签的容器头。三条门路：
// 老式（帧类型+编码编号）、真扩展头（0x80 起手）、以及老草案 12 号却带 FourCC 的混世写法。
// size 同 noteAudio：真正消耗掉的正文字节，视频那路的字节账按它记。
func (rep *FLVReport) noteVideo(body []byte, ms uint64, size int64) {
	rep.VideoTags++
	rep.VideoBytes += size
	rep.HasVideo = true
	rep.markMedia(ms)
	if len(body) == 0 {
		rep.addVideo("空标签")
		return
	}
	b0 := body[0]
	ext := b0&0x80 != 0
	if !ext && (b0&0x0F) == 12 && len(body) >= 5 && knownVideoFourCC(body[1:5]) != "" {
		ext = true // 现场见过没置 0x80 位却带 FourCC 的推流端：FourCC 说话算数
	}
	if ext {
		ft := int((b0 >> 4) & 0x07)
		pt := int(b0 & 0x0F)
		if len(body) < 5 {
			rep.addVideo("扩展头但 FourCC 没读全")
			return
		}
		if !printable(body[1:5]) {
			rep.addVideo("扩展头但 FourCC 不成字")
			return
		}
		fc := string(body[1:5])
		if fc[0] == 'F' && fc[1] >= '0' && fc[1] <= '5' {
			rep.MultiTrack = true
			rep.addVideo("多轨扩展头（" + fc + "）")
			return
		}
		name, known := fourCCNames[fc]
		if pt == 6 {
			rep.MultiTrack = true
		}
		if !known {
			rep.addVideo("fourcc " + strconv.Quote(fc))
			return
		}
		rep.addVideo(name)
		switch {
		case pt == 0: // SequenceStart：FourCC 后面就是解码器配置记录
			rep.parseVideoConfig(fc, body[5:])
		case pt == 1 && ft == 1: // CodedFrames 关键帧
			rep.countKeyframe(ms)
		case pt == 3 && ft == 1: // CodedFramesX（隐含零合成时间）
			rep.countKeyframe(ms)
		}
		return
	}
	ft := int(b0 >> 4)
	cid := int(b0 & 0x0F)
	rep.addVideo(videoCodecName(cid))
	if ft != 1 {
		return
	}
	switch cid {
	case 7: // AVC：规格那一路是 帧类型|编号(1) + 合成时间(3) + AVCPacketType(1) + CodecID(3)，
		// ★ 所以 AVCPacketType 在字节 4、配置记录从字节 8 起 —— 不是紧跟首字节。
		//   拿字节 1 当包类型的症状：合成时间为 0 的流（几乎所有非 B 帧流的常态）里，
		//   关键帧 NALU 会被当成序列头去解配置记录（解不出），关键帧一格不记；
		//   而真序列头因为前面多算了 3 个零字节，SPS 永远找不到、分辨率永远报不出来。
		if len(body) >= 8 && body[4] == 0 {
			rep.parseVideoConfig("avc1", body[8:])
			return
		}
		rep.countKeyframe(ms)
	case 12, 13: // 老草案 HEVC：布局照抄 AVC 那一套
		if len(body) >= 8 && body[4] == 0 {
			rep.parseVideoConfig("hvc1", body[8:])
			return
		}
		rep.countKeyframe(ms)
	default:
		rep.countKeyframe(ms) // Spark/VP6 这些没有序列头一说，关键帧就是关键帧
	}
}

// parseVideoConfig 从序列头的配置记录里找 SPS 并交给既有的解析器。
func (rep *FLVReport) parseVideoConfig(fc string, rec []byte) {
	if rep.Video != nil && rep.Video.Width > 0 {
		return // 已经有过一份解出来的，不再花力气
	}
	note := ""
	switch fc {
	case "avc1":
		nals, n := findAVCNALs(rec)
		if n > 0 && len(nals[0]) > 0 {
			if p, err := ParseH264SPS(nals[0]); err == nil && p.Width > 0 {
				rep.Video = &FLVVideoInfo{CodecID: 7, FourCC: fc, Codec: "h264",
					Width: p.Width, Height: p.Height}
				if n > 1 {
					rep.Video.ParamsNote = "多份 SPS，取的第一份"
				}
				return
			} else if err != nil {
				note = err.Error()
			}
		} else {
			note = "配置记录里没找到 SPS"
		}
	case "hvc1", "hev1":
		nal := findHEVCSPS(rec)
		if nal != nil {
			if p, err := ParseH265SPS(nal); err == nil && p.Width > 0 {
				rep.Video = &FLVVideoInfo{CodecID: 12, FourCC: fc, Codec: "h265",
					Width: p.Width, Height: p.Height}
				return
			} else if err != nil {
				note = err.Error()
			}
		} else {
			note = "配置记录里没找到 SPS"
		}
	default:
		return // av1/vp9 这些这版不解参数集，只报编码名
	}
	if rep.Video == nil {
		rep.Video = &FLVVideoInfo{FourCC: fc, Codec: fourCCName(fc), ParamsNote: note}
	}
}

func fourCCName(fc string) string {
	if n, ok := fourCCNames[fc]; ok {
		return n
	}
	return "fourcc " + strconv.Quote(fc)
}

// findAVCNALs 按 AVCDecoderConfigurationRecord 的 2 字节长度前缀取 SPS（们）。
// 每一处都拿剩余字节兜底 —— 长度字段是流上读来的，不许信。
func findAVCNALs(rec []byte) ([][]byte, int) {
	// version(1) profile compat level lengthSize(1) numSPS(1) 至少 6 字节
	if len(rec) < 6 || rec[0] != 1 {
		return nil, 0
	}
	numSPS := int(rec[5] & 0x1F)
	if numSPS == 0 || numSPS > 8 {
		return nil, 0
	}
	var out [][]byte
	i := 6
	for n := 0; n < numSPS; n++ {
		if i+2 > len(rec) {
			break
		}
		l := int(be16(rec[i:]))
		i += 2
		if l <= 0 || l > len(rec)-i || l > 1<<16 {
			break
		}
		nal := rec[i : i+l]
		i += l
		if len(nal) >= 1 && nal[0]&0x1F == 7 {
			out = append(out, nal)
		}
	}
	return out, len(out)
}

// findHEVCSPS 在 HEVCDecoderConfigurationRecord 里按内容找第一份 SPS。
//
// ★ 为什么不按固定偏移走数组表：规格修订里固定区的长度按位数数（43 位保留那种），
// 各家实现差一个字节就整表错位，错位的症状是解出一个「看着合理」的分辨率 ——
// 比直接报「没找到」坏得多。所以拿解析器本身当校验：长度前缀 + NAL 类型 33 +
// ParseH265SPS 解得开，三样都过了才算数。扫描范围以这一份配置记录为界，
// 且只在序列头标签里做（正常帧标签不进这条路径），误伤不了别的东西。
func findHEVCSPS(rec []byte) []byte {
	for off := 0; off+4 <= len(rec); off++ {
		l := int(be16(rec[off:]))
		if l < 6 || off+2+l > len(rec) {
			continue
		}
		nal := rec[off+2 : off+2+l]
		if (nal[0]>>1)&0x3F != 33 {
			continue
		}
		if p, err := ParseH265SPS(nal); err == nil && p.Width > 0 {
			return nal
		}
	}
	return nil
}

func be16(b []byte) uint32 { return uint32(b[0])<<8 | uint32(b[1]) }

// noteScript 解脚本标签（onMetaData / @setDataFrame）。AMF0 用的本包现成的解码器。
func (rep *FLVReport) noteScript(body []byte) {
	rep.ScriptTags++
	if int64(len(body)) == flvScriptMax {
		// 声明长度更大、只读了前 64 KiB 的那种：整段解是不安全的，点名即可。
		rep.ScriptTooBig++
		return
	}
	if rep.MetadataSeen {
		return
	}
	args, err := AMF0DecodeArgs(body)
	if err != nil || len(args) == 0 {
		rep.MetaErrCount++
		return
	}
	if s, _ := args[0].(string); s == "@setDataFrame" || s == "onFCPublish" {
		args = args[1:]
	}
	for _, a := range args {
		if m, ok := a.(map[string]any); ok {
			rep.MetadataSeen = true
			rep.Metadata = m
			return
		}
	}
	rep.MetaErrCount++
}

// ── 账的小格子 ──

func (rep *FLVReport) markMedia(ms uint64) {
	if !rep.MediaTSSeen {
		rep.MediaTSSeen = true
		rep.FirstMediaTS = ms
	}
	if ms > rep.LastMediaTS {
		rep.LastMediaTS = ms
	}
}

func (rep *FLVReport) countKeyframe(ms uint64) {
	rep.Keyframes++
	if !rep.HasKeyframe {
		rep.HasKeyframe = true
		rep.FirstKeyTS = ms
	}
}

func (rep *FLVReport) addAudio(name string) { rep.addName(&rep.AudioFormats, name) }
func (rep *FLVReport) addVideo(name string) { rep.addName(&rep.VideoFormats, name) }

func (rep *FLVReport) addName(list *[]string, name string) {
	for _, s := range *list {
		if s == name {
			return
		}
	}
	*list = append(*list, name)
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}

// byteBits 按位读字节（不动 bitReader —— 那个会去剥 H.264 的防竞争字节，
// AAC 的位流里可没有那套规矩，用错地方会把声道读歪）。
type byteBits struct {
	b   []byte
	pos int
}

func (x *byteBits) u(n int) (uint32, bool) {
	if n > 32 || x.pos+n > len(x.b)*8 {
		return 0, false
	}
	var v uint32
	for i := 0; i < n; i++ {
		bit := (x.b[x.pos/8] >> (7 - uint(x.pos%8))) & 1
		v = v<<1 | uint32(bit)
		x.pos++
	}
	return v, true
}
