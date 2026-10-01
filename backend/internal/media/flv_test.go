package media

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// FLV 容器走查的测试。字节全部由本文件那几个编码帮手**现编**出来。
//
// ★ 为什么不抄现成样本：这里要钉的多半是坏流 —— 声称 16 MiB 实际只剩 30 字节、
//   时间戳跨过 24 位写得下的范围、PreviousTagSize 整段都对不上那种。
//   抄来的字节只证明「这一条我认得」，编出来的字节才证明「每一种不老实我都不跟着犯」。

// ── 造字节的小工具 ──

type flvBits struct {
	buf []byte
	pos int
}

func (w *flvBits) put(v, n int) {
	for i := n - 1; i >= 0; i-- {
		bit := byte((v >> uint(i)) & 1)
		if w.pos%8 == 0 {
			w.buf = append(w.buf, 0)
		}
		w.buf[len(w.buf)-1] |= bit << uint(7-w.pos%8)
		w.pos++
	}
}

// putv 先写一个值再说它占几位 —— 调用点读起来就是规格里那一段 (值, 位宽) 的清单。
func (w *flvBits) putv(v int, n int) { w.put(v, n) }

// ascBits 拼一份 AudioSpecificConfig：ISO/IEC 14496-3 的位流没有字节对齐的便宜可占，
// 手搓两个十六进制就等着被下一个字节错位。
func ascBits(fields ...[2]int) []byte {
	w := &flvBits{}
	for _, f := range fields {
		w.putv(f[0], f[1])
	}
	return w.buf
}

// flvB24 大端三字节（FLV 的标签长度与低 24 位时间戳都是它）。
func flvB24(v int64) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

// flvHead 造流首：9 字节头 + 扩展头（DataOffset-9 个字节）+ PreviousTagSize0。
// dataOffset 是 uint32 —— 它是头里的四字节字段，故意写成 0 或一百万都造得出来。
func flvHead(version, flags byte, dataOffset uint32, ext []byte) []byte {
	h := []byte{'F', 'L', 'V', version, flags,
		byte(dataOffset >> 24), byte(dataOffset >> 16), byte(dataOffset >> 8), byte(dataOffset)}
	h = append(h, ext...)
	return append(h, 0, 0, 0, 0) // PreviousTagSize0：规格规定是 4 字节的 0
}

// flvTag 造一个规规矩矩的标签：11 字节标签头 + 正文 + 写对了的 PreviousTagSize。
// ts 走规格那一套：低 24 位在字节 4-6，高 8 位在字节 7（扩展位）。
func flvTag(typ byte, ts int64, body []byte) []byte {
	return flvTagDecl(typ, ts, int64(len(body)), body)
}

// flvTagDecl 造一个「声称 size 字节正文」的标签，实际只跟 len(body) 个字节。
// ★ 声称的和真到手的故意不一样 —— 「不许信流上读来的长度」那一半用例全靠这一格造。
func flvTagDecl(typ byte, ts, size int64, body []byte) []byte {
	out := []byte{typ}
	out = append(out, flvB24(size)...)
	out = append(out, flvB24(ts&0xFFFFFF)...)
	out = append(out, byte(ts>>24)) // 扩展时间戳：高 8 位在正文里排第 8 个字节
	out = append(out, 0, 0, 0)      // StreamID，规格要求写 0
	out = append(out, body...)
	prev := size + 11
	return append(out, byte(prev>>24), byte(prev>>16), byte(prev>>8), byte(prev))
}

// 真实设备的 SPS，与 sps_test.go 同一份来源（x264 / x265 真编码出来的，不是编的）。
// 探测端最终要交给人看的就是这两份 SPS 解出来的分辨率，所以这里用真东西。
const (
	flvSPSh264720  = "Z/QAH5GbKAoAt2AiAAADAAIAAAMAZB4wYyw=" // 1280x720
	flvSPSh2641080 = "Z/QAKJGbKA8ARPxOAiAAAAMAIAAABkHjBjLA" // 1920x1080（专门盯 1088 陷阱）
	flvSPSh2651080 = "QgEBBAgAAAMAnggAAAMAAHiQAHgQAhyyys0kmV4C3AgIABAAAAMAEAAAAwGQgA=="
)

func flvMustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64：%v", err)
	}
	return b
}

// flvAvcConfig 按 AVCDecoderConfigurationRecord 那一段语法编：
// version(8) profile(8) compat(8) level(8) 保留6+长度前缀大小2(8) 保留3+SPS个数5(8)，
// 然后每份 SPS 是 2 字节长度 + NAL。★ 长度字段是流上读来的，探测端拿剩余字节兜底。
func flvAvcConfig(sps []byte) []byte {
	w := &flvBits{}
	w.put(1, 8)
	w.put(0x42, 8)
	w.put(0x00, 8)
	w.put(30, 8)
	w.put(0xFC, 6)
	w.put(3, 2)
	w.put(0xE0, 3)
	w.put(1, 5)
	w.put(len(sps), 16)
	rec := w.buf
	return append(rec, sps...)
}

// flvHevcConfig 编一份 HEVC 的解码器配置记录：固定区之后是「数组头 3 字节 +
// 2 字节长度 + NAL」两组。
//
// 固定区那二十来个字节各家按位数数的保留位不一，这里照常见写法填死：
// ★ 探测端不许按偏移走那张数组表 —— 这份 fixture 顺带钉住「按内容认门」，
//
//	固定区写得再不合规格也不该影响它把 SPS 找出来；按偏移走的那种在这里会整表错位，
//	症状是解出一个看着合理的分辨率，比报「没找到」坏得多。
func flvHevcConfig(sps, pps []byte) []byte {
	rec := []byte{
		1, 0x40, 0x18, 0x20, 0x06, 0, 0, 0, // configurationVersion / profile 那一字节 / compat(4) / 约束位起
		0, 0, 0, 0, 0, 0, 0, 0, // 约束位余下的 + 保留
		0, 0, 0, 0x03, 0x02, // constantFrameRate / 长度前缀大小 / numOfArrays = 2
	}
	rec = append(rec, 0x20, 0x01, byte(len(sps)>>8), byte(len(sps)))
	rec = append(rec, sps...)
	rec = append(rec, 0x22, 0x01, byte(len(pps)>>8), byte(len(pps)))
	return append(rec, pps...)
}

// flvAvcSeqBody 老式（没置 0x80）AVC 序列头正文，照规格那一路布局：
// 字节 0 = 帧类型|编码编号，1-3 = 合成时间，4 = AVCPacketType(0 = 序列头)，
// 5-7 = CodecID(0,0,1)，8 起才是解码器配置记录。
// ★ 配置记录不在字节 5：差 3 个零字节的症状是 SPS 永远找不到、分辨率永远报不出来。
func flvAvcSeqBody(t *testing.T, cts int, sps []byte) []byte {
	t.Helper()
	b := []byte{0x17, byte(cts >> 16), byte(cts >> 8), byte(cts), 0, 0, 0, 1}
	return append(b, flvAvcConfig(sps)...)
}

// flvAvcKeyBody 老式 AVC 的一张关键帧（AVCPacketType=1，合成时间 cts）。
// 正文那截 NAL 是假的 —— 这一层只看头，别把「能数出关键帧」混进「能解出分辨率」。
func flvAvcKeyBody(cts int) []byte {
	b := []byte{0x17, byte(cts >> 16), byte(cts >> 8), byte(cts), 1, 0, 0, 1}
	return append(b, 0x41, 0xAA, 0xBB, 0xCC)
}

// flvExtVideoBody 扩展头（IsExHeader=1）视频正文：
// 字节 0 = 0x80 | 帧类型<<4 | 包类型，1-4 = FourCC；包类型 0 之后紧跟配置记录。
func flvExtVideoBody(ft, pt int, fourCC string, rec []byte) []byte {
	b := []byte{byte(0x80 | (ft&7)<<4 | pt&0x0F)}
	b = append(b, fourCC...)
	return append(b, rec...)
}

// flvHevcSeqBody 老草案那一号（12 号）的 HEVC 序列头：布局照抄 AVC 那一路。
func flvHevcSeqBody(t *testing.T, sps, pps []byte) []byte {
	t.Helper()
	b := []byte{0x1C, 0, 0, 0, 0, 0, 0, 1}
	return append(b, flvHevcConfig(sps, pps)...)
}

// flvAACBody 老式 AAC 音频正文：0xAF = 编号 10 + 44.1kHz + 16 位 + 立体声，
// 字节 1 是 AACPacketType（0 = 后面跟着 AudioSpecificConfig）。
func flvAACBody(asc ...byte) []byte {
	return append([]byte{0xAF, 0x00}, asc...)
}

// flvFourCCAudioBody 扩展音频头（SoundFormat=9）：低 4 位是包类型，FourCC 在字节 1-4。
func flvFourCCAudioBody(pt int, fourCC string, asc []byte) []byte {
	b := append([]byte{byte(0x90 | (pt & 0x0F))}, fourCC...)
	return append(b, asc...)
}

// flvMetaBody 把几个值编成脚本标签正文（onMetaData 那一类）。
func flvMetaBody(t *testing.T, vals ...any) []byte {
	t.Helper()
	b, err := AMF0Encode(vals...)
	if err != nil {
		t.Fatalf("编 AMF0：%v", err)
	}
	return b
}

// flvZeros 是永不到头的零字节 —— 用它才看得出探测端有没有真去追一个虚报的长度。
type flvZeros struct{ n int64 }

func (z *flvZeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	z.n += int64(len(p))
	return len(p), nil
}

// flvStall 先照常给前 n 个字节，之后的每一次读都报「到点了」。
// ★ 这是拿类型（net.Error 且 Timeout）分的档，不靠中文文本：现场那句「读超时」各家写法不一样。
type flvStall struct {
	r io.Reader
	n int
}

func (s *flvStall) Read(p []byte) (int, error) {
	if s.n <= 0 {
		return 0, flvTimeout{}
	}
	n, err := s.r.Read(p)
	s.n -= n
	return n, err
}

type flvTimeout struct{}

func (flvTimeout) Error() string { return "i/o timeout" }
func (flvTimeout) Timeout() bool { return true }

// ★ Temporary 也得写：net.Error 那个接口到现在还带着这一格，少了它
//
//	探测端那句「靠类型分档」直接落空，到点会被记成容器的长度对不上。
func (flvTimeout) Temporary() bool { return true }

// probeOK 走一遍并要它成功：报错就把整条错误与已经走到的那份账一起吐出来。
func probeOK(t *testing.T, stream []byte, lim FLVLimits) *FLVReport {
	t.Helper()
	rep, err := ProbeFLV(bytes.NewReader(stream), lim)
	if err != nil {
		t.Fatalf("好流却报错了：%v（账 %+v）", err, rep)
	}
	return rep
}

func flvErr(t *testing.T, stream []byte, lim FLVLimits) (*FLVReport, *FLVError) {
	t.Helper()
	rep, err := ProbeFLV(bytes.NewReader(stream), lim)
	if err == nil {
		t.Fatalf("该报错却成功了：%+v", rep)
	}
	var fe *FLVError
	if !errors.As(err, &fe) {
		t.Fatalf("错误没带 FLVError 外壳（工具层就按不了档）：%v", err)
	}
	return rep, fe
}

// concat 把若干段字节接起来。
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ── 头 ──

// 头是对的：声明的音视频标志、版本号、偏移都照实记，走到底说是「读完了」。
func Test好头走到底说ended(t *testing.T) {
	stream := concat(
		flvHead(1, 0x05, 9, nil),
		flvTag(8, 0, flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)),
		flvTag(18, 0, flvMetaBody(t, "onMetaData", map[string]any{"duration": float64(12)})),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.Version != 1 || rep.DataOffset != 9 {
		t.Errorf("头那三格要照实记，拿到 version=%d offset=%d", rep.Version, rep.DataOffset)
	}
	if !rep.FlagAudio || !rep.FlagVideo {
		t.Errorf("头的类型标志位（bit0 音频 / bit2 视频）没拆开：%02x", 0x05)
	}
	if len(rep.HeaderErrors) != 0 {
		t.Errorf("这头哪一处都不毛病，HeaderErrors 却有东西：%q", rep.HeaderErrors)
	}
	// ★ 干净的点播文件本来就该读到 EOF 收口。这一格要是空着或被说成 bytecap，
	//   工具层会把「容器就这么点内容」错报成「我们只看了前 8 MiB」。
	if rep.StopReason != FLVStopEnded {
		t.Errorf("StopReason = %q，想要 %q", rep.StopReason, FLVStopEnded)
	}
	if rep.Tags != 2 || rep.AudioTags != 1 || rep.ScriptTags != 1 {
		t.Errorf("标签数不对：%+v", rep)
	}
}

// 回的根本不是 FLV（现场真有其事：flv 域名给了个网页）。
// 这一档必须带「它像什么」的证据回去，工具层才分得开网页 / mp4 / 裸码流。
func Test回的不是FLV时把头那一截带回来(t *testing.T) {
	stream := []byte("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n<html>…")
	rep, fe := flvErr(t, stream, FLVLimits{})
	if fe.Kind != FLVKindNotFLV || fe.Stage != "header" {
		t.Fatalf("要的是 header/not-flv，拿到 %s/%s（%v）", fe.Stage, fe.Kind, fe)
	}
	// 前三个字节要说得出是哪三个字节：只看中文那句「不是 FLV」分不出这是网页还是 mp4。
	if !strings.Contains(fe.Detail, "48 54 54") {
		t.Errorf("错误里没带头的字样：%q", fe.Detail)
	}
	// ★ Head 是 9 字节头 + 之后最多 24 字节。少了这一截，「它像什么」那一档就没法判了。
	if len(fe.Head) != 33 {
		t.Errorf("Head 该是 9+24=%d 字节，实得 %d（% q）", 33, len(fe.Head), fe.Head)
	}
	if !bytes.HasPrefix(fe.Head, []byte("HTTP")) {
		t.Errorf("Head 开头不是到手的那几个字节：% q", fe.Head[:4])
	}
	if rep.Version != 0 {
		t.Errorf("签名都不对，不该有版本号可记：%+v", rep)
	}
}

// 版本号只认 0 和 1（规格写 1，现场见过写 0 的 muxer）；别的一律「这不是 FLV」。
func Test版本号不是1就当不是FLV(t *testing.T) {
	for _, tc := range []struct {
		ver     byte
		wantErr bool
	}{
		{1, false},
		{0, false}, // 0 是怪 muxer 写的，照样往下走
		{2, true},
		{4, true},
	} {
		stream := concat(flvHead(tc.ver, 0x04, 9, nil),
			flvTag(9, 0, flvAvcKeyBody(0)))
		rep, err := ProbeFLV(bytes.NewReader(stream), FLVLimits{})
		if tc.wantErr {
			var fe *FLVError
			if !errors.As(err, &fe) || fe.Kind != FLVKindNotFLV {
				t.Errorf("版本 %d 该判成 not-flv，拿到 %v", tc.ver, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("版本 %d 不该拦下来：%v", tc.ver, err)
			continue
		}
		if rep.Version != tc.ver {
			t.Errorf("版本号要照实带回去（界面得说「这头写的是 %d」）：实得 %d", tc.ver, rep.Version)
		}
	}
}

// 声明的数据起始偏移不合理：比 9 还小 / 大得离谱，都算「这不是 FLV」。
func Test数据起始偏移不合理(t *testing.T) {
	for _, tc := range []struct {
		off  uint32
		want string
	}{{8, "比 9 还小"}, {0, "比 9 还小"}, {1 << 20, "离谱"}} {
		stream := concat(flvHead(1, 0x04, tc.off, nil), flvTag(9, 0, flvAvcKeyBody(0)))
		rep, fe := flvErr(t, stream, FLVLimits{})
		if fe.Kind != FLVKindNotFLV || fe.Stage != "header" {
			t.Errorf("偏移 %d 要判成 header/not-flv，拿到 %s/%s", tc.off, fe.Stage, fe.Kind)
		}
		if !strings.Contains(fe.Detail, tc.want) {
			t.Errorf("错误里没说清是哪种不合理（想要含 %q）：%q", tc.want, fe.Detail)
		}
		// 声明值本身要留在账上 —— 「它自称偏移 8」是判定的依据，不是我们猜的。
		if rep.DataOffset != tc.off {
			t.Errorf("DataOffset 该记声明的 %d，实得 %d", tc.off, rep.DataOffset)
		}
	}
}

// 头的保留标志位非零：只记一句，不拦。
// ★ 现场有把音频标志写成 bit1 的怪 muxer —— 这种流照样能播，判成「不是 FLV」就是误伤。
func Test头的保留位非零只记一笔(t *testing.T) {
	stream := concat(flvHead(1, 0x07, 9, nil), flvTag(9, 0, flvAvcKeyBody(0)))
	rep := probeOK(t, stream, FLVLimits{})
	if len(rep.HeaderErrors) != 1 || !strings.Contains(rep.HeaderErrors[0], "保留") {
		t.Fatalf("保留位非零这件事没在账上留话：%q", rep.HeaderErrors)
	}
	if rep.Tags != 1 {
		t.Errorf("记一笔就够了，后面的标签照样要走：%+v", rep)
	}
}

// 连 9 字节的头都凑不齐：这一档是 header，不是「容器的标签断了」。
func Test凑不齐9字节的头(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"一个字节都没来", nil},
		{"来了 4 个字节", []byte{'F', 'L', 'V', 1}},
	} {
		_, fe := flvErr(t, tc.in, FLVLimits{})
		if fe.Kind != FLVKindHeader || fe.Stage != "header" {
			t.Errorf("%s：要 header 这一档，拿到 %s/%s", tc.name, fe.Stage, fe.Kind)
		}
		if int64(len(fe.Head)) != int64(len(tc.in)) {
			t.Errorf("%s：到手的字节都要留着（想要 %d 拿到 %d）", tc.name, len(tc.in), len(fe.Head))
		}
	}
	// ★ 签名对但头之后一个字节都没有：这时候 9 字节是齐的，锅在「后面的没来」，
	//   所以不是 header 那一档。抹开这一格，「平台只回了个头」就跟「连头都没回」混了。
	_, fe := flvErr(t, []byte{'F', 'L', 'V', 1, 0x04, 0, 0, 0, 9}, FLVLimits{})
	if fe.Stage != "header" || fe.Kind != FLVKindTag {
		t.Errorf("只有 9 字节的流：stage 该是 header、kind 该是 tag，拿到 %s/%s", fe.Stage, fe.Kind)
	}
}

// DataOffset 大于 9（带扩展头）也要按声明跳对。
// ★ 这一条钉的是「头的 9 个字节是 Peek 看的、没吃掉」那一类错位：
//
//	少算 9 字节的症状是第一个标签的类型读成头的 TypeFlags（4 或 5），
//	于是整条流从这儿歪掉，错误说的是「标签正文没读全」，看着像流的毛病。
func Test带扩展头的流也从正确的位置开始走(t *testing.T) {
	ext := []byte{0, 0, 0, 0} // 扩展头 4 个字节：DataOffset 13 - 9
	body := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	stream := concat(flvHead(1, 0x01, 13, ext), flvTag(8, 100, body))
	rep := probeOK(t, stream, FLVLimits{})
	if rep.Tags != 1 || rep.AudioTags != 1 {
		t.Fatalf("扩展头没跳对，标签就数不成：tags=%d audio=%d stop=%q", rep.Tags, rep.AudioTags, rep.StopReason)
	}
	if rep.FirstMediaTS != 100 {
		t.Errorf("时间戳读歪了（错位 9 字节的症状就是这个数）：%d", rep.FirstMediaTS)
	}
	if rep.BodyBytes != int64(len(body)) {
		t.Errorf("BodyBytes = %d，想要 %d", rep.BodyBytes, len(body))
	}
}

// ── 标签走查的账 ──

// 音视频脚本各自数，字节账按「真从流上消耗掉的」记。
// ★ 只 peek 了 512 字节不等于这一路视频就这么点 —— 按 peek 的数记账，
//
//	现场「音频字节比视频多十倍」这种结论就是编出来的。
func Test字节账按声明长度一格不多一格不少(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	vid := make([]byte, 900)
	vid[0], vid[4] = 0x17, 1
	meta := flvMetaBody(t, "onMetaData", map[string]any{"duration": float64(3)})
	agg := make([]byte, 2000)
	stream := concat(flvHead(1, 0x04, 9, nil),
		flvTag(8, 0, aac),
		flvTag(9, 40, vid),
		flvTag(18, 0, meta),
		flvTag(19, 0, agg),
		flvTag(8, 80, aac),
	)
	rep := probeOK(t, stream, FLVLimits{})
	want := int64(len(aac) + len(vid) + len(meta) + len(agg) + len(aac))
	if rep.Tags != 5 || rep.AudioTags != 2 || rep.VideoTags != 1 || rep.ScriptTags != 1 || rep.OtherTags != 1 {
		t.Errorf("各类标签的数不对：%+v", rep)
	}
	if rep.BodyBytes != want {
		t.Errorf("BodyBytes = %d，想要 %d", rep.BodyBytes, want)
	}
	if rep.AudioBytes != 2*int64(len(aac)) || rep.VideoBytes != int64(len(vid)) {
		t.Errorf("分路字节不对：audio=%d video=%d（想要 %d / %d）",
			rep.AudioBytes, rep.VideoBytes, 2*len(aac), len(vid))
	}
	if rep.PrevTagSizeBad != 0 {
		t.Errorf("每个 PreviousTagSize 都写对了，却记了 %d 次对不上", rep.PrevTagSizeBad)
	}
	// 聚合标签不进音视频任何一条时间戳序列，否则后面那条会被它带歪。
	if rep.FirstMediaTS != 0 || rep.LastMediaTS != 80 {
		t.Errorf("媒体时间戳 = [%d,%d]，想要 [0,80]", rep.FirstMediaTS, rep.LastMediaTS)
	}
	if !rep.HasAudio || !rep.HasVideo {
		t.Errorf("容器里两路都有：%+v", rep)
	}
}

// PreviousTagSize 对不上只记账、不走开。
// ★ 直播平台上这一项常见得很；整段都对不上是 muxer 有毛病的证据，
//
//	但不是「这流读不下去」。这里最容易被写成一见不对就 break。
func TestPrevTagSize对不上只记账不走开(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	single := flvTag(8, 0, aac)
	stream := concat(flvHead(1, 0x01, 9, nil),
		single[:len(single)-4], []byte{0, 0, 0, 7}, // 上一个标签的长度：错的
		flvTag(8, 40, aac),
		single[:len(single)-4], []byte{0xde, 0xad, 0xbe, 0xef},
		flvTag(8, 80, aac),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.Tags != 4 || rep.AudioTags != 4 {
		t.Fatalf("长度账对不上不该停：tags=%d audio=%d stop=%q", rep.Tags, rep.AudioTags, rep.StopReason)
	}
	if rep.PrevTagSizeBad != 2 {
		t.Errorf("PrevTagSizeBad = %d，想要 2 —— 这一格是「muxer 有毛病」唯一的证据", rep.PrevTagSizeBad)
	}
	if rep.StopReason != FLVStopEnded {
		t.Errorf("走到完了就说走完：%q", rep.StopReason)
	}
}

// 聚合/未知类型的标签按**声明的长度**跳过去，跳完下一条还在边界上。
// ★ 按「猜的」长度跳的症状是下一条标签的类型读成正文中间的垃圾，
//
//	于是一条好流被读成「断在标签里」。
func Test聚合标签按声明长度跳过去(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	vid := flvAvcKeyBody(0)
	sps := flvMustB64(t, flvSPSh264720)
	seq := flvAvcSeqBody(t, 0, sps)
	agg := make([]byte, 4096)
	stream := concat(flvHead(1, 0x05, 9, nil),
		flvTag(8, 0, aac),
		flvTag(19, 0, agg), // 声明 4 KiB 的聚合消息，正文对我们是垃圾
		flvTag(8, 40, aac),
		flvTag(9, 320, seq),
		flvTag(9, 360, vid),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.Tags != 5 || rep.OtherTags != 1 {
		t.Fatalf("聚合标签该只数一格就走：%+v", rep)
	}
	if rep.AudioTags != 2 || rep.VideoTags != 2 {
		t.Errorf("跳错字节的话后面这两路就读不到了：%+v", rep)
	}
	want := int64(2*len(aac) + len(agg) + len(seq) + len(vid))
	if rep.BodyBytes != want {
		t.Errorf("BodyBytes = %d，想要 %d（跳过的 4096 也要按声明算全）", rep.BodyBytes, want)
	}
	// 后面那条 AVC 序列头还得解得开 —— 跳歪了这里就是 0。
	if rep.Video == nil || rep.Video.Width != 1280 {
		t.Errorf("聚合标签之后的序列头没解出来：%+v", rep.Video)
	}
}

// ── 不许信流上读来的长度 ──

// 一个标签声称正文 16 MiB-1：不许分配、不许追、不许挂住，直接说「到字节预算了」。
// ★ 24 位长度字段最大约 16 MiB。真关键帧没这么长，超了多半是长度字段被写坏。
//
//	跟着读的代价是「问一句等三秒 + 一次巨量分配」，而现场那台机器还在等答案。
func Test声称16MiB的标签一口都不许吃(t *testing.T) {
	var zeros flvZeros
	head := flvHead(1, 0x04, 9, nil)
	huge := flvTagDecl(9, 0, 1<<24-1, nil) // 声明 16 MiB-1，实际一个正文字节都没给
	src := io.MultiReader(bytes.NewReader(concat(head, huge)), &zeros)
	rep, err := ProbeFLV(src, FLVLimits{})
	if err != nil {
		t.Fatalf("长度虚报不该报错，该收口给答案：%v", err)
	}
	if rep.StopReason != FLVStopByte {
		t.Errorf("StopReason = %q，想要 %q", rep.StopReason, FLVStopByte)
	}
	if rep.Tags != 0 || rep.BodyBytes != 0 {
		t.Errorf("这一条一口都没吃，账上却记了：%+v", rep)
	}
	// ★ 光「没挂住」不够：一次把 16 MiB 读进内存再扔掉，照样不挂住。
	//   真取走的字节数才是「长度字段有没有支配我们」的直接证据。
	if zeros.n > 32<<10 {
		t.Errorf("从源头取走了 %d 字节 —— 那个 16 MiB 的假长度被当真了", zeros.n)
	}
}

// 字节预算用完就说 bytecap：这一档与「读完了」必须分开。
// 工具层照着它说「只看了前 N 字节」，而不是说「容器里就这些」。
func Test字节预算用完说bytecap(t *testing.T) {
	const each = 40
	filler := make([]byte, each)
	var b []byte
	b = append(b, flvHead(1, 0x00, 9, nil)...)
	for i := 0; i < 5; i++ {
		b = append(b, flvTag(19, int64(i)*20, filler)...)
	}
	rep := probeOK(t, b, FLVLimits{MaxBody: 100})
	if rep.StopReason != FLVStopByte {
		t.Fatalf("StopReason = %q，想要 %q", rep.StopReason, FLVStopByte)
	}
	if rep.Tags != 2 || rep.BodyBytes != 2*each {
		t.Errorf("预算 100 只够两条 40 字节的标签，实得 tags=%d bytes=%d", rep.Tags, rep.BodyBytes)
	}
}

// 标签数预算用完就说 tagcap（垃圾标签灌进脚本/聚合标签里刷条数的那种）。
func Test标签数预算用完说tagcap(t *testing.T) {
	filler := make([]byte, 40)
	var b []byte
	b = append(b, flvHead(1, 0x00, 9, nil)...)
	for i := 0; i < 5; i++ {
		b = append(b, flvTag(19, int64(i)*20, filler)...)
	}
	rep := probeOK(t, b, FLVLimits{MaxTags: 2})
	if rep.StopReason != FLVStopTag {
		t.Fatalf("StopReason = %q，想要 %q", rep.StopReason, FLVStopTag)
	}
	if rep.Tags != 2 || rep.OtherTags != 2 {
		t.Errorf("MaxTags=2 却走了 %d 条（other=%d）", rep.Tags, rep.OtherTags)
	}
	if rep.BodyBytes != 80 {
		t.Errorf("字节账要和停下来的那一格对得上：%d", rep.BodyBytes)
	}
}

// 直播流永不到头，靠时间预算收口，说 window。
// ★ 喂一个当场就读完的字节串，Deadline 根本没机会生效 —— 那一版用例永远是绿的。
//
//	这里用 io.Pipe 真把读通道卡住，并且卡完要**吐出字节来**（不是 EOF）：
//	EOF 会让走查按「读完了」收口，把 window 这一档抹平成 ended —— 现场「窗口太小」
//	与「录完了就这么点」是两种判定，靠的就是这一格分开。
func Test到点了收口说window(t *testing.T) {
	pr, pw := io.Pipe()
	body := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	var burst []byte
	burst = append(burst, flvHead(1, 0x01, 9, nil)...)
	// 900 条 ≈ 17 KiB：比探测端 16 KiB 的读缓冲多一截，于是「卡住」发生在走到一半时。
	for i := 0; i < 900; i++ {
		burst = append(burst, flvTag(8, int64(i)*20, body)...)
	}
	var burst2 []byte
	for i := 0; i < 400; i++ {
		burst2 = append(burst2, flvTag(8, int64(i)*20, body)...)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := pw.Write(burst); err != nil {
			return
		}
		time.Sleep(600 * time.Millisecond) // 直播流在这一段里没有下一个标签
		_, _ = pw.Write(burst2)
	}()
	// 探测端收口之后就不读了；没有这一发，还堵在 Write 上的 goroutine 会一直挂着。
	wake := time.AfterFunc(3*time.Second, func() { _ = pw.Close() })
	t.Cleanup(func() {
		wake.Stop()
		_ = pw.Close()
		<-done
	})

	rep, err := ProbeFLV(pr, FLVLimits{Deadline: time.Now().Add(200 * time.Millisecond)})
	if err != nil {
		t.Fatalf("到点收口不该报错：%v", err)
	}
	if rep.StopReason != FLVStopWindow {
		t.Errorf("StopReason = %q，想要 %q（ended 就是把「卡住之后终于来的字节」当成了流末尾）",
			rep.StopReason, FLVStopWindow)
	}
	if rep.Tags < 1 {
		t.Error("一条都没走到就说是「到点了」—— 那是没读而不是读不完")
	}
	if rep.Tags >= 900+400 {
		t.Errorf("Tags=%d：预算没起作用，整条流都走完了", rep.Tags)
	}
	if !rep.MediaTSSeen {
		t.Error("窗口到点之前问到的媒体时间戳也要在账上")
	}
}

// 断在标签中间：报错，但已经走到的那一份账必须照样交回去。
// ★ 「问到一半断了」和「什么都没问到」是两档不同的判定，抹平它们就是把现场最常见的一种丢了。
func Test断在标签里也把手上那份交回去(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	sps := flvMustB64(t, flvSPSh264720)
	seq := flvAvcSeqBody(t, 0, sps)
	head := flvHead(1, 0x05, 9, nil)
	// 第三条声明 1000 字节，实际只给 300 字节
	trunc := flvTagDecl(8, 200, 1000, make([]byte, 300))
	rep, fe := flvErr(t, concat(head, flvTag(8, 0, aac), flvTag(9, 40, seq), trunc), FLVLimits{})
	if fe.Stage != "body" || fe.Kind != FLVKindTag {
		t.Errorf("要 body/tag 这一档，拿到 %s/%s", fe.Stage, fe.Kind)
	}
	if !errors.Is(fe, io.ErrUnexpectedEOF) {
		t.Errorf("没把底层「读半截」的原样留在错误链上：%v", fe)
	}
	seen := fe.Seen
	if seen == nil {
		t.Fatal("Seen 是空的 —— 已经走到的那些就这么丢了")
	}
	if seen.Tags != 2 || seen.AudioTags != 1 || seen.VideoTags != 1 {
		t.Errorf("出错之前的账没保住：%+v", seen)
	}
	if seen.BodyBytes != int64(len(aac)+len(seq)) {
		t.Errorf("字节账要只算真吃完的那两条：%d", seen.BodyBytes)
	}
	// ★ 断流之前解出来的分辨率也要保住：现场那句「只有 30 秒内容」的流照样有分辨率可报。
	if seen.Video == nil || seen.Video.Width != 1280 {
		t.Errorf("Seen 里的视频参数丢了：%+v", seen.Video)
	}
	if seen.StopReason != "" {
		t.Errorf("报错的时候 StopReason 该空着（非空表示走完了/预算到点）：%q", seen.StopReason)
	}
	if rep != seen {
		t.Errorf("返回的 rep 与 Seen 不是同一份，调用方拿哪个都可能不一致")
	}
}

// 最后一个标签的头缺几个字节：说的是「凑不齐 11 字节的标签头」，不是「容器里没有标签」。
func Test最后一个标签的头缺几个字节(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	stream := concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, aac), []byte{9, 0, 0, 1, 0})
	rep, fe := flvErr(t, stream, FLVLimits{})
	if fe.Stage != "tag" || fe.Kind != FLVKindTag {
		t.Fatalf("要 tag/tag，拿到 %s/%s", fe.Stage, fe.Kind)
	}
	if !strings.Contains(fe.Detail, "只读到 5 字节") {
		t.Errorf("要说清缺几个字节（现场分「截断」与「垃圾」就靠这句）：%q", fe.Detail)
	}
	if rep.Tags != 1 || rep.AudioBytes != int64(len(aac)) {
		t.Errorf("前面那条音频的账要保住：%+v", rep)
	}
}

// 读通道自己到点了：这一档是 io，不是「容器的长度对不上」。
// ★ 容器根本没毛病，是我们不读了 —— 混成一档，工具层就会把「窗口太小」说成「流是坏的」。
func Test读通道到点了算io(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	var b []byte
	b = append(b, flvHead(1, 0x01, 9, nil)...)
	for i := 0; i < 2; i++ {
		b = append(b, flvTag(8, int64(i)*20, aac)...)
	}
	src := &flvStall{r: bytes.NewReader(b), n: len(b)}
	rep, err := ProbeFLV(src, FLVLimits{})
	var fe *FLVError
	if !errors.As(err, &fe) {
		t.Fatalf("%v", err)
	}
	if fe.Kind != FLVKindIO || fe.Stage != "tag" {
		t.Errorf("要 tag/io 这一档，拿到 %s/%s（%v）", fe.Stage, fe.Kind, fe)
	}
	var ne net.Error
	if !errors.As(fe, &ne) || !ne.Timeout() {
		t.Errorf("原样的超时错误要留在链上，工具层用类型认它：%v", fe)
	}
	if rep.Tags != 2 || rep.AudioTags != 2 {
		t.Errorf("到点之前问到的那两条要交回去：%+v", rep)
	}
}

// ── 时间戳 ──

// 24 位 + 1 字节扩展高位要拼回 32 位。
// ★ 两种错法各钉一次：忘了扩展位就永远停在 16777215；
//
//	把字节 4-7 当连续大端读，0x01000000 会读成 1、0x01000001 会读成 257 —— 都是静默的错。
func Test时间戳的扩展位要拼回32位(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	stream := concat(flvHead(1, 0x01, 9, nil),
		flvTag(8, 0xFFFFFF, aac),
		flvTag(8, 0x01000000, aac),
		flvTag(8, 0x01000001, aac),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.FirstMediaTS != 0xFFFFFF {
		t.Errorf("FirstMediaTS = %d，想要 %d", rep.FirstMediaTS, 0xFFFFFF)
	}
	if rep.LastMediaTS != 0x01000001 {
		t.Errorf("LastMediaTS = %d，想要 %d（拿到 257 就是把 4-7 当连续大端读了）",
			rep.LastMediaTS, 0x01000001)
	}
	if rep.LastMediaTS <= 0xFFFFFF {
		t.Errorf("跨到扩展位的那些时间戳被截在 24 位里了：%d", rep.LastMediaTS)
	}
}

// 32 位回绕要补圈数：不补的症状是「最后时间戳」比第一个还小，时长成负数。
func Test时间戳跨32位补一圈(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	stream := concat(flvHead(1, 0x01, 9, nil),
		flvTag(8, 0xFFFFFFF0, aac),
		flvTag(8, 0x00000010, aac),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.FirstMediaTS != 0xFFFFFFF0 {
		t.Errorf("FirstMediaTS = %d", rep.FirstMediaTS)
	}
	want := uint64(1)<<32 + 0x10
	if rep.LastMediaTS != want {
		t.Errorf("LastMediaTS = %d，想要 %d —— 没补圈数它就是个比第一个还小的数", rep.LastMediaTS, want)
	}
}

// 那几个「快绕圈」的时间戳一律用 int64 具名常量。
// ★ 这仓库有 windows/386 的构建目标，那边的 int 是 32 位：把 0xFFFFFFF0 直接写进
// t.Errorf 的可变参数，整个测试包在 386 上会「常量溢出」编译不过 —— 而 386 正是
// 这一族用例要跑到的地方，编译不过就等于这一档没人守。
const (
	flvTSAlmostWrap = int64(0xFFFFFFF0) // 距 32 位满圈还差 16
	flvTSPastWrap   = int64(0xFFFFFFF5) // 比上面那一格再往前 5，仍在满圈之前
)

// 回绕按码种各自解：音频那条不许把视频解歪。
// ★ 拿一个全局游标的话，音频那条高时间戳之后，视频正常的增量会被当成绕了一圈，
//
//	时长凭空多 49.7 天 —— 而这一档在直播平台上天天见（音频从 0 起、视频从别处起）。
func Test音频的高时间戳不许把视频解歪(t *testing.T) {
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	vid := flvAvcKeyBody(0)
	stream := concat(flvHead(1, 0x05, 9, nil),
		flvTag(9, 0x10, vid),
		flvTag(8, flvTSAlmostWrap, aac),
		flvTag(9, 0x20, vid),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.LastMediaTS != uint64(flvTSAlmostWrap) {
		t.Errorf("LastMediaTS = %d，想要 %d（%d 就是被音频那条带歪了一圈）",
			rep.LastMediaTS, flvTSAlmostWrap, uint64(1)<<32+0x20)
	}
	if rep.FirstMediaTS != 0x10 {
		t.Errorf("FirstMediaTS = %d，想要 16（第一个媒体标签的时间戳）", rep.FirstMediaTS)
	}
}

// 脚本标签的时间戳不进音视频任何一条序列，也不算媒体时间戳。
// ★ 一条 ts=0 的 onMetaData 总在流首：让它进序列就把解回绕的起点带歪，
//
//	还会把 FirstMediaTS 说成 0 —— 「这流从 0 秒开始有画面」是编出来的。
func Test脚本标签的时间戳不算媒体时间戳(t *testing.T) {
	vid := flvAvcKeyBody(0)
	meta := flvTag(18, 0, flvMetaBody(t, "onMetaData", map[string]any{"duration": float64(1)}))
	stream := concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, flvTSAlmostWrap, vid),
		meta,
		flvTag(9, flvTSPastWrap, vid),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.ScriptTags != 1 || !rep.MetadataSeen {
		t.Fatalf("脚本标签本身要数到、元数据也要解开：%+v", rep)
	}
	if rep.FirstMediaTS != uint64(flvTSAlmostWrap) {
		t.Errorf("FirstMediaTS = %d，想要 %d（脚本那条 ts=0 不该参与）", rep.FirstMediaTS, flvTSAlmostWrap)
	}
	if rep.LastMediaTS != uint64(flvTSPastWrap) {
		t.Errorf("LastMediaTS = %d，想要 %d（%d 是把脚本标签当成视频序列的一部分解出来的）",
			rep.LastMediaTS, flvTSPastWrap, uint64(1)<<32+uint64(flvTSPastWrap))
	}
}

// ── 编码认门 ──

// 老式 AVC 序列头：配置记录在字节 8 之后，SPS 交给本包既有的解析器。
// ★ 分辨率是这条流能不能播的头一号数：报不出来（或报成 0）在现场就等于没用。
func TestAVC序列头解出分辨率(t *testing.T) {
	sps := flvMustB64(t, flvSPSh264720)
	stream := concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, 0, flvAvcSeqBody(t, 0, sps)),
		flvTag(9, 33, flvAvcKeyBody(0)),
	)
	rep := probeOK(t, stream, FLVLimits{})
	v := rep.Video
	if v == nil {
		t.Fatal("序列头解不开，Video 是空的")
	}
	if v.Width != 1280 || v.Height != 720 {
		t.Errorf("解出 %dx%d，想要 1280x720", v.Width, v.Height)
	}
	if v.Codec != "h264" || v.FourCC != "avc1" || v.CodecID != 7 {
		t.Errorf("认门认歪了：%+v", v)
	}
	if v.ParamsNote != "" {
		t.Errorf("解出来了还留一句「为什么没解出来」，界面就会两说：%q", v.ParamsNote)
	}
	if rep.VideoFormats[0] != "h264" {
		t.Errorf("VideoFormats = %q", rep.VideoFormats)
	}
	// 序列头是 1080 那一类老流常写的，这里顺带钉「不许把 720 报成 736」：
	// SPS 里的裁剪窗口不减就会多出整块的高度。
	if v.Height == 736 {
		t.Error("736 = 没减裁剪窗口，编码时补到 16 的整数倍")
	}
}

// 合成时间为 0 的关键帧照样数得着。
// ★ 把字节 1（合成时间高位，几乎所有非 B 帧流的常态就是 0）当成 AVCPacketType 的话，
//
//	所有关键帧都被当成序列头去解配置记录，Keyframes 一格不记，
//	「容器里有没有 I 帧」这一问就答错了 —— 而那正是「画面卡顿/黑屏」那一档的依据。
func Test合成时间为零的关键帧也数得着(t *testing.T) {
	sps := flvMustB64(t, flvSPSh264720)
	stream := concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, 0, flvAvcSeqBody(t, 0, sps)), // 序列头：不是关键帧，别混进这一格
		flvTag(9, 40, flvAvcKeyBody(0)),
		flvTag(9, 80, flvAvcKeyBody(0)),
		flvTag(9, 120, append([]byte{0x27, 0, 0, 0, 1, 0, 0, 1}, 0x41, 0x22)), // 帧型 2 = 增幅帧
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.Keyframes != 2 {
		t.Errorf("Keyframes = %d，想要 2（序列头不许算关键帧，增幅帧也不算）", rep.Keyframes)
	}
	if !rep.HasKeyframe || rep.FirstKeyTS != 40 {
		t.Errorf("HasKeyframe=%v FirstKeyTS=%d，想要 true / 40", rep.HasKeyframe, rep.FirstKeyTS)
	}
}

// 增强头（FourCC）单轨：avc1 与 hvc1/hev1 两种 2024 年写法都认，
// 认不出的 FourCC 只报名字、不编分辨率。
func Test增强头FourCC单轨(t *testing.T) {
	sps264 := flvMustB64(t, flvSPSh264720)
	sps265 := flvMustB64(t, flvSPSh2651080)
	pps := []byte{0x44, 0x01, 0xc0, 0xf8, 0x3a, 0x70} // 类型 34，用来钉「找的是 SPS 不是它」
	for _, tc := range []struct {
		name        string
		fourCC      string
		codec       string
		w, h        int
		configBytes []byte
		note        string
	}{
		{"avc1", "avc1", "h264", 1280, 720, flvAvcConfig(sps264), ""},
		{"hvc1", "hvc1", "h265", 1920, 1080, flvHevcConfig(sps265, pps), ""},
		{"hev1（参数集只当解码器配置那种写法）", "hev1", "h265", 1920, 1080, flvHevcConfig(sps265, pps), ""},
	} {
		rec := tc.configBytes
		body := flvExtVideoBody(1, 0, tc.fourCC, rec)
		stream := concat(flvHead(1, 0x04, 9, nil), flvTag(9, 10, body))
		rep := probeOK(t, stream, FLVLimits{})
		if rep.Video == nil {
			t.Fatalf("%s：增强头序列头没给出 Video", tc.name)
		}
		if rep.Video.Codec != tc.codec {
			t.Errorf("%s：Codec = %q，想要 %q", tc.name, rep.Video.Codec, tc.codec)
		}
		if rep.Video.Width != tc.w || rep.Video.Height != tc.h {
			t.Errorf("%s：解出 %dx%d，想要 %dx%d", tc.name, rep.Video.Width, rep.Video.Height, tc.w, tc.h)
		}
		if rep.Video.ParamsNote != tc.note {
			t.Errorf("%s：ParamsNote = %q，想要 %q", tc.name, rep.Video.ParamsNote, tc.note)
		}
	}

	// 认不出的 FourCC（老草案 XPCC 那一类）：报名字，分辨率那一格必须空着。
	// ★ 空着是「没解出来」，编一个数是「解错了」—— 后者会带着人往错的方向查。
	body := flvExtVideoBody(1, 0, "XPCC", flvHevcConfig(flvMustB64(t, flvSPSh2651080), []byte{0x44, 1, 2, 3, 4, 5}))
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil), flvTag(9, 0, body)), FLVLimits{})
	if len(rep.VideoFormats) != 1 || rep.VideoFormats[0] != `fourcc "XPCC"` {
		t.Errorf("认不出的 FourCC 该原样报名字：%q", rep.VideoFormats)
	}
	if rep.Video != nil {
		t.Errorf("认不出的编码不该有参数可报：%+v", rep.Video)
	}
}

// 增强头但 FourCC 那 4 个字节不成字 / 短得读不完：点名，不猜。
func Test增强头但FourCC读不成(t *testing.T) {
	short := flvExtVideoBody(1, 0, "av", nil) // 声明的正文只有 4 个字节，FourCC 缺两个
	garbage := []byte{0x90, 0x00, 0x11, 0x22, 0x33, 0x01, 0x02}
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, 0, short), flvTag(9, 20, garbage)), FLVLimits{})
	if len(rep.VideoFormats) != 2 {
		t.Fatalf("两种坏头各记一种，不该去重成一个：%q", rep.VideoFormats)
	}
	if rep.VideoFormats[0] != "扩展头但 FourCC 没读全" {
		t.Errorf("短的没点名：%q", rep.VideoFormats[0])
	}
	if rep.VideoFormats[1] != "扩展头但 FourCC 不成字" {
		t.Errorf("不成字的没点名：%q", rep.VideoFormats[1])
	}
	if rep.Video != nil {
		t.Errorf("这两种都解不出内容，不该有 Video：%+v", rep.Video)
	}
}

// 多轨封装（Enhanced RTMP 那一版只点名不解析）：分辨率那一格必须空着。
// ★ 这一版认多轨的依据是「F 开头、第二字节是 0-5 的数字」（F0v1 这一类写法）。
//
//	多轨 FourCC 的规范拼法我离线查不实（能查到的另一实现 mediamtx 走的是
//	「普通 FourCC + TrackID」那一套，压根不带 F 前缀），所以这一格只把**当前口径**
//	钉住：换成 Fv01 / FAAC 这种第二字节是字母的写法，这里就认不出多轨、
//	会顺着普通 FourCC 那一格去解配置记录 —— 现场真遇到再定，别照着猜改断言。
func Test多轨扩展头不报分辨率(t *testing.T) {
	sps := flvMustB64(t, flvSPSh264720)
	body := flvExtVideoBody(1, 0, "F0v1", flvAvcConfig(sps))
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil), flvTag(9, 0, body)), FLVLimits{})
	if !rep.MultiTrack {
		t.Error("多轨没标出来 —— 现场「只解一路当成整条流」的错分辨率就是从这儿漏的")
	}
	if rep.Video != nil {
		t.Errorf("多轨这一格明说不报分辨率，实得 %+v", rep.Video)
	}
	if len(rep.VideoFormats) == 0 || !strings.Contains(rep.VideoFormats[0], "多轨") {
		t.Errorf("账上没留「这是多轨」那一句：%q", rep.VideoFormats)
	}
	// 多轨标签仍然要是媒体标签：HasVideo 与字节账都该跟着记，不然「有没有视频」会答成没有。
	if !rep.HasVideo || rep.VideoTags != 1 {
		t.Errorf("多轨的账：%+v", rep)
	}
}

// 多轨的切换包（包类型 6）也标多轨：它带着普通 FourCC，光看 FourCC 认不出来。
func Test多轨切换包也标多轨(t *testing.T) {
	body := flvExtVideoBody(1, 6, "avc1", nil)
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil), flvTag(9, 0, body)), FLVLimits{})
	if !rep.MultiTrack {
		t.Error("后面要切换多轨这件事没在账上留话")
	}
	if rep.Video != nil {
		t.Errorf("切换包里没有配置记录，不该报参数：%+v", rep.Video)
	}
}

// 老草案那一号（12/13 号）的 HEVC：布局照抄 AVC 那一路，也要解得出分辨率。
// ★ 国内推流端把 codecID 写成 8 的也有 —— 那一号是保留位，报名字就够，不许猜内容。
func Test老草案编号的HEVC(t *testing.T) {
	sps := flvMustB64(t, flvSPSh2651080)
	pps := []byte{0x44, 0x01, 0xc0, 0xf8, 0x3a, 0x70}
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, 0, flvHevcSeqBody(t, sps, pps)),
		flvTag(9, 40, append([]byte{0x1C, 0, 0, 0, 1, 0, 0, 1}, 0x02, 0x11)),
	), FLVLimits{})
	if rep.Video == nil || rep.Video.Codec != "h265" {
		t.Fatalf("12 号序列头没解出来：%+v", rep.Video)
	}
	if rep.Video.Width != 1920 || rep.Video.Height != 1080 {
		t.Errorf("解出 %dx%d，想要 1920x1080", rep.Video.Width, rep.Video.Height)
	}
	if rep.Video.CodecID != 12 {
		t.Errorf("CodecID = %d（老草案那一号要照实带回去，工具层靠它说「非标准写法」）", rep.Video.CodecID)
	}
	if rep.Keyframes != 1 {
		t.Errorf("12 号的关键帧也要数：%d（序列头那条不算）", rep.Keyframes)
	}

	rep2 := probeOK(t, concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, 0, []byte{0x18, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x02}), // codecID 8 = 保留位写法
	), FLVLimits{})
	if len(rep2.VideoFormats) != 1 || !strings.Contains(rep2.VideoFormats[0], "保留位") {
		t.Errorf("8 号要说是保留位写法而不是 h265：%q", rep2.VideoFormats)
	}
	if rep2.Video != nil {
		t.Errorf("8 号认不出内容，不该报参数：%+v", rep2.Video)
	}
}

// 没置 0x80 却带 FourCC 的推流端：FourCC 说话算数，只认编码名、不猜分辨率。
// ★ 现场这一类端把 FourCC 写在合成时间那一格的位置：按老布局走就会把 FourCC
//
//	当配置记录去解，解出来的「分辨率」是拼出来的。
func Test没置0x80却带FourCC的只认编码名(t *testing.T) {
	w := &flvBits{}
	w.put(1, 4)
	w.put(12, 4)
	// ★ FourCC 那四个字节是可打印 ASCII 的「hvc1」，最后一个字符是 '1'（0x31）而不是 0x01 ——
	//   写成裸 1 的话探测端会判「FourCC 不成字」，用例就变成在测自己的拼写。
	b := []byte{w.buf[0], 'h', 'v', 'c', '1'}
	b = append(b, flvHevcConfig(flvMustB64(t, flvSPSh2651080), []byte{0x44, 1, 2, 3, 4, 5})...)
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil), flvTag(9, 0, b)), FLVLimits{})
	if len(rep.VideoFormats) == 0 || rep.VideoFormats[0] != "h265" {
		t.Errorf("FourCC 没当成认门依据：%q", rep.VideoFormats)
	}
	if rep.Video != nil {
		t.Errorf("这一路布局不敢当真，分辨率该空着：%+v", rep.Video)
	}
}

// ── 音频 ──

// 老式 AAC 序列头解采样率与声道（ISO/IEC 14496-3 的 AudioSpecificConfig）。
// 注：这一格结构体现在只有编号、采样率、声道 —— 没有 profile 那一栏，别指望它报 AAC-LC。
func TestAAC序列头解出采样率与声道(t *testing.T) {
	asc := ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4}) // AAC-LC / 44100 / 立体声
	seq := flvAACBody(asc...)
	nalu := []byte{0xAF, 0x01, 0xFF} // 后面的裸 AAC 帧：包头只有一个字节
	rep := probeOK(t, concat(flvHead(1, 0x01, 9, nil),
		flvTag(8, 0, seq),
		flvTag(8, 40, nalu),
	), FLVLimits{})
	if rep.AAC == nil {
		t.Fatal("AAC 序列头什么都没解出来")
	}
	if rep.AAC.SampleRateHz != 44100 {
		t.Errorf("采样率 = %d，想要 44100（错位一个 bit 就会解成 8000 或 64000）", rep.AAC.SampleRateHz)
	}
	if rep.AAC.Channels != 2 {
		t.Errorf("声道 = %d，想要 2（拿错声道数去下结论比不报更坏：「这路是单声道所以没声音」）", rep.AAC.Channels)
	}
	if rep.AAC.Format != 10 || rep.AAC.FourCC != "" {
		t.Errorf("认门歪了：%+v", rep.AAC)
	}
	if rep.AudioBytes != int64(len(seq)+len(nalu)) {
		t.Errorf("音频字节账按声明长度记：实得 %d，想要 %d", rep.AudioBytes, len(seq)+len(nalu))
	}
	// 后一条只有一个字节头：低 4 位的 AACPacketType 不该被当成编号的一部分。
	if strings.Join(rep.AudioFormats, ",") != "aac" {
		t.Errorf("AudioFormats 该去重成一条：%q", rep.AudioFormats)
	}
}

// 一份配置记录里挂着几份 SPS（多分辨率兜底那种写法）：取第一份，并且把这件事留话。
// ★ 不留话的症状是现场按「这路是 1920x1080」下结论，而实际用的是备用 SPS；
//
//	反过来第一份读歪了就会去用第二份 —— 报出来的数得知道是从哪一份来的。
func Test多份SPS取第一份并留话(t *testing.T) {
	sps1080 := flvMustB64(t, flvSPSh2641080)
	sps720 := flvMustB64(t, flvSPSh264720)
	w := &flvBits{}
	w.put(1, 8)
	w.put(0x64, 8)
	w.put(0, 8)
	w.put(40, 8)
	w.put(0xFC, 6)
	w.put(3, 2)
	w.put(0xE0, 3)
	w.put(2, 5) // numSPS = 2
	rec := w.buf
	rec = append(rec, byte(len(sps1080)>>8), byte(len(sps1080)))
	rec = append(rec, sps1080...)
	rec = append(rec, byte(len(sps720)>>8), byte(len(sps720)))
	rec = append(rec, sps720...)
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil),
		flvTag(9, 0, append([]byte{0x17, 0, 0, 0, 0, 0, 0, 1}, rec...)),
	), FLVLimits{})
	if rep.Video == nil {
		t.Fatal("两份 SPS 都没解出来")
	}
	if rep.Video.Width != 1920 || rep.Video.Height != 1080 {
		t.Errorf("解出 %dx%d，想要第一份 1920x1080", rep.Video.Width, rep.Video.Height)
	}
	if !strings.Contains(rep.Video.ParamsNote, "多份 SPS") {
		t.Errorf("取的是哪一份这件事得留话：%q", rep.Video.ParamsNote)
	}
}

// 解不出的 AudioSpecificConfig 留 0 或留空，不编一个数。
// ★ 采样率索引 13/14 是保留值、15 是 24 位精确频率：这些岔路走歪了的话，
//
//	后面每一个字段都错位 —— 拿错位的位数报「这路是 48kHz 单声道」比空白坏得多。
func Test解不出的AAC配置留空而不是猜(t *testing.T) {
	// 保留索引 12（表里就是 0）：采样率取不到，声道那格照实报。
	reserved := ascBits([2]int{2, 5}, [2]int{12, 4}, [2]int{2, 4})
	rep := probeOK(t, concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, flvAACBody(reserved...))), FLVLimits{})
	if rep.AAC == nil {
		t.Fatal("这一种是解得开结构、只是取不到频率：不该整份丢掉")
	}
	if rep.AAC.SampleRateHz != 0 {
		t.Errorf("保留索引却报了 %d Hz —— 那是编的", rep.AAC.SampleRateHz)
	}
	if rep.AAC.Channels != 2 {
		t.Errorf("能确证的声道也要留着：%+v", rep.AAC)
	}

	// 配置记录只有一个字节：连声道那格都读不出来，整份丢掉。
	rep2 := probeOK(t, concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, flvAACBody(0x12))), FLVLimits{})
	if rep2.AAC != nil {
		t.Errorf("只读到一个字节的 ASC 不该给出结论：%+v", rep2.AAC)
	}

	// 精确频率（索引 15）自称 0：那是无意义值，整份丢掉而不是报「0 Hz」。
	zeroExact := ascBits([2]int{2, 5}, [2]int{15, 4}, [2]int{0, 24}, [2]int{2, 4})
	rep3 := probeOK(t, concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, flvAACBody(zeroExact...))), FLVLimits{})
	if rep3.AAC != nil {
		t.Errorf("自称 0 Hz 的配置该丢掉：%+v", rep3.AAC)
	}

	// 声道配置 > 8 位流里写不出，读到就是后面全错位了。
	crazyCh := ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{15, 4})
	rep4 := probeOK(t, concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, flvAACBody(crazyCh...))), FLVLimits{})
	if rep4.AAC != nil {
		t.Errorf("声道那格错位了却报了结论：%+v", rep4.AAC)
	}
}

// SBR/PS（HE-AAC 那一类）的扩展频率岔路：跳不对就把扩展对象类型当成主频率索引，
// 症状是采样率解出一个看着合理却完全错的数。
func TestHEAAC的扩展频率岔路也要跳对(t *testing.T) {
	asc := ascBits([2]int{5, 5}, [2]int{7, 4}, [2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})
	rep := probeOK(t, concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, flvAACBody(asc...))), FLVLimits{})
	if rep.AAC == nil {
		t.Fatal("HE-AAC 的序列头整份丢了")
	}
	if rep.AAC.SampleRateHz != 44100 {
		t.Errorf("采样率 = %d，想要 44100（解成 8000 就是没跳过扩展对象类型那 5 位）", rep.AAC.SampleRateHz)
	}
	if rep.AAC.Channels != 2 {
		t.Errorf("声道 = %d，想要 2", rep.AAC.Channels)
	}
}

// 扩展音频头（FourCC 那一类，含 2024 年的 mp4a 写法）：FourCC 原样报名字，
// 序列头里的 AudioSpecificConfig 也要照解。
func TestFourCC音频头认mp4a并解配置(t *testing.T) {
	asc := ascBits([2]int{2, 5}, [2]int{3, 4}, [2]int{1, 4}) // 48000 / 单声道
	body := flvFourCCAudioBody(0, "mp4a", asc)
	rep := probeOK(t, concat(flvHead(1, 0x01, 9, nil), flvTag(8, 0, body)), FLVLimits{})
	if len(rep.AudioFormats) != 1 || rep.AudioFormats[0] != `fourcc "mp4a"` {
		t.Errorf("扩展头要按 FourCC 报名字：%q", rep.AudioFormats)
	}
	if rep.AAC == nil || rep.AAC.FourCC != "mp4a" || rep.AAC.Format != 10 {
		t.Fatalf("FourCC 音频的序列头没解：%+v", rep.AAC)
	}
	if rep.AAC.SampleRateHz != 48000 || rep.AAC.Channels != 1 {
		t.Errorf("解成 %+v，想要 48000 Hz 单声道", rep.AAC)
	}
}

// ── 脚本标签 / 元数据 ──

// onMetaData 解进 Metadata，MetadataSeen 为真。
// ★ 这一格是「推流端打算发多大」的那份声明，界面要拿它和实测码率对着看；
//
//	解不开就只能说「没问到」，现场「声明 2M 实际 200k」那一类毛病就没证据了。
func Test元数据onMetaData解进Metadata(t *testing.T) {
	meta := map[string]any{
		"duration":     float64(123.4),
		"width":        float64(1920),
		"videocodecid": float64(7),
		"encoder":      "yuzhong-expr",
		"canSeekToTS":  true,
	}
	body := flvMetaBody(t, "onMetaData", meta)
	rep := probeOK(t, concat(flvHead(1, 0x05, 9, nil), flvTag(18, 0, body)), FLVLimits{})
	if !rep.MetadataSeen {
		t.Fatal("MetadataSeen 没跟上")
	}
	if rep.Metadata["duration"] != float64(123.4) || rep.Metadata["width"] != float64(1920) {
		t.Errorf("元数据解歪了：%+v", rep.Metadata)
	}
	if s, _ := rep.Metadata["encoder"].(string); s != "yuzhong-expr" {
		t.Errorf("字符串那格：%+v", rep.Metadata["encoder"])
	}
	if b, _ := rep.Metadata["canSeekToTS"].(bool); !b {
		t.Errorf("布尔那格没按 AMF0 boolean 解：%+v", rep.Metadata["canSeekToTS"])
	}
	if rep.ScriptTags != 1 || rep.MetaErrCount != 0 {
		t.Errorf("脚本标签的数与错数：%+v", rep)
	}
	if rep.HasVideo || rep.HasAudio {
		t.Errorf("脚本标签不许冒充媒体标签：%+v", rep)
	}
}

// 带 @setDataFrame / onFCPublish 外壳的元数据也要剥掉外壳。
// 现场（尤其 SRS 一类的服务器转发的）就长这样，不剥就找不到那个对象。
func Test元数据带setDataFrame外壳也剥(t *testing.T) {
	inner := map[string]any{"duration": float64(7)}
	body := flvMetaBody(t, "@setDataFrame", "onMetaData", inner)
	rep := probeOK(t, concat(flvHead(1, 0x04, 9, nil), flvTag(18, 0, body)), FLVLimits{})
	if !rep.MetadataSeen || rep.Metadata["duration"] != float64(7) {
		t.Errorf("剥壳没剥成：%+v", rep.Metadata)
	}
	body2 := flvMetaBody(t, "onFCPublish", "onMetaData", inner)
	rep2 := probeOK(t, concat(flvHead(1, 0x04, 9, nil), flvTag(18, 0, body2)), FLVLimits{})
	if !rep2.MetadataSeen {
		t.Errorf("onFCPublish 那一类外壳也要剥：%+v", rep2)
	}
}

// 声明长度超过内部上限的脚本标签：不进内存解析，只点名。
// ★ 正常元数据没有几十 KB 的，那种多半是有人把码流灌进了脚本标签 ——
//
//	整段读进来跑 AMF0 是白送的内存与 CPU。但账上要点名，不然「元数据为空」会被读成「它没发」。
func Test脚本标签超上限不进内存只点名(t *testing.T) {
	const capSize = 64 << 10
	big := make([]byte, capSize+1)
	body := flvMetaBody(t, "onMetaData", map[string]any{"duration": float64(1)})
	stream := concat(flvHead(1, 0x05, 9, nil),
		flvTag(18, 0, big),
		flvTag(18, 20, body),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if rep.ScriptTooBig != 1 {
		t.Errorf("ScriptTooBig = %d，想要 1", rep.ScriptTooBig)
	}
	if rep.ScriptTags != 2 {
		t.Errorf("两条都数到了才算走了这一格：%d", rep.ScriptTags)
	}
	if rep.BodyBytes != int64(len(big))+int64(len(body)) {
		t.Errorf("字节账按声明长度记（不是按进内存的那 64 KiB）：实得 %d", rep.BodyBytes)
	}
	// ★ 第一条没解析不等于后面都不解析：这条要是丢了，「容器里没有元数据」就是误判。
	if !rep.MetadataSeen || rep.Metadata["duration"] != float64(1) {
		t.Errorf("超限之后第二条元数据没解出来：%+v", rep.Metadata)
	}

	// 刚好等于上限的：整段都在手里，按现在的写法也被点名没解析（保守一档）。
	// ★ 这是「宁可少解也不冒风险」的取舍，钉在这儿免得日后被人当成漏解的 bug 改掉。
	rep2 := probeOK(t, concat(flvHead(1, 0x05, 9, nil), flvTag(18, 0, make([]byte, capSize))), FLVLimits{})
	if rep2.ScriptTooBig != 1 || rep2.MetadataSeen {
		t.Errorf("等于上限这一档的现在口径是点名不解析：%+v", rep2)
	}
}

// AMF0 解不开只记错数，不许把整次探测带崩。
// ★ 现场脚本标签里灌垃圾太常见了（有人把 SEI 或私有数据当成 onMetaData 发）：
//
//	一见解不开就报错，工具层就答不出「这容器里有几路音视频」了。
func TestAMF0解不开只记错数(t *testing.T) {
	garbage := []byte{0x03, 0xff, 0xff, 0xff}         // 对象起手就断
	onlyStr := flvMetaBody(t, "whatever", "nonsense") // 解得开，可里面没有对象
	rep := probeOK(t, concat(flvHead(1, 0x05, 9, nil),
		flvTag(18, 0, garbage),
		flvTag(15, 20, onlyStr), // 15 号也按脚本走
		flvTag(9, 40, flvAvcKeyBody(0)),
	), FLVLimits{})
	if rep.MetaErrCount != 2 {
		t.Errorf("MetaErrCount = %d，想要 2（两种解不开各记一次）", rep.MetaErrCount)
	}
	if rep.ScriptTags != 2 {
		t.Errorf("解不开也要数到脚本标签：%d", rep.ScriptTags)
	}
	if rep.MetadataSeen || len(rep.Metadata) != 0 {
		t.Errorf("解不开不该有元数据：%+v", rep.Metadata)
	}
	// ★ 探测照常成功、后面的视频标签照常走：这是「错误分层」的硬要求。
	if rep.VideoTags != 1 || rep.StopReason != FLVStopEnded {
		t.Errorf("脚本解不开把整次探测带崩了：%+v", rep)
	}
}

// ── 格式清单与「容器是空的」 ──

// 出现过的编码名按第一次出现的顺序去重。
// ★ 顺序与去重是给现场那句话用的：「这流里先 h264 后 av1」与「有两个 h264」
//
//	是两种不同的事，糊成一串或糊成一个都没法说。
func Test音视频格式按出现顺序去重(t *testing.T) {
	sps := flvMustB64(t, flvSPSh264720)
	aac := flvAACBody(ascBits([2]int{2, 5}, [2]int{4, 4}, [2]int{2, 4})...)
	mp3 := []byte{0x22, 0x00, 0xFF, 0xFB} // 编号 2 = MP3，头两字节
	vp6 := []byte{0x34, 0, 0, 0, 0}       // 帧型 3（增幅）+ 编号 4 = VP6
	stream := concat(flvHead(1, 0x05, 9, nil),
		flvTag(8, 0, aac),
		flvTag(8, 20, mp3),
		flvTag(9, 0, flvAvcSeqBody(t, 0, sps)),
		flvTag(9, 40, flvAvcKeyBody(0)), // 又是 h264：不该重复出现
		flvTag(9, 60, flvExtVideoBody(1, 4, "av01", nil)),
		flvTag(8, 80, aac), // 又一发 AAC：也不该重复
		flvTag(9, 100, vp6),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if got := strings.Join(rep.AudioFormats, ","); got != "aac,mp3" {
		t.Errorf("AudioFormats = %q，想要 aac,mp3", got)
	}
	want := []string{"h264", "av1", "vp6"}
	if strings.Join(rep.VideoFormats, ",") != strings.Join(want, ",") {
		t.Errorf("VideoFormats = %q，想要 %q", rep.VideoFormats, want)
	}
}

// 只有脚本标签的容器：两路媒体都没有，读到了流末尾也要照实说。
// ★ 工具层拿这一档答「平台答应给流，可容器是空的」；
//
//	要是这里报 ended 之外的一档（或 HasVideo 被当成真），就成了「有画面但黑屏」。
func Test容器里一个媒体标签都没有(t *testing.T) {
	body := flvMetaBody(t, "onMetaData", map[string]any{"duration": float64(0)})
	stream := concat(flvHead(1, 0x05, 9, nil), flvTag(18, 0, body))
	rep := probeOK(t, stream, FLVLimits{})
	if rep.HasVideo || rep.HasAudio {
		t.Errorf("只有脚本标签却报了有媒体：%+v", rep)
	}
	if rep.MediaTSSeen || rep.FirstMediaTS != 0 || rep.LastMediaTS != 0 {
		t.Errorf("没有媒体标签就没有媒体时间戳：%+v", rep)
	}
	if rep.StopReason != FLVStopEnded {
		t.Errorf("StopReason = %q，想要 %q —— 这容器本来就只有这一条", rep.StopReason, FLVStopEnded)
	}
	if rep.Tags != 1 || rep.ScriptTags != 1 || !rep.MetadataSeen {
		t.Errorf("元数据那一格照样要给：%+v", rep)
	}
	if len(rep.VideoFormats) != 0 || len(rep.AudioFormats) != 0 {
		t.Errorf("没走过的编码不许出现在清单里：%q / %q", rep.VideoFormats, rep.AudioFormats)
	}
	if rep.HasKeyframe || rep.Keyframes != 0 {
		t.Errorf("脚本标签不许冒充关键帧：%+v", rep)
	}
}

// 头声明有音视频、实际只有空标签：Has* 是真的，但格式清单要点名「空标签」。
// ★ 现场「有音频标签但一个字节内容都没给」是另一档毛病（源断了），
//
//	把它记成「aac」就把证据磨平了。
func Test空标签点名而不当成有内容(t *testing.T) {
	stream := concat(flvHead(1, 0x05, 9, nil),
		flvTag(8, 0, nil),
		flvTag(9, 0, nil),
	)
	rep := probeOK(t, stream, FLVLimits{})
	if strings.Join(rep.AudioFormats, ",") != "空标签" ||
		strings.Join(rep.VideoFormats, ",") != "空标签" {
		t.Errorf("空标签没点名：%q / %q", rep.AudioFormats, rep.VideoFormats)
	}
	if !rep.HasAudio || !rep.HasVideo {
		t.Errorf("标签确实在容器里走了一趟，Has* 该是真：%+v", rep)
	}
	if rep.AAC != nil || rep.Video != nil {
		t.Errorf("空标签里什么都没有，不该解出参数：%+v / %+v", rep.AAC, rep.Video)
	}
	if rep.BodyBytes != 0 || rep.AudioBytes != 0 || rep.VideoBytes != 0 {
		t.Errorf("声明长度是 0，字节账也该是 0：%d/%d/%d", rep.BodyBytes, rep.AudioBytes, rep.VideoBytes)
	}
}
