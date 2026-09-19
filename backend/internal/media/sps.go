// Package media 解视频码流里的参数集，拿分辨率、帧率这些。
//
// ★★ 这个包存在的理由（docs/设计.md「流探测自研方案」）：
//
//	我们要的是**探测**，不是解码。ffprobe 那一套是解码器带来的，
//	而「这路流是多大分辨率」这个问题，答案就写在 SPS 里 —— 纯位流解析，
//	几百行，不需要任何解码器，也就不需要 ffmpeg。
//
// ★ 而且这样拿到的东西比 ffprobe 更适合现场：ffprobe 给不了
// 「实际到达码率」「RTP 丢包率」「关键帧间隔」，那几个才是判断
// 「盒子为什么没画面」的关键。
//
// 起因是 2026-09 某施工现场：40 路摄像头只出 11 路，
// 最后定位到盒子的帧池按 1080p 建、而相机出的是 2K。
// **分辨率对不对得上，是那一路里最要紧的一个数。**
package media

import (
	"errors"
	"fmt"
)

// Params 从参数集里解出来的东西。
type Params struct {
	Codec      string  `json:"codec"`             // h264 / h265
	Width      int     `json:"width"`             //
	Height     int     `json:"height"`            //
	Profile    int     `json:"profile,omitempty"` //
	Level      int     `json:"level,omitempty"`   //
	FPS        float64 `json:"fps,omitempty"`     // SPS 里有 VUI 时才有
	Interlaced bool    `json:"interlaced,omitempty"`
}

// bitReader 按位读，并处理 RBSP 的防竞争字节（emulation prevention）。
//
// ★ 这一步不能省：NAL 载荷里凡是出现 00 00 03，那个 03 是编码器插进去防止
// 和起始码混淆的，解析前必须去掉。不去掉的话，**大多数流看起来都正常，
// 偏偏某些分辨率会算错** —— 是那种偶发、难查的错。
type bitReader struct {
	data []byte
	pos  int // 位偏移
}

func newBitReader(nal []byte) *bitReader {
	// 去掉防竞争字节
	out := make([]byte, 0, len(nal))
	for i := 0; i < len(nal); i++ {
		if i+2 < len(nal) && nal[i] == 0 && nal[i+1] == 0 && nal[i+2] == 3 {
			out = append(out, 0, 0)
			i += 2
			continue
		}
		out = append(out, nal[i])
	}
	return &bitReader{data: out}
}

var errShort = errors.New("码流不够长，解不完")

func (r *bitReader) u(n int) (uint32, error) {
	if n > 32 {
		return 0, fmt.Errorf("一次最多读 32 位")
	}
	var v uint32
	for i := 0; i < n; i++ {
		if r.pos >= len(r.data)*8 {
			return 0, errShort
		}
		bit := (r.data[r.pos/8] >> (7 - uint(r.pos%8))) & 1
		v = v<<1 | uint32(bit)
		r.pos++
	}
	return v, nil
}

func (r *bitReader) flag() (bool, error) {
	v, err := r.u(1)
	return v == 1, err
}

// ue 读无符号指数哥伦布码。H.264/H.265 里绝大多数字段都是这个编码。
func (r *bitReader) ue() (uint32, error) {
	zeros := 0
	for {
		b, err := r.u(1)
		if err != nil {
			return 0, err
		}
		if b == 1 {
			break
		}
		zeros++
		if zeros > 32 {
			return 0, errors.New("指数哥伦布码异常长，码流多半是坏的")
		}
	}
	if zeros == 0 {
		return 0, nil
	}
	rest, err := r.u(zeros)
	if err != nil {
		return 0, err
	}
	return (1 << uint(zeros)) - 1 + rest, nil
}

// se 读有符号指数哥伦布码。
func (r *bitReader) se() (int32, error) {
	v, err := r.ue()
	if err != nil {
		return 0, err
	}
	if v%2 == 0 {
		return -int32(v / 2), nil
	}
	return int32((v + 1) / 2), nil
}

// ParseH264SPS 解 H.264 的 SPS，拿分辨率等。
//
// nal 是**去掉起始码之后**的 NAL 单元（含 1 字节 NAL 头）。
func ParseH264SPS(nal []byte) (Params, error) {
	var p Params
	p.Codec = "h264"
	if len(nal) < 4 {
		return p, errShort
	}
	if t := nal[0] & 0x1f; t != 7 {
		return p, fmt.Errorf("不是 SPS（NAL 类型 %d，SPS 应当是 7）", t)
	}
	r := newBitReader(nal[1:])

	profile, err := r.u(8)
	if err != nil {
		return p, err
	}
	p.Profile = int(profile)
	// ★ 先验 profile_idc 合不合法，再往下解。
	//   不验的话，一段乱码也能一路解下去、解出一个**看着挺合理的**小分辨率
	//   （比如 16x16）—— 那比直接报错坏得多，因为没人会怀疑它。
	//   16x16 本身是合法的 H.264 分辨率，所以不能靠"尺寸太小"来判，只能看 profile。
	if !knownH264Profile(profile) {
		return p, fmt.Errorf("profile_idc=%d 不是已知的 H.264 profile，这段多半不是 SPS 或已损坏", profile)
	}
	if _, err = r.u(8); err != nil { // constraint flags + reserved
		return p, err
	}
	level, err := r.u(8)
	if err != nil {
		return p, err
	}
	p.Level = int(level)
	if _, err = r.ue(); err != nil { // seq_parameter_set_id
		return p, err
	}

	chromaFormat := uint32(1)
	// ★ 这几个 profile 才有 chroma_format_idc 等字段。漏判的话后面所有字段都会错位，
	//   而错位的表现是算出一个"看起来像那么回事"的错分辨率 —— 比直接报错还坏。
	switch profile {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		if chromaFormat, err = r.ue(); err != nil {
			return p, err
		}
		if chromaFormat == 3 {
			if _, err = r.u(1); err != nil { // separate_colour_plane_flag
				return p, err
			}
		}
		if _, err = r.ue(); err != nil { // bit_depth_luma_minus8
			return p, err
		}
		if _, err = r.ue(); err != nil { // bit_depth_chroma_minus8
			return p, err
		}
		if _, err = r.u(1); err != nil { // qpprime_y_zero_transform_bypass_flag
			return p, err
		}
		seqScaling, err := r.flag()
		if err != nil {
			return p, err
		}
		if seqScaling {
			n := 8
			if chromaFormat == 3 {
				n = 12
			}
			for i := 0; i < n; i++ {
				present, err := r.flag()
				if err != nil {
					return p, err
				}
				if present {
					size := 16
					if i >= 6 {
						size = 64
					}
					last, next := int32(8), int32(8)
					for j := 0; j < size; j++ {
						if next != 0 {
							d, err := r.se()
							if err != nil {
								return p, err
							}
							next = (last + d + 256) % 256
						}
						if next != 0 {
							last = next
						}
					}
				}
			}
		}
	}

	if _, err = r.ue(); err != nil { // log2_max_frame_num_minus4
		return p, err
	}
	pocType, err := r.ue()
	if err != nil {
		return p, err
	}
	switch pocType {
	case 0:
		if _, err = r.ue(); err != nil {
			return p, err
		}
	case 1:
		if _, err = r.u(1); err != nil {
			return p, err
		}
		if _, err = r.se(); err != nil {
			return p, err
		}
		if _, err = r.se(); err != nil {
			return p, err
		}
		n, err := r.ue()
		if err != nil {
			return p, err
		}
		for i := uint32(0); i < n; i++ {
			if _, err = r.se(); err != nil {
				return p, err
			}
		}
	}
	if _, err = r.ue(); err != nil { // max_num_ref_frames
		return p, err
	}
	if _, err = r.u(1); err != nil { // gaps_in_frame_num_value_allowed_flag
		return p, err
	}

	widthMBs, err := r.ue()
	if err != nil {
		return p, err
	}
	heightMapUnits, err := r.ue()
	if err != nil {
		return p, err
	}
	frameMBsOnly, err := r.flag()
	if err != nil {
		return p, err
	}
	p.Interlaced = !frameMBsOnly
	if !frameMBsOnly {
		if _, err = r.u(1); err != nil { // mb_adaptive_frame_field_flag
			return p, err
		}
	}
	if _, err = r.u(1); err != nil { // direct_8x8_inference_flag
		return p, err
	}

	width := int(widthMBs+1) * 16
	height := int(heightMapUnits+1) * 16
	if !frameMBsOnly {
		height *= 2
	}

	// 裁剪窗口。★ 这一步很容易被漏掉，漏了的典型症状是
	//   1080p 被报成 1088（因为 1080 不是 16 的整数倍，编码时补到了 1088）。
	cropping, err := r.flag()
	if err != nil {
		return p, err
	}
	if cropping {
		left, err := r.ue()
		if err != nil {
			return p, err
		}
		right, err := r.ue()
		if err != nil {
			return p, err
		}
		top, err := r.ue()
		if err != nil {
			return p, err
		}
		bottom, err := r.ue()
		if err != nil {
			return p, err
		}
		subW, subH := 2, 2
		switch chromaFormat {
		case 0: // 单色
			subW, subH = 1, 1
		case 3: // 4:4:4
			subW, subH = 1, 1
		case 2: // 4:2:2
			subH = 1
		}
		if frameMBsOnly {
			height -= int(top+bottom) * subH
		} else {
			height -= int(top+bottom) * subH * 2
		}
		width -= int(left+right) * subW
	}
	p.Width, p.Height = width, height

	// VUI 里可能有帧率。没有也不影响主要结论，所以解失败就算了。
	if vui, err := r.flag(); err == nil && vui {
		p.FPS = h264FPS(r)
	}
	if p.Width <= 0 || p.Height <= 0 {
		return p, fmt.Errorf("解出的分辨率不合理：%dx%d", p.Width, p.Height)
	}
	return p, nil
}

// knownH264Profile 报告 profile_idc 是不是标准里定义过的。
// 列表取自 H.264 标准附录 A 与各扩展。
func knownH264Profile(p uint32) bool {
	switch p {
	case 66, 77, 88, // Baseline / Main / Extended
		100, 110, 122, 244, // High / High10 / High422 / High444Predictive
		44,     // CAVLC444
		83, 86, // Scalable Baseline / High
		118, 128, // Multiview High / Stereo High
		138, 139, 134, 135: // MFC / 深度类扩展
		return true
	}
	return false
}

// h264FPS 从 VUI 里取帧率。取不到返回 0 —— 取不到不是错误，很多流本来就没写。
func h264FPS(r *bitReader) float64 {
	if ar, err := r.flag(); err != nil {
		return 0
	} else if ar {
		idc, err := r.u(8)
		if err != nil {
			return 0
		}
		if idc == 255 { // Extended_SAR
			if _, err = r.u(16); err != nil {
				return 0
			}
			if _, err = r.u(16); err != nil {
				return 0
			}
		}
	}
	if f, err := r.flag(); err != nil {
		return 0
	} else if f {
		if _, err = r.u(1); err != nil {
			return 0
		}
	}
	if f, err := r.flag(); err != nil {
		return 0
	} else if f {
		if _, err = r.u(3); err != nil { // video_format
			return 0
		}
		if _, err = r.u(1); err != nil { // video_full_range_flag
			return 0
		}
		if c, err := r.flag(); err != nil {
			return 0
		} else if c {
			if _, err = r.u(24); err != nil {
				return 0
			}
		}
	}
	if f, err := r.flag(); err != nil { // chroma_loc_info_present_flag
		return 0
	} else if f {
		if _, err = r.ue(); err != nil {
			return 0
		}
		if _, err = r.ue(); err != nil {
			return 0
		}
	}
	timing, err := r.flag()
	if err != nil || !timing {
		return 0
	}
	numUnits, err := r.u(32)
	if err != nil || numUnits == 0 {
		return 0
	}
	timeScale, err := r.u(32)
	if err != nil {
		return 0
	}
	return float64(timeScale) / (2 * float64(numUnits))
}
