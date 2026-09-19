package media

import "fmt"

// ParseH265SPS 解 H.265（HEVC）的 SPS。
//
// ★ 为什么非做不可：某施工现场的相机出的就是 2K，而 2K 摄像机现在普遍用 H.265。
// 只支持 H.264 等于在最需要它的场合用不上。
//
// nal 是去掉起始码之后的 NAL 单元（含 2 字节 NAL 头）。
func ParseH265SPS(nal []byte) (Params, error) {
	p := Params{Codec: "h265"}
	if len(nal) < 4 {
		return p, errShort
	}
	// H.265 的 NAL 头是 2 字节，类型在第一字节的 bit1-6
	if t := (nal[0] >> 1) & 0x3f; t != 33 {
		return p, fmt.Errorf("不是 SPS（NAL 类型 %d，H.265 的 SPS 应当是 33）", t)
	}
	r := newBitReader(nal[2:])

	if _, err := r.u(4); err != nil { // sps_video_parameter_set_id
		return p, err
	}
	maxSubLayersMinus1, err := r.u(3)
	if err != nil {
		return p, err
	}
	if _, err := r.u(1); err != nil { // sps_temporal_id_nesting_flag
		return p, err
	}
	if err := skipPTL(r, int(maxSubLayersMinus1)); err != nil {
		return p, err
	}
	if _, err := r.ue(); err != nil { // sps_seq_parameter_set_id
		return p, err
	}
	chromaFormat, err := r.ue()
	if err != nil {
		return p, err
	}
	if chromaFormat == 3 {
		if _, err := r.u(1); err != nil { // separate_colour_plane_flag
			return p, err
		}
	}
	w, err := r.ue()
	if err != nil {
		return p, err
	}
	h, err := r.ue()
	if err != nil {
		return p, err
	}
	width, height := int(w), int(h)

	// 一致性裁剪窗口。和 H.264 那边同一个道理：不减的话 1080 会被报成 1088。
	if crop, err := r.flag(); err != nil {
		return p, err
	} else if crop {
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
		case 0, 3:
			subW, subH = 1, 1
		case 2:
			subH = 1
		}
		width -= int(left+right) * subW
		height -= int(top+bottom) * subH
	}
	p.Width, p.Height = width, height

	if _, err := r.ue(); err != nil { // bit_depth_luma_minus8
		return p, err
	}
	if _, err := r.ue(); err != nil { // bit_depth_chroma_minus8
		return p, err
	}

	if p.Width <= 0 || p.Height <= 0 {
		return p, fmt.Errorf("解出的分辨率不合理：%dx%d", p.Width, p.Height)
	}
	return p, nil
}

// skipPTL 跳过 profile_tier_level 结构。
//
// ★ 这一段是 H.265 解析里最容易出错的地方：长度取决于子层数量，
// 而且中间那 43 位保留字段必须按位跳过，不能想当然地按字节走。
// 跳错一位，后面解出来的宽高就是一个看着挺合理的错数。
func skipPTL(r *bitReader, maxSubLayersMinus1 int) error {
	// general_profile_space(2) tier(1) profile_idc(5)
	if _, err := r.u(8); err != nil {
		return err
	}
	// general_profile_compatibility_flag[32]
	if _, err := r.u(32); err != nil {
		return err
	}
	// progressive/interlaced/non_packed/frame_only(4) + 43 位保留 + 1 位
	if _, err := r.u(4); err != nil {
		return err
	}
	for i := 0; i < 43; i++ {
		if _, err := r.u(1); err != nil {
			return err
		}
	}
	if _, err := r.u(1); err != nil {
		return err
	}
	// general_level_idc
	if _, err := r.u(8); err != nil {
		return err
	}

	profilePresent := make([]bool, maxSubLayersMinus1)
	levelPresent := make([]bool, maxSubLayersMinus1)
	for i := 0; i < maxSubLayersMinus1; i++ {
		pp, err := r.flag()
		if err != nil {
			return err
		}
		lp, err := r.flag()
		if err != nil {
			return err
		}
		profilePresent[i], levelPresent[i] = pp, lp
	}
	if maxSubLayersMinus1 > 0 {
		for i := maxSubLayersMinus1; i < 8; i++ {
			if _, err := r.u(2); err != nil { // reserved_zero_2bits
				return err
			}
		}
	}
	for i := 0; i < maxSubLayersMinus1; i++ {
		if profilePresent[i] {
			if _, err := r.u(8); err != nil {
				return err
			}
			if _, err := r.u(32); err != nil {
				return err
			}
			if _, err := r.u(4); err != nil {
				return err
			}
			for j := 0; j < 43; j++ {
				if _, err := r.u(1); err != nil {
					return err
				}
			}
			if _, err := r.u(1); err != nil {
				return err
			}
		}
		if levelPresent[i] {
			if _, err := r.u(8); err != nil {
				return err
			}
		}
	}
	return nil
}
