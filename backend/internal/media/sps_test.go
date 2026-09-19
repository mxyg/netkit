package media

import (
	"encoding/base64"
	"testing"
)

// ★ 这些是**真实设备**的 SPS，不是编出来的。
// 自己造的数据只能证明代码自洽，证明不了它认得真东西。
// 这些向量由 x264 / x265 在已知分辨率下真实编码生成（2026-09-19，见 testdata 说明），
// 不是手写的。★ 生成用的 ffmpeg 只是**开发机上的工具**，产品从不分发它
// —— 见 docs/设计.md「流探测自研方案」。
func TestParseH264SPS真实码流(t *testing.T) {
	cases := []struct {
		name string
		b64  string
		w, h int
	}{
		// ★ 1080p 专门盯「1088 陷阱」：1080 不是 16 的整数倍，编码时补到 1088，
		//   不减裁剪窗口就会报成 1088。
		{"1080p", "Z/QAKJGbKA8ARPxOAiAAAAMAIAAABkHjBjLA", 1920, 1080},
		{"720p", "Z/QAH5GbKAoAt2AiAAADAAIAAAMAZB4wYyw=", 1280, 720},
		{"704x576（D1 一类的老设备）", "Z/QAHpGbKBYCTYCIAAADAAgAAAMBkHixbLA=", 704, 576},
		// 2K —— 某施工现场那类相机的分辨率，这一路的关键数
		{"1440p", "Z/QAMpGbKAUAFrYCIAAAAwAgAAAGQeMGMsA=", 2560, 1440},
		{"2160p", "Z/QAM5GbKAeACH2AiAAAAwAIAAADAZB4wYyw", 3840, 2160},
		// 360 同样不是 16 的整数倍（补到 368），再钉一次裁剪
		{"640x360", "Z/QAHpGbKBQF/xOAiAAAAwAIAAADAZB4sWyw", 640, 360},
	}
	for _, c := range cases {
		nal, err := base64.StdEncoding.DecodeString(c.b64)
		if err != nil {
			t.Fatalf("%s: base64 解不开：%v", c.name, err)
		}
		p, err := ParseH264SPS(nal)
		if err != nil {
			t.Errorf("%s: 解析失败：%v", c.name, err)
			continue
		}
		if p.Width != c.w || p.Height != c.h {
			t.Errorf("%s: 解出 %dx%d，实际是 %dx%d", c.name, p.Width, p.Height, c.w, c.h)
		}
		if p.Codec != "h264" {
			t.Errorf("%s: codec = %q", c.name, p.Codec)
		}
	}
}

// ★ 1088 陷阱单独钉一条：这个错会让「盒子帧池按 1080p 建」这类问题
// 的排查结论差之毫厘 —— 而那次现场排查要的就是这个数准不准。
func Test不许把1080报成1088(t *testing.T) {
	nal, _ := base64.StdEncoding.DecodeString("Z/QAKJGbKA8ARPxOAiAAAAMAIAAABkHjBjLA")
	p, err := ParseH264SPS(nal)
	if err != nil {
		t.Fatal(err)
	}
	if p.Height == 1088 {
		t.Fatal("报成了 1088 —— 裁剪窗口没减。1080 不是 16 的整数倍，编码时补到 1088，" +
			"不减裁剪窗口就会多出 8 行")
	}
	if p.Height != 1080 {
		t.Fatalf("高 = %d", p.Height)
	}
}

func TestParseH265SPS(t *testing.T) {
	cases := []struct {
		name string
		b64  string
		w, h int
	}{
		{"1080p", "QgEBBAgAAAMAnggAAAMAAHiQAHgQAhyyys0kmV4C3AgIABAAAAMAEAAAAwGQgA==", 1920, 1080},
		{"1440p", "QgEBBAgAAAMAnggAAAMAAJaQACgEALQssrNJJleAtwICAAQAAAMABAAAAwBkIA==", 2560, 1440},
		{"720p", "QgEBBAgAAAMAnggAAAMAAF2QAFAQBaLLKzSSZXgLcCAgAEAAAAMAQAAABkI=", 1280, 720},
		{"2160p", "QgEBBAgAAAMAnggAAAMAAJaQADwEAEOLLKzSSZXgLcCAgAEAAAMAAQAAAwAZCA==", 3840, 2160},
	}
	for _, c := range cases {
		nal, err := base64.StdEncoding.DecodeString(c.b64)
		if err != nil {
			t.Fatalf("%s: base64：%v", c.name, err)
		}
		p, err := ParseH265SPS(nal)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if p.Width != c.w || p.Height != c.h {
			t.Errorf("%s: 解出 %dx%d，实际 %dx%d", c.name, p.Width, p.Height, c.w, c.h)
		}
	}
}

// ★ 防竞争字节（00 00 03）必须在解析前去掉。
// 不去掉的症状是**大多数流看着正常、偏偏某些分辨率算错**，最难查的那一类。
func Test去掉防竞争字节(t *testing.T) {
	r := newBitReader([]byte{0x00, 0x00, 0x03, 0x01, 0xff})
	got := make([]byte, 0, 4)
	for i := 0; i < 4; i++ {
		v, err := r.u(8)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, byte(v))
	}
	want := []byte{0x00, 0x00, 0x01, 0xff}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("去防竞争字节后 = % x，想要 % x", got, want)
		}
	}
}

func Test坏码流要报错不要编个数出来(t *testing.T) {
	for _, bad := range [][]byte{
		{},
		{0x67},
		{0x68, 0xce, 0x3c, 0x80},             // 是 PPS 不是 SPS
		{0x67, 0xff, 0xff, 0xff, 0xff, 0xff}, // 乱码
	} {
		if p, err := ParseH264SPS(bad); err == nil {
			t.Errorf("% x 本该报错，却解出了 %dx%d —— "+
				"编一个看着合理的错分辨率，比直接报错坏得多", bad, p.Width, p.Height)
		}
	}
}
