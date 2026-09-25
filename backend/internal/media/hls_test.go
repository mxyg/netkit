package media

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 一份现场常见的直播清单：窗口六片、序号从 4310 起、每片六秒。
const liveM3U8 = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:4310
#EXTINF:6.000000,
seg-4310.ts
#EXTINF:6.000000,
seg-4311.ts
#EXTINF:5.986000,
seg-4312.ts
#EXTINF:6.000000,
seg-4313.ts
#EXTINF:6.000000,
seg-4314.ts
#EXTINF:6.000000,
seg-4315.ts
`

func Test媒体清单读出窗口最后一片与序号(t *testing.T) {
	p, err := ParseM3U8(liveM3U8)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsMaster {
		t.Errorf("一份分片清单被判成了主清单")
	}
	if len(p.Segments) != 6 {
		t.Fatalf("分片数 %d，要 6", len(p.Segments))
	}
	if p.TargetDuration != 6 {
		t.Errorf("TARGETDURATION 读成 %v", p.TargetDuration)
	}
	if got := p.WindowSeconds(); got < 35.9 || got > 36.1 {
		t.Errorf("窗口算成 %.2f 秒", got)
	}
	last, ok := p.LastSegment()
	// ★ 号要从 MEDIA-SEQUENCE 起算，不是从 0：那句「窗口在往前挪」靠的就是这个号。
	if !ok || last.Seq != 4315 || last.URI != "seg-4315.ts" {
		t.Errorf("最后一片读成 %+v", last)
	}
	if p.EndList {
		t.Errorf("没有 ENDLIST 却被判成录完了")
	}
}

func Test主清单认得出多路并且带逗号的编码表不切开(t *testing.T) {
	text := `#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=4000000,AVERAGE-BANDWIDTH=3800000,RESOLUTION=1920x1080,FRAME-RATE=25.000,CODECS="avc1.640028,mp4a.40.2"
1080.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=1200000,RESOLUTION=704x576,CODECS="avc1.64001f"
d1.m3u8
`
	p, err := ParseM3U8(text)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsMaster {
		t.Fatalf("主清单没认出来")
	}
	if len(p.Variants) != 2 {
		t.Fatalf("几路读成 %d", len(p.Variants))
	}
	v := p.Variants[0]
	if v.URI != "1080.m3u8" || v.Bandwidth != 4000000 || v.Resolution != "1920x1080" || v.FrameRate != 25 {
		t.Errorf("第一路读成 %+v", v)
	}
	// CODECS 里那个逗号在引号内：切开的话带宽那一路整行都会读歪
	if v.Codecs != "avc1.640028,mp4a.40.2" {
		t.Errorf("编码表被切开了：%q", v.Codecs)
	}
	if p.Variants[1].AverageBandwidth != 0 {
		t.Errorf("没给的 AVERAGE-BANDWIDTH 凭空造了一个数")
	}
	if len(p.Segments) != 0 {
		t.Errorf("主清单里不该数出分片")
	}
}

func Test看不懂的标签只留名字不漏属性值(t *testing.T) {
	text := `#EXTM3U
#EXT-X-TARGETDURATION:6
#EXT-X-KEY:METHOD=AES-128,URI="http://10.0.0.9/getkey?token=abc123secret"
#EXT-X-WHATEVER-PRIVATE:foo=bar
#EXTINF:6.0,
a.ts
`
	p, err := ParseM3U8(text)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.UnknownTags, ",")
	if !strings.Contains(joined, "EXT-X-KEY") || !strings.Contains(joined, "EXT-X-WHATEVER-PRIVATE") {
		t.Errorf("认不出的标签没留下名字：%q", joined)
	}
	// ★ 取键地址里就带着口令：这份结构体会被塞进结果发给 AI，值一个字都不许跟着走
	blob, _ := json.Marshal(p)
	for _, leak := range []string{"abc123secret", "10.0.0.9", "foo=bar"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("属性值漏进了结果：%s", leak)
		}
	}
	if len(p.Segments) != 1 {
		t.Errorf("带 KEY 标签的分片被咽掉了：%+v", p.Segments)
	}
}

func Test带BYTERANGE的那一片不许当成能单独取(t *testing.T) {
	text := `#EXTM3U
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
#EXT-X-BYTERANGE:512000@0
big.mp4
#EXTINF:10.0,
#EXT-X-BYTERANGE:512000@512000
big.mp4
`
	p, err := ParseM3U8(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Segments) != 2 {
		t.Fatalf("两片读成 %d", len(p.Segments))
	}
	for i, s := range p.Segments {
		if s.ByteRange == "" {
			t.Errorf("第 %d 片丢了 BYTERANGE —— 照着 URI 去取会把整个文件搬回来", i)
		}
	}
}

func Test两次清单比出窗口有没有往前挪(t *testing.T) {
	prev, _ := ParseM3U8(liveM3U8)

	// 窗口片数不变、只是换了一片 —— 这是最常见的直播形态，只看片数会判成没动
	rotated := strings.Replace(liveM3U8, "MEDIA-SEQUENCE:4310", "MEDIA-SEQUENCE:4311", 1)
	rotated = strings.Replace(rotated, "seg-4310.ts", "seg-4316.ts", 1)
	moved, err := ParseM3U8(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if !Advanced(prev, moved) {
		t.Errorf("窗口明明换了一片，却说没动")
	}
	if Advanced(prev, prev) {
		t.Errorf("两次一模一样，却说动了 —— 那句「卡住了」就是这么漏掉的")
	}

	// 片数变了（刚起流时窗口在长）
	short := liveM3U8[:strings.Index(liveM3U8, "seg-4314.ts")]
	grew, err := ParseM3U8(short)
	if err != nil {
		t.Fatal(err)
	}
	if !Advanced(grew, prev) {
		t.Errorf("窗口从 4 片长到 6 片，却说没动")
	}
	// 一次都没拉到过分片时不下结论
	empty, _ := ParseM3U8("#EXTM3U\n#EXT-X-TARGETDURATION:6\n")
	if Advanced(empty, prev) || Advanced(prev, empty) {
		t.Errorf("有一边一片都没有，「动没动」这一问问不出来，不该硬答")
	}
}

func Test没有EXTM3U的不算清单(t *testing.T) {
	for _, body := range []string{
		"<html><body>设备网页</body></html>",
		"",
		"#EXTINF:6.0,\nseg.ts\n",
	} {
		if _, err := ParseM3U8(body); !errors.Is(err, ErrNotM3U8) {
			t.Errorf("这份不是清单却过了：%q", body)
		}
	}
}

func Test容错_CRLF_BOM_与带标题的EXTINF(t *testing.T) {
	text := "\ufeff" + strings.ReplaceAll(`#EXTM3U
#EXT-X-TARGETDURATION:6
#EXTINF:6.000000,第 3 路 主码流
中文名字.ts
`, "\n", "\r\n")
	p, err := ParseM3U8(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Segments) != 1 || p.Segments[0].URI != "中文名字.ts" {
		t.Fatalf("分片读成 %+v", p.Segments)
	}
	if p.Segments[0].Duration != 6 {
		t.Errorf("带标题的 EXTINF 时长读成 %v", p.Segments[0].Duration)
	}
}

func Test断点计数落在它后面那一片上(t *testing.T) {
	text := `#EXTM3U
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:1
#EXTINF:6.0,
a.ts
#EXT-X-DISCONTINUITY
#EXTINF:6.0,
b.ts
#EXTINF:6.0,
c.ts
`
	p, err := ParseM3U8(text)
	if err != nil {
		t.Fatal(err)
	}
	if p.Discontinuities != 1 {
		t.Errorf("断点数成 %d，要 1", p.Discontinuities)
	}
	if !p.Segments[1].Discontinuity || p.Segments[0].Discontinuity || p.Segments[2].Discontinuity {
		t.Errorf("断点标错了片：%+v", p.Segments)
	}
}

func Test有ENDLIST的是录完的那一段(t *testing.T) {
	p, err := ParseM3U8(liveM3U8 + "#EXT-X-ENDLIST\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.EndList {
		t.Errorf("ENDLIST 没认出来 —— 点播被当成「直播卡住了」，那是个假故障")
	}
}

func Test那条fMP4初始化段要留着(t *testing.T) {
	p, err := ParseM3U8(`#EXTM3U
#EXT-X-TARGETDURATION:4
#EXT-X-MAP:URI="init.mp4"
#EXTINF:4.0,
m1.m4s
`)
	if err != nil {
		t.Fatal(err)
	}
	if p.MapURI != "init.mp4" {
		t.Errorf("MAP 段丢了：%+v", p)
	}
}
