package media

// HLS 播放列表（RFC 8216）的解析。★ 这一路问的不是「设备打算发什么」，
// 而是「平台那份清单此刻到底还写着什么」：
//
//	RTSP 那一路量的是码流到没到本机；HLS 中间隔着一层平台 —— 盒子说没画面，
//	有一种毛病是清单还在、里面的分片已经不再往前加了。
//
// ★ 只解「播得起来吗、卡没卡」用得上的那几项。各家平台自加的 #EXT-X- 前缀
//
//	千奇百怪，认不出的照实留个标签名，不猜它的意思。
//
// ★★ 属性值一律不进结果：#EXT-X-KEY:URI="…?token=…" 这种标签里就带着取键口令，
//
//	认不出来时只留标签名，值留在原地。

import (
	"errors"
	"strconv"
	"strings"
)

// HLSVariant 主清单里的一路（带宽 / 分辨率不同的同一内容）。
type HLSVariant struct {
	URI              string  `json:"uri"`
	Bandwidth        int     `json:"bandwidth,omitempty"`
	AverageBandwidth int     `json:"averageBandwidth,omitempty"`
	Resolution       string  `json:"resolution,omitempty"`
	Codecs           string  `json:"codecs,omitempty"`
	FrameRate        float64 `json:"frameRate,omitempty"`
}

// HLSSegment 媒体清单里的一个分片。
type HLSSegment struct {
	URI      string  `json:"uri"`
	Duration float64 `json:"duration"`
	Seq      int     `json:"seq"`
	// ByteRange 非空 = 这个「分片」其实是同一个文件里的一段。
	// 单独按 URI 去取会取回整个文件，码率与「分片可达」都会算错。
	ByteRange string `json:"byteRange,omitempty"`
	// Discontinuity 这一片前面标了 DISCONTINUITY（时间戳不连续，多半是源断过又接上）。
	Discontinuity bool `json:"discontinuity,omitempty"`
}

// HLSPlaylist 一份播放列表。
type HLSPlaylist struct {
	IsMaster bool
	Variants []HLSVariant

	Segments        []HLSSegment
	TargetDuration  float64 // #EXT-X-TARGETDURATION，没给就是 0
	MediaSequence   int     // 第一个分片的序号
	EndList         bool    // 有 ENDLIST = 点播/这段已经录完，不是直播
	MapURI          string  // fMP4 那一路的初始化段
	Version         int
	Discontinuities int
	UnknownTags     []string
}

// ErrNotM3U8 回来的不是 HLS 清单。
var ErrNotM3U8 = errors.New("回来的不是 HLS 清单（没有 #EXTM3U 那一行）")

// ParseM3U8 解一份播放列表。
//
// ★ 容错按「对岸是不可控的服务端」设：BOM、CRLF、#EXTINF 后面跟的标题、
//
//	属性里带逗号的引号段，都得咽得下 —— 解不开就等于把一路好好的流判成坏的。
func ParseM3U8(text string) (HLSPlaylist, error) {
	var p HLSPlaylist
	text = strings.TrimPrefix(text, "\ufeff")
	lines := strings.Split(text, "\n")

	var (
		dur        float64
		hasDur     bool
		discont    bool
		byterange  string
		pendingVar *HLSVariant // 刚读了 STREAM-INF，下一行不是标签就是它的地址
	)
	seen := map[string]bool{}

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			// 数据行：变体地址或分片地址
			if pendingVar != nil {
				v := *pendingVar
				v.URI = line
				p.Variants = append(p.Variants, v)
				p.IsMaster = true
				pendingVar = nil
				continue
			}
			if hasDur {
				p.Segments = append(p.Segments, HLSSegment{
					URI: line, Duration: dur, Seq: p.MediaSequence + len(p.Segments),
					ByteRange: byterange, Discontinuity: discont,
				})
				dur, hasDur, discont, byterange = 0, false, false, ""
				continue
			}
			// 没有 #EXTINF 兜着的数据行：不猜它是什么
			continue
		}
		tag, attrs, _ := strings.Cut(strings.TrimPrefix(line, "#"), ":")
		switch tag {
		case "EXTM3U":
			seen["EXTM3U"] = true
		case "EXT-X-STREAM-INF":
			var v HLSVariant
			for _, kv := range splitAttrList(attrs) {
				k, val, ok := strings.Cut(kv, "=")
				if !ok {
					continue
				}
				val = strings.Trim(val, `"`)
				switch strings.ToUpper(strings.TrimSpace(k)) {
				case "BANDWIDTH":
					v.Bandwidth, _ = strconv.Atoi(val)
				case "AVERAGE-BANDWIDTH":
					v.AverageBandwidth, _ = strconv.Atoi(val)
				case "RESOLUTION":
					v.Resolution = val
				case "CODECS":
					v.Codecs = val
				case "FRAME-RATE":
					v.FrameRate, _ = strconv.ParseFloat(val, 64)
				}
			}
			// 地址在下一行，先带着属性等它
			pendingVar = &v
		case "EXT-X-TARGETDURATION":
			p.TargetDuration, _ = strconv.ParseFloat(strings.TrimSpace(attrs), 64)
		case "EXT-X-MEDIA-SEQUENCE":
			n, err := strconv.Atoi(strings.TrimSpace(attrs))
			if err == nil {
				p.MediaSequence = n
			}
		case "EXT-X-VERSION":
			p.Version, _ = strconv.Atoi(strings.TrimSpace(attrs))
		case "EXT-X-ENDLIST":
			p.EndList = true
		case "EXT-X-DISCONTINUITY":
			if !discont {
				p.Discontinuities++
			}
			discont = true
		case "EXT-X-BYTERANGE":
			byterange = strings.TrimSpace(attrs)
		case "EXT-X-MAP":
			for _, kv := range splitAttrList(attrs) {
				if k, val, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "URI") {
					p.MapURI = strings.Trim(val, `"`)
				}
			}
		case "EXTINF":
			// #EXTINF:6.000000,标题 —— 标题里可能有中文名，逗号要按第一个切
			head, _, _ := strings.Cut(attrs, ",")
			dur, _ = strconv.ParseFloat(strings.TrimSpace(head), 64)
			hasDur = true
		default:
			name := tag
			if !strings.HasPrefix(name, "EXT") {
				name = "EXT-" + name // 注释行（# 开头不带标签）不记成标签
			}
			if !seen[name] {
				seen[name] = true
				p.UnknownTags = append(p.UnknownTags, name)
			}
		}
	}
	if !seen["EXTM3U"] {
		return p, ErrNotM3U8
	}
	return p, nil
}

// WindowSeconds 这份清单盖住多少秒的直播窗口（分片时长累加）。
func (p HLSPlaylist) WindowSeconds() float64 {
	var t float64
	for _, s := range p.Segments {
		t += s.Duration
	}
	return t
}

// LastSegment 窗口里最后一片（推进没推进就看它换没换）。
func (p HLSPlaylist) LastSegment() (HLSSegment, bool) {
	if len(p.Segments) == 0 {
		return HLSSegment{}, false
	}
	return p.Segments[len(p.Segments)-1], true
}

// Advanced 比较两次拉到的清单，答「窗口在往前挪吗」。
//
// ★ 三种「挪了」都算：最后一片换了、序号跳了、片数变了 —— 只看其中一种都会漏。
//
//	片数不变的窗口最常见（服务器每 6 秒换一片，窗口一直是 6 片）；
//	而「刚起流那阵子窗口在长」恰恰是片数变了、最后一片还没换。
//	两边都没片时答不了 —— 空清单对空清单不算「动了」。
func Advanced(prev, cur HLSPlaylist) bool {
	a, ok1 := prev.LastSegment()
	b, ok2 := cur.LastSegment()
	if !ok1 || !ok2 {
		return false
	}
	if a.URI != b.URI || a.Seq != b.Seq {
		return true
	}
	return len(prev.Segments) != len(cur.Segments)
}

// splitAttrList 按逗号切属性表，引号里的逗号不算。
// 不切的症状：CODECS="avc1.64001F,mp4a.40.2" 会被切成两半，带宽那一路整个读丢。
func splitAttrList(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
