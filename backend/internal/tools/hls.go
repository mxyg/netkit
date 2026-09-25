package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/media"
	"net.yuhox.com/netkit/internal/ots"
)

// HLS 探测的判定码。
//
// ★ 每一档的下一步动作都不一样，这才是分档的理由：
//
//	hls-ok               清单能拉、分片能取、直播窗口在往前挪 —— 这一路是活的
//	hls-stalled          清单还在，可两次拉下来窗口一片没换 —— 源头没在往前推
//	hls-segment-missing  清单点出来的分片取不到 —— 平台与源站之间对不上号
//	hls-empty-playlist   清单是空的 —— 推流还没上来（刚点开播、或已经掉线）
//	hls-target-over      分片实测比清单承诺的还长 —— 能播，但播放器会反复缓冲
//	hls-auth-required    要账号才给清单
//	hls-not-found        这个路径上没有这路（应用名 / 流名写错）
//	hls-not-hls          回的不是 m3u8 —— 多半是裸流、网页或别的协议
//	hls-unreachable      连都连不上
//	hls-timeout          连上了，问一句到点没回话
const (
	verdictHLSOK         = "hls-ok"
	verdictHLSStalled    = "hls-stalled"
	verdictHLSSegMiss    = "hls-segment-missing"
	verdictHLSEmpty      = "hls-empty-playlist"
	verdictHLSTargetOver = "hls-target-over"
	verdictHLSAuth       = "hls-auth-required"
	verdictHLSNotFound   = "hls-not-found"
	verdictHLSNotHLS     = "hls-not-hls"
	verdictHLSUnreach    = "hls-unreachable"
	verdictHLSTimeout    = "hls-timeout"
)

var hlsProbeTool = ots.Tool{
	Name:  "media.hls.probe",
	Class: ots.ClassRead,
	Summary: "拉一遍一路 HLS（m3u8）：分清「清单有没有」「分片取不取得到」" +
		"「直播窗口在不在往前挪」，并估一个实际码率。\n" +
		"★ 现场那句「平台说这路没画面」，中间隔着一层平台 —— RTSP 那一路量的是码流到没到本机，" +
		"这一路问的是平台这份清单此刻还写着什么。最有价值的一档是 stalled：" +
		"清单在、地址对、也不报错，可连着两次拉的窗口一片没换 —— 那说明源头早就没在往前推了，" +
		"和「这一路从来没推上来」是两回事。\n" +
		"主清单（多路）会替调用方挑最高码率那一路再问一次，各路本身也列出来。\n" +
		"只读：不改任何配置，也不下载整段录像（抽查的分片最多读 4 MiB）。地址里的口令不进结果。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["url"],
	  "properties": {
	    "url": {"type": "string", "description": "m3u8 地址，如 http://192.168.1.20:80/hls/cam1/index.m3u8 。口令可以写在地址里，也可以用下面两个字段分开给"},
	    "username": {"type": "string", "description": "Basic 认证的用户名。地址里已经带了就不用填"},
	    "password": {"type": "string", "description": "Basic 认证的口令。地址里已经带了就不用填"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 60000, "description": "一次请求的超时毫秒数，默认 5000"},
	    "watchMs": {"type": "integer", "minimum": 0, "maximum": 30000, "description": "隔多久再拉一次清单，用来判窗口有没有往前挪，默认 4000。填 0 只拉一次、不说卡没卡（对着点播或不想多等的时候用）"},
	    "sampleSegments": {"type": "integer", "minimum": 0, "maximum": 5, "description": "抽查几片分片，默认 2：数最少的一片、中间的一片和最新那一片。填 0 只问清单、不取分片"}
	  }
	}`),
	Invoke: probeHLS,
}

type hlsArgs struct {
	URL       string `json:"url"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
	WatchMS   *int   `json:"watchMs,omitempty"`
	Sample    *int   `json:"sampleSegments,omitempty"`
}

// 一次清单最多读这么多：一个 30 天的录像清单也不至于超，
// 超了多半是有人把 mp4 挂在了 .m3u8 上 —— 那本来就该判成「这不是清单」。
const playlistCap = 2 << 20

// 抽查一片最多读这么多。★ 读满就停手并如实标「没读完」：
// 一片没读完的字节数算不出码率，硬算会给出一个偏低的假数。
const segmentCap = 4 << 20

func probeHLS(ctx context.Context, raw json.RawMessage) (any, error) {
	var a hlsArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	u, err := normalizeM3U8URL(a.URL)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	user, pass := a.Username, a.Password
	if u.User != nil {
		if user == "" {
			user = u.User.Username()
		}
		if pass == "" {
			pass, _ = u.User.Password()
		}
	}
	// ★ 拨出去的那一份不带凭据：口令只进 Authorization 头，不进结果、不进日志
	u.User = nil

	signal := time.Duration(a.TimeoutMS) * time.Millisecond
	if signal <= 0 {
		signal = 5 * time.Second
	}
	watch := hlsWatchWindow(a.WatchMS)
	sample := 2
	if a.Sample != nil {
		sample = *a.Sample
		if sample < 0 || sample > 5 {
			return nil, ots.Errf(ots.ErrInvalidArgument, "抽查几片只能填 0 到 5")
		}
	}
	// 整体预算：拉清单 + 等窗口 + 再拉一次 + 抽查这几片，各留一次超时
	total := signal*3 + watch + time.Duration(sample+1)*signal + time.Second
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	values := map[string]any{"url": redactURL(u)}
	client := &http.Client{Timeout: signal}

	first, resp, status, sig, err := fetchM3U8(ctx, client, u, user, pass)
	defer closeResp(resp)
	values["httpStatus"] = status
	if resp != nil {
		values["contentType"] = resp.Header.Get("content-type")
		// ★ 报的是「最后落在哪儿」，不是「跳没跳过」：跳板落在哪个主机上决定了
		//   这一问到底问的是哪台机器（CDN、平台内网、还是它自己）。
		if final := resp.Request.URL; final != nil {
			if s := redactURL(final); s != redactURL(u) {
				values["finalURL"] = s
			}
		}
	}
	switch {
	case err != nil:
		code, note := hlsClassify(err)
		values["detail"] = err.Error()
		// ★ closed（机器在、这个口没服务）和 filtered（一句都不答）下一步完全不同，
		//   合并成「连不上」就等于让人去查一个根本没挡着的防火墙 —— 码合并，证据留着。
		if reach := classify(err); reach != "" {
			values["reach"] = reach
		}
		if sig != "" {
			values["looksLike"] = sig
		}
		return ots.Verdict{Code: code, Values: values, Note: note}, nil
	case status == 401 || status == 403:
		return ots.Verdict{Code: verdictHLSAuth, Values: values,
			Note: "要账号才给这份清单 —— " + redactURL(u)}, nil
	case status == 404 || status == 410:
		return ots.Verdict{Code: verdictHLSNotFound, Values: values,
			Note: "这个路径上没有清单（" + strconv.Itoa(status) + "）—— 应用名或流名多半写错了"}, nil
	case status >= 300:
		return ots.Verdict{Code: verdictHLSNotHLS, Values: values,
			Note: "回来的不是清单（HTTP " + strconv.Itoa(status) + "）"}, nil
	}

	pend := first
	// ★ base 是「后面这些相对地址该拼到谁身上」。默认就是给的那个地址，
	//   可一旦顺着主清单下到某一路，分片和第二次拉清单都得跟着那一路走 ——
	//   拼错了指向的是另一码率的那组文件，取 404 会算到源站头上。
	base := u
	// 主清单：各路都列出来，再替调用方挑最高码率那一路往下问
	if pend.IsMaster {
		if len(pend.Variants) == 0 {
			return ots.Verdict{Code: verdictHLSEmpty, Values: values,
				Note: "这是一份主清单，可里面一路都没列 —— 平台上这路上头是空的"}, nil
		}
		values["master"] = true
		values["variants"] = hlsVariants(pend.Variants)
		best := pickVariant(pend.Variants)
		vu, uerr := u.Parse(best.URI)
		if uerr != nil {
			values["detail"] = uerr.Error()
			return ots.Verdict{Code: verdictHLSNotHLS, Values: values,
				Note: "主清单里那一路的地址拼不出来"}, nil
		}
		pv, resp2, st2, sig2, err2 := fetchM3U8(ctx, client, vu, user, pass)
		defer closeResp(resp2)
		values["variant"] = redactURL(vu)
		values["variantHTTPStatus"] = st2
		if len(best.Resolution) > 0 {
			values["variantResolution"] = best.Resolution
		}
		switch {
		case err2 != nil:
			code, note := hlsClassify(err2)
			values["detail"] = err2.Error()
			if sig2 != "" {
				values["looksLike"] = sig2
			}
			return ots.Verdict{Code: code, Values: values, Note: note}, nil
		case st2 == 401 || st2 == 403:
			return ots.Verdict{Code: verdictHLSAuth, Values: values, Note: "挑出来那一路要账号"}, nil
		case st2 >= 300:
			return ots.Verdict{Code: verdictHLSNotHLS, Values: values,
				Note: "主清单是好的，挑出来那一路回 " + strconv.Itoa(st2)}, nil
		}
		pend = pv
		base = vu
	}

	values["isLive"] = !pend.EndList
	values["segmentCount"] = len(pend.Segments)
	values["mediaSequence"] = pend.MediaSequence
	if pend.TargetDuration > 0 {
		values["targetDurationSec"] = pend.TargetDuration
	}
	if pend.MapURI != "" {
		values["hasInitSegment"] = true
	}
	if len(pend.UnknownTags) > 0 {
		values["unknownTags"] = pend.UnknownTags
	}
	if pend.Discontinuities > 0 {
		values["discontinuities"] = pend.Discontinuities
	}
	if w := pend.WindowSeconds(); w > 0 {
		values["windowSec"] = round1(w)
	}
	if len(pend.Segments) == 0 {
		return ots.Verdict{Code: verdictHLSEmpty, Values: values,
			Note: "清单拉到了，里面一片分片都没有 —— 这路还没推上来（或刚刚掉线）"}, nil
	}

	// 抽查分片
	if sample > 0 {
		picks := pickSegments(pend.Segments, sample)
		rows := make([]map[string]any, 0, len(picks))
		var bytesSum, durSum float64
		var measured, oversize int
		for _, idx := range picks {
			seg := pend.Segments[idx]
			su, uerr := base.Parse(seg.URI)
			if uerr != nil {
				rows = append(rows, map[string]any{"uri": redactString(seg.URI), "error": "地址拼不出来"})
				continue
			}
			row := fetchSegment(ctx, client, su, seg, user, pass)
			row["uri"] = redactURL(su)
			rows = append(rows, row)
		}
		// ★ fMP4 那一路的初始化段：它 404 了，媒体片全都是解不开的废字节 ——
		//   清单看着没毛病、分片也都在，播放器偏偏起不来，而这一片清单里根本不列。
		if pend.MapURI != "" {
			row := map[string]any{"uri": redactString(pend.MapURI), "initSegment": true}
			if mu, merr := base.Parse(pend.MapURI); merr != nil {
				row["error"] = "地址拼不出来"
			} else {
				row = fetchSegment(ctx, client, mu, media.HLSSegment{URI: pend.MapURI}, user, pass)
				row["uri"] = redactURL(mu)
				row["initSegment"] = true
			}
			rows = append(rows, row)
		}
		values["sampled"] = rows
		// 码率只算「整片读完」的那些媒体片：
		// 初始化段没有时长可对，读满上限的那片是半截的 —— 硬算会给出一个偏低的假码率。
		// 「读到了但没读完」本身就是证据（源上这片比承诺的大得多），单独记一项。
		for _, row := range rows {
			if ok, _ := row["ok"].(bool); !ok {
				continue
			}
			if init, _ := row["initSegment"].(bool); init {
				continue
			}
			if truncated, _ := row["truncated"].(bool); truncated {
				oversize++
				continue
			}
			n, _ := row["bytes"].(int64)
			dur, _ := row["durationSec"].(float64)
			if n > 0 && dur > 0 {
				bytesSum += float64(n)
				durSum += dur
				measured++
			}
		}
		if measured > 0 {
			kbps := bytesSum * 8 / 1000 / durSum
			values["bitrateKbps"] = int(kbps)
			values["bitrateBasis"] = fmt.Sprintf("%d 片实测字节 ÷ 它们的标称时长", measured)
		}
		if oversize > 0 {
			values["bitrateSkipped"] = fmt.Sprintf("另有 %d 片读满了单次读取上限 %s，字节数不完整，没算进码率",
				oversize, humanBytes(segmentCap))
		}
		if bad := firstBadSegment(rows); bad != nil {
			// ★ 「哪一片」单独一项，而不是把整行塞进 detail：detail 这一格在别处
			//   写的是原文错误，界面按一句文本来读，给它一个对象就渲染成一坨。
			values["missingSegment"] = bad["uri"]
			return ots.Verdict{Code: verdictHLSSegMiss, Values: values,
				Note: "清单点出来的分片取不到：" + whyBad(bad)}, nil
		}
	}

	// 窗口在不在往前挪
	if watch > 0 && !pend.EndList {
		select {
		case <-ctx.Done():
		case <-time.After(watch):
		}
		again, resp3, st3, _, err3 := fetchM3U8(ctx, client, base, user, pass)
		defer closeResp(resp3)
		if err3 == nil && st3 < 300 {
			advanced := media.Advanced(pend, again)
			values["watchedMs"] = int(watch / time.Millisecond)
			values["windowAdvanced"] = advanced
			if last, ok := again.LastSegment(); ok {
				values["lastSegmentNow"] = redactString(last.URI)
			}
			if !advanced {
				if last, ok := pend.LastSegment(); ok {
					values["stuckOn"] = redactString(last.URI)
				}
				return ots.Verdict{Code: verdictHLSStalled, Values: values,
					Note: "清单还在，可这么久而是一片没往前加 —— 源头没在往前推（不是这一问问不到，是它真的没动）"}, nil
			}
		}
	}

	// 分片比清单承诺的长：能播，但播放器会反复缓冲
	if pend.TargetDuration > 0 {
		var mx float64
		var mxURI string
		for _, s := range pend.Segments {
			if s.Duration > mx {
				mx, mxURI = s.Duration, s.URI
			}
		}
		if mx > pend.TargetDuration*1.05 {
			values["longestSegmentSec"] = round1(mx)
			values["longestSegment"] = redactString(mxURI)
			return ots.Verdict{Code: verdictHLSTargetOver, Values: values,
				Note: fmt.Sprintf("清单写着每片最长 %.0f 秒，实际有一片 %.1f 秒 —— 播放器会在这里反复缓冲",
					pend.TargetDuration, mx)}, nil
		}
	}

	return ots.Verdict{Code: verdictHLSOK, Values: values,
		Note: hlsOKNote(pend, values)}, nil
}

// hlsWatchWindow 要不要再拉一次清单。★ 指针：没填（默认看 4 秒）
// 和特意填 0（点播、不想多等）是两回事。
func hlsWatchWindow(p *int) time.Duration {
	if p == nil {
		return 4 * time.Second
	}
	return time.Duration(*p) * time.Millisecond
}

func normalizeM3U8URL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("没给地址")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + strings.TrimPrefix(s, "/")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("看不懂地址 %q：%s", redactString(s), err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("只支持 http/https 的 m3u8，给的是 %q。RTSP 用 media.rtsp.probe，RTMP 用 media.rtmp.probe", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("地址里没有主机名：%q", redactString(s))
	}
	return u, nil
}

// fetchM3U8 拉一份清单。返回的 resp 即使有错也可能非空（调用方要关，也要从里面读状态码）。
// sig 只在「回 2xx 但内容不是清单」时非空：那是「它到底回了什么」的一句话形状。
func fetchM3U8(ctx context.Context, client *http.Client, u *url.URL, user, pass string) (media.HLSPlaylist, *http.Response, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return media.HLSPlaylist{}, nil, 0, "", err
	}
	// 有些平台按 Accept 决定给不给这份清单；顺手把口令只放进头里，不进 URL
	req.Header.Set("Accept", "application/vnd.apple.mpegurl, application/x-mpegURL, */*")
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return media.HLSPlaylist{}, nil, 0, "", err
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, playlistCap))
	if rerr != nil {
		return media.HLSPlaylist{}, resp, resp.StatusCode, "", rerr
	}
	// 状态码非 2xx 时不解析：401 那份 HTML 登录页里也可能有 "#EXTM3U" 字样
	if resp.StatusCode >= 300 {
		return media.HLSPlaylist{}, resp, resp.StatusCode, "", nil
	}
	p, perr := media.ParseM3U8(string(body))
	if perr != nil {
		// 把「它到底回了什么」留下：头几个字节够认出是网页、FLV 还是别的裸流
		return media.HLSPlaylist{}, resp, resp.StatusCode, headSignature(body), perr
	}
	return p, resp, resp.StatusCode, "", nil
}

// headSignature 头几个字节的样子 —— 认得出「这是一段网页 / 一个 FLV / 一个 mp4」，
// 不整段抄进结果（里面可能带着口令）。
func headSignature(b []byte) string {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "FLV"):
		return "flv"
	case strings.Contains(s[:min(len(s), 32)], "ftyp"):
		return "mp4"
	case strings.HasPrefix(strings.TrimSpace(s), "<"):
		return "html"
	}
	sum := sha256.Sum256(b)
	return "非清单，前 32 字节的 SHA-256 前缀 " + hex.EncodeToString(sum[:4])
}

// fetchSegment 取一片，读满 segmentCap 就停手。
func fetchSegment(ctx context.Context, client *http.Client, u *url.URL, seg media.HLSSegment, user, pass string) map[string]any {
	row := map[string]any{"seq": seg.Seq, "durationSec": seg.Duration}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		row["error"] = err.Error()
		return row
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	// ★ 带 BYTERANGE 的「分片」其实是同一个文件里的一段：
	//	不加 Range 去取会把整个文件搬回来，码率会算出一个高得离谱的数。
	//	清单里的写法是 <字节数>@<起始偏移>，而 HTTP 的 Range 要的是首尾两个字节位置 —— 别切错分隔符。
	if seg.ByteRange != "" {
		size, offset := parseByteRange(seg.ByteRange)
		if size > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+size-1))
		}
		row["byteRange"] = seg.ByteRange
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		row["error"] = err.Error()
		return row
	}
	defer resp.Body.Close()
	row["httpStatus"] = resp.StatusCode
	if resp.StatusCode >= 300 {
		row["ok"] = false
		return row
	}
	buf := make([]byte, segmentCap)
	n, rerr := io.ReadFull(resp.Body, buf)
	truncated := rerr == nil // 读满了整个上限 = 后面还有，这片没读完
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		row["error"] = rerr.Error()
		return row
	}
	row["bytes"] = int64(n)
	row["elapsedMs"] = time.Since(started).Milliseconds()
	// ★ 回 200 但一个字节都没有，不算「取到了」：BYTERANGE 指到文件外面、
	//   平台截了个空段、源站磁盘出事 —— 都是播放器起不来的实病，
	//   写成 ok 就等于用一次成功的读数把这一片划掉。
	if n == 0 {
		row["ok"] = false
		row["error"] = "回的是空的（0 字节）"
		return row
	}
	row["ok"] = true
	row["truncated"] = truncated
	return row
}

// parseByteRange 解 #EXT-X-BYTERANGE 那一串：<字节数>[@<起始偏移>]。
// 省略偏移就是从头读起。认不出来时返回 0 —— 调用方退回去整段取，
// 那至少是「慢一点」，而算错偏移是「取回来一段对不上号的东西」。
func parseByteRange(s string) (size, offset int64) {
	nPart, oPart, hasOffset := strings.Cut(s, "@")
	size, err := strconv.ParseInt(strings.TrimSpace(nPart), 10, 64)
	if err != nil || size <= 0 {
		return 0, 0
	}
	if hasOffset {
		offset, _ = strconv.ParseInt(strings.TrimSpace(oPart), 10, 64)
	}
	return size, offset
}

// pickSegments 挑几片去抽查：最新的那一片、最老的那一片、再是中间。
// ★ 顺序不能反：只抽窗口头上那几片会看不出「最新一片还在写、取回来是半截的」，
//
//	而头上前那几片已经被平台清掉 —— 播放器正在播的那一段随时会断。
//	抽查只给两片时，必须是「一头一尾」，不是「头两片」。
func pickSegments(segs []media.HLSSegment, n int) []int {
	if n <= 0 || len(segs) == 0 {
		return nil
	}
	cands := []int{len(segs) - 1, 0, len(segs) / 2}
	seen := map[int]bool{}
	var out []int
	for _, i := range cands {
		if !seen[i] && len(out) < n {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}

// pickVariant 主清单里挑一路：带宽最大的，没写带宽就按分辨率高的。
// 平手时取列在前的那份 —— 平台自己排的顺序通常就是它建议的顺序。
func pickVariant(vs []media.HLSVariant) media.HLSVariant {
	best := vs[0]
	for _, v := range vs[1:] {
		if v.Bandwidth > best.Bandwidth {
			best = v
		}
	}
	return best
}

func firstBadSegment(rows []map[string]any) map[string]any {
	for _, r := range rows {
		if ok, _ := r["ok"].(bool); ok {
			continue
		}
		if _, has := r["httpStatus"]; has {
			return r
		}
		if e, _ := r["error"].(string); e != "" {
			return r
		}
	}
	return nil
}

func whyBad(bad map[string]any) string {
	// ★ 只有状态码本身是错的时候才拿它当原因：回 200 却一片正文都没有，
	//   说「回 HTTP 200」是把真正的毛病（空）盖掉。
	if st, has := bad["httpStatus"]; has && anyInt(st) >= 300 {
		switch anyInt(st) {
		case 404:
			return "回 404（清单还点着它，源上已经没有这一片了）"
		case 403:
			return "回 403（分片要另外的凭据或签名）"
		}
		return "回 HTTP " + strconv.Itoa(int(anyInt(st)))
	}
	if e, _ := bad["error"].(string); e != "" {
		return e
	}
	return "没取到"
}

func anyInt(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	}
	return 0
}

// hlsVariants 把多路清单摊开给人看（带宽、分辨率、编码），不带凭据。
func hlsVariants(vs []media.HLSVariant) []map[string]any {
	out := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		row := map[string]any{"uri": redactString(v.URI)}
		if v.Bandwidth > 0 {
			row["bandwidth"] = v.Bandwidth
		}
		if v.Resolution != "" {
			row["resolution"] = v.Resolution
		}
		if v.Codecs != "" {
			row["codecs"] = v.Codecs
		}
		if v.FrameRate > 0 {
			row["frameRate"] = v.FrameRate
		}
		out = append(out, row)
	}
	return out
}

// hlsOKNote 那一句「好」只能按**这一次真的问了什么**来写。
//
// ★★ 抽查填 0 就一片分片都没碰，观看窗口填 0 就没看过第二遍 ——
// 把没问过的东西写进那句账里，等于替调用方排除了两个他其实还没排除的可能。
func hlsOKNote(p media.HLSPlaylist, v map[string]any) string {
	sampled, _ := v["sampled"].([]map[string]any)
	what := "清单是好的"
	if len(sampled) > 0 {
		what = "清单与抽到的分片都是好的"
	}
	if adv, has := v["windowAdvanced"].(bool); has && adv {
		what += "，窗口也在往前挪"
	}
	if p.EndList {
		return what + "（这是一段录完的点播）"
	}
	return what
}

// hlsClassify 把一次请求的错分成「连不上 / 超时 / 回的不是 HTTP」。
func hlsClassify(err error) (string, string) {
	if errors.Is(err, media.ErrNotM3U8) {
		return verdictHLSNotHLS, "回来的不是 HLS 清单 —— 这个地址多半是网页、裸流（FLV/MP4）或别的协议"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return verdictHLSTimeout, "问了一句到点没回话"
	}
	if code, note := classifyHTTP(err); code != "" {
		switch code {
		case httpTimeout:
			return verdictHLSTimeout, note
		case httpWrongScheme, httpTLSFailed,
			verdictUnreachable, tlsNameUnresolved, verdictClosed, verdictFiltered:
			// ★ 前两种是「这一问根本没问到」：连一次完整的 HTTP 对话都没成。
			//   前缀写反的那种改一下就好（改完再问，它可能就在「有流」和「要账号」之间挪一格），
			//   TLS 被拒的那一种要去「网站与证书」那页问证书。两种都不归这路流的毛病。
			return verdictHLSUnreach, note
		default:
			// httpNotHTTP：它答话了，答的却不是 HTTP —— 对着 RTSP 端口问 m3u8 就是这个落点。
			// 这仍是「回来的不是清单」，和「我们认不出它说的 HLS」（同一个码，看 note 分）一路。
			return verdictHLSNotHLS, note
		}
	}
	return verdictHLSUnreach, err.Error()
}

func closeResp(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}
