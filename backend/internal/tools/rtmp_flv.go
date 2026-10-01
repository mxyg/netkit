package tools

// HTTP-FLV 探测（media.rtmp.probe 的 flv:// 分支）。
//
// ★ 现场抄下来的「这一路的 flv 地址」是 SRS / nginx-rtmp / ZLMediaKit 那几家的
//
//	HTTP-FLV 约定：写成 flv://主机[:口]/应用/流名，取的时候就是对该主机对该路径发一次
//	HTTP GET（不写口默认 80）。这一支问的是**容器这一层**：这条 HTTP 通道给回来的
//	字节到底是不是 FLV、里面有没有视频、只有音频没有画面、还是头是好的可一帧都没有。
//	上面那层 RTMP（推流到没到服务器）是 rtmp.go 那一支问的，两层各有各的答法，
//	谁也不替谁 —— 所以判定码另起一套 flv- 前缀，不复用 rtmp-。
//
// ★★ 两处最容易被后来人「抹平」的地方，这里钉死：
//
//	① 404 ≠ 不是 FLV。平台回 404 说的是「这一路名字在我这儿没有」，下一步是回去核流名；
//	   「不是 FLV」说的是「给了 200 可里面那堆字节不是 FLV 容器」，下一步是查取流协议配错了。
//	   合并成一档就把两条不同的下一步支到同一个方向去了。
//	② 读满预算而停 ≠ 错误。直播流永远读不到头，ProbeFLV 到字节/标签/时间预算就收口，
//	   返回的是「到目前为止这一路有什么」的那一份账 —— 那是**正常答案**，不是故障。
//	   把 window/bytecap/tagcap 当错误报，等于每天对着一条好流喊「出问题了」。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"net.yuhox.com/netkit/internal/media"
	"net.yuhox.com/netkit/internal/ots"
)

// HTTP-FLV 探测的判定码。
//
// ★ 每一档落下去的下一步不一样，这才是分档唯一的理由：
//
//	flv-ok              容器里有视频：这一路有画面（顺手把分辨率/关键帧/码种种种记进账）
//	flv-audio-only      容器里只有音频没有视频 —— 现场那句「打开了但没画面」的答案就是这一档
//	flv-no-media        给了 200，可这一路一帧都没有（头是好的没标签，或压根一个字节没来）
//	flv-not-flv         给了 200，可那堆字节根本不是 FLV（带「它像什么」的证据）
//	flv-http-status     回的不是 200：404 这一路没有 / 403·401 要凭据 / 30x 被重定向（状态码留在账上）
//	flv-unreachable     HTTP 通道就没搭起来：DNS 解析不出 / 端口拒绝 / 没有路由
//	flv-timeout         端口连上了，可回话（响应头）到点没来
//	flv-tag-broken      FLV 标签声称的长度与到手的对不上，断在标签里（partial 账照样留）
//	flv-stream-dropped  读到一半连接被断（不是预算到点，是通道自己坏了；断之前的账留着）
const (
	verdictFLVOk        = "flv-ok"
	verdictFLVAudioOnly = "flv-audio-only"
	verdictFLVNoMedia   = "flv-no-media"
	verdictFLVNotFLV    = "flv-not-flv"
	verdictFLVStatus    = "flv-http-status"
	verdictFLVUnreach   = "flv-unreachable"
	verdictFLVTimeout   = "flv-timeout"
	verdictFLVTagBroken = "flv-tag-broken"
	verdictFLVDropped   = "flv-stream-dropped"
)

// maxBytes 的边界。★ 都是能塞进 int32 的量（1<<22、16<<20），不留裸的大常量：
// 这一版要过 windows/386，历史上被「没类型的大常量」崩过两次。
const (
	flvMaxBytesMin  = 1 << 16        // 64 KiB：再小连一个视频序列头都可能装不下，问不出东西
	flvMaxBytesMax  = 16 << 20       // 16 MiB：一次探测的封顶，再大就是拿别人的服务器下载整段录像
	flvMaxBytesDef  = int64(8 << 20) // 默认按 media 那侧的窗口（8 MiB）
	flvPortDefault  = 80             // flv:// 不写口就是 HTTP 的 80（SRS/nginx-rtmp 约定）
	flvMetadataKeys = 24             // 元数据最多摊开几格：再多多半是把码流灌进了脚本标签
)

// flvArgs 是这一支用到的参数。用现成的 rtmpArgs（同一次 Invoke 的参数），
// 这里只是给取个名字，免得读代码时以为另有一套入参。
type flvArgs = rtmpArgs

// probeHTTPFLV 是 media.rtmp.probe 收到 flv:// 地址时走的那一支。
// 返回 (判定, nil) —— 「连上了可它给的不是流」这类落点都是**查出来的状态**，
// 是判定不是错误；只有参数非法才回 error。[OTS-6.2]
func probeHTTPFLV(ctx context.Context, a flvArgs, u *url.URL) (any, error) {
	// 一步的超时（连接 + 等响应头）：与 RTMP 那一支同口径，越界挡在门外不静默夹。
	signal := time.Duration(a.TimeoutMS) * time.Millisecond
	if a.TimeoutMS != 0 && (a.TimeoutMS < 500 || a.TimeoutMS > 60000) {
		return nil, ots.Errf(ots.ErrInvalidArgument, "一步的超时只能填 500 到 60000 毫秒，给的是 %d", a.TimeoutMS)
	}
	if signal <= 0 {
		signal = 5 * time.Second
	}
	watch := time.Duration(a.WatchMS) * time.Millisecond
	if a.WatchMS != 0 && (a.WatchMS < 500 || a.WatchMS > 15000) {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"观测窗口只能填 500 到 15000 毫秒，给的是 %d（不填按 3000）", a.WatchMS)
	}
	if watch <= 0 {
		watch = 3 * time.Second
	}
	lim := media.FLVLimits{MaxBody: flvMaxBytesDef, MaxTags: media.FLVDefaultMaxTags}
	if a.MaxBytes != 0 {
		if a.MaxBytes < flvMaxBytesMin || a.MaxBytes > flvMaxBytesMax {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"读取上限只能填 %d 到 %d 字节，给的是 %d", flvMaxBytesMin, flvMaxBytesMax, a.MaxBytes)
		}
		lim.MaxBody = int64(a.MaxBytes)
	}

	port := flvPort(u)
	values := map[string]any{
		// ★ 进结果的只有打了码那一份：口令只在线路上下一次去，不落这一张账。
		"url":       redactURL(u),
		"host":      u.Hostname(),
		"port":      port,
		"protocol":  "flv",
		"transport": "http",
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	values["path"] = path

	// 拨出去的那份：scheme 换成 http，原样带上 path 与 query（?key=… 是平台校验要的，
	// 拆掉就等于把凭据丢了 —— 与 RTMP 那支「参数只上线路」同一条规矩）。
	hu := &url.URL{Scheme: "http", Host: net.JoinHostPort(u.Hostname(), strconv.Itoa(port)), Path: path}
	// query 里有口令类参数也不改：照样发过去，只是不进 values。
	hu.RawQuery = u.RawQuery
	var user, pass string
	if u.User != nil { // HTTP 有 Basic 这一说：口令只进 Authorization 头，不进 URL 那份账
		user = u.User.Username()
		pass, _ = u.User.Password()
		hu.User = nil
		values["hasUserinfo"] = true
	}

	// 预算：响应头那一步到点就断，之后按观测窗口给 ProbeFLV 收口；外层再留一次总兜底。
	ctx, cancel := context.WithTimeout(ctx, signal+watch+2*signal)
	defer cancel()

	client := &http.Client{Transport: flvTransport(signal)}
	// ★ 不跟跳转：302 是「被重定向」这一档要照实报的东西，跟着跳就把落点换到了别的机器上，
	//   而界面那句下一步得指着「此刻它把这一路领去了哪儿」。
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hu.String(), nil)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "这一问的地址拼不出来：%s", err)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	// 有些平台按 Accept 决定给不给这段裸流；顺手报一句我们要 FLV。
	req.Header.Set("Accept", "video/x-flv, application/octet-stream, */*")

	resp, err := client.Do(req)
	if err != nil {
		code, note := flvClassifyNet(err)
		values["detail"] = maskSecretText(err.Error())
		if reach := classify(unwrapNet(err)); reach != "" {
			values["reach"] = reach
		}
		return ots.Verdict{Code: code, Values: values, Note: note}, nil
	}
	defer closeResp(resp)
	values["httpStatus"] = resp.StatusCode
	if ct := resp.Header.Get("content-type"); ct != "" {
		values["contentType"] = ct
	}
	if cl := resp.Header.Get("content-length"); cl != "" {
		values["contentLength"] = cl
	}
	// ★ 报「最后落在哪儿」，也报跳没跳过：跳转的落点决定这一问到底问的是哪台机器。
	if loc := resp.Header.Get("location"); loc != "" {
		values["redirectLocation"] = redactString(loc)
	}

	// 非 200：这一支先按「平台对这一路说了什么」收口，不去碰那半截正文。
	// ★★ 404 绝不落到「不是 FLV」那一档 —— 见文件头那条钉死。
	if resp.StatusCode != http.StatusOK {
		values["httpStatus"] = resp.StatusCode
		return ots.Verdict{Code: verdictFLVStatus, Values: values,
			Note: flvStatusNote(resp.StatusCode, redactURL(u))}, nil
	}

	// 200：把正文喂给容器走查。窗口收口 = 直播流的正常答案（见文件头②）。
	lim.Deadline = time.Now().Add(watch)
	rep, perr := media.ProbeFLV(resp.Body, lim)
	seen := rep
	if seen != nil {
		flvFillValues(values, seen)
	}
	if perr == nil {
		// 读满预算而停（bytecap/tagcap/window）与读到末尾（ended）都是好答案，不是故障。
		code, note := flvFromReport(values, seen, redactURL(u))
		return ots.Verdict{Code: code, Values: values, Note: note}, nil
	}

	var fe *media.FLVError
	if !errors.As(perr, &fe) {
		values["detail"] = maskSecretText(perr.Error())
		return ots.Verdict{Code: ots.CodeUnknown, Values: values,
			Note: "这一问的落点我们没有一个对应判定，把已经问到的照实给出"}, nil
	}
	values["stage"] = fe.Stage
	values["detail"] = maskSecretText(fe.Error())
	if fe.Seen != nil && seen == nil {
		flvFillValues(values, fe.Seen)
	}

	switch fe.Kind {
	case media.FLVKindNotFLV:
		// 200 可那堆字节不是 FLV：带「它像什么」的证据，让人一眼看出这条 HTTP 通道上挂着的是别的。
		if len(fe.Head) > 0 {
			values["looksLike"] = flvLooksLike(fe.Head)
		}
		return ots.Verdict{Code: verdictFLVNotFLV, Values: values,
			Note: "回 200，可里面不是 FLV 容器" + flvLooksNote(values["looksLike"]) +
				" —— 这个地址多半配的是网页、mp4 或另一路协议"}, nil
	case media.FLVKindHeader:
		// 头都读不成：要么一个字节都没来（200 空正文），要么来了点东西却凑不齐 FLV 头。
		if len(fe.Head) == 0 {
			values["emptyBody"] = true
			return ots.Verdict{Code: verdictFLVNoMedia, Values: values,
				Note: "给了 200，可这一路一个字节都没来 —— 平台答应给流，此刻却没画面可给"}, nil
		}
		values["looksLike"] = flvLooksLike(fe.Head)
		return ots.Verdict{Code: verdictFLVNotFLV, Values: values,
			Note: "给了 200，可连 9 字节的 FLV 头都凑不齐" + flvLooksNote(values["looksLike"])}, nil
	case media.FLVKindTag:
		// 断在标签里：声称的长度与到手的对不上。★ partial 的账（上面已填）照留 ——
		// 问到一半断了，问到的那一段照样是证据。
		return ots.Verdict{Code: verdictFLVTagBroken, Values: values,
			Note: "FLV 标签声称的长度与到手的对不上，断在标签里 —— 断之前" + flvSeenNote(values)}, nil
	case media.FLVKindIO:
		if flvIsTimeout(perr) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// 读通道到点没回话：与「预算读满收口」不同，这是网络那一侧卡住了。
			return ots.Verdict{Code: verdictFLVTimeout, Values: values,
				Note: "连上了，可这段流到点没继续给过来 —— 网络或那一侧卡住了"}, nil
		}
		return ots.Verdict{Code: verdictFLVDropped, Values: values,
			Note: "读到一半它把连接断了 —— 断之前" + flvSeenNote(values)}, nil
	}
	return ots.Verdict{Code: ots.CodeUnknown, Values: values,
		Note: maskSecretText(fe.Error())}, nil
}

// flvTransport 造一个探测用的传输层：族别明确的连接超时 + 响应头超时 + 关压缩。
//
// ★ DisableCompression 不能省：让 net/http 自动加 Accept-Encoding 并透明解压，
//
//	会把这段本该原样交给容器走查的 FLV 字节给 gunzip 歪 —— 判成「不是 FLV」就成了假案。
//	★ ResponseHeaderTimeout 把「连上却不让 first byte 落地」和「连上了开始给流」分开：
//	前者是通道坏了（flv-timeout），后者进了容器走查。拨号超时用 dialer 的 Timeout。
func flvTransport(signal time.Duration) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableCompression = true
	tr.ResponseHeaderTimeout = signal
	d := &net.Dialer{Timeout: signal}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	return tr
}

// flvPort 与 rtmpPort 同一手法：显式写了就用、合法才认，否则这一族默认 80。
func flvPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 && n < 65536 {
			return n
		}
		return flvPortDefault
	}
	return flvPortDefault
}

// flvFillValues 把一份 FLV 走查的账摊进结果。成功与「断在流里」共用这一份，
// 好让「容器里到底有什么」和「断之前问到了什么」出自同一个填法，不分叉。
func flvFillValues(values map[string]any, rep *media.FLVReport) {
	if rep == nil {
		return
	}
	values["tags"] = rep.Tags
	values["videoTags"] = rep.VideoTags
	values["audioTags"] = rep.AudioTags
	values["scriptTags"] = rep.ScriptTags
	values["bodyBytes"] = rep.BodyBytes
	values["hasVideo"] = rep.HasVideo
	values["hasAudio"] = rep.HasAudio
	values["keyframes"] = rep.Keyframes
	values["hasKeyframe"] = rep.HasKeyframe
	if rep.StopReason != "" {
		values["stopReason"] = rep.StopReason
	}
	if rep.MediaTSSeen {
		values["firstMediaTS"] = rep.FirstMediaTS
		values["lastMediaTS"] = rep.LastMediaTS
	}
	if rep.HasKeyframe {
		values["firstKeyTS"] = rep.FirstKeyTS
	}
	if len(rep.AudioFormats) > 0 {
		values["audioFormats"] = rep.AudioFormats
	}
	if len(rep.VideoFormats) > 0 {
		values["videoFormats"] = rep.VideoFormats
	}
	if rep.MultiTrack {
		values["multiTrack"] = true
	}
	// ★ PrevTagSizeBad 非零不等于流坏了：直播平台上这一项很常见。只记账，不改判定。
	if rep.PrevTagSizeBad > 0 {
		values["prevTagSizeBad"] = rep.PrevTagSizeBad
	}
	if rep.ScriptTooBig > 0 {
		values["scriptTooBig"] = rep.ScriptTooBig
	}
	if rep.HeaderErrors != nil {
		values["headerErrors"] = rep.HeaderErrors
	}
	if rep.AAC != nil {
		if rep.AAC.SampleRateHz > 0 {
			values["audioSampleRateHz"] = rep.AAC.SampleRateHz
		}
		if rep.AAC.Channels > 0 {
			values["audioChannels"] = rep.AAC.Channels
		}
	}
	if v := rep.Video; v != nil {
		if v.Codec != "" {
			values["videoCodec"] = v.Codec
		}
		if v.Width > 0 && v.Height > 0 {
			values["width"] = v.Width
			values["height"] = v.Height
		}
		if v.ParamsNote != "" {
			values["videoParamsNote"] = v.ParamsNote
		}
	}
	if rep.Metadata != nil {
		values["metadataSeen"] = true
		// ★ 元数据整段先过一遍码再进结果：脚本标签里也可能挂着 key/token 这类东西。
		if m := flvScrubMetadata(rep.Metadata); len(m) > 0 {
			values["metadata"] = m
		}
	}
	// 码率按「真读了多少字节」给个粗算：容器层的参考数，不是推流端声明的那一份。
	if rep.BodyBytes > 0 {
		values["flvBytes"] = rep.BodyBytes
	}
}

// flvScrubMetadata 只摊开标量、口令类键打码、控制字符清掉、格数封顶。
//
// ★★ 元数据进结果是硬规矩之外的例外口子：onMetaData 里各家写过 vhost、streamName
//
//	这种带租户/密钥的东西。宁可少看一格，也不能把口令抄进会发给 AI、打进诊断包的账上。
func flvScrubMetadata(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	n := 0
	for k, v := range m {
		if n >= flvMetadataKeys {
			out["…"] = "元数据条目过多，只摊开了前面的"
			break
		}
		n++
		if isSecretParam(k) {
			out[k] = "***"
			continue
		}
		switch x := v.(type) {
		case float64:
			out[k] = x
		case int:
			out[k] = x
		case bool:
			out[k] = x
		case string:
			out[k] = maskSecretText(x)
		default:
			// 嵌套对象/数组不进结果：这一格给的是「有哪些数」，不是把整棵结构树搬回来。
			out[k] = fmt.Sprintf("(%T)", v)
		}
	}
	return out
}

// flvFromReport 从一份读满预算/读到末尾的账落判定。★ 先后顺序即分档理由：
// 有视频是「有画面」，只有音频是那句「打开了但没画面」，两者都没有才是「一帧都没给」。
func flvFromReport(values map[string]any, rep *media.FLVReport, redacted string) (string, string) {
	switch {
	case rep == nil:
		return verdictFLVNoMedia, "给了 200，可这一路什么都没读出来"
	case rep.HasVideo:
		return verdictFLVOk, flvOKNote(values)
	case rep.HasAudio:
		return verdictFLVAudioOnly, "这一路只有音频没有视频 —— 现场那句「打开了但没画面」说的就是这个"
	default:
		return verdictFLVNoMedia, "头是好的 FLV，可一个音视频标签都没有：平台答应给流，这一路一帧都没到"
	}
}

func flvOKNote(values map[string]any) string {
	s := "容器里有视频：" + strconv.FormatInt(intOr(values["videoTags"]), 10) + " 个视频标签"
	if w, ok := values["width"].(int); ok {
		if h, ok2 := values["height"].(int); ok2 && w > 0 && h > 0 {
			s += fmt.Sprintf("，声明分辨率 %d×%d", w, h)
		}
	}
	if c, ok := values["videoCodec"].(string); ok && c != "" {
		s += "，编码 " + c
	}
	return s
}

// flvStatusNote 状态码的下一步各不相同 —— 所以把状态数留在账上，note 说清指向。
func flvStatusNote(status int, redacted string) string {
	switch {
	case status == http.StatusNotFound || status == http.StatusGone:
		return "这个地址上没有这一路（HTTP " + strconv.Itoa(status) + "）—— 应用名或流名多半写错了，去核一遍"
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		return "要凭据才给这段流（HTTP " + strconv.Itoa(status) + "）—— 这一路要 key/sign 或账号，补齐再问"
	case status >= 300 && status < 400:
		return "被重定向了（HTTP " + strconv.Itoa(status) + "）—— 这一路此刻被领去了别处，去向见 redirectLocation"
	case status == http.StatusTooManyRequests:
		return "取流的口子被限流了（HTTP 429）—— 不是这一路坏了，是这一刻问得太多"
	case status >= 500:
		return "那一侧自己出错了（HTTP " + strconv.Itoa(status) + "）—— 不是地址不对，是平台/源站此刻给不出"
	default:
		return "回的不是 200（HTTP " + strconv.Itoa(status) + "）—— " + redacted
	}
}

// flvLooksLike 「那一段像什么」—— 复用本包既有的 headSignature，只补它没盖到的两种常见形态。
//
// ★ 不另起一套识别器：网页 / mp4 / flv 那几种 headSignature 已经认了；
//
//	这一层只加「JSON 错误体」和「RTMP 裸握手」这两种现场常见、而 headSignature 会滑进
//	那句 sha 摘要的形态 —— 认出它们是 JSON，下一步就是去看平台回的错误消息；
//	认出是 RTMP 握手，下一步就是这条地址其实该走 rtmp://。★ 只回分类，不回原始字节：
//	那截字节里可能整段抄着口令，把它原样塞进结果就破了「凭据不进结果」那条。
func flvLooksLike(head []byte) string {
	i := 0
	for i < len(head) && (head[i] == ' ' || head[i] == '\t' || head[i] == '\n' || head[i] == '\r') {
		i++
	}
	if i < len(head) && (head[i] == '{' || head[i] == '[') {
		return "json" // 平台回的错误体：不是网页也不是流
	}
	if len(head) > 0 && head[0] == 0x03 {
		return "rtmp-handshake" // 0x03 起手一大段：这条地址多半该走 rtmp://
	}
	return headSignature(head)
}

// flvLooksNote 「那一段看着像什么」那一小句。
func flvLooksNote(looks any) string {
	if s, ok := looks.(string); ok && s != "" {
		return "（那一段看着像 " + s + "）"
	}
	return ""
}

// flvSeenNote 断之前问到的那一点东西 —— 判定与它的账必须同源。
func flvSeenNote(values map[string]any) string {
	tags := intOr(values["tags"])
	body := intOr(values["bodyBytes"])
	switch {
	case tags > 0 && body > 0:
		return "已经数到 " + strconv.FormatInt(tags, 10) + " 个标签、" + strconv.FormatInt(body, 10) + " 字节"
	case tags > 0:
		return "已经数到 " + strconv.FormatInt(tags, 10) + " 个标签"
	default:
		return "什么都没问到"
	}
}

func intOr(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

// flvClassifyNet 把一次请求没问到状态码的错分成「连不上 / 超时」。
// ★ closed（机器在、这个口没服务）与 filtered（一句都不答）在 values 里靠 reach 分开，
//
//	码这里先并成一档 —— 两者的下一步都是「先确认这台/这个口在不在」，方向一致。
func flvClassifyNet(err error) (string, string) {
	if flvIsTimeout(err) || errors.Is(err, context.Canceled) {
		return verdictFLVTimeout, "端口连上了，可回话到点没来 —— 多半是中间有东西放着半开的连接"
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return verdictFLVUnreach, de.Name + " 解析不到地址 —— 还没到连接那一步"
	}
	if c := classify(unwrapNet(err)); c != "" {
		switch c {
		case verdictClosed:
			return verdictFLVUnreach, "这个口没人应答（明确拒绝）—— 这台机器在，可这个口上没有 HTTP-FLV 服务"
		case verdictFiltered:
			return verdictFLVUnreach, "这个口一句都不答 —— 分不清是关着还是被静默丢了"
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// 连上了却连一句 HTTP 响应都没给就断：通道没搭起来，归到连不上这一档。
		return verdictFLVUnreach, "连上了，可它一句 HTTP 响应都没给就把连接断了"
	}
	return verdictFLVUnreach, "连不上：" + maskSecretText(err.Error())
}

// unwrapNet http.Client 把底层错误包在 *url.Error 里，classify 要的是最外面那个网络错。
func unwrapNet(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// flvIsTimeout 认「到点没回话」这一类错：context 超时、以及 net.Error 自己说超时。
// 与 http.go/classify 同一手法 —— 按类型判，不靠错误文本里的中文。
func flvIsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
