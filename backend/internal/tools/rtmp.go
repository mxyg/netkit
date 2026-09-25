package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/media"
	"net.yuhox.com/netkit/internal/ots"
)

// RTMP 探测的判定码。
//
// ★ 一句「推流没到平台」在这条路上要问五步，每一步落下来都是不同的毛病、
//
//	不同的下一步：
//
//	rtmp-ok                    在推 —— 窗口里真收到媒体字节（顺手把码率量出来）
//	rtmp-no-media              服务器说有这路、play 也答应了，可一个媒体字节都没到
//	rtmp-stream-absent         这个名字上根本没有流 —— 流名写错
//	rtmp-stream-not-publishing 名字认得，可此刻没人推 —— 推流端没上来
//	rtmp-app-accepted          应用认了，但这次没问「这路在不在推」
//	rtmp-app-rejected          connect 被拒（应用名不对，或这台只肯收推流）
//	rtmp-auth-required         被拒的理由是缺口令 / key / token
//	rtmp-command-silent        握手通了，命令发出去到点不回话
//	rtmp-not-rtmp              端口开着，回的不是 RTMP（带「它像什么」）
//	rtmp-unreachable           TCP 就没连上（closed 与 filtered 在 reach 里分开）
//	rtmp-timeout               端口能连上，可握手那一句到点没回
//	rtmp-connection-lost       问到一半它把连接断了（断之前问到的都留着）
const (
	verdictRTMPOk            = "rtmp-ok"
	verdictRTMPNoMedia       = "rtmp-no-media"
	verdictRTMPStreamAbsent  = "rtmp-stream-absent"
	verdictRTMPNotPublishing = "rtmp-stream-not-publishing"
	verdictRTMPAppAccepted   = "rtmp-app-accepted"
	verdictRTMPAppRejected   = "rtmp-app-rejected"
	verdictRTMPAuth          = "rtmp-auth-required"
	verdictRTMPCmdSilent     = "rtmp-command-silent"
	verdictRTMPNotRTMP       = "rtmp-not-rtmp"
	verdictRTMPUnreachable   = "rtmp-unreachable"
	verdictRTMPTimeout       = "rtmp-timeout"
	verdictRTMPDropped       = "rtmp-connection-lost"
)

var rtmpProbeTool = ots.Tool{
	Name:  "media.rtmp.probe",
	Class: ots.ClassRead,
	Summary: "问一路 RTMP：把「推流没到平台」拆成连不上、端口开着但不是 RTMP、握手不回、" +
		"应用被拒、要口令、这路名上没有、名字对可此刻没人推、答应给流却一个媒体字节都没到、" +
		"以及在推（顺手量出实际码率与它声明的分辨率）。" +
		"★ 这问的是**推流那一路**（相机/OBS 往平台推、平台之间转推），" +
		"取流看摄像机用 media.rtsp.probe，看平台给出来的清单用 media.hls.probe —— 三问隔的是三层，谁也不替谁。" +
		"只读：只发 connect / createStream / play 三条命令，绝不发 publish / FCPublish / releaseStream / deleteStream，" +
		"不往别人服务器上挂流。口令与 key 只上线路，不进结果。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["url"],
	  "properties": {
	    "url": {"type": "string", "description": "RTMP 地址，如 rtmp://192.168.1.20:1935/live/cam1 。路径第一段是应用名（live），后面的算流名。只想问「这台认不认这个应用」时把流名省掉"},
	    "app": {"type": "string", "description": "应用名。填了就覆盖地址里那一段 —— 地址写法古怪（应用名带参数）时用它分开填"},
	    "stream": {"type": "string", "description": "流名。填了就覆盖地址里那一段。留空且地址里也没有时，这一问只问到「应用认不认」，判定会明说这路在不在推根本没问"},
	    "connectParams": {"type": "object", "additionalProperties": true, "description": "connect 命令里额外的参数，各家服务器自要的：vhost、key、token 这类。★ 这些值只发出去，不进结果、不进日志。app 与 tcUrl 由探测方自己算，填了也不收"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 60000, "description": "一步的超时毫秒数（连接、握手、每条命令各算一次），默认 5000"},
	    "watchMs": {"type": "integer", "minimum": 500, "maximum": 15000, "description": "play 之后收多久的媒体字节，默认 3000。这一段决定「在不在推」问得准不准：给得太短，一秒一两个关键帧的流会被说成没在推"}
	  }
	}`),
	Invoke: probeRTMP,
}

type rtmpArgs struct {
	URL           string         `json:"url"`
	App           string         `json:"app,omitempty"`
	Stream        string         `json:"stream,omitempty"`
	ConnectParams map[string]any `json:"connectParams,omitempty"`
	TimeoutMS     int            `json:"timeoutMs,omitempty"`
	WatchMS       int            `json:"watchMs,omitempty"`
}

func probeRTMP(ctx context.Context, raw json.RawMessage) (any, error) {
	var a rtmpArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	u, err := normalizeRTMPURL(a.URL)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	app, stream, err := rtmpSplitPath(u, a.App, a.Stream)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	// ★ 口令只在这份 local 里：进结果、进日志的一律是 redactURL 那一份
	extra, err := rtmpConnectParams(a.ConnectParams)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	hasUserinfo := u.User != nil // RTMP 没有 HTTP 那种 Basic 认证：写在这儿我们既不改用、也不猜

	signal := time.Duration(a.TimeoutMS) * time.Millisecond
	if a.TimeoutMS != 0 && (a.TimeoutMS < 500 || a.TimeoutMS > 60000) {
		return nil, ots.Errf(ots.ErrInvalidArgument, "一步的超时只能填 500 到 60000 毫秒，给的是 %d", a.TimeoutMS)
	}
	if signal <= 0 {
		signal = 5 * time.Second
	}
	watch := time.Duration(a.WatchMS) * time.Millisecond
	if a.WatchMS != 0 && (a.WatchMS < 500 || a.WatchMS > 15000) {
		// ★ 短于半秒的窗口问不出「在不在推」，却会给出一个 rtmp-no-media ——
		//   那是我们没问到，不是它没在推。这种问法直接挡在门外，不靠 note 里补一句。
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"观测窗口只能填 500 到 15000 毫秒，给的是 %d（不填按 3000）", a.WatchMS)
	}
	if watch <= 0 {
		watch = 3 * time.Second
	}
	// 整体预算：连接 + 握手 + connect + createStream + play + 观测窗口，各留一次超时
	ctx, cancel := context.WithTimeout(ctx, signal*5+watch+time.Second)
	defer cancel()

	values := map[string]any{
		"url":      redactURL(u),
		"host":     u.Hostname(),
		"port":     rtmpPort(u),
		"app":      app,
		"protocol": "rtmp",
	}
	if stream != "" {
		values["stream"] = redactString(stream)
	}
	if hasUserinfo {
		values["ignoredUserinfo"] = true // 口令写错了地方：这一问没带上它
	}
	if u.RawQuery != "" {
		// ?key=… 留在流名上一并发给 play（nginx-rtmp 那一族就这么认）
		stream = rtmpJoinQuery(stream, u.RawQuery)
		values["stream"] = redactString(stream)
		values["streamHasQuery"] = true
	}
	tcURL := redactTCURL(u, app)

	sess, err := media.RTMPDial(ctx, u.Hostname(), rtmpPort(u), signal)
	if err != nil {
		return rtmpFault(values, err), nil
	}
	defer sess.Close()
	values["handshakeMs"] = sess.Handshake.Elapsed.Milliseconds()

	if err := sess.Begin(signal); err != nil {
		return rtmpFault(values, err), nil
	}
	connectCmd, err := sess.Connect(app, tcURL, extra, signal)
	if err != nil {
		// ★ 命令发出去却报错时，已经问到的那一格先留下：握手通了但 connect 被打回，
		//   与端口根本没开是两条不同的路 —— 别把问到的丢掉。
		fillConnectReply(values, connectCmd)
		return rtmpFault(values, err), nil
	}
	fillConnectReply(values, connectCmd)
	if code, note, rejected := rtmpConnectReject(connectCmd); rejected {
		values["statusCodes"] = sess.Stats.StatusCodes
		return ots.Verdict{Code: code, Values: values, Note: note}, nil
	}
	if sess.Stats.PeerChunkSet == 0 {
		values["peerChunkSet"] = false // 这台没宣告过自己的块大小：少见，但真有不发就完蛋的
	}

	if stream == "" {
		// ★ 「没问到」不能写成「问了没问题」：没给流名时这一路在不在推压根没问。
		return ots.Verdict{Code: verdictRTMPAppAccepted, Values: values,
			Note: "应用「" + app + "」认了，可这次没给流名 —— 这路在不在推根本没问。补上流名再问一次"}, nil
	}

	streamID, err := sess.CreateStream(2, signal)
	if err != nil {
		return rtmpFault(values, err), nil
	}
	values["streamID"] = streamID
	if err := sess.Play(stream, 2, signal); err != nil {
		return rtmpFault(values, err), nil
	}

	ob := sess.Observe(watch, func(cm media.RTMPCommand) bool {
		return strings.HasPrefix(cm.Code(), "NetStream.Play.")
	})
	values["watchMs"] = int(watch / time.Millisecond)
	values["observedMs"] = ob.Elapsed.Milliseconds()
	values["mediaBytes"] = ob.MediaBytes
	values["audioBytes"] = ob.AudioBytes
	values["videoBytes"] = ob.VideoBytes
	values["messages"] = ob.Messages
	values["keyFrames"] = ob.Stats.KeyFrames
	if len(ob.Stats.StatusCodes) > 0 {
		values["statusCodes"] = ob.Stats.StatusCodes
	}
	if ob.StatusSeen {
		values["playCode"] = ob.Status.Code()
		if d := maskSecretText(rtmpCommandText(ob.Status)); d != "" {
			values["playDetail"] = d
		}
	}
	fillMetadata(values, ob.Meta)

	// ★ 判定的先后：先看它说了什么，再看字节到没到。
	//   「回包说这路不存在」和「回包说在播可字节没来」是两件事，反过来的话前者会被后者盖掉。
	switch {
	case ob.StatusSeen && strings.Contains(ob.Status.Code(), "StreamNotFound"):
		return ots.Verdict{Code: verdictRTMPStreamAbsent, Values: values,
			Note: "这个名字上没有流（" + ob.Status.Code() + "）—— 流名多半写错了"}, nil
	case ob.StatusSeen && rtmpSaysGone(ob.Status.Code()):
		return ots.Verdict{Code: verdictRTMPNotPublishing, Values: values,
			Note: "服务器认得这一路，可它说此刻没人推（" + ob.Status.Code() + "）—— 去看推流端有没有上来"}, nil
	case ob.Closed != nil && ob.MediaBytes == 0:
		// 断在哪儿算证据：回包都没等到就断，与「说要开始播然后就断了」是两种毛病
		var inner *media.RTMPError
		detail := ob.Closed.Error()
		if errors.As(ob.Closed, &inner) {
			detail = inner.Kind + "：" + inner.Detail
		}
		values["detail"] = maskSecretText(detail)
		if ob.StatusSeen {
			values["droppedAfter"] = ob.Status.Code()
		}
		return ots.Verdict{Code: verdictRTMPDropped, Values: values,
			Note: "刚问到一半它把连接断了 —— 断之前" + rtmpDropNote(ob)}, nil
	}

	if ob.MediaBytes == 0 {
		note := "play 答应了，可这一段窗口里一个媒体字节都没到"
		if !ob.StatusSeen {
			note = "play 发出去了，窗口里既没有回包也没有媒体字节"
		}
		if ob.Closed != nil {
			// 有字节有断线：窗口读满前就断了，仍然按「没问到在推」算，但把断线一并说明
			note += "（而且它中途把连接断了：" + maskSecretText(ob.Closed.Error()) + "）"
		}
		if !rtmpWatchEnough(watch) {
			// ★ 窗口太短时的「没在推」是我们问出来的还是没问出来，得说清 ——
			//   一秒一两个关键帧的流在这个窗口里本来就是零字节。
			note += "。★ 这个窗口只有 " + strconv.Itoa(int(watch/time.Millisecond)) +
				" 毫秒，太短，别按这一条下结论"
		}
		return ots.Verdict{Code: verdictRTMPNoMedia, Values: values, Note: note}, nil
	}

	// 到这儿就是真收到码流了。码率按「真读了多久」除，不按想要的那几秒除。
	sec := ob.Elapsed.Seconds()
	if sec > 0 {
		kbps := float64(ob.MediaBytes) * 8 / 1000 / sec
		values["bitrateKbps"] = int(kbps)
		values["bitrateBasis"] = fmt.Sprintf("窗口内实测 %d 字节 ÷ 真读了 %.2f 秒", ob.MediaBytes, sec)
		if values["observedMs"].(int64) < int64(watch/time.Millisecond)*9/10 {
			values["observedShort"] = true // 没读满窗口：这个码率的分母比想要的短
		}
	}
	return ots.Verdict{Code: verdictRTMPOk, Values: values,
		Note: rtmpOKNote(values, ob)}, nil
}

// rtmpWatchEnough 这个窗口短到不足以说「没在推」吗。
//
// ★ 口径：一秒。低帧率的监控流（事件触发、一秒一帧）在 500 毫秒窗口里可能就是零字节。
func rtmpWatchEnough(w time.Duration) bool { return w >= time.Second }

// rtmpDropNote 断线之前已经问到的那一点东西 —— 判定与它的账必须同源。
func rtmpDropNote(ob media.Observation) string {
	switch {
	case ob.StatusSeen && ob.Messages > 1:
		return "已经收到「" + ob.Status.Code() + "」和 " + strconv.Itoa(ob.Messages) + " 条消息"
	case ob.StatusSeen:
		return "已经收到「" + ob.Status.Code() + "」"
	case ob.Messages > 0:
		return "已经读到 " + strconv.Itoa(ob.Messages) + " 条消息"
	default:
		return "什么都没问到"
	}
}

// rtmpOKNote 那句「好」只能按这一次真问了什么来写。
//
// ★ 声明的码率与实测差得远时，「在推」是真话，可这一路多半有毛病 ——
//
//	账要写在判定同一份取值里，不然界面上一句「正常」就把证据盖掉了。
func rtmpOKNote(values map[string]any, ob media.Observation) string {
	s := "这路在推：窗口内收到 " + strconv.Itoa(ob.MediaBytes) + " 字节媒体"
	if k, ok := values["bitrateKbps"].(int); ok {
		s += "，实际约 " + strconv.Itoa(k) + " kbps"
	}
	if d, ok := values["declaredVideoKbps"].(int); ok && d > 0 {
		if k, ok2 := values["bitrateKbps"].(int); ok2 && k > 0 && int64(k)*2 < int64(d) {
			s += fmt.Sprintf("；★ 推流端声明的是 %d kbps，实测只有它的 %d%% —— 到了但没按声明的速率过来",
				d, k*100/d)
		}
	}
	if ob.Meta != nil {
		if w, ok := media.AmfNumber(ob.Meta["width"]); ok && w > 0 {
			s += "，声明分辨率 " + strconv.Itoa(int(w)) + "×" +
				strconv.Itoa(int(numOr(ob.Meta["height"])))
		}
	}
	return s
}

func numOr(v any) float64 {
	f, _ := media.AmfNumber(v)
	return f
}

// fillConnectReply 把 connect 那一条答案里能说的都留下：服务器自报的版本、回包类型、
//
//	级别与原文。★ 原文先过 maskSecretText —— 有些服务器把带 key 的 tcUrl 原样抄回描述里。
func fillConnectReply(values map[string]any, c media.RTMPCommand) {
	if c.Name == "" {
		return
	}
	values["connectReply"] = c.Name
	info := c.Info()
	if info == nil {
		return
	}
	if s, ok := info["server"].(string); ok && s != "" {
		values["server"] = s
	}
	if s, ok := info["code"].(string); ok && s != "" {
		values["connectCode"] = s
	}
	if s, ok := info["level"].(string); ok && s != "" {
		values["connectLevel"] = s
	}
	if s, ok := info["description"].(string); ok && s != "" {
		values["connectDetail"] = maskSecretText(s)
	}
}

// fillMetadata 把推流端声明的那一份摊开（只挑判定与界面用得上、且是数的那几项）。
func fillMetadata(values map[string]any, m map[string]any) {
	if m == nil {
		return
	}
	values["metadataSeen"] = true
	if w, ok := media.AmfNumber(m["width"]); ok && w > 0 {
		values["declaredWidth"] = int(w)
	}
	if h, ok := media.AmfNumber(m["height"]); ok && h > 0 {
		values["declaredHeight"] = int(h)
	}
	if f, ok := media.AmfNumber(m["framerate"]); ok && f > 0 {
		values["declaredFps"] = round1(f)
	}
	// videodatarate 的单位是 kbps（Flash 那套元数据的历史约定）
	if k, ok := media.AmfNumber(m["videodatarate"]); ok && k > 0 {
		values["declaredVideoKbps"] = int(k)
	}
	if k, ok := media.AmfNumber(m["audiodatarate"]); ok && k > 0 {
		values["declaredAudioKbps"] = int(k)
	}
	if c, ok := media.AmfNumber(m["videocodecid"]); ok && c > 0 {
		values["declaredVideoCodec"] = rtmpCodecName(int(c))
	}
}

// rtmpCodecName 只认 Flash 元数据里那三个常见值：认不出就说「编号 X」，不猜。
func rtmpCodecName(id int) string {
	switch id {
	case 2:
		return "jpeg"
	case 3:
		return "svp"
	case 4:
		return "vp6"
	case 5:
		return "vp6a"
	case 6:
		return "screen"
	case 7:
		return "h264"
	}
	return "编号 " + strconv.Itoa(id)
}

// rtmpSaysGone 这些码说的是「这一路此刻没人推」，与「名字上没这个流」分开两档。
func rtmpSaysGone(code string) bool {
	switch {
	case code == "":
		return false
	case strings.Contains(code, "NetStream.Play.Failed"):
		return true
	case strings.Contains(code, "Unpublished"), strings.Contains(code, "not publishing"):
		return true
	case strings.Contains(code, "NetStream.Play.Stop"):
		// 播完/被停了：这一刻确实没在往前推
		return true
	}
	return false
}

// rtmpCommandText 取命令里那一句人话（description / message / what/who 各家都写过）。
func rtmpCommandText(c media.RTMPCommand) string {
	info := c.Info()
	if info == nil {
		return ""
	}
	for _, k := range []string{"description", "message", "details", "what", "why"} {
		if s, ok := info[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// rtmpConnectReject：connect 的回包是不是「拒绝」。
//
// ★ 只认 level=error 与 _error 两种明确说法。有些服务器回 onStatus 而 level 是空的，
//
//	那种按「认了」走 —— 猜成拒绝会指着好机器让人去查口令。
func rtmpConnectReject(c media.RTMPCommand) (string, string, bool) {
	info := c.Info()
	level, _ := info["level"].(string)
	code, _ := info["code"].(string)
	text, _ := info["description"].(string)
	if text == "" {
		text, _ = info["message"].(string)
	}
	if c.Name != "_error" && !strings.EqualFold(level, "error") {
		return "", "", false
	}
	joined := strings.ToLower(code + " " + text)
	if rtmpLooksAuth(joined) {
		return verdictRTMPAuth, "这台要凭据才给进 —— 拒绝原文：" +
			firstNonEmpty(maskSecretText(text), code), true
	}
	return verdictRTMPAppRejected, "connect 被拒（" + firstNonEmpty(code, c.Name) + "）—— " +
		firstNonEmpty(maskSecretText(text), "应用名不对，或这台只肯收推流"), true
}

// rtmpLooksAuth 拒绝的理由像不像「缺凭据」。
//
// ★ 各家文案不统一，只能按词认：nginx-rtmp 的 on_connect 回 "wrong key"、
//
//	SRS 回 "auth failed"、相机固件回 "password error"，说的都是同一件事。
func rtmpLooksAuth(s string) bool {
	for _, w := range []string{"key", "token", "password", "passwd", "auth", "sign",
		"forbidden", "unauthor", "denied", "deny", "credential", "drm", "凭", "口令", "鉴权", "认证"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// rtmpFault 把一次 RTMPError 落成判定码。★ 阶段与类型分开看：同样是超时，
//
//	握手不回和命令不回下一步完全不同 —— 前者多半是中间有东西吃掉，后者多半是这台只肯收推流。
func rtmpFault(values map[string]any, err error) ots.Verdict {
	var re *media.RTMPError
	if !errors.As(err, &re) {
		values["detail"] = maskSecretText(err.Error())
		return ots.Verdict{Code: ots.CodeUnknown, Values: values,
			Note: "这一问的落点我们没有一个对应判定，把已经问到的照实给出"}
	}
	values["stage"] = re.Stage
	if re.Detail != "" {
		values["detail"] = maskSecretText(re.Detail)
	} else if re.Err != nil {
		values["detail"] = maskSecretText(re.Err.Error())
	}
	if re.Kind == media.RTMPKindNotRTMP {
		var hang *media.RTMPHangError
		if errors.As(re, &hang) && hang.Info != (media.RTMPHandshake{}) {
			values["handshakeVersion"] = hang.Info.Version
			if hang.Info.Sig != "" {
				values["looksLike"] = hang.Info.Sig
			}
			if hang.Info.Peek != "" {
				values["firstBytes"] = hang.Info.Peek
			}
		}
		return ots.Verdict{Code: verdictRTMPNotRTMP, Values: values,
			Note: "端口开着，可它回的不是 RTMP 握手" + rtmpLooksNote(values) +
				" —— 这个口多半配错了服务"}
	}

	switch re.Kind {
	case media.RTMPKindDial:
		// ★ closed（机器在、这个口没服务）与 filtered（一句都不答）下一步完全不同：
		//   合并成「连不上」就等于让人去查一个根本没挡着的防火墙。
		reach := classify(re)
		if reach != "" {
			values["reach"] = reach
		}
		return ots.Verdict{Code: verdictRTMPUnreachable, Values: values,
			Note: "TCP 就没连上（" + firstNonEmpty(reach, "连不上") + "）—— " +
				maskSecretText(re.Error())}
	case media.RTMPKindTimeout:
		if re.Stage == "handshake" {
			return ots.Verdict{Code: verdictRTMPTimeout, Values: values,
				Note: "端口连上了，可握手那一句到点没回 —— 多半是中间有东西放着半开的连接，或这台只对外地那几台答话"}
		}
		if re.Stage == "play" {
			// play 那一步我们不等回包，所以这里的超时只会是「写不出去」
			return ots.Verdict{Code: verdictRTMPDropped, Values: values,
				Note: "play 发出去卡住了：" + maskSecretText(re.Error())}
		}
		return ots.Verdict{Code: verdictRTMPCmdSilent, Values: values,
			Note: "握手通了，「" + re.Stage + "」这句发出去到点没回话 —— 只肯收推流的服务器、或中间那台把命令吃掉了"}
	case media.RTMPKindClosed:
		if re.Stage == "handshake" {
			return ots.Verdict{Code: verdictRTMPNotRTMP, Values: values,
				Note: "连上了，可它没把 RTMP 握手做完就把连接关了 —— 只认复杂握手的服务器、或这个口上压根不是 RTMP"}
		}
		return ots.Verdict{Code: verdictRTMPDropped, Values: values,
			Note: "走到「" + re.Stage + "」这一步它把连接关了 —— 有些服务器用这一手表示拒绝"}
	case media.RTMPKindProtocol:
		return ots.Verdict{Code: verdictRTMPNotRTMP, Values: values,
			Note: "它回的报文对不上 RTMP 的分块规则：" + maskSecretText(re.Error())}
	}
	return ots.Verdict{Code: verdictRTMPUnreachable, Values: values,
		Note: maskSecretText(re.Error())}
}

func rtmpLooksNote(values map[string]any) string {
	if s, ok := values["looksLike"].(string); ok && s != "" {
		return "（那一段看着像 " + s + "）"
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// maskSecretText 给一句要进结果的文本过一遍：口令类的参数值打码、控制字符去掉、截断。
//
// ★★ 服务器回包里的描述经常把 tcUrl 整条抄回来，而 tcUrl 里就带着 key ——
//
//	「凭据不进结果」这条不能只对 URL 生效。
func maskSecretText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	// 先整段打码，再截断：截在最中间的字符串会把「=」后面的部分留下，反而更好认
	if i := strings.Index(s, "://"); i >= 0 {
		// 把嵌在句子里的那一段地址单独摘出来打码（按空白与常见终止符断开）
		j := i
		for j < len(s) && !strings.ContainsRune(" \"'），;「」", rune(s[j])) {
			j++
		}
		if u, err := url.Parse(s[i:j]); err == nil && u.Host != "" {
			s = s[:i] + redactURL(u) + s[j:]
		}
	}
	s = secretAssign.ReplaceAllStringFunc(s, func(m string) string {
		k := m[:strings.Index(m, "=")+1]
		return k + "***"
	})
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// secretAssign 认的是句子里裸写的 key=abc123（没有 URL 前缀的那种）。
//
// ★ vhost 也在列里：它本身不是口令，可各家把它当租户密钥用的不少 ——
//
//	打码的代价只是少看一个值，漏掉的代价是一串口令进了诊断包。
var secretAssign = regexp.MustCompile(`(?i)\b(key|token|secret|password|passwd|pwd|sign|vhost|auth|session)=([^&;,'" )（】\[\]]+)`)

// normalizeRTMPURL 认 rtmp:// 与 rtmps://，别的族一律推到对应的卡上去。
func normalizeRTMPURL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("没给地址")
	}
	if !strings.Contains(s, "://") {
		s = "rtmp://" + strings.TrimPrefix(s, "/")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("看不懂地址 %q：%s", redactString(s), err)
	}
	switch u.Scheme {
	case "rtmp", "rtmps":
	case "rtsp", "rtsps":
		return nil, errors.New("这是 RTSP 地址，请用 media.rtsp.probe")
	case "http", "https":
		return nil, errors.New("这是 http 地址；m3u8 清单用 media.hls.probe，别的要按那一族的规矩问")
	case "flv":
		return nil, errors.New("FLV 裸流这一版还没做；先用 media.rtmp.probe 问它上面那路 RTMP")
	default:
		return nil, fmt.Errorf("只支持 rtmp:// 与 rtmps://，给的是 %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("地址里没有主机名：%q", redactString(s))
	}
	return u, nil
}

func rtmpPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 && n < 65536 {
			return n
		}
		return 0
	}
	if u.Scheme == "rtmps" {
		return 443
	}
	return 1935
}

// rtmpSplitPath 拆应用名与流名。★ 显式填的优先：地址写法古怪（应用名带参数、
//
//	流名本身带斜杠）时，只有分开填才说得清哪一段是哪个。
func rtmpSplitPath(u *url.URL, appArg, streamArg string) (string, string, error) {
	path := strings.TrimPrefix(u.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	app, stream := "", ""
	if parts[0] != "" {
		app = parts[0]
	}
	if len(parts) > 1 {
		stream = parts[1]
	}
	if appArg != "" {
		app = appArg
	}
	if streamArg != "" {
		stream = streamArg
	}
	if app == "" {
		return "", "", fmt.Errorf("地址里没有应用名：rtmp 地址得写成 rtmp://主机/应用名/流名（只问应用认不认时至少要写应用名）")
	}
	// 应用名里那一段参数（live?some=1）不参与猜测：RTMP 的应用名就是那一段
	return app, strings.Trim(stream, "/"), nil
}

// rtmpJoinQuery 把地址上那段 ?key=… 重新挂回流名：nginx-rtmp 那一族在 play 里
//
//	按整串去校验，拆掉就等于把凭据丢了。
func rtmpJoinQuery(stream, query string) string {
	if query == "" {
		return stream
	}
	if stream == "" {
		return "?" + query
	}
	if i := strings.Index(stream, "?"); i >= 0 {
		return stream + "&" + query
	}
	return stream + "?" + query
}

// redactTCURL 发给服务器的那份 tcUrl —— ★ 不带凭据：口令只进 connect 参数，
//
//	不写进 tcUrl 让服务器原样抄回描述里。
func redactTCURL(u *url.URL, app string) string {
	cp := *u
	cp.User = nil
	cp.RawQuery = ""
	cp.Path = "/" + strings.TrimPrefix(app, "/")
	return cp.String()
}

// rtmpConnectParams 只收标量：一层嵌套都不收，免得把调用方自己都不清楚的东西发出去。
func rtmpConnectParams(m map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range m {
		if k == "app" || k == "tcUrl" {
			continue // 这两个由探测方自己算
		}
		switch x := v.(type) {
		case string:
			out[k] = x
		case float64:
			out[k] = x
		case bool:
			out[k] = x
		case nil:
			out[k] = nil
		default:
			return nil, fmt.Errorf("connect 参数 %q 给的是 %T，只收字符串、数字、布尔", k, v)
		}
	}
	return out, nil
}
