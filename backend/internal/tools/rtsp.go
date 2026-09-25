package tools

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/media"
	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// RTSP 探测的判定码。
//
// ★ 这几个的区分就是现场「盒子没画面」的排查树：
//
//	stream-ok       拿到了流描述，参数解出来了 —— 流本身没问题，问题在下游
//	stream-no-media 认证过了、也回了 200，可应答里没有一条媒体轨 —— 这路流没配出来
//	auth-required   要认证，没给或给错了 —— 十有八九是密码错，不是网络问题
//	not-found       连上了、认证过了，但这个路径没有流 —— 通道号/路径写错了
//	stream-no-data  轨有、SETUP 与 PLAY 也都要到了，可一段时间里一个 RTP 包都没到
//	no-response     TCP 连上了，RTSP 不回话 —— 对面开着端口但不是 RTSP，或者卡死了
//	unreachable     连都连不上
const (
	verdictStreamOK     = "stream-ok"
	verdictStreamNoMed  = "stream-no-media"
	verdictStreamNoData = "stream-no-data"
	verdictAuthRequired = "auth-required"
	verdictNotFound     = "not-found"
	verdictNoResponse   = "no-response"
	verdictRTSPUnreach  = "unreachable"
)

var rtspProbeTool = ots.Tool{
	Name:  "media.rtsp.probe",
	Class: ots.ClassRead,
	Summary: "探测一路 RTSP 流：拿编码格式、**分辨率**、帧率、通道数，" +
		"再实际收一小段流，量出**实际码率、到达帧率、RTP 丢包、关键帧间隔**。" +
		"走 DESCRIBE 取 SDP、解 H.264/H.265 的 SPS 得到真实分辨率，" +
		"再 SETUP+PLAY 收几秒 RTP 数包 —— 不依赖 ffmpeg，也不解码。支持 Basic 与 Digest 认证。" +
		"★ 现场最常用的一条：判断相机实际出的是多大分辨率、实际发没发、" +
		"以及它和下游（盒子/平台）的预期对不对得上。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["url"],
	  "properties": {
	    "url": {"type": "string",
	      "description": "RTSP 地址，如 rtsp://192.168.1.64:554/cam/realmonitor?channel=1&subtype=0 。用户名密码可以写在地址里，也可以用下面两个字段分开给。IPv6 地址要写方括号：rtsp://[fd00::1]:554/... "},
	    "username": {"type": "string", "description": "用户名。地址里已经带了就不用填。"},
	    "password": {"type": "string", "description": "密码。地址里已经带了就不用填。"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 60000,
	      "description": "一问一答的超时毫秒数，默认 5000。"},
	    "measureMs": {"type": "integer", "minimum": 0, "maximum": 10000,
	      "description": "收多久的流来量实际码率、到达帧率、丢包与关键帧间隔，默认 3000。填 0 只问参数、不收流（设备只允许一路取流、或者不想打断现网播放时用）。"}
	  }
	}`),
	Invoke: probeRTSP,
}

type rtspArgs struct {
	URL       string `json:"url"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
	// MeasureMS 是指针：没填（默认收 3 秒）和特意填 0（不收流）是两回事。
	MeasureMS *int `json:"measureMs,omitempty"`
}

// track 一路媒体轨。
type track struct {
	Kind       string  `json:"kind"`                 // video / audio / application
	Codec      string  `json:"codec,omitempty"`      // h264 / h265 / pcma ...
	Width      int     `json:"width,omitempty"`      //
	Height     int     `json:"height,omitempty"`     //
	FPS        float64 `json:"fps,omitempty"`        //
	Profile    int     `json:"profile,omitempty"`    //
	Level      int     `json:"level,omitempty"`      //
	Interlaced bool    `json:"interlaced,omitempty"` //
	// ParamsNote 参数集解析没成功时说明原因。
	// ★ 解不出分辨率不等于整条探测失败 —— 流可能确实是通的，只是没给参数集。
	//   这时候要如实说「没拿到」，不是编一个数。
	ParamsNote string `json:"paramsNote,omitempty"`

	// 下面三项是 SETUP+PLAY 收流要用的，不是给人看的那一份（小写开头 = 不进 JSON）。
	ctl   string // a=control 的那一段，SETUP 的地址就拼在它身上
	pt    string // 载荷类型，rtpmap/fmtp 都按它对齐
	clock int    // SDP 给的时钟频率，收流折算关键帧间隔要用
}

func probeRTSP(ctx context.Context, raw json.RawMessage) (any, error) {
	var a rtspArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.URL == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 url")
	}
	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme != "rtsp" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "不是合法的 rtsp:// 地址：%s", a.URL)
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
	// 拨号用的地址不带凭据；请求行里的 URL 也不带 —— 免得凭据出现在日志里
	u.User = nil

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "554"
	}
	dial := net.JoinHostPort(host, port)
	// IPv6 / 链路本地：统一走 netaddr 拼，别在这里手搓
	if addr, perr := netaddr.Parse(host); perr == nil {
		pn, _ := strconv.Atoi(port)
		if hp, herr := addr.HostPort(pn, runtime.GOOS); herr == nil {
			dial = hp
		}
	}

	signal := time.Duration(a.TimeoutMS) * time.Millisecond
	if signal <= 0 {
		signal = 5 * time.Second
	}
	window := rtspMeasureWindow(a.MeasureMS)
	// ★ 收流那一段要单独给时间。拿原来「一问一答」的那个超时去卡三秒收包，
	//   量到一半就被掐了，读数会退成「窗口太短，码率不算」。
	total := signal
	if window > 0 {
		total = signal + window + 2*time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	values := map[string]any{"url": u.String(), "target": dial}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dial)
	if err != nil {
		values["detail"] = err.Error()
		return ots.Verdict{Code: verdictRTSPUnreach, Values: values,
			Note: dial + " 连不上"}, nil
	}
	defer conn.Close()
	arm := func() { _ = conn.SetDeadline(time.Now().Add(signal)) }
	arm()

	br := bufio.NewReader(conn)
	seq := 0
	var auth string
	// 第一次 DESCRIBE：多半会拿到 401，从里面取认证挑战
	status, hdr, body, err := rtspDo(conn, br, "DESCRIBE", u.String(), &seq, auth)
	if err != nil {
		values["detail"] = err.Error()
		return ots.Verdict{Code: verdictNoResponse, Values: values,
			Note: dial + " 连上了但 RTSP 不回话 —— 对面开着这个端口，但可能不是 RTSP 服务"}, nil
	}
	if status == 401 {
		chal := hdr["www-authenticate"]
		values["authScheme"] = schemeOf(chal)
		if user == "" && pass == "" {
			return ots.Verdict{Code: verdictAuthRequired, Values: values,
				Note: "需要用户名密码"}, nil
		}
		var aerr error
		auth, aerr = authHeader(chal, user, pass, "DESCRIBE", u.String())
		if aerr != nil {
			values["detail"] = aerr.Error()
			return ots.Verdict{Code: verdictAuthRequired, Values: values,
				Note: "看不懂对方要求的认证方式"}, nil
		}
		arm()
		status, hdr, body, err = rtspDo(conn, br, "DESCRIBE", u.String(), &seq, auth)
		if err != nil {
			values["detail"] = err.Error()
			return ots.Verdict{Code: verdictNoResponse, Values: values}, nil
		}
	}

	values["status"] = status
	switch {
	case status == 401 || status == 403:
		return ots.Verdict{Code: verdictAuthRequired, Values: values,
			Note: "认证没通过 —— 用户名密码多半不对"}, nil
	case status == 404:
		return ots.Verdict{Code: verdictNotFound, Values: values,
			Note: "连上也认证过了，但这个路径没有流 —— 通道号或路径写错了"}, nil
	case status < 200 || status >= 300:
		values["detail"] = hdr["_status_line"]
		// ★ [OTS-5.7] 没有对应判定码就返回 unknown 加证据，不编一句话糊过去
		return ots.Unknown(values), nil
	}

	tracks, sessionCtl := parseSDP(body)
	values["tracks"] = tracks
	if n := len(tracks); n > 0 {
		values["trackCount"] = n
	}
	// ★ 回了 200 不等于有流。描述头是空的（该通道没配码流、固件半应答），
	//	按 stream-ok 报就成了「工具说流是好的、画面还是没有」——
	//	这一格必须单独说，因为它把「去看下游」翻成「回设备那头配通道」。
	if len(tracks) == 0 {
		return ots.Verdict{Code: verdictStreamNoMed, Values: values,
			Note: "连上、认证都过了，应答里却一条媒体轨都没有 —— 这路流在设备那侧就没配出来"}, nil
	}
	if v := firstVideo(tracks); v != nil && v.Width > 0 {
		values["width"], values["height"], values["codec"] = v.Width, v.Height, v.Codec
	}
	// 参数问完了，接着**实际收一小段**。★ 这两问不能并成一格：
	// SDP 写着 25fps 说的是设备打算发什么，几秒里到了多少包才是盒子里真有的东西。
	if window == 0 {
		values["measured"] = false
		values["measureNote"] = "这一问按你的选择没听码流，下面这些只来自流描述"
	} else {
		arm()
		m := measureStream(ctx, conn, br, u.String(), auth, &seq, pickTrack(tracks), sessionCtl, signal, window)
		if m.switched != "" {
			values["transportNote"] = m.switched
		}
		switch {
		case m.silent:
			values["measured"] = false
			values["transport"] = m.transport
			return ots.Verdict{Code: verdictStreamNoData, Values: values, Note: m.note}, nil
		case m.note != "":
			values["measured"] = false
			values["measureNote"] = m.note
		default:
			values["measured"] = true
			values["transport"] = m.transport
			values["rtp"] = m.reading
		}
	}
	return ots.Verdict{Code: verdictStreamOK, Values: values,
		Note: describeTracks(tracks)}, nil
}

// pickTrack 挑一路来收：优先视频，没有视频轨就收第一轨。
func pickTrack(ts []track) *track {
	if v := firstVideo(ts); v != nil {
		return v
	}
	return &ts[0]
}

func firstVideo(ts []track) *track {
	for i := range ts {
		if ts[i].Kind == "video" {
			return &ts[i]
		}
	}
	return nil
}

func describeTracks(ts []track) string {
	if len(ts) == 0 {
		return "取到了流描述，但里面没有媒体轨"
	}
	var parts []string
	for _, t := range ts {
		s := t.Kind
		if t.Codec != "" {
			s += " " + t.Codec
		}
		if t.Width > 0 {
			s += fmt.Sprintf(" %dx%d", t.Width, t.Height)
		}
		if t.FPS > 0 {
			s += fmt.Sprintf(" %.3gfps", t.FPS)
		}
		if t.ParamsNote != "" {
			s += "（" + t.ParamsNote + "）"
		}
		parts = append(parts, s)
	}
	return "流正常：" + strings.Join(parts, "；")
}

// ── RTSP 最小实现 ──

// rtspDo 发一问读一答。extra 是这一问多出来的请求头（Transport、Session、Range）。
func rtspDo(conn net.Conn, br *bufio.Reader, method, uri string, seq *int, auth string, extra ...string) (int, map[string]string, string, error) {
	*seq++
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s RTSP/1.0\r\n", method, uri)
	fmt.Fprintf(&sb, "CSeq: %d\r\n", *seq)
	sb.WriteString("User-Agent: yuhox-netkit\r\n")
	if method == "DESCRIBE" {
		sb.WriteString("Accept: application/sdp\r\n")
	}
	if auth != "" {
		fmt.Fprintf(&sb, "Authorization: %s\r\n", auth)
	}
	for _, h := range extra {
		fmt.Fprintf(&sb, "%s\r\n", h)
	}
	sb.WriteString("\r\n")
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return 0, nil, "", err
	}

	line, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, "", err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "RTSP/") {
		return 0, nil, "", fmt.Errorf("回的不是 RTSP 响应：%q", strings.TrimSpace(line))
	}
	code, _ := strconv.Atoi(parts[1])

	hdr := map[string]string{"_status_line": strings.TrimSpace(line)}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return code, hdr, "", err
		}
		l = strings.TrimRight(l, "\r\n")
		if l == "" {
			break
		}
		if i := strings.Index(l, ":"); i > 0 {
			hdr[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
		}
	}
	n, _ := strconv.Atoi(hdr["content-length"])
	if n <= 0 {
		return code, hdr, "", nil
	}
	if n > 1<<20 {
		n = 1 << 20
	}
	buf := make([]byte, n)
	if _, err := ioReadFull(br, buf); err != nil {
		return code, hdr, "", err
	}
	return code, hdr, string(buf), nil
}

func ioReadFull(br *bufio.Reader, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := br.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func schemeOf(chal string) string {
	if strings.HasPrefix(strings.ToLower(chal), "digest") {
		return "digest"
	}
	if strings.HasPrefix(strings.ToLower(chal), "basic") {
		return "basic"
	}
	return ""
}

// authHeader 按挑战造 Authorization。
//
// ★ 必须支持 Digest：主流网络摄像机（大华、海康）默认都是 Digest，
// 只做 Basic 等于在最常见的设备上用不了。
func authHeader(chal, user, pass, method, uri string) (string, error) {
	switch schemeOf(chal) {
	case "basic":
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
	case "digest":
		p := parseChallenge(chal)
		realm, nonce := p["realm"], p["nonce"]
		if realm == "" || nonce == "" {
			return "", fmt.Errorf("Digest 挑战里缺 realm 或 nonce")
		}
		ha1 := md5hex(user + ":" + realm + ":" + pass)
		ha2 := md5hex(method + ":" + uri)
		var resp string
		out := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s"`,
			user, realm, nonce, uri)
		if qop := p["qop"]; strings.Contains(qop, "auth") {
			cnonce := randHex(8)
			nc := "00000001"
			resp = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
			out += fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, cnonce)
		} else {
			resp = md5hex(ha1 + ":" + nonce + ":" + ha2)
		}
		out += fmt.Sprintf(`, response="%s"`, resp)
		if op := p["opaque"]; op != "" {
			out += fmt.Sprintf(`, opaque="%s"`, op)
		}
		return out, nil
	}
	return "", fmt.Errorf("不认识的认证方式：%q", chal)
}

func parseChallenge(s string) map[string]string {
	out := map[string]string{}
	if i := strings.IndexByte(s, ' '); i > 0 {
		s = s[i+1:]
	}
	for _, kv := range splitOutsideQuotes(s) {
		i := strings.Index(kv, "=")
		if i < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[:i]))
		v := strings.Trim(strings.TrimSpace(kv[i+1:]), `"`)
		out[k] = v
	}
	return out
}

// splitOutsideQuotes 按逗号切，但不切引号里的逗号（qop="auth,auth-int" 会踩这个）。
func splitOutsideQuotes(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case r == ',' && !inQ:
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

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── SDP ──

// parseSDP 解 SDP，拿每一路轨的编码和分辨率。
//
// parseSDP 解 SDP，拿每一路轨的编码、分辨率，另外把会话级的 a=control 一并带出来
// （收流时 SETUP 的地址要拿它拼）。
//
// ★ 分辨率不在 SDP 的字段里，而是藏在 fmtp 的 sprop-parameter-sets（H.264）
// 或 sprop-sps（H.265）里 —— 那是 base64 过的 SPS，解开它才有真实分辨率。
// 这就是我们不需要 ffmpeg 的原因：答案本来就在描述里。
func parseSDP(sdp string) ([]track, string) {
	var tracks []track
	var cur *track
	var sessionCtl string
	rtpmap := map[string]string{} // payload type → codec
	fmtp := map[string]string{}   // payload type → 参数

	flush := func() {
		if cur != nil {
			tracks = append(tracks, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "m="):
			flush()
			f := strings.Fields(strings.TrimPrefix(line, "m="))
			if len(f) == 0 {
				continue
			}
			cur = &track{Kind: f[0]}
			if len(f) >= 4 {
				cur.pt = f[3]
			}
		case strings.HasPrefix(line, "a=control:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "a=control:"))
			if cur == nil {
				sessionCtl = v // 会话级那一条：它是各轨地址的前缀
			} else {
				cur.ctl = v
			}
		case strings.HasPrefix(line, "a=rtpmap:"):
			v := strings.TrimPrefix(line, "a=rtpmap:")
			f := strings.Fields(v)
			if len(f) >= 2 {
				rtpmap[f[0]] = f[1]
			}
		case strings.HasPrefix(line, "a=fmtp:"):
			v := strings.TrimPrefix(line, "a=fmtp:")
			if i := strings.IndexByte(v, ' '); i > 0 {
				fmtp[v[:i]] = v[i+1:]
			}
		}
	}
	flush()

	for i := range tracks {
		pt := tracks[i].pt
		if enc := rtpmap[pt]; enc != "" {
			tracks[i].Codec = strings.ToLower(strings.SplitN(enc, "/", 2)[0])
			// rtpmap 的第二段是时钟频率（H264/90000）—— 收流折算关键帧间隔只认它。
			if f := strings.Split(enc, "/"); len(f) >= 2 {
				tracks[i].clock, _ = strconv.Atoi(f[1])
			}
		}
		if tracks[i].Kind != "video" {
			continue
		}
		p, note := paramsFromFmtp(fmtp[pt])
		if note != "" {
			tracks[i].ParamsNote = note
			continue
		}
		tracks[i].Codec = p.Codec
		tracks[i].Width, tracks[i].Height = p.Width, p.Height
		tracks[i].FPS, tracks[i].Profile, tracks[i].Level = p.FPS, p.Profile, p.Level
		tracks[i].Interlaced = p.Interlaced
	}
	return tracks, sessionCtl
}

// paramsFromFmtp 从 fmtp 参数里取出 SPS 并解析。
func paramsFromFmtp(f string) (media.Params, string) {
	if f == "" {
		return media.Params{}, "SDP 里没给参数集，拿不到分辨率"
	}
	kv := map[string]string{}
	for _, part := range strings.Split(f, ";") {
		i := strings.Index(part, "=")
		if i < 0 {
			continue
		}
		kv[strings.ToLower(strings.TrimSpace(part[:i]))] = strings.TrimSpace(part[i+1:])
	}
	// H.264：sprop-parameter-sets=<SPS>,<PPS>
	if v := kv["sprop-parameter-sets"]; v != "" {
		b64 := strings.SplitN(v, ",", 2)[0]
		nal, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return media.Params{}, "参数集 base64 解不开"
		}
		p, err := media.ParseH264SPS(nal)
		if err != nil {
			return media.Params{}, "SPS 解析失败：" + err.Error()
		}
		return p, ""
	}
	// H.265：sprop-sps 单独一个字段
	if v := kv["sprop-sps"]; v != "" {
		nal, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return media.Params{}, "参数集 base64 解不开"
		}
		p, err := media.ParseH265SPS(nal)
		if err != nil {
			return media.Params{}, "SPS 解析失败：" + err.Error()
		}
		return p, ""
	}
	return media.Params{}, "SDP 里没给参数集，拿不到分辨率"
}
