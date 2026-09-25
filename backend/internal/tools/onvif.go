package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/onvif"
	"net.yuhox.com/netkit/internal/ots"
)

// media.onvif.info —— 问一台设备「你是谁、现在几点、有几路流、流地址是什么」。
//
// ★★ 这张卡是 RTSP 探测的前置。现场最常见的一步卡壳不是「流不通」，
//
//	而是「我手里只有这台设备的网页后台，取流地址是多少」——
//	ONVIF 把地址问得出来（GetProfiles 给出码流，GetStreamUri 给出地址），
//	「没画面」的排查因此能从**问出地址**开始，而不是从猜地址开始。
//
// ★ 时间那一格答的是**设备自己说它几点、它靠什么对时**。偏移照给，
//
//	但注明是「相对本机」：拿本机那把尺去论设备的对错，本机自己不准的时候
//	就把它的准算成了错 —— 谁对谁错归校时那张卡判。
var onvifInfoTool = ots.Tool{
	Name:  "media.onvif.info",
	Class: ots.ClassRead,
	Summary: "向一台 ONVIF 设备发五个只读 SOAP 请求：问身份（GetDeviceInformation）、" +
		"问它自己说现在几点、靠什么对时（GetSystemDateAndTime）、问服务挂在哪儿（GetCapabilities）、" +
		"问有几路码流及各路规格（GetProfiles）、问第一路的 RTSP 取流地址（GetStreamUri）。" +
		"带 WS-Security UsernameToken 摘要认证。" +
		"★ 拿不到取流地址时用它问出来再去验流；哪一问没问出去都单独留痕，不含糊成「问了没问题」。" +
		"密码不进结果也不进日志。属于只读。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["url"],
	  "properties": {
	    "url": {"type": "string",
	      "description": "ONVIF 服务地址。填 http://192.168.1.64 这样的主机就行（默认端口 80、路径 /onvif/device_service），也可以填完整地址。只走 http(s)。"},
	    "username": {"type": "string", "description": "ONVIF 账号。多数相机匿名只回 Fault，得带账号才问得出东西。"},
	    "password": {"type": "string", "description": "ONVIF 密码。结果与日志里都不会回显。"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 30000,
	      "description": "整次问话（几问加起来）最多等多久，默认 10000。"}
	  }
}`),
	Invoke: probeONVIFInfo,
}

// ONVIF 问话的判定码。[OTS-6.2] 401 与 SOAP Fault 都是**问出来的状态**，不是工具失败。
const (
	verdictONVIFOK        = "onvif-ok"         // 身份问到了，码流也问到了
	verdictONVIFNoProfile = "onvif-no-profile" // 问到了、它也说没有码流 —— 和「问不通媒体服务」是两件事
	verdictONVIFPartial   = "onvif-partial"    // 身份问到了，媒体那一路没问出来
	verdictONVIFAuth      = "auth-required"    // 没给账号，或给了被挡
	verdictONVIFFault     = "onvif-fault"      // 认证过了，设备回的是 SOAP Fault
	verdictONVIFNotOnvif  = "not-onvif"        // 端口活着，可回的不是 ONVIF
	verdictONVIFNoRepl    = "no-response"      // 连上了不回话
	verdictONVIFUnreach   = "unreachable"      // 连不上
)

type onvifArgs struct {
	URL       string `json:"url"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// ONVIF 的设备服务与媒体服务通常在同一台主机上，路径各家不通用。
const (
	onvifDevPath   = "/onvif/device_service"
	onvifMediaPath = "/onvif/media_service"
)

func probeONVIFInfo(ctx context.Context, raw json.RawMessage) (any, error) {
	var a onvifArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	devURL, err := onvifEndpoint(a.URL)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(a.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cred := &onvif.Credential{Username: a.Username, Password: a.Password}
	cl := &onvifClient{
		hc:   &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()},
		cred: cred,
	}
	values := map[string]any{"url": devURL}
	tr := &onvifTrail{values: values}

	// ── 第一问：它是谁 ──
	tr.ask("问它是谁")
	info, status, err := cl.ask(ctx, devURL, onvif.DeviceNS, "GetDeviceInformation")
	if v, done := tr.early(devURL, status, err); done {
		return v, nil
	}
	if f := onvif.FaultOf(info); f != nil {
		tr.faulted("它回了 Fault", f)
		return onvifFaultVerdict(values, f, cred), nil
	}
	d := onvif.DecodeDeviceInfo(info)
	setIfNotEmpty(values, "manufacturer", d.Manufacturer)
	setIfNotEmpty(values, "model", d.Model)
	setIfNotEmpty(values, "firmwareVersion", d.Firmware)
	setIfNotEmpty(values, "serialNumber", d.Serial)
	setIfNotEmpty(values, "hardwareId", d.HardwareID)
	if d.Manufacturer == "" && d.Model == "" && d.Firmware == "" && d.Serial == "" && d.HardwareID == "" {
		// 回了 SOAP 却一个身份字段都没有 —— 这台没照 ONVIF 答话，不能报成「问到了」
		values["status"] = status
		return ots.Verdict{Code: verdictONVIFNotOnvif, Values: values,
			Note: "这个地址回了话，可应答里一个 ONVIF 设备信息字段都没有 —— 它大概不是 ONVIF 服务"}, nil
	}

	// ── 第二问：它自己说几点 ──
	tr.ask("问它现在几点")
	tnode, _, terr := cl.ask(ctx, devURL, onvif.DeviceNS, "GetSystemDateAndTime")
	switch {
	case terr != nil:
		tr.notAsked("没问出去", terr)
	case onvif.FaultOf(tnode) != nil:
		tr.faulted("它回了 Fault", onvif.FaultOf(tnode))
	default:
		t := onvif.DecodeTime(tnode)
		base := firstNonEmptyStr(t.UTC, t.Local)
		setIfNotEmpty(values, "deviceTime", base)
		if t.LocalOnly() {
			// ★ 它只给了本地时间、没给出可换算的 UTC：这个时刻不能拿去算偏移。
			//	时区一差就是几小时，「它时间不对」会被我们算成假的。
			tr.note("它只给了本地时间，没给可用的时区偏移，这一格不换算成偏差")
		} else if base != "" {
			setIfNotEmpty(values, "deviceTimezone", t.Timezone)
			if ts, perr := time.Parse(time.RFC3339, base); perr == nil {
				// 正数 = 它比本机快。这一格只说明「它和我不一致」，
				// 谁准归校时那张卡判 —— 本机那把尺也可能就是歪的。
				values["offsetMsVsLocal"] = ts.Sub(cl.replyAt).Milliseconds()
			}
		}
		setIfNotEmpty(values, "deviceTimeType", t.DateTime) // NTP / Manual / SetManually
		if t.Dst != "" {
			values["daylightSavings"] = strings.EqualFold(t.Dst, "true")
		}
		if len(t.NTPAddrs) > 0 {
			values["ntpServers"] = t.NTPAddrs
		}
		if t.NTPFromDHCP {
			values["ntpFromDHCP"] = true
		}
	}

	// ── 第三问：媒体服务挂在哪儿 ──
	tr.ask("问它服务挂在哪儿")
	mediaURL := onvifMediaEndpoint(devURL)
	cnode, _, cerr := cl.ask(ctx, devURL, onvif.DeviceNS, "GetCapabilities")
	switch {
	case cerr != nil:
		tr.notAsked("没问出去", cerr)
	case onvif.FaultOf(cnode) != nil:
		tr.faulted("它回了 Fault", onvif.FaultOf(cnode))
	default:
		if x := onvif.MediaXAddr(cnode); x != "" {
			// ★ 这一句是**设备自报**的地址，不是核实过的事实：只取它的路径与端口，
			//	主机钉死在我们正在问的这一台上。否则一台设备就能把探测工具
			//	支使去敲别人的门。
			if pinned, ok := onvifPinHost(devURL, x); ok {
				mediaURL = pinned
				values["mediaService"] = pinned
			} else {
				tr.note("它报的媒体服务地址不在这台主机上，没去问")
			}
		}
	}

	// ── 第四问：有几路码流 ──
	tr.ask("问它有几路码流")
	pnode, _, perr := cl.ask(ctx, mediaURL, onvif.MediaNS, "GetProfiles")
	var profiles []onvif.Profile
	mediaAsked := true
	switch {
	case perr != nil:
		mediaAsked = false
		tr.notAsked("没问出去", perr)
	case onvif.FaultOf(pnode) != nil:
		mediaAsked = false
		tr.faulted("它回了 Fault", onvif.FaultOf(pnode))
	default:
		profiles = onvif.DecodeProfiles(pnode)
		values["profileCount"] = len(profiles)
		out := make([]map[string]any, 0, len(profiles))
		for _, p := range profiles {
			m := map[string]any{}
			setIfNotEmpty(m, "name", p.Name)
			setIfNotEmpty(m, "token", p.Token)
			setIfNotEmpty(m, "codec", p.Encoding)
			setIfNotEmpty(m, "width", p.Width)
			setIfNotEmpty(m, "height", p.Height)
			setIfNotEmpty(m, "framerate", p.Framerate)
			setIfNotEmpty(m, "bitrateKbps", p.Bitrate)
			setIfNotEmpty(m, "audio", p.Audio)
			out = append(out, m)
		}
		if len(out) > 0 {
			values["profiles"] = out
		}
		if len(profiles) > 0 {
			setIfNotEmpty(values, "profileName", profiles[0].Name)
			setIfNotEmpty(values, "streamProfileToken", profiles[0].Token)
			setIfNotEmpty(values, "codec", profiles[0].Encoding)
			if profiles[0].Width != "" || profiles[0].Height != "" {
				values["width"] = atoiOr(profiles[0].Width)
				values["height"] = atoiOr(profiles[0].Height)
			}
		}
	}

	// ── 第五问：第一路的取流地址 ──
	// ★ 地址不在 GetProfiles 的应答里 —— ONVIF 把它单独放在 GetStreamUri 那一答，
	//	少了这一问，「替现场问出地址」这件事就没做成。
	if len(profiles) > 0 && profiles[0].Token != "" {
		tr.ask("问它第一路的取流地址")
		unode, _, uerr := cl.askURI(ctx, mediaURL, profiles[0].Token)
		switch {
		case uerr != nil:
			tr.notAsked("没问出去", uerr)
		case onvif.FaultOf(unode) != nil:
			tr.faulted("它回了 Fault", onvif.FaultOf(unode))
		default:
			if uri := redactONVIFURI(onvif.DecodeStreamURI(unode)); uri != "" {
				values["mediaUri"] = uri
			} else {
				tr.note("它回了，可应答里没有地址")
			}
		}
	}

	// 三档分开答：媒体那一路没问出去 / 问出去而它说没有码流 / 都问到了。
	// 混成一档的话，「去翻这台的 ONVIF 支持范围」和「去设备上把码流配出来」
	// 就成了同一句话 —— 而这两个动作完全不同。
	if !mediaAsked {
		return ots.Verdict{Code: verdictONVIFPartial, Values: values,
			Note: "设备身份问到了（" + firstNonEmptyStr(d.Manufacturer, "?") + " " +
				firstNonEmptyStr(d.Model, "?") + "），可媒体那一路问不出 —— 几路流、什么地址，这一张答不了"}, nil
	}
	if len(profiles) == 0 {
		return ots.Verdict{Code: verdictONVIFNoProfile, Values: values,
			Note: "媒体服务答得清清楚楚：这台上一条码流都没配 —— 不是链路的问题"}, nil
	}
	return ots.Verdict{Code: verdictONVIFOK, Values: values,
		Note: describeONVIF(d, values)}, nil
}

// ── 每一步留痕：问了 / 没问出去 / 问了它回 Fault ──

type onvifTrail struct {
	values map[string]any
	items  []map[string]any
}

func (t *onvifTrail) ask(step string) {
	t.items = append(t.items, map[string]any{"step": step, "state": "asked"})
	t.flush()
}

func (t *onvifTrail) notAsked(why string, err error) {
	t.last(why, onvifErrText(err))
}

func (t *onvifTrail) faulted(why string, f *onvif.Fault) {
	t.last(why, firstNonEmptyStr(f.Reason, f.Code))
}

func (t *onvifTrail) last(why, detail string) {
	if len(t.items) == 0 {
		return
	}
	cur := t.items[len(t.items)-1]
	cur["state"] = "not-asked"
	if detail == "" {
		cur["note"] = why
	} else {
		cur["note"] = why + " · " + detail
	}
	t.flush()
}

func (t *onvifTrail) note(s string) {
	if len(t.items) > 0 {
		t.items[len(t.items)-1]["note"] = s
		t.flush()
	}
}

// flush 把这一本的账挂回结果。★ 每次改动都要挂：连不上这种在第一问就出结果的
// 走法，界面上也得看得见「哪一步没问出去」—— 否则「没问到」和「问到一切正常」
// 在界面上长得一模一样。
func (t *onvifTrail) flush() { t.values["steps"] = t.items }

// early 第一问就出不了结果时，把这一句记进问话记录并交出判定。
// ★ 记录与判定必须同源：判成「要账号」却在账上写传输错误的原文
//
//	（401 的空应答在 Go 这边长成「回的不是 SOAP 应答」），两句话各说一件小事，
//	合起来就读不懂了 —— 而这一格恰恰是现场最需要一眼看懂的。
func (t *onvifTrail) early(endpoint string, status int, err error) (any, bool) {
	if err == nil {
		return nil, false
	}
	stop := onvifEarly(t.values, endpoint, status, err)
	t.last(stop.why, stop.detail)
	return stop.v, true
}

// onvifClient 一次问一答。★ WS-Security 头每次现算：nonce 与 Created 都得是新的，
// 复用同一份摘要会被设备的时间窗挡掉 —— 那看起来就像密码错了。
type onvifClient struct {
	hc      *http.Client
	cred    *onvif.Credential
	replyAt time.Time
}

func (c *onvifClient) ask(ctx context.Context, endpoint, ns, action string) (*onvif.Node, int, error) {
	return c.send(ctx, endpoint, onvif.Call{Action: action, Body: onvif.Body(ns, action, "")})
}

func (c *onvifClient) askURI(ctx context.Context, endpoint, token string) (*onvif.Node, int, error) {
	return c.send(ctx, endpoint, onvif.StreamURICall(token))
}

func (c *onvifClient) send(ctx context.Context, endpoint string, cl onvif.Call) (*onvif.Node, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(onvif.Request(onvif.SecurityHeader(c.cred), cl.Body)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", `application/soap+xml;charset=utf-8;action="`+cl.Action+`"`)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	c.replyAt = time.Now() // ★ 偏移拿**收到应答那一刻**当基准，不是开始问话那一刻
	if rerr != nil {
		return nil, resp.StatusCode, rerr
	}
	root, perr := onvif.Parse(data)
	if perr != nil {
		return nil, resp.StatusCode, perr
	}
	// 连 Envelope 都没有：那是一页 HTML、一声不响，或者一个别的协议。
	if root.Find("Envelope") == nil {
		return nil, resp.StatusCode, errNotSOAP
	}
	return root, resp.StatusCode, nil
}

// errNotSOAP 单独立一个：「连得上」和「回的是 ONVIF」不是一件事，
// 混在一起就会把「那个端口是设备的 Web 后台」报成「设备没回应」。
var errNotSOAP = errors.New("回的不是 SOAP 应答")

// onvifStop 是第一问就出结果的那几档：判定，加上记进问话记录的那一句。
// detail 只在传输层原文真能解释时才带（401 带原文反而绕）。
type onvifStop struct {
	v      ots.Verdict
	why    string
	detail string
}

// onvifEarly 把「连不上 / 挡了 / 不是 ONVIF / 不回话」这四档分开答。
func onvifEarly(values map[string]any, endpoint string, status int, err error) onvifStop {
	text := onvifErrText(err)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		values["status"] = status
		code := "HTTP " + strconv.Itoa(status)
		values["detail"] = code
		return onvifStop{why: "设备挡了这一问", detail: code,
			v: ots.Verdict{Code: verdictONVIFAuth, Values: values,
				Note: fmt.Sprintf("设备挡了这一问（%d）—— 账号没给、密码不对，或者这个账号没开 ONVIF 权限", status)}}
	case errors.Is(err, errNotSOAP):
		values["status"] = status
		return onvifStop{why: "它回的不是 ONVIF 应答",
			v: ots.Verdict{Code: verdictONVIFNotOnvif, Values: values,
				Note: endpoint + " 连得上、也回了话，可回的不是 ONVIF 应答 —— 那个端口上是别的服务（设备的 Web 后台最常见）"}}
	case strings.Contains(text, "malformed HTTP response"):
		// 明文 POST 到一个 TLS 端口：对面递回来一条 TLS 记录。
		// ★ 这一档单独给，是因为改一个前缀就好 —— 报成「连不上」会让人去查线路。
		values["detail"] = text
		return onvifStop{why: "那个端口说的是 HTTPS",
			v: ots.Verdict{Code: verdictONVIFNotOnvif, Values: values,
				Note: endpoint + " 那个端口说的是 HTTPS：把地址前缀改成 https:// 再问一次就好，这不是故障"}}
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		values["detail"] = text
		return onvifStop{why: "等它回话超时", detail: text,
			v: ots.Verdict{Code: verdictONVIFNoRepl, Values: values,
				Note: endpoint + " 连上了却不回话 —— 端口开着，服务卡住了或者没认这一问"}}
	default:
		values["detail"] = text
		return onvifStop{why: "没问出去", detail: text,
			v: ots.Verdict{Code: verdictONVIFUnreach, Values: values,
				Note: endpoint + " 连不上 —— ONVIF 多在 80（也有 8899、2020、8080），先进设备的 Web 后台确认它开了 ONVIF"}}
	}
}

func onvifFaultVerdict(values map[string]any, f *onvif.Fault, cred *onvif.Credential) ots.Verdict {
	values["faultCode"] = f.Code
	values["faultReason"] = f.Reason
	if onvif.LooksAuthFault(f) {
		if cred.Authenticated() {
			return ots.Verdict{Code: verdictONVIFAuth, Values: values,
				Note: "设备以 Fault 挡了这一问：" + firstNonEmptyStr(f.Reason, f.Code) +
					" —— 账号给了仍被挡，很多相机把 ONVIF 账号与 Web 登录账号分开管，去它自己的用户列表里加一个"}
		}
		return ots.Verdict{Code: verdictONVIFAuth, Values: values,
			Note: "设备要账号：" + firstNonEmptyStr(f.Reason, f.Code)}
	}
	return ots.Verdict{Code: verdictONVIFFault, Values: values,
		Note: "连上也认了这个包，设备回的是 Fault：" + firstNonEmptyStr(f.Reason, f.Code) +
			" —— 这是这台不接这一问，不是密码不对"}
}

func describeONVIF(d onvif.DeviceInfo, values map[string]any) string {
	parts := []string{strings.TrimSpace(firstNonEmptyStr(d.Manufacturer, "?") + " " + firstNonEmptyStr(d.Model, "?"))}
	if d.Firmware != "" {
		parts = append(parts, "固件 "+d.Firmware)
	}
	if n, ok := values["profileCount"]; ok {
		parts = append(parts, fmt.Sprint(n)+" 路码流")
	}
	if t, ok := values["deviceTime"].(string); ok && t != "" {
		parts = append(parts, "它说现在是 "+t)
	}
	if u, ok := values["mediaUri"].(string); ok && u != "" {
		parts = append(parts, "取流地址 "+u)
	}
	return strings.Join(parts, " · ")
}

// redactONVIFURI 把取流地址里的口令摘掉。★ 地址本身要留在结果里（现场要拿它去验流），
// 但 rtsp://user:pass@host/... 里的口令一留，就等于把它送进诊断包和发给 AI 的那份文本。
func redactONVIFURI(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	name := u.User.Username()
	if name == "" {
		name = "?"
	}
	u.User = url.User(name + "（口令已隐去）")
	return u.String()
}

func onvifErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// firstNonEmptyStr 取第一个非空串；全空就返回空，不编一个填上。
func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func setIfNotEmpty(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func atoiOr(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// onvifEndpoint 允许只填主机：补上 http:// 与设备服务路径。
//
// ★ 只认 http(s)：ONVIF 是 SOAP over HTTP。放行 file://、gopher:// 这类前缀，
//
//	等于拿一个探测工具去读本地文件 —— 在拼地址这一层就当面拒掉。
func onvifEndpoint(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", ots.Errf(ots.ErrInvalidArgument, "没给 url")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", ots.Errf(ots.ErrInvalidArgument, "地址解不开：%s", in)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ots.Errf(ots.ErrInvalidArgument, "ONVIF 只走 http(s)，给的是 %q", u.Scheme)
	}
	if u.Host == "" {
		return "", ots.Errf(ots.ErrInvalidArgument, "地址里没有主机：%s", in)
	}
	u.User = nil // ★ 地址里写的 user:pass 在这一层就摘掉，不进结果也不进日志
	if u.Path == "" || u.Path == "/" {
		u.Path = onvifDevPath
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// onvifMediaEndpoint 兜底的媒体服务地址（设备没说 XAddr 时用它）。
func onvifMediaEndpoint(devURL string) string {
	u, err := url.Parse(devURL)
	if err != nil {
		return strings.TrimSuffix(devURL, onvifDevPath) + onvifMediaPath
	}
	u.Path = onvifMediaPath
	return u.String()
}

// onvifPinHost 拿设备自报的媒体地址，只取它的路径与端口，主机钉死正在问的这一台。
// 自报的地址不能照着直接去敲 —— 否则一台设备就能把探测工具支使去访问别的主机。
func onvifPinHost(devURL, xaddr string) (string, bool) {
	d, err1 := url.Parse(devURL)
	x, err2 := url.Parse(xaddr)
	if err1 != nil || err2 != nil {
		return "", false
	}
	if !strings.EqualFold(d.Hostname(), x.Hostname()) {
		return "", false
	}
	if x.Path == "" || x.Path == "/" {
		x.Path = onvifMediaPath
	}
	d.Scheme = x.Scheme // 同一台主机上 http/https 分开，跟着它报的走
	d.Host = x.Host     // 端口跟它，主机不跟
	d.Path = x.Path
	d.RawQuery, d.Fragment = "", ""
	return d.String(), true
}
