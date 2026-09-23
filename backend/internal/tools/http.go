package tools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// net.http.probe —— 网页/接口探测：状态码、**分段耗时**、重定向链。
//
// ★★ 到这里，「网页打不开」这条链的四段就齐了：解析（net.dns.query）→
//
//	连接（net.tcp.probe）→ 证书（net.tls.check）→ 应用层（这个）。
//	四段的处理办法完全不同，浏览器却只给一句「无法访问此网站」。
//
// ★ 分段耗时才是这一页的价值：「很慢」要分清卡在 解析 / 连接 / TLS /
//
//	还是**服务端到首字节**。前三段是网络的事，最后一段是应用的事 ——
//	只有一个总耗时的话，分不出该找网络组还是找应用组。
var httpProbeTool = ots.Tool{
	Name:  "net.http.probe",
	Class: ots.ClassRead,
	Summary: "请求一个 HTTP(S) 地址：给出状态码、完整重定向链（每一跳的回码、Location、各花多久），" +
		"并把最后一跳的耗时拆成 解析 / 连接 / TLS / 等首字节 四段；HTTPS 顺带给出协商到的协议版本与证书结论。" +
		"★ 用来分清「打不开」和「很慢」各卡在哪一段：前三段慢是网络的事，等首字节慢是服务端的事。" +
		"★ 证书照常判，但**不因证书坏就不给结果**；不读响应正文。属于只读。",
	Schema: json.RawMessage(`{
		  "type": "object",
		  "additionalProperties": false,
		  "required": ["url"],
		  "properties": {
		    "url": {"type": "string",
		      "description": "完整地址，或 host(:port)。不写协议时默认按 https 试；地址里的账号密码不会回显（结果和日志里都打码）。"},
		    "method": {"type": "string", "enum": ["GET", "HEAD"],
		      "description": "默认 GET。不少设备对 HEAD 答得不规范，除非专门要查它，用 GET。"},
		    "maxRedirects": {"type": "integer", "minimum": 0, "maximum": 20,
		      "description": "最多跟几跳，默认 10。填 0 表示只看第一跳 —— 想查「它 301 到哪儿」就填 0。"},
		    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 30000,
		      "description": "整条请求（含跟随重定向）最多等多久，默认 8000。"}
		  }
		}`),
	Invoke: doHTTPProbe,
}

// HTTP 探测的判定码。★ 4xx/5xx 是**查出来的状态**不是工具失败（[OTS-6.2]）：
// 拿到 502 也是这一跳问成功了，得带着状态码和分段耗时回来。
const (
	httpOK           = "http-ok" // 2xx
	httpRedirect     = "http-redirect"
	httpClientError  = "http-client-error" // 4xx：地址 / 权限 / 请求本身的事
	httpServerError  = "http-server-error" // 5xx：服务自己的事
	httpRedirectLoop = "http-redirect-loop"
	httpTimeout      = "http-timeout" // 整体超时；哪一段没走完看得见的都在 values 里
	httpNotHTTP      = "not-http"     // 这个端口回的不是 HTTP
	httpWrongScheme  = "wrong-scheme" // 明文和 HTTPS 弄反了 —— 改个前缀就好，不是故障
	httpTLSFailed    = "tls-handshake-failed"
)

// tlsRecordPrefix 是 TLS 记录头渲染进 %q 之后的**字面**写法（0x14~0x17 四类记录）。
// 拿真控制字节去比永远匹配不上：文本里那四个字符才是 Go 给出来的东西。
const tlsRecordPrefix = `"\x1`

type httpArgs struct {
	URL          string `json:"url"`
	Method       string `json:"method,omitempty"`
	MaxRedirects *int   `json:"maxRedirects,omitempty"`
	TimeoutMS    int    `json:"timeoutMs,omitempty"`
}

// hop 是重定向链上的一跳。
type hop struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
	Ms       int64  `json:"ms"`
}

// stages 是一跳里成功走到的那几段各自花了多久。
//
// ★ 走的是连接池，**复用上的那一段会是 0**（比如第二跳不用再解析、不用再握手）。
//
//	0 在这里是「这一跳没花这段」，不是「这一段坏了」，界面得按这个意思写。
type stages struct {
	LookupMs  int64  `json:"lookupMs"`
	ConnectMs int64  `json:"connectMs"`
	TLSMs     int64  `json:"tlsMs"`
	TTFBMs    int64  `json:"ttfbMs"`
	Remote    string `json:"remote,omitempty"`
}

// addStages 把一跳累加进整条链。
//
// ★★ 报的必须是**整条链**的累加，不能只报最后一跳：连接一旦被复用，后面每一跳的
//
//	连接与 TLS 都是 0，而当初建那条连接花掉的几百毫秒是真实花掉了的 ——
//	只报最后一跳就会把它弄丢，于是全部剩余时间都被算到「服务端自己想」头上，
//	正好把这一页要分的两头（网络 / 应用）弄反。
func addStages(dst, src stages) stages {
	dst.LookupMs += src.LookupMs
	dst.ConnectMs += src.ConnectMs
	dst.TLSMs += src.TLSMs
	dst.TTFBMs += src.TTFBMs
	if src.Remote != "" {
		dst.Remote = src.Remote
	}
	return dst
}

// serverThinkMs 是**服务端自己想的时间**：首字节里扣掉网络那三段。
//
// ★ 四个数并排放着不解决问题，现场要的是那一句「慢在网络还是在应用」。
//
//	ttfb 是从请求起算的（含前三段），所以要减；减成负数说明这几段拼不起来
//	（连接复用、内部重试），那就如实给 0，不编一个负数出来。
func serverThinkMs(st stages) int64 {
	if st.TTFBMs == 0 {
		return 0 // 压根没回首字节，谈不上"服务端想多久"
	}
	n := st.TTFBMs - st.LookupMs - st.ConnectMs - st.TLSMs
	if n < 0 {
		return 0
	}
	return n
}

func doHTTPProbe(ctx context.Context, raw json.RawMessage) (any, error) {
	var a httpArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	cur, err := normalizeHTTPURL(a.URL)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	method := strings.ToUpper(a.Method)
	if method == "" {
		method = http.MethodGet
	}
	maxHops := 10
	if a.MaxRedirects != nil {
		maxHops = *a.MaxRedirects
	}
	timeout := 8 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var remote remoteAddr
	// 重定向**自己跟**，不用 http.Client 的自动跟随：自动跟随会把中间每一跳吃掉，
	// 而现场要看的恰恰是「它 301 到了哪儿」—— http 没跳到 https、
	// 跳进了一个内网地址、绕回自己，是三种完全不同的问题。
	client := &http.Client{
		Transport:     httpClientTransport(&remote),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	var (
		hops   []hop
		total  int64
		st     stages
		seen   = map[string]bool{}
		curURL = cur
	)
	for hopNo := 0; ; hopNo++ {
		seen[curURL.String()] = true
		var hs stages
		hopStart := time.Now()
		resp, rerr := httpOnce(ctx, client, method, curURL, &hs)
		ms := time.Since(hopStart).Milliseconds()
		hs.Remote = remote.get()
		// ★ 累加，而不是覆盖：只留最后一跳的话，前面跳掉在连接上的时间会凭空消失
		st = addStages(st, hs)
		if rerr != nil {
			return httpFail(curURL, method, hops, st, total+ms, rerr)
		}
		loc := resp.Header.Get("Location")
		hops = append(hops, hop{URL: redactURL(curURL), Status: resp.StatusCode, Location: loc, Ms: ms})
		total += ms
		values := httpValues(curURL, method, resp, hops, st, total)
		resp.Body.Close() // ★ 正文一行都不读：只问「它在不在、回什么码」，不下载内容

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return ots.Verdict{Code: httpOK, Values: values, Note: httpNote(values)}, nil

		case resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "":
			if hopNo >= maxHops {
				// ★ 这不是绕圈，是人让停在第一跳。混成一个码，界面就会往「服务配坏了」查
				values["reason"] = fmt.Sprintf("跟到第 %d 跳还在跳，按 maxRedirects=%d 停下", hopNo+1, maxHops)
				return ots.Verdict{Code: httpRedirect, Values: values,
					Note: "重定向没跟完 —— 全链见 redirects"}, nil
			}
			next, uerr := curURL.Parse(loc)
			if uerr != nil || (next.Scheme != "http" && next.Scheme != "https") {
				values["reason"] = "Location 指向的不是 HTTP(S) 地址：" + loc
				return ots.Verdict{Code: httpRedirect, Values: values,
					Note: "它让跳去一个不是 HTTP(S) 的地方"}, nil
			}
			if seen[next.String()] {
				values["reason"] = "Location 指回了这一链里已经去过的地址"
				return ots.Verdict{Code: httpRedirectLoop, Values: values,
					Note: "重定向绕圈：跳到 " + redactURL(next) + " 之前就去过一次"}, nil
			}
			curURL = next
			continue

		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			return ots.Verdict{Code: httpClientError, Values: values, Note: httpNote(values)}, nil

		case resp.StatusCode >= 500:
			return ots.Verdict{Code: httpServerError, Values: values, Note: httpNote(values)}, nil

		default:
			// 3xx 没给 Location、1xx，以及没见过的码 —— 如实带回状态，不硬编一个码
			values["reason"] = fmt.Sprintf("状态码 %d 不在常规区间（3xx 没带 Location 也归这里）", resp.StatusCode)
			return ots.Verdict{Code: httpRedirect, Values: values,
				Note: "对方回了 " + resp.Status + "，没有可跟的去向"}, nil
		}
	}
}

// httpClientTransport 造一个探测用的传输层。
//
// ★ MinVersion 放到 TLS1.0、证书不硬拦：这两条都是为了**让老设备答得上话**，
//
//	答上了才有得判。弱版本和坏证书都会作为判定报回去，不是被偷偷放行。
//
// remote 记的是**这次真的连上了哪个地址**：域名两族都有记录时，
// 这一点决定人是往 v4 查还是往 v6 查，光看 URL 里那个域名看不出来。
func httpClientTransport(remote *remoteAddr) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	d := &net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err == nil {
			remote.set(c.RemoteAddr().String())
		}
		return c, err
	}
	return tr
}

// remoteAddr 是个带锁的字符串：拨号可能在别的 goroutine 上写，主 goroutine 读。
type remoteAddr struct {
	mu sync.Mutex
	s  string
}

func (r *remoteAddr) set(s string) {
	r.mu.Lock()
	r.s = s
	r.mu.Unlock()
}

func (r *remoteAddr) get() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s
}

// httpOnce 发一次请求（不跟随重定向），四段耗时写进 st。
func httpOnce(ctx context.Context, client *http.Client, method string, u *url.URL, st *stages) (*http.Response, error) {
	var dnsStart, connStart, tlsStart time.Time
	reqStart := time.Now()
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { st.LookupMs = time.Since(dnsStart).Milliseconds() },
		ConnectStart:      func(string, string) { connStart = time.Now() },
		ConnectDone:       func(_, _ string, err error) { st.ConnectMs = time.Since(connStart).Milliseconds() },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { st.TLSMs = time.Since(tlsStart).Milliseconds() },
		// ★ 首字节从**这次请求**起算：服务端想多久就是这一段减去前三段，
		//   从连接起算会把网络时间算进应用头上。
		GotFirstResponseByte: func() { st.TTFBMs = time.Since(reqStart).Milliseconds() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// 读掉极小一点正文，连接才能干净地还进池子；上限 1KB，不往下拖设备的东西。
	_, _ = io.CopyN(io.Discard, resp.Body, 1024)
	return resp, nil
}

// httpTimings 把分段耗时摊平成结果里的一块。★ 只有查得到状态码的那条路用得上，
// 失败那条也带同一块，人才能看出「是走到哪一段断的」。
func httpTimings(st stages, totalMs int64) map[string]any {
	return map[string]any{"lookupMs": st.LookupMs, "connectMs": st.ConnectMs,
		"tlsMs": st.TLSMs, "ttfbMs": st.TTFBMs, "serverMs": serverThinkMs(st), "totalMs": totalMs}
}

func httpValues(u *url.URL, method string, resp *http.Response, hops []hop, st stages, totalMs int64) map[string]any {
	v := map[string]any{
		"url":       redactURL(u),
		"method":    method,
		"status":    resp.StatusCode,
		"proto":     resp.Proto,
		"timings":   httpTimings(st, totalMs),
		"redirects": hops,
	}
	if st.Remote != "" {
		v["remote"] = st.Remote
	}
	if len(hops) > 1 {
		v["redirectCount"] = len(hops) - 1
	}
	if s := resp.Header.Get("Server"); s != "" {
		v["server"] = s
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		v["contentType"] = ct
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		v["contentLength"] = cl
	}
	if resp.TLS != nil {
		v["tls"] = tlsBrief(time.Now(), resp.TLS, u.Hostname())
	}
	return v
}

// httpFail 把「没问到状态码」的那一类分门别类。
//
// ★ 这里守 [OTS-6.2]：连不上、被拒、超时、回了不是 HTTP 的东西，**都是查出来的状态**，
//
//	一律回判定并带上已经拿到的分段耗时；只有参数不对才回错误。
func httpFail(u *url.URL, method string, hops []hop, st stages, totalMs int64, err error) (any, error) {
	values := map[string]any{
		"url": redactURL(u), "method": method,
		"timings": httpTimings(st, totalMs),
	}
	if len(hops) > 0 {
		values["redirects"] = hops
	}
	if st.Remote != "" {
		values["remote"] = st.Remote
	}
	values["detail"] = err.Error()
	code, note := classifyHTTP(err)
	if code == "" {
		return ots.Unknown(values), nil
	}
	return ots.Verdict{Code: code, Values: values, Note: note + "（" + redactURL(u) + "）"}, nil
}

// classifyHTTP 认错误来自链上的哪一段。认不出来回空串，调用方如实给 unknown。
func classifyHTTP(err error) (string, string) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return httpTimeout, "整条请求超时 —— 哪一段没走完看 timings，全 0 说明连上就没回过话"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return httpTimeout, "连接或读取超时"
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsNotFound {
			return tlsNameUnresolved, de.Name + " 解析不到地址 —— 还没到连接那一步"
		}
		return verdictUnreachable, "DNS 没能给出地址（" + de.Err + "），先换台服务器问一遍"
	}
	if c := classify(err); c != "" {
		switch c {
		case verdictClosed:
			return verdictClosed, "端口关着（对方明确拒绝）—— 这个端口上没有 HTTP 服务"
		case verdictFiltered:
			return verdictFiltered, "没有任何回应 —— 分不清端口是关着还是被静默丢了"
		}
	}
	s := err.Error()
	switch {
	// ★ 这两种不是故障，是**前缀写反了**：不点破，人会去查一个根本没坏的防火墙。
	// 下面比的是**字面**反斜杠：Go 的 textproto 用 %q 渲染首字节，TLS 记录的 0x16 到了错误
	// 文本里就是 `\x16` 这四个 ASCII 字符，不是真控制字节 —— 拿真字节去比永远匹配不上。
	case strings.Contains(s, "server gave HTTP response to HTTPS client"):
		return httpWrongScheme, "这个端口是明文 HTTP，地址要用 http:// 开头"
	case strings.Contains(s, "first record does not look like a TLS handshake"),
		strings.Contains(s, "http: server gave HTTP response"):
		return httpWrongScheme, "这个端口不谈 TLS，把地址改成 http:// 再试"
	case strings.Contains(s, "transport connection broken") && strings.Contains(s, tlsRecordPrefix),
		strings.Contains(s, "malformed HTTP response "+tlsRecordPrefix):
		return httpWrongScheme, "这个端口只在 TLS 后面说话，把地址改成 https:// 再试"
	case strings.Contains(s, "malformed HTTP"), strings.Contains(s, "malformed HTTP status"),
		strings.Contains(s, "unsupported protocol scheme"):
		return httpNotHTTP, "这个端口回的不是 HTTP —— 多半是 RTSP、RTMP、私有协议或设备管理口"
	case strings.Contains(s, "remote error: tls:"):
		return httpTLSFailed, "TLS 握手被对方拒了，原因见 detail"
	case errors.Is(err, io.EOF), strings.Contains(s, "EOF"):
		return httpNotHTTP, "话没说完就被断开 —— 它可能不是 HTTP 服务，或要求客户端证书"
	}
	return "", ""
}

func httpNote(v map[string]any) string {
	st, _ := v["timings"].(map[string]any)
	ms := func(k string) string {
		n, _ := st[k].(int64)
		return fmt.Sprintf("%d", n)
	}
	note := fmt.Sprintf("%s %s → %v", v["method"], v["url"], v["status"])
	if rc, ok := v["redirectCount"].(int); ok && rc > 0 {
		note += fmt.Sprintf("（中间跳了 %d 次）", rc)
	}
	note += fmt.Sprintf("，总耗时 %sms：解析 %s + 连接 %s + TLS %s + 等回话 %s（其中服务端自己想 %s）",
		ms("totalMs"), ms("lookupMs"), ms("connectMs"), ms("tlsMs"), ms("ttfbMs"), ms("serverMs"))
	if t, ok := v["tls"].(map[string]any); ok {
		if code, _ := t["verdict"].(string); code != "" && code != certOK {
			note += "；证书有问题（见 tls.verdict）"
		}
	}
	return note
}

// tlsBrief 把这次 HTTPS 连接上的证书判一遍，交给 values 里单独一块。
// ★ 页面通了 ≠ 证书没问题：浏览器会拦的东西我们照样判出来，只是不让它挡住状态码。
func tlsBrief(now time.Time, cs *tls.ConnectionState, host string) map[string]any {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil
	}
	leaf := cs.PeerCertificates[0]
	assess := assessTLS(now, leaf, host, cs.Version, 14, verifyChain(now, leaf, host))
	out := map[string]any{
		"protocol":      tls.VersionName(cs.Version),
		"cipherSuite":   tls.CipherSuiteName(cs.CipherSuite),
		"subject":       certName(leaf.Subject),
		"issuer":        certName(leaf.Issuer),
		"notAfter":      leaf.NotAfter.Format(time.RFC3339),
		"daysLeft":      assess.DaysLeft,
		"verdict":       assess.Code,
		"hostnameMatch": assess.HostnameOK,
		"trusted":       assess.Trusted,
		"selfSigned":    assess.SelfSigned,
		"weakProtocol":  assess.WeakProtocol,
	}
	if len(assess.Reasons) > 0 {
		out["reason"] = strings.Join(assess.Reasons, "；")
	}
	return out
}

// normalizeHTTPURL 宽进：现场从浏览器地址栏、别家文档里拷出来的写法五花八门。
// 不写协议默认 https，`192.168.1.64:8080`、`cam.local/cam` 这种没有协议的都认。
func normalizeHTTPURL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("没给地址")
	}
	if !strings.Contains(s, "://") {
		// 只写了 host 或 host:port 或 host/path —— 补上默认协议
		s = "https://" + strings.TrimPrefix(s, "/")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("看不懂地址 %q：%s", redactString(s), err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("只支持 http/https，给的是 %q。RTSP 流请用 media.rtsp.probe", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("地址里没有主机名：%q", s)
	}
	return u, nil
}

// redactURL 结果和日志里能出现的只有这个：去掉凭据、口令类参数打码。
//
// ★★ 凭据不进结果是硬规矩（结果会发给 AI、会进诊断包）。而相机、NVR 的地址里
//
//	带 admin:密码、还有一堆 ?user=&password= 的写法 —— 不处理就等于把口令抄在报告上。
func redactURL(u *url.URL) string {
	cp := *u
	cp.User = nil
	cp.RawQuery = maskSecrets(cp.RawQuery)
	cp.Opaque = ""
	return cp.String()
}

func redactString(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return redactURL(u)
}

// secretParams 是名字一看就是口令的参数。整名匹配、大小写不敏感。
var secretParams = []string{
	"password", "passwd", "pwd", "pass", "key", "secret", "token", "apikey", "api_key",
	"access_token", "accesstoken", "signature", "sign", "auth", "credential", "session",
}

func maskSecrets(q string) string {
	if q == "" {
		return q
	}
	// 手工切而不是走 url.Values：Values.Encode() 会按 key 重排并改写编码，
	// 而这一串是要拿去和原始地址对得上的，顺序和写法不能变。
	var out []string
	for _, pair := range strings.Split(q, "&") {
		k, _, found := strings.Cut(pair, "=")
		if found && isSecretParam(k) {
			out = append(out, k+"=***")
			continue
		}
		out = append(out, pair)
	}
	return strings.Join(out, "&")
}

func isSecretParam(k string) bool {
	lower := strings.ToLower(strings.TrimSpace(k))
	for _, s := range secretParams {
		if lower == s {
			return true
		}
	}
	return false
}
