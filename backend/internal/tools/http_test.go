package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

func httpProbe(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	// 超时压到 4s：测试里不该有哪个请求真要跑满默认 8s，跑满就是哪里错了
	if _, ok := args["timeoutMs"]; !ok {
		m := map[string]any{"timeoutMs": 4000}
		for k, v := range args {
			m[k] = v
		}
		args = m
		raw, _ = json.Marshal(args)
	}
	got, err := doHTTPProbe(context.Background(), raw)
	if err != nil {
		t.Fatalf("探测本身失败：%v", err)
	}
	v, ok := got.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%#v", got)
	}
	return v
}

func Test不写协议也能填(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "https://example.com"},
		{"192.168.1.64:8080", "https://192.168.1.64:8080"},
		{"cam.local/cam/cgi", "https://cam.local/cam/cgi"},
		{"http://192.168.1.1", "http://192.168.1.1"},
		{"  https://a.test/x?y=1  ", "https://a.test/x?y=1"},
	}
	for _, tc := range cases {
		u, err := normalizeHTTPURL(tc.in)
		if err != nil {
			t.Errorf("%q: %s", tc.in, err)
			continue
		}
		if got := u.String(); got != tc.want {
			t.Errorf("%q: got %s, want %s", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "rtsp://192.168.1.64/cam", "https://", "ftp://a.test"} {
		if _, err := normalizeHTTPURL(bad); err == nil {
			t.Errorf("%q 该被拒掉", bad)
		}
	}
}

func Test口令不出现在结果里(t *testing.T) {
	// ★★ 相机 NVR 的地址十有八九带 admin:密码，还有一堆 ?user=&password=。
	//   结果会发给 AI、会进诊断包 —— 口令漏进去就是漏到别人机器上。
	u, err := normalizeHTTPURL("http://admin:S3cr3t@192.168.1.64:80/web/index.html?user=admin&password=S3cr3t&channel=1")
	if err != nil {
		t.Fatal(err)
	}
	got := redactURL(u)
	if strings.Contains(got, "S3cr3t") {
		t.Errorf("口令漏了：%s", got)
	}
	for _, keep := range []string{"192.168.1.64:80", "/web/index.html", "channel=1", "user=admin"} {
		if !strings.Contains(got, keep) {
			t.Errorf("该留下的没留下：%s（缺 %s）", got, keep)
		}
	}
	// 参数顺序和写法不许被改写：人要拿它对原始地址
	if !strings.Contains(got, "password=***") {
		t.Errorf("口令参数该打码而不是删掉：%s", got)
	}
	if strings.HasPrefix(got, "http://?") || strings.Contains(got, "@") {
		t.Errorf("userinfo 没剥干净：%s", got)
	}
}

func Test只打码口令类参数(t *testing.T) {
	q := "Password=abc&name=foo&access_token=xyz&ip=1.2.3.4&sign=deadbeef"
	got := maskSecrets(q)
	if !strings.Contains(got, "Password=***") || !strings.Contains(got, "access_token=***") ||
		!strings.Contains(got, "sign=***") {
		t.Errorf("该打的码没打：%s", got)
	}
	if !strings.Contains(got, "name=foo") || !strings.Contains(got, "ip=1.2.3.4") {
		t.Errorf("不该动的动了：%s", got)
	}
	if strings.Contains(got, "abc") || strings.Contains(got, "xyz") || strings.Contains(got, "deadbeef") {
		t.Errorf("原值还在：%s", got)
	}
}

func Test服务端时间是从首字节里减出来的(t *testing.T) {
	cases := []struct {
		name string
		st   stages
		want int64
	}{
		{"各段都齐", stages{LookupMs: 10, ConnectMs: 20, TLSMs: 30, TTFBMs: 100}, 40},
		{"连接复用后只有服务端时间", stages{TTFBMs: 50}, 50},
		{"没回首字节", stages{LookupMs: 5, ConnectMs: 100}, 0},
		{"拼不成负数就如实给零", stages{LookupMs: 900, ConnectMs: 900, TLSMs: 900, TTFBMs: 100}, 0},
	}
	for _, tc := range cases {
		if got := serverThinkMs(tc.st); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func Test认得出协议弄反了不是故障(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{errors.New(`Get "https://a.test": http: server gave HTTP response to HTTPS client`), httpWrongScheme},
		{errors.New(`Get "https://a.test": remote error: tls: first record does not look like a TLS handshake`),
			httpWrongScheme},
		// ★ 这里用 raw string 是**故意**的：Go 的 textproto 拿 %q 渲染首字节，
		// 0x16 在错误文本里是字面的 `\x16` 四个字符。写成真控制字节反而认不出来。
		{errors.New(`Get "http://a.test": net/http: HTTP/1.x transport connection broken: ` +
			`malformed HTTP response "\x15\x03\x03"`), httpWrongScheme},
		{errors.New(`Get "http://a.test": malformed HTTP status code "RTSP/1.0"`), httpNotHTTP},
		{errors.New(`Get "https://a.test": EOF`), httpNotHTTP},
		// DNS 查不到：包在 url.Error 里，classifyHTTP 得顺着 Unwrap 认出来
		{&url.Error{Op: "Get", URL: "https://a.test",
			Err: &net.DNSError{Err: "no such host", Name: "a.test", IsNotFound: true}}, tlsNameUnresolved},
	}
	// ★★ 「域名不存在」不是端口不通。归错类的后果是让人去查一个根本没坏的防火墙。
	for _, tc := range cases {
		code, note := classifyHTTP(tc.err)
		if code != tc.want {
			t.Errorf("%v: got %q, want %q", tc.err, code, tc.want)
		}
		if code != "" && note == "" {
			t.Errorf("%v: 认出了码却没给人话", tc.err)
		}
	}
}

func Test认不出来的错误就如实说认不出来(t *testing.T) {
	// [OTS-5.7]：没有对应判定码时回 unknown + 已拿到的取值，不许编一句人话
	if code, _ := classifyHTTP(errors.New("某种没见过的错")); code != "" {
		t.Errorf("不该硬认出一个码，got %s", code)
	}
	v, err := httpFail(mustURL(t, "https://a.test"), "GET", nil, stages{}, 12,
		errors.New("某种没见过的错"))
	if err != nil {
		t.Fatal(err)
	}
	ver, ok := v.(ots.Verdict)
	if !ok || ver.Code != ots.CodeUnknown {
		t.Fatalf("got %#v", v)
	}
	if ver.Values["detail"] == nil {
		t.Error("unknown 也要带上已经拿到的东西")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := normalizeHTTPURL(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func Test探一台真服务器(t *testing.T) {
	var finalHits int
	// 每一跳都慢一点点：回环上千分位全是 0，不加这点等待就**测不出**
	// 「分段耗时是累加的」这条 —— 那种怎么都能过的测试等于没测。
	slow := func(d time.Duration) { time.Sleep(d) }
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		finalHits++
		slow(30 * time.Millisecond)
		w.Header().Set("Server", "netkit-test")
		fmt.Fprintf(w, "这一段的正文不该被读走")
	})
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop2", http.StatusFound)
	})
	mux.HandleFunc("/loop2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	// 一条三跳链：建连接只发生在第一跳，后两跳复用同一条
	mux.HandleFunc("/s1", func(w http.ResponseWriter, r *http.Request) {
		slow(12 * time.Millisecond)
		http.Redirect(w, r, "/s2", http.StatusFound)
	})
	mux.HandleFunc("/s2", func(w http.ResponseWriter, r *http.Request) {
		slow(12 * time.Millisecond)
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusMovedPermanently)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("跟完整条重定向链", func(t *testing.T) {
		before := finalHits
		v := httpProbe(t, map[string]any{"url": srv.URL})
		// ★ 问到 200 就够了，**不该再要一遍**：正文一行都不读，也不许重取
		if n := finalHits - before; n != 1 {
			t.Errorf("终点被问了 %d 次，应该是 1 次", n)
		}
		if v.Code != httpOK {
			t.Fatalf("got %s（%s）", v.Code, v.Note)
		}
		if v.Values["status"] != 200 {
			t.Errorf("status got %v", v.Values["status"])
		}
		hs, _ := v.Values["redirects"].([]hop)
		if len(hs) != 2 {
			t.Fatalf("应该看见两跳，got %d：%+v", len(hs), v.Values["redirects"])
		}
		if hs[0].Status != 301 || !strings.HasSuffix(hs[0].Location, "/final") {
			t.Errorf("第一跳 %+v", hs[0])
		}
		if v.Values["redirectCount"] != 1 {
			t.Errorf("跳数 got %v", v.Values["redirectCount"])
		}
		if v.Values["server"] != "netkit-test" {
			t.Errorf("Server 头 got %v", v.Values["server"])
		}
		tm, _ := v.Values["timings"].(map[string]any)
		if tm == nil {
			t.Fatal("结果里该有 timings")
		}
		// ★ 回环地址上解析/连接都是 0ms 级，这里钉的是**别把没发生的段编出来**：
		//   真花了时间在服务端，就得看得见它在 serverMs 上，不是摊到网络三段里。
		if tm["ttfbMs"].(int64) < 25 || tm["serverMs"].(int64) < 25 {
			t.Errorf("服务端那 30ms 该落在 ttfb/server 上：%+v", tm)
		}
		if tm["totalMs"].(int64) < tm["ttfbMs"].(int64) {
			t.Errorf("总耗时不该小于首字节：%+v", tm)
		}
	})

	// ★★ 复用连接时**只报最后一跳**是这一页最容易犯的错：连接在第一跳建的，
	// 后面两跳的 connect/tls 都是 0，于是前面花掉的时间凭空蒸发，
	// 剩下的全被算到「服务端想」头上 —— 正好把要分的两头弄反。
	t.Run("复用连接时前面几跳的时间不丢", func(t *testing.T) {
		v := httpProbe(t, map[string]any{"url": srv.URL + "/s1"})
		if v.Code != httpOK {
			t.Fatalf("got %s（%s）", v.Code, v.Note)
		}
		if rc := v.Values["redirectCount"]; rc != 2 {
			t.Fatalf("该跳两次，got %v", rc)
		}
		tm, _ := v.Values["timings"].(map[string]any)
		if tm == nil {
			t.Fatal("没有 timings")
		}
		// 三跳各等 12/12/30ms：只留最后一跳的话这里会是 30
		if tm["ttfbMs"].(int64) < 50 {
			t.Errorf("分段耗时没按整条链累加：%+v", tm)
		}
		if tm["serverMs"].(int64) < 40 {
			t.Errorf("三跳都是服务端在等，serverMs 该占大头：%+v", tm)
		}
		if tm["totalMs"].(int64) < tm["ttfbMs"].(int64) {
			t.Errorf("总耗时小于首字节，说明哪里重复计了：%+v", tm)
		}
	})

	t.Run("只看第一跳", func(t *testing.T) {
		v := httpProbe(t, map[string]any{"url": srv.URL, "maxRedirects": 0})
		// ★ 停在第一跳是**按参数办事**，不是绕圈，码不能混
		if v.Code != httpRedirect {
			t.Fatalf("got %s, want %s", v.Code, httpRedirect)
		}
		if !strings.Contains(fmt.Sprint(v.Values["reason"]), "maxRedirects=0") {
			t.Errorf("该说清楚为什么停：%v", v.Values["reason"])
		}
	})

	t.Run("绕圈", func(t *testing.T) {
		v := httpProbe(t, map[string]any{"url": srv.URL + "/loop"})
		if v.Code != httpRedirectLoop {
			t.Fatalf("got %s", v.Code)
		}
	})

	t.Run("状态码是判定不是错误", func(t *testing.T) {
		if got := httpProbe(t, map[string]any{"url": srv.URL + "/gone"}); got.Code != httpClientError {
			t.Errorf("404 got %s", got.Code)
		}
		got := httpProbe(t, map[string]any{"url": srv.URL + "/boom"})
		if got.Code != httpServerError {
			t.Errorf("503 got %s", got.Code)
		}
		if got.Values["status"] != 503 {
			t.Errorf("状态码得带回去，got %v", got.Values["status"])
		}
	})

	t.Run("端口关着是判定", func(t *testing.T) {
		v := httpProbe(t, map[string]any{"url": "http://127.0.0.1:1/x"})
		if v.Code != verdictClosed {
			t.Fatalf("got %s", v.Code)
		}
	})
}

func TestHTTPS顺带把证书判了(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	v := httpProbe(t, map[string]any{"url": srv.URL})
	// ★ 证书坏**不挡结果**：状态码照给。挡住的话就看不到「它其实活着、只是证书坏了」
	if v.Code != httpOK {
		t.Fatalf("got %s（%s）", v.Code, v.Note)
	}
	brief, _ := v.Values["tls"].(map[string]any)
	if brief == nil {
		t.Fatal("HTTPS 结果里该有一块 tls")
	}
	if brief["protocol"] == "" || brief["cipherSuite"] == "" {
		t.Errorf("协议与套件该带上：%+v", brief)
	}
	if brief["trusted"] != false || brief["selfSigned"] != true {
		t.Errorf("httptest 这张是自签且不受信：%+v", brief)
	}
	if brief["verdict"] != certSelfSigned {
		t.Errorf("got %v, want %s", brief["verdict"], certSelfSigned)
	}
	if !strings.Contains(v.Note, "证书") {
		t.Errorf("note 该带一句证书有问题：%s", v.Note)
	}
}

func Test超时带上已经走到的那段(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	v := httpProbe(t, map[string]any{"url": srv.URL, "timeoutMs": 500})
	if v.Code != httpTimeout {
		t.Fatalf("got %s", v.Code)
	}
	tm, _ := v.Values["timings"].(map[string]any)
	if tm == nil || tm["connectMs"] == nil {
		t.Fatalf("超时也要带回分段耗时：%+v", v.Values)
	}
	if !strings.Contains(fmt.Sprint(v.Values["detail"]), "deadline") {
		t.Errorf("原始错误该留着：%v", v.Values["detail"])
	}
}
