package tools

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// hlsFake 是一个可拨的假 HLS 平台。
//
// ★ 窗口是「第 n 次问清单」的函数：往前挪的直播、卡住不动的直播，
//
//	在同一个对象上只是这条函数写成什么样子。
type hlsFake struct {
	srv       *httptest.Server
	hits      atomic.Int32 // 被问过几次清单
	segHits   atomic.Int32 // 被问过几次分片
	rangeSeen atomic.Value // 分片请求带过来的 Range 头
	authOK    func(r *http.Request) bool
	playlist  func(n int) string
	segStatus map[string]int // 某个分片回指定状态（模拟「清单还点着、源上没了」）
	segBody   func(uri string) []byte
	delay     time.Duration
}

func newHLSFake() *hlsFake {
	f := &hlsFake{segStatus: map[string]int{}, authOK: func(*http.Request) bool { return true }}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *hlsFake) url(path string) string { return f.srv.URL + path }

func (f *hlsFake) serve(w http.ResponseWriter, r *http.Request) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if !f.authOK(r) {
		w.Header().Set("www-authenticate", "Basic realm=\"x\"")
		w.WriteHeader(401)
		// ★ 真有这么干的登录页：状态码是 401，正文里却嵌着一行 "#EXTM3U"。
		//   只看内容不看状态码，就会把一张登录页当成空清单往下走。
		fmt.Fprint(w, "<html>请先登录 admin/s3cr3tpw</html><!--#EXTM3U-->")
		return
	}
	if strings.HasSuffix(r.URL.Path, ".m3u8") {
		n := int(f.hits.Add(1))
		body := f.playlist(n)
		if body == "" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("content-type", "application/vnd.apple.mpegurl")
		fmt.Fprint(w, body)
		return
	}
	// 分片
	f.segHits.Add(1)
	f.rangeSeen.Store(r.Header.Get("Range"))
	if st := f.segStatus[r.URL.Path]; st != 0 {
		w.WriteHeader(st)
		return
	}
	if !strings.Contains(r.URL.Path, ".m4s") {
		w.WriteHeader(404)
		return
	}
	body := f.segBody
	if body == nil {
		body = func(string) []byte { return make([]byte, 60000) }
	}
	w.Header().Set("content-type", "video/mp2t")
	_, _ = w.Write(body(r.URL.Path))
}

// liveWindow 给出「第 n 次问」时的直播窗口：序号每次往前推 3 片。
func liveWindow(n int) string {
	var b strings.Builder
	seq := 100 + 3*(n-1)
	b.WriteString("#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n")
	fmt.Fprintf(&b, "#EXT-X-MEDIA-SEQUENCE:%d\n", seq)
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&b, "#EXTINF:6.000,\nseg%d.m4s\n", seq+i)
	}
	return b.String()
}

func callHLS(t *testing.T, args map[string]any) (ots.Verdict, string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hlsProbeTool.Invoke(t.Context(), raw)
	if err != nil {
		t.Fatalf("这一问本该出判定，却报了错：%s", err)
	}
	v, ok := got.(ots.Verdict)
	if !ok {
		t.Fatalf("回来的不是判定：%T", got)
	}
	blob, _ := json.Marshal(v)
	return v, string(blob)
}

func Test拉一路在往前挪的直播(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = liveWindow
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8"), "watchMs": 200})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s，想要 %s（整包：%s）", v.Code, verdictHLSOK, blob)
	}
	if v.Values["windowAdvanced"] != true {
		t.Errorf("窗口没判成「挪了」：%v", v.Values["windowAdvanced"])
	}
	if v.Values["isLive"] != true {
		t.Errorf("直播被认成了点播")
	}
	if kb, _ := v.Values["bitrateKbps"].(int); kb <= 0 {
		t.Errorf("没估出码率：%v", v.Values["bitrateKbps"])
	}
	// 抽查最老/中间/最新三处里的两片，至少要取到 2 片
	rows, _ := v.Values["sampled"].([]map[string]any)
	if len(rows) < 2 {
		t.Fatalf("抽查记录只剩 %d 条", len(rows))
	}
	if !strings.Contains(v.Note, "往前挪") {
		t.Errorf("那句账没说出「窗口在往前挪」：%s", v.Note)
	}
	if !strings.Contains(v.Note, "分片") {
		t.Errorf("真取了分片，那句账却只字不提：%s", v.Note)
	}
}

func Test清单在但窗口一片没换(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return liveWindow(1) } // 死的：永远那三片
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/dead/index.m3u8"), "watchMs": 200})
	if v.Code != verdictHLSStalled {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSStalled, blob)
	}
	if v.Values["windowAdvanced"] != false {
		t.Errorf("windowAdvanced = %v，应该明说没挪", v.Values["windowAdvanced"])
	}
	if s, _ := v.Values["stuckOn"].(string); !strings.Contains(s, "seg102.m4s") {
		t.Errorf("没说清卡在最后那一片上：%v", v.Values["stuckOn"])
	}
	if f.hits.Load() < 2 {
		t.Errorf("只问了 %d 次清单就说人卡住了 —— 一次都算不上「不动」", f.hits.Load())
	}
}

func Test不填观看窗口就不说卡没卡(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return liveWindow(1) }
	// watchMs=0 是「特意不看」：点播、或者不想多等
	v, _ := callHLS(t, map[string]any{"url": f.url("/hls/vod/index.m3u8"), "watchMs": 0})
	if _, has := v.Values["windowAdvanced"]; has {
		t.Errorf("没问的事被写成了结论：%v", v.Values["windowAdvanced"])
	}
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s —— 只拉一次时不该扯上卡不卡", v.Code)
	}
	if f.hits.Load() != 1 {
		t.Errorf("说了不看还拉了 %d 次", f.hits.Load())
	}
}

func Test清单还点着的分片源上没有了(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return liveWindow(1) }
	f.segStatus["/hls/cam1/seg102.m4s"] = 404
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSSegMiss {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSSegMiss, blob)
	}
	if !strings.Contains(v.Note, "404") {
		t.Errorf("那句没说清是哪一片、回什么：%s", v.Note)
	}
	// ★ 判定与账同源：说「取不到」的时候，那一条记录必须真的挂在 sampled 里
	if !strings.Contains(blob, `"httpStatus":404`) {
		t.Errorf("抽查记录里找不到那条 404：%s", blob)
	}
	// ★ 「哪一片」是一个能直接显示的字符串，不是一整行对象：界面那一格按文本读，
	//   给它对象就渲染成一坨，等于把已经问到的东西又变成看不见的。
	if which, ok := v.Values["missingSegment"].(string); !ok || !strings.Contains(which, "seg102.m4s") {
		t.Errorf("取不到的那一片没给出来（想要 seg102.m4s）：%v", v.Values["missingSegment"])
	}
	if d, has := v.Values["detail"]; has {
		if _, isStr := d.(string); !isStr {
			t.Errorf("detail 这一格只能是原文错误那句文本，给的是 %T", d)
		}
	}
}

// Test回200但一个字节都没有不算取到 —— BYTERANGE 指到文件外面、平台截了个空段，
// 播放器都是起不来；写成「取到了」等于把这一片从嫌疑名单里划掉。
func Test回200但一个字节都没有不算取到(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return liveWindow(1) }
	f.segBody = func(uri string) []byte {
		if strings.HasSuffix(uri, "seg101.m4s") {
			return nil // 空的：状态 200，正文一个字节都没有
		}
		return make([]byte, 60000)
	}
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8"),
		"watchMs": 0, "sampleSegments": 3})
	if v.Code != verdictHLSSegMiss {
		t.Fatalf("空的一片被当成取到了，判定 = %s（%s）", v.Code, blob)
	}
	if !strings.Contains(v.Note, "0 字节") {
		t.Errorf("那句没说清是空的：%s", v.Note)
	}
	for _, raw := range v.Values["sampled"].([]map[string]any) {
		if raw["bytes"] == int64(0) && raw["ok"] == true {
			t.Errorf("0 字节那片还是 ok：%v", raw)
		}
	}
}

func Test空清单是还没推上来(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:0\n"
	}
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/none/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSEmpty {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSEmpty, blob)
	}
	if v.Values["segmentCount"] != 0 {
		t.Errorf("片数没写成 0：%v", v.Values["segmentCount"])
	}
	if f.segHits.Load() != 0 {
		t.Errorf("一片都没有还去取了 %d 次分片", f.segHits.Load())
	}
}

func Test实测分片比承诺的长(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:9\n" +
			"#EXTINF:6.000,\nseg9.m4s\n#EXTINF:14.500,\nseg10.m4s\n"
	}
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/long/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSTargetOver {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSTargetOver, blob)
	}
	if v.Values["longestSegmentSec"] != 14.5 {
		t.Errorf("最长那片记成了 %v", v.Values["longestSegmentSec"])
	}
	if !strings.Contains(v.Note, "缓冲") {
		t.Errorf("那句没说到人会撞上的现象：%s", v.Note)
	}
}

func Test差一点点不算超承诺(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		// 6.2 / 6 = 1.033，在 5% 容差里：各家编码器都会超一点点，判成坏就是狼来了
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:9\n" +
			"#EXTINF:6.200,\nseg9.m4s\n"
	}
	v, _ := callHLS(t, map[string]any{"url": f.url("/hls/near/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s —— 容差内的偏差被判成了毛病", v.Code)
	}
}

func Test要账号才给清单(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.authOK = func(r *http.Request) bool { return r.Header.Get("authorization") != "" }
	f.playlist = liveWindow
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/sec/index.m3u8")})
	if v.Code != verdictHLSAuth {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSAuth, blob)
	}

	// 填对了账号就该往下走
	v2, blob2 := callHLS(t, map[string]any{"url": f.url("/hls/sec/index.m3u8"),
		"username": "ops", "password": "hunter2", "watchMs": 200})
	if v2.Code != verdictHLSOK {
		t.Fatalf("给了账号还是 %s（%s）", v2.Code, blob2)
	}
	// ★ 口令不进结果：Basic 头是 base64，明文口令也不许出现在任何一处
	if strings.Contains(blob2, "hunter2") || strings.Contains(strings.ToLower(blob2), "aHVudGVyMg") {
		t.Errorf("口令漏进结果里了：%s", blob2)
	}
}

func Test登录页里的假清单字样不许骗过去(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	// 401 + 一段 HTML，里面还嵌着 "#EXTM3U" 字样 —— 有的平台真这么干
	f.authOK = func(*http.Request) bool { return false }
	f.playlist = func(int) string { return "" }
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/guard/index.m3u8")})
	if v.Code != verdictHLSAuth {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSAuth, blob)
	}
	if strings.Contains(blob, "s3cr3tpw") {
		t.Errorf("登录页里的口令被抄进结果了：%s", blob)
	}
}

func Test路径上没有这路(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return "" } // 404
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/wrongname/index.m3u8")})
	if v.Code != verdictHLSNotFound {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSNotFound, blob)
	}
	if !strings.Contains(v.Note, "流名") {
		t.Errorf("那句没给出下一步该查什么：%s", v.Note)
	}
}

func Test回的不是清单而是网页(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return "<html><body>首页</body></html>" }
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8")})
	if v.Code != verdictHLSNotHLS {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSNotHLS, blob)
	}
	if v.Values["looksLike"] != "html" {
		t.Errorf("没说清它到底回了个什么：%v", v.Values["looksLike"])
	}
}

func Test裸流FLV要认出来(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	// 有人把 flv 的地址当成 m3u8 填进来：回 200 + 一段裸流
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "video/x-flv")
		_, _ = w.Write(append([]byte("FLV\x01\x00"), make([]byte, 500)...))
	})
	v, _ := callHLS(t, map[string]any{"url": f.url("/live/cam1.flv")})
	if v.Code != verdictHLSNotHLS {
		t.Fatalf("判定 = %s，想要 %s", v.Code, verdictHLSNotHLS)
	}
	if v.Values["looksLike"] != "flv" {
		t.Errorf("没认出这是 FLV 裸流：%v", v.Values["looksLike"])
	}
}

func Test主清单替人挑一路并列出各路(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hls/cam1/index.m3u8":
			fmt.Fprint(w, "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=5120000,RESOLUTION=1920x1080,CODECS=\"avc1.64001F,mp4a.40.2\"\nlow/index.m3u8\n"+
				"#EXT-X-STREAM-INF:BANDWIDTH=12000000,RESOLUTION=3840x2160,CODECS=\"avc1.640028\"\nhigh/index.m3u8\n")
		case "/hls/cam1/high/index.m3u8":
			n := int(f.hits.Add(1))
			fmt.Fprint(w, liveWindow(n))
		default:
			if strings.Contains(r.URL.Path, ".m4s") {
				_, _ = w.Write(make([]byte, 60000))
				return
			}
			w.WriteHeader(404)
		}
	})
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8"), "watchMs": 200})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s（%s）", v.Code, blob)
	}
	if v.Values["master"] != true {
		t.Errorf("没标出这是主清单")
	}
	variants, _ := v.Values["variants"].([]map[string]any)
	if len(variants) != 2 {
		t.Fatalf("两路只列出 %d 路：%v", len(variants), v.Values["variants"])
	}
	// ★ 挑的是带宽最大的那一路（12M / 4K），不是列在前面的那一路
	res, _ := v.Values["variantResolution"].(string)
	if res != "3840x2160" {
		t.Errorf("挑了 %q，想要 3840x2160", res)
	}
	if s, _ := v.Values["variant"].(string); !strings.HasSuffix(s, "/high/index.m3u8") {
		t.Errorf("往下问的地址是 %q", s)
	}
	// 带逗号的 CODECS 不许被切坏
	if c, _ := variants[0]["codecs"].(string); c != "avc1.64001F,mp4a.40.2" {
		t.Errorf("编码表被切开了：%q", c)
	}
}

func Test带BYTERANGE的分片要按段取(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:1\n" +
			"#EXTINF:6.000,\n#EXT-X-BYTERANGE:240000@120000\nbig.m4s\n"
	}
	f.segBody = func(string) []byte { return make([]byte, 240000) }
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/br/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s（%s）", v.Code, blob)
	}
	if got, _ := f.rangeSeen.Load().(string); got != "bytes=120000-359999" {
		t.Errorf("Range 头是 %q —— 不加这一段就会把整个文件搬回来，码率算出个高得离谱的数", got)
	}
	if kb, _ := v.Values["bitrateKbps"].(int); kb > 5000 {
		t.Errorf("码率 %d kbps 不对劲：那是把整个文件当成一片了", kb)
	}
	rows, _ := v.Values["sampled"].([]map[string]any)
	if len(rows) == 0 || rows[0]["byteRange"] != "240000@120000" {
		t.Errorf("抽查记录里没留下这个段：%v", v.Values["sampled"])
	}
}

func Test连不上和没人答话分开看(t *testing.T) {
	// 端口关着：机器在，这个口上没服务
	v, blob := callHLS(t, map[string]any{"url": "http://127.0.0.1:1/index.m3u8"})
	if v.Code != verdictHLSUnreach {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSUnreach, blob)
	}
	if v.Values["reach"] != verdictClosed {
		t.Errorf("没说清是「端口关着」还是「没人答话」：%v", v.Values["reach"])
	}

	// 连上了不吭声
	f := newHLSFake()
	defer f.srv.Close()
	f.delay = 1200 * time.Millisecond
	f.playlist = liveWindow
	v2, _ := callHLS(t, map[string]any{"url": f.url("/hls/slow/index.m3u8"), "timeoutMs": 500})
	if v2.Code != verdictHLSTimeout {
		t.Fatalf("判定 = %s，想要 %s", v2.Code, verdictHLSTimeout)
	}
}

func Test地址里的口令与签名不进结果(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = liveWindow
	v, blob := callHLS(t, map[string]any{
		"url":     f.url("/hls/cam1/index.m3u8") + "?token=eyJhbGciOi.s3cr3t&pwd=TopSecret1",
		"watchMs": 200,
	})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s（%s）", v.Code, blob)
	}
	for _, leak := range []string{"TopSecret1", "s3cr3t", "eyJhbGciOi"} {
		if strings.Contains(blob, leak) {
			t.Errorf("%q 漏进了结果：%s", leak, blob)
		}
	}
	// ★ 参数名留着、值打掉：现场要看的是「这里挂的是 token 还是 pwd」，
	//   那一个词就决定了去查哪边的签名过期。
	got, _ := v.Values["url"].(string)
	if !strings.Contains(got, "token=***") || !strings.Contains(got, "pwd=***") {
		t.Errorf("两个口令类参数没都打码：%q", got)
	}
}

func Test只问清单不去取分片(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = liveWindow
	f.segStatus["/hls/cam1/seg100.m4s"] = 500 // 分片是坏的，但这次没说要去问
	v, _ := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8"),
		"sampleSegments": 0, "watchMs": 0})
	if _, has := v.Values["sampled"]; has {
		t.Errorf("说了不取分片，还是留下了抽查记录：%v", v.Values["sampled"])
	}
	if f.segHits.Load() != 0 {
		t.Errorf("取了 %d 次分片", f.segHits.Load())
	}
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s", v.Code)
	}
	// ★ 没问的事不许写成结论：一片都没取，那句里就不许出现「分片」；
	// 没看第二遍，也不许出现「往前挪」。
	if strings.Contains(v.Note, "分片") {
		t.Errorf("一句账说了没问过的事：%s", v.Note)
	}
	if strings.Contains(v.Note, "往前挪") {
		t.Errorf("只拉了一次清单，却说窗口在往前挪：%s", v.Note)
	}
}

func Test带初始化段的流它不进码率(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:9\n" +
			"#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:6.000,\nseg9.m4s\n"
	}
	// 媒体片 60 KB / 6 秒 = 80 kbps；初始化段 600 KB，但它没有时长可对
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".m3u8"):
			w.Header().Set("content-type", "application/vnd.apple.mpegurl")
			fmt.Fprint(w, f.playlist(int(f.hits.Add(1))))
		case strings.HasSuffix(r.URL.Path, "init.mp4"):
			_, _ = w.Write(make([]byte, 600000))
		default:
			_, _ = w.Write(make([]byte, 60000))
		}
	})
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/fmp4/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s（%s）", v.Code, blob)
	}
	if v.Values["hasInitSegment"] != true {
		t.Errorf("没标出这一路带初始化段")
	}
	rows, _ := v.Values["sampled"].([]map[string]any)
	if len(rows) != 2 {
		t.Fatalf("抽查记录 %d 条，想要「媒体片 + 初始化段」两条：%v", len(rows), v.Values["sampled"])
	}
	if kb, _ := v.Values["bitrateKbps"].(int); kb != 80 {
		t.Errorf("码率 = %v —— 初始化段那 600 KB 混进来了，它根本没有时长可对", v.Values["bitrateKbps"])
	}
}

func Test初始化段取不到这一路就是起不来(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:9\n" +
			"#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:6.000,\nseg9.m4s\n"
	}
	// 媒体片好好的，只有初始化段 404 —— 播放器黑屏，而清单上看不出所以然
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".m3u8"):
			w.Header().Set("content-type", "application/vnd.apple.mpegurl")
			fmt.Fprint(w, f.playlist(int(f.hits.Add(1))))
		case strings.HasSuffix(r.URL.Path, "init.mp4"):
			w.WriteHeader(404)
		default:
			_, _ = w.Write(make([]byte, 60000))
		}
	})
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/fmp4/index.m3u8"), "watchMs": 0})
	if v.Code != verdictHLSSegMiss {
		t.Fatalf("判定 = %s，想要 %s（%s）", v.Code, verdictHLSSegMiss, blob)
	}
	if !strings.Contains(blob, "init.mp4") {
		t.Errorf("那笔账没指到初始化段上：%v", v.Values["sampled"])
	}
}

func Test读满上限的那片不许算出一个偏低的码率(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:9\n#EXTINF:6.000,\nseg9.m4s\n"
	}
	// 一片 5 MiB：单次上限 4 MiB，读满就得停手
	f.segBody = func(string) []byte { return make([]byte, 5<<20) }
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/big/index.m3u8"), "watchMs": 0})
	rows, _ := v.Values["sampled"].([]map[string]any)
	if len(rows) != 1 || rows[0]["truncated"] != true {
		t.Fatalf("没记下「这片没读完」：%v", v.Values["sampled"])
	}
	if _, has := v.Values["bitrateKbps"]; has {
		t.Errorf("半截的字节算出了码率：%v（%s）", v.Values["bitrateKbps"], blob)
	}
	if s, _ := v.Values["bitrateSkipped"].(string); !strings.Contains(s, "1 片") {
		t.Errorf("没说清有几片被跳过：%v", v.Values["bitrateSkipped"])
	}
}

func Test点播与断点都照实记一笔(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string {
		return "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:1\n" +
			"#EXT-X-DISCONTINUITY\n#EXTINF:6.000,\nseg1.m4s\n" +
			"#EXT-X-ALLOW-CACHE:YES\n#EXTINF:6.000,\nseg2.m4s\n#EXT-X-ENDLIST\n"
	}
	v, blob := callHLS(t, map[string]any{"url": f.url("/hls/rec/index.m3u8"), "watchMs": 200})
	if v.Code != verdictHLSOK {
		t.Fatalf("判定 = %s（%s）", v.Code, blob)
	}
	if v.Values["isLive"] != false {
		t.Errorf("录完的那段被当成直播：第二次拉清单都省了才对")
	}
	if f.hits.Load() != 1 {
		t.Errorf("点播又拉了 %d 次清单 —— 录完的东西不会有「卡住」这回事", f.hits.Load())
	}
	if v.Values["discontinuities"] != 1 {
		t.Errorf("断点没记上：%v", v.Values["discontinuities"])
	}
	tags, _ := v.Values["unknownTags"].([]string)
	if len(tags) != 1 || tags[0] != "EXT-X-ALLOW-CACHE" {
		t.Errorf("认不出的标签没留下名字：%v", v.Values["unknownTags"])
	}
	// ★ 只留标签名，值不进结果：认不出的那一串里可能正带着口令
	if strings.Contains(blob, "YES") {
		t.Errorf("标签的值抄进结果了：%s", blob)
	}
	if !strings.Contains(v.Note, "录完") {
		t.Errorf("那句没说清这是点播：%s", v.Note)
	}
}

func Test窗口长度与序号起点照实给(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = func(int) string { return liveWindow(1) }
	v, _ := callHLS(t, map[string]any{"url": f.url("/hls/cam1/index.m3u8"),
		"sampleSegments": 0, "watchMs": 0})
	if v.Values["mediaSequence"] != 100 {
		t.Errorf("序号起点 = %v，想要 100", v.Values["mediaSequence"])
	}
	if v.Values["windowSec"] != 18.0 {
		t.Errorf("窗口长度 = %v，想要 18 秒", v.Values["windowSec"])
	}
	if _, has := v.Values["finalURL"]; has {
		t.Errorf("没跳过还写了跳转落点：%v", v.Values["finalURL"])
	}
}

func Test填非法参数要挡在门外(t *testing.T) {
	for _, args := range []map[string]any{
		{},                            // 没给地址
		{"url": "rtsp://1.2.3.4/cam"}, // 别的协议
		{"url": "http://127.0.0.1:1/x.m3u8", "sampleSegments": 9},
	} {
		raw, _ := json.Marshal(args)
		if _, err := hlsProbeTool.Invoke(t.Context(), raw); err == nil {
			t.Errorf("%v 居然放行了 —— 越界的抽查片数会让一次探测搬回几十兆", args)
		}
	}
}

func Test前缀写反和它答的都不是HTTP分开(t *testing.T) {
	f := newHLSFake()
	defer f.srv.Close()
	f.playlist = liveWindow
	// 明文服务却用 https:// 去问：TLS 那一步就没谈成，这一问根本没问到东西
	v, _ := callHLS(t, map[string]any{"url": strings.Replace(f.url("/hls/cam1/index.m3u8"), "http://", "https://", 1)})
	if v.Code != verdictHLSUnreach {
		t.Fatalf("判定 = %s，想要 %s —— 判成「回的不是清单」会把人支去查平台", v.Code, verdictHLSUnreach)
	}
	if !strings.Contains(v.Note, "http://") {
		t.Errorf("那句没给出下一步动作（改前缀）：%s", v.Note)
	}

	// 端口上说的是别的协议：它答话了，答的不是 HTTP
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("开不了本地端口：", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 256)
		_, _ = c.Read(b)
		_, _ = c.Write([]byte("\x00\x01RTSP/1.0 200 OK\r\n\r\n")) // 一开口就不是 HTTP
	}()
	v2, _ := callHLS(t, map[string]any{"url": "http://" + ln.Addr().String() + "/index.m3u8"})
	if v2.Code != verdictHLSNotHLS {
		t.Fatalf("判定 = %s，想要 %s", v2.Code, verdictHLSNotHLS)
	}
}

func Test只读且没有改任何东西(t *testing.T) {
	r := ots.NewRegistry(true)
	r.MustRegister(hlsProbeTool)
	got, ok := r.Lookup("media.hls.probe")
	if !ok {
		t.Fatal("没注册进注册表")
	}
	if got.Class != ots.ClassRead {
		t.Errorf("被判成 %q —— 拉一份清单不改任何东西", got.Class)
	}
	if !json.Valid(got.Schema) {
		t.Error("schema 不是合法 JSON")
	}
}
