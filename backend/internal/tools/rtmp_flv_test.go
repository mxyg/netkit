package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// ── FLV 字节串的拼装：现场验的是「喂进去什么容器，落哪个判定」，不是解析器本身 ──
//
// ★ 只造到「能让 ProbeFLV 走到我们要的那一档」为止：头 + 标签 + PreviousTagSize。
//	时间戳/长度这些字段照规格写，好让标签这一层的账（tags/keyframe）也能被验。

func flvHead(flags byte, dataOffset uint32) []byte {
	h := []byte{'F', 'L', 'V', 0x01, flags}
	h = append(h, byte(dataOffset>>24), byte(dataOffset>>16), byte(dataOffset>>8), byte(dataOffset))
	// PreviousTagSize0：规范要 4 字节 0；这里给对，免得 PrevTagSizeBad 干扰断言。
	return append(h, 0, 0, 0, 0)
}

func flvTag(typ byte, ts uint32, body []byte) []byte {
	n := len(body)
	h := make([]byte, 11)
	h[0] = typ
	h[1] = byte(n >> 16)
	h[2] = byte(n >> 8)
	h[3] = byte(n)
	h[4] = byte(ts >> 16)
	h[5] = byte(ts >> 8)
	h[6] = byte(ts)
	h[7] = byte(ts >> 24) // 扩展高位：24 位不够时靠这一字节拼回去
	// h[8..10] 流 ID，留 0
	out := append(h, body...)
	pts := 11 + n
	return append(out, byte(pts>>24), byte(pts>>16), byte(pts>>8), byte(pts))
}

// flvVideoKey 一个「关键帧、AVC、NALU 包」的老式视频标签：够数到视频标签与关键帧，
// 但不带序列头 —— 所以解不出分辨率是应该的，测试也就不断言 width。
//
// ★ 布局按规格：首字节(帧类型|编码编号) + 合成时间 3 字节 + AVCPacketType 1 字节 + 载荷。
//
//	AVCPacketType=1（NALU）才落到「关键帧」那一格；写成 0 会被当序列头去解配置记录。
func flvVideoKey(ts uint32) []byte {
	body := []byte{0x17, 0, 0, 0, 0x01, 0xde, 0xad, 0xbe, 0xef}
	return flvTag(9, ts, body)
}

// flvAudioAAC 一个 AAC 音频标签（非序列头，纯包）。
func flvAudioAAC(ts uint32) []byte {
	body := []byte{0xaf, 0x01, 0, 0, 0x21}
	return flvTag(8, ts, body)
}

// flvVideoTruncated 声明 size 与到手正文对不上：断在标签里那一档的证据。
func flvVideoTruncated(size int) []byte {
	body := []byte{0x17, 0x01, 0, 0, 0, 1, 2, 3, 4, 5} // 只给 10 字节
	h := make([]byte, 11)
	h[0] = 9
	h[1] = byte(size >> 16)
	h[2] = byte(size >> 8)
	h[3] = byte(size)
	h[7] = 0
	return append(h, body...) // 不补齐、也不写 PreviousTagSize
}

// flvGiantTagHead 头声明长度 16 MiB-1：证我们既不信它、也不为它分配/挂住。
func flvGiantTagHead() []byte {
	return []byte{9, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0}
}

// callFLV 走 flv:// 这一支的界面入口：地址进、判定出。
func callFLV(t *testing.T, args map[string]any) (ots.Verdict, string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rtmpProbeTool.Invoke(t.Context(), raw)
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

// flvServe 起一台假 HTTP-FLV 平台：把给定正文/状态码原样回出去。
// flvURL 把 httptest 的 http:// 前缀换成 flv://，正是现场抄下来的那串前缀。
func flvURL(srv *httptest.Server, pathQuery string) string {
	return "flv://" + strings.TrimPrefix(srv.URL, "http://") + pathQuery
}

func flvBodyServer(t *testing.T, status int, body []byte, ct string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if status != 0 && status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── 一档一测 ──

func TestFLV有视频标签判成在播(t *testing.T) {
	body := append(flvHead(0x05, 9), flvVideoKey(0)...)
	body = append(body, flvVideoKey(33)...)
	body = append(body, flvAudioAAC(0)...)
	srv := flvBodyServer(t, 200, body, "video/x-flv")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVOk)
	// ★ 那份账要和容器里真的东西对上，不是「有画面」三个字盖过去。
	if n, _ := int64Val(v, "videoTags"); n != 2 {
		t.Errorf("视频标签数 = %v，想要 2：%s", v.Values["videoTags"], blob)
	}
	if v.Values["hasVideo"] != true || v.Values["hasAudio"] != true {
		t.Errorf("音视频都在场却没都记到：%s", blob)
	}
	if v.Values["hasKeyframe"] != true {
		t.Errorf("关键帧没被数到（0x17 就是关键帧）：%s", blob)
	}
	if n, _ := int64Val(v, "keyframes"); n < 2 {
		t.Errorf("关键帧数 = %v，想要 ≥2：%s", v.Values["keyframes"], blob)
	}
	if n, _ := int64Val(v, "tags"); n != 3 {
		t.Errorf("标签总数 = %v，想要 3（两视频一音频）：%s", v.Values["tags"], blob)
	}
	if n, _ := int64Val(v, "bodyBytes"); n <= 0 {
		t.Errorf("正文字节没记上：%s", blob)
	}
	if v.Values["protocol"] != "flv" || v.Values["transport"] != "http" {
		t.Errorf("没标清这是 flv-over-http 那一问：%s", blob)
	}
}

func TestFLV只有头没有媒体标签(t *testing.T) {
	body := flvHead(0x05, 9) // 头 + PreviousTagSize0，后面一个标签都没有
	srv := flvBodyServer(t, 200, body, "video/x-flv")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVNoMedia)
	// ★ 与「不是 FLV」分开：头是对的，只是此刻一帧都没有。
	if v.Values["hasVideo"] != false || v.Values["hasAudio"] != false {
		t.Errorf("明明没媒体却记成有：%s", blob)
	}
	if s, _ := v.Values["stopReason"].(string); s != "ended" {
		t.Errorf("读到干净末尾应记 ended，得到 %v：%s", v.Values["stopReason"], blob)
	}
	if !strings.Contains(v.Note, "一帧") {
		t.Errorf("这一档那句得说清「答应给流却一帧没有」：%s", v.Note)
	}
}

func TestFLV只有音频没有画面(t *testing.T) {
	body := append(flvHead(0x04, 9), flvAudioAAC(0)...)
	body = append(body, flvAudioAAC(100)...)
	srv := flvBodyServer(t, 200, body, "video/x-flv")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVAudioOnly)
	if v.Values["hasAudio"] != true || v.Values["hasVideo"] != false {
		t.Errorf("音频-only 却记歪了：%s", blob)
	}
	// 现场那句「打开了但没画面」的答案就是这一档 —— note 得落到音频有、视频没有。
	if !strings.Contains(v.Note, "画面") {
		t.Errorf("这一档的下一步是去查视频那一路，note 得说到：\n%s", v.Note)
	}
}

func TestFLV回404不等于不是FLV(t *testing.T) {
	srv := flvBodyServer(t, 404, nil, "")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/typo")})
	// ★★ 404 落这一档，绝不落 flv-not-flv：两者的下一步一个是核流名、一个是换协议。
	wantCode(t, v, blob, verdictFLVStatus)
	if n, _ := int64Val(v, "httpStatus"); n != 404 {
		t.Errorf("状态码没留在账上：%s", blob)
	}
	if !strings.Contains(v.Note, "流名") && !strings.Contains(v.Note, "没有") {
		t.Errorf("404 那句得指向「回去核这一路的名字」：%s", v.Note)
	}
	if s, _ := v.Values["looksLike"].(string); s != "" {
		t.Errorf("404 根本不该去猜容器内容：%v", s)
	}
}

func TestFLV回403要凭据(t *testing.T) {
	srv := flvBodyServer(t, 403, nil, "")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVStatus)
	if n, _ := int64Val(v, "httpStatus"); n != 403 {
		t.Errorf("状态码没留在账上：%s", blob)
	}
	if !strings.Contains(v.Note, "凭据") {
		t.Errorf("403 的下一步是补 key/账号，note 得说到：%s", v.Note)
	}
}

func TestFLV回200可正文是网页(t *testing.T) {
	body := []byte("<html><body>先登录 admin:hunter2</body></html>")
	srv := flvBodyServer(t, 200, body, "text/html")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVNotFLV)
	if v.Values["looksLike"] != "html" {
		t.Errorf("没说清「那一段看着像什么」等于让人再猜一遍：%s", blob)
	}
	if n, _ := int64Val(v, "httpStatus"); n != 200 {
		t.Errorf("这一档明明是 200 回了别的东西，状态码没留：%s", blob)
	}
}

func TestFLV断在标签里仍留partial账(t *testing.T) {
	// 一个完整的视频标签（Tags 记 1），后面接一个声明 200 字节却只给 10 字节的标签就关。
	body := append(flvHead(0x05, 9), flvVideoKey(0)...)
	body = append(body, flvVideoTruncated(200)...)
	srv := flvBodyServer(t, 200, body, "video/x-flv")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVTagBroken)
	// ★ 断之前数到的标签照样是证据，不能因为断了就清零。
	if n, _ := int64Val(v, "tags"); n != 1 {
		t.Errorf("断之前数到的 1 个标签没留下：%s", blob)
	}
	if !strings.Contains(v.Note, "标签") {
		t.Errorf("判定与它的账不同源：%s\n%s", v.Note, blob)
	}
}

func TestFLV走chunked传输照样认(t *testing.T) {
	// 用 chunked（不写 Content-Length、分两次 Flush）回一段好 FLV：
	// net/http 会把 chunk 拼回原字节流，ProbeFLV 拿到的应与一次性写出的完全一致。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/x-flv")
		fw := w.(http.Flusher)
		_, _ = w.Write(flvHead(0x05, 9))
		fw.Flush()
		_, _ = w.Write(flvVideoKey(0))
		fw.Flush()
	}))
	t.Cleanup(srv.Close)
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVOk)
	if n, _ := int64Val(v, "videoTags"); n != 1 {
		t.Errorf("chunked 拼回来的视频标签数 = %v，想要 1：%s", v.Values["videoTags"], blob)
	}
}

func TestFLV连上却不回话判成超时(t *testing.T) {
	// 收了连接、一个响应字节都不写，直到响应头超时。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	t.Cleanup(srv.Close)
	started := time.Now()
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1"), "timeoutMs": 600})
	wantCode(t, v, blob, verdictFLVTimeout)
	if d := time.Since(started); d > 3*time.Second {
		t.Errorf("响应头超时给了 600 毫秒，这一问却等了 %v —— 没按步收口", d)
	}
	if v.Values["httpStatus"] != nil {
		t.Errorf("根本没问到状态码，账上不该有一个：%s", blob)
	}
}

func TestFLV立刻关闭且空正文判成一帧没有(t *testing.T) {
	// 回一个 200、正文 0 字节就结束：连 FLV 头都无从读起。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/x-flv")
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	wantCode(t, v, blob, verdictFLVNoMedia)
	if v.Values["emptyBody"] != true {
		t.Errorf("200 空正文这一格要留下（与「有头没标签」分开看）：%s", blob)
	}
	if n, _ := int64Val(v, "httpStatus"); n != 200 {
		t.Errorf("明明是 200，状态码却没留：%s", blob)
	}
}

func TestFLV声明长度16MiB既不分配也不挂死(t *testing.T) {
	// 头之后一个标签声明长度 0xFFFFFF（≈16 MiB-1），后面什么都不发。
	body := append(flvHead(0x05, 9), flvGiantTagHead()...)
	srv := flvBodyServer(t, 200, body, "video/x-flv")
	started := time.Now()
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1"), "timeoutMs": 1500, "watchMs": 1000})
	// ★ 不信流上读来的长度：超过封顶就按预算收口，绝不为它 malloc。
	if d := time.Since(started); d > 4*time.Second {
		t.Errorf("一个假的 16 MiB 标签就把探测挂死 %v —— 长度字段被当真了", d)
	}
	wantCode(t, v, blob, verdictFLVNoMedia)
	if s, _ := v.Values["stopReason"].(string); s != "bytecap" {
		t.Errorf("该按字节预算收口（bytecap），得到 %v：%s", v.Values["stopReason"], blob)
	}
}

func TestFLV端口没开着判成连不上(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // 关掉，端口上没人听了：本机 connect 立刻回 RST
	v, blob := callFLV(t, map[string]any{"url": "flv://" + addr + "/live/cam1", "timeoutMs": 900})
	wantCode(t, v, blob, verdictFLVUnreach)
	if v.Values["reach"] != verdictClosed {
		t.Errorf("本机没人监听该记成 closed：%v\n%s", v.Values["reach"], blob)
	}
}

func TestFLV不写端口默认80(t *testing.T) {
	// 只验地址拆法：flv://host/app/stream 不写口 → 按 80 报（这一支约定）。
	u, err := normalizeRTMPURL("flv://10.0.0.7/live/cam1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "flv" {
		t.Fatalf("normalizeRTMPURL 现在得放行 flv，得到 %q", u.Scheme)
	}
	if got := flvPort(u); got != 80 {
		t.Errorf("flv 默认端口 = %d，想要 80", got)
	}
	if got := flvPort(mustParse(t, "flv://10.0.0.7:8080/live/c")); got != 8080 {
		t.Errorf("显式端口没生效：%d", got)
	}
}

// ── 凭据：只上线路，不进结果 ──

const (
	flvLeakQuery   = "flvquerykey9d2"
	flvLeakUser    = "camuser7"
	flvLeakPass    = "campass4q1"
	flvLeakSignKey = "flvsignkey3f8"
)

func TestFLV地址里的凭据不进结果(t *testing.T) {
	body := append(flvHead(0x05, 9), flvVideoKey(0)...)
	srv := flvBodyServer(t, 200, body, "video/x-flv")
	u := fmt.Sprintf("flv://%s:%s@%s/live/cam1?key=%s&sign=%s",
		flvLeakUser, flvLeakPass, strings.TrimPrefix(srv.URL, "http://"), flvLeakQuery, flvLeakSignKey)
	v, blob := callFLV(t, map[string]any{"url": u})
	wantCode(t, v, blob, verdictFLVOk) // 判定本身要能用：口令该发出去照发，只是不落账
	// ★★ 三个值一个都不许出现在结果里 —— 这份结果会发给 AI、也会打进诊断包。
	for _, leak := range []string{flvLeakQuery, flvLeakPass, flvLeakSignKey} {
		if strings.Contains(blob, leak) {
			t.Errorf("凭据 %s 进了结果：\n%s", leak, blob)
		}
	}
	// redactURL 那份才是进结果的：参数名留着、值打码，user:pass 整个抹掉。
	got, _ := v.Values["url"].(string)
	if !strings.Contains(got, "key=***") || !strings.Contains(got, "sign=***") {
		t.Errorf("口令类参数没打码留名：%q", got)
	}
	if strings.Contains(got, flvLeakUser) || strings.Contains(got, "@") {
		t.Errorf("userinfo 没抹干净：%q", got)
	}
	if v.Values["hasUserinfo"] != true {
		t.Errorf("地址带了 user:pass 却没在账上点明：%s", blob)
	}
}

func TestFLV服务器抄回带口令的描述也要打码(t *testing.T) {
	// 非 FLV 正文里嵌一段带 key 的地址：looksLike 之外 detail 也要过闸。
	body := []byte(`{"error":"need key=abcInBody for stream"}`)
	srv := flvBodyServer(t, 200, body, "application/json")
	v, blob := callFLV(t, map[string]any{"url": flvURL(srv, "/live/cam1")})
	// 正文不是 FLV：落 flv-not-flv（JSON 那一段认得出）。
	wantCode(t, v, blob, verdictFLVNotFLV)
	if strings.Contains(blob, "abcInBody") {
		t.Errorf("detail 里那段裸 key 没打码：%s", blob)
	}
}

// ── 参数：越界拒绝，不静默夹 ──

func TestFLV参数越界挡在门外(t *testing.T) {
	srv := flvBodyServer(t, 200, flvHead(0x05, 9), "video/x-flv")
	for _, args := range []map[string]any{
		{"url": flvURL(srv, "/live/c"), "maxBytes": 10},         // 太短
		{"url": flvURL(srv, "/live/c"), "maxBytes": 99 << 20},   // 太长
		{"url": flvURL(srv, "/live/c"), "watchMs": 100},         // 窗口太短
		{"url": flvURL(srv, "/live/c"), "timeoutMs": 100000000}, // 超时太长
	} {
		raw, _ := json.Marshal(args)
		if _, err := rtmpProbeTool.Invoke(t.Context(), raw); err == nil {
			t.Errorf("越界参数放行了：%v", args)
		}
	}
}

// ── 判定码合规：小写-数字-连字符、带 flv- 前缀、互不重复 ──

func TestFLV判定码写法与不重复(t *testing.T) {
	want := []string{
		verdictFLVOk, verdictFLVAudioOnly, verdictFLVNoMedia, verdictFLVNotFLV,
		verdictFLVStatus, verdictFLVUnreach, verdictFLVTimeout, verdictFLVTagBroken,
		verdictFLVDropped,
	}
	seen := map[string]bool{}
	for _, c := range want {
		if seen[c] {
			t.Errorf("判定码 %s 重复", c)
		}
		seen[c] = true
		if !strings.HasPrefix(c, "flv-") {
			t.Errorf("判定码 %s 没带 flv- 前缀", c)
		}
		if !ots.ValidVerdictCode(c) {
			t.Errorf("判定码 %q 不合 [OTS-5.5]", c)
		}
	}
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := normalizeRTMPURL(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func int64Val(v ots.Verdict, key string) (int64, bool) {
	switch n := v.Values[key].(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// ★ 后端只出码，中文得有人写 —— 这一条钉的是 flv:// 那一支的九档。
//
// 为什么不能只查「app.js 里出现过这个码」：码在提示文字里露一次就能把测试骗绿，
// 而界面上那一格会直接印出 flv-audio-only 给现场工程师看。所以查的是**那张表里
// `code': [` 后面跟着的那一句人话**。
//
// 另外钉两件事，因为这一族最容易出的错不是漏一条，而是**走错表**：
// flv 的码落在 RTMP_CODE 里（或反过来），分派查不到就是裸码；
// 而分派本身没写（FLV_CODE 成了一张没人读的表），全文扫一遍也扫不出问题。
func TestFLV判定码界面上都有人话(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面文件：%v", err)
	}
	js := string(b)
	flv := jsBlock(js, "const FLV_CODE = {")
	if flv == "" {
		t.Fatal("界面里找不到 FLV_CODE 这张表 —— flv:// 那九档全都没有人话")
	}
	rtmp := jsBlock(js, "const RTMP_CODE = {")
	if rtmp == "" {
		t.Fatal("界面里找不到 RTMP_CODE 这张表")
	}
	// 分派：查表那一处必须真的按 protocol 换表，不然 FLV_CODE 是死码。
	if !strings.Contains(js, "=== 'flv'") || !strings.Contains(js, "FLV_CODE") {
		t.Error("rtmpDisplay 里没有按 flv 换表的分支，FLV_CODE 永远不会被读到")
	}
	for _, code := range []string{verdictFLVOk, verdictFLVAudioOnly, verdictFLVNoMedia,
		verdictFLVNotFLV, verdictFLVStatus, verdictFLVUnreach, verdictFLVTimeout,
		verdictFLVTagBroken, verdictFLVDropped} {
		at := strings.Index(flv, "'"+code+"': [")
		if at < 0 {
			t.Errorf("FLV_CODE 里没有 %s —— 界面上会直接印出这个码", code)
			continue
		}
		if _, ok := jsPhrase(flv[at+len("'")+len(code)+len("': ["):]); !ok {
			t.Errorf("%s 在 FLV_CODE 里没配人话（或那句是空的、不像 ['人话', '档色']）", code)
		}
		// 同一个码挂在两张表上 = 分派错一次就静默给出另一族的话，看不出来。
		if strings.Contains(rtmp, "'"+code+"'") {
			t.Errorf("%s 同时出现在 RTMP_CODE 与 FLV_CODE 里，两张表必须各管一族", code)
		}
	}
	for _, code := range []string{"rtmp-no-media", "rtmp-not-rtmp", "rtmp-stream-absent"} {
		if strings.Contains(flv, "'"+code+"'") {
			t.Errorf("%s 落进了 FLV_CODE —— RTMP 的码归 RTMP 那张表", code)
		}
	}
}
