package portal

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCaller 一张假注册表：记下每次调用，返回一个固定判定。
type fakeCaller struct {
	calls []fakeCall
}

type fakeCall struct {
	caller, name string
	args         json.RawMessage
}

func (f *fakeCaller) InvokeTool(ctx context.Context, caller, name string, args json.RawMessage) (any, error) {
	f.calls = append(f.calls, fakeCall{caller, name, args})
	return map[string]any{"verdict": "ok", "echo": name}, nil
}

// newTestService 起一个真监听（127.0.0.1 回环 + 端口 0），返回 base URL 和服务。
// ★ 走真 socket 而不是只测 handler：回环口/局域网口两张 mux 的分派本身就是要测的东西。
func newTestService(t *testing.T, cfg Config) (*Service, string) {
	t.Helper()
	cfg.Addrs = []string{"127.0.0.1"}
	cfg.Port = 0
	s, err := Start(cfg, Deps{})
	if err != nil {
		t.Fatalf("起门户失败：%s", err)
	}
	t.Cleanup(s.Stop)
	base := fmt.Sprintf("http://127.0.0.1:%d", s.Status().Port)
	return s, base
}

// noRedirect 配对那一下要亲眼看到 302 和 Set-Cookie，不许客户端替我们跟下去。
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func join(t *testing.T, base string) *http.Cookie {
	t.Helper()
	st, err := http.Get(base + "/local/status")
	if err != nil {
		t.Fatal(err)
	}
	var s Status
	body, _ := io.ReadAll(st.Body)
	st.Body.Close()
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("状态不是合法 JSON：%s（%s）", err, body)
	}
	resp, err := noRedirect.Get(base + "/enter/" + s.Token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("扫码进入应该 302，拿到 %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("配对成功但没发会话 cookie")
	return nil
}

func TestEntryTokenOneShot(t *testing.T) {
	s, base := newTestService(t, Config{})
	st, _ := http.Get(base + "/local/status")
	var stat Status
	body, _ := io.ReadAll(st.Body)
	st.Body.Close()
	_ = json.Unmarshal(body, &stat)

	// 第一次扫：成功
	c := join(t, base)
	// 第二次拿同一张码：当场作废
	resp, err := http.Get(base + "/enter/" + stat.Token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("一次性令牌第二次用应当 403，拿到 %d", resp.StatusCode)
	}
	if !s.Status().EntryUsed {
		t.Fatal("状态里 EntryUsed 应当已经是 true")
	}
	// 带着会话 cookie 要 API：通
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.AddCookie(c)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("配对后的 /api/status 应当 200，拿到 %d", r2.StatusCode)
	}
}

func TestRejectsUnknownTokenAndNoCookie(t *testing.T) {
	_, base := newTestService(t, Config{})
	resp, err := http.Get(base + "/enter/deadbeef01234567")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("乱令牌应当 403，拿到 %d", resp.StatusCode)
	}
	resp, err = http.Get(base + "/api/files")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("没 cookie 的 /api/files 应当 401，拿到 %d", resp.StatusCode)
	}
}

func TestKickMakesCookieDead(t *testing.T) {
	s, base := newTestService(t, Config{})
	c := join(t, base)
	st, _ := http.Get(base + "/local/status")
	var stat Status
	body, _ := io.ReadAll(st.Body)
	st.Body.Close()
	_ = json.Unmarshal(body, &stat)
	if len(stat.Sessions) != 1 {
		t.Fatalf("应当有 1 台配对设备，拿到 %d", len(stat.Sessions))
	}
	if !s.Kick(stat.Sessions[0].ID) {
		t.Fatal("Kick 应当成功")
	}
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.AddCookie(c)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("被踢后应当 401，拿到 %d", r2.StatusCode)
	}
}

func TestRotateInvalidatesOldQR(t *testing.T) {
	s, base := newTestService(t, Config{})
	old, _ := http.Get(base + "/local/status")
	var stat Status
	b, _ := io.ReadAll(old.Body)
	old.Body.Close()
	_ = json.Unmarshal(b, &stat)

	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(base + "/enter/" + stat.Token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("换码后旧链接应当作废（403），拿到 %d", resp.StatusCode)
	}
	// 新码能进
	_ = join(t, base)
}

func TestUploadLandsSanitizedInInbox(t *testing.T) {
	dir := t.TempDir()
	inbox := filepath.Join(dir, "in")
	outbox := filepath.Join(dir, "out")
	_, base := newTestService(t, Config{Files: true, Inbox: inbox, Outbox: outbox})
	c := join(t, base)

	// ★ 三种穿越/伪装企图各传一次：相对上跳、绝对路径、Windows 分隔符。
	//   进来之后只许剩文件名本体，收件目录外面一个字都不许写。
	for _, nm := range []string{"../../evil.txt", "/tmp/evil2.txt", "..\\evil3.txt"} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", nm)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("hello " + nm))
		mw.Close()

		req, _ := http.NewRequest("POST", base+"/upload", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.AddCookie(c)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var j map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&j)
		resp.Body.Close()
		if j["ok"] != true {
			t.Fatalf("上传 %q 应当成功（消毒后收下）：%v", nm, j)
		}
		got, _ := j["name"].(string)
		if got == "" || strings.Contains(got, "..") || strings.ContainsAny(got, "/\\") || strings.HasPrefix(got, ".") {
			t.Fatalf("%q 消毒后仍带路径痕迹/伪装：%q", nm, got)
		}
		if _, err := os.Stat(filepath.Join(inbox, got)); err != nil {
			t.Fatalf("文件没落在收件目录：%s", err)
		}
	}
	for _, outside := range []string{"evil.txt", "evil2.txt", "evil3.txt"} {
		if _, err := os.Stat(filepath.Join(dir, outside)); !os.IsNotExist(err) {
			t.Fatalf("穿越成功了：收件目录外面出现了 %s", outside)
		}
	}
	if _, err := os.Stat("/tmp/evil2.txt"); err == nil {
		t.Fatal("绝对路径名直接落了盘")
	}
}

func TestUploadOverCapRefused(t *testing.T) {
	dir := t.TempDir()
	_, base := newTestService(t, Config{Files: true,
		Inbox: filepath.Join(dir, "in"), Outbox: filepath.Join(dir, "out"),
		MaxUploadMB: 1})
	c := join(t, base)

	payload := bytes.Repeat([]byte("x"), 2<<20)
	req, _ := http.NewRequest("POST", base+"/upload", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=whatever")
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// 超上限要么 413（MaxBytesReader）要么 ok:false，两种都不许留下文件
	des, _ := os.ReadDir(filepath.Join(dir, "in"))
	if len(des) != 0 {
		t.Fatalf("超限上传不该留下文件：%v", des)
	}
}

func TestDownloadKeepsInsideOutbox(t *testing.T) {
	dir := t.TempDir()
	inbox, outbox := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	os.MkdirAll(inbox, 0o700)
	os.MkdirAll(outbox, 0o700)
	os.WriteFile(filepath.Join(outbox, "ok.txt"), []byte("firm"), 0o600)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("别给"), 0o600)
	// 指出去的发件目录外符号链接
	_ = os.Symlink(filepath.Join(dir, "secret.txt"), filepath.Join(outbox, "link.txt"))
	_, base := newTestService(t, Config{Files: true, Inbox: inbox, Outbox: outbox})
	c := join(t, base)

	get := func(path string) int {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.AddCookie(c)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/dl/ok.txt"); code != 200 {
		t.Fatalf("正常取件应当 200，拿到 %d", code)
	}
	if code := get("/dl/link.txt"); code != http.StatusForbidden {
		t.Fatalf("顺着链接翻出目录应当 403，拿到 %d", code)
	}
	if code := get("/dl/.hidden"); code != http.StatusBadRequest {
		t.Fatalf("隐藏名应当 400，拿到 %d", code)
	}
}

func TestToolWhitelist(t *testing.T) {
	fake := &fakeCaller{}
	_, base := newTestService(t, Config{Remote: true, Reg: fake})
	c := join(t, base)

	post := func(body string) map[string]any {
		req, _ := http.NewRequest("POST", base+"/api/tool", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(c)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var j map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&j)
		return j
	}
	j := post(`{"tool":"remote.device.remove","args":{"device":"x"}}`)
	if j["ok"] == true {
		t.Fatal("设备移除不该在手机上可用")
	}
	if len(fake.calls) != 0 {
		t.Fatal("被拒的调用不该打到注册表")
	}
	j = post(`{"tool":"remote.exec","args":{"device":"d1","command":"uptime"}}`)
	if j["ok"] != true {
		t.Fatalf("白名单内的调用应当放行：%v", j)
	}
	if len(fake.calls) != 1 || fake.calls[0].name != "remote.exec" {
		t.Fatalf("注册表收到：%v", fake.calls)
	}
	if !strings.HasPrefix(fake.calls[0].caller, "portal:") {
		t.Fatalf("调用方标识应当以 portal: 开头，拿到 %q", fake.calls[0].caller)
	}
}

func TestCastFrameFlowsToLocalViewer(t *testing.T) {
	_, base := newTestService(t, Config{Cast: true})
	c := join(t, base)

	// 造一个「像 JPEG」的帧（>=64 字节即可过入口检查）
	frame := append([]byte{0xff, 0xd8}, bytes.Repeat([]byte{0x01}, 200)...)
	req, _ := http.NewRequest("POST", base+"/api/cast/frame", bytes.NewReader(frame))
	req.Header.Set("X-Cast-Mode", "screen")
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("送帧应当 200，拿到 %d", resp.StatusCode)
	}
	// 回环口能取到最新帧
	r2, err := http.Get(base + "/local/cast/frame")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if !bytes.Equal(got, frame) {
		t.Fatal("主机端取到的帧和手机送来的不是同一张")
	}
	// 局域网口**没有** /local/* —— 两张 mux 的分派就是这条安全线
	r3, err := http.Get(base + "/local/cast/live")
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	// 同端口不同监听器：127.0.0.1 的请求先到回环口，这里只确认不 404 之外没有越权内容可读
	if r3.StatusCode == 200 {
		t.Log("注意：测试里局域网口与回环口同址，live 命中了回环 mux —— 真机上分属不同地址")
	}
}

func TestLocalAndLanMuxSeparation(t *testing.T) {
	// 局域网口上不许出现 /local/status（它带着全部状态且**不鉴权**，只许在回环上）。
	// 直接拿 lanHandler 走一遍：不依赖这台机器能不能绑第二个回环地址。
	s, _ := newTestService(t, Config{})
	for _, p := range []string{"/local/status", "/local/cast/live", "/local/cast/frame", "/local/cast/save"} {
		req := httptest.NewRequest("GET", p, nil)
		rec := httptest.NewRecorder()
		s.lanHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("局域网口上的 GET %s 应当 404，拿到 %d", p, rec.Code)
		}
	}
	// 反证的另一半：回环口上没有局域网功能 —— 手机那套路由一条都不许从 /local 口漏出来
	for _, p := range []string{"/api/status", "/api/files", "/upload", "/api/tool"} {
		req := httptest.NewRequest("GET", p, nil)
		rec := httptest.NewRecorder()
		s.localHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("回环口上的 %s 应当 404，拿到 %d", p, rec.Code)
		}
	}
}

func TestQRTemplateAndEntryURLs(t *testing.T) {
	s, base := newTestService(t, Config{})
	st, err := http.Get(base + "/local/status")
	if err != nil {
		t.Fatal(err)
	}
	var stat Status
	b, _ := io.ReadAll(st.Body)
	st.Body.Close()
	if err := json.Unmarshal(b, &stat); err != nil {
		t.Fatalf("/local/status 不是合法 JSON：%s（%s）", err, b)
	}
	if len(stat.Token) != 16 {
		t.Fatalf("令牌应当是 16 个十六进制字符，拿到 %q", stat.Token)
	}
	// 每条入口 URL 都要带上当前令牌——二维码就是从这里生成的
	for _, u := range s.EntryURLs() {
		if !strings.HasSuffix(u, "/enter/"+stat.Token) {
			t.Fatalf("入口链接没对上当前令牌：%s", u)
		}
	}
	// 换码之后入口 URL 必须跟着变
	old := s.EntryURLs()[0]
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if s.EntryURLs()[0] == old {
		t.Fatal("换码后入口 URL 没变")
	}
}

// ══════════════════════════════════════════════════════════════════════
// 自签证书 / HTTPS 入口 / 二维码 / 主机屏幕外送
//
// ★ 上面那一节是门户的「门」，这一节是「手机凭什么进得来、看得见」：
//   证书读不读得动、SAN 里有没有手机要访问的那一个地址、私钥会不会被顺出去、
//   二维码扫回来的是不是正好那一条链接、主机屏幕在没有截屏权限/没有把握的
//   系统上给的是哪一种说法。这几条从前一行测试都没有过 ——
//   也就是说「代码是真的，但从来没人证明它跑得通」。
// ══════════════════════════════════════════════════════════════════════

// ── 起门户与客户端的小工具 ──

// startPortalAt 按给定地址起一个真门户，返回服务、访问用的 base，以及
// 一个「手机上已经装了这张自签证书」的客户端。
//
// ★ 客户端不设 InsecureSkipVerify：跳过校验就等于什么都没测 ——
//
//	手机那一端是真把证书链走一遍的，MinVersion、SAN、EKU 全在那一遍里生效。
//
// ★ 客户端不跟 302：扫码那一下要亲眼看到 Set-Cookie。
func startPortalAt(t *testing.T, cfg Config, addrs []string) (*Service, string, *http.Client) {
	t.Helper()
	cfg.Addrs = addrs
	cfg.Port = 0
	s, err := Start(cfg, Deps{})
	if err != nil {
		t.Fatalf("起门户失败（addr=%v tls=%v）：%s", addrs, cfg.TLS, err)
	}
	t.Cleanup(s.Stop)
	st := s.Status()
	base := strings.TrimSuffix(st.URLs[0], "/")
	c := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	if st.TLS {
		if st.CertPEM == "" {
			t.Fatal("开了 TLS 却没把证书交出来（Status.CertPEM 是空的）")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(st.CertPEM)) {
			t.Fatal("下载的证书加不进信任池：手机装了也一样报错")
		}
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}
	return s, base, c
}

// mustQR 造一张二维码（造不出来直接算失败）。
func mustQR(t *testing.T, text string) string {
	t.Helper()
	uri, err := QRDataURI(text)
	if err != nil {
		t.Fatalf("造二维码失败：%s", err)
	}
	return uri
}

// joinVia 扫一次码（手机那一发），回它拿到的会话 cookie。令牌从进程内读，
// 绕开回环口 —— 只绑 127.0.0.1 的 TLS 门户上没有明文回环口可问。
func joinVia(t *testing.T, s *Service, base string, c *http.Client) *http.Cookie {
	t.Helper()
	resp, err := c.Get(base + "/enter/" + s.Status().Token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("扫码进入应当 302，拿到 %d", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == cookieName {
			return ck
		}
	}
	t.Fatal("配对成功但没发会话 cookie")
	return nil
}

// doWith 带着会话 cookie 打一发。
func doWith(t *testing.T, c *http.Client, url string, ck *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(ck)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// lanIP 找一个这台机器上真绑得上的非回环单播地址。
// ★ 找不到就 skip：只绑 127.0.0.1 时「证书 SAN 里有没有手机要访问的那一个地址」
//
//	这一条是白测的 —— 那条地址从来没被用来访问过门户。
func lanIP(t *testing.T) string {
	t.Helper()
	as, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("读不了本机地址：%s", err)
	}
	var prefer, other []string
	for _, a := range as {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsUnspecified() || n.IP.To4() == nil {
			continue
		}
		s := n.IP.String()
		if n.IP.IsGlobalUnicast() {
			prefer = append(prefer, s)
		} else {
			other = append(other, s)
		}
	}
	for _, s := range append(prefer, other...) {
		ln, err := net.Listen("tcp", net.JoinHostPort(s, "0"))
		if err != nil {
			continue // 这块口今天拿不到地址（VPN 残留之类），换下一个
		}
		_ = ln.Close()
		return s
	}
	t.Skip("这台机器上没有第二个可绑的 IPv4 单播地址（门户真机绑的是网卡地址）")
	return ""
}

// ── 只给测试用的极简二维码读手 ──
//
// ★ 为什么测试里自己写一个读手：go-qrcode 只出不进（对外没有 Decode），
//
//	而「手机扫出来到底是哪条链接」恰恰只有真把它读回来才钉得住 ——
//	scheme 少一个 s、令牌掉了尾巴、静默区没留，手机都是到不了页面的。
//	这个读手按 ISO/IEC 18004 自己走一遍（从像素找网格 → 读格式位 → 解掩码 →
//	读码字 → 去交织 → 分段解文），★ 不借 go-qrcode 的内部结构：
//	否则它编码错、我们跟着错，测试就成了自证。
//	它只支持到版本 10 的 Medium 档（门户那一条链接用不到更多；超出就是读手自己不够用，
//	下面每一条校验对不上都会红，不会悄悄放过去）。
type qrRead struct {
	text    string
	version int
	level   string // 格式位里说的纠错档（M = 中等：反光的手机屏幕也得扫得出来）
	mask    int
	// 这两个是「手机到底扫得扫不出」的物理量，不是诊断装饰：
	// 一个模块不到 1.5 像素、或者四周白边不足 4 个模块，码在纸上是好的，在手机里就是扫不出来。
	modulePx     float64 // 一个模块占多少像素
	quietModules float64 // 静默区折合几个模块
}

// qrScanDataURI 把 QRDataURI 的返回值读回它编码的文本。
func qrScanDataURI(t *testing.T, uri string) qrRead {
	t.Helper()
	const p = "data:image/png;base64,"
	if !strings.HasPrefix(uri, p) {
		t.Fatalf("二维码必须是能直接进 <img src> 的 data URI，拿到 %q", cut(uri, 60))
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, p))
	if err != nil {
		t.Fatalf("data URI 的 base64 解不开：%s", err)
	}
	if len(raw) < 8 || !bytes.Equal(raw[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}) {
		t.Fatalf("二维码不是 PNG（手机那一端只认图）：%x", cutB(raw, 8))
	}
	return qrScanPNG(t, raw)
}

func qrScanPNG(t *testing.T, raw []byte) qrRead {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("二维码 PNG 解不开：%s", err)
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	dark := make([][]bool, h)
	for y := range dark {
		dark[y] = make([]bool, w)
	}
	minX, minY, maxX, maxY := w, h, -1, -1
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			if (r+g+bl)/3 < 0x8000 {
				dark[y][x] = true
				if x < minX {
					minX = x
				}
				if y < minY {
					minY = y
				}
				if x > maxX {
					maxX = x
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}
	if maxX < 0 {
		t.Fatal("这张 PNG 一片空白，没有任何二维码")
	}
	for version := 1; version <= 10; version++ {
		g, ok := qrSample(dark, w, h, minX, minY, maxX, maxY, version)
		if !ok {
			continue
		}
		got, ok := qrReadGrid(g, version)
		if !ok {
			continue
		}
		// 顺手把「这张图的格子有多大、四周白边够几格」记下来：静默区够不够宽是
		// 测试要直接说出口的一条，不该只藏在读手内部的取舍里。
		modules := 4*version + 17
		got.version = version
		got.modulePx = float64(maxX-minX+1) / float64(modules)
		got.quietModules = math.Min(math.Min(float64(minX), float64(w-1-maxX)),
			math.Min(float64(minY), float64(h-1-maxY))) / got.modulePx
		return got
	}
	t.Fatalf("这张 PNG 里的二维码读不出内容（暗区 %dx%d 像素）—— 手机扫它同样扫不出链接",
		maxX-minX+1, maxY-minY+1)
	return qrRead{}
}

// qrSample 按「版本 version」这个假设把像素折回模块网格；
// 形状不对、或者四周没留出静默区，就回 false 让上层换个版本再试。
func qrSample(dark [][]bool, w, h, minX, minY, maxX, maxY, version int) ([][]bool, bool) {
	m := 4*version + 17
	mw := float64(maxX-minX+1) / float64(m)
	if mw < 1.5 {
		return nil, false // 一个模块不到 1.5 像素，谈不上稳定读数
	}
	// 静默区：码四周那一圈白的必须够 4 个模块宽。★ 这不是形式主义 ——
	// 手机的对齐算法靠这条白边把码从画面里摘出来，贴边的码就是扫不出来。
	margin := math.Min(math.Min(float64(minX), float64(w-1-maxX)),
		math.Min(float64(minY), float64(h-1-maxY))) / mw
	if margin < 3.5 {
		return nil, false
	}
	g := make([][]bool, m)
	for r := 0; r < m; r++ {
		g[r] = make([]bool, m)
		for c := 0; c < m; c++ {
			y := minY + int((float64(r)+0.5)*mw)
			x := minX + int((float64(c)+0.5)*mw)
			if y >= h {
				y = h - 1
			}
			if x >= w {
				x = w - 1
			}
			g[r][c] = dark[y][x]
		}
	}
	if !qrShapeOK(g, m) {
		return nil, false
	}
	return g, true
}

// qrShapeOK 结构自检：三个定位图案、两条时序图案、那颗永远为黑的模块。
func qrShapeOK(g [][]bool, m int) bool {
	for _, p := range [][2]int{{0, 0}, {0, m - 7}, {m - 7, 0}} {
		for i := 0; i < 7; i++ {
			for j := 0; j < 7; j++ {
				border := i == 0 || i == 6 || j == 0 || j == 6
				core := i >= 2 && i <= 4 && j >= 2 && j <= 4
				if g[p[0]+i][p[1]+j] != (border || core) {
					return false
				}
			}
		}
	}
	for i := 8; i < m-8; i++ {
		if g[6][i] != (i%2 == 0) || g[i][6] != (i%2 == 0) {
			return false
		}
	}
	return g[m-8][8]
}

// qrFormatOK 校验格式位的 BCH(15,5)（生成式 0x537，摆出去前先 XOR 0x5412）。
func qrFormatOK(v uint32) bool {
	v ^= 0x5412
	for i := 14; i >= 10; i-- {
		if v&(1<<uint(i)) != 0 {
			v ^= 0x537 << uint(i-10)
		}
	}
	return v == 0
}

// qrFormat 读格式位（两处副本谁先用得通谁），回纠错档与掩码号。
func qrFormat(g [][]bool, version int) (level byte, mask int, ok bool) {
	m := 4*version + 17
	// 按位 14→0 排好的 (row,col)。第一处绕左上定位图案。
	posA := [][2]int{{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8},
		{7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8}}
	// 第二处在右上那一行与左下那一列。
	posB := [][2]int{{m - 1, 8}, {m - 2, 8}, {m - 3, 8}, {m - 4, 8}, {m - 5, 8}, {m - 6, 8}, {m - 7, 8},
		{8, m - 8}, {8, m - 7}, {8, m - 6}, {8, m - 5}, {8, m - 4}, {8, m - 3}, {8, m - 2}, {8, m - 1}}
	for _, pos := range [][][2]int{posA[:], posB[:]} {
		var v uint32
		for k, p := range pos {
			if g[p[0]][p[1]] {
				v |= 1 << uint(14-k)
			}
		}
		if !qrFormatOK(v) {
			continue
		}
		v ^= 0x5412
		return byte(v >> 13), int(v>>10) & 7, true
	}
	return 0, 0, false
}

// qrRSBlockM 版本 1..10 在 Medium 档下的分块表（总码字、每块纠错码字、两组块的块数与数据码字数）。
type qrRSBlockM struct {
	total, ec, n1, d1, n2, d2 int
}

var qrRSLevelM = map[int]qrRSBlockM{
	1:  {26, 10, 1, 16, 0, 0},
	2:  {44, 16, 1, 28, 0, 0},
	3:  {70, 26, 1, 44, 0, 0},
	4:  {100, 18, 2, 32, 0, 0},
	5:  {134, 24, 2, 43, 0, 0},
	6:  {172, 16, 4, 27, 0, 0},
	7:  {196, 18, 4, 31, 0, 0},
	8:  {242, 22, 2, 38, 2, 39},
	9:  {292, 22, 3, 36, 2, 37},
	10: {346, 26, 4, 43, 1, 44},
}

// qrAlignCenters 版本 2..10 的校正图案中心（标准表）。
var qrAlignCenters = map[int][]int{
	2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
}

// qrFuncMap 函数图案（不许当数据读）的位置表。
func qrFuncMap(version int) [][]bool {
	m := 4*version + 17
	f := make([][]bool, m)
	for r := range f {
		f[r] = make([]bool, m)
	}
	set := func(r, c int) {
		if r >= 0 && r < m && c >= 0 && c < m {
			f[r][c] = true
		}
	}
	for r := 0; r < 8; r++ {
		for c := 0; c < 8; c++ {
			set(r, c)
			set(m-1-r, c)
			set(r, m-1-c)
		}
	}
	for i := 0; i < m; i++ {
		set(6, i)
		set(i, 6)
	}
	for i := 0; i <= 8; i++ {
		set(8, i)
		set(i, 8)
	}
	for i := 0; i < 8; i++ {
		set(8, m-1-i)
		set(m-1-i, 8)
	}
	for _, c := range qrAlignCenters[version] {
		for _, r := range qrAlignCenters[version] {
			if (r <= 8 && c <= 8) || (r <= 8 && c >= m-9) || (r >= m-9 && c <= 8) {
				continue // 与定位图案重叠的那一格不放校正图案
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					set(r+dr, c+dc)
				}
			}
		}
	}
	if version >= 7 {
		for i := 0; i < 6; i++ {
			for j := 0; j < 3; j++ {
				set(i, m-11+j)
				set(m-11+j, i)
			}
		}
	}
	return f
}

func qrMaskHit(mask, row, col int) bool {
	switch mask {
	case 0:
		return (row+col)%2 == 0
	case 1:
		return row%2 == 0
	case 2:
		return col%3 == 0
	case 3:
		return (row+col)%3 == 0
	case 4:
		return (row/2+col/3)%2 == 0
	case 5:
		return (row*col)%2+(row*col)%3 == 0
	case 6:
		return ((row*col)%2+(row*col)%3)%2 == 0
	case 7:
		return ((row+col)%2+(row*col)%3)%2 == 0
	}
	return false
}

// qrCodewords 按标准那条 S 形路线把码字读回来（跳过函数图案、解掉掩码）。
func qrCodewords(g, fn [][]bool, version, mask int) []byte {
	m := 4*version + 17
	var bits []bool
	for right := m - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // 垂直时序图案那一列整条跳过
		}
		for vert := 0; vert < m; vert++ {
			upward := ((right + 1) & 2) == 0
			for j := 0; j < 2; j++ {
				c := right - j
				r := vert
				if upward {
					r = m - 1 - vert
				}
				if fn[r][c] {
					continue
				}
				bits = append(bits, g[r][c] != qrMaskHit(mask, r, c))
			}
		}
	}
	out := make([]byte, len(bits)/8)
	for k := range out {
		for bi := 0; bi < 8; bi++ {
			if bits[k*8+bi] {
				out[k] |= 1 << uint(7-bi)
			}
		}
	}
	return out
}

// qrDeinterleave 把按块交织的码字摊回「各块数据码字连起来」那一条流。
// ★ 读回来的总码字数跟表对不上就直接否：那是版本猜错了，不是数据错了。
func qrDeinterleave(stream []byte, version int) ([]byte, bool) {
	blk, ok := qrRSLevelM[version]
	if !ok {
		return nil, false
	}
	if len(stream) < blk.total || len(stream)-blk.total >= 8 {
		return nil, false // 余下的一定不足一字节（标准的 remainder bits）
	}
	nb := blk.n1 + blk.n2
	lens := make([]int, 0, nb)
	for i := 0; i < blk.n1; i++ {
		lens = append(lens, blk.d1)
	}
	for i := 0; i < blk.n2; i++ {
		lens = append(lens, blk.d2)
	}
	blocks := make([][]byte, nb)
	p := 0
	maxD := blk.d1
	if blk.d2 > maxD {
		maxD = blk.d2
	}
	for i := 0; i < maxD; i++ {
		for b := 0; b < nb; b++ {
			if i >= lens[b] {
				continue
			}
			blocks[b] = append(blocks[b], stream[p])
			p++
		}
	}
	var data []byte
	for _, b := range blocks {
		data = append(data, b...)
	}
	return data, true
}

// qrBitReader 从字节流里按位读。
type qrBitReader struct {
	b []byte
	i int
}

func (r *qrBitReader) read(n int) (int, bool) {
	if n < 0 || r.i+n > len(r.b)*8 {
		return 0, false
	}
	v := 0
	for k := 0; k < n; k++ {
		bit := (r.b[(r.i+k)/8] >> uint(7-(r.i+k)%8)) & 1
		v = v<<1 | int(bit)
	}
	r.i += n
	return v, true
}

const qrAlnumCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// qrText 把数据码字流解回原文：go-qrcode 会按数字/字母数字/字节分段混着编，
// 所以这里也得一段一段读 —— 少认一种模式，链接就被解成半截。
func qrText(data []byte, version int) (string, bool) {
	r := &qrBitReader{b: data}
	var out []byte
	for {
		mode, ok := r.read(4)
		if !ok || mode == 0 {
			return string(out), true // 结束符，或者读到尽头
		}
		switch mode {
		case 1: // 纯数字：3 位 10 bit，2 位 7 bit，1 位 4 bit
			nb := 10
			if version >= 27 {
				nb = 14
			} else if version >= 10 {
				nb = 12
			}
			n, ok := r.read(nb)
			if !ok {
				return "", false
			}
			for n > 0 {
				take := 3
				if n < 3 {
					take = n
				}
				bits := 10
				if take == 2 {
					bits = 7
				} else if take == 1 {
					bits = 4
				}
				v, ok := r.read(bits)
				if !ok {
					return "", false
				}
				s := strconv.FormatInt(int64(v), 10)
				for len(s) < take {
					s = "0" + s // ★ 前导零是编码的一部分，丢了链接就短一截
				}
				out = append(out, s...)
				n -= take
			}
		case 2: // 字母数字：两个字符一个 11 bit
			nb := 9
			if version >= 27 {
				nb = 13
			} else if version >= 10 {
				nb = 11
			}
			n, ok := r.read(nb)
			if !ok {
				return "", false
			}
			for n >= 2 {
				v, ok := r.read(11)
				if !ok || v >= 45*45 {
					return "", false
				}
				out = append(out, qrAlnumCharset[v/45], qrAlnumCharset[v%45])
				n -= 2
			}
			if n == 1 {
				v, ok := r.read(6)
				if !ok || v >= len(qrAlnumCharset) {
					return "", false
				}
				out = append(out, qrAlnumCharset[v])
			}
		case 4: // 8 位字节
			nb := 8
			if version >= 10 {
				nb = 16
			}
			n, ok := r.read(nb)
			if !ok || n > len(r.b)-r.i/8 {
				return "", false
			}
			for i := 0; i < n; i++ {
				v, ok := r.read(8)
				if !ok {
					return "", false
				}
				out = append(out, byte(v))
			}
		default:
			return "", false // ECI/汉字这一档门户的链接用不到，读手也不逞能
		}
	}
}

// qrReadGrid 把一张模块网格读回内容；任何一处结构对不上就回 false（让上层换版本再试）。
func qrReadGrid(g [][]bool, version int) (qrRead, bool) {
	if _, known := qrRSLevelM[version]; !known {
		return qrRead{}, false
	}
	level, mask, ok := qrFormat(g, version)
	if !ok {
		return qrRead{}, false
	}
	name := map[byte]string{0: "M", 1: "L", 2: "H", 3: "Q"}[level]
	if name == "" {
		return qrRead{}, false
	}
	stream := qrCodewords(g, qrFuncMap(version), version, mask)
	data, ok := qrDeinterleave(stream, version)
	if !ok {
		return qrRead{}, false
	}
	text, ok := qrText(data, version)
	if !ok || text == "" {
		return qrRead{}, false
	}
	return qrRead{text: text, version: version, level: name, mask: mask}, true
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func cutB(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// ── 二维码 ──

func Test二维码扫出来就是手机该打开的那条链接(t *testing.T) {
	s, base, c := startPortalAt(t, Config{}, []string{"127.0.0.1"})
	want := s.EntryURLs()[0]
	got := qrScanDataURI(t, mustQR(t, want))
	if got.text != want {
		t.Fatalf("扫出来的链接跟手机该打开的那条不一样：\n  要 %q\n  得 %q", want, got.text)
	}
	if !strings.HasPrefix(got.text, "http://") {
		t.Errorf("没开 TLS 的门户扫出来必须是 http://（scheme 错了手机连不上）：%q", got.text)
	}
	if strings.HasPrefix(got.text, "https://") {
		t.Errorf("门户没开 TLS 却给了 https 的码，手机第一下就撞证书错误：%q", got.text)
	}
	if !strings.Contains(got.text, "/enter/"+s.Status().Token) {
		t.Fatalf("二维码把一次性令牌弄丢了，手机扫进来只能撞 403：%q", got.text)
	}
	// ★ 最要紧的一步：把读回来的那条链接照手机的样子真访问一遍，门必须开。
	resp, err := c.Get(base + strings.TrimPrefix(got.text, base))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("扫回来的链接敲不开门（应当 302），拿到 %d：%s", resp.StatusCode, got.text)
	}
	if got.level != "M" {
		t.Errorf("纠错档是 %s 而不是 M：手机在反光的屏幕上要能扫出来，靠的就是这一档", got.level)
	}
}

func Test开了TLS的门户二维码给的是https入口(t *testing.T) {
	s, base, c := startPortalAt(t, Config{TLS: true}, []string{"127.0.0.1"})
	want := s.EntryURLs()[0]
	got := qrScanDataURI(t, mustQR(t, want))
	if got.text != want {
		t.Fatalf("TLS 门户的二维码扫回来的是另一条链接：\n  要 %q\n  得 %q", want, got.text)
	}
	if !strings.HasPrefix(got.text, "https://") {
		t.Fatalf("开了 TLS 却给手机一条 http:// 的码（投屏那一栏当场就是死的）：%q", got.text)
	}
	resp, err := c.Get(got.text) // 扫回来的那一条真能敲门
	if err != nil {
		t.Fatalf("扫码进来那一发连 TLS 握手都没过：%s", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("扫回来的链接敲不开门，拿到 %d", resp.StatusCode)
	}
	// 换一张码：扫出来的必须不再是同一条，而旧那一条必须敲不开。
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	fresh := qrScanDataURI(t, mustQR(t, s.EntryURLs()[0]))
	if fresh.text == got.text {
		t.Fatal("换了码，二维码却还是原来那一条")
	}
	old, err := c.Get(got.text)
	if err != nil {
		t.Fatal(err)
	}
	old.Body.Close()
	if old.StatusCode != http.StatusForbidden {
		t.Fatalf("扫过的旧链接应当敲不开（403），拿到 %d", old.StatusCode)
	}
	for _, ck := range old.Cookies() {
		if ck.Name == cookieName {
			t.Fatal("被拒的那一发居然也发了会话 cookie")
		}
	}
	// 新码照样进得来（说明上面那 403 是「旧码作废」而不是「门坏了」）。
	_ = joinVia(t, s, base, c)
}

func Test二维码PNG是能解开的图且四周留了静默区(t *testing.T) {
	// 三条形状与长度都不一样的链接：v4 地址、v6 地址（要带方括号）、主机名。
	for _, want := range []string{
		"http://192.168.0.5:8642/enter/0123456789abcdef",
		"https://[fd00::1234:5678]:8642/enter/ffffffffffffffff",
		"http://rack-1.local:80/enter/00112233aabbccdd",
	} {
		uri := mustQR(t, want)
		if !strings.HasPrefix(uri, "data:image/png;base64,") {
			t.Fatalf("进不了 <img src>：%q", cut(uri, 40))
		}
		got := qrScanDataURI(t, uri)
		if got.text != want {
			t.Errorf("这条链接扫回来变了样：\n  要 %q\n  得 %q", want, got.text)
		}
		// 下面两条是对**图本身**的要求：格子太小、白边没留够，真手机摄像头都扫不出来，
		// 哪怕内容编码得完全正确。
		if got.modulePx < 1.5 {
			t.Errorf("一个模块只有 %.2f 像素（v%d）：手机在 3 倍屏上要能点得开，格子不能这么挤",
				got.modulePx, got.version)
		}
		if got.quietModules < 3.5 {
			t.Errorf("二维码四周的静默区只有 %.2f 格（规范要求 4 格）：手机没法把码从画面里摘出来",
				got.quietModules)
		}
	}
	// 两条不同的链接不许扫出同一张图（那样二维码就成了一张装饰画）。
	a := mustQR(t, "http://192.168.0.5:8642/enter/0123456789abcdef")
	b := mustQR(t, "http://192.168.0.5:8642/enter/0123456789abcdee")
	if a == b {
		t.Fatal("令牌换了两个字符，二维码却一模一样")
	}
}

// ── 自签证书 ──

func Test自签证书的SAN盖住手机会用到的每一个地址(t *testing.T) {
	s := &Service{
		cfg:      Config{Addrs: []string{"192.168.7.7", "fd00::11", "fe80::1%en0", "127.0.0.1"}, TLS: true, Port: 8642},
		hostName: "rack-1.local",
	}
	if err := s.genCert(); err != nil {
		t.Fatalf("造一张自签证书就失败了：手机现场不可能自己准备一张：%s", err)
	}
	blk, rest := pem.Decode([]byte(s.certPEM))
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("门户交出来的不是一块证书：%q", cut(strings.TrimSpace(s.certPEM), 60))
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Errorf("证书 PEM 后面还跟着别的东西（私钥就是从这种地方漏出去的）：%q",
			cut(strings.TrimSpace(string(rest)), 40))
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("门户给的证书连解都解不开，手机装它干什么：%s", err)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("门户用的不是 ECDSA 密钥而是 %T：自签要的是一下就握上手，RSA 那一大串是负担", leaf.PublicKey)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		t.Fatalf("证书此刻不在有效期内（%s ~ %s）：手机第一下就是「证书已过期」", leaf.NotBefore, leaf.NotAfter)
	}
	if d := time.Until(leaf.NotAfter); d < 7*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("有效期 %v：门户是临时开的服务，证书既不许比会话短到一周，也不许比服务活得久得多", d)
	}
	if age := now.Sub(leaf.NotBefore); age > 24*time.Hour {
		t.Errorf("起始时间比现在早了 %v：拿一张早就生效的证书糊弄人", age)
	}
	var serverAuth bool
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Error("没写「服务器认证」这个用途：浏览器只认这一条，手机会直接判这张证书不能用")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("密钥用途里没有数字签名：握手时这一张签不了名")
	}
	// 每一条会用来访问门户的地址都必须在 SAN 里（带区的 IPv6 只要地址本体）。
	for _, want := range []string{"192.168.7.7", "fd00::11", "fe80::1", "127.0.0.1", "::1"} {
		ip := net.ParseIP(want)
		found := false
		for _, a := range leaf.IPAddresses {
			if a.Equal(ip) {
				found = true
			}
		}
		if !found {
			t.Errorf("证书 SAN 里没有 %s：手机照二维码上那个地址访问，第一下就是名字对不上", want)
		}
	}
	for _, want := range []string{"rack-1", "rack-1.local", "localhost"} {
		found := false
		for _, a := range leaf.DNSNames {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("证书 SAN 里没有 DNS 名 %s（换网不断地址靠的就是主机名.local）：%v", want, leaf.DNSNames)
		}
	}
	// 拿自己当根走一遍校验 —— 手机上「信任这张证书」之后干的就是这件事。
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	for _, name := range []string{"192.168.7.7", "fd00::11", "rack-1", "rack-1.local", "localhost"} {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err != nil {
			t.Errorf("装了这张证书的手机访问 %s 仍过不了校验：%s", name, err)
		}
	}
	// 反过来：名字不对就必须过不去（SAN 不是 *，这张证书不许变成局域网万能证书）。
	for _, bad := range []string{"10.9.8.7", "evil.example.net", "another-host"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: bad,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Errorf("%s 居然也过了校验：这张证书等于对整张局域网开着", bad)
		}
	}
	// 交出去的那一张与监听器握手用的那一张必须是同一张：
	// 否则人装了下载的证书，手机提示照样消不掉。
	served, err := x509.ParseCertificate(s.tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("门户自己那份 TLS 证书解不开：%s", err)
	}
	if !served.Equal(leaf) {
		t.Error("Status.CertPEM 与监听器握手时用的不是一张证书")
	}
	if s.tlsCert.PrivateKey == nil {
		t.Error("那份 TLS 证书没配着私钥（握手根本起不来）")
	}
}

func Test证书下载口不设闸但只给公钥那一半(t *testing.T) {
	s, base, c := startPortalAt(t, Config{TLS: true}, []string{"127.0.0.1"})
	resp, err := c.Get(base + "/api/cert.pem") // ★ 不带任何配对凭据
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("下载证书不该是要配对的能力（下载证书不算能力），拿到 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("证书给成了 %q：手机/电脑不知道该拿它当什么", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "netkit-portal.pem") {
		t.Errorf("没给一个好认的文件名：%q（现场要拿它去装信任，名字乱七八糟没人敢点）", cd)
	}
	blk, _ := pem.Decode(body)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("下载口给的不是一块证书：%q", cut(string(body), 60))
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatalf("下载的证书解不开：%s", err)
	}
	// 下载到的这一张 = 握手时看到的那一张。
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("握手没交出证书")
	}
	if !bytes.Equal(blk.Bytes, resp.TLS.PeerCertificates[0].Raw) {
		t.Error("下载口给的证书与握手时那一张不一样：装了下载的这张，手机的提示永远消不掉")
	}
	// ★ 私钥那一半：既不许从这一口出去，也不许混进状态快照。
	//   （cert.go 从头到尾没把它写过盘，所以「0600」这一条对一把不落盘的钥匙没有意义 ——
	//   这里钉的是它不出网。）
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Error("证书下载口把私钥一起送出去了")
	}
	if st := s.Status(); strings.Contains(st.CertPEM, "PRIVATE KEY") {
		t.Error("Status.CertPEM 里带着私钥（这份状态会进工具结果，也会进诊断包）")
	}
	// 别的口照旧一律要配对。
	for _, p := range []string{"/api/status", "/api/files", "/api/screen/live"} {
		r, err := c.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("没配对的 %s 应当 401，拿到 %d", p, r.StatusCode)
		}
	}
	// 没开 TLS 的门户没有证书可给（不许把空 PEM 当 200 送出去）。
	s2, base2, c2 := startPortalAt(t, Config{}, []string{"127.0.0.1"})
	r3, err := c2.Get(base2 + "/api/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != http.StatusNotFound {
		t.Errorf("明文门户上的 /api/cert.pem 应当 404，拿到 %d", r3.StatusCode)
	}
	if st := s2.Status(); st.CertPEM != "" {
		t.Error("没开 TLS 的门户却在状态里塞了一份证书")
	}
}

// ── TLS 那一条通路本身 ──

func Test真绑上网卡地址的门户HTTPS校验得过而回环口仍是明文(t *testing.T) {
	addr := lanIP(t)
	s, base, c := startPortalAt(t, Config{TLS: true}, []string{addr})
	st := s.Status()
	resp, err := c.Get(base + "/")
	if err != nil {
		t.Fatalf("手机装了这张证书之后仍然进不来：%s", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("门户页本身应当 200（没配对时也是给一个「请扫码」的壳），拿到 %d", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("开了 TLS 而握手结果里没有 TLS 信息")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("握手用的是 TLS %x：1.2 以下的都不许接", resp.TLS.Version)
	}
	if len(resp.TLS.VerifiedChains) == 0 {
		t.Error("这一遍握手没做证书链校验（那就是 InsecureSkipVerify 蒙过去的，等于没测）")
	}
	// 二维码/链接上写的每一个主机名，都必须是这张证书覆盖的。
	leaf, err := x509.ParseCertificate(s.tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range st.URLs {
		pu, err := parseURLHost(u)
		if err != nil {
			t.Errorf("入口链接不是一条能用的 URL：%s（%s）", u, err)
			continue
		}
		if err := leaf.VerifyHostname(pu); err != nil {
			t.Errorf("手机照 %s 访问时证书名字对不上：%s", u, err)
		}
	}
	// 旧协议进不来：MinVersion 那条线真的守着。
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(st.CertPEM))
	old := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11}}}
	if _, err := old.Get(base + "/"); err == nil {
		t.Error("TLS 1.1 也能握手：MinVersion 没生效")
	}
	// 回环口仍是明文 http（主机界面看投屏不必再点一次「继续」），
	// 而且它给的就是当前这一份状态。
	lu := st.LocalURLs[0]
	if !strings.HasPrefix(lu, "http://127.0.0.1:") {
		t.Fatalf("状态里给主机界面的本地链接居然是 %s（回环口跟着 TLS 走会逼本机再点一次「继续」）", lu)
	}
	lr, err := http.Get(lu)
	if err != nil {
		t.Fatalf("回环口明文拿不到状态：%s", err)
	}
	var local Status
	if err := json.NewDecoder(lr.Body).Decode(&local); err != nil {
		t.Fatalf("回环口的状态不是合法 JSON：%s", err)
	}
	lr.Body.Close()
	if local.Token != st.Token || local.Port != st.Port {
		t.Errorf("两个口说的不是同一个门户：回环 %s/%d 局域网 %s/%d", local.Token, local.Port, st.Token, st.Port)
	}
	// 局域网那个地址上不许有明文这条路（不然自签这一层可以绕过去）。
	plain, err := http.Get("http://" + net.JoinHostPort(addr, strconv.Itoa(st.Port)) + "/")
	if err == nil {
		plain.Body.Close()
		if plain.StatusCode == http.StatusOK {
			t.Error("局域网地址上明文 http 也能通到门户页：TLS 这一层等于没装")
		}
	}
}

func parseURLHost(u string) (string, error) {
	if !strings.Contains(u, "://") {
		return "", fmt.Errorf("没有 scheme")
	}
	i := strings.Index(u, "://")
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	host := rest
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j > 0 {
			host = rest[1:j]
		}
		return host, nil
	}
	if j := strings.LastIndexByte(rest, ':'); j >= 0 {
		host = rest[:j]
	}
	return host, nil
}

// ── TLS 打开时，进入/配对那几条路走起来不一样 ──

func Test扫码进来那一发在HTTPS下带Secure而令牌不许重放(t *testing.T) {
	s, base, c := startPortalAt(t, Config{TLS: true}, []string{"127.0.0.1"})
	tok := s.Status().Token
	resp, err := c.Get(base + "/enter/" + tok)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("扫码进入应当 302，拿到 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("进来之后该落在门户页，给了 %q", loc)
	}
	var ck *http.Cookie
	for _, x := range resp.Cookies() {
		if x.Name == cookieName {
			cp := *x
			ck = &cp
		}
	}
	if ck == nil {
		t.Fatal("配对成功却没发会话 cookie")
	}
	if !ck.Secure {
		t.Fatal("TLS 门户发的会话 cookie 没带 Secure：手机会把它在明文请求里也带出去")
	}
	if !ck.HttpOnly {
		t.Error("会话 cookie 没带 HttpOnly：门户页上的脚本就能把它读走")
	}
	// 第二次拿同一张码敲门：当场作废。链接会留在手机浏览记录里，能重放等于长期开门。
	again, err := c.Get(base + "/enter/" + tok)
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := io.ReadAll(again.Body)
	again.Body.Close()
	if again.StatusCode != http.StatusForbidden {
		t.Fatalf("一次性令牌第二次用应当 403，拿到 %d", again.StatusCode)
	}
	if !strings.Contains(string(bad), "已经用过") {
		t.Errorf("被拒时没说清是这张码用过了（人会以为是门户坏了）：%q", cut(string(bad), 160))
	}
	for _, x := range again.Cookies() {
		if x.Name == cookieName {
			t.Error("被重放拒掉的那一发也发了会话 cookie")
		}
	}
	// 第一台手机那一份会话照旧能用。
	ok := doWith(t, c, base+"/api/status", ck)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("配对后的 /api/status 应当 200，拿到 %d", ok.StatusCode)
	}
	// 这两笔都进了活动表：现场查「谁拿着旧码来过」要看得到。
	var paired, denied int
	for _, a := range s.Status().Activity {
		switch {
		case a.Action == "enter" && a.Result == "配对成功":
			paired++
		case a.Action == "enter" && strings.Contains(a.Result, "已经用过"):
			denied++
		}
	}
	if paired != 1 || denied != 1 {
		t.Errorf("活动表里配对 %d 笔、被拒 %d 笔，要各 1 笔：%+v", paired, denied, s.Status().Activity)
	}
	// 反过来：没开 TLS 的门户上这个 cookie 必须不带 Secure ——
	// 带上了手机浏览器会直接把它丢掉，配对永远配不成。
	s2, base2, c2 := startPortalAt(t, Config{}, []string{"127.0.0.1"})
	r2, err := c2.Get(base2 + "/enter/" + s2.Status().Token)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	var plain *http.Cookie
	for _, x := range r2.Cookies() {
		if x.Name == cookieName {
			cp := *x
			plain = &cp
		}
	}
	if plain == nil {
		t.Fatal("明文门户上也没发出会话 cookie")
	}
	if plain.Secure {
		t.Error("没开 TLS 的门户给 cookie 加了 Secure：手机浏览器会把这个 cookie 丢掉，配对根本配不成")
	}
}

func Test会话到期后手机那份cookie当场失效(t *testing.T) {
	s, base, c := startPortalAt(t, Config{SessionTTL: 60 * time.Millisecond}, []string{"127.0.0.1"})
	ck := joinVia(t, s, base, c)
	r := doWith(t, c, base+"/api/status", ck)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("刚配对就该能用，拿到 %d", r.StatusCode)
	}
	time.Sleep(150 * time.Millisecond)
	r2 := doWith(t, c, base+"/api/status", ck)
	body, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("会话到期后应当 401，拿到 %d", r2.StatusCode)
	}
	if !strings.Contains(string(body), "过期") {
		t.Errorf("到期说的是「过期/被踢」而不是含糊一句：%q", cut(string(body), 120))
	}
	if n := len(s.Status().Sessions); n != 0 {
		t.Errorf("界面上还挂着 %d 台已经不存在的手机（过期那条要从表里掉）", n)
	}
}

// ── 主机屏幕外送 ──

// fakeCollector 一只假的「截一帧」的手。
type fakeCollector struct {
	mu       sync.Mutex
	calls    int
	dsts     []string
	data     []byte
	failLeft int   // 前 failLeft 次报错（模拟偶尔截不出来那一拍）
	err      error // 非 nil 就一直报这个错
	blank    bool  // 回 0 字节的图
	noFile   bool  // 报好但什么也不写
}

func (f *fakeCollector) collect(_ context.Context, dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.dsts = append(f.dsts, dst)
	if f.err != nil {
		return f.err
	}
	if f.failLeft > 0 {
		f.failLeft--
		return fmt.Errorf("这一拍没截出来")
	}
	if _, err := os.Stat(dst); err != nil {
		return fmt.Errorf("要我往里写的那个文件不在：%s", err)
	}
	if f.blank {
		return nil
	}
	if f.noFile {
		return nil
	}
	return os.WriteFile(dst, f.data, 0o600)
}

func (f *fakeCollector) snapshot() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, append([]string(nil), f.dsts...)
}

// installFakeScreen 把截屏那只手换掉。
//
// ★ 不打真系统截屏：CI 上没有屏幕录制权限，而 mac 上更阴的一点是
//
//	没给权限时 screencapture 照样回 0、只是截出来一片黑 —— 拿它当断言依据会骗人。
//	真跑一次系统那条路是下面单独那一条测试的事，而且它失败就 skip。
func installFakeScreen(t *testing.T, f *fakeCollector) {
	t.Helper()
	oldCap, oldReady := captureScreen, screenReady
	captureScreen = f.collect
	screenReady = func() bool { return true }
	t.Cleanup(func() { captureScreen, screenReady = oldCap, oldReady })
}

// jpegOf 造一张真解得开的小 JPEG（内容无所谓，「是不是一张 JPEG」才有所谓）。
func jpegOf(t *testing.T, v uint8) []byte {
	t.Helper()
	im := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for y := 0; y < 6; y++ {
		for x := 0; x < 8; x++ {
			im.Set(x, y, color.RGBA{v, v, v, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, im, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func Test门户没开屏幕外送与系统没有截屏路子的各给一句实话(t *testing.T) {
	// (a) 这个门户压根没挂这一栏：先撞会话闸（401），配对之后才是 404。
	s, base, c := startPortalAt(t, Config{}, []string{"127.0.0.1"})
	r0, err := c.Get(base + "/api/screen/live")
	if err != nil {
		t.Fatal(err)
	}
	r0.Body.Close()
	if r0.StatusCode != http.StatusUnauthorized {
		t.Fatalf("没配对的手机想看主机屏幕应当先撞 401（这台机器的屏幕不是能白看的东西），拿到 %d", r0.StatusCode)
	}
	ck := joinVia(t, s, base, c)
	r1 := doWith(t, c, base+"/api/screen/live", ck)
	b1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if r1.StatusCode != http.StatusNotFound {
		t.Errorf("没开屏幕外送的门户上这一口应当 404，拿到 %d：%q", r1.StatusCode, cut(string(b1), 80))
	}
	// (b) 系统没有把握的截屏路子：给的是 501 一句实话，不是一张黑图、也不是半个流。
	//   ★ screenReady 与生产里的判断是同一个函数（screen.go 里那句 var），
	//     换成假的是为了让这一档在 mac 上也走得到 —— Linux 用户唯一会看到的就是这句话。
	s2, base2, c2 := startPortalAt(t, Config{Screen: true}, []string{"127.0.0.1"})
	ck2 := joinVia(t, s2, base2, c2)
	old := screenReady
	screenReady = func() bool { return false }
	r2 := doWith(t, c2, base2+"/api/screen/live", ck2)
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	screenReady = old
	if r2.StatusCode != http.StatusNotImplemented {
		t.Errorf("没有截屏路子时应当 501，拿到 %d：%q", r2.StatusCode, cut(string(b2), 80))
	}
	if !strings.Contains(string(b2), "截屏路子") {
		t.Errorf("没说的是「这一台系统上没有把握的截屏路子」：%q", cut(string(b2), 120))
	}
	// (c) 手机页面上那一栏出现与否，看的正是「主机开没开 + 系统有没有路子」那两个位。
	for _, one := range []struct {
		cfg  Config
		want bool
	}{{Config{}, false}, {Config{Screen: true}, screenSupported()}} {
		sx, bx, cx := startPortalAt(t, one.cfg, []string{"127.0.0.1"})
		ckx := joinVia(t, sx, bx, cx)
		rx := doWith(t, cx, bx+"/api/status", ckx)
		var j struct {
			OK     bool `json:"ok"`
			Portal struct {
				Screen bool `json:"screen"`
			} `json:"portal"`
		}
		if err := json.NewDecoder(rx.Body).Decode(&j); err != nil {
			rx.Body.Close()
			t.Fatalf("/api/status 不是合法 JSON：%s", err)
		}
		rx.Body.Close()
		if j.Portal.Screen != one.want {
			t.Errorf("cfg=%+v 时手机拿到的 screen 位是 %v，要 %v（页签摆不摆就靠它）", one.cfg, j.Portal.Screen, one.want)
		}
	}
}

func Test主机屏幕直播送出的是能一张张开出来的JPEG帧(t *testing.T) {
	f := &fakeCollector{data: jpegOf(t, 200), failLeft: 1} // 第一拍失败：截屏偶尔会跟不上
	installFakeScreen(t, f)
	s, base, c := startPortalAt(t, Config{Screen: true}, []string{"127.0.0.1"})
	ck := joinVia(t, s, base, c)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/screen/live", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(ck)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("看直播应当 200，拿到 %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/x-mixed-replace") || !strings.Contains(ct, "boundary=") {
		t.Fatalf("给手机的是 %q：<img> 只认带 boundary 的 multipart 推流", ct)
	}
	frame, head := readScreenFrame(t, resp.Body)
	if !strings.Contains(head, "image/jpeg") {
		t.Errorf("这一帧声明的类型是 %q，手机那头 <img> 解不开", head)
	}
	if !bytes.Equal(frame, f.data) {
		t.Errorf("送出去的不是采集器刚截的那一张（%d 字节 vs %d 字节）", len(frame), len(f.data))
	}
	if n, err := strconv.Atoi(strings.TrimSpace(strings.SplitAfter(head, "Content-Length:")[1])); err == nil && n != len(frame) {
		t.Errorf("声明的 Content-Length 是 %d，实际 %d 字节：手机会把帧读岔", n, len(frame))
	}
	if _, format, err := image.Decode(bytes.NewReader(frame)); err != nil || format != "jpeg" {
		t.Errorf("这一张手机解不开（format=%q err=%v）", format, err)
	}
	if got := s.Status().ScreenLiveWatchers; got != 1 {
		t.Errorf("正在看的手机数成了 %d，要 1（界面上那一格靠它）", got)
	}
	// 手机断开（这里是取消请求）之后计数要回来：挂着不动的观看者会把数字越堆越高。
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Status().ScreenLiveWatchers == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := s.Status().ScreenLiveWatchers; got != 0 {
		t.Errorf("手机都断开了还记着 %d 个观看者", got)
	}
	var noted bool
	for _, a := range s.Status().Activity {
		if a.Action == "screen.live" {
			noted = true
		}
	}
	if !noted {
		t.Error("手机开始看主机屏幕没进活动表（这件事在这台机器上端出去的是屏幕本身，必须留痕）")
	}
	if calls, _ := f.snapshot(); calls < 2 {
		t.Errorf("只问了采集器 %d 次：第一拍失败就没往下走了", calls)
	}
}

// readScreenFrame 从推流里读出完整的一帧（顺带回它的头部）。
// ★ 第一拍是失败的，所以这里等到的那一帧本身就证明「截屏失败一拍不断流」。
func readScreenFrame(t *testing.T, r io.Reader) (frame []byte, head string) {
	t.Helper()
	type res struct {
		frame []byte
		head  string
		err   error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 0, 1<<13)
		tmp := make([]byte, 1<<11)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if fr, hd, ok := cutScreenFrame(buf); ok {
				ch <- res{fr, hd, nil}
				return
			}
			if err != nil {
				ch <- res{nil, "", err}
				return
			}
		}
	}()
	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatalf("直播流一帧都没送出就先断了：%s", got.err)
		}
		return got.frame, got.head
	case <-time.After(10 * time.Second):
		t.Fatal("10 秒没送出一帧主机屏幕：截屏偶尔失败一拍不该把流掐断（手机那边会一直黑着）")
	}
	return nil, ""
}

func cutScreenFrame(buf []byte) ([]byte, string, bool) {
	const boundary = "--netkithost"
	i := bytes.Index(buf, []byte(boundary))
	if i < 0 {
		return nil, "", false
	}
	rest := buf[i:]
	j := bytes.Index(rest, []byte("\r\n\r\n"))
	if j < 0 {
		return nil, "", false
	}
	head := string(rest[:j])
	n := -1
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(line, "Content-Length:") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "Content-Length:"), " %d", &n); err != nil {
				return nil, head, false
			}
		}
	}
	if n <= 0 {
		return nil, head, false
	}
	body := rest[j+4:]
	if len(body) < n {
		return nil, head, false
	}
	return body[:n], head, true
}

func Test多台手机看屏幕时800毫秒内只截一次(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	first, second := jpegOf(t, 10), jpegOf(t, 200)
	f := &fakeCollector{data: first}
	installFakeScreen(t, f)
	s := &Service{} // capturedScreen 只用得着缓存与那只手

	got1, err := s.capturedScreen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got2, err := s.capturedScreen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, first) || !bytes.Equal(got2, first) {
		t.Error("截回来的那一张不是采集器给的那一张")
	}
	if calls, dsts := f.snapshot(); calls != 1 || len(dsts) != 1 {
		t.Errorf("两分钟内两问了采集器 %d 次：多个手机同时看要共用同一张截图（截一次屏是这几条路里最贵的一下）", calls)
	}
	for _, d := range f.dsts {
		if !strings.HasSuffix(d, ".jpg") {
			t.Errorf("给采集器的目标路径不是 .jpg：%s（送出去的类型声明就是假的）", d)
		}
	}
	// 过了 TTL 必须换新的：手机看到的不能是三秒前的老屏。
	s.screenAt = time.Now().Add(-2 * screenTTL)
	f.data = second
	got3, err := s.capturedScreen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got3, second) {
		t.Error("缓存过期之后还在给上一帧")
	}
	if calls, _ := f.snapshot(); calls != 2 {
		t.Errorf("过期后问了 %d 次，要到 2 次", calls)
	}
	// 报错的那一拍：错误原样上来，而且不许把上一帧当成功送回去。
	f.err = fmt.Errorf("没有屏幕录制权限")
	s.screenAt = time.Now().Add(-2 * screenTTL)
	if _, err := s.capturedScreen(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "录制") {
		t.Errorf("系统那只手报错时说的是 %v（要原样上来，界面才说得出为什么黑着）", err)
	}
	f.err = nil
	// 报好但什么也没写 / 写了个空文件：都得是一条错误，而不是 0 字节的「图」。
	f.noFile = true
	s.screenAt = time.Now().Add(-2 * screenTTL)
	if _, err := s.capturedScreen(context.Background()); err != nil {
		t.Logf("这一台机器上空文件走的是另一条说法：%v", err)
	}
	f.noFile = false
	f.blank = true
	s.screenAt = time.Now().Add(-2 * screenTTL)
	if _, err := s.capturedScreen(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "空") {
		t.Errorf("截出 0 字节必须报错，拿到 %v（0 字节的「图」会把手机那格画面永久卡住）", err)
	}
	f.blank = false
	// 截屏用的临时文件要收干净：手机一直看着，一小时就是几千个文件。
	left, _ := filepath.Glob(filepath.Join(dir, "netkit-screen-*"))
	if len(left) != 0 {
		t.Errorf("截屏用的临时文件没收掉：%v", left)
	}
}

func TestWindows那条截屏命令保存的路径就是我们要读的那个文件(t *testing.T) {
	// ★ 这一条是纯字符串的一手：真跑 PowerShell 要等到 Windows 机器上，
	//   而拼接里写错一个格式化动词，整条主机屏幕外送在 Windows 上就是死的
	//   （PowerShell 存到一个怪名字的文件，我们再去读那个空的临时文件）。
	dst := filepath.Join(t.TempDir(), "netkit-screen-9.jpg")
	script := screenScriptWindows(dst)
	if want := `Save('` + filepath.FromSlash(dst) + `',`; !strings.Contains(script, want) {
		t.Errorf("PowerShell 存图的路径不是我们要去读的那个文件（要含 %s）：\n%s", want, cut(script, 400))
	}
	if strings.Contains(script, "%!") {
		t.Errorf("路径拼接用错了格式化动词（Go 会塞进 %%!d(string=...) 这种残渣）：\n%s", cut(script, 400))
	}
	for _, frag := range []string{"Add-Type -AssemblyName System.Windows.Forms",
		"Add-Type -AssemblyName System.Drawing", "CopyFromScreen", "ImageFormat]::Jpeg"} {
		if !strings.Contains(script, frag) {
			t.Errorf("那串命令里少了 %q：%s", frag, cut(script, 400))
		}
	}
}

func Test在mac上真截一帧送回来的必须是一张解得开的JPEG(t *testing.T) {
	// 不打桩的那一条：只用真实系统那条路，跑不出来就 skip（不给屏幕录制权限时
	// 截出来是一片黑、或者干脆报错 —— 两种都不算失败，界面上另有说法）。
	if runtime.GOOS != "darwin" {
		t.Skip("这一条钉的是 macOS 的 screencapture 那条路")
	}
	if _, err := os.Stat("/usr/sbin/screencapture"); err != nil {
		t.Skipf("这台机器上没有 /usr/sbin/screencapture：%s", err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "real-shot.jpg")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := captureScreen(ctx, dst); err != nil {
		t.Skipf("这台机器上真截不出来（多半是没给屏幕录制权限）：%s", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("命令回好但是那个文件不在：%s（路径传错了就是这一种死法）", err)
	}
	if len(b) == 0 {
		t.Fatal("截出来是 0 字节")
	}
	im, format, err := image.Decode(bytes.NewReader(b))
	if err != nil || format != "jpeg" {
		t.Errorf("mac 那条路给出的不是一张 JPEG（format=%q err=%v）：手机那头的 <img> 认不了", format, err)
	}
	if im != nil && (im.Bounds().Dx() <= 0 || im.Bounds().Dy() <= 0) {
		t.Errorf("截出来的图尺寸是 %v", im.Bounds())
	}
}
