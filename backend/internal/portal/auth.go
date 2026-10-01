package portal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"time"
)

const cookieName = "nkportal"

// lanHandler 局域网口：除进入页外一律要会话。
func (s *Service) lanHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /enter/{token}", s.handleEntry)
	m.HandleFunc("GET /", s.handlePage)
	m.HandleFunc("GET /api/status", s.auth(s.handleAPISStatus))
	m.HandleFunc("GET /api/files", s.auth(s.handleFilesList))
	m.HandleFunc("GET /dl/{name}", s.auth(s.handleDownload))
	m.HandleFunc("POST /upload", s.auth(s.handleUpload))
	m.HandleFunc("POST /api/tool", s.auth(s.handleTool))
	m.HandleFunc("POST /api/cast/frame", s.auth(s.handleCastFrame))
	m.HandleFunc("GET /api/cast/state", s.auth(s.handleCastState))
	m.HandleFunc("GET /api/screen/live", s.auth(s.handleScreenLive))
	m.HandleFunc("GET /api/cert.pem", s.handleCertPEM) // 下载证书不算能力，不设闸
	return m
}

// lanAPI 过完会话闸的处理函数：第三个参数是已经验证过的会话（含对端 IP）。
type lanAPI func(w http.ResponseWriter, r *http.Request, sess *Session)

// auth 会话闸。[OTS-7.1] 的同一条精神：身份由**进入时那一次扫码**确立，
// 之后请求里自称什么都不算。
func (s *Service) auth(next lanAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			s.reject(w, r, "没带配对凭据：请用主机上的二维码重新进入")
			return
		}
		sess := s.touch(c.Value)
		if sess == nil {
			s.reject(w, r, "配对已过期或被主机踢下线：请用主机上的二维码重新进入")
			return
		}
		next(w, r, sess)
	}
}

func (s *Service) reject(w http.ResponseWriter, r *http.Request, why string) {
	// 被拒也要留痕：现场查「手机说打不开」时，得知道有人带着旧 cookie 来过。
	s.note(peerIP(r), "denied", "", r.URL.Path, why)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": why})
}

// touch 找到会话并记一次活跃。过期/不存在返回 nil。
func (s *Service) touch(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return nil
	}
	sess.LastSeen = now
	sess.Requests++
	cp := *sess
	return &cp
}

// handleEntry 一次性令牌换会话。
//
// ★ 令牌用掉就作废（设计稿「一键开通-安全」那条）：链接会进手机浏览记录，
//
//	不一次性就等于把门长期开着。第二台手机进来要的是**换一张新二维码**
//	（主机界面上的「换一张」按钮），不是把旧链接再发一遍。
func (s *Service) handleEntry(w http.ResponseWriter, r *http.Request) {
	got := r.PathValue("token")
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		http.Error(w, "门户已关闭", http.StatusServiceUnavailable)
		return
	case s.entryUsed:
		s.mu.Unlock()
		s.failEntry(w, r, "这张二维码已经用过了：请让主机界面上的「换一张二维码」点一下再扫")
		return
	case time.Now().After(s.entryExp):
		s.mu.Unlock()
		s.failEntry(w, r, "二维码超时作废了（10 分钟）：让主机换一张新的")
		return
	case subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1:
		s.mu.Unlock()
		s.failEntry(w, r, "令牌不对：请扫主机界面上现在显示的这一张")
		return
	}
	s.entryUsed = true
	id := newID()
	sess := &Session{
		ID: id, Peer: peerIP(r), UA: trimUA(r.UserAgent()),
		JoinedAt: time.Now(), LastSeen: time.Now(),
		ExpiresAt: time.Now().Add(s.cfg.SessionTTL),
	}
	s.sessions[id] = sess
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cfg.TLS,
		Expires: sess.ExpiresAt,
	})
	s.note(sess.Peer, "enter", sess.UA, "", "配对成功")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Service) failEntry(w http.ResponseWriter, r *http.Request, why string) {
	s.note(peerIP(r), "enter", "", r.PathValue("token"), why)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>" +
		"<body style='font:16px/1.6 system-ui;margin:40px auto;max-width:34em;padding:0 20px'>" +
		"<h2>进不去</h2><p>" + why + "</p></body>"))
}

// handlePage 门户页本身：没配对的人只能拿到一个「请扫码」的壳，
// 拿不到功能，也探不到这台机器有什么。
func (s *Service) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess := s.sessionByCookie(r)
	if sess == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(entryHintHTML))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pageHTML)
}

func (s *Service) sessionByCookie(r *http.Request) *Session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	return s.touch(c.Value)
}

// handleAPISStatus 手机页面用它决定摆哪几个功能页签 —— 数据就是门户自己的开关，
// 不外带任何这台机器的信息。
func (s *Service) handleAPISStatus(w http.ResponseWriter, r *http.Request, sess *Session) {
	st := s.Status()
	writeJSON(w, map[string]any{
		"ok": true,
		"me": map[string]any{"peer": sess.Peer, "expiresAt": sess.ExpiresAt},
		"portal": map[string]any{
			"files": st.Files, "remote": st.Remote, "cast": st.Cast,
			"screen": st.Screen && st.ScreenSupported,
			"inbox":  st.Inbox, "hostName": st.HostName,
		},
	})
}

func (s *Service) handleCertPEM(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.TLS || s.certPEM == "" {
		http.Error(w, "这个门户没开 TLS，没有证书可给", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="netkit-portal.pem"`)
	_, _ = w.Write([]byte(s.certPEM))
}

// ── 小工具 ──

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func trimUA(ua string) string {
	if len(ua) > 120 {
		return ua[:120]
	}
	return ua
}

// screenSupported 主机屏幕外送给手机看，一期只支持 macOS / Windows：
// mac 有 screencapture，Windows 有 PowerShell 的 CopyFromScreen，
// 都不必引依赖。Linux 桌面千差万别（Wayland 还锁屏截图），没有把握就不装能。
func screenSupported() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

const entryHintHTML = `<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<body style='font:16px/1.7 system-ui;margin:40px auto;max-width:34em;padding:0 20px'>
<h2>昱弘网通 · 手机门户</h2>
<p>这个页面要用<b>主机界面上的二维码</b>扫码进入 —— 链接带一次性令牌，直接访问地址进不来。</p>
<p>在 NetKit 界面打开「手机互联与投屏」那一页，扫上面那张码。</p>
</body>`
