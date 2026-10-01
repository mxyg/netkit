package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── 文件收发 ──
//
// ★ 收件目录是整个门户**唯一的写路径**，而且写进去的一律是「一个新文件」：
//   不许覆盖、不许带路径、不许隐藏名。手机能往这台机器上塞的最坏情况，
//   就是一个封顶大小的新文件躺在收件目录里等人去翻 —— 这是批准的边界，
//   所以它必须出现在批准说明里（见 tools.PortalDescribe）。

func (s *Service) handleFilesList(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.cfg.Files {
		http.Error(w, "这个门户没开文件收发", http.StatusNotFound)
		return
	}
	des, err := os.ReadDir(s.cfg.Outbox)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "发件目录打不开：" + err.Error()})
		return
	}
	type item struct {
		Name  string `json:"name"`
		Bytes int64  `json:"bytes"`
		At    string `json:"at"`
		Dir   bool   `json:"dir"`
	}
	var out []item
	for _, de := range des {
		fi, ierr := de.Info()
		if ierr != nil {
			continue
		}
		if strings.HasPrefix(de.Name(), ".") {
			continue // 隐藏文件不列：收件人看不见它，发件人也不该把它端给手机
		}
		out = append(out, item{Name: de.Name(), Bytes: fi.Size(),
			At: fi.ModTime().Format(time.RFC3339), Dir: de.IsDir()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, map[string]any{"ok": true, "files": out,
		"uploadMaxMB": s.cfg.MaxUploadMB})
}

// handleDownload 只按**单层文件名**取件：路径分隔符一律拒绝，
// 解析完还要过一道「真身还在发件目录里」的检查（符号链接也挡得住）。
func (s *Service) handleDownload(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.cfg.Files {
		http.Error(w, "这个门户没开文件收发", http.StatusNotFound)
		return
	}
	name := r.PathValue("name")
	if name != filepath.Base(name) || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		s.note(sess.Peer, "download", name, "", "被拒：文件名不对")
		http.Error(w, "文件名不对", http.StatusBadRequest)
		return
	}
	full := filepath.Join(s.cfg.Outbox, name)
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		s.note(sess.Peer, "download", name, "", "没找到")
		http.Error(w, "没有这个文件", http.StatusNotFound)
		return
	}
	if !inside(real, s.outboxReal) {
		s.note(sess.Peer, "download", name, "", "被拒：想顺着链接翻出发件目录")
		http.Error(w, "这个文件不在发件目录里", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(real)
	if err != nil || fi.IsDir() {
		http.Error(w, "没有这个文件", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, real)
	s.note(sess.Peer, "download", name, humanBytes(fi.Size()), "ok")
}

// handleUpload 手机 → 主机。流式落盘、封顶、消毒文件名、唯一名不覆盖。
func (s *Service) handleUpload(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.cfg.Files {
		http.Error(w, "这个门户没开文件收发", http.StatusNotFound)
		return
	}
	maxBytes := int64(s.cfg.MaxUploadMB) << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+1<<20) //  multipart 边界留余量
	if err := r.ParseMultipartForm(1 << 22); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.note(sess.Peer, "upload", "", "", fmt.Sprintf("被拒：超过上限 %d MB", s.cfg.MaxUploadMB))
			writeJSON(w, map[string]any{"ok": false,
				"error": fmt.Sprintf("文件超过上限 %d MB", s.cfg.MaxUploadMB)})
			return
		}
		writeJSON(w, map[string]any{"ok": false, "error": "读不到上传内容：" + err.Error()})
		return
	}
	defer r.MultipartForm.RemoveAll()
	f, hdr, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "表单里要有 file 这一栏"})
		return
	}
	defer f.Close()

	name := sanitizeUploadName(hdr.Filename)
	if name == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "文件名看不懂"})
		return
	}
	dst, err := uniquePath(s.cfg.Inbox, name)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		s.note(sess.Peer, "upload", name, "", "写不进去："+err.Error())
		writeJSON(w, map[string]any{"ok": false, "error": "收件目录写不进去：" + err.Error()})
		return
	}
	n, cerr := io.Copy(out, io.LimitReader(f, maxBytes+1))
	out.Close()
	if n > maxBytes {
		os.Remove(dst)
		s.note(sess.Peer, "upload", name, "", "被拒：超过上限")
		writeJSON(w, map[string]any{"ok": false,
			"error": fmt.Sprintf("文件超过上限 %d MB", s.cfg.MaxUploadMB)})
		return
	}
	if cerr != nil {
		os.Remove(dst)
		s.note(sess.Peer, "upload", name, "", "传断了："+cerr.Error())
		writeJSON(w, map[string]any{"ok": false, "error": "上传中断：" + cerr.Error()})
		return
	}
	base := filepath.Base(dst)
	s.note(sess.Peer, "upload", base, humanBytes(n), "已落到收件目录")
	writeJSON(w, map[string]any{"ok": true, "name": base, "bytes": n})
}

// sanitizeUploadName 只留文件名本体，去掉分隔符、开头的点（不许往收件目录
// 塞 .env / .ssh 这类伪装）、控制字符。返回空串表示没法救。
func sanitizeUploadName(raw string) string {
	n := filepath.Base(strings.ReplaceAll(raw, "\\", "/"))
	n = filepath.Base(n)
	n = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return '_'
		}
		return c
	}, n)
	n = strings.TrimLeft(n, ".")
	n = strings.TrimSpace(n)
	if n == "" {
		return ""
	}
	if len(n) > 180 {
		n = n[:180]
	}
	return n
}

// uniquePath 收件目录里永远**新增**，不覆盖已有文件（含已有目录）。
func uniquePath(dir, name string) (string, error) {
	if name == "." || name == ".." {
		return "", errors.New("文件名不对")
	}
	candidate := filepath.Join(dir, name)
	if _, err := os.Stat(candidate); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		return "", err
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 2; i < 1000; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, i, ext))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
	}
	return "", errors.New("同名文件太多，换个名再传")
}

func inside(p, base string) bool {
	if p == base {
		return true
	}
	return strings.HasPrefix(p, base+string(filepath.Separator))
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d 字节", n)
}

// ── 遥控器：把手机上的点转成注册表里的工具调用 ──
//
// ★ 白名单是**点名**的，不是按前缀放宽的：门户只转发这几个动作，
//   其余工具（改登记簿、 forget 主机密钥、 config.set……）在手机上没有入口。
//   改系统的工具照旧会在主机界面弹批准框 —— 手机拿不到「绕过主机确认」这条路。

var portalTools = map[string]bool{
	"remote.device.list":   true,
	"remote.device.probe":  true,
	"remote.sessions":      true,
	"remote.playbook.list": true,
	"remote.playbook.run":  true,
	"remote.exec":          true,
	"remote.msg.send":      true,
	"remote.desktop.open":  true,
}

func (s *Service) handleTool(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.cfg.Remote {
		writeJSON(w, map[string]any{"ok": false, "error": "这个门户没开遥控器"})
		return
	}
	if s.cfg.Reg == nil {
		writeJSON(w, map[string]any{"ok": false, "error": "主机没把工具注册表交给门户"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "读不了请求体"})
		return
	}
	var req struct {
		Tool json.RawMessage `json:"tool"`
		Args json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "请求不是合法 JSON"})
		return
	}
	var name string
	if err := json.Unmarshal(req.Tool, &name); err != nil || !portalTools[name] {
		s.note(sess.Peer, "tool", string(req.Tool), "", "被拒：不在手机可用清单里")
		writeJSON(w, map[string]any{"ok": false,
			"error": "这个动作手机上用不了（只开了设备查看、探测、执行命令、发消息、开桌面、跑剧本）"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	caller := "portal:" + sess.Peer
	result, ierr := s.cfg.Reg.InvokeTool(ctx, caller, name, nonNil(req.Args))
	if ierr != nil {
		s.note(sess.Peer, "tool", name, summarizeToolArgs(name, req.Args), "失败："+ierr.Error())
		writeJSON(w, map[string]any{"ok": false, "error": ierr.Error()})
		return
	}
	s.note(sess.Peer, "tool", name, summarizeToolArgs(name, req.Args), "ok")
	writeJSON(w, map[string]any{"ok": true, "result": result})
}

func nonNil(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("{}")
	}
	return b
}

// summarizeToolArgs 活动表里只留能说明白「干了哪件事」的那一栏：
// 命令内容本身进远程审计（那边有脱敏），活动表不复制第二份。
func summarizeToolArgs(tool string, args json.RawMessage) string {
	var a map[string]any
	_ = json.Unmarshal(args, &a)
	switch v := a["device"].(type) {
	case string:
		return "device=" + v
	}
	return ""
}

// ── 投屏（手机 → 主机）：帧的入口和状态出口 ──

const maxCastFrame = 2 << 20

func (s *Service) handleCastFrame(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.cfg.Cast {
		writeJSON(w, map[string]any{"ok": false, "error": "这个门户没开投屏接收"})
		return
	}
	mode := r.Header.Get("X-Cast-Mode")
	if mode != "screen" && mode != "camera" {
		mode = "screen"
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCastFrame))
	if err != nil || len(data) < 64 {
		writeJSON(w, map[string]any{"ok": false, "error": "这一帧太小或读断了"})
		return
	}
	started := s.putFrame(data, sess.Peer, mode)
	if started {
		s.note(sess.Peer, "cast.start", "", mode, "手机开始投屏")
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Service) handleCastState(w http.ResponseWriter, r *http.Request, sess *Session) {
	writeJSON(w, map[string]any{"ok": true, "cast": s.castSnapshot()})
}

// ── 主机屏幕给手机看（主机 → 手机）──

func (s *Service) handleScreenLive(w http.ResponseWriter, r *http.Request, sess *Session) {
	if !s.cfg.Screen {
		http.Error(w, "主机没开「屏幕给手机看」", http.StatusNotFound)
		return
	}
	if !screenReady() {
		http.Error(w, "这个系统上没有把握的截屏路子，主机屏幕看不了", http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", `multipart/x-mixed-replace; boundary=netkithost`)
	w.Header().Set("Cache-Control", "no-store")
	flusher, _ := w.(http.Flusher)

	s.addScreenWatcher()
	defer s.removeScreenWatcher()
	s.note(sess.Peer, "screen.live", "", "", "手机开始看主机屏幕")

	tick := time.NewTicker(1200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			frame, err := s.capturedScreen(r.Context())
			if err != nil {
				continue // 截一下失败不算断流：下一拍再试，手机那边画面停在上一帧
			}
			_, _ = w.Write([]byte("--netkithost\r\nContent-Type: image/jpeg\r\nContent-Length: "))
			_, _ = w.Write([]byte(strconv.Itoa(len(frame))))
			_, _ = w.Write([]byte("\r\n\r\n"))
			_, _ = w.Write(frame)
			_, _ = w.Write([]byte("\r\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

func (s *Service) addScreenWatcher() {
	s.mu.Lock()
	s.screenWatchers++
	s.mu.Unlock()
}

func (s *Service) removeScreenWatcher() {
	s.mu.Lock()
	s.screenWatchers--
	s.mu.Unlock()
}
