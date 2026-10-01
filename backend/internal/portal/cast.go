package portal

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ── 投屏帧：收、存、播 ──
//
// ★ 为什么不开 WebSocket：手机那一端只要能连续 POST 小 JPEG 就够了，
//   主机这一端要看的（界面直播窗）也只是「最新一帧 + 后续帧推流」。
//   multipart 推流 + 短 POST 是两端都不用引依赖、后台挂起也能自然断的写法。

const (
	castActiveWindow = 12 * time.Second // 最后一帧在这窗口内才算「还在投」
	castStaleWindow  = 5 * time.Second  // 超过这个没新帧 = 停在老帧上
)

// putFrame 收一帧。返回是不是这次投屏的第一帧（用来记一条活动）。
func (s *Service) putFrame(data []byte, peer, mode string) bool {
	now := time.Now()
	s.castMu.Lock()
	first := !s.cast.Active || s.cast.Peer != peer ||
		s.cast.LastAt == nil || now.Sub(*s.cast.LastAt) > castActiveWindow
	if s.cast.LastAt != nil && now.Sub(*s.cast.LastAt) > castActiveWindow {
		s.cast.Frames, s.cast.Bytes = 0, 0 // 新一轮从头数
	}
	s.castFrame = data
	s.cast = CastState{
		Active: true, Peer: peer, Mode: mode,
		Frames: s.cast.Frames + 1, Bytes: s.cast.Bytes + int64(len(data)),
		LastAt: &now,
	}
	for ch := range s.subs {
		select {
		case ch <- data:
		default: // 观看者跟不上就丢旧帧：投屏宁可跳帧也不积压
		}
	}
	s.castMu.Unlock()
	return first
}

func (s *Service) castSnapshot() CastState {
	s.castMu.Lock()
	defer s.castMu.Unlock()
	c := s.cast
	if c.LastAt != nil {
		age := time.Since(*c.LastAt)
		c.Stale = age > castStaleWindow
		c.Active = age <= castActiveWindow
		if !c.Active {
			c.Peer, c.Mode = "", ""
		}
	}
	return c
}

// handleCastLive 投屏直播（给主机界面，也顺带给已配对的其它手机看）。
// 走 multipart 推流：一个 <img> 就完事，界面不写一行帧处理代码。
func (s *Service) handleCastLive(w http.ResponseWriter, r *http.Request) {
	s.castMu.Lock()
	if s.closed {
		s.castMu.Unlock()
		http.Error(w, "门户没在跑", http.StatusServiceUnavailable)
		return
	}
	ch := make(chan []byte, 2)
	s.subs[ch] = struct{}{}
	latest := s.castFrame
	s.castMu.Unlock()
	defer func() {
		s.castMu.Lock()
		delete(s.subs, ch)
		s.castMu.Unlock()
	}()

	w.Header().Set("Content-Type", `multipart/x-mixed-replace; boundary=netkitframe`)
	w.Header().Set("Cache-Control", "no-store")
	flusher, _ := w.(http.Flusher)
	write := func(data []byte) bool {
		_, err := w.Write([]byte("--netkitframe\r\nContent-Type: image/jpeg\r\nContent-Length: "))
		if err != nil {
			return false
		}
		_, _ = w.Write([]byte(strconv.Itoa(len(data))))
		if _, err := w.Write([]byte("\r\n\r\n")); err != nil {
			return false
		}
		if _, err := w.Write(data); err != nil {
			return false
		}
		_, err = w.Write([]byte("\r\n"))
		if flusher != nil {
			flusher.Flush()
		}
		return err == nil
	}
	// 先补一帧当前的：刚点开的窗口不该先黑几秒。
	if len(latest) > 0 {
		if !write(latest) {
			return
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return // 门户停了：流断，界面自己会把这格渲染成「投屏已停」
			}
			if !write(data) {
				return
			}
		}
	}
}

func (s *Service) handleCastFrameLatest(w http.ResponseWriter, r *http.Request) {
	s.castMu.Lock()
	frame := s.castFrame
	s.castMu.Unlock()
	if len(frame) == 0 {
		http.Error(w, "还没有帧", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(frame)
}

// handleCastSave 把当前这一帧存成文件（抓拍现场证据用）。
// 落 SnapDir；没给 SnapDir 就不提供这个动作，不往收件目录里混。
func (s *Service) handleCastSave(w http.ResponseWriter, r *http.Request) {
	s.castMu.Lock()
	frame := append([]byte(nil), s.castFrame...)
	peer := s.cast.Peer
	s.castMu.Unlock()
	if len(frame) == 0 {
		writeJSON(w, map[string]any{"ok": false, "error": "现在没有可存的帧"})
		return
	}
	if strings.TrimSpace(s.cfg.SnapDir) == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "主机没设投屏抓拍目录"})
		return
	}
	if err := ensureDir(s.cfg.SnapDir); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	name := fmt.Sprintf("投屏-%s.jpg", time.Now().Format("20060102-150405"))
	dst := filepath.Join(s.cfg.SnapDir, name)
	if err := os.WriteFile(dst, frame, 0o600); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "存不下：" + err.Error()})
		return
	}
	s.note("host", "cast.save", peer, name, "已存这一帧")
	writeJSON(w, map[string]any{"ok": true, "path": dst})
}
