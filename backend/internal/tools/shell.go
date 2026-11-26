package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/ots"
)

// ═══════════════════════════════════════════════════════════════════════
// 交互式终端会话（remote.shell.*）
//
// 为什么必须有：单条命令（remote.exec）干不了 top、journalctl -f 这类
// 持续输出，也丢不了上下文 —— 现场一半的活靠的是"留在那台机器里"。
//
// ★ 安全规矩（与 remote.exec 同一条）：开一条 shell 等于把那台机器的
//   手脚都交出来了 —— open/close 记审计，读写不逐条弹批准（批准发生在
//   open，同 remote.desk.open 的先例）；缓冲区只留最近 512 KB，
//   口令不进结果、不进日志。
// ═══════════════════════════════════════════════════════════════════════

const shellBufCap = 512 << 10 // 每条会话最多留这么多输出

// shellSessions 在跑的终端会话。键是会话 ID。
var shellSessions = struct {
	mu sync.Mutex
	m  map[string]*shellSession
}{m: map[string]*shellSession{}}

// shellSession 一条活着的 PTY。
//
// ★ client 的生命周期归会话管：dial 出来的连接不能 defer close
//
//	（那是单条命令的写法），要等 close 才断，否则 PTY 一起死。
type shellSession struct {
	id     string
	device string

	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser

	mu      sync.Mutex
	buf     []byte // 最近 shellBufCap 字节的输出（可能被截头）
	trunc   bool   // buf 头是不是被截过（给调用方的诚实提示）
	base    int64  // buf[0] 在全部输出流里的字节序号
	closed  bool
	closeEl error // close 时抓到的第一个错，read 时一并报
}

// shellWriter 把会话的 write 包成 io.Writer（SSH 的 Stdout/Stderr 都灌进同一缓冲）。
type shellWriter struct{ s *shellSession }

func (w *shellWriter) Write(p []byte) (int, error) { return w.s.write(p) }

func (s *shellSession) write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if len(s.buf)+len(p) > shellBufCap {
		drop := len(s.buf) + len(p) - shellBufCap
		if drop >= len(s.buf) {
			s.base += int64(len(s.buf))
			s.buf = s.buf[:0]
		} else {
			s.buf = append(s.buf[:0], s.buf[drop:]...)
			s.base += int64(drop)
		}
		s.trunc = true
	}
	s.buf = append(s.buf, p...)
	return len(p), nil
}

// since 从流序号 offset 起取输出。offset 过旧（已被环形缓冲扔掉）时从头给。
func (s *shellSession) since(offset int64) (data []byte, newOff int64, truncated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.base + int64(len(s.buf))
	if offset < s.base {
		offset = s.base
		truncated = s.trunc
	}
	if offset > end {
		offset = end
	}
	out := make([]byte, end-offset)
	copy(out, s.buf[offset-s.base:])
	return out, end, truncated
}

func shellSessionOf(id string) (*shellSession, bool) {
	shellSessions.mu.Lock()
	defer shellSessions.mu.Unlock()
	s, ok := shellSessions.m[id]
	return s, ok
}

func shellDrop(id string) {
	shellSessions.mu.Lock()
	defer shellSessions.mu.Unlock()
	delete(shellSessions.m, id)
}

// ── remote.shell.open（mutate：开的就是一条全权终端）──

var shellOpenTool = ots.Tool{
	Name:  "remote.shell.open",
	Class: ots.ClassMutate,
	Summary: "在一台登记过的设备上开一条**交互式终端**（PTY），之后用 remote.shell.read 收输出、" +
		"remote.shell.write 发按键，remote.shell.close 关掉。单条命令（remote.exec）干不了的事——" +
		"top、journalctl -f、需要上下文的现场排查——走这里。" +
		"★ open 这一次要人批准，之后的读写算在这一次批准里；open/close 全程审计。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {
	    "device": {"type": "string", "description": "设备 ID（user@host）或 host"},
	    "cols": {"type": "integer", "minimum": 20, "maximum": 500, "description": "终端列数，默认 100"},
	    "rows": {"type": "integer", "minimum": 5, "maximum": 200, "description": "终端行数，默认 30"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Device string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return "在远程设备 " + a.Device + " 上开一条交互式终端（PTY）。" +
			"批准的是**整条终端**：之后在里面敲的每条命令不再逐条弹框，但全部记入审计"
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device string
			Cols   int
			Rows   int
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if a.Cols <= 0 {
			a.Cols = 100
		}
		if a.Rows <= 0 {
			a.Rows = 30
		}
		d, c, _, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		// 从这里起连接归会话管；任何失败路径都要自己 c.Close()。
		sess, err := c.NewSession()
		if err != nil {
			c.Close()
			return nil, ots.Errf(ots.ErrUnreachable, "开不了会话：%s", err)
		}
		if err := sess.RequestPty("xterm-256color", a.Rows, a.Cols, nil); err != nil {
			sess.Close()
			c.Close()
			return nil, ots.Errf(ots.ErrNotSupported, "对端不给 PTY（多半是限制型账号）：%s", err)
		}
		stdin, err := sess.StdinPipe()
		if err != nil {
			sess.Close()
			c.Close()
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		s := &shellSession{
			device: d.ID,
			client: c,
			sess:   sess,
			stdin:  stdin,
		}
		out := &shellWriter{s}
		sess.Stdout = out
		sess.Stderr = out
		if err := sess.Shell(); err != nil {
			sess.Close()
			c.Close()
			return nil, ots.Errf(ots.ErrUnreachable, "起不了 shell：%s", err)
		}
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		s.id = "sh-" + hex.EncodeToString(b)[:10]
		// 会话结束时（远端退出）把连接收掉、标成关闭 —— read 会把这件事报出来。
		go func(s *shellSession) {
			_ = sess.Wait()
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			s.client.Close()
		}(s)
		shellSessions.mu.Lock()
		// 同一台设备只留一条：再来一条就把旧的关掉（页面语义：一台一个终端标签）。
		for id, old := range shellSessions.m {
			if old.device == d.ID {
				old.closeQuietly()
				delete(shellSessions.m, id)
			}
		}
		shellSessions.m[s.id] = s
		shellSessions.mu.Unlock()
		mgr.Audit(ots.CallerFrom(ctx), "shell.open", d.ID,
			fmt.Sprintf("pty %dx%d", a.Rows, a.Cols), "ok")
		return ots.Verdict{Code: "shell-open", Values: map[string]any{
			"session": s.id, "device": d.ID,
		}, Note: "终端已开。用 remote.shell.read 收输出、remote.shell.write 发内容。"}, nil
	},
}

// closeQuietly 关会话与连接，不记账（由 closeQuietly 的调用方决定记什么）。
func (s *shellSession) closeQuietly() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.sess.Close()
	_ = s.stdin.Close()
	_ = s.client.Close()
}

// ── remote.shell.read（read）──

var shellReadTool = ots.Tool{
	Name:  "remote.shell.read",
	Class: ots.ClassRead,
	Summary: "收一条终端会话自 offset 之后的输出（字节序号续读，适合轮询）。" +
		"会话被远端关掉时 done=true。缓冲区最多留最近 512 KB，offset 落在已丢弃的区间时从头给并标 truncated。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["session"],
	  "properties": {
	    "session": {"type": "string"},
	    "offset": {"type": "integer", "minimum": 0, "description": "上次 read 回来的 offset。第一次传 0"}
	  }
	}`),
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			Session string
			Offset  int64
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		s, ok := shellSessionOf(a.Session)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "没有这条会话（可能已经关了），先 remote.shell.open")
		}
		data, off, trunc := s.since(a.Offset)
		s.mu.Lock()
		closed := s.closed
		closeErr := s.closeEl
		s.mu.Unlock()
		out := map[string]any{
			"session":   s.id,
			"output":    string(data),
			"offset":    off,
			"truncated": trunc,
			"done":      closed,
		}
		if closed && closeErr != nil {
			out["closeErr"] = closeErr.Error()
		}
		return out, nil
	},
}

// ── remote.shell.write（read 档：按键算在 open 那次批准里，同 desk.input 先例）──

var shellWriteTool = ots.Tool{
	Name:  "remote.shell.write",
	Class: ots.ClassRead,
	Summary: "往一条终端会话送内容：整段命令（记得带换行）、一个按键（如 \"\\u0003\" = Ctrl-C）、" +
		"或对 y/n 提示的回答。也可改终端尺寸（cols/rows）。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["session", "data"],
	  "properties": {
	    "session": {"type": "string"},
	    "data": {"type": "string", "description": "要送的字节。发命令记得带换行；Ctrl-C 用 \"\\u0003\""},
	    "cols": {"type": "integer", "minimum": 20, "maximum": 500, "description": "顺带改终端列数"},
	    "rows": {"type": "integer", "minimum": 5, "maximum": 200, "description": "顺带改终端行数"}
	  }
	}`),
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			Session string
			Data    string
			Cols    int
			Rows    int
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		s, ok := shellSessionOf(a.Session)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "没有这条会话，先 remote.shell.open")
		}
		if a.Data != "" {
			if _, err := s.stdin.Write([]byte(a.Data)); err != nil {
				return nil, ots.Errf(ots.ErrUnreachable, "送不进去（会话可能断了）：%s", err)
			}
		}
		if a.Cols > 0 && a.Rows > 0 {
			if err := s.sess.WindowChange(a.Rows, a.Cols); err != nil {
				// 尺寸改不动不拦人：有些老对端不支持，别把按键这件事挡了
				return map[string]any{"sent": true, "resized": false}, nil
			}
			return map[string]any{"sent": true, "resized": true}, nil
		}
		return map[string]any{"sent": true}, nil
	},
}

// ── remote.shell.close（read 档：关掉自己开的会话不是改系统）──

var shellCloseTool = ots.Tool{
	Name:    "remote.shell.close",
	Class:   ots.ClassRead,
	Summary: "关掉一条终端会话（连同那路 SSH 连接）。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["session"],
	  "properties": {"session": {"type": "string"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a struct{ Session string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		s, ok := shellSessionOf(a.Session)
		if !ok {
			return ots.Verdict{Code: "shell-closed", Note: "这条会话本来就不在了"}, nil
		}
		s.closeQuietly()
		shellDrop(a.Session)
		mgr.Audit(ots.CallerFrom(ctx), "shell.close", s.device, a.Session, "ok")
		return ots.Verdict{Code: "shell-closed", Note: "终端已关"}, nil
	},
}

// （writerFunc 已不需要：write 直接满足 io.Writer。）
