package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
)

// ═══════════════════════════════════════════════════════════════════════
// 桌面画质选项（remote.desk.options）与剪贴板（remote.desk.clipboard）
//
// 画质：200ms 全彩 JPEG 在弱网必卡 —— 画质/宽度要能降。选项记在会话上，
// remote.desk.frame 取帧时带上；旧版被控端不认识参数就退回默认画质（诚实降级）。
//
// 剪贴板：桌面里连个字符串都拷不出来是不行的。取/送都走 SSH 命令行
// （Windows PowerShell / macOS pbcopy·pbpaste / Linux xclip·xsel），
// 文本统一 base64 过境，杜绝引号与编码把内容搞坏。
// ═══════════════════════════════════════════════════════════════════════

// ── remote.desk.options（read 档：改的是这次画面会话的取帧参数，不动系统）──

var deskOptionsTool = ots.Tool{
	Name:  "remote.desk.options",
	Class: ots.ClassRead,
	Summary: "调一次已打开画面会话的画质：JPEG 质量（30–95，默认 82）与最大宽度（默认 1280）。" +
		"弱网就降：quality=55、maxWidth=1024 之类。设置后 remote.desk.frame 起生效；" +
		"旧版被控端不认识这两个参数，会照旧用默认画质（返回里标 applied=false 就是这种情况）。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {
	    "device": {"type": "string"},
	    "quality": {"type": "integer", "minimum": 30, "maximum": 95, "description": "JPEG 质量，默认 82"},
	    "maxWidth": {"type": "integer", "minimum": 480, "maximum": 4096, "description": "画面最大宽度像素，默认 1280"}
	  }
	}`),
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			Device   string
			Quality  int
			MaxWidth int
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		s, ok := deskSessionOf(a.Device)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "这台还没打开画面，先 remote.desk.open")
		}
		deskSessions.mu.Lock()
		if a.Quality > 0 {
			s.quality = a.Quality
		}
		if a.MaxWidth > 0 {
			s.maxWidth = a.MaxWidth
		}
		q, w := s.quality, s.maxWidth
		deskSessions.mu.Unlock()
		return ots.Verdict{Code: "desk-options", Values: map[string]any{
			"device": a.Device, "quality": q, "maxWidth": w,
		}, Note: fmt.Sprintf("画面参数已记下：质量 %d、最大宽 %d。下一帧起生效（旧版被控端会照旧用默认画质）。", q, w)}, nil
	},
}

// ── remote.desk.clipboard（get 是 read；set 是 mutate）──

var deskClipboardTool = ots.Tool{
	Name:  "remote.desk.clipboard",
	Class: ots.ClassRead,
	Summary: "取对方机器的剪贴板文本（走 SSH：PowerShell Get-Clipboard / pbpaste / xclip）。" +
		"送文本（text 参数）改的是对方的剪贴板 → mutate 档单独走 remote.desk.clipboard.set。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {"device": {"type": "string"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ Device string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, c, _, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		cmd := clipboardGetCmd(d.OS)
		if cmd == "" {
			return nil, ots.Errf(ots.ErrNotSupported, "%s 上没有现成的剪贴板命令（装 xclip / xsel 再来）", d.OS)
		}
		out, err := remote.Exec(ctx, c, d, cmd, 10*time.Second)
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		if out.ExitCode != 0 {
			return nil, ots.Errf(ots.ErrNotSupported, "取不到剪贴板（exit=%d）：%.200s", out.ExitCode, out.Stderr)
		}
		text := decodeClipboardPayload(out.Stdout)
		return map[string]any{"device": d.ID, "text": text, "empty": text == ""}, nil
	},
}

var deskClipboardSetTool = ots.Tool{
	Name:  "remote.desk.clipboard.set",
	Class: ots.ClassMutate,
	Summary: "把一段文本送进对方机器的剪贴板（PowerShell Set-Clipboard / pbcopy / xclip）。" +
		"文本 base64 过境，不会被引号/编码搞坏；对方下一条粘贴就是这段。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device", "text"],
	  "properties": {"device": {"type": "string"}, "text": {"type": "string", "description": "要放进对方剪贴板的文本"}}
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Device, Text string
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		preview := a.Text
		if len(preview) > 80 {
			preview = preview[:80] + "…"
		}
		return fmt.Sprintf("把一段文本送进设备 %s 的剪贴板：「%s」（替换对方当前的剪贴板内容）", a.Device, preview)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device string
			Text   string
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, c, _, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		cmd, ok := clipboardSetCmd(d.OS, a.Text)
		if !ok {
			return nil, ots.Errf(ots.ErrNotSupported, "%s 上没有现成的剪贴板命令（装 xclip / xsel 再来）", d.OS)
		}
		out, err := remote.Exec(ctx, c, d, cmd, 10*time.Second)
		if err != nil {
			mgr.Audit(ots.CallerFrom(ctx), "desk.clipboard.set", d.ID, fmt.Sprintf("%dB", len(a.Text)), "failed: "+err.Error())
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		if out.ExitCode != 0 {
			mgr.Audit(ots.CallerFrom(ctx), "desk.clipboard.set", d.ID, fmt.Sprintf("%dB", len(a.Text)), fmt.Sprintf("failed exit=%d", out.ExitCode))
			return nil, ots.Errf(ots.ErrNotSupported, "送不进剪贴板（exit=%d）：%.200s", out.ExitCode, out.Stderr)
		}
		mgr.Audit(ots.CallerFrom(ctx), "desk.clipboard.set", d.ID, fmt.Sprintf("%dB 文本", len(a.Text)), "ok")
		return ots.Verdict{Code: "clipboard-set",
			Note: fmt.Sprintf("已放进 %s 的剪贴板（%d 字符）。那边下一条粘贴就是这段。", d.ID, len(a.Text))}, nil
	},
}

// clipboardGetCmd 按 OS 取剪贴板文本（统一 base64 出来，杜绝编码/引号把内容搞坏）。
func clipboardGetCmd(os string) string {
	switch os {
	case "windows":
		return `powershell -NoProfile -Command "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Clipboard -Raw))))"`
	case "darwin":
		return `pbpaste | base64`
	default:
		return `xclip -o -selection clipboard 2>/dev/null | base64 || xsel -o 2>/dev/null | base64`
	}
}

// clipboardSetCmd 把 base64 过境的文本写进对方剪贴板。
func clipboardSetCmd(os, text string) (string, bool) {
	b64 := base64.StdEncoding.EncodeToString([]byte(text))
	switch os {
	case "windows":
		// EncodedCommand 整段 UTF-16LE base64 过境，引号怎么配都炸不了
		ps := fmt.Sprintf("Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')))", b64)
		return "powershell -NoProfile -EncodedCommand " + psEncoded(ps), true
	case "darwin":
		return "echo " + b64 + " | base64 -d | pbcopy", true
	default:
		return "echo " + b64 + " | base64 -d | (xclip -selection clipboard 2>/dev/null || xsel --input 2>/dev/null)", true
	}
}

// decodeClipboardPayload 把回来的一坨 base64 还原成文本；不是 base64 就按原样给
// （老对端不支持 base64 管道时兜底，总比空手强）。
func decodeClipboardPayload(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	clean := strings.NewReplacer("\n", "", "\r", "").Replace(s)
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil && len(b) > 0 {
		return string(b)
	}
	return s
}
