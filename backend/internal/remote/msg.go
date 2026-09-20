package remote

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// Session 目标机上的一个登录会话。
type Session struct {
	Name   string `json:"name"`
	User   string `json:"user,omitempty"`
	ID     int    `json:"id"`
	State  string `json:"state"`
	Active bool   `json:"active"`
	// Current 发起本次 SSH 连接落在的会话（Windows query session 的 > 行）。
	Current bool `json:"current,omitempty"`
}

// ListSessions 目标机上的会话列表。
//
// ★ 会话号不能瞎猜（docs/设计.md 实测坑）：SSH 进 Windows 落在 session 0，
//
//	用户实际在 session 1（console）。发到 0 号等于石沉大海。
func ListSessions(ctx context.Context, x SSHExecer, d *Device) ([]Session, error) {
	switch d.OS {
	case "windows":
		out, err := x.Exec(ctx, d, "query session", 20*time.Second)
		if err != nil {
			return nil, err
		}
		if out.ExitCode != 0 {
			return nil, fmt.Errorf("query session 失败：%s", firstNonEmpty(out.Stderr, out.Stdout))
		}
		return ParseQuerySession(out.Stdout), nil
	case "linux", "darwin":
		out, err := x.Exec(ctx, d, "who", 20*time.Second)
		if err != nil {
			return nil, err
		}
		return parseWho(out.Stdout), nil
	default:
		return nil, fmt.Errorf("还不知道 %s 是什么系统，先跑 remote.device.probe", d.ID)
	}
}

// ParseQuerySession 解析 Windows `query session` 输出。
//
// ★ 按**表头列位置**切，不按空格分词 —— USERNAME 一列经常是空的
//
//	（services 会话没有用户名），按空格分会把 ID 当成用户名，全体错位。
//	测试样本就是设计文档里现场抄回来的那段。
func ParseQuerySession(out string) []Session {
	lines := strings.Split(out, "\n")
	headerIdx := -1
	var colUser, colID, colState int
	for i, ln := range lines {
		up := strings.ToUpper(ln)
		if strings.Contains(up, "SESSIONNAME") && strings.Contains(up, "STATE") {
			headerIdx = i
			colUser = strings.Index(up, "USERNAME")
			colID = indexWord(up, "ID")
			colState = strings.Index(up, "STATE")
			break
		}
	}
	if headerIdx < 0 || colUser < 0 || colID < 0 || colState < 0 {
		return nil
	}
	at := func(ln string, start, end int) string {
		if start < 0 || start >= len(ln) {
			return ""
		}
		if end <= start || end > len(ln) {
			end = len(ln)
		}
		return strings.TrimSpace(ln[start:end])
	}
	var sessions []Session
	for _, ln := range lines[headerIdx+1:] {
		if strings.TrimSpace(strings.TrimPrefix(ln, ">")) == "" {
			continue
		}
		cur := strings.HasPrefix(ln, ">")
		raw := ln
		if cur {
			// ">" 占了一个字符位，补一个空格保持列对齐
			raw = " " + ln[1:]
		}
		s := Session{
			Name:    at(raw, 0, colUser),
			User:    at(raw, colUser, colID),
			State:   at(raw, colState, colState+8),
			Current: cur,
		}
		if idStr := at(raw, colID, colState); idStr != "" {
			s.ID, _ = strconv.Atoi(idStr)
		}
		s.Active = strings.EqualFold(s.State, "Active")
		if s.Name == "" && s.User == "" && !cur {
			continue
		}
		sessions = append(sessions, s)
	}
	return sessions
}

// indexWord 找独立单词的位置（" ID" 而不是 "IDLE" 里的 ID）。
func indexWord(s, w string) int {
	for i := 0; i+len(w) <= len(s); {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return -1
		}
		pos := i + j
		beforeOK := pos == 0 || s[pos-1] == ' '
		afterOK := pos+len(w) == len(s) || s[pos+len(w)] == ' '
		if beforeOK && afterOK {
			return pos
		}
		i = pos + 1
	}
	return -1
}

// parseWho 解析 Unix `who` 输出：`pc  tty1  2026-09-20 10:00 (:0)`。
func parseWho(out string) []Session {
	var sessions []Session
	for i, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		sessions = append(sessions, Session{
			Name: f[1], User: f[0], ID: i,
			State: "Active", Active: true,
		})
	}
	return sessions
}

// firstNonEmpty 返回第一个非空串。
func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// ── 给屏幕发消息 ──

// MsgResult 发消息的结果。
//
// ★ 判定码区分「发不出去」和「发了但不确定对方看没看到」
//
//	（docs/设计.md：msg.exe 走终端服务消息，有的机器上禁用了）。
type MsgResult struct {
	Code    string `json:"code"` // sent / sent-unconfirmed / no-session / send-failed
	Session *int   `json:"session,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// SendScreenMessage 往目标机的屏幕上发一条消息。
//
// ★★ 消息**必须带发送方标识**（docs/设计.md 安全第 4 条：
//
//	不得用于骚扰或伪装系统提示）。from 是「谁从哪发的」，由调用方给。
//	sessionID < 0 = 自动挑 Active 的会话（Windows）。
func SendScreenMessage(ctx context.Context, x SSHExecer, d *Device, text, from string, sessionID int) (*MsgResult, error) {
	body := fmt.Sprintf("[NetKit · %s] %s", from, text)
	switch d.OS {
	case "windows":
		return sendWindows(ctx, x, d, body, sessionID)
	case "linux":
		return sendLinux(ctx, x, d, body)
	case "darwin":
		return sendDarwin(ctx, x, d, body)
	default:
		return nil, fmt.Errorf("还不知道 %s 是什么系统，先跑 remote.device.probe", d.ID)
	}
}

func sendWindows(ctx context.Context, x SSHExecer, d *Device, body string, sessionID int) (*MsgResult, error) {
	target := "*"
	sid := sessionID
	if sid < 0 {
		// 没指定会话：挑 Active 且有用户的那个。发到 0 号等于石沉大海，必须先挑。
		out, err := x.Exec(ctx, d, "query session", 20*time.Second)
		if err == nil && out.ExitCode == 0 {
			for _, s := range ParseQuerySession(out.Stdout) {
				if s.Active && s.User != "" {
					sid = s.ID
					break
				}
			}
		}
		if sid < 0 {
			return &MsgResult{Code: "no-session",
				Detail: "这台机器上没有找到有人登录的 Active 会话 —— 屏幕前没人，消息发了也没人看"}, nil
		}
	}
	if sid >= 0 {
		target = strconv.Itoa(sid)
	}
	// msg 的内容参数不走 shell 引号（Windows cmd 没有单引号语义），用双引号
	cmd := fmt.Sprintf(`msg %s /time:60 "%s"`, target, strings.ReplaceAll(body, `"`, `""`))
	out, err := x.Exec(ctx, d, cmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	if out.ExitCode == 0 {
		r := &MsgResult{Code: "sent", Detail: "msg.exe 已受理"}
		if sid >= 0 {
			r.Session = &sid
		}
		return r, nil
	}
	detail := firstNonEmpty(out.Stderr, out.Stdout)
	return &MsgResult{
		Code: "send-failed", Detail: fmt.Sprintf(
			"msg.exe 失败（%s）—— 可能这台机器禁用了终端服务消息，或目标会话没有交互桌面", detail),
	}, nil
}

func sendLinux(ctx context.Context, x SSHExecer, d *Device, body string) (*MsgResult, error) {
	q := shellQuote(body)
	// 有图形会话就借第一个登录用户的 DISPLAY 弹 notify-send，没有就 wall 兜底
	cmd := fmt.Sprintf(
		`u=$(who | awk 'NR==1{print $1}'); `+
			`if [ -n "$u" ] && command -v notify-send >/dev/null 2>&1; then `+
			`su - "$u" -c 'DISPLAY=:0 notify-send %s' 2>/dev/null && exit 0; fi; `+
			`wall %s`, q, q)
	out, err := x.Exec(ctx, d, cmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	if out.ExitCode == 0 {
		return &MsgResult{Code: "sent-unconfirmed",
			Detail: "已交给 notify-send/wall。SSH 进去发的桌面通知不保证弹得出来（没有图形会话时只有 wall 写终端）"}, nil
	}
	return &MsgResult{Code: "send-failed", Detail: firstNonEmpty(out.Stderr, out.Stdout)}, nil
}

func sendDarwin(ctx context.Context, x SSHExecer, d *Device, body string) (*MsgResult, error) {
	esc := strings.ReplaceAll(body, `"`, `\"`)
	cmd := fmt.Sprintf(`osascript -e 'display notification "%s" with title "昱弘网通 NetKit"'`, esc)
	out, err := x.Exec(ctx, d, cmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	if out.ExitCode == 0 {
		return &MsgResult{Code: "sent-unconfirmed",
			Detail: "osascript 已受理。SSH 会话里发通知，只有连接用户就是当前登录用户时才弹得出来"}, nil
	}
	return &MsgResult{Code: "send-failed", Detail: firstNonEmpty(out.Stderr, out.Stdout)}, nil
}

// NotifyConnecting 在「对方可见」开着时，连接前给目标机屏幕发一句。
// best-effort：发不出去不拦连接，但审计里如实记。
func NotifyConnecting(ctx context.Context, m *Manager, x SSHExecer, d *Device, action string) {
	if !m.NotifyTarget() {
		return
	}
	from := OperatorLabel()
	r, err := SendScreenMessage(ctx, x, d, "有人正在通过 NetKit "+action, from, -1)
	result := "send-failed"
	if err == nil && r != nil {
		result = r.Code
	}
	m.Audit(from, "notify-target", d.ID, action, result)
}

// OperatorLabel 「谁从哪发的」。NetKit 主机上的当前用户@主机名。
func OperatorLabel() string {
	u := "unknown"
	if cur, err := user.Current(); err == nil && cur.Username != "" {
		u = cur.Username
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return u + "@" + h
	}
	return u
}

// shellQuote POSIX 单引号转义。
func shellQuote(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'\''`) + `'`
}
