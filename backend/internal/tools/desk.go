package tools

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"net.yuhox.com/netkit/internal/desk"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
)

// 一次已经批准的画面会话。键鼠不再逐次弹批准，批准发生在 open。
var deskSessions = struct {
	mu sync.Mutex
	m  map[string]deskSession
}{m: map[string]deskSession{}}

type deskSession struct {
	Host  string
	Token string

	// 画质参数（remote.desk.options 改这里；旧版被控端会忽略，照旧默认画质）。
	quality  int // JPEG 质量 30–95
	maxWidth int // 画面最大宽度像素
}

func init() {
	// 注册放在 RegisterRemote 里，这里只占位避免漏编译。
}

var deskOpenTool = ots.Tool{
	Name:  "remote.desk.open",
	Class: ots.ClassRead,
	Summary: "在对方网通上打开本机画面通道，之后用 remote.desk.frame 取画面、remote.desk.input 送键鼠。" +
		"不依赖 Windows 远程桌面，家庭版也能看。对方屏幕上会提示正在被查看。",
	Schema: json.RawMessage(`{
	  "type":"object","additionalProperties":false,"required":["device"],
	  "properties":{"device":{"type":"string"}}
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
		token := randToken()
		// 先停掉上次那个，否则端口被占、新令牌对不上，画面就出不来。
		// /IT：在已经登录的桌面里跑，才能抓到屏幕。命令写进 cmd，避免引号被计划任务吃掉。
		// wscript 的窗口样式 0 = 隐藏。直接跑 cmd 会在对方桌上留一个黑框。
		cmd := fmt.Sprintf(`taskkill /F /IM netkitd-desk2.exe & echo CreateObject("Wscript.Shell").Run "C:\Users\lm\netkitd-desk2.exe -desk 0.0.0.0:%d -desk-token %s", 0, False> C:\Users\lm\nk-desk.vbs & schtasks /Create /TN NetKitDesk /TR "wscript.exe //B C:\Users\lm\nk-desk.vbs" /SC ONCE /ST 23:59 /F /IT & schtasks /Run /TN NetKitDesk`,
			desk.Port, token)
		out, err := remote.Exec(ctx, c, d, cmd, 20*time.Second)
		if err != nil {
			return nil, ots.Errf(ots.ErrUnreachable, "没能在对方桌面里启动共享：%s", err)
		}
		if out.ExitCode != 0 {
			return nil, ots.Errf(ots.ErrUnreachable, "没能在对方桌面里启动共享：%s %s", out.Stdout, out.Stderr)
		}
		if err := waitHealth(d.Host, token, 12*time.Second); err != nil {
			return nil, ots.Errf(ots.ErrUnreachable, "%s", err)
		}
		deskSessions.mu.Lock()
		deskSessions.m[d.ID] = deskSession{Host: d.Host, Token: token, quality: 82, maxWidth: 1280}
		deskSessions.mu.Unlock()
		mgr.Audit(ots.CallerFrom(ctx), "desk.open", d.ID, d.Host, "ok")
		return ots.Verdict{Code: "desk-open", Values: map[string]any{"device": d.ID, "host": d.Host},
			Note: "对方屏幕已共享。用 remote.desk.frame 取画面。"}, nil
	},
}

var deskFrameTool = ots.Tool{
	Name:    "remote.desk.frame",
	Class:   ots.ClassRead,
	Summary: "取一帧已经打开的网通画面（JPEG，base64）。先 remote.desk.open。",
	Schema: json.RawMessage(`{
	  "type":"object","additionalProperties":false,"required":["device"],
	  "properties":{"device":{"type":"string"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a struct{ Device string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		s, ok := deskSessionOf(a.Device)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "这台还没打开画面，先 remote.desk.open")
		}
		// 会话上记的画质参数随帧走；旧版被控端不认识这两个参数，会照旧默认画质。
		url := fmt.Sprintf("http://%s:%d/frame.jpg", s.Host, desk.Port)
		if s.quality > 0 && s.maxWidth > 0 {
			url += fmt.Sprintf("?q=%d&maxw=%d", s.quality, s.maxWidth)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		req.Header.Set("X-Desk-Token", s.Token)
		cli := &http.Client{Timeout: 4 * time.Second}
		res, err := cli.Do(req)
		if err != nil {
			return nil, ots.Errf(ots.ErrUnreachable, "画面中断：%s", err)
		}
		defer res.Body.Close()
		b, err := io.ReadAll(io.LimitReader(res.Body, 6<<20))
		if err != nil || res.StatusCode != 200 {
			return nil, ots.Errf(ots.ErrUnreachable, "画面中断：HTTP %d", res.StatusCode)
		}
		var shot struct {
			JPEG []byte  `json:"jpeg"`
			CX   float64 `json:"cx"`
			CY   float64 `json:"cy"`
			HotX int     `json:"hotx"`
			HotY int     `json:"hoty"`
			PNG  []byte  `json:"png"`
		}
		if json.Unmarshal(b, &shot) == nil && len(shot.JPEG) > 0 {
			return map[string]any{
				"jpeg": base64.StdEncoding.EncodeToString(shot.JPEG),
				"cx":   shot.CX, "cy": shot.CY,
				"hotx": shot.HotX, "hoty": shot.HotY,
				"png": base64.StdEncoding.EncodeToString(shot.PNG),
			}, nil
		}
		return map[string]any{"jpeg": base64.StdEncoding.EncodeToString(b)}, nil
	},
}

var deskInputTool = ots.Tool{
	Name:    "remote.desk.input",
	Class:   ots.ClassRead,
	Summary: "把一次鼠标或键盘送到已经打开的画面。坐标 x、y 是 0 到 1。这次操作算在 remote.desk.open 那次批准里。",
	Schema: json.RawMessage(`{
	  "type":"object","additionalProperties":false,"required":["device","kind","action"],
	  "properties":{
	    "device":{"type":"string"},
	    "kind":{"type":"string"},
	    "action":{"type":"string"},
	    "x":{"type":"number"},
	    "y":{"type":"number"},
	    "button":{"type":"string"},
	    "key":{"type":"string"}
	  }
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			Device string
			Kind   string
			Action string
			X, Y   float64
			Button string
			Key    string
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		s, ok := deskSessionOf(a.Device)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "这台还没打开画面")
		}
		body, _ := json.Marshal(map[string]any{
			"kind": a.Kind, "action": a.Action, "x": a.X, "y": a.Y, "button": a.Button, "key": a.Key,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s:%d/input", s.Host, desk.Port), bytesReader(body))
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		req.Header.Set("X-Desk-Token", s.Token)
		req.Header.Set("Content-Type", "application/json")
		cli := &http.Client{Timeout: 2 * time.Second}
		res, err := cli.Do(req)
		if err != nil {
			return nil, ots.Errf(ots.ErrUnreachable, "%s", err)
		}
		res.Body.Close()
		return map[string]any{"sent": res.StatusCode < 300}, nil
	},
}

var deskDropTool = ots.Tool{
	Name:    "remote.desk.drop",
	Class:   ots.ClassRead,
	Summary: "把本机一个文件传到对方。对方正打开着资源管理器文件夹就放进那个文件夹，否则放到桌面。",
	Schema: json.RawMessage(`{
	  "type":"object","additionalProperties":false,"required":["device","local"],
	  "properties":{"device":{"type":"string"},"local":{"type":"string"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device string
			Local  string
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if _, ok := deskSessionOf(a.Device); !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "先打开对方屏幕，再把文件拖进去")
		}
		d, c, x, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		dir, err := remote.Exec(ctx, c, d, "powershell -NoProfile -EncodedCommand "+psEncoded(deskDropDirPS), 20*time.Second)
		destDir := `C:\Users\lm\Desktop`
		if err == nil && dir.ExitCode == 0 {
			line := strings.TrimSpace(dir.Stdout)
			if line != "" {
				destDir = line
			}
		}
		base := a.Local
		if i := strings.LastIndexAny(base, `\/`); i >= 0 {
			base = base[i+1:]
		}
		remotePath := strings.TrimRight(destDir, `\`) + `\` + base
		t, err := remote.Push(ctx, c, x, d, a.Local, remotePath)
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "desk.drop", d.ID, a.Local+" → "+remotePath, "ok")
		return ots.Verdict{Code: "desk-dropped", Values: map[string]any{"remote": remotePath, "bytes": t.Bytes},
			Note: "已放到 " + remotePath}, nil
	},
}

var deskCloseTool = ots.Tool{
	Name:    "remote.desk.close",
	Class:   ots.ClassRead,
	Summary: "关掉对方的网通屏幕共享。",
	Schema: json.RawMessage(`{
	  "type":"object","additionalProperties":false,"required":["device"],
	  "properties":{"device":{"type":"string"}}
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
		if err == nil {
			_, _ = remote.Exec(ctx, c, d, `schtasks /End /TN NetKitDesk & taskkill /IM netkitd-desk.exe /F & taskkill /IM netkitd-desk2.exe /F`, 15*time.Second)
			c.Close()
		}
		deskSessions.mu.Lock()
		delete(deskSessions.m, a.Device)
		deskSessions.mu.Unlock()
		return ots.Verdict{Code: "desk-closed", Note: "已停止看对方屏幕"}, nil
	},
}

func deskSessionOf(id string) (deskSession, bool) {
	deskSessions.mu.Lock()
	defer deskSessions.mu.Unlock()
	s, ok := deskSessions.m[id]
	return s, ok
}

const deskDropDirPS = `
$p = [Environment]::GetFolderPath('Desktop')
try {
  Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();' -Name W -Namespace N
  $h = [N.W]::GetForegroundWindow()
  $sh = New-Object -ComObject Shell.Application
  foreach ($w in @($sh.Windows())) {
    if ([int64]$w.HWND -eq [int64]$h) { $p = $w.Document.Folder.Self.Path; break }
  }
} catch {}
Write-Output $p
`

func psEncoded(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func waitHealth(host, token string, d time.Duration) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/health", host, desk.Port), nil)
		req.Header.Set("X-Desk-Token", token)
		cli := &http.Client{Timeout: time.Second}
		res, err := cli.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				return nil
			}
			last = fmt.Errorf("HTTP %d", res.StatusCode)
		} else {
			last = err
		}
		time.Sleep(400 * time.Millisecond)
	}
	return fmt.Errorf("对方共享没有起来：%v", last)
}

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
