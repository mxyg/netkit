package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
)

// mgr 远程功能的数据（设备登记、配置、审计）。由 main 装进来。
var mgr *remote.Manager

// SetRemote 装上远程数据目录。没装的话远程工具一律拒绝执行。
func SetRemote(m *remote.Manager) { mgr = m }

// RegisterRemote 把远程相关的工具装进注册表。
func RegisterRemote(r *ots.Registry) {
	r.MustRegister(
		remoteDeviceAddTool, remoteDeviceListTool, remoteDeviceRemoveTool,
		remoteForgetHostkeyTool, remoteDeviceProbeTool, remoteSessionsTool,
		remoteExecTool, remoteFilePushTool, remoteFilePullTool,
		remoteMsgTool, remoteDesktopTool,
		remoteConfigGetTool, remoteConfigSetTool, remoteAuditTool,
	)
}

func needRemote() error {
	if mgr == nil {
		return ots.Errf(ots.ErrInternal, "远程功能的数据目录没初始化，用不了")
	}
	return nil
}

// dial 连一台登记过的设备，顺带审计 + 「对方可见」提示。
func dial(ctx context.Context, device string) (*remote.Device, *ssh.Client, remote.SSHExecer, error) {
	d, err := mgr.Get(device)
	if err != nil {
		return nil, nil, nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	c, err := mgr.Dial(ctx, d)
	if err != nil {
		code := "connect-failed"
		msg := err.Error()
		switch {
		case strings.Contains(msg, "主机密钥"):
			code = "host-key-changed"
		case strings.Contains(msg, "认证被拒"):
			code = "auth-rejected"
		case strings.Contains(msg, "拒绝了连接"):
			code = "refused"
		case strings.Contains(msg, "连不通"):
			code = "unreachable"
		}
		mgr.Audit(ots.CallerFrom(ctx), "connect", d.ID, "失败："+code, msg)
		return nil, nil, nil, ots.Errf(ots.ErrUnreachable, "[%s] %s", code, msg)
	}
	// 首连记下的主机密钥落盘
	_ = mgr.UpdateDevice(d)
	x := remote.Execer(c)
	mgr.Audit(ots.CallerFrom(ctx), "connect", d.ID, d.User+"@"+d.Host, "ok")
	return d, c, x, nil
}

// ── remote.device.add（登记，不动任何系统 → read）──

var remoteDeviceAddTool = ots.Tool{
	Name:  "remote.device.add",
	Class: ots.ClassRead,
	Summary: "登记一台远程设备（SSH）：地址、账号、凭据。只写 NetKit 自己的登记簿，不碰任何机器。" +
		"★ 凭据只落盘在本机 0600 的文件里，永远不出现在任何返回结果和日志里；能用私钥（keyPath）就别用口令。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["host", "user"],
	  "properties": {
	    "host": {"type": "string", "description": "IP 或主机名。支持带 zone 的 fe80:: 写法，如 fe80::1%en0"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "SSH 端口，默认 22"},
	    "user": {"type": "string", "description": "登录账号。★ 不确定就先猜常见值，连不上时 remote.device.probe 会把对端主机名报回来"},
	    "password": {"type": "string", "description": "口令。和 keyPath 至少给一个"},
	    "keyPath": {"type": "string", "description": "NetKit 主机上的私钥文件路径（推荐）"},
	    "name": {"type": "string", "description": "备注名，可不填"}
	  }
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			User     string `json:"user"`
			Password string `json:"password"`
			KeyPath  string `json:"keyPath"`
			Name     string `json:"name"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if a.Password == "" && a.KeyPath == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument, "password 和 keyPath 至少给一个 —— 没凭据连不上")
		}
		d, err := mgr.AddDevice(remote.Device{
			Host: a.Host, Port: a.Port, User: a.User,
			Password: a.Password, KeyPath: a.KeyPath, Name: a.Name,
		})
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "device.add", d.ID, "登记设备（凭据不落审计）", "ok")
		// ★ 返回里绝不带凭据
		return ots.Verdict{Code: "registered", Values: d.Public(),
			Note: fmt.Sprintf("已登记 %s，接着用 remote.device.probe 连一次拿身份", d.ID)}, nil
	},
}

// ── remote.device.list / remove / forget-hostkey ──

var remoteDeviceListTool = ots.Tool{
	Name:    "remote.device.list",
	Class:   ots.ClassRead,
	Summary: "列出登记过的远程设备（不含任何凭据），带最近一次探到的身份信息。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: func(ctx context.Context, _ json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		ds := mgr.Devices()
		return map[string]any{"devices": ds, "count": len(ds),
			"notifyTarget": mgr.NotifyTarget()}, nil
	},
}

var remoteDeviceRemoveTool = ots.Tool{
	Name:    "remote.device.remove",
	Class:   ots.ClassRead,
	Summary: "删掉一台设备的登记（连同存的凭据）。只动 NetKit 自己的登记簿，不碰设备。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {"device": {"type": "string", "description": "设备 ID（user@host）或 host"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ Device string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if err := mgr.RemoveDevice(a.Device); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "device.remove", a.Device, "", "ok")
		return ots.Verdict{Code: "removed", Note: "已从登记簿删掉 " + a.Device}, nil
	},
}

var remoteForgetHostkeyTool = ots.Tool{
	Name:  "remote.device.forget-hostkey",
	Class: ots.ClassRead,
	Summary: "清掉一台设备记下的主机密钥，下次连接重新首连记录。" +
		"★ 只在**确认**那台机器重装了系统/换了机器时用 —— 主机密钥变了也可能是有人冒充它。",
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
		d, err := mgr.Get(a.Device)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		d.HostKey = ""
		if err := mgr.UpdateDevice(d); err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "device.forget-hostkey", d.ID, "", "ok")
		return ots.Verdict{Code: "forgotten",
			Note: "已清掉 " + d.ID + " 的主机密钥记录，下次连接会重新首连记录"}, nil
	},
}

// ── remote.device.probe（连接 + 身份回报，只观察 → read）──

var remoteDeviceProbeTool = ots.Tool{
	Name:  "remote.device.probe",
	Class: ots.ClassRead,
	Summary: "连一台登记过的设备并自动把身份问清楚：主机名、账号、系统版本、网卡地址、时区、监听端口。" +
		"★ 现场「22 通了但不知道账号名」那种事就靠它终结 —— 连接失败时它会把已探到的线索给人话建议。" +
		"「对方可见」开着时，连接会在目标机屏幕上提示一声。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {"device": {"type": "string", "description": "设备 ID（user@host）或 host"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ Device string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, c, x, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()

		targetOS := remote.DetectOS(ctx, c)
		d.OS = targetOS
		remote.NotifyConnecting(ctx, mgr, x, d, "连接并读取设备信息")
		id, idErr := remote.CollectIdentity(ctx, c, targetOS)
		if idErr == nil && id != nil {
			d.Identity = id
			d.LastSeen = time.Now()
		}
		_ = mgr.UpdateDevice(d)

		values := map[string]any{"device": d.Public(), "os": targetOS}
		hostname := "?"
		if id != nil {
			values["identity"] = id
			if id.Hostname != "" {
				hostname = id.Hostname
			}
		}
		note := fmt.Sprintf("连上了：%s 是 %s（%s），账号 %s", d.ID, targetOS, hostname, d.User)
		if idErr != nil {
			note = "连上了，但身份信息没问全：" + idErr.Error()
		}
		mgr.Audit(ots.CallerFrom(ctx), "device.probe", d.ID, "os="+targetOS, "ok")
		return ots.Verdict{Code: "connected", Values: values, Note: note}, nil
	},
}

// ── remote.sessions（read）──

var remoteSessionsTool = ots.Tool{
	Name:  "remote.sessions",
	Class: ots.ClassRead,
	Summary: "列出目标机上的登录会话。★ Windows 上发消息/弹屏必须指定会话号，" +
		"SSH 落在 session 0（services），人在 session 1（console）—— 发错会话等于石沉大海。",
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
		d, c, x, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		ss, err := remote.ListSessions(ctx, x, d)
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return map[string]any{"sessions": ss, "count": len(ss)}, nil
	},
}

// ── remote.exec（改系统档：命令能干什么不可预知 → mutate）──

var remoteExecTool = ots.Tool{
	Name:  "remote.exec",
	Class: ots.ClassMutate,
	Summary: "在一台登记过的设备上执行命令并收回输出。这是远程诊断的主力通道：" +
		"看资源、抓日志、重启服务都走它。Windows 目标自动垫 UTF-8 编码协商（不然中文全是乱码）。" +
		"★ 每次执行都要人在界面上确认，且全程审计 —— 命令能改任何东西，不能凭调用方一句话就放。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device", "command"],
	  "properties": {
	    "device": {"type": "string", "description": "设备 ID（user@host）或 host"},
	    "command": {"type": "string", "description": "要执行的命令。Windows 目标用 cmd 语法"},
	    "timeoutSec": {"type": "integer", "minimum": 1, "maximum": 3600, "description": "超时秒数，默认 60"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Device, Command string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("在远程设备 %s 上执行命令：%s（输出会被收回并记入审计）", a.Device, a.Command)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device     string `json:"device"`
			Command    string `json:"command"`
			TimeoutSec int    `json:"timeoutSec"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, c, _, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		out, err := remote.Exec(ctx, c, d, a.Command, time.Duration(a.TimeoutSec)*time.Second)
		if err != nil {
			mgr.Audit(ots.CallerFrom(ctx), "exec", d.ID, a.Command, "failed: "+err.Error())
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		code := "exec-ok"
		if out.ExitCode != 0 {
			code = "exec-nonzero"
		}
		mgr.Audit(ots.CallerFrom(ctx), "exec", d.ID, a.Command,
			fmt.Sprintf("exit=%d stdout=%dB stderr=%dB", out.ExitCode, len(out.Stdout), len(out.Stderr)))
		return ots.Verdict{Code: code, Values: map[string]any{
			"device": d.ID, "exitCode": out.ExitCode,
			"stdout": out.Stdout, "stderr": out.Stderr, "seconds": out.Seconds,
		}}, nil
	},
}

// ── remote.file.push / pull（mutate：往对端/本机写文件）──

var remoteFilePushTool = ots.Tool{
	Name:  "remote.file.push",
	Class: ots.ClassMutate,
	Summary: "把 NetKit 主机上的一个文件送到远程设备上（装软件、送配置、送升级包）。" +
		"走 SFTP；目标目录不存在就建；**断点续传**：断了再跑一次会接着传；" +
		"**整包 SHA256 校验**：传完在对端复核，复核不了会如实说 unavailable，不假装校验过。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device", "local", "remote"],
	  "properties": {
	    "device": {"type": "string"},
	    "local":  {"type": "string", "description": "NetKit 主机上的源文件路径"},
	    "remote": {"type": "string", "description": "设备上的目标路径（绝对路径）"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Device, Local, Remote string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("把本机文件 %s 传到设备 %s 的 %s（对端已有半截会续传，传完做 SHA256 复核）",
			a.Local, a.Device, a.Remote)
	},
	Invoke: transferInvoke(true),
}

var remoteFilePullTool = ots.Tool{
	Name:  "remote.file.pull",
	Class: ots.ClassMutate,
	Summary: "把远程设备上的一个文件拉回 NetKit 主机（取日志、诊断包、崩溃转储）。" +
		"走 SFTP；断点续传；拉回来本地算整包 SHA256 并和对端复核。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device", "remote", "local"],
	  "properties": {
	    "device": {"type": "string"},
	    "remote": {"type": "string", "description": "设备上的源文件路径（绝对路径）"},
	    "local":  {"type": "string", "description": "存到 NetKit 主机的路径"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Device, Local, Remote string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("把设备 %s 上的 %s 拉到本机 %s（写本机磁盘，断点续传，SHA256 复核）",
			a.Device, a.Remote, a.Local)
	},
	Invoke: transferInvoke(false),
}

func transferInvoke(push bool) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device string `json:"device"`
			Local  string `json:"local"`
			Remote string `json:"remote"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, c, x, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		action := "file.pull"
		var t *remote.Transfer
		if push {
			action = "file.push"
			t, err = remote.Push(ctx, c, x, d, a.Local, a.Remote)
		} else {
			t, err = remote.Pull(ctx, c, x, d, a.Remote, a.Local)
		}
		if err != nil {
			mgr.Audit(ots.CallerFrom(ctx), action, d.ID, a.Local+" ↔ "+a.Remote, "failed: "+err.Error())
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), action, d.ID,
			fmt.Sprintf("%s ↔ %s（%d 字节，续传起点 %d）", a.Local, a.Remote, t.Bytes, t.ResumedFrom),
			"sha256="+t.SHA256[:16]+"… verified="+t.Verified)
		code := "transferred"
		note := fmt.Sprintf("传完 %d 字节（%.1f 秒），整包 SHA256 %s…", t.Bytes, t.Seconds, t.SHA256[:12])
		switch t.Verified {
		case "match":
			note += "，对端复核一致"
		case "mismatch":
			code = "checksum-mismatch"
			note = "★ 传完了但对端复核**不一致** —— 文件是坏的，别用它，重传一次"
		case "unavailable":
			note += "；对端算不了校验和（没有 sha256sum/certutil），**没有复核过**，重要文件请人工确认"
		}
		if t.ResumedFrom > 0 {
			note += fmt.Sprintf("（从 %d 字节处续传）", t.ResumedFrom)
		}
		return ots.Verdict{Code: code, Values: map[string]any{"transfer": t}, Note: note}, nil
	}
}

// ── remote.msg.send（mutate：改的是别人屏幕上的东西）──

var remoteMsgTool = ots.Tool{
	Name:  "remote.msg.send",
	Class: ots.ClassMutate,
	Summary: "往目标机的屏幕上发一条消息（Windows msg.exe / Linux notify-send·wall / macOS 通知）。" +
		"★ 消息自动带发送方标识，不得用于伪装系统提示。判定码区分「发出去了 sent」、" +
		"「发了但不保证对方看得见 sent-unconfirmed」、「没有有人的会话 no-session」、「发不出去 send-failed」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device", "text"],
	  "properties": {
	    "device": {"type": "string"},
	    "text": {"type": "string", "description": "消息内容。发送方标识会自动加上，不用自己写"},
	    "session": {"type": "integer", "minimum": 0, "description": "Windows 会话号。不填自动挑 Active 且有人的；用 remote.sessions 看"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Device string `json:"device"`
			Text   string `json:"text"`
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("在设备 %s 的屏幕上弹一条消息：%s（会带上「来自 NetKit·谁」的标识，全程审计）",
			a.Device, a.Text)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device  string `json:"device"`
			Text    string `json:"text"`
			Session *int   `json:"session"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if strings.TrimSpace(a.Text) == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument, "消息内容不能是空的")
		}
		d, c, x, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		sid := -1
		if a.Session != nil {
			sid = *a.Session
		}
		r, err := remote.SendScreenMessage(ctx, x, d, a.Text, remote.OperatorLabel(), sid)
		if err != nil {
			mgr.Audit(ots.CallerFrom(ctx), "msg.send", d.ID, a.Text, "failed: "+err.Error())
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "msg.send", d.ID, a.Text, r.Code)
		return ots.Verdict{Code: r.Code, Values: map[string]any{
			"device": d.ID, "result": r,
		}, Note: r.Detail}, nil
	},
}

// ── remote.desktop.open（mutate：可能要改对端注册表/防火墙/launchd）──

// desktopArgs remote.desktop.open 的入参。
type desktopArgs struct {
	Device string `json:"device"`
	Enable bool   `json:"enable"`
}

// changeRecord 进改动账本的那一份：动了什么、以及**怎么关回去**。
//
// ★★ Undo 一定要跟着落盘。「先登记后执行、能还原」里那句"能还原"靠的就是这几条命令：
//
//	账本里只写"打开过远程桌面"却留不下关回去的那几条，等于把对端系统改成了一个
//	连 NetKit 自己都说不清怎么复原的状态 —— 那是设计原则 2 明确不放的。
type changeRecord struct {
	Device  string              `json:"device"`
	Desktop *remote.DesktopInfo `json:"desktop"`
	Change  *remote.Change      `json:"change"`
}

var remoteDesktopTool = ots.Tool{
	Name:  "remote.desktop.open",
	Class: ots.ClassMutate,
	Summary: "打通到一台设备的远程桌面并拿到连接参数，然后尝试在 NetKit 主机上拉起现成的客户端（不自己造协议）。" +
		"★ 各系统实际做的事不一样，别拿一句「打通」理解它：\n" +
		"  Windows 目标：查 fDenyTSConnections 与 NetKit-RDP 防火墙规则；没开且 enable=true 时替它开" +
		"（改注册表、起 TermService、放行 3389/TCP 入站）。\n" +
		"  macOS 目标：查 5900 在不在听；没开且 enable=true 时，那台账号给了免密 sudo 就替它打开「屏幕共享」" +
		"（launchctl enable + bootstrap），不给免密 sudo 就把那两条命令原样交给你贴 —— " +
		"★ NetKit 不会拿你登记着的口令去喂 sudo -S。\n" +
		"  Linux 目标：只查 5900；enable=true 时探测它的桌面环境，把该跑的命令拼好给你，" +
		"★ 不装包、不替你动桌面会话（所以这一路不改对端任何东西）。\n" +
		"  NetKit 主机是 Windows、目标又是 VNC 时：先在注册表与常见安装目录里找 TigerVNC / UltraVNC / " +
		"RealVNC Viewer / TightVNC，找到就用它连；一台都没装就把地址放进剪贴板（不下载也不捆绑第三方查看器）。\n" +
		"「对方可见」开着时会在目标机屏幕上提示一声。改对端的操作先登记后执行、全程记审计。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device"],
	  "properties": {
	    "device": {"type": "string"},
	    "enable": {"type": "boolean", "description": "目标机没开远程桌面时是否替它打开。Windows=改注册表+服务+防火墙；macOS=launchctl 打开屏幕共享（要那台给免密 sudo）；Linux 这一项不代跑，只会把命令拼好给你（要装包的事 NetKit 不替人决定）"}
	  }
	}`),
	Describe: describeDesktopOpen,
	Invoke:   invokeDesktopOpen,
}

// describeDesktopOpen 批准框里那句话。
//
// ★★ 按**那台的系统**分别写清楚要跑哪几条命令、用什么权限，还要写清楚哪一路 NetKit 不代跑。
//
//	人在框里点的应该是他真正批准的东西；一句"会改对端注册表和防火墙"盖不住 macOS
//	那一路（改的是 launchd，而且只在给了免密 sudo 时才动）。
func describeDesktopOpen(raw json.RawMessage) string {
	var a desktopArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	d, err := mgr.Get(a.Device)
	if err != nil {
		return fmt.Sprintf("打通到 %s 的远程桌面：登记簿里没有这一台（连不上，也不会改任何机器）", a.Device)
	}
	head := fmt.Sprintf("%s（%s@%s）", d.ID, d.User, d.Host)
	if !a.Enable {
		return fmt.Sprintf("查询 %s 的远程桌面状态并拿连接参数 —— 这一趟只读：Windows 读注册表与防火墙规则、"+
			"Linux/macOS 只查 5900 在不在听，不改对端任何东西", head)
	}
	switch d.OS {
	case "windows":
		return fmt.Sprintf("要替 %s 打开远程桌面，按顺序在那台机器上跑：\n%s\n"+
			"用的是登记账号本身的权限（Windows 上多半要管理员）；哪一步被拒就报错停下，不动剩下的。"+
			"改动先记进账本，账本里带着关回去的那几条", head, cmdLines(remote.RDPChange().Do))
	case "darwin":
		do, undo := remote.MacShareCmds("sudo ")
		return fmt.Sprintf("要替 %s 打开「屏幕共享」。先只读问两句（id -Gn、sudo -n true）看这个账号的底气；"+
			"只有它给了免密 sudo，才跑：\n%s\n关回去跑：\n%s\n"+
			"★ 不给免密 sudo 就一条都不跑，把上面那两条原样交给你自己贴；NetKit 不会拿登记簿里的口令去喂 sudo。\n"+
			"（未实测：本机 sudo 要口令，带 root 那半段没跑过；跑完会回查 5900，查不到就照实说没核实）",
			head, cmdLines(do), cmdLines(undo))
	case "linux":
		return fmt.Sprintf("要在 %s 上开屏幕共享：这一趟只读探测它的桌面环境（command -v 一圈、读 /etc/os-release、"+
			"看桌面会话），然后把该跑的命令按环境拼好给你。★ NetKit 不在 Linux 上装包、不替你动桌面会话，"+
			"所以这一趟不改对端任何东西，也不会写改动账本", head)
	default:
		return fmt.Sprintf("%s 是什么系统还没探明 —— 这一趟不会改任何东西，先跑 remote.device.probe", head)
	}
}

func invokeDesktopOpen(ctx context.Context, raw json.RawMessage) (any, error) {
	if err := needRemote(); err != nil {
		return nil, err
	}
	var a desktopArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	d, c, x, err := dial(ctx, a.Device)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	pre, err := remote.PrepareDesktop(ctx, x, d)
	if err != nil {
		mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, fmt.Sprint("enable=", a.Enable), "failed: "+err.Error())
		return nil, ots.Errf(ots.ErrNotSupported, "%s", err)
	}
	info := pre.Info

	// ── 那台现在没开：enable=false 时这是判定不是错误 ──
	if !info.WasEnabled && !a.Enable {
		code, note := desktopNotOpenNext(d.OS)
		mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, "只查不改", code)
		return ots.Verdict{Code: code, Values: map[string]any{
			"device": d.ID, "desktop": info, "state": pre.Before,
		}, Note: note}, nil
	}

	// ── 要替它开：先问清"这一趟到底能不能替你干"，再登记，再动手 ──
	var changed bool
	var journalID string
	if !info.WasEnabled {
		ch, err := remote.PlanChange(ctx, x, d)
		if err != nil {
			mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, "enable=true", "failed: "+err.Error())
			return nil, ots.Errf(ots.ErrNotSupported, "%s", err)
		}
		if ch.HandsOff {
			// ★ enable 这个参数没被悄悄丢掉：不代跑就说清为什么不代跑、并给到能贴的命令。
			//   计划里没带判定码就是代码没写全，宁可报错也不编一个码糊过去。
			if ch.Code == "" {
				return nil, ots.Errf(ots.ErrInternal,
					"这份「不替你动手」的计划没给判定码（kind=%s），不敢替你编一个：%s", ch.Kind, ch.Reason)
			}
			mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, "enable=true（未代跑）", ch.Code)
			return ots.Verdict{Code: ch.Code, Values: map[string]any{
				"device": d.ID, "desktop": info, "state": pre.Before, "plan": ch,
			}, Note: ch.Reason + "\n" + cmdLines(ch.Do)}, nil
		}
		if journal == nil {
			// ★ 和 net.address.set / dhcp.serve 同一条纪律：没账本就不许改系统
			return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝改系统")
		}
		what := desktopLedgerWhat(d, ch)
		id, jerr := journal.Register("remote-desktop", what, pre.Before,
			changeRecord{Device: d.ID, Desktop: info, Change: ch})
		if jerr != nil {
			return nil, ots.Errf(ots.ErrInternal, "改动没登记成，就不动手：%s", jerr)
		}
		if err := remote.ApplyChange(ctx, x, d, ch); err != nil {
			_ = journal.Drop(id, "这一趟没改成："+err.Error())
			mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, what, "failed: "+err.Error())
			var ae *remote.ApplyError
			if errors.As(err, &ae) {
				return nil, ots.Errf(ots.ErrPermissionRequired, "[%s] %s —— 下一步：这个账号大概没有改这一项的权限"+
					"（Windows 要管理员，macOS 要免密 sudo）；换管理员账号重新登记，或照批准框里那几条自己在那台上跑",
					desktopFailCode(d.OS), ae)
			}
			return nil, ots.Errf(ots.ErrInternal, "%s（账本里已记成没改成）", err)
		}
		_ = journal.MarkApplied(id)
		journalID, changed = id, true
		info.EnabledNow = true
		if d.OS == "windows" {
			info.Firewall = "NetKit-RDP（3389/TCP 入站，已在对端防火墙放行）"
		}
		// ★ 动了就得回查一眼：命令跑回来 0 不等于那台机器现在真有人在听。
		//   查不到就照实说"没核实"，账本不回滚（可能只是回查时机太早）。
		ok, ev, err := confirmDesktopOpened(ctx, x, d)
		if err != nil {
			mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, what, "回查失败: "+err.Error())
			return nil, ots.Errf(ots.ErrTimeout, "改动已经在那台上生效（账本 %s），可回查它有没有真的开起来时连接断了：%s", id, err)
		}
		if !ok {
			mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID, what, "unconfirmed")
			code := "share-enabled-unconfirmed"
			if d.OS == "windows" {
				code = "rdp-enabled-unconfirmed"
			}
			return ots.Verdict{Code: code, Values: map[string]any{
				"device": d.ID, "desktop": info, "state": pre.Before, "journal": id, "evidence": ev,
			}, Note: fmt.Sprintf("命令都跑完了（账本 %s），但回查没看到它真的开起来：%s。"+
				"下一步：过几秒再点一次「查状态」；还是没有就去那台上看着 —— 别把这条当成已经打通了", id, ev)}, nil
		}
	}

	// 「对方可见」：连桌面前先在目标机屏幕上说一声
	remote.NotifyConnecting(ctx, mgr, x, d, "连接远程桌面")

	res := remote.LaunchClient(info)
	mgr.Audit(ots.CallerFrom(ctx), "desktop.open", d.ID,
		fmt.Sprintf("%s://%s enable=%v launched=%v changed=%v", info.Protocol, info.Host, a.Enable, res.Launched, changed),
		firstNonEmpty(res.Code, "ok"))

	note := fmt.Sprintf("%s 连接参数：%s:%d，账号 %s", strings.ToUpper(info.Protocol), info.Host, info.Port, info.User)
	if changed {
		note = "这次替那台打开了（改动在账本 " + journalID + " 里，含关回去的命令）。" + note
	}
	switch {
	case res.Launched:
		note += "，已在本机拉起客户端"
		if res.Viewer != "" {
			note += "（用的 " + res.Viewer + "）"
		}
	default:
		note += "。本机没拉起客户端：" + firstNonEmpty(res.Cmd, "（没有可拼的命令）")
	}
	if res.Copied {
		note += "；地址已放进剪贴板"
	}
	if res.Next != "" {
		note += "\n" + res.Next
	}
	code := res.Code
	if code == "" {
		// ★ 拉不起来必须有码：判定点是"下一步在哪"，没码就等于没给下一步
		code = "desktop-ready"
		if !res.Launched {
			code = "desktop-ready-no-client"
		}
	}
	return ots.Verdict{Code: code, Values: map[string]any{
		"device": d.ID, "desktop": info, "state": pre.Before,
		"launched": res.Launched, "launchCmd": res.Cmd, "viewer": res.Viewer, "copied": res.Copied,
		"changed": changed, "journal": journalID,
		"notifyTarget": mgr.NotifyTarget(),
	}, Note: note}, nil
}

// desktopNotOpenNext 「没开、而且这次没让开」的三档 —— 下一步各不相同，所以三个码。
func desktopNotOpenNext(goos string) (string, string) {
	switch goos {
	case "windows":
		return "rdp-disabled", "目标机没开远程桌面。确认要替它打开就带 enable=true 再来" +
			"（会改对端注册表 fDenyTSConnections、起 TermService、加一条 3389/TCP 入站规则，先登记后执行）"
	case "darwin":
		return "screen-sharing-disabled", "那台 Mac 的 5900 没人听（屏幕共享没开）。" +
			"带 enable=true 可以替你打开：前提是那台账号给免密 sudo，不给就把那两条 launchctl 命令交给你自己贴"
	case "linux":
		return "vnc-not-listening", "那台 Linux 的 5900 没人听。带 enable=true 会探它的桌面环境、" +
			"把该跑的命令拼好给你 —— NetKit 不在 Linux 上装包，也不会替你动桌面会话"
	default:
		return "desktop-disabled", "那台现在没有远程桌面在听，而且它的系统还没探明 —— 先跑 remote.device.probe"
	}
}

// desktopFailCode 动手那一步被拒时按系统分档（下一步不同：换管理员账号 / 给免密 sudo）。
func desktopFailCode(goos string) string {
	switch goos {
	case "windows":
		return "rdp-enable-refused"
	case "darwin":
		return "share-enable-refused"
	default:
		return "desktop-enable-refused"
	}
}

// desktopLedgerWhat 账本里那一句：要包含**关回去的那几条**，不然还原时无非是照着猜。
func desktopLedgerWhat(d *remote.Device, ch *remote.Change) string {
	var b strings.Builder
	fmt.Fprintf(&b, "在 %s 上%s。关回去：", d.ID, ch.Title)
	for i, u := range ch.Undo {
		if i > 0 {
			b.WriteString(" ／ ")
		}
		b.WriteString(u.Line)
	}
	return b.String()
}

// cmdLines 把要跑的命令摊成批准框里那几行（带每条在干什么）。
func cmdLines(cmds []remote.Cmd) string {
	var b strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&b, "  · %s\n    ← %s", c.Line, c.Why)
	}
	return strings.TrimRight(b.String(), "\n")
}

// confirmDesktopOpened 动手之后回看一眼：只回答「看到了它真的开起来了没有」，
// 附一句证据给人看，不替人下"肯定没问题"的结论。
func confirmDesktopOpened(ctx context.Context, x remote.SSHExecer, d *remote.Device) (bool, string, error) {
	if d.OS == "windows" {
		st, err := remote.QueryRDP(ctx, x, d)
		if err != nil {
			return false, "", err
		}
		return st.Enabled, fmt.Sprintf("再读一次注册表：允许远程连接 = %v", st.Enabled), nil
	}
	ok, err := remote.ConfirmListening(ctx, x, d, 4, 500*time.Millisecond)
	if err != nil {
		return false, "", err
	}
	return ok, fmt.Sprintf("回查 5900：在听 = %v", ok), nil
}

// ── remote.config.get / set ──

var remoteConfigGetTool = ots.Tool{
	Name:    "remote.config.get",
	Class:   ots.ClassRead,
	Summary: "读远程功能的配置。目前一项：notifyTarget（连接/控制时是否在目标机屏幕上给提示，默认 true）。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: func(_ context.Context, _ json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		return map[string]any{"notifyTarget": mgr.NotifyTarget()}, nil
	},
}

var remoteConfigSetTool = ots.Tool{
	Name:  "remote.config.set",
	Class: ots.ClassMutate,
	Summary: "改远程功能的配置。★ 把 notifyTarget 改成 false（静默模式）是一次要被记住的选择：" +
		"目标机屏幕前的人将不知道有人在连接/操作。审计日志不受这个开关影响，照记。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["notifyTarget"],
	  "properties": {
	    "notifyTarget": {"type": "boolean", "description": "true=连接时目标机屏幕给提示（默认）；false=静默"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ NotifyTarget bool }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		if a.NotifyTarget {
			return "打开「对方可见」：远程连接/控制时在目标机屏幕上给出提示（推荐的默认状态）"
		}
		return "★ 关闭「对方可见」，进入静默模式：之后远程连接/控制时，目标机屏幕前的人将不会收到任何提示。" +
			"请确认场景是无人值守（服务器、机柜一体机、数字标牌）。" +
			"由购买方负责在其组织内合规使用并履行告知义务。审计日志不受影响，照记。"
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ NotifyTarget bool }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		before, after, err := mgr.SetNotifyTarget(a.NotifyTarget)
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		// ★ 关提示这件事本身必须进审计 —— 它正是「谁在什么时候选择了静默」的记录
		mgr.Audit(ots.CallerFrom(ctx), "config.set", "notifyTarget",
			fmt.Sprintf("%v → %v", before, after), "ok")
		code := "notify-on"
		note := "「对方可见」已打开：远程连接/控制时目标机屏幕会给提示"
		if !after {
			code = "notify-off"
			note = "★ 已进入静默模式：目标机屏幕前的人不会收到连接提示。审计日志照记。"
		}
		return ots.Verdict{Code: code, Values: map[string]any{
			"notifyTarget": after, "before": before,
		}, Note: note}, nil
	},
}

// ── remote.audit.tail（read）──

var remoteAuditTool = ots.Tool{
	Name:  "remote.audit.tail",
	Class: ots.ClassRead,
	Summary: "取远程操作的审计日志（谁、何时、对哪台、做了什么、结果如何）。" +
		"审计独立于 notifyTarget：静默模式只关屏幕提示，不关留痕。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false,
	  "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "取最近几条，默认 100"}}
	}`),
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ N int }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		n := a.N
		if n == 0 {
			n = 100
		}
		es := mgr.AuditTail(n)
		return map[string]any{"entries": es, "count": len(es)}, nil
	},
}
