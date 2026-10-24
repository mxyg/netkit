package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/winssh"
)

var winsshStartTool = ots.Tool{
	Name:  "remote.winssh.start",
	Class: ots.ClassMutate,
	Summary: "在本机开一个网页，让网线另一头的 Windows 下载脚本、安装 OpenSSH 并放行 22 端口。" +
		"本机只多一个监听，不改本机系统设置。对方要点管理员确认才会改那台 Windows。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string {
		urls := winssh.Default.URLs()
		if len(urls) == 0 {
			return "在本机打开给 Windows 安装 OpenSSH 的网页。当前没有可用的 IPv4 地址。"
		}
		return "在本机这些地址上打开网页，供网线另一头的 Windows 下载并安装 OpenSSH（放行 22 端口）：\n" +
			strings.Join(urls, "\n") +
			"\n本机不改系统设置。对方运行脚本时会弹出管理员确认。"
	},
	Invoke: func(ctx context.Context, _ json.RawMessage) (any, error) {
		s, err := winssh.Default.Start()
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		return ots.Verdict{Code: "winssh-serving", Values: snapMap(s),
			Note: fmt.Sprintf("页面已开，让 Windows 打开 %s", s.URLs[0])}, nil
	},
}

var winsshStatusTool = ots.Tool{
	Name:    "remote.winssh.status",
	Class:   ots.ClassRead,
	Summary: "看给 Windows 开 SSH 的页面是否还开着、对方脚本报到哪一步、哪些地址的 22 端口已经通。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: func(ctx context.Context, _ json.RawMessage) (any, error) {
		s := winssh.Default.Status()
		code := "winssh-idle"
		if s.Running {
			code = "winssh-serving"
		}
		return ots.Verdict{Code: code, Values: snapMap(s)}, nil
	},
}

var winsshStopTool = ots.Tool{
	Name:    "remote.winssh.stop",
	Class:   ots.ClassMutate,
	Summary: "关掉给 Windows 安装 OpenSSH 的网页。已经装上的 SSH 不受影响。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string {
		return "关掉本机上给 Windows 安装 OpenSSH 的网页。对方已经装好的 SSH 不会被关掉。"
	},
	Invoke: func(ctx context.Context, _ json.RawMessage) (any, error) {
		winssh.Default.Stop()
		return ots.Verdict{Code: "winssh-stopped", Note: "页面已关"}, nil
	},
}

func snapMap(s winssh.Snapshot) map[string]any {
	return map[string]any{
		"running": s.Running,
		"port":    s.Port,
		"urls":    s.URLs,
		"lines":   s.Lines,
		"peers":   s.Peers,
		"user":    s.User,
		"done":    s.Done,
	}
}
