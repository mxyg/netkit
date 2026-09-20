package remote

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DesktopInfo 远程桌面的连接信息。
//
// ★ 设计定死的边界（docs/设计.md「远程控制三件套」）：**不自己造协议**。
//
//	Windows 走 RDP、Linux/macOS 走 VNC；NetKit 负责**开通与连接** ——
//	查会话、开服务、放行防火墙、拿连接参数，然后交给各平台现成的客户端。
type DesktopInfo struct {
	Protocol   string `json:"protocol"` // rdp / vnc
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user,omitempty"`
	WasEnabled bool   `json:"wasEnabled"` // 之前服务就是开着的
	EnabledNow bool   `json:"enabledNow"` // 这次由 NetKit 打开的（改了对端系统，账本里有登记）
	Firewall   string `json:"firewall,omitempty"`
}

// RDPState 目标机 RDP 的当前状态（给账本记 Before/After，也给人看）。
type RDPState struct {
	Enabled  bool   `json:"enabled"`
	Firewall string `json:"firewall,omitempty"`
	Raw      string `json:"raw,omitempty"`
}

// QueryRDP 读 Windows 目标的 RDP 状态：fDenyTSConnections + 防火墙规则。
func QueryRDP(ctx context.Context, x SSHExecer, d *Device) (*RDPState, error) {
	if d.OS != "windows" {
		return nil, fmt.Errorf("RDP 开通只对 Windows 目标做了；%s 是 %s", d.ID, d.OS)
	}
	out, err := x.Exec(ctx, d,
		`reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections`,
		30*time.Second)
	if err != nil {
		return nil, err
	}
	raw := out.Stdout + out.Stderr
	st := &RDPState{Raw: strings.TrimSpace(raw)}
	// 0x0 = 允许远程连接；0x1 = 拒绝
	st.Enabled = strings.Contains(raw, "0x0")
	fw, _ := x.Exec(ctx, d,
		`netsh advfirewall firewall show rule name="NetKit-RDP"`, 30*time.Second)
	if strings.Contains(fw.Stdout, "NetKit-RDP") && strings.Contains(fw.Stdout+fw.Stderr, "Enabled:") {
		st.Firewall = "NetKit-RDP"
	}
	return st, nil
}

// EnableRDP 在 Windows 目标上打开远程桌面：注册表 + 服务 + 防火墙。
//
// ★ 这是**改对端系统**的操作，调用方（tools 层）必须先过账本登记。
//
//	防火墙只加一条明确的 3389 入站规则（名字 NetKit-RDP），
//	不动"远程桌面"规则组 —— 那个组名是本地化的（中文系统叫「远程桌面」），
//	按英文名下发在中文 Windows 上会静默失败。
func EnableRDP(ctx context.Context, x SSHExecer, d *Device) error {
	steps := []string{
		`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`,
		`sc start TermService`, // 已在跑会报错，无所谓，下一步照常
		`netsh advfirewall firewall add rule name="NetKit-RDP" dir=in action=allow protocol=TCP localport=3389`,
	}
	for _, s := range steps {
		out, err := x.Exec(ctx, d, s, 60*time.Second)
		if err != nil {
			return fmt.Errorf("执行 %q 失败：%w", s, err)
		}
		// sc start 对已运行的服务返回非 0，跳过它的失败
		if out.ExitCode != 0 && !strings.HasPrefix(s, "sc start") {
			return fmt.Errorf("执行 %q 被拒（退出码 %d）：%s —— 这个账号可能没有管理员权限",
				s, out.ExitCode, firstNonEmpty(out.Stderr, out.Stdout))
		}
	}
	return nil
}

// OpenDesktop 把远程桌面这条路打通并拿到连接参数。
func OpenDesktop(ctx context.Context, x SSHExecer, d *Device, enable bool) (*DesktopInfo, *RDPState, error) {
	switch d.OS {
	case "windows":
		before, err := QueryRDP(ctx, x, d)
		if err != nil {
			return nil, nil, err
		}
		info := &DesktopInfo{Protocol: "rdp", Host: d.Host, Port: 3389, User: d.User, WasEnabled: before.Enabled}
		if !before.Enabled {
			if !enable {
				return info, before, fmt.Errorf("目标机没开远程桌面；确认要开就用 enable 再来一次")
			}
			if err := EnableRDP(ctx, x, d); err != nil {
				return info, before, err
			}
			info.EnabledNow = true
			info.Firewall = "NetKit-RDP（3389/TCP 入站，已在对端防火墙放行）"
		}
		return info, before, nil
	case "linux", "darwin":
		// VNC：各桌面环境开法五花八门，NetKit 不替它乱改 —— 查端口给参数
		info := &DesktopInfo{Protocol: "vnc", Host: d.Host, Port: 5900, User: d.User}
		out, err := x.Exec(ctx, d, "ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null", 20*time.Second)
		if err != nil {
			return nil, nil, err
		}
		listening := false
		for _, ln := range strings.Split(out.Stdout, "\n") {
			if strings.Contains(ln, "LISTEN") && strings.Contains(ln, ":5900") {
				listening = true
				break
			}
		}
		if !listening {
			return info, nil, fmt.Errorf(
				"目标机 5900 端口没有 VNC 在听。Linux/macOS 的屏幕共享开法因桌面环境而异，" +
					"NetKit 不替你改：macOS 在「系统设置→通用→共享→屏幕共享」打开；" +
					"Linux 装 vino/gnome-remote-desktop 或 x11vnc 后开启，再回来连")
		}
		info.WasEnabled = true
		return info, nil, nil
	default:
		return nil, nil, fmt.Errorf("还不知道 %s 是什么系统，先跑 remote.device.probe", d.ID)
	}
}

// LaunchClient 在 NetKit 主机上拉起现成的桌面客户端。
//
// ★ 拉不起来不算失败：把连接参数原样给人，手动连也就是十秒的事。
//
//	返回 launched=false + 用的命令，界面照实显示。
func LaunchClient(info *DesktopInfo) (bool, string) {
	addr := fmt.Sprintf("%s:%d", info.Host, info.Port)
	switch info.Protocol {
	case "rdp":
		switch runtime.GOOS {
		case "windows":
			return launch("mstsc", "/v:"+addr)
		case "darwin":
			// 写一个 .rdp 文件交给系统打开 —— 装了 Microsoft Remote Desktop / Windows App 就会接
			p := filepath.Join(os.TempDir(), "netkit-"+strings.ReplaceAll(addr, ":", "_")+".rdp")
			body := fmt.Sprintf("full address:s:%s\nusername:s:%s\n", addr, info.User)
			if err := os.WriteFile(p, []byte(body), 0o600); err == nil {
				return launch("open", p)
			}
			return false, "open " + p
		default:
			return launch("xfreerdp", "/v:"+addr, "/u:"+info.User)
		}
	case "vnc":
		url := "vnc://" + addr
		switch runtime.GOOS {
		case "darwin":
			return launch("open", url) // 系统自带屏幕共享
		case "windows":
			return false, "（Windows 没有自带 VNC 客户端，参数：" + addr + "）"
		default:
			return launch("xdg-open", url)
		}
	}
	return false, ""
}

func launch(name string, args ...string) (bool, string) {
	cmdStr := name + " " + strings.Join(args, " ")
	if _, err := exec.LookPath(name); err != nil {
		return false, cmdStr
	}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return false, cmdStr
	}
	return true, cmdStr
}
