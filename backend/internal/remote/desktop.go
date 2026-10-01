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

// ShareState 目标机 VNC / 屏幕共享这一侧的现状（linux、darwin）。
//
// ★ 「5900 有没有人在听」是唯一的硬证据。本机（macOS 15.6）实测：
//
//	非 root 读不到 system 域 —— `launchctl print system/com.apple.screensharing`
//	回 "Could not find service ... in domain for system"，所以**不能拿它判开关**；
//	而 `launchctl print-disabled system` 非 root 读得到，只当辅助证据摆着。
type ShareState struct {
	OS        string `json:"os"`
	Listening bool   `json:"listening"`
	// Disabled launchctl print-disabled system 里 com.apple.screensharing 的记录：
	// enabled / disabled / 未记录（实测：从没开过屏幕共享的 Mac 上这条压根不在表里）。
	Disabled string `json:"launchctlDisabled,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ── 「要改对端」怎么表达 ──

// Cmd 一条要在对端跑的命令，和它自带的说明。
//
// ★ 为什么要带 Why/AlreadyOK，而不是一个字符串列表：
//
//	批准框、改动账本、审计都得说得出「这一步在干什么」；
//	而「服务已经在跑」这类非 0 退出不能算失败（sc start、launchctl bootstrap 都是这个脾气）。
//
// ★★ AlreadyOK 是**能报出名号的退出码白名单**，不是「非 0 一律放过」：
//
//	一个非 0 码背后可能是三件事 —— 已经这样了 / 权限不够 / 这东西根本不存在。
//	后面两种放过去，界面就会报「开好了」，人连不上还得自己猜回来。
//	所以每一条都得写出码与它的意思；写不出的（没实测过、苹果/微软没文档）
//	就宁可不放过：报错多报一次是噪音，少报一次是骗人。
type Cmd struct {
	Line string `json:"line"`
	Why  string `json:"why"`
	// AlreadyOK：这些退出码表示「这件事已经是这样了」，不算失败。
	AlreadyOK []int `json:"alreadyOk,omitempty"`
}

// tolerates 这个退出码是不是在白名单里。
func (c Cmd) tolerates(code int) bool {
	for _, ok := range c.AlreadyOK {
		if ok == code {
			return true
		}
	}
	return false
}

// Change 一次「要改对端」的完整计划：动什么、跑哪几条、**怎么关回去**。
//
// ★★ Undo 不是写给人看的客气话：它跟 Change 一起进改动账本。
//
//	「先登记后执行、能还原」里的「能还原」靠的就是这几条 —— 记不下关回去的命令，
//	就等于把对端系统改成了一个连 NetKit 自己都说不出怎么复原的状态。
type Change struct {
	Kind  string `json:"kind"` // rdp / mac-screensharing / linux-vnc
	Title string `json:"title"`
	Do    []Cmd  `json:"do"`
	Undo  []Cmd  `json:"undo"`
	// HandsOff 为真时这几条**只给人看、给人贴**，NetKit 不在对端执行。
	//   Linux：要装包、要动别人的桌面会话，这一版明确不替人干；
	//   macOS：那台账号不给免密 sudo。
	HandsOff bool   `json:"handsOff,omitempty"`
	Reason   string `json:"reason,omitempty"` // 为什么不替你动手（一句话）
	// Code HandsOff 时的判定码。**下一步不一样的两件事不许共用一个码**：
	//   「这台账号不给免密 sudo」（去给免密、或自己贴）和
	//   「这台账号压根不是管理员」（换账号登记）是两条完全不同的路。
	Code string `json:"code,omitempty"`
}

// ApplyError 动手时某一步没跑成的详情。
//
// ★ 调用方要靠它分得开「这个账号没权限」和「那条命令在这台上跑砸了」——
//
//	前者的下一步是换账号/给免密 sudo，后者的下一步是照实去那台上查。
type ApplyError struct {
	Cmd      string `json:"cmd"`
	Why      string `json:"why"`
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output,omitempty"`
}

func (e *ApplyError) Error() string {
	return fmt.Sprintf("执行 %q（%s）被拒：退出码 %d：%s", e.Cmd, e.Why, e.ExitCode, strings.TrimSpace(e.Output))
}

// Prepared PrepareDesktop 的结果：连接参数 + 现状 + 「没开的话该怎么改」。
type Prepared struct {
	Info *DesktopInfo `json:"info"`
	// Before 改之前的状态，原样进账本（*RDPState 或 *ShareState）。
	Before any `json:"before,omitempty"`
}

// probeSep 探测命令分段用的分隔符。★ 不能带 shell 元字符（ssh.go 里那条 `<` 的教训）。
const probeSep = "---netkit-share---"

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

// RDPChange Windows 目标打开/关回远程桌面的计划：注册表 + 服务 + 防火墙。
//
// ★ 这是**改对端系统**的东西，调用方（tools 层）必须先登记再执行。
//
//	防火墙只加一条明确的 3389 入站规则（名字 NetKit-RDP），
//	不动"远程桌面"规则组 —— 那个组名是本地化的（中文系统叫「远程桌面」），
//	按英文名下发在中文 Windows 上会静默失败。
func RDPChange() *Change {
	return &Change{
		Kind:  "rdp",
		Title: "打开 Windows 目标的远程桌面（注册表 + TermService + 防火墙 3389 入站）",
		Do: []Cmd{
			{Line: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`,
				Why: "注册表 fDenyTSConnections 1→0：允许远程连接"},
			// 1056 = ERROR_SERVICE_ALREADY_RUNNING（sc.exe 拿 Win32 错误码当退出码）。
			// ★ 只放过这一个：权限不够是 5、服务不存在是 1060、被禁用是 1058 ——
			//   那三种都是「这一份计划没做成」，报成「开好了」等于把人往错的路上送。
			{Line: `sc start TermService`, Why: "起远程桌面服务",
				AlreadyOK: []int{1056}},
			{Line: `netsh advfirewall firewall add rule name="NetKit-RDP" dir=in action=allow protocol=TCP localport=3389`,
				Why: "对端防火墙加一条 3389/TCP 入站规则（固定名 NetKit-RDP）"},
		},
		Undo: []Cmd{
			{Line: `netsh advfirewall firewall delete rule name="NetKit-RDP"`,
				Why: "删掉 NetKit 加的那条 3389 入站规则（只删这条，不碰别人下的）"},
			{Line: `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`,
				Why: "注册表 fDenyTSConnections 回到 1（拒绝远程连接）"},
		},
	}
}

// listenProbeCmd 查「本机哪些 TCP 口在听」。
//
// ★ macOS 那一档必须走 netstat -an，不能是 netstat -ltn：
//
//	它 -ltn **不报错**（退出码 0）但输出里没有 LISTEN 行，会把 || 兜底链堵死
//	（ssh.go 的 CollectIdentity 里同一个坑，实测踩过）。端口解析交给 extractListening，
//	冒号和 macOS 的点分（*.5900）都认。
const listenProbeCmd = `ss -ltn 2>/dev/null || netstat -an 2>/dev/null`

// portListening 在探测输出里找某个端口有没有人在听。
func portListening(out, port string) bool {
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, "LISTEN") {
			continue
		}
		for _, p := range extractListening(ln, false) {
			if p == port {
				return true
			}
		}
	}
	return false
}

// QueryShare 读 linux/darwin 目标的 VNC（5900）现状。只读，不动对端任何东西。
func QueryShare(ctx context.Context, x SSHExecer, d *Device) (*ShareState, error) {
	if d.OS != "linux" && d.OS != "darwin" {
		return nil, fmt.Errorf("屏幕共享/VNC 状态查询只对 linux、darwin 目标做了；%s 是 %s", d.ID, d.OS)
	}
	st := &ShareState{OS: d.OS}
	if d.OS == "darwin" {
		// ★ 两段一次跑完：省一个来回，且两段都是纯读（print-disabled 非 root 可读，本机实测）
		out, err := x.Exec(ctx, d, listenProbeCmd+
			"; echo "+probeSep+"; launchctl print-disabled system 2>/dev/null", 20*time.Second)
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(out.Stdout, probeSep, 2)
		st.Listening = portListening(parts[0], "5900")
		st.Disabled = parsePrintDisabled(parts[len(parts)-1], macScreensharingLabel)
		return st, nil
	}
	out, err := x.Exec(ctx, d, listenProbeCmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	st.Listening = portListening(out.Stdout, "5900")
	return st, nil
}

// parsePrintDisabled 从 `launchctl print-disabled system` 的输出里取某个 label 的记录。
//
// 实测格式是一行行的 `"com.apple.ftpd" => disabled`。表里没这条 = 系统没记过（默认那一份）。
func parsePrintDisabled(out, label string) string {
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, `"`+label+`"`) {
			continue
		}
		if i := strings.Index(ln, "=>"); i >= 0 {
			return strings.TrimSpace(ln[i+2:])
		}
	}
	return "未记录"
}

// ── macOS：替人把「屏幕共享」打开 ──

const (
	macScreensharingLabel = "com.apple.screensharing"
	macScreensharingPlist = "/System/Library/LaunchDaemons/com.apple.screensharing.plist"
)

// MacPriv 那台 Mac 上「NetKit 能不能替你把屏幕共享打开」的底气。
type MacPriv struct {
	Admin    bool   `json:"admin"`
	SudoFree bool   `json:"sudoNopasswd"`
	SudoText string `json:"sudoHint,omitempty"` // sudo -n 原话（判「要口令」还是「压根不在 sudoers」）
	Raw      string `json:"raw,omitempty"`
}

// ProbeMacSudo 问两句只读的：这个 SSH 账号是不是管理员、给不给免密 sudo。
//
// ★ 只在 enable 这条路上问（批准框里会写明跑了这两句）。不拿登记着的口令去喂
//
//	`sudo -S` —— 那等于替人隐式提权，批准框里那句「要改什么」就变成假话。
//	不给免密就把命令原样交回给人自己贴。
func ProbeMacSudo(ctx context.Context, x SSHExecer, d *Device) (*MacPriv, error) {
	out, err := x.Exec(ctx, d,
		`id -Gn; echo `+probeSep+`; sudo -n true 2>&1; echo "netkit-rc=$?"`, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return parseMacPriv(out.Stdout + out.Stderr), nil
}

func parseMacPriv(raw string) *MacPriv {
	p := &MacPriv{Raw: strings.TrimSpace(raw)}
	parts := strings.SplitN(raw, probeSep, 2)
	groups := parts[0]
	tail := ""
	if len(parts) > 1 {
		tail = parts[1]
	}
	for _, g := range strings.Fields(groups) {
		if g == "admin" {
			p.Admin = true
		}
	}
	// sudo -n 的答复：本机实测「a password is required」+ rc=1（这台机器不给免密）
	for _, ln := range strings.Split(tail, "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(ln), "netkit-rc="):
			p.SudoFree = strings.TrimSpace(ln) == "netkit-rc=0"
		case strings.TrimSpace(ln) != "":
			p.SudoText = strings.TrimSpace(ln)
		}
	}
	return p
}

// MacShareCmds 打开/关掉 macOS 屏幕共享的那几条命令。
//
// # 事实核对（本机 macOS 15.6，无 sudo 能做的部分全部实测过，退出码是量出来的）
//
//   - plist 与 label：plutil -p 读到 Label=com.apple.screensharing，
//     起的是 screensharingd，Sockets 里 SockServiceName=vnc-server（所以 5900 由 launchd 监听）；
//   - help 明写 system 域"要 root 才能改"，本机不带 sudo 跑 enable 实测回
//     "Could not enable service: 1: Operation not permitted"；
//   - help 里 load/unload 标注「Recommended alternatives: bootstrap|enable / bootout|disable」，
//     所以主用 bootstrap，load -w 只作为老系统的兜底。
//
// # launchctl 的退出码不能单独当证据（这一条把我原来的写法推翻了）
//
// 在用户域拿一个自建 plist 量过「重复做同一件事」各回什么（★ 系统域那两条不敢量：
// 真跑成功就等于没打招呼把老板这台机器的屏幕共享打开了）：
//
//	bootstrap 第二次  → 退出码 5（"Bootstrap failed: 5: Input/output error"）
//	bootout 第二次    → 退出码 3（"Boot-out failed: 3: No such process"）
//	print  加载过的    → 0；print 没加载/不存在的 → 113
//	enable 第二次     → 0；disable 从没 bootstrap 过的 → 0
//	load -w 已加载的  → ★ 嘴上说 "Load failed: 5"，**退出码却是 0**
//	unload -w 没加载的 → ★ 同样 "Unload failed: 5"，**退出码 0**
//
// 后两条是要命的：`bootstrap … || load -w …` 这种兜底链，最后那个 0 可能是
// 「它根本没权限、只是懒得说不行」。所以**链尾一律换成 print** ——
// 让这一条命令的成败由「服务现在到底在不在这个域里」决定，而不是由 launchctl 的心情决定。
// print 读的退出码在上面量过：0 = 加载着，113 = 没加载。
//
// ★ 未实测（要 sudo 口令，这台机器不给）：带 root 的这两条真跑下去会不会一次到位、
//
//	以及屏幕共享打开后 5900 多久开始听。所以执行后一律回查端口，查不到就照实说。
func MacShareCmds(sudoPrefix string) (do, undo []Cmd) {
	printed := "launchctl print system/" + macScreensharingLabel + " >/dev/null 2>&1"
	do = []Cmd{
		{Line: sudoPrefix + "launchctl enable system/" + macScreensharingLabel,
			Why: "把屏幕共享记成「要开」（清掉 print-disabled 里的 disabled）"},
		// 已经起着 → print 直接给 0，一条改系统的命令都不发；
		// 没起着 → bootstrap（老系统兜 load -w），最后再由 print 定成败。
		{Line: printed + " || " + sudoPrefix + "launchctl bootstrap system " + macScreensharingPlist +
			" || " + sudoPrefix + "launchctl load -w " + macScreensharingPlist + "; " + printed,
			Why: "把屏幕共享起起来（成败以 launchctl print 说的为准）"},
	}
	undo = []Cmd{
		// 本来就没起着 → print 给非 0，`&&` 短路，bootout 不必跑；跑完仍由 print 反证一次。
		{Line: printed + " && (" + sudoPrefix + "launchctl bootout system/" + macScreensharingLabel +
			" || " + sudoPrefix + "launchctl unload -w " + macScreensharingPlist + "); !" + printed,
			Why: "当场停掉屏幕共享（停没停以 launchctl print 说的为准）"},
		{Line: sudoPrefix + "launchctl disable system/" + macScreensharingLabel,
			Why: "记成「开机不要自己起」"},
	}
	return do, undo
}

// MacShareChange 按「那台的底气」决定这次是替你开、还是把命令交给你。纯函数，好测。
func MacShareChange(priv *MacPriv) *Change {
	do, undo := MacShareCmds("")
	ch := &Change{
		Kind: "mac-screensharing",
		Title: fmt.Sprintf("打开 macOS 目标的屏幕共享（launchctl enable + bootstrap %s）",
			macScreensharingLabel),
		Undo: undo,
	}
	switch {
	case priv == nil:
		// ★ 没问过权限就不许演"我能替你开"：这一步不猜，交回给人处理
		ch.HandsOff, ch.Reason, ch.Code = true, "还没问清那台账号的 sudo 底气。下一步：重连一次再试", "share-priv-unknown"
		ch.Do = do
	case priv.SudoFree:
		// 免密 sudo 可用：NetKit 替你把这几条跑掉，全程记审计与账本
		ch.Do = withSudo(do, "sudo ")
		ch.Undo = withSudo(undo, "sudo ")
		ch.Title += "（用那台账号的免密 sudo）"
	case !priv.Admin:
		ch.HandsOff, ch.Code = true, "share-not-admin"
		hint := ""
		if priv.SudoText != "" {
			hint = "（sudo 那一句回：" + priv.SudoText + "）"
		}
		ch.Reason = "那台 Mac 上这个 SSH 账号不在 admin 组里，开不了屏幕共享" + hint +
			"。下一步：换个管理员账号登记这台机器，" +
			"或在那台的「系统设置→用户与群组」里把它加进管理员，再带 enable=true 来一次"
		ch.Do = withSudo(do, "sudo ")
	default:
		ch.HandsOff, ch.Code = true, "share-need-sudo"
		ch.Reason = "这台账号不给免密 sudo（NetKit 不会拿登记着的口令去喂 sudo —— 那等于背着你在批准框之外提权）。" +
			"把下面这一条贴到那台机器的终端里跑一次就开好了"
		ch.Do = withSudo(do, "sudo ")
	}
	return ch
}

func withSudo(cmds []Cmd, prefix string) []Cmd {
	out := make([]Cmd, 0, len(cmds))
	for _, c := range cmds {
		c.Line = prefix + c.Line
		out = append(out, c)
	}
	return out
}

// ── Linux：不装包，但把话说到「哪一条命令」这个份上 ──

// LinuxEnv 从探测数据里读出来的那台 Linux 的桌面情况（不猜，读到什么算什么）。
type LinuxEnv struct {
	Distro   string   `json:"distro,omitempty"`   // /etc/os-release 的 ID=
	Pretty   string   `json:"pretty,omitempty"`   // PRETTY_NAME=，界面/账本上给人看
	Bins     []string `json:"bins,omitempty"`     // 装了哪些 VNC 服务端（按探测顺序）
	Sessions []string `json:"sessions,omitempty"` // xsessions / wayland-sessions 里的会话名
}

// DE 认出来的桌面环境（gnome / kde / 空=认不出）。
func (e LinuxEnv) DE() string {
	has := func(name string) bool {
		for _, b := range e.Bins {
			if b == name {
				return true
			}
		}
		return false
	}
	switch {
	case has("gnome-remote-desktop") || has("grdctl") || hasAny(e.Sessions, "gnome"):
		return "gnome"
	case has("vino-passwd") || has("vino-server"):
		return "gnome-vino"
	case has("krfb") || hasAny(e.Sessions, "plasma", "kde"):
		return "kde"
	case has("x11vnc"):
		return "x11vnc"
	}
	return ""
}

// Installed 有没有任何现成的 VNC 服务端（没装就只剩「装包」这一条路，那是人的决定）。
func (e LinuxEnv) Installed() bool { return len(e.Bins) > 0 }

func hasAny(xs []string, subs ...string) bool {
	for _, x := range xs {
		low := strings.ToLower(x)
		for _, sub := range subs {
			if strings.Contains(low, sub) {
				return true
			}
		}
	}
	return false
}

// linuxProbeCmd 一次读全：装了哪些服务端、桌面会话、发行版。★ 全是只读命令。
const linuxProbeCmd = `for c in gnome-remote-desktop grdctl vino-passwd vino-server x11vnc krfb; do command -v "$c" 2>/dev/null; done; ` +
	`echo ` + probeSep + `; ls /usr/share/xsessions /usr/share/wayland-sessions 2>/dev/null; ` +
	`echo ` + probeSep + `; (grep -m1 '^ID=' /etc/os-release 2>/dev/null; grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null)`

// ProbeLinux 读那台 Linux 的桌面环境。只读。
func ProbeLinux(ctx context.Context, x SSHExecer, d *Device) (*LinuxEnv, error) {
	out, err := x.Exec(ctx, d, linuxProbeCmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return parseLinuxProbe(out.Stdout), nil
}

// parseLinuxProbe 解探测输出。纯函数（测试对着真命令输出样本喂进来）。
func parseLinuxProbe(raw string) *LinuxEnv {
	parts := strings.Split(raw, probeSep)
	env := &LinuxEnv{}
	if len(parts) > 0 {
		for _, ln := range strings.Split(parts[0], "\n") {
			// command -v 打的是绝对路径，只留文件名：判定和命令生成都只看"有没有这个工具"
			p := strings.TrimSpace(ln)
			if p == "" || !strings.Contains(p, "/") {
				continue
			}
			env.Bins = append(env.Bins, filepath.Base(p))
		}
	}
	if len(parts) > 1 {
		for _, ln := range strings.Split(parts[1], "\n") {
			s := strings.TrimSpace(ln)
			// ★ 只收"一个会话文件名"这种形状（不含空格、不含斜杠）：
			//   ls 打两个目录时会带表头（/usr/share/xsessions:）和
			//   `ls: cannot access ...` 那种报错行，混进来会让 DE() 把噪声认成桌面
			if s == "" || strings.ContainsAny(s, " /") {
				continue
			}
			env.Sessions = append(env.Sessions, strings.TrimSuffix(s, ".desktop"))
		}
	}
	if len(parts) > 2 {
		for _, ln := range strings.Split(parts[2], "\n") {
			s := strings.TrimSpace(ln)
			switch {
			case strings.HasPrefix(s, "ID="):
				env.Distro = strings.Trim(strings.TrimPrefix(s, "ID="), `"`)
			case strings.HasPrefix(s, "PRETTY_NAME="):
				env.Pretty = strings.Trim(strings.TrimPrefix(s, "PRETTY_NAME="), `"`)
			}
		}
	}
	return env
}

// pkgInstall 按发行版给装包那一句（★ 只给人看，NetKit 不跑）。
func pkgInstall(distro string, pkg string) string {
	switch distro {
	case "ubuntu", "debian":
		return "sudo apt install -y " + pkg
	case "fedora":
		return "sudo dnf install -y " + pkg
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "sudo zypper install -y " + pkg
	case "arch", "manjaro":
		return "sudo pacman -S --noconfirm " + pkg
	}
	return "（" + firstNonEmpty(distro, "没认出发行版") + " 的包管理器 NetKit 没读到）sudo <你的包管理器> install " + pkg
}

// userSessionEnv 走 SSH 动桌面服务必须的两句话。
//
// ★ 现场最容易卡在这：SSH 会话里没有 XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS，
//
//	`systemctl --user` 与 `gsettings` 会直接 "Could not connect to bus"，
//	看着像"这台的桌面服务坏了"，其实只是环境里少这两个变量。
const userSessionEnv = `export XDG_RUNTIME_DIR=/run/user/$(id -u) ` +
	`DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus`

// LinuxShareChange 针对**已经探测到的桌面环境**给出打开屏幕共享的具体命令。
//
// ★ HandsOff 一定为真：装包、动别人的桌面会话不是 NetKit 该替人干的事
//
//	（docs/设计.md 里"不替人改系统"那条边界在 Linux 桌面这一侧仍然守着）。
//	但不再停在"你自己去开"——命令按探测结果拼好，能贴。
//	未实测（手上没有 GNOME/KDE 真机可开 VNC 核），所以每条 Why 都写了它是谁的写法。
func LinuxShareChange(env *LinuxEnv) *Change {
	ch := &Change{
		Kind:     "linux-vnc",
		HandsOff: true,
		Code:     "linux-share-commands",
		Reason:   "Linux 这一版 NetKit 不装包、不替你动桌面会话；下面这几条按探测到的桌面环境拼好了，贴过去跑",
	}
	de := env.DE()
	ch.Title = fmt.Sprintf("Linux 目标（%s / 桌面：%s）打开屏幕共享要跑的命令",
		firstNonEmpty(env.Pretty, env.Distro, "发行版没读到"), firstNonEmpty(de, "没认出来"))

	// 桌面服务是 user 级的，SSH 里先补环境变量再谈别的
	add := func(why, line string) { ch.Do = append(ch.Do, Cmd{Line: line, Why: why}) }
	add("SSH 会话里没有这两个变量，systemctl --user / gsettings 会报 Could not connect to bus", userSessionEnv)

	switch de {
	case "gnome":
		add("GNOME 42+ 自带远控服务端（gnome-remote-desktop），VNC 后端要 gsettings 打开",
			`gsettings set org.gnome.desktop.remote-desktop.vnc enabled true`)
		add("打开之后要有口令才有人敢连；grdctl 是官方命令行（未实测的旧系统用 gsettings 配 authentication-method）",
			`grdctl vnc set-credentials 你的口令`)
		add("user 级服务：起了它 5900 才真的在听",
			`systemctl --user enable --now gnome-remote-desktop`)
	case "gnome-vino":
		add("老 GNOME 的 vino：打开共享", `gsettings set org.gnome.Vino enabled true`)
		add("vino 默认每次连都弹框问人，SSH 里没人点，得关掉", `gsettings set org.gnome.Vino prompt-enabled false`)
		add("不开加密的客户端连不上加密的 vino，两头对齐", `gsettings set org.gnome.Vino require-encryption false`)
		add("vino 没有 systemd 单元，起进程（-n 让它自己 fork 到后台）", `/usr/lib/vino/vino-server -n &`)
	case "kde":
		add("KDE 的桌面共享是 krfb（它自己监听 5900）", `krfb --nofork &`)
		add("krfb 的端口/口令在配置里，命令行只负责起来；界面里勾「允许远程连接」更稳",
			`# 或者：系统设置 → 共享 → 桌面共享（krfb）里打开`)
	case "x11vnc":
		add("x11vnc 要先有一份口令文件", `x11vnc -storepasswd`)
		add("贴住 :0 那个已登录会话的屏幕，-forever 断开不退出",
			`x11vnc -display :0 -forever -rfbauth ~/.vnc/passwd`)
	default:
		if env.Installed() {
			add("探测到这些服务端程序，但桌面环境没认出来，别照着猜的跑",
				`# 装在这台上的：`+strings.Join(env.Bins, "、"))
		}
		add("没认出桌面环境，也没探到现成的服务端 —— 先装一个（这一步 NetKit 不替你跑）",
			pkgInstall(env.Distro, "gnome-remote-desktop"))
		add("装完照上面 GNOME/KDE 那几条打开；只想临时共享一个 X 会话的话 x11vnc 最轻",
			pkgInstall(env.Distro, "x11vnc"))
	}
	// 还原这一栏在 Linux 上是"关掉"而不是"回到原样"——因为 NetKit 压根没改过它
	ch.Undo = append(ch.Undo, Cmd{
		Line: `# 这一台 NetKit 没有改动过，也就没有还原：上面几条是你自己跑的，改回去也照上面那几条的反面`,
		Why:  "NetKit 不代跑，所以账本里这一栏只说明「没动过」",
	})
	return ch
}

// ── 编排：查 → （要改就先登记）→ 改 → 回查 ──

// PrepareDesktop 只读：拿连接参数与现状。**不动对端任何东西**。
func PrepareDesktop(ctx context.Context, x SSHExecer, d *Device) (*Prepared, error) {
	switch d.OS {
	case "windows":
		before, err := QueryRDP(ctx, x, d)
		if err != nil {
			return nil, err
		}
		info := &DesktopInfo{Protocol: "rdp", Host: d.Host, Port: 3389, User: d.User, WasEnabled: before.Enabled}
		return &Prepared{Info: info, Before: before}, nil
	case "linux", "darwin":
		before, err := QueryShare(ctx, x, d)
		if err != nil {
			return nil, err
		}
		info := &DesktopInfo{Protocol: "vnc", Host: d.Host, Port: 5900, User: d.User, WasEnabled: before.Listening}
		return &Prepared{Info: info, Before: before}, nil
	default:
		return nil, fmt.Errorf("还不知道 %s 是什么系统，先跑 remote.device.probe", d.ID)
	}
}

// PlanChange 「这台现在没开」时，问清楚 NetKit 能不能替它开、要跑哪几条。
//
// ★ 这一步仍然只读（macOS 问两句权限、Linux 探一遍桌面环境）。
//
//	真正的写入在 ApplyChange，而调用方必须在它之前把 Change 记进账本。
func PlanChange(ctx context.Context, x SSHExecer, d *Device) (*Change, error) {
	switch d.OS {
	case "windows":
		return RDPChange(), nil
	case "darwin":
		priv, err := ProbeMacSudo(ctx, x, d)
		if err != nil {
			return nil, fmt.Errorf("问不了那台的 sudo 底气：%w", err)
		}
		return MacShareChange(priv), nil
	case "linux":
		env, err := ProbeLinux(ctx, x, d)
		if err != nil {
			return nil, fmt.Errorf("探测那台的桌面环境失败：%w", err)
		}
		return LinuxShareChange(env), nil
	default:
		return nil, fmt.Errorf("还不知道 %s 是什么系统（%s），开不了远程桌面 —— 先跑 remote.device.probe", d.ID, d.OS)
	}
}

// ApplyChange 按计划在对端动手。★ 调用方必须先登记（先登记后执行）。
func ApplyChange(ctx context.Context, x SSHExecer, d *Device, ch *Change) error {
	if ch == nil {
		return nil
	}
	if ch.HandsOff {
		// ★ 不能悄悄放过：HandsOff 的计划里没有"跑了就对了"的命令，执行它等于拿给人看的文本去动系统
		return fmt.Errorf("这份计划 NetKit 不代跑（%s），只可照抄到那台机器上执行", ch.Reason)
	}
	for _, c := range ch.Do {
		out, err := x.Exec(ctx, d, c.Line, 60*time.Second)
		if err != nil {
			return fmt.Errorf("执行 %q 失败：%w", c.Line, err)
		}
		if out.ExitCode != 0 && !c.tolerates(out.ExitCode) {
			return &ApplyError{Cmd: c.Line, Why: c.Why, ExitCode: out.ExitCode,
				Output: firstNonEmpty(out.Stderr, out.Stdout)}
		}
	}
	return nil
}

// ConfirmListening 动手之后回查端口。
//
// ★ macOS 那一侧 5900 是 launchd 的 socket，起来要一点时间；跑完命令就说「开好了」
//
//	是把没核实的话讲满了。查不到就照实回，让人再点一次「查状态」。
func ConfirmListening(ctx context.Context, x SSHExecer, d *Device, tries int, gap time.Duration) (bool, error) {
	if tries < 1 {
		tries = 1
	}
	for i := 0; i < tries; i++ {
		st, err := QueryShare(ctx, x, d)
		if err != nil {
			return false, err
		}
		if st.Listening {
			return true, nil
		}
		if i < tries-1 {
			time.Sleep(gap)
		}
	}
	return false, nil
}

// ── 在 NetKit 主机上拉起现成的客户端 ──

// LaunchResult 拉起客户端的结果。
//
// ★ 拉不起来不算失败：把连接参数原样给人，手动连也就是十秒的事。
//
//	但"拉不起来"和"根本没客户端可拉"和"地址进了剪贴板"是三件事，
//	下一步各不相同，所以分开报（Code/Next）。
type LaunchResult struct {
	Launched bool   `json:"launched"`
	Cmd      string `json:"cmd"`              // 用了/准备用的命令，界面照实显示
	Code     string `json:"code,omitempty"`   // 附加判定（空 = 就是 launched/cmd 那两件事）
	Next     string `json:"next,omitempty"`   // 一句话下一步
	Viewer   string `json:"viewer,omitempty"` // 找到的查看器路径
	Copied   bool   `json:"copied,omitempty"` // 地址已进剪贴板
}

// LaunchClient 在 NetKit 主机上拉起现成的桌面客户端。
func LaunchClient(info *DesktopInfo) *LaunchResult {
	addr := fmt.Sprintf("%s:%d", info.Host, info.Port)
	switch info.Protocol {
	case "rdp":
		switch runtime.GOOS {
		case "windows":
			ok, cmd := launch("mstsc", "/v:"+addr)
			return rdpResult(ok, cmd, addr)
		case "darwin":
			// 写一个 .rdp 文件交给系统打开 —— 装了 Microsoft Remote Desktop / Windows App 就会接
			p := filepath.Join(os.TempDir(), "netkit-"+strings.ReplaceAll(addr, ":", "_")+".rdp")
			body := fmt.Sprintf("full address:s:%s\nusername:s:%s\n", addr, info.User)
			if err := os.WriteFile(p, []byte(body), 0o600); err == nil {
				ok, cmd := launch("open", p)
				return rdpResult(ok, cmd, addr)
			}
			return &LaunchResult{Cmd: "open " + p, Code: "desktop-ready-no-client",
				Next: "写这份 .rdp 都没写成；手动连：任何 RDP 客户端里填 " + addr}
		default:
			ok, cmd := launch("xfreerdp", "/v:"+addr, "/u:"+info.User)
			return rdpResult(ok, cmd, addr)
		}
	case "vnc":
		url := "vnc://" + addr
		switch runtime.GOOS {
		case "darwin":
			// 系统自带「屏幕共享」，open vnc:// 就是它的入口
			ok, cmd := launch("open", url)
			return clientResult(ok, cmd,
				"没拉起来：打开「屏幕共享」App 连 vnc://"+addr+"（Finder → 前往 → 连接服务器 也行）")
		case "windows":
			return launchWindowsVNCViewer(info.Host, info.Port)
		default:
			ok, cmd := launch("xdg-open", url)
			return clientResult(ok, cmd,
				"这台 Linux 上没有认 VNC URL 的程序；手动连 "+addr+"（vinagre / krfb / TigerVNC 都行）")
		}
	}
	return &LaunchResult{Code: "desktop-ready-no-client",
		Next: "不知道这是什么协议，连接参数：" + addr}
}

// rdpResult RDP 那一路的结果：拉起就好，没拉起来就把连接参数再说一遍。
func rdpResult(ok bool, cmd, addr string) *LaunchResult {
	return clientResult(ok, cmd, "没拉起来（"+cmd+"）；手动连：任何 RDP 客户端里填 "+addr)
}

// clientResult 三件事分开报：拉起来了没、用的什么命令、没拉起来下一步做什么。
func clientResult(ok bool, cmd, next string) *LaunchResult {
	if ok {
		return &LaunchResult{Launched: true, Cmd: cmd}
	}
	return &LaunchResult{Cmd: cmd, Code: "desktop-ready-no-client", Next: next}
}

// launchWindowsVNCViewer Windows 上当 NetKit 主机、目标是 VNC 时的一趟。
//
// ★ Windows 不带 VNC 客户端，但装过 TigerVNC/UltraVNC/RealVNC/TightVNC 的机器很常见 ——
//
//	先去找，找到就用它连；真没装，把地址放进剪贴板（**.vnc 不是 Windows 的格式，
//	写一个双击打不开的"连接文件"是骗人**），并如实说这一版不下载、不捆绑第三方查看器
//	（那是许可决定，不归工具层擅自定）。
func launchWindowsVNCViewer(host string, port int) *LaunchResult {
	dirs := winViewerDirsFromRegistry()
	cands := viewerCandidates(append(dirs, winDefaultViewerDirs()...))
	exe := firstExisting(cands)
	if exe == "" {
		addr := vncClipboardText(host, port)
		res := &LaunchResult{
			Code: "vnc-no-viewer-address-copied",
			Next: "这台 Windows 上没找到 VNC 查看器。地址已放进剪贴板（" + addr +
				"，双冒号是「直接给端口号」的写法）；粘贴到任意查看器的连接栏即可。" +
				"要 NetKit 能直接拉起，装 TigerVNC/UltraVNC/RealVNC Viewer/TightVNC 任一（NetKit 不代下载，也不捆绑第三方程序）",
		}
		if err := windowsClipboard(addr); err != nil {
			res.Code = "vnc-no-viewer"
			res.Next = "这台 Windows 上没找到 VNC 查看器，剪贴板也没放进去（" + err.Error() +
				"）：手动连 " + host + " 的 " + fmt.Sprint(port) + " 端口"
			return res
		}
		res.Copied = true
		res.Cmd = "clip < " + addr
		return res
	}
	args, shape := vncViewerArgs(exe, host, port)
	ok, cmd := launch(exe, args...)
	if !ok {
		return &LaunchResult{Viewer: exe, Cmd: cmd, Code: "vnc-viewer-launch-failed",
			Next: "找到了 " + exe + " 却没拉起来（" + cmd + "）；手动连 " + host + " 端口 " + fmt.Sprint(port)}
	}
	return &LaunchResult{Launched: true, Viewer: exe, Cmd: cmd,
		Next: "参数写法：" + shape}
}

// winUninstallRoots 注册表里放"装了什么"的那几个位置。
//
// ★★ 386 位进程读 HKLM\SOFTWARE\... 会被注册表**重定向**到 Wow6432NODE ——
//
//	windows/386 是发版目标（Win7），所以那条路径必须单独查一遍：
//	只查"看着正常"的那一条，64 位系统上装到 Program Files (x86) 的查看器会看不见。
var winUninstallRoots = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKLM\SOFTWARE\Wow6432NODE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// winViewerDirsFromRegistry 用 reg.exe 查装了哪个 VNC 产品，拿到安装目录。
//
// ★ 只用 reg query：CGO_ENABLED=0 与 windows/386 都要过（x/sys 在这个模块里是
//
//	indirect 依赖，不为这件事把它提成直接依赖）。reg.exe 从 XP/Win7 起就在系统里。
func winViewerDirsFromRegistry() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	var dirs []string
	for _, root := range winUninstallRoots {
		out, err := runLocal(5*time.Second, "reg", "query", root, "/s", "/f", "VNC")
		if err != nil {
			continue // 查不到不是失败：这台可能就是没装
		}
		dirs = append(dirs, parseRegInstallDirs(out)...)
	}
	return dirs
}

// parseRegInstallDirs 从 `reg query ... /s /f` 的输出里捞安装目录。
//
// 实测样本形状（reg.exe 的固定排版：值名、类型、数据三列）：
//
//	HKEY_LOCAL_MACHINE\...\Uninstall\TigerVNC
//	    InstallLocation    REG_SZ    C:\Program Files\TigerVNC\
//	    DisplayName        REG_SZ    TigerVNC 1.13.1
//	FOUND 100500
func parseRegInstallDirs(out string) []string {
	var dirs []string
	seen := map[string]bool{}
	push := func(d string) {
		d = strings.Trim(strings.TrimSpace(d), `"`)
		// 末尾那个 `\` 是注册表里写法带的，留着它当目录前缀去拼 exe 路径会拼出双分隔符。
		// 长度卡在 >3：`C:\` 削一刀就变成 `C:`，那已经不是同一个路径了。
		if len(d) > 3 {
			d = strings.TrimRight(d, `\`)
		}
		if d == "" || seen[strings.ToLower(d)] {
			return
		}
		seen[strings.ToLower(d)] = true
		dirs = append(dirs, d)
	}
	for _, ln := range strings.Split(out, "\n") {
		trimmed := strings.TrimLeft(ln, " \t")
		// ★ 按**四个空格**分列，不能用 Fields：reg 把值原样放在第三列，
		//   而 Windows 路径里就是有空格（C:\Program Files\…）。按空白切词会把
		//   「C:\Program Files\TigerVNC」切成「C:\Program」+「Files\TigerVNC」，
		//   于是查看器永远找不到 —— 报错还报成「这台没装 VNC」。
		cols := strings.SplitN(trimmed, "    ", 3)
		if len(cols) < 3 {
			f := strings.Fields(trimmed)
			if len(f) < 3 {
				continue
			}
			cols = []string{f[0], f[1], strings.Join(f[2:], " ")}
		}
		name := strings.ToLower(strings.TrimSpace(cols[0]))
		val := strings.Trim(strings.TrimSpace(cols[2]), `"`)
		if val == "" {
			continue
		}
		switch name {
		case "installlocation":
			// InstallLocation 本身就是目录，取目录会把它切掉一层
			//（`C:\Program Files\TigerVNC\` 一切就成了 `C:\Program Files`）。
			push(val)
		case "displayicon", "uninstallstring":
			// ★ 切的是**字符串里的 Windows 路径**，不能用宿主 filepath：
			//   在 macOS 上跑测试时 filepath.Dir(`C:\a\vncviewer.exe`) 会切出 "."（它只认 /），
			//   于是"这条只在 Windows 上跑的代码"永远测不到真形状。winDir 自己按 \ 与 / 切。
			push(winDir(val))
		}
	}
	return dirs
}

// winDir 取 Windows 路径的目录部分（字符串级，与宿主平台无关）。
func winDir(p string) string {
	p = strings.TrimRight(p, `\`)
	if i := strings.LastIndexAny(p, `\`); i >= 0 {
		return p[:i]
	}
	return p
}

// winJoin Windows 路径拼接（同样不用宿主 filepath）。
func winJoin(dir string, elems ...string) string {
	out := strings.TrimRight(dir, `\`)
	for _, e := range elems {
		out += `\` + strings.TrimLeft(e, `\`)
	}
	return out
}

// winDefaultViewerDirs 各家产品的常见安装目录（含 %ProgramFiles% 两种视图）。
func winDefaultViewerDirs() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pf86 := os.Getenv("ProgramFiles(x86)")
	if pf86 == "" {
		pf86 = `C:\Program Files (x86)`
	}
	roots := []string{pf, pf86}
	var out []string
	for _, r := range roots {
		for _, sub := range []string{
			`TigerVNC`, `TigerVNC\x64`, `uvnc bvba\UltraVNC`, `UltraVNC`,
			`RealVNC\VNC Viewer`, `RealVNC\VNC4`, `TightVNC`,
		} {
			out = append(out, winJoin(r, sub))
		}
	}
	return out
}

// viewerExeNames 各家查看器的可执行文件名。
var viewerExeNames = []string{"vncviewer.exe", "tvnviewer.exe", "uvnc_viewerr.exe", "vncviewer_x64.exe"}

// viewerCandidates 把一堆安装目录摊平成"可能的查看器可执行文件"。纯函数，好测。
func viewerCandidates(dirs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		for _, exe := range viewerExeNames {
			for _, p := range []string{winJoin(dir, exe), winJoin(dir, "bin", exe)} {
				k := strings.ToLower(p)
				if !seen[k] {
					seen[k] = true
					out = append(out, p)
				}
			}
		}
	}
	return out
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	// 最后问 PATH（装的时候勾了"加入 PATH"的产品）
	for _, name := range []string{"vncviewer", "tvnviewer"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// vncViewerArgs 按产品给出命令行形状。
//
// ★★ 各家查看器的参数**不一样**，这里每一形的假设都写明，且都标了未实测
//
//	（手上没有 Windows 真机可以逐个装了核）。所以把实际用的那条命令连同"用的是哪一形"
//	一起报回界面：连不上时人一眼看得见是写法不对，而不是只会说"拉不起来"。
//	  - TigerVNC / TightVNC 1.x / UltraVNC：`vncviewer 主机::端口`
//	    （双冒号 = 直接给 TCP 端口号；单冒号是 display 号，5901 是 :1。未实测）
//	  - TightVNC 2.x 的 tvnviewer：`tvnviewer -connect=主机::端口`（未实测）
//	  - RealVNC Viewer：`vncviewer 主机::端口`（它的文档里 host::port 也吃；未实测）
//	  - 认不出的产品：按最通用的 `主机::端口` 试（未实测）
func vncViewerArgs(exe, host string, port int) ([]string, string) {
	low := strings.ToLower(exe)
	addr := fmt.Sprintf("%s::%d", host, port)
	switch {
	case strings.Contains(low, "tvnviewer"):
		return []string{"-connect=" + addr}, "TightVNC 2.x：-connect=主机::端口"
	default:
		return []string{addr}, "主机::端口（双冒号直接给端口号）"
	}
}

// vncClipboardText 放进剪贴板的那一句。
//
// ★ 用双冒号（192.168.3.82::5900）：主流查看器（TigerVNC/UltraVNC/TightVNC/RealVNC）
//
//	的连接栏都认"双冒号 = 直接给 TCP 端口号"，而单冒号是 display 号（5901 是 :1）。
//	界面上会把这两种写法都念出来，粘错了人自己能看出来。
func vncClipboardText(host string, port int) string {
	return fmt.Sprintf("%s::%d", host, port)
}

// windowsClipboard 把文本放进剪贴板（clip.exe，Win7 起就在系统里）。
func windowsClipboard(text string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("剪贴板兜底只在 Windows 主机上有意义（当前 %s）", runtime.GOOS)
	}
	cmd := exec.Command("clip")
	cmd.Stdin = strings.NewReader(text + "\r\n") // clip 会带尾换行，这里显式给一个，行为一致
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clip 没能收下这段文本：%w", err)
	}
	return nil
}

// runLocal 本机跑一条外部命令拿输出（★ 只用于"当 NetKit 主机是 Windows 时查注册表"这一件事）。
//
// 非 Windows 上直接返回错误，调用方都忽略错误 —— 这样同一份代码三个平台都能编、
// 也不会有 POSIX 测试机器意外去跑 reg.exe。
func runLocal(timeout time.Duration, name string, args ...string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("本机不是 Windows（%s），不跑 %s", runtime.GOOS, name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
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
