package tools

// ── net.portal.start / .status / .stop / .kick / .rotate ──
//
// 手机端门户：主机在局域网里开一个网页，手机**扫二维码**进来 ——
// 传文件（进收件目录 / 从发件目录下载）、当遥控器操作已登记的远程设备、
// 把手机屏幕投到主机上。设计见 docs/设计.md「一键开通」与「移动端调试」两节，
// 这一张是其中「手机当遥控器 + 收发文件 + 投屏」那一半的落地。
//
// ★ 为什么它是 mutate：和文件共享同一条理由 —— 改的不是配置，是**这台机器对外的可见面**，
//
//	而且这个面比只读共享多两条：一个受鉴权的写路径（收件目录）、一条能驱动别的机器的通道（遥控器）。
//
// ★ 安全闸按设计稿逐条装：只绑指定网卡的地址（绝不通配）；进入链接一次性令牌、
//
//	10 分钟没人扫就作废；手机上的执行动作全部走注册表 —— 改系统的照旧要在主机界面弹框（[OTS-7.1]）；
//	谁扫了码、传了什么、执行了什么，门户活动表 + 远程审计各记一笔；默认不开机自启、进程退出端口即释放。
//
// ★ 投屏为什么要连 TLS 一起说：手机浏览器只在**安全上下文**里交出屏幕，
//
//	http://192.168.x.x 拿不到屏幕权限 —— 不是我们挑形式，是浏览器的边界。
//	开投屏时默认把自签 TLS 也带上，批准说明里写清「手机第一次会提示证书不受信任」。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/portal"
	"net.yuhox.com/netkit/internal/remote"
)

const (
	verdictPortalServing = "portal-serving"
	verdictPortalStopped = "portal-stopped"
	verdictPortalIdle    = "portal-idle"
)

const portalDefaultPort = 8642

// portalSrv 当前在跑的门户。全场只允许一个（同文件共享的纪律）。
var portalSrv = struct {
	mu      sync.Mutex
	srv     *portal.Service
	entryID string
	reg     *ots.Registry
	plan    portalPlan
}{}

// RegisterPortal 装进门户工具，并把注册表交给门户当遥控器的手。
func RegisterPortal(r *ots.Registry) {
	portalSrv.mu.Lock()
	portalSrv.reg = r
	portalSrv.mu.Unlock()
	r.MustRegister(portalStartTool, portalStatusTool, portalStopTool, portalKickTool, portalRotateTool)
}

type portalArgs struct {
	Iface        string   `json:"iface,omitempty"`
	Addrs        []string `json:"addrs,omitempty"`
	Port         int      `json:"port,omitempty"`
	Files        *bool    `json:"files,omitempty"`
	Remote       *bool    `json:"remote,omitempty"`
	Cast         *bool    `json:"cast,omitempty"`
	Screen       bool     `json:"screen,omitempty"`
	TLS          *bool    `json:"tls,omitempty"`
	Outbox       string   `json:"outbox,omitempty"`
	Inbox        string   `json:"inbox,omitempty"`
	MaxUploadMB  int      `json:"maxUploadMB,omitempty"`
	SessionHours int      `json:"sessionHours,omitempty"`
}

var portalStartTool = ots.Tool{
	Name:  "net.portal.start",
	Class: ots.ClassMutate,
	Summary: "在局域网里开「手机门户」：主机界面出二维码，手机扫一下就能进来 —— " +
		"传文件（手机→主机落收件目录；主机→手机从发件目录下载）、" +
		"当遥控器操作已登记的远程设备、把手机屏幕投到主机上。\n" +
		"★ 进入链接带一次性令牌（10 分钟没人扫作废；用过一次也作废，第二台手机点「换一张二维码」）。\n" +
		"★ 只绑指定网卡上的地址，绝不绑 0.0.0.0；IPv4 与 IPv6（ULA/全局）一起绑，双栈网络里的手机从哪边都进得来。\n" +
		"★ 手机上点到的执行动作全部走同一张工具表：改系统的那一半照旧在主机界面弹框确认，手机绕不过去。\n" +
		"投屏需要 TLS（手机浏览器只在 https 里交出屏幕），默认自动带自签证书：手机第一次打开会提示不受信任，点「继续」即可。\n" +
		"screen=true 时**这台机器的屏幕**会实时推给配过对的手机 —— 单独开关，默认关。\n" +
		"用完调 net.portal.stop 关掉；进程退出端口也就释放。全程留痕（门户活动表 + 远程审计）。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "iface": {"type": "string", "description": "开在哪块网卡（en0 / eth0 / WLAN）。不填按 IPv4 默认路由那块；只有一块可用网卡时用它。"},
	    "addrs": {"type": "array", "items": {"type": "string"},
	      "description": "直接指定绑哪些地址（覆盖 iface）。★ 不接受 0.0.0.0 / :: —— 那是要绕开按网卡挑地址这条线，请改成填 iface。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "端口，默认 8642。回环口同用这个号给主机界面看投屏直播。"},
	    "files": {"type": "boolean", "description": "开不开文件收发，默认开。收件目录是本机唯一的写路径：只新增文件、封顶大小、名字消毒。"},
	    "remote": {"type": "boolean", "description": "开不开遥控器（手机上看设备/执行命令/发消息），默认开。执行动作全部经工具表，改系统的要在主机确认。"},
	    "cast": {"type": "boolean", "description": "开不开手机投屏接收，默认开。开了会自动带 TLS —— 没有 https 手机浏览器根本不给屏幕权限。"},
	    "screen": {"type": "boolean", "description": "★ 把这台机器的屏幕实时推给手机看。默认关：它端出去的是这台机器本身，和看手机投屏不是一回事。"},
	    "tls": {"type": "boolean", "description": "开不开自签 TLS。默认：开投屏就自动开。关掉它投屏必失败（不是我们实现的毛病，是浏览器的安全上下文边界）。"},
	    "outbox": {"type": "string", "description": "发给手机的目录（对手机只读）。默认用配置目录下的 portal/发件目录。"},
	    "inbox": {"type": "string", "description": "手机传过来的落点。默认配置目录下的 portal/收件箱 —— 想收到别处就填绝对路径。"},
	    "maxUploadMB": {"type": "integer", "minimum": 1, "maximum": 20480, "description": "单个上传封顶 MB，默认 1024。"},
	    "sessionHours": {"type": "integer", "minimum": 1, "maximum": 72, "description": "配对后的会话寿命（小时），默认 8。"}
	  }
	}`),
	Describe: describePortalStart,
	Invoke:   startPortal,
}

var portalStatusTool = ots.Tool{
	Name:  "net.portal.status",
	Class: ots.ClassRead,
	Summary: "看手机门户现在的状态：开没开、绑在哪些地址（v4/v6 各列）、当前二维码、" +
		"几台手机配对中（谁、什么时候、还剩多久）、投屏进行到哪（几帧、多大、停没停）、" +
		"最近的活动（谁扫了码、传了什么、跑了哪个动作）。二维码链接带一次性令牌，令牌被用过就提示换一张。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: statusPortal,
}

var portalStopTool = ots.Tool{
	Name:    "net.portal.stop",
	Class:   ots.ClassMutate,
	Summary: "关掉手机门户：端口当场释放，手机上残留的页面再请求一律失效（配对凭据随服务一起没）。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string {
		return "关闭手机门户：局域网里的手机将不再能访问（已配对的全部立即失效）"
	},
	Invoke: stopPortal,
}

var portalKickTool = ots.Tool{
	Name:  "net.portal.kick",
	Class: ots.ClassMutate,
	Summary: "把一台手机立即踢下门户线：它的配对凭据当场作废，再要进来得重新扫码。" +
		"现场用：换人值班了、手机递出去了、或者就是不想让它再连着。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["session"],
	  "properties": {"session": {"type": "string", "description": "会话 ID（从 net.portal.status 的 sessions 里取）"}}
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Session string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("踢下线一台已配对的手机（会话 %s），它必须重新扫码", a.Session)
	},
	Invoke: kickPortal,
}

var portalRotateTool = ots.Tool{
	Name:  "net.portal.rotate",
	Class: ots.ClassRead,
	Summary: "换一张新的进入二维码：旧链接当场作废（不管用没用过），新令牌再起 10 分钟有效。" +
		"第二台手机要进来、或者怀疑旧码被人存下来了，就点这个。已配对的手机不受影响。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: rotatePortal,
}

// ── 计划 ──

type portalPlan struct {
	addrs    []string
	iface    string
	ifaceWhy string
	port     int
	files    bool
	remoteOn bool
	cast     bool
	screen   bool
	tls      bool
	outbox   string
	inbox    string
	maxMB    int
	session  time.Duration
	warnings []string
}

func planPortal(a portalArgs) (portalPlan, error) {
	var p portalPlan
	p.port = a.Port
	if p.port == 0 {
		p.port = portalDefaultPort
	}
	p.files = a.Files == nil || *a.Files
	p.remoteOn = a.Remote == nil || *a.Remote
	p.cast = a.Cast == nil || *a.Cast
	p.screen = a.Screen
	p.tls = p.cast
	if a.TLS != nil {
		p.tls = *a.TLS
	}
	p.maxMB = a.MaxUploadMB
	if p.maxMB == 0 {
		p.maxMB = 1024
	}
	p.session = time.Duration(a.SessionHours) * time.Hour
	if p.session == 0 {
		p.session = 8 * time.Hour
	}

	dir, err := remote.DefaultDir()
	if err != nil {
		return p, ots.Errf(ots.ErrInternal, "找不到放门户数据的目录：%s", err)
	}
	p.outbox = absOr(a.Outbox, filepath.Join(dir, "portal", "outbox"))
	p.inbox = absOr(a.Inbox, filepath.Join(dir, "portal", "inbox"))

	nics, err := fileshareNICs()
	if err != nil {
		return p, ots.Errf(ots.ErrInternal, "读网卡列表失败：%s", err)
	}

	if len(a.Addrs) > 0 {
		var pub []string
		for _, x := range a.Addrs {
			x = strings.TrimSpace(x)
			if x == "" {
				continue
			}
			if x == "0.0.0.0" || x == "::" || x == "*" {
				return p, ots.Errf(ots.ErrInvalidArgument,
					"不接受绑 %s：那会把门户从本机所有网卡上开放出去，包括可能连着的办公网和公网。改成填 iface", x)
			}
			ad, perr := netaddr.Parse(x)
			if perr != nil || !ad.IP.IsValid() {
				return p, ots.Errf(ots.ErrInvalidArgument, "%q 不是一个地址", x)
			}
			pub = append(pub, x)
			if ad.Scope() == netaddr.ScopeGlobal {
				p.warnings = append(p.warnings, fmt.Sprintf("%s 是公网可路由地址，这个门户等于对互联网开着", x))
			}
		}
		if len(pub) == 0 {
			return p, ots.Errf(ots.ErrInvalidArgument, "addrs 里没有有效地址")
		}
		p.addrs, p.iface, p.ifaceWhy = pub, "", "你直接给的地址"
		return p, nil
	}

	byName := map[string]netif.NIC{}
	for _, n := range nics {
		byName[n.Name] = n
	}
	var pick *netif.NIC
	switch {
	case a.Iface != "":
		n, ok := byName[a.Iface]
		if !ok {
			return p, ots.Errf(ots.ErrInvalidArgument, "没有叫 %s 的网卡（用 net.interfaces 看有哪些）", a.Iface)
		}
		pick = &n
		p.ifaceWhy = "你指定的网卡"
	default:
		cand, why, err := defaultShareNIC(nics)
		if err != nil {
			return p, err
		}
		pick = cand
		p.ifaceWhy = why
	}
	addrs := portalAddrs(*pick)
	if len(addrs) == 0 {
		return p, ots.Errf(ots.ErrInvalidArgument,
			"%s 上没有一个可绑的地址（要私网或全局的 v4/v6；169.254 和 fe80:: 那种不能拿来配对）", pick.Name)
	}
	p.iface = pick.Name
	p.addrs = addrs
	for _, x := range addrs {
		if ad, err := netaddr.Parse(x); err == nil && ad.Scope() == netaddr.ScopeGlobal {
			p.warnings = append(p.warnings,
				fmt.Sprintf("%s（%s 上）是公网可路由地址，这个门户等于对互联网开着", x, pick.Name))
		}
	}
	return p, nil
}

// portalAddrs 这块网卡上能绑来**给手机访问**的地址：v4 在前（手机连的多数还是 v4），
// 再给 v6 的 ULA/全局 —— 和固件共享不同，手机浏览器认得 http://[fd00::…]，
// 双栈网段里 v6 这条路该一起摆出来，谁通用谁。
// ★ 仍然不给链路本地：URL 里塞不下 %zone，给了就是给现场挖坑。
func portalAddrs(n netif.NIC) []string { return shareAddrs(n) }

func absOr(given, def string) string {
	if strings.TrimSpace(given) == "" {
		return def
	}
	abs, err := filepath.Abs(given)
	if err != nil {
		return given
	}
	return abs
}

// ── 批准说明 ──

func describePortalStart(raw json.RawMessage) string {
	var a portalArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	plan, err := planPortal(a)
	scheme := "http"
	if plan.tls {
		scheme = "https"
	}
	s := fmt.Sprintf("在手机门户上开放：文件收发（%v）、远程操作（%v）、手机投屏接收（%v）、主机屏幕外送（%v）"+
		"—— 用 %s 端口 %d，进门户要扫一次性二维码",
		plan.files, plan.remoteOn, plan.cast, plan.screen, scheme, plan.port)
	switch {
	case err != nil:
		s += fmt.Sprintf("；网卡没定下来：%s", err)
	case plan.iface == "":
		s += "；绑在这些地址：" + strings.Join(plan.addrs, "、")
	default:
		s += fmt.Sprintf("；开在网卡 %s 上（%s），绑 %s", plan.iface, plan.ifaceWhy, strings.Join(plan.addrs, "、"))
	}
	if plan.files {
		s += fmt.Sprintf("。★ 手机能往收件目录写新文件（%s，单文件封顶 %d MB，只新增不覆盖）；"+
			"发件目录对手机只读（%s）", plan.inbox, plan.maxMB, plan.outbox)
	}
	if plan.remoteOn {
		s += "。手机上点的执行/发消息/开桌面/跑剧本仍走这套工具表 —— 改系统的会在本机弹框确认"
	}
	if plan.screen {
		s += "。★ 这台机器的屏幕会实时推给配过对的手机看"
	}
	if plan.tls {
		s += "。证书为自签：手机首开会提示不受信任"
	}
	if len(plan.warnings) > 0 {
		s += "。★ " + strings.Join(plan.warnings, "；")
	}
	return s
}

// ── 实现 ──

// registryCaller 把注册表包成门户要的那只手。
// ★ 调用方标识在这里由**传输层**塞进 ctx（portal:<对端IP>），工具里读到的才是真身份（[OTS-7.3]）。
type registryCaller struct{ r *ots.Registry }

func (c registryCaller) InvokeTool(ctx context.Context, caller, name string, args json.RawMessage) (any, error) {
	out, err := c.r.Invoke(ots.WithCaller(ctx, caller), name, args)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func startPortal(ctx context.Context, raw json.RawMessage) (any, error) {
	var a portalArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	plan, err := planPortal(a)
	if err != nil {
		return nil, err
	}
	if journal == nil {
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝开手机门户")
	}

	portalSrv.mu.Lock()
	defer portalSrv.mu.Unlock()
	if portalSrv.srv != nil {
		st := portalSrv.srv.Status()
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"手机门户已经在跑（端口 %d，%d 台手机连着）。先停掉再开新的", st.Port, len(st.Sessions))
	}

	dir, _ := remote.DefaultDir()
	deps := portal.Deps{}
	if mgr != nil {
		deps.Audit = mgr.Audit
	}
	srv, err := portal.Start(portal.Config{
		Addrs: plan.addrs, Port: plan.port, TLS: plan.tls,
		Files: plan.files, Outbox: plan.outbox, Inbox: plan.inbox, MaxUploadMB: plan.maxMB,
		Remote: plan.remoteOn, Reg: registryCaller{r: portalSrv.reg},
		Cast: plan.cast, Screen: plan.screen,
		SnapDir:    filepath.Join(dir, "portal", "snapshots"),
		SessionTTL: plan.session,
	}, deps)
	if err != nil {
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}

	if id, jerr := journal.Register("mobile-portal", describePortalStart(raw),
		map[string]any{"serving": false},
		map[string]any{"iface": plan.iface, "addrs": plan.addrs, "port": plan.port,
			"files": plan.files, "remote": plan.remoteOn, "cast": plan.cast,
			"screen": plan.screen, "tls": plan.tls}); jerr == nil {
		_ = journal.MarkApplied(id)
		portalSrv.entryID = id
	}
	portalSrv.srv = srv
	portalSrv.plan = plan

	vals, note := portalView(srv, plan)
	return ots.Verdict{Code: verdictPortalServing, Values: vals, Note: note}, nil
}

// portalView 把「状态 + 现刷的二维码」拼成结果。start/status/rotate 三处共用一份，
// 免得哪一处忘了刷新二维码、把用过的旧码当新的显示。
func portalView(srv *portal.Service, plan portalPlan) (map[string]any, string) {
	st := srv.Status()
	entries := srv.EntryURLs()
	type qrItem struct {
		URL string `json:"url"`
		PNG string `json:"png"`
	}
	var qrs []qrItem
	for _, u := range entries {
		if png, err := portal.QRDataURI(u); err == nil {
			qrs = append(qrs, qrItem{URL: u, PNG: png})
		}
	}
	vals := map[string]any{
		"status":   st,
		"qr":       qrs,
		"iface":    plan.iface,
		"ifaceWhy": plan.ifaceWhy,
		"snapDir":  st.SnapDir,
	}
	note := fmt.Sprintf("手机门户已开在 %s 端口 %d（网卡 %s，%s）",
		st.Scheme, st.Port, portalIfaceDesc(plan.iface), strings.Join(plan.addrs, "、"))
	if st.EntryUsed {
		note += "；这张二维码已被用过 —— 再要一台手机进来就点「换一张」"
	}
	return vals, note
}

func portalIfaceDesc(s string) string {
	if s == "" {
		return "（手填地址）"
	}
	return s
}

func statusPortal(ctx context.Context, raw json.RawMessage) (any, error) {
	portalSrv.mu.Lock()
	srv, plan := portalSrv.srv, portalSrv.plan
	portalSrv.mu.Unlock()
	if srv == nil {
		return ots.Verdict{
			Code:   verdictPortalIdle,
			Values: map[string]any{"status": portal.Status{Sessions: []portal.Session{}, Activity: []portal.Activity{}}},
			Note:   "本机没在开手机门户",
		}, nil
	}
	vals, note := portalView(srv, plan)
	return ots.Verdict{Code: verdictPortalServing, Values: vals, Note: note}, nil
}

func stopPortal(ctx context.Context, raw json.RawMessage) (any, error) {
	portalSrv.mu.Lock()
	defer portalSrv.mu.Unlock()
	if portalSrv.srv == nil {
		return ots.Verdict{Code: verdictPortalIdle,
			Values: map[string]any{"status": portal.Status{}},
			Note:   "本机没有在跑的手机门户"}, nil
	}
	st := portalSrv.srv.Status()
	portalSrv.srv.Stop()
	if journal != nil && portalSrv.entryID != "" {
		_ = journal.MarkReverted(portalSrv.entryID, "用户关掉了手机门户")
	}
	portalSrv.srv, portalSrv.entryID, portalSrv.plan = nil, "", portalPlan{}
	return ots.Verdict{
		Code:   verdictPortalStopped,
		Values: map[string]any{"port": st.Port, "urls": st.URLs, "sessions": len(st.Sessions)},
		Note: fmt.Sprintf("手机门户已关：%s 端口 %d 已释放，%d 台手机的配对当场失效（活动已留痕 %d 笔）",
			st.Scheme, st.Port, len(st.Sessions), len(st.Activity)),
	}, nil
}

func kickPortal(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	portalSrv.mu.Lock()
	srv := portalSrv.srv
	portalSrv.mu.Unlock()
	if srv == nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "手机门户没在跑，没有可踢的会话")
	}
	if !srv.Kick(a.Session) {
		return ots.Verdict{Code: "portal-session-gone",
			Values: map[string]any{"session": a.Session},
			Note:   "这个会话已经不在了（过期或被踢过）"}, nil
	}
	return ots.Verdict{Code: "portal-kicked",
		Values: map[string]any{"session": a.Session},
		Note:   "已踢下线：那台手机再要进来得重新扫码"}, nil
}

func rotatePortal(ctx context.Context, raw json.RawMessage) (any, error) {
	portalSrv.mu.Lock()
	srv, plan := portalSrv.srv, portalSrv.plan
	portalSrv.mu.Unlock()
	if srv == nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "手机门户没在跑：先开门户才有二维码可换")
	}
	if err := srv.Rotate(); err != nil {
		return nil, ots.Errf(ots.ErrInternal, "%s", err)
	}
	vals, note := portalView(srv, plan)
	return ots.Verdict{Code: verdictPortalServing, Values: vals,
		Note: "已换新的进入二维码（旧链接当场作废，10 分钟有效）；" + note}, nil
}

// restorePortal 处理上次没停的门户账。监听器随进程退出即失效，
// **没有状态要还原**，但这笔账必须了结（同 restoreFileShare 的理由）。
func restorePortal(log *slog.Logger) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind != "mobile-portal" {
			continue
		}
		log.Warn("上次退出时手机门户没有正常关闭 —— 本次启动不会自动重开（端口已随上次进程退出而释放）",
			"改动", e.What, "时间", e.At.Format(time.RFC3339))
		_ = journal.MarkReverted(e.ID, "进程重启：监听器已随上次进程退出而释放")
	}
}
