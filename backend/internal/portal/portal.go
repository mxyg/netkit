// Package portal 是「手机端门户」：网通主机在局域网里开一个网页服务，
// 手机扫一下二维码就能进来 —— 传文件、当遥控器操作已登记的远程设备、
// 把手机屏幕投到主机上。
//
// ★★ 它和 docs/设计.md「一键开通」一节守同一套闸：
//
//	只绑指定网卡上的地址（绝不绑通配）；进入链接带**一次性令牌**，
//	页面上同时给二维码；执行类动作全部转成同一张工具注册表里的调用 ——
//	改系统的那一半照旧要在主机界面上有人点头（[OTS-7.1]），
//	手机拿不到任何「只在手机上存在」的能力（[OTS-4.5]）。
//
// 两条通道，信任级别不同，各起各的监听器：
//
//	局域网口 —— 除进入页外一切都要会话 cookie（扫码配对之后才发）；
//	回环口   —— 只服务主机自己的界面（投屏直播、状态快照），不开任何写路径。
//
// 投屏为什么基本一定要 TLS：浏览器只在**安全上下文**里交出屏幕和摄像头，
// http://192.168.x.x 不是安全上下文 —— 这是浏览器的边界，不是我们的偏好。
package portal

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNoAddr 一个可绑的地址都没有：宁可当场失败，也不悄悄退回 0.0.0.0。
var ErrNoAddr = errors.New("没有可绑定的地址")

// entryTokenTTL 配对令牌没人扫就作废的时长。设计稿定的 10 分钟，
// 现场「掏出手机、打开相机、对焦」就是这一档。
const entryTokenTTL = 10 * time.Minute

// Deps 门户干活要用的邻居，由调用方（工具层）装好，这里不自己找。
type Deps struct {
	// Audit 远程审计那本账的回调（remote.Manager.Audit 同形）。可以为 nil：
	// 门户自己的活动表照记，只是不落那本账。
	Audit func(actor, action, target, detail, result string)
}

// ToolCaller 门户调用工具的那只手。*ots.Registry 由工具层包一层满足它；
// 定成接口是为了测试能塞一张假表进去。caller 是给审计看的调用方标识，
// ★ 由门户这一层给（参数里自称的不算数，[OTS-7.3]）。
type ToolCaller interface {
	InvokeTool(ctx context.Context, caller, name string, args json.RawMessage) (any, error)
}

// Config 一次启动的参数。地址由调用方按网卡算好，这里不猜网卡。
type Config struct {
	Addrs []string // 局域网监听地址（v4 与 v6 可混）
	Port  int      // 0 = 系统挑号；挑中几号从 Status 读回
	TLS   bool     // 自签证书。手机要交出屏幕（投屏）时基本必须开

	// Files 文件收发：手机能下载发件目录里的东西、上传文件到收件目录。
	Files  bool
	Outbox string // 发给手机的目录（对手机只读）
	Inbox  string // 手机传过来的落这里（门户唯一的写路径）
	// MaxUploadMB 单个上传封顶，默认 1024。
	MaxUploadMB int

	// Remote 遥控器：手机页面上点到的动作，转成注册表里白名单内的工具调用。
	Remote bool
	Reg    ToolCaller // Remote=true 时必填 —— 门户不自己实现任何动作

	Cast   bool // 手机投屏（手机 → 主机）
	Screen bool // 主机屏幕给手机看（主机 → 手机）。单独开关：它端出去的是这台机器本身
	// SnapDir 投屏抓拍目录（主机界面点「存这一帧」落这里）。空 = 不提供抓拍。
	SnapDir string

	// SessionTTL 配对后的会话寿命，默认 8 小时。
	SessionTTL time.Duration
}

// Session 一个已经扫码进来的设备。
type Session struct {
	ID        string    `json:"id"`
	Peer      string    `json:"peer"`
	UA        string    `json:"ua"`
	JoinedAt  time.Time `json:"joinedAt"`
	LastSeen  time.Time `json:"lastSeen"`
	Requests  int64     `json:"requests"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Activity 门户里发生过的一件事。内存里留最近 100 条 —— 这是给现场看的，
// 真要翻旧账去远程审计那本 JSONL。
type Activity struct {
	At     time.Time `json:"at"`
	Peer   string    `json:"peer"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Result string    `json:"result"`
}

// CastState 手机投屏的当前状况。
type CastState struct {
	Active bool       `json:"active"`
	Peer   string     `json:"peer,omitempty"`
	Mode   string     `json:"mode,omitempty"` // screen / camera
	Frames int64      `json:"frames"`
	Bytes  int64      `json:"bytes"`
	LastAt *time.Time `json:"lastAt,omitempty"`
	// Stale 最后一帧超过 5 秒没来：手机把页面切到后台是常态，
	// 界面要分得清「还在流」和「停在那一帧」。
	Stale bool `json:"stale"`
}

// Status 当前状态。没在跑时 Running=false，其余字段照常给（界面统一渲染）。
type Status struct {
	Running   bool     `json:"running"`
	Scheme    string   `json:"scheme,omitempty"`
	Addrs     []string `json:"addrs,omitempty"`
	URLs      []string `json:"urls,omitempty"`
	LocalURLs []string `json:"localUrls,omitempty"`
	Port      int      `json:"port"`
	TLS       bool     `json:"tls"`

	// Token 当前配对令牌。一次性：被用掉之后 EntryUsed=true，
	// 第二台手机要进来得先 Rotate 换一张新的二维码。
	Token     string     `json:"token,omitempty"`
	EntryUsed bool       `json:"entryUsed"`
	EntryExp  *time.Time `json:"entryExpiresAt,omitempty"`

	Files  bool   `json:"files"`
	Outbox string `json:"outbox,omitempty"`
	Inbox  string `json:"inbox,omitempty"`
	Remote bool   `json:"remote"`
	Cast   bool   `json:"cast"`
	Screen bool   `json:"screen"`

	CastNow            CastState `json:"castNow"`
	ScreenSupported    bool      `json:"screenSupported"`
	ScreenLiveWatchers int       `json:"screenLiveWatchers"`

	Sessions []Session  `json:"sessions"`
	Activity []Activity `json:"activity"`
	Warnings []string   `json:"warnings,omitempty"`

	// SnapDir 投屏抓拍目录（主机界面「存这一帧」的落点）。空 = 没这个动作。
	SnapDir string `json:"snapDir,omitempty"`

	HostName string `json:"hostName,omitempty"`
	// LocalName 主机名.local —— macOS 的系统 Bonjour 会自动应答这个名字，
	// 手机换网不断地址就靠它；其它系统不保证，界面按「备用」渲染。
	LocalName string `json:"localName,omitempty"`
	// CertPEM 自签证书（PEM）。手机要长期信任这个门户时下载它。
	CertPEM string `json:"certPem,omitempty"`
}

// Service 运行中的门户。全场只允许一个（和文件共享同一条纪律：
// 两个门户的界面要让人分清「关的是哪个」，这件事在现场一定出错）。
type Service struct {
	cfg  Config
	deps Deps

	// 目录启动时把符号链接走完，之后每个请求的归属检查只对真身做（同 filesrv）。
	outboxReal string
	inboxReal  string

	hostName string
	certPEM  string
	tlsCert  tls.Certificate
	lns      []net.Listener
	srvs     []*http.Server

	mu             sync.Mutex
	token          string
	entryUsed      bool
	entryExp       time.Time
	sessions       map[string]*Session
	warnings       []string
	activity       []Activity
	closed         bool
	screenWatchers int

	castMu    sync.Mutex
	castFrame []byte
	cast      CastState
	subs      map[chan []byte]struct{}

	screenMu    sync.Mutex
	screenCache []byte
	screenAt    time.Time
}

// Start 建服务并监听。不合理组合（开遥控器没给注册表）当场拒。
func Start(cfg Config, deps Deps) (*Service, error) {
	if len(cfg.Addrs) == 0 {
		return nil, ErrNoAddr
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("端口 %d 不对，要 0（自动挑）到 65535", cfg.Port)
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.MaxUploadMB == 0 {
		cfg.MaxUploadMB = 1024
	}
	if cfg.Remote && cfg.Reg == nil {
		return nil, errors.New("开了遥控器但没给工具注册表：门户不自己实现任何动作")
	}
	if cfg.Files {
		if strings.TrimSpace(cfg.Outbox) == "" || strings.TrimSpace(cfg.Inbox) == "" {
			return nil, errors.New("开了文件收发，发件目录和收件目录都得给")
		}
		for _, d := range []struct{ what, p string }{{"发件目录", cfg.Outbox}, {"收件目录", cfg.Inbox}} {
			if err := ensureDir(d.p); err != nil {
				return nil, fmt.Errorf("%s %s 用不了：%s", d.what, d.p, err)
			}
		}
	}

	s := &Service{
		cfg:      cfg,
		deps:     deps,
		sessions: map[string]*Session{},
		subs:     map[chan []byte]struct{}{},
	}
	if cfg.Files {
		s.outboxReal = realPath(cfg.Outbox)
		s.inboxReal = realPath(cfg.Inbox)
	}
	if hn, err := os.Hostname(); err == nil {
		s.hostName = hn
	}
	if err := s.newEntryToken(); err != nil {
		return nil, err
	}
	if cfg.TLS {
		if err := s.genCert(); err != nil {
			return nil, err
		}
		s.warnings = append(s.warnings,
			"证书是自签的：手机第一次打开会提示「未受信任」，选「继续」即可；想消掉提示可下载证书并信任")
	}
	if cfg.Cast && !cfg.TLS {
		// 这一条必须提前说出来：不 TLS 时手机的浏览器根本不给屏幕权限，
		// 现场会以为是网通坏了。
		s.warnings = append(s.warnings,
			"没开 TLS 时手机浏览器不会交出屏幕（安全上下文限制）：投屏要用请把 tls 打开")
	}

	var tlsCfg *tls.Config
	if cfg.TLS {
		tlsCfg = s.tlsConfigForHTTP()
	}

	var started []net.Listener
	// 局域网地址里有没有 127.0.0.1（只有测试和手工配错会出现）。
	// 出现过就不另起回环监听器 —— 同一个号自己撞自己。
	lanHasLoopback := false
	for _, a := range cfg.Addrs {
		if strings.Trim(a, "[]") == "127.0.0.1" {
			lanHasLoopback = true
		}
	}
	for _, a := range cfg.Addrs {
		host := strings.Trim(a, "[]")
		ln, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(cfg.Port)))
		if err != nil {
			s.stopAll(started)
			return nil, bindErr(host, cfg.Port, err)
		}
		if cfg.Port == 0 {
			// 系统挑中的号记回来：剩下的监听器（含回环口）必须绑同一个号，
			// 否则二维码上写的和实际听的不是一回事。
			_, port, e := net.SplitHostPort(ln.Addr().String())
			if e != nil {
				s.stopAll(started)
				return nil, e
			}
			fmt.Sscanf(port, "%d", &cfg.Port)
			s.cfg.Port = cfg.Port
		}
		started = append(started, wrapTLS(ln, tlsCfg))
	}
	if !lanHasLoopback {
		// 回环口永远明文：主机界面（Electron 的 file:// 页）拿 http://127.0.0.1:同一号
		// 看投屏直播，不用替自签证书再点一次「继续」。
		lnLocal, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.Port)))
		if err != nil {
			s.stopAll(started)
			return nil, bindErr("127.0.0.1", cfg.Port, err)
		}
		started = append(started, lnLocal)
	}
	s.lns = started

	for _, ln := range started {
		hv := &http.Server{
			Handler:           s.dispatch(ln),
			ReadHeaderTimeout: 10 * time.Second,
		}
		s.srvs = append(s.srvs, hv)
		go func(hv *http.Server, ln net.Listener) { _ = hv.Serve(ln) }(hv, ln)
	}
	return s, nil
}

// dispatch 按监听器分派：回环口只挂 /local/*，局域网口挂其余全部。
// ★ 一条路由都不许多挂 —— 回环口不鉴权，任何写路径或工具调用漏上去
//
//	就等于本机进程自己给自己开了后门。
//
// 例外只有一种：监听地址本身就只有回环（测试、或手工把 127.0.0.1 填进了 addrs）。
// 这时不另起监听器，改为在这一条上按路径分 —— 127.0.0.1 上本来就只到得了本机自己，
// 两条 mux 并存在这里不越那条安全线；真机（绑的是网卡地址）走的仍是上面的严格分派。
func (s *Service) dispatch(ln net.Listener) http.Handler {
	host, _, err := net.SplitHostPort(ln.Addr().String())
	local := err == nil && host == "127.0.0.1"
	lan, lcl := s.lanHandler(), s.localHandler()
	if !local {
		return lan
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/local/") {
			lcl.ServeHTTP(w, r)
			return
		}
		lan.ServeHTTP(w, r)
	})
}

func (s *Service) stopAll(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// Stop 关掉监听器，掐断所有还在挂着的连接。停了手机上残留的会话也就失效了。
func (s *Service) Stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	srvs, lns := s.srvs, s.lns
	s.mu.Unlock()

	s.castMu.Lock()
	subs := s.subs
	s.subs = map[chan []byte]struct{}{}
	s.castMu.Unlock()
	for ch := range subs {
		close(ch) // 直播的观看者收到「流断了」，界面上那格画面会自己变成「投屏已停」
	}

	for _, hv := range srvs {
		_ = hv.Close()
	}
	s.stopAll(lns)
}

// Rotate 换一张新的进入令牌（旧二维码当场作废）。
func (s *Service) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("门户没在跑")
	}
	return s.newEntryTokenLocked()
}

// Kick 踢掉一个已配对的会话：它的 cookie 当场作废，再请求要重新扫码。
func (s *Service) Kick(id string) bool {
	s.mu.Lock()
	_, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	// note 自己拿锁，必须在锁外记。
	s.note("host", "kick", id, "", "已踢下线")
	return true
}

func (s *Service) newEntryToken() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newEntryTokenLocked()
}

func (s *Service) newEntryTokenLocked() error {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("造不出配对令牌：%s", err)
	}
	s.token = hex.EncodeToString(b)
	s.entryUsed = false
	s.entryExp = time.Now().Add(entryTokenTTL)
	return nil
}

// Status 当前快照。
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := s.entryExp
	st := Status{
		Running:            !s.closed,
		Scheme:             s.scheme(),
		Addrs:              append([]string(nil), s.cfg.Addrs...),
		URLs:               s.URLs(),
		LocalURLs:          []string{"http://127.0.0.1:" + fmt.Sprint(s.cfg.Port) + "/local/status"},
		Port:               s.cfg.Port,
		TLS:                s.cfg.TLS,
		Token:              s.token,
		EntryUsed:          s.entryUsed,
		EntryExp:           &exp,
		Files:              s.cfg.Files,
		Outbox:             s.cfg.Outbox,
		Inbox:              s.cfg.Inbox,
		Remote:             s.cfg.Remote,
		Cast:               s.cfg.Cast,
		Screen:             s.cfg.Screen,
		SnapDir:            s.cfg.SnapDir,
		ScreenLiveWatchers: s.screenWatchers,
		ScreenSupported:    screenSupported(),
		CastNow:            s.castSnapshot(),
		HostName:           s.hostName,
		Warnings:           append([]string(nil), s.warnings...),
	}
	if s.cfg.TLS {
		st.CertPEM = s.certPEM
	}
	if base := shortHost(s.hostName); base != "" {
		st.LocalName = base + ".local"
	}
	for _, sess := range s.sessions {
		cp := *sess
		st.Sessions = append(st.Sessions, cp)
	}
	sort.Slice(st.Sessions, func(i, j int) bool { return st.Sessions[i].JoinedAt.Before(st.Sessions[j].JoinedAt) })
	rec := make([]Activity, len(s.activity))
	copy(rec, s.activity)
	for i, j := 0, len(rec)-1; i < j; i, j = i+1, j-1 {
		rec[i], rec[j] = rec[j], rec[i]
	}
	st.Activity = rec
	return st
}

func (s *Service) scheme() string {
	if s.cfg.TLS {
		return "https"
	}
	return "http"
}

// URLs 每个地址一条可扫可贴的进入链接（不带令牌 —— 令牌从 /enter/<token> 单独给，
// 见 EntryURLs：链接会进手机浏览记录，二维码只活 10 分钟，两者故意不是一条）。
func (s *Service) URLs() []string {
	var u []string
	for _, a := range s.cfg.Addrs {
		host := a
		if strings.Contains(a, ":") { // v6：URL 里必须带方括号，不然端口分隔符歧义
			host = "[" + a + "]"
		}
		u = append(u, fmt.Sprintf("%s://%s:%d/", s.scheme(), host, s.cfg.Port))
	}
	sort.Strings(u)
	return u
}

// EntryURLs 每个地址一条**带令牌**的进入链接。二维码刷的就是它。
func (s *Service) EntryURLs() []string {
	s.mu.Lock()
	token := s.token
	s.mu.Unlock()
	var u []string
	for _, base := range s.URLs() {
		u = append(u, base+"enter/"+token)
	}
	return u
}

// note 记一笔活动 + （装了的话）落一行远程审计。
func (s *Service) note(peer, action, target, detail, result string) {
	a := Activity{At: time.Now(), Peer: peer, Action: action, Target: target, Detail: detail, Result: result}
	s.mu.Lock()
	s.activity = append(s.activity, a)
	if len(s.activity) > 100 {
		s.activity = s.activity[len(s.activity)-100:]
	}
	s.mu.Unlock()
	if s.deps.Audit != nil {
		s.deps.Audit("portal:"+peer, action, target, detail, result)
	}
}

// Auditf 走远程审计那本账，不带活动表（活动表另有 note 的场合用它）。
func (s *Service) auditf(actor, action, target, detail, result string) {
	if s.deps.Audit != nil {
		s.deps.Audit(actor, action, target, detail, result)
	}
}

func ensureDir(p string) error {
	fi, err := os.Stat(p)
	if err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s 不是目录", p)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(p, 0o700)
}

func realPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return filepath.Clean(abs)
}

func shortHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

// bindErr 把「绑不上」分成现场要区别对待的三类（措辞和 filesrv 同源）。
func bindErr(addr string, port int, err error) error {
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "permission"):
		return fmt.Errorf("%s:%d 绑不上：这个端口要更高权限（1024 以下）。换个端口，比如 8642", addr, port)
	case strings.Contains(err.Error(), "address already in use"):
		return fmt.Errorf("%s:%d 已经被别的服务占了：换个端口，或者用「本机端口占用」那张卡先看是谁占着", addr, port)
	case strings.Contains(err.Error(), "assign requested address"):
		return fmt.Errorf("本机没有 %s 这个地址（网卡刚换过 / 地址掉了？重新读一次网卡列表再试）", addr)
	}
	return fmt.Errorf("%s:%d 绑不上：%s", addr, port, err)
}
