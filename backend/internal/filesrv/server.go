// Package filesrv 起一个**只读**的文件服务，把本机一个目录开放给同网段的设备取。
//
// 现场用途很具体：设备的升级页面要一个「固件下载地址」，或者交换机要把配置文件
// 拉回去。这时候要么去翻 U 盘、要么临时装个第三方服务（那些服务默认能写、
// 默认绑 0.0.0.0、默认把整个盘端出来）。这里只做三件事：只读、只绑指定的
// 那几个地址、只开指定的那一个目录。
//
// ★ 这个包里**不留任何写路径**：HTTP 只接 GET/HEAD（不收 PUT/POST），
//
//	TFTP 只处理 RRQ（不处理 WRQ），FTP 不许 STOR/APPE/MKD/RNM。
//	「能让局域网里任何设备往本机写文件」和「让任何设备读一个固件目录」
//	不是一个量级的风险，而这两件事在现场经常被当成同一个功能。
//
// 凭据：无。不鉴权 = 这个目录里的一切对同一网段可见 —— 所以每一次启动都要
// 有人点头，并且把「谁能读到什么」写进批准说明里。
package filesrv

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNoAddr 一个可绑的地址都没有：宁可当场失败，也不悄悄退回 0.0.0.0。
var ErrNoAddr = errors.New("没有可绑定的地址")

// Config 一次启动的参数。地址列表由调用方（工具层）算好，这里不猜网卡。
type Config struct {
	Root    string // 绝对路径，已确认是目录
	Addrs   []string
	Port    int
	Listing bool // 目录列表开不开

	// TFTP 是给**只认 tftp 的那批老设备**的：它们的固件页面连不上 http。
	// ★ 默认关着：多开一个口就是多一处对外可见面，而多数设备用不到它。
	//   真要用时端口一般填 69（要更高权限），起不来会照 bindErr 那句直说是要权限还是要换号。
	TFTP     bool
	TFTPPort int
}

// Transfer 一次取文件：谁取的、取了什么、多少字节、什么时候、成没成。
//
// ★ 现场要的就是这一列。「设备说下载失败」——到底有没有来取过、
// 取到第几个字节断的，看这里就知道，不用再猜是网的问题还是固件的问题。
type Transfer struct {
	At     time.Time `json:"at"`
	Peer   string    `json:"peer"`
	Proto  string    `json:"proto"` // http / tftp / ftp
	Path   string    `json:"path"`
	Bytes  int64     `json:"bytes"`
	Status string    `json:"status"` // ok / partial / denied / not-found
}

// Status 当前状态。没在跑时 Running=false，其他字段照样给（界面统一渲染）。
type Status struct {
	Running  bool     `json:"running"`
	Root     string   `json:"root,omitempty"`
	AddrInfo []string `json:"addrInfo,omitempty"`
	URLs     []string `json:"urls,omitempty"`
	// TFTPURLs 只在开了 TFTP 时给：设备那一栏填的是 tftp://…，
	// 和 http 那几条一起摆出来，人才不会把两种地址抄混。
	TFTPURLs []string `json:"tftpUrls,omitempty"`
	Port     int      `json:"port"` // 实际在听的号（填 0 让系统挑时只有这里说得清）
	// TFTPPort 只在开了 TFTP 时非 0：设备里那行地址要照着它写，别嘴上说 69 而实际不是。
	TFTPPort int   `json:"tftpPort,omitempty"`
	TFTP     bool  `json:"tftp"`
	Listing  bool  `json:"listing"` // 目录列表开没开：刷新一次状态也要看得见这一栏
	Requests int64 `json:"requests"`
	Bytes    int64 `json:"bytes"`
	Denied   int64 `json:"denied"`
	// NotFound 单独一个数，不并进 Denied：
	// ★ 文件名写错在现场是常态，把它算进「被拒」会让一个干净的共享看着像被攻击过，
	//   而真正该警惕的那一类（有人 POST 上传、想翻出目录）就被这个数埋掉了。
	NotFound int64      `json:"notFound"`
	Since    *time.Time `json:"since,omitempty"`
	Recent   []Transfer `json:"recent"`
}

// Server 运行中的服务。
type Server struct {
	cfg  Config
	lns  []net.Listener
	srvs []*http.Server

	// rootReal 是根目录把符号链接走完之后那个路径。
	// ★ 必须一开始就定下来：macOS 上 /tmp 是 /private/tmp 的链接，而每个请求
	//   resolve 出来的是链接后的真身 —— 拿没解开的 cfg.Root 去比，根目录这一层
	//   永远「不相等」，目录页标题就成了 ../../private/tmp/xxx 那种没人看得懂的东西。
	rootReal string

	// tfts 是每个地址上一个 UDP 监听口（TFTP）。和 HTTP 一样一地址一个口：
	// 共用一个通配口就等于绕开「按网卡挑地址」这条线。
	tfts []*tftpListener

	mu       sync.Mutex
	active   int // 在传的 TFTP 笔数，见 tftpMaxActive
	since    time.Time
	reqs     int64
	bytes    int64
	denied   int64
	notfound int64
	recent   []Transfer
	closed   bool
}

// Start 在每一个给定地址上各起一个监听器。
//
// ★ 一个地址一个监听器，不绑通配：绑 0.0.0.0 会让这块固件目录从**所有**网卡上可见，
// 包括那台机器连着的办公网甚至公网口。地址由调用方按网卡现算，这里只做。
func Start(cfg Config) (*Server, error) {
	if cfg.Root == "" {
		return nil, errors.New("没给目录")
	}
	fi, err := os.Stat(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("打不开这个目录：%s", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s 不是目录", cfg.Root)
	}
	if len(cfg.Addrs) == 0 {
		return nil, ErrNoAddr
	}
	// Port==0 是「让系统挑一个空 port」，给测试和「这台机器上 8080 已经被占了」
	// 那种现场用；挑中了几号必须从监听器上读回来（见下面 realPort），
	// 不然界面上会显示 http://ip:0/ 那种没人能用的地址。
	if cfg.Port < 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("端口 %d 不对，要 0（自动挑）到 65535", cfg.Port)
	}

	s := &Server{cfg: cfg, since: time.Now()}
	root, err := filepathAbs(cfg.Root)
	if err != nil {
		return nil, err
	}
	s.rootReal = root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		s.rootReal = r // 解不开就用没解开的：下面 inside 那道检查照样拦得住越界
	}
	s.cfg.Root = root
	h := s.handler()

	var started []net.Listener
	for _, a := range cfg.Addrs {
		// 用 s.cfg.Port 而不是 cfg.Port：填 0（让系统挑）时，第一块网卡上拿到
		// 真实端口后，剩下几块必须绑**同一个号** —— 否则同一个共享在两块网卡上
		// 是两个端口，设备照着界面里那条 URL 去下载，换块口就失败。
		ln, err := net.Listen("tcp", net.JoinHostPort(a, fmt.Sprint(s.cfg.Port)))
		if err != nil {
			s.stopListeners(started)
			// ★ 端口被占和地址不能绑要分开报：前者是「换个端口」，
			//   后者是「这个地址本机没有，你是不是想开在别块网卡上」。
			return nil, bindErr("http", a, s.cfg.Port, err)
		}
		started = append(started, ln)
		if s.cfg.Port == 0 {
			// 把系统挑中的那个号记回来，URL、状态、批准说明全用这个
			if _, port, err := net.SplitHostPort(ln.Addr().String()); err == nil {
				if n, cerr := strconv.Atoi(port); cerr == nil {
					s.cfg.Port = n
				}
			}
		}
	}
	s.lns = started
	for _, ln := range started {
		hv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
		s.srvs = append(s.srvs, hv)
		go func(srv *http.Server, ln net.Listener) { _ = srv.Serve(ln) }(hv, ln)
	}

	if cfg.TFTP {
		// ★ TFTP 起不来要**整个回滚**，不许留一个只开了 http 的共享：
		//   批准说明里写的是两种协议，人点头的是那个整体，留下半个比全起不来更坏。
		ts, terr := s.startTFTP()
		if terr != nil {
			s.Stop()
			return nil, terr
		}
		s.tfts = ts
	}
	return s, nil
}

// startTFTP 在每个地址上各起一个 UDP 监听口。
func (s *Server) startTFTP() ([]*tftpListener, error) {
	var out []*tftpListener
	for _, a := range s.cfg.Addrs {
		// ★ 用 ResolveUDPAddr 而不是 ParseIP：带区的地址（fe80::1%en0 这种链路本地，
		//   交换机管理口常用）ParseIP 会解成 nil，而 nil 在 ListenUDP 里是**绑所有网卡** ——
		//   一个「只开管理口」的共享就这么从别的口也漏出去了。
		ua, err := net.ResolveUDPAddr(tftpFamily(a), net.JoinHostPort(strings.Trim(a, "[]"), strconv.Itoa(s.cfg.TFTPPort)))
		if err != nil {
			return nil, fmt.Errorf("这个地址本机没有：%s（%v）", a, err)
		}
		pc, err := net.ListenUDP(tftpFamily(a), ua)
		if err != nil {
			for _, l := range out {
				_ = l.pc.Close()
			}
			return nil, bindErr("tftp", a, s.cfg.TFTPPort, err)
		}
		// 系统挑中几号要读回来（填 69 以下时现场最常见就是「这台机器上这个号被占了 / 要权限」）
		if s.cfg.TFTPPort == 0 {
			s.cfg.TFTPPort = pc.LocalAddr().(*net.UDPAddr).Port
		}
		ln := &tftpListener{pc: pc, done: make(chan struct{})}
		out = append(out, ln)
		go s.serveTFTP(ln)
	}
	return out, nil
}

// tftpFamily 按地址自己判断用哪个 socket 族：v6 地址给 udp6，其余 udp4。
// ★ 不能用一个双栈口收两族的请求 —— 那样 v4 来的请求，回话的源地址就说不清了。
func tftpFamily(addr string) string {
	if strings.Contains(addr, ":") {
		return "udp6"
	}
	return "udp4"
}

// TFTPURLs 每个地址一条 tftp 地址（设备固件页面里那一栏要的就是这个形状）。
func (s *Server) TFTPURLs() []string {
	if !s.cfg.TFTP {
		return nil
	}
	var u []string
	for _, a := range s.cfg.Addrs {
		if strings.Contains(a, ":") {
			u = append(u, fmt.Sprintf("tftp://[%s]:%d/", a, s.cfg.TFTPPort))
		} else {
			u = append(u, fmt.Sprintf("tftp://%s:%d/", a, s.cfg.TFTPPort))
		}
	}
	sort.Strings(u)
	return u
}

func (s *Server) stopListeners(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// Stop 关掉监听器并断开还在传的连接。
func (s *Server) Stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	srvs, lns, tfts := s.srvs, s.lns, s.tfts
	s.mu.Unlock()
	for _, l := range tfts {
		close(l.done)
		_ = l.pc.Close() // 正在传的那一发也一起断：Close 之后它的读一定报错
	}
	for _, hv := range srvs {
		_ = hv.Close() // Close 而不是 Shutdown：固件传到一半不用等它传完
	}
	s.stopListeners(lns)
}

// Port 实际在听的端口（0 表示还没起来）。界面和账都要用它，不让调用方自己记。
func (s *Server) Port() int { return s.cfg.Port }

// URLs 每个地址一条可贴的下载地址。
func (s *Server) URLs() []string {
	var u []string
	for _, a := range s.cfg.Addrs {
		if strings.Contains(a, ":") { // v6：URL 里必须带方括号，不然端口分隔符歧义
			u = append(u, fmt.Sprintf("http://[%s]:%d/", a, s.cfg.Port))
		} else {
			u = append(u, fmt.Sprintf("http://%s:%d/", a, s.cfg.Port))
		}
	}
	sort.Strings(u)
	return u
}

// Record 记一笔传输。测试和三种协议都走这里，字段含义只有一处。
func (s *Server) Record(t Transfer) {
	if t.At.IsZero() {
		t.At = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch t.Status {
	case "denied":
		s.denied++
	case "not-found":
		s.notfound++
	default:
		s.reqs++
		s.bytes += t.Bytes
	}
	s.recent = append(s.recent, t)
	if len(s.recent) > 50 { // 只留最近 50 笔：这是给现场看的，不是日志归档
		s.recent = s.recent[len(s.recent)-50:]
	}
}

// Status 当前快照。
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := make([]Transfer, len(s.recent))
	copy(rec, s.recent)
	// 倒着给：最新那一笔才是人第一眼要的（「它刚刚来取过，取到一半断了」）
	for i, j := 0, len(rec)-1; i < j; i, j = i+1, j-1 {
		rec[i], rec[j] = rec[j], rec[i]
	}
	return Status{
		Running:  !s.closed,
		Root:     s.cfg.Root,
		Port:     s.cfg.Port,
		TFTPPort: s.cfg.TFTPPort,
		TFTP:     s.cfg.TFTP,
		Listing:  s.cfg.Listing,
		AddrInfo: append([]string(nil), s.cfg.Addrs...),
		URLs:     s.URLs(),
		TFTPURLs: s.TFTPURLs(),
		Requests: s.reqs,
		Bytes:    s.bytes,
		Denied:   s.denied,
		NotFound: s.notfound,
		Since:    &s.since,
		Recent:   rec,
	}
}

// IdleStatus 没在跑的时候给界面渲染用。
func IdleStatus() Status { return Status{Recent: []Transfer{}} }

func filepathAbs(p string) (string, error) {
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(p), nil
}

// bindErr 把「绑不上」分成现场要区别对待的三类。
func bindErr(proto, addr string, port int, err error) error {
	var ose *os.PathError
	perm := errors.As(err, &ose) && strings.Contains(ose.Err.Error(), "permission")
	switch {
	case perm && proto == "tftp":
		// ★ 这一句要按 tftp 的现场来给：设备的 tftp 栏很多**写死了 69**，
		//   「换个端口」对它没用，能做的只有用管理员权限把本程序起起来。
		return fmt.Errorf("%s:%d 绑不上：tftp 的 69 口要更高权限（1024 以下）。"+
			"设备的地址栏能填端口就换一个；只能认 69 的话，要用管理员权限启动本程序", addr, port)
	case perm:
		return fmt.Errorf("%s:%d 绑不上：这个端口要更高权限（1024 以下）。换个端口，比如 8080", addr, port)
	case strings.Contains(err.Error(), "address already in use"):
		return fmt.Errorf("%s:%d 已经被别的服务占了：换个端口，或者用「本机端口占用」那张卡先看是谁占着", addr, port)
	// macOS/BSD 这句写的是 can't assign requested address，Linux 是 cannot assign...：
	// 只匹配一种的话，Mac 上这条会掉到最笼统的那句去，人就跑去查端口了。
	case strings.Contains(err.Error(), "assign requested address"):
		return fmt.Errorf("本机没有 %s 这个地址（网卡刚换过 / 地址掉了？重新读一次网卡列表再试）", addr)
	}
	return fmt.Errorf("%s:%d 绑不上：%s", addr, port, err)
}
