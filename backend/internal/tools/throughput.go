package tools

// ── net.throughput.serve / .status / .stop / .test ──
//
// 局域网两点对测：一台开一个对测口，另一台连过去打一轮流，问「这两台之间此刻能吃下多少」。
//
// ★★ 为什么这一张要 mutate + 点头，两头都要：
//
//	开那半句改的是**这台机器对外的可见面** —— 口一开，同一网段任何机器连上来都能让它
//	收发字节。这个协议不鉴权（鉴权就得存凭据，而现场是两台临时凑起来的机器），
//	拦住它的是「一路最多多少字节 + 同时几路 + 每路活多久」这三道闸，
//	所以**闸开在哪个口、开到多大**必须有人看一眼再放行，并记一笔账。
//
//	测那半句改的是**这条链路**：一秒的满速流量足以把现场正在跑的摄像头、
//	PLC 的轮询挤掉。没人批准就往一台活着的设备上打流，是我们自己变成事故。
//
// ★ 为什么按网卡绑地址、绝不 0.0.0.0：多网卡工控机上另一块口连着办公网甚至公网，
//   绑法一错就等于把对测口开到那边去（和文件共享同一条线，理由同源）。
//
// 凭据：这套协议没有凭据这一说，结果里也就没有东西可泄漏。带出去的是地址、端口、
// 字节数、曲线和内核那本账 —— 对端 IP 会带上（这是「谁连过」的唯一线索，删了就白记）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/throughput"
)

// 口那三问的判定。
const (
	verdictThruServing = "thru-serving"
	verdictThruIdle    = "thru-idle"
	verdictThruStopped = "thru-stopped"
)

// 测那一问的判定。★ 每一档都得是「下一步动作不一样」的两件事，不然不该单开一档。
const (
	verdictThruOK            = "thru-ok"             // 数拿到了，也稳
	verdictThruLoopback      = "thru-loopback"       // 对端就是本机：量的是这台机器的协议栈，不是链路
	verdictThruBufferbloat   = "thru-bufferbloat"    // 吞吐上得去而带载往返涨了几倍：中间那台在囤包
	verdictThruUnstable      = "thru-unstable"       // 平均值好看但一阵一阵：曲线自己会说话
	verdictThruWindowLimited = "thru-window-limited" // 卡的不是线，是这一条连接的窗口（cwnd/rtt 就这么多）
	verdictThruTruncated     = "thru-truncated"      // 跑够之前先撞上了对面的字节闸
	verdictThruDropped       = "thru-dropped"        // 两端数到的字节对不上：这一路在吞数据
	verdictThruBusy          = "thru-busy"           // 对面的口满着
	verdictThruProto         = "thru-proto"          // 端口配错 / 那台上跑的是别的服务
	verdictThruClosed        = "thru-closed"         // 明确拒绝：那台机器活着，只是没开对测口
	verdictThruFiltered      = "thru-filtered"       // 一句不答：防火墙静默丢包，连机器在不在都不知道
	verdictThruTimeout       = "thru-timeout"        // 连上了、话问到一半超时
)

const (
	thruDefaultPort = 5201 // 和 iperf 同号是故意的：现场记住的往往是这一个
	thruDefaultSecs = 3

	thruMinPort   = 1
	thruMaxPort   = 65535
	thruMinSecs   = 1
	thruMaxSecs   = 10
	thruMinBytes  = int64(1) << 20
	thruMaxBytes  = int64(16) << 30
	thruMinSess   = 1
	thruMaxSess   = 8
	thruDialTo    = 5 * time.Second
	thruTestGrace = 25 * time.Second // 两向 + 空载往返 + 等对面那句账的余量
)

// 三个读取口走变量：测试因此不必真有一块网卡，也不必看这台机器的地址。
var (
	thruNICs = netif.Interfaces
	// thruLocalAddrs 是「这几个地址就是本机」。★ 判 loopback 靠它，
	// 而测试要能把 thru-ok 那条路跑出来（同机两端拿不到「对端是别人」的事实）。
	thruLocalAddrs = localAddrStrings
)

// thru 当前在跑的对测口。全场只允许一个，和文件共享同一个理由：
// 界面上要让人分清「停的是哪个口」，两个口在现场一定出错。
var thru = struct {
	mu      sync.Mutex
	srv     *throughput.Server
	entryID string
	plan    throughputPlan
}{mu: sync.Mutex{}}

type throughputArgs struct {
	Iface       string   `json:"iface,omitempty"`
	Addrs       []string `json:"addrs,omitempty"`
	Port        int      `json:"port,omitempty"`
	MaxBytes    int64    `json:"maxBytes,omitempty"`
	MaxSessions int      `json:"maxSessions,omitempty"`
}

type throughputTestArgs struct {
	Host    string `json:"host"`
	Port    int    `json:"port,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Seconds int    `json:"seconds,omitempty"`
}

var throughputServeTool = ots.Tool{
	Name:  "net.throughput.serve",
	Class: ots.ClassMutate,
	Summary: "在本机开一个**局域网对测口**，让另一台 NetKit 连过来量「这两台之间此刻能吃下多少」" +
		"（配套的 net.throughput.test 在另一台上跑）。\n" +
		"★ 只讲这一套自研的对测协议，不做通用服务：不是 iperf3，不鉴权，也不听任何别的请求 —— " +
		"回的不是这套协议的第一句就被拒掉。\n" +
		"★ 只绑指定网卡上的地址，绝不绑 0.0.0.0：多网卡机器上那等于把对测口从办公网/公网那块口也开出去。\n" +
		"不填 iface 就按 IPv4 默认路由那块网卡挑，挑中了会在结果里说清是哪块、哪些地址、哪个端口。\n" +
		"三道闸拦的是「有人连上就不停手」：一路最多 maxBytes（默认 16 GiB，够万兆跑满十秒）、" +
		"同时最多 maxSessions 路（默认 4）、每路最长 5 分钟。用完请调 net.throughput.stop 停掉。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "iface": {"type": "string", "description": "开在哪块网卡（en0 / eth0 / WLAN）。不填按 IPv4 默认路由那块；只有本机一块可用网卡时用它。"},
	    "addrs": {"type": "array", "items": {"type": "string"},
	      "description": "直接指定绑哪些地址（覆盖 iface）。★ 不接受 0.0.0.0 / :: —— 那是要绕开按网卡挑地址这条线，请改成填 iface。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "对测端口，默认 5201。两端必须是同一个号，对面填地址时要对着它。1024 以下要更高权限，起不来会直说。"},
	    "maxBytes": {"type": "integer", "description": "一路会话最多收发多少字节，默认 16 GiB，允许 1 MiB–16 GiB。★ 这是闸不是目标：设太小会把一条健康的万兆链路判成「被对面截了」。"},
	    "maxSessions": {"type": "integer", "minimum": 1, "maximum": 8, "description": "同时接几路，默认 4。满了再来直接回「口满」，不排队不超时。"}
	  }
	}`),
	Describe: describeThroughputServe,
	Invoke:   serveThroughput,
}

var throughputStatusTool = ots.Tool{
	Name:  "net.throughput.status",
	Class: ots.ClassRead,
	Summary: "看本机现在有没有开着对测口：开在哪块网卡的哪几个地址哪个端口、" +
		"闸开在多大、此刻在跑第几路、以及**最近跑过哪几路**（含跑砸的那些：谁连的、要了多少、为什么断）。\n" +
		"★ 排查「另一台说连不上/连上就断」就看这一张：有没有人来过、它要了多少、我们这侧数到多少。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: statusThroughput,
}

var throughputStopTool = ots.Tool{
	Name:    "net.throughput.stop",
	Class:   ots.ClassMutate,
	Summary: "停掉本机的对测口。停了之后对面连上来就是「明确拒绝」。已经跑完的那些账还在最近记录里。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string {
		return "停掉本机的局域网对测口（同网段不再能连过来打流）"
	},
	Invoke: stopThroughput,
}

var throughputTestTool = ots.Tool{
	Name:  "net.throughput.test",
	Class: ots.ClassMutate,
	Summary: "连到另一台的 NetKit 对测口，量「这两台之间此刻能吃下多少」，TCP，只测这一套协议。\n" +
		"一次带回四样东西，缺一样这句「多少」就不完整：\n" +
		"  · 每 200 毫秒一个点的曲线（平均值会骗人：稳定 900M 和 1800M/0 交替，平均值一模一样）\n" +
		"  · 空载往返与带载往返**分两条线量**（复用正在传数据的那条量不出缓冲膨胀 —— 那 8 个字节排在几万个字节后面）\n" +
		"  · 发送侧与接收侧各一份耗时和字节数（差得远就是数据堆在本机发送缓冲里，链路其实没吃下那么多）\n" +
		"  · 内核自己那本账：往返估计、重传计数、拥塞窗口（macOS/Linux 取得到；取不到的字段明说「这台给不了」，不拿 0 冒充）\n" +
		"mode：up 是本机往外打、down 是收、both 两向各跑一轮。seconds 允许 1–10。\n" +
		"★ 这一发会占满这条链路几秒钟：现场正跑着摄像头、PLC 轮询的时候别打，所以它要人点头。" +
		"对端地址是本机的话会单独判成 thru-loopback —— 那个数量的是这台机器的协议栈，不是链路。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["host"],
	  "properties": {
	    "host": {"type": "string", "description": "对面那台的地址（就是 net.throughput.serve 报出来的那几个地址之一）。也接受 host:port 的写法。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "对面的对测端口，默认 5201。host 里已经写了端口就以 host 为准。"},
	    "mode": {"type": "string", "enum": ["up", "down", "both"], "description": "up 本机往外打 / down 本机收 / both 两向各一轮。默认 both。"},
	    "seconds": {"type": "integer", "minimum": 1, "maximum": 10, "description": "每个方向跑多久，默认 3 秒，允许 1–10。想看稳态给 5 秒以上；短于 1 秒问不出稳态，所以不接。"}
	  }
	}`),
	Describe: describeThroughputTest,
	Invoke:   testThroughput,
}

// ── 批准说明 [OTS-7.2] ──

// describeThroughputServe 要把**会改成什么**说到人能拍板：开在哪块口、绑哪几个地址、
// 闸开在多大。★ 和文件共享同一条理由：批准的人只看到「开对测口」四个字，
// 他其实不知道自己是同意了「同网段任何机器都能让这台机器收发字节」。
func describeThroughputServe(raw json.RawMessage) string {
	var a throughputArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	p, err := planThroughputServe(a)
	s := fmt.Sprintf("在本机开局域网对测口，端口 %d", p.port)
	switch {
	case err != nil:
		s += fmt.Sprintf("；网卡没定下来：%s", err)
	case p.iface == "":
		s += "；绑在这些地址上：" + strings.Join(p.addrs, "、")
	default:
		s += fmt.Sprintf("；开在网卡 %s 上（%s），绑 %s", p.iface, p.ifaceWhy, strings.Join(p.addrs, "、"))
	}
	s += fmt.Sprintf("。★ 这个口不鉴权：同网段任何机器连上来都能让它收发数据，"+
		"拦住它的是三道闸 —— 一路最多 %s、同时 %d 路、每路最长 5 分钟", humanSize(p.maxBytes), p.maxSessions)
	return s
}

func describeThroughputTest(raw json.RawMessage) string {
	var a throughputTestArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	mode := a.Mode
	if mode == "" {
		mode = "both"
	}
	secs := a.Seconds
	if secs == 0 {
		secs = thruDefaultSecs
	}
	host, port := a.Host, a.Port
	if h, pstr, err := net.SplitHostPort(a.Host); err == nil {
		host = h
		if n, cerr := atoiPort(pstr); cerr == nil {
			port = n
		}
	}
	if port == 0 {
		port = thruDefaultPort
	}
	dir := map[string]string{"up": "往外打", "down": "收", "both": "往外打 + 收，各一轮"}[mode]
	return fmt.Sprintf("连到 %s:%d 打一轮对测（TCP，%s %d 秒）"+
		"：这一会儿这条链路会被推到接近满，中间正跑着摄像头/轮询控制的那几秒会卡",
		host, port, dir, secs)
}

// ── 参数化成一份可执行的计划（所有夹取都在代码里：Invoke 不查 schema）──

type throughputPlan struct {
	addrs       []string
	iface       string
	ifaceWhy    string
	port        int
	maxBytes    int64
	maxSessions int
}

func atoiPort(s string) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("端口不是数")
		}
		n = n*10 + int(r-'0')
		if n > thruMaxPort {
			return 0, errors.New("端口超出范围")
		}
	}
	return n, nil
}

// clampPort 0 交给默认值。★ 这里**不接受 0 当「让内核挑」**：两端必须报同一个号，
// 内核挑完对面不知道 —— 底座允许 0 只给自己进程里的测试用。
func clampPort(p int) (int, error) {
	if p == 0 {
		return thruDefaultPort, nil
	}
	if p < thruMinPort || p > thruMaxPort {
		return 0, ots.Errf(ots.ErrInvalidArgument,
			"端口只认 %d–%d（0 是「让内核挑一个」，对面拿不到这个号，这里不收）", thruMinPort, thruMaxPort)
	}
	return p, nil
}

func planThroughputServe(a throughputArgs) (throughputPlan, error) {
	var p throughputPlan
	port, err := clampPort(a.Port)
	if err != nil {
		return p, err
	}
	p.port = port
	p.maxBytes = a.MaxBytes
	if p.maxBytes == 0 {
		p.maxBytes = thruMaxBytes
	}
	if p.maxBytes < thruMinBytes || p.maxBytes > thruMaxBytes {
		return p, ots.Errf(ots.ErrInvalidArgument,
			"maxBytes 只认 %s–%s（给 %d）：太小会把健康链路判成「被对面截了」，太大这一口就成了放大器",
			humanSize(thruMinBytes), humanSize(thruMaxBytes), a.MaxBytes)
	}
	p.maxSessions = a.MaxSessions
	if p.maxSessions == 0 {
		p.maxSessions = 4
	}
	if p.maxSessions < thruMinSess || p.maxSessions > thruMaxSess {
		return p, ots.Errf(ots.ErrInvalidArgument, "maxSessions 只认 %d–%d，给的是 %d",
			thruMinSess, thruMaxSess, a.MaxSessions)
	}

	for _, s := range a.Addrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip == nil {
			return p, ots.Errf(ots.ErrInvalidArgument,
				"这个地址看不懂：%q（这一栏要的是 192.168.1.20 这种 IP，不是网卡名）", s)
		} else if ip.IsUnspecified() {
			// ★ 0.0.0.0 / :: 不是「忘了填」，是要绕开按网卡挑地址那一条线：
			//   多网卡机器上那等于把对测口从办公网甚至公网那块口也开出去。
			return p, ots.Errf(ots.ErrInvalidArgument,
				"不接受 %s：那是把对测口从**所有**网卡上开出去。要开在哪块口上，请填 iface", s)
		} else {
			p.addrs = append(p.addrs, s)
		}
	}
	if len(p.addrs) > 0 {
		return p, nil
	}

	nics, err := thruNICs()
	if err != nil {
		return p, ots.Errf(ots.ErrInternal, "读网卡列表失败：%s", err)
	}
	usable := func(n netif.NIC) bool {
		return !n.Loop && !n.Virtual && n.Up && n.Running && len(shareAddrs(n)) > 0
	}
	var pick *netif.NIC
	var names []string
	for i, n := range nics {
		if usable(n) {
			names = append(names, fmt.Sprintf("%s(%s)", n.Name, strings.Join(shareAddrs(n), "+")))
			pick = &nics[i]
		}
	}
	if a.Iface != "" {
		for _, n := range nics {
			if n.Name == a.Iface {
				if !usable(n) {
					return p, ots.Errf(ots.ErrInvalidArgument,
						"网卡 %s 上没有一个能用来对测的地址（没插线、没启用、或者只有链路本地地址）", a.Iface)
				}
				p.iface, p.ifaceWhy = n.Name, "人指定的网卡"
				p.addrs = shareAddrs(n)
				return p, nil
			}
		}
		return p, ots.Errf(ots.ErrInvalidArgument,
			"没有叫 %s 的网卡（本机可用的是 %s）", a.Iface, strings.Join(names, "、"))
	}
	// 默认路由那块优先（和文件共享同一个挑法）：现场对测的常常就是那块口。
	if rs, err := fileshareRoutes(); err == nil {
		for _, r := range rs {
			if r.Family != "ipv4" || r.Iface == "" {
				continue
			}
			for _, n := range nics {
				if n.Name == r.Iface && usable(n) {
					p.iface, p.ifaceWhy = n.Name, "IPv4 默认路由走这块"
					p.addrs = shareAddrs(n)
					return p, nil
				}
			}
		}
	}
	if len(names) == 1 {
		p.iface, p.ifaceWhy = pick.Name, "本机只有一块带可用 IPv4 的网卡"
		p.addrs = shareAddrs(*pick)
		return p, nil
	}
	if len(names) == 0 {
		return p, ots.Errf(ots.ErrInvalidArgument,
			"本机没有一块带可用 IPv4 地址的网卡，对测口开不出去（先看网线，或用 net.interfaces 确认地址）")
	}
	return p, ots.Errf(ots.ErrInvalidArgument,
		"有 %d 块网卡都能开对测口（%s），猜错口就是「对面连得上却慢得离谱」，请填 iface 指定其中一块",
		len(names), strings.Join(names, "、"))
}

// ── 口：开 / 看 / 停 ──

func serveThroughput(ctx context.Context, raw json.RawMessage) (any, error) {
	var a throughputArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	plan, err := planThroughputServe(a)
	if err != nil {
		// 参数不对先说参数：这条错跟账本没关系，掺在一起人就跑去查配置了。
		return nil, err
	}
	if journal == nil {
		// ★ 没有账本就不许改：开这个口记不下来，重启后谁都不知道它开过。
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝开对测口")
	}

	thru.mu.Lock()
	defer thru.mu.Unlock()
	if thru.srv != nil {
		st := thru.srv.Status()
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"已经有一个对测口在跑（%s 端口 %d）。先用 net.throughput.stop 停掉再开新的",
			strings.Join(st.Addrs, "、"), st.Port)
	}
	sweepThruJournal("开新口之前先了结上次那笔")

	srv, err := throughput.Start(throughput.Config{
		Addrs: plan.addrs, Port: plan.port,
		MaxBytes: plan.maxBytes, MaxSessions: plan.maxSessions,
	})
	if err != nil {
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}
	if id, jerr := journal.Register("throughput-serve", describeThroughputServe(raw),
		map[string]any{"serving": false},
		map[string]any{"iface": plan.iface, "addrs": plan.addrs, "port": plan.port,
			"maxBytes": plan.maxBytes, "maxSessions": plan.maxSessions}); jerr == nil {
		_ = journal.MarkApplied(id)
		thru.entryID = id
	}
	thru.srv = srv
	thru.plan = plan

	st := srv.Status()
	vals := map[string]any{
		"serving": true, "iface": plan.iface, "ifaceWhy": plan.ifaceWhy,
		"addrs": st.Addrs, "port": st.Port, "maxBytes": st.MaxBytes,
		"maxSessions": st.MaxSession, "active": st.Active,
		// 开那一刻算好的事实跟着状态走：界面 3 秒刷一次，不能刷一次丢一行。
		"peerHelp": fmt.Sprintf("对面那台填：地址 %s、端口 %d",
			strings.Join(st.Addrs, " 或 "), st.Port),
	}
	note := fmt.Sprintf("对测口已开在 %s 的 %s 端口 %d（一路最多 %s、同时 %d 路）；对面那台用 net.throughput.test 连过来",
		plan.iface, strings.Join(st.Addrs, "、"), st.Port, humanSize(st.MaxBytes), st.MaxSession)
	if plan.iface == "" {
		note = fmt.Sprintf("对测口已开在 %s 端口 %d（一路最多 %s、同时 %d 路）；对面那台用 net.throughput.test 连过来",
			strings.Join(st.Addrs, "、"), st.Port, humanSize(st.MaxBytes), st.MaxSession)
	}
	return ots.Verdict{Code: verdictThruServing, Values: vals, Note: note}, nil
}

func statusThroughput(ctx context.Context, raw json.RawMessage) (any, error) {
	thru.mu.Lock()
	srv, plan := thru.srv, thru.plan
	thru.mu.Unlock()
	if srv == nil {
		sweepThruJournal("看状态时顺手了结上次那笔")
		return ots.Verdict{
			Code: verdictThruIdle,
			Values: map[string]any{"serving": false, "defaultPort": thruDefaultPort,
				"hint": "没在开：对面连过来会得到「明确拒绝」。要用就先调 net.throughput.serve"},
			Note: "本机现在没有开对测口：对面连过来会被明确拒绝。要量就先调 net.throughput.serve",
		}, nil
	}
	st := srv.Status()
	vals := map[string]any{
		"serving": true, "status": st,
		"iface": plan.iface, "ifaceWhy": plan.ifaceWhy,
		"maxBytes": st.MaxBytes, "maxSessions": st.MaxSession,
		// 一共过了多少字节：这一格是「这口被人当炮使了多久」的唯一证据。
		"servedBytes": st.Served, "servedSize": humanSize(st.Served),
		"peerHelp": fmt.Sprintf("对面那台填：地址 %s、端口 %d",
			strings.Join(st.Addrs, " 或 "), st.Port),
	}
	note := fmt.Sprintf("对测口开着：%s 端口 %d，已跑过 %d 路、共 %s",
		strings.Join(st.Addrs, "、"), st.Port, len(st.Recent), humanSize(st.Served))
	if st.Active > 0 {
		note += fmt.Sprintf("；此刻正有第 %d 路在跑", st.Active)
	}
	if n := countThruFault(st.Recent); n > 0 {
		note += fmt.Sprintf("；最近这几路里有 %d 路是跑砸的（各自为什么断，看 recent 那一列）", n)
	}
	return ots.Verdict{Code: verdictThruServing, Values: vals, Note: note}, nil
}

func countThruFault(ss []throughput.Session) int {
	var n int
	for _, s := range ss {
		if s.Fault != "" {
			n++
		}
	}
	return n
}

func stopThroughput(ctx context.Context, raw json.RawMessage) (any, error) {
	thru.mu.Lock()
	defer thru.mu.Unlock()
	if thru.srv == nil {
		sweepThruJournal("停一个本来就没开的口")
		return ots.Verdict{Code: verdictThruIdle, Values: map[string]any{"serving": false,
			"hint": "本机没有在跑的对测口，这一句不是失败：什么都没被改动"},
			Note: "本机没有在跑的对测口"}, nil
	}
	st := thru.srv.Status()
	thru.srv.Stop()
	if journal != nil && thru.entryID != "" {
		_ = journal.MarkReverted(thru.entryID, "用户停掉了对测口")
	}
	thru.srv, thru.entryID, thru.plan = nil, "", throughputPlan{}
	return ots.Verdict{
		Code: verdictThruStopped,
		Values: map[string]any{"serving": false, "addrs": st.Addrs, "port": st.Port,
			"servedBytes": st.Served, "sessions": len(st.Recent),
			// ★ 停口不清账：刚跑砸的那几路正是人停下来要看的，账要跟着这一份结果走，
			//   不能只留在「还开着」的那个状态里 —— 界面按这句话画台账。
			"recent": st.Recent},
		// ★ 要说清放掉了哪几个地址上的哪个口：多网卡时「已经停了」分辨不出
		//   是不是每块口都停了，而现场最怕的正是「以为停了，其实还开着」。
		Note: fmt.Sprintf("对测口已停：%s 端口 %d 不再应答（这中间一共过了 %s）",
			strings.Join(st.Addrs, "、"), st.Port, humanSize(st.Served)),
	}, nil
}

// sweepThruJournal 了结「上次开着对测口」那笔没走完的账。
//
// ★★ 监听器是本进程持有的，进程一退端口就空了 —— **没有任何状态要还原**。
//
//	但这笔账必须了结：挂着不管，下次看账本的人会去查一个早就不存在的口。
//	也不自动重开：那等于人不在场就把一个能收发字节的口开到网上去。
func sweepThruJournal(why string) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind == "throughput-serve" {
			_ = journal.MarkReverted(e.ID, "进程重启后本进程没在开这个口（"+why+"）")
		}
	}
}

// ── 测 ──

func testThroughput(ctx context.Context, raw json.RawMessage) (any, error) {
	var a throughputTestArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	host, port, err := splitTarget(a.Host, a.Port)
	if err != nil {
		return nil, err
	}
	mode := a.Mode
	if mode == "" {
		mode = "both"
	}
	switch mode {
	case "up", "down", "both":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "mode 只认 up / down / both，给的是 %q", a.Mode)
	}
	secs := a.Seconds
	if secs == 0 {
		secs = thruDefaultSecs
	}
	if secs < thruMinSecs || secs > thruMaxSecs {
		// ★ 短于 1 秒问不出稳态（那是一段建连爬坡），却会给出一个看着合理的低数；
		//   长于 10 秒在现场就是把链路按住得太久。两头都挡在门外，不在判定里补一句。
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"seconds 只认 %d–%d（给的是 %d）：这么短的窗口问不出稳态", thruMinSecs, thruMaxSecs, a.Seconds)
	}
	// ★ 这一发会占满这条链路：没有账本就不许动，和开口的理由同源。
	if journal == nil {
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝对测")
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second*2+thruTestGrace)
	defer cancel()
	res, runErr := throughput.Run(runCtx, throughput.Options{
		Host: host, Port: port, Mode: mode, Seconds: secs, Timeout: thruDialTo,
	})

	vals := thruValues(res)
	loop := isLocalTarget(host)
	vals["loopback"] = loop
	if id, jerr := journal.Register("throughput-test", describeThroughputTest(raw),
		map[string]any{}, map[string]any{"addr": res.Addr, "mode": mode, "seconds": secs}); jerr == nil {
		_ = journal.MarkApplied(id)
	}

	if runErr != nil {
		if code, note := faultCode(runErr, res.Addr); code != "" {
			vals["fault"] = runErr.Error()
			return ots.Verdict{Code: code, Values: vals, Note: note}, nil
		}
		vals["fault"] = runErr.Error()
		return ots.Unknown(vals), nil
	}
	code, note := measureCode(res, loop)
	vals["verdictReason"] = note
	return ots.Verdict{Code: code, Values: vals, Note: note}, nil
}

// splitTarget 认 192.168.1.20、192.168.1.20:5201、[fe80::1%en0]:5201 三种写法。
//
// ★ 现场抄的就是这三种，多问一步「端口填哪一栏」就是这里没接住。
func splitTarget(h string, port int) (string, int, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", 0, ots.Errf(ots.ErrInvalidArgument, "没给对面地址")
	}
	// ★ 一律交给 net.SplitHostPort 判：它认 v6 的方括号和 %en0 的 zone。
	// 自己数字符串切的话，「fe80::1%en0:5201」这种一定会切错地方。
	if host, pstr, err := net.SplitHostPort(h); err == nil {
		p, perr := atoiPort(pstr)
		if perr != nil {
			return "", 0, ots.Errf(ots.ErrInvalidArgument, "地址里那个端口不对：%s", perr)
		}
		if port != 0 && port != p {
			return "", 0, ots.Errf(ots.ErrInvalidArgument,
				"host 里写了 %d，port 又填了 %d：这两个得是同一个数", p, port)
		}
		return strings.Trim(host, "[]"), p, nil
	}
	p, err := clampPort(port)
	if err != nil {
		return "", 0, err
	}
	if net.ParseIP(h) == nil {
		// 带 zone 的 v6 写法（fe80::1%en0）ParseIP 不认，交给 netip 判。
		if _, err := netip.ParseAddr(h); err != nil {
			// 主机名也接：很多现场抄的是 DNS 名。认不出来不直接拒 —— 交给 dial 去报
			// 「解析不到」那句，那一句话里带的是真实的 DNS 毛病。
			if !strings.Contains(h, ".") && !strings.Contains(h, "-") {
				return "", 0, ots.Errf(ots.ErrInvalidArgument,
					"这既不是一个 IP 也不像个主机名：%q", h)
			}
		}
	}
	return h, p, nil
}

func thruValues(res throughput.Result) map[string]any {
	v := map[string]any{
		"addr": res.Addr, "mode": res.Mode, "seconds": res.Seconds,
		"peerMaxBytes": res.PeerMaxBytes,
		"peerMaxSize":  humanSize(res.PeerMaxBytes),
	}
	if res.Up != nil {
		v["up"] = dirValues(*res.Up)
	}
	if res.Down != nil {
		v["down"] = dirValues(*res.Down)
	}
	v["idle"] = res.Idle
	v["loaded"] = res.Loaded
	return v
}

func dirValues(d throughput.Direction) map[string]any {
	out := map[string]any{
		"bytes": d.Bytes, "size": humanSize(d.Bytes),
		"elapsedMs": d.ElapsedMs, "mbps": d.MBps,
		"peerBytes": d.PeerBytes, "peerSize": humanSize(d.PeerBytes),
		"peerElapsedMs": d.PeerMs, "peerMBps": mbpsOf(d.PeerBytes, d.PeerMs),
		"truncated": d.Truncated, "samples": d.Samples,
		"tcp": d.TCP,
	}
	if d.Fault != "" {
		out["fault"] = d.Fault
	}
	if ceil, ok := d.TCP.CeilingMbps(); ok {
		out["ceilingMbps"] = ceil
	}
	if d.TCP.Source != "" {
		out["tcpSource"] = d.TCP.Source
	} else {
		out["tcpWhy"] = d.TCP.Why
	}
	return out
}

func mbpsOf(bytes int64, ms int64) float64 {
	if ms <= 0 || bytes <= 0 {
		return 0
	}
	return float64(int64(float64(bytes)*8/(float64(ms)/1000)/1e6*10+0.5)) / 10
}

// faultCode 把「这一趟没跑成」归到判定档。★ closed 与 filtered 必须分开：
// 前者说明那台机器活着、只是没开对测口（去那台上开一下就行），
// 后者连机器在不在都不知道（要先去查防火墙/路由，而不是去重启那台）。
func faultCode(err error, addr string) (string, string) {
	var te *throughput.Error
	if !errors.As(err, &te) {
		return "", ""
	}
	switch te.Kind {
	case "busy":
		return verdictThruBusy, fmt.Sprintf(
			"%s 连上了，可它的对测口同时跑的路数已经满了：那边要么等几秒再问，要么去把没在用的会话停掉", addr)
	case "proto":
		return verdictThruProto, fmt.Sprintf(
			"%s 这个端口上回的不是 NetKit 的对测协议 —— 多半是端口填错，或者那台跑着别的服务（iperf3 也是这一格）", addr)
	case "timeout":
		return verdictThruFiltered, fmt.Sprintf(
			"%s 一句都不答：这不是「端口没开」，是包在路上就被静默丢掉了，先去查中间那道防火墙", addr)
	case "dial":
		switch classify(err) {
		case verdictClosed:
			return verdictThruClosed, fmt.Sprintf(
				"%s 明确拒绝：那台机器活着，只是没开对测口 —— 在那台上跑一次 net.throughput.serve 再问", addr)
		case verdictFiltered:
			return verdictThruFiltered, fmt.Sprintf(
				"%s 没有任何响应：多半是防火墙静默丢包", addr)
		}
		return "", ""
	case "handshake", "io":
		return verdictThruTimeout, fmt.Sprintf("%s 连上了，问到一半超时：%s", addr, te.Err)
	}
	return "", ""
}

// thruDir 把一个方向的账和它的中文方向名捆在一起：判定句子、界面表头、
// 以及「哪一段忽快忽慢」都用这同一个词，不各自再拼一遍。
type thruDir struct {
	word string
	d    *throughput.Direction
}

func thruDirs(res throughput.Result) []thruDir {
	var out []thruDir
	if res.Up != nil {
		out = append(out, thruDir{"往外打", res.Up})
	}
	if res.Down != nil {
		out = append(out, thruDir{"收", res.Down})
	}
	return out
}

// measureCode 从两向的账里挑一个判定。★ 顺序就是证据的顺序：先问「这个数能不能信」，
// 再问「这个数说明什么」。反过来的话，两端字节对不上账的那种一路会被读成「慢」，
// 而真相是「在吞数据」——下一步完全不同。
//
// 「对端就是本机」排在最前：那一发量到的数整本都不作数，
// 它顺带撞没撞上字节闸都无所谓 —— 先说这一句，人才不会拿它去说链路。
func measureCode(res throughput.Result, loop bool) (string, string) {
	dirs := thruDirs(res)
	var acc []string
	for _, x := range dirs {
		d := x.d
		acc = append(acc, fmt.Sprintf("%s %s Mbps（%s，本机侧 %d ms，对面 %d ms）",
			x.word, trimZero(d.MBps), humanSize(d.Bytes), d.ElapsedMs, d.PeerMs))
	}
	base := strings.Join(acc, "；")
	if base == "" {
		// 两向都没跑成：没有一本账可判，交回 unknown 让上面带证据说话。
		return "", ""
	}
	if loop {
		return verdictThruLoopback, fmt.Sprintf(
			"%s；★ 这个地址就是本机：量到的数是这台机器的协议栈，不是任何一段链路。"+
				"要量现场那条路，得在**另一台**上开对测口", base)
	}
	for _, x := range dirs {
		d := x.d
		if d.PeerBytes > 0 && d.PeerBytes != d.Bytes {
			// ★ 「对不上账」优先于其余数值判读：账都不可信的时候谈快慢没有意义。
			return verdictThruDropped, fmt.Sprintf(
				"%s —— 但这一路的账对不上：%s这侧数到 %d 字节，对面那侧只有 %d 字节。"+
					"先别管快慢，这一条链路在吞数据", base, x.word,
				maxInt64(d.Bytes, d.PeerBytes), minInt64(d.Bytes, d.PeerBytes))
		}
	}

	for _, x := range dirs {
		if x.d.Truncated {
			return verdictThruTruncated, fmt.Sprintf(
				"%s；★ %s这一路是被对面的字节闸截掉的（它回执里就写了最多给 %s），"+
					"不是链路只能跑这么多 —— 要看真数就在那台上把 maxBytes 放大再问",
				base, x.word, humanSize(res.PeerMaxBytes))
		}
	}
	// 带载往返只在「空载也量到了」的前提下才可比：少了对照，涨了多少无从谈起。
	if res.Idle.Count > 0 && res.Loaded.Count > 0 && res.Idle.AvgMs > 0 {
		ratio := res.Loaded.AvgMs / res.Idle.AvgMs
		if res.Loaded.AvgMs >= res.Idle.AvgMs+20 && ratio >= 3 {
			return verdictThruBufferbloat, fmt.Sprintf(
				"%s；★ 吞吐上得去，可往返从空载 %s ms 涨到带载 %s ms（%.1f 倍）—— "+
					"中间那台的队列在囤包：带宽看着够，画面和轮询就是卡。去查路上那台的队列/限速",
				base, trimZero(res.Idle.AvgMs), trimZero(res.Loaded.AvgMs), ratio)
		}
	}
	if code, note := unstableCode(dirs, base); code != "" {
		return code, note
	}
	for _, x := range dirs {
		if ceil, ok := x.d.TCP.CeilingMbps(); ok && x.d.MBps >= 0.9*ceil {
			return verdictThruWindowLimited, fmt.Sprintf(
				"%s；★ 这个数顶到了**这一条连接自己**的天花板：按内核报的窗口 %s 和往返 %s ms 算，"+
					"单条 TCP 最多就跑 %s Mbps —— 换多路并发再量才有更高的数，不是链路上不去",
				base, humanSize(x.d.TCP.SndCwndBytes), trimZero(x.d.TCP.SrttMs), trimZero(ceil))
		}
	}
	return verdictThruOK, fmt.Sprintf("%s；空载往返 %s，带载往返 %s，曲线 %s",
		base, rttWord(res.Idle), rttWord(res.Loaded), samplesWord(dirs))
}

// unstableCode 认「平均值好看，其实一阵一阵」。★ 只看极差比与有没有断流，
// 不去拟合什么趋势 —— 趋势这种词在这里既说不出下一步该动什么，也数不清。
func unstableCode(dirs []thruDir, base string) (string, string) {
	for _, x := range dirs {
		if len(x.d.Samples) < 3 {
			continue
		}
		var hi, lo, zero float64
		for _, s := range x.d.Samples {
			if s.MBps > hi {
				hi = s.MBps
			}
			if lo == 0 || s.MBps < lo {
				lo = s.MBps
			}
			if s.MBps == 0 {
				zero++
			}
		}
		if zero >= 2 {
			return verdictThruUnstable, fmt.Sprintf(
				"%s；★ %s那一段里有 %d 个 200 毫秒完全没动 —— 不是一直慢，是一阵一阵。"+
					"平均数把这个藏住了，看曲线那一条线才看得出来", base, x.word, int(zero))
		}
		if lo > 0 && hi >= 3*lo {
			return verdictThruUnstable, fmt.Sprintf(
				"%s；★ %s那一段忽快忽慢：最快 %s Mbps、最慢 %s Mbps（差 %.1f 倍）。"+
					"平均值看着正常，这种形状多半是有人在抢这一条路或者无线在重传",
				base, x.word, trimZero(hi), trimZero(lo), hi/lo)
		}
	}
	return "", ""
}

func samplesWord(dirs []thruDir) string {
	for _, x := range dirs {
		if len(x.d.Samples) > 0 {
			return fmt.Sprintf("一共 %d 个点", len(x.d.Samples))
		}
	}
	return "一个点都没取到"
}

func rttWord(r throughput.RTT) string {
	if r.Count == 0 {
		// ★ 「没问到」不许写成 0 ms：那是两件完全不同的事
		return "没问到"
	}
	return trimZero(r.AvgMs) + " ms"
}

func trimZero(f float64) string {
	s := fmt.Sprintf("%.1f", f)
	return strings.TrimSuffix(s, ".0")
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// isLocalTarget 认「这个地址就是本机」。★ 量到本机等于什么都没量：
// 现场最常见的假数就是把对测打在 127.0.0.1 上，然后拿那个几百 G 的数去说网不行。
func isLocalTarget(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.Split(host, "%")[0], "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return true
		}
	}
	for _, a := range thruLocalAddrs() {
		if a == host {
			return true
		}
	}
	if net.ParseIP(host) == nil {
		// 主机名：解析出来是本机的地址也算打在自己身上（现场真有人填本机的主机名）
		if ips, err := net.LookupHost(host); err == nil {
			set := map[string]bool{}
			for _, a := range thruLocalAddrs() {
				set[a] = true
			}
			for _, ip := range ips {
				if set[ip] {
					return true
				}
			}
		}
	}
	return false
}

// localAddrStrings 是本机所有网卡上的地址（含 127.0.0.1 与 ::1 之外的那一层由 IsLoopback 管）。
func localAddrStrings() []string {
	nics, err := thruNICs()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range nics {
		for _, a := range n.Addrs {
			out = append(out, a.IP.String())
		}
	}
	return out
}
