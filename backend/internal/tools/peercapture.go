package tools

// ── net.capture.peer.* ──
//
// ★★ 这一格和 net.capture.* 最不一样的一点：**对端那一路不是本机的延伸。**
//
//	本机进程退了，采集口跟着就没了；对端那一路是别人机器上的一个进程，
//	我们重启、断线、闪退，它都照常在写人家的盘。
//	所以「这笔账什么时候算结掉」「这句话怎么说」都得按「我们随时可能失去它」来写：
//	悬账的说法、取不回来的说法、通道断了的说法，全都要把人指回**那台机器**，
//	而不是指回我们这个已经不在了的进程。
//
// ★ 一路只许一个在跑，理由和本机那一路一样但更硬：两路同时挂在别人机器上，
//   现场分不清哪份文件是哪一路的，而那颗「停」也不知道对应谁 ——
//   在对端多留一路没人收的采集，是要写进别人审计的事。
//
// ★ 起不来的七种档各有各的下一步（没权限、没这块口、过滤器写错、起了又死、
//   没装采集器、打招呼不听、通道断了）。混成一句「起不来」，人就只会一遍遍
//   点同一个按钮；而这七种的修法没有一样是相同的。
//
// ★ 对端回来的任何自由文本（tcpdump 的 stderr、它自己的报错）进结果之前先洗一遍：
//   结果会发给 AI、也可能被打进诊断包，而现场见过设备把带口令的命令行回显进那里。
//   键名留着、值抹掉 —— 「带了但没给你看」不等于「没带」。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/diag"
	"net.yuhox.com/netkit/internal/flow"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
)

// 判定码。★ 一个码一种说法一个下一步，不许合并（尤其不许把「到量停」
// 和「对端自己死了」并进同一个 stopped）。
const (
	capPeerReady           = "capture-peer-ready"
	capPeerNoCollector     = "capture-peer-no-collector"
	capPeerNoIfaceList     = "capture-peer-no-interface-list"
	capPeerRunning         = "capture-peer-running"
	capPeerStopped         = "capture-peer-stopped"
	capPeerStopping        = "capture-peer-stopping"
	capPeerStoppedForced   = "capture-peer-stopped-forced"
	capPeerStoppedNoCounts = "capture-peer-stopped-no-counts"
	capPeerPullFailed      = "capture-peer-pull-failed"
	capPeerVerifyMismatch  = "capture-peer-verify-mismatch"
	capPeerNoSession       = "capture-peer-no-session"
	capPeerUnsupportedOS   = "capture-peer-unsupported-os"
	capPeerStartFailed     = "capture-peer-start-failed"
	capPeerNoPriv          = "capture-peer-no-privilege"
	capPeerNoIface         = "capture-peer-no-interface"
	capPeerBadFilter       = "capture-peer-bad-filter"
	capPeerDied            = "capture-peer-died-at-start"
	capPeerStuck           = "capture-peer-stuck"
	capPeerConn            = "capture-peer-connection"

	// ── Windows/pktmon 这一路独有的几档 ──
	// ★ 为什么单列而不并进上面那几档：pktmon 那一档「起得来、抓得下、就是转不成表」
	//   和 tcpdump 那一档「压根没起来」下一步完全相反（一个去补转换/换机器，一个去查权限）。
	//   合成一句，人就只会照着「没权限」去提权，而那份 .etl 早就躺在盘上了。
	capPeerNoEtl2Pcap        = "capture-peer-no-etl2pcap"        // 有 pktmon，但那台的 build 没有 etl2pcap
	capPeerConvertFailed     = "capture-peer-convert-failed"     // .etl 抓到了，收口时那台转 pcapng 没成
	capPeerBusy              = "capture-peer-busy"               // 那台已经有一路 pktmon 在录（全机器只能一路）
	capPeerFilterUnsupported = "capture-peer-filter-unsupported" // 这一档（pktmon）不认 BPF 那句话
)

// 对端那一路停下来的两种「不是我们停的」。★ 必须和「人停的」「到量」「到时长」分开：
// 「那一路自己退了」和「跟它失去联系」是两个完全不同的下一步（去看对端的日志 / 去看通道）。
const (
	capWhyPeerDied = "peer-died"
	capWhyPeerLost = "peer-lost"
)

// peerJournalKind 是这一路在改动账本上的类别。★ 不叫 "capture"：
// 收悬账那一段要对两种悬账说**相反**的话（本机的自己没了 / 对端的还在跑），
// 共用一个类别就只能靠猜。
const peerJournalKind = "capture-peer"

// peerDefaultCloseWait：打招呼之后等它自己走多久。和对端那一层的默认一致，
// 但写在这一层，因为「等到什么程度算不听招呼」是界面上那句话的口径。
const peerDefaultCloseWait = 5 * time.Second

type peerArgs struct {
	Device    string `json:"device"`
	Interface string `json:"interface,omitempty"`
	Filter    string `json:"filter,omitempty"`
	SnapLen   int    `json:"snapLen,omitempty"`
	Seconds   int    `json:"seconds,omitempty"`
	MaxMB     int    `json:"maxMB,omitempty"`
	KeepPeer  bool   `json:"keepPeer,omitempty"`
}

// peerPlan 是一次对端采集的口径。★ 校验与默认值只这一处：Describe（批准框上那句
// 「这次到底要改什么」）与 Invoke 各算一遍，迟早给出两种说法。
type peerPlan struct {
	device   string
	iface    string
	filter   string
	snapLen  int
	seconds  int
	maxBytes int64
	keepPeer bool
	// peerFile / peerLog 落在对端，local 落在本机。
	peerFile string
	peerLog  string
	local    string
}

func peerPlanOf(a peerArgs) (peerPlan, error) {
	p := peerPlan{
		device:   strings.TrimSpace(a.Device),
		iface:    strings.TrimSpace(a.Interface),
		filter:   strings.TrimSpace(a.Filter),
		snapLen:  a.SnapLen,
		seconds:  a.Seconds,
		maxBytes: int64(capDefaultFileMaxMB) << 20,
		keepPeer: a.KeepPeer,
	}
	if a.SnapLen < 0 || a.Seconds < 0 || a.MaxMB < 0 {
		// ★ 负数是「明确要一个不可能的值」，当场拒（口径同本机那一路）。
		return p, fmt.Errorf("snapLen / seconds / maxMB 都不能是负数")
	}
	if p.device == "" {
		return p, fmt.Errorf("得点名在哪台设备上抓（remote.device.list 里那个 id）")
	}
	if p.iface == "" {
		return p, fmt.Errorf("interface 要给：这一档不替你选「所有口」—— 在那台机器上抓所有口" +
			"是另一件事，而且往往抓到的全是它自己连自己的那一段")
	}
	if p.snapLen == 0 {
		p.snapLen = capDefaultSnapLen
	}
	if p.snapLen > capMaxSnapLen {
		return p, fmt.Errorf("snapLen 最多 %d（再大就是拿抓包当录像，对端那个环几秒就满）", capMaxSnapLen)
	}
	if p.seconds > capMaxSeconds {
		return p, fmt.Errorf("seconds 最多 %d（要盯更久用 net.quality.*，抓包不当录像用）", capMaxSeconds)
	}
	if a.MaxMB > 0 {
		if a.MaxMB > capMaxFileMB {
			return p, fmt.Errorf("maxMB 最多 %d", capMaxFileMB)
		}
		p.maxBytes = int64(a.MaxMB) << 20
	}
	return p, nil
}

// ── 与对端打交道的那只手 ──
//
// ★ 全部做成包级变量，只有一个理由：判定层要用一台「说得出各种话」的假对端
//   把每一种判定钉住，而不是依赖此刻有没有一台能连的机器。
//   那一句命令到底怎么说、对端那句话怎么分档，internal/remote 已经拿真 sh、
//   真后台进程、真 SIGINT 验过一遍（见 peercap_test.go），这一层不重复验。

// peerConn 是一条开着的对端通道：设备、执行器、取文件的动作、关它的那一下。
//
// ★ 会话期间一直握着：那一路的进程号、那份文件、那本日志都要从同一个通道问得出来，
//
//	每次调用重连等于在对端多留几个连接数，而且中途换了通道就找不回那一路。
type peerConn struct {
	d       *remote.Device
	x       remote.SSHExecer
	c       *ssh.Client
	pull    func(ctx context.Context, remotePath, localPath string) (*remote.Transfer, error)
	closeFn func()
}

func (c *peerConn) close() {
	if c == nil {
		return
	}
	if c.closeFn != nil {
		c.closeFn()
	} else if c.c != nil {
		_ = c.c.Close()
	}
}

var peerDial = func(ctx context.Context, device string) (*peerConn, error) {
	d, c, x, err := dial(ctx, device)
	if err != nil {
		return nil, err
	}
	return &peerConn{
		d: d, x: x, c: c,
		pull: func(ctx context.Context, rp, lp string) (*remote.Transfer, error) {
			return remote.Pull(ctx, c, x, d, rp, lp)
		},
	}, nil
}

var (
	peerProbeFn   = remote.ProbePeerCapture
	peerStartFn   = remote.StartPeerCapture
	peerStatFn    = remote.PeerCaptureStat
	peerStopFn    = remote.StopPeerCapture
	peerRemoveFn  = remote.RemovePeerFiles
	peerPollEvery = 2 * time.Second
)

// ── 会话 ──

// peerSession 是一路开在对端的采集。★ 它不是 captureRun 的远程版：这一路没有
// 本机的采集口、没有本机的写手，包是在对端的盘上长的，我们只做
// 「看一眼」「打招呼」「取回来」。
type peerSession struct {
	mu        sync.Mutex
	conn      *peerConn
	run       *remote.PeerRun
	plan      peerPlan
	collector string
	journal   string

	lastBytes int64
	lastSeen  time.Time
	startedAt time.Time

	wantWhy string
	// keepPeerLive 是「按停那颗钮时补的那句 keepPeer」。★ 不复用 s.plan.keepPeer：
	// plan 在会话对外可见之后就只读，而收口那一路会先给它拍一份快照 ——
	// 改在飞的那一份上，就是两个人抢同一个字段（race 抓到过这一次）。
	keepPeerLive bool
	// stopping：有人已经认领了收口这一步（打招呼、等退出、取回、读成表）。
	// ★ 和 settled 分开是必须的：收口可以很慢，而这一段时间里界面上仍然要看得见这一路。
	stopping bool
	settled  bool
	led      *captureLedger
	// result：收口那一次的判定。★ 停完再问状态要接着上一次的账说，
	// 「抓完了停在那儿」和「压根没起过」是两件事。
	result *ots.Verdict

	cancel context.CancelFunc
	// done 在收口落账那一下（record）关闭，不在看门退出时关 —— 要等的是「这份账结了」，
	// 不是「那个 goroutine 走了」。
	done chan struct{}

	// ★ 对端那四件事的口径在「起这一路」那一刻一次定下，之后只读。
	//   一路会话半路换一套问法是不成立的：那台上起的采集、那份文件、那个通道，
	//   都是按开局这一套来的；换口径只会让正在跑的这一路对着一个对不上的世界说话。
	statFn    func(context.Context, remote.SSHExecer, *remote.Device, *remote.PeerRun) (*remote.PeerStat, error)
	stopFn    func(context.Context, remote.SSHExecer, *remote.Device, *remote.PeerRun, time.Duration) (*remote.PeerStopInfo, error)
	removeFn  func(context.Context, remote.SSHExecer, *remote.Device, ...string) error
	pollEvery time.Duration
}

var peerSource = struct {
	mu      sync.Mutex
	session *peerSession
}{mu: sync.Mutex{}}

func (s *peerSession) finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settled
}

// closing 这一路正在收口、还没收完的那一段（有人已经抢下这一步，结果还没落账）。
func (s *peerSession) closing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping && !s.settled
}

func (s *peerSession) what() string {
	return fmt.Sprintf("%s 的 %s（对端文件 %s）", s.plan.device, s.plan.iface, s.run.PeerFile)
}

// peerFileTag 生成对端那两份的名字。★ 名字由我们自己出，绝不让调用方给：
// 那等于让他们在自己机器上挑一个已有文件，而后面那句 rm 就等着它。
func peerFileTag() string { return time.Now().Format("20060102-150405") }

func peerJoin(dir, name string) string {
	if dir == "" {
		dir = "/tmp"
	}
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

// peerJoinWin 拼对端 Windows 那一份的路径。★ 分隔符必须是反斜杠：caps.Dir 从 %TEMP% 问
// 出来就是 `C:\Users\...\Temp` 那种形态，拿正斜杠拼出的路径 pktmon 不认（cmd.exe 里
// 正斜杠是开关的引导符）。末尾已经带 `\` 的（盘根那种）不重复加。
func peerJoinWin(dir, name string) string {
	if dir == "" {
		dir = `C:\Windows\Temp`
	}
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}

func peerLocalPath(device string) string {
	safe := strings.NewReplacer("@", "-", ":", "-", "/", "-", `\`, "-", " ", "-").Replace(device)
	return filepath.Join(captureDir, "netkit-peer-"+safe+"-"+peerFileTag()+".pcap")
}

// peerLocalPathWin 取回来那份落本机的名字。★ 后缀用 .pcapng 而不是 .pcap：pktmon etl2pcap
//
//	转出来的是 pcapng，本机读取那一路靠魔数认（capture.Open），后缀不影响能不能读，
//	但人拿这份去开 Wireshark 时，后缀对得上少一句解释。
func peerLocalPathWin(device string) string {
	safe := strings.NewReplacer("@", "-", ":", "-", "/", "-", `\`, "-", " ", "-").Replace(device)
	return filepath.Join(captureDir, "netkit-peer-"+safe+"-"+peerFileTag()+".pcapng")
}

// ── net.capture.peer.probe ──

var peerCaptureProbeTool = ots.Tool{
	Name:  "net.capture.peer.probe",
	Class: ots.ClassRead,
	Summary: "问对端那台机器：有没有能用的采集器、它在哪、有哪些口可以点名、那份文件能落哪儿。" +
		"远程抓包之前先问这一句 —— 口名是那台机器自己报的，不是我们从本机网卡名猜的。\n" +
		"★ 「那台上没装 tcpdump」回的是判定不是报错：那是一个能让你决定下一步的事实" +
		"（装它、换 Windows 那一路、还是回到本机抓），不是这个工具坏了。\n" +
		"采集器在但给不出口列表（老 tcpdump 不认 -D）也单独说：那时口名没核过。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device"],
	  "properties": {
	    "device": {"type": "string", "description": "登记过的设备 id（remote.device.list 里那个，如 ops@10.0.0.9）"}
	  }
	}`),
	Invoke: probePeerCapture,
}

func probePeerCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	var a peerArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	device := strings.TrimSpace(a.Device)
	if device == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "得点名在哪台设备上抓（remote.device.list 里那个 id）")
	}
	conn, err := peerDial(ctx, device)
	if err != nil {
		return nil, err
	}
	defer conn.close()

	// ★ 这一档分流看的是「那台的系统探明了没有」，不是「是不是 Windows」：
	//   Windows 走 pktmon（见 remote/peercap_windows_path.go）、Linux/macOS 走 tcpdump，
	//   两条都能驱动；真正驱动不了的是「压根没探过、不知道对面是什么」—— 那一句命令
	//   连该怎么写都说不清，起不来的理由就只能靠猜。所以这里只拦 unknown/空。
	if unsupportedPeerOS(conn.d) {
		return peerVerdict(capPeerUnsupportedOS,
			"那台的系统还没探明，不知道那句采集命令该怎么写（先 remote.device.probe）",
			conn.d.ID, conn.d.OS), nil
	}
	caps, err := peerProbeFn(ctx, conn.x, conn.d)
	if err != nil {
		return peerVerdict(capPeerConn, "那台机器上问不出话（通道断了或认证没过）",
			conn.d.ID, err.Error()), nil
	}
	windows := conn.d.OS == "windows"
	switch {
	case caps.Tool == "":
		return peerVerdict(capPeerNoCollector,
			fmt.Sprintf("%s 上没有可用的采集器", conn.d.ID), conn.d.ID, caps.Note), nil
	case windows && !caps.Etl2Pcap:
		// ★ pktmon 在、但没有 etl2pcap 那一项：抓得出 .etl，转不成我们这张表读得动的东西。
		//   这不是「没采集器」（能抓），也不是「没接口列表」，是一个专门的下一步（换机器/本机抓）。
		return peerVerdict(capPeerNoEtl2Pcap,
			fmt.Sprintf("%s 的 pktmon 没有 etl2pcap 那一项，转不成能读的表", conn.d.ID),
			conn.d.ID, caps.Note), nil
	case !windows && len(caps.Ifaces) == 0:
		// ★ Windows 那一档不列口是**设计如此**（pktmon 只能 --comp nics 全机器抓，见下），
		//   不是「问不出来」；拿「没有口列表」拦它就把一条本来能走的路堵死。所以这条只管 POSIX。
		return peerVerdict(capPeerNoIfaceList,
			"采集器在，但那台机器给不出口列表 —— 口名没核过", conn.d.ID, caps.Note), nil
	}
	said, _ := diag.Scrub(caps.Note)
	next := peerNextStep(capPeerReady, "")
	// ★ 口那一格的说法分两种：POSIX 列出可点名的口；Windows/pktmon 如实说「全机器一起抓、
	//   不逐块点名」—— 不能留个空列表让人以为挑了某块口就只抓那一块。
	ifaceSaid := "能点名的口：" + strings.Join(caps.Ifaces, "、")
	if windows {
		ifaceSaid = "pktmon 这一档抓的是那台机器上全部网卡（--comp nics），不逐块点名"
	}
	return ots.Verdict{
		Code: capPeerReady,
		Values: map[string]any{
			"device":     conn.d.ID,
			"collector":  caps.Tool,
			"path":       caps.Path,
			"interfaces": caps.Ifaces,
			"peerDir":    caps.Dir,
			"etl2pcap":   caps.Etl2Pcap,
			"note":       said,
			"next":       next,
		},
		Note: fmt.Sprintf("%s 上可以用 %s（%s）。%s。那份文件落 %s。\n下一步：%s",
			conn.d.ID, caps.Tool, caps.Path, ifaceSaid, caps.Dir, next),
	}, nil
}

// unsupportedPeerOS：探不出系统（或探出来是我们不会驱动的那一种）时，那句采集命令压根
// 没法写 —— 注意这**不再是**「Windows 不支持」：Windows 走 pktmon 那一档，已经接上了。
// 真正驱动不了的是「没探过 / unknown」：不知道对面是 Windows 还是某种 POSIX，两句命令写法
// 南辕北辙，硬起一路，起不来的理由就只能靠猜。
func unsupportedPeerOS(d *remote.Device) bool {
	return d == nil || d.OS == "" || d.OS == "unknown"
}

// ── net.capture.peer.start ──

var peerCaptureStartTool = ots.Tool{
	Name:  "net.capture.peer.start",
	Class: ots.ClassMutate,
	Summary: "在远程设备后台起一路 tcpdump 抓包：点名的那块口、可选的 BPF 过滤器、全帧长度，" +
		"包落在那台机器的临时目录里；到量或到时长自己停，也可以调 net.capture.peer.stop 停。\n" +
		"★ 起了以后先看一眼（等一会儿再问），因为「收条据、一秒后自己死掉」这一种是真存在的：" +
		"非 root 的 tcpdump 就是这样。不回头确认的那一版会说「抓起来了」，" +
		"人等到停的时候才发现那份文件是空的。\n" +
		"★ 起不来的七种档各给一个码：capture-peer-no-privilege（那台要提权）、" +
		"capture-peer-no-interface（那块口在那台上不存在）、capture-peer-bad-filter（过滤器写错）、" +
		"capture-peer-died-at-start（起了又死，说不出为什么）、capture-peer-no-collector、" +
		"capture-peer-stuck、capture-peer-connection（通道断了）。每一种的下一步都不一样。\n" +
		"★ 这一路会进改动账本，但**本进程重启不会把它停掉** —— 它是别人机器上的一个进程。" +
		"账上那句会明写这份文件还在对端哪儿。\n" +
		"对端回来的任何原话进结果之前先脱敏一遍（结果会发给 AI，也可能打进诊断包）。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device", "interface"],
	  "properties": {
	    "device": {"type": "string", "description": "登记过的设备 id（如 ops@10.0.0.9）。★ 系统得先探过（remote.device.probe）：Windows 走的是另一套下发"},
	    "interface": {"type": "string", "description": "抓哪块口，用 net.capture.peer.probe 报出来的名字。★ 不替你选「所有口」"},
	    "filter": {"type": "string", "description": "BPF 过滤器原话（如 \"tcp port 554\"）。★ 写错会在对端当场报错并归到 capture-peer-bad-filter，不会悄悄当成没流量"},
	    "snapLen": {"type": "integer", "minimum": 64, "maximum": 65535,
	      "description": "一包最多留多少字节，默认 1600。★ 默认留全帧：半截报文是最难查的一种假象"},
	    "seconds": {"type": "integer", "minimum": 1, "maximum": 3600,
	      "description": "到这么久自己停，默认不停。★ 一直挂着会把**现场那台机器**的盘写满，而我们这边随时可能失去它"},
	    "maxMB": {"type": "integer", "minimum": 1, "maximum": 4096,
	      "description": "对端那份文件到这么大就停，默认 256MB。到顶会写「是到上限了，不是没流量」"},
	    "keepPeer": {"type": "boolean",
	      "description": "停完取回之后**不删**对端那一份。★ 默认删：那是原始包，含明文口令与团体名，我们这边已经有了就不该留"}
	  }
	}`),
	Describe: describeCapturePeerStart,
	Invoke:   startPeerCapture,
}

func describeCapturePeerStart(raw json.RawMessage) string {
	var a peerArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	p, err := peerPlanOf(a)
	if err != nil {
		return "★ 在别人家的机器上开一路抓包（参数没定下来：" + err.Error() + "）"
	}
	s := fmt.Sprintf("★ 在别人家的机器上开一路抓包：%s 的 %s 上，一包留 %d 字节，对端文件上限 %dMB",
		p.device, p.iface, p.snapLen, p.maxBytes>>20)
	if p.filter != "" {
		s += "，只收「" + p.filter + "」"
	}
	if p.seconds > 0 {
		s += fmt.Sprintf("，最长 %s 自己停", humanDur(time.Duration(p.seconds)*time.Second))
	} else {
		s += "，一直抓到你调 net.capture.peer.stop 停为止"
	}
	s += "。★ 那台上会真的起一个采集进程、往那台的盘上写原始包；"
	s += "本进程重启不会替你把那一路停掉，那份文件也留在现场那台机器上"
	if p.keepPeer {
		s += "。这一条说了 keepPeer：取回来之后对端那一份**不删**"
	}
	return s
}

func startPeerCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	var a peerArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	plan, err := peerPlanOf(a)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if journal == nil {
		// ★ 会在别人机器上一路跑、一路写的改动记不下来，就不许开始。
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝在对端开抓包")
	}
	if captureDir == "" {
		return nil, ots.Errf(ots.ErrInternal, "找不到用户配置目录，取回来的那份没地方落，拒绝开这一路")
	}

	peerSource.mu.Lock()
	busy := peerSource.session != nil && !peerSource.session.finished()
	var old string
	if busy {
		old = peerSource.session.what()
	}
	peerSource.mu.Unlock()
	if busy {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"已经有一路远程抓包在跑了（%s）。先 net.capture.peer.stop 停掉那一路再开新的 —— "+
				"两路同时挂在别人机器上，现场分不清哪份是哪一路，那颗「停」也不知道对应谁", old)
	}

	conn, err := peerDial(ctx, plan.device)
	if err != nil {
		return nil, err
	}
	fail := func(code, reason, said string) (any, error) {
		conn.close()
		return peerVerdict(code, reason, conn.d.ID, said), nil
	}
	// ★ Windows 已经接上了（走 pktmon，见 remote/peercap_windows_path.go），这里不再拦它。
	//   真正拦的是「没探过 / unknown」：不知道对面是 Windows 还是某种 POSIX，两句采集命令
	//   写法南辕北辙，硬起一路，起不来的理由就只能靠猜。
	if unsupportedPeerOS(conn.d) {
		conn.close()
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%s 的系统还没探过（先 remote.device.probe），不知道那句命令该怎么写 —— "+
				"不知道的情况下起采集，起不来的理由就只能靠猜", plan.device)
	}
	windows := conn.d.OS == "windows"

	caps, err := peerProbeFn(ctx, conn.x, conn.d)
	if err != nil {
		return fail(capPeerConn, "那台机器上问不出话（通道断了或认证没过）", err.Error())
	}
	if caps.Tool == "" {
		return fail(capPeerNoCollector,
			fmt.Sprintf("%s 上没有可用的采集器", conn.d.ID), caps.Note)
	}
	// ★ BPF 那句话在 pktmon 这一档不认：pktmon 用的是另一套 filter（`pktmon filter add`，
	//   且只按端口/IP 分层，不吃 BPF 表达式）。这一档没实现那套，所以带 filter 来就当场拒 ——
	//   绝不悄悄丢掉这个参数假装「全抓」：筛没筛是结论级的事，丢掉就等于给人一份口径不同的表。
	if windows && plan.filter != "" {
		return fail(capPeerFilterUnsupported,
			fmt.Sprintf("%s 走的是 pktmon，不认 BPF 过滤器（pktmon 用的是另一套 filter，这一档没接）", conn.d.ID),
			plan.filter)
	}
	// ★ 没有 etl2pcap 就别起这一路：抓得下 .etl 也停得了，就是转不成我们这张表读得动的东西，
	//   等收口才说「转不了」等于白写一路别人的盘。probe 已经问出来了，这里再钉一次。
	if windows && !caps.Etl2Pcap {
		return fail(capPeerNoEtl2Pcap,
			fmt.Sprintf("%s 的 pktmon 没有 etl2pcap 那一项，抓得出 .etl 但转不成能读的表", conn.d.ID),
			caps.Note)
	}
	// ★ 口名只在那台机器报得出列表时才核：报不出列表时不拦 ——
	//   「问不出来」不等于「这块口不存在」，拦了就把一条本来能走的路堵死。
	//   Windows 那一档 caps.Ifaces 是空的（pktmon 只能全机器抓），本来也就不用核。
	if len(caps.Ifaces) > 0 && !hasPeerIface(caps.Ifaces, plan.iface) {
		return fail(capPeerNoIface,
			fmt.Sprintf("%s 上报出来的口里没有 %s", conn.d.ID, plan.iface),
			"那台机器报的口："+strings.Join(caps.Ifaces, "、"))
	}

	tag := peerFileTag()
	var etlPath, pcapPath string
	if windows {
		// Windows 那一路落两份：pktmon 录的 .etl，和收口时 etl2pcap 转出的 .pcapng。
		// plan.peerFile 指向**最终要 pull 回来的那份 pcapng**（POSIX 那一路同名同义，
		// 上层取回、删对端、进表那几段一行都不用改）。
		etlPath = peerJoinWin(caps.Dir, "netkit-cap-"+tag+".etl")
		pcapPath = peerJoinWin(caps.Dir, "netkit-cap-"+tag+".pcapng")
		plan.peerFile = pcapPath
		plan.peerLog = "" // pktmon 不写 tcpdump 那种 stderr 账，对端没有日志文件要留要删
		plan.local = peerLocalPathWin(plan.device)
	} else {
		plan.peerFile = peerJoin(caps.Dir, "netkit-cap-"+tag+".pcap")
		plan.peerLog = peerJoin(caps.Dir, "netkit-cap-"+tag+".log")
		plan.local = peerLocalPath(plan.device)
	}

	// ★ 传给 pktmon 的 -s（MB）向上取整：0 在它那里不是「不限」是「默认 512MB」（实测清单第 5 条），
	//   而 256.5MB 那种向下取整会提前一点点停 —— 宁可比用户说的多半 MB，也不要报成「到顶」其实没到。
	winMB := int((plan.maxBytes + (1 << 20) - 1) >> 20)
	if winMB < 1 {
		winMB = 1
	}

	id, err := journal.Register(peerJournalKind, describeCapturePeerStart(raw),
		map[string]any{"capturing": false},
		map[string]any{"device": plan.device, "interface": plan.iface,
			"peerFile": plan.peerFile, "snapLen": plan.snapLen,
			"maxMB": int(plan.maxBytes >> 20)})
	if err != nil {
		conn.close()
		return nil, ots.Errf(ots.ErrInternal, "这一路远程抓包记不进改动账本，拒绝开：%s", err)
	}
	_ = journal.MarkApplied(id)

	run, err := peerStartFn(ctx, conn.x, conn.d, remote.PeerCaptureSpec{
		Collector: caps.Path,
		Interface: plan.iface,
		Filter:    plan.filter,
		SnapLen:   plan.snapLen,
		PeerFile:  plan.peerFile,
		PeerLog:   plan.peerLog,
		MaxMB:     winMB,
		EtlPath:   etlPath,
		PcapPath:  pcapPath,
	})
	if err != nil {
		// ★ 没起来就把那笔账结掉：挂着一笔「在抓」的账，下一个人会去查一路
		//   压根没存在的采集，还会照着账上的文件名去对端找一份没写过的文件。
		_ = journal.Drop(id, "起那一路没成，对端没留下进程："+scrubOne(err.Error()))
		mgr.Audit(ots.CallerFrom(ctx), "capture-peer.start", conn.d.ID,
			plan.iface+" 起不来", scrubOne(err.Error()))
		code, reason := peerStartProblem(err)
		return fail(code, reason, err.Error())
	}

	mgr.Audit(ots.CallerFrom(ctx), "capture-peer.start", conn.d.ID,
		fmt.Sprintf("%s → %s", plan.iface, plan.peerFile), "ok")

	cctx, cancel := context.WithCancel(context.Background())
	s := &peerSession{
		conn:      conn,
		run:       run,
		plan:      plan,
		collector: caps.Tool,
		journal:   id,
		lastSeen:  time.Now(),
		startedAt: run.StartedAt,
		cancel:    cancel,
		done:      make(chan struct{}),
		statFn:    peerStatFn,
		stopFn:    peerStopFn,
		removeFn:  peerRemoveFn,
		pollEvery: peerPollEvery,
	}
	// ★ 先对外可见、再放看门那一路：反过来的话，对端可能已经写进去几包，
	//   而界面上还查不到「有一路在跑」—— 那颗「停」就慢一拍，而它是唯一能收手的口子。
	peerSource.mu.Lock()
	peerSource.session = s
	peerSource.mu.Unlock()
	go s.watch(cctx)

	return peerRunningVerdict(s, ""), nil
}

func hasPeerIface(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// peerStartProblem 把底座那句错分成一档。★ 认不出就老实说 start-failed：
// 猜出来的档会把人支去查一个没病的地方。
func peerStartProblem(err error) (string, string) {
	var pe *remote.PeerStartError
	if errors.As(err, &pe) {
		switch pe.Problem {
		case remote.PeerProblemPrivilege:
			return capPeerNoPriv, "在那台机器上以现在这个账号抓不了 —— 采集要 root 或 CAP_NET_RAW"
		case remote.PeerProblemInterface:
			return capPeerNoIface, "那块口在那台机器上不存在（或者此刻不在这台上）"
		case remote.PeerProblemFilter:
			return capPeerBadFilter, "过滤器那句话对端不认（BPF 语法写错了）"
		case remote.PeerProblemNoTool:
			return capPeerNoCollector, "那台机器上那个采集器在这一步又找不着了"
		case remote.PeerProblemStuck:
			return capPeerStuck, "那一路起来又卡住：既不继续也不退出"
		case remote.PeerProblemConnection:
			return capPeerConn, "起那一路的时候通道断了"
		case remote.PeerProblemBusy:
			// ★ 单独一档的理由：pktmon 全机器只能一路，159 说的是「别人（或你上一路没停干净的）
			//   正占着」。它的下一步是去 stop 那一录，不是去提权 —— 混进 no-privilege 就把人支反了。
			return capPeerBusy, "那台机器上已经有一路 pktmon 在录（全机器只能一路），这一路起不来"
		case remote.PeerProblemDied:
			return capPeerDied, "那一路起了又死，对端没说出是几种里的哪一种"
		}
	}
	if connBroken(err) {
		return capPeerConn, "对端的通道断了"
	}
	return capPeerStartFailed, "对端那一路没起来，且说不出是哪一档"
}

// ── 看门：到量、到时长、对端自己死了 ──

func (s *peerSession) watch(ctx context.Context) {
	var until <-chan time.Time
	if s.plan.seconds > 0 {
		t := time.NewTimer(time.Duration(s.plan.seconds) * time.Second)
		defer t.Stop()
		until = t.C
	}
	tick := time.NewTicker(s.pollEvery)
	defer tick.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-until:
			s.stop(context.WithoutCancel(ctx), capWhyDuration)
			return
		case <-tick.C:
			st, err := s.statFn(ctx, s.conn.x, s.conn.d, s.run)
			if err != nil {
				// ★ 问不出一次先不算死：现场 SSH 抖一下太常见，一抖就把账收掉，
				//   会把还在正常写的那一路误报成「死了」。连着问不出三次才收口。
				misses++
				if misses >= 3 {
					s.stop(context.WithoutCancel(ctx), capWhyPeerLost)
					return
				}
				continue
			}
			misses = 0
			s.mu.Lock()
			s.lastBytes = st.Bytes
			s.lastSeen = time.Now()
			s.mu.Unlock()
			if !st.Alive {
				s.stop(context.WithoutCancel(ctx), capWhyPeerDied)
				return
			}
			// ★ 「到顶了」和「这条链路真的没流量」是两种相反的下一步，
			//   所以这里只按字节数停，并把理由单独带进账。
			if st.BytesKnown && st.Bytes >= s.plan.maxBytes {
				s.stop(context.WithoutCancel(ctx), capWhyMaxBytes)
				return
			}
		}
	}
}

func peerRunningVerdict(s *peerSession, extra string) ots.Verdict {
	s.mu.Lock()
	bytes, seen := s.lastBytes, s.lastSeen
	s.mu.Unlock()
	v := map[string]any{
		"running":   true,
		"device":    s.plan.device,
		"interface": s.plan.iface,
		"collector": s.collector,
		"peerFile":  s.run.PeerFile,
		"peerLog":   s.run.PeerLog,
		"snapLen":   s.plan.snapLen,
		"filter":    s.plan.filter,
		"maxMB":     int(s.plan.maxBytes >> 20),
		"seconds":   s.plan.seconds,
		"peerBytes": bytes,
		"startedAt": s.startedAt.Format(time.RFC3339),
		"lastCheck": seen.Format(time.RFC3339),
		"localFile": s.plan.local,
		"next":      peerNextStep(capPeerRunning, ""),
	}
	if s.run != nil && s.run.Windows {
		// ★ 点名了接口也要如实说这一档抓的是全部网卡：pktmon 只能 --comp nics，
		//   点的那块口名在这条路上不生效 —— 悄悄按名字只抓一块是假的，说破它是诚实。
		v["capturesAllInterfaces"] = true
	}
	note := fmt.Sprintf("对端在抓：%s。一包留 %d 字节。", s.what(), s.plan.snapLen)
	if s.run != nil && s.run.Windows {
		note += "★ pktmon 这一档抓的是那台机器上全部网卡（--comp nics），点名的那块口不逐块区分。"
	}
	if s.plan.seconds > 0 {
		note += fmt.Sprintf("到 %s 自己停。", humanDur(time.Duration(s.plan.seconds)*time.Second))
	}
	note += fmt.Sprintf("对端那份到 %dMB 自己停。", int(s.plan.maxBytes>>20))
	note += "★ 这一路在别人机器上：NetKit 重启不会把它停掉。"
	if s.plan.filter != "" {
		note += "只收「" + s.plan.filter + "」里的包 —— 表上没看到的流量可能是被筛掉了，不是没发生。"
	}
	if extra != "" {
		note = extra + "\n" + note
	}
	return ots.Verdict{Code: capPeerRunning, Values: v, Note: note}
}

// peerStoppingVerdict 是「已经打过招呼、那份还在往回走」这一段。★ 这一段可以很长
// （整份文件要过一遍 SSH，还要读成表），而它既不是「还在抓」也不是「停了」：
// 报成「没有这一路」等于把一路正在收的采集凭空抹掉，报成「在抓」会让人以为还能再等下去。
func peerStoppingVerdict(s *peerSession) ots.Verdict {
	v := peerRunningVerdict(s, "")
	v.Code = capPeerStopping
	v.Values["stopping"] = true
	next := peerNextStep(capPeerStopping, s.run.PeerFile)
	v.Values["next"] = next
	v.Note = "这一路正在收口：已经打过招呼（SIGINT），还在等对端退出、把那份取回本机并读成表。\n" +
		"★ 别催第二下 —— 再按一次「停」不会让它更快，只会拿到这同一句话；" +
		"那一路是别人机器上的进程，收口这中间我们退了它也不会跟着退，所以这一步只能等它走完。\n" +
		"下一步：" + next
	return v
}

// ── 收口：打招呼停 → 取回 → 进表 → 清对端 → 关通道 ──

// stop 把这一路收干净。★ 只有一个收口的人：stopping 那一下抢到才算，
// 看门和人手同时伸手时不会把同一份账结两次、更不会向对端打两次招呼。
// 没抢到的那一个拿到的就是「正在收口」那一句 —— 它没有停成什么，只是看见别人正在停。
func (s *peerSession) stop(ctx context.Context, why string) ots.Verdict {
	s.mu.Lock()
	if s.settled {
		v := s.result
		s.mu.Unlock()
		if v != nil {
			return *v
		}
		return ots.Verdict{Code: capPeerNoSession, Values: map[string]any{},
			Note: "这一路已经收过口了"}
	}
	if s.stopping {
		s.mu.Unlock()
		return peerStoppingVerdict(s)
	}
	s.stopping = true
	if s.wantWhy == "" {
		s.wantWhy = why
	}
	why = s.wantWhy
	conn, run, plan := s.conn, s.run, s.plan
	// ★ keepPeer 只在收口这一刻合进这一份快照：plan 从会话对外可见起就是只读的
	//   （看门与状态都在不加锁地读它），往它身上写字就是和那两路抢同一个字段。
	plan.keepPeer = plan.keepPeer || s.keepPeerLive
	jid := s.journal
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	info, err := s.stopFn(ctx, conn.x, conn.d, run, peerStopWait(why))
	if err != nil {
		v := peerVerdict(capPeerConn,
			"停的那一下没回音（通道断了）：那一路可能还在写，也可能已经退了，这边说不出",
			conn.d.ID, err.Error())
		v.Values["stopWhy"] = why
		v.Values["peerFile"] = run.PeerFile
		// ★ 这笔账不能报成「已还原」：我们压根没核过。但它也不能一直挂着 ——
		//   挂着的后果是下一个人去查一路我们再也问不到的采集。所以照实写没核过。
		_ = journal.MarkReverted(jid, "通道断了，对端那一路的收口没核过：文件 "+run.PeerFile)
		conn.close()
		s.record(&v)
		return v
	}

	// ★ 转换失败是 Windows 这一路独有的一档，必须排在 pull 之前：pktmon stop 成了、
	//   包尽在那一份 .etl 里，只是那台的 etl2pcap 没转出 pcapng。这时候
	//   (1) 不能去 pull —— 那份 pcapng 压根不存在，pull 会报一句对不上号的 I/O 错；
	//   (2) 绝不能删对端 —— 那份 .etl 是唯一的原件，删了就把现场证据丢了；
	//   (3) 下一步与 pull-failed 相反：pull-failed 是「文件在、通道取不动」，这一档是
	//       「文件还没变成能取的样子」，人去补的是转换（在那台手动 etl2pcap，或换台新 build）。
	if info.ConvertErr != "" {
		clean, _ := diag.Scrub(firstLineOfPeer(info.ConvertErr))
		v := peerVerdict(capPeerConvertFailed,
			fmt.Sprintf("%s 那一路停了、包也落到了 .etl，但那台没能把它转成 pcapng", conn.d.ID),
			conn.d.ID, info.ConvertErr)
		v.Values["stopWhy"] = why
		v.Values["etlFile"] = run.EtlPath
		v.Values["peerRemoved"] = false
		v.Note += "\n★ 那一份 .etl 是唯一的原件，没敢删，还留在对端：" + run.EtlPath +
			"\n对端自己说：" + clean +
			"\n下一步：" + peerNextStep(capPeerConvertFailed, run.EtlPath)
		_ = journal.MarkReverted(jid, fmt.Sprintf(
			"对端已停，但 etl2pcap 没成，.etl 原件留在 %s（本机这份没取回）", run.EtlPath))
		mgr.Audit(ots.CallerFrom(ctx), "capture-peer.stop", conn.d.ID,
			plan.iface+" 停了，转 pcapng 没成", "convert-failed")
		conn.close()
		s.record(&v)
		return v
	}

	logText, redacted := diag.Scrub(info.Log)
	v := ots.Verdict{
		Code: capPeerStopped,
		Values: map[string]any{
			"running":      false,
			"device":       plan.device,
			"interface":    plan.iface,
			"peerFile":     run.PeerFile,
			"stopWhy":      why,
			"captured":     info.Captured,
			"received":     info.Received,
			"dropped":      info.Dropped,
			"droppedKnown": info.HasCounts,
			"peerSaid":     firstLineOfPeer(logText),
			"peerLog":      logText,
			"redacted":     redacted,
			"redactedHow":  redactedHow(redacted),
			"keepPeer":     plan.keepPeer,
		},
	}
	switch {
	case info.Forced:
		v.Code = capPeerStoppedForced
	case !info.HasCounts:
		v.Code = capPeerStoppedNoCounts
	}

	tf, pullErr := conn.pull(ctx, run.PeerFile, plan.local)
	if pullErr != nil {
		// ★ 取不回来是最要緊的一步：包已经停了，但那份还在别人的机器上。
		v.Code = capPeerPullFailed
		v.Values["pullError"] = scrubOne(pullErr.Error())
		note := fmt.Sprintf("那一路停了（%s），但 %s 没取回本机：%s\n"+
			"★ 那份还在对端：%s —— 本进程退了不会把它带走，得自己去那台机器上收。",
			whyClausePeer(why), run.PeerFile, scrubOne(pullErr.Error()), run.PeerFile)
		if info.Forced {
			note += "另外这一路是硬断的，那份文件末尾可能短一截。"
		}
		v.Note = note + "\n下一步：" + peerNextStep(capPeerPullFailed, run.PeerFile)
		v.Values["next"] = peerNextStep(capPeerPullFailed, run.PeerFile)
		// 对端那一份**不删**：我们这边还没有。
		_ = journal.MarkReverted(jid, fmt.Sprintf("对端已停，文件留在 %s（没取回：%s）",
			run.PeerFile, scrubOne(pullErr.Error())))
		mgr.Audit(ots.CallerFrom(ctx), "capture-peer.stop", conn.d.ID,
			plan.iface+" 停了，文件没取回", "pull-failed")
		conn.close()
		s.record(&v)
		return v
	}

	v.Values["file"] = plan.local
	v.Values["bytes"] = tf.Bytes
	if tf.SHA256 != "" {
		v.Values["sha256"] = tf.SHA256
	}
	if tf.Verified == "mismatch" {
		// ★ 字节数对得上而整包摘要对不上 = 这份传坏了或被人动过。
		v.Code = capPeerVerifyMismatch
	}

	led, readErr := peerImportLedger(plan, info, why, s.startedAt)
	if led != nil && readErr == nil {
		captureSource.mu.Lock()
		// ★ 顶进「当前那本账」：界面上「看表」那一栏不许因为包是从对端来的就走另一套口径。
		//   但本机正在跑的那一路不许被顶掉 —— 顶掉了那颗「停」就找不回原来的采集口。
		if captureSource.run == nil || captureSource.run.finished() {
			captureSource.ledger = led
		}
		captureSource.mu.Unlock()
		v.Values["packets"] = led.packets
	}

	switch v.Code {
	case capPeerStoppedForced:
		v.Note = fmt.Sprintf("那一路上面打招呼（SIGINT）不听，等到超时才硬断的：%s。\n"+
			"★ 硬断没有「退出」那一下，采集器打不出那本账，**那份文件末尾可能短一截**，丢包也说不出。"+
			"别按「这就是全部」用。", s.what())
	case capPeerStoppedNoCounts:
		v.Note = fmt.Sprintf("停了：%s。★ 对端退出时没报那本账，包数只能从文件里数，"+
			"**丢没丢说不出来** —— 这一档不许说成「一包没丢」。", s.what())
	case capPeerVerifyMismatch:
		v.Note = fmt.Sprintf("停了也取回来了，但★ 本机这份的整包摘要与对端那份**对不上**（%s）："+
			"别拿这份下结论：要么重抓要么重取一次，要么在对端直接看那一份。", tf.Verified)
	default:
		v.Note = fmt.Sprintf("停了：%s（%s）。对端报了 %d 包收到、%d 包被内核丢掉。",
			s.what(), whyClausePeer(why), info.Captured, info.Dropped)
	}
	if info.Dropped > 0 {
		v.Note += fmt.Sprintf("\n★ 内核在那台机器上丢了 %d 包（环满了，不是网络慢）——"+
			"「重传很少」这类结论在这个口径下作废，先把对端的负载降下来或换一块口再抓一次。",
			info.Dropped)
	}
	if readErr != nil {
		v.Note += "\n★ 取回来的那份读不动：" + scrubOne(readErr.Error()) +
			"（这一份的表出不了，但文件在本机 " + plan.local + "）"
	}
	switch {
	case plan.keepPeer:
		v.Values["peerRemoved"] = false
		v.Note += "\n按 keepPeer 留着了对端那一份：" + peerLeftBehind(run) +
			"（原始包，含明文口令）—— 那台机器上的东西不归我们清，用完自己删。"
	case v.Code == capPeerVerifyMismatch:
		v.Values["peerRemoved"] = false
		v.Note += "\n★ 校验没对上的这一份，对端原件没敢删，还留着：" + peerLeftBehind(run)
	default:
		// ★ 删的时候要连 Windows 那一份 .etl 一起删（run.EtlPath 在 POSIX 那一路是空的，
		//   remote.RemovePeerFiles 会把空的滤掉）：转好的 pcapng 取回来了，那原件 .etl 就是
		//   第二份躺在别人盘上的原始包，不留干净等于把口令团体名丢在现场。
		if err := s.removeFn(ctx, conn.x, conn.d, run.PeerFile, run.PeerLog, run.EtlPath); err != nil {
			v.Values["peerRemoved"] = false
			v.Values["peerLeft"] = peerLeftBehind(run)
			v.Note += "\n★ 对端那几份没删掉（" + scrubOne(err.Error()) +
				"）：原始包还留在那台机器上，得自己去收。"
		} else {
			v.Values["peerRemoved"] = true
			v.Note += "\n对端那几份已删（" + peerLeftBehind(run) + "）。"
		}
	}
	v.Note += "\n★ 取回来的这份是原始包：发给谁就等于把明文口令发给了谁，" +
		"要给人看结论就发 net.capture.flows 那张表（脱过敏的）。"
	v.Values["next"] = peerNextStep(v.Code, run.PeerFile)
	v.Note += "\n下一步：" + v.Values["next"].(string)

	_ = journal.MarkReverted(jid, fmt.Sprintf("对端已停（%s），本机这份 %s", why, plan.local))
	mgr.Audit(ots.CallerFrom(ctx), "capture-peer.stop", conn.d.ID,
		fmt.Sprintf("%s → %d 包 / %d 字节（%s）", plan.iface, info.Captured, tf.Bytes, why), v.Code)
	conn.close()
	s.record(&v)
	if led != nil {
		s.mu.Lock()
		s.led = led
		s.mu.Unlock()
	}
	return v
}

// peerStopWait：已经知道那一路自己退了或联系不上了，就别再等它打招呼。
func peerStopWait(why string) time.Duration {
	if why == capWhyPeerDied || why == capWhyPeerLost {
		return 500 * time.Millisecond
	}
	return peerDefaultCloseWait
}

func (s *peerSession) record(v *ots.Verdict) {
	s.mu.Lock()
	s.result = v
	s.settled = true
	s.mu.Unlock()
	close(s.done)
}

// peerImportLedger 把取回来的那一份读成一张表。★ 走的正是本机那一路同一套读取与聚合
// （readInto + flow.Table），差别只在 origin 记成 "peer"。
func peerImportLedger(plan peerPlan, info *remote.PeerStopInfo, why string, startedAt time.Time) (*captureLedger, error) {
	f, err := os.Open(plan.local)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	led := &captureLedger{
		origin:    "peer",
		path:      plan.local,
		table:     flow.NewTable(flow.Options{}),
		startedAt: startedAt,
	}
	n, err := readInto(led, f, capOpenDefaultPackets)
	led.packets = n
	led.stoppedAt = time.Now()
	led.stopWhy = why
	if info.Dropped > 0 {
		led.dropped = uint64(info.Dropped)
		led.hasDropCnt = true
		led.lossy = true
	}
	if err != nil {
		led.writeErr = err.Error()
		return led, err
	}
	if n >= capOpenDefaultPackets {
		led.partialRead = true
	}
	return led, nil
}

// ── net.capture.peer.status ──

var peerCaptureStatusTool = ots.Tool{
	Name:  "net.capture.peer.status",
	Class: ots.ClassRead,
	Summary: "现在有没有一路远程抓包在跑：跑在哪台哪个口、对端那份文件在哪、已经写了多大、" +
		"上一次问到是什么时候。\n" +
		"★ 没在跑的时候同样要说清上一次那份账还在不在（本机这份、对端那份、为什么停的）—— " +
		"「抓完了停在那儿」和「压根没起过」是两件事，前者回去看表就行。\n" +
		"自动停的会点名是哪一种：人停的、到时长、到量、对端那一路自己退了、还是跟它失去了联系。" +
		"「对端自己死了」和「通道断了」的下一步完全不同，不许合成一句「停了」。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: statusPeerCapture,
}

func statusPeerCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	peerSource.mu.Lock()
	s := peerSource.session
	peerSource.mu.Unlock()
	if s == nil {
		next := peerNextStep(capPeerNoSession, "")
		return ots.Verdict{Code: capPeerNoSession, Values: map[string]any{
			"running": false, "next": next,
		}, Note: "手上没有一路远程抓包。" + next}, nil
	}
	if s.closing() {
		return peerStoppingVerdict(s), nil
	}
	if !s.finished() {
		return peerRunningVerdict(s, ""), nil
	}
	s.mu.Lock()
	v := s.result
	s.mu.Unlock()
	if v == nil {
		return ots.Verdict{Code: capPeerNoSession, Values: map[string]any{"running": false},
			Note: "上一路远程抓包收过口了，但那一次的账没留下"}, nil
	}
	out := *v
	out.Values = map[string]any{}
	for k, val := range v.Values {
		out.Values[k] = val
	}
	out.Values["running"] = false
	return out, nil
}

// ── net.capture.peer.stop ──

var peerCaptureStopTool = ots.Tool{
	Name:  "net.capture.peer.stop",
	Class: ots.ClassMutate,
	Summary: "停掉对端那一路抓包：先打 SIGINT（tcpdump 会收尾并把那本账打在 stderr 上），" +
		"等它自己走；到点没走才 SIGKILL，并明写这一路没打出账、文件可能短一截。\n" +
		"停了以后用 SFTP 把那份取回本机、读成一张表（和 net.capture.* 同一张），" +
		"默认再把对端那两份删掉 —— 那是原始包，含明文口令与团体名，留在别人机器上而我们这边已经有了。\n" +
		"★ keepPeer=true 才不删，且会把那份还在对端哪儿原样写出来。\n" +
		"取不回来（设备没开 SFTP）单独成一档：包已经停了，但那份还在现场那台机器上，" +
		"下一步会说清楚路径与怎么接着用。校验对不上的那份不许当整份用。",
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Device   string `json:"device"`
			KeepPeer bool   `json:"keepPeer"`
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		s := "停掉对端正在抓的那一路包，把那份取回本机"
		if strings.TrimSpace(a.Device) != "" {
			s += "（" + strings.TrimSpace(a.Device) + "）"
		} else {
			peerSource.mu.Lock()
			cur := peerSource.session
			peerSource.mu.Unlock()
			if cur != nil {
				s += "（" + cur.what() + "）"
			} else {
				s += "（当前那一路）"
			}
		}
		if a.KeepPeer {
			s += "。★ 这一条说了 keepPeer：对端那一份原始包**不删**，留在现场那台机器上"
		} else {
			s += "。★ 取回之后会把对端那两份删掉（原始包不该留在别人机器上）"
		}
		return s
	},
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "keepPeer": {"type": "boolean",
	      "description": "取回之后**不删**对端那一份和那份日志。★ 默认删；要留着给别人接着看的，一定要在这里明写，结果里会把路径原样报出来"}
	  }
	}`),
	Invoke: stopPeerCapture,
}

func stopPeerCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		KeepPeer bool `json:"keepPeer"`
	}
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	peerSource.mu.Lock()
	s := peerSource.session
	ledger := captureSource.ledger
	peerSource.mu.Unlock()
	if s == nil {
		if ledger != nil && ledger.origin == "peer" {
			v := captureLedgerValues(ledger)
			v["running"] = false
			return ots.Verdict{Code: capPeerStopped, Values: v,
				Note: fmt.Sprintf("没有正在跑的这一路了，上一次从对端来的那份账还在：%s（%d 包）。"+
					"表就是它，直接 net.capture.flows 问。", ledger.path, ledger.packets)}, nil
		}
		next := peerNextStep(capPeerNoSession, "")
		return ots.Verdict{Code: capPeerNoSession, Values: map[string]any{"running": false, "next": next},
			Note: "没有正在跑的远程抓包。" + next}, nil
	}
	if s.finished() {
		s.mu.Lock()
		v := s.result
		s.mu.Unlock()
		if v != nil {
			out := *v
			return out, nil
		}
		return ots.Verdict{Code: capPeerNoSession, Values: map[string]any{"running": false},
			Note: "这一路已经收过口了，但那一次的账没留下"}, nil
	}
	if s.closing() {
		// ★ 收口已经在走了，这时候改 keepPeer 也没人去读它 ——
		//   那一口已经在删对端那两份了，不能让它以为改成不删了。
		return peerStoppingVerdict(s), nil
	}
	s.mu.Lock()
	s.keepPeerLive = a.KeepPeer || s.keepPeerLive
	s.mu.Unlock()
	return s.stop(ctx, capWhyUser), nil
}

// ── 说法 ──

func peerVerdict(code, reason, device, said string) ots.Verdict {
	clean, _ := diag.Scrub(firstLineOfPeer(said))
	next := peerNextStep(code, "")
	v := map[string]any{
		"reason":   reason,
		"peerSaid": clean,
		"device":   device,
		"next":     next,
		"platform": runtime.GOOS,
	}
	note := reason
	if device != "" {
		note = fmt.Sprintf("%s：%s", device, reason)
	}
	if clean != "" {
		note += "\n对端自己说：" + clean
	}
	note += "\n下一步：" + next
	return ots.Verdict{Code: code, Values: v, Note: note}
}

// peerNextStep 是这一栏唯一那句「所以呢」。★ 每一种都得指着一个能做的动作，
// 而且不同档指的动作必须不同 —— 指成同一句，人就只会重复点同一个按钮。
func peerNextStep(code, peerFile string) string {
	switch code {
	case capPeerReady:
		return "接着 net.capture.peer.start，interface 就点上面列表里那一个（别从本机网卡名猜）"
	case capPeerNoCollector:
		return "在那台机器上装采集器（Linux：apt/yum 装 tcpdump，或改用抓好的文件），" +
			"或者干脆在本机 net.capture.start 抓这一端；实在要在那台上抓就用它自己带的采集命令"
	case capPeerNoIfaceList:
		return "口名没核过：先在那台上跑一句 tcpdump -D 看名字，再点名开 net.capture.peer.start。" +
			"★ 别拿本机网卡名当那边能用"
	case capPeerRunning:
		return "看一眼对端写了多大用 net.capture.peer.status；要那张表就得先 net.capture.peer.stop 取回来 —— " +
			"包在对端的盘上长，本机这张表只有取回之后才有"
	case capPeerStopping:
		return "等这一步走完再问 net.capture.peer.status（那份大的时候要传一会儿）。" +
			"★ 中间别开第二路抓包、也别对着同一台再按一次停 —— 现在这一路还没落账，" +
			"新的那一路会跟它抢同一个改动账本"
	case capPeerStopped:
		return "表已经在当前这本账上，直接 net.capture.flows 问；要那份原始包的路径就在 file 那一格"
	case capPeerStoppedForced:
		return "这一路没打出账：先看 file 那份的包数（net.capture.flows），" +
			"并把它当成**可能少了一截**的一份用；要完整的就重抓一次并早点 net.capture.peer.stop"
	case capPeerStoppedNoCounts:
		return "对端没报账，丢没丢说不出：结论要写成「不知道丢没丢」，" +
			"别写成「没丢」。要那份的账就在那台上直接看采集器的输出"
	case capPeerPullFailed:
		if peerFile == "" {
			peerFile = "对端那份"
		}
		return "那份还在对端：" + peerFile + "。★ 那台机器上取：给它开 SFTP 子系统（OpenSSH 默认带）" +
			"或换一台能取的，或者把文件人工拷过来后用 net.capture.open 打开 —— 表是同一张。" +
			"别忘了那一路的进程可能已经退了，但文件不会跟着消失"
	case capPeerVerifyMismatch:
		return "整包摘要对不上：这份只能当线索不能当结论。重取一次（先删本机那份），" +
			"或者在对端直接算一遍 sha256 跟这边对；对不上之前别把这份发出去给人看"
	case capPeerNoSession:
		return "先 net.capture.peer.probe 问那台上有什么，再 net.capture.peer.start 点名开一路"
	case capPeerUnsupportedOS:
		// ★ 这一档现在说的是「那台系统没探明」，不是「Windows 不支持」—— Windows 已经走 pktmon 接上了。
		return "先 remote.device.probe 把那台的系统探出来（这一档认 Windows / Linux / macOS：Windows 走 pktmon，" +
			"其余走 tcpdump）。探不出是通道或认证的问题，先把 ssh 走通再说"
	case capPeerNoEtl2Pcap:
		return "那台的 pktmon 太老，缺 etl2pcap（Win10 1809 / Server 2019 起才有）：把那份系统升上去，" +
			"或在那台手动 etl2pcap 转成 pcapng 再传过来用 net.capture.open 打开 —— 表是同一张；" +
			"再不行就本机 net.capture.start 抓这一端"
	case capPeerConvertFailed:
		if peerFile == "" {
			peerFile = "那一份 .etl"
		}
		return "包已经在对端的 " + peerFile + " 里（那是唯一原件，没敢删）：到那台上手动补一句 " +
			"pktmon etl2pcap \"" + peerFile + "\" --out 目标.pcapng，再把 pcapng 传过来 net.capture.open 打开；" +
			"★ 别在那台把 .etl 删了再来找 NetKit 要 —— 转没成之前它就是唯一的一份"
	case capPeerBusy:
		return "那台已经有一路 pktmon 在录（全机器只能一路）：先在那台 `pktmon stop` 掉那一录" +
			"（可能是同事的现场，问过再停），或等它结束再 net.capture.peer.start。" +
			"★ 我们不去替你 stop 别人那一录 —— 那可能正是人家要抓的东西"
	case capPeerFilterUnsupported:
		return "pktmon 这一档不吃 BPF（它另有 `pktmon filter add` 那套，只按端口/IP 分层）：这一路先不带 filter 全抓，" +
			"回来在表上（net.capture.flows）或本机过滤；真要边抓边筛就换 Linux 对端用 tcpdump。" +
			"★ 我们没有悄悄把这句话丢掉假装全抓 —— 那是两种不同的口径"
	case capPeerStartFailed:
		return "对端没说清是哪种：去看那一本的日志（peerLog 那一格），" +
			"或者先在那台机器上手敲一句同样的 tcpdump —— 手敲能起来而这里起不来，就是通道或目录权限的事"
	case capPeerNoPriv:
		return "换 root 或带 CAP_NET_RAW 的账号再连一次（remote.device.add 里的凭据），" +
			"或者让那台机器上有权的人抓一份传过来。★ 提权这件事得由现场的人点头，我们不动别人的机器"
	case capPeerNoIface:
		return "先 net.capture.peer.probe 看那台报出来的口名，再点名 —— 名字对不上通常是虚拟口、" +
			"绑定口或者那台已经把这块口下了"
	case capPeerBadFilter:
		return "过滤器那句话按 BPF 语法改（如 tcp port 554、host 10.0.0.9 and port 8000）。" +
			"★ 别把它当没流量：筛错条件比不筛更容易得出反的结论"
	case capPeerDied:
		return "看 peerSaid 那句原文；最常见是那份文件落不了盘（对端目录不可写）或那台上采集器被包过。" +
			"换一块口、换个目录或者在本机抓这一端"
	case capPeerStuck:
		return "那一卡在既不退出也不继续：先 net.capture.peer.stop（它会硬断并明写文件可能短一截），" +
			"再去那台机器上看那个进程还在不在 —— 在对端留一个没人收的采集是最难查的账"
	case capPeerConn:
		return "先 remote.device.probe 确认通道还通不通（认证、主机密钥、地址），再重开这一路。" +
			"★ 通道断了不等于对端停了：那一路很可能还在写，那份文件也还在"
	}
	return "先 net.capture.peer.status 看一眼，再决定是重开还是回到本机抓"
}

func whyClausePeer(why string) string {
	switch why {
	case capWhyUser:
		return "人停的"
	case capWhyDuration:
		return "到了自己定的时长"
	case capWhyMaxBytes:
		return "★ 到了文件大小上限（**不是没流量了**，后面还有包没进来）"
	case capWhyPeerDied:
		return "★ 对端那一路自己退了（没等我们打招呼）—— 去看对端那句话说的什么原因"
	case capWhyPeerLost:
		return "★ 是这边跟它失去了联系（连着三次问不出话），不是它停了"
	}
	return why
}

// peerLeftBehind 把「收口后还留在对端的那几份」列成一句人话。★ POSIX 那一路只有
// pcap + log；Windows 那一路是 pcapng + .etl（log 那格是空的，滤掉）。不分流的话，
// Windows 这一路会说「那一份已删」而那份 .etl（唯一原件）还在别人盘上。
func peerLeftBehind(run *remote.PeerRun) string {
	var keep []string
	for _, p := range []string{run.PeerFile, run.PeerLog, run.EtlPath} {
		if p != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, " 与 ")
}

func firstLineOfPeer(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	r := []rune(s)
	if len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

func redactedHow(m map[string]int) string {
	total := 0
	var parts []string
	for k, n := range m {
		total += n
		parts = append(parts, fmt.Sprintf("%s %d", k, n))
	}
	if total == 0 {
		return "没抹掉任何东西（对端那句话里本来就没有凭据的形态）"
	}
	return fmt.Sprintf("共抹掉 %d 处（%s）：键名留着、值换成掩码 —— 那是「带了但没给你看」，不是「没带」",
		total, strings.Join(parts, "、"))
}

// scrubOne 给「只有一句」的自由文本脱敏（错误、对端原话）。
func scrubOne(s string) string {
	clean, _ := diag.Scrub(strings.TrimSpace(s))
	return clean
}

// ── 悬账 ──

// restorePeerCapture 收上次没停的对端抓包账。
//
// ★★ 和本机那一路最不一样的一点：本机的采集口随进程一起没了，这句话就能照说；
//
//	对端那一路是别人机器上的一个进程，**我们重启不等于它停**。
//	说成「已随上次进程退出而关」就是把人支去查一件根本不成立的事，
//	而真相是那台上可能还在往盘上写原始包。所以这里只报「不归我们管了」，
//	并把设备与那份文件的路径原样印出来。
func restorePeerCapture(log *slog.Logger) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind != peerJournalKind {
			continue
		}
		var after struct {
			Device   string `json:"device"`
			PeerFile string `json:"peerFile"`
		}
		_ = json.Unmarshal(e.After, &after)
		log.Warn("上次退出时那一路远程抓包没有正常收口 —— 对端那个进程不随本进程退出，得自己去那台机器上看",
			"改动", e.What, "设备", after.Device, "对端文件", after.PeerFile,
			"时间", e.At.Format(time.RFC3339))
		_ = journal.MarkReverted(e.ID, fmt.Sprintf(
			"进程重启：这一路不归本进程管了，对端 %s 上那个采集可能还在跑、文件还在 %s",
			after.Device, after.PeerFile))
	}
}
