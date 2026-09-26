package tools

// ── net.capture.* ──
//
// ★★ 这一格要守住的第一条：**落盘的那一份和给人看的那一张表，是两种东西。**
//
//	文件里必须是原始包 —— 现场抓包的全部意义就是「别人怎么发的我就怎么收到」。
//	写进文件之前先洗一遍，Wireshark 打开来就是一份被改过的证据；
//	拿去跟同事对、跟设备厂商对，对不上的那一句会整个人担着。
//	而表（发给界面、发给 AI、打进诊断包的那一份）反过来必须脱敏：
//	凭据的值一个字节都不出去，只留「带没带、多长」（口径见 internal/flow/redact.go）。
//	所以两头都要说清：停的时候明写「文件里有明文口令，别整份往外贴」，
//	出表的时候明写「这张表脱过敏，看不到凭据不代表设备没带」。
//
// ★ 一路只允许一个在跑，和文件共享、对测口、质量监测同一个理由：界面上那颗「停」
//   必须只对应一件事。抓包这一路还更硬 —— 两路同时往一台机器写原始包，
//   现场没人说得清哪一份是哪一路的。
//
// ★ 到量自动停与「没包了」必须分开。抓包是个会自己长个的东西：不给上限，它会一路写到
//   把盘写满，而那台机器往往是现场唯一能登录的；给了上限却不区分「到顶了」和
//   「这条链路上真的没流量」，人就拿着半截文件下结论。所以这两种各有说法。
//
// ★ 丢包有三种口径，谁都不许冒充谁：内核报了具体包数、内核只标过「这一路丢过」
//   但给不出数、以及这一档压根给不出凭据。第三种最要紧 —— 界面必须敢写「说不出丢没丢」。
//   把「一个包都没丢」当成默认答案，是把环开小了的罪记到链路上。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"net.yuhox.com/netkit/internal/capture"
	"net.yuhox.com/netkit/internal/flow"
	"net.yuhox.com/netkit/internal/ots"
)

// 判定码。★ 每个码对应界面上一种说法和一个下一步，码不许合并。
const (
	capRunning     = "capture-running"         // 正在收，没听到内核报丢包
	capLossy       = "capture-running-lossy"   // 正在收，但内核已经报了丢包：环小了
	capIdle        = "capture-idle"            // 没在跑（同时说清上一次的账还在不在）
	capStopped     = "capture-stopped"         // 刚停完，带这一份的账
	capNoPriv      = "capture-no-privilege"    // 这一档要提权，现在起不来
	capUnsupported = "capture-unsupported"     // 这个平台没有现场抓这一档（读文件还是行的）
	capFilterOn    = "capture-filter-present"  // 场上挂着别人下的筛选器，这一档不替你删
	capNoIface     = "capture-no-interface"    // 点名的口在这台机器上没有
	capFlows       = "capture-flows"           // 表出来了，逐条流各带自己的判定
	capNoPackets   = "capture-no-packets"      // 一个包都没收到（几种可能分开列）
	capNoFlows     = "capture-no-flows"        // 收到包了，但归不出一条流
	capNothing     = "capture-no-session"      // 没在跑、也没有上一次的账、也没导入过文件
	capNoFlow      = "capture-no-flow"         // key 指的那一条流不在当前这张表上
	capFileBad     = "capture-file-unreadable" // 那不是抓包文件，或者半路上读不动
)

// 自动停下来的那几种原因。★ 必须进结果：「停了」这一件事如果没有原因，
// 界面就只能让人自己猜是哪种。
const (
	capWhyUser     = "user"      // 人调 net.capture.stop 停的
	capWhyDuration = "duration"  // 到了自己定的时长
	capWhyMaxBytes = "max-bytes" // 到了文件大小上限
	capWhyIOError  = "io-error"  // 读包或写文件出错（盘满、口被外力关掉）
	capWhyStuck    = "close-timeout"
)

const (
	capDefaultSnapLen = capture.DefaultSnapLen
	// capMaxSnapLen 是上限不是建议值：留全帧在百兆链路上几秒就吃掉一个环，
	// 那种口径要人明确写出来。
	capMaxSnapLen = 65535
	// capDefaultFileMaxMB 到量自动停。256MB 是「够查一次点播对不上号」与
	// 「不会把现场那台机器的盘挤掉」之间的那一档：全帧 1500 字节下约 18 万包。
	capDefaultFileMaxMB = 256
	capMaxFileMB        = 4096
	// capMaxSeconds 一次最长盯一小时。再久该用持续监测那一类工具，而不是拿抓包当录像。
	capMaxSeconds = 3600
	// capDefaultFlows 表上默认给多少条流。★ 只给前 N 条这件事一定另外写出来，
	// 不许让人以为整张表就这些。
	capDefaultFlows = 60
	capMaxFlows     = 500
	// capOpenDefaultPackets 导入一份文件默认最多读这么多包：读多少报多少，
	// 因为「这张表的结论」只对读到的那一段成立。
	capOpenDefaultPackets = 200000
	capOpenMaxPackets     = 2000000
	// capCloseWait 等采集口把最后几包交出来并退出的时间。★ 到点不回来也要把账收口：
	// 一份没写完尾的 pcapng 还能读，一个永远转圈的界面不能。
	capCloseWait = 5 * time.Second
)

// captureDir 是抓包文件的落盘目录。空 = 找不到用户配置目录，那一档直接拒起
// （一份记不下来的抓包等于没抓）。
var captureDir string

// SetCaptureDir 装进落盘目录（由 main 在启动时调）。
func SetCaptureDir(dir string) { captureDir = dir }

type captureArgs struct {
	Interface     string `json:"interface,omitempty"`
	SnapLen       int    `json:"snapLen,omitempty"`
	BufferMB      int    `json:"bufferMB,omitempty"`
	Promisc       bool   `json:"promisc,omitempty"`
	BlockRetireMS int    `json:"blockRetireMs,omitempty"`
	Seconds       int    `json:"seconds,omitempty"`
	MaxMB         int    `json:"maxMB,omitempty"`
	File          string `json:"file,omitempty"`
}

// capturePlan 是定下来的一次采集口径。★ 校验与默认值只这一处：Describe（批准框里
// 那句「这次到底要改什么」）与 Invoke 各算一遍，迟早给出两种说法。
type capturePlan struct {
	iface       string
	snapLen     int
	buffer      int
	promisc     bool
	blockRetire time.Duration
	seconds     int
	maxBytes    int64
	file        string
}

func captureTiming(a captureArgs) (capturePlan, error) {
	p := capturePlan{
		iface:       strings.TrimSpace(a.Interface),
		snapLen:     a.SnapLen,
		buffer:      capture.DefaultBufferSize,
		promisc:     a.Promisc,
		blockRetire: capture.DefaultBlockRetire,
		seconds:     a.Seconds,
		maxBytes:    int64(capDefaultFileMaxMB) << 20,
		file:        strings.TrimSpace(a.File),
	}
	if a.SnapLen < 0 || a.BufferMB < 0 || a.BlockRetireMS < 0 || a.Seconds < 0 || a.MaxMB < 0 {
		// ★ 负数是「明确要一个不可能的值」，当场拒。悄悄换成默认值会把
		// 「参数写错了」演成「这台机器就这样」，人下次还这么填。
		return p, fmt.Errorf("snapLen / bufferMB / blockRetireMs / seconds / maxMB 都不能是负数")
	}
	if p.snapLen == 0 {
		p.snapLen = capDefaultSnapLen
	}
	if p.snapLen > capMaxSnapLen {
		return p, fmt.Errorf("snapLen 最多 %d（再大就是拿抓包当录像，环几秒就满）", capMaxSnapLen)
	}
	if a.BufferMB > 0 {
		p.buffer = a.BufferMB << 20
	}
	if a.BlockRetireMS > 0 {
		p.blockRetire = time.Duration(a.BlockRetireMS) * time.Millisecond
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
	if p.file != "" && !filepath.IsAbs(p.file) {
		// ★ 路径这类事要在开采集口**之前**问完：Windows 那一档开一次口是要动系统状态的
		//   （起 pktmon 会话），不能为了一个写错的文件名去动一次别人的机器。
		return p, fmt.Errorf("file 要给完整路径（现在是 %q）", a.File)
	}
	return p, nil
}

// ── 一份能看的账 ──

// captureLedger 是一份抓包的账：正在跑的那一路、上一次停掉的那一路、
// 或者导入进来的那一个文件，三种都用这一个形状。
//
// ★ 三种来源共用一个形状不是省事：界面「看表」那一栏不许关心包是从网卡上接的还是
// 从磁盘上读的 —— 同一台设备在两张口径不同的表上给出两个结论，是最难查的那种分歧。
type captureLedger struct {
	origin    string // live / file
	path      string
	plan      capturePlan
	table     *flow.Table
	ifaces    []capture.Interface
	packets   int
	bytes     int64
	startedAt time.Time
	stoppedAt time.Time
	stopWhy   string
	writeErr  string
	// 丢包的三种口径。hasDropCount=false 且 lossy=false 时，界面必须写「说不出丢没丢」，
	// 不许把 dropped=0 当成「没丢」。
	dropped    uint64
	hasDropCnt bool
	lossy      bool
	// 只读了文件前一段：★ 报出来，不然半截文件的结论会被当成整份的。
	partialRead bool
}

var captureSource = struct {
	mu     sync.Mutex
	run    *captureRun
	ledger *captureLedger
}{mu: sync.Mutex{}}

// captureRun 是一份开着的抓包：采集口 + pcapng 写手 + 那本账。
//
// 状态统一由 captureSource.mu 护着。★ 写文件与更新表必须在同一次加锁里做完：
// 分开就会出现「文件里 100 包、表上 87 包」，那种数差一次就让人怀疑整张表，
// 而正确的解释只是「读的一瞬间还没攒完」。
type captureRun struct {
	plan    capturePlan
	journal string

	src    capture.Source
	wr     *capture.Writer
	file   *os.File
	led    *captureLedger
	done   chan struct{}
	cancel context.CancelFunc

	closed atomic.Bool // 采集口关没关：收包那一路每包都要读它，不能去抢 wantWhy 那把锁

	mu      sync.Mutex
	wantWhy string // 停的理由（定时器或 stop 先记下来，退出那一路 finish 时照着写）
	done0   bool   // finish 走过了 —— 只有一个收口的人，账才只结一次
}

// captureOpen 起一个采集口。★ 做成包级变量只有一个理由：判定层要用一路假的包
// 钉住每一种判定，而不是依赖跑测试这台机器此刻有没有提权。
var captureOpen = func(opt capture.Options) (capture.Source, error) { return capture.OpenSource(opt) }

func (r *captureRun) loop() {
	defer close(r.done)
	for {
		p, err := r.src.Next()
		if err != nil {
			if errors.Is(err, capture.ErrClosed) {
				r.finish(err)
				return
			}
			r.finish(err)
			return
		}
		captureSource.mu.Lock()
		if r.closed.Load() {
			// ★ Close 之后不再递包：口正在关的时候拿到的那一包写进文件，
			// 就成了「文件里多出一包，表上没有」。
			captureSource.mu.Unlock()
			return
		}
		// ★ 口表要跟着这一路长：采集口是「见到一块登记一块」（多口抓包时，第二块口
		//   往往晚于第一块才 up），包上的口序号一旦超过手上那份口表，表就把那些包
		//   整个扔掉 —— 而扔掉之后表上一切正常，只是「没有流量」。
		//   只在序号越界那一下才去问一次，常见路径上不多花一次调用。
		if p.InterfaceIndex >= len(r.led.ifaces) {
			if ifs := r.src.Interfaces(); len(ifs) > len(r.led.ifaces) {
				r.led.ifaces = ifs
				r.led.table.SetInterfaces(ifs)
			}
		}
		r.led.packets++
		r.led.bytes += int64(len(p.Data))
		var writeErr error
		if writeErr = r.wr.WritePacket(p.InterfaceIndex, p.Timestamp, p.Data, p.OrigLen); writeErr == nil {
			writeErr = r.wr.Flush()
		}
		if writeErr != nil {
			r.led.writeErr = writeErr.Error()
		}
		_ = r.led.table.Add(p)
		over := r.led.bytes >= r.plan.maxBytes
		badWrite := r.led.writeErr
		captureSource.mu.Unlock()
		if badWrite != "" {
			r.finish(errors.New(badWrite))
			return
		}
		if over {
			r.requestStop(capWhyMaxBytes)
			r.finish(nil)
			return
		}
	}
}

// requestStop 请这一路收手：记下理由，再把采集口关掉，让正堵在 Next 上的那一路退出来。
func (r *captureRun) requestStop(why string) {
	r.mu.Lock()
	if r.wantWhy == "" {
		r.wantWhy = why
	}
	r.mu.Unlock()
	// ★ 只关一次：到时长与到人停同时伸手时，第二次 Close 会把另一路正在用的口关掉。
	if r.closed.CompareAndSwap(false, true) {
		_ = r.src.Close()
	}
}

// finish 是唯一收口的地方：落账、关文件、把这一路挪到「上一次的账」。
func (r *captureRun) finish(err error) {
	r.mu.Lock()
	if r.done0 {
		r.mu.Unlock()
		return
	}
	r.done0 = true
	why := r.wantWhy
	r.mu.Unlock()
	if why == "" {
		switch {
		case err != nil && !errors.Is(err, capture.ErrClosed):
			why = capWhyIOError
		default:
			why = capWhyDuration
		}
	}

	captureSource.mu.Lock()
	if r.closed.CompareAndSwap(false, true) {
		_ = r.src.Close()
	}
	r.led.stoppedAt = time.Now()
	if r.led.stopWhy == "" {
		r.led.stopWhy = why
	}
	// ★ 关口之前那一格的账要拿走：口一关，这一档的丢包计数在许多平台上就归零了，
	//   停完之后再来问「这一路丢了几包」只能得到一个说不出话的 0。
	st := r.src.Stats()
	r.led.dropped, r.led.hasDropCnt, r.led.lossy = st.Dropped, st.Dropped > 0, st.Lossy
	if err != nil && !errors.Is(err, capture.ErrClosed) && r.led.writeErr == "" {
		r.led.writeErr = err.Error()
	}
	if r.file != nil {
		_ = r.wr.Flush()
		_ = r.file.Close()
	}
	captureSource.ledger = r.led
	if captureSource.run == r {
		captureSource.run = nil
	}
	packets := r.led.packets
	path := r.led.path
	captureSource.mu.Unlock()

	if r.cancel != nil {
		r.cancel()
	}
	if r.journal != "" {
		_ = journal.MarkReverted(r.journal,
			fmt.Sprintf("抓包已停（%s）：共 %d 包，文件 %s", why, packets, path))
	}
}

// waitFor 等这一路的 goroutine 真退出；等不到回 true（调用方要如实说）。
func (r *captureRun) waitFor(d time.Duration) bool {
	select {
	case <-r.done:
		return true
	case <-time.After(d):
		return false
	}
}

// ── net.capture.start ──

var captureStartTool = ots.Tool{
	Name:  "net.capture.start",
	Class: ots.ClassMutate,
	Summary: "在本机开一路抓包：所有网卡（或点名的那一块）上的每一个包都原样落到一个 pcapng 文件里，" +
		"同时按流聚合成一张表。★ 默认就抓全帧（一包 1600 字节），因为「半截报文」是最难查的" +
		"一种假象 —— 长度看着对，内容却是空的。\n" +
		"★ 三种「起不来」是分开的：capture-no-privilege（要 root / CAP_NET_RAW / 管理员）、" +
		"capture-unsupported（这个平台没有现场抓这一档，只能读现成的文件）、" +
		"capture-filter-present（这台机器上挂着别人下的筛选器 —— 这一档绝不替你删，" +
		"那种「先清掉省事」的写法会把他人的采集一起抹了）。点名的口没有直接报 " +
		"capture-no-interface，绝不悄悄退化成「那就全抓」：现场最常见的误判就是抓了半天" +
		"没有对方的包，因为抓的是另一块网卡。\n" +
		"★ 到量（默认 256MB）与到时长各自停下来，结果里写清是哪一种：「到顶了」和" +
		"「这条链路真的没流量」是两种相反的下一步。丢包三种口径不混：报了包数、只说丢过、说不出。\n" +
		"★ 文件里是原始包，含明文口令与团体名；发给界面与 AI 的表是脱敏的。停下来的时候" +
		"会把这句原样给你一次，别把整份文件贴进群。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "interface": {"type": "string",
	      "description": "只抓这一块网卡（用 net.interfaces 里的名字）。★ 留空 = 这台机器上所有网卡，含 lo：本机服务自己连自己那一段，只有回环上抓得到。点名的网卡没有就直接报错，不会退化成全抓。"},
	    "snapLen": {"type": "integer", "minimum": 64, "maximum": 65535,
	      "description": "一包最多留多少字节，默认 1600（1500 MTU 全帧放得下）。★ 调小省地方，但正文与后面那半截字段就不可信，表上会明写有多少包被截过。"},
	    "bufferMB": {"type": "integer", "minimum": 1, "maximum": 256,
	      "description": "内核环多大，默认 4MB。★ 现场丢包十有八九是环小了，不是网络慢了：百兆口全速时 4MB 撑不到一秒。报出丢包就先把这一格调大再抓一次。"},
	    "promisc": {"type": "boolean",
	      "description": "开混杂模式：不是发给本机的帧也收。★ 它不是「抓到别人的包」的开关 —— 交换机上本来也收不到别人的单播，开了只对集线器和镜像口有意义，而且虚拟口与部分无线网卡会直接拒。"},
	    "blockRetireMs": {"type": "integer", "minimum": 10, "maximum": 5000,
	      "description": "一块攒多久就强制交给界面，默认 100ms。★ 没有这一档，低流量时会「抓到了但看不见」：包躺在没退休的块里，看着就像网络没流量 —— 这一格就是把「等不到包」和「真的没包」分开的那把刀。"},
	    "seconds": {"type": "integer", "minimum": 1, "maximum": 3600,
	      "description": "到这么久自己停，默认不停（一直抓到 net.capture.stop）。★ 挂着不停会把盘写满，而现场往往只有这一台机器能登录。"},
	    "maxMB": {"type": "integer", "minimum": 1, "maximum": 4096,
	      "description": "文件到这么大就停，默认 256MB。★ 到顶停下来会写「是到上限了，不是没流量」。"},
	    "file": {"type": "string",
	      "description": "落到哪个绝对路径（默认落在 NetKit 数据目录，文件名带时刻）。★ 已经存在的文件直接拒，不覆盖：现场那一份证据没了是不可逆的。"}
	  }
	}`),
	Describe: describeCaptureStart,
	Invoke:   startCapture,
}

func describeCaptureStart(raw json.RawMessage) string {
	var a captureArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	p, err := captureTiming(a)
	if err != nil {
		return "在本机开一路抓包（参数没定下来：" + err.Error() + "）"
	}
	s := "在本机开一路抓包："
	if p.iface == "" {
		s += "所有网卡（含回环）"
	} else {
		s += "只抓 " + p.iface
	}
	s += fmt.Sprintf("，一包留 %d 字节，环 %dMB，文件上限 %dMB",
		p.snapLen, p.buffer>>20, p.maxBytes>>20)
	if p.seconds > 0 {
		s += fmt.Sprintf("，最长 %s 自己停", humanDur(time.Duration(p.seconds)*time.Second))
	} else {
		s += "，一直抓到你调 net.capture.stop 停为止"
	}
	if captureDir == "" && p.file == "" {
		s += "。★ 找不到用户配置目录，文件没地方落 —— 这一路开不起来"
		return s
	}
	s += "。原始包落到 " + capturePath(p)
	s += "。★ 文件里是原始包，含明文口令与团体名：表脱敏，那份文件不脱敏，别整份往外发"
	return s
}

func capturePath(p capturePlan) string {
	if p.file != "" {
		return p.file
	}
	name := fmt.Sprintf("netkit-%s.pcapng", time.Now().Format("20060102-150405"))
	return filepath.Join(captureDir, name)
}

func startCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	var a captureArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	plan, err := captureTiming(a)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if journal == nil {
		// ★ 会一直占着采集口、一直往盘上写的改动记不下来，就不许开始。
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝开抓包")
	}
	if captureDir == "" && plan.file == "" {
		// ★ 这一句要早于开采集口：找不到落盘地方时，报「file 要给完整路径」
		// 会让人去改一个自己压根没填的参数，而真相是这台机器连目录都没有。
		return nil, ots.Errf(ots.ErrInternal, "找不到用户配置目录，抓包文件没地方落，拒绝开这一路")
	}
	captureSource.mu.Lock()
	running := captureSource.run != nil && !captureSource.run.finished()
	captureSource.mu.Unlock()
	if running {
		return nil, ots.Errf(ots.ErrInvalidArgument, "已经有一路抓包在跑了（文件 %s，已收 %d 包）。"+
			"先 net.capture.stop 停掉再开新的 —— 两路同时往一台机器写原始包，现场分不清哪份是哪路",
			capturePathOf(), capturePacketsOf())
	}

	src, err := captureOpen(capture.Options{
		Interface:   plan.iface,
		SnapLen:     plan.snapLen,
		BufferSize:  plan.buffer,
		Promisc:     plan.promisc,
		BlockRetire: plan.blockRetire,
	})
	if err != nil {
		return captureStartFailed(err)
	}
	// 口开出来了才定文件名：★ 起不来的时候不许留下一个 0 字节的空文件，
	// 那种文件第二天会被当成「昨天抓的没有包」，而真相是压根没抓起来。
	path := capturePath(plan)
	if path == "" {
		_ = src.Close()
		return nil, ots.Errf(ots.ErrInternal, "找不到用户配置目录，抓包文件没地方落，拒绝开这一路")
	}
	f, err := captureCreateFile(path)
	if err != nil {
		_ = src.Close()
		return nil, err
	}
	ifaces := src.Interfaces()
	wr, err := capture.NewWriter(f, ifaces)
	if err != nil {
		_ = f.Close()
		_ = src.Close()
		return nil, ots.Errf(ots.ErrInternal, "pcapng 起不了头：%s", err)
	}
	r := &captureRun{
		plan:   plan,
		src:    src,
		wr:     wr,
		file:   f,
		done:   make(chan struct{}),
		cancel: nil,
		led: &captureLedger{
			origin:    "live",
			path:      path,
			plan:      plan,
			table:     flow.NewTable(flow.Options{}),
			ifaces:    ifaces,
			startedAt: time.Now(),
		},
	}
	// ★ 口表一开头就要交给表：链路类型是按口查的，表上口表空着的时候，
	//   每一个包都会在「口表里没有这一号」上撞回去 —— 于是这一路「抓到了」而表是空的。
	r.led.table.SetInterfaces(ifaces)
	if plan.seconds > 0 {
		var cctx context.Context
		cctx, r.cancel = context.WithCancel(context.Background())
		go func() {
			select {
			case <-cctx.Done():
			case <-time.After(time.Duration(plan.seconds) * time.Second):
				r.requestStop(capWhyDuration)
			}
		}()
	}
	id, err := journal.Register("capture", describeCaptureStart(raw),
		map[string]any{"capturing": false},
		map[string]any{"interface": plan.iface, "file": path,
			"snapLen": plan.snapLen, "maxMB": int(plan.maxBytes >> 20)})
	if err != nil {
		_ = f.Close()
		_ = src.Close()
		return nil, ots.Errf(ots.ErrInternal, "这一路抓包记不进改动账本，拒绝开：%s", err)
	}
	_ = journal.MarkApplied(id)
	r.journal = id

	// ★ 先对外可见、再放 goroutine：反过来的话，采集器可能已经收了十几包而界面上
	// 还查不到「有一路在跑」，那颗「停」就慢一拍 —— 而它是唯一能收手的口子。
	captureSource.mu.Lock()
	captureSource.run, captureSource.ledger = r, r.led
	captureSource.mu.Unlock()
	go r.loop()

	return captureRunningVerdict(r, ""), nil
}

// captureCreateFile 落盘。★ O_EXCL：已经存在的名字直接拒 ——
// 现场那份抓了一半的文件被一次手滑的参数覆盖掉，是这一格里唯一不可逆的一件事。
func captureCreateFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"file 要给完整路径（现在是 %q）。★ 相对路径会落在后端自己的工作目录上，"+
				"而那个目录在现场根本没人知道在哪", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, ots.Errf(ots.ErrInternal, "开不出目录：%s", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"文件已经存在：%s —— 不覆盖别人的现场。换个名字或者先把它挪走", path)
	}
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "写不了 %s：%s", path, err)
	}
	return f, nil
}

// captureStartFailed 把起不来的那几种分开报。
//
// ★ 全按 internal error 报是一种偷懒：「没权限」的下一步是提权，
// 「场上有筛选器」的下一步是去问是谁下的（绝不能自己删），
// 「这平台没有这一档」的下一步是改成读现成的文件 —— 三种混成一句，
// 人就只会一遍遍点同一个按钮。
func captureStartFailed(err error) (any, error) {
	switch {
	case errors.Is(err, capture.ErrNeedPrivilege):
		return captureRefused(capNoPriv, err.Error(),
			"这一档要提权才起得来（Linux 要 root 或 CAP_NET_RAW，macOS 要 root，Windows 要管理员）。"+
				"这不是本机坏了：以不够的权限去问网卡，内核根本不给你那个套接字。"+
				"下一步是提权重开一次 NetKit，或者改用 net.capture.open 读一份别人抓好的文件"), nil
	case errors.Is(err, capture.ErrUnsupported):
		return captureRefused(capUnsupported, err.Error(),
			"这个平台没有现场抓包这一档，但读现成的 pcapng 完全可以：让同事在能抓的机器上抓一份，"+
				"再用 net.capture.open 打开，表是同一张"), nil
	case errors.Is(err, capture.ErrFilterPresent):
		return captureRefused(capFilterOn, err.Error(),
			"这台机器上挂着别人下的筛选器。这一档不替你删：filter remove 是全清，"+
				"会把别人正在用的采集一起抹掉。先问清这些是谁下的，要么让下来的人自己清"), nil
	case errors.Is(err, capture.ErrNoSuchInterface):
		return captureRefused(capNoIface, err.Error(),
			"点名的网卡在这台机器上没有。★ 这里没有退化成「那就全抓」是故意的 ——"+
				"那种省事会让表上永远看不到对端的包，而人一直以为是链路的问题。"+
				"先跑一句 net.interfaces 看准名字"), nil
	}
	return nil, ots.Errf(ots.ErrInternal, "%s", err)
}

func captureRefused(code, why, next string) ots.Verdict {
	return ots.Verdict{Code: code, Values: map[string]any{
		"reason": why, "next": next, "platform": runtime.GOOS,
	}, Note: why + "\n下一步：" + next}
}

func captureRunningVerdict(r *captureRun, extra string) ots.Verdict {
	st := r.src.Stats()
	code := capRunning
	if st.Dropped > 0 || st.Lossy {
		code = capLossy
	}
	captureSource.mu.Lock()
	packets, bytes := r.led.packets, r.led.bytes
	captureSource.mu.Unlock()
	vals := map[string]any{
		"interface":   r.plan.iface,
		"interfaces":  len(r.led.ifaces),
		"snapLen":     r.plan.snapLen,
		"promisc":     r.plan.promisc,
		"bufferMB":    r.plan.buffer >> 20,
		"file":        r.led.path,
		"maxMB":       int(r.plan.maxBytes >> 20),
		"seconds":     r.plan.seconds,
		"packets":     packets,
		"bytes":       bytes,
		"startedAt":   r.led.startedAt.Format(time.RFC3339),
		"dropped":     st.Dropped,
		"lossy":       st.Lossy,
		"dropAccount": captureDropAccount(st),
	}
	note := fmt.Sprintf("正在抓：%s，一包留 %d 字节，原始包落到 %s。",
		captureIfaceClause(r.plan.iface), r.plan.snapLen, r.led.path)
	note += captureDropClause(st)
	if r.plan.seconds > 0 {
		note += fmt.Sprintf("到 %s 自己停。", humanDur(time.Duration(r.plan.seconds)*time.Second))
	}
	note += "★ 文件里是原始包（含明文口令），表才是脱敏的。看表调 net.capture.flows。"
	if extra != "" {
		note = extra + "\n" + note
	}
	return ots.Verdict{Code: code, Values: vals, Note: note}
}

// captureDropAccount 说清丢包是**哪一种口径**数出来的。
// 三种状态必须能分开：数到了几包、只知道丢过、以及这一档说不出。
func captureDropAccount(st capture.Stats) string {
	switch {
	case st.Dropped > 0:
		return "counted"
	case st.Lossy:
		return "flagged-only"
	case st.Packets > 0:
		return "none-reported"
	default:
		return "unknown"
	}
}

func captureDropClause(st capture.Stats) string {
	switch {
	case st.Dropped > 0:
		return fmt.Sprintf("★ 内核报了 %d 包被丢掉（环满了，不是网络慢）。"+
			"把 bufferMB 调大或者只抓点名的那块网卡再抓一次 —— 丢的偏偏是零星那几包时，"+
			"「重传很少」这类结论就整个作废。", st.Dropped)
	case st.Lossy:
		return "★ 内核在包上标过「这一路丢过」，但给不出丢了几包（这一档平台没有那份计数）。" +
			"按「丢过量不计数」用：结论方向不变，别说「全收到了」。"
	default:
		return "内核没报丢包（这一档说不出丢没丢时，这里也只是「没报」，不等于一包没丢）。"
	}
}

func captureIfaceClause(iface string) string {
	if iface == "" {
		return "所有网卡（含回环）"
	}
	return "网卡 " + iface
}

// ── net.capture.status ──

var captureStatusTool = ots.Tool{
	Name:  "net.capture.status",
	Class: ots.ClassRead,
	Summary: "本机现在有没有在抓包：抓的是哪些网卡、已经收了几包几字节、文件落在哪、写了多大、" +
		"到没到自动停的那一档，以及丢包是哪一种口径（数到了包数 / 只知道丢过 / 说不出）。\n" +
		"★ 没在跑的时候同样要说清上一次那份账还在不在（文件、包数、为什么停的）——" +
		"「抓完了停在那儿」和「压根没抓起来」是两件事，前者回去看表就行。\n" +
		"自己停下来的会点名：到时长、到文件大小、还是读包出错。到顶与没流量必须分开说。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: statusCapture,
}

func statusCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	captureSource.mu.Lock()
	r := captureSource.run
	led := captureSource.ledger
	captureSource.mu.Unlock()
	if r != nil && !r.finished() {
		return captureRunningVerdict(r, ""), nil
	}
	if led == nil {
		return ots.Verdict{Code: capNothing, Values: map[string]any{"platform": runtime.GOOS},
			Note: "本机现在没在抓，也没有上过一次的账：net.capture.start 开一路，" +
				"或者 net.capture.open 打开一份别人抓好的文件"}, nil
	}
	vals := captureLedgerValues(led)
	vals["running"] = false
	note := fmt.Sprintf("没在抓。上一次那份账还在：%s（%d 包，%s）",
		led.path, led.packets, captureWhyClause(led.stopWhy))
	if led.writeErr != "" {
		note += "\n★ 那一路是出错停的：" + led.writeErr
	}
	note += "。表还在，直接 net.capture.flows 问。"
	return ots.Verdict{Code: capIdle, Values: vals, Note: note}, nil
}

// captureLedgerValues 是一份账对外的形状。★ 三种来路（在跑的、停掉的、导入的）都走这里，
// 界面上「看表」那一栏因此不需要分辨包是从网卡上接的还是从磁盘上读的。
func captureLedgerValues(led *captureLedger) map[string]any {
	v := map[string]any{
		"origin":      led.origin,
		"file":        led.path,
		"packets":     led.packets,
		"bytes":       led.bytes,
		"interfaces":  len(led.ifaces),
		"stopWhy":     led.stopWhy,
		"writeErr":    led.writeErr,
		"lossy":       led.lossy,
		"dropped":     led.dropped,
		"partialRead": led.partialRead,
	}
	if !led.startedAt.IsZero() {
		v["startedAt"] = led.startedAt.Format(time.RFC3339)
	}
	if !led.stoppedAt.IsZero() {
		v["stoppedAt"] = led.stoppedAt.Format(time.RFC3339)
		v["spanMs"] = led.stoppedAt.Sub(led.startedAt).Milliseconds()
	}
	return v
}

func captureWhyClause(why string) string {
	switch why {
	case capWhyUser:
		return "人停的"
	case capWhyDuration:
		return "到了自己定的时长"
	case capWhyMaxBytes:
		return "★ 到了文件大小上限（**不是没流量了**，后面还有包没进来）"
	case capWhyIOError:
		return "读包或写文件出错（先看是不是盘满了）"
	case capWhyStuck:
		return "★ 采集口在关的时候没有回音，账先收在这儿：文件末尾可能还差几包"
	case "":
		return "还在收"
	}
	return why
}

// ── net.capture.stop ──

var captureStopTool = ots.Tool{
	Name:  "net.capture.stop",
	Class: ots.ClassMutate,
	Summary: "停掉正在抓的这一路：把文件尾收好（pcapng 写完这一段，Wireshark / tcpdump 打得开），" +
		"给出这一份的账（包数、字节、时长、丢包口径）和文件路径。\n" +
		"★ 文件**不删**：那是现场证据，删文件是不可逆的，要删由人自己删。\n" +
		"这里会把风险那句原样再给一次：落盘的是原始包，里面有明文口令、SNMP 团体名、" +
		"国标平台的 digest response —— 整份文件发给谁都等于发给了谁。表（net.capture.flows）才是脱敏的。\n" +
		"没在跑的时候调它不报错，只回一句「没在抓」和上一次那份账在哪。",
	Describe: func(raw json.RawMessage) string {
		return "停掉本机正在抓的这一路包（文件保留，不删）"
	},
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: stopCapture,
}

func stopCapture(ctx context.Context, raw json.RawMessage) (any, error) {
	captureSource.mu.Lock()
	r := captureSource.run
	led := captureSource.ledger
	captureSource.mu.Unlock()
	if r == nil || r.finished() {
		if led == nil {
			return ots.Verdict{Code: capNothing, Values: map[string]any{},
				Note: "没有正在抓的这一路，也没有上一次的账"}, nil
		}
		v := captureLedgerValues(led)
		v["running"] = false
		return ots.Verdict{Code: capIdle, Values: v,
			Note: fmt.Sprintf("没在抓。上一次那份账在 %s（%d 包，%s）",
				led.path, led.packets, captureWhyClause(led.stopWhy))}, nil
	}
	r.requestStop(capWhyUser)
	if !r.waitFor(capCloseWait) {
		// ★ 采集口不回话也要把账收口：一份没写完尾的 pcapng 还能读，
		// 一个永远转圈的界面不能。这一种必须明写「末尾可能还差几包」。
		r.finish(fmt.Errorf("采集口在 Close 之后 %s 内没有退出", capCloseWait))
		v := captureLedgerValues(r.led)
		v["stopWhy"] = capWhyStuck
		return ots.Verdict{Code: capStopped, Values: v,
			Note: fmt.Sprintf("已经让它停了，但采集口在 %s 内没有回音，账先收在这儿：%s（%d 包）。"+
				"★ 文件末尾可能还差几包，别按「这就是全部」用。",
				capCloseWait, r.led.path, r.led.packets)}, nil
	}
	v := captureLedgerValues(r.led)
	v["running"] = false
	note := fmt.Sprintf("停了：%s，共 %d 包 / %d 字节，%s。文件保留在 %s。",
		captureIfaceClause(r.plan.iface), r.led.packets, r.led.bytes,
		humanDur(r.led.stoppedAt.Sub(r.led.startedAt)), r.led.path)
	if r.led.writeErr != "" {
		note += "★ 那一路写文件出过错：" + r.led.writeErr + "（文件可能不完整）"
	}
	note += "★ 这是原始包，里面有明文口令与团体名：整份文件发给谁就等于发给了谁，" +
		"要给人看结论就发 net.capture.flows 那张表（脱过敏的）。"
	return ots.Verdict{Code: capStopped, Values: v, Note: note}, nil
}

// ── net.capture.flows / net.capture.flow ──

type captureFlowsArgs struct {
	Flows int    `json:"flows,omitempty"`
	App   string `json:"app,omitempty"`
	Host  string `json:"host,omitempty"`
}

var captureFlowsTool = ots.Tool{
	Name:  "net.capture.flows",
	Class: ots.ClassRead,
	Summary: "把这一路抓包（或 net.capture.open 刚导入的那份文件）按流聚合出一张表：" +
		"每条流给端点、网卡、包数与字节、两个方向各自的账、TCP 状态、认出来的应用协议" +
		"（以及它是**按内容**还是**只按端口**认的），还有这条流自己的全部判定。\n" +
		"★ 表是整表脱敏的：凭据只留「带没带、多长」，用户名/ClientID/设备编号留着 ——" +
		"看不到口令不代表设备没带口令。\n" +
		"★ 还会给整张表那一层的口径（Table.Report）：包数账对不上、流表撞到上限、" +
		"多少包被截过、多少包没带时刻。这些不是某一条流的问题，是这份来源的问题，" +
		"混进某条流的判定里就会把人支去查一台没病的机器。\n" +
		"只给前 N 条时会明写还有多少条没列出来。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "flows": {"type": "integer", "minimum": 1, "maximum": 500,
	      "description": "最多列几条流，默认 60，按包数从多到少。★ 只给前 N 条一定另外写出来，不会让你以为整张表就这些。"},
	    "app": {"type": "string",
	      "description": "只看这一个应用协议的流（rtsp / sip / onvif / mqtt / snmp / dhcp / dns / dahua / rtp …）。"},
	    "host": {"type": "string",
	      "description": "只看端点里带这一串（IP 或 IP:port 的 IP 部分）的流。设备只有一台的时候用它把表收干净。"}
	  }
	}`),
	Invoke: captureFlowsView,
}

func captureFlowsView(ctx context.Context, raw json.RawMessage) (any, error) {
	var a captureFlowsArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Flows < 0 || a.Flows > capMaxFlows {
		return nil, ots.Errf(ots.ErrInvalidArgument, "flows 只能在 1–%d 之间", capMaxFlows)
	}
	want := a.Flows
	if want == 0 {
		want = capDefaultFlows
	}
	led := currentLedger()
	if led == nil {
		return ots.Verdict{Code: capNothing, Values: map[string]any{},
			Note: "手上没有一份能看的账：先 net.capture.start 抓一路，或者 net.capture.open 打开一个文件"}, nil
	}
	return captureTableVerdict(led, want, a.App, a.Host), nil
}

// captureTableVerdict 把一张表出成结果。★ 实时那一路和导入的文件走这一个函数：
// 同一份包从网卡上接的和从磁盘上读的，必须给出同一张表，两套口径迟早给出两个数。
func captureTableVerdict(led *captureLedger, want int, app, host string) ots.Verdict {
	all := led.table.Flows()
	kept := filterFlows(all, app, host)
	packets := led.packets
	v := captureLedgerValues(led)
	// ★ 整张表那一层的口径，三种情形都得带：「一个包都没有」「有包归不出流」恰恰是
	//   最需要知道这份来源有什么毛病的时候。包数账（几句按数说话的话）与 Report 一起给，
	//   放在人能读到的那一栏里，不用再去问一次。
	l := led.table.Ledger()
	rep := led.table.Report()
	v["report"] = rep
	v["packetAccount"] = l.String()
	accountNote := "\n包数账：" + l.String()
	reportNote := ""
	if len(rep) > 0 {
		reportNote = "\n这份来源自己的毛病：" + strings.Join(rep, "；")
	}
	if packets == 0 {
		return ots.Verdict{Code: capNoPackets, Values: v,
			Note: noPacketNote(led) + accountNote + reportNote}
	}
	if len(kept) == 0 {
		return ots.Verdict{Code: capNoFlows, Values: v,
			Note: fmt.Sprintf("收了 %d 包，一条流都没归出来。★ 这不代表链路是空的 —— "+
				"要么是这些包压根拆不到 IP/ARP（看下面那句包数账），"+
				"要么是被 app/host 那两个筛选项筛光了（去掉筛项再问一次）。%s%s",
				packets, accountNote, reportNote)}
	}
	rows := kept
	if len(rows) > want {
		rows = rows[:want]
	}
	out := make([]any, 0, len(rows))
	for _, fl := range rows {
		out = append(out, flowRow(fl))
	}
	v["flows"] = out
	v["flowCount"] = len(kept)
	note := fmt.Sprintf("%d 包，归出 %d 条流。", packets, len(kept))
	if l.Decoded != packets {
		// ★ 我们数到的包与表拆到的包对不上，这一句必须自己说出来。
		note += accountNote
	}
	if len(kept) > want {
		note += fmt.Sprintf("★ 只列了包数最多的前 %d 条，还有 %d 条没列出来（把 flows 调大或者用 app/host 筛）。",
			want, len(kept)-want)
	}
	note += reportNote
	note += "\n★ 这张表脱过敏：凭据只留「带没带、多长」，看不到口令不代表设备没带。"
	if led.partialRead {
		note += "\n★ 这份文件只读了前面一段就停了，下面所有结论只对读到的那一段成立。"
	}
	if led.stopWhy == capWhyMaxBytes {
		note += "\n★ 这一路是**到了文件大小上限**停的，不是这条链路没流量了：后面的包没进来。"
	}
	if n := led.packets - len(all); n > 0 {
		// ★ 包数与流数对不上账是两码事：一条流上可以走一万包。
		//   不写这一句，人就会拿「675 包 / 1 条流」去怀疑表漏了什么。
		note += fmt.Sprintf("\n%d 包落在 %d 条流里（一条流上可以走很多包，这两个数不该相等）。",
			led.packets, len(all))
	}
	return ots.Verdict{Code: capFlows, Values: v, Note: note}
}

func noPacketNote(led *captureLedger) string {
	s := "一个包都没收到。"
	switch led.origin {
	case "live":
		s += "★ 这有几种完全不同的下一步，先按这个顺序排：" +
			"① 抓的是不是这块口（点名的口和流量实际走的口不是同一块，是现场第一大原因）；" +
			"② 这台机器是不是根本没流量（先看 net.bandwidth.top 的网卡计数）；" +
			"③ 这一档平台上收不到回环（Windows 的 pktmon 就这样，本机自己连自己的那一段抓不到）；" +
			"④ 集线器/交换机之分：交换机上收不到别人的单播，混杂模式也办不到 —— 那要端口镜像。"
	default:
		s += "这份文件里一个包块都没有（只有段头和接口描述）。"
	}
	if led.stopWhy == capWhyMaxBytes {
		s += "另外：这一路是**到了文件大小上限**停的，不是没流量。"
	}
	return s
}

// filterFlows 按应用协议与端点筛，并按包数从多到少排。
// ★ 排序放在这一层做而不是交给聚合器：聚合器的顺序是「见到的先后」，
// 现场翻表要的是「哪条最忙」，这两件事不同。
func filterFlows(all []*flow.Flow, app, host string) []*flow.Flow {
	app = strings.ToLower(strings.TrimSpace(app))
	host = strings.TrimSpace(host)
	var out []*flow.Flow
	for _, fl := range all {
		if app != "" && fl.App != app {
			continue
		}
		if host != "" && !strings.Contains(fl.A, host) && !strings.Contains(fl.B, host) {
			continue
		}
		out = append(out, fl)
	}
	sortFlowsByTraffic(out)
	return out
}

// flowRow 是一条流的对外形状。★ 直接放结构体也行，但那会把「界面读哪几格」这件事
// 变成改结构体就破的事；这里显式列一遍，哪一格有出入一目了然。
func flowRow(fl *flow.Flow) map[string]any {
	m := map[string]any{
		"key":       fl.Key,
		"proto":     fl.Proto,
		"a":         fl.A,
		"b":         fl.B,
		"endpoints": fl.Endpoints(),
		"iface":     fl.Iface,
		"packets":   fl.Packets,
		"bytes":     fl.Bytes,
		"ab":        fl.AB.Packets,
		"ba":        fl.BA.Packets,
		"app":       fl.App,
		"appBy":     fl.AppBy,
		"messages":  len(fl.Messages),
		"creds":     credCount(fl),
		"notes":     fl.Notes,
	}
	if !fl.First.IsZero() {
		m["first"] = fl.First.Format(time.RFC3339)
	}
	if !fl.Last.IsZero() {
		m["last"] = fl.Last.Format(time.RFC3339)
		m["durationMs"] = fl.Duration().Milliseconds()
	}
	if fl.AMAC != "" {
		m["amac"] = fl.AMAC
	}
	if fl.BMAC != "" {
		m["bmac"] = fl.BMAC
	}
	if fl.TCP != nil {
		m["handshake"] = fl.TCP.Handshake.Meaning()
	}
	if len(fl.VLANs) > 0 {
		m["vlans"] = fl.VLANs
	}
	if len(fl.Media) > 0 {
		m["media"] = flowRefs(fl.Media)
	}
	if len(fl.Signaling) > 0 {
		m["signaling"] = flowRefs(fl.Signaling)
	}
	if len(fl.Missing) > 0 {
		m["missing"] = fl.Missing
	}
	fs := make([]any, 0, len(fl.Findings))
	for _, f := range fl.Findings {
		fs = append(fs, map[string]any{"code": f.Code, "text": f.Text})
	}
	if len(fs) > 0 {
		m["findings"] = fs
	}
	return m
}

func flowRefs(refs []flow.FlowRef) []any {
	out := make([]any, 0, len(refs))
	for _, r := range refs {
		out = append(out, map[string]any{"key": r.Key, "why": r.Why, "endpoints": r.EPs})
	}
	return out
}

// credCount 这一条流里有几格是脱过敏的。★ 界面拿它写「这条已脱敏 N 处」，
// 没有这一格就只能说「我们脱过敏」，而那句话在表上无从核对。
func credCount(fl *flow.Flow) int {
	n := 0
	for _, m := range fl.Messages {
		for _, fd := range m.Fields {
			if fd.Redacted {
				n++
			}
		}
	}
	return n
}

var captureFlowTool = ots.Tool{
	Name:  "net.capture.flow",
	Class: ots.ClassRead,
	Summary: "看一张表里某一条流的明细：报文列表（每条一起始行/方法/状态码/关键字段）、" +
		"跨流引用、这一条自己的全部判定与注记。\n" +
		"★ 字段是脱过敏的：认证那几格只留「带没带、多长」。想看真正的包，" +
		"去 net.capture.start 落在磁盘上的那份 pcapng（原始包，含明文口令，自己权衡发给谁）。\n" +
		"key 用 net.capture.flows 里给的那个。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["key"],
	  "properties": {
	    "key": {"type": "string", "description": "哪一条流（net.capture.flows 每行都带着它）。"},
	    "messages": {"type": "integer", "minimum": 1, "maximum": 200,
	      "description": "最多列几条报文，默认 40。★ 聚合器本来就只留每条流的前 200 条，这里再筛一次是给界面用的。"}
	  }
	}`),
	Invoke: captureFlowView,
}

type captureFlowArgs struct {
	Key      string `json:"key"`
	Messages int    `json:"messages,omitempty"`
}

func captureFlowView(ctx context.Context, raw json.RawMessage) (any, error) {
	var a captureFlowArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	key := strings.TrimSpace(a.Key)
	if key == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 key（net.capture.flows 的每行都带着它）")
	}
	if a.Messages < 0 || a.Messages > 200 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "messages 只能在 1–200 之间")
	}
	want := a.Messages
	if want == 0 {
		want = 40
	}
	led := currentLedger()
	if led == nil {
		return ots.Verdict{Code: capNothing, Values: map[string]any{},
			Note: "手上没有一份能看的账：先 net.capture.start 抓一路，或者 net.capture.open 打开一个文件"}, nil
	}
	fl, ok := led.table.Agg().Flow(key)
	if !ok {
		return ots.Verdict{Code: capNoFlow, Values: map[string]any{"key": key},
			Note: fmt.Sprintf("当前这张表上没有 %s 这一条流。★ key 是从 net.capture.flows 的结果里抄的 ——"+
				"重新抓一路或换了文件，旧 key 就作废了（流表不跨路保留）。先用 net.capture.flows 看现在有哪些条", key)}, nil
	}
	msgs := make([]any, 0, want)
	for i, m := range fl.Messages {
		if i >= want {
			break
		}
		msgs = append(msgs, messageRow(m))
	}
	v := flowRow(fl)
	v["messagesList"] = msgs
	v["shown"] = len(msgs)
	note := fmt.Sprintf("%s：%d 包，解出 %d 条 %s 报文（这里列了 %d 条）。",
		fl.Endpoints(), fl.Packets, len(fl.Messages), orNone(fl.App), len(msgs))
	note += "★ 字段脱过敏：认证那几格只有「带没带、多长」。"
	if len(fl.Messages) > want {
		note += fmt.Sprintf("还有 %d 条没列（把 messages 调大）。", len(fl.Messages)-want)
	}
	return ots.Verdict{Code: capFlows, Values: v, Note: note}, nil
}

func messageRow(m flow.Message) map[string]any {
	fs := make([]any, 0, len(m.Fields))
	for _, fd := range m.Fields {
		fs = append(fs, map[string]any{"k": fd.K, "v": fd.V, "redacted": fd.Redacted})
	}
	out := map[string]any{
		"at":     m.At.Format(time.RFC3339Nano),
		"proto":  m.Proto,
		"kind":   m.Kind,
		"dir":    m.Dir,
		"line":   m.String(),
		"fields": fs,
		"creds":  m.Creds,
	}
	if m.Method != "" {
		out["method"] = m.Method
	}
	if m.Status != 0 {
		out["status"] = m.Status
	}
	if m.URI != "" {
		out["uri"] = m.URI
	}
	if m.Seq != "" {
		out["seq"] = m.Seq
	}
	if m.CallID != "" {
		out["callId"] = m.CallID
	}
	if m.Soap != "" {
		out["soap"] = m.Soap
	}
	if m.CmdType != "" {
		out["cmdType"] = m.CmdType
	}
	if m.SDP != nil {
		out["sdp"] = m.SDP.Summary()
	}
	if m.Note != "" {
		out["note"] = m.Note
	}
	fs2 := make([]any, 0, len(m.Findings))
	for _, f := range m.Findings {
		fs2 = append(fs2, map[string]any{"code": f.Code, "text": f.Text})
	}
	if len(fs2) > 0 {
		out["findings"] = fs2
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "没认出"
	}
	return s
}

// ── net.capture.open ──

type captureOpenArgs struct {
	File    string `json:"file"`
	Packets int    `json:"packets,omitempty"`
	Flows   int    `json:"flows,omitempty"`
	App     string `json:"app,omitempty"`
	Host    string `json:"host,omitempty"`
}

var captureOpenTool = ots.Tool{
	Name:  "net.capture.open",
	Class: ots.ClassRead,
	Summary: "打开一份已有的抓包文件（pcapng 与老 pcap 都认；同事用 tcpdump 抓的、设备导出来的、" +
		"Wireshark 转出来的都算），出与本机抓包同一张表：按流聚合、协议专解、逐条判定、整表脱敏。\n" +
		"★ 只读这个文件，不改它、不删它。\n" +
		"★ 有包数上限（默认 20 万）：撞到就停下来并明写「只读了前 N 包」，" +
		"因为下面所有结论只对读到的那一段成立 —— 悄悄读完一半就给整份的判断，是最坏的一种错。\n" +
		"读不动的时候说清是哪一层读不动（不是抓包文件 / 段头断了 / 口表不齐），" +
		"而不是只回一句「打不开」让人去猜是不是字节序的事。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["file"],
	  "properties": {
	    "file": {"type": "string", "description": "抓包文件的完整路径。"},
	    "packets": {"type": "integer", "minimum": 1, "maximum": 2000000,
	      "description": "最多读多少包，默认 200000。★ 到上限会停下并说清没读完；要读整份大文件就自己把它调大。"},
	    "flows": {"type": "integer", "minimum": 1, "maximum": 500, "description": "表上列几条流，默认 60。"},
	    "app": {"type": "string", "description": "只看这一个应用协议的流。"},
	    "host": {"type": "string", "description": "只看端点里带这一串的流。"}
	  }
	}`),
	Invoke: openCaptureFile,
}

func openCaptureFile(ctx context.Context, raw json.RawMessage) (any, error) {
	var a captureOpenArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	path := strings.TrimSpace(a.File)
	if path == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 file")
	}
	if a.Packets < 0 || a.Packets > capOpenMaxPackets {
		return nil, ots.Errf(ots.ErrInvalidArgument, "packets 只能在 1–%d 之间", capOpenMaxPackets)
	}
	if a.Flows < 0 || a.Flows > capMaxFlows {
		return nil, ots.Errf(ots.ErrInvalidArgument, "flows 只能在 1–%d 之间", capMaxFlows)
	}
	limit := a.Packets
	if limit == 0 {
		limit = capOpenDefaultPackets
	}
	want := a.Flows
	if want == 0 {
		want = capDefaultFlows
	}
	f, err := os.Open(path)
	if err != nil {
		// ★ 回判定不回错误：「这份文件不在/读不动」是对这份文件的一个说法，
		// 不是这个工具坏了。错误码留给真正没参数的情况。
		return ots.Verdict{Code: capFileBad, Values: map[string]any{"file": path},
			Note: fmt.Sprintf("%s 打不开：%s。★ 先确认路径写对了、这一路后端有权读它 ——"+
				"这和「文件在、但里面不是抓包格式」是两种下一步，后面那一种的报错会说块签名", path, err)}, nil
	}
	defer func() { _ = f.Close() }()

	led := &captureLedger{
		origin: "file", path: path, table: flow.NewTable(flow.Options{}),
		startedAt: time.Now(),
	}
	n, err := readInto(led, f, limit)
	led.stoppedAt = time.Now()
	if err != nil && n == 0 {
		return ots.Verdict{Code: capFileBad, Values: map[string]any{"file": path},
			Note: fmt.Sprintf("%s 这份读不动：%s。★ 这不是「文件里没有包」——"+
				"那一档另有说法（一个包块都没有时会说文件是空的）。先确认它是不是真的抓包文件", path, err)}, nil
	}
	led.packets = n
	if err != nil {
		led.writeErr = err.Error()
		led.stopWhy = capWhyIOError
	}
	if a.Packets > 0 || n >= limit {
		led.partialRead = err == nil && n >= limit
	}
	captureSource.mu.Lock()
	// ★ 导入的这份成为当前账：界面上「看表」那一栏不必分辨表是从哪来的。
	// 但正在跑的那一路不许被顶掉 —— 顶掉了那颗「停」就找不回原来的采集口。
	if captureSource.run == nil || captureSource.run.finished() {
		captureSource.ledger = led
	}
	captureSource.mu.Unlock()

	v := captureTableVerdict(led, want, a.App, a.Host)
	v.Values["file"] = path
	if led.partialRead {
		v.Note = fmt.Sprintf("★ 只读了前 %d 包（上限），这份文件没读完 —— 下面的结论只对这一段成立。\n%s",
			n, v.Note)
	} else if err != nil {
		v.Note = fmt.Sprintf("读到第 %d 包时这份文件读不动了：%s\n%s", n, err, v.Note)
	}
	return v, nil
}

// readInto 读一份文件进来，最多 limit 包。
//
// ★ 上限这一档必须由调用方管：flow.Table 自己不设「只读前一半」，
// 因为「只读了前一半」一旦被忘掉，界面上就会把前一半的结论当成整份的。
func readInto(led *captureLedger, r io.Reader, limit int) (int, error) {
	rd, err := capture.Open(r)
	if err != nil {
		return 0, err
	}
	led.ifaces = rd.Ifaces()
	led.table.SetInterfaces(rd.Ifaces())
	n := 0
	for n < limit {
		p, err := rd.Read()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			led.ifaces = rd.Ifaces()
			led.table.SetInterfaces(rd.Ifaces())
			return n, err
		}
		led.table.SetInterfaces(rd.Ifaces())
		n++
		led.bytes += int64(len(p.Data))
		if e := led.table.Add(p); e != nil {
			continue // 口表缺号这类错一路都会犯，不能一犯就停
		}
	}
	return n, nil
}

// ── 共用的账 ──

func currentLedger() *captureLedger {
	captureSource.mu.Lock()
	defer captureSource.mu.Unlock()
	if r := captureSource.run; r != nil && !r.finished() {
		return r.led
	}
	return captureSource.ledger
}

func capturePathOf() string {
	captureSource.mu.Lock()
	defer captureSource.mu.Unlock()
	if captureSource.run != nil {
		return captureSource.run.led.path
	}
	return ""
}

func capturePacketsOf() int {
	captureSource.mu.Lock()
	defer captureSource.mu.Unlock()
	if captureSource.run != nil {
		return captureSource.run.led.packets
	}
	return 0
}

// finished 问这一路收口了没有。★ 不读 stopped 而读 done0：收口这件事只有一个地方做，
// 判断它做没做就看那一个标记，别去猜「包数没涨了所以停了吧」。
func (r *captureRun) finished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done0
}

// restoreCapture 收上次没停的抓包账。
//
// ★★ 采集口与文件句柄都是本进程持有的，进程退了就不在了 —— 没有要还原的东西，
// 但这笔账必须了结：挂着不管，下次看账本的人会去查一路早就不抓了的包，
// 甚至照着账上的文件名再去找一份可能压根没写完的文件。
// 文件一律不动：那是现场证据，删了才是不可逆的。
func restoreCapture(log *slog.Logger) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind != "capture" {
			continue
		}
		log.Warn("上次退出时这一路抓包没有正常停止 —— 本次启动不会自动重开（文件保留）",
			"改动", e.What, "时间", e.At.Format(time.RFC3339))
		_ = journal.MarkReverted(e.ID, "进程重启：采集口已随上次进程退出而关，文件保留")
	}
}

// sortFlowsByTraffic 按包数从多到少，同数按 key 定序（★ 必须有第二把尺：
// 光按包数排，两条一样忙的流每次刷新可能互换位置，界面上看着就像在跳）。
func sortFlowsByTraffic(fl []*flow.Flow) {
	for i := 1; i < len(fl); i++ {
		for j := i; j > 0 && lessFlow(fl[j], fl[j-1]); j-- {
			fl[j], fl[j-1] = fl[j-1], fl[j]
		}
	}
}

func lessFlow(a, b *flow.Flow) bool {
	if a.Packets != b.Packets {
		return a.Packets > b.Packets
	}
	return a.Key < b.Key
}
