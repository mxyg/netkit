package remote

// 对端抓包：把「在那台机器上跑一句采集」这一路会用到的动作拆成四件 ——
// 问那台上有什么、起一路、看一眼、停下来。
//
// ★★ 为什么这一层在 remote 里而不是 tools 里：这四件事的难点全在
//   「对端那句话怎么说」上 —— 同一件「起不来」，tcpdump 会说
//   "You don't have permission to capture on that device"、
//   "eth9: No such device available"、"syntax error in filter expression"，
//   那是三个不同的下一步。分档这件事得贴着命令走，得能被真 sh 验。
//   工具层只管会话、账本与批准。
//
// ★ 每一句都在对端跑真命令，不猜：能问出来的绝不写「大概是这样」。
//   问不出来的（那台的 tcpdump 太老、不给口列表）就明写「没核过」。

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerCaptureCaps 是对端那台上采集能用的东西。
//
// Windows 那一档走的是 pktmon，采集与「能不能转 pcapng」是两码事（etl2pcap
// 是 Win10 1809 起才有，老 build 缺它就只能落 .etl，那份我们读不动）。
// 所以 Etl2Pcap 单列 —— 上层要拿它给一个专门的下一步，不许并成「没采集器」。
type PeerCaptureCaps struct {
	Tool     string   // 认出来的采集器：tcpdump / pktmon。空 = 这台上没有可用的
	Path     string   // 对端上那个命令在哪儿（起不来时这是唯一能指着说的东西）
	Ifaces   []string // 那台上报出来的口名，原样列（Down 的也在，现场就是要在这里挑）
	Dir      string   // 那份文件落在对端哪儿
	Note     string   // 问不出来的那一格，说清是哪一格问不出来
	Etl2Pcap bool     // Windows 那一档：那台 pktmon 的 /? 里认不认得出 etl2pcap 这一项
}

// ProbePeerCapture 问对端：有没有能用的采集器、有哪些口、文件能落哪儿。
//
// ★ 探不到采集器**不是错误**：那台机器上没装 tcpdump 是一个事实，
// 一个能拿去决定的事实（下一步是装它、换 pktmon、还是回本机抓），
// 所以它从返回值里说话，不从 error 里说话。
func ProbePeerCapture(ctx context.Context, x SSHExecer, d *Device) (*PeerCaptureCaps, error) {
	if d != nil && d.OS == "windows" {
		return probePeerCaptureWindows(ctx, x, d)
	}
	caps := &PeerCaptureCaps{}

	out, err := x.Exec(ctx, d, "command -v tcpdump", 15*time.Second)
	if err != nil {
		return nil, err
	}
	if out.ExitCode == 0 {
		caps.Tool = "tcpdump"
		caps.Path = strings.TrimSpace(out.Stdout)
	} else {
		caps.Note = "那台机器的 PATH 里找不着 tcpdump"
	}

	if caps.Tool != "tcpdump" {
		// 没采集器就别再问它要口列表了 —— 那只会多一句没根据的话
		caps.Dir = peerScratchDir(ctx, x, d)
		return caps, nil
	}

	// ★ Path 要引起来：Windows 上那个命令常带空格，POSIX 上也可能在带空格的目录里。
	if out, err := x.Exec(ctx, d, shellQuote(caps.Path)+" -D", 20*time.Second); err != nil {
		return nil, err
	} else if out.ExitCode == 0 {
		caps.Ifaces = parseTcpdumpInterfaces(out.Stdout)
	} else {
		caps.Note = "那台的 tcpdump 给不出口列表（-D 没成），口名没核过"
	}
	caps.Dir = peerScratchDir(ctx, x, d)
	return caps, nil
}

// peerScratchDir 问对端一句「临时文件往哪儿放」。
//
// ★ 不许直接写死 /tmp：那台上可能是别的（也只有一问才知道）。
// 问不出来就退回 /tmp 并把这一格说成没核过 —— 不静默换一个地方。
func peerScratchDir(ctx context.Context, x SSHExecer, d *Device) string {
	out, err := x.Exec(ctx, d, `echo "${TMPDIR:-/tmp}"`, 10*time.Second)
	if err != nil || out.ExitCode != 0 {
		return "/tmp"
	}
	if s := strings.TrimSpace(out.Stdout); s != "" && !strings.Contains(s, "\n") {
		return strings.TrimRight(s, "/")
	}
	return "/tmp"
}

// parseTcpdumpInterfaces 读 `tcpdump -D` 那份列表：
//
//	1.eth0 [Up, Running]
//	3.bge1 [Down]
//
// 序号是 tcpdump 自己编的，和内核口序号没关系，所以只取名字。
func parseTcpdumpInterfaces(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, '.')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[i+1:])
		if j := strings.IndexByte(name, ' '); j >= 0 {
			name = name[:j]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// PeerCaptureProblem 是「那一句话说明的起不来的原因」。
//
// ★ 分档而不是把对端那句原文当结论：原文要进结果给人看，
// 但它各家写法不一样，钉不住判定；档按「下一步」分，原文另带。
type PeerCaptureProblem string

const (
	PeerProblemNone       PeerCaptureProblem = ""
	PeerProblemNoTool     PeerCaptureProblem = "no-collector"
	PeerProblemPrivilege  PeerCaptureProblem = "no-privilege"
	PeerProblemInterface  PeerCaptureProblem = "no-interface"
	PeerProblemFilter     PeerCaptureProblem = "bad-filter"
	PeerProblemDied       PeerCaptureProblem = "died-at-start"
	PeerProblemStuck      PeerCaptureProblem = "stuck"
	PeerProblemConnection PeerCaptureProblem = "connection"
	// PeerProblemBusy 是 Windows/pktmon 独有的那一档：退出码 159，
	// 「这台机器上已经有一路 pktmon 在录（全机器只能一路）」（实测码，见 internal/capture 那份清单）。
	// 它跟「没权限」「那块口没有」下一步完全相反 —— 那一步是先 pktmon stop 掉别人那一录，不是提权。
	PeerProblemBusy PeerCaptureProblem = "busy"
)

// classifyPeerStart 把对端 tcpdump 起手那几句话分成一档。
//
// 只认这三类**真出现过的原话**，认不出就老实说 died-at-start：
// 猜出来的档会把人领去查错的地方。
func classifyPeerStart(detail string) PeerCaptureProblem {
	s := strings.ToLower(detail)
	switch {
	case strings.Contains(s, "permission"), strings.Contains(s, "operation not permitted"),
		strings.Contains(s, "not supported on active interface"), strings.Contains(s, "need to be privileged"),
		strings.Contains(s, "must be run as"):
		return PeerProblemPrivilege
	case strings.Contains(s, "no such device"), strings.Contains(s, "doesn't exist"),
		strings.Contains(s, "unknown interface"):
		return PeerProblemInterface
	case strings.Contains(s, "syntax error in filter"), strings.Contains(s, "filter expression"),
		strings.Contains(s, "can't parse filter"):
		return PeerProblemFilter
	}
	return PeerProblemDied
}

// firstLineOf 取第一句人话并剪短 —— 这句可能进结果，也可能进诊断包。
func firstLineOf(s string) string {
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

// peerPath 在对端的落盘目录下拼一个文件名。
// ★ 文件名由我们自己生成（时间戳 + 随机后缀），调用方给的东西不进这条路。
func peerPath(dir, name string) string {
	if dir == "" {
		dir = "/tmp"
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir + name
}

func peerNameTag() string {
	return fmt.Sprintf("%d%04d", time.Now().Unix(), time.Now().Nanosecond()/100000%10000)
}

// PeerCaptureSpec 是「在那台上起一路采集」的口径。
//
// 路径与文件名都由上层从 caps 拼出来 —— 这一层不猜对端的目录结构。
//
// Windows 那一档不走 tcpdump，走系统自带的 pktmon：那一条 start 命令本身就
// 是「起一个全机器唯一的 ETW 会话，把包写进 -f 指定的 .etl，命令当场返回」，
// 所以 EtlPath / PcapPath / MaxMB 三格只在 Windows 那一头用；
// POSIX 那一档看 Collector / PeerFile 就够了。
type PeerCaptureSpec struct {
	Collector string // caps.Path：那台上找到的命令
	Interface string
	Filter    string
	SnapLen   int
	PeerFile  string
	PeerLog   string
	// Windows 那一档另要这三格（POSIX 那两格留空、不参与拼命令）：
	MaxMB    int    // 传给 pktmon 的 -s（单位 MB，已向上取整，0 = 走 pktmon 默认）
	EtlPath  string // pktmon 那一路正在写的那一份 .etl
	PcapPath string // 收口时 pktmon etl2pcap 转出来的那一份 .pcapng（最后 pull 的就是它）
}

// PeerRun 是一路已经交给对端的采集。
//
// Windows 那一档没有 PID 可带回：pktmon 起的是一路系统级的会话（不是我们能
// 发信号的那个进程），所以那一头靠 Windows bool 分流，靠 EtlPath 判断「还在不在写」。
type PeerRun struct {
	PID       int
	PeerFile  string
	PeerLog   string
	StartedAt time.Time
	Windows   bool   // true = 这一路走 pktmon，不用 PID/信号那套
	EtlPath   string // Windows：正在被 pktmon 写的那一份 .etl
}

// PeerStartError 是「起了，但那一下没成」，带着分档与对端原话。
type PeerStartError struct {
	Problem PeerCaptureProblem
	Detail  string
}

func (e *PeerStartError) Error() string {
	return fmt.Sprintf("对端采集起不来（%s）：%s", e.Problem, e.Detail)
}

// StartPeerCapture 在对端后台起一路 tcpdump，回来先确认它真的活着。
//
// ★★ 为什么要「起了再看一眼」而不是起了就算成：
//
//	非 root 那一种，命令收条据、后台进程照起，一秒后才在日志里说一句
//	"You don't have permission to capture on that device" 然后自己走掉。
//	不回头看的那一版会说「抓起来了」，人等到停的时候才发现那份文件是空的。
//
// 全部对端给的、人给的字符串一律走单引号转义后再拼：
// 口名、过滤器、命令路径、文件路径 —— 一个都不裸着进 shell。
func StartPeerCapture(ctx context.Context, x SSHExecer, d *Device, spec PeerCaptureSpec) (*PeerRun, error) {
	if d != nil && d.OS == "windows" {
		return startPeerCaptureWindows(ctx, x, d, spec)
	}
	if spec.Collector == "" {
		return nil, &PeerStartError{Problem: PeerProblemNoTool, Detail: "那台上没有可用的采集命令"}
	}
	if spec.Interface == "" {
		return nil, fmt.Errorf("得点名对口上抓（这一档不替你选「所有口」，那块口在抓包时是另一件事）")
	}
	if spec.SnapLen <= 0 {
		return nil, fmt.Errorf("snapLen 要给正数，现在是 %d", spec.SnapLen)
	}
	// ★ 数字这一格先钉死再拼命令：snapLen 是上层算出来的，
	// 但这一层不该假设调用方一定算对。
	snap := fmt.Sprintf("%d", spec.SnapLen)

	argv := shellQuote(spec.Collector) + " -i " + shellQuote(spec.Interface) +
		" -s " + snap + " -w " + shellQuote(spec.PeerFile)
	if spec.Filter != "" {
		argv += " " + shellQuote(spec.Filter)
	}
	// nohup + 两个流都接走：SSH 那一条通道要能关掉，进程才不会跟着挂。
	// ★ 两个流各归各的：stdout 没东西可给，stderr 是**那一本账和那句报错**唯一的去处。
	//   这里要是多写一次 2>，后头那句会把前头的盖掉 —— 日志永远是空的，
	//   「起了又死」就全成了猜。
	//
	// ★★ 前面那句 set -m 不是装饰，是「打招呼能把它劝停」的前提（本机 /bin/sh 实测）：
	//   非交互 shell 里用 & 挂起来的命令，按 POSIX 会先把 SIGINT 设成「忽略」再交给它。
	//   shell 脚本改不回被忽略的信号，tcpdump 那种自己装处理函数的二进制能改回来 ——
	//   但这一路不能赌对端的采集器是二进制（有的设备上 /usr/sbin/tcpdump 就是个脚本，
	//   现场还有 dumpcap、有厂商包着的 wrapper）。没这句 set -m 的话，
	//   SIGINT 打上去没反应，每一路都会等到超时被判成「不听招呼，只能硬断」：
	//   硬断打不出那本账，那份文件还可能短一截，而这三件事其实都是这一句没写。
	cmd := "set -m 2>/dev/null; nohup " + argv + " >/dev/null 2>" + shellQuote(spec.PeerLog) + " & echo $!"
	out, err := x.Exec(ctx, d, cmd, 30*time.Second)
	if err != nil {
		return nil, err
	}
	// 对端回的那一串是外人能影响的东西：只收纯数字，别的都不认。
	pid, perr := parsePeerPID(out.Stdout)
	if perr != nil {
		// ★ 那一格认不出来 ≠ 对端那一路没起来。它多半真在跑，只是我们不知道它的号。
		//   报了错就走，等于留一路没人收口的采集在别人盘上写原始包（里头什么明文都有）。
		//   所以这一格认不得垃圾之后还得把那一路收掉：按我们生成的那个唯一文件名找回去。
		return nil, fmt.Errorf("%w。%s", perr, reapPeerOrphan(ctx, x, d, spec.PeerFile))
	}
	run := &PeerRun{PID: pid, PeerFile: spec.PeerFile, PeerLog: spec.PeerLog, StartedAt: time.Now()}

	// ★ 先看一眼之前要等一会儿：刚 fork 出来的那一瞬间它总是「活着」的，
	//   立刻问等于没问 —— 非 root 那一种要一秒后才在日志里说完那句话走掉。
	time.Sleep(peerStartSettle)
	deadline := time.Now().Add(peerStartWatch)
	for {
		alive, _, err := PollPeerCapture(ctx, x, d, run)
		if err != nil {
			return nil, err
		}
		if alive {
			return run, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	detail := readPeerLog(ctx, x, d, run.PeerLog)
	return nil, &PeerStartError{Problem: classifyPeerStart(detail), Detail: firstLineOf(detail)}
}

// peerStartSettle 是「起了以后先别急着问」那一段。
// peerStartWatch 是之后每隔一点问一次、问到哪为止。
// 太短会把「还在初始化」看成「死了」，太长会让第一次判定等到人烦。
const (
	peerStartSettle = 400 * time.Millisecond
	peerStartWatch  = 1500 * time.Millisecond
)

// parsePeerPID 只认那一串里唯一的数字。
//
// ★ 不认垃圾：对端 echo 回来的东西，我们改不了它怎么写
//
//	（被换过的 tcpdump、被劫持的 PATH、上一版脚本留下的输出）。
//	把那一串原样拼进后面那句 kill -0 就等于让对端替我们写命令。
func parsePeerPID(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("对端没回采集进程的进程号")
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("对端回的进程号不是一个数（%q）—— 不敢拿它去发信号", firstLineOf(s))
		}
		// 1<<22 是 Linux 内核 pid_max 的上限，再大就不可能是进程号了。
		// 不许往上涨：n*10 在 32 位档要留得下，出厂那份 windows/386 会溢出。
		if n = n*10 + int(r-'0'); n > 1<<22 {
			return 0, fmt.Errorf("对端回的进程号大得不像话（%q）", s)
		}
	}
	if n <= 0 {
		return 0, fmt.Errorf("对端回的进程号是 %q，不像一个开着的进程", s)
	}
	return n, nil
}

// reapPeerOrphan 在「进程号那一格认不出来」之后按我们生成的文件名找回去收口。
//
// ★ 为什么还要多跑这一句：报了错就走，等于在对端留一路没人收口的采集 ——
//
//	那份文件里是原始包，口令、团体名、摘要全在里面，写到手停为止。
//	没有进程号就按那一个我们自己也知道的唯一文件名找。
//	找不找得回来要说清：这一句的返回值是要跟着错误一起给人看的，
//	不许含含糊糊地当「已经处理了」。
func reapPeerOrphan(ctx context.Context, x SSHExecer, d *Device, peerFile string) string {
	q := shellQuote(peerFile)
	// 打完招呼等一秒再看还在不在：pkill 各家的退出码说法不一（有的把「没匹配到」
	// 也报 1，有的老版本干脆不认 -f），所以数一数比读码实在。
	// 那句 ps 自己也在命令行里带着这个文件名，用 grep -v grep 把它和 grep 一起滤掉。
	out, err := x.Exec(ctx, d,
		"pkill -INT -f "+q+" 2>/dev/null; sleep 1; "+
			"ps -ef 2>/dev/null | grep -F "+q+" | grep -v grep | wc -l", 20*time.Second)
	if err != nil {
		return fmt.Sprintf("按文件名找回去收尾的那句没跑成（通道断了）—— %s 可能还在写，得自己去那台上收掉", peerFile)
	}
	n := strings.TrimSpace(out.Stdout)
	switch {
	case !isAllDigits(n):
		return fmt.Sprintf("那台机器没答出「还在不在」—— %s 可能还在写，得自己去那台上收掉", peerFile)
	case n == "0":
		return "已按那个文件名打招呼，对端那一路退了"
	default:
		return fmt.Sprintf("没能让它退（那台上没有 pkill，或它不听招呼，还在跑的有 %s 个）—— %s 得自己去那台上收掉", n, peerFile)
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// PeerStat 是对端那一路此刻的样子。
type PeerStat struct {
	Alive bool
	Bytes int64
	// BytesKnown=false：那份文件此刻读不到大小（还没建、或那台的 wc 不配合）。
	// ★ 不许把读不到报成 0 —— 「到量了自己停」那一档就是拿这个数决定的。
	BytesKnown bool
}

// PollPeerCapture 看一眼活着没、文件多大了。一次 SSH 往返问完两格。
func PollPeerCapture(ctx context.Context, x SSHExecer, d *Device, run *PeerRun) (bool, int64, error) {
	st, err := PeerCaptureStat(ctx, x, d, run)
	if err != nil {
		return false, 0, err
	}
	return st.Alive, st.Bytes, nil
}

// PeerCaptureStat 同 PollPeerCapture，但把「读不到大小」这一格留着说话。
func PeerCaptureStat(ctx context.Context, x SSHExecer, d *Device, run *PeerRun) (*PeerStat, error) {
	if run != nil && run.Windows {
		return peerCaptureStatWindows(ctx, x, d, run)
	}
	pid := fmt.Sprintf("%d", run.PID)
	// ★ 僵尸要算「死了」：kill -0 对僵尸是成功的，而我们那一层父 shell 已经走了，
	//   那台机器什么时候收掉它我们说了不算。把它当活的，「停一下看看走没走」
	//   就会一路等到超时，然后误判成「它不听招呼，只能硬断」。
	//   ps 问不出状态的老设备（busybox 那一类）退回原样当活的 —— 宁可少判一次硬断，
	//   也不把还在写的那一路掐掉。
	cmd := "if kill -0 " + pid + " 2>/dev/null; then " +
		"st=$(ps -o state= -p " + pid + " 2>/dev/null | tr -d ' '); " +
		"case \"$st\" in Z*) echo down ;; *) echo up ;; esac; else echo down; fi; " +
		"wc -c < " + shellQuote(run.PeerFile) + " 2>/dev/null | tr -dc '0-9'"
	out, err := x.Exec(ctx, d, cmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	st := &PeerStat{}
	lines := strings.Split(strings.TrimSpace(out.Stdout), "\n")
	if len(lines) > 0 {
		st.Alive = strings.TrimSpace(lines[0]) == "up"
	}
	if len(lines) > 1 {
		if n, err := fmt.Sscanf(strings.TrimSpace(lines[1]), "%d", &st.Bytes); n == 1 && err == nil {
			st.BytesKnown = true
		}
	}
	return st, nil
}

// PeerStopInfo 是停下来那一下收到的账。
type PeerStopInfo struct {
	// Forced：true = 这一路是 SIGKILL 掐的。它来不及打那本账，
	// 那份文件也可能短一截 —— 上层必须把这句话带给人。
	Forced bool
	// StillAlive：连 SIGKILL 都没能收口（那台在动别的东西，或那个进程已不属于我们）。
	StillAlive bool
	HasCounts  bool
	Captured   int64
	Received   int64
	Dropped    int64
	Log        string // 对端那一句原文（剪过），给人指着看的
	// ConvertErr：Windows 那一路 stop 成了、etl2pcap 那一步没成 —— 那一份 .etl 还在对端，
	// 上层要单独给一档说人话：包已经在盘上了，只是转不成 pcapng，
	// 别混进 pull-failed（那份连转都没转出来，SFTP 拿不到东西本来就是应该的）。
	ConvertErr string
}

// StopPeerCapture 先按规矩打招呼（SIGINT：tcpdump 会收尾并把那本账打在 stderr 上），
// 等它自己走；到点没走才硬断。
//
// Windows 那一档不走这一条：没有 PID 可发信号，收口靠 pktmon stop + etl2pcap
// （见 stopPeerCaptureWindows）。分流按 run.Windows 走，不看 d.OS —— 一路会话在起的
// 那一刻就把「用什么收口」这件事定下来了，中途换了设备登记里的 OS 说法也不能改口。
func StopPeerCapture(ctx context.Context, x SSHExecer, d *Device, run *PeerRun, wait time.Duration) (*PeerStopInfo, error) {
	if run != nil && run.Windows {
		return stopPeerCaptureWindows(ctx, x, d, run, wait)
	}
	pid := fmt.Sprintf("%d", run.PID)
	if wait <= 0 {
		wait = 5 * time.Second
	}
	if _, err := x.Exec(ctx, d, "kill -INT "+pid+" 2>/dev/null; echo done", 20*time.Second); err != nil {
		return nil, err
	}
	info := &PeerStopInfo{}
	deadline := time.Now().Add(wait)
	alive := true
	for alive {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		var err error
		alive, _, err = PollPeerCapture(ctx, x, d, run)
		if err != nil {
			return nil, err
		}
		if alive && time.Now().After(deadline) {
			break
		}
	}
	if alive {
		// ★ 硬断这一路要单独说话：tcpdump 那本账是退出时打的，SIGKILL 没有退出那一下。
		info.Forced = true
		if _, err := x.Exec(ctx, d, "kill -9 "+pid+" 2>/dev/null; echo done", 20*time.Second); err != nil {
			return nil, err
		}
		time.Sleep(400 * time.Millisecond)
		if still, _, err := PollPeerCapture(ctx, x, d, run); err != nil {
			return nil, err
		} else {
			info.StillAlive = still
		}
	}
	info.Log = readPeerLog(ctx, x, d, run.PeerLog)
	info.Captured, info.Received, info.Dropped, info.HasCounts = parsePeerCounts(info.Log)
	if info.Forced {
		info.HasCounts = false // 硬断的那一路打不出账，读到旧日志里的半句也不算
	}
	return info, nil
}

// parsePeerCounts 读 tcpdump 退出时那三行：
//
//	12 packets captured
//	12 packets received by filter
//	3 packets dropped by kernel
//
// ★ 三个数各归各的：「抓到的」与「内核给的」与「被丢的」是三种不同的少，
// 合成一个数就没法说「这份文件少了多少」。
func parsePeerCounts(s string) (captured, received, dropped int64, ok bool) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimRight(f[0], ":"), 10, 64)
		if err != nil {
			continue
		}
		rest := strings.ToLower(strings.Join(f[1:], " "))
		switch {
		case strings.HasPrefix(rest, "packets captured"):
			captured, ok = n, true
		case strings.HasPrefix(rest, "packets received by filter"):
			received, ok = n, true
		case strings.HasPrefix(rest, "packets dropped by kernel"):
			dropped, ok = n, true
		}
	}
	return
}

// readPeerLog 读对端那一句原文。
func readPeerLog(ctx context.Context, x SSHExecer, d *Device, logPath string) string {
	out, err := x.Exec(ctx, d, "cat "+shellQuote(logPath)+" 2>/dev/null", 20*time.Second)
	if err != nil {
		return ""
	}
	return out.Stdout + out.Stderr
}

// RemovePeerFiles 删掉对端那几份。
//
// ★ 默认要删：那一份里是原始包 —— 口令、团体名、摘要全在里面，
//
//	留在别人机器上而我们这边已经取走了，等于把凭据丢在现场。
//	不想删的要调用方明确说（见 tools 层 keepPeer）。
//
// Windows 那一档走 del /q（cmd.exe 那一套），POSIX 那一路才用 rm -f。
func RemovePeerFiles(ctx context.Context, x SSHExecer, d *Device, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	var q []string
	for _, pp := range paths {
		if pp != "" {
			q = append(q, pp)
		}
	}
	if len(q) == 0 {
		return nil
	}
	if d != nil && d.OS == "windows" {
		return removePeerFilesWindows(ctx, x, d, q)
	}
	quoted := make([]string, 0, len(q))
	for _, pp := range q {
		quoted = append(quoted, shellQuote(pp))
	}
	if _, err := x.Exec(ctx, d, "rm -f "+strings.Join(quoted, " "), 30*time.Second); err != nil {
		return err
	}
	return nil
}
