//go:build windows

// Windows 这一档：系统自带的 pktmon（Packet Monitor，Win10 1809 / Server 1809 起才有）。
//
// 为什么走这一条：不装驱动、不带第三方二进制，抓到的东西转成 pcapng 之后，
// 跟另外两档读的是同一份表。自己写 NDIS 轻量筛选驱动那一条明确不走 ——
// 那是内核态的东西，要签名、要重启、要出事时能在现场卸干净，三样都不占。
// netsh trace 也不走：它落的还是 .etl，转出来要么靠外来的 etl2pcapng，
// 要么靠 Windows SDK 那一套，比 pktmon 多带一个外来件。
//
// ★ 出货清单里有 windows/386（Win7 那一档），那儿没有 pktmon。
//
//	所以起口之前先问一句「这台机器上有没有、会不会转 pcapng」，问不出来就报一句
//	「只能读现成的 pcapng」，不许退化成「那就换个别的办法抓一遍」——
//	现场最怕的不是抓不到，是抓到的东西跟界面上说的不是一回事。
//
// 下面这一串是在 UTM 里那台 Win11 ARM64（26200，中文系统）上逐条量出来的（2026-09-25）。
// 每一条都写着「不这么做会怎样」，因为它们全都在退出码上看不出来：
//
//  1. 不写 --comp → 默认 ALL 组件，同一个包在转出来的 pcapng 里出现 4 次（10 包变 40 包）。
//  2. ★ 写 --comp <某块网卡的号> → 只剩出的方向（同样十个 ping：0 进 7 出）。
//     只有 --comp nics 是两个方向都收（实测 26 进 14 出）。所以这一档定口不能靠它，
//     见 pktmonFrameHere。
//  3. ★ filter add -m <MAC> 同样只剩出的方向（22 包全是本机发出的，进来的 0 包）。
//     它自己的帮助里写的是「匹配源或目标 MAC 地址」—— 量出来不是这么回事。
//     所以这一档不往机器上下任何筛选器；场上的筛选器一律当成「别人在用」，直接不起。
//  4. 不写 --pkt-size → 默认每包只记 128 字节，1500 MTU 的包被剪断
//     （caplen=128，线上长度照实报）。用不数长度的看法时完全看不出被剪过。
//  5. -s 那一格的单位是 MB，而且 0 不是「不限」，是「按默认的 512MB」。
//  6. ★ 正在录的那一个 .etl 直接拿去转 → 退出码 0、转出来 172 字节
//     （只有段头和接口头，一个包都没有）。这一条最阴：它不报错，
//     只给你一份「什么都没抓到」。所以每段先 stop、再换下一段、然后才转已经停掉的那一份。
//  7. 已经在录的时候再 start → 它说「已启动数据包监视器。」（听着像成功），退出码 159；
//     stop 一个没在录的 → 它说「数据包监视器没有运行。」，退出码 0。
//     ★ 两句话都不能信，只有退出码可信 —— 所以这一档不读它说的任何一个字来判断状态，
//     只把第一句原样带进报错里给人看。
//  8. 循环日志按需增长（20 个包 → 3,538 字节，那一格上限 16MB），没按 -s 预分配，
//     所以「这一段有没有写过上限」能拿文件大小去比 —— 见 pktmonSegmentFilled。
//  9. 转出来的 pcapng 里只有一条 unnamed 接口记录：链路类型 1（以太网）、刻度 1µs、
//     接口那一格的 snaplen 写 0。也就是说「这一包来自哪块网卡」在文件里根本没有。
//  10. ★ --comp nics 收不到回环：录一段、期间 ping 自己 20 次，转出来 0 包。
//     这是这一档跟 Linux/macOS 两档最实在的一个口径差（那两档的 lo 抓得到，
//     本机服务自己连自己的东西就在那儿）。「抓不到」和「没有」是两句话，
//     这一条得原样带进 #92 的说明里。
//  11. 中文系统上 pktmon 说的每一句话都是中文，但命令里那些 token
//     （start / stop / etl2pcap / filter / list / --comp / --pkt-size / -s / -f / --drop-only）
//     不受显示语言影响，实测照用。所以我们只喂参数、只看退出码。
//     （唯一一处要读它的话的是能力探测：在 `pktmon /?` 的输出里找 etl2pcap 这一个命令名，
//     命令名不翻译，实测过。）
//  12. pktmon 自己那份「丢弃计数」只在转换时跟着中文说出来，而 `counters --json` 是开工那
//     一刻的快照（实测：抓包期间丢了 7 包，它一直报 0）。所以丢包数走 --drop-only
//     那一份转换，我们自己数文件里有几包。
package capture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 起口这一档的三条前置检查（负数、硬件时刻、混杂）都在 OpenSource 里，
// 顺序是定的：先把「界面上能填的格」挡完，再问这台机器行不行，最后才落临时目录。
// 反过来先落了地再失败，就会留下一地没人收的抓包文件。

// pktmonRunner 是「跑一条 pktmon」这一格。抽出来只为了一件事：
// 命令的先后（尤其「先 stop、立刻起下一段、然后才转」）能在测试里钉住，
// 不必真在机器上起一个系统会话。
type pktmonRunner interface {
	run(args ...string) (string, error)
}

// execPktmon 是真那一个：用系统里的 pktmon.exe，一句一句喂。
type execPktmon struct{ exe string }

func (e execPktmon) run(args ...string) (string, error) {
	cmd := exec.Command(e.exe, args...)
	// 我们是后台服务，不该每问一次就闪一个控制台窗口。
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		return out, fmt.Errorf("capture: pktmon %s 没成（%v）：%s", cmdLabel(args), err, firstLine(out))
	}
	return out, nil
}

func cmdLabel(args []string) string {
	if len(args) == 0 {
		return "(空)"
	}
	if len(args) > 1 {
		return args[0] + " " + args[1]
	}
	return args[0]
}

// exitCode 从 exec 的错里把退出码抠出来；拿不到就回 -1（那不是任何一个已知的码）。
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// firstLine 取输出的第一句，剪到 pktmonErrTextSize 以内。
// ★ 这里只是「把人家说的原话带上」给人看，不用它判断任何一个状态 —— 见顶上第 7 条。
// 剪是因为这句话可能进诊断包，而 pktmon 的话里带着我们自己的临时目录全路径。
func firstLine(out string) string {
	s := strings.ReplaceAll(out, "\r\n", "\n")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > pktmonErrTextSize {
		s = s[:pktmonErrTextSize] + "…"
	}
	if s == "" {
		return "（它什么都没说）"
	}
	return s
}

// OpenSource 起一路采集。Interface 为空 = 这台机器上所有网卡合一路。
//
// 三道前置检查（负数、硬件时刻、混杂）的顺序是定的：先把「界面上能填的格」挡完，
// 再问这台机器行不行，最后才落临时目录。反过来先落了地再失败，
// 就会留下一地没人收的抓包文件。
func OpenSource(opt Options) (Source, error) {
	if opt.SnapLen < 0 || opt.BufferSize < 0 {
		return nil, fmt.Errorf("capture: 留长与环大小不能为负（留长 %d、环 %d）", opt.SnapLen, opt.BufferSize)
	}
	if opt.Timestamp == TSHardware {
		// 不许悄悄退回软件时刻：拿硬件戳算出来的延迟和拿软中断那一份差一截，
		// 报表上看不出来。这一档压根没有那一格，就如实说没有。
		return nil, fmt.Errorf("capture: pktmon 这一档没有网卡打戳那一项，要硬件时刻请换一台机器")
	}
	if opt.Promisc {
		// 这一档没有「混杂」可开：包是协议栈收发的时候顺手抄下来的，栈收不到的它也没有。
		// 界面上勾了这一格不许当成勾过了 —— 那种话说出去是假的。
		return nil, fmt.Errorf("capture: pktmon 这一档没有混杂模式那一项（收不收由协议栈决定）；要抓镜像口，直接把那个口选上")
	}
	names, err := sourceIfaces(opt.Interface)
	if err != nil {
		return nil, err
	}
	run, err := lookUpPktmon()
	if err != nil {
		return nil, err
	}
	return openPktmon(opt, names, run, probeElevated())
}

// openPktmon 是起了口之后的那一段：定口、落地、查筛选器、起第一段。
//
// 单独切开只为了一件事 —— 命令的先后能在测试里钉住。合成一个函数的话，
// 想验「场上有筛选器就不起」得先有一台装着 pktmon 的 Windows 机器，
// 而那条顺序恰恰是这一档最容易被人顺手改回去的（改成「先清筛选器再起来省事」）。
func openPktmon(opt Options, names []string, run pktmonRunner, elevated int8) (Source, error) {
	s := &windowsSource{
		run:      run,
		segDur:   pktmonSegment(opt.BlockRetire),
		snapLen:  opt.SnapLen,
		bufSize:  int64(opt.BufferSize),
		segs:     make(chan pktmonSegmentFile, 1),
		quit:     make(chan struct{}),
		elevated: elevated,
	}
	// 点名的时候要按 MAC 认口（顶上第 2、3 条：pktmon 那两条定口的路都只有出的方向）。
	// 认不出的口在这里就拒掉，不许悄悄退化成「那就全抓」。
	if len(names) == 1 {
		in, err := net.InterfaceByName(names[0])
		if err != nil {
			return nil, fmt.Errorf("capture: 口 %s 查不到：%w", names[0], err)
		}
		if len(in.HardwareAddr) != 6 {
			return nil, fmt.Errorf("capture: 口 %s 没有 MAC（%s），pktmon 这一档认不出它的包；"+
				"回环与虚拟口本来也收不到（见这一档的口径说明）", names[0], in.HardwareAddr)
		}
		s.wantMAC = append([]byte(nil), in.HardwareAddr...)
		s.ifaces = []Interface{{
			Name:        names[0],
			Description: "pktmon：整块网卡两个方向都收，再按 MAC 分（广播/组播认不出是哪块口进来的，这一路放行）",
			LinkType:    LinkTypeEN10MB,
			SnapLen:     pktmonSnapLen(opt.SnapLen),
		}}
	} else {
		s.ifaces = []Interface{{
			Name:        "pktmon:all",
			Description: fmt.Sprintf("pktmon：%d 块网卡的包合在一路，转出来的文件里分不开（要分就点名）", len(names)),
			LinkType:    LinkTypeEN10MB,
			SnapLen:     pktmonSnapLen(opt.SnapLen),
		}}
	}
	dir, err := os.MkdirTemp("", "netkit-capture-")
	if err != nil {
		// ★ 不许猜配置文件目录在哪儿：那台验证机上账户改过名，%USERPROFILE% 是 C:\Users\nktest，
		//   照着用户名拼路径直接一句「找不到路径」（退出码 3）。临时目录让系统给。
		return nil, fmt.Errorf("capture: 落不下临时目录：%w", err)
	}
	s.dir = dir
	// 场上有筛选器就不起：它们会限制所有会话能看到的包（包括我们这一路），
	// 而 `filter remove` 是全清 —— 不许拿别人的现场换自己的能跑。
	if out, err := run.run("filter", "list"); err != nil {
		s.cleanup()
		return nil, err
	} else if names := pktmonFilters(out); len(names) > 0 {
		s.cleanup()
		return nil, fmt.Errorf("capture: 这台机器上挂着 pktmon 筛选器（%s），"+
			"它们会把这一路能看见的包滤掉。这一档不替你删别人的东西，请先跑一句 pktmon filter remove",
			strings.Join(names, "、"))
	}
	if err := s.startSegment(); err != nil {
		s.cleanup()
		return nil, err
	}
	s.wg.Add(1)
	go s.rollLoop()
	return s, nil
}

func pktmonSnapLen(snapLen int) uint32 {
	if snapLen <= 0 {
		return DefaultSnapLen
	}
	return uint32(snapLen)
}

// lookUpPktmon 分三种状态报：没这个命令 / 有命令但不会转 pcapng / 全功能。
// 这三句在界面上是三件事：第一句是「这台机器不支持」，第二句是「支持一半」，
// 第三句才是「往下走」。并成一句会让人去装一个根本装不上的东西。
func lookUpPktmon() (pktmonRunner, error) {
	exe, err := exec.LookPath("pktmon")
	if err != nil {
		return nil, pktmonAvailability(err, "", nil)
	}
	run := execPktmon{exe: exe}
	out, err := run.run("/?")
	if err != nil {
		return nil, pktmonAvailability(nil, "", err)
	}
	if err := pktmonAvailability(nil, out, nil); err != nil {
		return nil, err
	}
	return run, nil
}

// pktmonAvailability 只把「这台机器上的 pktmon 用不用得了」说成一句人话。
//
// ★ 拆成不带执行的一格， 是因为 windows/386 那一档卖的正是 Win7 —— 那里根本没有 pktmon，
// 而这一句在 Win10 上永远走不到。不拆出来就没法验：真机上补不了一条「没有 pktmon」的机器，
// 只能拿「找命令的结果 ＋ help 的输出」这两样观测值喂它。
func pktmonAvailability(lookErr error, help string, helpErr error) error {
	switch {
	case lookErr != nil:
		return fmt.Errorf("capture: 这台机器上没有 pktmon（系统自带的报文监视器，Win10 1809 起才有）——"+
			"这一档只能读现成的 pcapng，不能现场抓（%w）", ErrUnsupported)
	case helpErr != nil:
		// 这一句不套 ErrUnsupported：机器上明明有，只是问不动。
		// 套错了，界面会叫这台机器别用了，而真因多半是它自己的服务没起来。
		return fmt.Errorf("capture: 问不动 pktmon：%w", helpErr)
	case !strings.Contains(help, "etl2pcap"):
		return fmt.Errorf("capture: 这台机器上的 pktmon 没有 etl2pcap 那一项，抓得出 .etl 但转不成我们能读的表——"+
			"这一档只能读现成的 pcapng（%w）", ErrUnsupported)
	}
	return nil
}

// pktmonSegmentFile 是一段录完、转好、交给我们读的那一份 pcapng。
type pktmonSegmentFile struct {
	path   string
	drops  uint64
	filled bool
}

type windowsSource struct {
	run     pktmonRunner
	ifaces  []Interface
	wantMAC []byte // 点名的那一块口的 MAC；空 = 全都算

	segDur  time.Duration
	snapLen int
	bufSize int64

	dir   string
	live  string // 正在录的那一个 .etl
	segNo int

	elevated int8 // 1 提过权、0 没提权、-1 问不出来

	mu     sync.Mutex
	closed bool
	quit   chan struct{}
	segs   chan pktmonSegmentFile
	wg     sync.WaitGroup

	// 下面三格只有读的那一条路碰（Next 一个调用方），Close 一概不碰；
	// Close 撤文件走 files 那一格 —— *os.File 自己挡得住「关的时候正在读」，
	// 读的那一路于是拿到 os.ErrClosed，转成 ErrClosed 交回去（见 Next）。
	cur     *os.File
	reader  *Reader
	curPath string

	// files 与上面三格是同一批句柄，只是这一格归 mu 管：Close 要能在读的人手上
	// 撒开口子（不然临时目录删不掉），而它不许碰 reader 那三格。
	files []*os.File

	pkts   uint64
	drops  uint64
	lossy  bool
	bad    error
	badSet bool
}

var _ Source = (*windowsSource)(nil)

// startSegment 起一段（新的 .etl 落点）。调用方持着 mu，或者刚在 Open 里一个人用。
func (s *windowsSource) startSegment() error {
	path := s.segPath(s.segNo)
	args, err := pktmonStartArgs(s.snapLen, s.bufSize, path)
	if err != nil {
		return err
	}
	if _, err := s.run.run(args...); err != nil {
		switch {
		case pktmonIsBusyExit(exitCode(err)):
			// 这一个码是实测的：它说的话是「已启动」，只有码说真话。
			return fmt.Errorf("capture: 这台机器上已经有一路 pktmon 在录（全机器只能有一路）——"+
				"先把在录的那一路停掉：pktmon stop。原始错：%w", err)
		case s.elevated == 0:
			// 探测只用来把错话说准，不用来放行也不用来拦路（问不出来时不许猜一个填上去）：
			// 套错了 ErrNeedPrivilege，界面就叫人去提权，而那台机器可能早就提过了。
			return fmt.Errorf("capture: 起不来 pktmon（这一档要管理员：它是系统级的，普通用户开不了那个会话）。"+
				"原始错：%w（%w）", err, ErrNeedPrivilege)
		default:
			return err
		}
	}
	s.live = path
	return nil
}

func (s *windowsSource) segPath(n int) string {
	return filepath.Join(s.dir, "seg-"+strconv.Itoa(n)+".etl")
}

func (s *windowsSource) segPcapPath(n int) string {
	return filepath.Join(s.dir, "seg-"+strconv.Itoa(n)+".pcapng")
}

// rollLoop 按段换：等、换段、把转好的那一份递出去。
func (s *windowsSource) rollLoop() {
	defer s.wg.Done()
	defer close(s.segs)
	t := time.NewTicker(s.segDur)
	defer t.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-t.C:
		}
		seg, ok, err := s.roll()
		if err != nil {
			s.setBad(err)
			return
		}
		if !ok {
			return // 关掉的那一下：不递、直接出去
		}
		select {
		case s.segs <- seg:
		case <-s.quit:
			// 没人要了：把已经转好的那一份删干净再走。里面是原样流量，不是普通垃圾文件。
			os.Remove(seg.path)
			return
		}
	}
}

// roll 换一段。
//
// ★ 顺序是量出来的：stop → 立刻起下一段 → 才去转旧的那一段。
//
//	转换排在「起下一段」之前的话，瞎掉的那一段时间就把转换也算进去了。
//	而旧的那一份必须先 stop 才准转（顶上第 6 条：正在录的转出来是空的，还回退出码 0）。
//	换段那两拍仍旧有抓不到的空隙，所以「这一段之内没丢包」不等于「整场没丢包」——
//	这句话在这一档只能这么写。
func (s *windowsSource) roll() (pktmonSegmentFile, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return pktmonSegmentFile{}, false, nil
	}
	if _, err := s.run.run("stop"); err != nil {
		return pktmonSegmentFile{}, true, err
	}
	prev := s.segNo
	s.segNo++
	if err := s.startSegment(); err != nil {
		return pktmonSegmentFile{}, true, err
	}
	seg, err := s.convertLocked(prev)
	return seg, true, err
}

// convertLocked 把第 n 段转成两份 pcapng：全量那一份交给读的人，
// 「只有丢包」那一份我们自己数一遍就删。
func (s *windowsSource) convertLocked(n int) (pktmonSegmentFile, error) {
	etl := s.segPath(n)
	st, err := os.Stat(etl)
	if err != nil {
		return pktmonSegmentFile{}, fmt.Errorf("capture: 找不到 pktmon 刚落盘的 %s：%w", filepath.Base(etl), err)
	}
	size := st.Size()
	// 原样流量不在临时目录里多留一刻：.etl 里的东西跟 pcapng 里的一模一样。
	defer os.Remove(etl)

	pcap := s.segPcapPath(n)
	if _, err := s.run.run("etl2pcap", etl, "--out", pcap); err != nil {
		return pktmonSegmentFile{}, err
	}
	dropPath := strings.TrimSuffix(etl, ".etl") + "-drops.pcapng"
	if _, err := s.run.run("etl2pcap", etl, "--out", dropPath, "--drop-only"); err != nil {
		os.Remove(pcap)
		return pktmonSegmentFile{}, err
	}
	defer os.Remove(dropPath)
	drops, err := countFilePackets(dropPath)
	if err != nil {
		os.Remove(pcap)
		return pktmonSegmentFile{}, err
	}
	mb, err := pktmonFileMB(s.bufSize)
	if err != nil {
		os.Remove(pcap)
		return pktmonSegmentFile{}, err
	}
	filled := pktmonSegmentFilled(size, mb)
	s.drops += uint64(drops)
	if filled {
		s.lossy = true
	}
	return pktmonSegmentFile{path: pcap, drops: uint64(drops), filled: filled}, nil
}

func (s *windowsSource) setBad(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.badSet {
		s.bad, s.badSet = err, true
	}
}

// Next 取下一包。一段读空了就去要下一段；正等的时候 Close 了，拿 ErrClosed。
//
// 点名的时候这一路要把别的口的包跳过 —— 跳过的不算进 Packets：
// 界面那句「这一路递了多少包」说的是用户看得见的数。
func (s *windowsSource) Next() (Packet, error) {
	for {
		if s.reader != nil {
			for {
				// ★ 每一包都问一句「还开着没有」， 不能只等句柄那一个错：
				//   读侧的缓冲里可能还压着几包， 那种包在 Close 之后照样会递出去，
				//   界面上就是「按了停止， 包还在动」。
				if s.isClosed() {
					return Packet{}, ErrClosed
				}
				p, err := s.reader.Read()
				if errors.Is(err, os.ErrClosed) {
					// Close 抢着把句柄关了：这一路到此为止，不猜半包。
					return Packet{}, ErrClosed
				}
				if err == io.EOF {
					s.finishSegment()
					break
				}
				if err != nil {
					return Packet{}, err
				}
				if s.wantMAC != nil && !pktmonFrameHere(p.Data, s.wantMAC) && !pktmonFrameBroadcast(p.Data) {
					continue
				}
				s.mu.Lock()
				s.pkts++
				s.mu.Unlock()
				return p, nil
			}
			continue
		}
		seg, ok := <-s.segs
		if !ok {
			return Packet{}, s.doneErr()
		}
		f, err := os.Open(seg.path)
		if err != nil {
			return Packet{}, fmt.Errorf("capture: 转好的那一段打不开：%w", err)
		}
		rd, err := Open(f)
		if err != nil {
			f.Close()
			os.Remove(seg.path)
			return Packet{}, err
		}
		s.hand(f)
		s.cur, s.reader, s.curPath = f, rd, seg.path
	}
}

// hand 把正在读的那一份登记进 files：Close 只认这一格，不碰 reader 那三格。
func (s *windowsSource) hand(f *os.File) {
	s.mu.Lock()
	s.files = append(s.files, f)
	s.mu.Unlock()
}

// isClosed 问那一路还开着没有。
func (s *windowsSource) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// retire 交还一个已经读完的句柄。
func (s *windowsSource) retire(f *os.File) {
	s.mu.Lock()
	for i, g := range s.files {
		if g == f {
			s.files = append(s.files[:i], s.files[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
}

// finishSegment 读完一段：句柄和那一份 pcapng 一起收掉。
// ★ 转出来的文件也要当场删：抓包文件里是真实流量，多留一份就是多一份要防的拷贝。
// 更要紧的是句柄得先撒开 —— Windows 上一个还开着的文件删不掉，
// Close 里那句 RemoveAll 会撞在这一格上。
func (s *windowsSource) finishSegment() {
	if s.cur != nil {
		s.cur.Close()
		s.retire(s.cur)
		s.cur = nil
	}
	s.reader = nil
	if s.curPath != "" {
		os.Remove(s.curPath)
		s.curPath = ""
	}
}

// doneErr 是「这一路读到头了」那一句话，而且每次问都回同一句。
// 换段出错时递出去的是 pktmon 的原话；读的人往后每次问还是那一句，
// 不会一遍一个错、看着像链路在抖。
func (s *windowsSource) doneErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.badSet {
		return s.bad
	}
	return ErrClosed
}

func (s *windowsSource) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{
		Packets:    s.pkts,
		Dropped:    s.drops,
		Lossy:      s.lossy,
		Interfaces: len(s.ifaces),
	}
}

func (s *windowsSource) Interfaces() []Interface {
	return append([]Interface(nil), s.ifaces...)
}

// Close 收口。关两次不算一次错。
//
// 顺序：先把换段那一条路按住（不许它再起新的一段），再 stop，再把临时目录整个抹掉。
// s.mu 是那条路和这里唯一的交点：路拿着它跑命令，这里等它交出来之后再动手，
// 于是「Close 返回之后机器上不再有一路在录」这一句是算数的。
func (s *windowsSource) Close() error {
	var errs []error
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.quit)
	if _, err := s.run.run("stop"); err != nil {
		errs = append(errs, err)
	}
	// 读的人手上那一份 pcapng 的句柄要在这里撒开：一是 Windows 上开着的文件删不掉，
	// 二是正读着的那一路该拿一句 ErrClosed 结束。这里只关句柄，不碰 reader 那三格 ——
	// 那三格是读的那一条路的，两处都动就是竞态。
	for _, f := range s.files {
		f.Close() // 已经是关过的再关一次不回错，这里也不拿它记账
	}
	s.files = nil
	s.mu.Unlock()

	s.wg.Wait()
	if err := os.RemoveAll(s.dir); err != nil {
		errs = append(errs, fmt.Errorf("capture: 临时目录没删干净：%w", err))
	}
	return errors.Join(errs...)
}

func (s *windowsSource) cleanup() {
	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}
