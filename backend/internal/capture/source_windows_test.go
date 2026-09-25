//go:build windows

package capture

// Windows 这一档的测试。分三档，因为能验的东西分三层：
//
//   - 桩跑的那一堆：命令的先后顺序（尤其是「先 stop、立刻起下一段、然后才转」）、
//     场上的筛选器、权限与「已经有人在录」那两句话、临时目录有没有清干净、
//     读的那一路按 MAC 分口。这些都不必真起一个系统会话。
//   - 真机的那一条：需要管理员，而且需要这台机器上真有 pktmon ——
//     跑不过就明写跑不过， 见最后那一条的 skip 口径。
//   - 能力探测那两条：Win7（windows/386 那一档）上根本没有 pktmon，
//     那一句在 Win10 上永远走不到， 所以只能拿观测值喂它 —— 见 TestWin25。
//   - 纯算术与纯解析不在这儿：那一份在 pktmon_plan_test.go（不带 tag， 改代码的机器上就能跑）。
//
// 名字前那一段 TestWin + 两位数是给人留的口子：cmd.exe 按 GBK 收发，
// 中文测试名敲不进去， 于是「单独跑某一条」在真机上会变成办不到的事。
// 只跑这一档：capture_test.exe -test.run TestWin；只跑换段那一条：-test.run TestWin08。

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
	"testing"
	"time"
)

// ==================== 桩 ====================

// stubPktmon 记下每一条调用， 并且真的把「转出来的那一份」落到盘上 ——
// 因为读的那一路要拿真文件走一遍， 只在内存里演一遍等于没验。
type stubPktmon struct {
	mu    sync.Mutex
	calls []string

	// filterList 是 `filter list` 回的那一段正文。
	filterList string
	// startErr 按第几条 start（从 0 数）回一个错； 回 nil 就是起成了。
	startErr func(nth int) error
	// full 是「全量」那一份转换的内容， drops 是 --drop-only 那一份。
	full  []byte
	drops []byte

	// etlGoneAtConvert 记「转换那一条命令被叫起来时， 正在录的那一个 .etl 还在不在」。
	// ★ 这一格钉的是顶上第 6 条：正在录的转出来是空的、还回退出码 0。
	convertedWhenLive []string
}

func (s *stubPktmon) run(args ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, strings.Join(args, " "))
	switch args[0] {
	case "filter":
		return s.filterList, nil
	case "start":
		n := s.nth("start")
		// ★ 落完就撒手：Windows 上一个还开着的文件删不掉， 桩握着句柄
		//   会让「.etl 转完就没了」那两条撞上自己的漏。
		f, err := os.Create(args[len(args)-1])
		if err != nil {
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		if s.startErr != nil {
			if err := s.startErr(n); err != nil {
				return "已启动数据包监视器。", err
			}
		}
		return "", nil
	case "stop":
		return "", nil
	case "etl2pcap":
		out := args[3]
		body := s.full
		if len(args) > 4 && args[4] == "--drop-only" {
			body = s.drops
			s.convertedWhenLive = append(s.convertedWhenLive, args[1])
		}
		if body == nil {
			body = []byte{}
		}
		if err := os.WriteFile(out, body, 0o600); err != nil {
			return "", err
		}
		return "", nil
	}
	return "", fmt.Errorf("桩不认的命令：%v", args)
}

// nth 数「这是第几条 start」， 从 0 起。
func (s *stubPktmon) nth(verb string) int {
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, verb+" ") {
			n++
		}
	}
	return n - 1
}

func (s *stubPktmon) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// exitWith 拿一次真进程的退出码造一个 *exec.ExitError。
// 为什么要造真的：这一档判断状态只认退出码（顶上第 7 条），
// 拿一个假的错类型去喂，等于把「只认码」这一条测成了「认我们自己的类型」。
func exitWith(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("cmd", "/c", "exit", strconv.Itoa(code)).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("造不出退出码 %d 的错：%v", code, err)
	}
	if ee.ExitCode() != code {
		t.Fatalf("造出来的错带着 %d， 要 %d", ee.ExitCode(), code)
	}
	return ee
}

// mustSource 起一路（桩）， 返回可直接摆弄内部状态的那一个。
// names 给两个假名字 = 走「不点名、所有口合一路」那一条分支； 要验点名分支自己传一个真口名。
func mustSource(t *testing.T, stub *stubPktmon, opt Options, elevated int8) *windowsSource {
	t.Helper()
	return mustSourceNames(t, stub, opt, elevated, []string{"乙", "甲"})
}

func mustSourceNames(t *testing.T, stub *stubPktmon, opt Options, elevated int8, names []string) *windowsSource {
	t.Helper()
	if opt.BlockRetire == 0 {
		opt.BlockRetire = time.Hour // 测试里不让它自己换段， 换段那一步由 roll 手动叫
	}
	src, err := openPktmon(opt, names, stub, elevated)
	if err != nil {
		t.Fatalf("起口失败：%v", err)
	}
	s := src.(*windowsSource)
	t.Cleanup(func() { s.Close() })
	return s
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// frame 搭一条只带以太网头的帧（够认方向就行， 往上的协议这一档不看）。
func frame(dst, src []byte) []byte {
	b := make([]byte, ethHdrSize+4)
	copy(b[ethDstOff:], dst)
	copy(b[ethSrcOff:], src)
	copy(b[ethHdrSize:], "hi!!")
	return b
}

// ==================== 界面上能填的格先挡 ====================

// 这四条都在 lookUpPktmon 之前， 所以在一台没有 pktmon 的机器上照样成立 ——
// 「这个平台能不能抓」不该盖住「你填的这一格是错的」。
func TestWin01界面上填错的格当场就拒(t *testing.T) {
	cases := []struct {
		name string
		opt  Options
		want string
	}{
		{"留长负数", Options{SnapLen: -1}, "不能为负"},
		{"环负数", Options{BufferSize: -1}, "不能为负"},
		{"要硬件时刻", Options{Timestamp: TSHardware}, "没有网卡打戳"},
		{"要混杂", Options{Promisc: true}, "没有混杂模式"},
		{"点名的口不存在", Options{Interface: "这台机器上没有这个口-9a7b"}, "没有叫"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OpenSource(tc.opt)
			if err == nil {
				t.Fatal("起了一个口， 这一格该拒的")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("说的是 %q， 要带上 %q", err.Error(), tc.want)
			}
		})
	}
}

// 混杂那一格不许「ignoring 一下继续」：勾了的人以为抓到别人的包了， 实际一份都没有。
func TestWin02要混杂时不会悄悄照抓(t *testing.T) {
	_, err := OpenSource(Options{Promisc: true})
	if err == nil {
		t.Fatal("混杂被当成了勾过了")
	}
	if !strings.Contains(err.Error(), "镜像口") {
		t.Errorf("没给出路：%v", err)
	}
}

// ==================== 场上的筛选器 ====================

// ★ 这一条挡住的是最容易「顺手优化」成一个 bug 的地方：
//
//	筛掉别的会话能看见的包是 pktmon 筛选器的真效果， 而 `filter remove` 是全清 ——
//	清了别人的现场， 换自己这一路能跑。所以这里既不能起、也不能替人删。
func TestWin03场上有筛选器就不起也不替人删(t *testing.T) {
	stub := &stubPktmon{filterList: "# 名称\tMAC 地址 协议\r\n1 netkit ICMP\r\n"}
	src, err := openPktmon(Options{}, []string{"甲", "乙"}, stub, 1)
	if err == nil {
		src.Close()
		t.Fatal("带着别人的筛选器起了口")
	}
	if !strings.Contains(err.Error(), "filter remove") {
		t.Errorf("没说该怎么收场：%v", err)
	}
	for _, c := range stub.called() {
		if strings.HasPrefix(c, "start") {
			t.Errorf("起了口：%s", c)
		}
		if strings.Contains(c, "filter remove") || strings.Contains(c, "filter add") {
			t.Errorf("动了别人的筛选器：%s", c)
		}
	}
}

// 空表（只有一句「暂无」）不算在场 —— 那种情况下拒起口，
// Windows 上就永远抓不了包了。
func TestWin04没有筛选器时照常起(t *testing.T) {
	stub := &stubPktmon{filterList: "暂无数据包筛选器。\r\n"}
	src, err := openPktmon(Options{BlockRetire: time.Hour}, []string{"甲", "乙"}, stub, 1)
	if err != nil {
		t.Fatalf("空表被当成了在场：%v", err)
	}
	defer src.Close()
	calls := stub.called()
	if len(calls) == 0 || !strings.HasPrefix(calls[len(calls)-1], "start ") {
		t.Errorf("调用序列是 %v， 末一条应为 start", calls)
	}
}

// ==================== 状态只认退出码：那两句错话 ====================

// 已经有一路在录 → 界面要说「先把那一路停了」， 不能说「去提权」。
// 说错的那一种会让人去开一个管理员窗口， 而问题不在权限上。
func TestWin05已经有一路在录时说的是那一句(t *testing.T) {
	busy := exitWith(t, pktmonBusyExit)
	stub := &stubPktmon{startErr: func(nthCall int) error {
		if nthCall == 0 {
			return busy
		}
		return nil
	}}
	_, err := openPktmon(Options{}, []string{"甲", "乙"}, stub, 1)
	if err == nil {
		t.Fatal("已经在录还能起第二路")
	}
	if !strings.Contains(err.Error(), "pktmon stop") {
		t.Errorf("没给出路：%v", err)
	}
	if errors.Is(err, ErrNeedPrivilege) {
		t.Error("把「有人在录」说成了「权限不够」")
	}
}

// 起不来 + 探到确实没提权 → 才许套 ErrNeedPrivilege。
func TestWin06没提权时起不来就说要提权(t *testing.T) {
	other := exitWith(t, 3)
	stub := &stubPktmon{startErr: func(int) error { return other }}
	_, err := openPktmon(Options{}, []string{"甲", "乙"}, stub, 0)
	if !errors.Is(err, ErrNeedPrivilege) {
		t.Errorf("得 %v， 要套上 ErrNeedPrivilege", err)
	}
	if !strings.Contains(err.Error(), "原始错") {
		t.Errorf("把原话丢了：%v", err)
	}
}

// ★ 问不出提没提权时， 不许拿「不知道」当「没提权」用：
//
//	套错了的那一句会把人支去开管理员窗口， 而那台机器早就提过了。
func TestWin07问不出权限时不臆断要提权(t *testing.T) {
	other := exitWith(t, 3)
	stub := &stubPktmon{startErr: func(int) error { return other }}
	_, err := openPktmon(Options{}, []string{"甲", "乙"}, stub, -1)
	if errors.Is(err, ErrNeedPrivilege) {
		t.Errorf("问不出来却说了提权：%v", err)
	}
	if err == nil {
		t.Fatal("起不来还回没出错")
	}
}

// ==================== 换段 ====================

// 顺序是这一档最要紧的一条：stop → 立刻起下一段 → 才转旧的那一份。
// 转换排在前面的话， 瞎掉的那一段时间把转换也算进去了；
// 而正在录的那一份转出来是空的、还回退出码 0（顶上第 6 条）。
func TestWin08换段先停再起后转(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-nics.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	before := len(stub.called())

	seg, ok, err := s.roll()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("没关掉却说不用递")
	}
	var seq []string
	for _, c := range stub.called()[before:] {
		seq = append(seq, strings.Fields(c)[0])
	}
	want := []string{"stop", "start", "etl2pcap", "etl2pcap"}
	if strings.Join(seq, ",") != strings.Join(want, ",") {
		t.Errorf("顺序是\n%v\n要\n%v", seq, want)
	}
	// 交出来的那一份不是正在录的那一个。
	if seg.path == s.live {
		t.Error("交出去的是正在录的那一份")
	}
	// 转的必须是已经停掉的那一段。
	for _, p := range stub.convertedWhenLive {
		if p == s.live {
			t.Errorf("拿正在录的 %s 去转了", filepath.Base(p))
		}
	}
	// 旧的 .etl 转完就没了：里面是原样流量， 多留一份就是多一份要防的拷贝。
	if _, err := os.Stat(s.segPath(0)); !errors.Is(err, os.ErrNotExist) {
		t.Error("上一段的 .etl 还留在盘上")
	}
	if s.segNo != 1 {
		t.Errorf("段号是 %d， 换过一次该到 1", s.segNo)
	}
	if got, err := countFilePackets(seg.path); err != nil || got != 10 {
		t.Errorf("那一段数出 %v 包（%v）， 要 10", got, err)
	}
}

// 丢弃计数走 --drop-only 那一份， 我们自己在文件里数（counters --json 是开工时的快照）。
func TestWin09丢弃数从drop_only那一份里数(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-nics.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	if _, _, err := s.roll(); err != nil {
		t.Fatal(err)
	}
	if s.Stats().Dropped != 10 {
		t.Errorf("丢了 %d 包， 那一份 drop-only 里是 10 包", s.Stats().Dropped)
	}
	if s.Stats().Lossy {
		t.Error("没写满上限却被标了残缺")
	}
}

// 一段写到循环上限：新事件盖掉最早的， 不报错也不进丢弃计数。
// 认不出来就是拿一份缺了开头的账去下结论。
func TestWin10写满过的那一段要标残缺(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{BufferSize: 1 << 20}, 1)
	// 上限 1MB 的那一段， 把 .etl 撑到线上（1MB 的 99%）。
	big := make([]byte, (1<<20)-(1<<20)/100)
	if err := os.WriteFile(s.segPath(0), big, 0o600); err != nil {
		t.Fatal(err)
	}
	seg, _, err := s.roll()
	if err != nil {
		t.Fatal(err)
	}
	if !seg.filled {
		t.Error("写到上限了却没认出来")
	}
	if !s.Stats().Lossy {
		t.Error("这一段没有背书「全须全尾」的那一格")
	}
}

// ==================== 读的那一路 ====================

// 递一段转好的 pcapng 进去（绕开真 pktmon）， 走一遍 Next。
// 连递两段时要换个名字：那一份文件读完就会被收掉， 同名会把下一份盖在还开着的那一份上。
//
// 交出去是异步的：s.segs 只留一格（读的人跟不上时， 换段那一路该等着而不是攒一堆文件），
// 所以「先递两段再开始读」这种写法会自己把自己堵死。
func seedFile(t *testing.T, s *windowsSource, as string, body []byte) string {
	t.Helper()
	path := filepath.Join(s.dir, "seed-"+as+".pcapng")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) }) // 读到了的人会把这份收掉； 没读到的那份不该留到下一场
	go func() {
		select {
		case s.segs <- pktmonSegmentFile{path: path}:
		case <-time.After(10 * time.Second):
			t.Errorf("递不进 %s（ 换段的那一路卡住了？）", as)
		}
	}()
	return path
}

func seedSegment(t *testing.T, s *windowsSource, as, fixtureName string) string {
	t.Helper()
	return seedFile(t, s, as, fixture(t, fixtureName))
}

// 读满 n 包。Next 在两段之间是「等下一段」而不是「读完了」， 所以这里不许出现
// 「读空了一段就以为到头了」那种写法 —— 那正是界面会一直转圈的地方。
func readPackets(t *testing.T, s *windowsSource, n int) []Packet {
	t.Helper()
	out := make([]Packet, 0, n)
	for len(out) < n {
		p, err := s.Next()
		if err != nil {
			t.Fatalf("读第 %d 包：%v", len(out)+1, err)
		}
		out = append(out, p)
	}
	return out
}

// 两段连着读：段与段之间接得上， 账也连着记。
func TestWin11一段接一段地读出包(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-nics.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	first := seedSegment(t, s, "a", "pktmon-nics.pcapng")
	readPackets(t, s, 10)
	second := seedSegment(t, s, "b", "pktmon-nics.pcapng")
	got := readPackets(t, s, 10)

	if !pktmonFrameHere(got[0].Data, pktmonMAC) || !pktmonFrameHere(got[9].Data, pktmonMAC) {
		t.Error("第二段的首尾两包不像那一份文件里的")
	}
	if s.Stats().Packets != 20 {
		t.Errorf("账上记了 %d 包， 两段一共递出 20 包", s.Stats().Packets)
	}
	// 读完的那一段不该留在盘上：里面是原样流量。
	if _, err := os.Stat(first); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("第一段读完了还留着：%v", err)
	}
	// 正在读的这一份该还在（读空了才收， 不许提前删）。
	if _, err := os.Stat(second); err != nil {
		t.Errorf("第二段被提前收掉了：%v", err)
	}
}

// ★ 点名一块口时， 别的口的单播要跳过 —— 而且跳过的不许算进「递了多少包」：
//
//	那一句说的是用户看得见的数。这里先递一段两个方向都不是那块口的， 再递一段是它的，
//	于是「跳过了」和「卡在下一段上」两种结果分得开。
func TestWin12点名时别人的单播不递也不记账(t *testing.T) {
	foreign := []byte{0x02, 0x99, 0x88, 0x77, 0x66, 0x55}
	stub := &stubPktmon{full: fixture(t, "pktmon-nics.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	s.wantMAC = foreign
	seedSegment(t, s, "foreign", "pktmon-nics.pcapng") // 那十个包两个方向都不是 foreign
	seedFile(t, s, "mine", oneFrameFile(t, frame(foreign, []byte{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02})))

	p, err := s.Next()
	if err != nil {
		t.Fatalf("Next：%v", err)
	}
	if !pktmonFrameHere(p.Data, foreign) {
		t.Errorf("递上来的是别人的帧：% x", p.Data[:12])
	}
	if s.Stats().Packets != 1 {
		t.Errorf("账上记了 %d 包， 跳过去的那十个不该记账", s.Stats().Packets)
	}
}

// 广播/组播认不出是从哪块口进来的 —— 宁可一块口上多看见几包。
// 这一条钉住「跳过」那两个条件之间的放行：只按 src/dst 认的话， ARP 会在每一块口上消失。
func TestWin13点名时广播照样放行(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	s.wantMAC = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	broadcast := frame([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02})
	seedFile(t, s, "广播", oneFrameFile(t, broadcast))
	p, err := s.Next()
	if err != nil {
		t.Fatalf("广播被跳过了：%v", err)
	}
	if len(p.Data) != len(broadcast) {
		t.Errorf("读出 %d 字节， 要 %d", len(p.Data), len(broadcast))
	}
}

// 拿我们自己的写侧写一份只有一包的 pcapng（读的那一路于是也顺带对了一次账）。
func oneFrameFile(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []Interface{{Name: "甲", LinkType: LinkTypeEN10MB, SnapLen: DefaultSnapLen}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(0, time.Now(), data, len(data)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ==================== 关口 ====================

// Close 之后「机器上不再有一路在录」这一句要算数：stop 必须发出去，
// 而关第二次不算一次错（上层常常是 defer Close 加显式 Close 各一次）。
func TestWin14关两次不算错但一定要停(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	dir := s.dir
	if err := s.Close(); err != nil {
		t.Fatalf("Close：%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("第二次 Close：%v", err)
	}
	stops := 0
	for _, c := range stub.called() {
		if c == "stop" {
			stops++
		}
	}
	if stops != 1 {
		t.Errorf("stop 发了 %d 次， 关两回只该停一次", stops)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("临时目录还在：%v", err)
	}
	if _, err := s.Next(); !errors.Is(err, ErrClosed) {
		t.Errorf("关完还在读， 得 %v， 要 ErrClosed", err)
	}
}

// 读的人手上那一份的句柄必须在 Close 时撒开：
// Windows 上一个还开着的文件删不掉， Close 里那句 RemoveAll 会撞在这一格上。
func TestWin15读一半时关掉那一路拿到ErrClosed(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-nics.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{}, 1)
	seedSegment(t, s, "读到一半", "pktmon-nics.pcapng")
	if _, err := s.Next(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("读了一半就关不掉：%v", err)
	}
	if _, err := s.Next(); !errors.Is(err, ErrClosed) {
		t.Errorf("得 %v， 要 ErrClosed", err)
	}
}

// 换段那一路坏了之后， 读的人每次问都该拿同一句话 ——
// 一遍一个错会让人以为链路在抖。
//
// 走的是真那一条路：起第一段成了， 换段时起不来 → rollLoop 收摊（把 segs 关掉），
// 读的人于是从「等下一段」转成「每次都是那一句」。
func TestWin16坏掉的那一路每次回同一个错(t *testing.T) {
	boom := errors.New("capture: 这一段起不来（ 桩）")
	stub := &stubPktmon{
		full:  fixture(t, "pktmon-empty.pcapng"),
		drops: fixture(t, "pktmon-empty.pcapng"),
		startErr: func(nth int) error {
			if nth >= 1 {
				return boom
			}
			return nil
		},
	}
	s := mustSource(t, stub, Options{BlockRetire: time.Second}, 1)
	for i := 0; i < 3; i++ {
		if _, err := s.Next(); !errors.Is(err, boom) {
			t.Fatalf("第 %d 次得 %v， 要同一句", i+1, err)
		}
	}
}

// ==================== 接口表 ====================

// 点名一块口 → 表里就那一个名字， 并且认得出 MAC（认不出就在这儿拒掉，
// 不许悄悄退化成「那就全抓」）。
func TestWin17点名的口按MAC认(t *testing.T) {
	var named string
	for _, in := range ifacesForTest(t) {
		if len(in.HardwareAddr) == 6 {
			named = in.Name
			break
		}
	}
	if named == "" {
		t.Skip("这台机器上没有带 MAC 的口")
	}
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	src, err := openPktmon(Options{BlockRetire: time.Hour}, []string{named}, stub, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	s := src.(*windowsSource)
	if len(s.wantMAC) != 6 {
		t.Errorf("没记住 MAC， 点名的口会退化成整块机器一起收")
	}
	list := s.Interfaces()
	if len(list) != 1 || list[0].Name != named {
		t.Errorf("接口表是 %+v， 要只有 %s 那一条", list, named)
	}
	if list[0].LinkType != LinkTypeEN10MB {
		t.Errorf("链路类型 %d", list[0].LinkType)
	}
}

// 没 MAC 的口（回环、虚拟口）在这一档认不出包， 当场拒 ——
// 这一档连收都收不到回环（顶上第 10 条）， 说清比抓空一份强。
func TestWin18没有MAC的口当场拒(t *testing.T) {
	var name string
	for _, in := range ifacesForTest(t) {
		if len(in.HardwareAddr) != 6 && in.Flags&net.FlagLoopback != 0 {
			name = in.Name
			break
		}
	}
	if name == "" {
		t.Skip("这台机器上没有不带 MAC 的回环口")
	}
	stub := &stubPktmon{}
	if _, err := openPktmon(Options{}, []string{name}, stub, 1); err == nil {
		t.Fatalf("%s 被接了单， 这一档认不出它的包", name)
	} else if !strings.Contains(err.Error(), "没有 MAC") {
		t.Errorf("说的是 %v", err)
	}
	for _, c := range stub.called() {
		if strings.HasPrefix(c, "start") {
			t.Errorf("认不出口还起了会话：%s", c)
		}
	}
}

// 不点名 = 所有网卡合一路， 表上明写分不开（要分就点名）。
func TestWin19不点名时合一路并说清分不开(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	src, err := openPktmon(Options{BlockRetire: time.Hour}, []string{"甲", "乙", "丙"}, stub, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	list := src.Interfaces()
	if len(list) != 1 || list[0].Name != "pktmon:all" {
		t.Fatalf("接口表 %+v", list)
	}
	if !strings.Contains(list[0].Description, "分不开") {
		t.Error("没告诉用户这一路合了几块口、 能不能分开")
	}
}

func ifacesForTest(t *testing.T) []net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	return ifs
}

// ==================== 每一格都落到位的那条 start ====================

// 界面上填的留长与环大小要真到命令上去。少了 --pkt-size 是「每包只记 128 字节」，
// 少了 --comp nics 是「一个包抄四份」—— 两种都不会报错。
func TestWin20起段的命令带着界面上填的那两格(t *testing.T) {
	stub := &stubPktmon{full: fixture(t, "pktmon-empty.pcapng"), drops: fixture(t, "pktmon-empty.pcapng")}
	s := mustSource(t, stub, Options{SnapLen: 200, BufferSize: 3 << 20}, 1)
	_ = s
	var start string
	for _, c := range stub.called() {
		if strings.HasPrefix(c, "start ") {
			start = c
		}
	}
	if start == "" {
		t.Fatal("没起过段")
	}
	for _, want := range []string{"--capture", "--comp nics", "--pkt-size 200", "-s 3", "-f "} {
		if !strings.Contains(start, want) {
			t.Errorf("那条命令里没有 %q：%s", want, start)
		}
	}
	if !strings.Contains(start, s.dir) {
		t.Errorf("录到别人的目录里去了：%s", start)
	}
}

// ==================== 真机那一条 ====================

// 这一条要管理员。跑不过就 skip 并说清为什么， 不许让它绿着骗人。
// 它验的是桩验不了的那一段：真 pktmon 起不起来、段换不换得动、
// 转出来的那一份我们的读侧认不认、关完之后临时目录在不在。
func TestWin21真机跑一段(t *testing.T) {
	run, err := lookUpPktmon()
	if err != nil {
		t.Skipf("这台机器上没有能用的 pktmon：%v", err)
	}
	if probeElevated() != 1 {
		t.Skip("这一档要管理员会话（pktmon 是系统级的）， 现在这一会话没提权")
	}
	// 别人的筛选器在场时这一条跑不了 —— 那就是这一档该拒起口的样子。
	if out, err := run.run("filter", "list"); err == nil && len(pktmonFilters(out)) > 0 {
		t.Skipf("场上挂着筛选器：%s", strings.Join(pktmonFilters(out), "、"))
	}

	// 口表按真机器给：只有一块网卡时这会走「点名」那一条分支，
	// 于是这一条也顺带验了「按 MAC 认」在真产物上认得出东西（顶上第 2、3 条）。
	src, err := openPktmon(Options{BlockRetire: 2 * time.Second}, mustNames(t), run, probeElevated())
	if err != nil {
		t.Fatalf("真起口：%v", err)
	}
	s := src.(*windowsSource)
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close：%v", err)
		}
		if _, err := os.Stat(s.dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("临时目录没清掉：%s", s.dir)
		}
	}()

	// 造一点真出去的流量。不用 DNS 查询：那台机器上解析器不通时会把这一条拖成几十秒，
	// 而我们要的只是「线上有帧经过」—— 回环那一档本来也收不到（顶上第 10 条）。
	// 发的是能一路推到线上的 UDP 数据报（对面没人接也不影响这一路看见它出去），
	// 另一份发给广播地址：那种帧认不出是哪块口进来的， 正好走「放行」那一条。
	go func() {
		for i := 0; i < 8; i++ {
			d, err := net.ListenPacket("udp", ":0")
			if err != nil {
				t.Logf("开不出出的口子：%v", err)
				return
			}
			for _, dst := range []*net.UDPAddr{
				{IP: net.IPv4(8, 8, 8, 8), Port: 53}, // 一路推到线上的单播（ 对面没人接也照样看得见它出去）
				{IP: net.IPv4bcast, Port: 5353},      // 广播： 认不出是哪块口进来的， 走「放行」那一条
			} {
				if _, err := d.WriteTo([]byte("netkit-capture-probe"), dst); err != nil {
					t.Logf("发给 %s 没出去：%v", dst, err)
				}
			}
			d.Close()
			time.Sleep(400 * time.Millisecond)
		}
	}()

	deadline := time.After(15 * time.Second)
	pkts := 0
	var first Packet
	for pkts < 3 {
		select {
		case <-deadline:
			t.Fatalf("15 秒里只读出 %d 包（ 段换了 %d 回）", pkts, s.segNo)
		default:
		}
		p, err := s.Next()
		if errors.Is(err, ErrClosed) {
			break
		}
		if err != nil {
			t.Fatalf("Next：%v", err)
		}
		if pkts == 0 {
			first = p
		}
		pkts++
	}
	if pkts == 0 {
		t.Fatal("一个包都没有")
	}
	if !first.HasTimestamp {
		t.Error("第一包没带时刻")
	}
	if len(first.Data) < ethHdrSize {
		t.Errorf("第一包 %d 字节， 连以太网头都不够", len(first.Data))
	}
	st := s.Stats()
	if st.Packets < uint64(pkts) {
		t.Errorf("账上 %d 包， 递出去 %d 包", st.Packets, pkts)
	}
	t.Logf("真机读到 %d 包， 换过 %d 段， 丢弃 %d， 残缺 %v", pkts, s.segNo, st.Dropped, st.Lossy)
}

func mustNames(t *testing.T) []string {
	t.Helper()
	names, err := sourceIfaces("")
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// ==================== 桩本身要没骗人 ====================

// 上面那一堆都靠这个桩。桩自己错了的话， 「顺序对」这句结论也是空的，
// 所以把桩的行为钉一条：它至少得真的按参数落文件、 并且能把退出码造对。
func TestWin22桩自己说得过去(t *testing.T) {
	if got := exitWith(t, 159); exitCode(got) != 159 {
		t.Errorf("造出来的错带着 %d", exitCode(got))
	}
	if got := exitCode(io.EOF); got != -1 {
		t.Errorf("拿不到码时回 %d， 要 -1（那不是任何一个已知的码）", got)
	}
	dir := t.TempDir()
	stub := &stubPktmon{full: []byte("正文")}
	if _, err := stub.run("etl2pcap", "x.etl", "--out", filepath.Join(dir, "o.pcapng")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "o.pcapng"))
	if err != nil || string(b) != "正文" {
		t.Errorf("桩没把转换的产物落到盘上：%v", err)
	}
}

// ==================== 这台机器上的 pktmon 用不用得了 ====================

// ★ windows/386 那一档卖的正是 Win7， 而 Win7 上没有 pktmon；「这台机器不支持现场抓」
//
//	这句在 Win10 的机器上永远走不到。不拆成「拿观测值喂」的一格就没法验 ——
//	真机上补不出一台「没有 pktmon」的 Windows。
//	三句话各归各：没有 = ErrUnsupported；有但不会转 = 也是 ErrUnsupported（半件功能）；
//	问不动 = 不算不支持（机器明明有，套错了界面会让用户在这台机器上放弃这一档）。
func TestWin25能力探测按观测值分三句(t *testing.T) {
	notFound := errors.New("exec: \"pktmon\": executable file not found in $PATH")
	cases := []struct {
		name      string
		lookErr   error
		help      string
		helpErr   error
		wantUnsup bool
		wantText  string
	}{
		{"没有这个命令", notFound, "", nil, true, "Win10 1809"},
		{"有，但转不成 pcapng", nil, "用法: pktmon start ...", nil, true, "etl2pcap"},
		{"在，但问不动", nil, "", notFound, false, "问不动"},
		{"全功能", nil, "start stop ... etl2pcap ...", nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := pktmonAvailability(c.lookErr, c.help, c.helpErr)
			if got := errors.Is(err, ErrUnsupported); got != c.wantUnsup {
				t.Errorf("ErrUnsupported = %v， 要 %v（%v）", got, c.wantUnsup, err)
			}
			if c.wantText == "" {
				if err != nil {
					t.Errorf("全功能时回了错：%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantText) {
				t.Errorf("句里没提 %q：%v", c.wantText, err)
			}
		})
	}
}

// 上面那一条靠的是「认得出 etl2pcap 这一项」。中文系统上 pktmon 的帮助整页是中文，
// 所以这一条真机判据要成立，前提必须是**子命令名不被翻译** —— 这台验证机正是中文系统，
// 顺手把前提也量一遍（与提权那一条同一句话：不读它说的话，读跟显示语言无关的那一格）。
func TestWin26中文系统上子命令名仍是英文(t *testing.T) {
	run, err := lookUpPktmon()
	if err != nil {
		t.Skipf("这台机器上没有可用的 pktmon：%v", err)
	}
	out, err := run.run("/?")
	if err != nil {
		t.Skipf("问不动 pktmon：%v", err)
	}
	if !strings.Contains(out, "etl2pcap") {
		t.Errorf("帮助里没有 etl2pcap 这一项， 那探测的判据就得换（这一台回：%s）", firstLines(out, 3))
	}
	var localized bool
	for _, r := range out {
		if r >= 0x4e00 && r <= 0x9fff {
			localized = true
			break
		}
	}
	if !localized {
		t.Log("这台是英文系统：「整页中文而子命令仍是英文」那一半在这台机器上没量到")
	}
}

// firstLines 取前几行， 给报错看形状用（不把整页帮助抄进日志）。
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}
