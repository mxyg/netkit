package tools

// net.capture.peer.* 的测试。
//
// ★ 打桩打在「对端四件事」那一道边上（探测/起/看一眼/停 + 取回），不打在 SSH 上：
//   那一句命令怎么说、对端那句话怎么分档，internal/remote 已经拿真 sh、
//   真后台进程、真 SIGINT 验过一遍了（见 peercap_test.go）。
//   这一层的职责是会话、账本、批准、取回与进表 —— 那些不必再靠一台真机器才能钉住。
//   ★ 也正因为是这样，这一层的测试里出现「假对端说了一句什么」时，
//     盯的是我们**怎么把它说给人听**，不是那句真话对不对。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
	"net.yuhox.com/netkit/internal/state"
)

// ── 假对端 ──

// peerStandin 顶住对端那四件事。字段就是「那台上会回什么」，
// 计数（statCalls/stops）是用来把「看了几次、停了几次」这件事钉住的。
type peerStandin struct {
	mu sync.Mutex

	caps  *remote.PeerCaptureCaps
	probe error

	run      *remote.PeerRun
	startErr error
	spec     remote.PeerCaptureSpec // 底座收到的口径，测试要照着它说话

	statFn    func(calls int) (*remote.PeerStat, error)
	statCalls int

	stop   *remote.PeerStopInfo
	stopFn func(seq int) (*remote.PeerStopInfo, error)
	stops  int

	transfer *remote.Transfer
	pullErr  error
	pulled   []string // 取回时问过哪一份、落在本机哪儿

	removed []string
	closes  int

	d *remote.Device
	x remote.SSHExecer
}

func (f *peerStandin) snapshot() (stops, statCalls, closes int, pulled, removed []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stops, f.statCalls, f.closes, append([]string(nil), f.pulled...), append([]string(nil), f.removed...)
}

func fixPeerEnv(t *testing.T) (*peerStandin, *remote.Manager) {
	t.Helper()
	base := t.TempDir()
	j, err := state.Open(filepath.Join(base, "changes.json"))
	if err != nil {
		t.Fatalf("开不了测试账本：%v", err)
	}
	oldDir, oldJ := captureDir, journal
	oldDial, oldProbe := peerDial, peerProbeFn
	oldStart, oldStat := peerStartFn, peerStatFn
	oldStop, oldRemove := peerStopFn, peerRemoveFn
	oldPoll := peerPollEvery
	captureDir = filepath.Join(base, "captures")
	journal = j
	peerPollEvery = 20 * time.Millisecond
	// 落盘目录先建出来（生产那一路是 remote.Pull 里 MkdirAll 的，假对端不建）
	if err := os.MkdirAll(captureDir, 0o700); err != nil {
		t.Fatal(err)
	}

	f := &peerStandin{
		caps: &remote.PeerCaptureCaps{
			Tool: "tcpdump", Path: "/usr/sbin/tcpdump",
			Ifaces: []string{"eth0", "bge1"}, Dir: "/tmp",
		},
		d: &remote.Device{ID: "ops@10.0.0.9", Host: "10.0.0.9", User: "ops", OS: "linux"},
		x: &fakeSSH{out: map[string]*remote.Output{}, errs: map[string]error{}},
	}
	f.run = &remote.PeerRun{PID: 4242, PeerFile: "/tmp/netkit-cap-test.pcap",
		PeerLog: "/tmp/netkit-cap-test.log", StartedAt: time.Now()}
	// 默认那一本账：起得来、活着、停得干净且报了数
	f.stopFn = func(int) (*remote.PeerStopInfo, error) {
		return &remote.PeerStopInfo{HasCounts: true, Captured: 10, Received: 10,
			Log: "10 packets captured\n10 packets received by filter\n0 packets dropped by kernel"}, nil
	}
	f.transfer = &remote.Transfer{Bytes: 512, Total: 512, Verified: "match", SHA256: "abc"}

	peerDial = func(context.Context, string) (*peerConn, error) {
		return &peerConn{
			d: f.d, x: f.x,
			pull: func(_ context.Context, remotePath, localPath string) (*remote.Transfer, error) {
				f.mu.Lock()
				f.pulled = append(f.pulled, remotePath, localPath)
				tr, perr := f.transfer, f.pullErr
				f.mu.Unlock()
				if perr != nil {
					return nil, perr
				}
				// ★ 假对端「把字节送过来」这件事直接落磁盘：真的没在这条链上，
				//   这一层要验的是停完之后那张表接的是哪一份、对那一份说了什么。
				if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
					t.Fatal(err)
				}
				seedPeerFile(t, localPath)
				return tr, nil
			},
			closeFn: func() { f.mu.Lock(); f.closes++; f.mu.Unlock() },
		}, nil
	}
	peerProbeFn = func(context.Context, remote.SSHExecer, *remote.Device) (*remote.PeerCaptureCaps, error) {
		return f.caps, f.probe
	}
	peerStartFn = func(_ context.Context, _ remote.SSHExecer, _ *remote.Device,
		spec remote.PeerCaptureSpec) (*remote.PeerRun, error) {
		f.mu.Lock()
		f.spec = spec
		err := f.startErr
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return f.run, nil
	}
	peerStatFn = func(_ context.Context, _ remote.SSHExecer, _ *remote.Device,
		_ *remote.PeerRun) (*remote.PeerStat, error) {
		f.mu.Lock()
		f.statCalls++
		n := f.statCalls
		fn := f.statFn
		f.mu.Unlock()
		if fn != nil {
			return fn(n)
		}
		return &remote.PeerStat{Alive: true, Bytes: 4096, BytesKnown: true}, nil
	}
	peerStopFn = func(_ context.Context, _ remote.SSHExecer, _ *remote.Device,
		_ *remote.PeerRun, _ time.Duration) (*remote.PeerStopInfo, error) {
		f.mu.Lock()
		f.stops++
		n, fn, info := f.stops, f.stopFn, f.stop
		f.mu.Unlock()
		if fn != nil {
			return fn(n)
		}
		return info, nil
	}
	peerRemoveFn = func(_ context.Context, _ remote.SSHExecer, _ *remote.Device, paths ...string) error {
		f.mu.Lock()
		f.removed = append(f.removed, paths...)
		f.mu.Unlock()
		return nil
	}

	m := useMgr(t)
	if _, err := m.AddDevice(*f.d); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		haltPeerCapture(t)
		captureDir, journal = oldDir, oldJ
		peerDial, peerProbeFn, peerStartFn = oldDial, oldProbe, oldStart
		peerStatFn, peerStopFn, peerRemoveFn = oldStat, oldStop, oldRemove
		peerPollEvery = oldPoll
	})
	return f, m
}

// haltPeerCapture 收掉测试中途可能留下的那一路：挂着不收，
// 下一个测试的「同一时刻只许一路」就会变成必然失败。
func haltPeerCapture(t *testing.T) {
	t.Helper()
	peerSource.mu.Lock()
	s := peerSource.session
	peerSource.mu.Unlock()
	if s != nil && !s.finished() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.stop(ctx, capWhyUser)
		cancel()
		// ★ 等到那份账真落了才收摊：不等的话，下一个测试拿到的是一个还在收口中的假对端，
		//   它会替上一个测试把计数加一遍，然后两个人一起莫名其妙。
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			t.Errorf("上一路远程抓包的收口没走完就退出测试了")
		}
	}
	// ★ 会话与本机的「当前那本账」一起清（口径同 haltCapture）：上一路的会话或账留着，
	//   下一个测试一进门就看见「已经有一路在跑」，或者更糟 —— 拿着一份不是自己造的账下结论。
	//   只清 ledger，不碰 captureSource.run：那一格是本机那一路的，
	//   正在跑的时候清掉等于替它的 fixture 把「等它退出」这一步跳过去。
	peerSource.mu.Lock()
	peerSource.session = nil
	peerSource.mu.Unlock()
	captureSource.mu.Lock()
	if captureSource.run == nil || captureSource.run.finished() {
		captureSource.ledger = nil
	}
	captureSource.mu.Unlock()
}

func callPeer(t *testing.T, tool ots.Tool, args map[string]any) (ots.Verdict, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Invoke(context.Background(), raw)
	if err != nil {
		return ots.Verdict{}, err
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("%s 没回判定，回了 %T", tool.Name, out)
	}
	return v, nil
}

// peerJSON 把一份判定摊平成字符串好搜。
func peerJSON(t *testing.T, v ots.Verdict) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// seedPeerFile 造一份真读得动的抓包文件，摆在「已经取回来的那一份」那个路径上。
// ★ 用生产的写手真写一遍，再让 net.capture.flows 真读回来 —— 「文件里 100 包、
//
//	表上 87 包」这类错只有把文件当真读一遍才看得见。
func seedPeerFile(t *testing.T, path string) {
	t.Helper()
	pkts := append(rtspSession(time.Now().Add(-time.Second)), arpGarbage(time.Now(), 4)...)
	src := writeCapFile(t, t.TempDir(), pkts)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ── 探测 ──

func Test探对端把采集器与口列出来(t *testing.T) {
	f, _ := fixPeerEnv(t)
	v, err := callPeer(t, peerCaptureProbeTool, map[string]any{"device": f.d.ID})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerReady {
		t.Errorf("有采集器却判成 %q：%s", v.Code, v.Note)
	}
	if got, _ := v.Values["interfaces"].([]string); strings.Join(got, ",") != "eth0,bge1" {
		t.Errorf("口列表没按那台上说的原样给：%v（现场要在两块口里挑，少了名字就挑不成）", got)
	}
	if p, _ := v.Values["path"].(string); p != "/usr/sbin/tcpdump" {
		t.Errorf("没说那个命令在对端哪儿：%v（起不来时这一格是唯一能指着说的东西）", v.Values["path"])
	}
}

func Test对端没有采集器时说的是一个事实不是一句报错(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.caps = &remote.PeerCaptureCaps{Note: "那台机器的 PATH 里找不着 tcpdump", Dir: "/tmp"}
	v, err := callPeer(t, peerCaptureProbeTool, map[string]any{"device": f.d.ID})
	if err != nil {
		t.Fatalf("那台上没装 tcpdump 是对这台机器的一句说明，不是这个工具坏了：%v", err)
	}
	if v.Code != capPeerNoCollector {
		t.Errorf("判成 %q，要 %q", v.Code, capPeerNoCollector)
	}
	if n, _ := v.Values["next"].(string); n == "" || !strings.Contains(n, "装") {
		t.Errorf("没说下一步：%q", v.Values["next"])
	}
}

// ── Windows 这一路（pktmon）：这一层验的是「怎么把那一档说给人听」，
//   那一句 pktmon 到底怎么说、退出码 159 怎么分档，internal/remote 拿真 sh +
//   假 pktmon 验过一遍（见 peercap_test.go）。这里把对端四件事打桩成 pktmon 那一档，
//   钉的是分流走没走对、两份路径拼没拼对、每一种独有判定给没给对码和下一步。 ──

// winCaps 是探出来的那台 Windows 的样子：pktmon 在、会 etl2pcap、落点是反斜杠目录、
// 不列口（pktmon 只能全机器抓，见 remote 那一层）。
func winCaps() *remote.PeerCaptureCaps {
	return &remote.PeerCaptureCaps{
		Tool: "pktmon", Path: `C:\Windows\System32\pktmon.exe`,
		Ifaces: nil, Dir: `C:\Users\ops\AppData\Local\Temp`,
		Etl2Pcap: true, Note: "pktmon 这一档抓全部网卡，不逐块点名",
	}
}

func winRun() *remote.PeerRun {
	return &remote.PeerRun{Windows: true,
		PeerFile:  `C:\Users\ops\AppData\Local\Temp\netkit-cap-x.pcapng`,
		EtlPath:   `C:\Users\ops\AppData\Local\Temp\netkit-cap-x.etl`,
		StartedAt: time.Now()}
}

// Windows 探测：pktmon 在且能转 → ready，口列表如实为空也不当「问不出来」拦掉。
func TestWindows对端探测走pktmon且空口列表不算没接口(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	v, err := callPeer(t, peerCaptureProbeTool, map[string]any{"device": f.d.ID})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerReady {
		t.Errorf("pktmon 在、能转，却判成 %q：%s", v.Code, v.Note)
	}
	if got, _ := v.Values["etl2pcap"].(bool); !got {
		t.Errorf("没把 etl2pcap 能力如实带回来：%+v", v.Values)
	}
	// ★ 空口列表在 Windows 上是设计如此，不能报成 no-interface-list（那会把能走的路堵死）。
	if v.Code == capPeerNoIfaceList {
		t.Error("Windows 那一路本来就只全机器抓，报「没有口列表」等于骗人说这台不能用")
	}
}

// Windows 那台没有 etl2pcap：专门一档，别混进「没采集器」。
func TestWindows没有etl2pcap给专门的码(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	f.caps.Etl2Pcap = false
	v, err := callPeer(t, peerCaptureProbeTool, map[string]any{"device": f.d.ID})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerNoEtl2Pcap {
		t.Errorf("判成 %q，要 %q（抓得出 .etl、转不成表是第三种事实，不是没采集器）", v.Code, capPeerNoEtl2Pcap)
	}
	if n, _ := v.Values["next"].(string); !strings.Contains(n, "etl2pcap") && !strings.Contains(n, "升") {
		t.Errorf("没说这一档怎么补（升级/手动转/换机器）：%q", n)
	}
}

// Windows 起一路：把 .etl 与 .pcapng 两个落点和 -s（向上取整）都算出来传给底座。
func TestWindows起一路拼出etl与pcapng两份路径(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	f.run = winRun()
	v, err := callPeer(t, peerCaptureStartTool, map[string]any{
		"device": f.d.ID, "interface": "以太网", "maxMB": 100})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerRunning {
		t.Errorf("判成 %q：%s", v.Code, v.Note)
	}
	sp := f.spec
	if !strings.HasSuffix(sp.EtlPath, ".etl") || !strings.Contains(sp.EtlPath, `\`) {
		t.Errorf(".etl 落点不对（要用反斜杠、要以 .etl 结尾）：%q", sp.EtlPath)
	}
	if !strings.HasSuffix(sp.PcapPath, ".pcapng") || !strings.Contains(sp.PcapPath, `\`) {
		t.Errorf(".pcapng 落点不对：%q", sp.PcapPath)
	}
	if sp.MaxMB < 1 {
		t.Errorf("-s 传了 %d：0 在 pktmon 那里是「默认 512MB」不是「不限」，必须向上取整到 >=1", sp.MaxMB)
	}
	// ★ 点名的接口在 Windows 上不做逐块区分，运行那句必须说破「抓的是全部网卡」。
	if all, _ := v.Values["capturesAllInterfaces"].(bool); !all {
		t.Errorf("没如实标出「这一档抓全部网卡、点名的口不生效」（悄悄按名字只抓一块是假的）：%+v", v.Values)
	}
}

// Windows 这一档不认 BPF：带 filter 来当场拒，绝不悄悄丢掉假装全抓。
func TestWindows这一档不认BPF当场拒(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	f.run = winRun()
	v, err := callPeer(t, peerCaptureStartTool, map[string]any{
		"device": f.d.ID, "interface": "以太网", "filter": "tcp port 554"})
	if err != nil {
		t.Fatalf("带 filter 该出一条判定，不该把工具问倒：%v", err)
	}
	if v.Code != capPeerFilterUnsupported {
		t.Errorf("判成 %q，要 %q（丢掉这个参数假装全抓 = 给人一份口径不同的表）", v.Code, capPeerFilterUnsupported)
	}
	// 当场拒就意味着压根没起那一路。
	if _, stats, _, _, _ := f.snapshot(); stats != 0 {
		t.Error("过滤器这条档拒之前不许先起采集")
	}
}

// pktmon 回 159（全机器只能一路）：单独一档，下一步是去 stop 那一录，不是提权。
func TestWindows那台已有一路pktmon给busy码(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	f.startErr = &remote.PeerStartError{Problem: remote.PeerProblemBusy,
		Detail: "There is already a capture running on this computer."}
	v, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "以太网"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerBusy {
		t.Errorf("判成 %q，要 %q", v.Code, capPeerBusy)
	}
	if n, _ := v.Values["next"].(string); !strings.Contains(n, "stop") {
		t.Errorf("busy 的下一步该是去停掉别人那一录，不是提权：%q", n)
	}
}

// 收口时 etl2pcap 没成：专门一档，且绝不能删那唯一一份 .etl、也不去 pull 一份不存在的东西。
func TestWindows转换失败留原件给专门的码(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	f.run = winRun()
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "以太网"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.stopFn = nil
	f.stop = &remote.PeerStopInfo{ConvertErr: "etl2pcap: the file is not a valid trace"}
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerConvertFailed {
		t.Errorf("判成 %q，要 %q", v.Code, capPeerConvertFailed)
	}
	_, _, _, pulled, removed := f.snapshot()
	if len(pulled) != 0 {
		t.Errorf("转换没成还去 pull 一份不存在的 pcapng：%v", pulled)
	}
	if len(removed) != 0 {
		t.Errorf("转换没成却删了对端（那份 .etl 是唯一原件）：%v", removed)
	}
	if etl, _ := v.Values["etlFile"].(string); !strings.HasSuffix(etl, ".etl") {
		t.Errorf("没说那份 .etl 还在对端哪儿：%+v", v.Values)
	}
}

// 收口顺利：转好的 pcapng 取回本机，对端那两份（pcapng + .etl）都要删干净。
func TestWindows停完取回pcapng并连etl一起删(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.d.OS = "windows"
	f.caps = winCaps()
	f.run = winRun()
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "以太网"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.stopFn = nil
	// pktmon 不打 tcpdump 那三行账 → HasCounts=false；转换成功 → ConvertErr 空。
	f.stop = &remote.PeerStopInfo{HasCounts: false}
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	// 包数从文件里数（对端没报账），落 no-counts 这一档，是诚实的说法。
	if v.Code != capPeerStoppedNoCounts {
		t.Errorf("判成 %q，要 %q（pktmon 不打那本账）", v.Code, capPeerStoppedNoCounts)
	}
	_, _, _, _, removed := f.snapshot()
	j := strings.Join(removed, " ")
	if !strings.Contains(j, ".pcapng") || !strings.Contains(j, ".etl") {
		t.Errorf("对端没删干净（原始包留在现场 = 把明文丢那儿）：%v", removed)
	}
}

// ── 起 ──

func Test起远程抓包先过改动账本这一关(t *testing.T) {
	f, _ := fixPeerEnv(t)
	v, err := callPeer(t, peerCaptureStartTool, map[string]any{
		"device": f.d.ID, "interface": "eth0", "filter": "tcp port 554", "snapLen": 1600, "seconds": 30,
	})
	if err != nil {
		t.Fatalf("起不来：%v", err)
	}
	if v.Code != capPeerRunning {
		t.Errorf("判成 %q：%s", v.Code, v.Note)
	}
	if f.spec.Interface != "eth0" || f.spec.Filter != "tcp port 554" || f.spec.SnapLen != 1600 {
		t.Errorf("底座收到的口径跟人给的不一样：%+v", f.spec)
	}
	if f.spec.PeerFile == "" || f.spec.PeerLog == "" {
		t.Errorf("没定下那份文件与那本日志落在对端哪儿：%+v", f.spec)
	}
	if f.spec.Collector != "/usr/sbin/tcpdump" {
		t.Errorf("没用探出来的那一个命令：%+v", f.spec)
	}
	// ★ 会一直在别人机器上跑东西、一直往人家盘上写的改动，必须进账本
	es := journal.Outstanding()
	if len(es) != 1 || es[0].Kind != "capture-peer" {
		t.Fatalf("改动账本里没有这一路：%+v", es)
	}
	if !strings.Contains(es[0].What, "10.0.0.9") || !strings.Contains(es[0].What, "eth0") {
		t.Errorf("账本上那句话没念清动的是哪台、抓的是哪个口：%s", es[0].What)
	}
	if a := fmt.Sprint(mgr.AuditTail(20)); !strings.Contains(a, "capture-peer.start") {
		t.Errorf("这一路没进审计：%s", a)
	}
}

func Test批准框那句话念出设备口与上限(t *testing.T) {
	fixPeerEnv(t)
	raw := json.RawMessage(`{"device":"ops@10.0.0.9","interface":"eth0","maxMB":64,"seconds":60}`)
	d := peerCaptureStartTool.Describe(raw)
	for _, want := range []string{"10.0.0.9", "eth0", "64", "60"} {
		if !strings.Contains(d, want) {
			t.Errorf("批准框里没念到 %q：%s", want, d)
		}
	}
	if !strings.Contains(d, "★") {
		t.Errorf("这一条会在别人机器上留一路一直写的采集，批准框里没摆出那句风险：%s", d)
	}
	// 参数没给对也要念得出人话，不能空白一片
	if d := peerCaptureStartTool.Describe(json.RawMessage(`{"device":"x","seconds":-5}`)); d == "" {
		t.Error("参数不合式时批准框空白一片")
	}
}

func Test同一时刻只许一路远程抓包(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	_, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "bge1"})
	if err == nil {
		t.Fatal("两路同时挂在别人机器上，现场分不清哪份是哪一路，那颗「停」也不知道对应谁")
	}
	if !strings.Contains(err.Error(), "net.capture.peer.stop") {
		t.Errorf("没说先停掉那一路：%v", err)
	}
}

func Test起不来的每一种各给一个码和一句下一步(t *testing.T) {
	cases := []struct {
		problem remote.PeerCaptureProblem
		want    string
	}{
		{remote.PeerProblemPrivilege, capPeerNoPriv},
		{remote.PeerProblemInterface, capPeerNoIface},
		{remote.PeerProblemFilter, capPeerBadFilter},
		{remote.PeerProblemDied, capPeerDied},
		{remote.PeerProblemNoTool, capPeerNoCollector},
		{remote.PeerProblemStuck, capPeerStuck},
		{remote.PeerProblemConnection, capPeerConn},
	}
	for _, c := range cases {
		f, _ := fixPeerEnv(t)
		f.startErr = &remote.PeerStartError{Problem: c.problem,
			Detail: "tcpdump: eth0: You don't have permission to capture on that device"}
		v, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"})
		if err != nil {
			t.Fatalf("%s：起不来该出一条判定，不该把工具问倒：%v", c.problem, err)
		}
		if v.Code != c.want {
			t.Errorf("%s 判成 %q，要 %q", c.problem, v.Code, c.want)
		}
		// ★ 每一种的下一步都不一样：提权、改名、改过滤器、换本机抓 —— 混成一句人就只会重复点同一个按钮
		if n, _ := v.Values["next"].(string); n == "" {
			t.Errorf("%s 没给下一步", c.problem)
		}
		if !otsCodeRE.MatchString(v.Code) {
			t.Errorf("判定码 %q 不合式", v.Code)
		}
		// 对端那句原话要留着：档是我们分的，人要看的是那台自己说了什么
		if s, _ := v.Values["peerSaid"].(string); s == "" {
			t.Errorf("%s 没带上对端那句话：%+v", c.problem, v.Values)
		}
	}
}

// ── 看一眼 / 自动停 ──

func Test到量了自己停并说清是到顶了不是没流量(t *testing.T) {
	f, _ := fixPeerEnv(t)
	// 每看一次涨 1MB：maxMB=1 那一档很快就该被自己掐掉
	f.statFn = func(calls int) (*remote.PeerStat, error) {
		return &remote.PeerStat{Alive: true, Bytes: int64(calls) << 20, BytesKnown: true}, nil
	}
	if _, err := callPeer(t, peerCaptureStartTool,
		map[string]any{"device": f.d.ID, "interface": "eth0", "maxMB": 1}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v, err := callPeer(t, peerCaptureStatusTool, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(v.Code, "capture-peer-stopped") {
			if why, _ := v.Values["stopWhy"].(string); why != capWhyMaxBytes {
				t.Errorf("到量停的却记成 %q —— 「到顶了」和「这条链路真的没流量」是两种相反的下一步", why)
			}
			if !strings.Contains(v.Note, "上限") {
				t.Errorf("没把「文件到上限了，后面还有包没进来」说出口：%s", v.Note)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("到了 maxMB 还没自己停（挂着不停会把现场那台机器的盘写满）：%+v", f.spec)
}

func Test对端那一路自己死了要说死在哪儿(t *testing.T) {
	f, _ := fixPeerEnv(t)
	f.statFn = func(calls int) (*remote.PeerStat, error) {
		if calls <= 1 {
			return &remote.PeerStat{Alive: true, Bytes: 4096, BytesKnown: true}, nil
		}
		return &remote.PeerStat{Alive: false, Bytes: 8192, BytesKnown: true}, nil
	}
	f.stopFn = func(int) (*remote.PeerStopInfo, error) {
		// ★ 那三个数是底座从原文里数出来的（remote.parsePeerCounts），
		//   真跑时 Log 与结构体这两格一定同源；这里把两边都摆上，
		//   盯的是「对端报的丢包数有没有一路带到结果里」。
		return &remote.PeerStopInfo{HasCounts: true, Captured: 20, Received: 20, Dropped: 5,
			Log: "20 packets captured\n20 packets received by filter\n5 packets dropped by kernel"}, nil
	}
	if _, err := callPeer(t, peerCaptureStartTool,
		map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	var v ots.Verdict
	last, lastNote := "", ""
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := callPeer(t, peerCaptureStatusTool, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		last = got.Code
		lastNote = got.Note
		if strings.HasPrefix(got.Code, "capture-peer-stopped") {
			v = got
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v.Code == "" {
		_, stats, _, _, _ := f.snapshot()
		t.Fatalf("对端那一路死了而我们还在报「在跑」—— 界面上会一直显示一个已经不存在的采集（%q）：看门这 3 秒里问了对端 %d 次；它说的是：%s", last, stats, lastNote)
	}
	if why, _ := v.Values["stopWhy"].(string); why != capWhyPeerDied {
		t.Errorf("这一种停的理由记成 %q，要 %q：人自己停的、到量、对端自己死了，是三件不同的事",
			why, capWhyPeerDied)
	}
	if d, _ := v.Values["dropped"].(int64); d != 5 {
		t.Errorf("对端报了丢包 5 却没带回来：%v", v.Values["dropped"])
	}
}

// Test收口那一段还在做的时候这一路要看得见 盯的是中间那一档：已经打过招呼（SIGINT）、
// 还在等对端退出、把那份取回来并读成表。★ 这一步可以很慢（文件大就要整份过一遍 SSH），
// 期间界面必须还认这一路 —— 报成「没有这一路」等于凭空抹掉一路正在收的采集，
// 而那颗再按一次的「停」会以为自己已经停成了。
func Test收口那一段还在做的时候这一路要看得见(t *testing.T) {
	f, _ := fixPeerEnv(t)
	release := make(chan struct{})
	f.stopFn = func(int) (*remote.PeerStopInfo, error) {
		<-release // 顶住「打招呼那一下」，把收口中这一段拉出来
		return &remote.PeerStopInfo{HasCounts: true, Captured: 3, Received: 3,
			Log: "3 packets captured\n3 packets received by filter\n0 packets dropped by kernel"}, nil
	}
	if _, err := callPeer(t, peerCaptureStartTool,
		map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	type done struct {
		v   ots.Verdict
		err error
	}
	stopped := make(chan done, 1)
	go func() {
		out, err := peerCaptureStopTool.Invoke(context.Background(), json.RawMessage(`{}`))
		if v, ok := out.(ots.Verdict); ok {
			stopped <- done{v, err}
			return
		}
		stopped <- done{ots.Verdict{}, err}
	}()

	// 先确认真的进到「收口中」，再问状态（否则测的是还没开始停）
	deadline := time.Now().Add(2 * time.Second)
	for {
		stops, _, _, _, _ := f.snapshot()
		if stops > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("那颗停压根没去碰对端那一路")
		}
		time.Sleep(5 * time.Millisecond)
	}

	v, err := callPeer(t, peerCaptureStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code == capPeerNoSession {
		t.Errorf("收口还在做就问状态，答的是「没有这一路」：%s —— 界面上这一路会凭空消失", v.Note)
	}
	if v.Code != capPeerStopping {
		t.Errorf("这一档判成 %q，要 %q：%s", v.Code, capPeerStopping, v.Note)
	}
	if s, _ := v.Values["stopping"].(bool); !s {
		t.Errorf("没标出「正在收口」，界面没法把那颗停按下去：%+v", v.Values)
	}
	if next, _ := v.Values["next"].(string); next == "" {
		t.Errorf("没给下一步：%+v", v.Values)
	}

	// 收口期间再按一次「停」不许另起一路收口：两次打招呼会把对端那份切坏，
	// 而且第二个人会以为自己停成了。
	again, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if again.Code != capPeerStopping {
		t.Errorf("收口期间第二次停判成 %q，要 %q：%s", again.Code, capPeerStopping, again.Note)
	}

	close(release)
	got := <-stopped
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.v.Code != capPeerStopped {
		t.Errorf("收完判成 %q：%s", got.v.Code, got.v.Note)
	}
	stops, _, _, _, _ := f.snapshot()
	if stops != 1 {
		t.Errorf("对端那一路被打招呼 %d 次，只能 1 次：第二次是把同一份文件再切一刀", stops)
	}
	after, err := callPeer(t, peerCaptureStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if after.Code != capPeerStopped {
		t.Errorf("停完再问状态判成 %q：%s", after.Code, after.Note)
	}
}

// ── 停、取回、进表 ──

func Test停完把那份取回来并进同一张表(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	// 取回这一步要真落一份读得动的文件到本机（假对端直接写磁盘，字节怎么过来是 Pull 那一路的事）
	f.pullErr = fmt.Errorf("还没落盘")
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	_ = v
	_ = err
	// 换回能落盘的版本重跑一次这一路（上面那一次已经把会话收掉了）
	haltPeerCapture(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.pullErr = nil
	f.transfer = &remote.Transfer{Bytes: 1, Total: 1, Verified: "match"}
	f.mu.Unlock()
	v, err = callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatalf("停不下来：%v", err)
	}
	if v.Code != capPeerStopped {
		t.Errorf("判成 %q：%s", v.Code, v.Note)
	}
	local, _ := v.Values["file"].(string)
	if local == "" {
		t.Fatalf("没说本机这一份落在哪儿：%+v", v.Values)
	}
	if _, err := os.Stat(local); err != nil {
		t.Fatalf("报的本机路径上没这份：%v", err)
	}
	// ★ 停了以后这份要顶进「当前那本账」，net.capture.flows 那张表就是它 ——
	//   同一个界面不许因为包是从对端来的就走另一套口径。
	fv, err := callPeer(t, captureFlowsTool, map[string]any{})
	if err != nil {
		t.Fatalf("出表失败：%v", err)
	}
	if fv.Code != capFlows {
		t.Errorf("表判成 %q：%s", fv.Code, fv.Note)
	}
	if led := currentLedger(); led == nil || led.origin != "peer" {
		t.Errorf("这张表的来路没记成对端来的：%+v", led)
	}
	// ★ 收完对端那一路以后，本机那一路的问话必须还答得出：顶账那一步借用了本机的
	//   那把锁，忘了还的话，从这里起「本机在不在抓」这一问就永远没有回音，
	//   连 net.capture.start 的开新一路都会一起挂住（它进门先问的就是这一把锁）。
	sv, err := callPeer(t, captureStatusTool, map[string]any{})
	if err != nil {
		t.Fatalf("对端那一路收完之后，本机的状态问不出来了：%v", err)
	}
	if sv.Code != capIdle {
		t.Errorf("本机状态判成 %q：%s", sv.Code, sv.Note)
	}
	if on, _ := sv.Values["running"].(bool); on {
		t.Errorf("本机的状态里凭空多出一路在跑的抓包：%+v", sv.Values)
	}
	// 对端那一份默认要删掉：那是原始包，留在别人机器上而我们这边已经取走了
	stops, _, closes, _, removed := f.snapshot()
	if stops != 2 {
		t.Errorf("停了 %d 次（两路各一次才对）", stops)
	}
	if len(removed) == 0 || !strings.Contains(strings.Join(removed, " "), "netkit-cap-test.pcap") {
		t.Errorf("对端那一份没删：%v（原始包留在现场那台机器上 = 把明文丢在那儿）", removed)
	}
	if closes != 2 {
		t.Errorf("通道没关：%d —— 挂着不动的远程会话就是别人机器上的一个连接数", closes)
	}
	// 账本上这一路要结掉：停完并收干净了，就不该再挂着一笔「还改着」的账
	if es := journal.Outstanding(); len(es) != 0 {
		t.Errorf("停完还留着一笔没结的账：%+v", es)
	}
}

func Test不删对端那一份要明写它还在哪儿(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{"keepPeer": true})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, removed := f.snapshot()
	if len(removed) != 0 {
		t.Errorf("说了留，还是删了：%v", removed)
	}
	if !strings.Contains(v.Note, "/tmp/netkit-cap-test.pcap") {
		t.Errorf("没说那份还留在对端哪儿：%s（人第二天回去找就找不到东西了）", v.Note)
	}
}

func Test取不回来时说清那份还在对端(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.pullErr = fmt.Errorf("设备 ops@10.0.0.9 没开 SFTP 子系统")
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatalf("取不回来是对那一份的一个说法，不该把工具问倒：%v", err)
	}
	if v.Code != capPeerPullFailed {
		t.Errorf("判成 %q，要 %q", v.Code, capPeerPullFailed)
	}
	n, _ := v.Values["next"].(string)
	if !strings.Contains(n, "/tmp/netkit-cap-test.pcap") || !strings.Contains(n, "net.capture.open") {
		t.Errorf("下一步没说那份在哪、怎么接着用：%q", n)
	}
	if led := currentLedger(); led != nil && led.origin == "peer" {
		t.Error("一份压根没取回来的东西却顶进了当前账")
	}
}

func Test校验对不上的那份不许当整份用(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.transfer = &remote.Transfer{Bytes: 512, Total: 512, Verified: "mismatch"}
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerVerifyMismatch {
		t.Errorf("判成 %q，要 %q —— 字节数对得上但整包摘要对不上，是「这份被人动过或传坏了」", v.Code, capPeerVerifyMismatch)
	}
	if !strings.Contains(v.Note, "别拿这份下结论") && !strings.Contains(v.Note, "重抓") {
		t.Errorf("没说清这一份的账不可信：%s", v.Note)
	}
}

func Test对端没说账的时候包数只能从文件里数(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.stopFn = nil
	f.stop = &remote.PeerStopInfo{HasCounts: false, Log: "tcpdump: eth0: listening, but no counts on exit"}
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerStoppedNoCounts {
		t.Errorf("判成 %q，要 %q", v.Code, capPeerStoppedNoCounts)
	}
	if !strings.Contains(v.Note, "丢没丢") {
		t.Errorf("对端没说账的时候，界面必须敢写「说不出丢没丢」：%s", v.Note)
	}
	if got, _ := v.Values["droppedKnown"].(bool); got {
		t.Error("对端没报丢包，却把 droppedKnown 报成知道（那等于把「没数到」说成「没丢」）")
	}
}

func Test硬断的那一路明写文件可能短一截(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.stopFn = nil
	f.stop = &remote.PeerStopInfo{Forced: true, HasCounts: false, Log: ""}
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerStoppedForced {
		t.Errorf("判成 %q，要 %q —— 硬断的那一路打不出账，那份文件也可能短一截", v.Code, capPeerStoppedForced)
	}
	if !strings.Contains(v.Note, "短一截") {
		t.Errorf("没写那句：SIGKILL 没有退出那一下，文件末尾可能缺包：%s", v.Note)
	}
	if !strings.Contains(v.Note, "不听招呼") && !strings.Contains(v.Note, "SIGINT") {
		t.Errorf("没说这一路是先不听打招呼才硬断的：%s", v.Note)
	}
}

func Test对端那句原话进结果之前先洗一遍(t *testing.T) {
	f, _ := fixPeerEnv(t)
	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.stopFn = nil
	// ★ 结果会发给 AI、也可能被打进诊断包。对端的 stderr 是别人的机器上回来的自由文本：
	//   现场见过设备把带口令的命令行回显进那里。
	f.stop = &remote.PeerStopInfo{HasCounts: true, Captured: 2, Received: 2,
		Log: "password: hunter2\n2 packets captured\n2 packets received by filter"}
	f.mu.Unlock()
	v, err := callPeer(t, peerCaptureStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	blob := peerJSON(t, v)
	if strings.Contains(blob, "hunter2") {
		t.Errorf("对端那本日志里的口令原样进了结果：%s", blob)
	}
	if !strings.Contains(blob, "password:") {
		t.Errorf("键名该留着（那是「带了但没给你看」，不是「没带」）：%s", blob)
	}
	if a := fmt.Sprint(mgr.AuditTail(30)); strings.Contains(a, "hunter2") {
		t.Errorf("口令进了审计：%s", a)
	}
	if got, _ := v.Values["captured"].(int64); got != 2 {
		t.Errorf("洗的时候把账洗掉了：captured=%v", v.Values["captured"])
	}
}

func Test没在跑的时候状态要接着上一次的账说(t *testing.T) {
	f, _ := fixPeerEnv(t)
	v, err := callPeer(t, peerCaptureStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerNoSession {
		t.Errorf("判成 %q，要 %q", v.Code, capPeerNoSession)
	}
	if !strings.Contains(v.Note, "net.capture.peer.probe") {
		t.Errorf("没说先探一下：%s", v.Note)
	}

	if _, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := callPeer(t, peerCaptureStopTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	v, err = callPeer(t, peerCaptureStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != capPeerStopped {
		t.Errorf("停完再问状态判成 %q：%s", v.Code, v.Note)
	}
	if s, _ := v.Values["file"].(string); s == "" {
		t.Errorf("上一次的账没留本机那份在哪：%+v", v.Values)
	}
}

func Test进程重启时对端那一路不能算已经停了(t *testing.T) {
	base := t.TempDir()
	j, err := state.Open(filepath.Join(base, "changes.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldJ := journal
	journal = j
	t.Cleanup(func() { journal = oldJ })

	if _, err := j.Register("capture-peer", "在 ops@10.0.0.9 的 eth0 上开一路抓包",
		map[string]any{"capturing": false},
		map[string]any{"device": "ops@10.0.0.9", "peerFile": "/tmp/netkit-cap-1.pcap"}); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(base, "log.txt")
	f, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	lg := slog.New(slog.NewTextHandler(f, nil))
	restoreCapture(lg)
	f.Close()
	logged, _ := os.ReadFile(logFile)
	if len(j.Outstanding()) != 0 {
		t.Errorf("这笔悬账没结：%+v", j.Outstanding())
	}
	// ★★ 与本机那一路最不一样的一点：本机进程退了，采集口跟着没了；
	//   对端那一路是别人机器上的一个进程，我们重启不等于它停 ——
	//   说成「已随上次进程退出而关」就是把人支去查一件根本不成立的事。
	s := string(logged)
	if strings.Contains(s, "已随上次进程退出") {
		t.Errorf("把对端那一路说成本机那样自己关了：%s", s)
	}
	if !strings.Contains(s, "/tmp/netkit-cap-1.pcap") {
		t.Errorf("没告诉人那份还在对端哪儿：%s", s)
	}
	if !strings.Contains(s, "10.0.0.9") {
		t.Errorf("没说是哪台机器上可能还挂着这一路：%s", s)
	}
}

// ── 声明 ──

func Test远程抓包四个工具的声明(t *testing.T) {
	fixPeerEnv(t)
	r := ots.NewRegistry(true)
	Register(r)
	for _, name := range []string{"net.capture.peer.probe", "net.capture.peer.start",
		"net.capture.peer.status", "net.capture.peer.stop"} {
		got, ok := r.Lookup(name)
		if !ok {
			t.Fatalf("%s 没注册进注册表", name)
		}
		if !json.Valid(got.Schema) {
			t.Errorf("%s 的 schema 不是合法 JSON", name)
		}
		if got.Class == ots.ClassMutate && got.Describe == nil {
			t.Errorf("%s 是 mutate 却没有 Describe —— 批准框上会空白一片", name)
		}
	}
	// 只有「问问那台上有什么」「看一眼」是只读的：起与停都在动别人的机器
	if tool, _ := r.Lookup("net.capture.peer.probe"); tool.Class != ots.ClassRead {
		t.Errorf("probe 被判成 %q", tool.Class)
	}
	if tool, _ := r.Lookup("net.capture.peer.status"); tool.Class != ots.ClassRead {
		t.Errorf("status 被判成 %q", tool.Class)
	}
	for _, name := range []string{"net.capture.peer.start", "net.capture.peer.stop"} {
		tool, _ := r.Lookup(name)
		if tool.Class != ots.ClassMutate {
			t.Errorf("%s 是 %q —— 关在 mutate 总开关外面才拦得住", name, tool.Class)
		}
	}
}

func Test远程抓包的判定码都合式且不重复(t *testing.T) {
	seen := map[string]string{}
	for _, c := range []string{capPeerReady, capPeerNoCollector, capPeerNoIfaceList,
		capPeerRunning, capPeerStopping, capPeerStopped, capPeerStoppedForced, capPeerStoppedNoCounts,
		capPeerPullFailed, capPeerVerifyMismatch, capPeerNoSession, capPeerUnsupportedOS,
		capPeerStartFailed, capPeerNoPriv, capPeerNoIface, capPeerBadFilter,
		capPeerDied, capPeerStuck, capPeerConn,
		capPeerNoEtl2Pcap, capPeerConvertFailed, capPeerBusy, capPeerFilterUnsupported} {
		if !otsCodeRE.MatchString(c) {
			t.Errorf("判定码 %q 不合 [OTS-5.5]（只能小写字母数字连字符）", c)
		}
		if prev, dup := seen[c]; dup {
			t.Errorf("%q 出现了两次（%s 与 %s）—— 一个码对应一种说法，重复就等于两种说法挤在一起", c, prev, c)
		}
		seen[c] = "seen"
	}
}

// 每一种判定都要能指着一个具体的下一步说：这一栏是界面上唯一那句「所以呢」。
func Test每一种远程判定都给了下一步(t *testing.T) {
	codes := []string{capPeerReady, capPeerNoCollector, capPeerNoIfaceList, capPeerRunning,
		capPeerStopping,
		capPeerStopped, capPeerStoppedForced, capPeerStoppedNoCounts, capPeerPullFailed,
		capPeerVerifyMismatch, capPeerNoSession, capPeerStartFailed, capPeerNoPriv,
		capPeerNoIface, capPeerBadFilter, capPeerDied, capPeerStuck, capPeerConn,
		capPeerNoEtl2Pcap, capPeerConvertFailed, capPeerBusy, capPeerFilterUnsupported}
	for _, c := range codes {
		if peerNextStep(c, "") == "" {
			t.Errorf("%s 没有下一步", c)
		}
	}
}

func Test参数写错当场拒不换成默认值(t *testing.T) {
	f, _ := fixPeerEnv(t)
	for _, a := range []map[string]any{
		{"device": f.d.ID, "interface": "eth0", "snapLen": -1},
		{"device": f.d.ID, "interface": "eth0", "seconds": -5},
		{"device": f.d.ID, "interface": "eth0", "maxMB": -1},
		{"device": f.d.ID, "interface": ""},
		{"device": "", "interface": "eth0"},
	} {
		_, err := callPeer(t, peerCaptureStartTool, a)
		if err == nil {
			t.Errorf("%v 被收下了 —— 负数是「明确要一个不可能的值」，悄悄换成默认值会把「参数写错了」演成「这台机器就这样」", a)
			haltPeerCapture(t)
		}
	}
}

func Test远程那一路不许把凭据带进结果(t *testing.T) {
	f, _ := fixPeerEnv(t)
	v, err := callPeer(t, peerCaptureStartTool, map[string]any{"device": f.d.ID, "interface": "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	blob := peerJSON(t, v)
	for _, leak := range []string{"hunter2", `"password"`} {
		if strings.Contains(blob, leak) {
			t.Errorf("结果里带了 %s（结果会发给 AI，也可能打进诊断包）：%s", leak, blob)
		}
	}
	if pw := f.d.Password; pw != "" && strings.Contains(blob, pw) {
		t.Errorf("登记时那个口令原样回到了结果里：%s", blob)
	}
}
