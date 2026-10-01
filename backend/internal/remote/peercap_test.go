package remote

// 对端抓包的测试底座。
//
// ★ 跑的是**真**东西：进程内的 SSH + SFTP 服务器（和 remote_test.go 同一套路）、
//   `/bin/sh -c` 真起真落盘的假 tcpdump（一个后台长起来的真 pcap 文件）、
//   真 SIGINT、真文件字节数。
//   不是因为省事才用假设备 —— 这一路的判定全在「对端那句话怎么说」上：
//   「You don't have permission to capture on that device」和
//   「eth9: No such device available」和「syntax error in filter expression」
//   是三件不同的事、三个下一步，拿注入的字符串钉不出它们各自怎么走。
//
// 假 tcpdump 用**口名与过滤器里的记号**分档（见 fakeTcpdumpScript），
// 这样一个脚本能供起全部失败档，而它报的话是真从 stderr 回来的。

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/capture"
)

// peer 一台假的但对端行为是真的设备：sshd + sftp + 一个受控的 PATH。
type peer struct {
	dir    string // 假对端的家（脚本、种子文件、抓包落盘都在这儿）
	binDir string
	addr   string
	ln     net.Listener
	sshCfg *ssh.ServerConfig

	mu      sync.Mutex
	cmds    []string                                // 那台上收到过的每一句命令：用来证明垃圾没被拼进 kill
	corrupt func(cmd, stdout string) (string, bool) // 改写某一句命令的回显（见 Test对端回的那个进程号）

	windows *winScenario // 非 nil = 这台是 Windows 对端：runExec 按 cmd.exe 那一套翻译
}

// winScenario 是假 Windows 对端这一场要演什么。★ 演的是「那台回的话与退出码」，
// 命令的形状仍由被测代码（peercap_windows_path.go）原样发出、经 translateWin 落到真 sh 上跑，
// 所以「我们把 pktmon 那句话拼错了」这一类错照样当场红。
type winScenario struct {
	present  bool   // where pktmon 找不找得着
	etl2pcap bool   // pktmon /? 里认不认得 etl2pcap
	start    string // ok | busy(159) | denied | noload（回 0 但不落盘 → died）
	convert  string // ok | fail（etl2pcap 转不出 pcapng）
	temp     string // %TEMP% 问出来的落点（这台是 unix，就用 p.dir）
}

// setCorrupt 让某一句命令「回来的那一格」不是我们以为的那一串。
func (p *peer) setCorrupt(f func(cmd, stdout string) (string, bool)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.corrupt = f
}

func (p *peer) ranCommands() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.cmds...)
}

func startPeer(t *testing.T) *peer {
	t.Helper()
	dir := t.TempDir()
	p := &peer{dir: dir, binDir: filepath.Join(dir, "bin")}
	if err := os.MkdirAll(p.binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 种子：一份真 pcap 的全局头 + 一个包。假 tcpdump 一条条往后接，
	// 于是「文件在长」是真的，取回来的那份也是真读得动的。
	if err := os.WriteFile(filepath.Join(dir, "hdr.bin"), pcapGlobalHeader(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rec.bin"), pcapRecord(), 0o644); err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "test" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("nope")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.addr, p.ln, p.sshCfg = ln.Addr().String(), ln, cfg
	go p.serve()
	t.Cleanup(func() { ln.Close() })
	return p
}

// installTcpdump 把假 tcpdump 装上对端的 PATH。装成 nil 就是「那台上没这个命令」。
func (p *peer) installTcpdump(t *testing.T) {
	t.Helper()
	sh := filepath.Join(p.binDir, "tcpdump")
	if err := os.WriteFile(sh, []byte(fakeTcpdumpScript(p.dir)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (p *peer) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			sc, chans, reqs, err := ssh.NewServerConn(conn, p.sshCfg)
			if err != nil {
				conn.Close()
				return
			}
			_ = sc
			go ssh.DiscardRequests(reqs)
			for newCh := range chans {
				if newCh.ChannelType() != "session" {
					newCh.Reject(ssh.UnknownChannelType, "只支持 session")
					continue
				}
				ch, chReqs, err := newCh.Accept()
				if err != nil {
					continue
				}
				go p.session(ch, chReqs)
			}
		}()
	}
}

func (p *peer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload = struct{ Cmd string }{}
			ssh.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				req.Reply(true, nil)
			}
			p.runExec(ch, payload.Cmd)
			return
		case "subsystem":
			var payload = struct{ Name string }{}
			ssh.Unmarshal(req.Payload, &payload)
			if payload.Name == "sftp" {
				if req.WantReply {
					req.Reply(true, nil)
				}
				if srv, err := sftp.NewServer(ch); err == nil {
					_ = srv.Serve()
				}
				return
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// runExec 真跑，但 PATH 受控：只有假 tcpdump 与系统那几个基础命令。
// ★ 不含 /usr/sbin —— 那台 Mac 上有真 tcpdump，混进来就会把「假对端」变成真提权失败。
//
// ★★ Windows 对端这一路（p.windows != nil）：被测代码发的是 cmd.exe 那一句
//
//	（`for %I in (...) do @echo %~zI`、`echo %TEMP%`、`del /q /f`、`where pktmon`、
//	带 `chcp 65001 >nul & ` 前缀）。这些在 unix 上 none of them 跑得了。所以这里
//	按 cmd.exe 的形状把它们翻译成等价的 unix 动作再真跑 —— ★ 落盘的文件是真文件、
//	退出码是真退出码、文件多大是真去 stat，被测代码那句拼错（比如把 `%~zI` 写成
//	`%~zX`、把 -s 的位数弄错、把转换排在 stop 之前）翻译器接不住，当场红。
//	EtlPath/PcapPath 在测试里给的是 unix 路径（这一层不在乎路径长什么样，只把它嵌进命令），
//	真机上的 `C:\...` 形态由 tools 层的 peerJoinWin 测（见 peercapture_test.go）。
func (p *peer) runExec(ch ssh.Channel, cmd string) {
	p.mu.Lock()
	p.cmds = append(p.cmds, cmd)
	corrupt := p.corrupt
	win := p.windows
	p.mu.Unlock()

	execCmd := cmd
	if win != nil {
		t, ok := translateWin(cmd, p.dir)
		if !ok {
			// 翻译器不认识的那一句 = 被测代码发了一句不是 cmd.exe 也不是我们约定形状的东西。
			// 如实报错，别静默当 unix 跑。
			ch.Write([]byte("translator: 没料到对端会发这句：" + cmd))
			bs := make([]byte, 4)
			binary.BigEndian.PutUint32(bs, 127)
			ch.SendRequest("exit-status", false, bs)
			return
		}
		execCmd = t
	}

	c := exec.Command("/bin/sh", "-c", execCmd)
	env := []string{"PATH=" + p.binDir + ":/bin:/usr/bin",
		"FAKE_PRESENT=0", "FAKE_ETL2PCAP=0", "FAKE_START=ok", "FAKE_CONVERT=ok",
		"FAKE_TEMP=" + p.dir}
	if win != nil {
		if win.present {
			env[1] = "FAKE_PRESENT=1"
		}
		if win.etl2pcap {
			env[2] = "FAKE_ETL2PCAP=1"
		}
		if win.start != "" {
			env[3] = "FAKE_START=" + win.start
		}
		if win.convert != "" {
			env[4] = "FAKE_CONVERT=" + win.convert
		}
		if win.temp != "" {
			env[5] = "FAKE_TEMP=" + win.temp
		}
	}
	c.Env = append(os.Environ(), env...)
	c.Dir = p.dir
	out, err := c.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	if corrupt != nil {
		if s, ok := corrupt(cmd, string(out)); ok {
			out = []byte(s)
		}
	}
	ch.Write(out)
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(code))
	ch.SendRequest("exit-status", false, bs)
}

func (p *peer) dial(t *testing.T) (*Device, *ssh.Client, SSHExecer) {
	t.Helper()
	return p.dialAs(t, "linux")
}

// dialAs 用指定的 OS 登记并连上这台假对端。★ OS 就是分流开关：Windows 那一路
//
//	（Probe/Start/Stat/Stop/Remove 全部按 d.OS 走 pktmon 那一支）要靠它才进得去。
func (p *peer) dialAs(t *testing.T, os string) (*Device, *ssh.Client, SSHExecer) {
	t.Helper()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(p.addr)
	if err != nil {
		t.Fatal(err)
	}
	var pn int
	fmt.Sscanf(port, "%d", &pn)
	d, err := m.AddDevice(Device{Host: host, Port: pn, User: "test", Password: "pw", OS: os})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := m.Dial(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return d, c, Execer(c)
}

// ── 假 tcpdump ──
//
// 分档记号（写在参数里，脚本自己按真话报错）：
//   - 口名含 deny    → 报「没权限抓」（真 tcpdump 非 root 就这一句）
//   - 口名含 missing → 报「没有这个口」
//   - 过滤器含 badf  → 报「过滤器读不成句」
//   - 过滤器含 hang  → 收到 SIGINT 也不退出（用来钉「掐了还不死」那一档）
//   - 其余           → 后台一条条往 -w 那个文件接包，退出时把 tcpdump 那三行账打到 stderr
const fakeTcpdumpTemplate = `#!/bin/sh
if [ "$1" = "-D" ]; then
  echo "1.eth0 [Up, Running]"
  echo "2.lo0 [Up, Running, Loopback]"
  echo "3.bge1 [Down]"
  exit 0
fi
if [ "$1" = "--version" ]; then
  echo "tcpdump version 4.99.1"
  exit 0
fi
iface=""; snap=0; out=""; filter=""
while [ $# -gt 0 ]; do
  case "$1" in
    -i) iface="$2"; shift 2 ;;
    -s) snap="$2"; shift 2 ;;
    -w) out="$2"; shift 2 ;;
    *) filter="$filter $1"; shift ;;
  esac
done
case "$iface" in
  *deny*)
    echo "tcpdump: $iface: You don't have permission to capture on that device (socket: Operation not permitted)" >&2
    exit 1 ;;
  *missing*)
    echo "tcpdump: $iface: No such device available" >&2
    exit 1 ;;
esac
case "$filter" in
  *badf*)
    echo "tcpdump: syntax error in filter expression near \"$filter\"" >&2
    exit 1 ;;
esac
case "$filter" in
  *bogus*)
    echo "tcpdump: $iface: some wording we have never seen" >&2
    exit 1 ;;
esac
[ -n "$out" ] || exit 2
cat __DIR__/hdr.bin > "$out"
stopped=0
onint() { stopped=1; }
case "$filter" in
  *hang*) trap '' INT TERM ;;
  *) trap onint INT TERM ;;
esac
while [ $stopped -eq 0 ]; do
  cat __DIR__/rec.bin >> "$out"
  sleep 0.02
done
# 退出时按**文件本身**算这本账：脚本在信号与写文件之间没有先后保证，
# 自己数会差一条，那一条会被下面那个「对端说的与文件里数的必须一致」的断言当场抓住。
sz=$(wc -c < "$out")
n=$(( (sz - __HDR__ ) / __REC__ ))
echo "tcpdump: $iface: Packet capture filter:$filter" >&2
echo "$n packets captured" >&2
echo "$n packets received by filter" >&2
echo "3 packets dropped by kernel" >&2
exit 0
`

// fakeTcpdumpScript 把种子路径与那两个长度常量烧进脚本。
// 那两个长度是**从真生成的字节**算出来的，不是写在纸上的数字 ——
// 改了包形而忘了改数字，脚本自己就会把账算错，测试当场红。
func fakeTcpdumpScript(dir string) string {
	s := strings.ReplaceAll(fakeTcpdumpTemplate, "__DIR__", dir)
	s = strings.ReplaceAll(s, "__HDR__", fmt.Sprintf("%d", len(pcapGlobalHeader())))
	s = strings.ReplaceAll(s, "__REC__", fmt.Sprintf("%d", len(pcapRecord())))
	return s
}

// pcapGlobalHeader / pcapRecord 手写一份老 pcap：全局头 + 一个以太网帧。
// 假 tcpdump 接的就是这个，所以取回来的那份是真读得动的。
func pcapGlobalHeader() []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[8:], 0)
	binary.LittleEndian.PutUint32(b[12:], 0)
	binary.LittleEndian.PutUint32(b[16:], 65535)
	binary.LittleEndian.PutUint32(b[20:], 1) // DLT_EN10MB
	return b
}

func pcapRecord() []byte {
	frame := ethFrame()
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:], 1700000000)
	binary.LittleEndian.PutUint32(h[4:], 0)
	binary.LittleEndian.PutUint32(h[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(h[12:], uint32(len(frame)))
	return append(h, frame...)
}

// ethFrame 一个最小的 IPv4/TCP 帧：10.0.0.1:34567 → 10.0.0.2:80。
func ethFrame() []byte {
	l4 := []byte{0x87, 0x78, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0}
	l3 := []byte{0x45, 0, 0, 0, byte(20 + len(l4)), 0, 0, 0, 0x40, 0x06, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	binary.BigEndian.PutUint16(l3[10:], checksum(l3, l4))
	eth := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00}
	out := append(eth, l3...)
	return append(out, l4...)
}

func checksum(l3, l4 []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(l3); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l3[i:]))
	}
	for i := 0; i+1 < len(l4); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func peerCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ── 探测：那台上有什么可用的 ──

func Test对端有tcpdump时探得出采集器与口列表(t *testing.T) {
	p := startPeer(t)
	p.installTcpdump(t)
	d, _, x := p.dial(t)
	got, err := ProbePeerCapture(peerCtx(t), x, d)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tool != "tcpdump" {
		t.Errorf("采集器认成 %q，要 tcpdump", got.Tool)
	}
	if got.Path == "" {
		t.Error("没带回调那台上命令在哪儿 —— 起不来时这句话是唯一能指着说的东西")
	}
	if strings.Join(got.Ifaces, ",") != "eth0,lo0,bge1" {
		t.Errorf("口列表 = %v，要按那台上说的原样列出来（Down 的口也在，现场就是要在两块口里挑）", got.Ifaces)
	}
	if got.Dir == "" {
		t.Error("没说那份文件落对端哪儿")
	}
}

func Test对端没有采集器时说的是一件事不是一句报错(t *testing.T) {
	// PATH 里没有 tcpdump：这不算 SSH 失败，那台上就是这样。
	p := startPeer(t)
	d, _, x := p.dial(t)
	got, err := ProbePeerCapture(peerCtx(t), x, d)
	if err != nil {
		t.Fatalf("探不到采集器却当成连不上了：%v", err)
	}
	if got.Tool != "" {
		t.Errorf("那台上没这个命令却认出了 %q", got.Tool)
	}
	if !strings.Contains(got.Note, "tcpdump") {
		t.Errorf("没说清缺的是哪一个：%q", got.Note)
	}
}

// ── 起、看、停 ──

func specOf(caps *PeerCaptureCaps, iface, filter string, snap int, dir string) PeerCaptureSpec {
	tag := peerNameTag()
	return PeerCaptureSpec{
		Collector: caps.Path, Interface: iface, Filter: filter, SnapLen: snap,
		PeerFile: peerPath(dir, "netkit-cap-"+tag+".pcap"),
		PeerLog:  peerPath(dir, "netkit-cap-"+tag+".log"),
	}
}

// startSpec 用对端的落盘目录，但把文件放到测试自己的家里（那台上跑的就是本机，
// 这样「对端那份文件」是真在磁盘上的一份，取回与删除都能验真的）。
func startSpec(p *peer, caps *PeerCaptureCaps, iface, filter string) PeerCaptureSpec {
	s := specOf(caps, iface, filter, 1600, p.dir)
	return s
}

func Test起得来的那一路带着PID且文件真的在长(t *testing.T) {
	p := startPeer(t)
	p.installTcpdump(t)
	d, _, x := p.dial(t)
	caps, err := ProbePeerCapture(peerCtx(t), x, d)
	if err != nil {
		t.Fatal(err)
	}
	ctx := peerCtx(t)
	run, err := StartPeerCapture(ctx, x, d, startSpec(p, caps, "eth0", ""))
	if err != nil {
		t.Fatalf("起不来：%v", err)
	}
	// ★ 这一路是这一张表里唯一「起了但不停」的：起了不收掉，
	//   跑测试这台机器上就留一路永远在写的采集（实测真的攒下过四路，每路几 MB/s 地爬盘）。
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := StopPeerCapture(cctx, x, d, run, 5*time.Second); err != nil {
			t.Errorf("收尾停不下来：%v", err)
		}
	})
	if run.PID <= 0 {
		t.Errorf("没拿到对端那个进程号：%+v（停不下来就没法收口）", run)
	}
	alive, n1, err := PollPeerCapture(ctx, x, d, run)
	if err != nil {
		t.Fatal(err)
	}
	if !alive {
		t.Error("刚起的那一路第一眼看就没活着 —— 起来了又立刻死的档要单独说话，不许混在这儿")
	}
	time.Sleep(300 * time.Millisecond)
	_, n2, err := PollPeerCapture(ctx, x, d, run)
	if err != nil {
		t.Fatal(err)
	}
	if n2 <= n1 {
		t.Errorf("文件没长：%d → %d（轮询报的字节数是用来决定「到量了该停了」的，它不动就会一路写到把盘挤掉）", n1, n2)
	}
}

func Test起了就死的那几种各说各的下一步(t *testing.T) {
	cases := []struct {
		iface, filter string
		want          PeerCaptureProblem
	}{
		{"deny0", "", PeerProblemPrivilege},
		{"eth9missing", "", PeerProblemInterface},
		{"eth0", "badf", PeerProblemFilter},
	}
	for _, c := range cases {
		p := startPeer(t)
		p.installTcpdump(t)
		d, _, x := p.dial(t)
		caps, err := ProbePeerCapture(peerCtx(t), x, d)
		if err != nil {
			t.Fatal(err)
		}
		_, err = StartPeerCapture(peerCtx(t), x, d, startSpec(p, caps, c.iface, c.filter))
		var se *PeerStartError
		if !asStartErr(err, &se) {
			t.Fatalf("%s/%s：起不来却没给出分档：%v", c.iface, c.filter, err)
		}
		if se.Problem != c.want {
			t.Errorf("%s/%s 分成 %q，要 %q（对端原话：%q）", c.iface, c.filter, se.Problem, c.want, se.Detail)
		}
		// ★ 原话要留着：档是我们分的，人要看的是那台自己说了什么
		if se.Detail == "" {
			t.Errorf("%s/%s 没带对端那句话", c.iface, c.filter)
		}
	}
}

func Test认不出来的那句不许硬贴一档(t *testing.T) {
	// 假 tcpdump 报一句我们从没见过的话。硬猜成「要提权」会把人领去装 sudo。
	p := startPeer(t)
	p.installTcpdump(t)
	d, _, x := p.dial(t)
	caps, _ := ProbePeerCapture(peerCtx(t), x, d)
	_, err := StartPeerCapture(peerCtx(t), x, d, startSpec(p, caps, "eth0", "bogus"))
	var se *PeerStartError
	if !asStartErr(err, &se) {
		t.Fatalf("没分档：%v", err)
	}
	if se.Problem != PeerProblemDied {
		t.Errorf("认不出的一句被贴成 %q，要 died-at-start 并带上原话（%q）", se.Problem, se.Detail)
	}
}

func Test对端回的那个进程号是外人给的(t *testing.T) {
	// ★ 为什么改的是「那一句命令的回显」而不是假 tcpdump 脚本：
	//   进程号是从对端 shell 的 `echo $!` 那一格来的，采集器自己的 stdout 早在
	//   我们拼的命令里被接到 /dev/null 了 —— 换脚本只脏得了日志，脏不到这一格。
	//   真会脏这一格的是对端那台机器本身：被换过的 shell、把作业通知打到 stdout 的
	//   shell（tcsh 那一类）、成心下毒的对端。这一格我们说了不算，只能不认垃圾。
	//
	// 断言的不是「报了错」，是「那段垃圾没被拿去发信号」：探针文件不许出现，
	// 而且那台上收到过的每一句命令里都不许带它。
	p := startPeer(t)
	p.installTcpdump(t)
	canary := filepath.Join(p.dir, "pwned")
	noise := "1; touch " + canary + " #"
	p.setCorrupt(func(cmd, stdout string) (string, bool) {
		if !strings.Contains(cmd, "echo $!") {
			return "", false
		}
		// 真起来的那一路得收掉，不然这个测试走了它还在往临时目录里写
		if pid := strings.TrimSpace(stdout); isAllDigits(pid) {
			t.Cleanup(func() { exec.Command("kill", "-9", pid).Run() })
		}
		return noise, true
	})

	d, _, x := p.dial(t)
	caps, _ := ProbePeerCapture(peerCtx(t), x, d)
	spec := startSpec(p, caps, "eth0", "")
	_, err := StartPeerCapture(peerCtx(t), x, d, spec)
	if err == nil {
		t.Fatal("对端回的进程号不是数字，却当成正经进程号收下了")
	}
	if !strings.Contains(err.Error(), "进程号") {
		t.Errorf("错误里没说清是进程号这一格的问题：%v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(canary); err == nil {
		t.Error("★ 那句垃圾被拼进命令跑了一遍，探针文件都出来了")
	}
	for _, c := range p.ranCommands() {
		if strings.Contains(c, "pwned") {
			t.Errorf("★ 垃圾被原样拼进了后面那句命令：%s", c)
		}
	}

	// ★ 那一格认不出来，不代表对端那一路没起来 —— 它真在跑，只是我们不知道它的号。
	// 就这么走掉，等于留一路没人收口的 tcpdump 在别人盘上写原始包（里面什么明文都有）。
	// 所以报了错还得把它收掉：文件不许还在长。
	if n0, err := os.Stat(spec.PeerFile); err == nil {
		time.Sleep(400 * time.Millisecond)
		n1, err := os.Stat(spec.PeerFile)
		if err != nil {
			t.Fatalf("收口之后那份就查不到了：%v", err)
		}
		if n1.Size() > n0.Size() {
			t.Errorf("报了错就走，对端留了一路还在写的采集：%d → %d 字节（错误里说的文件路径 %s 得是真的能拿去收尾的）",
				n0.Size(), n1.Size(), spec.PeerFile)
		}
	}
}

func Test进程号那一格带前言的认带尾巴的不认(t *testing.T) {
	// 有的对端会在 echo 之前先蹦一行（MOTD、包装脚本留下的话）：认最后一行。
	// 数字后面拖了东西就不认 —— 那一格后面要拼进 kill，多出来的一个字都是外人写的。
	if n, err := parsePeerPID("[1] 4242\n"); err == nil {
		t.Errorf("整行带方括号的作业通知被认成了 %d，该拒（拼进 kill 的那一串必须只有数字）", n)
	}
	if n, err := parsePeerPID("banner line\n4242\n"); err != nil || n != 4242 {
		t.Errorf("前言后数字没认出来：%d %v", n, err)
	}
	for _, s := range []string{"", "4242; rm -rf /", "42x", "-1", "0"} {
		if n, err := parsePeerPID(s); err == nil {
			t.Errorf("%q 被认成了进程号 %d，且没报错", s, n)
		}
	}
}

func Test停下来的那一本账是从对端那句原话里读的(t *testing.T) {
	p := startPeer(t)
	p.installTcpdump(t)
	d, _, x := p.dial(t)
	caps, _ := ProbePeerCapture(peerCtx(t), x, d)
	ctx := peerCtx(t)
	run, err := StartPeerCapture(ctx, x, d, startSpec(p, caps, "eth0", ""))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	info, err := StopPeerCapture(ctx, x, d, run, 5*time.Second)
	if err != nil {
		t.Fatalf("停不下来：%v", err)
	}
	if info.StillAlive {
		t.Error("SIGINT 之后那一路还活着，却没说清")
	}
	if !info.HasCounts || info.Captured == 0 {
		t.Errorf("那本账没读出来：%+v（tcpdump 退出时把包数打在 stderr 上，这一格是「对端到底收了多少」唯一的来源）", info)
	}
	if info.Dropped != 3 {
		t.Errorf("对端报的丢包 = %d，要 3", info.Dropped)
	}
	// 停了以后那份文件必须是真读得动的 pcap
	f, err := os.Open(run.PeerFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, err := countPcapPackets(f)
	if err != nil {
		t.Fatalf("停下来的那份读不动：%v", err)
	}
	if n == 0 {
		t.Error("包数为 0 —— 那一路白跑")
	}
	if int64(n) != info.Captured {
		t.Errorf("对端说收了 %d 包，文件里数出来 %d 包 —— 这两个数不一样就该说出来，不该并列摆着", info.Captured, n)
	}
}

func Test掐了还不死的那一路要退成硬断并写明文件可能短一截(t *testing.T) {
	p := startPeer(t)
	p.installTcpdump(t)
	d, _, x := p.dial(t)
	caps, _ := ProbePeerCapture(peerCtx(t), x, d)
	ctx := peerCtx(t)
	run, err := StartPeerCapture(ctx, x, d, startSpec(p, caps, "eth0", "hang"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := StopPeerCapture(ctx, x, d, run, 2*time.Second)
	if err != nil {
		t.Fatalf("硬断也没做成：%v", err)
	}
	if !info.Forced {
		t.Error("对端那一路无视 SIGINT，这里却没说是硬断的（SIGKILL）—— 那句「文件可能短一截」就没了依据")
	}
	if info.HasCounts {
		t.Error("硬断的那一路来不及打那本账，却有账")
	}
	// 硬断之后再看一眼：真死了才算收口，别留一个还在写的进程在对端
	if alive, _, err := PollPeerCapture(ctx, x, d, run); err != nil {
		t.Fatal(err)
	} else if alive {
		t.Error("说了硬断，对端那个进程却还在")
	}
}

func Test删对端那一份是真删(t *testing.T) {
	p := startPeer(t)
	p.installTcpdump(t)
	d, _, x := p.dial(t)
	caps, _ := ProbePeerCapture(peerCtx(t), x, d)
	ctx := peerCtx(t)
	run, err := StartPeerCapture(ctx, x, d, startSpec(p, caps, "eth0", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StopPeerCapture(ctx, x, d, run, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(run.PeerFile); err != nil {
		t.Fatalf("停完那份就没了，测不下去：%v", err)
	}
	if err := RemovePeerFiles(ctx, x, d, run.PeerFile, run.PeerLog); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{run.PeerFile, run.PeerLog} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s 还在（对端那份留着 = 把明文口令留在别人机器上）", f)
		}
	}
}

// asStartErr 取出分档那个错误。
func asStartErr(err error, target **PeerStartError) bool {
	for err != nil {
		if e, ok := err.(*PeerStartError); ok {
			*target = e
			return true
		}
		u := errors.Unwrap(err)
		if u == nil {
			return false
		}
		err = u
	}
	return false
}

// countPcapPackets 用**项目自己的读包代码**数一遍那份文件：
// ★ 断言的是「取回来的这份，工具读得动」，不是「脚本自己数对了」。
func countPcapPackets(r io.Reader) (int, error) {
	rd, err := capture.Open(r)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		if _, err := rd.Read(); err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		n++
	}
}

// ── Windows 对端（pktmon）：假 pktmon + cmd.exe→sh 翻译器 ──
//
// 被测代码发的是 cmd.exe 那一套；翻译器只负责把那句 cmd.exe **形状**落到真 unix 上执行，
// 于是「退出码是真从脚本回来的、文件是真在盘上的、多大是真 stat 出来的」。翻译器接不住
// 一句拼错了形状的命令（少个引号、把 `%~zI` 写歪、转换排到 stop 前），当场报 127。

// installFakePktmon 把假 pktmon 装上 PATH。分档靠 env（见 runExec）：
// FAKE_START=ok|busy|denied|noload、FAKE_CONVERT=ok|fail、FAKE_ETL2PCAP=0/1。
func (p *peer) installFakePktmon(t *testing.T) {
	t.Helper()
	s := fakePktmonTemplate
	s = strings.ReplaceAll(s, "__SEED__", filepath.Join(p.dir, "rec.bin"))
	s = strings.ReplaceAll(s, "__HDR__", filepath.Join(p.dir, "hdr.bin"))
	s = strings.ReplaceAll(s, "__REC__", filepath.Join(p.dir, "rec.bin"))
	if err := os.WriteFile(filepath.Join(p.binDir, "pktmon"), []byte(s), 0o755); err != nil {
		t.Fatal(err)
	}
}

const fakePktmonTemplate = `#!/bin/sh
# 收到的 argv 已被翻译器规整成 unix 形状（路径是真 unix 路径、去掉了对端的引号）。
if [ "$1" = "/?" ]; then
  echo "Packet Monitor (pktmon)"
  echo "start | stop | session"
  if [ "$FAKE_ETL2PCAP" = "1" ]; then echo "  etl2pcap    Convert collected .etl to .pcapng"; fi
  exit 0
fi
if [ "$1" = "start" ]; then
  case "$FAKE_START" in
    busy)   echo "There is already a capture in progress on this computer." >&2; exit 159 ;;
    denied) echo "Access is denied." >&2; exit 5 ;;
    noload) echo "Packet capture start." >&2; exit 0 ;;   # 回 0 但根本不落盘 -> died-at-start
  esac
  out=""; prev=""
  for a in "$@"; do
    if [ "$prev" = "-f" ]; then out="$a"; fi
    prev="$a"
  done
  [ -n "$out" ] || { echo "pktmon: 没给 -f" >&2; exit 1; }
  cat __SEED__ > "$out"          # 建一份非空 .etl（判活只看它在不在、多大）
  echo "Packet capture start." >&2
  exit 0
fi
if [ "$1" = "stop" ]; then echo "Packet capture stop." >&2; exit 0; fi
if [ "$1" = "etl2pcap" ]; then
  out=""; prev=""
  for a in "$@"; do
    if [ "$prev" = "--out" ]; then out="$a"; fi
    prev="$a"
  done
  case "$FAKE_CONVERT" in
    fail) echo "etl2pcap: the file is not a valid trace" >&2; exit 1 ;;  # 不产出 -> 上层判 convert-failed
  esac
  [ -n "$out" ] || { echo "etl2pcap: 没给 --out" >&2; exit 1; }
  cat __HDR__ > "$out"; cat __REC__ >> "$out"   # 一份真读得动的 pcap（pktmon 转的其实是 pcapng，这里取「非空且读得动」这一条）
  exit 0
fi
echo "pktmon: 不认的调用 $*" >&2
exit 2
`

// translateWin 把对端发来的一句（可能带 chcp 前缀的）cmd.exe 命令，翻译成等价的 unix 命令。
// 认不出形状 → ok=false（runExec 据此报 127，等于「被测代码发了一句我们没打算发的东西」）。
func translateWin(raw, dir string) (string, bool) {
	cmd := strings.TrimPrefix(raw, winUTF8Preamble+" & ")
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "where pktmon":
		return `if [ "$FAKE_PRESENT" = 1 ]; then echo 'C:\Windows\System32\pktmon.exe'; else exit 1; fi`, true
	case strings.HasPrefix(cmd, "pktmon /?"):
		return `pktmon '/?'`, true
	case strings.HasPrefix(cmd, "echo %TEMP%"):
		return `printf '%s\n' "$FAKE_TEMP"`, true
	case strings.HasPrefix(cmd, `for %I in ("`):
		rest := strings.TrimPrefix(cmd, `for %I in ("`)
		i := strings.Index(rest, `")`)
		if i < 0 {
			return "", false
		}
		path := rest[:i]
		return `[ -f '` + path + `' ] && wc -c < '` + path + `' | tr -dc 0-9`, true
	case strings.HasPrefix(cmd, "del /q /f "):
		// 去掉所有双引号后按空格拆 —— 测试里的路径没有空格。
		paths := strings.ReplaceAll(strings.TrimPrefix(cmd, "del /q /f "), `"`, "")
		return `rm -f ` + paths, true
	case cmd == "pktmon stop":
		return `pktmon stop`, true
	case strings.HasPrefix(cmd, "pktmon etl2pcap "):
		args := strings.ReplaceAll(strings.TrimPrefix(cmd, "pktmon etl2pcap "), `"`, "")
		return `pktmon etl2pcap ` + args, true
	}
	// start：形状是 `"<collector path>" start --capture ... -f "<etl>"`（collector 带反斜杠路径，
	// unix 起不动），把第一个 token 换成裸 pktmon、并去掉所有引号。
	if i := strings.Index(cmd, `" start `); i >= 0 {
		rest := cmd[i+len(`" start `)-len("start "):] // 从 "start" 起
		rest = strings.ReplaceAll(rest, `"`, "")
		return `pktmon ` + rest, true
	}
	return "", false
}

// winSpecOf 用真 unix 路径当 .etl/.pcapng 落点（这一层不在乎路径长什么样，只把它嵌进命令）。
func winSpecOf(p *peer, collector, iface string, snap, mb int) PeerCaptureSpec {
	tag := peerNameTag()
	return PeerCaptureSpec{
		Collector: collector, Interface: iface, SnapLen: snap,
		MaxMB:    mb,
		EtlPath:  filepath.Join(p.dir, "netkit-cap-"+tag+".etl"),
		PcapPath: filepath.Join(p.dir, "netkit-cap-"+tag+".pcapng"),
	}
}

func asStartProblem(t *testing.T, err error) PeerCaptureProblem {
	t.Helper()
	var se *PeerStartError
	if !asStartErr(err, &se) {
		t.Fatalf("起不来却没给出分档：%v", err)
	}
	return se.Problem
}

func TestWindows对端探得出pktmon与转换能力(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "ok",
		temp: `C:\Users\test\AppData\Local\Temp`}
	d, _, x := p.dialAs(t, "windows")
	got, err := ProbePeerCapture(peerCtx(t), x, d)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tool != "pktmon" {
		t.Errorf("采集器认成 %q，要 pktmon", got.Tool)
	}
	if got.Path == "" {
		t.Error("没带回调那个命令在哪儿")
	}
	if !got.Etl2Pcap {
		t.Error("/? 里明明有 etl2pcap，却没认出这能力（缺它就只能落 .etl，上层要专门说一档）")
	}
	// ★ Dir 拿的是问出来的 %TEMP%（带反斜杠那种），不是写死的 /tmp。
	if !strings.Contains(got.Dir, `\`) {
		t.Errorf("落点 %q 没按 Windows 那台的 %%TEMP%% 来", got.Dir)
	}
}

func TestWindows对端没有pktmon是一句事实(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: false, temp: `C:\Windows\Temp`}
	d, _, x := p.dialAs(t, "windows")
	got, err := ProbePeerCapture(peerCtx(t), x, d)
	if err != nil {
		t.Fatalf("没有 pktmon 该是一句事实不是连接失败：%v", err)
	}
	if got.Tool != "" {
		t.Errorf("where pktmon 会失败，却认出了 %q", got.Tool)
	}
	if !strings.Contains(got.Note, "pktmon") {
		t.Errorf("没说清缺的是 pktmon：%q", got.Note)
	}
}

func TestWindows起一路pktmon落到etl(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "ok", temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	ctx := peerCtx(t)
	spec := winSpecOf(p, `C:\Windows\System32\pktmon.exe`, "以太网", 1600, 256)
	run, err := StartPeerCapture(ctx, x, d, spec)
	if err != nil {
		t.Fatalf("起不来：%v", err)
	}
	if !run.Windows {
		t.Error("这一路没标成 Windows（收口会走错分支去发信号）")
	}
	if run.PeerFile != spec.PcapPath || run.EtlPath != spec.EtlPath {
		t.Errorf("落点没带回：run=%+v spec=%+v", run, spec)
	}
	if _, err := os.Stat(spec.EtlPath); err != nil {
		t.Errorf("说起来了，那份 .etl 却不在盘上：%v", err)
	}
	// 看一眼：报 .etl 多大、还活着。
	st, err := PeerCaptureStat(ctx, x, d, run)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Alive || !st.BytesKnown || st.Bytes <= 0 {
		t.Errorf("看一眼报成 %+v，要在、且大小 >0（到量停全靠这个数）", st)
	}
}

func TestWindows那台已有一路pktmon报busy(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "busy", temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	_, err := StartPeerCapture(peerCtx(t), x, d, winSpecOf(p, "pktmon", "以太网", 1600, 256))
	if got := asStartProblem(t, err); got != PeerProblemBusy {
		t.Errorf("退出码 159 分成 %q，要 busy（下一步是去 stop 那一录，不是提权）", got)
	}
}

func TestWindows非管理员报no_privilege(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "denied", temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	_, err := StartPeerCapture(peerCtx(t), x, d, winSpecOf(p, "pktmon", "以太网", 1600, 256))
	if got := asStartProblem(t, err); got != PeerProblemPrivilege {
		t.Errorf("分成 %q，要 no-privilege（%v）", got, err)
	}
}

func TestWindows回0却不落盘算died(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "noload", temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	_, err := StartPeerCapture(peerCtx(t), x, d, winSpecOf(p, "pktmon", "以太网", 1600, 256))
	if got := asStartProblem(t, err); got != PeerProblemDied {
		t.Errorf("分成 %q，要 died-at-start（回 0 却没见着 .etl）", got)
	}
}

func TestWindows收口先stop再转换出pcapng(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "ok", convert: "ok", temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	ctx := peerCtx(t)
	spec := winSpecOf(p, "pktmon", "以太网", 1600, 256)
	run, err := StartPeerCapture(ctx, x, d, spec)
	if err != nil {
		t.Fatal(err)
	}
	info, err := StopPeerCapture(ctx, x, d, run, 3*time.Second)
	if err != nil {
		t.Fatalf("收口失败：%v", err)
	}
	if info.ConvertErr != "" {
		t.Errorf("转换成功却带了 ConvertErr：%q", info.ConvertErr)
	}
	// 转出来的那份 pcapng 要在盘上、且用项目自己的读包代码真读得动（pull 取的就是它）。
	f, err := os.Open(spec.PcapPath)
	if err != nil {
		t.Fatalf("pcapng 没转出来：%v", err)
	}
	defer f.Close()
	if n, err := countPcapPackets(f); err != nil || n == 0 {
		t.Errorf("转出来的那份读不动或空：%d %v", n, err)
	}
	// ★ 顺序不许反：正在录的 .etl 直接转会出「退出码 0 的空壳」。收口时 .etl 应还在（没删）。
	if _, err := os.Stat(spec.EtlPath); err != nil {
		t.Errorf("收口这一步就把 .etl 删了（那是删该由 remove 那一档管）：%v", err)
	}
}

func TestWindows转换失败带ConvertErr且留着etl原件(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, etl2pcap: true, start: "ok", convert: "fail", temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	ctx := peerCtx(t)
	spec := winSpecOf(p, "pktmon", "以太网", 1600, 256)
	run, err := StartPeerCapture(ctx, x, d, spec)
	if err != nil {
		t.Fatal(err)
	}
	info, err := StopPeerCapture(ctx, x, d, run, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if info.ConvertErr == "" {
		t.Error("etl2pcap 没成却报转换成功（pull 会去取一份不存在的东西，报错对不上号）")
	}
	if _, err := os.Stat(spec.PcapPath); err == nil {
		t.Error("转换失败却还有一份 pcapng")
	}
	if _, err := os.Stat(spec.EtlPath); err != nil {
		t.Errorf("转换失败时那份 .etl 是唯一原件，被收口删了：%v", err)
	}
}

func TestWindows删对端那两份是真删(t *testing.T) {
	p := startPeer(t)
	p.installFakePktmon(t)
	p.windows = &winScenario{present: true, temp: p.dir}
	d, _, x := p.dialAs(t, "windows")
	etl := filepath.Join(p.dir, "a.etl")
	pcap := filepath.Join(p.dir, "a.pcapng")
	for _, f := range []string{etl, pcap} {
		if err := os.WriteFile(f, []byte("原始包"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemovePeerFiles(peerCtx(t), x, d, pcap, etl); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{etl, pcap} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s 还在（del 那一句没真删；原始包留在别人机器上 = 把明文丢现场）", f)
		}
	}
}
