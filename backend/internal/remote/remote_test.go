package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ── ParseQuerySession：样本就是设计文档里现场抄回来的那段 ──

// 真实 query session 输出是按列对齐的，手写样本必须一样对齐，
// 否则测的是「解析器扛不住错位样本」而不是解析本身。
func qsHeader() string {
	return " " + fmt.Sprintf("%-17s%-25s%-6s%-8s%-12s%s",
		"SESSIONNAME", "USERNAME", "ID", "STATE", "TYPE", "DEVICE")
}

func qsRow(marker, name, user string, id int, state string) string {
	return marker + fmt.Sprintf("%-17s%-25s%-6d%-8s", name, user, id, state)
}

func TestParseQuerySession(t *testing.T) {
	out := qsHeader() + "\n" +
		qsRow(">", "services", "", 0, "Disc") + "\n" +
		qsRow(" ", "console", "PC", 1, "Active") + "\n" +
		qsRow(" ", "rdp-tcp", "", 65536, "Listen") + "\n"
	ss := ParseQuerySession(out)
	if len(ss) != 3 {
		t.Fatalf("要 3 个会话，拿到 %d：%+v", len(ss), ss)
	}
	if ss[0].Name != "services" || ss[0].ID != 0 || ss[0].State != "Disc" || !ss[0].Current {
		t.Errorf("services 会话解错：%+v", ss[0])
	}
	// ★ 关键坑：USERNAME 为空时按空格分词会全体错位 —— 列位置切才不会
	if ss[0].User != "" {
		t.Errorf("services 会话不该有用户名，拿到 %q", ss[0].User)
	}
	if ss[1].Name != "console" || ss[1].User != "PC" || ss[1].ID != 1 || !ss[1].Active {
		t.Errorf("console 会话解错：%+v", ss[1])
	}
	if ss[2].ID != 65536 {
		t.Errorf("rdp-tcp 会话号解错：%+v", ss[2])
	}
}

func TestParseQuerySessionJunk(t *testing.T) {
	if ss := ParseQuerySession("不是 query session 的输出"); ss != nil {
		t.Errorf("认不出的输出该给 nil，给了 %+v", ss)
	}
}

// ── 设备登记：凭据不出后端 ──

func TestDeviceStore(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := m.AddDevice(Device{Host: "192.168.3.82", User: "pc", Password: "秘密", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "pc@192.168.3.82" {
		t.Errorf("ID 该是 user@host，拿到 %s", d.ID)
	}
	pub := d.Public()
	for k, v := range pub {
		if s, ok := v.(string); ok && strings.Contains(s, "秘密") {
			t.Errorf("★ 凭据从 Public() 泄露了：%s=%v", k, v)
		}
	}
	// 落盘文件 0600
	fi, err := os.Stat(filepath.Join(dir, "devices.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("devices.json 权限该是 0600：%v %v", fi, err)
	}
	// 覆盖更新不丢凭据
	d2, err := m.AddDevice(Device{Host: "192.168.3.82", User: "pc", Name: "现场那台"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Devices()) != 1 {
		t.Errorf("同 host+user 重复登记该覆盖，不该多一条")
	}
	got, _ := m.Get("pc@192.168.3.82")
	if got.Password != "秘密" || got.Name != "现场那台" {
		t.Errorf("覆盖更新丢了东西：pw=%q name=%q", got.Password, got.Name)
	}
	if d2 == nil {
		t.Fatal("nil")
	}
	if err := m.RemoveDevice("192.168.3.82"); err != nil {
		t.Fatal(err)
	}
	if len(m.Devices()) != 0 {
		t.Errorf("删不掉")
	}
}

// ── 配置：notifyTarget 默认必须是开 ──

func TestConfigNotifyDefault(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !m.NotifyTarget() {
		t.Error("★ 默认必须是「对方可见」。装上就能被静默围观不是可接受的默认值")
	}
	before, after, err := m.SetNotifyTarget(false)
	if err != nil || before != true || after != false {
		t.Fatalf("SetNotifyTarget: %v %v %v", before, after, err)
	}
	// 重新打开目录，静默状态必须还在（配置本身可见、可持久）
	m2, _ := Open(m.dir)
	if m2.NotifyTarget() {
		t.Error("关掉后重新加载又变回开了")
	}
	m2.SetNotifyTarget(true)
	m3, _ := Open(m.dir)
	if !m3.NotifyTarget() {
		t.Error("打开后没落盘")
	}
}

// ── 审计：静默不静痕 ──

func TestAuditIndependentOfNotify(t *testing.T) {
	m, _ := Open(t.TempDir())
	m.SetNotifyTarget(false) // ★ 静默模式
	m.Audit("tester", "exec", "pc@box", "whoami", "ok")
	m.Audit("", "connect", "pc@box", "", "ok")
	es := m.AuditTail(10)
	if len(es) != 2 {
		t.Fatalf("静默模式下审计也必须照记，拿到 %d 条", len(es))
	}
	if es[1].Actor != "unknown" {
		t.Errorf("没给 actor 该记 unknown，拿到 %q", es[1].Actor)
	}
}

// ── 进程内 SSH + SFTP 服务器（端到端） ──

type testServer struct {
	addr    string
	ln      net.Listener
	signer  ssh.Signer
	lastCmd string
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{addr: ln.Addr().String(), ln: ln, signer: signer}
	go ts.serve(t)
	return ts
}

func (ts *testServer) serve(t *testing.T) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "test" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("nope")
		},
	}
	cfg.AddHostKey(ts.signer)
	for {
		conn, err := ts.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
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
				go ts.session(ch, chReqs)
			}
		}()
	}
}

func (ts *testServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload = struct{ Cmd string }{}
			ssh.Unmarshal(req.Payload, &payload)
			ts.lastCmd = payload.Cmd
			if req.WantReply {
				req.Reply(true, nil)
			}
			ts.runExec(ch, payload.Cmd)
			return
		case "subsystem":
			var payload = struct{ Name string }{}
			ssh.Unmarshal(req.Payload, &payload)
			if payload.Name == "sftp" {
				if req.WantReply {
					req.Reply(true, nil)
				}
				srv, err := sftp.NewServer(ch)
				if err == nil {
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

// runExec 测试服务器的命令处理：
//   - Windows 编码垫（chcp 开头）→ 原样回显收到的命令，用来断言垫上了
//   - 其余 → 真跑 /bin/sh -c，让 sha256sum、echo 都是真的
func (ts *testServer) runExec(ch ssh.Channel, cmd string) {
	var stdout []byte
	code := 0
	if strings.HasPrefix(cmd, winUTF8Preamble) {
		stdout = []byte(cmd)
	} else {
		out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
		stdout = out
		if err != nil {
			code = 1
		}
	}
	ch.Write(stdout)
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(code))
	ch.SendRequest("exit-status", false, bs)
}

func testDevice(ts *testServer) *Device {
	host, portS, _ := net.SplitHostPort(ts.addr)
	var port int
	fmt.Sscanf(portS, "%d", &port)
	return &Device{ID: "test@" + host, Host: host, Port: port, User: "test", Password: "pw", OS: "linux"}
}

func TestE2EDialExecTOFU(t *testing.T) {
	ts := startTestServer(t)
	defer ts.ln.Close()
	m, _ := Open(t.TempDir())
	d, _ := m.AddDevice(*testDevice(ts))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := m.Dial(ctx, d)
	if err != nil {
		t.Fatalf("首连失败：%s", err)
	}
	defer c.Close()
	if d.HostKey == "" {
		t.Error("★ 首连必须记下主机密钥（TOFU），没记")
	}
	if err := m.UpdateDevice(d); err != nil {
		t.Fatal(err)
	}

	out, err := Exec(ctx, c, d, "echo 你好", 10*time.Second)
	if err != nil || strings.TrimSpace(out.Stdout) != "你好" {
		t.Fatalf("exec 中文往返失败：%v %+v", err, out)
	}

	// Windows 目标：命令前必须垫 UTF-8 编码协商
	wd := *d
	wd.OS = "windows"
	out, err = Exec(ctx, c, &wd, "whoami", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Stdout, "chcp 65001") {
		t.Errorf("★ Windows 命令没垫 UTF-8 协商（现场乱码坑），收到：%q", out.Stdout)
	}

	// 重连：主机密钥一致，应当照常连上
	c2, err := m.Dial(ctx, d)
	if err != nil {
		t.Fatalf("主机密钥没变却连不上：%s", err)
	}
	c2.Close()

	// 主机密钥变了 → 必须拒绝，不许悄悄接受
	m2, _ := Open(t.TempDir())
	d2, _ := m2.AddDevice(Device{Host: d.Host, Port: d.Port, User: "test", Password: "pw",
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIWrongKeyWrongKeyWrongKeyWrongKeyWrong"})
	if _, err := m2.Dial(ctx, d2); err == nil || !strings.Contains(err.Error(), "主机密钥") {
		t.Errorf("★ 主机密钥变了必须拒绝连接并说清后果，err=%v", err)
	}
}

func TestE2EAuthRejectedHumanWords(t *testing.T) {
	ts := startTestServer(t)
	defer ts.ln.Close()
	m, _ := Open(t.TempDir())
	d := testDevice(ts)
	d.Password = "错的"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := m.Dial(ctx, d)
	if err == nil {
		t.Fatal("错口令该连不上")
	}
	// ★ 人话：认证被拒要给「可能是账号名不对」级别的提示，不是干巴巴 Permission denied
	if !strings.Contains(err.Error(), "认证被拒") || !strings.Contains(err.Error(), "whoami") {
		t.Errorf("认证失败没给人话：%s", err)
	}
}

func TestE2EFilePushPullResumeVerify(t *testing.T) {
	ts := startTestServer(t)
	defer ts.ln.Close()
	m, _ := Open(t.TempDir())
	d, _ := m.AddDevice(*testDevice(ts))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := m.Dial(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	x := Execer(c)

	dir := t.TempDir()
	local := filepath.Join(dir, "固件包.bin")
	body := strings.Repeat("昱弘网通NetKit测试数据0123456789", 5000)
	if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	remotePath := filepath.Join(dir, "remote", "dest", "固件包.bin")

	// 推：目录不存在要能建；整包 SHA256 对端复核（测试服务器真跑 sha256sum）
	tr, err := Push(ctx, c, x, d, local, remotePath)
	if err != nil {
		t.Fatalf("push 失败：%s", err)
	}
	if tr.Verified != "match" {
		t.Errorf("★ 整包校验该 match，拿到 %q（sha %s）", tr.Verified, tr.SHA256)
	}
	if tr.Bytes != int64(len(body)) || tr.ResumedFrom != 0 {
		t.Errorf("push 统计不对：%+v", tr)
	}

	// 断点续传：把对端文件截半，再推一次应当从半截接着传
	half := int64(len(body) / 2)
	if err := os.Truncate(remotePath, half); err != nil {
		t.Fatal(err)
	}
	tr2, err := Push(ctx, c, x, d, local, remotePath)
	if err != nil {
		t.Fatalf("续传失败：%s", err)
	}
	if tr2.ResumedFrom != half {
		t.Errorf("★ 该从 %d 续传，报告 %d", half, tr2.ResumedFrom)
	}
	if tr2.Verified != "match" {
		t.Errorf("续传后整包校验该 match（校验的是整包不是这一段），拿到 %q", tr2.Verified)
	}
	got, _ := os.ReadFile(remotePath)
	if string(got) != body {
		t.Errorf("续传后的文件内容不对（%d 字节）", len(got))
	}

	// 拉回来：双向是硬要求
	back := filepath.Join(dir, "拉回.bin")
	tr3, err := Pull(ctx, c, x, d, remotePath, back)
	if err != nil {
		t.Fatalf("pull 失败：%s", err)
	}
	if tr3.Verified != "match" {
		t.Errorf("pull 校验该 match，拿到 %q", tr3.Verified)
	}
	got2, _ := os.ReadFile(back)
	if string(got2) != body {
		t.Errorf("拉回来的内容不对")
	}
}

// ── 消息判定：没有有人的会话必须说清，不是发出去完事 ──

type fakeExecer struct {
	// seq 按调用顺序消费；用完后一直返回最后一个
	seq  []*Output
	n    int
	seen []string
}

func (f *fakeExecer) Exec(_ context.Context, _ *Device, cmd string, _ time.Duration) (*Output, error) {
	f.seen = append(f.seen, cmd)
	i := f.n
	if i >= len(f.seq) {
		i = len(f.seq) - 1
	}
	f.n++
	return f.seq[i], nil
}

// ── 身份采集里的两个解析坑（都是 macOS 真机踩出来的）──

func TestExtractAddrsZone(t *testing.T) {
	// ★ IPv6 的 %zone 必须整个收进来：zone 里有非十六进制字母（en0 的 n），
	//   早先的正则到 % 后第一个字母就停，捞回来一堆 "fe80::1%" 半截地址
	got := extractAddrs(`		inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
		inet 192.168.0.101 netmask 0xffffff00 broadcast 192.168.0.255
		inet6 fe80::814:1480:955:6f74%en0 prefixlen 64`)
	// 广播地址也会被捞进来 —— 这是「宁可多捞，不许编」的既定行为
	want := []string{"fe80::1%lo0", "192.168.0.101", "192.168.0.255", "fe80::814:1480:955:6f74%en0"}
	if len(got) != len(want) {
		t.Fatalf("要 %v，拿到 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 个要 %q，拿到 %q", i, want[i], got[i])
		}
	}
}

func TestExtractListeningFormats(t *testing.T) {
	// Linux ss：本地地址在第 3 列，冒号分端口
	linux := "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\nLISTEN 0      128    0.0.0.0:22         0.0.0.0:*\nLISTEN 0      128    [::1]:631          [::]:*"
	got := extractListening(linux, false)
	if len(got) != 2 || got[0] != "22" || got[1] != "631" {
		t.Errorf("ss 格式解错：%v", got)
	}
	// ★ macOS netstat -an：点分端口（127.0.0.1.22 / *.22），冒号找不到
	mac := "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\ntcp4       0      0  *.22                   *.*                    LISTEN\ntcp4       0      0  127.0.0.1.631          *.*                    LISTEN"
	got = extractListening(mac, false)
	if len(got) != 2 || got[0] != "22" || got[1] != "631" {
		t.Errorf("macOS 格式解错：%v", got)
	}
	// Windows netstat：本地地址在第 1 列
	win := "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING"
	got = extractListening(win, true)
	if len(got) != 2 || got[0] != "3389" {
		t.Errorf("Windows 格式解错：%v", got)
	}
}

func TestSendMsgWindowsNoSession(t *testing.T) {
	f := &fakeExecer{seq: []*Output{{Stdout: qsHeader() + "\n" +
		qsRow(">", "services", "", 0, "Disc") + "\n"}}}
	d := &Device{OS: "windows"}
	r, err := SendScreenMessage(context.Background(), f, d, "hi", "me@mac", -1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != "no-session" {
		t.Errorf("没有有人的会话该判 no-session，拿到 %s", r.Code)
	}
}

func TestSendMsgWindowsSent(t *testing.T) {
	f := &fakeExecer{seq: []*Output{
		{Stdout: qsHeader() + "\n" +
			qsRow(">", "services", "", 0, "Disc") + "\n" +
			qsRow(" ", "console", "PC", 1, "Active") + "\n"},
		{Stdout: ""}, // msg.exe 成功
	}}
	d := &Device{OS: "windows"}
	r, err := SendScreenMessage(context.Background(), f, d, "维护通知", "me@mac", -1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != "sent" || r.Session == nil || *r.Session != 1 {
		t.Errorf("该发到 Active 的 1 号会话：%+v", r)
	}
	// ★ 消息必须带发送方标识，不许伪装系统提示
	if !strings.Contains(f.seen[len(f.seen)-1], "me@mac") {
		t.Errorf("消息里没带发送方标识：%q", f.seen[len(f.seen)-1])
	}
}

func TestSendMsgWindowsMsgDisabled(t *testing.T) {
	// query session 挑到会话；msg 本身失败 → send-failed，说清可能是被禁用
	f := &fakeExecer{seq: []*Output{
		{Stdout: qsHeader() + "\n" + qsRow(" ", "console", "PC", 1, "Active") + "\n"},
		{ExitCode: 1, Stderr: "无法联系会话 1"},
	}}
	d := &Device{OS: "windows"}
	r, err := SendScreenMessage(context.Background(), f, d, "hi", "me@mac", -1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != "send-failed" || !strings.Contains(r.Detail, "禁用") {
		t.Errorf("msg.exe 失败该判 send-failed 并提示可能被禁用：%+v", r)
	}
}

// 掐表和跑砸是两件事：剧本那一层靠这个码分得开「加等待秒数」和「改这条命令」。
func Test掐掉的命令要能被认成超时(t *testing.T) {
	err := timeoutErr(20 * time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("丢了 DeadlineExceeded，调用方会把「等太久」判成「跑砸」：%v", err)
	}
	if !strings.Contains(err.Error(), "没跑完") {
		t.Errorf("光有码没有人话：%v", err)
	}
}

// ── 远程桌面：三种目标各走各的路（desktop.go）──

// macOS 上非 root 读不到 system 域，只能拿「5900 在不在听」当硬证据。
// ★ 而它的 netstat 是点分端口（*.5900），且 -ltn 退出码 0 却没有 LISTEN 行 ——
//
//	这条钉住探测链不许退回 `netstat -ltn`（身份采集那边实测踩过的坑）。
func TestQueryShareUsesNetstatANOnMac(t *testing.T) {
	f := &fakeExecer{seq: []*Output{{Stdout: `
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  *.5900                 *.*                    LISTEN
`}}}
	d := &Device{ID: "me@mac", OS: "darwin", Host: "192.168.3.20", User: "me"}
	st, err := QueryShare(context.Background(), f, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.seen[0], "netstat -an") || strings.Contains(f.seen[0], "netstat -ltn") {
		t.Errorf("macOS 探测链不对（-ltn 在那边不给 LISTEN 行）：%q", f.seen[0])
	}
	if !st.Listening {
		t.Errorf("点分端口的 *.5900 要认成在听：%+v", st)
	}
}

func TestQueryShareNotListening(t *testing.T) {
	// 5901（第二路显示）不能被当成 5900，也不能被当成没开：这是两件事
	f := &fakeExecer{seq: []*Output{{Stdout: "LISTEN 0 128 0.0.0.0:5901 0.0.0.0:*\n"}}}
	st, err := QueryShare(context.Background(), f, &Device{ID: "u@h", OS: "linux"})
	if err != nil || st.Listening {
		t.Fatalf("5901 不该判成 5900 在听：%+v %v", st, err)
	}
}

func TestParsePrintDisabled(t *testing.T) {
	// 本机实测：从没开过屏幕共享的 Mac 上，这条压根不在这张表里
	if got := parsePrintDisabled(`	disabled services = {
		"com.apple.ftpd" => disabled
	}`, "com.apple.screensharing"); got != "未记录" {
		t.Errorf("没记录该说「未记录」，拿到 %q", got)
	}
	if got := parsePrintDisabled(`	"com.apple.screensharing" => enabled`, "com.apple.screensharing"); got != "enabled" {
		t.Errorf("要 enabled，拿到 %q", got)
	}
}

// ★ 这台机器（macOS 15.6）实测的 sudo -n 形状：`sudo: a password is required` + rc=1。
//
//	测试用的是这份真输出，不是编的。
func TestParseMacPrivThisMac(t *testing.T) {
	raw := "staff access_bpf everyone admin _lpoperator com.apple.access_screensharing\n" +
		probeSep + "\nsudo: a password is required\nnetkit-rc=1\n"
	p := parseMacPriv(raw)
	if !p.Admin {
		t.Error("在 admin 组里要判成管理员")
	}
	if p.SudoFree {
		t.Error("★ 这台不给免密 sudo，判成给就是假话")
	}
	if !strings.Contains(p.SudoText, "password") {
		t.Errorf("sudo 的原话要留着给人看：%q", p.SudoText)
	}
	p2 := parseMacPriv("admin staff\n" + probeSep + "\nnetkit-rc=0\n")
	if !p2.SudoFree || !p2.Admin {
		t.Errorf("免密那条要判成能动手：%+v", p2)
	}
	p3 := parseMacPriv("staff everyone\n" + probeSep +
		"\nsudo: user is not in the sudoers file\nnetkit-rc=1\n")
	if p3.Admin || p3.SudoFree {
		t.Errorf("不在 admin 组要判成不是管理员：%+v", p3)
	}
}

// 三档下一步各不相同：能替开 / 给你贴（给免密才行）/ 换账号。判定码必须分得开。
func TestMacShareChangeTiers(t *testing.T) {
	free := MacShareChange(&MacPriv{Admin: true, SudoFree: true})
	if free.HandsOff || free.Code != "" {
		t.Errorf("给了免密 sudo 就该是 NetKit 替跑：%+v", free)
	}
	joined := strings.Join(cmdLinesOf(free.Do), "\n")
	if !strings.Contains(joined, "sudo launchctl enable system/com.apple.screensharing") ||
		!strings.Contains(joined, "/System/Library/LaunchDaemons/com.apple.screensharing.plist") {
		t.Errorf("开屏幕共享的两条命令不齐：\n%s", joined)
	}
	if !strings.Contains(strings.Join(cmdLinesOf(free.Undo), "\n"), "launchctl disable system/com.apple.screensharing") {
		t.Error("没有关回去的那几条，账本就还原不了")
	}

	needSudo := MacShareChange(&MacPriv{Admin: true})
	if !needSudo.HandsOff || needSudo.Code != "share-need-sudo" {
		t.Errorf("不给免密要判 share-need-sudo：%+v", needSudo)
	}
	// ★ 交给人贴的必须还是那两条（带 sudo），不能退化成一句"你自己去开"
	if got := strings.Join(cmdLinesOf(needSudo.Do), "\n"); !strings.Contains(got, "launchctl enable") {
		t.Errorf("不代跑也得把命令给全：\n%s", got)
	}
	if strings.Contains(strings.Join(cmdLinesOf(needSudo.Do), "\n"), "sudo -S") {
		t.Error("★ 不许出现把口令喂给 sudo -S 的写法")
	}

	notAdmin := MacShareChange(&MacPriv{})
	if notAdmin.Code != "share-not-admin" || !strings.Contains(notAdmin.Reason, "管理员") {
		t.Errorf("不是管理员要判 share-not-admin 并说清换账号：%+v", notAdmin)
	}

	unknown := MacShareChange(nil)
	if !unknown.HandsOff || unknown.Code == "" {
		t.Errorf("没问过权限就不许演「我能替你开」：%+v", unknown)
	}
}

func cmdLinesOf(cmds []Cmd) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.Line)
	}
	return out
}

// 动手那一步：顺序跑完、"已经在跑"那一类非 0 不算失败、别的非 0 必须报出是哪一步。
func TestApplyRDPOrdersAndToleratesAlreadyRunning(t *testing.T) {
	f := &fakeExecer{seq: []*Output{
		{Stdout: "操作成功完成。"},
		// 1056 = ERROR_SERVICE_ALREADY_RUNNING。★ 不是 1062：那是 ERROR_SERVICE_PAUSED
		// （服务挂着），拿它当「已经在跑」会把一种真故障洗成成功。
		{ExitCode: 1056, Stderr: "SERVICE_ALREADY_RUNNING"}, // sc start 对已运行的服务
		{Stdout: "Ok."},
	}}
	if err := ApplyChange(context.Background(), f, &Device{OS: "windows"}, RDPChange()); err != nil {
		t.Fatalf("服务已在跑不该算失败：%v", err)
	}
	if len(f.seen) != 3 {
		t.Fatalf("要按顺序跑 3 步，跑了 %d：%q", len(f.seen), f.seen)
	}
	if !strings.Contains(f.seen[0], "fDenyTSConnections /t REG_DWORD /d 0") {
		t.Errorf("第一步该是注册表：%q", f.seen[0])
	}
	if !strings.Contains(f.seen[2], `name="NetKit-RDP"`) || !strings.Contains(f.seen[2], "localport=3389") {
		t.Errorf("第三步该加那条固定名的防火墙规则：%q", f.seen[2])
	}
	// ★ 不碰本地化的「远程桌面」规则组
	for _, c := range f.seen {
		if strings.Contains(c, "rule group=") {
			t.Errorf("不许按本地化组名下发防火墙规则：%q", c)
		}
	}
}

func TestApplyChangeReportsWhichStepRefused(t *testing.T) {
	f := &fakeExecer{seq: []*Output{
		{Stdout: "ok"},
		{ExitCode: 5, Stderr: "拒绝访问。"},
		{Stdout: "不该跑到这"},
	}}
	err := ApplyChange(context.Background(), f, &Device{OS: "windows"}, RDPChange())
	var ae *ApplyError
	if !errors.As(err, &ae) {
		t.Fatalf("权限不够要报成 ApplyError，拿到 %v", err)
	}
	if ae.ExitCode != 5 || !strings.Contains(ae.Cmd, "TermService") {
		t.Errorf("要说清是哪一步、退出码多少：%+v", ae)
	}
	if len(f.seen) != 2 {
		t.Errorf("失败后不许接着往下跑：%q", f.seen)
	}
}

// ★★ macOS 那两条的纪律：成败由 `launchctl print` 说，不由 launchctl 自己的退出码说。
//
//	本机量过：load -w 对已加载的 plist 嘴上回 "Load failed: 5" 却**退出 0**，
//	unload -w 对没加载的也一样 —— 所以「|| load -w 兜底」这条链的最后一码可以是 0，
//	而那一趟其实什么都没改成。钉法要能红：把链尾那句 print 删掉，这一条就必须失败。
func TestMacShareCommandsEndWithStateProof(t *testing.T) {
	do, undo := MacShareCmds("sudo ")
	if len(do) != 2 || len(undo) != 2 {
		t.Fatalf("计划形状变了：%q / %q", cmdLinesOf(do), cmdLinesOf(undo))
	}
	起 := do[1].Line
	停 := undo[0].Line
	for _, c := range []struct{ what, line string }{{"起", 起}, {"停", 停}} {
		if !strings.HasPrefix(c.line, "launchctl print system/"+macScreensharingLabel) {
			t.Errorf("%s 这一条没先看状态就动手：%q", c.what, c.line)
		}
		if i := strings.LastIndex(c.line, ";"); i < 0 || !strings.Contains(c.line[i:], "launchctl print") {
			t.Errorf("%s 这一条的链尾不是 print 定成败（launchctl 自己的退出码会骗人）：%q", c.what, c.line)
		}
	}
	// 白名单必须空着：这两条不靠「非 0 也放过」，放过任何一码都是把没改成说成改成了。
	for _, c := range append(append([]Cmd{}, do...), undo...) {
		if len(c.AlreadyOK) != 0 {
			t.Errorf("这一条又用回「退出码放过」了（%v）：%q", c.AlreadyOK, c.Line)
		}
	}
	// 反证的正身：假对端每一步都回非 0（等于「print 说没起着 / 没权限」），必须报成失败。
	f := &fakeExecer{seq: []*Output{{ExitCode: 1}, {ExitCode: 1}}}
	err := ApplyChange(context.Background(), f, &Device{OS: "darwin"}, &Change{Kind: "mac", Do: do})
	var ae *ApplyError
	if !errors.As(err, &ae) {
		t.Fatalf("链尾 print 说没起着，就要报失败，拿到 %v", err)
	}
}

// ★★ Linux 这一路的纪律：只给命令、不代跑。这里钉的是"计划一旦 HandsOff，
//
//	ApplyChange 必须大声拒绝"——否则哪天有人把 HandsOff 忘了，就会拿给人看的文本去动系统。
func TestApplyChangeRefusesHandsOffPlan(t *testing.T) {
	f := &fakeExecer{seq: []*Output{{}}}
	ch := LinuxShareChange(&LinuxEnv{Distro: "ubuntu", Pretty: "Ubuntu 22.04", Bins: []string{"gnome-remote-desktop"}})
	err := ApplyChange(context.Background(), f, &Device{OS: "linux"}, ch)
	if err == nil || !strings.Contains(err.Error(), "不代跑") {
		t.Fatalf("不代跑的计划被执行了：%v", err)
	}
	if len(f.seen) != 0 {
		t.Errorf("一条命令都不许发到对端：%q", f.seen)
	}
}

func TestLinuxShareChangeGivesConcreteCommands(t *testing.T) {
	cases := []struct {
		name string
		env  *LinuxEnv
		want []string
	}{
		{"gnome-新", &LinuxEnv{Distro: "ubuntu", Bins: []string{"gnome-remote-desktop", "grdctl"}},
			[]string{"org.gnome.desktop.remote-desktop.vnc enabled true", "systemctl --user enable --now gnome-remote-desktop"}},
		{"gnome-vino", &LinuxEnv{Distro: "debian", Bins: []string{"vino-passwd"}},
			[]string{"org.gnome.Vino enabled true", "vino-server"}},
		{"kde", &LinuxEnv{Distro: "fedora", Sessions: []string{"plasma"}},
			[]string{"krfb"}},
		{"只有x11vnc", &LinuxEnv{Distro: "opensuse", Bins: []string{"x11vnc"}},
			[]string{"x11vnc -display :0", "x11vnc -storepasswd"}},
		{"什么都没装", &LinuxEnv{Distro: "ubuntu"},
			[]string{"sudo apt install -y gnome-remote-desktop", "sudo apt install -y x11vnc"}},
		{"没装且发行版陌生", &LinuxEnv{Distro: "kylin"},
			[]string{"install gnome-remote-desktop"}},
	}
	for _, tc := range cases {
		ch := LinuxShareChange(tc.env)
		if !ch.HandsOff || ch.Code != "linux-share-commands" {
			t.Errorf("%s: 这一路必须是不代跑：%+v", tc.name, ch)
		}
		got := strings.Join(cmdLinesOf(ch.Do), "\n")
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: 缺这一条 %q，拿到：\n%s", tc.name, w, got)
			}
		}
		// ★ SSH 会话里没有这两个变量，systemctl --user / gsettings 会报 Could not connect to bus，
		//   看着像"那台的桌面服务坏了"。每条计划都先给这两句。
		if !strings.Contains(got, "XDG_RUNTIME_DIR=/run/user/$(id -u)") ||
			!strings.Contains(got, "DBUS_SESSION_BUS_ADDRESS") {
			t.Errorf("%s: 没给 user 会话缺的那两个环境变量：\n%s", tc.name, got)
		}
		if len(ch.Undo) == 0 || !strings.Contains(cmdLinesOf(ch.Undo)[0], "没有改动过") {
			t.Errorf("%s: Linux 这一路没改过对端，账本里要写明没有要还原的东西", tc.name)
		}
	}
}

func TestParseLinuxProbe(t *testing.T) {
	raw := `/usr/bin/gnome-remote-desktop
/usr/bin/grdctl
` + probeSep + `
/usr/share/wayland-sessions:
gnome.desktop
plasma.desktop

` + probeSep + `
ID="ubuntu"
PRETTY_NAME="Ubuntu 24.04.1 LTS"
`
	env := parseLinuxProbe(raw)
	if env.DE() != "gnome" {
		t.Errorf("要认出 gnome：%+v", env)
	}
	if env.Distro != "ubuntu" || env.Pretty != "Ubuntu 24.04.1 LTS" {
		t.Errorf("发行版解错：%+v", env)
	}
	if len(env.Bins) != 2 || env.Bins[0] != "gnome-remote-desktop" {
		t.Errorf("服务端程序要只留文件名：%v", env.Bins)
	}
	// ls 的表头与空行不能混进会话名
	for _, s := range env.Sessions {
		if strings.Contains(s, "/") || s == "" {
			t.Errorf("会话名混进了噪声：%v", env.Sessions)
		}
	}
}

// 只读那一路：PrepareDesktop 一条改系统的命令都不许发出去。
func TestPrepareDesktopIsReadOnly(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin"} {
		f := &fakeExecer{seq: []*Output{{Stdout: "0x1\n"}, {Stdout: ""}, {Stdout: ""}}}
		if _, err := PrepareDesktop(context.Background(), f, &Device{ID: "u@h", OS: goos, User: "u", Host: "h"}); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		for _, c := range f.seen {
			for _, bad := range []string{"reg add", "sc start", "launchctl enable", "launchctl bootstrap",
				"systemctl --user enable", "gsettings set", "apt install", "sudo"} {
				if strings.Contains(c, bad) {
					t.Errorf("%s 的「查状态」里发出了改动命令 %q：%q", goos, bad, c)
				}
			}
		}
	}
}

func TestPrepareDesktopUnknownOSLoudly(t *testing.T) {
	f := &fakeExecer{seq: []*Output{{}}}
	if _, err := PrepareDesktop(context.Background(), f, &Device{OS: "routeros"}); err == nil ||
		!strings.Contains(err.Error(), "remote.device.probe") {
		t.Errorf("认不出的系统要大声报错并给下一步，拿到 %v", err)
	}
}

func TestConfirmListeningRetries(t *testing.T) {
	f := &fakeExecer{seq: []*Output{
		{Stdout: "tcp4 0 0 *.22 *.* LISTEN\n"},
		{Stdout: "tcp4 0 0 *.5900 *.* LISTEN\n"},
	}}
	ok, err := ConfirmListening(context.Background(), f, &Device{OS: "darwin"}, 3, time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("第二次就该看到 5900：%v %v", ok, err)
	}
	if len(f.seen) != 2 {
		t.Errorf("看到就该停，跑了 %d 次", len(f.seen))
	}
	// 一直查不到就是查不到 —— 不许把"没核实"说成"开好了"
	f2 := &fakeExecer{seq: []*Output{{Stdout: "no listener here\n"}}}
	ok, err = ConfirmListening(context.Background(), f2, &Device{OS: "darwin"}, 2, time.Millisecond)
	if err != nil || ok {
		t.Fatalf("没在听要报 false：%v %v", ok, err)
	}
}

// ── NetKit 主机是 Windows、目标是 VNC：先找装过的查看器 ──

func TestParseRegInstallDirs(t *testing.T) {
	// reg query ... /s /f 的真实排版：键路径行 + 三列的值行
	out := `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TigerVNC
    DisplayName    REG_SZ    TigerVNC 1.13.1
    InstallLocation    REG_SZ    C:\Program Files\TigerVNC\
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RealVNC-VNC Viewer_is1
    DisplayIcon    REG_SZ    C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe

Found.`
	dirs := parseRegInstallDirs(out)
	want := []string{`C:\Program Files\TigerVNC`, `C:\Program Files\RealVNC\VNC Viewer`}
	if len(dirs) != len(want) {
		t.Fatalf("要 %v，拿到 %v", want, dirs)
	}
	for i := range want {
		// ★ 不许切成 "."：那是拿宿主 filepath 切 Windows 路径的下场
		if dirs[i] != want[i] {
			t.Errorf("第 %d 个要 %q，拿到 %q", i, want[i], dirs[i])
		}
	}
}

func TestViewerCandidatesAndArgs(t *testing.T) {
	cands := viewerCandidates([]string{`C:\Program Files\TigerVNC`, `C:\Program Files\TightVNC`})
	if len(cands) == 0 || !strings.Contains(cands[0], `C:\Program Files\TigerVNC\vncviewer.exe`) {
		t.Fatalf("候选路径形状不对：%v", cands)
	}
	for _, c := range cands {
		if strings.Contains(c, `\\`) {
			t.Errorf("拼路径拼出了双反斜杠：%q", c)
		}
	}
	// 各家命令行形状不同，认不出的产品按最通用那一形，且一定把形状说出去（界面上看得见）
	args, shape := vncViewerArgs(`C:\Program Files\TigerVNC\vncviewer.exe`, "192.168.3.20", 5900)
	if len(args) != 1 || args[0] != "192.168.3.20::5900" || shape == "" {
		t.Errorf("TigerVNC 要主机::端口，且要报出用的是哪一形：%v %q", args, shape)
	}
	args, shape = vncViewerArgs(`C:\Program Files\TightVNC\tvnviewer.exe`, "192.168.3.20", 5901)
	if len(args) != 1 || !strings.HasPrefix(args[0], "-connect=") || !strings.Contains(args[0], "::5901") {
		t.Errorf("TightVNC 2.x 那一形没给对：%v %q", args, shape)
	}
	if vncClipboardText("192.168.3.20", 5900) != "192.168.3.20::5900" {
		t.Error("剪贴板里那句要和查看器连的一样（双冒号=直接给端口号）")
	}
	// 认不出产品也要给个形状说出去，不能默默丢参数
	_, shape = vncViewerArgs(`D:\somewhere\weird.exe`, "h", 5900)
	if shape == "" {
		t.Error("没说出用的是哪一形，人连不上时看不见原因")
	}
}

// Windows 主机上找查看器：不在 Windows 上跑就明说不跑（POSIX 测试机器不许去 exec reg.exe）。
func TestRunLocalRefusesNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("这一条钉的是非 Windows 的护栏")
	}
	if _, err := runLocal(time.Second, "reg", "query", "HKLM"); err == nil ||
		!strings.Contains(err.Error(), "不是 Windows") {
		t.Errorf("非 Windows 主机上跑本机命令要报错，拿到 %v", err)
	}
	if dirs := winViewerDirsFromRegistry(); dirs != nil {
		t.Errorf("非 Windows 上不该去查注册表：%v", dirs)
	}
	if err := windowsClipboard("x"); err == nil {
		t.Error("非 Windows 上剪贴板兜底要如实报做不了")
	}
}
