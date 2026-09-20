package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
