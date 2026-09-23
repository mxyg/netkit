package filesrv

// FTP 这一侧的测试：★ 手写一个最小客户端，不引第三方库。
//
// 理由和 TFTP 那次一样 —— 拿库来验自己，库把哪个坑替我们填了我们就永远看不见。
// 这里要钉住的主要是三件事：
//
//	1. **没有写路径**（STOR / DELE / MKD / RNFR 全部当场拒，而且本机磁盘上不许多出东西）
//	2. **数据口不许开到别的地址上**（PASV 绑通配 = 从这台机器其余每块网卡也开出去）
//	3. **PORT 不许借本机去连第三方**（不校验就是一个现成的内网探针）

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type ftpCli struct {
	t      *testing.T
	c      net.Conn
	br     *bufio.Reader
	srv    string // 服务端地址（控制连接连的那个）
	local  string // 本机这一侧的地址:端口（PASV 应当回同一个地址）
	closed bool
}

func ftpDial(t *testing.T, addr string) *ftpCli {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		_ = c
	} else {
		t.Fatalf("连不上 %s：%v", addr, err)
	}
	cl := &ftpCli{t: t, c: c, br: bufio.NewReader(c), srv: addr}
	l, _, _ := net.SplitHostPort(c.LocalAddr().String())
	cl.local = l
	cl.expect("", "220") // 问候语
	return cl
}

func (cl *ftpCli) send(line string) {
	cl.t.Helper()
	if _, err := cl.c.Write([]byte(line + "\r\n")); err != nil {
		cl.t.Fatalf("发不出去（%s）：%v", line, err)
	}
}

// reply 读一条应答；多行的（FEAT 那种）读到「三位数 + 空格」那行为止。
//
// ★ 光秃秃一个「200」（后面没文本）也是完整应答 —— 只认「三位数+空格」的话，
//
//	读到这种就会当成多行应答的中间一行继续等，测试表现为莫名超时，
//	而服务端其实早就答完了。
func (cl *ftpCli) reply() string {
	cl.t.Helper()
	var out strings.Builder
	for {
		line, err := cl.br.ReadString('\n')
		if err != nil {
			cl.t.Fatalf("读应答等不到：%v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString(line)
		if len(line) == 3 || (len(line) >= 4 && line[3] == ' ') {
			return out.String()
		}
	}
}

func (cl *ftpCli) expect(cmd, wantCode string) string {
	cl.t.Helper()
	if cmd != "" {
		cl.send(cmd)
	}
	r := cl.reply()
	if !strings.HasPrefix(r, wantCode) {
		cl.t.Fatalf("%q 的回话不对：要 %s…，实际 %q", cmd, wantCode, r)
	}
	return r
}

// pasv 发 PASV 并回数据口地址；同时把「回的是哪个地址」交给调用方比对。
func (cl *ftpCli) pasv() string {
	cl.t.Helper()
	r := cl.expect("PASV", "227")
	i := strings.Index(r, "(")
	j := strings.Index(r, ")")
	if i < 0 || j < i {
		cl.t.Fatalf("227 里找不到括号：%q", r)
	}
	nums := strings.Split(r[i+1:j], ",")
	if len(nums) != 6 {
		cl.t.Fatalf("227 里不是六个数：%q", r)
	}
	var ip [4]byte
	for k := 0; k < 4; k++ {
		n, err := strconv.Atoi(nums[k])
		if err != nil || n < 0 || n > 255 {
			cl.t.Fatalf("227 里的地址不成样子：%q", r)
		}
		ip[k] = byte(n)
	}
	port := atoi(nums[4])*256 + atoi(nums[5])
	return net.JoinHostPort(net.IP(ip[:]).String(), strconv.Itoa(port))
}

func (cl *ftpCli) epsv() string {
	cl.t.Helper()
	r := cl.expect("EPSV", "229")
	i := strings.Index(r, "|||")
	j := strings.Index(r, "|)")
	if i < 0 || j < i {
		cl.t.Fatalf("229 里找不到端口：%q", r)
	}
	port, err := strconv.Atoi(r[i+3 : j])
	if err != nil {
		cl.t.Fatalf("229 里的端口看不懂：%q", r)
	}
	host, _, _ := net.SplitHostPort(cl.srv)
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (cl *ftpCli) login() {
	cl.t.Helper()
	cl.expect("USER tester", "331")
	cl.expect("PASS 一句话也别信我", "230")
	cl.expect("TYPE I", "200")
}

func (cl *ftpCli) quit() {
	cl.t.Helper()
	if cl.closed {
		return
	}
	cl.closed = true
	cl.expect("QUIT", "221")
	_ = cl.c.Close()
}

func (cl *ftpCli) closeNow() {
	cl.closed = true
	_ = cl.c.Close()
}

// dialData 连数据口。★ 必须在服务端已经回 150 之后再连：那时它才在 Accept 上等。
func dialData(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		t.Fatalf("连不上数据口 %s：%v", addr, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	return c
}

func ftpReadAll(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, 8192)
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return out // EOF 就是「这一发发完了」
		}
	}
}

// ftpShare 起一个只开了 FTP 的共享（127.0.0.1，端口交给系统挑）。
func ftpShare(t *testing.T, cfg func(*Config)) (*Server, string, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "fw.bin", []byte(strings.Repeat("Z", 4000)))
	writeFile(t, root, "tiny.bin", []byte("12345"))
	if err := os.WriteFile(filepath.Join(root, "外层的密钥"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0, Listing: true,
		FTP: true, FTPPort: 0}
	if cfg != nil {
		cfg(&c)
	}
	s, err := Start(c)
	if err != nil {
		t.Fatalf("起不来：%v", err)
	}
	t.Cleanup(s.Stop)
	st := s.Status()
	if len(st.FTPURLs) == 0 {
		t.Fatal("FTP 开着却没给出地址")
	}
	addr := strings.TrimPrefix(strings.TrimPrefix(st.FTPURLs[0], "ftp://"), "[")
	addr = strings.TrimSuffix(addr, "/")
	addr = strings.Replace(addr, "]:", ":", 1)
	return s, addr, root
}

func ftpOccupyPort(t *testing.T) (int, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return n, ln
}

// ── 读得到 ──

func TestFTP取走一整份并且记账(t *testing.T) {
	s, addr, _ := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	cl.expect("SIZE /fw.bin", "213") // 设备升级前常常只问大小

	dataAddr := cl.pasv()
	cl.expect("LIST", "150")
	dc := dialData(t, dataAddr)
	body := string(ftpReadAll(t, dc))
	_ = dc.Close()
	cl.expect("", "226")
	if !strings.Contains(body, "fw.bin") || !strings.Contains(body, "tiny.bin") {
		t.Errorf("目录里两个文件都该在：%q", body)
	}
	if !strings.Contains(body, "4000") {
		t.Errorf("列表里要带大小：%q", body)
	}

	dataAddr = cl.pasv()
	cl.expect("RETR /fw.bin", "150")
	c := dialData(t, dataAddr)
	got := ftpReadAll(t, c)
	_ = c.Close()
	cl.expect("", "226")
	if string(got) != strings.Repeat("Z", 4000) {
		t.Fatalf("内容不对：%d 字节", len(got))
	}

	st := waitStats(t, s, func(st Status) bool { return st.Requests >= 3 })
	var ok, head, list int
	for _, tr := range st.Recent {
		if tr.Proto != "ftp" {
			continue
		}
		switch tr.Status {
		case "ok":
			ok++
			if tr.Bytes != 4000 {
				t.Errorf("那一笔记成 %d 字节", tr.Bytes)
			}
		case "head":
			head++
		case "list":
			list++
		}
	}
	if ok != 1 || head != 1 || list != 1 {
		t.Errorf("ok/head/list 应各一笔，实际 %d/%d/%d", ok, head, list)
	}
}

func TestFTP一次会话连着取两枚(t *testing.T) {
	// ★ 每笔换一个数据口，用完就关。复用上一个口的实现，第二枚会永远卡住
	//   （设备的表现是「第一枚固件下得动、第二枚不动」，最难查的一类）。
	s, addr, _ := ftpShare(t, nil)
	_ = s
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	first := cl.pasv()
	cl.expect("RETR /fw.bin", "150")
	c := dialData(t, first)
	if len(ftpReadAll(t, c)) != 4000 {
		t.Fatal("第一枚没取满")
	}
	_ = c.Close()
	cl.expect("", "226")

	second := cl.pasv()
	if second == first {
		t.Errorf("两笔用了同一个数据口：%s", second)
	}
	cl.expect("RETR /tiny.bin", "150")
	c2 := dialData(t, second)
	if string(ftpReadAll(t, c2)) != "12345" {
		t.Fatal("第二枚内容不对")
	}
	_ = c2.Close()
	cl.expect("", "226")
}

func TestFTP用EPSV也取得到(t *testing.T) {
	// EPSV 是 v6 那条路（227 装不下 v6 地址），v4 上也要能用。
	s, addr, _ := ftpShare(t, nil)
	_ = s
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	dataAddr := cl.epsv()
	cl.expect("RETR /tiny.bin", "150")
	c := dialData(t, dataAddr)
	if string(ftpReadAll(t, c)) != "12345" {
		t.Fatal("EPSV 这条路取不到东西")
	}
	_ = c.Close()
	cl.expect("", "226")
}

func TestFTP主动模式取得到文件(t *testing.T) {
	// PORT：让我们来连对端指定的地址。只允许连**同一个 IP**，见下一条。
	s, addr, _ := ftpShare(t, nil)
	_ = s
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	cl.expect(fmt.Sprintf("PORT %s", strings.ReplaceAll(host, ".", ",")+
		fmt.Sprintf(",%d,%d", port/256, port%256)), "200")
	cl.expect("RETR /fw.bin", "150")
	c, aerr := ln.Accept()
	if aerr != nil {
		t.Fatalf("本机没连过来：%v", aerr)
	}
	defer c.Close()
	if n := len(ftpReadAll(t, c)); n != 4000 {
		t.Errorf("主动模式发出去 %d 字节", n)
	}
	cl.expect("", "226")
}

// ── 没有写路径 ──

func TestFTP上传一律当场拒(t *testing.T) {
	s, addr, root := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	before, _ := filepath.Glob(filepath.Join(root, "*"))
	dataAddr := cl.pasv()
	r := cl.expect("STOR /evil.bin", "550")
	if !strings.Contains(r, "只") || !strings.Contains(r, "不收") {
		t.Errorf("要回一句看得懂的「只发不收」：%q", r)
	}
	_ = dataAddr
	// ★ 拒了还不够，必须确认磁盘上什么都没多出来：
	//   「回了 550 但其实文件已经建了一半」是实现里真出过的错。
	after, _ := filepath.Glob(filepath.Join(root, "*"))
	if len(after) != len(before) {
		t.Errorf("拒了却还是落盘了：%v", after)
	}
	if _, err := os.Stat(filepath.Join(root, "evil.bin")); err == nil {
		t.Error("evil.bin 被建出来了")
	}
	if st := s.Status(); st.Denied == 0 {
		t.Error("这一笔要单独记成「被拒」，不能混进失败里")
	}
}

func TestFTP删除改名建目录同样当场拒(t *testing.T) {
	s, addr, root := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	for _, cmd := range []string{"DELE /fw.bin", "RNFR /fw.bin", "RNTO /x.bin",
		"MKD /sub", "RMD /sub", "APPE /fw.bin"} {
		verb := strings.SplitN(cmd, " ", 2)[0]
		r := cl.expect(cmd, "550")
		if !strings.Contains(r, "上传") && !strings.Contains(r, "不收") {
			t.Errorf("%s 回得太含糊：%q", verb, r)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "fw.bin")); err != nil {
		t.Error("fw.bin 被删了")
	}
	if _, err := os.Stat(filepath.Join(root, "sub")); err == nil {
		t.Error("sub 目录被建出来了")
	}
	if st := s.Status(); st.Denied < 6 {
		t.Errorf("六笔都该单独记账，实际 Denied=%d", st.Denied)
	}
}

// ── 数据口绑在哪、PORT 允许连谁 ──

func TestFTP数据口只绑控制连接那一侧的地址(t *testing.T) {
	// ★★ 这条钉的是上一轮在 TFTP 上踩过的同一类泄漏：数据口要是绑了通配，
	// 它就会从这台机器**其余每一块网卡**上也开出去，而且不会报任何错。
	// 127.0.0.0/8 整段都在环回上，所以「从另一个本机地址连这个口」正好能测出来：
	// 绑 127.0.0.1 会拒，绑 0.0.0.0 会连上。
	s, addr, _ := ftpShare(t, nil)
	_ = s
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	dataAddr := cl.pasv()
	host, portStr, err := net.SplitHostPort(dataAddr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("PASV 回了 %s：必须回控制连接本机那一侧的地址", host)
	}
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.2", portStr), 2*time.Second); err == nil {
		t.Fatal("从 127.0.0.2 也连得上这个数据口 —— 它绑在通配地址上")
	}
	// 正主还得连得上（上面那发失败的连接不许把这一笔吃掉）
	cl.expect("RETR /tiny.bin", "150")
	c := dialData(t, dataAddr)
	if string(ftpReadAll(t, c)) != "12345" {
		t.Error("正常那条路取不到东西了")
	}
	_ = c.Close()
	cl.expect("", "226")
}

func TestFTP的PORT不许借本机连别人(t *testing.T) {
	s, addr, _ := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	// 127.0.0.2 不是这条控制连接的源地址：允许它，就等于谁都能借这台机器
	// 挨个试内网哪个地址哪个端口能连。
	r := cl.expect("PORT 127,0,0,2,193,200", "550")
	if !strings.Contains(r, "只允许连你自己") {
		t.Errorf("这一句要说清为什么不接：%q", r)
	}
	if st := s.Status(); st.Denied == 0 {
		t.Error("借道未遂必须单独记一笔，不能和「命令不认识」混在一起")
	}
	// 拒完这条会话还要能用：不许把状态弄坏
	cl.expect("PWD", "257")
}

// ── 出不去这个目录 ──

func TestFTP两个点的路径到不了目录外(t *testing.T) {
	// ★ 这里断言的不是「它报错了」，而是**目录外的东西没被发出去**。
	//   path.Clean("/"+…) 把两个点就地吃掉，所以这些请求落在根内一个不存在的名字上 ——
	//   报「没有这个文件」是对的，悄悄把 /etc/passwd 发走才是事故。
	s, addr, root := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	for _, p := range []string{
		"/../../etc/passwd", "/../../../etc/hosts", "/..%2f..%2fetc/passwd",
	} {
		r := cl.expect("RETR "+p, "550")
		if strings.Contains(r, "root:") {
			t.Errorf("%q 把文件内容发出去了：%q", p, r)
		}
	}
	for _, p := range []string{"/../../etc", "/../etc"} {
		cl.expect("CWD "+p, "550")
	}
	// ★ /.. 单独说：Clean 之后它就是根，所以这一条**应当成功**。
	//   把它也当成越界，是实现里最容易顺手做错的一格。
	cl.expect("CWD /..", "250")
	if r := cl.expect("PWD", "257"); !strings.Contains(r, `"/"`) {
		t.Errorf("/.. 之后位置还在根外？%q", r)
	}
	// 抄错路径与两个点都只算「没找到」，不许污染那条「有人在试」的计数。
	st := s.Status()
	if st.Denied != 0 {
		t.Errorf("这些都没越出去，不该记成被拒：Denied=%d", st.Denied)
	}

	// ★ 真能越出去的是**符号链接**：现场有人把 /etc 或者用户目录软进固件目录，
	//   字符串怎么拼都看不出问题。这条走的是 resolve 里那第二道检查。
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "链出去的")); err != nil {
		t.Skip("这台机器上建不了符号链接")
	}
	cl.expect("RETR /链出去的", "550")
	cl.expect("CWD /链出去的行不行", "550")
	if st := waitStats(t, s, func(st Status) bool { return st.Denied >= 1 }); st.Denied == 0 {
		t.Error("顺符号链接往外取这一笔必须记成被拒")
	}
}

func TestFTP反斜杠文件名取得到(t *testing.T) {
	// Windows 侧的客户端传的是 \fw.bin 那种；不归一的话它永远「没有这个文件」，
	// 而人只会以为是共享没开对。
	s, addr, _ := ftpShare(t, nil)
	_ = s
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	dataAddr := cl.pasv()
	cl.expect("RETR \\fw.bin", "150")
	c := dialData(t, dataAddr)
	if len(ftpReadAll(t, c)) != 4000 {
		t.Error("反斜杠那条路取不到")
	}
	_ = c.Close()
	cl.expect("", "226")
}

func TestFTP关列表时目录翻不了文件仍可取(t *testing.T) {
	// ★ 关掉列表后给 550 而不是「空目录」：让人知道目录在、只是不给翻，
	//   否则会以为是路径写错，在那儿反复改斜杠。
	s, addr, _ := ftpShare(t, func(c *Config) { c.Listing = false })
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	r := cl.expect("LIST", "550")
	if !strings.Contains(r, "完整文件名") {
		t.Errorf("这一句要给得有用：%q", r)
	}
	dataAddr := cl.pasv()
	cl.expect("RETR /tiny.bin", "150")
	c := dialData(t, dataAddr)
	if string(ftpReadAll(t, c)) != "12345" {
		t.Error("关掉列表不该影响取文件")
	}
	_ = c.Close()
	cl.expect("", "226")
	if st := s.Status(); st.Denied == 0 {
		t.Error("想翻目录这一笔要记成被拒")
	}
}

func TestFTP没有的文件报不存在并且不污染被拒(t *testing.T) {
	s, addr, _ := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	for i := 0; i < 3; i++ {
		cl.expect("RETR /抄错的固件名.bin", "550")
	}
	st := waitStats(t, s, func(st Status) bool { return st.NotFound >= 3 })
	if st.Denied != 0 {
		t.Errorf("抄错三笔就把一个干净的共享记成「被试过」？Denied=%d", st.Denied)
	}
	if st.NotFound != 3 {
		t.Errorf("NotFound=%d", st.NotFound)
	}
}

func TestFTP的密码不留存也不进任何结果(t *testing.T) {
	// ★ 结果会发给 AI、台账会显示在界面上：密码一个字节都不许出现在那里。
	s, addr, _ := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.expect("USER tester", "331")
	cl.expect("PASS 绝不该出现的一串字", "230")
	dataAddr := cl.pasv()
	cl.expect("RETR /tiny.bin", "150")
	c := dialData(t, dataAddr)
	_ = ftpReadAll(t, c)
	_ = c.Close()
	cl.expect("", "226")

	blob, _ := json.Marshal(s.Status())
	if strings.Contains(string(blob), "绝不该出现的一串字") {
		t.Fatal("状态里带着密码")
	}
	if strings.Contains(string(blob), "tester") {
		t.Error("用户名也没必要留在台账里：这个服务不鉴权，记下来只是噪音")
	}
}

// ── 停与不接 ──

func TestFTP停掉时挂着的会话当场断(t *testing.T) {
	// ★ 「立刻停掉」必须是真的立刻：只关监听口的话，已经挂着的会话还在原地，
	// 而界面上写着「端口都放掉了」—— 那就是「看着停了、其实还开着」。
	s, addr, _ := ftpShare(t, nil)
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()

	s.Stop()
	_ = cl.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if line, err := cl.br.ReadString('\n'); err == nil {
		t.Fatalf("停了之后这条会话还在应答：%q", line)
	}
	// 新连接也不许再进来
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		_ = c.Close()
		t.Error("停了之后 ftp 口还在收连接")
	}
}

func TestFTP同时太多会话时不接新的(t *testing.T) {
	s, addr, _ := ftpShare(t, nil)
	var clis []*ftpCli
	for i := 0; i < ftpMaxSessions; i++ {
		c := ftpDial(t, addr)
		c.expect("NOOP", "200") // 别停在问候语那一步，算一条真会话
		clis = append(clis, c)
	}
	defer func() {
		for _, c := range clis {
			c.closeNow()
		}
	}()

	over, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("第 %d 条连不上：限流失效前它该被拒，不是连不上", ftpMaxSessions+1)
	}
	defer over.Close()
	_ = over.SetDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReader(over).ReadString('\n')
	if !strings.HasPrefix(line, "421") {
		t.Errorf("超上限要当场回 421（而不是收下连接再冷处理）：%q", line)
	}
	if st := s.Status(); st.Denied+st.Requests == 0 {
		t.Error("这一笔也得记账：有人在拿这个口占连接")
	}
}

func Test不开FTP时一个ftp口都不开(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fw.bin", []byte("x"))
	s, err := Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0, Listing: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := s.Status()
	if st.FTP || len(st.FTPURLs) != 0 || st.FTPPort != 0 {
		t.Errorf("没开 FTP 却在状态里报了 ftp： %+v", st)
	}
}

func TestFTP绑不上时不留半个共享(t *testing.T) {
	// 批准说明里写的是「几个协议各开一个口」，人点头的是那个整体：
	// 起不齐就一个都不许留 —— 留一个只开了 http 的共享比全起不来更坏。
	root := t.TempDir()
	writeFile(t, root, "fw.bin", []byte("x"))
	occupied, hold := ftpOccupyPort(t) // 先把一个号占住，让 FTP 这一步一定失败
	defer hold.Close()
	_, err := Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0,
		Listing: true, FTP: true, FTPPort: occupied})
	if err == nil {
		t.Fatal("绑不上时居然起来了")
	}
	if !strings.Contains(err.Error(), "绑不上") && !strings.Contains(err.Error(), "占") {
		t.Errorf("要按端口那类话报：%v", err)
	}
}

func TestFTP没这个命令要如实说不认识(t *testing.T) {
	// ★ 未实现和「只读所以拒」要分开：把扩展命令一律回 550「只发不收」，
	//   现场会以为有人在防他，其实是我们没做那条命令。
	s, addr, _ := ftpShare(t, nil)
	_ = s
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	cl.login()
	cl.expect("MFFM /x", "500")
	cl.expect("HELP", "500")
	// MLST 走控制连接回一条：为「这个文件在不在、多大」再开一个数据口不值。
	r := cl.expect("MLST /fw.bin", "250")
	if !strings.Contains(r, "Size=4000") {
		t.Errorf("MLST 要带大小：%q", r)
	}
}

func TestFEAT里报的命令都必须真能用(t *testing.T) {
	s, addr, _ := ftpShare(t, nil)
	_ = s
	cl := ftpDial(t, addr)
	defer cl.closeNow()
	r := cl.expect("FEAT", "211")
	feat := r
	if !strings.Contains(feat, "PASV") || !strings.Contains(feat, "EPSV") {
		t.Fatalf("FEAT 少内容：%q", feat)
	}
	// 逐条试：报了就代表做了，客户端会照着走那条路。
	cl.login()
	for _, c := range []string{"TYPE I", "PWD", "SIZE /fw.bin", "MDTM /fw.bin", "MLST /fw.bin", "MLSD /"} {
		want := "2"
		switch {
		case strings.HasPrefix(c, "SIZE") || strings.HasPrefix(c, "MDTM"):
			want = "213"
		case strings.HasPrefix(c, "PWD"):
			want = "257"
		case strings.HasPrefix(c, "MLST"):
			want = "250"
		case strings.HasPrefix(c, "MLSD"):
			// 没先 PASV 就发 MLSD：该回「数据口没设好」这一类，而不是「没这个命令」。
			want = "4"
		}
		r := cl.expect(c, "")
		if strings.HasPrefix(r, "500") {
			t.Errorf("FEAT 报了 %q 但实际没实现：%q", c, r)
		}
		if strings.HasPrefix(c, "MLSD") {
			// 发了 150 之后连不上数据口，必须补一条 425 把这一笔结掉；
			// 只发 150 就没了的写法，客户端会永远等在数据口上。
			cl.expect("", "425")
			continue
		}
		if want != "2" && !strings.HasPrefix(r, want) {
			t.Errorf("%q 回话奇怪：%q", c, r)
		}
	}
}
