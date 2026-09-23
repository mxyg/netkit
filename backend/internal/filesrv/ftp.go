package filesrv

// ── FTP 这一侧：只有读 ──
//
// 为什么还要做第三种协议：设备的固件页面里，**写死 ftp:// 的那一批还没绝迹**，
// 而且比想象中多 —— 交换机、老 IPC、一些国产网关，地址栏只有「主机 / 用户名 / 文件名」三栏。
//
// ★ 和另外两侧同一条纪律：**这个文件里没有写路径**。
//
//	STOR / STOU / APPE / DELE / RNFR / RNTO / MKD / RMD / SITE 一律当场回 550。
//	不是「鉴权后允许写」，而是这些命令在这里根本没有对应实现。
//	FTP 的 STOR 比 HTTP 的 PUT 更直接 —— 文件名和落点都是对端给的。
//
// ★ 两处最容易做错、而症状都是「有的设备上能用、有的永远卡住」的地方：
//
//	1. **PASV 的数据口必须绑在控制连接本机这一侧的地址上**。绑通配最省事，
//	   但那等于把数据口从这台机器其余每一块网卡上也开出去 ——
//	   和 TFTP 那个「带区地址解成 nil」是同一类泄漏，而且这一步不会有任何报错。
//	2. **PORT（主动模式）是让本机反过来去连对端指定的地址端口**。
//	   不校验就是一个现成的内网探针：谁都能借这台机器挨个试内网哪个地址能连。
//	   这里只允许连**控制连接的同一个 IP**，别的当场拒并单独记一笔。
//
// 无鉴权照旧：USER/PASS 只为走完握手。密码**不留存、不回显、不进任何一条结果和日志**。

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ftpDefault = 21

	// ftpMaxSessions 同时在线的控制连接上限。FTP 是**长连接**，一个客户端能挂着不动；
	// 这是个不鉴权的服务，不封顶的话几个脚本就把这台机器的句柄占住了。
	ftpMaxSessions = 16

	// ftpIdle 控制连接多久没话就断：设备取完固件经常不发 QUIT，直接走人。
	ftpIdle = 2 * time.Minute

	// ftpDataSlack 是给「对端拔网线」留的。没有读写超时，一个挂住的数据连接
	// 会让这一笔永远停在 partial 之前 —— 而现场最需要看见的正是「停在哪儿」。
	ftpDataSlack = 30 * time.Second

	// ftpAcceptSlack 是被动模式下等对端来连数据口的耐心。
	ftpAcceptSlack = 20 * time.Second
)

// ftpWriteCmds 是那些「要往本机写」的命令。★ 这张表不是为了分发，而是为了
// 给得出一句有用的拒绝：只回 502（不实现）现场会以为是这个服务没做完、
// 跑去翻设置；回 550 说清「只发不收」，人才知道要换办法。
var ftpWriteCmds = map[string]bool{
	"STOR": true, "STOU": true, "APPE": true, "DELE": true,
	"RNFR": true, "RNTO": true, "MKD": true, "XMKD": true,
	"RMD": true, "XRMD": true, "SITE": true, "SMNT": true,
}

type ftpListener struct {
	ln   net.Listener
	done chan struct{}
}

// startFTP 每个地址一个 TCP 监听口 —— 和 HTTP/TFTP 一样，绝不共用一个通配口。
func (s *Server) startFTP() ([]*ftpListener, error) {
	var out []*ftpListener
	for _, a := range s.cfg.Addrs {
		host := strings.Trim(a, "[]")
		fam := "tcp4"
		if strings.Contains(a, ":") {
			fam = "tcp6"
		}
		ln, err := net.Listen(fam, net.JoinHostPort(host, strconv.Itoa(s.cfg.FTPPort)))
		if err != nil {
			for _, l := range out {
				_ = l.ln.Close()
			}
			return nil, bindErr("ftp", a, s.cfg.FTPPort, err)
		}
		if s.cfg.FTPPort == 0 { // 系统挑中几号要读回来，不然界面上是 ftp://ip:0/
			_, p, _ := net.SplitHostPort(ln.Addr().String())
			s.cfg.FTPPort, _ = strconv.Atoi(p)
		}
		l := &ftpListener{ln: ln, done: make(chan struct{})}
		out = append(out, l)
		go s.serveFTP(l)
	}
	return out, nil
}

// FTPURLs 每个地址一条 ftp 地址（设备那一栏要的形状）。
func (s *Server) FTPURLs() []string {
	if !s.cfg.FTP {
		return nil
	}
	var u []string
	for _, a := range s.cfg.Addrs {
		if strings.Contains(a, ":") {
			u = append(u, fmt.Sprintf("ftp://[%s]:%d/", a, s.cfg.FTPPort))
		} else {
			u = append(u, fmt.Sprintf("ftp://%s:%d/", a, s.cfg.FTPPort))
		}
	}
	return u
}

func (s *Server) serveFTP(ln *ftpListener) {
	tl, ok := ln.ln.(*net.TCPListener)
	if !ok {
		return
	}
	for {
		_ = tl.SetDeadline(time.Now().Add(time.Second))
		c, err := ln.ln.Accept()
		if err != nil {
			var ne *net.OpError
			if errors.As(err, &ne) && ne.Timeout() {
				select {
				case <-ln.done:
					return
				default:
				}
				continue
			}
			return // 口已被 Stop() 关掉
		}
		if !s.ftpAcquire() {
			_, _ = c.Write([]byte("421 这个共享同时连的人太多了，先断开一下\r\n"))
			_ = c.Close()
			s.Record(Transfer{Peer: hostOnly(c.RemoteAddr()), Proto: "ftp", Status: "busy"})
			continue
		}
		go func() {
			defer s.ftpRelease()
			defer s.ftpOff(c)
			s.ftpOn(c)
			s.ftpSession(c)
		}()
	}
}

// ── 一个会话 ──

type ftpSession struct {
	s     *Server
	c     net.Conn
	br    *bufio.Reader
	peer  string // 对端 IP
	local string // 本机这一侧的 地址:端口 —— PASV 绑的就是它
	cwd   string // 以 / 开头的**共享内**路径

	pasvLn   *net.TCPListener
	pasvHost string
	pasvPort int
	portTo   *net.TCPAddr // 主动模式：对端让我们来连它
	ascii    bool
}

func (s *Server) ftpSession(c net.Conn) {
	defer c.Close()
	f := &ftpSession{s: s, c: c, br: bufio.NewReader(c),
		peer: hostOnly(c.RemoteAddr()), local: c.LocalAddr().String(), cwd: "/"}
	if f.peer == "" || f.local == "" {
		return
	}
	// ★ 会话走时必须把没用的数据口一起收掉：客户端不发 QUIT 就走人是常态，
	//   那些口留在原地就是「共享停了还有一串监听」。
	defer f.dropData()

	f.say("220 这个共享是只读的：只能取文件，不能上传、不能改、不能删")
	for {
		_ = c.SetReadDeadline(time.Now().Add(ftpIdle))
		line, err := f.br.ReadString('\n')
		if err != nil {
			return // 对端走了 / 超时：FTP 客户端经常不发 QUIT，这不算事故
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		verb, arg := splitCmd(line)
		if f.dispatch(strings.ToUpper(verb), arg) {
			return
		}
	}
}

// dispatch 返回 true 表示这个会话该结束了。
func (f *ftpSession) dispatch(verb, arg string) bool {
	switch verb {
	case "QUIT":
		f.dropData()
		f.say("221 再见")
		return true

	case "USER":
		// ★ 名字不留存也不记账：这个服务无鉴权，用户名不是凭据、也没人有它，
		//   记下来只会把台账变成噪音。
		f.say("331 不需要密码（这是个只读共享），随手填一个就行")
	case "PASS":
		// ★ 这一条的 arg 就是密码：不回显、不留存、不进台账，只回一句 230。
		f.say("230 已登录（只读）：本共享不收文件")

	case "SYST":
		f.say("215 UNIX Type: L8")
	case "FEAT":
		// 只声明真做了的：报一个没实现的特性，客户端就会走那条路然后卡住。
		f.multi("211-Features:", " UTF8", " PASV", " EPSV", " PORT", " EPRT",
			" SIZE", " MDTM", " MLST", " MLSD", " LIST", " NLST", " RETR", " CWD", " PWD", "211 End")
	case "OPTS":
		if strings.HasPrefix(strings.ToUpper(arg), "UTF8") {
			f.say("200 UTF8 开着的")
		} else {
			f.say("551 这个选项我没实现")
		}
	case "NOOP":
		f.say("200 好")
	case "STRU", "MODE":
		f.say("200 好")

	case "TYPE":
		switch strings.ToUpper(arg) {
		case "A", "ASCII", "A 7", "A N":
			f.ascii = true
			// ★ 说清楚我们**不转行尾**：真去转 CRLF 就是把固件刷坏。
			f.say("200 好（但一律按原样字节发，不做行尾转换）")
		case "I", "BINARY", "L 8", "E":
			f.ascii = false
			f.say("200 二进制")
		default:
			f.say("504 只认 TYPE A 和 TYPE I")
		}

	case "PWD":
		f.say(`257 "` + f.cwd + `" 是当前位置（共享目录，出不去）`)
	case "CWD":
		f.cmdCwd(arg)
	case "CDUP":
		f.cwd = path.Dir(f.cwd)
		if f.cwd == "" || f.cwd == "." {
			f.cwd = "/"
		}
		f.say("250 好")

	case "PASV":
		f.cmdPasv()
	case "EPSV":
		f.cmdEpsv(arg)
	case "PORT":
		f.cmdPort(arg, false)
	case "EPRT":
		f.cmdPort(arg, true)

	case "LIST":
		f.cmdList(f.argPath(arg), false)
	case "NLST":
		f.cmdNames(f.argPath(arg))
	case "MLSD":
		f.cmdList(f.argPath(arg), true)
	case "RETR":
		f.cmdRetr(f.argPath(arg))
	case "SIZE":
		f.cmdSize(f.argPath(arg))
	case "MDTM":
		f.cmdMdtm(f.argPath(arg))
	case "MLST":
		f.cmdMlst(f.argPath(arg))

	case "REST":
		f.say("502 不支持续传：FTP 这一侧一次取整份")
	case "ABOR":
		f.dropData()
		f.say("226 已中断")

	default:
		if ftpWriteCmds[verb] {
			// ★ 单独记「被拒」，不和「命令不认识」混：有人在拿这个口试写，
			//   这件事必须单独看得见。台账里那一条带的是命令名，不是文件内容。
			f.s.Record(Transfer{Peer: f.peer, Proto: "ftp",
				Path: verb + " " + clip(arg, 64), Status: "denied"})
			f.say("550 这个共享只发不收：不接受上传、改名、删除")
			return false
		}
		f.say("500 没这个命令：" + clip(verb, 32))
	}
	return false
}

func (f *ftpSession) cmdCwd(arg string) {
	p := f.argPath(arg)
	fi, _, why, err := f.s.resolve(p)
	if err != nil {
		if why == "outside" {
			f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
			f.say("550 这个路径不在共享目录里")
			return
		}
		f.say("550 没有这个目录")
		return
	}
	if !fi.IsDir() {
		f.say("550 那是个文件，不是目录")
		return
	}
	f.cwd = p
	f.say("250 进到 " + p)
}

// argPath 把参数落到共享内的绝对路径。
//
// ★ 相对路径按 cwd 拼再 Clean：拼出来永远是根内的形状（Clean("/a/../../b") = "/b"），
//
//	真正的越界检查在 resolve 那两道（逐段拒符号链接 + EvalSymlinks 复核落点）。
//	★ Windows 侧的客户端传反斜杠，也有客户端不带头顶的斜杠，先归一。
func (f *ftpSession) argPath(arg string) string {
	a := strings.TrimSpace(arg)
	a = strings.ReplaceAll(a, "\\", "/")
	if a == "" {
		return f.cwd
	}
	if !strings.HasPrefix(a, "/") {
		a = path.Join(strings.TrimSuffix(f.cwd, "/"), a)
	}
	return path.Clean(a)
}

// ── 数据口：被动 / 主动 ──

func (f *ftpSession) cmdPasv() {
	if strings.Contains(f.local, ":") && strings.Contains(f.local, "]") {
		// v6 控制连接：227 那个四字节的格式装不下 IPv6 地址。
		// ★ 不许「顺手开一个 v4 的口」糊过去 —— 设备是 v6 的就连不上，
		//   而失败停在客户端里，看不出为什么。
		f.say("500 这是 IPv6 连接，请改用 EPSV")
		return
	}
	if err := f.openPasv(); err != nil {
		f.say("425 开不了数据口：" + err.Error())
		return
	}
	f.say(fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d).",
		strings.ReplaceAll(f.pasvHost, ".", ","), f.pasvPort/256, f.pasvPort%256))
}

func (f *ftpSession) cmdEpsv(arg string) {
	if strings.TrimSpace(arg) != "" {
		f.say("522 只支持不带参数的 EPSV")
		return
	}
	if err := f.openPasv(); err != nil {
		f.say("425 开不了数据口：" + err.Error())
		return
	}
	f.say(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)", f.pasvPort))
}

// openPasv ★ 绑在控制连接**本机这一侧**的地址上：绑通配等于把数据口
// 从这台机器其余每一块网卡上也开出去，而这一步不会报任何错。
func (f *ftpSession) openPasv() error {
	f.dropData()
	host, _, err := net.SplitHostPort(f.local)
	if err != nil {
		return err
	}
	fam := "tcp4"
	if strings.Contains(host, ":") {
		fam = "tcp6"
	}
	ln, err := net.Listen(fam, net.JoinHostPort(host, "0"))
	if err != nil {
		return err
	}
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		_ = ln.Close()
		return errors.New("开出来的不是 TCP 口")
	}
	_, p, _ := net.SplitHostPort(tl.Addr().String())
	port, _ := strconv.Atoi(p)
	f.pasvLn, f.pasvHost, f.pasvPort = tl, host, port
	return nil
}

func (f *ftpSession) cmdPort(arg string, extended bool) {
	var (
		host  string
		port  int
		bad   string
		parts []string
	)
	if extended {
		// EPRT |1|192.168.1.5|4096|   （1=v4，2=v6）
		parts = strings.Split(strings.Trim(arg, "|"), "|")
		if len(parts) != 3 {
			f.say("501 EPRT 要这个形状：|1|地址|端口|")
			return
		}
		host, port, bad = parts[1], atoi(parts[2]), parts[0]
		if bad != "1" && bad != "2" {
			f.say("501 EPRT 的地址族只认 1（v4）和 2（v6）")
			return
		}
	} else {
		nums := strings.Split(arg, ",")
		if len(nums) != 6 {
			f.say("501 PORT 要六个数")
			return
		}
		host = strings.Join(nums[:4], ".")
		port = atoi(nums[4])*256 + atoi(nums[5])
	}
	if host == "" || port <= 0 || port > 65535 {
		f.say("501 这个地址端口看不懂")
		return
	}
	ip := net.ParseIP(host)
	if ip == nil {
		f.say("501 地址解不开")
		return
	}
	// ★★ 只允许连**控制连接的同一个 IP**。PORT 是本机主动出站去连对端给的地址端口，
	// 不校验就成了现成的内网探针：借这台机器挨个试内网哪个地址哪个端口能连。
	if !ip.Equal(f.peerIP()) {
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp",
			Path: fmt.Sprintf("PORT→%s:%d（不是连进来的那个地址）", host, port), Status: "denied"})
		f.say("550 不接受连别的地址：主动模式只允许连你自己")
		return
	}
	f.dropData()
	f.portTo = &net.TCPAddr{IP: ip, Port: port}
	f.say("200 好")
}

func (f *ftpSession) peerIP() net.IP { return net.ParseIP(f.peer) }

// openData 按当前设好的模式拿到数据连接。调用方负责 Close。
func (f *ftpSession) openData() (net.Conn, error) {
	if f.pasvLn != nil {
		ln := f.pasvLn
		f.pasvLn = nil // 一次一发：这一笔用完就关，下一笔重新开
		// 等不到对端来连就把这一笔断掉：不设这个期限，设备掉线时这条会话永远挂着。
		_ = ln.SetDeadline(time.Now().Add(ftpAcceptSlack))
		c, err := ln.Accept()
		_ = ln.Close()
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	if f.portTo != nil {
		target := f.portTo
		f.portTo = nil
		d := &net.Dialer{Timeout: ftpAcceptSlack}
		c, err := d.Dial("tcp", target.String())
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, errors.New("没设数据口（要先 PASV 或 PORT）")
}

func (f *ftpSession) dropData() {
	if f.pasvLn != nil {
		_ = f.pasvLn.Close()
		f.pasvLn = nil
	}
	f.portTo = nil
}

// ── 取东西：列目录 / 取文件 ──

func (f *ftpSession) cmdList(p string, extended bool) {
	fi, full, why, err := f.s.resolve(p)
	if err != nil {
		if why == "outside" {
			f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
			f.say("550 这个路径不在共享目录里")
			return
		}
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "not-found"})
		f.say("550 没有这个东西")
		return
	}
	if fi.IsDir() && !f.s.cfg.Listing {
		// ★ 关列表时给 550 而不是「空目录」：让人知道目录在、只是不给翻，
		//   否则会以为是路径写错，在那儿反复改斜杠。
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
		f.say("550 这个共享关掉了目录列表：请直接填完整文件名")
		return
	}

	var body strings.Builder
	if !fi.IsDir() { // 对文件用 LIST：按 FTP 的老规矩发**这一条**的条目
		fmt.Fprint(&body, ftpEntry(fi, baseOf(p), extended))
	} else {
		entries, rerr := os.ReadDir(full)
		if rerr != nil {
			f.say("550 这个目录读不出来")
			return
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, de := range entries {
			info, ierr := de.Info()
			if ierr != nil {
				continue
			}
			name := de.Name()
			if extended {
				name = ftpName(path.Join(p, name))
			} else {
				name = ftpName(name)
			}
			fmt.Fprint(&body, ftpEntry(info, name, extended))
		}
	}

	f.say("150 开数据口，这就发目录")
	c, err := f.openData()
	if err != nil {
		f.say("425 数据口没连上：" + err.Error())
		return
	}
	dc := newDeadlineConn(c)
	b := []byte(body.String())
	_, werr := dc.Write(b)
	_ = dc.Close()
	f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Bytes: int64(len(b)), Status: "list"})
	if werr != nil {
		f.say("426 目录发到一半断了")
		return
	}
	f.say("226 目录发完")
}

// cmdRetr 取一份文件。★ 一次整份：没有 REST，续传在设备侧多半也没实现，
// 而「传一半」的现场真相全部落在台账那一笔 partial 上。
func (f *ftpSession) cmdRetr(p string) {
	fi, full, why, err := f.s.resolve(p)
	if err != nil {
		if why == "outside" {
			f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
			f.say("550 这个路径不在共享目录里")
			return
		}
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "not-found"})
		f.say("550 没有这个文件")
		return
	}
	if fi.IsDir() {
		f.say("550 那是个目录：要翻内容用 LIST，要取文件填完整文件名")
		return
	}
	file, oerr := os.Open(full)
	if oerr != nil {
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
		f.say("550 这个文件读不出来")
		return
	}
	defer file.Close()

	f.say(fmt.Sprintf("150 正在传 %s（%d 字节）", baseOf(p), fi.Size()))
	c, derr := f.openData()
	if derr != nil {
		f.say("425 数据口没连上：" + derr.Error())
		return
	}
	dc := newDeadlineConn(c)
	n, cerr := io.Copy(dc, file)
	_ = dc.Close()

	// ★ partial 和 ok 分开：「设备来取了、取到第 N 字节停的」就是现场要的那一笔，
	//   它既不是「没来取」也不是「文件名写错」，该查的方向完全不同。
	if cerr != nil {
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Bytes: n, Status: "partial"})
		f.say("426 传到一半断了：" + cerr.Error())
		return
	}
	status := "ok"
	if f.ascii { // 按原样字节发的，但要知道它是按 netascii 来要的（和 TFTP 那一侧同一件事）
		status = "octet-served"
	}
	f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Bytes: n, Status: status})
	f.say("226 传完")
}

func (f *ftpSession) cmdSize(p string) {
	fi, _, why, err := f.s.resolve(p)
	if err != nil || fi.IsDir() {
		if why == "outside" {
			f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
			f.say("550 这个路径不在共享目录里")
			return
		}
		f.say("550 没有这个文件")
		return
	}
	// ★ SIZE 记成一笔 head：设备升级前常常先问大小不取内容，
	//   「来过但没取」和「压根没来」在现场是两个不同的下一步。
	f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "head"})
	f.say("213 " + strconv.FormatInt(fi.Size(), 10))
}

func (f *ftpSession) cmdMdtm(p string) {
	fi, _, _, err := f.s.resolve(p)
	if err != nil || fi.IsDir() {
		f.say("550 没有这个文件")
		return
	}
	f.say("213 " + fi.ModTime().UTC().Format("20060102150405"))
}

// cmdMlst 一条条目，走**控制连接**回（[RFC 3659]）。
//
//	★ 和 MLSD 分开不是凑数：设备的升级页面常常只问「这个文件名在不在、多大」，
//	为这一问再开一个数据口，慢的链路上就是多一次握手。
func (f *ftpSession) cmdMlst(p string) {
	fi, _, _, err := f.s.resolve(p)
	if err != nil || fi.IsDir() {
		f.say("550 没有这个文件")
		return
	}
	typ := "File"
	if fi.IsDir() {
		typ = "dir"
	}
	f.multi("250-Listing "+p,
		fmt.Sprintf(" Type=%s;Size=%d;Modify=%s; %s",
			typ, fi.Size(), fi.ModTime().UTC().Format("20060102150405"), baseOf(p)),
		"250 End")
}

// cmdNames 只发文件名：一批设备的固件页面只会「按名字取」，
// 完整列表对它是噪音，但没列表又没法确认文件在不在。
func (f *ftpSession) cmdNames(p string) {
	fi, full, why, err := f.s.resolve(p)
	if err != nil {
		f.deniedOrMissing(why, p)
		return
	}
	if !fi.IsDir() {
		f.say("550 那是个文件，不是目录")
		return
	}
	if !f.s.cfg.Listing {
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
		f.say("550 这个共享关掉了目录列表：请直接填完整文件名")
		return
	}
	var body strings.Builder
	if names, rerr := os.ReadDir(full); rerr == nil {
		sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
		for _, de := range names {
			fmt.Fprintf(&body, "%s\r\n", de.Name())
		}
	}
	f.say("150 开数据口，这就发文件名")
	c, derr := f.openData()
	if derr != nil {
		f.say("425 数据口没连上：" + derr.Error())
		return
	}
	dc := newDeadlineConn(c)
	b := []byte(body.String())
	_, werr := dc.Write(b)
	_ = dc.Close()
	f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Bytes: int64(len(b)), Status: "list"})
	if werr != nil {
		f.say("426 名单发到一半断了")
		return
	}
	f.say("226 名单发完")
}

// deniedOrMissing 把「为什么够不着」落成两种账。
//
// ★★ 越出目录和「文件名写错」必须是两个数：前者是有人在拿这个口试，
//
//	后者是现场常态；混成一个「失败 N 次」，要么真出事的那几次被埋掉，
//	要么一个干净的共享一直显示像被攻击过。
func (f *ftpSession) deniedOrMissing(why, p string) {
	if why == "outside" {
		f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "denied"})
		f.say("550 这个路径不在共享目录里")
		return
	}
	f.s.Record(Transfer{Peer: f.peer, Proto: "ftp", Path: p, Status: "not-found"})
	f.say("550 没有这个东西")
}

// ── 目录条目 ──

// ftpEntry 一行列表。extended 时给 MLSD 那种 name=...;size=...;modify=... 的形状，
// 否则给最老的 Unix LIST 形状（现场那批设备只认后者）。
func ftpEntry(fi os.FileInfo, name string, extended bool) string {
	if extended {
		typ := "file"
		if fi.IsDir() {
			typ = "dir"
		}
		return fmt.Sprintf("%s;type=%s;size=%d;modify=%s; \r\n",
			strings.TrimSuffix(name, "/"), typ, fi.Size(),
			fi.ModTime().UTC().Format("20060102150405"))
	}
	mode := "-rw-r--r--"
	if fi.IsDir() {
		mode = "drwxr-xr-x"
	}
	return fmt.Sprintf("%s   1 ftp      ftp    %8d %s %s\r\n",
		mode, fi.Size(), ftpStamp(fi.ModTime()), name)
}

// ftpStamp 老 LIST 的日期口径：半年内的给「月 日 时:分」，更久的给年份。
// ★ 给错的话一部分客户端把整行解析失败，整个目录看起来是空的。
func ftpStamp(t time.Time) string {
	if time.Since(t) > 180*24*time.Hour || t.After(time.Now()) {
		return t.Format("Jan  2 2006")
	}
	return t.Format("Jan _2 15:04")
}

func ftpName(p string) string {
	if !strings.HasPrefix(p, "/") {
		return path.Base(p)
	}
	return p
}

func baseOf(p string) string {
	b := path.Base(strings.TrimSuffix(p, "/"))
	if b == "." || b == "/" {
		return "/"
	}
	return b
}

// ── 收发的小工具 ──

func (f *ftpSession) say(line string) {
	_, _ = f.c.Write([]byte(strings.TrimRight(line, "\r\n") + "\r\n"))
}

func (f *ftpSession) multi(lines ...string) {
	for _, l := range lines {
		f.say(l)
	}
}

// deadlineConn 每一次读写都各自续一次期限。
//
// ★ 不能用「整发一个总超时」：一份 40MB 的固件正常也要几十秒，
//
//	那样会把成功的传输判成失败；只有真的停住了才断。
type deadlineConn struct {
	net.Conn
}

func newDeadlineConn(c net.Conn) *deadlineConn { return &deadlineConn{Conn: c} }

func (d *deadlineConn) Write(b []byte) (int, error) {
	_ = d.Conn.SetWriteDeadline(time.Now().Add(ftpDataSlack))
	return d.Conn.Write(b)
}

func (d *deadlineConn) Read(b []byte) (int, error) {
	_ = d.Conn.SetReadDeadline(time.Now().Add(ftpDataSlack))
	return d.Conn.Read(b)
}

func hostOnly(addr net.Addr) string {
	s, ok := addr.(*net.TCPAddr)
	if !ok {
		h, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return ""
		}
		return h
	}
	return s.IP.String()
}

func splitCmd(line string) (string, string) {
	if i := strings.IndexAny(line, " "); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── 在线笔数 ──

func (s *Server) ftpAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ftpSess >= ftpMaxSessions {
		return false
	}
	s.ftpSess++
	return true
}

func (s *Server) ftpRelease() {
	s.mu.Lock()
	s.ftpSess--
	s.mu.Unlock()
}

// ftpOn / ftpOff 登记在册的会话。★ 停共享时必须当场掐掉：
// FTP 是长连接，只关监听口的话，已经挂着的会话（连同正在传的那一发）会留在原地，
// 而界面上已经写着「端口都放掉了」—— 那就成了「看着停了、其实还开着」。
func (s *Server) ftpOn(c net.Conn) {
	s.mu.Lock()
	if s.ftpLive == nil {
		s.ftpLive = map[net.Conn]struct{}{}
	}
	s.ftpLive[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) ftpOff(c net.Conn) {
	s.mu.Lock()
	delete(s.ftpLive, c)
	s.mu.Unlock()
}
