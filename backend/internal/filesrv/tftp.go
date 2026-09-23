package filesrv

// ── TFTP 这一侧：只处理 RRQ ──
//
// 为什么还要做 TFTP：设备的固件页面里，**老设备只认 tftp**。它连不上 http，
// 你把地址填进去它就报「下载失败」，而现场没人会怀疑是协议。
//
// ★ 这个文件里**没有写路径**：WRQ 一律回 ERROR(2) 并记一笔被拒。
//   TFTP 的 WRQ 比 HTTP 的 PUT 更危险 —— 连文件名都是对端给的。
//   「不收文件的 TFTP」在别的实现里经常只是「没人去点那个开关」，这里是没得点。
//
// ★ 几处必须照规范来的地方，做错的表现都是「有的设备上能用、有的永远卡住」：
//
//   1. **每笔传输换一个源端口**（[RFC 1350] 的 TID）。不换的话客户端只在自己
//      那个随机端口上等回话，我们从监听口发出去的东西它不认 ——
//      netcat 上手测永远正常，接上真实设备就卡在第一包，最难查的一类。
//   2. **每一发都要能重传**。固件几十 MB、交换机管理口那点 UDP 缓冲，
//      丢一个 ACK 是常态不是异常；不重传的表现是「传到一半停了」，
//      而现场只会以为是网不好。
//   3. **块号 65535 之后回绕到 0**。这条只在文件和 blksize 足够大时才碰到
//      （512 字节要 32MB 才绕一次，blksize=1456 时 90MB 绕）——
//      也就是说它**从来不在随手写的测试样本里**，所以单独钉一条测试。
//   4. **OACK 里只回自己认得的选项**。把对端提的选项原样抄回去，
//      等于答应了我们没实现的事。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	tftpRRQ   = uint16(1)
	tftpWRQ   = uint16(2)
	tftpDATA  = uint16(3)
	tftpACK   = uint16(4)
	tftpERROR = uint16(5)
	tftpOACK  = uint16(6)

	tftpDefault = 512
	tftpMax     = 64508 // [RFC 2348] 上限；再大单个 UDP 包就得 IP 分片，现场等于自杀

	// tftpMaxActive 同时在传的上限。这是一个**不鉴权**的服务，同网段谁都能开一笔：
	// 不设上限的话谁在脚本里循环一下，这台机器的 goroutine 和 socket 就上去了。
	tftpMaxActive = 32

	// tftpTries 是一发等 ACK 的总尝试次数（含第一次）。间隔 1 秒起指数退避：
	// 太密会打在交换机那点 UDP 缓冲上，太慢会撞设备的下载超时（多数 30 秒）。
	tftpTries = 5
)

// [RFC 1350] 的错误码，只用到这几个。
const (
	errNotDefined   = uint16(0)
	errFileNotFound = uint16(1)
	errAccessViolat = uint16(2)
	errIllegalOp    = uint16(4)
)

// tftpListener 一个地址一个 UDP 监听口 —— 和 HTTP 那边「一个地址一个监听器」同构。
type tftpListener struct {
	pc   *net.UDPConn
	done chan struct{}
}

// serveTFTP 读请求并分发。每笔实际传输另外开一个临时 socket（TID）去发。
func (s *Server) serveTFTP(ln *tftpListener) {
	buf := make([]byte, tftpMax+4)
	for {
		// 带截止时间地读，是为了 Stop() 之后这条 goroutine 一定退出，
		// 而不是挂在一次永远不来的读上。
		if err := ln.pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return
		}
		n, peer, err := ln.pc.ReadFromUDP(buf)
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
			return // socket 已被 Stop() 关掉
		}
		if n < 4 {
			continue
		}
		p := append([]byte(nil), buf[:n]...) // 交给 goroutine 前先拷：下一轮读会覆盖 buf
		peerStr := peer.IP.String()
		switch binary.BigEndian.Uint16(p) {
		case tftpRRQ:
			if !s.tftpAcquire() {
				s.tftpError(ln.pc, peer, errIllegalOp, "这个共享同时在传的笔数已到上限")
				s.Record(Transfer{Peer: peerStr, Proto: "tftp", Status: "busy"})
				continue
			}
			go s.tftpTransfer(ln, peer, p)
		case tftpWRQ:
			name, _, _ := nextCStr(p[2:])
			// ★ 单独记「被拒」而不是「没找到」：有人在拿这个口试上传，
			//   这件事必须单独看得见，混进失败里就没人会去看。
			s.Record(Transfer{Peer: peerStr, Proto: "tftp", Path: name, Status: "denied"})
			s.tftpError(ln.pc, peer, errAccessViolat, "这个共享只发不收：不接受上传")
		default:
			s.tftpError(ln.pc, peer, errIllegalOp, "只支持读（RRQ）")
		}
	}
}

// tftpTransfer 一笔下载：换 TID、按需 OACK、然后一块一块发。
func (s *Server) tftpTransfer(ln *tftpListener, peer *net.UDPAddr, pkt []byte) {
	defer s.tftpRelease()

	req, err := parseTFRQ(pkt)
	if err != nil {
		s.tftpError(ln.pc, peer, errIllegalOp, err.Error())
		s.Record(Transfer{Peer: peer.IP.String(), Proto: "tftp", Status: "denied"})
		return
	}
	peerStr := peer.IP.String()
	rec := func(status string, n int64) {
		s.Record(Transfer{Peer: peerStr, Proto: "tftp", Path: req.filename, Bytes: n, Status: status})
	}

	fi, full, why, err := s.resolve(tftpPath(req.filename))
	if err != nil {
		code, status := errFileNotFound, "not-found"
		if why == "outside" {
			// ★ 越出目录和「文件名写错」分开：后者是现场常态，
			//   混在一起的话一个干净的共享会一直显示有人被拒。
			code, status = errAccessViolat, "denied"
		}
		rec(status, 0)
		s.tftpError(ln.pc, peer, code, tftpReason(why))
		return
	}
	if fi.IsDir() {
		// TFTP 没有「列目录」这回事，所以这一句要给得有用。
		rec("not-found", 0)
		s.tftpError(ln.pc, peer, errFileNotFound, "TFTP 取不了目录：请直接填完整文件名")
		return
	}

	f, err := os.Open(full)
	if err != nil {
		rec("denied", 0)
		s.tftpError(ln.pc, peer, errAccessViolat, "这个文件读不出来")
		return
	}
	defer f.Close()

	// ★ 换源端口：从监听口回数据是最常见的 TFTP 实现错误。
	tid, err := tftpDial(ln.pc.LocalAddr().Network(), ln.pc.LocalAddr().String())
	if err != nil {
		rec("denied", 0)
		s.tftpError(ln.pc, peer, errNotDefined, "开不了这一笔的传输端口："+err.Error())
		return
	}
	defer tid.Close()

	blk := req.blksize
	sent := int64(0)
	status := "ok"

	// 对端提了选项才回 OACK，并且要等它的 ACK(0) 才发第一块。
	if len(req.order) > 0 {
		if !tftpSend(tid, peer, tftpOack(req, fi.Size()), 0, tftpTries) {
			// 协商这一步就没回话：多半是那台设备**不支持 OACK** 却又提了选项。
			// 单独记 aborted，不和「传到一半断了」混一起 —— 该做的下一步不一样。
			rec("aborted", 0)
			return
		}
	}
	if req.mode == "netascii" {
		// ★ 按原样字节发，不做行尾转换：现场用 TFTP 取的全是固件，
		//   真去转 CRLF 就是把设备刷坏。这一笔单独记一个状态，
		//   让人看得见「它是按 netascii 来要的」，而不是我们悄悄替它决定。
		status = "octet-served"
	}

	buf := make([]byte, blk)
	block := uint16(1) // 0 那一发是 OACK，它的 ACK 上面收过了
	for {
		n, rerr := io.ReadFull(f, buf)
		last := rerr == io.ErrUnexpectedEOF || rerr == io.EOF
		if rerr != nil && !last {
			rec("partial", sent)
			s.tftpError(tid, peer, errNotDefined, "读这个文件时出错了")
			return
		}
		data := make([]byte, 4+n)
		binary.BigEndian.PutUint16(data, tftpDATA)
		binary.BigEndian.PutUint16(data[2:], block)
		copy(data[4:], buf[:n])
		if !tftpSend(tid, peer, data, block, tftpTries) {
			// 对端不再回话：它掉了、还是中途被取消。**现场要的就是这一笔** ——
			// 「它来取了，取到第 N 字节停的」。
			rec("partial", sent)
			return
		}
		sent += int64(n)
		block++ // 65535 之后自然回绕成 0，这里不许自己加判断
		if last || n < blk {
			break // 不足一块的那一发就是最后一发（[RFC 1350]）
		}
	}
	rec(status, sent)
}

// tftpDial 开一个和监听口**不同源端口**的 socket，地址族和绑的地址都跟着监听口。
//
// ★ 必须显式跟族：双栈机器上默认那个口发 v6 单播会失败，
//
//	症状是「IPv6 的设备取不到」而 v4 一切正常。
//	绑监听口那个地址：从别的网卡回话，设备按源地址过滤就把包丢了。
func tftpDial(network, listenAddr string) (*net.UDPConn, error) {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, err
	}
	var bind net.IP
	if host != "" && host != "::" && host != "0.0.0.0" {
		if bind = net.ParseIP(strings.Trim(host, "[]")); bind == nil {
			return nil, fmt.Errorf("监听口上的地址看不懂：%s", host)
		}
	}
	return net.ListenUDP(network, &net.UDPAddr{IP: bind})
}

// tftpSend 发一发并等它对号的 ACK，等不到就整发重发。
//
// ★ 重传必须**连数据一起重发**：只重等不发，丢的正好是那一发数据时永远等不到。
func tftpSend(pc *net.UDPConn, peer *net.UDPAddr, pkt []byte, want uint16, tries int) bool {
	buf := make([]byte, 512)
	for attempt := 0; attempt < tries; attempt++ {
		if err := writeTidy(pc, peer, pkt); err != nil {
			return false
		}
		deadline := time.Now().Add(time.Duration(1<<attempt) * time.Second)
		for {
			_ = pc.SetReadDeadline(deadline)
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil || !time.Now().Before(deadline) {
				break // 这一轮到点了：出去重发
			}
			if !sameHost(from, peer) || n < 4 {
				continue // 别人的一笔、对端乱发的东西：不算失败，接着等
			}
			// 号对不上多半是对端重发的旧 ACK —— 接着等，不重发（重发会把它卡得更死）。
			if binary.BigEndian.Uint16(buf) == tftpACK && binary.BigEndian.Uint16(buf[2:]) == want {
				return true
			}
		}
	}
	return false
}

// ── 包的编解码 ──

type tftpRequest struct {
	filename string
	mode     string
	blksize  int
	timeout  int
	order    []string // 对端提选项的顺序：OACK 按同样的顺序回
}

// parseTFRQ 解 RRQ。★ 这里每一个长度都来自对端，所以每一步都看边界。
func parseTFRQ(pkt []byte) (tftpRequest, error) {
	r := tftpRequest{blksize: tftpDefault, timeout: 1, mode: "octet"}
	if len(pkt) < 4 {
		return r, errors.New("包太短")
	}
	name, rest, ok := nextCStr(pkt[2:])
	if !ok {
		return r, errors.New("缺文件名")
	}
	mode, rest, ok := nextCStr(rest)
	if !ok {
		return r, errors.New("缺传输模式")
	}
	r.filename = name
	r.mode = strings.ToLower(mode)
	if r.mode != "octet" && r.mode != "netascii" {
		return r, errors.New("只支持 octet 和 netascii")
	}
	// 选项成对出现。尾巴上不足一对的就丢掉、不报错：
	// 现场有一批实现会在 RRQ 末尾多带一个 0，为这个拒掉设备没有意义。
	for {
		k, next, okk := nextCStr(rest)
		if !okk || k == "" {
			break
		}
		v, after, okv := nextCStr(next)
		if !okv {
			break
		}
		rest = after
		switch strings.ToLower(k) {
		case "blksize":
			n, err := strconv.Atoi(v)
			if err != nil || n < 16 || n > tftpMax {
				return r, fmt.Errorf("blksize %q 不在 16 到 %d 之间", v, tftpMax)
			}
			r.blksize = n
			r.order = append(r.order, "blksize")
		case "tsize":
			r.order = append(r.order, "tsize")
		case "timeout":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 5 {
				// 超范围按我们默认的来，而且**不回这一项**：
				// 回了就是答应「我按你说的秒数重传」，而我们没有。
				break
			}
			r.timeout = n
			r.order = append(r.order, "timeout")
		}
		// 其它选项不回：原样抄回去等于答应了我们没实现的东西。
	}
	return r, nil
}

// nextCStr 取一个以 0 结尾的字段，并返回剩下的字节。
func nextCStr(b []byte) (string, []byte, bool) {
	for i, x := range b {
		if x == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", b, false // 没有结尾那个 0：这个包是残缺的
}

// tftpOack 组 OACK：只回认得的选项，顺序跟对端提的一致。
func tftpOack(r tftpRequest, size int64) []byte {
	out := []byte{byte(tftpOACK >> 8), byte(tftpOACK)}
	add := func(k, v string) {
		out = append(out, []byte(k)...)
		out = append(out, 0)
		out = append(out, []byte(v)...)
		out = append(out, 0)
	}
	for _, k := range r.order {
		switch k {
		case "blksize":
			add("blksize", strconv.Itoa(r.blksize))
		case "timeout":
			add("timeout", strconv.Itoa(r.timeout))
		case "tsize":
			// ★ 报**真实大小**：设备的升级页面靠这个数判断取完没有，
			//   报 0 会让它「传完了还以为没传完」，然后反复重下。
			add("tsize", strconv.FormatInt(size, 10))
		}
	}
	return append(out, 0) // 选项表以空字段结尾
}

func (s *Server) tftpError(pc *net.UDPConn, peer *net.UDPAddr, code uint16, msg string) {
	b := make([]byte, 4, 4+len(msg)+1)
	binary.BigEndian.PutUint16(b, tftpERROR)
	binary.BigEndian.PutUint16(b[2:], code)
	b = append(b, msg...)
	b = append(b, 0)
	_ = writeTidy(pc, peer, b)
}

func writeTidy(pc *net.UDPConn, peer *net.UDPAddr, b []byte) error {
	_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := pc.WriteToUDP(b, peer)
	return err
}

func sameHost(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP)
}

// tftpPath 把 TFTP 的文件名落到 HTTP 那套解析里（含符号链接那两道检查）。
//
// ★ Windows 那侧的设备会传反斜杠，也有设备不带头顶的斜杠 ——
//
//	不先归一的话它们全都「没有这个文件」，而人只会以为是共享没开对。
func tftpPath(name string) string {
	n := strings.ReplaceAll(name, "\\", "/")
	if !strings.HasPrefix(n, "/") {
		n = "/" + n
	}
	return n
}

func tftpReason(why string) string {
	switch why {
	case "outside":
		return "这个路径不在共享目录里"
	case "missing":
		return "File not found"
	}
	return "读不到"
}

// ── 在传的笔数 ──

func (s *Server) tftpAcquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= tftpMaxActive {
		return false
	}
	s.active++
	return true
}

func (s *Server) tftpRelease() {
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
}
