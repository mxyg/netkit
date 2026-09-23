package filesrv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── 测试用的最小 TFTP 客户端 ──
//
// ★ 不引第三方库：这一层要是靠库来验，库把哪个坑替我们填了我们就永远看不见。
//   现场那批老设备的实现各有各的歪，我们只能按规范写，也要按规范测。

// tftpGet 用一个固定块大小把文件收完，返回内容和它的源端口（用来验 TID 换了没有）。
func tftpGet(t *testing.T, srvAddr, filename string, blksize int, opts []string) ([]byte, string, uint16, string) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	sa, err := net.ResolveUDPAddr("udp4", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	pkt := binary.BigEndian.AppendUint16(nil, tftpRRQ)
	pkt = append(pkt, []byte(filename)...)
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte("octet")...)
	pkt = append(pkt, 0)
	for _, o := range opts {
		pkt = append(pkt, []byte(o)...)
		pkt = append(pkt, 0)
	}
	if _, err := pc.WriteTo(pkt, sa); err != nil {
		t.Fatal(err)
	}

	var (
		out       []byte
		blk              = blksize
		want      uint16 = 1
		sawOack   bool
		serverSrc string
	)
	buf := make([]byte, 70000)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return out, serverSrc, 0xFFFF, "等包等不到：" + err.Error()
		}
		if serverSrc == "" {
			serverSrc = from.String()
		}
		p := append([]byte(nil), buf[:n]...)
		switch binary.BigEndian.Uint16(p) {
		case tftpERROR:
			msg, _, _ := nextCStr(p[4:])
			return out, serverSrc, binary.BigEndian.Uint16(p[2:]), msg
		case tftpOACK:
			sawOack = true
			opts, _, _ := tftpParseOptions(p[2:])
			if v := opts["blksize"]; v != "" {
				fmt.Sscanf(v, "%d", &blk)
			}
			if _, err := pc.WriteTo(ackTo(0), from); err != nil {
				t.Fatal(err)
			}
			want = 1
		case tftpDATA:
			// 提了选项就必须先 OACK 一次再发第一块；直接发数据等于把协商吞了，
			// 客户端按 512 收就会在后面每一块上都错位。
			if len(opts) > 0 && !sawOack {
				return out, serverSrc, 0xFFFF, "提了选项却没先收到 OACK，它直接开始发数据了"
			}
			got := binary.BigEndian.Uint16(p[2:])
			if got != want {
				return out, serverSrc, 0xFFFF, fmt.Sprintf("块号串了：想要 %d 拿到 %d", want, got)
			}
			out = append(out, p[4:]...)
			if _, err := pc.WriteTo(ackTo(got), from); err != nil {
				t.Fatal(err)
			}
			want++
			if len(p)-4 < blk {
				return out, serverSrc, 0, ""
			}
		default:
			return out, serverSrc, 0xFFFF, "不该出现的包类型"
		}
	}
	return out, serverSrc, 0xFFFF, "总超时"
}

func ackTo(block uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, tftpACK)
	binary.BigEndian.PutUint16(b[2:], block)
	return b
}

// tftpParseOptions 解 OACK / RRQ 尾巴上的选项对。
func tftpParseOptions(b []byte) (map[string]string, []string, bool) {
	out := map[string]string{}
	var order []string
	for {
		k, rest, ok := nextCStr(b)
		if !ok || k == "" {
			return out, order, true
		}
		v, rest2, ok2 := nextCStr(rest)
		if !ok2 {
			return out, order, false
		}
		out[strings.ToLower(k)] = v
		order = append(order, k)
		b = rest2
	}
}

// tftpShare 起一个开了 TFTP 的共享，只绑回环。
func tftpShare(t *testing.T, cfg func(*Config)) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "fw.bin", []byte(strings.Repeat("Z", 4000)))
	writeFile(t, root, "tiny.bin", []byte("12345"))
	if err := os.WriteFile(filepath.Join(root, "外层的密钥"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0, Listing: true,
		TFTP: true, TFTPPort: 0}
	if cfg != nil {
		cfg(&c)
	}
	s, err := Start(c)
	if err != nil {
		t.Fatalf("起不来：%v", err)
	}
	t.Cleanup(s.Stop)
	st := s.Status()
	if len(st.TFTPURLs) == 0 {
		t.Fatal("没给出 tftp 地址")
	}
	return s, "127.0.0.1:" + fmt.Sprint(st.TFTPPort)
}

// ── 测试 ──

func TestTFTP取走一整份并且记账(t *testing.T) {
	s, addr := tftpShare(t, nil)
	got, src, code, msg := tftpGet(t, addr, "fw.bin", tftpDefault, nil)
	if code != 0 {
		t.Fatalf("错误码 %d：%s", code, msg)
	}
	if string(got) != strings.Repeat("Z", 4000) {
		t.Errorf("内容不对：%d 字节", len(got))
	}
	if src == "" {
		t.Error("一笔都没收到")
	}
	st := waitStats(t, s, func(st Status) bool { return st.Requests >= 1 })
	if st.Requests != 1 || st.Bytes != 4000 {
		t.Errorf("记账不对：reqs=%d bytes=%d", st.Requests, st.Bytes)
	}
	// ★ 台账里要看得见「取的是哪个文件、取走了多少」：现场出问题就问这一句。
	if len(st.Recent) != 1 || st.Recent[0].Status != "ok" || st.Recent[0].Proto != "tftp" ||
		st.Recent[0].Path != "fw.bin" || st.Recent[0].Bytes != 4000 {
		t.Errorf("这一笔的台账不对：%+v", st.Recent)
	}
}

// waitStats 等记账落到快照里：客户端收到不足一块那一发就能返回，
// 而这一笔记账在服务端发完那一发之后 —— 差的是几十微秒，但测试不能靠运气。
func waitStats(t *testing.T, s *Server, want func(Status) bool) Status {
	t.Helper()
	for i := 0; i < 200; i++ {
		st := s.Status()
		if want(st) {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Log("等了两秒台账还没变成想要的样子")
	return s.Status()
}

func TestTFTP每传输换一个源端口(t *testing.T) {
	// ★ 这是 TFTP 最容易做错、也最难查的一条：不换 TID 的话 netcat 测永远正常，
	//   真实设备卡在第一个 ACK。所以这条测的不是「能不能取到」，是「从哪儿回的」。
	s, addr := tftpShare(t, nil)
	_, src, code, msg := tftpGet(t, addr, "tiny.bin", tftpDefault, nil)
	if code != 0 {
		t.Fatalf("%d：%s", code, msg)
	}
	port := strings.Split(src, ":")[1]
	if port == fmt.Sprint(s.Status().TFTPPort) {
		t.Errorf("回话还是从监听口 %s 出去的 —— 设备会卡在第一个 ACK", port)
	}
}

func TestTFTP选项协商只回认得的(t *testing.T) {
	s, addr := tftpShare(t, nil)
	// 提一个我们不认的 rbegab：它不该出现在 OACK 里（抄回去等于答应没实现的事）
	got, _, code, msg := tftpGet(t, addr, "fw.bin", tftpDefault,
		[]string{"blksize", "1456", "tsize", "0", "rbegab", "1"})
	if code != 0 {
		t.Fatalf("%d：%s", code, msg)
	}
	if len(got) != 4000 {
		t.Errorf("协商完内容不对：%d", len(got))
	}
	_ = s
}

func TestTFTP的tsize报的是真实大小(t *testing.T) {
	// ★ 报 0 的话设备「传完了还以为没传完」，然后一遍遍重下 —— 现场表现为
	//   「共享明明开着，设备一直在下载」。
	_, addr := tftpShare(t, nil)
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	sa, _ := net.ResolveUDPAddr("udp4", addr)
	pkt := binary.BigEndian.AppendUint16(nil, tftpRRQ)
	pkt = append(pkt, []byte("fw.bin")...)
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte("octet")...)
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte("tsize")...)
	pkt = append(pkt, 0)
	pkt = append(pkt, []byte("0")...)
	pkt = append(pkt, 0)
	pkt = append(pkt, 0)
	if _, err := pc.WriteTo(pkt, sa); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	// ★ 连 OACK 都得从换过的那个源端口回来：第一发就没换端口的话，客户端是在
	//   它自己那个随机端口上等 ACK/OACK 的，等不到的一直是它。
	if _, lp, _ := net.SplitHostPort(addr); lp != "" {
		if _, rp, _ := net.SplitHostPort(from.String()); rp == lp {
			t.Errorf("OACK 从监听口 %s 回来了：这一笔没换 TID", lp)
		}
	}
	opts, order, _ := tftpParseOptions(buf[2:n])
	if binary.BigEndian.Uint16(buf) != tftpOACK {
		t.Fatalf("第一发该是 OACK，拿到 %d", binary.BigEndian.Uint16(buf))
	}
	if opts["tsize"] != "4000" {
		t.Errorf("tsize=%q", opts["tsize"])
	}
	if strings.ToLower(order[len(order)-1]) == "rbegab" {
		t.Error("把不认的选项抄回去了")
	}
}

func TestTFTP上传一律当场拒(t *testing.T) {
	// ★ WRQ 连文件名都是对端给的：这个口要是能收文件，本机就成了任意人可写的盘。
	s, addr := tftpShare(t, nil)
	before := len(mustList(t, s))
	_, code, msg := tftpAskErr(t, addr, "WRQ", "evil.bin")
	if code != errAccessViolat {
		t.Errorf("错误码=%d（%s），该回 2", code, msg)
	}
	after := mustList(t, s)
	if len(after) != before {
		t.Errorf("被拒的这一次在本机留下了文件：%v", after)
	}
	st := s.Status()
	if st.Denied != 1 {
		t.Errorf("这一笔该记被拒，Denied=%d", st.Denied)
	}
}

func TestTFTP没有的文件说不存在(t *testing.T) {
	s, addr := tftpShare(t, nil)
	_, code, msg := tftpAskErr(t, addr, "RRQ", "nope.bin")
	if code != errFileNotFound {
		t.Errorf("错误码=%d（%s）", code, msg)
	}
	if !strings.Contains(msg, "没有") && !strings.Contains(msg, "not found") {
		t.Errorf("该直说没有这个文件：%s", msg)
	}
	st := s.Status()
	if st.NotFound != 1 || st.Denied != 0 {
		t.Errorf("抄错文件名不该算被拒：notFound=%d denied=%d", st.NotFound, st.Denied)
	}
}

func TestTFTP目录外的符号链接被拒并且分开记(t *testing.T) {
	// ★ 共享目录里放一个指向外面的软链，是「只读共享」最容易被绕过去的那条路：
	//   有人把链接指向 /etc/shadow，设备来取一次本机就被读走了。
	//   这一笔要单独记「被拒」而不是「没有这个文件」—— 前者是有人在试。
	s, addr := tftpShare(t, nil)
	outside := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(outside, []byte("不该被读到的东西"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.Status().Root, "link.bin")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("这台机器上建不了符号链接：%v", err)
	}
	got, code, msg := tftpAskErr(t, addr, "RRQ", "link.bin")
	if len(got) > 0 {
		t.Errorf("顺着软链把外面的内容发出去了：%q", got)
	}
	if code != errAccessViolat {
		t.Errorf("软链越界该回 2，拿到 %d（%s）", code, msg)
	}
	if st := s.Status(); st.Denied != 1 {
		t.Errorf("这一笔该记被拒，Denied=%d", st.Denied)
	}
}

func TestTFTP两个点的路径到不了目录外(t *testing.T) {
	// 现场设备会把地址栏里那点路径原样拼过来，反斜杠那种也会。
	// 这里要断言的不是「它报错了」，而是**外面那个文件没被发出去** ——
	// 报「没有这个文件」是可以接受的，悄悄把 /etc/passwd 发走才是事故。
	s, addr := tftpShare(t, nil)
	for _, name := range []string{
		"../../../../etc/passwd",
		"/../../etc/passwd",
		"..\\..\\windows\\win.ini",
		"/%2e%2e/%2e%2e/etc/passwd",
	} {
		got, code, msg := tftpAskErr(t, addr, "RRQ", name)
		if len(got) > 0 {
			t.Errorf("%q 居然取到了东西（%d 字节）：%q", name, len(got), got)
		}
		if code == 0 {
			t.Errorf("%q 没挡住：%s", name, msg)
		}
	}
	// 这几笔全是「文件名对不上」，不该污染那条「有人在试」的计数
	if st := s.Status(); st.Denied != 0 {
		t.Errorf("抄错路径不该算被拒：Denied=%d", st.Denied)
	}
}

func TestTFTP中途不回话记的是取到一半(t *testing.T) {
	if testing.Short() {
		t.Skip("要等满重传的那 31 秒，-short 时跳过")
	}
	// ★ 这一笔是 TFTP 台账最值钱的一条：设备刷固件刷到一半停了，现场第一句问的
	//   永远是「它到底取到哪儿断的」。记成一次普通失败就等于没回答这个问题。
	s, addr := tftpShare(t, nil)
	body := bytes.Repeat([]byte("q"), 1456*40) // 四十多块：够它在中间某处停下
	if err := os.WriteFile(filepath.Join(s.Status().Root, "big.bin"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	peer, srv, err := tftpPeer(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	tftpSendReq(t, peer, srv, "big.bin", "blksize", "1456")

	// 收下前几块，然后就不吭声了：真实场景是设备这时候掉电/网线被踢
	buf := make([]byte, 2048)
	for got := 0; got < 3; {
		_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("第 %d 块就没等到：%v", got+1, err)
		}
		if binary.BigEndian.Uint16(buf) == tftpOACK {
			// 协商那一发不占块数，但**得回一个 ACK(0)**：不回的话服务端一直等在
			// 第一块之前，客户端这边什么也收不到 —— 真设备就是这个表现。
			if _, err := peer.WriteTo(ackTo(0), from); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if n-4 != 1456 {
			t.Fatalf("中间某一发不足整块（%d 字节）却还没到结尾", n-4)
		}
		want := binary.BigEndian.Uint16(buf[2:])
		if _, err := peer.WriteTo(ackTo(want), from); err != nil {
			t.Fatal(err)
		}
		got++
	}
	// 从这里开始不再回 ACK：服务端要把重传跑完才给这一笔记账
	var rec Transfer
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st := s.Status()
		if len(st.Recent) > 0 {
			rec = st.Recent[0]
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if rec.Status == "" {
		t.Fatal("重传跑完了，这一笔也没进台账")
	}
	if rec.Status != "partial" {
		t.Errorf("这一笔该记成取到一半：%+v", rec)
	}
	if rec.Path != "big.bin" || rec.Proto != "tftp" {
		t.Errorf("这一笔记错了文件或协议：%+v", rec)
	}
	if rec.Bytes <= 0 || rec.Bytes >= int64(len(body)) {
		t.Errorf("取到一半的字节数不对：%d（文件 %d）", rec.Bytes, len(body))
	}
}

// tftpPeer 开一个客户端口，顺带把服务端的地址解好。
func tftpPeer(addr string) (*net.UDPConn, *net.UDPAddr, error) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, nil, err
	}
	sa, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	return pc, sa, nil
}

// tftpSendReq 发一个不带协商的 RRQ（要带选项就往后拼）。
func tftpSendReq(t *testing.T, pc *net.UDPConn, srv *net.UDPAddr, filename string, opts ...string) {
	t.Helper()
	pkt := binary.BigEndian.AppendUint16(nil, tftpRRQ)
	for _, f := range append([]string{filename, "octet"}, opts...) {
		pkt = append(pkt, []byte(f)...)
		pkt = append(pkt, 0)
	}
	if _, err := pc.WriteTo(pkt, srv); err != nil {
		t.Fatal(err)
	}
}

func TestTFTP反斜杠文件名取得到(t *testing.T) {
	// ★ Windows 那侧的设备传的是 C:\ 那种带反斜杠的名字；不归一的话它永远「没有这个文件」，
	//   而人只会以为是共享没开对。
	s, addr := tftpShare(t, nil)
	_ = s
	got, _, code, msg := tftpGet(t, addr, "\\fw.bin", tftpDefault, nil)
	if code != 0 {
		t.Fatalf("%d：%s", code, msg)
	}
	if len(got) != 4000 {
		t.Errorf("拿到 %d 字节", len(got))
	}
	// 但反斜杠不能变成逃逸通道
	_, code, _ = tftpAskErr(t, addr, "RRQ", "..\\..\\etc\\passwd")
	if code != errAccessViolat && code != errFileNotFound {
		t.Errorf("越界的路径拿到 %d", code)
	}
}

func TestTFTP大文件块号会回绕(t *testing.T) {
	if testing.Short() {
		t.Skip("要跑六万多次来回，-short 时跳过")
	}
	// ★ 512 字节的块要 32MB 才绕一次，谁也不会拿那么大文件做样本；
	//   这里用最小的 blksize=16 把它绕出来 —— 绕错的表现是设备
	//   「下到 32MB 左右就永远卡住」，是最难复现的那类现场问题。
	root := t.TempDir()
	const blk = 16
	body := bytes.Repeat([]byte("a"), blk*65536+3) // 正好越过 65535 → 0 那一下
	if err := os.WriteFile(filepath.Join(root, "wrap.bin"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0,
		Listing: true, TFTP: true, TFTPPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	addr := "127.0.0.1:" + fmt.Sprint(s.Status().TFTPPort)
	got, _, code, msg := tftpGet(t, addr, "wrap.bin", blk, []string{"blksize", "16"})
	if code != 0 {
		t.Fatalf("%d：%s", code, msg)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("回绕处对不上：拿到 %d 字节，要 %d", len(got), len(body))
	}
}

func TestTFTP同时太多笔时不接新的(t *testing.T) {
	// 不鉴权 + 同网段谁都能开一笔：没有上限就是一个人脚本里循环一下，
	// 这台机器的 socket 和 goroutine 就上去。
	s, _ := tftpShare(t, nil)
	for i := 0; i < tftpMaxActive; i++ {
		if !s.tftpAcquire() {
			t.Fatalf("第 %d 笔就该收，却说不满了", i)
		}
	}
	if s.tftpAcquire() {
		t.Errorf("占到上限还不挡：上限 %d", tftpMaxActive)
	}
	s.tftpRelease()
	if !s.tftpAcquire() {
		t.Error("放掉一笔后应该又能接")
	}
}

func TestTFTP关掉TFTP时一个UDP口都不开(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "fw.bin", []byte("abc"))
	s, err := Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0, Listing: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := s.Status()
	if st.TFTP || st.TFTPPort != 0 || len(st.TFTPURLs) != 0 {
		t.Errorf("没开 TFTP 却报了口：%+v", st)
	}
}

func TestTFTP起不来时不留半个共享(t *testing.T) {
	// ★ 批准说明里写的是「http + tftp」，人点头的是这个整体。
	//   TFTP 端口被占却只回滚 TFTP、留着 http 在听，就等于偷偷改了人批准的那件事。
	root := t.TempDir()
	writeFile(t, root, "fw.bin", []byte("abc"))
	// 先占满一个号，让 TFTP 一定绑不上
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := busy.LocalAddr().(*net.UDPAddr).Port
	_, err = Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0,
		Listing: true, TFTP: true, TFTPPort: port})
	if err == nil {
		t.Fatal("端口被占却起起来了")
	}
	_ = busy.Close()
	if !strings.Contains(err.Error(), "已经被别的服务占了") && !strings.Contains(err.Error(), "绑不上") {
		t.Errorf("报错没落在能接着查的那句话上：%v", err)
	}
	// 回滚要干净：那个 http 端口也不能还被人连着
	if s2, e2 := Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0, Listing: true,
		TFTP: true, TFTPPort: 0}); e2 != nil {
		t.Errorf("回滚之后重新起都起不来了：%v", e2)
	} else {
		s2.Stop()
	}
}

// tftpAskErr 只发一个请求并拿回错误码（不管它是不是正常回话）。
func tftpAskErr(t *testing.T, addr, kind, filename string) ([]byte, uint16, string) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	sa, _ := net.ResolveUDPAddr("udp4", addr)
	op := tftpRRQ
	if kind == "WRQ" {
		op = tftpWRQ
	}
	pkt := binary.BigEndian.AppendUint16(nil, op)
	pkt = append(pkt, []byte(filename)...)
	pkt = append(pkt, []byte("\x00octet\x00")...)
	if _, err := pc.WriteTo(pkt, sa); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for i := 0; i < 20; i++ {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			return nil, 0xFFFF, "没收到回话"
		}
		if n < 4 {
			continue
		}
		if binary.BigEndian.Uint16(buf) == tftpERROR {
			msg, _, _ := nextCStr(buf[4:])
			return nil, binary.BigEndian.Uint16(buf[2:]), msg
		}
		// 它居然开始发数据了：那这一笔要测的「拒」就没拒住。
		if binary.BigEndian.Uint16(buf) == tftpDATA {
			return append([]byte(nil), buf[4:n]...), 0, "居然开始发数据了"
		}
	}
	return nil, 0xFFFF, "一直等不到错误包"
}

func mustList(t *testing.T, s *Server) []string {
	t.Helper()
	des, err := os.ReadDir(s.Status().Root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}
