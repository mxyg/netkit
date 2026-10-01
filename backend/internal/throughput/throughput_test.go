package throughput

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// startSink 起一个对测口。★ 端口给 0 让内核挑：并行跑测试时抢固定端口
// 会造成「同一份代码两次跑结果不同」这种最难查的假失败。
func startSink(t *testing.T, cfg Config) *Server {
	t.Helper()
	if len(cfg.Addrs) == 0 {
		cfg.Addrs = []string{"127.0.0.1"}
	}
	cfg.Port = 0
	s, err := Start(cfg)
	if err != nil {
		t.Fatalf("对测口起不来：%v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func opts(port int, mode string, seconds int) Options {
	return Options{Host: "127.0.0.1", Port: port, Mode: mode, Seconds: seconds,
		Timeout: 3 * time.Second}
}

// ── 两端对跑 ──

func Test上行两端数到的字节要是一样的(t *testing.T) {
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "up", 1))
	if err != nil {
		t.Fatalf("上行没跑成：%v", err)
	}
	up := res.Up
	if up.Bytes <= 0 {
		t.Fatalf("一个字节都没写出去：%+v", up)
	}
	if up.PeerBytes != up.Bytes {
		t.Errorf("对面数到 %d 字节，我们写出 %d —— 两本账对不上", up.PeerBytes, up.Bytes)
	}
	if up.MBps <= 0 {
		t.Errorf("速率算出来是 %v，字节 %d 耗时 %d ms", up.MBps, up.Bytes, up.ElapsedMs)
	}
	if len(up.Samples) < 2 {
		t.Errorf("一秒的曲线只有 %d 个点，200 毫秒一档该有 4、5 个", len(up.Samples))
	}
	if st := s.Status(); st.Served <= 0 {
		t.Errorf("口子上记着收过 %d 字节", st.Served)
	}
}

func Test下行到点就该停不是把上限整个推过来(t *testing.T) {
	// 这一条盯的是「反向那句 STOP 到底有没有人听」：没人听的话，
	// 「跑一秒」会被执行成「把这台上限那一整块都推过来」，界面上看就是卡住。
	s := startSink(t, Config{})
	start := time.Now()
	res, err := Run(context.Background(), opts(s.Port(), "down", 1))
	if err != nil {
		t.Fatalf("下行没跑成：%v", err)
	}
	spent := time.Since(start)
	if spent > 5*time.Second {
		t.Errorf("喊了停还没停：这一趟用了 %v", spent)
	}
	down := res.Down
	if down.Bytes <= 0 {
		t.Fatalf("收到 0 字节：%+v", down)
	}
	if down.Truncated {
		t.Errorf("跑满约定时长不算被截：%+v", down)
	}
	if down.PeerBytes != down.Bytes {
		t.Errorf("对面写出 %d，我们数到 %d", down.PeerBytes, down.Bytes)
	}
}

func Test两边各记一份耗时差得远就是本机在囤(t *testing.T) {
	// 发送侧「写完」和接收侧「收完」是两个数：它们的差正是堆在本机发送缓冲里的部分。
	// 这里只要求两个数都真拿到了（拿不到的话界面上只能写「没问到」）。
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "up", 1))
	if err != nil {
		t.Fatal(err)
	}
	if res.Up.ElapsedMs <= 0 || res.Up.PeerMs <= 0 {
		t.Errorf("两端耗时至少有一边没问到：本机 %d ms，对面 %d ms", res.Up.ElapsedMs, res.Up.PeerMs)
	}
}

func Test上下行都问一遍两向各自有账(t *testing.T) {
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "both", 1))
	if err != nil {
		t.Fatalf("两向一起没跑成：%v", err)
	}
	if res.Up == nil || res.Down == nil {
		t.Fatalf("两向少了一向：%+v", res)
	}
	if res.Up.Bytes <= 0 || res.Down.Bytes <= 0 {
		t.Errorf("有一向是空的：up %+v down %+v", res.Up, res.Down)
	}
}

func Test半截的账也是账要明说是半截(t *testing.T) {
	// ctx 到点时正在灌的那一路要带着已写出的字节退出来，不能什么数都不给。
	s := startSink(t, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := Run(ctx, opts(s.Port(), "up", 30))
	_ = err
	if res.Up == nil {
		t.Fatalf("没拿到上行那本账：%+v", res)
	}
	if res.Up.Bytes <= 0 {
		t.Errorf("两秒一个字节都没写出去：%+v", res.Up)
	}
	if el := time.Duration(res.Up.ElapsedMs) * time.Millisecond; el > 3*time.Second {
		t.Errorf("说好两百毫秒内退出，量出来 %v", el)
	}
}

// ── 采样与曲线 ──

func Test曲线记的是那一段不是从头平均(t *testing.T) {
	// 平均速率的曲线永远是平的；平的那条线看不出「稳 900」和「1800/0 交替」。
	start := time.Now().Add(-300 * time.Millisecond)
	d := &Direction{}
	appendSample(d, start, 300_000_000) // 前三百毫秒走了 300 MB ≈ 800 Mbps
	time.Sleep(260 * time.Millisecond)
	appendSample(d, start, 300_000_000) // 这一段一个新字节都没走
	if len(d.Samples) < 2 {
		t.Fatalf("只落下 %d 个点，第二段没被记进曲线", len(d.Samples))
	}
	if first := d.Samples[0].MBps; first < 500 {
		t.Errorf("第一段 300 MB / 0.3 秒应当接近 800 Mbps，报成 %v", first)
	}
	if last := d.Samples[len(d.Samples)-1].MBps; last > 100 {
		t.Errorf("停住的那一段报成 %v Mbps —— 曲线在画从头到尾的平均值", last)
	}
}

func Test采样点数有上限(t *testing.T) {
	// 对面一直不结束（或被中间设备保持着连接）时，曲线不能无限长下去 —— 那份结果要进
	// 诊断包、要发给 AI，几万个点会把它撑爆。
	d := &Direction{}
	for i := 1; i <= 600; i++ {
		d.Samples = append(d.Samples, Sample{AtMs: int64(i) * 200, MBps: 10})
	}
	start := time.Now().Add(-time.Duration(601*200) * time.Millisecond)
	appendSample(d, start, 1<<40)
	if len(d.Samples) != 600 {
		t.Errorf("点数从 600 长到了 %d —— 那一格上限没拦住", len(d.Samples))
	}
}

// ── 往返 ──

func Test空载往返量到的是十次不是一次平均(t *testing.T) {
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "up", 1))
	if err != nil {
		t.Fatal(err)
	}
	if res.Idle.Count == 0 {
		t.Fatalf("空载往返一次都没量到：%+v", res.Idle)
	}
	if res.Idle.Count < idlePings/2 {
		t.Errorf("说好 %d 次，只量到 %d 次：%+v", idlePings, res.Idle.Count, res.Idle)
	}
	if res.Idle.MaxMs < res.Idle.MinMs {
		t.Errorf("最大值 %v 比最小值 %v 还小", res.Idle.MaxMs, res.Idle.MinMs)
	}
}

func Test带载往返另开一条线量(t *testing.T) {
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "down", 1))
	if err != nil {
		t.Fatal(err)
	}
	if res.Loaded.Count == 0 {
		t.Errorf("打流的同时没量到往返（这一路的账：%v）—— 复用正在传数据的那条连接是量不出缓冲膨胀的",
			res.Loaded.Fault)
	}
}

func Test一次没回来的往返不叫零毫秒(t *testing.T) {
	// 对端只接不接受回话：这一路要给出「没问到」，不是 MinMs=0 AvgMs=0。
	c, br := mustDialSilent(t)
	r := measureRTT(c, br, 3, time.Millisecond)
	if r.Count == 0 && r.Fault == "" {
		t.Errorf("一次没回来却说成「量到了 0 次且没问题」：%+v", r)
	}
	if r.Fault == "" {
		t.Errorf("对面装死却报了个干净的账：%+v", r)
	}
}

// mustDialSilent 连上一个「握手答应得好、之后一个字都不回」的对面。
//
// ★ 交回去的 reader 就是读握手那一个，和 dialPing 同一个口径（测试要照生产的走法走）。
func mustDialSilent(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		line, err := readLine(br)
		if err != nil {
			return
		}
		f := strings.Fields(line)
		_, _ = c.Write([]byte(replyLine("OK", 0, f[3]))) // 回执给对，然后装死
		_, _ = io.Copy(io.Discard, c)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte(requestLine(ModePing, 0, "aaaa"))); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	line, err := readLine(br)
	if err != nil || !strings.Contains(line, "OK") {
		t.Fatalf("对面没答应：%q %v", line, err)
	}
	return c, br
}

// ── 协议的门口 ──

func Test对面回的不是这套协议要单独说(t *testing.T) {
	// 端口配错、连上的其实是个 http 服务 —— 这和「连不上」是两种病，别并成一格。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = c.Close()
		}
	}()
	_, err = Run(context.Background(), Options{Host: "127.0.0.1",
		Port: portOf(t, ln.Addr()), Mode: "up", Seconds: 1, Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("对面说的是 http，Run 却当跑成功了")
	}
	var te *Error
	if !errors.As(err, &te) || te.Kind != "proto" {
		t.Errorf("这一条应当报成「不是这套协议」，报成了 %v（%T）", err, err)
	}
}

func Test回执里编号对不上就不当自己的账(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = readLine(bufio.NewReader(c))
		_, _ = c.Write([]byte(replyLine("OK", 1<<20, "别人的编号")))
	}()
	_, err = Run(context.Background(), Options{Host: "127.0.0.1",
		Port: portOf(t, ln.Addr()), Mode: "up", Seconds: 1, Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "编号对不上") {
		t.Errorf("把别人那一轮的回执当成自己的账了：%v", err)
	}
}

func Test口满了要说口满而不是超时(t *testing.T) {
	s := startSink(t, Config{MaxSessions: 1})
	// 先把唯一那个位子占住：连上、说对第一句，然后什么都不做。
	c, err := net.Dial("tcp", s.lns[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(requestLine(ModeUp, 0, newNonce()))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // 让服务端把这一路记进在跑的那一格
	_, err = Run(context.Background(), opts(s.Port(), "up", 1))
	if err == nil {
		t.Fatal("口已经满了，Run 却说跑成了")
	}
	var te *Error
	if !errors.As(err, &te) || te.Kind != "busy" {
		t.Errorf("这一条应当报成「口满」，报成了 %v（%T）", err, err)
	}
}

func Test超过上限的量当场夹住(t *testing.T) {
	s := startSink(t, Config{MaxBytes: 1 << 20}) // 1 MiB
	res, err := Run(context.Background(), opts(s.Port(), "up", 3))
	_ = err
	if res.Up == nil {
		t.Fatalf("没拿到上行账：%+v", res)
	}
	if !res.Up.Truncated {
		t.Errorf("对面只肯收 1 MiB，我们写出 %d 字节却没说被截了", res.Up.Bytes)
	}
	if res.PeerMaxBytes != 1<<20 {
		t.Errorf("对面给的上限没带回来：%d", res.PeerMaxBytes)
	}
}

func Test不认识的第一句直接拒(t *testing.T) {
	for _, line := range []string{
		"GET / HTTP/1.1\n",
		"NETKIT-THRU/1 sidestream 0 abc\n", // 模式不在这三档里
		"NETKIT-THRU/1 up -5 abc\n",        // 负数
		"NETKIT-THRU/1 up 100\n",           // 少一句
	} {
		if _, _, _, err := parseRequest(line); err == nil {
			t.Errorf("这一句居然认了：%q", line)
		} else if !errors.Is(err, ErrProto) && !strings.Contains(err.Error(), "不认识") &&
			!strings.Contains(err.Error(), "不像数") {
			t.Errorf("这一句报的原因不对：%q → %v", line, err)
		}
	}
}

func Test一行长过一句话就挡住(t *testing.T) {
	long := strings.Repeat("x", maxLineBytes+10) + "\n"
	_, err := readLine(bufio.NewReader(strings.NewReader(long)))
	if err == nil {
		t.Fatal("对面一句话撑爆内存这条路还开着")
	}
}

func Test帧长超过单帧上限就断开(t *testing.T) {
	buf := make([]byte, 1024)
	_, _, err := readFrame(bufio.NewReader(strings.NewReader("\xff\xff\xff\xff")), buf)
	if err == nil || !strings.Contains(err.Error(), "超过单帧上限") {
		t.Errorf("一个 4G 的帧长被当成了什么：%v", err)
	}
}

// ── 内核那本账 ──

func Test这条连接的账取得到就取得到取不到就说(t *testing.T) {
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "up", 1))
	if err != nil {
		t.Fatal(err)
	}
	info := res.Up.TCP
	switch runtime.GOOS {
	case "darwin", "linux":
		if !info.Given {
			t.Errorf("%s 上这份账用 getsockopt 就取得到，现在说取不到：%s", runtime.GOOS, info.Why)
		}
		if info.SndCwndBytes <= 0 {
			t.Errorf("拥塞窗口报 %d —— 刚灌完一轮的量，窗口不可能是 0：%+v", info.SndCwndBytes, info)
		}
	case "windows":
		// Windows 走 iphlpapi 每连接统计：只有「以管理员开着采集」时才给得全；
		// 没提权那台就是给不了（Given=false）——两种都是这台的真话，别硬判其中一种。
		if info.Given {
			if info.SndCwndBytes <= 0 {
				t.Errorf("Given=true 却说拥塞窗口 %d —— 要么真开了统计，要么别报 Given：%+v", info.SndCwndBytes, info)
			}
		} else if info.Why == "" {
			t.Error("Windows 这份账给不了就得说清为什么给不了")
		}
	default:
		if info.Given {
			t.Errorf("%s 上这份账没核对过结构，不该报取得到：%+v", runtime.GOOS, info)
		}
		if info.Why == "" {
			t.Errorf("给不了就要说清为什么给不了")
		}
	}
}

func Test拿不到的字段不许冒充零(t *testing.T) {
	// 发送缓冲那一格只有 macOS 给：拿不到时是 nil，界面据此写「这台给不了」，
	// 而不是写 0 让人以为「本机没囤东西」。
	s := startSink(t, Config{})
	res, err := Run(context.Background(), opts(s.Port(), "up", 1))
	if err != nil {
		t.Fatal(err)
	}
	info := res.Up.TCP
	if runtime.GOOS == "darwin" {
		if info.SndBufBytes == nil {
			t.Errorf("macOS 给得了发送缓冲这一格，却报了个「没有」：%+v", info)
		}
		return
	}
	if info.SndBufBytes != nil {
		t.Errorf("%s 上这份账里没有发送缓冲，不该凭空报一个：%+v", runtime.GOOS, info)
	}
}

func Test顶速要拿窗口和往返算而不是猜(t *testing.T) {
	// 拥塞窗口 ÷ 往返 = 这一条连接 TCP 自己允许的顶。少了任何一个数都不能给这个数。
	if _, ok := (TCPInfo{Given: true, SndCwndBytes: 10000}).CeilingMbps(); ok {
		t.Error("没有往返也算出了顶")
	}
	if _, ok := (TCPInfo{Given: true, SrttMs: 1}).CeilingMbps(); ok {
		t.Error("没有拥塞窗口也算出了顶")
	}
	v, ok := (TCPInfo{Given: true, SrttMs: 10, SndCwndBytes: 12500}).CeilingMbps()
	if !ok || v < 9 || v > 11 {
		t.Errorf("12500 字节窗口 / 10 毫秒 = 10 Mbps，算出来 %v", v)
	}
}

// ── 口的生死 ──

func Test停止之后不再接新的(t *testing.T) {
	s := startSink(t, Config{})
	s.Stop()
	if _, err := Run(context.Background(), opts(s.Port(), "up", 1)); err == nil {
		t.Fatal("口都停了还能连上")
	}
	if st := s.Status(); st.Serving {
		t.Error("已经停了，状态还说在开着")
	}
}

func Test绑一块没人认领的地址要如实失败(t *testing.T) {
	if _, err := Start(Config{Addrs: []string{"240.0.0.1"}, Port: 0}); err == nil {
		t.Fatal("在一个不属于本机的地址上开起来了 —— 那意味着绑到 0.0.0.0 去了")
	}
}

func Test只给一个地址起不来就别装作开着(t *testing.T) {
	// 两块地址里有一块被别的程序占着：必须整体失败，不能起了那块就报「已开」。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, ln.Addr())
	if _, err := Start(Config{Addrs: []string{"127.0.0.1", "::1"}, Port: port}); err == nil {
		ln.Close()
		t.Fatal("端口被占着却起成功了")
	}
	ln.Close()
}

func portOf(t *testing.T, a net.Addr) int {
	t.Helper()
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		t.Fatalf("不是 tcp 地址：%v", a)
	}
	return tcp.Port
}
