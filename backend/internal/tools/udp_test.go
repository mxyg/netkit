package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// ── 测试用的假 UDP 服务 ──
//
// ★ 全部打在 127.0.0.1 上、由测试自己起服务，偏差和判定都是**确切已知的**，
//   不碰公网也不依赖本机装了什么。

type udpFake struct {
	addr   string
	port   int
	got    chan int // 每收到一发就投一个字节数（0 = 空包也算收到了）
	closed chan struct{}
}

// startUDPFake 起一个 UDP 端口。reply 为 nil 表示「收到也不答」（装成一个不响的服务）；
// reply 非 nil（含零长）表示原样回这么多个字节。
func startUDPFake(t *testing.T, reply []byte) *udpFake {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假服务失败：%v", err)
	}
	host, ps, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("假服务地址读不出来：%v", err)
	}
	p, _ := strconv.Atoi(ps)
	f := &udpFake{addr: host + ":" + ps, port: p, got: make(chan int, 16), closed: make(chan struct{})}
	go func() {
		defer pc.Close()
		buf := make([]byte, 2048)
		for {
			select {
			case <-f.closed:
				return
			default:
			}
			// 读超时是为了 close 之后这个 goroutine 能退出，不影响测试判定
			pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				return
			}
			select {
			case f.got <- n:
			default:
			}
			if reply != nil {
				r := make([]byte, len(reply))
				copy(r, reply)
				pc.WriteTo(r, src)
			}
		}
	}()
	t.Cleanup(func() { close(f.closed) })
	return f
}

// sawPacket 看这一发到底有没有出去（含零长数据报）。
func (f *udpFake) sawPacket(d time.Duration) (int, bool) {
	select {
	case n := <-f.got:
		return n, true
	case <-time.After(d):
		return 0, false
	}
}

func udpRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doUDPProbe(context.Background(), b)
	if err != nil {
		t.Fatalf("udp.probe(%v) 报错：%v", args, err)
	}
	out, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("udp.probe 没返回判定，返回 %T", v)
	}
	return out
}

func udpVals(t *testing.T, v ots.Verdict) map[string]any {
	t.Helper()
	m := map[string]any{}
	raw, err := json.Marshal(v.Values)
	if err != nil {
		t.Fatalf("values 序列化不了：%v", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("values 反序列化不了：%v", err)
	}
	return m
}

func TestUDP探到有回包的服务(t *testing.T) {
	f := startUDPFake(t, []byte("pong"))
	v := udpRun(t, map[string]any{"addr": f.addr, "payload": "ping", "timeoutMs": 1500})
	if v.Code != udpResponsive {
		t.Fatalf("判成 %s，应该是 %s（note：%s）", v.Code, udpResponsive, v.Note)
	}
	vals := udpVals(t, v)
	if vals["bytes"] != float64(len("pong")) {
		t.Errorf("回包大小记成 %v，应该 %d", vals["bytes"], len("pong"))
	}
	if vals["answered"] != true {
		t.Errorf("answered 没置上：%v", vals)
	}
	if n, ok := f.sawPacket(time.Second); !ok || n != len("ping") {
		t.Errorf("假服务收到 n=%v ok=%v，应该收到 %d 字节的 ping", n, ok, len("ping"))
	}
}

// ★ 空包不是「什么都没干」。Go 在连好的 UDP 套接字上确实会下发零长数据报，
//
//	这一条把它钉住：不填 payload 时，对面真的收到一发，回包也算数。
func TestUDP空包真的发得出去(t *testing.T) {
	f := startUDPFake(t, []byte("ack"))
	v := udpRun(t, map[string]any{"addr": f.addr, "timeoutMs": 1500})
	if v.Code != udpResponsive {
		t.Fatalf("判成 %s，应该是 %s", v.Code, udpResponsive)
	}
	if _, ok := f.sawPacket(time.Second); !ok {
		t.Fatal("没给 payload 时对面什么都没收到 —— 那判定就是凭空来的")
	}
}

// 二进制协议报文用 payloadHex 发（比如 DHCP/ONVIF 那种不许有一个字节差的头）。
func TestUDP按十六进制发报文(t *testing.T) {
	f := startUDPFake(t, nil)
	v := udpRun(t, map[string]any{"addr": f.addr, "payloadHex": "00 01\r\n02", "timeoutMs": 300})
	_ = v
	b, ok := f.sawPacket(time.Second)
	if !ok || b != 3 {
		t.Fatalf("对面收到 n=%v ok=%v，应该收到 3 字节", b, ok)
	}
}

func TestUDP十六进制写错了直接拒(t *testing.T) {
	for _, s := range []string{"zz", "0", "0x00"} {
		b, _ := json.Marshal(map[string]any{"addr": "127.0.0.1:9", "payloadHex": s})
		if _, err := doUDPProbe(context.Background(), b); err == nil {
			t.Errorf("payloadHex=%q 居然收下了", s)
		}
	}
}

// 「没人答」和「机器不对」得分开 —— 这就是对照组存在的唯一理由。
func TestUDP没答时对照组把它分开(t *testing.T) {
	silent := startUDPFake(t, nil)       // 目标端口：收到不答（像是个不该这句话的服务）
	loud := startUDPFake(t, []byte("x")) // 对照端口：出声
	v := udpRun(t, map[string]any{
		"addr": silent.addr, "controlPort": loud.port, "timeoutMs": 300,
	})
	if v.Code != udpSilentAlive {
		t.Fatalf("判成 %s，应该是 %s（对照端口出声了，不能说整台机器不对）", v.Code, udpSilentAlive)
	}
	vals := udpVals(t, v)
	c, ok := vals["control"].(map[string]any)
	if !ok {
		t.Fatalf("control 没记进 values：%v", vals)
	}
	if c["answered"] != true {
		t.Errorf("对照组记成不应答：%v", c)
	}
	if c["code"] != udpResponsive {
		t.Errorf("对照组码记成 %v", c["code"])
	}
}

func TestUDP对照也不出声就报静默(t *testing.T) {
	silent := startUDPFake(t, nil)
	quiet := startUDPFake(t, nil)
	v := udpRun(t, map[string]any{
		"addr": silent.addr, "controlPort": quiet.port, "timeoutMs": 300,
	})
	if v.Code != udpSilent {
		t.Fatalf("判成 %s，应该是 %s", v.Code, udpSilent)
	}
	// 静默的备注必须给出下一步往哪查，不能只说「不通」
	if v.Note == "" {
		t.Error("udp-silent 没带备注")
	}
}

// 生产设备上多发一个「没点名」的包是要报备的：noControl 必须真的一个额外包都不发。
func TestUDP关掉对照就只发一发(t *testing.T) {
	silent := startUDPFake(t, nil)
	quiet := startUDPFake(t, nil)
	v := udpRun(t, map[string]any{
		"addr": silent.addr, "controlPort": quiet.port, "timeoutMs": 300, "noControl": true,
	})
	if v.Code != udpSilent {
		t.Fatalf("判成 %s", v.Code)
	}
	if _, ok := quiet.sawPacket(200 * time.Millisecond); ok {
		t.Error("关了对照还往对照端口发包 —— 那 noControl 是假的")
	}
	vals := udpVals(t, v)
	if _, has := vals["control"]; has {
		t.Errorf("关了对照还留了 control：%v", vals)
	}
	// ★ 没跑对照就不许说「对照也没出声」：备注只能写我们真做过的事，
	//   否则人会把一个没测过的东西当成测过的证据。
	if strings.Contains(v.Note, "对照端口没出声") || strings.Contains(v.Note, "和对照端口都没出声") {
		t.Errorf("没跑对照却把对照算成了观测：%s", v.Note)
	}
	if !strings.Contains(v.Note, "没跑对照") {
		t.Errorf("备注该说清楚这次没跑对照：%s", v.Note)
	}
}

// 对照端口填成目标端口 = 再问一遍同一个问题，没有信息量，跳过。
func TestUDP对照端口和目标相同就不跑(t *testing.T) {
	f := startUDPFake(t, nil)
	v := udpRun(t, map[string]any{"addr": f.addr, "controlPort": f.port, "timeoutMs": 300})
	if v.Code != udpSilent {
		t.Fatalf("判成 %s", v.Code)
	}
	vals := udpVals(t, v)
	if _, has := vals["control"]; has {
		t.Errorf("对照端口等于目标端口，不该跑：%v", vals)
	}
}

// 端口没监听时内核会回 ICMP 端口不可达 —— 这是 closed 的唯一来源。
// 拿一个刚释放的端口当靶子（本机回环上稳定可复现，不出机器）。
func TestUDP端口没人监听时报closed(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close() // 关掉之后这个端口没人认领
	v := udpRun(t, map[string]any{"addr": addr, "payload": "x", "timeoutMs": 1200, "noControl": true})
	if v.Code == udpSilent {
		t.Skip("这台机器没把 ICMP 端口不可达透给套接字 —— 判定退回「没反应」，不算错")
	}
	if v.Code != udpClosed {
		t.Fatalf("判成 %s，应该是 %s", v.Code, udpClosed)
	}
	vals := udpVals(t, v)
	if vals["answered"] != false {
		t.Errorf("closed 应该记 answered=false：%v", vals)
	}
}

// ★★ 这一族工具只收 IP（和 net.tcp.probe、net.ping 一致），域名要先过 net.dns.query。
//
//	报错必须把下一步指出来：只说「看不懂地址」，现场会以为是写法不对，
//	而不是「这里压根不接受域名」。
func TestUDP不收域名并指路DNS(t *testing.T) {
	for _, addr := range []string{"udp-bogus.invalid:53", "camera.local"} {
		b, _ := json.Marshal(map[string]any{"addr": addr})
		_, err := doUDPProbe(context.Background(), b)
		if err == nil {
			t.Fatalf("%q 居然收下了", addr)
		}
		if !strings.Contains(err.Error(), "net.dns.query") {
			t.Errorf("%q 的报错没指下一步：%v", addr, err)
		}
	}
}

func TestUDP没给地址和端口越界(t *testing.T) {
	b, _ := json.Marshal(map[string]any{})
	if _, err := doUDPProbe(context.Background(), b); err == nil {
		t.Error("没给 addr 也该拒")
	}
	for _, a := range []map[string]any{{"addr": "127.0.0.1", "port": 0}, {"addr": "127.0.0.1", "port": 70000}} {
		b, _ := json.Marshal(a)
		if _, err := doUDPProbe(context.Background(), b); err == nil {
			t.Errorf("%v 端口越界也该拒", a)
		}
	}
}

// addr 里自带端口时以它为准；不带时用 port 参数。这条走的是 netaddr 那套宽进。
func TestUDP地址写法两种都能拆出端口(t *testing.T) {
	f := startUDPFake(t, []byte("ok"))
	if _, port, err := net.SplitHostPort(f.addr); err != nil || port == "" {
		t.Fatalf("假服务地址不合法：%v", f.addr)
	}
	v := udpRun(t, map[string]any{"addr": "127.0.0.1:" + strconv.Itoa(f.port), "timeoutMs": 800})
	if v.Code != udpResponsive {
		t.Fatalf("addr 自带端口的写法判成 %s", v.Code)
	}
	v = udpRun(t, map[string]any{"addr": "127.0.0.1", "port": f.port, "timeoutMs": 800})
	if v.Code != udpResponsive {
		t.Fatalf("addr + port 分开写的判成 %s", v.Code)
	}
}

// 等不到回话时，备注要写「等了多久没回话」，不许漏出 Go 的 "i/o timeout"。
func TestUDP没回话时说的是人话(t *testing.T) {
	f := startUDPFake(t, nil)
	res := udpAsk(context.Background(), f.addr, nil, 200*time.Millisecond)
	if res.code != "" {
		t.Fatalf("假服务不该有判定码，拿到 %s", res.code)
	}
	if res.err != nil {
		t.Fatalf("没人答不是工具自己的错，err=%v", res.err)
	}
	if res.detail == "" || res.detail != "等了 200ms 没回话" {
		t.Errorf("detail 是 %q，应该是「等了 200ms 没回话」", res.detail)
	}
}

// 取消要能立刻收摊：长任务的地基（[设计] 里那条「发起→查进度」）从这里起步。
func TestUDP上下文取消立刻回(t *testing.T) {
	f := startUDPFake(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	res := udpAsk(ctx, f.addr, nil, 5*time.Second)
	if time.Since(start) > 3*time.Second {
		t.Fatalf("取消了还等了 %v —— 没听 ctx", time.Since(start))
	}
	if res.err == nil {
		t.Error("取消要如实记成错误，不能算成「没反应」")
	}
}
