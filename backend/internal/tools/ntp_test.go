package tools

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// ---------- 假 NTP 服务器 ----------

// ntpDwell 是假服务器「收到」到「发出」之间的停留。
//
// ★ 它必须**真的睡这么久了才回**：往返 = 总耗时 - 停留，停留比耗时还长的话算出来是负的，
//
//	而负往返在这里被当成「对方的钟在跳」拒掉 —— 测试会假得很难看。
const ntpDwell = 2 * time.Millisecond

// ntpFake 在本机起一个 UDP 服务，按 reply 现算应答；reply 返回 nil 表示装死不回。
//
// ★ 时间戳全由测试控制，偏差才算得出**确切**的数：打公网源只能验形状，
//
//	验不了「本机落后 500 毫秒」这句话到底是不是 500 毫秒。
func ntpFake(t *testing.T, network string, reply func(req []byte, now time.Time) []byte) (string, int) {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		ip = net.IPv6loopback
	}
	pc, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("这台机器起不了 %s 监听：%v", network, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, peer, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			out := reply(req, time.Now())
			if out == nil {
				continue // 装死：UDP 没有「连不上」这回事，不回就是被挡了
			}
			if _, e := pc.WriteTo(out, peer); e != nil {
				return
			}
		}
	}()
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	p, _ := strconv.Atoi(port)
	return host, p
}

// ntpOk 造一个正常应答。shift 是「服务器的钟」相对本机的平移：
// 正 shift = 服务器读数更大 = 本机**落后**。这个方向是整个工具的符号约定，测试按它钉死。
//
// delay 是在停留之外**再多磨掉**的时间，用来造一次被队列拖慢的问答。
func ntpOk(shift, delay time.Duration, stratum int, refID string) func(req []byte, now time.Time) []byte {
	return func(req []byte, now time.Time) []byte {
		// Origin 必须回显请求里的 Transmit 戳，否则这一包会被认成「不是答复我们问的」
		b := ntpFix(binary.BigEndian.Uint64(req[40:48]), now.Add(shift), now.Add(shift).Add(ntpDwell), stratum, refID)
		time.Sleep(ntpDwell + delay)
		return b
	}
}

// ntpFix 拼一个字段齐全的正常应答：Origin 与收/发时刻都由调用方定。
func ntpFix(origin uint64, rx, tx time.Time, stratum int, refID string) []byte {
	var b [48]byte
	b[0] = 0x24 // LI=0 VN=4 mode=4（server）
	b[1] = byte(stratum)
	copy(b[12:16], refID)
	binary.BigEndian.PutUint64(b[24:32], origin)
	binary.BigEndian.PutUint64(b[32:40], ntpFromTime(rx))
	binary.BigEndian.PutUint64(b[40:48], ntpFromTime(tx))
	return b[:]
}

// ntpRaw 造一个形状可控的应答：是不是 NTP 由测试说了算。
func ntpRaw(mutate func(b, req []byte, now time.Time)) func(req []byte, now time.Time) []byte {
	return func(req []byte, now time.Time) []byte {
		b := make([]byte, 48)
		mutate(b, req, now)
		return b
	}
}

// ntpDead 装死：一个包都不回，等价于 UDP 123 被中间的东西挡了。
func ntpDead() func(req []byte, now time.Time) []byte {
	return func([]byte, time.Time) []byte { return nil }
}

func ntpAsk(t *testing.T, server string, port, samples int) timeSource {
	t.Helper()
	return askSource(context.Background(), server, port, samples, 2*time.Second)
}

func timeRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doTimeCheck(context.Background(), b)
	if err != nil {
		t.Fatalf("time.check(%v) 报错：%v", args, err)
	}
	out, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("time.check 没返回判定，返回 %T", v)
	}
	return out
}

// tsrc 是一行源结果，够摆出各种顶层判定的组合。
func tsrc(server, code string, offset, rtt float64) timeSource {
	return timeSource{Server: server, Code: code, OffsetMs: offset, RTTMs: rtt}
}

// ---------- 一次问答的算术 ----------

func Test偏差的符号是本机落后(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	t3 := t0.Add(50 * time.Millisecond)
	// 服务器收到 = t0+10ms，发出 = t0+12ms：θ = (10 + (12-50))/2 = -14，δ = 10-(-38) = 48
	b := ntpFix(ntpFromTime(t0), t0.Add(10*time.Millisecond), t0.Add(12*time.Millisecond), 2, "GOOG")
	s, err := parseNTP(b, t0, t3, ntpFromTime(t0))
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(s.offset+14) > 0.001 {
		t.Errorf("偏差 = %v，想要 -14", s.offset)
	}
	if math.Abs(s.rtt-48) > 0.001 {
		t.Errorf("往返 = %v，想要 48（总耗时 50 减掉服务器停留 2）", s.rtt)
	}
	if s.stratum != 2 {
		t.Errorf("stratum = %d", s.stratum)
	}
}

func Test往返算成负数不当样本用(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	t3 := t0.Add(5 * time.Millisecond)
	// 服务器的「收到」在本机发出之前、「发出」在本机收到之后：它的钟在跳，不是在走
	b := ntpFix(ntpFromTime(t0), t0.Add(-time.Second), t3.Add(time.Second), 2, "GOOG")
	if _, err := parseNTP(b, t0, t3, ntpFromTime(t0)); !errors.Is(err, errNTPFormat) {
		t.Errorf("负往返要认成坏应答（不然它会被当成「往返 0 毫秒的高置信样本」用掉），得到 %v", err)
	}
}

func Test回包对不上问的就不算(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	b := ntpFix(ntpFromTime(t0.Add(time.Hour)), t0, t0.Add(time.Millisecond), 2, "GOOG")
	if _, err := parseNTP(b, t0, t0.Add(10*time.Millisecond), ntpFromTime(t0)); !errors.Is(err, errNTPFormat) {
		t.Errorf("原始戳对不上要拒掉，得到 %v", err)
	}
}

func Test认不出的应答形状(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	origin := ntpFromTime(t0)
	t3 := t0.Add(10 * time.Millisecond)
	cases := []struct {
		name string
		b    []byte
	}{
		{"mode 不对", func() []byte {
			b := ntpFix(origin, t0, t0.Add(time.Millisecond), 2, "GOOG")
			b[0] = 0x22 // mode=2：这不是给客户端的答复
			return b
		}()},
		{"服务器时间戳是空的", func() []byte {
			b := ntpFix(origin, t0, t0.Add(time.Millisecond), 2, "GOOG")
			binary.BigEndian.PutUint64(b[40:48], 0)
			return b
		}()},
		{"短包", func() []byte { return make([]byte, 47) }()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseNTP(c.b, t0, t3, origin); !errors.Is(err, errNTPFormat) {
				t.Errorf("要认成「回来的不是 NTP」，得到 %v", err)
			}
		})
	}
}

func Test拒答的码留在字段里(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	b := ntpFix(ntpFromTime(t0), t0, t0.Add(time.Millisecond), 0, "STEP")
	_, err := parseNTP(b, t0, t0.Add(time.Millisecond), ntpFromTime(t0))
	var k *ntpKiss
	if !errors.As(err, &k) || k.code != "STEP" {
		t.Fatalf("要拿到 KoDR STEP，得到 %v / %#v", err, k)
	}
	if !errors.Is(err, errNTPKiss) {
		t.Error("拒答要能被 errNTPKiss 认出来")
	}
}

func Test闰秒预警不是错误(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	b := ntpFix(ntpFromTime(t0), t0, t0.Add(time.Millisecond), 2, "GOOG")
	b[0] |= 1 << 6 // LI=1：接下来要插一秒
	s, err := parseNTP(b, t0, t0.Add(10*time.Millisecond), ntpFromTime(t0))
	if err != nil {
		t.Fatal(err)
	}
	if s.leap != "insert" {
		t.Errorf("闰秒预警要留着（那是「对时会有 1 秒台阶」的现场信号），得到 %q", s.leap)
	}
}

func Test时间戳换算过得去(t *testing.T) {
	for _, ts := range []string{"2026-09-23T10:00:00.123456Z", "1970-01-01T00:00:00Z", "2035-06-01T00:00:00.5Z"} {
		want, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			t.Fatal(err)
		}
		if d := ntpToTime(ntpFromTime(want)).Sub(want); d > time.Microsecond || d < -time.Microsecond {
			t.Errorf("%s 来回换算差了 %v", ts, d)
		}
	}
	if !ntpToTime(0).IsZero() {
		t.Error("全零要认成「没有这个时间戳」，不能算成 1900 年")
	}
}

func Test参考时钟标识两种形状(t *testing.T) {
	if got := refIDString([]byte("GPS\x00")); got != "GPS" {
		t.Errorf("stratum 1 的标签 = %q，想要 GPS", got)
	}
	if got := refIDString([]byte{10, 0, 0, 1}); got != "10.0.0.1" {
		t.Errorf("上游地址 = %q", got)
	}
}

// ---------- 一个源 ----------

func Test问一个源拿到确切偏差(t *testing.T) {
	host, port := ntpFake(t, "udp", ntpOk(500*time.Millisecond, 0, 2, "GOOG"))
	res := ntpAsk(t, host, port, 2)
	if res.Code != timeAnswered {
		t.Fatalf("码 = %s（%s）", res.Code, res.Detail)
	}
	if res.OffsetMs < 400 || res.OffsetMs > 600 {
		t.Errorf("偏差 = %v ms，想要 500 上下", res.OffsetMs)
	}
	if res.Answers != 2 || res.Samples != 2 {
		t.Errorf("问答计数 = %d/%d", res.Answers, res.Samples)
	}
	if res.Stratum != 2 || res.RefID != "GOOG" {
		t.Errorf("stratum/refID = %d/%q", res.Stratum, res.RefID)
	}
	if res.ServerTime == "" || res.LocalTime == "" {
		t.Error("「服务器说几点」和「本机说几点」都要带上，界面那句对比靠它")
	}
}

func Test取往返最短的那次(t *testing.T) {
	// 第一包在服务器上排了 200 毫秒的队。★ 不取最短的话，这一次排队会把
	// 「本机落后 3 毫秒」算成「本机落后 100 多毫秒」—— 而 3 毫秒才是真相。
	var n int
	host, port := ntpFake(t, "udp", func(req []byte, now time.Time) []byte {
		n++
		if n == 1 {
			return ntpOk(10*time.Second, 200*time.Millisecond, 2, "GOOG")(req, now)
		}
		return ntpOk(3*time.Millisecond, 0, 2, "GOOG")(req, now)
	})
	res := ntpAsk(t, host, port, 2)
	if res.OffsetMs > 1000 {
		t.Errorf("偏差 = %v ms，想要取到那次干净的（约 4ms）", res.OffsetMs)
	}
}

func Test源各自的原因分得开(t *testing.T) {
	t.Run("一个包都不回", func(t *testing.T) {
		host, port := ntpFake(t, "udp", ntpDead())
		res := ntpAsk(t, host, port, 1)
		if res.Code != timeNoResponse {
			t.Errorf("码 = %s，想要 %s", res.Code, timeNoResponse)
		}
		if res.Samples != 1 || res.Answers != 0 {
			t.Errorf("计数 = %d/%d：问了几个、回了几个要分开", res.Samples, res.Answers)
		}
		if !strings.Contains(res.Detail, "没回话") {
			t.Errorf("Detail = %q，要写成现场读得懂的话，不是 Go 的错误原文", res.Detail)
		}
	})
	t.Run("拒答", func(t *testing.T) {
		host, port := ntpFake(t, "udp", ntpRaw(func(b, req []byte, now time.Time) {
			copy(b, ntpFix(binary.BigEndian.Uint64(req[40:48]), now, now, 0, "RATE"))
		}))
		res := ntpAsk(t, host, port, 2)
		if res.Code != timeKissed || res.Kiss != "RATE" {
			t.Errorf("码 = %s / kiss = %q，想要 %s/RATE", res.Code, res.Kiss, timeKissed)
		}
	})
	t.Run("回的不是NTP", func(t *testing.T) {
		host, port := ntpFake(t, "udp", ntpRaw(func(b, req []byte, now time.Time) {
			copy(b, []byte("HTTP/1.1 400 Bad Request")) // 这个端口上挂着别的东西
		}))
		res := ntpAsk(t, host, port, 2)
		if res.Code != timeBadFormat {
			t.Errorf("码 = %s，想要 %s", res.Code, timeBadFormat)
		}
	})
	t.Run("域名解析不出来", func(t *testing.T) {
		name := "ntp-check.invalid"
		if _, err := net.LookupHost(name); err == nil {
			t.Skipf("这台机器的解析器给 %s 编了个地址（假 IP 型 DNS），这一档在这里验不了", name)
		}
		res := ntpAsk(t, name, 123, 1)
		if res.Code != tlsNameUnresolved {
			t.Errorf("码 = %s，想要 %s —— 报成「没回」会让人去查一条根本没挡着的防火墙", res.Code, tlsNameUnresolved)
		}
	})
}

// ---------- 顶层判定 ----------

func Test校时顶层判定(t *testing.T) {
	cases := []struct {
		name  string
		srcs  []timeSource
		want  string
		slow  bool
		agree int
		attr  string
		with  string
	}{
		{
			name: "两个源都说准",
			srcs: []timeSource{tsrc("a", timeAnswered, -12, 5), tsrc("b", timeAnswered, 8, 30)},
			want: timeOK, agree: 2, attr: "corroborated", with: "a",
		},
		{
			name: "小偏差",
			srcs: []timeSource{tsrc("a", timeAnswered, 5000, 5)},
			want: timeSkewed, slow: true, agree: 1, attr: "single-source", with: "a",
		},
		{
			name: "大偏差（落后）",
			srcs: []timeSource{tsrc("a", timeAnswered, 300000, 5)},
			want: timeWayOff, slow: true, agree: 1, attr: "single-source", with: "a",
		},
		{
			name: "大偏差（快着）",
			srcs: []timeSource{tsrc("a", timeAnswered, -86400000, 5)},
			want: timeWayOff, agree: 1, attr: "single-source", with: "a",
		},
		{
			name: "源互相矛盾",
			srcs: []timeSource{tsrc("a", timeAnswered, 400000, 5), tsrc("b", timeAnswered, 0, 8)},
			want: timeDisagree, slow: true, agree: 2, attr: "conflict", with: "a",
		},
		{
			name: "全部没回",
			srcs: []timeSource{tsrc("a", timeNoResponse, 0, 0), tsrc("b", timeNoResponse, 0, 0)},
			want: timeNoResponse, agree: 0, attr: "none",
		},
		{
			name: "有一个拒答",
			srcs: []timeSource{tsrc("a", timeNoResponse, 0, 0), {Server: "b", Code: timeKissed, Kiss: "STEP"}},
			want: timeKissed, agree: 0, attr: "none",
		},
		{
			name: "全都解析不出来",
			srcs: []timeSource{tsrc("a", tlsNameUnresolved, 0, 0), tsrc("b", tlsNameUnresolved, 0, 0)},
			want: tlsNameUnresolved, agree: 0, attr: "none",
		},
		{
			// ★ 一个解析不出来、一个没回：只报解析会让人以为查完 DNS 就完事了
			name: "解析和没回混着",
			srcs: []timeSource{tsrc("a", tlsNameUnresolved, 0, 0), tsrc("b", timeNoResponse, 0, 0)},
			want: timeNoResponse, agree: 0, attr: "none",
		},
		{
			// 两个源都给数时，报的是**往返最短**那个 —— 队列拖长的那次不算数
			name: "取往返最短的那个源",
			srcs: []timeSource{tsrc("a", timeAnswered, 30, 40), tsrc("b", timeAnswered, -35, 6)},
			want: timeOK, agree: 2, attr: "corroborated", with: "b",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, code := summarizeTime(c.srcs)
			if code != c.want {
				t.Errorf("码 = %s，想要 %s", code, c.want)
			}
			if v["localSlow"] != c.slow {
				t.Errorf("localSlow = %v，想要 %v（正偏差 = 本机落后）", v["localSlow"], c.slow)
			}
			if v["agreeSources"] != c.agree {
				t.Errorf("agreeSources = %v，想要 %v", v["agreeSources"], c.agree)
			}
			if v["attribution"] != c.attr {
				t.Errorf("attribution = %v，想要 %v", v["attribution"], c.attr)
			}
			if c.with != "" && v["checkedWith"] != c.with {
				t.Errorf("checkedWith = %v，想要 %s", v["checkedWith"], c.with)
			}
		})
	}
}

func Test矛盾时不指认谁错(t *testing.T) {
	v, code := summarizeTime([]timeSource{tsrc("a", timeAnswered, 600000, 5), tsrc("b", timeAnswered, 0, 9)})
	if code != timeDisagree {
		t.Fatalf("码 = %s", code)
	}
	if v["attribution"] != "conflict" {
		t.Error("源之间对不上时 attribution 必须是 conflict：它们谁的话都不能当准绳")
	}
	if sp, _ := v["spreadMs"].(float64); sp < 599000 {
		t.Errorf("spreadMs = %v，要如实带上差值", sp)
	}
}

func Test没答的源也留在表里(t *testing.T) {
	v, _ := summarizeTime([]timeSource{tsrc("good", timeAnswered, 10, 5), tsrc("dead", timeNoResponse, 0, 0)})
	srcs, ok := v["sources"].([]timeSource)
	if !ok || len(srcs) != 2 {
		t.Fatalf("sources = %#v", v["sources"])
	}
	if srcs[1].Code != timeNoResponse {
		t.Error("没回的那个源要被留着：只列答了的那一个，人看不出「有一个根本不理你」")
	}
}

func Test校时备注只给码和事实(t *testing.T) {
	n := timeNote(timeSkewed, []timeSource{
		{Server: "a", Code: timeAnswered, OffsetMs: 5000.4},
		{Server: "b", Code: timeNoResponse},
	})
	if n != "time-skewed a=answered offset=5000.4ms b=time-no-response" {
		t.Errorf("备注 = %q", n)
	}
}

func Test校时服务器写法(t *testing.T) {
	for _, bad := range []string{"", "   ", "a b", "1.2.3.4/24"} {
		b, _ := json.Marshal(map[string]any{"servers": []string{bad}, "samples": 1})
		if _, err := doTimeCheck(context.Background(), b); err == nil {
			t.Errorf("%q 要直接拒掉：它不会自己变好，只会让一个源看起来「不回」", bad)
		}
	}
}

func TestIPv6的区号要先去掉(t *testing.T) {
	// %lo0 是本机网卡名，拨号认不得它：留着区号会被报成「问不到」，而真相只是地址写错了
	host, port := ntpFake(t, "udp6", ntpOk(0, 0, 1, "GPS"))
	zoned := netip.MustParseAddr(host).WithZone("lo0").String()
	ver := timeRun(t, map[string]any{"servers": []string{zoned}, "port": port, "samples": 1})
	if ver.Code == timeNoResponse || ver.Code == tlsNameUnresolved {
		t.Errorf("码 = %s（%s）—— 区号没去掉就会这样", ver.Code, ver.Note)
	}
}

func Test重复的源只问一次(t *testing.T) {
	// 并行问同一个地址两次，第二次会吃到自己造成的 RATE 拒答 —— 那是这一栏自己造的假结论
	host, port := ntpFake(t, "udp", ntpOk(0, 0, 2, "GOOG"))
	ver := timeRun(t, map[string]any{"servers": []string{host, host, " " + host + " "}, "port": port, "samples": 1})
	srcs := ver.Values["sources"].([]timeSource)
	if len(srcs) != 1 {
		t.Errorf("源数 = %d，重复的（只差空白的也算）要去掉", len(srcs))
	}
}

// ---------- 整体跑通 ----------

func Test校时端到端(t *testing.T) {
	host, port := ntpFake(t, "udp", ntpOk(5*time.Minute, 0, 2, "GOOG"))
	ver := timeRun(t, map[string]any{"servers": []string{host}, "port": port, "samples": 2, "timeoutMs": 2000})
	if ver.Code != timeWayOff {
		t.Errorf("码 = %s（差 5 分钟要报 %s，TLS 的容错就在这个量级上）", ver.Code, timeWayOff)
	}
	if !ver.Values["localSlow"].(bool) {
		t.Error("服务器读数更大 = 本机落后，方向不能反")
	}
	if ver.Values["checkedWith"] != host {
		t.Errorf("checkedWith = %v", ver.Values["checkedWith"])
	}
	if !strings.HasPrefix(ver.Note, "time-way-off") {
		t.Errorf("备注 = %q", ver.Note)
	}
}

func Test默认源不止一个(t *testing.T) {
	// 只有一个源时「差了多少」可以说，「是谁不对」不能说 —— 默认给多个才敢指认
	if len(defaultNTPServers) < 2 {
		t.Fatalf("默认源 = %v，要至少两个", defaultNTPServers)
	}
	for _, s := range defaultNTPServers {
		if strings.ContainsAny(s, " %/") {
			t.Errorf("默认源 %q 写法不对", s)
		}
	}
}

// 真打一次公网源：验的是「和真服务器对得上话」，不是某个具体偏差。不在网上就跳过。
func Test真问一台公网NTP(t *testing.T) {
	if _, err := net.LookupHost("pool.ntp.org"); err != nil {
		t.Skipf("这台机器连不上公网：%v", err)
	}
	ver := timeRun(t, map[string]any{"samples": 2})
	srcs, ok := ver.Values["sources"].([]timeSource)
	if !ok || len(srcs) != len(defaultNTPServers) {
		t.Fatalf("sources = %#v，每个默认源都要有一行（没答的也要留行）", ver.Values["sources"])
	}
	answered := 0
	for _, s := range srcs {
		if s.Code == timeAnswered {
			answered++
			if s.ServerTime == "" || s.Stratum == 0 {
				t.Errorf("答了的源缺一半事实：%+v", s)
			}
		}
	}
	if answered == 0 {
		t.Skipf("这台机器问不到公网 NTP（UDP 123 被挡是常态）：%s", ver.Note)
	}
	t.Logf("码 = %s，偏差 = %v ms，答了 %d/%d 个源", ver.Code, ver.Values["offsetMs"], answered, len(srcs))
}
