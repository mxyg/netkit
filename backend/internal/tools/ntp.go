package tools

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// net.time.check —— 拿权威时间源对一下本机时钟，差多少、往哪边差。
//
// ★★ 这台设备的时钟不对，症状却长在别的地方：证书报「还没生效」或「已过期」（其实证书好好的）、
//
//	日志时间戳排不成序、DHCP 租约判成过期、Kerberos/TLS 直接拒。现场踩过的那台设备掉电后
//	时钟重置回几年前，查证书查了半小时 —— 该先问的是「现在几点，谁说的」。
//
// ★ 「差了多少」和「是谁不对」是两件事，这一栏把后者也如实处理：
//
//	只问到一个时间源时，那 3 年的差值既可能是本机错，也可能是对方错 —— 拿单方说法下结论
//	就是编。所以问多个源，**一致**才敢说是本机不对；不一致就说明有个源本身坏了。
var timeCheckTool = ots.Tool{
	Name:  "net.time.check",
	Class: ots.ClassRead,
	Summary: "向 NTP 服务器问一次标准时间，给出本机时钟的偏差（毫秒级）、往返与方向，并区分：正常 / 有偏差 / " +
		"偏差大到会让证书和租约都出错 / 多个时间源互相矛盾 / 一个都没回（常见于 UDP 123 被挡）/ " +
		"服务器拒答（限速、或它明说你的钟差太多）/ 回的不是 NTP / 服务器域名解析不出来。" +
		"★ 默认问多个源，只有它们**彼此一致**时才说「是本机时钟不对」；只问到一个源时只报偏差、不指认谁错。属于只读。",
	Schema: json.RawMessage(`{
		  "type": "object",
		  "additionalProperties": false,
		  "properties": {
		    "servers": {"type": "array", "items": {"type": "string"},
		      "description": "NTP 服务器，可填域名或 IP，各自都会问。默认问两个公网源；内网有自己的时钟源时把它填进来（多个源之间要一致才敢指认本机不对）。"},
		    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
		      "description": "NTP 端口，默认 123。"},
		    "samples": {"type": "integer", "minimum": 1, "maximum": 8,
		      "description": "每个源问几次，取往返最短的那次（抖动小的那次才算数），默认 3。"},
		    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 15000,
		      "description": "一次问答的最长等待，默认 3000。各源并行问；一个源最长 samples × timeoutMs。"}
		  }
		}`),
	Invoke: doTimeCheck,
}

const (
	// 偏差在这以内算正常：人机对表不会用到这个精度，而网络往返本身就有几十毫秒
	timeOKMs = 2000.0
	// 超过这个就开始出错事了：TLS/Kerberos 的容错、租约判断、日志排序
	timeBigMs = 120000.0
	// 两个源之间差这么多，就说明其中一个自己不对，不能拿来当准绳
	timeSpreadMs = 2000.0
)

// stampFormat 带毫秒的时刻。★ 对表这件事上，秒级精度会让「本机 18:44:38」和
// 「标准 18:44:38」长得一模一样 —— 而那 50 毫秒正是要给人看见的东西。
const stampFormat = "2006-01-02T15:04:05.000Z07:00"

const (
	timeOK         = "time-ok"
	timeSkewed     = "time-skewed"
	timeWayOff     = "time-way-off"
	timeDisagree   = "time-servers-disagree"
	timeNoResponse = "time-no-response"
	timeKissed     = "time-kiss-rejected" // 服务器拒答/限速（含 STEP：它明说你的钟太离谱）
	timeBadFormat  = "time-bad-response"  // 回了，但不是 NTP 的样子
)

type timeArgs struct {
	Servers   []string `json:"servers,omitempty"`
	Port      int      `json:"port,omitempty"`
	Samples   int      `json:"samples,omitempty"`
	TimeoutMS int      `json:"timeoutMs,omitempty"`
}

// timeSource 是一个源的结果。★ 没答的源也要留在表里并说明为什么：
// 只列答了的那一个，人看不出「两个源里有一个根本不理你」这件事。
type timeSource struct {
	Server     string  `json:"server"`
	Code       string  `json:"code"`
	OffsetMs   float64 `json:"offsetMs"` // 正 = 本机落后（要往前调）
	RTTMs      float64 `json:"rttMs,omitempty"`
	Stratum    int     `json:"stratum,omitempty"`
	RefID      string  `json:"refId,omitempty"`
	Kiss       string  `json:"kiss,omitempty"`       // KoDR 的四字码，如 RATE / STEP
	Leap       string  `json:"leap,omitempty"`       // insert / delete：这一族里有过闰秒预警
	ServerTime string  `json:"serverTime,omitempty"` // 服务器那一侧的时刻（RFC3339）
	LocalTime  string  `json:"localTime,omitempty"`  // 问的时候本机读到的时刻
	Samples    int     `json:"samples"`              // 问了几个包
	Answers    int     `json:"answers"`              // 回了几个
	Detail     string  `json:"detail,omitempty"`
}

// timeSummary 是顶层要的那几个数（界面读 values，后端不拼中文句子）。
type timeSummary struct {
	OffsetMs    float64 `json:"offsetMs"`
	RTTMs       float64 `json:"rttMs"`
	Slow        bool    `json:"localSlow"` // 正偏差 = 本机落后
	SpreadMs    float64 `json:"spreadMs"`
	AgreeCount  int     `json:"agreeSources"`
	Attribution string  `json:"attribution"` // none / single-source / corroborated / conflict
}

func doTimeCheck(ctx context.Context, raw json.RawMessage) (any, error) {
	var a timeArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	servers := a.Servers
	if len(servers) == 0 {
		servers = defaultNTPServers
	}
	port := a.Port
	if port == 0 {
		port = 123
	}
	samples := a.Samples
	if samples == 0 {
		samples = 3
	}
	timeout := 3 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	// ★ 目标写死成命令行传进来的地址/域名，这里唯一要拦的是空串和带空白的那一类：
	// 它们不会自己变好，只会让某个源看起来「不回」。
	clean := make([]string, 0, len(servers))
	seen := map[string]bool{}
	for _, s := range servers {
		s = trimZone(strings.TrimSpace(s))
		if s == "" || strings.ContainsAny(s, " \t\r\n/") {
			return nil, ots.Errf(ots.ErrInvalidArgument, "NTP 服务器写法不对：%q", s)
		}
		// 重复的源要去掉：并行问同一个地址两次，第二次大概率吃一个 RATE 拒答，
		// 而那条「服务器拒答」是这里自己造成的。
		if seen[s] {
			continue
		}
		seen[s] = true
		clean = append(clean, s)
	}

	// ★ 各源并行问：串行问三个源、每个三个包，最坏要等 9 秒才看到第一行结果，
	// 而「有多个源可问」正是这一栏的用法（内网时钟源 + 公网源各问一遍）。
	// 同一台服务器仍然只按 samples 的顺序问，不会自己把自己限速掉。
	out := make([]timeSource, len(clean))
	var wg sync.WaitGroup
	for i, s := range clean {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			out[i] = askSource(ctx, s, port, samples, timeout)
		}(i, s)
	}
	wg.Wait()

	values, code := summarizeTime(out)
	return ots.Verdict{Code: code, Values: values, Note: timeNote(code, out)}, nil
}

var defaultNTPServers = []string{"pool.ntp.org", "time.cloudflare.com"}

// askSource 问一个源若干次，取往返最短的那次。
//
// ★ 取「往返最短」不是省时间：NTP 的偏差公式里往返是误差的主要来源，
//
//	一次被队列拖了 300ms 的问答会把「本机快 20ms」算成「本机快 170ms」。
func askSource(ctx context.Context, server string, port, samples int, timeout time.Duration) timeSource {
	res := timeSource{Server: server, Code: timeNoResponse}
	var best *ntpSample
	// 没答上的那几个包各自的原因。★ 优先报「拒答」和「回的不是 NTP」：
	// 它们和「压根没回」是三种不同的活 —— 前者是服务器在说话（只是不肯给），
	// 中间那个说明链路上有个东西在冒充/改写 UDP 123，最后那个才是 UDP 123 被挡。
	// 解析不了域名又要单独一档：那连着的是 DNS，不是防火墙，
	// 报成「没回」会让人去查一条根本没被挡的路。
	var kissed, weird string
	var unresolved bool
	for i := 0; i < samples; i++ {
		sctx, cancel := context.WithTimeout(ctx, timeout)
		s, err := sntpQuery(sctx, server, port)
		cancel()
		if err != nil {
			res.Detail = err.Error()
			// ★ 超时的原文是 Go 的 "i/o timeout" / "context deadline exceeded"，现场读不出这是什么意思；
			//   「等了 3 秒没回话」才是这条链路上发生的事。
			if errors.Is(err, errNTPTimeout) || errors.Is(err, context.DeadlineExceeded) {
				res.Detail = "等了 " + timeout.String() + " 没回话"
			}
			var dns *net.DNSError
			var kiss *ntpKiss
			switch {
			case errors.As(err, &kiss):
				kissed = kiss.Error()
				res.Kiss = kiss.code
			case errors.As(err, &dns):
				unresolved = true
			case errors.Is(err, errNTPFormat):
				weird = res.Detail
			}
			continue
		}
		res.Answers++
		if best == nil || s.rtt < best.rtt {
			best = s
		}
	}
	res.Samples = samples
	if best == nil {
		switch {
		case unresolved:
			res.Code = tlsNameUnresolved
		case res.Kiss != "":
			res.Code = timeKissed
			res.Detail = kissed
		case weird != "":
			res.Code = timeBadFormat
		}
		return res
	}
	res.Code = timeAnswered
	res.OffsetMs = round1(best.offset)
	res.RTTMs = round1(best.rtt)
	res.Stratum = best.stratum
	res.RefID = best.refID
	// ★ 带毫秒：对表这件事上「本机 18:44:38 / 标准 18:44:38」是两个一样的字符串，
	// 而差的那 50 毫秒正是要给人看见的东西。
	res.ServerTime = best.serverTime.Format(stampFormat)
	res.LocalTime = best.localTime.Format(stampFormat)
	res.Leap = best.leap
	return res
}

// 本机问到了答案，但 summarizeTime 只关心偏差 —— 单独一个码，免得「答了」被当成一种判定。
const timeAnswered = "answered"

// summarizeTime 汇成顶层判定。★ 顺序是有意的：先处理「源之间互相矛盾」，
// 再谈本机差多少 —— 拿一个自己就不准的源去说本机错了，是最难被发现的错法。
func summarizeTime(srcs []timeSource) (map[string]any, string) {
	var good []timeSource
	for _, s := range srcs {
		if s.Code == timeAnswered {
			good = append(good, s)
		}
	}
	best := timeSource{}
	for _, s := range good {
		if best.Server == "" || s.RTTMs < best.RTTMs {
			best = s
		}
	}
	var spread float64
	if len(good) > 1 {
		lo, hi := math.Inf(1), math.Inf(-1)
		for _, s := range good {
			if s.OffsetMs < lo {
				lo = s.OffsetMs
			}
			if s.OffsetMs > hi {
				hi = s.OffsetMs
			}
		}
		spread = hi - lo
	}
	attribution := "single-source"
	switch {
	case len(good) == 0:
		attribution = "none"
	case spread > timeSpreadMs:
		attribution = "conflict"
	case len(good) > 1:
		attribution = "corroborated"
	}
	out := timeSummary{SpreadMs: round1(spread), AgreeCount: len(good), Attribution: attribution}
	if best.Server != "" {
		out.OffsetMs = best.OffsetMs
		out.RTTMs = best.RTTMs
		out.Slow = best.OffsetMs > 0
	}
	code := timeCodeFor(srcs, good, best, spread)
	values := map[string]any{
		"sources": srcs,
		// 偏差的口径：以往返最短那次为准，多个源一致时它们本来就差不多
		"offsetMs":     out.OffsetMs,
		"rttMs":        out.RTTMs,
		"localSlow":    out.Slow,
		"spreadMs":     out.SpreadMs,
		"agreeSources": out.AgreeCount,
		"attribution":  out.Attribution,
		"thresholdsMs": map[string]any{"ok": timeOKMs, "big": timeBigMs, "spread": timeSpreadMs},
	}
	if best.Server != "" {
		// 界面直接要的两句「本机说几点 / 标准说几点」，省得它自己挑源
		values["checkedWith"] = best.Server
		values["localTime"] = best.LocalTime
		values["standardTime"] = best.ServerTime
	}
	return values, code
}

// timeCodeFor 出顶层判定。★ srcs 是**全部**源（含没答的），good 是答了的那些：
// 一个都没答时，"为什么没答"本身就是结论，得从各自的失败原因里挑最要紧的那个说。
func timeCodeFor(srcs, good []timeSource, best timeSource, spread float64) string {
	if len(good) == 0 {
		// 一个源都没答：把「域名解析不出来」和「问不到」分开 —— 前者连着 DNS（这台机器
		// 可能压根没配服务器，顺带解释了为什么时间也说不准），后者才是 UDP 123 被挡。
		// ★ 只有**每个**没答的源都栽在解析上才敢报这一个码：混进一个超时的话，
		//   真相是两件事同时坏着，只报解析会让人以为查完 DNS 就完事了。
		unresolved, other := 0, 0
		var kissed, weird string
		for _, s := range srcs {
			switch s.Code {
			case tlsNameUnresolved:
				unresolved++
			case timeKissed:
				kissed = s.Server
			case timeBadFormat:
				weird = s.Server
			default:
				other++
			}
		}
		switch {
		case unresolved > 0 && other == 0 && kissed == "" && weird == "":
			return tlsNameUnresolved
		case kissed != "" || weird != "":
			// 有人拒答/答得不对：这比「没回」更值得先看，但也不能盖掉没人答这件事
			if kissed != "" {
				return timeKissed
			}
			return timeBadFormat
		}
		return timeNoResponse
	}
	if spread > timeSpreadMs {
		return timeDisagree
	}
	if math.Abs(best.OffsetMs) > timeBigMs {
		return timeWayOff
	}
	if math.Abs(best.OffsetMs) > timeOKMs {
		return timeSkewed
	}
	return timeOK
}

// timeNote 只给码 + 已拿到的事实，不拼中文句子（界面按语言渲染）。
func timeNote(code string, srcs []timeSource) string {
	parts := make([]string, 0, len(srcs))
	for _, s := range srcs {
		if s.Code == timeAnswered {
			parts = append(parts, s.Server+"=answered offset="+strconv.FormatFloat(s.OffsetMs, 'f', 1, 64)+"ms")
			continue
		}
		parts = append(parts, s.Server+"="+s.Code)
	}
	return code + " " + strings.Join(parts, " ")
}

// ---------- 一次 SNTP 问答 ----------

var (
	errNTPTimeout = errors.New("没回话")
	errNTPKiss    = errors.New("服务器拒答")
	errNTPFormat  = errors.New("回来的不是 NTP")
)

// ntpKiss 是服务器**明说**的拒答（stratum 0 + 那 4 字节原因码）。
//
// ★ 码留在字段里，不靠从错误文本里捞：错误句是要给人看的，改了措辞就把结论改没了。
type ntpKiss struct{ code string }

func (k *ntpKiss) Error() string { return "服务器拒答：" + k.code }

func (k *ntpKiss) Is(target error) bool { return target == errNTPKiss }

// ntpSample 是一次问答算出来的东西。
type ntpSample struct {
	offset     float64 // 毫秒，正 = 本机快
	rtt        float64 // 毫秒
	stratum    int
	refID      string
	kiss       string
	leap       string // insert / delete（闰秒预警）
	serverTime time.Time
	localTime  time.Time
}

const ntpEpochDelta = 2208988800 // 1900-01-01 到 1970-01-01 的秒数

func sntpQuery(ctx context.Context, server string, port int) (*ntpSample, error) {
	addr := net.JoinHostPort(server, strconv.Itoa(port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("%w：对端不是 UDP", errNTPFormat)
	}
	defer uc.Close()

	var req [48]byte
	// LI=0（时钟没预警）| VN=4 | Mode=3（客户端）
	req[0] = 0x23
	tx := time.Now()
	reqTX := ntpFromTime(tx)
	binary.BigEndian.PutUint64(req[40:48], reqTX)
	if _, err := uc.Write(req[:]); err != nil {
		return nil, err
	}
	// 等到 ctx 到期为止：UDP 没有「连接失败」这回事，超时就是唯一的答案
	done := make(chan struct{})
	var resp []byte
	var rerr error
	var t3 time.Time
	go func() {
		defer close(done)
		buf := make([]byte, 48)
		_ = uc.SetReadDeadline(deadlineOr(ctx))
		n, _, e := uc.ReadFrom(buf)
		if e != nil {
			rerr = e
			return
		}
		t3 = time.Now()
		resp = buf[:n]
	}()
	select {
	case <-done:
	case <-ctx.Done():
		<-done // 让读协程把连接收尾，不留半个 goroutine
		return nil, errors.Join(errNTPTimeout, ctx.Err())
	}
	if rerr != nil {
		// ★ 读超时先于 ctx 到期触发时，Go 给的是 `i/o timeout`，不是 context 的错误。
		// 两条路都是「到点了还没回话」，得汇成同一个判定，否则界面会印出一句网络栈黑话。
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			return nil, fmt.Errorf("%w：%s", errNTPTimeout, rerr)
		}
		return nil, rerr
	}
	return parseNTP(resp, tx, t3, reqTX)
}

func deadlineOr(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(3 * time.Second)
}

func parseNTP(resp []byte, t0, t3 time.Time, reqTX uint64) (*ntpSample, error) {
	if len(resp) < 48 {
		return nil, fmt.Errorf("%w：只有 %d 字节", errNTPFormat, len(resp))
	}
	vn := (resp[0] >> 3) & 0x7
	mode := resp[0] & 0x7
	if mode != 4 && mode != 5 && mode != 1 {
		// 4=server、5=broadcast、1=symmetric active：都带着需要的时间戳
		return nil, fmt.Errorf("%w：mode=%d", errNTPFormat, mode)
	}
	// ★ 认回包：OriginTimestamp（24:32）里应当是**我们发出去时盖的那个戳**。
	// 对不上说明这个包不是对我们那次问的答复 —— 拿它算偏差会得到一个来历不明的数字。
	// NTP 没有事务 ID 可依赖（那是 DNS 的东西）， originate 戳就是这里唯一的凭据。
	if o := binary.BigEndian.Uint64(resp[24:32]); o != reqTX {
		return nil, fmt.Errorf("%w：回包里的原始时间戳和这次问的对不上", errNTPFormat)
	}
	stratum := int(resp[1])
	li := resp[0] >> 6
	sRX := ntpToTime(binary.BigEndian.Uint64(resp[32:40]))
	sTX := ntpToTime(binary.BigEndian.Uint64(resp[40:48]))
	s := &ntpSample{stratum: stratum, refID: refIDString(resp[12:16]), localTime: t0}
	if stratum == 0 {
		// stratum 0 时那 4 字节不是参考时钟，而是拒答原因码（KoDR）
		return s, &ntpKiss{code: refIDString(resp[12:16])}
	}
	// 时钟同步告警：LI=1 要插入闰秒、LI=2 说明这一分钟被删过一秒。不当错误，
	// 但那是「接下来 24 小时里对时会有 1 秒台阶」的现场信号，留着比丢掉有用。
	switch li {
	case 1:
		s.leap = "insert"
	case 2:
		s.leap = "delete"
	}
	if sRX.IsZero() || sTX.IsZero() {
		return nil, fmt.Errorf("%w：服务器时间戳是空的", errNTPFormat)
	}
	s.serverTime = sTX
	// 记 d1 = 服务器收到 - 本机发出，d2 = 服务器发出 - 本机收到（两者都是有符号的）：
	//   偏差 θ = (d1 + d2) / 2，往返 δ = (t3-t0) - (t2-t1) = d1 - d2。
	// ★ θ 的符号按 NTP 的口径来：**正 = 本机的钟落后**（要往前调）。
	//   写成「本机快」就把结论反了 —— 这是这个工具唯一不可挽回的一种错法。
	d1 := float64(sRX.Sub(t0)) / float64(time.Millisecond)
	d2 := float64(sTX.Sub(t3)) / float64(time.Millisecond)
	s.offset = (d1 + d2) / 2
	s.rtt = d1 - d2
	if s.rtt < 0 {
		// 服务器自己的钟在跳（未同步的 stratum 源会这样）：算出负的往返说明这次问答对不上，
		// 不许把它当成「往返 0 毫秒的高置信样本」用掉。
		return nil, fmt.Errorf("%w：往返算成负数（服务器时钟未同步或在跳）", errNTPFormat)
	}
	if vn != 4 {
		s.refID += "/v" + strconv.Itoa(int(vn))
	}
	return s, nil
}

func ntpFromTime(t time.Time) uint64 {
	sec := uint64(t.Unix() + ntpEpochDelta)
	// 纳秒按小数折算成 2^32 分之几：整除会把纳秒抹成 0，等于自己丢掉亚微秒精度
	frac := uint64(float64(t.Nanosecond()) / float64(time.Second) * fracFull)
	return sec<<32 | frac
}

// fracFull 是 NTP 小数部分的满量程（2^32）。写成常量而不是 uint32(1)<<32 —— 后者会溢出。
const fracFull = 4294967296.0

func ntpToTime(v uint64) time.Time {
	sec := int64(v>>32) - ntpEpochDelta
	frac := float64(v&0xffffffff) / fracFull
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(sec, int64(frac*float64(time.Second)))
}

func refIDString(b []byte) string {
	// stratum 1 的 refID 是 "GPS\0"、"PPS\0" 这类标签；更高层是 IPv4 或哈希前 4 字节
	if allPrintable(b) {
		return strings.TrimRight(string(b), "\x00 ")
	}
	if len(b) == 4 {
		ip, err := netip.ParseAddr(fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]))
		if err == nil {
			return ip.String()
		}
	}
	return fmt.Sprintf("%x", b)
}

func allPrintable(b []byte) bool {
	for _, c := range b {
		if c == 0 || (c >= ' ' && c <= '~') {
			continue
		}
		return false
	}
	return true
}
