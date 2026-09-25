package tools

// net.speed.test —— 到公网那一头有多快：下载、上传、往返、抖，v4 与 v6 各钉一条栈量一遍。
//
// ★★ 为什么这张卡非要存在：现场那句「网慢」，多数问的不是局域网，是「出去公网关没关」。
//
//	局域网对测（net.throughput.*）量的是内圈，量不到出口那条路；
//	而浏览器只会说「加载失败」，不会说它当时走的是 v4 还是 v6。
//
// ★★ 为什么不预设任何测速服务器：这个软件不替用户去碰别人家的机器。
//	目标由人填，填了才动；没目标就判 speed-no-target，这一趟一个包都不替你发。
//
// ★ 为什么两栈要分开钉：拿名字去连时栈由系统挑，两个栈混在一个数里 ——
//	现场最常见的「v6 路由不通所以整体慢」正好被平均掉。所以先把名字解成两栈的地址，
//	再各自钉死一条栈去连（SNI 与证书仍按名字给，钉地址不是为了绕证书）。

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

var speedTestTool = ots.Tool{
	Name:  "net.speed.test",
	Class: ots.ClassMutate,
	Summary: "往**你填的那个地址**量四件事：下载多快、上传多快、往返多少毫秒、往返抖不抖；" +
		"IPv4 与 IPv6 各钉一条栈单独测，两本账并排放。" +
		"★ 不预设任何测速服务器：没给目标就判 speed-no-target，这一趟一个包都不替你发。" +
		"下载是 GET 读到你给的上限为止，读到的正文直接丢掉不落盘；" +
		"上传是 POST 一段纯填充字节（不含本机任何内容），多少由秒数与 maxMiB 两道闸共同卡住。" +
		"★ 算 mutate：它会往你点名的那台服务器发一批数据，对面可能把它存下来 —— 批准框里逐条写着发多少、发到哪。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "url": {"type": "string",
	      "description": "下载地址（http/https）。不写协议时默认按 https 试。地址里的账号密码不会回显（结果和日志里都打码）。这一趟只量这一个名字下的目标。"},
	    "uploadUrl": {"type": "string",
	      "description": "收 POST 的地址，用来量上传。必须与 url 同一个名字（端口可以不同），否则报参数错 —— 要量两家就分两趟跑。不填就不测上传。"},
	    "host": {"type": "string",
	      "description": "只填一个名字或地址，只量往返不搬数据。已有 url/uploadUrl 时忽略它。可以带端口（host:8080），IPv6 带方括号或不带都认。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "量往返打在哪一口。地址里带了端口就以地址里的为准。默认 443。"},
	    "allowPrivate": {"type": "boolean",
	      "description": "目标是内网/本机地址时要不要照量。默认关：那句「出去公网有多快」拿内网的数来答是错的，而且默认就把几十上百 MiB 打进现场一台弱交换机更是错的。打开后判定会写明这是内网的数。"},
	    "family": {"type": "string", "enum": ["auto", "v4", "v6"],
	      "description": "量哪条栈，默认 auto（两条各跑一遍，结果并排放）。填 v6 而那个名字没有 AAAA 记录时，判 speed-single-family 而不是给你一个 0。"},
	    "seconds": {"type": "integer", "minimum": 1, "maximum": 30,
	      "description": "每一头最多搬几秒，默认 5。★ 这道闸只管搬数据那一段，建连与 TLS 握手另算，所以秒数给小也不会把快路误报成到点。"},
	    "maxMiB": {"type": "integer", "minimum": 1, "maximum": 512,
	      "description": "每一头最多搬多少 MiB，默认 64。到这道闸收的会明写成下界（speed-capped），不当成实测上限。"},
	    "connects": {"type": "integer", "minimum": 1, "maximum": 50,
	      "description": "量往返打几发，默认 10。那个口明确回了「拒」就当场收表，不会把十发全等完。"}
	  }
	}`),
	Describe: describeSpeedTest,
	Invoke:   doSpeedTest,
}

// 判定码。★ 顺序就是证据的先后：先问「这个目标算不算公网」，再问「那条路说得上话吗」，
// 最后才轮到「这本账说明什么」。
const (
	speedNoTarget     = "speed-no-target"     // 一个目标都没给：不替你发
	speedLocalTarget  = "speed-local-target"  // 目标其实还在自己家：这个数不代表出去公网
	speedUnreachable  = "speed-unreachable"   // 一次都没连上（关着与一声不响在账里分开）
	speedFlaky        = "speed-flaky"         // 连得上但有几发没通：这条路本身在抖
	speedBadStatus    = "speed-bad-status"    // 目标回的不是数据（4xx/5xx），速率数不代表链路
	speedCutShort     = "speed-cut-short"     // 搬到一半断了：速率按真搬了多久算
	speedCapped       = "speed-capped"        // 到秒数或字节闸收的：这个数是下界不是实测上限
	speedLatencyOnly  = "speed-latency-only"  // 只给了 host：只量到往返，没量到快慢
	speedOneSided     = "speed-one-sided"     // 下载与上传只测到一头
	speedSingleFamily = "speed-single-family" // 只有一条栈量到了（另一栈那个名字下没地址）
	speedOK           = "speed-ok"
)

// 每一头搬数据收尾的方式。★ 必须分开写：「读完了」和「到秒数收的」给出同一个速率，
// 前者是实测，后者只是下界 —— 混在一起就会让人拿下限去和运营商合同比。
const (
	xferComplete = "complete" // 对边给的那份，读满/发满了
	xferTimeCap  = "time-cap" // 秒数到点收的
	xferByteCap  = "byte-cap" // maxMiB 到闸收的（它还有，我们不再读）
	xferCut      = "cut"      // 中途断的（连接重置、读到一半没声、TLS 坏了）
	xferFailed   = "failed"   // 连上之前就没成，一个字节都没搬
)

type speedArgs struct {
	URL          string `json:"url,omitempty"`
	UploadURL    string `json:"uploadUrl,omitempty"`
	Host         string `json:"host,omitempty"`
	Port         int    `json:"port,omitempty"`
	Family       string `json:"family,omitempty"` // auto（默认）/ v4 / v6
	Seconds      int    `json:"seconds,omitempty"`
	MaxMiB       int    `json:"maxMiB,omitempty"`
	Connects     int    `json:"connects,omitempty"`
	AllowPrivate bool   `json:"allowPrivate,omitempty"`
}

const (
	speedDefaultSeconds  = 5
	speedMaxSeconds      = 30
	speedDefaultMaxMiB   = 64
	speedMaxMaxMiB       = 512
	speedDefaultConnects = 10
	speedMaxConnects     = 50
	speedDialTimeout     = 2 * time.Second
	speedResolveTimeout  = 8 * time.Second
	// 往返连不发满就把表收掉：一个已经拒了的口再问九次还是拒，
	// 白等九拍；这里要的是「这条路现在什么样」，不是重试次数。
	speedRTTStopAfter = 3
)

func describeSpeedTest(raw json.RawMessage) string {
	var a speedArgs
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &a)
	}
	seconds, maxMiB, connects := speedLimits(a)
	var b strings.Builder
	b.WriteString("这一趟会往你点名的目标发这些数据，请逐条看过再放行：\n")
	if a.URL != "" {
		b.WriteString("- 向 " + redactString(a.URL) + " 发一个 GET，读到的正文直接丢掉（不落盘、不上传给任何人）\n")
	}
	if a.UploadURL != "" {
		b.WriteString("- 向 " + redactString(a.UploadURL) + " POST 最多 " + itoa(maxMiB) +
			" MiB 的**纯填充字节**（不是本机文件，也不含本机任何内容），对面可能把它存下来\n")
	}
	if a.URL == "" && a.UploadURL == "" {
		b.WriteString("- 只对 " + redactString(a.Host) + " 打最多 " + itoa(connects) + " 次 TCP 连接量往返，不搬数据\n")
	}
	b.WriteString("- 每头最长 " + itoa(seconds) + " 秒；IPv4 与 IPv6 各跑一遍，所以最坏时间是它的两倍\n")
	b.WriteString("- 目标解出来是内网或本机地址时，默认一个字节都不发（判 speed-local-target）\n")
	if a.AllowPrivate {
		b.WriteString("- ★ 你勾了「内网目标也照量」：默认这一趟不给内网/本机地址搬数据，" +
			"打开后就会真往那台上打 " + itoa(maxMiB) + " MiB —— 弱的内网设备可能被打趴，确认那是你自己的测试机\n")
	}
	b.WriteString("- 域名解析用的是本机配的那台 DNS；结果里不带任何凭据（地址里的账号密码会打码）")
	return b.String()
}

func speedLimits(a speedArgs) (seconds, maxMiB, connects int) {
	seconds = clampInt(a.Seconds, speedDefaultSeconds, 1, speedMaxSeconds)
	maxMiB = clampInt(a.MaxMiB, speedDefaultMaxMiB, 1, speedMaxMaxMiB)
	connects = clampInt(a.Connects, speedDefaultConnects, 1, speedMaxConnects)
	return seconds, maxMiB, connects
}

func clampInt(v, def, lo, hi int) int {
	if v <= 0 {
		return def
	}
	if v > hi {
		return hi
	}
	if v < lo {
		return lo
	}
	return v
}

// speedSide 是一条栈（v4 或 v6）的整份账。
type speedSide struct {
	Family  string     `json:"family"`
	Addr    string     `json:"addr,omitempty"`
	Skip    string     `json:"skipped,omitempty"` // no-address / local
	Private bool       `json:"private,omitempty"` // 这一栈量的是内网，不是公网
	Lat     *speedRT   `json:"latency,omitempty"`
	Down    *speedXfer `json:"download,omitempty"`
	Up      *speedXfer `json:"upload,omitempty"`
}

// speedRT 是往返那本账。
type speedRT struct {
	Sent     int       `json:"sent"`      // 打算发几发
	Done     int       `json:"connected"` // 真连上的几发
	Refused  int       `json:"refused"`   // 被明确拒了（那口关着）
	TimedOut int       `json:"timedOut"`  // 一声不响
	Other    int       `json:"other"`     // 别的错（没有路由、网络不可达…）
	Untried  int       `json:"untried"`   // 提前收表没发的
	MinMS    float64   `json:"minMs"`
	AvgMS    float64   `json:"avgMs"`
	MedMS    float64   `json:"medMs"`
	P95MS    float64   `json:"p95Ms"`
	MaxMS    float64   `json:"maxMs"`
	JitterMS float64   `json:"jitterMs"`
	Samples  []float64 `json:"-"`
}

// speedXfer 是一头（下载或上传）的账。
type speedXfer struct {
	URL     string  `json:"url"`
	Status  int     `json:"status,omitempty"`
	Bytes   int64   `json:"bytes"`
	MS      int64   `json:"ms"`
	Mbps    float64 `json:"mbps"`
	TTFBMs  float64 `json:"ttfbMs,omitempty"`
	Length  int64   `json:"contentLength,omitempty"` // 它说这份多大；不给就是 0
	End     string  `json:"end"`                     // complete / time-cap / byte-cap / cut / failed
	ErrKind string  `json:"errKind,omitempty"`       // refused / timeout / reset / tls / other
	Err     string  `json:"error,omitempty"`
}

func doSpeedTest(ctx context.Context, raw json.RawMessage) (any, error) {
	var a speedArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	seconds, maxMiB, connects := speedLimits(a)
	a.URL = strings.TrimSpace(a.URL)
	a.UploadURL = strings.TrimSpace(a.UploadURL)
	a.Host = strings.TrimSpace(a.Host)
	if a.URL == "" && a.UploadURL == "" && a.Host == "" {
		return ots.Verdict{Code: speedNoTarget, Values: map[string]any{
			"seconds": seconds, "maxMiB": maxMiB, "connects": connects,
		}, Note: "没给目标 —— 这一趟一个包都不发。填一个下载地址（http/https）量下载，" +
			"要测上传再另填一个收 POST 的地址；只填 host 就只量往返。"}, nil
	}
	dl, err := speedParseURL(a.URL)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "下载地址：%s", err)
	}
	ul, err := speedParseURL(a.UploadURL)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "上传地址：%s", err)
	}
	name, port, err := speedTarget(dl, ul, a.Host, a.Port)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	want := strings.ToLower(strings.TrimSpace(a.Family))
	if want == "" {
		want = "auto"
	}
	switch want {
	case "auto", "v4", "v6":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "family 只能填 auto / v4 / v6，给的是 %q", a.Family)
	}

	v4, v6, err := speedResolve(ctx, name)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%q 解不出地址：%s", name, err)
	}
	asked := 1
	if want == "auto" {
		asked = 2
	}
	values := map[string]any{
		"target":        name,
		"port":          port,
		"seconds":       seconds,
		"maxMiB":        maxMiB,
		"connects":      connects,
		"family":        want,
		"v4Addresses":   addrList(v4),
		"v6Addresses":   addrList(v6),
		"askedFamilies": asked,
	}

	sides := make([]*speedSide, 0, 2)
	if want != "v6" {
		sides = append(sides, speedRunSide(ctx, "v4", v4, port, dl, ul, seconds, maxMiB, connects, a.AllowPrivate))
	}
	if want != "v4" {
		sides = append(sides, speedRunSide(ctx, "v6", v6, port, dl, ul, seconds, maxMiB, connects, a.AllowPrivate))
	}
	jsonSides := make([]map[string]any, 0, len(sides))
	for _, s := range sides {
		jsonSides = append(jsonSides, speedSideJSON(s))
	}
	values["sides"] = jsonSides
	return speedVerdict(values, sides, asked, seconds, maxMiB)
}

// speedRunSide 跑一条栈。这一栈压根没地址时只记一句为什么，不编任何数字。
//
// ★ allowPrivate=false（默认）时内网地址直接不收这一趟：那句「出去公网有多快」
//
//	拿内网的数来答是错的，而默认就把 512 MiB 打进现场一台弱交换机更是错的。
//	要量内网请显式打开，打开之后判定照样写明这不是公网。
func speedRunSide(ctx context.Context, fam string, ips []net.IP, port int, dl, ul *url.URL,
	seconds, maxMiB, connects int, allowPrivate bool) *speedSide {
	if len(ips) == 0 {
		return &speedSide{Family: fam, Skip: "no-address"}
	}
	ip := ips[0]
	private := speedIsInner(ip)
	if private && !allowPrivate {
		return &speedSide{Family: fam, Addr: ip.String(), Skip: "local"}
	}
	s := &speedSide{Family: fam, Addr: ip.String(), Private: private}
	s.Lat = speedMeasureRTT(ctx, ip, port, connects)
	// 往返一发都没通就别再去搬数据：那时下载只会把同一个不通再说一遍，
	// 还多花掉几秒 —— 那几秒留给「先去看那条路通不通」。
	if s.Lat.Done == 0 {
		return s
	}
	if dl != nil {
		s.Down = speedTransfer(ctx, dl, ip, seconds, maxMiB, false)
	}
	if ul != nil {
		s.Up = speedTransfer(ctx, ul, ip, seconds, maxMiB, true)
	}
	return s
}

// speedIsInner 是不是「其实还在自己家」。
//
// ★ 单独分出来，因为这类目标测出来的数**很好看但那不是公网**：
//
//	填成 192.168.1.1、127.0.0.1 时给一个公网速率，比不给数更害人。
func speedIsInner(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// speedParseURL 只收 http/https：别的协议这一趟不代跑（要测就用它自己那张卡）。
func speedParseURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%q 读不成一个地址（%v）", s, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("只支持 http/https，给的是 %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%q 里没有主机名", redactURL(u))
	}
	return u, nil
}

// speedTarget 取出这一趟真正要问的名字与量往返的端口。
//
// ★ 要求下载与上传写在同一个名字下：这一趟只量一个目标，
//
//	两个名字的话「v4 那条路多快」就说不清是谁的路了。端口可以不同。
func speedTarget(dl, ul *url.URL, host string, portArg int) (string, int, error) {
	var urls []*url.URL
	if dl != nil {
		urls = append(urls, dl)
	}
	if ul != nil {
		urls = append(urls, ul)
	}
	if len(urls) > 0 {
		name := urls[0].Hostname()
		for _, u := range urls[1:] {
			if !strings.EqualFold(u.Hostname(), name) {
				return "", 0, fmt.Errorf("下载与上传不在同一个名字下（%s 与 %s）—— 这一趟只量一个目标，分开跑两趟",
					name, u.Hostname())
			}
		}
		return name, speedURLOrArgPort(urls[0], portArg), nil
	}
	return speedTargetHost(host, portArg)
}

// speedURLOrArgPort：地址里写了端口就用它，没写按协议默认。
func speedURLOrArgPort(u *url.URL, portArg int) int {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	if portArg > 0 {
		return portArg
	}
	return speedDefaultPort(u.Scheme)
}

func speedDefaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// speedTargetHost 处理只填 host 的那种写法：光一个地址、host:port、[v6]:port 都认。
func speedTargetHost(host string, portArg int) (string, int, error) {
	// 先试 IP 字面量：v6 地址里满是冒号，不能拿 SplitHostPort 的报错当依据往下切。
	if h := strings.Trim(host, "[]"); net.ParseIP(h) != nil {
		if portArg <= 0 {
			portArg = 443
		}
		if portArg > 65535 {
			return "", 0, fmt.Errorf("端口 %d 不在 1-65535 之间", portArg)
		}
		return h, portArg, nil
	}
	h := host
	port := portArg
	if hh, pp, err := net.SplitHostPort(host); err == nil {
		n, cerr := strconv.Atoi(pp)
		if cerr != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("端口 %q 不在 1-65535 之间", pp)
		}
		h, port = hh, n
	}
	if h == "" {
		return "", 0, fmt.Errorf("没给目标")
	}
	if port <= 0 {
		port = 443
	}
	return strings.Trim(h, "[]"), port, nil
}

// speedResolve 把名字解成两条栈各自的地址列表（走本机配的那台 DNS）。
// 字面 IP 就直接用 —— 现场经常拿 IP 问，那时「另一栈没地址」是事实而不是故障。
func speedResolve(ctx context.Context, name string) (v4, v6 []net.IP, err error) {
	if ip := net.ParseIP(name); ip != nil {
		if ip.To4() != nil {
			return []net.IP{ip}, nil, nil
		}
		return nil, []net.IP{ip}, nil
	}
	cctx, cancel := context.WithTimeout(ctx, speedResolveTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(cctx, "ip", name)
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, nil, fmt.Errorf("它一条地址都没给")
	}
	return v4, v6, nil
}

func addrList(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// speedMeasureRTT 打 connects 次 TCP 连接量往返。
//
// ★ 这里量的是**建连那一趟**的耗时，等于一个 RTT，不是 ICMP 的往返：
//
//	不开放权限就能在用户机器上跑，而且量的正是「这条路现在接不接受我」。
//	所以它和 net.ping 那两个数不等长是应该的，界面上各说各的。
func speedMeasureRTT(ctx context.Context, ip net.IP, port, connects int) *speedRT {
	rt := &speedRT{Sent: connects}
	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	network := "tcp4"
	if ip.To4() == nil {
		network = "tcp6"
	}
	d := &net.Dialer{}
	silentRun := 0
	for i := 0; i < connects; i++ {
		if err := ctx.Err(); err != nil {
			rt.Untried = connects - i
			break
		}
		dctx, cancel := context.WithTimeout(ctx, speedDialTimeout)
		t0 := time.Now()
		c, err := d.DialContext(dctx, network, target)
		elapsed := ms(time.Since(t0))
		cancel()
		// ★ 收尾分两种：**确定性**的错（那个口明说拒了、本机没这一栈的路）一发就够，当场收表；
		//	**没声**的错要连着攒到第三发才敢断定 —— 单发超时可能是路边抖了一下，
		//	而「连得上但有几发没通」这件事本身就是要报给用户的信息。
		if err != nil {
			var werr *net.OpError
			deterministic := errors.Is(err, syscall.ECONNREFUSED)
			switch {
			case deterministic:
				rt.Refused++
			case errors.As(err, &werr) && werr.Err != nil && !isTimeout(werr.Err):
				rt.Other++
				deterministic = true
			case isTimeout(err):
				rt.TimedOut++
			default:
				rt.Other++
			}
			if deterministic {
				rt.Untried = connects - i - 1
				break
			}
			silentRun++
			if silentRun >= speedRTTStopAfter {
				rt.Untried = connects - i - 1
				break
			}
			continue
		}
		_ = c.Close()
		rt.Done++
		rt.Samples = append(rt.Samples, elapsed)
	}
	rt.Sent = connects - rt.Untried
	if len(rt.Samples) > 0 {
		sorted := append([]float64(nil), rt.Samples...)
		sort.Float64s(sorted)
		rt.MinMS = roundMS2(sorted[0])
		rt.MaxMS = roundMS2(sorted[len(sorted)-1])
		rt.MedMS = roundMS2(nearestRank(sorted, 50))
		rt.P95MS = roundMS2(nearestRank(sorted, 95))
		var sum float64
		for _, v := range rt.Samples {
			sum += v
		}
		rt.AvgMS = roundMS2(sum / float64(len(rt.Samples)))
		// ★ 抖动按发的先后算，不按大小：要的是「上一发和这一发差多少」。
		rt.JitterMS = roundMS2(speedJitter(rt.Samples))
	}
	return rt
}

// speedJitter 是 RFC 3550 那个「相邻两发落差」的平均。
func speedJitter(samples []float64) float64 {
	if len(samples) < 2 {
		return 0
	}
	var jit float64
	for i := 1; i < len(samples); i++ {
		d := samples[i] - samples[i-1]
		if d < 0 {
			d = -d
		}
		jit += d
	}
	return jit / float64(len(samples)-1)
}

// speedTimer 管「搬运那一段」的表：从第一个真上路的字节起算，到秒数就把这次请求断掉。
//
// ★★ 为什么不能用 context.WithTimeout 一次算到位：POST 的正文是在 cl.Do **里面**
//
//	写完的，而响应头要等对面存完文件才回来。表从请求起算的话，秒数一到
//	连「已经搬完了、正在等回执」也被掐断 —— 上传慢被记成「没搬完」，正好记反。
//	所以这道表**到搬运真正开始那一刻才上弦**。
type speedTimer struct {
	mu     sync.Mutex
	start  time.Time
	fired  bool
	cancel func()
	secs   int
	timer  *time.Timer
}

func (t *speedTimer) arm(secs int, cancel func()) {
	t.mu.Lock()
	t.secs, t.cancel = secs, cancel
	t.mu.Unlock()
}

// begin 上弦；已经上过就什么也不做（第一个字节之后每交一次都会调它）。
func (t *speedTimer) begin() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.start.IsZero() || t.cancel == nil {
		return
	}
	t.start = time.Now()
	d := time.Duration(t.secs) * time.Second
	t.timer = time.AfterFunc(d, func() {
		t.mu.Lock()
		t.fired = true
		t.mu.Unlock()
		t.cancel()
	})
}

func (t *speedTimer) stop() {
	t.mu.Lock()
	if t.timer != nil {
		t.timer.Stop()
	}
	t.mu.Unlock()
}

// hit 是「这次断是我这道表掐的」—— 用它把「到点收的」和「半路断了」分开。
func (t *speedTimer) hit() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fired
}

// window 是搬运那一段已经走了多久。没上过弦给 0。
func (t *speedTimer) window() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.start.IsZero() {
		return 0
	}
	return time.Since(t.start)
}

// quietCut 判「这一头到底搬没搬起来」：
// 表没到点却已经收在读上、或者一个字都没过来，那就不是上限而是这条路没下文。
func (t *speedTimer) quietCut(bytes int64) bool {
	if bytes == 0 {
		return true
	}
	return !t.hit() && t.window() > 500*time.Millisecond && bytes < 4<<10
}

// speedTransfer 搬一头。上传那头的正文是纯填充字节，本函数不读本机任何文件。
//
// ★★ 两道表分开上：一道管「建连 + 握手 + 等到响应头」（在 transport 上），
//
//	另一道管**搬数据的那几秒**（speedTimer，第一个字节上路才上弦）。
//	合成一道的话，握手慢掉两秒会把「搬满五秒」误报成「到点只搬了三秒」。
func speedTransfer(ctx context.Context, u *url.URL, ip net.IP, seconds, maxMiB int, upload bool) *speedXfer {
	x := &speedXfer{URL: redactURL(u), End: xferFailed}
	maxBytes := int64(maxMiB) << 20
	method := http.MethodGet
	var body io.Reader
	if upload {
		method = http.MethodPost
		body = io.LimitReader(speedPadding(), maxBytes)
	}
	tctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, method, u.String(), body)
	if err != nil {
		x.ErrKind = "other"
		x.Err = err.Error()
		return x
	}
	var gate speedTimer
	gate.arm(seconds, cancel)
	var clock speedClock
	if upload {
		req.ContentLength = maxBytes
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Body = &speedCounter{R: req.Body, N: &x.Bytes, Clock: &clock, Gate: &gate}
	}

	t0 := time.Now()
	cl := &http.Client{Transport: speedPinnedTransport(ip, u), CheckRedirect: func(*http.Request, []*http.Request) error {
		// ★ 跟着一跳走就不在这条路上量了，数会算到别家身上：把重定向如实报成一次 3xx。
		return http.ErrUseLastResponse
	}}
	res, err := cl.Do(req)
	gate.stop()
	if err != nil {
		x.MS = maxInt64(time.Since(t0).Milliseconds(), 1)
		x.Err = err.Error()
		x.ErrKind = speedErrKind(err)
		switch {
		case gate.hit() && x.Bytes > 0:
			// 上传写出去的那一截是真的出去了 —— 表到点就按时间封顶报，别报成 0。
			x.End = xferTimeCap
			x.Mbps = mbpsOf(x.Bytes, maxInt64(clock.ms(), 1))
		default:
			x.End = xferFailed
		}
		return x
	}
	defer res.Body.Close()
	x.Status = res.StatusCode
	x.TTFBMs = roundMS2(float64(time.Since(t0)) / float64(time.Millisecond))
	// ★ 只有下载才把它的 Content-Length 当「这份多大」记下来：
	//	上传那份回执的大小是对面回的一句话，跟这份多大没有关系，记进去就成了假账。
	if !upload {
		if n, e := strconv.ParseInt(res.Header.Get("Content-Length"), 10, 64); e == nil && n > 0 {
			x.Length = n
		}
	}

	if upload {
		// 正文在 Do 里面就写完了，这里只把回执读一小截丢掉。
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
		switch {
		case res.StatusCode >= 400:
			x.End = xferFailed
		case x.Bytes < maxBytes:
			// 没写满就被叫停了：要么表到点，要么这条路半路断了。
			if gate.hit() {
				x.End = xferTimeCap
			} else {
				x.End = xferCut
			}
		default:
			x.End = xferComplete
		}
	} else if res.StatusCode >= 400 {
		x.End = xferFailed
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
	} else {
		// 下载这一段自己读、自己上弦，才能把「到点」与「断了」分清。
		x.End = speedDrain(&clock, &gate, tctx, res.Body, &x.Bytes, maxBytes)
	}
	// ★ 速率只按**真在搬的那一段**算：从第一个上路/到达的字节到最后一个。
	//	把建连、握手、对面存文件的时间混进分母，就是把网络和应用两头的账搅在了一句里。
	//	快得量不出来时按 1 ms 记（回环上就是这样）：宁可高估这一段的快，
	//	也不许退回整窗口 —— 一退回，对面回执慢两秒就成了「这条路只跑这么快」。
	ms := clock.ms()
	if ms <= 0 {
		ms = 1
	}
	x.MS = ms
	x.Mbps = mbpsOf(x.Bytes, ms)
	return x
}

// speedClock 记下第一个与最后一个真上路的字节是什么时候。
type speedClock struct {
	first time.Time
	last  time.Time
}

func (c *speedClock) tick() {
	now := time.Now()
	if c.first.IsZero() {
		c.first = now
	}
	c.last = now
}

// ms 是搬运那一段的时长。只搬了一下的时候给 0，让调用方退回整窗口。
func (c *speedClock) ms() int64 {
	if c.first.IsZero() || c.last.Sub(c.first) <= 0 {
		return 0
	}
	return int64(c.last.Sub(c.first) / time.Millisecond)
}

// speedDrain 把下载读空，按收尾的原因归类。
//
// ★ 读到的字节直接丢：这一趟要的是「这条路能搬多快」，不是那份文件。
//
//	表的弦也在这里上 —— 第一个字节过来才开始算那几秒。
func speedDrain(clock *speedClock, gate *speedTimer, ctx context.Context, r io.Reader, n *int64, maxBytes int64) string {
	gate.begin()
	buf := make([]byte, 64<<10)
	for {
		want := len(buf)
		if left := maxBytes - *n; left < int64(want) {
			// ★ 按剩下的量读：一buf 读过头了，报出去的字节数就比闸大，
			//	「按 1 MiB 收的」那句也成了假话。
			if left <= 0 {
				return xferByteCap
			}
			want = int(left)
		}
		read, err := r.Read(buf[:want])
		if read > 0 {
			*n += int64(read)
			clock.tick()
			gate.begin()
		}
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				if gate.quietCut(*n) {
					// 它 200 了却几乎什么都没给：那不叫「搬完了」，是这条路没下文。
					return xferCut
				}
				return xferComplete
			case gate.hit():
				return xferTimeCap // 表到点收的：这个数是下界
			case ctx.Err() != nil:
				return xferCut // 上面这一趟被叫停（父级取消），不是我们量满了
			default:
				return xferCut
			}
		}
		if *n >= maxBytes {
			return xferByteCap // 它还有，我们按闸收的 —— 这个数是下界
		}
	}
}

// speedErrKind 把「连上之前/之中」的错归到四类：关着、静默、TLS、别的。
// ★ 这四类的处理方向不同（去开服务 / 去查防火墙 / 去换证书 / 去看客户端），不许并成一类。
func speedErrKind(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case isTimeout(err):
		return "timeout"
	default:
		s := strings.ToLower(err.Error())
		if strings.Contains(s, "tls") || strings.Contains(s, "x509") || strings.Contains(s, "handshake") ||
			strings.Contains(s, "certificate") {
			return "tls"
		}
		return "other"
	}
}

// speedPinnedTransport 把这一趟钉死在指定那条栈的那个地址上。
//
// ★ 名字仍留在 URL 与 SNI 里，HTTPS 的证书照常按名字校验 ——
//
//	钉地址是为了让「v4 的数」和「v6 的数」各归各，不是为了绕证书。
//	关掉压缩：开着的话读到的是解压后的字节，那比线上真搬的多，速率会算高。
func speedPinnedTransport(ip net.IP, u *url.URL) *http.Transport {
	d := &net.Dialer{Timeout: speedDialTimeout}
	network := "tcp4"
	if ip.To4() == nil {
		network = "tcp6"
	}
	port := u.Port()
	if port == "" {
		port = strconv.Itoa(speedDefaultPort(u.Scheme))
	}
	remote := net.JoinHostPort(ip.String(), port)
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, remote)
		},
		ForceAttemptHTTP2:   false, // ★ 一条流上跑多路复用会把「这一条路多快」糊成一团
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{ServerName: u.Hostname()},
		TLSHandshakeTimeout: speedDialTimeout + 3*time.Second,
	}
}

// speedPadding 是一段写法确定的填充字节：不是随机数（那样白烧 CPU），
// 也不含本机任何内容 —— 批准框里那句「纯填充字节」说的就是这个。
func speedPadding() io.Reader {
	return &speedPad{chunk: speedPadBytes(64 << 10)}
}

func speedPadBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 13)
	}
	return b
}

type speedPad struct {
	chunk []byte
	i     int
}

func (p *speedPad) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	n := copy(dst, p.chunk[p.i:])
	p.i = (p.i + n) % len(p.chunk)
	return n, nil
}

// speedCounter 数出真交出去的字节，并给每次交接盖时间戳 ——
// 上传的速率要用它，不能用「客户端整个请求返回」的时间。
type speedCounter struct {
	R     io.Reader
	N     *int64
	Clock *speedClock
	Gate  *speedTimer
}

func (c *speedCounter) Read(p []byte) (int, error) {
	n, err := c.R.Read(p)
	if n > 0 {
		if c.N != nil {
			*c.N += int64(n)
		}
		if c.Clock != nil {
			c.Clock.tick()
		}
		if c.Gate != nil {
			c.Gate.begin()
		}
	}
	return n, err
}

func (c *speedCounter) Close() error { return nil }

func speedSideJSON(s *speedSide) map[string]any {
	out := map[string]any{"family": s.Family}
	if s.Skip != "" {
		out["skipped"] = s.Skip
		if s.Addr != "" {
			out["addr"] = s.Addr
		}
		return out
	}
	out["addr"] = s.Addr
	if s.Private {
		out["private"] = true
	}
	if s.Lat != nil {
		out["latency"] = map[string]any{
			"sent": s.Lat.Sent, "connected": s.Lat.Done, "refused": s.Lat.Refused,
			"timedOut": s.Lat.TimedOut, "other": s.Lat.Other, "untried": s.Lat.Untried,
			"minMs": s.Lat.MinMS, "avgMs": s.Lat.AvgMS, "medMs": s.Lat.MedMS,
			"p95Ms": s.Lat.P95MS, "maxMs": s.Lat.MaxMS, "jitterMs": s.Lat.JitterMS,
		}
	}
	if s.Down != nil {
		out["download"] = speedXferJSON(s.Down)
	}
	if s.Up != nil {
		out["upload"] = speedXferJSON(s.Up)
	}
	return out
}

func speedXferJSON(x *speedXfer) map[string]any {
	out := map[string]any{
		"url": x.URL, "bytes": x.Bytes, "ms": x.MS, "mbps": x.Mbps, "end": x.End,
	}
	if x.Status != 0 {
		out["status"] = x.Status
	}
	if x.TTFBMs > 0 {
		out["ttfbMs"] = x.TTFBMs
	}
	if x.Length > 0 {
		out["contentLength"] = x.Length
	}
	if x.ErrKind != "" {
		out["errKind"] = x.ErrKind
	}
	if x.Err != "" {
		out["error"] = x.Err
	}
	return out
}

// speedVerdict 按证据先后挑那一个码，并把那句账写在**同一份 values** 上。
//
// ★ 判定与账同源：Note 里出现的每个数都取自 sides，不另算一遍。
func speedVerdict(values map[string]any, sides []*speedSide, asked, seconds, maxMiB int) (ots.Verdict, error) {
	var (
		ran         = 0
		local       = 0
		noAddr      = 0
		privRan     = 0 // 量了、但量的是内网：数照给，那句「这不是公网」必须摆在判定里
		unreachable = make([]string, 0, 2)
		flaky       []string
		badStatus   []string
		cut         []string
		capped      []string
		measured    []string
		legs        = 0 // 真跑了的下载/上传有几头
		done        = 0 // 搬完了的有几头
		sawDown     = 0 // 这一趟带了下载地址的栈有几条
		sawUp       = 0
		miss        []string // 哪几条压根没量到 —— 「没问到」不许说成「问了没问题」
	)
	for _, s := range sides {
		switch s.Skip {
		case "no-address":
			noAddr++
			miss = append(miss, s.Family+" 那条栈那个名字下没地址，没量")
			continue
		case "local":
			local++
			miss = append(miss, s.Family+" 解出来是内网/本机地址，默认没量")
			continue
		}
		ran++
		if s.Private {
			privRan++
		}
		if s.Lat != nil && s.Lat.Done == 0 {
			why := "连不上"
			switch {
			case s.Lat.Refused > 0 && s.Lat.Refused+s.Lat.Untried >= s.Lat.Sent:
				why = "那一口关着（连接被明确拒了）"
			case s.Lat.TimedOut > 0:
				why = "一声不响（连接超时，包半路没了）"
			}
			unreachable = append(unreachable, s.Family+"："+why)
			continue
		}
		if s.Lat != nil && s.Lat.Sent > s.Lat.Done {
			flaky = append(flaky, fmt.Sprintf("%s（%d 发里连上 %d 发）", s.Family, s.Lat.Sent, s.Lat.Done))
		}
		if s.Lat != nil {
			measured = append(measured, s.Family+" 往返 "+speedFms(s.Lat.MedMS))
		}
		// ★ 两头的先后是写死的：下载在前，上传在后。
		//	拿 map 遍历的话同一份数据每次出来的句子顺序都不一样。
		for _, leg := range []struct {
			name string
			x    *speedXfer
		}{{"下载", s.Down}, {"上传", s.Up}} {
			x := leg.x
			if x == nil {
				continue
			}
			legs++
			if leg.name == "下载" {
				sawDown++
			} else {
				sawUp++
			}
			label := s.Family + " " + leg.name
			switch {
			case x.Status >= 400:
				badStatus = append(badStatus, fmt.Sprintf("%s（回 %d）", label, x.Status))
			case x.End == xferFailed:
				unreachable = append(unreachable, label+"："+speedXferWhy(x))
			case x.End == xferCut:
				cut = append(cut, fmt.Sprintf("%s（搬到 %s 就断了）", label, humanBytes(x.Bytes)))
			case x.End == xferTimeCap, x.End == xferByteCap:
				what := "秒数到点"
				if x.End == xferByteCap {
					what = "字节闸到点"
				}
				capped = append(capped, fmt.Sprintf("%s %s Mbps（%s收的）", label, ftos(x.Mbps), what))
			case x.Bytes > 0:
				done++
				measured = append(measured, fmt.Sprintf("%s %s Mbps", label, ftos(x.Mbps)))
			}
		}
	}
	values["ranFamilies"] = ran
	values["skippedNoAddress"] = noAddr
	values["skippedLocal"] = local
	values["privateFamilies"] = privRan
	values["xferLegs"] = legs
	values["xferCompleteLegs"] = done

	// ★ 拼接时把空的那截跳掉：留着就会出来「…；）」那种句子，
	//	读起来像这里本来还有半句没写出来。
	note := func(parts ...string) string {
		var keep []string
		for _, p := range parts {
			if p != "" {
				keep = append(keep, p)
			}
		}
		return strings.Join(keep, "；")
	}
	// 没量到的那几条跟在每句话后面 —— 只报量到的那些，等于把「没问到」说成「没问题」。
	missTail := func() string {
		if len(miss) == 0 {
			return ""
		}
		return "。另有没量到的：" + strings.Join(miss, "；")
	}
	switch {
	case ran == 0 && local > 0:
		return ots.Verdict{Code: speedLocalTarget, Values: values,
			Note: "你给的名字解出来全是内网或本机地址（" + strings.Join(localAddrs(sides), "、") +
				"）—— 这一趟一个字节都没打过去。要量公网，把目标换成公网上的一个地址；" +
				"确实要拿它量内网，就把 allowPrivate 打开"}, nil
	case ran == 0:
		return ots.Verdict{Code: speedSingleFamily, Values: values,
			Note: "那个名字在要问的那条栈里没有地址（v4 " + itoa(lenAny(values, "v4Addresses")) +
				" 条、v6 " + itoa(lenAny(values, "v6Addresses")) +
				" 条）—— 这一趟一个连接都没发"}, nil
	case len(unreachable) == ran && legs == 0:
		// 每一条自己带着它是被拒了还是一声不响，这里不再统一概括一遍：
		// 两条栈往往是两种病。
		return ots.Verdict{Code: speedUnreachable, Values: values,
			Note: "一次都没连上：" + strings.Join(unreachable, "；") +
				"。先用 net.tcp.probe 看那个端口开不开，再回来量快慢"}, nil
	case len(unreachable) > 0:
		return ots.Verdict{Code: speedFlaky, Values: values,
			Note: note(append([]string{"有一条路连上就没下文：" + strings.Join(unreachable, "；")},
				measured...)...) + "。已连上那几本的数照给，但整条路在抖，先去看出口设备与链路"}, nil
	case len(flaky) > 0:
		return ots.Verdict{Code: speedFlaky, Values: values,
			Note: "连接有几发没通：" + strings.Join(flaky, "、") +
				"。这条路本身在抖，速率数只能当下限看",
		}, nil
	case len(badStatus) > 0:
		return ots.Verdict{Code: speedBadStatus, Values: values,
			Note: "目标回的不是数据：" + strings.Join(badStatus, "、") +
				"。这一趟的数不代表链路，先把它自己的服务弄回来"}, nil
	case len(cut) > 0:
		return ots.Verdict{Code: speedCutShort, Values: values,
			Note: "搬到一半就断了：" + strings.Join(cut, "、") +
				"。速率按真搬了多久算，没编"}, nil
	case legs == 0:
		return ots.Verdict{Code: speedLatencyOnly, Values: values,
			Note: "只量到了往返（" + note(measured...) +
				"）—— 没给可下载/上传的地址，这一趟一个字节都没搬" + missTail()}, nil
	case privRan == ran:
		// ★ 数照给，但先说清这不是公网：拿内网的数去对运营商合同，是这一页最容易犯的错。
		//	「只量到一头」也要跟着说完 —— 换了一个更响的理由就把另一本账藏掉，
		//	等于替用户认定「内网嘛，单向够了」。
		extra := ""
		if sawDown == 0 || sawUp == 0 {
			extra = "，而且只量到了" + gotLeg(sawDown, sawUp) + "一头"
		}
		return ots.Verdict{Code: speedLocalTarget, Values: values,
			Note: "这是「内网」的数，不是出去公网的数（" + note(append(append([]string{}, measured...), capped...)...) +
				"）—— 你开了 allowPrivate，量到的是本机到那台机器之间" + extra + missTail()}, nil
	case len(capped) > 0:
		return ots.Verdict{Code: speedCapped, Values: values,
			Note: "到上限收的：" + strings.Join(capped, "、") +
				"。这个数是「下界」，不是这条路真正的顶；想看到顶就把秒数与 maxMiB 一起加大" + missTail()}, nil
	case sawDown == 0 || sawUp == 0:
		// ★ 只量到一头：另一头要么没给地址，要么给了但连上就没下文 —— 两种都不是「它慢」。
		return ots.Verdict{Code: speedOneSided, Values: values,
			Note: "只量到了" + gotLeg(sawDown, sawUp) + "一头（" + note(measured...) +
				"）—— 另一头没测到。要两本账都有，得把另一头的地址也填上；填了还没测到，就是那一头自己没通" + missTail(),
		}, nil
	case ran < asked:
		return ots.Verdict{Code: speedSingleFamily, Values: values,
			Note: itoa(ran) + " 条栈量到了，另一条栈那个名字下没地址：" + note(measured...) +
				"。没测到那条不是坏了，是这个名字没写那一栈的记录"}, nil
	default:
		return ots.Verdict{Code: speedOK, Values: values,
			Note: note(measured...) + "（每头最长 " + itoa(seconds) + " 秒、" + itoa(maxMiB) +
				" MiB；v4 与 v6 各钉一条栈量的）" + missTail()}, nil
	}
}

// gotLeg 说出**量到的那一头**叫什么。
// ★ 「只量到一头」这句话的主语是量到的那本账，不是缺的那本 —— 说反了，
//
//	人就照着去填已经填过的那一个地址。
func gotLeg(sawDown, sawUp int) string {
	if sawDown > 0 {
		return "下载"
	}
	return "上传"
}

func speedXferWhy(x *speedXfer) string {
	switch x.ErrKind {
	case "refused":
		return "连接被明确拒了"
	case "timeout":
		return "等它开口等到点"
	case "tls":
		return "TLS 握手没成"
	default:
		if x.Err != "" {
			return x.Err
		}
		return "没搬成"
	}
}

func localAddrs(sides []*speedSide) []string {
	var out []string
	for _, s := range sides {
		if s.Skip == "local" {
			out = append(out, s.Family+" "+s.Addr)
		}
	}
	return out
}

func lenAny(values map[string]any, key string) int {
	if v, ok := values[key].([]string); ok {
		return len(v)
	}
	return 0
}

func ftos(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) }

// speedFms 写毫秒数。<1ms 保留三位，1–100ms 保留一位，再往上取整：
// ★ 局域网与回环上往返就是零点零几毫秒，写成「0.1ms」和「0.0ms」看着像坏了，
//
//	而那一位小数恰恰是「这台到那台有多近」的全部信息。
func speedFms(v float64) string {
	switch {
	case v >= 100:
		return itoa(int(math.Round(v))) + "ms"
	case v >= 1:
		return strconv.FormatFloat(v, 'f', 1, 64) + "ms"
	default:
		return strconv.FormatFloat(v, 'f', 3, 64) + "ms"
	}
}
