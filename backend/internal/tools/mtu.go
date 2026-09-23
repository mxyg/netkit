package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.mtu.path ──
//
// ★ 这一栏查的病是「小包什么都好，大包过不去」：TCP 连得上、页面打得开、登录也进去了，
//   可视频一出来就卡住、传文件传到一半断 —— 因为这条路上某个环节能过的尺寸比 1500 小
//   （隧道、PPPoE、VPN、被偷偷改了 MTU 的交换机口、云上的虚拟化开销）。
//   ping 和 net.tcp.probe 都查不出这个，因为它们发的包本来就不大。
//
// ★★ 做法上唯一要紧的一点：**这个「过大被挡」的信号从哪来**。自己发 ICMP 并读回
//   「需要分片但不许分片」那个差错，要原始套接字、要管理员权限。这里换一条不要权限的路：
//   给一个连好的 UDP 套接字设「不许分片」，然后按二分法发 progressively 大的数据报，
//   看它从哪个尺寸开始发不出去 —— 内核会把「太长了」原样顶回来（EMSGSIZE），
//   不管这是本机网卡卡住的还是路上某台设备报了 ICMP「需要分片」。
//   所以**归属必须判**：只有还没到本机网卡上限就被挡住的，才是路径 MTU。

const (
	mtuCodePath     = "mtu-path"           // 路上有一个比本机网卡更小的限制，值就是它
	mtuCodeLocal    = "mtu-local"          // 没测到更小的，上限就是本机网卡的 MTU
	mtuCodeNoAnswer = "mtu-no-response"    // 连探测都收不到回执，这条路上什么都测不出来
	mtuCodeNoRoute  = "mtu-no-route"       // 本机没路，一个包都没发出去
	mtuCodeNoDF     = "mtu-df-unsupported" // 这个平台上「不许分片」设不上或设了不干活
	mtuCodeNoLimit  = "mtu-no-limit-found" // 测到这次给的上限都没被挡（结论只到「至少这么大」）
)

// 单个尺寸的探测结果。★ through / too-big 这两个是这一栏的全部信息量：
// 收到 ICMP 端口不可达（在连好的 UDP 套接字上就是 ECONNREFUSED）说明这个尺寸
// **来回都走得下**；EMSGSIZE 说明它被挡了。
const (
	mtuThrough  = "through"
	mtuTooBig   = "too-big"
	mtuSilent   = "silent"
	mtuNoRoute  = "no-route"
	mtuProbeErr = "error"
)

const (
	// 探测打在哪个端口：一个几乎不会有服务的高端口。★ 要的就是「肯定没人监听」，
	// 这样对方才会回 ICMP 端口不可达 —— 那个回执就是「这个尺寸过得去」的证据。
	defaultMTUPort = 9253
	mtuBaseSize    = 500 // 起手的尺寸，先确认这条路至少能过小包
	mtuUDPHeader   = 8
)

var mtuPathTool = ots.Tool{
	Name:  "net.mtu.path",
	Class: ots.ClassRead,
	Summary: "探到一台主机的**路径 MTU**：这条路上最大能过多少个字节（IP 包总长）。" +
		"专查「连得上、小包都好，就是大包过不去」—— 隧道 / VPN / PPPoE / 被改过 MTU 的端口都会这样，" +
		"而 ping 和端口探测查不出来，因为它们发的包本来就不大。\n" +
		"做法：给一个 UDP 套接字设「不许分片」，二分地发不同大小的包，看从多大开始被挡住。" +
		"判定：mtu-path（路上有个更小的限制，值就是它，网卡 MTU 照着设）、" +
		"mtu-local（没撞到更小的，上限就是本机网卡的 MTU）、" +
		"mtu-no-limit-found（上限是填进来的，只说明「至少这么大」）、" +
		"mtu-no-limit-found（测到这次给的上限都没被挡，结论只到「至少这么大」）、" +
		"mtu-no-response（对方不回 ICMP，什么都测不出来 —— 这**不是**MTU 有问题）、" +
		"mtu-no-route（本机没路）、mtu-df-unsupported（这台机器的这一层不干活，测不了）。\n" +
		"★ 只往目标的一个 UDP 端口发包，不碰中间设备。IPv6 上路由器本来就不分片，测的是本机敢发多大。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string",
	      "description": "目标地址，只收 IP（可以带端口，但端口以 port 为准）。IPv6 带不带方括号都认，链路本地地址必须带 zone。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "探测打在哪个 UDP 端口，默认 9253（一个肯定没人监听的高端口，就为了拿回 ICMP 端口不可达）。"},
	    "maxSize": {"type": "integer", "minimum": 501, "maximum": 65535,
	      "description": "最多测到多大。默认用出口网卡的 MTU（读不到时按 1500）。填大了没坏处，只是多二分几步。"},
	    "timeoutMs": {"type": "integer", "minimum": 100, "maximum": 5000,
	      "description": "单个尺寸等多久，默认 700。二分大约十步，最坏耗时就是十倍。"}
	  }
	}`),
	Invoke: doMTUPath,
}

type mtuArgs struct {
	Addr      string `json:"addr"`
	Port      int    `json:"port,omitempty"`
	MaxSize   int    `json:"maxSize,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
}

// mtuStep 是一次探测的记录。★ 全程逐步留在结果里：这一栏给的是一个**推出来的数**，
// 人不看到「哪一步开始过不去」就没法信它，尤其在路上有 ICMP 限速的时候。
type mtuStep struct {
	Size      int    `json:"size"`
	Outcome   string `json:"outcome"`
	ElapsedMS int64  `json:"elapsedMs,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// mtuProbe 探一个尺寸（IP 包总长，含 IP 头和 UDP 头）。
// ★ 做成函数而不是内联在流程里，是为了让二分、归属和判定能脱离真网络测：
//
//	「谁把包挡了」在测试里造不出来，但「多大开始被挡」可以按脚本给。
type mtuProbe func(size int) mtuStep

func doMTUPath(ctx context.Context, raw json.RawMessage) (any, error) {
	var a mtuArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	addr, _, err := netaddr.SplitHostPort(a.Addr)
	if err != nil {
		if host, ok := addrLooksLikeName(a.Addr); ok {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%q 不是 IP —— 这里只收 IP，域名先用 net.dns.query 查出地址再来探", host)
		}
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	port := a.Port
	if port <= 0 {
		port = defaultMTUPort
	}
	timeout := 700 * time.Millisecond
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	v6 := addr.Is6()
	minSize := mtuMinPacket(v6)

	// 上限：填了就听人的，没填用出口网卡的 MTU（读不到才退 1500）。
	egress := mtuEgressFor(ctx, addr)
	maxSize := a.MaxSize
	if maxSize <= 0 {
		maxSize = 1500
		if egress.MTU >= minSize {
			maxSize = egress.MTU
		}
	}
	if maxSize > 65535 {
		maxSize = 65535
	}
	if maxSize <= mtuBaseSize {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"maxSize %d 还没到起手的探测尺寸 %d —— 这个上限测不出东西，把它调大或者别填（不填就用出口网卡的 MTU）",
			maxSize, mtuBaseSize)
	}

	probe := mtuRealProber(ctx, addr, port, timeout, v6)
	values := map[string]any{
		"target": addr.String(),
		"family": udpFamily(addr),
		"port":   port,
		"engine": dfEngine,
	}
	if egress.Iface != "" {
		values["egress"] = map[string]any{"iface": egress.Iface, "mtu": egress.MTU}
	} else {
		// ★ 不知道出口网卡 MTU，最后那句归属就只能是「不知道是谁挡的」—— 先在这里说清楚，
		//   比在判定里含糊过去强。
		values["egressUnknown"] = true
	}

	var steps []mtuStep
	baseSize := mtuBaseSize
	if baseSize < minSize {
		baseSize = minSize
	}
	base := record(&steps, probe(baseSize))
	if base.Outcome == mtuNoRoute {
		return mtuVerdict(values, steps, mtuCodeNoRoute,
			"到 "+addr.String()+" 没有路 —— 一个包都没发出去。先查本机网卡和路由（net.interfaces / net.dualstack.check）")
	}
	if base.Outcome == mtuSilent {
		// ★ 这**不是** MTU 有问题。这一步什么都没测到，把它说成任何 MTU 结论都是凭空造的。
		return mtuVerdict(values, steps, mtuCodeNoAnswer,
			fmt.Sprintf("连 %d 字节的小包都收不到回执（%s）—— 这台主机不回 ICMP、或者这条路把差错报文挡了。"+
				"这一栏在它身上测不出东西：先 net.ping 看它在不在、回不回话",
				base.Size, orDefault(base.Detail, "等了 "+timeout.String()+" 没回音")))
	}
	if base.Outcome == mtuProbeErr {
		return mtuVerdict(values, steps, mtuCodeNoDF,
			"探测包发不出去："+base.Detail+" —— 这台机器上「不许分片」这一层没干活（engine="+dfEngine+"），路径 MTU 测不了")
	}

	// ★★ 验一下「不许分片」是不是**真的**生效了，不在编译期假设它成立。
	//   拿一个明显超过本机网卡 MTU 的尺寸发一发：选项真生效时内核当场拒（too-big）；
	//   没生效时它自己把包切开发出去，什么都不会报 —— 那接下来量到的数会偏到没有上限，
	//   一个假 MTU 比测不出来坏得多，所以宁可停下来说明这台机器测不了。
	if egress.MTU >= minSize && egress.MTU+400 <= 65535 {
		switch chk := record(&steps, probe(egress.MTU+400)); chk.Outcome {
		case mtuThrough:
			values["dfVerified"] = false
			return mtuVerdict(values, steps, mtuCodeNoDF,
				fmt.Sprintf("%d 字节的包（本机网卡 MTU 是 %d）居然发得出去 —— 说明「不许分片」在这台机器上没生效，"+
					"内核把大包自己切开了。这样量出来的任何 MTU 都是假的，这一栏在这上面测不了（engine=%s）",
					chk.Size, egress.MTU, dfEngine))
		case mtuTooBig:
			values["dfVerified"] = true
		}
		// 没回执 / 没路：这一项验不成，如实不写 dfVerified，继续往下测（后面的归属会带上不确定性）
	}

	var res mtuSearchResult
	if base.Outcome == mtuTooBig {
		// 起手就被挡：拿最小包当对照 —— 连最小包都发不出去，就不可能是路的 MTU 这么小。
		if baseSize <= minSize {
			return mtuVerdict(values, steps, mtuCodeNoDF,
				fmt.Sprintf("连 %d 字节的最小探测包都发不出去 —— 这不像路的 MTU 这么小，像是这台机器上"+
					"「不许分片」设上了却不干活（%s），这一栏在它上面给不出可信的数",
					minSize, orDefault(base.Detail, "EMSGSIZE")))
		}
		res = mtuSearch(probe, &steps, minSize, base.Size)
	} else {
		res = mtuSearch(probe, &steps, base.Size, maxSize)
	}
	return mtuFinish(values, steps, res, egress, maxSize, addr, v6)
}

func mtuVerdict(values map[string]any, steps []mtuStep, code, note string) (any, error) {
	values["steps"] = steps
	return ots.Verdict{Code: code, Values: values, Note: note}, nil
}

// mtuSearchResult 是二分跑完之后的样子。
type mtuSearchResult struct {
	through int    // 最后一个**确认能过去**的尺寸
	stopped string // mtuThrough=到上限还能过（没撞到墙）；mtuTooBig=撞到了；其余=测不动
}

// mtuSearch 在「已知 lo 能过、hi 是上限」之间二分出能过的最大尺寸。
// ★ 二分而不是从 lo 一路试上去：500 到 1500 逐个试要发一千个包。这在现场不是慢，
//
//	是把自己变成攻击流量 —— 摄像头的防爆破会把这台机器锁掉，交换机也可能直接限速。
func mtuSearch(probe mtuProbe, steps *[]mtuStep, lo, hi int) mtuSearchResult {
	switch s := record(steps, probe(hi)); s.Outcome {
	case mtuThrough:
		return mtuSearchResult{through: hi, stopped: mtuThrough}
	case mtuTooBig: // 正常的二分入口
	default:
		// 中途开始没回执 / 发不出去：**不许**把已经过的那个尺寸当成路径 MTU。
		// 那只是「测到这儿测不动了」，报成 MTU 会让人照着设一个更小的网卡 MTU。
		return mtuSearchResult{through: lo, stopped: s.Outcome}
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		switch s := record(steps, probe(mid)); s.Outcome {
		case mtuThrough:
			lo = mid
		case mtuTooBig:
			hi = mid
		default:
			return mtuSearchResult{through: lo, stopped: s.Outcome}
		}
	}
	return mtuSearchResult{through: lo, stopped: mtuTooBig}
}

// mtuFinish 把二分的结果翻成判定。**这一步的产品价值全在归属上**：同样是「这么大就过不去」，
// 被本机网卡挡住说明路上没测到更小的限制（要查的是本机设置），还没到本机上限就被挡住才是
// 路径 MTU（要改的才是本机 MTU）。这两个报反，人就会去改一个根本没坏的东西。
func mtuFinish(values map[string]any, steps []mtuStep, res mtuSearchResult,
	egress mtuEgress, ceiling int, addr netaddr.Addr, v6 bool) (any, error) {
	values["steps"] = steps
	switch res.stopped {
	case mtuThrough:
		values["carriesAtLeast"] = res.through
		if egress.MTU > 0 && res.through >= egress.MTU {
			return ots.Verdict{Code: mtuCodeLocal, Values: values,
				Note: fmt.Sprintf("到 %s 连本机网卡的 MTU（%d，出口 %s）都过得去 —— 这条路上没有更小的限制。"+
					"★ 大包发不出去的话，别往路径 MTU 上查，去看对端服务和本机的分片设置",
					addr.String(), egress.MTU, egress.Iface)}, nil
		}
		// 上限是用户填的、比本机 MTU 小（或者本机 MTU 压根没读到）：结论只能到「至少这么大」。
		return ots.Verdict{Code: mtuCodeNoLimit, Values: values,
			Note: fmt.Sprintf("测到 %d 字节都没被挡住，但这只是这次给的上限（出口网卡：%s）—— "+
				"想要更大的结论就把 maxSize 调到 %d 以上再测一次，多花的只是几次二分",
				res.through, mtuEgressDesc(egress), ceiling+1)}, nil

	case mtuSilent, mtuProbeErr:
		return ots.Verdict{Code: mtuCodeNoAnswer, Values: values,
			Note: fmt.Sprintf("%d 字节还过得去，再往上就收不到回执了 —— 这不能当成「路径 MTU 是 %d」："+
				"%s 不回 ICMP 差错和这条路真被卡住，长得一模一样。先确认这台主机会不会回 ICMP，再照这个数设网卡 MTU",
				res.through, res.through, addr.String())}, nil

	case mtuNoRoute:
		return ots.Verdict{Code: mtuCodeNoRoute, Values: values,
			Note: "测到一半，到 " + addr.String() + " 没有路了 —— 后面的包根本没发出去。先查本机网卡和路由（net.interfaces）"}, nil
	}

	blocked := valuesBlockedSize(steps, res.through)
	switch mtuBlockedBy(egress.MTU, res.through, blocked) {
	case "local":
		values["localMtuLimited"] = true
		return ots.Verdict{Code: mtuCodeLocal, Values: values,
			Note: fmt.Sprintf("%d 字节开始发不出去，而卡住它的是**本机网卡**（出口 %s 的 MTU %d）—— 包没出过本机，"+
				"所以路上有没有更小的限制这一趟测不出来。要查大包不通，先看本机 MTU 和分片设置",
				blocked, egress.Iface, egress.MTU)}, nil
	case "unknown":
		values["pathMtu"] = res.through
		return ots.Verdict{Code: mtuCodePath, Values: values,
			Note: fmt.Sprintf("%d 字节开始过不去（%d 还过得去）—— 但没读到出口网卡的 MTU，"+
				"分不清是本机网卡先卡住还是路上某台设备卡的。先看一眼 net.interfaces 里这块网卡 MTU 多大再定",
				blocked, res.through)}, nil
	default:
		values["pathMtu"] = res.through
		values["suggestion"] = res.through
		if v6 && res.through < 1280 {
			// RFC 8200 要求 IPv6 链路上至少能过 1280：测出比这还小，说明中间有人在乱来。
			values["warning"] = "below-ipv6-min"
		}
		return ots.Verdict{Code: mtuCodePath, Values: values,
			Note: fmt.Sprintf("到 %s 的路径 MTU 是 %d 字节：%d 字节开始被挡（本机 %s，比这宽松）——"+
				"★ 这就是「小包都好、大包过不去」的那个原因。把这台机器的网卡 MTU 设成 %d 或更小，"+
				"或者去查中间那个把尺寸压小的环节（隧道、PPPoE、VPN、被改过 MTU 的端口）",
				addr.String(), res.through, blocked, mtuEgressDesc(egress), res.through)}, nil
	}
}

func mtuEgressDesc(e mtuEgress) string {
	if e.MTU > 0 {
		return fmt.Sprintf("%s MTU %d", e.Iface, e.MTU)
	}
	return "没读到"
}

// mtuBlockedBy 判「是谁把这个尺寸挡住的」。★ 这是这一栏最容易说错的一步，
// 判错的后果不是报错，是人照着设一个错的网卡 MTU：
//
//	被挡的那个尺寸已经超过本机网卡的 MTU → 包根本没出过本机，说不上路径 MTU；
//	还没到本机上限就被挡 → 只能是路上某台设备回的「需要分片但不许分片」。
func mtuBlockedBy(localMTU, through, blocked int) string {
	if localMTU <= 0 {
		return "unknown"
	}
	if blocked > localMTU {
		return "local"
	}
	return "path"
}

// valuesBlockedSize 从逐步记录里找出「第一个过不去」的尺寸（二分不一定正好测到 through+1）。
func valuesBlockedSize(steps []mtuStep, through int) int {
	best := 0
	for _, s := range steps {
		if s.Outcome == mtuTooBig && s.Size > through && (best == 0 || s.Size < best) {
			best = s.Size
		}
	}
	if best == 0 {
		return through + 1
	}
	return best
}

func record(steps *[]mtuStep, s mtuStep) mtuStep {
	*steps = append(*steps, s)
	return s
}

// mtuMinPacket 是能发的最小 IP 包（IP 头 + UDP 头 + 一个字节数据）。
func mtuMinPacket(v6 bool) int {
	if v6 {
		return 40 + mtuUDPHeader + 1
	}
	return 20 + mtuUDPHeader + 1
}

// mtuPayloadLen 把一个 IP 包总长换算成要写进套接字的载荷长度。
// ★ 结果里的尺寸一律是 **IP 包总长**，因为 MTU 本来就是按 IP 包算的 ——
//
//	按载荷报会把每个数都说大 28/48 字节，人拿去设网卡就设错了。
func mtuPayloadLen(size int, v6 bool) int {
	h := 20 + mtuUDPHeader
	if v6 {
		h = 40 + mtuUDPHeader
	}
	return size - h
}

type mtuEgress struct {
	Iface string
	MTU   int
}

// mtuEgressFor 找「到这个地址本机走哪块网卡、那块网卡 MTU 多大」。
// ★ 交给内核回答：连一个 UDP 套接字（不发包），看内核挑了哪个源地址，再拿它去网卡清单里对。
//
//	自己解析路由表要每个平台写一套，而且**内核挑的那块才是真的**。
func mtuEgressFor(ctx context.Context, addr netaddr.Addr) mtuEgress {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	target, err := addr.HostPort(defaultMTUPort, runtime.GOOS)
	if err != nil {
		return mtuEgress{}
	}
	var d net.Dialer
	conn, derr := d.DialContext(cctx, "udp", target)
	if derr != nil {
		return mtuEgress{}
	}
	defer conn.Close()
	l, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return mtuEgress{}
	}
	src, perr := netip.ParseAddr(l.IP.String())
	if perr != nil {
		return mtuEgress{}
	}
	nics, ierr := netif.Interfaces()
	if ierr != nil {
		return mtuEgress{}
	}
	for _, n := range nics {
		for _, a := range n.Addrs {
			// ★ 比地址本身，不带 zone：zone 是本机网卡名，两边写法不一样，带上就永远对不上。
			if a.IP.WithZone("") == src {
				return mtuEgress{Iface: n.Name, MTU: n.MTU}
			}
		}
	}
	return mtuEgress{}
}

// mtuRealProber 是真的往路上发一包。★ 一个尺寸一个新套接字：套接字选项是**每套接字**的，
// 复用同一个套接字换尺寸没问题，但一旦哪次被内核记了错（ICMP 差错是挂在套接字上的），
// 下一个尺寸就会吃到上一个的回执 —— 新建就没这个纠缠。
func mtuRealProber(ctx context.Context, addr netaddr.Addr, port int, timeout time.Duration, v6 bool) mtuProbe {
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	return func(size int) mtuStep {
		payload := mtuPayloadLen(size, v6)
		if payload < 1 {
			return mtuStep{Size: size, Outcome: mtuProbeErr, Detail: "这个尺寸装不下一个字节的数据"}
		}
		target, err := addr.HostPort(port, runtime.GOOS)
		if err != nil {
			return mtuStep{Size: size, Outcome: mtuProbeErr, Detail: err.Error()}
		}
		// 选项设不上就直接说测不了：退化成「允许分片」去发，量出来的数会大得离谱
		// （内核自己切开了，谁都不吭声），那比测不出来坏得多。
		ctrl, cerr := dfControl(v6)
		if cerr != nil {
			return mtuStep{Size: size, Outcome: mtuProbeErr, Detail: cerr.Error()}
		}
		d := net.Dialer{Control: ctrl}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, derr := d.DialContext(cctx, network, target)
		if derr != nil {
			return classifyMTUDial(size, derr)
		}
		defer conn.Close()
		// ctx 取消时立刻把套接字关掉，别等满超时（理由同 net.udp.probe）。
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-cctx.Done():
				conn.Close()
			case <-done:
			}
		}()
		buf := make([]byte, payload)
		start := time.Now()
		if _, werr := conn.Write(buf); werr != nil {
			return mtuStep{Size: size, Outcome: classifyMTU(size, werr).Outcome,
				ElapsedMS: time.Since(start).Milliseconds(), Detail: werr.Error()}
		}
		rbuf := make([]byte, 1)
		_, rerr := conn.Read(rbuf)
		el := time.Since(start).Milliseconds()
		if rerr == nil {
			// 对面有个服务答话了 —— 同样是「这个尺寸过得去」的证据。
			return mtuStep{Size: size, Outcome: mtuThrough, ElapsedMS: el}
		}
		st := classifyMTU(size, rerr)
		st.ElapsedMS = el
		if ctxErr := cctx.Err(); ctxErr != nil {
			switch {
			case ctxErr == context.DeadlineExceeded && st.Outcome == mtuProbeErr:
				// ★ 超时是我们自己把套接字关掉的：macOS 上这样一关，Read 报的是
				//   "use of closed network connection"，而不是带 Timeout() 的 net.Error。
				//   认成「探测包发不出去」会把人引去查 DF 选项，其实只是对方没回音。
				st.Outcome = mtuSilent
				st.Detail = "没回音"
			case ctxErr == context.Canceled:
				st.Outcome = mtuProbeErr
				st.Detail = "探测被取消：" + ctxErr.Error()
			}
		}
		return st
	}
}

func classifyMTUDial(size int, err error) mtuStep {
	st := classifyMTU(size, err)
	if st.Outcome == mtuSilent {
		// 连不上不都是「没回执」：选项设不上、地址发不出去，都要如实分开。
		st.Outcome = mtuProbeErr
		st.Detail = err.Error()
	}
	return st
}

// classifyMTU 把一个错误翻成这一栏的三个信号之一。
// ★ EMSGSIZE 在两条路上都会来：本机网卡装不下（内核在本地就拒），
//
//	和路上设备回了「需要分片但不许分片」。这里**不猜**是谁 —— 归属交给 mtuBlockedBy
//	拿本机 MTU 去对，因为那是唯一有依据的判法。
func classifyMTU(size int, err error) mtuStep {
	switch {
	case err == nil:
		return mtuStep{Size: size, Outcome: mtuThrough}
	case errors.Is(err, syscall.EMSGSIZE):
		return mtuStep{Size: size, Outcome: mtuTooBig, Detail: err.Error()}
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		// ICMP 端口不可达 —— 这个尺寸的包完整走了一个来回。
		return mtuStep{Size: size, Outcome: mtuThrough}
	case isNoRoute(err):
		return mtuStep{Size: size, Outcome: mtuNoRoute, Detail: err.Error()}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return mtuStep{Size: size, Outcome: mtuSilent, Detail: "没回音"}
	}
	return mtuStep{Size: size, Outcome: mtuProbeErr, Detail: err.Error()}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
