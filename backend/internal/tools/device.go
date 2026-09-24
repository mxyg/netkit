package tools

// ── net.device.identify 设备识别 ──
//
// ★★ 这一栏答的是现场那句最难答的话：「10.0.12.77 我知道有人，可它是哪一台？」
//
//	前面所有工具（ping、网段扫描、端口扫描、ARP）都只能回答「这个地址有人」，
//	回答不了「它是谁」。答案不在地址里，**在设备自己喊的话里**：
//	摄像头喊 ONVIF（WS-Discovery），NAS、打印机、AirPlay 盒子喊 mDNS/DNS-SD，
//	Windows 机器喊 NetBIOS，媒体服务器与智能设备喊 SSDP/UPnP。
//	报文本身由 internal/broadcast 逐字节解，这一层只管「在哪块网卡上问、问几轮、
//	收齐了怎么归并成一台设备、该给什么判定」。
//
// ★ 只放设备自己说过的话。没说的字段留空，由界面写「这台没说」。
//
//	「按 MAC 前缀猜是海康」这种猜测是这一栏最不该出现的东西：猜对九次、错一次，
//	人就顺着错的那一次去机房。OUI 那一栏想看有 net.mac.analyze，那是另一码事。
//
// ★ 四路都用**临时源端口**发问，不去占 1900 / 5353 / 3702：
//
//	mDNS 那一问置了 QU 位（RFC 6762 §6.7，见 broadcast.MDNSQuery），SSDP 与
//	WS-Discovery 的应答本来就是单播发给问的人，NetBIOS 是点名单播问。
//	好处是不需要管理员权限，也不会和系统自带的 mDNSResponder / SSDP 服务抢端口 ——
//	那两个抢起来是**静默失败**的：绑定报错，界面上看起来像「网上没设备」。
//
// ★ NetBIOS 是这一路唯一能拿到 MAC 的（node status 的统计段里写着 UNIT_ID），
//
//	所以它排在另外三路之后跑：先用组播那一轮问出「哪些地址上有人」，
//	再挨个点名问那几台「你叫什么、你的 MAC 是多少」。整段挨个问不归这里，那是 net.subnet.scan。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"net.yuhox.com/netkit/internal/broadcast"
	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// 判定码。★ 分开的原则是「下一步要不要人干活」，不是「有没有结果」：
const (
	verdictDevicesFound   = "devices-found"      // 认出了至少一台（它自己报过名字、类型或地址）
	verdictHeardAnonymous = "heard-anonymous"    // 有东西应了，但一句身份都没说 —— 要人去查，不等于没设备
	verdictNothingHeard   = "no-device-answered" // 一个应答都没收到（不等于这个网段没有设备）
	verdictNoInterface    = "no-interface"       // 一块能问的网卡都没有：压根没问出去
	verdictNoMulticast    = "no-multicast-route" // 组播发不出去：本机或中间设备不让
	// 人中途点了「停」沿用 net.dhcp leases 那一个码 verdictStopped（"stopped"）：
	// ★ 单独一个码是因为这时候「一个设备都没收到」只说明停之前没收到，
	//   把它报成 no-device-answered 等于拿半次的观察下一个全段的结论。
)

// 四路问法。界面上的选项用这几个词，所以它们是对外的名字。
const (
	protoSSDP    = "ssdp"
	protoMDNS    = "mdns"
	protoWSDisco = "ws-discovery"
	protoNetBIOS = "netbios"
)

var allProtocols = []string{protoSSDP, protoMDNS, protoWSDisco, protoNetBIOS}

// 默认问哪几种 DNS-SD 服务。
//
// ★ 不写「把所有服务都报出来」那种问法：一个网里几十台 NAS、打印机各自能报出十几种类型，
//
//	一次能回上百条，而这一栏是给人一眼看完的。要全查，Services 参数留着口。
var defaultMDNSServices = []string{
	"_rtsp._tcp.local", "_onvif._tcp.local", "_smb._tcp.local",
	"_afpovertcp._tcp.local", "_printer._tcp.local", "_http._tcp.local",
	"_airplay._tcp.local", "_googlecast._tcp.local",
}

// 限量。★ 广播收起来没有上界，这几个数是「一眼看完」和「变成日志」的分界。
const (
	maxIdentifyIfaces  = 8
	maxNetBIOSTargets  = 64 // 点名问 MAC 最多问这么多台
	maxDescribeFetches = 12 // 一轮里最多取几份描述文件
	describeTimeout    = 3 * time.Second
	maxDescribeBytes   = 256 << 10

	// 一轮问多久、问几轮的天花板。★ 这两个数与 Schema 里写的 maximum 是同一件事，
	//   改一处必须改两处 —— 而代码这一道才是真的：Schema 只是给人和 AI 看的承诺。
	//   为什么要有天花板：等得更久并不多出设备（SSDP 自己规定的 MX 上限才 5 秒，
	//   答得慢的在第二轮才来），而广播是从人自己的笔记本上灌出去的。
	//   想覆盖慢的设备就加 rounds，不是加 seconds。
	maxIdentifyWindow = 20 * time.Second
	maxIdentifyRounds = 5
)

var identifyTool = ots.Tool{
	Name:  "net.device.identify",
	Class: ots.ClassRead,
	Summary: "问一遍这个网段，把**每台设备自己说过的话**摊开：它是谁（主机名 / 实例名）、" +
		"它是什么（ONVIF 网络视频设备、UPnP 媒体服务器、SMB 文件共享、AirPlay……）、" +
		"管理地址在哪、MAC 是多少。\n" +
		"★ 这是「这个 IP 是谁」唯一有意义的答法：ping、扫端口只能证明有人，证明不了是谁。" +
		"走 SSDP/UPnP、mDNS/DNS-SD、WS-Discovery(ONVIF)、NetBIOS 四种自报口径，" +
		"四路各自给出「问了几个、应了几个」—— 一路没应不代表设备不在，只代表它不说这一种话。" +
		"没说过话的设备一律留空并写「这台没说」，绝不按 MAC 前缀猜厂商。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "iface": {"type": "string",
	      "description": "只问某块网卡，如 en0 / eth1。不给就在所有插着线、有 IPv4 地址的物理网卡上问。"},
	    "seconds": {"type": "integer", "minimum": 1, "maximum": 20,
	      "description": "每轮等多久，默认 3。设备答话有快有慢，太短会把慢的当成不在。"},
	    "rounds": {"type": "integer", "minimum": 1, "maximum": 5,
	      "description": "问几轮，默认 2。UDP 会丢，问两轮的命中率明显高于把一轮拉长。"},
	    "protocols": {"type": "array", "items": {"type": "string",
	        "enum": ["ssdp", "mdns", "ws-discovery", "netbios"]},
	      "description": "只问这几种。默认四种全问。查监控专用 ws-discovery，查 NAS 与打印机用 mdns+ssdp。"},
	    "services": {"type": "array", "items": {"type": "string"},
	      "description": "额外要问的 DNS-SD 服务类型，如 _raop._tcp.local。默认问摄像头、文件共享、打印机、投屏那几种。"},
	    "addrs": {"type": "array", "items": {"type": "string"},
	      "description": "点名只问这些地址（单个 IP 或 CIDR 网段）。给了它就只问这些，不再先靠组播找目标。"},
	    "describe": {"type": "boolean",
	      "description": "SSDP 应答里带的 LOCATION 指向一份设备自报的描述文件（型号、序列号、服务清单）。默认 false：那是往设备上发 HTTP 请求，虽然只读但会在那台设备上留下访问记录。"}
	  }
	}`),
	Invoke: doIdentify,
}

type identifyArgs struct {
	Iface     string   `json:"iface,omitempty"`
	Seconds   int      `json:"seconds,omitempty"`
	Rounds    int      `json:"rounds,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
	Services  []string `json:"services,omitempty"`
	Addrs     []string `json:"addrs,omitempty"`
	Describe  bool     `json:"describe,omitempty"`
}

// deviceSources 是这一栏「会碰网」的部分。★ 全部抽成函数（理由同 bundleSources）：
// 归并与判定那一层不该只能靠「真有一台摄像头在场」来验。
type deviceSources struct {
	nics func() ([]netif.NIC, error)
	// ask 一轮：在指定的网卡上把查表报文发出去，在窗口里把报文解成自报记录。
	ask func(ctx context.Context, plan identifyPlan) (askResult, error)
	// fetch 取一份描述文件（SSDP 的 LOCATION）。★ 单独一个字段：
	// 测试要能只换「发流量」这一部分，而不连带把组播那一整套都替掉。
	fetch func(ctx context.Context, url string) ([]byte, error)
}

// askOutcome 一轮问完的结果。
//
// ★ 为什么不只返回自报记录：点名问的时候「包根本没发出去」（地址跨网段被路由挡了、
//
//	那个 IP 不存在）和「发了没人答」在结果上长得一模一样，而下一步要查的东西完全不同 ——
//	前者查路由和本机，后者才轮到查设备。所以这里把没发出去的单独带回去。
//	**注意这只影响叙述，不改变判定码**：判定码仍按「有没有认出设备」给，
//	这一栏是往 note 和 values 里添一句，不许拿它去把 no-device-answered 说成别的。
//
// askResult 一轮问完的结果。
//
// ★ 为什么不只返回自报记录：点名问的时候「包根本没发出去」（地址跨网段被路由挡了、
//
//	那个 IP 压根不存在）和「发了没人答」在结果上长得一模一样，而下一步要查的东西
//	完全不同 —— 前者查路由和本机，后者才轮到查设备。所以这里把没发出去的单独带回去。
//	这一栏只往 values 与 note 里添一句话，**不改变判定码**：判定仍按「有没有认出设备」给。
type askResult struct {
	Reports []broadcast.Report
	Failed  []string // 一个包都没发出去的点名地址
}

// identifyPlan 一轮要问什么。
type identifyPlan struct {
	// Ifaces 网卡名 → 这块网卡上当场要用的 IPv4 源地址。
	// ★ 带源地址而不是只带名字：套接字要绑到那块网卡自己的地址上，
	//   否则收回来的应答分不出是哪块网卡看到的（两块网卡接两个网段是常态）。
	Ifaces map[string]string
	// Targets 点名单播问这些地址。★ 非空时组播那三路改走单播，发给
	//   「目标地址:协议端口」而不是组播组 —— 因为跨网段的设备**收不到组播**，
	//   而现场那句「10.0.12.77 是谁」恰恰常常是跨网段的。
	//   三种问法都允许单播送达：UPnP 允许对已知设备单播 M-SEARCH，
	//   WS-Discovery 本来就支持把 Probe 单播发给某个 Endpoint，
	//   mDNS 置了 QU 位（RFC 6762 §6.7）时应答就是单播回给问的人。
	Targets   []string
	Protocols []string
	Window    time.Duration
	Services  []string // DNS-SD 类型
	ST        string   // SSDP 的 SEARCHTARGET
	WSDTypes  string   // WS-Discovery 的 Types
	NBAddrs   []string // NetBIOS 点名问的地址；空 = 这一路不问
}

func defaultDeviceSources() deviceSources {
	return deviceSources{nics: netif.Interfaces, ask: askDevices, fetch: fetchDescription}
}

func doIdentify(ctx context.Context, raw json.RawMessage) (any, error) {
	return runIdentify(ctx, raw, defaultDeviceSources())
}

func runIdentify(ctx context.Context, raw json.RawMessage, src deviceSources) (any, error) {
	var a identifyArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	protos, err := pickProtocols(a.Protocols)
	if err != nil {
		return nil, err
	}
	rounds := a.Rounds
	if rounds <= 0 {
		rounds = 2
	}
	if rounds > maxIdentifyRounds {
		return nil, ots.Errf(ots.ErrInvalidArgument, "问 %d 轮太多了（上限 %d）：慢的设备两轮里必有，"+
			"再多只是在人自己的笔记本上一直灌广播", rounds, maxIdentifyRounds)
	}
	window := time.Duration(a.Seconds) * time.Second
	if window <= 0 {
		window = 3 * time.Second
	}
	if window > maxIdentifyWindow {
		return nil, ots.Errf(ots.ErrInvalidArgument, "一轮问 %d 秒太长了（上限 %s）：设备的自报窗口就在头几秒"+
			"（SSDP 自己定的 MX 上限才 5 秒），等再久也不会多出设备来。要覆盖答得慢的那几台，加 rounds 而不是加 seconds",
			a.Seconds, maxIdentifyWindow)
	}
	// 点名的地址在列网卡之前先解析完：坏写法要是排在后面，它会被
	// 「没有可用网卡」那个判定盖掉——人把网卡修好了还是撞同一个错。
	given, badAddrs, err := parseTargets(a.Addrs)
	if err != nil {
		return nil, err
	}

	nics, err := src.nics()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "列网卡失败：%s", err)
	}
	targets, skipped := pickIdentifyNICs(nics, a.Iface)
	if len(targets) == 0 {
		// ★ 「没问出去」和「问了没人应」是两件事，必须分开：
		//   前者要人去开网卡、查本机，后者才轮到去查设备那一侧。
		vals := map[string]any{"interfaces": []string{}, "skipped": skipped}
		if a.Iface != "" {
			vals["requested"] = a.Iface
		}
		return ots.Verdict{Code: verdictNoInterface, Values: vals,
			Note: "没有一块可用的网卡有 IPv4 地址 —— 一个都没问出去。" +
				"这不是「网段里没有设备」。下一步：看网线、看这块网卡是不是被禁用了。"}, nil
	}

	names := append(append([]string{}, defaultMDNSServices...), a.Services...)
	sources := ifaceSources(targets)
	// 给了 addrs 时组播那三路也改成单播发给它，不再先靠组播找目标。
	plan := identifyPlan{
		Ifaces:    sources,
		Targets:   given,
		Protocols: protos,
		Window:    window,
		Services:  dedupStrings(names),
		ST:        "ssdp:all",
		WSDTypes:  "dn:NetworkVideoTransmitter",
	}

	// ── 第一轮：组播那三路先问，问出「哪些地址上有人」 ──
	var all []broadcast.Report
	var asked []string
	var unsent []string // 包压根没发出去的点名地址，只往 values/note 里添一句话
	nbAsked := 0
	stopped := false
	done := 0
	for r := 0; r < rounds; r++ {
		if ctx.Err() != nil {
			stopped = true // 人点了「停」：这份结果只覆盖停之前那一段
			break
		}
		done++
		p := plan
		// NetBIOS 单独排在后面：它要点名，而名字要靠另外三路先给出来。
		p.Protocols = without(protos, protoNetBIOS)
		if len(p.Protocols) > 0 {
			got, aerr := src.ask(ctx, p)
			if aerr != nil {
				return identifyFailure(aerr, p)
			}
			all = append(all, got.Reports...)
			for _, a := range got.Failed {
				addUnique(&unsent, a)
			}
			asked = append(asked, p.Protocols...)
		}
		if containsStr(protos, protoNetBIOS) {
			nbTargets := given
			if len(nbTargets) == 0 {
				nbTargets = netBIOTargets(all)
			}
			nbAsked = len(nbTargets)
			if len(nbTargets) > 0 {
				np := identifyPlan{Ifaces: plan.Ifaces, Targets: nbTargets,
					Protocols: []string{protoNetBIOS}, Window: plan.Window, NBAddrs: nbTargets}
				got, aerr := src.ask(ctx, np)
				if aerr != nil {
					return identifyFailure(aerr, np)
				}
				all = append(all, got.Reports...)
				for _, a := range got.Failed {
					addUnique(&unsent, a)
				}
				asked = append(asked, protoNetBIOS)
			}
		}
	}

	if a.Describe {
		all = append(all, describeKnown(ctx, src, all)...)
	}

	devs := mergeDevices(all)
	vals := map[string]any{
		"devices":    devs,
		"count":      len(devs),
		"reports":    len(all),
		"interfaces": ifaceNames(targets),
		"rounds":     rounds,
		"roundsDone": done,
		"stopped":    stopped,
		"protocols":  protocolTally(asked, len(sources), all, nbAsked),
	}
	if len(given) > 0 {
		vals["targets"] = given
	}
	if len(unsent) > 0 {
		vals["notAsked"] = unsent
	}
	if n := len(skipped) + len(badAddrs); n > 0 {
		vals["skipped"] = append(skipped, badAddrs...)
	}
	v := identifyVerdict(devs, vals, stopped)
	if stopped {
		// 一轮都没跑完，「没人应」这句话就说不成了：只能说「停之前没收到」。
		v.Note += fmt.Sprintf("\n★ 这一栏是中途停的（问了 %d/%d 轮）："+
			"下面这份只覆盖停之前收到的，不能当成整个网段的答案。", done, rounds)
	}
	if len(unsent) > 0 {
		// ★ 只在句尾添一句实话，不改判定码：这些地址是「连问都没问成」，
		//   和「问了没人答」不是一回事，但也不构成另一种结果。
		v.Note += fmt.Sprintf("\n另有 %d 个地址一个包都没发出去（见 notAsked）："+
			"这一栏不能当成「那些设备上没这句话」。", len(unsent))
	}
	return v, nil
}

// identifyVerdict 决定给哪个判定码。
//
// ★ 关键的一条：answered（有应答）和 identified（认出了是谁）是两件事。
//
//	现场最容易被糊弄过去的就是这一步 —— 收上来一个包就报「发现了 3 台设备」，
//	而那 3 台其实什么都没说。所以这里按「有没有任何一项自报口径是空的」分档。
//
// stopped 是人中途点了「停」：这时候一个设备都没收到只说明停之前没收到，
// 报成 no-device-answered 等于拿半次的观察下一个全段的结论。
func identifyVerdict(devs []identifiedDevice, vals map[string]any, stopped bool) ots.Verdict {
	identified := 0
	for _, d := range devs {
		if d.Identified {
			identified++
		}
	}
	vals["identified"] = identified
	// ★ 「没人应」这句话要说的是**问过的那几路**没人应。只勾了 NetBIOS 的一次问，
	//   报成「四种自报口径都没收到应答」就是把没问过的三路也算成了问过 ——
	//   人据此会直接下「这网段的设备都不响应发现」的结论，而那三路根本没开口问过。
	askedWord := "四种自报口径都"
	if n, names := askedProtocols(vals); n > 0 && n < len(allProtocols) {
		quan := "都"
		if n == 1 {
			quan = "" // 只问了一路，说「都没收到应答」是话过头
		}
		askedWord = fmt.Sprintf("问过的 %d 路自报口径（%s）%s", n, strings.Join(names, "、"), quan)
	}
	switch {
	case stopped && len(devs) == 0:
		// ★ 这一档存在的意义就是不让人把「没问完」读成「没有」：
		//   点了停的人知道自己只等了一会儿，但把这份结果转给别人时那一层信息就没了。
		return ots.Verdict{Code: verdictStopped, Values: vals,
			Note: "还没问到东西就停了（见 roundsDone）。这一栏不下「网段里没有设备」的结论：" +
				"慢的设备（老摄像头、走 802.11 的笔记本）第二轮才答话是常态。"}
	case len(devs) == 0:
		return ots.Verdict{Code: verdictNothingHeard, Values: vals,
			Note: fmt.Sprintf("%s没收到应答。★ 这不能当成「这个网段里没有设备」："+
				"设备不喊这几种话（固件关了发现服务）、中间隔着三层、交换机做了组播抑制，"+
				"都会长这样。下一步：先用 net.subnet.scan 确认地址上有没有人，"+
				"再用 net.ports.scan 看它开了什么口。", askedWord)}
	case identified == 0:
		return ots.Verdict{Code: verdictHeardAnonymous, Values: vals,
			Note: fmt.Sprintf("应了的 %d 个地址没有一个说过自己是谁。"+
				"这一栏只放设备自己说过的话，所以这里给不出名字：要么换协议再问一次（protocols），"+
				"要么去看它们开了什么口（net.ports.scan）。", len(devs))}
	default:
		return ots.Verdict{Code: verdictDevicesFound, Values: vals,
			Note: fmt.Sprintf("认出 %d 台（共 %d 个地址应了）。没认出来的那些一律留空并标出来，不猜。",
				identified, len(devs))}
	}
}

// askedProtocols 从逐路那本账里挑出真问过的几路。★ 「没人应」这句话要说的是
// 问过的那几路没人应：只勾了 NetBIOS 的一次问，不能报成「四种口径都没应」——
// 那等于把没问过的三路也算成问过，人据此会直接下「这网段的设备都不响应发现」。
func askedProtocols(vals map[string]any) (int, []string) {
	list, _ := vals["protocols"].([]map[string]any)
	var names []string
	for _, row := range list {
		if a, _ := row["asked"].(bool); a {
			if p, _ := row["protocol"].(string); p != "" {
				names = append(names, p)
			}
		}
	}
	return len(names), names
}

// identifyFailure 分「工具跑不起来」和「网上没人应」：前者是错误，后者是判定。
//
// ★ 组播发不出去是**环境问题**不是没设备：容器里跑、VPN 只给了一个 /32、
//
//	系统禁了组播，都会在这里报错。这时候绝不能给 no-device-answered 那个判定，
//	否则人会把「我们没问成」记成「那个网段是空的」。
func identifyFailure(err error, p identifyPlan) (any, error) {
	if errors.Is(err, errNoMulticast) {
		ifaces := make([]string, 0, len(p.Ifaces))
		for n := range p.Ifaces {
			ifaces = append(ifaces, n)
		}
		sort.Strings(ifaces)
		return ots.Verdict{Code: verdictNoMulticast, Values: map[string]any{
			// ★ protocols 这一栏在**所有**判定里都是同一个形状（逐路的账），这里不能图省事
			//   退化成一组名字：形状一变，读结果的人（界面和 AI 都是）就要先猜这次是哪一种。
			"interfaces": ifaces,
			"protocols":  protocolTally(nil, len(ifaces), nil, 0),
			"reason":     err.Error(),
		}, Note: "组播发不出去（见 reason）。★ 一个设备都没问成，所以这个结果里" +
			"没有任何一栏可以当成「设备上没这句话」。换一块有 IPv4 的网卡，或直接用 addrs 点名问。"}, nil
	}
	return nil, ots.Errf(ots.ErrInternal, "%s", err)
}

// ── 归并 ──

// identifiedDevice 一台设备：同一个地址上的若干条自报归并成一条。
type identifiedDevice struct {
	Addr  string `json:"addr"`
	Iface string `json:"iface,omitempty"`
	MAC   string `json:"mac,omitempty"`
	Name  string `json:"name,omitempty"` // 它自己报的主机名 / 实例名 / 计算机名
	Kind  string `json:"kind,omitempty"` // 它自己报的类型（ONVIF、UPnP 媒体服务器……）
	URL   string `json:"url,omitempty"`  // 管理地址 / 服务地址
	Port  int    `json:"port,omitempty"`

	Protocols  []string          `json:"protocols"`
	Instances  []string          `json:"instances,omitempty"`
	Types      []string          `json:"types,omitempty"`
	ServiceURL []string          `json:"serviceUrl,omitempty"`
	Text       map[string]string `json:"text,omitempty"`
	Detail     []string          `json:"detail,omitempty"`
	TTL        int               `json:"ttl,omitempty"`

	// Identified 它到底有没有说过自己是干嘛的。★ 这个布尔是整个判定的支点。
	Identified bool `json:"identified"`
}

// mergeDevices 按地址归并。
//
// ★ 只按地址归并，**不按主机名归并**：现场一个地址上可以有二十个 DNS-SD 实例
//
//	（NAS 尤其如此），而两台设备重名（两台都叫 PC）也是真会碰到的。
//	拿名字当键会把两台并成一台、把一台拆成二十台，两种错都没法从结果里看出来。
func mergeDevices(reports []broadcast.Report) []identifiedDevice {
	byAddr := map[string]*identifiedDevice{}
	var order []string
	for i := range reports {
		rp := reports[i]
		if rp.From == "" {
			continue
		}
		d := byAddr[rp.From]
		if d == nil {
			d = &identifiedDevice{Addr: rp.From, Protocols: []string{}, Text: map[string]string{}}
			byAddr[rp.From] = d
			order = append(order, rp.From)
		}
		d.merge(rp)
	}
	out := make([]identifiedDevice, 0, len(order))
	for _, a := range order {
		d := byAddr[a]
		// ★ 表外的类型还原成设备自己那句话。哨兵值只在内部用来表达
		//   「这句话不在表里，但别的一个来源也不许盖掉它」，漏进结果就是
		//   界面上一串 \x00 —— 那一栏是给人抄进工单的。
		if d.Kind == kindUnknownSpoke {
			if len(d.Types) > 0 {
				d.Kind = d.Types[0]
			} else {
				d.Kind = ""
			}
		}
		if len(d.Text) == 0 {
			d.Text = nil // 空对象在界面上是一个碍事的空白框
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return deviceLess(out[i], out[j]) })
	return out
}

func (d *identifiedDevice) merge(r broadcast.Report) {
	addUnique(&d.Protocols, r.Source)
	if d.MAC == "" && r.MAC != "" {
		d.MAC = r.MAC
	}
	// 名字有几个来源。★ 优先「设备自己起的、给人看的那一个」：NetBIOS 的计算机名
	// 与 UPnP 的 friendlyName 是人脸上的名字，而 DNS-SD 的实例名常常是一串序列号。
	if r.Name != "" && (d.Name == "" || betterName(d.Name, r)) {
		d.Name = r.Name
	}
	if r.Instance != "" {
		addUnique(&d.Instances, r.Instance)
	}
	if r.Type != "" {
		addUnique(&d.Types, r.Type)
		kind := kindOf(r)
		if kind != "" && (d.Kind == "" || d.Kind == kindUnknownSpoke) {
			d.Kind = kind
		}
	}
	if r.URL != "" {
		if d.URL == "" {
			d.URL = r.URL
		} else {
			addUnique(&d.ServiceURL, r.URL)
		}
	}
	if r.Port != 0 && d.Port == 0 {
		d.Port = r.Port
	}
	for k, v := range r.Text {
		if v != "" && d.Text[k] == "" {
			d.Text[k] = v
		}
	}
	if r.Detail != "" {
		addUnique(&d.Detail, r.Detail)
	}
	if r.TTL > 0 && (d.TTL == 0 || r.TTL < d.TTL) {
		d.TTL = r.TTL
	}
	if r.Name != "" || r.Type != "" || r.URL != "" || r.Instance != "" || r.MAC != "" {
		d.Identified = true
	}
}

// kindOf 把设备自己报的类型写成一句人话。
//
// ★★ 表里只有**协议自己定义过的**词（ONVIF 的 NetworkVideoTransmitter、
//
//	UPnP 的 MediaServer、DNS-SD 注册文件里的那些服务类型）。表外的类型
//	原样把设备自己写的词给出去，不套一个「大概是摄像头吧」：
//	现场是照着这一栏决定带不带梯子去机房的东西。
func kindOf(r broadcast.Report) string {
	t := r.Type
	switch {
	case strings.Contains(t, "NetworkVideoTransmitter"):
		return "网络摄像头（ONVIF 定义的网络视频设备）"
	case strings.Contains(t, "NetworkVideoRecorder"):
		return "网络录像机（ONVIF）"
	case strings.Contains(t, "MediaServer"):
		return "媒体服务器（UPnP 定义的设备类型）"
	case strings.Contains(t, "MediaRenderer"):
		return "媒体播放端（UPnP 定义的设备类型）"
	case strings.Contains(t, "InternetGatewayDevice"), strings.Contains(t, "WANDevice"):
		return "网关/路由（UPnP 定义的设备类型）"
	case strings.Contains(t, "PrintDevice"), t == "_printer._tcp.local", strings.Contains(t, "_ipp._tcp"):
		return "打印机（它自己报的打印服务）"
	case t == "_smb._tcp.local", t == "_afpovertcp._tcp.local", t == "_webdav._tcp.local":
		return "文件共享（它自己报的服务类型）"
	case t == "_airplay._tcp.local", t == "_raop._tcp.local":
		return "投屏接收端（它自己报的服务类型）"
	case t == "_googlecast._tcp.local":
		return "投屏接收端（它自己报的服务类型）"
	case r.Source == broadcast.SourceNetBIOS && strings.Contains(r.Detail, "文件与打印共享"):
		return "开了文件共享的 Windows 机器"
	case t != "":
		return kindUnknownSpoke // 它报了自己是什么，只是那句话不在这张表里
	}
	return ""
}

const kindUnknownSpoke = "\x00自己说了但表里没有"

// betterName 两个来源都给了名字时选哪个。
//
// ★ 一串像序列号的实例名（"3F-A1B2C3"）不该盖掉设备自己起的友好名。
//
//	认「像序列号」只看形状不看厂商：这是显示层的选择，不是给设备分类。
func betterName(have string, r broadcast.Report) bool {
	if looksLikeSerial(have) && !looksLikeSerial(r.Name) {
		return true
	}
	// UPnP 的 friendlyName 与 NetBIOS 的计算机名是人写在机器脸上的那一串，
	// 优先于 DNS-SD 的实例名（常常等于主机名或序列号）。
	if r.Source == broadcast.SourceSSDP || r.Source == broadcast.SourceNetBIOS {
		return looksLikeSerial(have)
	}
	return false
}

func looksLikeSerial(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	dash, alnum := 0, 0
	for _, c := range strings.ToUpper(s) {
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z':
			alnum++
		case c == '-' || c == '_':
			dash++
		default:
			return false // 有空格、有点：那是人起的名字，不是编号
		}
	}
	return alnum > 0 && dash > 0
}

func deviceLess(a, b identifiedDevice) bool {
	if a.Identified != b.Identified {
		return a.Identified // 认出来的排前面：那一屏是给人抄进工单的
	}
	aa, aerr := netip.ParseAddr(a.Addr)
	bb, berr := netip.ParseAddr(b.Addr)
	if aerr == nil && berr == nil {
		return addrLessAddr(aa, bb)
	}
	return a.Addr < b.Addr
}

// ── 发与收：真正碰网的那一部分 ──

// errNoMulticast 组播这条路在本机走不通。★ 单独一个错误值：判定层要能把它
// 和「问了没人应」分开（见 identifyFailure）。
var errNoMulticast = errors.New("组播套接字建不起来")

// askDevices 在每块网卡上把要问的报文发出去，并在窗口里收应答。
//
// ★ 四路都用临时源端口（绑 :0），收完就关。这样不需要管理员权限，
//
//	也不会和系统的 mDNSResponder / SSDP 服务抢 5353 / 1900 —— 抢输了是静默的，
//	界面上会看起来像「这个网段没设备」。
func askDevices(ctx context.Context, plan identifyPlan) (askResult, error) {
	var (
		mu      sync.Mutex
		all     []broadcast.Report
		failed  []string
		wg      sync.WaitGroup
		failMu  sync.Mutex
		firstFn error
	)
	fail := func(err error) {
		failMu.Lock()
		if firstFn == nil {
			firstFn = err
		}
		failMu.Unlock()
	}
	addFailed := func(addrs []string) {
		mu.Lock()
		for _, a := range addrs {
			addUnique(&failed, a)
		}
		mu.Unlock()
	}

	want := map[string]bool{}
	for _, p := range plan.Protocols {
		want[p] = true
	}
	deadline := time.Now().Add(plan.Window)

	// 三路组播 + 一路单播，各自一个 goroutine：它们的收包节奏互不相干，
	// 串起来跑的话最慢的那一路会把窗口整个拉长。
	for _, p := range []string{protoSSDP, protoMDNS, protoWSDisco} {
		if !want[p] {
			continue
		}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			gs, err := multicastListener(p, plan.Ifaces)
			if err != nil {
				fail(err)
				return
			}
			defer gs.close()
			if err := gs.sendPlan(ctx, plan); err != nil {
				fail(err)
				return
			}
			gs.collect(ctx, deadline, func(rp []broadcast.Report) {
				mu.Lock()
				all = append(all, rp...)
				mu.Unlock()
			})
			addFailed(gs.unsentAddrs())
		}(p)
	}
	if want[protoNetBIOS] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nb := netbiosRound(ctx, plan)
			mu.Lock()
			all = append(all, nb.Reports...)
			for _, a := range nb.Failed {
				addUnique(&failed, a)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	res := askResult{Reports: all, Failed: failed}
	// 一路都没成、而且一个应答都没收到：把原因交回判定层。
	// 只要还有别的路上来了东西就不算失败 —— 那一路的账由 Failed 那一栏记。
	if firstFn != nil && len(all) == 0 {
		return res, firstFn
	}
	return res, nil
}

// mcastGroup 每一路的组播组与端口，以及怎么解回来的报文。
type mcastGroup struct {
	proto string
	group string
	port  int
}

func mcastGroups() map[string]mcastGroup {
	return map[string]mcastGroup{
		protoSSDP:    {protoSSDP, broadcast.McastSSDPv4, broadcast.PortSSDP},
		protoMDNS:    {protoMDNS, broadcast.McastMDNSv4, broadcast.PortMDNS},
		protoWSDisco: {protoWSDisco, broadcast.McastWSDiscoveryv4, broadcast.PortWSDiscovery},
	}
}

// mcastListener 每一路组播问法的收发口。
type mcastListener struct {
	proto  string
	conns  []*net.UDPConn
	pkts   []*ipv4.PacketConn
	ifaces []string // 与 conns 一一对应：这块网卡上看到的就是这一条
	group  *net.UDPAddr

	mu       sync.Mutex
	unsent   map[string]bool   // 一个网卡都没发出去的点名地址
	sendErrs map[string]string // 目标 → 最后一次的发送错误
}

// multicastListener 在每块网卡上开一个**绑到该网卡地址**的临时端口套接字，
// 并把组播出口指到它。
//
// ★ 每块网卡单独一个套接字，而不是一个套接字加 SetMulticastInterface：
//
//	后者只管**发**，收的时候几块网卡的应答会混在一个口里，
//	而「从哪块网卡看到的」是现场最常用的一栏（两块网卡接两个网段是常态）。
//	绑到网卡自己的地址上，回来的单播应答就落在对应那个套接字上，归属就清楚了。
func multicastListener(proto string, ifaces map[string]string) (*mcastListener, error) {
	g := mcastGroups()[proto]
	l := &mcastListener{proto: proto, group: &net.UDPAddr{IP: net.ParseIP(g.group), Port: g.port}}
	var lastErr error
	names := make([]string, 0, len(ifaces))
	for n := range ifaces {
		names = append(names, n)
	}
	sort.Strings(names) // 顺序固定：不然同样的输入每次跑发包顺序都不一样，比对现场时说不清
	for _, name := range names {
		ip := ifaces[name]
		iface, err := net.InterfaceByName(name)
		if err != nil {
			// ★ 这块网卡在「列网卡」和「按名字找它」之间没了（拔了 USB 网卡、
			//   macOS 改了接口名）。也算发不出去：判定层要给 no-multicast-route
			//   并带上 reason，不能报成内部错误——那样人看到的是一行代码，
			//   而实际要做的决定是「换一块网卡，或者点名问」。
			lastErr = fmt.Errorf("%w：找不到网卡 %s：%s", errNoMulticast, name, err)
			continue
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
		if err != nil {
			lastErr = fmt.Errorf("%w：(%s %s) %s", errNoMulticast, name, ip, err)
			continue
		}
		pc := ipv4.NewPacketConn(c)
		if err := pc.SetMulticastInterface(iface); err != nil {
			// ★ 这一步失败必须关掉套接字并报错：不报错的话包会从**默认路由那块网卡**
			//   出去 —— 笔记本同时插着有线、连着 Wi-Fi 时，问的不是盯着的那个网段，
			//   而结果看上去完全正常（没人应）。net.wol 那一栏就是照这条写的。
			c.Close()
			lastErr = fmt.Errorf("%w：%s 设不了组播出口：%s", errNoMulticast, name, err)
			continue
		}
		// TTL 2：够跨一层去查「是不是被路由挡了」，不至于灌进整张网。
		if err := pc.SetMulticastTTL(2); err != nil {
			c.Close()
			lastErr = fmt.Errorf("%w：%s 设不了组播范围：%s", errNoMulticast, name, err)
			continue
		}
		l.conns = append(l.conns, c)
		l.pkts = append(l.pkts, pc)
		l.ifaces = append(l.ifaces, name)
	}
	if len(l.conns) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("%w：没有可用的网卡", errNoMulticast)
		}
		return nil, lastErr
	}
	return l, nil
}

// sendPlan 把这一路的查询发出去。★ 第 i 个套接字就是第 i 块网卡上开的那个
// （multicastListener 是成对建的），所以出口不需要再设一次。
//
// 给了点名地址时发单播，否则发组播组。两种都用**同一个绑好源地址的套接字**：
// 单播包从哪块网卡出去是由源地址决定的，而回来的应答正好落回这个套接字，
// 「谁答的、从哪块网卡看到的」才不会被路由表悄悄换掉。
func (l *mcastListener) sendPlan(ctx context.Context, plan identifyPlan) error {
	payloads, err := planPayloads(l.proto, plan)
	if err != nil {
		return err
	}
	dsts, err := l.destinations(plan)
	if err != nil {
		return err
	}
	targeted := len(plan.Targets) > 0
	var lastErr error
	total := 0
	for _, dst := range dsts {
		sent := 0
		for _, pc := range l.pkts {
			for _, pl := range payloads {
				if _, err := pc.WriteTo(pl, nil, dst); err != nil {
					if ctx.Err() != nil {
						return nil // 已经被取消了：这一轮的应答没人要了，不当故障报
					}
					// 一块网卡发不出去不等于这一路失败（点名问跨网段时就会这样：
					// 不在这条路上的网卡必然被拒）。留着最后一次的错误，
					// 只在「一个包都没发出去」时才拿去报。
					lastErr = err
					continue
				}
				sent++
			}
		}
		total += sent
		if targeted {
			// 点名问：只要有一块网卡把它发出去了就算问过，一个都没发出去才记成没问成。
			if sent == 0 {
				l.markUnsent(dst.IP.String())
			} else {
				l.clearUnsent(dst.IP.String())
			}
		}
	}
	if !targeted && total == 0 && lastErr != nil {
		// 组播一个包都没发出去：整路失败。★ 这必须是错误，不能让它走到
		// 「没有设备应答」那个判定 —— 那是把「我们没问成」说成「网上没人」。
		return fmt.Errorf("组播发不出去（%s 这一路）：%w", l.proto, lastErr)
	}
	return nil
}

// markUnsent 记一个「问都没问成」的地址（见 askResult 的注释）。
func (l *mcastListener) markUnsent(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.unsent == nil {
		l.unsent = map[string]bool{}
	}
	l.unsent[addr] = true
}

// clearUnsent 一个地址在**任一**网卡上发出去过就不算没问成（两块网卡接两个网段是常态）。
func (l *mcastListener) clearUnsent(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.unsent, addr)
}

func (l *mcastListener) unsentAddrs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.unsent))
	for a := range l.unsent {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// destinations 这一轮把查询丢给哪些地址。
func (l *mcastListener) destinations(plan identifyPlan) ([]*net.UDPAddr, error) {
	if len(plan.Targets) == 0 {
		return []*net.UDPAddr{l.group}, nil
	}
	out := make([]*net.UDPAddr, 0, len(plan.Targets))
	for _, s := range plan.Targets {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%q 不是合法地址", s)
		}
		out = append(out, &net.UDPAddr{IP: ip, Port: l.group.Port})
	}
	return out, nil
}

// planPayloads 造这一路的查询报文。
func planPayloads(proto string, plan identifyPlan) ([][]byte, error) {
	switch proto {
	case protoSSDP:
		st := plan.ST
		if st == "" {
			st = "ssdp:all"
		}
		return [][]byte{broadcast.SSDPRequest(st, int(plan.Window/time.Second))}, nil
	case protoMDNS:
		q, err := broadcast.MDNSQuery(plan.Services, true)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "DNS-SD 查询造不出来：%s", err)
		}
		return [][]byte{q}, nil
	case protoWSDisco:
		return [][]byte{broadcast.WSDiscoveryProbe(plan.WSDTypes, "", "")}, nil
	}
	return nil, ots.Errf(ots.ErrInvalidArgument, "%s 这一路不是组播的", proto)
}

// collect 收到超时为止。
//
// ★ 每块网卡一个读取的 goroutine，而不是排队轮着读：轮着读的话，
//
//	三块网卡就是每条报文等三倍时间，第二块网卡上应得快的设备会被算成「没应」。
//	也不靠 socket 超时退出 —— 用 done 把读的那几个 goroutine 一起收掉，
//	套接字由调用方关。
func (l *mcastListener) collect(ctx context.Context, deadline time.Time, emit func([]broadcast.Report)) {
	type incoming struct {
		raw   []byte
		from  *net.UDPAddr
		iface string
	}
	var wg sync.WaitGroup
	ch := make(chan incoming, 256)
	done := make(chan struct{})
	for i, c := range l.conns {
		wg.Add(1)
		go func(c *net.UDPConn, iface string) {
			defer wg.Done()
			buf := make([]byte, 65535) // 一个 UDP 数据报的上限：mDNS 的应答常常贴着它
			for {
				c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, from, err := c.ReadFromUDP(buf)
				if err != nil {
					select {
					case <-done:
						return // 窗口到点了，正常收工
					default:
						continue // 这一次读超时：接着读，别的网卡上还有应答在来
					}
				}
				select {
				case ch <- incoming{raw: append([]byte(nil), buf[:n]...), from: from, iface: iface}:
				case <-done:
					return
				}
			}
		}(c, l.ifaces[i])
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case in := <-ch:
			emit(l.decode(in.raw, in.from, in.iface))
		case <-ctx.Done():
			close(done)
			wg.Wait()
			return
		case <-timer.C:
			close(done)
			wg.Wait()
			return
		}
	}
}

// decode 把一条报文交给对应协议的解码函数，并盖上「从哪块网卡看到的」。
func (l *mcastListener) decode(raw []byte, from *net.UDPAddr, iface string) []broadcast.Report {
	addr := from.IP.String()
	var reps []*broadcast.Report
	switch l.proto {
	case protoSSDP:
		if r, err := broadcast.ParseSSDP(raw, addr); err == nil {
			reps = []*broadcast.Report{r}
		}
	case protoMDNS:
		// ★ 应答的来源按**源地址**记：多播回来的那一条，源地址就是那台设备。
		if m, err := broadcast.ParseMDNS(raw); err == nil {
			reps = m.Reports(addr)
		}
	case protoWSDisco:
		if r, err := broadcast.ParseWSDiscovery(raw, addr); err == nil {
			reps = []*broadcast.Report{r}
		}
	}
	out := make([]broadcast.Report, 0, len(reps))
	for _, r := range reps {
		r.Iface = iface
		out = append(out, *r)
	}
	return out
}

func (l *mcastListener) close() {
	for _, c := range l.conns {
		c.Close()
	}
}

// netbiosRound 挨个点名问 node status。★ 只在已经知道哪些地址上有时才跑：
// 拿它扫整段是错的（那是 net.subnet.scan 的活）。
//
// 返回的 askResult.Failed 是「包连发都没发出去」的地址。★ 这个区分不是洁癖：
// 137 口被挡掉时发出去会立刻收到 ICMP 端口不可达，而那个 IP 不在这块网卡的网络上时
// 是直接 no route —— 两种都不该被记成「这台设备不说话」。
func netbiosRound(ctx context.Context, plan identifyPlan) askResult {
	var (
		mu     sync.Mutex
		all    []broadcast.Report
		failed []string
	)
	sem := make(chan struct{}, 16) // 同时问 16 台：再多就是拿这个工具当扫描器使了
	var wg sync.WaitGroup
	for i, s := range plan.NBAddrs {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			continue // 名称与 v6 一律不问：NetBIOS 这一路只有 v4 的写法
		}
		wg.Add(1)
		go func(trn uint16, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			req, err := broadcast.NodeStatusRequest(trn)
			if err != nil {
				return
			}
			// ★ 源地址交给内核按路由选：NetBIOS 是点名单播，要问的常常是**别的网段**
			//   （组播那一轮找到的地址就在本机另一块网卡的方向上）。这里再绑一个源地址
			//   等于替内核决定出口，绑错了就永远问不到 —— 和 net.wol 那一栏的取舍相反，
			//   因为wol 发的是广播，必须指定从哪个口喊。
			d := net.Dialer{}
			c, derr := d.DialContext(ctx, "udp4", net.JoinHostPort(target, "137"))
			if derr != nil {
				mu.Lock()
				addUnique(&failed, target)
				mu.Unlock()
				return
			}
			defer c.Close()
			if dl, ok := ctx.Deadline(); ok {
				c.SetDeadline(dl)
			} else {
				c.SetDeadline(time.Now().Add(plan.Window))
			}
			if _, err := c.Write(req); err != nil {
				mu.Lock()
				addUnique(&failed, target)
				mu.Unlock()
				return
			}
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil {
				return // 发了没人答：这一路被拦的机器太多，不记成「没问成」
			}
			ns, perr := broadcast.ParseNodeStatus(buf[:n])
			if perr != nil {
				return // 不应答 NetBIOS 的机器太多了，这不是判定，只是没消息
			}
			mu.Lock()
			for _, r := range ns.Reports(target) {
				all = append(all, *r)
			}
			mu.Unlock()
		}(uint16(i)+1, s)
	}
	wg.Wait()
	return askResult{Reports: all, Failed: failed}
}

// ── 参数与网卡挑选 ──

func pickIdentifyNICs(nics []netif.NIC, want string) (out []netif.NIC, skipped []string) {
	for _, n := range nics {
		if want != "" && n.Name != want {
			continue
		}
		switch {
		case n.Loop:
			continue // 回环上没有别人会应答组播
		case want == "" && n.Virtual:
			continue // 容器 / VPN 的虚拟口上问没意义，除非用户点名
		case !n.Up || !n.Running:
			skipped = append(skipped, n.Name+"：没启用或没插线")
		case !n.HasUsableV4():
			skipped = append(skipped, n.Name+"：没有可用的 IPv4 地址")
		case len(out) >= maxIdentifyIfaces:
			skipped = append(skipped, n.Name+"：一次最多问 "+fmt.Sprint(maxIdentifyIfaces)+" 块网卡")
		default:
			out = append(out, n)
		}
	}
	return out, skipped
}

func ifaceNames(nics []netif.NIC) []string {
	out := make([]string, 0, len(nics))
	for _, n := range nics {
		out = append(out, n.Name)
	}
	return out
}

// ifaceSources 每块网卡用哪个 IPv4 当源地址。
//
// ★ 取 netif 排好序的第一个可用地址：一块网卡上挂了几个 v4（虚 IP、第二个网段）时，
//
//	netif 的排序已经把「主地址」放在最前面。自己按字符串挑会挑到副地址，
//	而用副地址发出去的组播，应答回来时对方路由到的可能不是同一块网卡。
func ifaceSources(nics []netif.NIC) map[string]string {
	out := make(map[string]string, len(nics))
	for _, n := range nics {
		for _, a := range n.V4() {
			if a.Scope() == netaddr.ScopeLinkLocal {
				continue // 169.254 恰恰是「DHCP 没要到地址」的信号，拿它发组播没人应答
			}
			out[n.Name] = a.IP.String()
			break
		}
	}
	return out
}

func pickProtocols(in []string) ([]string, error) {
	if len(in) == 0 {
		return append([]string{}, allProtocols...), nil
	}
	ok := map[string]bool{}
	for _, p := range allProtocols {
		ok[p] = true
	}
	var out []string
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !ok[p] {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%q 不是会自报的协议 —— 只有 %s 这四种", p, strings.Join(allProtocols, " / "))
		}
		addUnique(&out, p)
	}
	if len(out) == 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "protocols 全被筛空了：至少留一种")
	}
	return out, nil
}

// parseTargets 把 addrs 参数摊成要点名的 IPv4 清单（单个 IP 或 CIDR 都认）。
//
// ★ 只收 IPv4：这四路的单播问法在市面上只有 v4 的设备实现稳定应答，
//
//	v6 要问就走组播（ff02::c / ff02::fb），拿 v6 地址点名单播会把「它没答」
//	误读成「它不在」。认不了的地址不猜，原样列进 skipped 给人看。
func parseTargets(in []string) (out, skipped []string, err error) {
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			pfx, perr := parseScanCIDR(s)
			if perr != nil {
				skipped = append(skipped, s+"：网段写法认不出来")
				continue
			}
			if !pfx.Addr().Is4() {
				skipped = append(skipped, s+"：点名单播只认 IPv4 网段")
				continue
			}
			for _, a := range hostList([]netip.Prefix{pfx}) {
				if len(out) >= maxNetBIOSTargets {
					skipped = append(skipped, fmt.Sprintf("点名地址超过 %d 个，后面的没问", maxNetBIOSTargets))
					return out, skipped, nil
				}
				addUnique(&out, a.String())
			}
			continue
		}
		ip, perr := netip.ParseAddr(s)
		if perr != nil {
			skipped = append(skipped, s+"：不是地址也不是网段")
			continue
		}
		if !ip.Is4() {
			skipped = append(skipped, s+"：点名单播只认 IPv4（v6 用组播问）")
			continue
		}
		if len(out) >= maxNetBIOSTargets {
			skipped = append(skipped, fmt.Sprintf("点名地址超过 %d 个，后面的没问", maxNetBIOSTargets))
			return out, skipped, nil
		}
		addUnique(&out, ip.String())
	}
	if len(in) > 0 && len(out) == 0 {
		return nil, skipped, ots.Errf(ots.ErrInvalidArgument,
			"addrs 一个都没解析出来：%s", strings.Join(skipped, "；"))
	}
	return out, skipped, nil
}

// netBIOTargets NetBIOS 要点名问哪些地址（没给 addrs 时）。
//
// ★ 只问**这一轮另外三路已经应答过的地址** —— 这不是偷懒，是这一路的正确用法：
//
//	NetBIOS 是唯一能给 MAC 的口径，用它去逐个地址试会把一次识别变成一次
//	全网段扫描（又慢又吵，而且那不是本工具的活：扫段用 net.subnet.scan）。
func netBIOTargets(reports []broadcast.Report) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reports {
		if r.MAC != "" || seen[r.From] || r.From == "" {
			continue // 已经有 MAC 的不用再问一遍
		}
		ip, err := netip.ParseAddr(r.From)
		if err != nil || !ip.Is4() {
			continue // NetBIOS 这一路只有 v4 的写法
		}
		seen[r.From] = true
		if len(out) >= maxNetBIOSTargets {
			break
		}
		addUnique(&out, r.From)
	}
	return out
}

// protocolTally 每一路「问了没有、应了几条、几个地址应的、点名叫了几个」。
//
// ★ 这一栏是整张卡片里最要紧的次要信息：只报「找到 5 台」，
//
//	人就会以为整个网段都在这儿；而 ONVIF 那一路回了 0 条完全可能是
//	「这一片摄像头关了发现服务」或「隔了一层」，那是要分开说的两件事。
func protocolTally(asked []string, ifaces int, reports []broadcast.Report, nbTargets int) []map[string]any {
	counted := map[string]int{}
	hosts := map[string]map[string]bool{}
	for _, r := range reports {
		counted[r.Source]++
		if hosts[r.Source] == nil {
			hosts[r.Source] = map[string]bool{}
		}
		hosts[r.Source][r.From] = true
	}
	askedSet := map[string]bool{}
	for _, a := range asked {
		askedSet[a] = true
	}
	out := make([]map[string]any, 0, len(allProtocols))
	for _, p := range allProtocols {
		row := map[string]any{"protocol": p, "asked": askedSet[p]}
		if p == protoNetBIOS {
			row["targets"] = nbTargets // 点名叫了几台：0 意味着另外三路一个地址都没问出来
		} else {
			row["targets"] = ifaces // 组播这一路是「每块网卡各问一遍」
		}
		row["reports"] = counted[p]
		row["hosts"] = len(hosts[p])
		out = append(out, row)
	}
	return out
}

// ── 描述文件（可选那一步） ──

// describeKnown 把 SSDP 应答里带的 LOCATION 取回来，摊成同一台设备下的又一条自报。
//
// ★ 为什么默认关：这是往设备上发一个 HTTP GET。它是只读的，但那台设备的
//
//	访问日志里会多一条 —— 现场有些设备（老的门禁、编码器）日志一满就重启。
//	所以「值不值得为多一个型号去碰它」由人决定，不由我们默认。
func describeKnown(ctx context.Context, src deviceSources, reports []broadcast.Report) []broadcast.Report {
	urls := map[string]string{} // addr → LOCATION
	var order []string
	for _, r := range reports {
		if r.Source != broadcast.SourceSSDP || r.URL == "" || r.From == "" {
			continue
		}
		// ★ 协议这一关在挑目标这里就把住，不交给取的那一步：LOCATION 是设备写的，
		//   它写 ftp://、写 file://、写一个别的什么都有可能，
		//   而这一栏只该发 HTTP 请求。
		if _, err := urlParse(r.URL); err != nil {
			continue
		}
		if _, have := urls[r.From]; have {
			continue
		}
		if len(urls) >= maxDescribeFetches {
			break
		}
		urls[r.From] = r.URL
		order = append(order, r.From) // ★ 按看到的顺序取，不按 map 顺序：同一份输入两次跑发出去的顺序要一样
	}
	var out []broadcast.Report
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, addr := range order { // ★ 按看到的顺序，不按 map 的顺序
		u := urls[addr]
		wg.Add(1)
		go func(addr, u string) {
			defer wg.Done()
			body, err := src.fetch(ctx, u)
			if err != nil {
				return // 取不到描述文件不改变任何判定：它只是少了一项「这台说了型号」
			}
			d, derr := broadcast.ParseDescription(body)
			if derr != nil {
				return
			}
			if r := d.Reports(addr, u); r != nil {
				r.Iface = ifaceOf(reports, addr) // 描述文件是顺着哪块网卡上那台设备取的
				mu.Lock()
				out = append(out, *r)
				mu.Unlock()
			}
		}(addr, u)
	}
	wg.Wait()
	return out
}

// ifaceOf 这个地址是从哪块网卡上看到的（组播那一轮已经记下来了）。
func ifaceOf(reports []broadcast.Report, addr string) string {
	for _, r := range reports {
		if r.From == addr && r.Iface != "" {
			return r.Iface
		}
	}
	return ""
}

// fetchDescription 取一份描述文件。
//
// ★ 只信 http/https，且大小与时间都卡死：LOCATION 是设备给的，
//
//	它写什么都有可能（写一个内网别的地址、写一个 60MB 的文件、写一个不答应的端口）。
func fetchDescription(ctx context.Context, u string) ([]byte, error) {
	ru, err := urlParse(u)
	if err != nil {
		return nil, err
	}
	cl := &http.Client{Timeout: describeTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ru, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("描述文件给了 %d，不是 200", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDescribeBytes))
}

// ── 小工具 ──

func urlParse(s string) (string, error) {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return "", fmt.Errorf("LOCATION %q 不是 http/https：这一栏不去碰别的东西", s)
	}
	return s, nil
}

func addUnique(list *[]string, v string) {
	if v == "" {
		return
	}
	for _, s := range *list {
		if s == v {
			return
		}
	}
	*list = append(*list, v)
}

func without(list []string, drop string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

func dedupStrings(in []string) []string {
	var out []string
	for _, s := range in {
		addUnique(&out, strings.TrimSpace(s))
	}
	return out
}
