package tools

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.subnet.scan ──
//
// ★ 这一栏答的是「这个网段上现在有谁」。v4 下这件事**没有一个万能办法**，四种路子各有盲区：
//
//	读 ARP 表：零成本、零打扰，但它是**缓存** —— 「我缓存里没有它」不是「它不在」的证据。
//	   （这条纪律是 net.discover 真机跑出来的教训，在这里同样成立。）
//	ICMP 回显：设备拦 ICMP 太常见了（摄像头上那一键「禁 ping」）。只看回执的扫描会漏掉一半设备，
//	   然后被人当成「工具不准」。
//	ARP 解析的副作用：往同网段发包，内核必须先做 ARP 解析 —— 对方哪怕拦了 ICMP，只要还应 ARP 就露出来了。
//	TCP 连一下：只在扫**路由过来**的网段时才有价值，那种情况下 ARP 根本用不上。
//
// 所以这里把几条并起来，而且每台都带着「凭什么说它在线」。
// ★★ 最要紧的一条：什么都没信号时只能说「没问到」，不能说「不在线」。
//
// ★ 只扫 IPv4。v6 不能这么扫（一个 /64 是 1.8×10^19 个地址，逐个问永远问不完），
//   v6 那一套是组播 + 听 RA，已经做成 net.discover。

const (
	scanNetFound = "hosts-found" // 问到了，清单在 hosts
	scanNetEmpty = "no-hosts"    // 一个信号都没收到（**不是**「这个网段是空的」）
)

// 在线的证据，按强弱分档。★ 报「谁在线」而不说凭什么，人就不敢信这张表。
const (
	evICMP  = "icmp"      // 收到它的 ICMP 回显应答 —— 最硬的一条
	evARP   = "arp"       // 它应了 ARP 但没应 ICMP：拦 ping 的设备就靠这条才不遗漏
	evCache = "arp-cache" // 还没发包，本机 ARP 表里就已经有它（可能是很久以前留下的，最弱）
	evTCP   = "tcp"       // 端口连上了、或者明确回了 RST —— 两种都说明主机在
)

const (
	// 一次最多问多少个地址。/24 是 254 个，/22 是 1022 个。
	// ★ 再大就不是「看看这个网段有谁」而是拿它当扫描器使了：又慢又吵，
	//   而且一个 /16 有六万多个地址，扫它会把这台机器变成网络里的噪音源。
	defaultScanNetMax = 1024
	hardScanNetMax    = 4096
	// TCP 兜底时探的端口。★ 目的是「拿到一个回执」而不是「列服务」—— 列服务有 net.ports.scan。
	defaultScanNetPorts = "22,80,443,554,8000"
)

var subnetScanTool = ots.Tool{
	Name:  "net.subnet.scan",
	Class: ots.ClassRead,
	Summary: "扫一个 IPv4 网段，列出**这个网段上现在有谁**：地址、MAC、走哪块网卡，" +
		"以及每台是凭什么证据被判成在线的（icmp / arp / arp-cache / tcp）。" +
		"不填 cidr 就扫本机自己所在的各个网段。\n" +
		"多策略是必需的：ARP 表只是缓存（里面没有 ≠ 它不在），设备拦 ICMP 又很常见，" +
		"所以先看缓存、再主动发包（顺带把 ARP 解析逼出来）收 ICMP 回执，扫路由过来的网段时可选地用 TCP 兜底。\n" +
		"★ arp / arp-cache 两档都要求那条邻居记录**真的解析出了 MAC**：表里那些 <incomplete> / FAILED " +
		"占位行是「问了没应」的证据，不是「它在这儿」的证据（发一轮包就能把整段地址塞成占位行）。\n" +
		"判定：hosts-found（问到了，清单在 hosts，每台带 evidence）、" +
		"no-hosts（**一个信号都没收到** —— 这不能当成网段是空的：整段被静默、" +
		"或者这段其实是路由过来的，都是这个形状）。\n" +
		"★ 只扫 IPv4。IPv6 不能这么扫（/64 枚举不完），用 net.discover。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "cidr": {"type": "string",
	      "description": "要扫的网段，如 192.168.1.0/24。留空 = 本机所在的各个网段。"},
	    "iface": {"type": "string",
	      "description": "只扫某块网卡所在的网段（cidr 留空时有效），如 en0 / Ethernet 3。"},
	    "maxHosts": {"type": "integer", "minimum": 2, "maximum": 4096,
	      "description": "一次最多问多少个地址，默认 1024（约 /22）。超过就直接拒，不许悄悄截断 —— 截断了人会以为没列出来的就是不在。"},
	    "waitMs": {"type": "integer", "minimum": 200, "maximum": 10000,
	      "description": "发完一轮后等多久收回执，默认 1500。网段里设备慢、或者隔着无线就调大。"},
	    "tcpPorts": {"type": "string",
	      "description": "可选：给还没信号的地址再 TCP 连这几个端口当兜底，写法同 net.ports.scan（如 22,80,554）。扫**路由过来**的网段时建议填 —— 那种网段上 ARP 用不上。"}
	  }
	}`),
	Invoke: doSubnetScan,
}

type subnetScanArgs struct {
	CIDR     string `json:"cidr,omitempty"`
	Iface    string `json:"iface,omitempty"`
	MaxHosts int    `json:"maxHosts,omitempty"`
	WaitMS   int    `json:"waitMs,omitempty"`
	TCPPorts string `json:"tcpPorts,omitempty"`
}

// scanHost 是一台被问到过的设备。★ Evidence 不是装饰：同一张表里，
// 「收到它自己的 ICMP 应答」和「缓存里有条旧记录」是两个可信度。
type scanHost struct {
	Addr      string `json:"addr"`
	MAC       string `json:"mac,omitempty"`
	Iface     string `json:"iface,omitempty"`
	Evidence  string `json:"evidence"`
	Detail    string `json:"detail,omitempty"`
	ElapsedMS int64  `json:"elapsedMs,omitempty"`
}

func doSubnetScan(ctx context.Context, raw json.RawMessage) (any, error) {
	var a subnetScanArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	maxHosts := a.MaxHosts
	if maxHosts <= 0 {
		maxHosts = defaultScanNetMax
	}
	if maxHosts > hardScanNetMax {
		maxHosts = hardScanNetMax
	}
	wait := 1500 * time.Millisecond
	if a.WaitMS > 0 {
		wait = time.Duration(a.WaitMS) * time.Millisecond
	}

	nics, err := netif.Interfaces()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "读网卡清单失败：%s", err)
	}
	local, skipped := localV4Subnets(nics, a.Iface)

	var prefixes []netip.Prefix
	if a.CIDR != "" {
		pfx, perr := parseScanCIDR(a.CIDR)
		if perr != nil {
			return nil, perr
		}
		prefixes = []netip.Prefix{pfx}
	} else {
		if len(local) == 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"本机没有可扫的 IPv4 网段（网卡没插线、没拿到地址，或者只有虚拟网卡）。"+
					"要么把线插好，要么把 cidr 直接填上。跳过：%s", strings.Join(skipped, "；"))
		}
		prefixes = local
	}

	onLink := coveredByAny(prefixes, local)
	all := hostList(prefixes)
	targets, self := dropOwn(all, ownV4Addrs(nics))
	if overflow := len(targets) > maxHosts; overflow {
		// ★ 不许「悄悄只扫前 1024 个」：没列出来的那些会被当成「不在」，那是凭空造的结论。
		hint := "把网段填小一点（一个 /24 一个 /24 地来）"
		if a.CIDR == "" {
			hint = "用 iface 指定一块网卡，或者把 cidr 填成具体网段"
		}
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"要问的地址有 %d 个，超过上限 %d —— 那不叫「看看这个网段有谁」，那是扫描器：又慢又吵，"+
				"还会把摄像头的防爆破触发，而且被限速之后结果反而更不全。%s（maxHosts 最多 %d）",
			len(targets), maxHosts, hint, hardScanNetMax)
	}

	values := map[string]any{
		"subnets": prefixStrings(prefixes),
		"family":  "ipv4",
		"asked":   len(targets),
		"onLink":  onLink,
	}
	if len(self) > 0 {
		// 自己的地址不列进「发现清单」，但要说明为什么少了一个 —— 否则人以为漏了。
		values["skippedSelf"] = self
	}
	if len(skipped) > 0 && a.CIDR == "" {
		values["skippedIface"] = skipped
	}

	hosts := map[string]*scanHost{}
	// ① 先读缓存：一个包都不发，快且不打扰。
	before := arpByAddr(ctx)
	markCache(hosts, targets, before)

	// ② 主动发一轮 ICMP。★ 真正值钱的副作用是内核为了发这些包必须先做 ARP 解析 ——
	//    所以下一步能从表里捞出那些「拦了 ICMP 但还应 ARP」的设备。
	replies, sockErr := icmpSweep(ctx, targets, wait)
	if sockErr != nil {
		// 权限一类的问题如实报。★ 绝不许把「我发不出去」演成「这个网段里没人」。
		return nil, sockErr
	}
	markReplies(hosts, replies)

	// ③ 再看一眼缓存：这一轮新冒出来的 MAC 就是应了 ARP 没应 ICMP 的那批。
	markARP(hosts, targets, arpByAddr(ctx))

	// ④ 可选 TCP 兜底：扫路由过来的网段时 ARP 完全用不上，全靠这条。
	ports, perr := scanNetTCPPorts(a, onLink)
	if perr != nil {
		return nil, perr
	}
	if pending := missingHosts(hosts, targets); len(ports) > 0 && len(pending) > 0 {
		markTCP(ctx, hosts, pending, ports, wait)
		values["tcpProbed"] = len(pending)
	}

	live := aliveList(hosts)
	values["hosts"] = live
	values["alive"] = len(live)
	values["noSignal"] = len(targets) - len(live)

	switch {
	case len(live) > 0:
		return ots.Verdict{Code: scanNetFound, Values: values,
			Note: fmt.Sprintf("%s 上问到了 %d 台（一共问了 %d 个地址）—— 每台都带着凭什么判定它在线：%s",
				strings.Join(prefixStrings(prefixes), "、"), len(live), len(targets),
				evidenceSummary(live))}, nil
	default:
		return ots.Verdict{Code: scanNetEmpty, Values: values,
			Note: fmt.Sprintf("问了 %s 的 %d 个地址，一个信号都没收到 —— 这不能当成「这个网段是空的」：%s",
				strings.Join(prefixStrings(prefixes), "、"), len(targets), emptySubnetHint(onLink))}, nil
	}
}

// scanNetTCPPorts 决定 TCP 兜底要不要跑、跑哪几个端口。
// ★ 用户没填时**不自动跑**：扫自己所在的链路用不着它（ARP 比它灵），
//
//	而扫路由过来的网段没它就只能靠 ICMP 一条路 —— 那才是需要它的场合。
func scanNetTCPPorts(a subnetScanArgs, onLink bool) ([]int, error) {
	s := strings.TrimSpace(a.TCPPorts)
	if s == "" {
		if onLink {
			return nil, nil
		}
		s = defaultScanNetPorts
	}
	ports, err := parsePortList(s)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "tcpPorts 看不懂：%s", err)
	}
	return ports, nil
}

// emptySubnetHint 分两种情况指下一步 —— 本机链路和路由过来的网段，查的方向完全不同。
func emptySubnetHint(onLink bool) string {
	if !onLink {
		return "这个网段不是本机所在的链路，ARP 用不上，只能靠 ICMP 和 TCP；" +
			"中间那道路由要是把 ICMP 静默丢了，就一个回执都收不到。带上 tcpPorts 再扫一次"
	}
	return "本网段的设备可能被统一静默了（交换机隔离端口、防火墙拦 ICMP）；" +
		"也先确认本机这块网卡真的接在这个网里 —— 看 net.interfaces，和「连通性」页顶部的双栈体检"
}

func evidenceSummary(live []scanHost) string {
	n := map[string]int{}
	for _, h := range live {
		n[h.Evidence]++
	}
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d 台", k, n[k]))
	}
	return strings.Join(parts, "、")
}

// parseScanCIDR 收 "192.168.1.0/24"。
// ★ 只收带前缀长度的写法：只给一个地址时不许猜它是 /24 还是 /8 ——
//
//	猜错的后果不是报错，是「扫出来的人比实际少」，而这种错在现场看不出来。
func parseScanCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		return netip.Prefix{}, ots.Errf(ots.ErrInvalidArgument,
			"cidr %q 没写前缀长度 —— 要填成 192.168.1.0/24 这样。不敢替你猜这个网段有多大", s)
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, ots.Errf(ots.ErrInvalidArgument, "cidr %q 看不懂：%s", s, err)
	}
	if !pfx.Addr().Is4() {
		return netip.Prefix{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 不是 IPv4 网段 —— IPv4 才这么扫。IPv6 一个 /64 有 1.8×10^19 个地址，逐个问是问不完的，用 net.discover", s)
	}
	if pfx.Bits() > 30 {
		return netip.Prefix{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 掩码长过 /30 了，这一栏问不出东西 —— 问一台主机用 net.ping / net.tcp.probe", s)
	}
	return pfx.Masked(), nil
}

// localV4Subnets 取本机所在的 IPv4 网段。
// ★ 没插线、只有 169.254、虚拟网卡的一律排除：扫这些「网段」只会得到一片空结果，
//
//	而空结果在现场会被读成「这个网段没人」——那是把人往错方向引。
func localV4Subnets(nics []netif.NIC, want string) (out []netip.Prefix, skipped []string) {
	for _, n := range nics {
		if want != "" && !strings.EqualFold(n.Name, want) {
			continue
		}
		if n.Loop {
			continue // 回环压根不算一档，不占跳过说明的位置
		}
		if !n.Up || !n.Running {
			skipped = append(skipped, n.Name+"（没插线或没启用）")
			continue
		}
		if n.Virtual {
			skipped = append(skipped, n.Name+"（虚拟网卡，扫它问的是本机内部）")
			continue
		}
		for _, a := range n.V4() {
			pfx, ok := a.Network()
			if !ok {
				continue
			}
			if a.Scope() != netaddr.ScopePrivate && a.Scope() != netaddr.ScopeGlobal {
				skipped = append(skipped, n.Name+" 的 "+a.IP.String()+"（link-local：DHCP 没要到地址，这段里问不到别人）")
				continue
			}
			if pfx.Bits() > 30 {
				continue
			}
			if !containsPrefix(out, pfx.Masked()) {
				out = append(out, pfx.Masked())
			}
		}
	}
	return out, skipped
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

// coveredByAny 要扫的这些网段，是不是都落在本机某块网卡真的连着的那一段里。
// ★ 这决定了 ARP 这条证据**能不能用**：路由过来的网段上，ARP 表里永远只有网关那一台，
//
//	于是「扫不到人」几乎必然，如果不说清这一点，结果就是凭空的一句「这段是空的」。
func coveredByAny(scanned, local []netip.Prefix) bool {
	if len(scanned) == 0 {
		return false
	}
	for _, s := range scanned {
		hit := false
		for _, l := range local {
			if l.Bits() <= s.Bits() && l.Contains(s.Addr()) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// hostList 展开要问的地址。★ 网络地址和广播地址都不问：
// 前者不是主机地址，后者会引来整段设备一起答 —— 那张表就没法读了，而且最容易被人当成攻击。
func hostList(prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, pfx := range prefixes {
		for ip := pfx.Addr().Next(); pfx.Contains(ip); ip = ip.Next() {
			if !pfx.Contains(ip.Next()) {
				break // 手里这个是广播地址
			}
			if !hasAddr(out, ip) {
				out = append(out, ip)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return addrLessAddr(out[i], out[j]) })
	return out
}

func hasAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// dropOwn 把本机自己的地址从「发现清单」里剔出去：问自己必然有回执，
// 于是每台机器扫完都会在自己那段里多出一行莫名其妙的记录。
func dropOwn(addrs []netip.Addr, own map[string]bool) ([]netip.Addr, []string) {
	out := make([]netip.Addr, 0, len(addrs))
	var self []string
	for _, a := range addrs {
		if own[a.String()] {
			self = append(self, a.String())
			continue
		}
		out = append(out, a)
	}
	return out, self
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// ownV4Addrs 本机在用的 IPv4（不含回环 —— 回环上的地址不是「设备」）。
func ownV4Addrs(nics []netif.NIC) map[string]bool {
	out := map[string]bool{}
	for _, n := range nics {
		if n.Loop {
			continue
		}
		for _, a := range n.V4() {
			out[a.IP.String()] = true
		}
	}
	return out
}

// arpByAddr 读 ARP 表：地址 → 那一条邻居记录。
//
// ★★ 只收**带 MAC 的那几条**。解析没成功的地址在表里同样占一行（macOS 打
//
//	`<incomplete>`、Linux 打 `FAILED`），它的意思是「我问了，它没应」，不是「它在这儿」。
//	这条是被现场打出来的：扫自己所在的 /24 时，一轮 ICMP 把整段地址都塞成了占位条目，
//	于是 253 个地址全被判成在线 —— 一张全是鬼的清单。宁可漏报也不能这么报。
func arpByAddr(ctx context.Context) map[string]neighbor {
	ns, err := neighborsV4(ctx)
	if err != nil {
		return map[string]neighbor{}
	}
	return neighborsByAddr(ns)
}

// neighborsByAddr 按地址索引邻居表，并且只留下**解析成功**的那些。
// ★ 存进去的 MAC 一律规整过（补零、小写、冒号分隔）：各平台打法不一样，
//
//	不规整的话同一台设备在清单里能出现两种写法，OUI 查询也对不上。
func neighborsByAddr(ns []neighbor) map[string]neighbor {
	out := map[string]neighbor{}
	for _, n := range ns {
		m := normMAC(n.MAC)
		if n.Addr == "" || m == "" {
			continue
		}
		n.MAC = m
		if _, dup := out[n.Addr]; !dup {
			out[n.Addr] = n
		}
	}
	return out
}

// markCache 发包之前表里就有的：算在线，但证据是最弱的一档（缓存可能是很久以前留下的）。
func markCache(hosts map[string]*scanHost, targets []netip.Addr, before map[string]neighbor) {
	for _, t := range targets {
		s := t.String()
		if n, ok := before[s]; ok {
			hosts[s] = &scanHost{Addr: s, MAC: normMAC(n.MAC), Iface: n.Iface, Evidence: evCache}
		}
	}
}

// markReplies 收到 ICMP 回显应答的。★ 这是最强的信号，直接盖过缓存那条记录。
func markReplies(hosts map[string]*scanHost, replies map[string]int64) {
	for s, ms := range replies {
		h := hosts[s]
		if h == nil {
			h = &scanHost{Addr: s}
			hosts[s] = h
		}
		h.Evidence = evICMP
		h.ElapsedMS = ms
	}
}

// markARP 这一轮之后 ARP 表里的记录。★ 分两种情况：
//
//	一台都没记过的地址现在有了 MAC —— 它就是「应了 ARP 但拦了 ICMP」那一档，
//	  这一条正是拦 ping 的设备唯一会被列出来的原因。
//	已经记过一笔（收到 ICMP 回执，或者发包前缓存里就有）—— 只把 MAC、网卡补齐，
//	  证据不许往弱的那档改。
func markARP(hosts map[string]*scanHost, targets []netip.Addr, after map[string]neighbor) {
	for _, t := range targets {
		s := t.String()
		n, ok := after[s]
		if !ok {
			continue
		}
		h := hosts[s]
		if h == nil {
			hosts[s] = &scanHost{Addr: s, MAC: normMAC(n.MAC), Iface: n.Iface, Evidence: evARP}
			continue
		}
		if h.MAC == "" {
			h.MAC = normMAC(n.MAC)
		}
		if h.Iface == "" {
			h.Iface = n.Iface
		}
	}
}

// markTCP 用 TCP 兜底：连上了、或者明确被拒（RST）都说明这台主机在。
// ★ 「没回话」不算信号 —— 那正是分不清在不在的那一档，不许拿它凑数。
func markTCP(ctx context.Context, hosts map[string]*scanHost, targets []netip.Addr, ports []int, wait time.Duration) {
	if len(ports) == 0 || len(targets) == 0 {
		return
	}
	to := 600 * time.Millisecond
	if wait < to {
		to = wait
	}
	type hit struct {
		addr    string
		port    int
		status  string
		elapsed int64
	}
	hits := make(chan hit, len(targets))
	sem := make(chan struct{}, 32) // ★ 有界，理由同 net.ports.scan
	var wg sync.WaitGroup
	goos := runtime.GOOS
	for _, t := range targets {
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			addr := netaddr.Addr{IP: a}
			for _, p := range ports {
				if ctx.Err() != nil {
					return
				}
				r := scanOne(ctx, addr, p, to, goos)
				if r.Status == verdictOpen || r.Status == verdictClosed {
					hits <- hit{addr: a.String(), port: p, status: r.Status, elapsed: r.ElapsedMS}
					return
				}
			}
		}(t)
	}
	go func() { wg.Wait(); close(hits) }()
	for h := range hits {
		// ★ 只补还没信号的那些： ICMP 回执比「端口有应答」硬得多，
		//   一律覆盖会把硬证据改写成弱证据，反而让人以为只能靠端口猜。
		if cur := hosts[h.addr]; cur != nil && cur.Evidence != "" {
			continue
		}
		hosts[h.addr] = &scanHost{Addr: h.addr, Evidence: evTCP,
			Detail:    fmt.Sprintf("端口 %d %s", h.port, h.status),
			ElapsedMS: h.elapsed}
	}
}

// missingHosts 到现在还没有任何信号的地址。
func missingHosts(hosts map[string]*scanHost, targets []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, t := range targets {
		if h := hosts[t.String()]; h == nil || h.Evidence == "" {
			out = append(out, t)
		}
	}
	return out
}

func aliveList(hosts map[string]*scanHost) []scanHost {
	out := make([]scanHost, 0, len(hosts))
	for _, h := range hosts {
		if h.Evidence != "" {
			out = append(out, *h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return addrLess(out[i].Addr, out[j].Addr) })
	return out
}

func addrLess(a, b string) bool {
	aa, ea := netip.ParseAddr(a)
	bb, eb := netip.ParseAddr(b)
	if ea != nil || eb != nil {
		return a < b
	}
	return addrLessAddr(aa, bb)
}

func addrLessAddr(a, b netip.Addr) bool {
	return binary.BigEndian.Uint32(a.AsSlice()) < binary.BigEndian.Uint32(b.AsSlice())
}

// icmpSweep 朝整串地址各发一个 ICMP 回显，然后读到超时为止。
//
// ★ 和 net.ping 的差别是「一发多收」：这里不指望谁一定答，要的是谁在有限的时间里吭了声。
//
//	★★ 识别回复**只按源地址**，不按 ICMP ID —— 非特权的数据报 ICMP 套接字上内核会自己
//	改写 ID（和别的 ping 进程共用这台机器时，ID 根本不由我们定），
//	拿 ID 去对就会把别人的应答算成自己的、或者把自己的丢掉。
func icmpSweep(ctx context.Context, targets []netip.Addr, wait time.Duration) (map[string]int64, error) {
	got := map[string]int64{}
	if len(targets) == 0 {
		return got, nil
	}
	self, err := netaddr.Parse("0.0.0.0")
	if err != nil {
		return got, nil
	}
	conn, lerr := listenICMP(self)
	if lerr != nil {
		return got, lerr
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("yuhox-netkit-scan")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return got, ots.Errf(ots.ErrInternal, "构造 ICMP 包失败：%s", err)
	}

	want := make(map[string]bool, len(targets))
	start := time.Now()
	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		want[t.String()] = true
		_, _ = conn.WriteTo(b, &net.UDPAddr{IP: net.IP(t.AsSlice())})
		// 别把一千个包挤在同一微秒里发出去：交换机和主机的 ICMP 栈会直接丢，
		// 症状是「明明在线却扫不到」，而且从结果上看不出是发包太快。
		if i%16 == 15 {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Millisecond):
			}
		}
	}

	deadline := start.Add(wait)
	buf := make([]byte, 1500)
	for {
		// ★ 每 100ms 醒一次看有没有被取消：界面上点了停，就不能还闷头等那一段等待时间。
		//   不用「另开协程把套接字关掉」那一招 —— macOS 上关掉之后 Read 返回的是
		//   "use of closed network connection" 而不是超时，会把「取消」错分类成别的结论。
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		next := time.Now().Add(100 * time.Millisecond)
		if deadline.Before(next) {
			next = deadline
		}
		if err := conn.SetReadDeadline(next); err != nil {
			break
		}
		n, peer, rerr := conn.ReadFrom(buf)
		if rerr != nil {
			continue // 这一小段没等到包；是不是整轮结束了，由上面的时钟说了算
		}
		p, ok := peer.(*net.UDPAddr)
		if !ok {
			continue
		}
		src := net.IP(p.IP).String()
		if !want[src] {
			continue // 不是要问的那些（本机别的进程引来的应答）
		}
		m, perr := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
		if perr != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if _, dup := got[src]; !dup {
			got[src] = time.Since(start).Milliseconds()
		}
	}
	return got, nil
}
