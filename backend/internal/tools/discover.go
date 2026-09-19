package tools

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// 发现的判定码。
//
// ★★ 这个工具存在的全部理由，是回答现场那个最常见也最难办的问题：
//
//	「新设备插上交换机了，但没人给它配 IP，我怎么找到它？」
//
// IPv4 下这个问题**无解** —— 没有地址就没法扫，只能扛显示器键盘一台台配。
// 但 IPv6 下它是**天生解决的**：内核给每块网卡自动配一个 fe80:: 链路本地地址，
// 不需要 DHCP、不需要任何人授权、插上网线就有。往 ff02::1（本链路全部节点）
// 喊一嗓子，所有活着的设备都会应答，连那些一个 IPv4 都没有的也会。
//
// 判定分三种，区分的是**「有没有找到没配网的」**，因为那才是要人干活的信号：
const (
	verdictFoundUnconfigured = "found-unconfigured" // 有设备只有链路本地地址，没有 v4 —— 大概率是没配网的新设备
	verdictAllConfigured     = "all-configured"     // 应答的设备都已经有 v4 地址
	verdictNoResponder       = "no-responder"       // 一个应答都没有
	verdictNoLinkLocal       = "no-link-local"      // 本机这块网卡自己就没有 v6 链路本地地址，喊不出去
)

var discoverTool = ots.Tool{
	Name:  "net.discover",
	Class: ots.ClassRead,
	Summary: "把本链路上**还没配 IP 的设备**找出来。往 ff02::1（本链路全部节点）发 ICMPv6，" +
		"所有活着的设备都会应答，包括一个 IPv4 地址都没有的新设备 —— 它们靠内核自动配的 " +
		"fe80:: 链路本地地址应答，不需要 DHCP。" +
		"★ 这是 IPv4 做不到的事：没有地址的设备在 IPv4 下根本扫不出来。" +
		"现场典型用法：新设备插上交换机、网里又没有 DHCP，用它直接定位，" +
		"然后 ssh 到 fe80::xxx%网卡名 上去配地址，不用接显示器键盘。" +
		"结果会标出每台设备有没有 v4 地址 —— 没有的就是要你去配的那些。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "iface": {"type": "string",
	      "description": "只在某块网卡上找，如 en0 / eth1。不给就在所有插着线的物理网卡上找。"},
	    "rounds": {"type": "integer", "minimum": 1, "maximum": 10,
	      "description": "喊几轮，默认 3。设备偶尔漏应答一次，多喊两轮更稳。"},
	    "waitMs": {"type": "integer", "minimum": 200, "maximum": 10000,
	      "description": "每轮等多久收应答，默认 1000。"},
	    "probeV4": {"type": "boolean",
	      "description": "关联前先把本网段的 IPv4 过一遍，好让\"没有 v4\"成为有证据的结论而不是\"缓存里没有\"。默认 true。网段大于 /22 时自动跳过。"}
	  }
	}`),
	Invoke: doDiscover,
}

type discoverArgs struct {
	Iface   string `json:"iface,omitempty"`
	Rounds  int    `json:"rounds,omitempty"`
	WaitMS  int    `json:"waitMs,omitempty"`
	ProbeV4 *bool  `json:"probeV4,omitempty"`
}

// found 一台被喊出来的设备。
type found struct {
	LinkLocal string  `json:"linkLocal"`      // fe80:: 地址，带 zone，可以直接拿去 ssh
	Iface     string  `json:"iface"`          // 从哪块网卡看到的
	MAC       string  `json:"mac,omitempty"`  // 从 NDP 邻居表补的
	IPv4      string  `json:"ipv4,omitempty"` // 从 ARP 表按 MAC 对出来的
	HasIPv4   *bool   `json:"hasIPv4"`        // ★ 三态：true 有 / false 没有 / null 不知道。见 doDiscover 里的说明
	Self      bool    `json:"self,omitempty"` // 本机自己（多播会把自己也喊应）
	RTTMs     float64 `json:"rttMs,omitempty"`
}

func doDiscover(ctx context.Context, raw json.RawMessage) (any, error) {
	var a discoverArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	rounds := a.Rounds
	if rounds <= 0 {
		rounds = 3
	}
	wait := time.Duration(a.WaitMS) * time.Millisecond
	if wait <= 0 {
		wait = time.Second
	}

	nics, err := netif.Interfaces()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "列网卡失败：%s", err)
	}
	targets, skipped := pickDiscoverNICs(nics, a.Iface)
	if len(targets) == 0 {
		// ★ 这不是"没找到设备"，是"压根没喊出去"。两者必须分开报，
		//   否则用户会以为网上真没设备，而实际是本机 IPv6 被关了 ——
		//   现场踩过这个坑：网卡 IPv6 一关，fe80:: 就没有，喊都喊不出去。
		vals := map[string]any{"interfaces": []string{}}
		if len(skipped) > 0 {
			vals["skipped"] = skipped
		}
		if a.Iface != "" {
			vals["requested"] = a.Iface
		}
		return ots.Verdict{Code: verdictNoLinkLocal, Values: vals,
			Note: "没有一块可用的网卡有 IPv6 链路本地地址（fe80::）—— " +
				"多半是这块网卡把 IPv6 关了。打开后再试：" +
				"macOS `networksetup -setv6automatic <服务名>`；" +
				"Linux `sysctl -w net.ipv6.conf.<网卡>.disable_ipv6=0`"}, nil
	}

	// 先喊，再读邻居表 —— 顺序不能反。
	// ★ 邻居表是缓存，喊之前多半是空的；正是这一轮多播把它填满的。
	var all []found
	var probeErrs []string
	for _, n := range targets {
		got, err := sweepLinkLocal(ctx, n.Name, rounds, wait)
		if err != nil {
			probeErrs = append(probeErrs, n.Name+"："+err.Error())
			continue
		}
		all = append(all, got...)
	}

	// ★★ 关联之前先把本网段的 IPv4 过一遍 —— 这一步是真机跑出来才加上的。
	//   不加的症状：ARP 缓存过期后，6 台配好地址的摄像头全被判成"没配网"，
	//   现场工程师照着结论去挨个查好设备。ARP 表是缓存，
	//   **"缓存里没有"不是"它没有 v4"的证据**，得自己去把证据造出来。
	probeV4 := a.ProbeV4 == nil || *a.ProbeV4
	var primed []string
	if probeV4 {
		for _, n := range targets {
			primed = append(primed, primeARP(ctx, n)...)
		}
	}

	macByLL := linkLocalMACs(ctx)
	v4ByMAC := ipv4ByMAC(ctx)
	selfMACs := map[string]bool{}
	for _, n := range nics {
		if m := normMAC(n.MAC); m != "" {
			selfMACs[m] = true
		}
	}

	for i := range all {
		mac := normMAC(macByLL[all[i].LinkLocal])
		all[i].MAC = mac
		all[i].Self = mac != "" && selfMACs[mac]
		switch {
		case mac == "":
			// 邻居表里没补到 MAC，对不上 ARP，只能说不知道。
			all[i].HasIPv4 = nil
		case v4ByMAC[mac] != "":
			t := true
			all[i].HasIPv4, all[i].IPv4 = &t, v4ByMAC[mac]
		case !probeV4 || len(primed) == 0:
			// 没探过（或没网段可探）就只有缓存这一个来源，
			// 而缓存里没有**不构成证据** —— 如实说不知道，不硬给 false。
			all[i].HasIPv4 = nil
		default:
			// 探过本网段仍然没出现在 ARP 表里：这是有证据的"没有 v4"。
			// ★ 仍然不是绝对的 —— 它的 v4 可能在**别的网段**上（我们只探了自己这段）。
			//   所以判定的 note 里必须保留这句，不能让人拿着结论去拔别人的网线。
			f := false
			all[i].HasIPv4 = &f
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Iface != all[j].Iface {
			return all[i].Iface < all[j].Iface
		}
		return all[i].LinkLocal < all[j].LinkLocal
	})

	unconfigured := 0
	for _, f := range all {
		if !f.Self && f.HasIPv4 != nil && !*f.HasIPv4 {
			unconfigured++
		}
	}

	names := make([]string, 0, len(targets))
	for _, n := range targets {
		names = append(names, n.Name)
	}
	values := map[string]any{
		"interfaces":   names,
		"devices":      all,
		"count":        len(all),
		"unconfigured": unconfigured,
	}
	if len(primed) > 0 {
		values["probedV4Networks"] = primed
	}
	if len(skipped) > 0 {
		values["skipped"] = skipped
	}
	if len(probeErrs) > 0 {
		values["failed"] = probeErrs
	}

	switch {
	case len(all) == 0:
		return ots.Verdict{Code: verdictNoResponder, Values: values,
			Note: "喊出去了，但一个应答都没有。注意这不等于链路上没有设备 —— " +
				"有些系统（尤其 Windows）默认不应答多播回显请求"}, nil
	case unconfigured > 0:
		return ots.Verdict{Code: verdictFoundUnconfigured, Values: values,
			Note: "有设备在链路本地上应答，但把本网段的 IPv4 过了一遍仍然没见到它 —— " +
				"大概率是还没配网的新设备。它的 v4 也可能在别的网段上（只探了本网段），" +
				"动手之前先按 linkLocal 连上去确认是哪一台"}, nil
	}
	return ots.Verdict{Code: verdictAllConfigured, Values: values,
		Note: "应答的设备都已经有 IPv4 地址"}, nil
}

// pickDiscoverNICs 挑该往哪些网卡上喊。
//
// ★ 只挑**有 fe80:: 的**：没有链路本地地址就发不出去，硬发只会得到一个
// "no route to host"，对用户毫无信息量。挑不中的原因要带回去告诉他。
func pickDiscoverNICs(nics []netif.NIC, want string) (out []netif.NIC, skipped []string) {
	for _, n := range nics {
		if want != "" && n.Name != want {
			continue
		}
		switch {
		case n.Loop:
			continue
		case want == "" && n.Virtual:
			// 虚拟网卡（docker0 / VPN）上喊没意义，除非用户点名要
			continue
		case !n.Up || !n.Running:
			skipped = append(skipped, n.Name+"：没启用或没插线")
		case !n.HasLinkLocalV6():
			skipped = append(skipped, n.Name+"：没有 IPv6 链路本地地址（IPv6 可能被关了）")
		default:
			out = append(out, n)
		}
	}
	return out, skipped
}

// sweepLinkLocal 往 ff02::1 喊 rounds 轮，把所有应答的源地址收回来。
//
// ★ 和 net.ping 的区别在于**收包的方式**：ping 只认自己那一个对端，
// 这里是一发多收 —— 一个请求会引来整条链路上所有设备的应答，
// 所以不能收到第一个就返回，要一直读到超时，并且按源地址去重。
func sweepLinkLocal(ctx context.Context, ifname string, rounds int, wait time.Duration) ([]found, error) {
	mcast, err := netaddr.Parse("ff02::1%" + ifname)
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "拼多播地址失败：%s", err)
	}
	conn, err := listenICMP(mcast)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.IP(mcast.IP.AsSlice()), Zone: ifname}
	seen := map[string]found{}

	for r := 1; r <= rounds; r++ {
		if err := ctx.Err(); err != nil {
			break
		}
		msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0,
			Body: &icmp.Echo{Seq: r, Data: []byte("yuhox-netkit-discover")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "组包失败：%s", err)
		}
		start := time.Now()
		if _, err := conn.WriteTo(b, dst); err != nil {
			return nil, ots.Errf(ots.ErrUnreachable, "往 %s 发多播失败：%s", dst, err)
		}

		deadline := start.Add(wait)
		buf := make([]byte, 1500)
		for {
			if err := conn.SetReadDeadline(deadline); err != nil {
				break
			}
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				break // 超时：这一轮收完了
			}
			rm, err := icmp.ParseMessage(58, buf[:n])
			if err != nil {
				continue
			}
			// ★ 非特权 ICMP 下内核会改写 ID，只能认 Seq（同 ping.go 里那条注释）。
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok || echo.Seq != r {
				continue
			}
			ll := peerLinkLocal(peer, ifname)
			if ll == "" {
				continue
			}
			if _, dup := seen[ll]; !dup {
				seen[ll] = found{LinkLocal: ll, Iface: ifname, RTTMs: ms(time.Since(start))}
			}
		}
	}

	out := make([]found, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	return out, nil
}

// peerLinkLocal 把应答方的地址规整成带 zone 的字符串，且**只要链路本地的**。
//
// ★ 只收 fe80:: 是有意的：这个工具卖点就是"没配 IP 也能找到"，
// 全局地址那些本来就能用别的办法发现，混进来只会让结果变噪音。
func peerLinkLocal(peer net.Addr, ifname string) string {
	ua, ok := peer.(*net.UDPAddr)
	if !ok {
		return ""
	}
	a, err := netaddr.Parse(ua.IP.String())
	if err != nil || !a.NeedsZone() {
		return ""
	}
	// 内核回填的 zone 有时是接口索引（%19），统一换成接口名 —— 索引换台机器就变了，
	// 存进结果里给人复制粘贴用会出事。
	a.Zone = ifname
	return a.String()
}

// linkLocalMACs 读 NDP 邻居表，得到 fe80:: → MAC。
func linkLocalMACs(ctx context.Context) map[string]string {
	out := map[string]string{}
	ns, err := neighborsV6(ctx)
	if err != nil {
		return out
	}
	for _, n := range ns {
		if n.MAC == "" || n.Addr == "" {
			continue
		}
		out[n.Addr] = n.MAC
	}
	return out
}

// ipv4ByMAC 读 ARP 表，得到 MAC → IPv4。
func ipv4ByMAC(ctx context.Context) map[string]string {
	out := map[string]string{}
	ns, err := neighborsV4(ctx)
	if err != nil {
		return out
	}
	for _, n := range ns {
		m := normMAC(n.MAC)
		if m == "" || n.Addr == "" {
			continue
		}
		if _, dup := out[m]; !dup {
			out[m] = n.Addr
		}
	}
	return out
}

// normMAC 把 MAC 规整成可比较的形式。
//
// ★ 非补零不可：macOS 的 arp 打的是 3c:6d:66:ba:3:f7（单位数不补零），
// ndp 打的是 3c:6d:66:ba:03:f7。不规整就永远对不上，
// 结果是每台设备都被判成"没配网"—— 这个 bug 在现场会让人白跑一趟。
func normMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "(incomplete)" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return ""
		}
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// primeARP 把这块网卡自己所在的 IPv4 网段过一遍，好让 ARP 表有内容可查。
//
// ★★ 这个函数是真机跑出来才加的，起因是一个会误伤好设备的 bug：
// ARP 是缓存，隔一会儿就过期。缓存空了之后，6 台地址配得好好的摄像头
// 全被判成"没配网"。**"我的缓存里没有它" 不是 "它没有地址" 的证据。**
// 要给出否定结论，就得自己先把证据造出来 —— 主动问一遍，问了还不吭声才算数。
//
// 发的是 ICMP 回显，但真正起作用的是**副作用**：往同网段某个地址发包，
// 内核必须先 ARP 解析它。所以哪怕对方把 ICMP 拦了、只要它还应 ARP，
// 我们照样能拿到 MAC —— 这比指望对方回 ping 可靠得多。
//
// 返回探过的网段，写进结果里：用户得知道这个"没有 v4"的结论是**在哪个范围内**成立的。
func primeARP(ctx context.Context, n netif.NIC) []string {
	var done []string
	for _, a := range n.V4() {
		pfx, ok := a.Network()
		if !ok || !pfx.Addr().Is4() {
			continue
		}
		bits := pfx.Bits()
		// ★ 大于 /22（1024 个地址）就不探了。再大就不是"顺手问一遍"而是全网扫描，
		//   既慢又吵 —— 一个发现工具不该在用户没要求时把整个 B 段扫一遍。
		if bits < 22 || bits > 30 {
			continue
		}
		if !primeOneNet(ctx, pfx) {
			continue
		}
		done = append(done, pfx.String())
	}
	return done
}

func primeOneNet(ctx context.Context, pfx netip.Prefix) bool {
	self, err := netaddr.Parse("0.0.0.0")
	if err != nil {
		return false
	}
	conn, err := listenICMP(self)
	if err != nil {
		return false
	}
	defer conn.Close()

	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{Seq: 1, Data: []byte("yuhox-netkit-arp")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	// 网络地址和广播地址不发。
	ip := pfx.Masked().Addr().Next()
	for pfx.Contains(ip) {
		next := ip.Next()
		if !pfx.Contains(next) {
			break // 最后一个是广播地址
		}
		if err := ctx.Err(); err != nil {
			return false
		}
		_, _ = conn.WriteTo(b, &net.UDPAddr{IP: net.IP(ip.AsSlice())})
		ip = next
	}
	// 给 ARP 解析留出完成的时间。不等的话表还没填好就去读，等于没探。
	select {
	case <-ctx.Done():
	case <-time.After(1200 * time.Millisecond):
	}
	return true
}
