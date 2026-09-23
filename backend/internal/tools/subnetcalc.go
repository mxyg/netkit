package tools

// ── net.subnet.calc ──
//
// ★★ 子网计算器看着像「谁都会算」，所以现场错的恰恰是它算的那一步：
//	把 255.0.255.0 这种**不连续的掩码**当成合法输入抄进设备，
//	把 192.168.1.100/24 里的 .100 当成网段地址登记，
//	以及最常见的 —— 新配的段和已经在线上的段**重叠**，
//	表现是「有时候连得上有时候连不上」，谁都不会往掩码上想。
//
//	所以顶层判定不是「算出来了」，是**这个输入本身值不值得信**：
//	掩码不连续当场拒；给的是主机地址 / 广播地址就点名点出来；
//	带了对照段就回答重不重叠 —— 重叠是唯一需要人去动手的结论。
//
// ★ v4 和 v6 不是一件事，不许共用一套字段：
//	v6 没有广播地址、没有「可用主机数 = 总数减二」这套规矩，
//	一个 /64 就有 1.8×10¹⁹ 个地址 —— 拿「能扫多少个」去问 v6 是问错了问题。

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

const (
	scSingle    = "single-address"  // 就一个地址，不是网段
	scNetwork   = "v4-network"      // 填的正是这个段的网络地址
	scHost      = "v4-host-address" // 填的是段里的一个主机地址（照样能算，但得点出来）
	scBroadcast = "v4-broadcast-address"
	scV6Prefix  = "v6-prefix"        // v6 段
	scOverlap   = "networks-overlap" // ★ 两个段撞了 —— 这是唯一一个「得有人去改配置」的结论
	scCrossFam  = "families-differ"  // 问的是 v4 和 v6 撞不撞 —— 这问题本身不成立，得明说
)

var subnetCalcTool = ots.Tool{
	Name:  "net.subnet.calc",
	Class: ots.ClassRead,
	Summary: "算一个网段：网络地址、掩码、通配码、广播地址、地址总数、可用主机段的首尾地址。" +
		"★ 填什么都认 —— CIDR（192.168.1.0/24）、点分掩码（192.168.1.0/255.255.255.0）、" +
		"裸地址（当成单地址并说明）。顶层判定说的是**这个输入值不值得信**：" +
		"single-address（就一个地址，不是段）、v4-network（填的正是网络地址）、" +
		"v4-host-address（填的是段里一个主机地址，登记网段时最容易拿错这个）、" +
		"v4-broadcast-address（填的是广播地址）、v6-prefix（v6 段，另有一套读法）。" +
		"★ 再多给一个段（peer）就问「两段重不重叠」—— networks-overlap 是现场那种" +
		"「有时候连得上有时候连不上」的根因；两段分属 v4 和 v6 时答 families-differ " +
		"（各自编址，谈不上撞）。掩码不连续当场报错，不用假掩码算出一个假网段。纯计算，不发任何包。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "cidr": {"type": "string",
	      "description": "要算的段或地址。接受 192.168.1.0/24、192.168.1.0/255.255.255.0、fe80::/64，也接受只写地址（按单地址算）。★ 掩码不连续（如 255.0.255.0）会直接报错而不是硬算。"},
	    "peer": {"type": "string",
	      "description": "另一个段，用来问「这两个撞不撞」。写法同 cidr。两个段只要有任意一个地址重合就算重叠，包含关系会另外标出来。"}
	  },
	  "required": ["cidr"]
	}`),
	Invoke: doSubnetCalc,
}

type subnetCalcArgs struct {
	CIDR string `json:"cidr"`
	Peer string `json:"peer,omitempty"`
}

// subnet 一个段：给定的地址 + 判出来的前缀。
//
// ★ given 和 net 要分开留：现场十分之八的输入给的是主机地址，
// 而人想知道的既包括「这个段是哪一段」也包括「我填的这个地址在段里排第几」。
type subnet struct {
	Given  netip.Addr
	Prefix netip.Prefix
	// Assumed 是真的没写掩码（前缀长度由我们按单地址补的）。
	// 必须带出来：不告诉人「这个 /32 是我猜的」，人以为本机就没配掩码。
	Assumed bool
	Text    string
}

func doSubnetCalc(ctx context.Context, raw json.RawMessage) (any, error) {
	var a subnetCalcArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if strings.TrimSpace(a.CIDR) == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "cidr 不能是空的 —— 要算段就得给地址，"+
			"写法如 192.168.1.0/24、192.168.1.0/255.255.255.0 或 fe80::/64")
	}
	sub, err := parseSubnet(a.CIDR)
	if err != nil {
		return nil, err
	}
	values := subnetFacts(sub)

	code := shapeCode(sub)
	if strings.TrimSpace(a.Peer) != "" {
		other, err := parseSubnet(a.Peer)
		if err != nil {
			return nil, fmt.Errorf("对照段：%w", err)
		}
		rel := relate(sub, other)
		for k, v := range rel {
			values[k] = v
		}
		if rel["overlaps"] == true {
			code = scOverlap
		} else if rel["notComparable"] == true {
			// ★ 问的是「v4 段和 v6 段撞不撞」—— 这问题本身不成立，不能咽下去答成
			// 「不撞」：两段各自编址，互不影响，真要问双栈得走 net.dualstack.check。
			code = scCrossFam
		}
	}
	return ots.Verdict{Code: code, Values: values, Note: subnetNote(code, sub, values)}, nil
}

// parseSubnet 宽进：CIDR、点分掩码、裸地址、带方括号的 v6 都认。
func parseSubnet(s string) (subnet, error) {
	text := strings.TrimSpace(s)
	body, maskPart, hasSlash := strings.Cut(text, "/")
	// [fd00::1]/64 —— 从 URL 里拷出来的写法
	if strings.HasPrefix(body, "[") && strings.HasSuffix(body, "]") {
		body = body[1 : len(body)-1]
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(body))
	if err != nil {
		// 让 netaddr 去给「为什么看不懂」—— 它的报错面向人（分得清前缀和地址）
		if _, e2 := netaddr.Parse(text); e2 != nil {
			return subnet{}, ots.Errf(ots.ErrInvalidArgument, "看不懂 %q：%s", text, e2)
		}
		return subnet{}, ots.Errf(ots.ErrInvalidArgument, "看不懂 %q：%s", text, err)
	}
	ip = ip.Unmap() // ::ffff:1.2.3.4 本质上就是个 v4 地址，别让它带着 v6 的壳去算段
	// ★ 作用域后缀（fe80::1%en0）在这里去掉：netip 认为「带 zone 的前缀」是非法值，
	// 留着它 Masked() 会返回一个空前缀，于是整栏答案变成 0.0.0.0/0 —— 不报错，只是全错。
	ip = ip.WithZone("")
	maxBits := 32
	if ip.Is6() {
		maxBits = 128
	}
	if !hasSlash {
		// ★ 没写掩码就按**单地址**算，并把「这个 /32 是补出来的」带出去。
		// 替人猜一个 /24 是这一栏最坏的错法：他会拿着猜出来的段去配设备。
		return subnet{Given: ip, Prefix: netip.PrefixFrom(ip, maxBits), Assumed: true, Text: text}, nil
	}
	if strings.TrimSpace(maskPart) == "" {
		// 写了斜杠却空着：他以为自己在填掩码，这时候按单地址算等于把错误咽下去
		return subnet{}, ots.Errf(ots.ErrInvalidArgument, "%q 的斜杠后面是空的 —— 掩码没填上。"+
			"要么写全（如 /24 或 /255.255.255.0），要么把斜杠一起去掉按一个地址算", text)
	}
	bits, err := prefixLen(maskPart, maxBits)
	if err != nil {
		return subnet{}, err
	}
	return subnet{Given: ip, Prefix: netip.PrefixFrom(ip, bits), Text: text}, nil
}

// prefixLen 前缀长度可以写成 /24，也可以写成 /255.255.255.0 —— 后者是
// 从设备配置页抄下来时的常态，必须认；★ 但**不连续的掩码必须报错**。
func prefixLen(part string, maxBits int) (int, error) {
	part = strings.TrimSpace(part)
	if strings.Contains(part, ".") {
		if maxBits == 128 {
			// v6 没有点分掩码这一写法。当 v4 掩码解会得到 /0 到 /32 之间的数，
			// 于是 fe80::/ffff:: 这类输入被算成一个大得离谱的段 —— 报错比硬算靠近人想问的。
			return 0, ots.Errf(ots.ErrInvalidArgument, "IPv6 只有前缀长度一种写法（如 /64），不认点分掩码 %s", part)
		}
		bits, err := maskToBits(part)
		if err != nil {
			return 0, err
		}
		return bits, nil
	}
	if strings.Contains(part, ":") || strings.Contains(part, "%") {
		return 0, ots.Errf(ots.ErrInvalidArgument, "斜杠后面写的是 %q，不像前缀长度也不像掩码", part)
	}
	n, err := strconv.Atoi(part)
	if err != nil {
		return 0, ots.Errf(ots.ErrInvalidArgument, "看不懂前缀长度 %q（要写 /24 这样的数字，或 /255.255.255.0 这样的掩码）", part)
	}
	if n < 0 || n > maxBits {
		return 0, ots.Errf(ots.ErrInvalidArgument, "前缀长度 /%d 超出 0 到 /%d", n, maxBits)
	}
	return n, nil
}

// maskToBits 点分掩码 → 前缀长度。
//
// ★★ 不连续的掩码（255.0.255.0 这类手滑）在这里就挡掉。
// 挡掉的理由不是洁癖：那种掩码在内核里根本不成段，
// 拿它算出一个「网段」会让人拿着一个假答案去改设备配置。
func maskToBits(mask string) (int, error) {
	ip, err := netip.ParseAddr(mask)
	if err != nil || ip.Is6() {
		return 0, ots.Errf(ots.ErrInvalidArgument, "掩码 %q 不是一个 IPv4 点分掩码", mask)
	}
	b := ip.As4()
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32(x)
	}
	bits := 0
	i := uint(31)
	for ; v&(1<<i) != 0 && i < 32; i-- { // 高位连续的 1
		bits++
		if i == 0 {
			break
		}
	}
	if v<<bits != 0 { // 低位还留着 1 → 不连续
		return 0, ots.Errf(ots.ErrInvalidArgument,
			"掩码 %s 的 1 不是连续的（二进制 %s）。这种掩码系统不接受，按它算出来的「网段」是假的 —— "+
				"检查一下是不是想写 255.255.0.0 / 255.255.255.0 这类",
			mask, maskBits(v))
	}
	return bits, nil
}

func maskBits(v uint32) string {
	var s []string
	for i := uint(31); ; i-- {
		if v&(1<<i) != 0 {
			s = append(s, "1")
		} else {
			s = append(s, "0")
		}
		if i == 0 {
			break
		}
	}
	return strings.Join(s, "")
}

func size(pfx netip.Prefix) *big.Int {
	bits := pfx.Bits()
	max := 32
	if pfx.Addr().Is6() {
		max = 128
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(max-bits))
}

// subnetFacts 一个段能给出的事实。
func subnetFacts(s subnet) map[string]any {
	pfx := s.Prefix.Masked()
	ip := s.Given
	is6 := ip.Is6()
	fam := "ipv4"
	maxBits := 32
	if is6 {
		fam = "ipv6"
		maxBits = 128
	}
	out := map[string]any{
		"input":       s.Text,
		"family":      fam,
		"given":       ip.String(),
		"canonical":   pfx.String(),
		"network":     pfx.Addr().String(),
		"prefix":      pfx.Bits(),
		"size":        size(pfx).String(),
		"givenIsNet":  ip == pfx.Addr(),
		"prefixAssum": s.Assumed,
	}
	if !is6 {
		out["mask"] = dottedU32(maskU32(pfx.Bits()))
		out["wildcard"] = dottedU32(^maskU32(pfx.Bits()))
		out["reverseZone"] = reverseZone(pfx)
	}
	if pfx.Bits() == maxBits {
		// 一个地址就是一段：首尾都是它自己。★ /32 也没有广播地址 ——
		// 把「它自己」标成广播，人会在设备上看到「广播地址 = 本机地址」这种荒唐一行。
		out["firstUsable"] = pfx.Addr().String()
		out["lastUsable"] = pfx.Addr().String()
		out["usable"] = "1"
		if is6 {
			// ★ /128 也得给性质：界面和 AI 都按 v6Notes.kind 说「这是链路本地的一个地址」，
			// 少了这一栏那条话就变成空的。
			out["v6Notes"] = v6Notes(pfx)
		}
		return out
	}
	last := lastAddr(pfx)
	if !is6 {
		if pfx.Bits() >= 31 {
			// ★ /31（RFC 3021）和 /32 一样没有网络地址/广播地址这一步 ——
			// 拿「总数减二」去算，得到的可用数比实际少 2，路由器互联口就会撞上
			out["firstUsable"] = pfx.Addr().String()
			out["lastUsable"] = last.String()
			out["usable"] = size(pfx).String()
			out["pointToPoint"] = true
		} else {
			out["firstUsable"] = incAddr(pfx.Addr()).String()
			out["lastUsable"] = decAddr(last).String()
			out["usable"] = new(big.Int).Sub(size(pfx), big.NewInt(2)).String()
			out["broadcast"] = last.String()
		}
		return out
	}
	// v6 没有广播地址，也没有「可用 = 总数 - 2」：一个 /64 就有 1.8×10¹⁹ 个地址，
	// 全段都能分。这里不许偷偷沿用 v4 那套减法 —— 那会把答案算小两名。
	out["firstUsable"] = pfx.Addr().String()
	out["lastUsable"] = last.String()
	out["usable"] = size(pfx).String()
	out["v6Notes"] = v6Notes(pfx)
	return out
}

func v6Notes(pfx netip.Prefix) map[string]any {
	n := map[string]any{"noBroadcast": true, "notEnumerable": pfx.Bits() < 128}
	switch {
	case pfx.Addr().IsPrivate():
		n["kind"] = "ula" // fc00::/7 —— 内网自建，不该往公网上发
	case pfx.Addr().IsLinkLocalUnicast():
		n["kind"] = "link-local" // fe80::/10 —— 内核自带，出不了这条链路
	case pfx.Addr().IsMulticast():
		n["kind"] = "multicast"
	case pfx.Addr().IsLoopback():
		n["kind"] = "loopback"
	case pfx.Addr().IsGlobalUnicast():
		n["kind"] = "global"
	default:
		n["kind"] = "unspec"
	}
	if pfx.Bits() < 64 {
		// 现场真正想知道的是「这个段能切出多少个 /64」—— 一个 /48 就是 65536 个
		n["sla64Count"] = new(big.Int).Lsh(big.NewInt(1), uint(64-pfx.Bits())).String()
	}
	return n
}

// maskU32 前缀长度 → 掩码的 32 位形式；通配码是它的按位取反。
//
// ★ 两个字段必须由同一个函数出：通配码不是「32-bits 个高位 1」，
// 那样 /24 会得到 128.0.0.0 —— 而它是配 ACL、静态路由时要抄进设备的一栏。
func maskU32(bits int) uint32 {
	switch {
	case bits <= 0:
		return 0
	case bits >= 32:
		return ^uint32(0)
	}
	return ^uint32(0) << uint(32-bits)
}

func dottedU32(v uint32) string {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}

func addrToBigInt(a netip.Addr) *big.Int {
	if a.Is4() || a.Is4In6() {
		return new(big.Int).SetUint64(uint64(addrToU32(a)))
	}
	return new(big.Int).SetBytes(a.AsSlice())
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func bigToAddr(v *big.Int, is6 bool) netip.Addr {
	if !is6 {
		return netip.AddrFrom4([4]byte{byte(v.Uint64() >> 24), byte(v.Uint64() >> 16), byte(v.Uint64() >> 8), byte(v.Uint64())})
	}
	b := v.Bytes()
	var full [16]byte
	copy(full[16-len(b):], b)
	return netip.AddrFrom16(full)
}

func incAddr(a netip.Addr) netip.Addr {
	return bigToAddr(new(big.Int).Add(addrToBigInt(a), big.NewInt(1)), a.Is6())
}

func decAddr(a netip.Addr) netip.Addr {
	return bigToAddr(new(big.Int).Sub(addrToBigInt(a), big.NewInt(1)), a.Is6())
}

func lastAddr(pfx netip.Prefix) netip.Addr {
	hostBits := new(big.Int).Sub(size(pfx), big.NewInt(1))
	return bigToAddr(new(big.Int).Or(addrToBigInt(pfx.Addr()), hostBits), pfx.Addr().Is6())
}

// reverseZone 反向解析区域名（in-addr.arpa）—— 配内网 DNS 时每次都要手拼。
//
// ★ 小于 /24 的段要按半个字节切（RFC 2317）：192.168.1.128/25 写成
// 1.168.192.in-addr.arpa 是和邻居撞区的，正确写法是 128-255.1.168.192.in-addr.arpa。
// 这一步手工极易拼错，直接给出结果比给公式有用。
func reverseZone(pfx netip.Prefix) string {
	if !pfx.Addr().Is4() {
		return ""
	}
	bits := pfx.Bits()
	if bits == 0 {
		return "" // 0.0.0.0/0 覆盖全部地址，反向区域名就是根，写出来反而误导
	}
	b := pfx.Addr().As4()
	full := bits / 8
	var parts []string
	if r := bits % 8; r != 0 {
		block := 1 << uint(8-r)
		lo := int(b[full]) &^ (block - 1)
		parts = append(parts, fmt.Sprintf("%d-%d", lo, lo+block-1))
	}
	for i := full - 1; i >= 0; i-- {
		parts = append(parts, strconv.Itoa(int(b[i])))
	}
	return strings.Join(parts, ".") + ".in-addr.arpa"
}

// relate 两个段的关系。
//
// ★ CIDR 段只有三种关系：不相交、谁把谁包住、两者相同 —— 不存在「交错重叠」
// （前缀对齐的段在数轴上要么嵌套要么分开）。所以这里不写 partial 那一档：
// 留一个永远进不去的分支，等于给以后的人留一个「以为测过」的坑。
func relate(a, b subnet) map[string]any {
	x, y := a.Prefix.Masked(), b.Prefix.Masked()
	out := map[string]any{"peer": y.String()}
	if x.Addr().Is6() != y.Addr().Is6() {
		out["overlaps"] = false
		out["notComparable"] = true // v4 和 v6 各自编址，谈不上撞
		return out
	}
	over := x.Contains(y.Addr()) || y.Contains(x.Addr())
	out["overlaps"] = over
	if !over {
		return out
	}
	switch {
	case x == y:
		out["contains"] = "identical"
		out["overlapSize"] = size(x).String()
	case x.Contains(y.Addr()): // y 更具体 → 对照段在填的这段里面
		out["contains"] = "peer-inside"
		out["overlapSize"] = size(y).String()
	default:
		out["contains"] = "peer-contains"
		out["overlapSize"] = size(x).String()
	}
	return out
}

func shapeCode(s subnet) string {
	pfx := s.Prefix.Masked()
	bits := pfx.Bits()
	if s.Given.Is6() {
		if bits == 128 {
			return scSingle
		}
		return scV6Prefix
	}
	if bits == 32 {
		return scSingle
	}
	// ★ /31 没有广播地址：RFC 3021 那一段的两个地址都能配给设备（路由器互联口）。
	// 按下末地址判成「广播」，人就不敢用那半个口 —— 这是会当场卡住开通的错法。
	if bits < 31 && s.Given == lastAddr(pfx) {
		return scBroadcast
	}
	if s.Given == pfx.Addr() {
		return scNetwork
	}
	return scHost
}

func subnetNote(code string, s subnet, v map[string]any) string {
	canon, _ := v["canonical"].(string)
	bits := s.Prefix.Bits()
	switch code {
	case scOverlap:
		how := map[string]string{
			"identical":     "两段**完全相同**",
			"peer-inside":   "填的这段把对照段**整个包住**了",
			"peer-contains": "对照段把填的这段**整个包住**了",
		}
		n := "★ 两段重叠：" + how[fmt.Sprint(v["contains"])] + "。" +
			"这就是「有时候连得上有时候连不上」的根因 —— 同一台机器上两条路由都能到一个地址，" +
			"走哪条看内核当时怎么选。得改掩码或改地址池，改完再问一次。"
		if sz, _ := v["overlapSize"].(string); sz != "" {
			n += "重叠部分是 " + sz + " 个地址。"
		}
		return n
	case scSingle:
		n := "这不是一个网段，是**一个地址**（/32 或 /128）。"
		if s.Assumed {
			return n + "★ 输入里没写掩码，所以按单地址算 —— 不替你猜一个 /24。" +
				"如果本意是算一个段，把掩码补上再问一次。"
		}
		return n + "如果本意是算一个段，那就是掩码填错了。"
	case scNetwork:
		switch {
		case bits == 0:
			return "0.0.0.0/0 是**所有地址**（默认路由写的就是它），不是一个可分配的网段。" +
				"★ 别把它当段去扫，也别拿它的地址数当地址池。"
		case bits == 31:
			return "填的正是网络地址 " + canon + "。★ /31 这一段两个地址都能配给设备（RFC 3021 互联口），" +
				"没有「减掉网络地址和广播地址」这一步。"
		}
		return "填的正是网络地址 " + canon + "，这个段是规整的。" +
			"★ 注意网络地址本身不能分给设备用（v4 里它是「这一段」的名字）。"
	case scHost:
		return "你填的是一个**主机地址**，它所在的段是 " + canon +
			"。★ 登记/配设备要的是段地址的时候，别把这台机器的地址抄进去 —— " +
			"这正是「掩码配对了但地址池还是撞了」的常见来源。"
	case scBroadcast:
		return "你填的是这个段的**广播地址**（" + canon + " 那一段的最后一个地址），" +
			"它不能配在任何设备上。★ 大概率是想填网络地址，末段该写 0。"
	case scV6Prefix:
		kind, _ := v6Kind(v)
		return "IPv6 段 " + canon + "，按 v6 的规矩读：没有广播地址、也没有「总数减二」这回事，" +
			"而一个段大到不可能拿去枚举（v6 扫描要走另一套办法）。" +
			"★ 地址性质：" + kind + noteExtra(v)
	case scCrossFam:
		return "这两段一个 IPv4、一个 IPv6，**各自编址，谈不上撞** —— 所以这个问题问不成立，" +
			"不是我确认了「不撞」。★ 两段可以同时在网，互不影响；" +
			"真要问「这台机器两族是不是都通」，用 net.dualstack.check。"
	}
	return ""
}

func v6Kind(v map[string]any) (string, map[string]any) {
	raw, _ := v["v6Notes"].(map[string]any)
	kind, _ := raw["kind"].(string)
	if kind == "" {
		kind = "未识别"
	}
	return kind, raw
}

// noteExtra 把「这个段能切出多少个 /64」这句人真正要的话补上。
func noteExtra(v map[string]any) string {
	_, raw := v6Kind(v)
	if n, _ := raw["sla64Count"].(string); n != "" {
		return "。可切出 /64 数量：" + n + "（v6 通常按 /64 分给一条链路）"
	}
	return ""
}
