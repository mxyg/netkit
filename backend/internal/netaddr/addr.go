// Package netaddr 是 NetKit 里**所有**地址的统一表示。
//
// ★★ 这个包存在的唯一理由：把「双栈」这件事在地基上做对一次，而不是在每个功能里各做一遍。
//
//	老板 2026-09-19：「这个项目要支持 ipv6。」
//	见 docs/设计.md「IPv6 支持」。那一节的四条纪律，三条落在这个包里：
//	  · 地址类型用 netip.Addr，不用 net.IP
//	  · 链路本地地址**存「地址 + 接口 ID」两个字段，不存拼好的字符串**
//	  · 「一台设备一个 IP」的数据结构一律是错的
//
// ★ 为什么不用 net.IP：它是 []byte，不可比较、不能当 map key、不带 zone、
//
//	同一个地址有 4 字节和 16 字节两种表示（v4 与 v4-in-v6 互相 == 不成立）。
//	netip.Addr 定长可比较、能当 map key、**自带 zone**，这三条正好是双栈要用的。
package netaddr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Scope 是地址的用途分类。
//
// ★ v6 和 v4 最大的形态差别在这里：v4 一块网卡通常就一个地址，
// v6 一块网卡**天生就有好几个**（链路本地 + ULA + 全局 + 隐私临时地址），
// 它们用途完全不同，混在一个列表里给用户看等于没给。
type Scope string

const (
	ScopeLoopback  Scope = "loopback"   // 127.0.0.0/8、::1
	ScopeLinkLocal Scope = "link-local" // 169.254.0.0/16、fe80::/10 —— v6 下**每块网卡必有**，且必须带 zone
	ScopePrivate   Scope = "private"    // 10/8 172.16/12 192.168/16（v4 私有）、fc00::/7（v6 ULA）
	ScopeGlobal    Scope = "global"     // 公网可路由
	ScopeMulticast Scope = "multicast"  // 224/4、ff00::/8
	ScopeUnspec    Scope = "unspecified"
)

// Label 给界面用的中文说明。不要在别处再写一份。
func (s Scope) Label() string {
	switch s {
	case ScopeLoopback:
		return "回环"
	case ScopeLinkLocal:
		return "链路本地"
	case ScopePrivate:
		return "内网"
	case ScopeGlobal:
		return "公网"
	case ScopeMulticast:
		return "组播"
	}
	return "未知"
}

// Addr 是一个地址，外加它挂在哪块网卡上。
//
// ★★ 关键设计：Zone 单独存**接口名**，不跟地址拼在一起。
//
//	fe80:: 地址不带 zone 根本没法用，而 zone 的写法**每个平台都不一样**：
//	  Linux / macOS  fe80::1%en0   接口名
//	  Windows        fe80::1%12    接口索引
//	所以内部只存接口名（人能看懂、跨平台稳定），要 Dial 的时候再按平台翻译成
//	当前系统认识的写法（见 DialString）。存拼好的字符串就等着在另一个平台上炸。
type Addr struct {
	IP     netip.Addr `json:"ip"`               // 不含 zone 的纯地址
	Prefix int        `json:"prefix"`           // 前缀长度；0 表示不知道
	Zone   string     `json:"zone,omitempty"`   // 接口名（不是索引），只有链路本地才需要
	ZoneID int        `json:"zoneID,omitempty"` // 接口索引，Windows 拼 zone 要用
	// Temporary 是 v6 隐私扩展（RFC 4941）临时地址。
	// 它会定期换，**不能拿来做绑定、登记、白名单**——这是 v6 上很常见的一个坑：
	// 今天记下的地址明天就不是它了。
	Temporary bool `json:"temporary,omitempty"`
}

// Is6 是不是 IPv6（v4-in-v6 映射地址算 v4，那本质上就是个 v4 地址）。
func (a Addr) Is6() bool { return a.IP.Is6() && !a.IP.Is4In6() }

// Is4 是不是 IPv4。
func (a Addr) Is4() bool { return a.IP.Is4() || a.IP.Is4In6() }

// NeedsZone 这个地址是不是非带 zone 不可。
//
// ★ v6 链路本地地址不带 zone 就是个废地址：同一条 fe80::1 可能挂在三块网卡上，
// 系统不知道该从哪块发出去。v4 的 169.254 虽然也是链路本地，但 v4 靠路由表选口，
// 不需要 zone —— 所以这里只认 v6。
func (a Addr) NeedsZone() bool { return a.Is6() && a.IP.IsLinkLocalUnicast() }

// Scope 判断地址用途。
func (a Addr) Scope() Scope {
	ip := a.IP
	switch {
	case !ip.IsValid():
		return ScopeUnspec
	case ip.IsUnspecified():
		return ScopeUnspec
	case ip.IsLoopback():
		return ScopeLoopback
	case ip.IsMulticast():
		return ScopeMulticast
	case ip.IsLinkLocalUnicast():
		return ScopeLinkLocal
	case ip.IsPrivate():
		// netip 的 IsPrivate 对 v6 认的是 fc00::/7（ULA），正是我们要的
		return ScopePrivate
	}
	return ScopeGlobal
}

// String 给人看的写法：带 zone，不带方括号。
func (a Addr) String() string {
	if !a.IP.IsValid() {
		return ""
	}
	s := a.IP.String()
	if a.Zone != "" && a.NeedsZone() {
		s += "%" + a.Zone
	}
	return s
}

// CIDR 带前缀长度的写法，如 192.168.1.10/24、fd00::1/64。前缀未知时退回 String。
func (a Addr) CIDR() string {
	if !a.IP.IsValid() || a.Prefix <= 0 {
		return a.String()
	}
	return a.String() + "/" + strconv.Itoa(a.Prefix)
}

// Network 这个地址所在的网段，如 192.168.1.0/24、fd00::/64。
func (a Addr) Network() (netip.Prefix, bool) {
	if !a.IP.IsValid() || a.Prefix <= 0 {
		return netip.Prefix{}, false
	}
	p, err := a.IP.Prefix(a.Prefix)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// DialString 拼出**当前这台机器**的网络库能用的地址串。
//
// ★★ 这是整个包最容易出错、也最值得单独成函数的一处：
//
//	Windows 的 zone 必须是**接口索引**（fe80::1%12），
//	Linux / macOS 必须是**接口名**（fe80::1%en0）。
//	写错的表现不是报错，是 Dial 到一个不存在的地方超时 —— 最难查的那种。
//
// goos 传 runtime.GOOS。单独作参数是为了能测所有平台（否则只能测本机这一个）。
func (a Addr) DialString(goos string) (string, error) {
	if !a.IP.IsValid() {
		return "", fmt.Errorf("地址是空的")
	}
	if !a.NeedsZone() {
		return a.IP.String(), nil
	}
	if goos == "windows" {
		if a.ZoneID <= 0 {
			return "", fmt.Errorf("链路本地地址 %s 在 Windows 上要用接口索引做 zone，但没拿到索引 —— "+
				"不能拿接口名 %q 硬拼，那样 Dial 会连到一个不存在的地方然后超时", a.IP, a.Zone)
		}
		return a.IP.String() + "%" + strconv.Itoa(a.ZoneID), nil
	}
	if a.Zone == "" {
		return "", fmt.Errorf("链路本地地址 %s 必须说清楚走哪块网卡（zone），否则系统不知道从哪个口发出去", a.IP)
	}
	return a.IP.String() + "%" + a.Zone, nil
}

// HostPort 拼 host:port。v6 **必须加方括号**，这是 RFC 3986 的要求，
// 也是双栈代码里最常见的低级错误之一（`fd00::1:8080` 根本分不清哪段是端口）。
func (a Addr) HostPort(port int, goos string) (string, error) {
	h, err := a.DialString(goos)
	if err != nil {
		return "", err
	}
	if a.Is6() {
		return "[" + h + "]:" + strconv.Itoa(port), nil
	}
	return h + ":" + strconv.Itoa(port), nil
}

// Parse 解析一个地址。
//
// ★ 宽进严出：用户从各种地方拷地址进来 —— 带方括号的（[fd00::1]）、
// 带 zone 的（fe80::1%en0）、带 Windows 索引 zone 的（fe80::1%12）、带前缀的（192.168.1.1/24）。
// 全都要认，因为「让用户自己记该写哪种」不是这个产品的作风。
func Parse(s string) (Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Addr{}, fmt.Errorf("地址是空的")
	}
	// [fd00::1] / [fe80::1%en0] —— 从 URL 里拷出来的常带方括号。
	// ★ 剥方括号时要把后面跟着的 /前缀 留住：`[fd00::1]/64` 两样都带的写法确实有人写
	//   （测试 TestParse宽进 抓到过：早先的实现在这里把 /64 一起吃掉了）。
	if strings.HasPrefix(s, "[") {
		if end := strings.LastIndex(s, "]"); end > 0 {
			rest := s[end+1:]
			s = s[1:end]
			if strings.HasPrefix(rest, "/") {
				s += rest
			}
		}
	}
	prefix := 0
	if i := strings.LastIndex(s, "/"); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return Addr{}, fmt.Errorf("看不懂前缀长度 %q", s[i+1:])
		}
		prefix = n
		s = s[:i]
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return Addr{}, fmt.Errorf("看不懂地址 %q", s)
	}
	a := Addr{IP: ip.WithZone(""), Prefix: prefix}
	if z := ip.Zone(); z != "" {
		// zone 是纯数字 → 是 Windows 那种接口索引；否则是接口名
		if n, err := strconv.Atoi(z); err == nil {
			a.ZoneID = n
		} else {
			a.Zone = z
		}
	}
	if prefix > 0 {
		max := 32
		if a.Is6() {
			max = 128
		}
		if prefix > max {
			return Addr{}, fmt.Errorf("前缀长度 /%d 超出了 %s 的上限 /%d", prefix, kind(a), max)
		}
	}
	return a, nil
}

func kind(a Addr) string {
	if a.Is6() {
		return "IPv6"
	}
	return "IPv4"
}

// SplitHostPort 拆 host:port，认方括号写法，也认没有端口的裸地址（端口返回 0）。
func SplitHostPort(s string) (Addr, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Addr{}, 0, fmt.Errorf("地址是空的")
	}
	// [fd00::1]:8080
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]")
		if end < 0 {
			return Addr{}, 0, fmt.Errorf("方括号没闭合：%q", s)
		}
		host := s[1:end]
		rest := s[end+1:]
		if rest == "" {
			a, err := Parse(host)
			return a, 0, err
		}
		if !strings.HasPrefix(rest, ":") {
			return Addr{}, 0, fmt.Errorf("方括号后面应该是 :端口，看到的是 %q", rest)
		}
		port, err := strconv.Atoi(rest[1:])
		if err != nil {
			return Addr{}, 0, fmt.Errorf("看不懂端口 %q", rest[1:])
		}
		a, err := Parse(host)
		return a, port, err
	}
	// 裸的 v6 地址冒号很多，只有**恰好一个**冒号才可能是 host:port
	if strings.Count(s, ":") == 1 {
		i := strings.Index(s, ":")
		port, err := strconv.Atoi(s[i+1:])
		if err == nil {
			a, err := Parse(s[:i])
			return a, port, err
		}
	}
	a, err := Parse(s)
	return a, 0, err
}
