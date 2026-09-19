// Package netif 枚举本机网卡。
//
// 来源：argus/hub/internal/netx/iface.go + pass/internal/netx/iface.go + relay 的 netinfo
// 三份同源分叉合并（见 docs/_research/README.md 的采纳裁定）。以 argus 版为基线。
//
// ★★ 合并时修掉的四处「v4 独大」假设 —— 原代码在纯 v6 或双栈环境下会给出**错误结论**：
//
//	① 原 iface.go 里 `if !ipnet.IP.IsLinkLocalUnicast() { ... }` **直接丢掉 v6 链路本地地址**。
//	   fe80:: 在 v6 上是每块网卡必有、且很多场合只能用它（邻居发现、无 RA 的直连排障）。
//	   丢掉它等于在 v6 现场把最有用的那个地址藏起来了。
//	② IPv4/IPv6 各存一个 []string：v6 丢了前缀长度、没有 zone、也分不出
//	   全局 / ULA / 链路本地 / 隐私临时地址 —— 而这几类的用途完全不同。
//	③ 排序 score() 只看 len(IPv4)：**纯 v6 网卡会被排到最后**，用户在列表底部找不到。
//	④ describeNIC 里 len(IPv4)==0 就说「没有拿到 IP 地址」：
//	   在 v6-only 环境下这是一句**错误的诊断**，会把人往错误方向带。
//
// 这个包只负责**读**。改配置（设静态/DHCP、改 DNS、启停网卡）是另一个包的事，
// 按 docs/设计.md 的原则，改系统的功能要先落盘登记再执行。
package netif

import (
	"fmt"
	"net"
	"sort"

	"net.yuhox.com/netkit/internal/netaddr"
)

// NIC 一张网卡。
//
// ★ 地址是**一个列表**，不是 IPv4/IPv6 两个字段 —— 见 docs/设计.md「IPv6 支持 · 四、写进纪律」：
// 「一台设备一个 IP」的数据结构一律是错的。v6 一块网卡天生就有好几个地址。
type NIC struct {
	Name    string `json:"name"`
	Index   int    `json:"index"` // 系统接口索引。★ Windows 上拼 v6 的 zone 要用它
	MAC     string `json:"mac"`
	MTU     int    `json:"mtu"`
	Up      bool   `json:"up"`       // 已启用
	Running bool   `json:"running"`  // 插着线 / 已连上
	Loop    bool   `json:"loopback"` //
	Virtual bool   `json:"virtual"`  // 容器 / 虚拟机 / VPN 建的

	Addrs []netaddr.Addr `json:"addrs"` // 全部地址，v4 v6 混在一起，按有用程度排序

	// Verdict 是这块网卡处于什么状态的**结构化判定**，不是一句话。
	// ★ 文案由前端按当前语言渲染 —— 后端只给判定，不给句子。
	//   见 verdict.go 开头那段（老板 2026-09-19：要支持多语种，参考 stage）。
	Verdict Verdict `json:"verdict"`
}

// v4 / v6 分别取出来给界面分组用。**内部逻辑不要靠这两个函数做判断**，
// 要判断「有没有地址」请用 HasUsableV4 / HasUsableV6。
func (n NIC) V4() []netaddr.Addr {
	return filter(n.Addrs, func(a netaddr.Addr) bool { return a.Is4() })
}
func (n NIC) V6() []netaddr.Addr {
	return filter(n.Addrs, func(a netaddr.Addr) bool { return a.Is6() })
}

// HasUsableV4 有没有**能用来跟别人通信**的 v4 地址。
// 169.254 自动私有地址不算 —— 它恰恰表示「DHCP 没要到地址」，是故障信号不是可用地址。
func (n NIC) HasUsableV4() bool {
	for _, a := range n.Addrs {
		if a.Is4() {
			switch a.Scope() {
			case netaddr.ScopePrivate, netaddr.ScopeGlobal:
				return true
			}
		}
	}
	return false
}

// HasUsableV6 有没有能跟别人通信的 v6 地址（ULA 或全局）。
//
// ★ 和 v4 的差别：链路本地在这里同样不算「可用」，但含义完全不同 ——
// v4 的 169.254 是故障，v6 的 fe80:: 是**正常且必有**的，只是它只能在本链路上用。
// 所以 fe80:: 不会让 HasUsableV6 为真，但也绝不该被当成故障，见 describe()。
func (n NIC) HasUsableV6() bool {
	for _, a := range n.Addrs {
		if a.Is6() {
			switch a.Scope() {
			case netaddr.ScopePrivate, netaddr.ScopeGlobal:
				return true
			}
		}
	}
	return false
}

// HasLinkLocalV6 有没有 v6 链路本地地址。
// 没有它往往说明这块网卡的 v6 被整个关掉了 —— 这是个值得告诉用户的信息。
func (n NIC) HasLinkLocalV6() bool {
	for _, a := range n.Addrs {
		if a.Is6() && a.Scope() == netaddr.ScopeLinkLocal {
			return true
		}
	}
	return false
}

// Networks 这块网卡所在的全部网段（v4 v6 都有）。
func (n NIC) Networks() []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range n.Addrs {
		if a.Scope() == netaddr.ScopeLinkLocal || a.Scope() == netaddr.ScopeLoopback {
			continue
		}
		if p, ok := a.Network(); ok && !seen[p.String()] {
			seen[p.String()] = true
			out = append(out, p.String())
		}
	}
	return out
}

func filter(in []netaddr.Addr, keep func(netaddr.Addr) bool) []netaddr.Addr {
	var out []netaddr.Addr
	for _, a := range in {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

// Interfaces 枚举本机网卡。
//
// 多网卡工控机很常见：一个口接设备网、一个口接办公网、一个口上外网。
// 界面上要把它们都列出来让用户标注用途，否则谁也说不清「设备到底该接哪个口」。
func Interfaces() ([]NIC, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("读取本机网卡失败: %w", err)
	}
	out := make([]NIC, 0, len(ifs))
	for _, in := range ifs {
		n := NIC{
			Name:    in.Name,
			Index:   in.Index,
			MAC:     in.HardwareAddr.String(),
			MTU:     in.MTU,
			Up:      in.Flags&net.FlagUp != 0,
			Running: in.Flags&net.FlagRunning != 0,
			Loop:    in.Flags&net.FlagLoopback != 0,
			Virtual: IsVirtualName(in.Name),
		}
		if addrs, err := in.Addrs(); err == nil {
			n.Addrs = collect(addrs, in.Name, in.Index)
		}
		n.Verdict = n.Judge()
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := score(out[i]), score(out[j])
		if si != sj {
			return si > sj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// collect 把系统给的地址转成我们的 Addr，**一个都不丢**。
//
// ★ 原 argus 版在这里丢掉了 v6 链路本地地址。这次不丢，改成「全收下 + 排序 + 标清用途」：
// 要不要显示是界面的事，不是枚举的事。枚举层偷偷少给一条，上层永远不知道自己少看了什么。
func collect(addrs []net.Addr, ifname string, ifindex int) []netaddr.Addr {
	var out []netaddr.Addr
	for _, raw := range addrs {
		ipnet, ok := raw.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netipFrom(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		a := netaddr.Addr{IP: ip, Prefix: ones}
		if a.NeedsZone() {
			// ★ 两个字段都填上：接口名给人看和给 Linux/macOS Dial，索引给 Windows Dial。
			//   见 netaddr.Addr.DialString —— 这里少填一个，到了另一个平台就 Dial 不出去。
			a.Zone = ifname
			a.ZoneID = ifindex
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := addrScore(out[i]), addrScore(out[j])
		if si != sj {
			return si > sj
		}
		return out[i].String() < out[j].String()
	})
	return out
}

// addrScore 地址的有用程度：能跟外面通的排前面，链路本地和回环靠后。
func addrScore(a netaddr.Addr) int {
	s := 0
	switch a.Scope() {
	case netaddr.ScopeGlobal:
		s = 40
	case netaddr.ScopePrivate:
		s = 30
	case netaddr.ScopeLinkLocal:
		s = 10
	case netaddr.ScopeLoopback:
		s = 5
	}
	// 同档里 v4 略靠前：现在的现场绝大多数还是先看 v4。
	// ★ 只是**同档内**的次序，不影响「纯 v6 网卡排不排得上去」——那是 score() 的事。
	if a.Is4() {
		s++
	}
	// 隐私临时地址会定期换，不能拿来绑定/登记，所以同档里排到正式地址后面
	if a.Temporary {
		s -= 5
	}
	return s
}

// score 网卡的有用程度，决定列表顺序。
//
// ★ 原版只看 len(IPv4)，纯 v6 网卡会被排到最后。这里改成「有没有可用地址」，
// v4 v6 一视同仁 —— 在 v6-only 现场，那块网卡才是用户唯一要找的那块。
func score(n NIC) int {
	s := 0
	if n.HasUsableV4() {
		s += 4
	}
	if n.HasUsableV6() {
		s += 4
	}
	if n.Running {
		s += 2
	}
	if !n.Virtual {
		s += 2
	}
	if n.Loop {
		s -= 8
	}
	return s
}
