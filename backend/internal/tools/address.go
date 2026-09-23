package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// RegisterAddress 装上「给网卡设地址」的工具。
func RegisterAddress(r *ots.Registry) { r.MustRegister(addressSetTool) }

// ── net.address.set（mutate：改的是本机网络配置）──

var addressSetTool = ots.Tool{
	Name:  "net.address.set",
	Class: ots.ClassMutate,
	Summary: "给本机一块网卡设静态 IPv4 地址。" +
		"★ 典型场景：USB/有线网卡插在一台没有 DHCP 的交换机上，系统只会给它 169.254 的自派地址，" +
		"而 DHCP 服务器自己必须先有固定 IP —— 这个工具就是把这条路打通的。" +
		"需要管理员/root 权限；改动登记进账本，可以还原回自动获取。" +
		"★ 新网段和别的网卡现有网段重叠时直接拒绝 —— 那会让路由打架，症状是玄学断网。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["iface", "ip"],
	  "properties": {
	    "iface":  {"type": "string", "description": "网卡名，如 en5 / eth0 / 以太网 2"},
	    "ip":     {"type": "string", "description": "要设的 IPv4 地址，必须是私网地址（10/172.16/192.168 段）"},
	    "prefix": {"type": "integer", "minimum": 8, "maximum": 30, "description": "前缀长度，默认 24"}
	  }
	}`),
	Describe: describeAddressSet,
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a addressSetArgs
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if a.Prefix == 0 {
			a.Prefix = 24
		}
		nic, ip, err := validateAddressArgs(a)
		if err != nil {
			return nil, err
		}
		// ★ 报出去、写进账本、设进系统的都是**主机地址**（192.168.50.1/24），
		//   不是网段地址（192.168.50.0/24）。早先这里用了 .Masked() 之后的前缀，
		//   把主机位抹成 0，结果给网卡设上了网段地址本身 —— 那块网卡根本不能用来通信。
		cidr := netip.PrefixFrom(ip, a.Prefix).String()

		// 幂等：已经设着一模一样的，就不折腾系统了
		for _, ad := range nic.Addrs {
			if ad.Is4() && ad.IP == ip && ad.Prefix == a.Prefix {
				return ots.Verdict{Code: "already-set",
					Values: map[string]any{"iface": nic.Name, "cidr": cidr},
					Note:   fmt.Sprintf("%s 上已经设着 %s，没有重复动手", nic.Name, cidr)}, nil
			}
		}

		if journal == nil {
			// ★ 和 dhcp.serve 同一条纪律：没有账本就不许改系统
			return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝改系统")
		}
		// ★ [OTS-7.5] 先登记再动手
		id, err := journal.Register("static-address", describeAddressSet(raw),
			map[string]any{"iface": nic.Name, "mode": "auto"},
			map[string]any{"iface": nic.Name, "cidr": cidr})
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "登记改动失败，没有动手：%s", err)
		}
		if err := netif.SetStaticIPv4(nic.Name, ip.String(), a.Prefix); err != nil {
			_ = journal.Drop(id, "设地址失败，没有改动："+err.Error())
			return nil, ots.Errf(ots.ErrPermissionRequired,
				"%s。（改地址需要管理员权限：Windows 以管理员身份运行；macOS/Linux 需要 root）", err)
		}
		_ = journal.MarkApplied(id)
		/*
		 * ★ 诚实校验：配置确实写进系统了，但网卡**有没有真的用上**这个地址是另一回事。
		 *   没插线（无载波）时 macOS 会把静态配置存下来却不激活地址 ——
		 *   这时候回一句「设好了」是骗人：用户接着去开 DHCP 照样失败，还以为是别的问题。
		 *   所以回去看一眼，没拿到地址就照实说，让人先去检查网线。
		 */
		if !addrActive(nic.Name, ip) {
			return ots.Verdict{Code: "address-set-inactive",
				Values: map[string]any{"iface": nic.Name, "cidr": cidr},
				Note: fmt.Sprintf("已经把 %s 改成静态 %s，但这块网卡现在还没真正用上这个地址 —— "+
					"多半是网线没插好、或对端交换机没上电。插好线后它会自动生效；"+
					"这笔改动在账本里，可还原回自动获取", nic.Name, cidr)}, nil
		}
		return ots.Verdict{Code: "address-set",
			Values: map[string]any{"iface": nic.Name, "cidr": cidr},
			Note: fmt.Sprintf("已给 %s 设上 %s。现在可以在这块网卡上开 DHCP（net.dhcp.defaults 会算好参数）；"+
				"这笔改动在账本里，可还原回自动获取", nic.Name, cidr)}, nil
	},
}

// addrActive 回去读一眼，网卡是不是真的拿到了这个地址。给系统一点反应时间，重试几次。
func addrActive(iface string, ip netip.Addr) bool {
	for i := 0; i < 5; i++ {
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		nics, err := netif.Interfaces()
		if err != nil {
			return false
		}
		for _, n := range nics {
			if n.Name != iface {
				continue
			}
			for _, ad := range n.Addrs {
				if ad.Is4() && ad.IP == ip {
					return true
				}
			}
		}
	}
	return false
}

type addressSetArgs struct {
	Iface  string `json:"iface"`
	IP     string `json:"ip"`
	Prefix int    `json:"prefix"`
}

func describeAddressSet(raw json.RawMessage) string {
	var a addressSetArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	pfx := a.Prefix
	if pfx == 0 {
		pfx = 24
	}
	return fmt.Sprintf("给本机网卡 %s 设静态地址 %s/%d（改系统网络配置；需要管理员权限，改动会登记，可还原回自动获取）",
		a.Iface, a.IP, pfx)
}

// validateAddressArgs 把参数验完，顺带把网卡找出来。返回的是**主机地址**（没被 Masked 抹过）。
//
// ★ 网段重叠检查是保命的：这台机器多半还连着别的网（Wi-Fi 上网），
//
//	给有线卡设一个和 Wi-Fi 同段的地址，两块网卡抢同一段路由 ——
//	症状是「时通时断、换个姿势又不通」，现场最难查的那类问题。
func validateAddressArgs(a addressSetArgs) (*netif.NIC, netip.Addr, error) {
	if a.Iface == "" || a.IP == "" {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument, "iface 和 ip 都得给")
	}
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || !ip.Is4() {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 不是合法的 IPv4 地址（这个工具目前只管 v4）", a.IP)
	}
	if !ip.IsPrivate() {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 不是私网地址。发地址的网段必须用私网（10.x / 172.16-31.x / 192.168.x），"+
				"公网地址不是这么来的", a.IP)
	}
	nics, err := netif.Interfaces()
	if err != nil {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInternal, "%s", err)
	}
	var nic *netif.NIC
	for i := range nics {
		if nics[i].Name == a.Iface {
			nic = &nics[i]
			break
		}
	}
	if nic == nil {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument, "没有叫 %s 的网卡", a.Iface)
	}
	if nic.Loop || nic.Virtual {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 是回环/虚拟网卡，设静态地址没有意义", a.Iface)
	}
	netPfx := netip.PrefixFrom(ip, a.Prefix).Masked()
	// ★ 网段地址（.0）和广播地址（.255）不能拿来当主机地址 ——
	//   设上去那块网卡发不出正常流量，症状是「地址明明设了，却谁也 ping 不通」。
	if ip == netPfx.Addr() {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 是网段 %s 的网络地址，不能当主机地址用。换成同段里别的地址（比如把最后一位改成 .1）",
			ip, netPfx)
	}
	if ip == prefixEnd(netPfx) {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 是网段 %s 的广播地址，不能设成主机地址。换成同段里别的地址", ip, netPfx)
	}
	if other, hit := v4Conflict(nics, a.Iface, netPfx); hit {
		return nil, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 和网卡 %s 现有的网段重叠 —— 两块网卡抢同一段路由，会时通时断。"+
				"换一个网段（比如 192.168.50.x）再设", netPfx, other)
	}
	return nic, ip, nil
}

// prefixEnd 一个已 Masked 的 v4 前缀里的最后一个地址（广播地址）。
func prefixEnd(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	hostBits := 32 - p.Bits()
	if hostBits > 0 {
		n |= (1 << hostBits) - 1
	}
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// v4Conflict 新设的网段和**别的**网卡现有 v4 网段重叠吗。返回撞上的网卡名。
func v4Conflict(nics []netif.NIC, skip string, pfx netip.Prefix) (string, bool) {
	for _, n := range nics {
		if n.Name == skip || n.Loop {
			continue
		}
		for _, ad := range n.Addrs {
			if !ad.Is4() || ad.Prefix <= 0 || ad.Prefix > 32 {
				continue
			}
			other := netip.PrefixFrom(ad.IP, ad.Prefix).Masked()
			if other.Overlaps(pfx) {
				return n.Name, true
			}
		}
	}
	return "", false
}
