package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// Defaults 一块网卡上开 DHCP 的推荐参数。
//
// ★★ 为什么要有这个（老板 2026-09-20：「dhcp 有默认参数，可以修改」）：
//
//	让人自己填地址池，等于让他当场做三个判断：本机在哪个网段、
//	哪一段没被占、会不会把自己的地址发出去。填错的后果不是报错，
//	是**发出去之后整网乱掉**。这些判断机器算得比人准，
//	所以默认值直接算好、预填进去，人改就行。
type Defaults struct {
	Iface      string   `json:"iface"`
	ServerIP   string   `json:"serverIp"`   // 本机在这个网段上的地址
	Network    string   `json:"network"`    // 网段，如 192.168.1.0/24
	Start      string   `json:"start"`      //
	End        string   `json:"end"`        //
	PoolSize   int      `json:"poolSize"`   //
	LeaseHours int      `json:"leaseHours"` //
	Router     string   `json:"router"`     // ★ 默认空，见 RouterNote
	RouterNote string   `json:"routerNote"` //
	DNS        []string `json:"dns"`        //
	Note       string   `json:"note"`       //
}

var dhcpDefaultsTool = ots.Tool{
	Name:  "net.dhcp.defaults",
	Class: ots.ClassRead,
	Summary: "给一块网卡算出开 DHCP 的推荐参数：地址池起止、掩码、租期。" +
		"★ 池子会自动避开本机地址和网段里常被路由器占用的头几个地址。" +
		"界面上用它预填表单，人改了再开；AI 也可以直接拿它的结果去调 net.dhcp.serve。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["iface"],
	  "properties": {"iface": {"type": "string", "description": "网卡名，如 en0 / eth0"}}
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			Iface string `json:"iface"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, err := DHCPDefaults(a.Iface)
		if err != nil {
			return nil, err
		}
		return d, nil
	},
}

// DHCPDefaults 算一块网卡的推荐参数。
func DHCPDefaults(ifaceName string) (*Defaults, error) {
	if ifaceName == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给网卡名")
	}
	nics, err := netif.Interfaces()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "%s", err)
	}
	var nic *netif.NIC
	for i := range nics {
		if nics[i].Name == ifaceName {
			nic = &nics[i]
			break
		}
	}
	if nic == nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没有叫 %s 的网卡", ifaceName)
	}

	var self netaddr.Addr
	for _, ad := range nic.Addrs {
		if ad.Is4() && (ad.Scope() == netaddr.ScopePrivate || ad.Scope() == netaddr.ScopeGlobal) {
			self = ad
			break
		}
	}
	if !self.IP.IsValid() {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"网卡 %s 上没有可用的 IPv4 地址 —— DHCP 服务器自己必须先有一个固定 IP，"+
				"才能给别人发地址。请先在「本机网络」里给它设一个", ifaceName)
	}
	prefix := self.Prefix
	if prefix <= 0 || prefix > 30 {
		prefix = 24
	}
	pfx := netip.PrefixFrom(self.IP, prefix).Masked()

	start, end, err := poolFor(pfx, self.IP)
	if err != nil {
		return nil, err
	}
	d := &Defaults{
		Iface: nic.Name, ServerIP: self.IP.String(), Network: pfx.String(),
		Start: start.String(), End: end.String(),
		PoolSize: countTo(start, end), LeaseHours: 12,
		// ★★ 网关默认**留空**，并且说清楚为什么。
		//   这台机器不是路由器，填它自己的地址当网关，设备会把流量发过来然后没人转发 ——
		//   表现成「拿到地址了，但什么都访问不了」，比不发网关难查得多。
		Router: "",
		RouterNote: "默认不下发网关：这台电脑只是发地址，不负责转发流量。" +
			"设备之间在同一网段内互通没问题。如果这个网里有真正的出口路由器，把它的地址填进来。",
		Note: fmt.Sprintf("本机 %s 在 %s 上，池子避开了本机地址和网段头几个地址",
			self.IP, pfx),
	}
	return d, nil
}

// poolFor 在一个网段里挑一段安全的地址池。
//
// ★ 避开三类地址，每一类都对应一种现场事故：
//   - 网络地址与广播地址：发出去设备直接不可用
//   - 网段头几个（.1–.9）：**路由器几乎总在这里**，发出去就是撞上现有设备
//   - 本机地址：把自己的地址发给别人，整段网冲突
func poolFor(pfx netip.Prefix, self netip.Addr) (netip.Addr, netip.Addr, error) {
	if !pfx.Addr().Is4() {
		return netip.Addr{}, netip.Addr{}, ots.Errf(ots.ErrNotSupported, "只支持 IPv4 网段")
	}
	bits := pfx.Bits()
	total := 1 << (32 - bits) // 网段里的地址总数
	if total < 8 {
		return netip.Addr{}, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"网段 %s 太小（只有 %d 个地址），放不下一个像样的地址池", pfx, total)
	}
	base := pfx.Addr()
	// 跳过网络地址 + 头 9 个（给路由器等固定设备留着）
	skip := 10
	if total < 32 {
		skip = 2
	}
	// 末尾留出广播地址 + 几个
	tail := 2
	first := nth(base, skip)
	last := nth(base, total-1-tail)
	if !first.IsValid() || !last.IsValid() || last.Less(first) {
		return netip.Addr{}, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument, "算不出合适的地址池")
	}
	// ★ 本机落在池里就把池子从本机之后开始 —— 不这么做的话
	//   Validate 会拒绝，而用户看到的是"默认值自己都不合法"
	if !self.Less(first) && !last.Less(self) {
		first = self.Next()
		if last.Less(first) {
			return netip.Addr{}, netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
				"本机地址 %s 太靠近网段末尾，自动算不出池子，请手工指定", self)
		}
	}
	return first, last, nil
}

// nth 网段基址往后第 n 个地址。
func nth(base netip.Addr, n int) netip.Addr {
	a := base
	for i := 0; i < n; i++ {
		a = a.Next()
		if !a.IsValid() {
			return netip.Addr{}
		}
	}
	return a
}

func countTo(a, b netip.Addr) int {
	n := 0
	for x := a; ; x = x.Next() {
		n++
		if x == b || n > 65536 {
			break
		}
	}
	return n
}
