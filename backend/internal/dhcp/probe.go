package dhcp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// Finding 探到的一个 DHCP 服务。
type Finding struct {
	// ServerID 它自称的服务器地址（选项 54）。没给就用源地址。
	ServerID string `json:"serverId"`
	// From 报文真正来自哪个地址
	From string `json:"from"`
	// OfferedIP 它打算分给我们的地址 —— ★ 这一条最能说明问题：
	// 它不只是"在那儿"，而是**真的在发地址**。
	OfferedIP string   `json:"offeredIp,omitempty"`
	Mask      string   `json:"mask,omitempty"`
	Router    string   `json:"router,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	LeaseSecs uint32   `json:"leaseSeconds,omitempty"`
}

// Probe 在指定网卡上问一句「有人管发地址吗」，收集所有回应。
//
// ★★ 这是开 DHCP 之前的**保命步骤**，不是可选的体检项：
//
//	网里已经有 DHCP 时再起一个，两边同时发地址 ——
//	设备可能拿到互相冲突的地址、错的网关，有的通有的不通，
//	而且故障是间歇的（看谁先应答），是现场最难查的一类。
//
//	所以 Serve() 会强制先调它，探到了就拒绝启动（除非人明确说"我知道，仍然要开"）。
//
// ★ 做法：发一个标准的 DHCPDISCOVER 广播，然后听 OFFER。
//
//	用**随机 XID** 并只认这个 XID 的回应 —— 否则会把网里别人正在进行的
//	DHCP 交互也算成"探到了"，给出一个假阳性。
func Probe(ctx context.Context, iface *net.Interface, wait time.Duration) ([]Finding, error) {
	if iface == nil {
		return nil, fmt.Errorf("没指定网卡")
	}
	if wait <= 0 {
		wait = 3 * time.Second
	}

	// ★ 绑 :68（DHCP 客户端口）来收 OFFER。绑不上通常意味着两件事之一：
	//   本机 DHCP 客户端正占着它，或者没有权限 —— 两种都要说清楚，别笼统报"失败"。
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", ClientPort))
	if err != nil {
		return nil, fmt.Errorf("监听 DHCP 客户端口(%d)失败：%w —— "+
			"这个端口通常被本机的 DHCP 客户端占着；"+
			"把这块网卡改成静态地址、或以管理员身份运行再试", ClientPort, err)
	}
	defer conn.Close()

	xid := rand.Uint32()
	req := &Packet{
		Op:     opRequest,
		XID:    xid,
		Flags:  0x8000, // 要求广播回应：我们此刻还没有地址，单播回来收不到
		CHAddr: iface.HardwareAddr,
		Options: map[byte][]byte{
			OptMessageType: {Discover},
			OptParamList:   {OptSubnetMask, OptRouter, OptDNS, OptLeaseTime},
		},
	}
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: ServerPort}
	if _, err := conn.WriteTo(req.Marshal(), dst); err != nil {
		return nil, fmt.Errorf("发 DHCP 探测包失败：%w", err)
	}

	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)

	seen := map[string]bool{}
	var out []Finding
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			break // 超时即结束，不算错误
		}
		p, err := Parse(buf[:n])
		if err != nil || p.XID != xid || p.MessageType() != Offer {
			continue
		}
		f := Finding{From: from.String()}
		if sid := p.OptionIP(OptServerID); sid != nil {
			f.ServerID = sid.String()
		} else if ua, ok := from.(*net.UDPAddr); ok {
			f.ServerID = ua.IP.String()
		}
		if seen[f.ServerID] {
			continue
		}
		seen[f.ServerID] = true
		if p.YIAddr != nil && !p.YIAddr.Equal(net.IPv4zero) {
			f.OfferedIP = p.YIAddr.String()
		}
		if m := p.OptionIP(OptSubnetMask); m != nil {
			f.Mask = m.String()
		}
		if r := p.OptionIP(OptRouter); r != nil {
			f.Router = r.String()
		}
		if v, ok := p.Options[OptDNS]; ok {
			for i := 0; i+4 <= len(v); i += 4 {
				f.DNS = append(f.DNS, net.IPv4(v[i], v[i+1], v[i+2], v[i+3]).String())
			}
		}
		if v, ok := p.Options[OptLeaseTime]; ok && len(v) >= 4 {
			f.LeaseSecs = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		}
		out = append(out, f)
	}
	return out, nil
}
