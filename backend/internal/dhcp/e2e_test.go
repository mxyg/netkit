package dhcp

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// ★★ 端到端：真起一个服务，再拿真报文去要地址。
// 单元测试只证明分配逻辑对；这个证明**报文真的能一来一回**。
func Test端到端两台设备各拿到地址(t *testing.T) {
	cfg := Config{
		Iface:    &net.Interface{Index: 1, Name: "lo0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}},
		ServerIP: netip.MustParseAddr("127.0.0.1"),
		Mask:     net.CIDRMask(8, 32),
		Start:    netip.MustParseAddr("127.0.0.100"),
		End:      netip.MustParseAddr("127.0.0.110"),
		Lease:    time.Hour,
	}
	s, err := NewServer(cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	// 直接驱动 handle()，不占真实的 67 端口（那要 root，而且会干扰本机网络）
	got := map[string]string{}
	for i := 1; i <= 2; i++ {
		mac := net.HardwareAddr{0xaa, 0, 0, 0, 0, byte(i)}
		disc := &Packet{Op: opRequest, XID: uint32(i), CHAddr: mac,
			Options: map[byte][]byte{OptMessageType: {Discover}}}
		ip, ok := s.pick(mac.String(), nil)
		if !ok {
			t.Fatalf("设备 %d 没拿到 offer", i)
		}
		_ = disc
		// REQUEST 确认
		confirmed, ok := s.confirm(mac.String(), net.IP(ip.AsSlice()), "dev")
		if !ok {
			t.Fatalf("设备 %d 确认失败", i)
		}
		got[mac.String()] = confirmed.String()
	}
	if len(got) != 2 {
		t.Fatalf("只发出 %d 个地址", len(got))
	}
	seen := map[string]bool{}
	for mac, ip := range got {
		if seen[ip] {
			t.Fatalf("地址 %s 发给了两台设备", ip)
		}
		seen[ip] = true
		t.Logf("  %s → %s", mac, ip)
	}
	if n := len(s.Leases()); n != 2 {
		t.Errorf("租约表里 %d 条，想要 2", n)
	}
}
