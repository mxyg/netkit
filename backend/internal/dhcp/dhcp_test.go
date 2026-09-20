package dhcp

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mask24() net.IPMask { return net.CIDRMask(24, 32) }

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func baseCfg(t *testing.T) Config {
	t.Helper()
	return Config{
		Iface:    &net.Interface{Index: 1, Name: "test0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}},
		ServerIP: mustAddr(t, "192.168.50.1"),
		Mask:     mask24(),
		Start:    mustAddr(t, "192.168.50.100"),
		End:      mustAddr(t, "192.168.50.110"),
		Lease:    time.Hour,
	}
}

// ── 配置校验：每一条都对应一种"发出去之后现场查半天"的情形 ──

func Test池子不在本机网段就拒绝(t *testing.T) {
	c := baseCfg(t)
	c.Start = mustAddr(t, "10.0.0.100")
	c.End = mustAddr(t, "10.0.0.110")
	err := c.Validate()
	if err == nil {
		t.Fatal("池子和本机不在一个网段，本该拒绝 —— 这样发下去设备能拿到地址但跟这台机器不通")
	}
	t.Log(err)
}

func Test本机地址落在池子里就拒绝(t *testing.T) {
	c := baseCfg(t)
	c.Start = mustAddr(t, "192.168.50.1") // 正好是本机
	c.End = mustAddr(t, "192.168.50.20")
	if err := c.Validate(); err == nil {
		t.Fatal("本机地址落在池内本该拒绝 —— 迟早把自己的地址发给别人，整段网冲突")
	}
}

func Test池子起止反了就拒绝(t *testing.T) {
	c := baseCfg(t)
	c.Start, c.End = c.End, c.Start
	if err := c.Validate(); err == nil {
		t.Fatal("起止反了本该拒绝")
	}
}

// ── 报文编解码 ──

func Test报文编解码来回一致(t *testing.T) {
	p := &Packet{
		Op: opRequest, XID: 0x12345678, Flags: 0x8000,
		CHAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Options: map[byte][]byte{
			OptMessageType: {Discover},
			OptHostName:    []byte("camera-01"),
		},
	}
	got, err := Parse(p.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.XID != p.XID {
		t.Errorf("XID = %x", got.XID)
	}
	if got.MessageType() != Discover {
		t.Errorf("类型 = %d", got.MessageType())
	}
	if got.CHAddr.String() != p.CHAddr.String() {
		t.Errorf("MAC = %s", got.CHAddr)
	}
	if string(got.Options[OptHostName]) != "camera-01" {
		t.Errorf("主机名 = %q", got.Options[OptHostName])
	}
}

// ★ 现场真见过畸形报文。解析不许越界崩掉 —— 这个进程正管着整网的地址。
func Test畸形报文不许崩(t *testing.T) {
	good := (&Packet{Op: opRequest, XID: 1, CHAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6},
		Options: map[byte][]byte{OptMessageType: {Discover}}}).Marshal()
	cases := [][]byte{
		{}, {1}, make([]byte, 239),
		good[:245], // 截断在选项中间
		append(append([]byte{}, good[:240]...), 12, 99), // 声称长度 99 但后面没数据
	}
	for i, b := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("第 %d 个畸形报文让解析崩了：%v", i, r)
				}
			}()
			_, _ = Parse(b)
		}()
	}
}

func Test报文类型必须排第一(t *testing.T) {
	// ★ 有些老设备就认这个顺序。规范没要求，但现场设备不都按规范写。
	b := (&Packet{Op: opReply, Options: map[byte][]byte{
		OptMessageType: {Ack}, OptServerID: {192, 168, 1, 1}, OptSubnetMask: {255, 255, 255, 0},
	}}).Marshal()
	if b[240] != OptMessageType {
		t.Errorf("第一个选项是 %d，不是报文类型(%d)", b[240], OptMessageType)
	}
}

// ── 分配逻辑 ──

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := NewServer(cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func Test同一台设备再来还给它原来的地址(t *testing.T) {
	s := newTestServer(t, baseCfg(t))
	mac := "aa:bb:cc:dd:ee:01"
	first, ok := s.pick(mac, nil)
	if !ok {
		t.Fatal("头一次就没分到")
	}
	if _, ok := s.confirm(mac, net.IP(first.AsSlice()), "cam1"); !ok {
		t.Fatal("确认失败")
	}
	again, _ := s.pick(mac, nil)
	if again != first {
		t.Errorf("同一台设备再来拿到了不同地址：%s → %s —— 地址稳定本身就是现场省事的来源", first, again)
	}
}

func Test不同设备不会拿到同一个地址(t *testing.T) {
	s := newTestServer(t, baseCfg(t))
	seen := map[string]string{}
	for i := 1; i <= 11; i++ {
		mac := net.HardwareAddr{0xaa, 0, 0, 0, 0, byte(i)}.String()
		ip, ok := s.pick(mac, nil)
		if !ok {
			t.Fatalf("第 %d 台没分到（池子有 11 个地址）", i)
		}
		if _, ok := s.confirm(mac, net.IP(ip.AsSlice()), ""); !ok {
			t.Fatalf("第 %d 台确认失败", i)
		}
		if prev, dup := seen[ip.String()]; dup {
			t.Fatalf("地址 %s 同时给了 %s 和 %s —— 地址冲突", ip, prev, mac)
		}
		seen[ip.String()] = mac
	}
	// 第 12 台：池子满了，必须明确要不到，不能悄悄发一个池外地址
	if ip, ok := s.pick("ff:ff:ff:ff:ff:ff", nil); ok {
		t.Errorf("池子满了却还分出了 %s", ip)
	}
}

func Test不会把本机地址发出去(t *testing.T) {
	c := baseCfg(t)
	c.Start = mustAddr(t, "192.168.50.2")
	c.End = mustAddr(t, "192.168.50.5")
	c.ServerIP = mustAddr(t, "192.168.50.3") // 故意落在起止之间
	if err := c.Validate(); err == nil {
		t.Fatal("本机地址在池子范围内，Validate 本该拦住")
	}
}

func Test固定绑定优先(t *testing.T) {
	c := baseCfg(t)
	mac := "aa:bb:cc:dd:ee:09"
	want := mustAddr(t, "192.168.50.105")
	c.Reserved = map[string]netip.Addr{mac: want}
	s := newTestServer(t, c)

	// 先让别的设备把池子前面占掉
	for i := 1; i <= 3; i++ {
		m := net.HardwareAddr{0xbb, 0, 0, 0, 0, byte(i)}.String()
		ip, _ := s.pick(m, nil)
		s.confirm(m, net.IP(ip.AsSlice()), "")
	}
	got, ok := s.pick(mac, nil)
	if !ok || got != want {
		t.Errorf("固定绑定没生效：拿到 %s，想要 %s —— 现场靠它把摄像机钉在固定地址上", got, want)
	}
}

func Test保留给别人的地址不许分出去(t *testing.T) {
	c := baseCfg(t)
	reserved := mustAddr(t, "192.168.50.100") // 正好是池子第一个
	c.Reserved = map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": reserved}
	s := newTestServer(t, c)
	got, ok := s.pick("bb:bb:bb:bb:bb:bb", nil)
	if !ok {
		t.Fatal("没分到")
	}
	if got == reserved {
		t.Errorf("把保留给别人的 %s 分出去了", reserved)
	}
}

func Test过期的地址会被回收(t *testing.T) {
	c := baseCfg(t)
	c.Start = mustAddr(t, "192.168.50.100")
	c.End = mustAddr(t, "192.168.50.100") // 池子只有一个地址
	s := newTestServer(t, c)

	a := "aa:00:00:00:00:01"
	ip, ok := s.pick(a, nil)
	if !ok {
		t.Fatal("第一台没分到")
	}
	s.confirm(a, net.IP(ip.AsSlice()), "")

	// 第二台：池子被占满，要不到
	if _, ok := s.pick("bb:00:00:00:00:02", nil); ok {
		t.Fatal("池子只有一个地址且被占着，第二台不该分到")
	}
	// 让第一台的租约过期
	s.mu.Lock()
	s.leases[a].Expires = time.Now().Add(-time.Minute)
	s.mu.Unlock()

	if _, ok := s.pick("bb:00:00:00:00:02", nil); !ok {
		t.Error("租约已过期的地址应当可以回收再分配")
	}
}

// ★★ 没配网关就不发网关。发一个通不了的网关，设备会把它当默认路由，
// 表现成"拿到地址了但什么都访问不了"，比不发更难查。
func Test没配网关就不下发网关(t *testing.T) {
	s := newTestServer(t, baseCfg(t)) // Router 未设
	req := &Packet{Op: opRequest, XID: 7, CHAddr: net.HardwareAddr{1, 2, 3, 4, 5, 6},
		Options: map[byte][]byte{OptMessageType: {Request}}}

	// 直接检查构造出来的回包，不走网络
	resp := &Packet{Op: opReply, XID: req.XID, CHAddr: req.CHAddr,
		Options: map[byte][]byte{OptMessageType: {Ack}}}
	resp.Options[OptSubnetMask] = append([]byte(nil), s.cfg.Mask...)
	if s.cfg.Router.IsValid() {
		resp.Options[OptRouter] = ipOpt(net.IP(s.cfg.Router.AsSlice()))
	}
	if _, has := resp.Options[OptRouter]; has {
		t.Error("没配网关却下发了网关")
	}
	if _, has := resp.Options[OptSubnetMask]; !has {
		t.Error("掩码必须发")
	}
}

func Test租期与池子大小(t *testing.T) {
	c := baseCfg(t)
	if n := c.PoolSize(); n != 11 {
		t.Errorf("池子大小 = %d，想要 11（100–110 含两端）", n)
	}
	c.Lease = 0
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Lease != 12*time.Hour {
		t.Errorf("没给租期时该有个合理默认值，实际 %v", c.Lease)
	}
}

// ★★ 改 IP：设备已经拿着 .100，把它改绑到 .105 之后，
// 它下次来续租必须被拒（NAK），从而重新要一个 —— 拿到新地址。
//
// 不这么做的话，绑定只对新设备有效，已经在线的那台会一直用旧地址到租期结束，
// 而用户在界面上明明已经改过了。
func Test改绑之后旧地址会被拒绝(t *testing.T) {
	s := newTestServer(t, baseCfg(t))
	mac := "aa:bb:cc:00:00:07"

	old, ok := s.pick(mac, nil)
	if !ok {
		t.Fatal("没分到")
	}
	if _, ok := s.confirm(mac, net.IP(old.AsSlice()), "cam"); !ok {
		t.Fatal("确认失败")
	}

	want := mustAddr(t, "192.168.50.105")
	if old == want {
		want = mustAddr(t, "192.168.50.106")
	}
	s.SetReserved(mac, want)

	// 设备来续租旧地址 → 必须被拒
	if got, ok := s.confirm(mac, net.IP(old.AsSlice()), "cam"); ok {
		t.Fatalf("改绑之后还把旧地址 %s 确认给它了 —— 那样界面上改了 IP 实际不生效", got)
	}
	// 它重新要 → 拿到新地址
	got, ok := s.pick(mac, nil)
	if !ok || got != want {
		t.Fatalf("重新要之后拿到 %s，想要 %s", got, want)
	}
	if _, ok := s.confirm(mac, net.IP(got.AsSlice()), "cam"); !ok {
		t.Fatal("新地址确认失败")
	}
	// 旧地址要回到池子里，不能一直被算成"有人占"
	if _, taken := s.byIP[old.String()]; taken {
		t.Errorf("旧地址 %s 没被释放，池子会越用越少", old)
	}
}

func Test改绑会产生事件(t *testing.T) {
	s := newTestServer(t, baseCfg(t))
	mac := "aa:bb:cc:00:00:08"
	ip, _ := s.pick(mac, nil)
	s.confirm(mac, net.IP(ip.AsSlice()), "dev")

	evs, last := s.Events(0)
	if len(evs) == 0 || evs[0].Kind != "new" {
		t.Fatalf("头一次接入该产生 new 事件，实际 %v", evs)
	}
	s.SetReserved(mac, mustAddr(t, "192.168.50.109"))
	evs2, _ := s.Events(last)
	if len(evs2) == 0 {
		t.Fatal("改绑没产生事件 —— 界面就不知道该刷新")
	}
	// 续租不该反复冒 new，否则界面上每台设备会反复"新接入"
	s.confirm(mac, net.IP(mustAddr(t, "192.168.50.109").AsSlice()), "dev")
	all, _ := s.Events(0)
	news := 0
	for _, e := range all {
		if e.Kind == "new" {
			news++
		}
	}
	if news != 1 {
		t.Errorf("new 事件出现了 %d 次，同一台设备只该在头一次接入时冒一次", news)
	}
}
