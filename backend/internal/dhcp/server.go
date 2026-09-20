package dhcp

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Config 一个 DHCP 服务怎么发地址。
type Config struct {
	// Iface 在哪块网卡上服务
	Iface *net.Interface
	// ServerIP 本机在这个网段上的地址。客户端会把它当 DHCP 服务器地址
	ServerIP netip.Addr
	// Mask 子网掩码
	Mask net.IPMask
	// Start / End 地址池的起止（含两端）
	Start, End netip.Addr
	// Router 下发的网关。**可以为空** —— 见 Validate 里那段说明
	Router netip.Addr
	// DNS 下发的 DNS
	DNS []netip.Addr
	// Lease 租期
	Lease time.Duration
	// Reserved MAC → 固定地址
	Reserved map[string]netip.Addr
}

// Lease 一条租约。
type LeaseRec struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac"`
	Host     string    `json:"host,omitempty"`
	Expires  time.Time `json:"expires"`
	LastSeen time.Time `json:"lastSeen"`
}

// Event 一件事：某台设备拿到/续了/释放了地址。
//
// ★★ 为什么要有事件而不是只给一张租约表（老板 2026-09-20：
//
//	「有设备接入能自动显示新加入的」）：
//	租约表回答"现在有谁"，回答不了"刚才多了谁"。
//	现场插上一台新设备，人要的就是**它出现的那一下**——
//	盯着一张全量表找哪一行是新的，等于没有这个功能。
type Event struct {
	Seq  int64     `json:"seq"`  // 单调递增，客户端按它增量取
	At   time.Time `json:"at"`   //
	Kind string    `json:"kind"` // new 新设备 / renew 续租 / release 释放 / conflict 要不到
	MAC  string    `json:"mac"`
	IP   string    `json:"ip,omitempty"`
	Host string    `json:"host,omitempty"`
}

// Server 一个跑着的 DHCP 服务。
type Server struct {
	cfg  Config
	log  *slog.Logger
	conn net.PacketConn

	mu     sync.Mutex
	leases map[string]*LeaseRec // MAC → 租约
	byIP   map[string]string    // IP → MAC
	// known 见过的 MAC。
	//
	// ★★ 判断"是不是新设备"必须看它，不能看 leases 里有没有 ——
	//   改绑 IP 会把租约删掉逼设备重新要，那一下它又会被当成"新接入"
	//   而冒一次泡。同一台设备在界面上反复"新接入"，人就不会再信这个提示了。
	known map[string]bool
	// events 事件环形缓冲。★ 有上限：现场跑上几天，无限增长会把内存吃光，
	//   而这个进程正管着整网的地址，它被 OOM 杀掉等于全网断续。
	events []Event
	seq    int64
	stop   chan struct{}
	done   chan struct{}
}

// maxEvents 事件最多留多少条。够界面回看一阵子，又不会无限长。
const maxEvents = 500

// Validate 检查配置立不立得住。
//
// ★ 这里每一条都对应一种"发出去之后客户端不通、而现场要查半天"的情形。
func (c *Config) Validate() error {
	if c.Iface == nil {
		return fmt.Errorf("没指定网卡")
	}
	if !c.ServerIP.Is4() {
		return fmt.Errorf("服务器地址必须是 IPv4")
	}
	if !c.Start.Is4() || !c.End.Is4() {
		return fmt.Errorf("地址池的起止必须是 IPv4")
	}
	if c.End.Less(c.Start) {
		return fmt.Errorf("地址池反了：结束地址 %s 小于起始地址 %s", c.End, c.Start)
	}
	if len(c.Mask) == 0 {
		return fmt.Errorf("没给子网掩码")
	}
	ones, bits := c.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("子网掩码不是 IPv4 掩码")
	}
	pfx := netip.PrefixFrom(c.ServerIP, ones)
	// ★★ 池子必须和本机地址在同一网段：不在同一网段的话，
	//   客户端拿到地址后跟本机不通 —— 而它自己不会报错，表现成"地址拿到了但还是上不了网"。
	if !pfx.Contains(c.Start) || !pfx.Contains(c.End) {
		return fmt.Errorf("地址池 %s–%s 不在本机网段 %s 内 —— "+
			"这样发下去，设备能拿到地址但跟这台机器不通", c.Start, c.End, pfx.Masked())
	}
	// ★ 本机地址落在池子里 = 迟早把自己的地址发给别人，然后整段网冲突。
	//
	// ★★ 这里**正着写**：inPool := Start <= ServerIP <= End。
	//   早先写成了 `if !Start.Less(ServerIP) || End.Less(ServerIP) { 正常 } else { 报错 }` ——
	//   本机地址**正好等于池子起点**时，Start.Less(ServerIP) 是 false、取反成 true，
	//   于是走进"正常"分支放行了。双重否定 + else 分支，是这种错的温床。
	inPool := !c.ServerIP.Less(c.Start) && !c.End.Less(c.ServerIP)
	if inPool {
		return fmt.Errorf("本机地址 %s 落在地址池 %s–%s 里 —— "+
			"迟早会把自己的地址发给别的设备，整段网都会冲突。请把池子避开本机地址",
			c.ServerIP, c.Start, c.End)
	}
	if c.Lease <= 0 {
		c.Lease = 12 * time.Hour
	}
	return nil
}

// NewServer 建一个服务（还没开始听）。
func NewServer(cfg Config, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg: cfg, log: log,
		leases: map[string]*LeaseRec{},
		byIP:   map[string]string{},
		known:  map[string]bool{},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}, nil
}

// Start 开始服务。非阻塞。
func (s *Server) Start() error {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", ServerPort))
	if err != nil {
		return fmt.Errorf("监听 DHCP 服务端口(%d)失败：%w —— "+
			"这个端口要管理员权限，而且如果本机已经在跑别的 DHCP（比如系统自带的网络共享），"+
			"也会占着它", ServerPort, err)
	}
	s.conn = conn
	go s.loop()
	return nil
}

// Stop 停止服务。
func (s *Server) Stop() {
	select {
	case <-s.stop:
		return // 已经停过
	default:
		close(s.stop)
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	<-s.done
}

func (s *Server) loop() {
	defer close(s.done)
	buf := make([]byte, 1500)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			continue // 超时是正常的，借它回到循环顶上看 stop
		}
		p, err := Parse(buf[:n])
		if err != nil {
			continue
		}
		if p.Op != opRequest {
			continue
		}
		s.handle(p, from)
	}
}

func (s *Server) handle(p *Packet, from net.Addr) {
	mac := p.CHAddr.String()
	switch p.MessageType() {
	case Discover:
		ip, ok := s.pick(mac, p.OptionIP(OptRequestedIP))
		if !ok {
			s.log.Warn("地址池满了，没法给新设备发地址", "mac", mac)
			return
		}
		s.reply(p, Offer, ip)
		s.log.Info("DHCP 提供地址", "mac", mac, "ip", ip)
	case Request:
		want := p.OptionIP(OptRequestedIP)
		if want == nil || want.Equal(net.IPv4zero) {
			want = p.CIAddr
		}
		ip, ok := s.confirm(mac, want, hostNameOf(p))
		if !ok {
			// ★ 要不到就明确回 NAK，让客户端立刻重来 ——
			//   不回的话它会一直重试到超时，表现成"插上网线好久没反应"
			s.reply(p, Nak, netip.Addr{})
			s.log.Warn("拒绝了地址请求", "mac", mac, "want", want)
			return
		}
		s.reply(p, Ack, ip)
		s.log.Info("DHCP 确认地址", "mac", mac, "ip", ip, "host", hostNameOf(p))
	case Release:
		s.release(mac)
		s.log.Info("设备释放了地址", "mac", mac)
	}
}

// pick 给这个 MAC 挑一个地址。
func (s *Server) pick(mac string, requested net.IP) (netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ★ 固定绑定优先：现场靠它把摄像机钉在固定地址上，不然换个地址就要改一遍平台配置
	if ip, ok := s.cfg.Reserved[mac]; ok {
		return ip, true
	}
	// 老客户回来了，尽量还给它原来那个地址 —— 地址稳定本身就是现场省事的来源
	if l, ok := s.leases[mac]; ok {
		if a, err := netip.ParseAddr(l.IP); err == nil {
			return a, true
		}
	}
	// 客户端指名要某个地址，且没被别人占，就给它
	if requested != nil && !requested.Equal(net.IPv4zero) {
		if a, ok := netip.AddrFromSlice(requested.To4()); ok && s.freeLocked(a, mac) {
			return a, true
		}
	}
	for a := s.cfg.Start; ; a = a.Next() {
		if s.freeLocked(a, mac) {
			return a, true
		}
		if a == s.cfg.End {
			break
		}
	}
	return netip.Addr{}, false
}

// freeLocked 这个地址现在能不能给 mac 用。调用方须持锁。
func (s *Server) freeLocked(a netip.Addr, mac string) bool {
	if !a.Is4() || a == s.cfg.ServerIP {
		return false
	}
	if a.Less(s.cfg.Start) || s.cfg.End.Less(a) {
		return false
	}
	// 被保留给别的 MAC 的地址不能动用
	for m, r := range s.cfg.Reserved {
		if r == a && m != mac {
			return false
		}
	}
	owner, taken := s.byIP[a.String()]
	if !taken || owner == mac {
		return true
	}
	// 别人占着但已经过期，可以回收
	if l, ok := s.leases[owner]; ok && time.Now().After(l.Expires) {
		return true
	}
	return false
}

// confirm 客户端 REQUEST 时确认地址。
func (s *Server) confirm(mac string, want net.IP, host string) (netip.Addr, bool) {
	if want == nil {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(want.To4())
	if !ok {
		return netip.Addr{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// ★★ 这台设备被固定到了**别的**地址：拒绝它继续用现在这个。
	//
	//   DHCP 是「客户端来要」的协议，服务端推不动新地址。
	//   但我们可以在它下次来续租时**回 NAK** —— 客户端收到 NAK 会立刻
	//   放弃当前地址、重新走一遍 DISCOVER，于是拿到我们给它留的那个。
	//   这是"改 IP"能真正落到设备上的唯一办法（老板 2026-09-20 要的那条）。
	//
	//   不这么做的话：绑定只对**新设备**有效，已经拿着地址的那台会一直
	//   用旧地址到租期结束 —— 而用户在界面上明明已经改过了。
	if want, ok := s.cfg.Reserved[mac]; ok && want != a {
		s.emitLocked("nak", mac, a.String(), host)
		return netip.Addr{}, false
	}

	if !s.freeLocked(a, mac) {
		return netip.Addr{}, false
	}
	// 换地址时把旧的索引清掉，否则旧地址会一直被算成"有人占"
	if old, ok := s.leases[mac]; ok && old.IP != a.String() {
		delete(s.byIP, old.IP)
	}
	now := time.Now()
	seenBefore := s.known[mac]
	s.known[mac] = true
	s.leases[mac] = &LeaseRec{
		IP: a.String(), MAC: mac, Host: host,
		Expires: now.Add(s.cfg.Lease), LastSeen: now,
	}
	s.byIP[a.String()] = mac
	// ★ 头一次见 = 新设备接入，界面要高亮它；之后是续租，不该反复冒泡
	if seenBefore {
		s.emitLocked("renew", mac, a.String(), host)
	} else {
		s.emitLocked("new", mac, a.String(), host)
	}
	return a, true
}

// emit 记一件事。调用方须持锁。
func (s *Server) emitLocked(kind, mac, ip, host string) {
	s.seq++
	s.events = append(s.events, Event{
		Seq: s.seq, At: time.Now(), Kind: kind, MAC: mac, IP: ip, Host: host,
	})
	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
	}
}

// Events 取 seq 之后的事件。sinceSeq=0 表示从头取。
//
// ★ 返回当前最大 seq，客户端下次拿它继续 —— 这样不会漏也不会重。
func (s *Server) Events(sinceSeq int64) ([]Event, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if e.Seq > sinceSeq {
			out = append(out, e)
		}
	}
	return out, s.seq
}

// SetReserved 运行中改 MAC 绑定。
//
// ★★ 已经拿着别的地址的设备，绑定不会立刻生效 —— 它要等续租时才会换。
//
//	所以这里把它的当前租约**作废**，逼它下次来重新要一个：
//	否则用户在界面上绑了地址、设备却几小时不变，会以为功能没用。
func (s *Server) SetReserved(mac string, ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Reserved == nil {
		s.cfg.Reserved = map[string]netip.Addr{}
	}
	s.cfg.Reserved[mac] = ip
	if l, ok := s.leases[mac]; ok && l.IP != ip.String() {
		delete(s.byIP, l.IP)
		delete(s.leases, mac)
		s.emitLocked("rebind", mac, ip.String(), l.Host)
	}
}

// Reserved 当前的固定绑定。
func (s *Server) Reserved() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for m, a := range s.cfg.Reserved {
		out[m] = a.String()
	}
	return out
}

func (s *Server) release(mac string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leases[mac]; ok {
		delete(s.byIP, l.IP)
		delete(s.leases, mac)
		s.emitLocked("release", mac, l.IP, l.Host)
	}
}

// reply 回一个报文。
func (s *Server) reply(req *Packet, typ byte, ip netip.Addr) {
	resp := &Packet{
		Op: opReply, XID: req.XID, Flags: req.Flags,
		CHAddr: req.CHAddr, GIAddr: req.GIAddr,
		SIAddr:  net.IP(s.cfg.ServerIP.AsSlice()),
		Options: map[byte][]byte{OptMessageType: {typ}},
	}
	if ip.IsValid() {
		resp.YIAddr = net.IP(ip.AsSlice())
	}
	resp.Options[OptServerID] = ipOpt(net.IP(s.cfg.ServerIP.AsSlice()))
	if typ == Offer || typ == Ack {
		resp.Options[OptSubnetMask] = append([]byte(nil), s.cfg.Mask...)
		resp.Options[OptLeaseTime] = durOpt(s.cfg.Lease)
		// ★ 网关和 DNS **没配就不发**，不要塞一个本机地址顶替。
		//   老板那个场景里压根没有出口 —— 发一个通不了的网关，
		//   设备会把它当默认路由，结果是"拿到地址了，但什么都访问不了"，
		//   比不发网关更难查。
		if s.cfg.Router.IsValid() {
			resp.Options[OptRouter] = ipOpt(net.IP(s.cfg.Router.AsSlice()))
		}
		if len(s.cfg.DNS) > 0 {
			var v []byte
			for _, d := range s.cfg.DNS {
				v = append(v, d.AsSlice()...)
			}
			resp.Options[OptDNS] = v
		}
	}

	// ★ 客户端此刻多半还没有地址，单播发过去它收不到 —— 一律广播。
	//   （严格说要看 Flags 的广播位和 CIAddr，但在我们这个场景里
	//     一律广播既正确又少一类难查的失败。）
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: ClientPort}
	if req.GIAddr != nil && !req.GIAddr.Equal(net.IPv4zero) {
		dst = &net.UDPAddr{IP: req.GIAddr, Port: ServerPort} // 经中继来的，回给中继
	}
	if _, err := s.conn.WriteTo(resp.Marshal(), dst); err != nil {
		s.log.Warn("回 DHCP 报文失败", "err", err)
	}
}

// Leases 当前租约，按 IP 排序。
func (s *Server) Leases() []LeaseRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LeaseRec, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out
}

// PoolSize 池子有多少个地址。
func (c *Config) PoolSize() int {
	n := 0
	for a := c.Start; ; a = a.Next() {
		n++
		if a == c.End || n > 65536 {
			break
		}
	}
	return n
}

func hostNameOf(p *Packet) string {
	if v, ok := p.Options[OptHostName]; ok {
		return string(v)
	}
	return ""
}
