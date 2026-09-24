package snmptest

// 一台只用来做测试的假交换机：按 MIB 的规矩答 GET/GETNEXT/GETBULK，
// 并且故意留了几处真实设备的毛病（每一个开关旁边都写了为什么留）。
//
// ★ 为什么单独成一个包，而不是留在 snmp 的 _test.go 里：
//   tools 那一层要拿它当「现场那台交换机」，测的是 SNMP 之上的语义
//   （MAC 表怎么拼、端口状态怎么判），而 _test.go 里的东西外面用不了。
//   搬到这里之后，底座自己的测试和 tools 的测试共用同一台假设备 ——
//   两台各写一遍，最容易错的那半正好测不出来。
//
// ★ 为什么不用第三方库测自己：那样两边错到一处就永远测不出来。
//   底座那侧另外有 interop 测试，拿系统自带的 Net-SNMP 客户端做互测。

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"net.yuhox.com/netkit/internal/snmp"
)

type fakeEntry struct {
	oid string
	tag byte
	val []byte
}

// Device 是一台会答话的设备。
type Device struct {
	pc        *net.UDPConn
	community string

	mu      sync.Mutex
	entries []fakeEntry

	// 下面几个开关用来复现现场那几种"设备答得不对"的样子
	dropReqs     int  // 前 N 个请求完全不答（丢包重传那条）
	noBulk       bool // 收到 GETBULK 回 tooBig（一批老设备就这样）
	ignorePrefix bool // 走到树末尾时不给 endOfMibView，而是把别的子树递过来
	v1Only       bool // 版本不是 v1 就干脆不答
	replyWrongID bool // 回话里的请求标识抄错一个字节
	stuck        bool // GETNEXT 永远回同一个 OID（走不动的那种设备）
	trapOnly     bool // 答非所问：回一条设备主动推的 trap

	gotReqs   int
	seenIDs   []int32
	seenPorts []int // 这些请求是从本机哪几个源端口来的 —— 一条连接复用的证据
}

// Start 起一台假设备，返回它和地址（port 由系统挑）。
func Start(t *testing.T, community string, entries map[string]Value) *Device {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{pc: pc, community: community}
	for oid, v := range entries {
		d.entries = append(d.entries, fakeEntry{oid: strings.TrimPrefix(oid, "."), tag: v.Tag, val: v.raw()})
	}
	sort.Slice(d.entries, func(i, j int) bool { return snmp.CmpOID(d.entries[i].oid, d.entries[j].oid) < 0 })
	go d.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return d
}

// Value 是测试里给假设备填的一栏值。
type Value struct {
	Tag byte
	S   string // 字符串 / 不透明数据
	N   int64  // INTEGER
	U   uint64 // Counter32 / Gauge32 / TimeTicks / Counter64
	OID string // 值本身是一个 OID（比如 sysObjectID、ifType 的枚举名）
	IP  net.IP
	B   []byte // 原始字节：MAC 表这类二进制就填这里
}

// raw 编成报文里那串内容字节。
//
// ★ 走的是 snmp.IntContent / snmp.UintContent —— 和真客户端拼请求同一份代码。
//
//	这里另写一遍 trim 逻辑的话，「两边各自错到一处」正好测不出来。
func (v Value) raw() []byte {
	switch v.Tag {
	case snmp.TagOctetString, snmp.TagOpaque:
		// ★ 二进制内容走 B：MAC、LLDP 的 chassisId、capability bitmap 都是 OCTET STRING，
		//   里面必然有 0x00 和不可打印字节。只认 S 的话，编出来是一串空内容 ——
		//   测试里看到的现象是「这一栏设备明明给了，读回来是 nil」，
		//   而人会以为是上层解析错了。
		if v.B != nil {
			return append([]byte(nil), v.B...)
		}
		return []byte(v.S)
	case snmp.TagInteger:
		return snmp.IntContent(v.N)
	case snmp.TagCounter64, snmp.TagGauge32, snmp.TagCounter32, snmp.TagTimeTicks:
		return snmp.UintContent(v.U)
	case snmp.TagOID:
		c, err := snmp.OIDContent(v.OID)
		if err != nil {
			panic(err)
		}
		return c
	case snmp.TagIPAddress:
		ip := v.IP.To4()
		if ip == nil {
			panic("假设备只能填 IPv4 地址")
		}
		return append([]byte(nil), ip...)
	}
	return append([]byte(nil), v.B...)
}

func Str(s string) Value      { return Value{Tag: snmp.TagOctetString, S: s} }
func Int(n int64) Value       { return Value{Tag: snmp.TagInteger, N: n} }
func Count(v uint64) Value    { return Value{Tag: snmp.TagCounter32, U: v} }
func Count64(v uint64) Value  { return Value{Tag: snmp.TagCounter64, U: v} }
func Gauge(v uint64) Value    { return Value{Tag: snmp.TagGauge32, U: v} }
func Ticks(v uint64) Value    { return Value{Tag: snmp.TagTimeTicks, U: v} }
func MAC(b []byte) Value      { return Value{Tag: snmp.TagOctetString, B: b} }
func Addr(ip net.IP) Value    { return Value{Tag: snmp.TagIPAddress, IP: ip} }
func Object(oid string) Value { return Value{Tag: snmp.TagOID, OID: oid} }

// Bind 直接拼一个 VarBind（不经网络）：列 OID + 行号 + 值。
//
// ★ 用在「考点是算法而不是报文」的那几条测试上（比如两遍读数相减）。
//
//	走一遍假设备的话，一条测试里就同时有设备行为又有算法，哪边错了都分不出来。
func Bind(columnOID string, row int, v Value) snmp.VarBind {
	return snmp.VarBind{
		OID: strings.TrimPrefix(columnOID, ".") + "." + strconv.Itoa(row),
		Tag: v.Tag, Val: v.raw(),
	}
}

func (d *Device) Addr() string { return d.pc.LocalAddr().String() }

func (d *Device) Port() int { return d.pc.LocalAddr().(*net.UDPAddr).Port }

func (d *Device) Reqs() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gotReqs
}

// IDs 返回这台设备见过的请求标识，按来的顺序。
//
// ★ 用来钉两件事：同一个客户端连着问时号不许重，而且每个号都必须是**正数** ——
//
//	最高位给了 1，设备按补码读回是负数，跟我们记的对不上，
//	表现成「每次请求都超时」，是这一层最难查的一种。
func (d *Device) IDs() []int32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int32(nil), d.seenIDs...)
}

func (d *Device) serve() {
	buf := make([]byte, 2000)
	for {
		n, peer, err := d.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		d.handle(buf[:n], peer)
	}
}

func (d *Device) handle(b []byte, peer *net.UDPAddr) {
	req, err := snmp.Parse(b)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.gotReqs++
	d.seenIDs = append(d.seenIDs, req.ID)
	if peer.Port != 0 {
		seen := false
		for _, p := range d.seenPorts {
			if p == peer.Port {
				seen = true
			}
		}
		if !seen {
			d.seenPorts = append(d.seenPorts, peer.Port)
		}
	}
	drop := d.dropReqs > 0
	if drop {
		d.dropReqs--
	}
	communityOK := req.Community == d.community
	v1Only, noBulk, wrongID := d.v1Only, d.noBulk, d.replyWrongID
	trapOnly, stuck := d.trapOnly, d.stuck
	d.mu.Unlock()

	// ★ 团体名不对时**不答**，不是答一句「不许读」：v2c 的常见实现就是这么装的，
	//   而这条决定了界面上那句「没回话」要同时怀疑防火墙和团体名。
	if drop || !communityOK || (v1Only && req.Version != snmp.Version1) {
		return
	}
	resp := snmp.Packet{
		Version:   req.Version,
		Community: d.community,
		PDU:       snmp.PDUGetResponse,
		ID:        req.ID,
	}
	if trapOnly {
		// ★ 答非所问：设备上配了往我们这台推 trap，于是我们问一句它回一条告警。
		//   这不是回话，但它是「设备活着、SNMP 开着」的证据 —— 两件事要分开说。
		resp.PDU = snmp.PDUTrapV2
	}
	if wrongID {
		// ★ 真毛病：回包标识对不上。客户端认了它，就是把别人的答案当成这次的。
		//   用异或而不是 ±1：重传时标识正好是 +1，那样会在「等下一次」和「丢掉」之间抖。
		resp.ID = req.ID ^ int32(0x4000)
	}
	switch req.PDU {
	case snmp.PDUGetRequest:
		resp.VarBinds, resp.ErrStatus, resp.ErrIndex = d.getBy(req.VarBinds, req.Version)
	case snmp.PDUGetNextRequest:
		resp.VarBinds, resp.ErrStatus, resp.ErrIndex = d.getNext(req.VarBinds, req.Version, stuck)
	case snmp.PDUGetBulkRequest:
		if noBulk {
			resp.ErrStatus = 1 // tooBig
			resp.VarBinds = req.VarBinds
			break
		}
		resp.VarBinds = d.getBulk(req, stuck)
	default:
		return
	}
	if trapOnly {
		resp.VarBinds = req.VarBinds
	}
	out, err := resp.Marshal()
	if err != nil {
		return
	}
	_, _ = d.pc.WriteTo(out, peer)
}

func (d *Device) lookup(oid string) (fakeEntry, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if snmp.CmpOID(e.oid, oid) == 0 {
			return e, true
		}
	}
	return fakeEntry{}, false
}

func (d *Device) next(oid string) (fakeEntry, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if snmp.CmpOID(e.oid, oid) > 0 {
			return e, true
		}
	}
	return fakeEntry{}, false
}

// getBy 精确取值：v2c 对「没有的这一栏」回 noSuchInstance，
// v1 是整个报文作废 —— error-status=noSuchName，error-index 指出第几栏。
// 两种写法都得留着，因为界面上「这台设备没有这一栏」和「这台只认 v1」是两件事。
func (d *Device) getBy(binds []snmp.VarBind, version int) ([]snmp.VarBind, int, int) {
	out := make([]snmp.VarBind, 0, len(binds))
	for i, b := range binds {
		if e, ok := d.lookup(b.OID); ok {
			out = append(out, snmp.VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
			continue
		}
		if version == snmp.Version1 {
			return append([]snmp.VarBind(nil), binds...), 2, i + 1
		}
		out = append(out, snmp.VarBind{OID: b.OID, Tag: snmp.TagNoSuchInstance})
	}
	return out, 0, 0
}

func (d *Device) getNext(binds []snmp.VarBind, version int, stuck bool) ([]snmp.VarBind, int, int) {
	out := make([]snmp.VarBind, 0, len(binds))
	for i, b := range binds {
		if stuck {
			// ★ 真毛病：回的还是问的那一栏。不查这一条的话 walk 就是一个死循环，
			//   而现场看到的是「程序卡住」，不是「这台设备走不动」。
			out = append(out, snmp.VarBind{OID: b.OID, Tag: snmp.TagInteger, Val: snmp.IntContent(1)})
			continue
		}
		e, ok := d.next(b.OID)
		if !ok {
			if version == snmp.Version1 {
				return append([]snmp.VarBind(nil), binds...), 2, i + 1
			}
			if d.leaky() {
				// ★ 真实毛病：有的实现走到树末尾时不给异常值，直接把 .0 那一栏之外的
				//   下一棵子树递过来。只认 endOfMibView 的 walk 会一路读到整张 MIB。
				out = append(out, snmp.VarBind{OID: "1.3.6.1.2.1.99.1", Tag: snmp.TagInteger, Val: snmp.IntContent(1)})
				continue
			}
			out = append(out, snmp.VarBind{OID: b.OID, Tag: snmp.TagEndOfMibView})
			continue
		}
		out = append(out, snmp.VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
	}
	return out, 0, 0
}

// getBulk 按 non-repeaters / max-repetitions 展开。
func (d *Device) getBulk(req snmp.Packet, stuck bool) []snmp.VarBind {
	nr, mr := req.ErrStatus, req.ErrIndex
	if nr > len(req.VarBinds) {
		nr = len(req.VarBinds)
	}
	if mr < 1 {
		mr = 1
	}
	if mr > 100 {
		mr = 100
	}
	if stuck {
		var out []snmp.VarBind
		for _, b := range req.VarBinds {
			out = append(out, snmp.VarBind{OID: b.OID, Tag: snmp.TagInteger, Val: snmp.IntContent(1)})
		}
		return out
	}
	var out []snmp.VarBind
	for _, b := range req.VarBinds[:nr] {
		if e, ok := d.next(b.OID); ok {
			out = append(out, snmp.VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
		} else {
			out = append(out, snmp.VarBind{OID: b.OID, Tag: snmp.TagEndOfMibView})
		}
	}
	cols := req.VarBinds[nr:]
	if len(cols) == 0 {
		return out
	}
	cur := append([]snmp.VarBind(nil), cols...)
	for i := 0; i < mr; i++ {
		done := true
		var nxt []snmp.VarBind
		for _, c := range cur {
			e, ok := d.next(c.OID)
			if !ok {
				nxt = append(nxt, snmp.VarBind{OID: c.OID, Tag: snmp.TagEndOfMibView})
				continue
			}
			done = false
			nxt = append(nxt, snmp.VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
		}
		out = append(out, nxt...)
		cur = nxt
		if done {
			break
		}
	}
	return out
}

func (d *Device) leaky() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ignorePrefix
}

// Ports 返回这台设备见过的源端口，按第一次出现的顺序。
//
// ★ 一个客户端问了好几次，这里就只能有一个号：
//
//	每次重新拨号的话源端口会变，设备的会话表会把我们登记成一堆新管理器。
//	这一条从外面看（测试里读不到私有字段），所以在这里记下来。
func (d *Device) Ports() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int(nil), d.seenPorts...)
}

// Set 在跑起来以后改一栏的值（没有这栏就加进去）。
//
// ★ 为什么需要：计数器类的那几栏（ifInOctets、dot1dTpFdb 的流量、PoE 的功率）
//
//	真正的考点是**两次读之间的差**。值写死在表里的话，第二遍读到的一样，
//	差永远是 0 —— 于是「回绕算错了」这种最要紧的 bug 恰恰测不出来。
//	所以这里要能在两次读当中把计数器推一把。
func (d *Device) Set(oid string, v Value) {
	o := strings.TrimPrefix(oid, ".")
	e := fakeEntry{oid: o, tag: v.Tag, val: v.raw()}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.entries {
		if d.entries[i].oid == o {
			d.entries[i] = e
			return
		}
	}
	d.entries = append(d.entries, e)
	sort.Slice(d.entries, func(i, j int) bool { return snmp.CmpOID(d.entries[i].oid, d.entries[j].oid) < 0 })
}

// Del 删掉一栏：用来复现「第一遍读得到、第二遍设备不给了」（换视图、重启后配置没回来）。
func (d *Device) Del(oid string) {
	o := strings.TrimPrefix(oid, ".")
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.entries {
		if d.entries[i].oid == o {
			d.entries = append(d.entries[:i], d.entries[i+1:]...)
			return
		}
	}
}

// SetDropNext 让后面 N 个请求不答（测重传）。
func (d *Device) SetDropNext(n int) {
	d.mu.Lock()
	d.dropReqs = n
	d.mu.Unlock()
}

// SetNoBulk 让这台设备对 GETBULK 回 tooBig（测 walk 退回 GETNEXT）。
func (d *Device) SetNoBulk(v bool) {
	d.mu.Lock()
	d.noBulk = v
	d.mu.Unlock()
}

// SetLeaky 让这台设备走到树末尾时把别的子树递过来（测 walk 的收口条件）。
func (d *Device) SetLeaky(v bool) {
	d.mu.Lock()
	d.ignorePrefix = v
	d.mu.Unlock()
}

// SetV1Only 让这台设备只答 v1（测版本那条）。
func (d *Device) SetV1Only(v bool) {
	d.mu.Lock()
	d.v1Only = v
	d.mu.Unlock()
}

// SetWrongID 让这台设备回话时把请求标识写错（测「认了别人的答案」）。
func (d *Device) SetWrongID(v bool) {
	d.mu.Lock()
	d.replyWrongID = v
	d.mu.Unlock()
}

// SetStuck 让这台设备对 GETNEXT/GETBULK 永远回同一栏（测 walk 的死循环兜底）。
func (d *Device) SetStuck(v bool) {
	d.mu.Lock()
	d.stuck = v
	d.mu.Unlock()
}

// SetTrapOnly 让这台设备问一句回一条 trap（测「有回包但不是答案」那句话）。
func (d *Device) SetTrapOnly(v bool) {
	d.mu.Lock()
	d.trapOnly = v
	d.mu.Unlock()
}
