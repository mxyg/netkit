package snmp

// 一个只用来做测试的"假交换机"：它按 MIB 的规矩答 GET/GETNEXT/GETBULK，
// 并且故意留了几处真实设备的毛病（见下面每一条注释）。
//
// ★ 为什么不用第三方库测自己：那样两边错到一处就永远测不出来。
//   这里除了自己写，另外在 interop_test.go 里拿系统自带的 Net-SNMP 客户端做互测。

import (
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
)

type fakeEntry struct {
	oid string
	tag byte
	val []byte
}

// FakeDevice 是一台会答话的设备。
type FakeDevice struct {
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

	gotReqs int
	seenIDs []int32
}

// StartFake 起一台假设备，返回它和地址（port 由系统挑）。
func StartFake(t *testing.T, community string, entries map[string]Value) *FakeDevice {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	d := &FakeDevice{pc: pc, community: community}
	for oid, v := range entries {
		d.entries = append(d.entries, fakeEntry{oid: strings.TrimPrefix(oid, "."), tag: v.Tag, val: v.raw()})
	}
	sort.Slice(d.entries, func(i, j int) bool { return CmpOID(d.entries[i].oid, d.entries[j].oid) < 0 })
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
// ★ 走的是 intContent / uintContent —— 和真客户端拼请求同一份代码。
//
//	这里另写一遍 trim 逻辑的话，「两边各自错到一处」正好测不出来。
func (v Value) raw() []byte {
	switch v.Tag {
	case TagOctetString, TagOpaque:
		return []byte(v.S)
	case TagInteger:
		return intContent(v.N)
	case TagCounter64, TagGauge32, TagCounter32, TagTimeTicks:
		return uintContent(v.U)
	case TagOID:
		c, err := OIDContent(v.OID)
		if err != nil {
			panic(err)
		}
		return c
	case TagIPAddress:
		ip := v.IP.To4()
		if ip == nil {
			panic("假设备只能填 IPv4 地址")
		}
		return append([]byte(nil), ip...)
	}
	return append([]byte(nil), v.B...)
}

func Str(s string) Value      { return Value{Tag: TagOctetString, S: s} }
func Int(n int64) Value       { return Value{Tag: TagInteger, N: n} }
func Count(v uint64) Value    { return Value{Tag: TagCounter32, U: v} }
func Count64(v uint64) Value  { return Value{Tag: TagCounter64, U: v} }
func Gauge(v uint64) Value    { return Value{Tag: TagGauge32, U: v} }
func Ticks(v uint64) Value    { return Value{Tag: TagTimeTicks, U: v} }
func MAC(b []byte) Value      { return Value{Tag: TagOctetString, B: b} }
func Addr(ip net.IP) Value    { return Value{Tag: TagIPAddress, IP: ip} }
func Object(oid string) Value { return Value{Tag: TagOID, OID: oid} }

func (d *FakeDevice) Addr() string { return d.pc.LocalAddr().String() }

func (d *FakeDevice) Port() int { return d.pc.LocalAddr().(*net.UDPAddr).Port }

func (d *FakeDevice) Reqs() int {
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
func (d *FakeDevice) IDs() []int32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int32(nil), d.seenIDs...)
}

func (d *FakeDevice) serve() {
	buf := make([]byte, 2000)
	for {
		n, peer, err := d.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		d.handle(buf[:n], peer)
	}
}

func (d *FakeDevice) handle(b []byte, peer *net.UDPAddr) {
	req, err := Parse(b)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.gotReqs++
	d.seenIDs = append(d.seenIDs, req.ID)
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
	if drop || !communityOK || (v1Only && req.Version != Version1) {
		return
	}
	resp := Packet{
		Version:   req.Version,
		Community: d.community,
		PDU:       PDUGetResponse,
		ID:        req.ID,
	}
	if trapOnly {
		// ★ 答非所问：设备上配了往我们这台推 trap，于是我们问一句它回一条告警。
		//   这不是回话，但它是「设备活着、SNMP 开着」的证据 —— 两件事要分开说。
		resp.PDU = PDUTrapV2
	}
	if wrongID {
		// ★ 真毛病：回包标识对不上。客户端认了它，就是把别人的答案当成这次的。
		//   用异或而不是 ±1：重传时标识正好是 +1，那样会在「等下一次」和「丢掉」之间抖。
		resp.ID = req.ID ^ int32(0x4000)
	}
	switch req.PDU {
	case PDUGetRequest:
		resp.VarBinds, resp.ErrStatus, resp.ErrIndex = d.getBy(req.VarBinds, req.Version)
	case PDUGetNextRequest:
		resp.VarBinds, resp.ErrStatus, resp.ErrIndex = d.getNext(req.VarBinds, req.Version, stuck)
	case PDUGetBulkRequest:
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

func (d *FakeDevice) lookup(oid string) (fakeEntry, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if CmpOID(e.oid, oid) == 0 {
			return e, true
		}
	}
	return fakeEntry{}, false
}

func (d *FakeDevice) next(oid string) (fakeEntry, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if CmpOID(e.oid, oid) > 0 {
			return e, true
		}
	}
	return fakeEntry{}, false
}

// getBy 精确取值：v2c 对「没有的这一栏」回 noSuchInstance，
// v1 是整个报文作废 —— error-status=noSuchName，error-index 指出第几栏。
// 两种写法都得留着，因为界面上「这台设备没有这一栏」和「这台只认 v1」是两件事。
func (d *FakeDevice) getBy(binds []VarBind, version int) ([]VarBind, int, int) {
	out := make([]VarBind, 0, len(binds))
	for i, b := range binds {
		if e, ok := d.lookup(b.OID); ok {
			out = append(out, VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
			continue
		}
		if version == Version1 {
			return append([]VarBind(nil), binds...), 2, i + 1
		}
		out = append(out, VarBind{OID: b.OID, Tag: TagNoSuchInstance})
	}
	return out, 0, 0
}

func (d *FakeDevice) getNext(binds []VarBind, version int, stuck bool) ([]VarBind, int, int) {
	out := make([]VarBind, 0, len(binds))
	for i, b := range binds {
		if stuck {
			// ★ 真毛病：回的还是问的那一栏。不查这一条的话 walk 就是一个死循环，
			//   而现场看到的是「程序卡住」，不是「这台设备走不动」。
			out = append(out, VarBind{OID: b.OID, Tag: TagInteger, Val: intContent(1)})
			continue
		}
		e, ok := d.next(b.OID)
		if !ok {
			if version == Version1 {
				return append([]VarBind(nil), binds...), 2, i + 1
			}
			if d.leaky() {
				// ★ 真实毛病：有的实现走到树末尾时不给异常值，直接把 .0 那一栏之外的
				//   下一棵子树递过来。只认 endOfMibView 的 walk 会一路读到整张 MIB。
				out = append(out, VarBind{OID: "1.3.6.1.2.1.99.1", Tag: TagInteger, Val: intContent(1)})
				continue
			}
			out = append(out, VarBind{OID: b.OID, Tag: TagEndOfMibView})
			continue
		}
		out = append(out, VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
	}
	return out, 0, 0
}

// getBulk 按 non-repeaters / max-repetitions 展开。
func (d *FakeDevice) getBulk(req Packet, stuck bool) []VarBind {
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
		var out []VarBind
		for _, b := range req.VarBinds {
			out = append(out, VarBind{OID: b.OID, Tag: TagInteger, Val: intContent(1)})
		}
		return out
	}
	var out []VarBind
	for _, b := range req.VarBinds[:nr] {
		if e, ok := d.next(b.OID); ok {
			out = append(out, VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
		} else {
			out = append(out, VarBind{OID: b.OID, Tag: TagEndOfMibView})
		}
	}
	cols := req.VarBinds[nr:]
	if len(cols) == 0 {
		return out
	}
	cur := append([]VarBind(nil), cols...)
	for i := 0; i < mr; i++ {
		done := true
		var nxt []VarBind
		for _, c := range cur {
			e, ok := d.next(c.OID)
			if !ok {
				nxt = append(nxt, VarBind{OID: c.OID, Tag: TagEndOfMibView})
				continue
			}
			done = false
			nxt = append(nxt, VarBind{OID: e.oid, Tag: e.tag, Val: e.val})
		}
		out = append(out, nxt...)
		cur = nxt
		if done {
			break
		}
	}
	return out
}

func (d *FakeDevice) leaky() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ignorePrefix
}

// SetDropNext 让后面 N 个请求不答（测重传）。
func (d *FakeDevice) SetDropNext(n int) {
	d.mu.Lock()
	d.dropReqs = n
	d.mu.Unlock()
}

// SetNoBulk 让这台设备对 GETBULK 回 tooBig（测 walk 退回 GETNEXT）。
func (d *FakeDevice) SetNoBulk(v bool) {
	d.mu.Lock()
	d.noBulk = v
	d.mu.Unlock()
}

// SetLeaky 让这台设备走到树末尾时把别的子树递过来（测 walk 的收口条件）。
func (d *FakeDevice) SetLeaky(v bool) {
	d.mu.Lock()
	d.ignorePrefix = v
	d.mu.Unlock()
}

// SetV1Only 让这台设备只答 v1（测版本那条）。
func (d *FakeDevice) SetV1Only(v bool) {
	d.mu.Lock()
	d.v1Only = v
	d.mu.Unlock()
}

// SetWrongID 让这台设备回话时把请求标识写错（测「认了别人的答案」）。
func (d *FakeDevice) SetWrongID(v bool) {
	d.mu.Lock()
	d.replyWrongID = v
	d.mu.Unlock()
}

// SetStuck 让这台设备对 GETNEXT/GETBULK 永远回同一栏（测 walk 的死循环兜底）。
func (d *FakeDevice) SetStuck(v bool) {
	d.mu.Lock()
	d.stuck = v
	d.mu.Unlock()
}

// SetTrapOnly 让这台设备问一句回一条 trap（测「有回包但不是答案」那句话）。
func (d *FakeDevice) SetTrapOnly(v bool) {
	d.mu.Lock()
	d.trapOnly = v
	d.mu.Unlock()
}
