package broadcast

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ── mDNS / DNS-SD ──
//
// ★ 报文格式就是 DNS（RFC 1035 那段），差别在两处：
//   类字段最高位 —— 应答里是 cache-flush，查询里是 unicast-response（QU）；
//   以及名字**允许压缩指针**，而设备发来的应答几乎都用指针。
//   指针这一条是这一整个文件里最容易写出错的地方：它是从报文开头算的偏移，
//   而且能互相指，所以必须有跳数上限，不然一条坏包就能让这一趟转不完。

// DNS 记录类型（这里只解现场用得上的几种）。
const (
	typeA      uint16 = 1
	typePTR    uint16 = 12
	typeTXT    uint16 = 16
	typeAAAA   uint16 = 28
	typeSRV    uint16 = 33
	typeNSEC   uint16 = 47
	classIN    uint16 = 1
	bitCache   uint16 = 0x8000 // 应答里：这条之前的缓存可以扔了
	bitUnicast uint16 = 0x8000 // 查询里：请用单播回我
)

// ErrNotMDNS 表示这一条不是能认的 DNS 报文。
var ErrNotMDNS = errors.New("不是 mDNS 报文")

// MDNSQuery 拼一条 PTR 查询。names 是 DNS-SD 服务类型名，如 "_rtsp._tcp.local"。
//
// ★ unicastReply 为真时置 QU 位：我们**不是**一个完整的 mDNS 实现
//
//	（不常驻 5353、不做冲突检测），照 RFC 6762 §6.7，应答方看到源端口不是 5353
//	就必须单播回我们。不置这一位的话，回答会 multicast 到 224.0.0.251:5353，
//	而我们这个临时套接字收不收得到，取决于本机有没有别的 mDNS 监听者 ——
//	那就变成「在有的机器上查得到、有的查不到」。
func MDNSQuery(names []string, unicastReply bool) ([]byte, error) {
	if len(names) == 0 {
		return nil, errors.New("一个服务类型都没给，问谁")
	}
	if len(names) > 32 {
		names = names[:32]
	}
	var b []byte
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(names))) // QDCOUNT；标志位全零 = 一条查询
	b = append(b, hdr[:]...)
	for _, n := range names {
		enc, err := EncodeName(n)
		if err != nil {
			return nil, err
		}
		b = append(b, enc...)
		var q [4]byte
		binary.BigEndian.PutUint16(q[0:2], typePTR)
		cl := classIN
		if unicastReply {
			cl |= bitUnicast
		}
		binary.BigEndian.PutUint16(q[2:4], cl)
		b = append(b, q[:]...)
	}
	return b, nil
}

// EncodeName 把 "a.b.c" 写成 DNS 的标签序列。
func EncodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	var b []byte
	for _, lbl := range strings.Split(name, ".") {
		if lbl == "" {
			return nil, fmt.Errorf("名字 %q 里有空标签", name)
		}
		if len(lbl) > 63 {
			return nil, fmt.Errorf("名字 %q 里有一段 %d 字节，超过 63 的标签上限", name, len(lbl))
		}
		b = append(b, byte(len(lbl)))
		b = append(b, lbl...)
	}
	return append(b, 0), nil
}

// Msg 一条解开的 DNS 报文。
type Msg struct {
	ID         uint16
	Response   bool
	Truncated  bool
	Questions  []Question
	Answers    []Record
	Authority  []Record
	Additional []Record
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Record 一条资源记录。Data 按类型是 PTRName / SRV / TXT / Addr 之一。
type Record struct {
	Name       string
	Type       uint16
	Class      uint16
	CacheFlush bool
	TTL        uint32
	Data       any
}

type PTRName struct{ Target string }
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}
type TXT struct {
	Entries []string
	Values  map[string]string // key=value 形式的那几条
}
type Addr struct{ Addr string } // A 或 AAAA，看记录的 Type

// ParseMDNS 解一条 mDNS/DNS 报文。
func ParseMDNS(msg []byte) (*Msg, error) {
	if len(msg) < 12 {
		return nil, ErrNotMDNS
	}
	m := &Msg{ID: binary.BigEndian.Uint16(msg[0:2])}
	flags := binary.BigEndian.Uint16(msg[2:4])
	m.Response = flags&0x8000 != 0
	m.Truncated = flags&0x0200 != 0
	counts := [4]uint16{
		binary.BigEndian.Uint16(msg[4:6]),
		binary.BigEndian.Uint16(msg[6:8]),
		binary.BigEndian.Uint16(msg[8:10]),
		binary.BigEndian.Uint16(msg[10:12]),
	}
	// ★ 段数上限：一条报文里写 6 万条记录是合法的字段值，但不是合法的网络行为。
	//   不设这一道，一个坏包（或一个故意捣乱的）就能把这一趟的收包循环拖死。
	for _, n := range counts {
		if int(n) > MaxReports {
			return nil, fmt.Errorf("一条报文里写了 %d 段记录，超过 %d 的上限", n, MaxReports)
		}
	}
	pos := 12
	var err error
	for i := 0; i < int(counts[0]); i++ {
		var q Question
		if q, pos, err = readQuestion(msg, pos); err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, q)
	}
	sections := []struct {
		n     int
		dest  *[]Record
		label string
	}{
		{int(counts[1]), &m.Answers, "answer"},
		{int(counts[2]), &m.Authority, "authority"},
		{int(counts[3]), &m.Additional, "additional"},
	}
	total := 0
	for _, s := range sections {
		for i := 0; i < s.n; i++ {
			var r Record
			if r, pos, err = readRecord(msg, pos); err != nil {
				// ★ 一条都没读出来的坏包就照坏包处理（界面上那一句是「收到了读不懂的东西」）；
				//   已经读到过几条的，剩下的按丢，**前面的留着** —— 一台设备常常是
				//   「一条 SRV + 两条 A」连着发，丢掉整条等于丢掉那台。
				if total == 0 {
					return nil, err
				}
				return m, nil
			}
			*s.dest = append(*s.dest, r)
			total++
		}
	}
	return m, nil
}

func readQuestion(msg []byte, pos int) (Question, int, error) {
	name, next, err := ReadName(msg, pos)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(msg) {
		return Question{}, 0, ErrNotMDNS
	}
	q := Question{Name: name,
		Type:  binary.BigEndian.Uint16(msg[next : next+2]),
		Class: binary.BigEndian.Uint16(msg[next+2 : next+4])}
	return q, next + 4, nil
}

func readRecord(msg []byte, pos int) (Record, int, error) {
	name, next, err := ReadName(msg, pos)
	if err != nil {
		return Record{}, 0, err
	}
	if next+10 > len(msg) {
		return Record{}, 0, ErrNotMDNS
	}
	r := Record{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[next : next+2]),
		Class: binary.BigEndian.Uint16(msg[next+2:next+4]) &^ bitCache,
	}
	r.CacheFlush = binary.BigEndian.Uint16(msg[next+2:next+4])&bitCache != 0
	r.TTL = binary.BigEndian.Uint32(msg[next+4 : next+8])
	rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
	body := next + 10
	if body+rdLen > len(msg) {
		return r, len(msg), nil // 声明的长度超出报文：这一条按读不全处理，不 panic
	}
	data := msg[body : body+rdLen]
	switch r.Type {
	case typePTR:
		if t, _, err := ReadName(msg, body); err == nil {
			r.Data = PTRName{Target: t}
		}
	case typeSRV:
		// RDATA = 优先级(2) + 权重(2) + 端口(2) + 目标名，所以名字从第 6 个字节起。
		// 少读两个字节就会把目标名的长度字节当成端口后面的东西。
		if len(data) >= 7 {
			t, _, err := ReadName(msg, body+6)
			if err != nil {
				break
			}
			r.Data = SRV{
				Priority: binary.BigEndian.Uint16(data[0:2]),
				Weight:   binary.BigEndian.Uint16(data[2:4]),
				Port:     binary.BigEndian.Uint16(data[4:6]),
				Target:   t,
			}
		}
	case typeTXT:
		r.Data = parseTXT(data)
	case typeA:
		if len(data) == 4 {
			r.Data = Addr{Addr: ipString(data)}
		}
	case typeAAAA:
		if len(data) == 16 {
			r.Data = Addr{Addr: ipString(data)}
		}
	}
	return r, body + rdLen, nil
}

// parseTXT 一条 TXT 的 RDATA 是若干「长度字节 + 内容」。
//
// ★ 为什么还要拆 key=value：DNS-SD 规定 TXT 里就是这个形式（txtvers=1、note=…），
//
//	现场想知道的「这台是什么型号、管理页在哪」常常就写在里面。
//	拆不出来的一律进 Entries 原样留着 —— 宁可给人看一行原文，不许显示成空。
func parseTXT(data []byte) TXT {
	var t TXT
	t.Values = map[string]string{}
	for len(data) > 0 {
		n := int(data[0])
		data = data[1:]
		if n > len(data) {
			t.Entries = append(t.Entries, clip(string(data), MaxTXTBytes))
			break
		}
		s := string(data[:n])
		data = data[n:]
		t.Entries = append(t.Entries, clip(s, MaxTXTBytes))
		if k, v, ok := strings.Cut(s, "="); ok && k != "" {
			if _, dup := t.Values[k]; !dup {
				t.Values[k] = clip(v, 200)
			}
		}
	}
	if len(t.Values) == 0 {
		t.Values = nil
	}
	return t
}

// ReadName 从 off 处读一个（可能压缩的）名字，返回名字与**跳过这段之后的位置**。
//
// ★ 压缩指针的坑有三个，逐个守住：
//   - 偏移是从报文开头算的，不是从当前位置；
//   - 指针可以指向另一个指针，所以要跟着跳，且必须有跳数上限（否则坏包无限循环）；
//   - 跳完指针之后，**外层记录里这段名字后面的字节**才是继续解析的位置，
//     所以返回的是第一次落到的「非指针」位置 + 1，不是指针指向处。
func ReadName(msg []byte, off int) (string, int, error) {
	var labels []string
	jumps := 0
	resume := 0 // 跟着指针跳走之前，记下第一次落点后面的位置
	for {
		if off >= len(msg) {
			return "", 0, ErrNotMDNS
		}
		l := int(msg[off])
		if l == 0 {
			off++
			if resume == 0 {
				resume = off
			}
			break
		}
		if l&0xC0 == 0xC0 { // 指针
			if off+2 > len(msg) {
				return "", 0, ErrNotMDNS
			}
			if resume == 0 {
				resume = off + 2
			}
			jumps++
			if jumps > 32 {
				return "", 0, errors.New("名字里的压缩指针跳了 32 次还没到头：这一条按坏包处理")
			}
			target := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			// ★ 指针只能往回指（被引用的名字一定在这之前出现过）。守住
			//   「新位置必须比当前位置小」，坏包就造不出「A 指 B、B 指 A」的循环 ——
			//   上面那个跳数上限只是第二道保险。
			if target >= off || target >= len(msg) {
				return "", 0, ErrNotMDNS
			}
			off = target
			continue
		}
		if l&0xC0 != 0 {
			return "", 0, errors.New("名字里出现了保留的标签类型（0x40/0x80 开头）")
		}
		off++
		if off+l > len(msg) {
			return "", 0, ErrNotMDNS
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
		if len(labels) > 64 {
			return "", 0, errors.New("名字标签超过 64 段")
		}
	}
	return strings.Join(labels, "."), resume, nil
}

// ServiceName 把 DNS-SD 的名字拆成「实例名」和「服务类型」两段：
//
//	"3楼球机._rtsp._tcp.local" → 实例 "3楼球机"、类型 "_rtsp._tcp.local"
//	"_rtsp._tcp.local"         → 实例空、类型同上
//
// ★ 为什么要拆：界面上「谁」用的是实例名（人给它起的名字），「是什么」用的是
//
//	服务类型；混在一行里显示，一百行全是同一个后缀。
//	切点取协议标签（_tcp / _udp）前面那一段，而不是第一个 "._" ——
//	实例名里带点的机器（"1F.摄像头._rtsp._tcp.local"）用第一个 "._" 会切错。
func ServiceName(name string) (instance, service string) {
	n := strings.TrimSuffix(name, ".")
	for _, proto := range []string{"._tcp.", "._udp."} {
		i := strings.Index(n, proto)
		if i < 0 {
			continue
		}
		start := strings.LastIndexByte(n[:i], '.') + 1
		if !strings.HasPrefix(n[start:], "_") {
			continue // 协议标签前面不是服务类型：整段都当名字给人看
		}
		return strings.TrimSuffix(n[:start], "."), n[start:]
	}
	return n, ""
}

// Reports 把一条应答摊成「谁在自报」的记录。
//
// ★★ 为什么要在这个包里摊，而不是让工具层去翻记录数组：
//
//	DNS-SD 的一句话是**散在好几条记录里**的 —— 实例名在 PTR 里、端口在 SRV 里、
//	型号在 TXT 里、地址在 A 里。工具层要是自己去拼，它就得懂 DNS-SD 的命名规则，
//	而那正是这一包存在的理由（拼错的实例名会把一台设备裂成三台）。
//
// ★ 按实例归并，一台设备多个服务就是多条（NAS 往往同时报 _smb 与 _rtsp）。
//
//	把多条合成一台是工具层的事，那里有 MAC 与地址这几个跨协议的口径。
func (m *Msg) Reports(from string) []*Report {
	if m == nil || !m.Response {
		return nil
	}
	var order []*Report
	byName := map[string]*Report{}
	// ★ TTL 单独记一张表：Report.TTL 的 0 已经是「对方在告退」的意思，
	//   不能同时再当「还没记过」用，否则最小值算不出来。
	ttl := map[*Report]uint32{}
	lowest := func(r *Report, v uint32) {
		if cur, ok := ttl[r]; !ok || v < cur {
			ttl[r] = v
		}
	}
	touch := func(instance, service string) *Report {
		if r := byName[instance]; r != nil {
			if r.Type == "" {
				r.Type = service
			}
			return r
		}
		r := &Report{Source: SourceMDNS, From: from, Instance: instance,
			Name: instance, Type: service}
		byName[instance] = r
		order = append(order, r)
		return r
	}
	walk := func(recs []Record) {
		for _, rec := range recs {
			inst, svc := ServiceName(rec.Name)
			switch d := rec.Data.(type) {
			case PTRName:
				// 服务类型那一头（"_rtsp._tcp.local" 报出实例名）：实例在 target 里。
				if inst == "" {
					if i2, s2 := ServiceName(d.Target); i2 != "" {
						inst, svc = i2, s2
					} else {
						continue // 报的是主机名不是实例：那一条留给 SRV 去接
					}
				}
				r := touch(inst, svc)
				if r.Host == "" {
					r.Host = strings.TrimSuffix(d.Target, ".")
				}
				lowest(r, rec.TTL)
			case SRV:
				if inst == "" {
					continue
				}
				r := touch(inst, svc)
				r.Host = strings.TrimSuffix(d.Target, ".")
				r.Port = int(d.Port)
				lowest(r, rec.TTL)
			case TXT:
				if inst == "" {
					continue
				}
				r := touch(inst, svc)
				for _, kv := range d.Entries {
					k, v, _ := strings.Cut(kv, "=")
					if k == "" {
						continue
					}
					r.Text = setText(r.Text, "txt:"+k, clip(v, 200))
				}
				lowest(r, rec.TTL)
			case Addr:
				// A/AAAA 挂在主机名上：只有它已经作为某实例的目标出现过，才算这条自报的地址。
				host := strings.TrimSuffix(rec.Name, ".")
				for _, r := range order {
					if r.Host == host && r.Text["address"] == "" {
						r.Text = setText(r.Text, "address", clip(d.Addr, 60))
					}
				}
			}
		}
	}
	walk(m.Answers)
	// 附加段里带着 SRV 与 A：DNS-SD 的应答经常把答案放那儿，只翻答案段会漏掉端口。
	walk(m.Additional)
	for _, r := range order {
		if v, ok := ttl[r]; ok {
			r.TTL = int(minUint32(v, MaxTTLSeconds))
		}
	}
	return order
}

// minUint32 取两个数里小的那个（Go 的内置 min 在这里要先做上限，写法更绕）。
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// TypeLabel 把记录类型编号翻成界面上的词。未知编号原样给数字。
func TypeLabel(t uint16) string {
	switch t {
	case typeA:
		return "A"
	case typeAAAA:
		return "AAAA"
	case typePTR:
		return "PTR"
	case typeSRV:
		return "SRV"
	case typeTXT:
		return "TXT"
	case typeNSEC:
		return "NSEC"
	}
	return fmt.Sprintf("类型 %d", t)
}

// ipString 用标准库渲染，保证 v6 是压缩过的那种写法。
// ★ 不在这里自己拼十六进制：自己拼出来的 "0:0:0:0:0:0:0:1" 和别的页面上的
//
//	"::1" 对不上，而现场是把这几个地址拿去和交换机 MAC 表、路由表对着看的。
func ipString(b []byte) string {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return ""
	}
	return a.String()
}
