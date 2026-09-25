package capture

// 读侧：pcapng 与老 pcap（libpcap/tcpdump 那一份）都要能开。
//
// ★ 为什么读要自己写一份而不是「只支持我们写出来的那种」：现场拿到的文件绝大多数不是本机抓的 ——
//   同事用 tcpdump 抓的、摄像头导出的一段、Wireshark 转出来的。这些文件的写法比规范松得多：
//   大端的、多个段串在一起的、块里塞满没见过的选项的、时间戳按纳秒填的。
//   读不开就等于「这单只能请用户重新抓一遍」，那是最贵的失败。

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

// 老 pcap 的文件头魔数（按写方字节序读出来才是这两个值，反过来就是大端文件）。
const (
	pcapMagicMicro uint32 = 0xA1B2C3D4
	pcapMagicNano  uint32 = 0xA1B23C4D
)

// Packet 是读到的一包。
type Packet struct {
	// InterfaceIndex 是全局口序号（跨段稳定，见 Reader.Ifaces）。
	InterfaceIndex int
	Timestamp      time.Time
	Data           []byte
	// OrigLen 是线上那一份的长度；Data 只有 caplen 那么长，短了就是被截过。
	OrigLen int
	// Comment 是块里那条注释选项（写侧脱敏时会留一句）。
	Comment string
	// HasTimestamp 假 = 这一包没带时刻（简单包块里压根没这一格）。
	// ★ 不许拿零值当「1970 年抓的」，也不许拿前一包的时刻凑：
	//   那会让「第 3 秒那一下丢包」这类结论看着成立，实际是抄来的。
	HasTimestamp bool
}

// Reader 顺序读一个抓包文件。
type Reader struct {
	br        *bufio.Reader
	le        binary.ByteOrder // 当前段的字节序；老 pcap 文件为 nil
	ifaces    []Interface      // 全局口表：序号在整个文件里稳定
	secIfaces []int            // 段内口序号 → 全局序号
	pkts      int
	pending   *Packet     // 开文件时多读进来的那一个包（见 readUntilFirstPacket）
	legacy    *pcapGlobal // 非 nil 就是老 pcap 文件，块那套逻辑一概不走
}

type pcapGlobal struct {
	le       binary.ByteOrder
	nano     bool
	linkType uint16
	snapLen  uint32
}

// Open 从任意流读一个抓包文件（调用方负责关自己那个 io）。
func Open(r io.Reader) (*Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 1<<16)
	}
	head, err := br.Peek(4)
	if err != nil {
		return nil, err
	}
	rd := &Reader{br: br}
	switch {
	case isSHBHead(head):
		if err := rd.readSHB(); err != nil {
			return nil, err
		}
		// ★ 开文件时先把「第一个包之前」的块走完：真实的文件都是段头 + 一串接口描述 + 包，
		//   走完这一段，Ifaces() 才在 Read() 之前就有内容 —— 界面要先报「这份文件里有几个口、
		//   各是什么链路类型」，不能等读到包才拿得到（一个包都没落下的文件同样得能报出口表）。
		if err := rd.readUntilFirstPacket(); err != nil {
			return nil, err
		}
		return rd, nil
	case isPcapHead(head):
		return rd.openLegacy()
	}
	return nil, fmt.Errorf("capture: 头四个字节是 % x，既不像 pcapng（0a 0d 0d 0a）也不像 pcap（a1 b2 c3 d4）—— 这不是抓包文件，别硬读", head)
}

// pending 是开文件时多读进来的那一个包（口表要先于包交给调用方）。
func (r *Reader) readUntilFirstPacket() error {
	for r.pending == nil {
		p, err := r.readBlock()
		if err == io.EOF {
			return nil // 只有头没有包：合法的空文件，口表照样交出去
		}
		if err != nil {
			return err
		}
		if p != nil {
			r.pending = p
		}
	}
	return nil
}

// Ifaces 回已经读到的口。
//
// ★ 序号跨段按「名字+链路类型+刻度」合并所以稳定：按流聚合的键里有口序号，
//
//	第二段里同名的口若换了号，两张表会把同一条流算成两条，报表上就多出个不存在的会话。
func (r *Reader) Ifaces() []Interface { return append([]Interface(nil), r.ifaces...) }

// Pkts 回已经读到的包数（界面读到一半要显示进度用的）。
func (r *Reader) Pkts() int { return r.pkts }

// Read 读下一包；读到文件尾返回 io.EOF。
func (r *Reader) Read() (Packet, error) {
	if r.legacy != nil {
		return r.readLegacy()
	}
	if r.pending != nil {
		p := *r.pending
		r.pending = nil
		r.pkts++
		return p, nil
	}
	for {
		p, err := r.readBlock()
		if err != nil {
			return Packet{}, err
		}
		if p == nil {
			continue // 这一种块里没有包（接口描述、名字解析、认不出的都算）
		}
		r.pkts++
		return *p, nil
	}
}

func (r *Reader) readBlock() (*Packet, error) {
	peek, err := r.br.Peek(4)
	if err != nil {
		return nil, err
	}
	if isSHBHead(peek) {
		// 多段文件：追加写就是这么来的。新段的口序号重新从 0 数，所以映射要清掉。
		return nil, r.readSHB()
	}
	if r.le == nil {
		return nil, fmt.Errorf("capture: 还没读到段头就碰上了块 % x", peek)
	}
	var head [8]byte
	if _, err := io.ReadFull(r.br, head[:]); err != nil {
		return nil, err // 这里要让 io.EOF 原样透出去：读完就是正常结束
	}
	typ := r.le.Uint32(head[0:])
	total := r.le.Uint32(head[4:])
	if total < 20 {
		return nil, fmt.Errorf("capture: 块 %08x 自称 %d 字节，装不下头尾加正文（最少 20）", typ, total)
	}
	if total&3 != 0 {
		return nil, fmt.Errorf("capture: 块 %08x 的总长 %d 不是 4 的倍数，后面每一块都会跟着跳歪", typ, total)
	}
	body := make([]byte, total-12) // 正文 + 选项表结束那 4 字节
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, truncErr(err, "块正文")
	}
	var tail [4]byte
	if _, err := io.ReadFull(r.br, tail[:]); err != nil {
		return nil, truncErr(err, "块尾重复的那份总长")
	}
	if got := r.le.Uint32(tail[:]); got != total {
		return nil, fmt.Errorf("capture: 块 %08x 头上写总长 %d、尾巴写 %d，两处对不上 —— 这个文件在半路断过", typ, total, got)
	}
	switch typ {
	case blockIDB:
		inf, err := parseIDB(body, r.le)
		if err != nil {
			return nil, err
		}
		r.appendIface(inf)
		return nil, nil
	case blockEPB:
		return r.parseEPB(body)
	case blockPBB:
		return r.parsePBB(body)
	}
	return nil, nil // 认不出的块（名字解析、注入选项、将来加的那些）：跳过，不停在这
}

// readSHB 读一个段头：字节序要看魔数，所以前三格（类型/总长/魔数）先按原样拿进来。
func (r *Reader) readSHB() error {
	var raw [12]byte
	if _, err := io.ReadFull(r.br, raw[:]); err != nil {
		return err
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(raw[8:]) {
	case byteOrderMagic:
		order = binary.LittleEndian
	case swap32(byteOrderMagic):
		order = binary.BigEndian
	default:
		return fmt.Errorf("capture: 字节序魔数是 %#08x，规范只认 %#08x 和它的反序", binary.LittleEndian.Uint32(raw[8:]), byteOrderMagic)
	}
	total := order.Uint32(raw[4:])
	if total < 32 {
		return fmt.Errorf("capture: 段头自称 %d 字节，装不下定长那 24 格加头尾", total)
	}
	if total > 1<<20 {
		return fmt.Errorf("capture: 段头自称 %d 字节，不像真的（多半是字节序猜错了）", total)
	}
	rest := make([]byte, total-16) // 主/次版本 + 段长度 + 选项（含选项表结束那一格）
	if _, err := io.ReadFull(r.br, rest); err != nil {
		return truncErr(err, "段头")
	}
	var tail [4]byte
	if _, err := io.ReadFull(r.br, tail[:]); err != nil {
		return truncErr(err, "段头尾巴那份总长")
	}
	if got := order.Uint32(tail[:]); got != total {
		return fmt.Errorf("capture: 段头总长两处不一致（%d / %d）", total, got)
	}
	if major := order.Uint16(rest[0:]); major != 1 {
		return fmt.Errorf("capture: 这是 pcapng %d.x，本软件只解 1.x（这种文件请先用原工具另存一份）", major)
	}
	r.le = order
	r.secIfaces = nil // 新段：段内口序号从 0 重数
	return nil
}

// parseIDB 解一条接口描述。
func parseIDB(body []byte, order binary.ByteOrder) (Interface, error) {
	if len(body) < 8 {
		return Interface{}, fmt.Errorf("capture: 接口描述块正文只有 %d 字节，连链路类型和抓拍长度都读不出", len(body))
	}
	inf := Interface{
		LinkType: order.Uint16(body[0:]),
		SnapLen:  order.Uint32(body[4:]),
		tsUnit:   DefaultTSUnit,
	}
	err := eachOption(body[8:], order, func(code uint16, val []byte) error {
		switch code {
		case optIfaceName:
			inf.Name = trimNUL(val)
		case optIfaceDesc:
			inf.Description = trimNUL(val)
		case optIfaceTSResol:
			if len(val) < 1 {
				return fmt.Errorf("capture: if_tsresol 这一格是空的，时间戳就没法折算")
			}
			inf.tsUnit = tsUnitFromResol(val[0])
		}
		return nil // 没见过的选项（if_tsoffset、if_packets_passed…）忽略，不是错
	})
	if err != nil {
		return Interface{}, fmt.Errorf("capture: 接口描述块的选项读坏了：%w", err)
	}
	return inf, nil
}

func (r *Reader) parseEPB(body []byte) (*Packet, error) {
	if len(body) < 20 {
		return nil, fmt.Errorf("capture: 增强包块正文只有 %d 字节，定长那 20 格都装不下", len(body))
	}
	order := r.le
	gi, err := r.ifaceFor(int(order.Uint32(body[0:])))
	if err != nil {
		return nil, err
	}
	ticks := uint64(order.Uint32(body[4:]))<<32 | uint64(order.Uint32(body[8:]))
	caplen := int(order.Uint32(body[12:]))
	origlen := int(order.Uint32(body[16:]))
	rest := body[20:]
	if caplen > len(rest) || paddedLen(caplen) > len(rest) {
		return nil, fmt.Errorf("capture: 块里说这一包留了 %d 字节，实际只剩 %d —— 这一包没写完文件就断了", caplen, len(rest))
	}
	p := &Packet{
		InterfaceIndex: gi,
		Timestamp:      timeFromTicks(r.ifaces[gi].TSUnit(), ticks),
		Data:           append([]byte(nil), rest[:caplen]...),
		OrigLen:        origlen,
		HasTimestamp:   true,
	}
	if err := eachOption(rest[paddedLen(caplen):], order, func(code uint16, val []byte) error {
		if code == optComment {
			p.Comment = trimNUL(val)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("capture: 这一包的选项读坏了：%w", err)
	}
	return p, nil
}

// parsePBB 解简单包块：这一种块的正文只有「口号 + 包数据」。
func (r *Reader) parsePBB(body []byte) (*Packet, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("capture: 简单包块正文只有 %d 字节，连口号都读不出", len(body))
	}
	order := r.le
	gi, err := r.ifaceFor(int(order.Uint32(body[0:])))
	if err != nil {
		return nil, err
	}
	rest := body[4:]
	// 末尾那 4 个 0 是选项表结束；真写着选项的 PBB 极少见，那种宁可整段交给上层，
	// 也不按猜的长度切掉尾巴 —— 切错了表现是「包看着少了几十字节」，谁也想不到是读的时候丢的。
	if len(rest) >= 4 && isZero(rest[len(rest)-4:]) {
		rest = rest[:len(rest)-4]
	}
	data := append([]byte(nil), rest...)
	return &Packet{
		InterfaceIndex: gi,
		Data:           data,
		OrigLen:        len(data),
	}, nil
}

// ifaceFor 把段内口序号换成全局序号；没见过对应 IDB 就是硬错。
func (r *Reader) ifaceFor(secIdx int) (int, error) {
	if secIdx < 0 || secIdx >= len(r.secIfaces) {
		return 0, fmt.Errorf("capture: 包挂在段内第 %d 个口上，这个段只见过 %d 条接口描述 —— 文件缺 IDB，这一包挂不到任何口上",
			secIdx, len(r.secIfaces))
	}
	return r.secIfaces[secIdx], nil
}

// appendIface 登记一条 IDB：名字+链路类型+刻度都相同就当是同一个口（跨段合并）。
func (r *Reader) appendIface(inf Interface) {
	gi := len(r.ifaces)
	for i, have := range r.ifaces {
		if have.Name == inf.Name && have.LinkType == inf.LinkType && have.tsUnit == inf.tsUnit {
			gi = i
			break
		}
	}
	r.secIfaces = append(r.secIfaces, gi)
	if gi == len(r.ifaces) {
		r.ifaces = append(r.ifaces, inf)
	}
}

// openLegacy 解老 pcap 的文件头：这种文件没有口表，整份就一个链路类型。
func (r *Reader) openLegacy() (*Reader, error) {
	var head [24]byte
	if _, err := io.ReadFull(r.br, head[:]); err != nil {
		return nil, truncErr(err, "老 pcap 文件头")
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if m := binary.LittleEndian.Uint32(head[0:]); m == swap32(pcapMagicMicro) || m == swap32(pcapMagicNano) {
		order = binary.BigEndian
	}
	magic := order.Uint32(head[0:])
	nano := false
	switch magic {
	case pcapMagicMicro:
	case pcapMagicNano:
		nano = true
	default:
		return nil, fmt.Errorf("capture: 老 pcap 的魔数是 %#08x，这一版只认微秒 %08x 与纳秒 %08x 两种", magic, pcapMagicMicro, pcapMagicNano)
	}
	if major := order.Uint16(head[4:]); major != 2 {
		return nil, fmt.Errorf("capture: 老 pcap 文件主版本号是 %d，只解 2.x", major)
	}
	inf := Interface{
		Name:        "(老 pcap：文件头里没有口名)",
		Description: fmt.Sprintf("libpcap 文件头，主版本 %d", order.Uint16(head[4:])),
		LinkType:    uint16(order.Uint32(head[20:])),
		SnapLen:     order.Uint32(head[16:]),
		tsUnit:      time.Microsecond,
	}
	if nano {
		inf.tsUnit = time.Nanosecond
	}
	r.legacy = &pcapGlobal{le: order, nano: nano, linkType: inf.LinkType, snapLen: inf.SnapLen}
	r.appendIface(inf)
	return r, nil
}

func (r *Reader) readLegacy() (Packet, error) {
	var ph [16]byte
	if _, err := io.ReadFull(r.br, ph[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return Packet{}, io.EOF // 文件尾正好切掉半条包头条：当读完了
		}
		return Packet{}, err
	}
	order := r.legacy.le
	caplen := int(order.Uint32(ph[8:]))
	if caplen < 0 || caplen > 1<<26 {
		return Packet{}, fmt.Errorf("capture: 这一包自称留了 %d 字节，不像真的（多半是字节序猜错了）", caplen)
	}
	data := make([]byte, caplen)
	if _, err := io.ReadFull(r.br, data); err != nil {
		return Packet{}, truncErr(err, "包正文")
	}
	// ★ 老 pcap 的时间戳是「秒」+「那一秒内的小数位」两格分开，不是 pcapng 那种拼起来的 64 位整数：
	//   照 EPB 的拼法解，秒数会串进小数的格子里，读出来的时刻看着合法、全都落在同一秒。
	ts := time.Unix(int64(order.Uint32(ph[0:])), int64(order.Uint32(ph[4:]))*int64(r.ifaces[0].TSUnit()))
	r.pkts++
	return Packet{InterfaceIndex: 0, Timestamp: ts, Data: data, OrigLen: int(order.Uint32(ph[12:])), HasTimestamp: true}, nil
}

// eachOption 走一遍选项区：碰到「码 0、长 0」就收。
//
// ★ 不许按定长步长硬跳：选项是「码 2 + 长 2 + 值 + 补到 4 对齐」，值可长可短；
//
//	按 8 字节一步走会走进值里，读出来的口名就成了半截汉字加两个乱码。
func eachOption(b []byte, order binary.ByteOrder, fn func(code uint16, value []byte) error) error {
	for len(b) >= 4 {
		code := order.Uint16(b[0:])
		size := int(order.Uint16(b[2:]))
		b = b[4:]
		if code == 0 && size == 0 {
			return nil
		}
		padded := paddedLen(size)
		if padded > len(b) {
			return fmt.Errorf("选项 %d 自称 %d 字节（加对齐 %d），块里只剩 %d", code, size, padded, len(b))
		}
		if err := fn(code, b[:size]); err != nil {
			return err
		}
		b = b[padded:]
	}
	return nil
}

// tsUnitFromResol 把 if_tsresol 那一格换成刻度：高位是 1 按 2 的幂，否则按 10 的幂。
func tsUnitFromResol(b byte) time.Duration {
	if b&0x80 != 0 {
		n := int(b & 0x7F)
		if n > 63 {
			return DefaultTSUnit
		}
		return time.Duration(int64(time.Second) / (int64(1) << uint(n)))
	}
	if b <= 9 {
		return decimalUnit(int(b))
	}
	return DefaultTSUnit
}

func isSHBHead(b []byte) bool {
	// 段头那个类型号字节序来回读都是它（0A 0D 0D 0A 是回文的）—— 这是规范特意选的。
	return len(b) >= 4 && (b[0] == 0x0A && b[1] == 0x0D && b[2] == 0x0D && b[3] == 0x0A)
}

func isPcapHead(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(b) {
	case pcapMagicMicro, pcapMagicNano, swap32(pcapMagicMicro), swap32(pcapMagicNano):
		return true
	}
	return false
}

// trimNUL 剪掉尾巴上的 0：有的工具把字符串选项按 C 串写（带结尾 0），
// 不剪的话「lo 带结尾零」和「lo」会被当成两个口，同一个抓包口在表里多出第二条。
func trimNUL(b []byte) string { return strings.TrimRight(string(b), "\x00") }

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func swap32(v uint32) uint32 {
	return v>>24 | (v>>8)&0xFF00 | (v&0xFF00)<<8 | v<<24
}

func truncErr(err error, what string) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return fmt.Errorf("capture: 文件在「%s」中间断了：%w", what, io.ErrUnexpectedEOF)
	}
	return err
}
