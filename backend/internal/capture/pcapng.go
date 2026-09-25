// Package capture 抓这一层的底座：pcapng/pcap 的读写、按流聚合、各平台的取包口。
//
// 老板定的口径（docs/设计.md「抓包引擎自研方案」）：**不依赖 Npcap、不依赖 libpcap**，
// 所以格式这一层也得自己写 —— pcapng 只是字节布局，没有许可与分发问题。
// 这一份纯标准库：读侧要能吃别人（tcpdump、Wireshark、dumpcap）写的文件，
// 因为现场拿到的往往是同事已经抓好的那一个。
package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"
)

// 链路类型（libpcap 那份 LINKTYPE_* 表里的号，IDB 直接用）。
// 只列这台软件会碰到的：写错的号不会报错，只会让上层把裸 IP 当以太网解，
// 解出来的「源地址」是 MAC 的前四字节 —— 所以这里宁缺勿滥。
const (
	LinkTypeNull      uint16 = 0   // BSD loopback（macOS 的 lo0）
	LinkTypeEN10MB    uint16 = 1   // 以太网（不带 FCS）
	LinkTypeIEEE80211 uint16 = 23  // 802.11 帧，没有 RadioTap 前缀
	LinkTypeRaw       uint16 = 101 // 裸 IP，没有链路口
	LinkTypeLinuxSLL  uint16 = 113 // Linux cooked v1（-i any 抓出来的就是它）
	LinkTypePFSync    uint16 = 117 // pflog
	// Linux cooked v2 的头比 v1 长：混了等于没解，所以两个号都得单独认。
	LinkTypeLinuxSLL2 uint16 = 276
	LinkTypeRadioTap  uint16 = 127 // 802.11 + RadioTap
	LinkTypeIPv4      uint16 = 228
	LinkTypeIPv6      uint16 = 229
)

// pcapng 的块类型。
const (
	blockIDB = 0x00000001
	blockPBB = 0x00000003 // 简单包块：块里没有这一包的时间戳
	blockSHB = 0x0A0D0D0A
	blockEPB = 0x00000006
)

// 块里用到的选项号。
const (
	optComment      = 1
	optIfaceName    = 2
	optIfaceDesc    = 3
	optIfaceTSResol = 9
)

// byteOrderMagic 是段头里的字节序记号：按本机序写出去就是这四个字节，
// 读侧看到反过来的 4D 3C 2B 1A 就知道整段要按大端解。
const byteOrderMagic uint32 = 0x1A2B3C4D

// DefaultTSUnit 是规范写的缺省刻度：微秒。
// ★ 缺省不等于安全：有的工具（部分抓过口的 tcpdump、有些设备的导出件）压根不写 if_tsresol，
//
//	有的却按纳秒填数 —— 读侧照微秒解，时间线会被整条压平一千倍。
const DefaultTSUnit = time.Microsecond

// Interface 是一个抓包口的描述：写进一条 IDB，读回来也带这一份。
type Interface struct {
	Name        string
	Description string
	LinkType    uint16
	SnapLen     uint32
	// tsUnit 是把块里那个整数时间戳换成 time.Time 用的刻度。
	tsUnit time.Duration
}

// TSUnit 回这个口的时间戳刻度；没填过就是规范缺省（微秒）。
func (inf Interface) TSUnit() time.Duration {
	if inf.tsUnit == 0 {
		return DefaultTSUnit
	}
	return inf.tsUnit
}

// option 是块里的一条选项：码 2 字节 + 长 2 字节 + 值 + 补到 4 字节对齐。
type option struct {
	code  uint16
	value []byte
}

// paddedLen 把一个长度抬到 4 的倍数（pcapng 里所有变长段都按 4 对齐）。
func paddedLen(n int) int { return (n + 3) & ^3 }

// buildBlock 在内存里把一个块拼好，返回可以整块写出去的那段字节。
//
// ★ 不许「先写个占位总长、写完正文再回头补」：bufio.Writer 里排在缓冲区前面的字节
//
//	可能已经落到下游（文件、甚至对端）了，回头补就是补不回来 —— 现场的表现是
//	文件能开、包数对，但 Wireshark 报「块长度不一致」然后丢掉后半段。
//	拼一次算一次，头上与尾上那个总长就只可能来自同一个表达式。
func buildBlock(typ uint32, body []byte, opts []option) ([]byte, error) {
	// 12 = 类型 + 头上总长 + 尾巴总长；再加 4 = 选项表结束那一格（码 0、长 0）。
	total := 16 + len(body)
	for _, o := range opts {
		if len(o.value) > math.MaxUint16 {
			return nil, fmt.Errorf("capture: 选项 %d 的正文有 %d 字节，块里那一格只记到 65535", o.code, len(o.value))
		}
		total += 4 + paddedLen(len(o.value))
	}
	if uint64(total) > math.MaxUint32 {
		return nil, fmt.Errorf("capture: 这一块要 %d 字节，超出了一个块能记下的长度", total)
	}
	buf := make([]byte, 0, total)
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], typ)
	buf = append(buf, u[:]...)
	binary.LittleEndian.PutUint32(u[:], uint32(total))
	buf = append(buf, u[:]...)
	buf = append(buf, body...)
	for _, o := range opts {
		buf = append(buf, byte(o.code), byte(o.code>>8), byte(len(o.value)), byte(len(o.value)>>8))
		buf = append(buf, o.value...)
		if pad := paddedLen(len(o.value)) - len(o.value); pad > 0 {
			buf = append(buf, make([]byte, pad)...)
		}
	}
	buf = append(buf, 0, 0, 0, 0) // 选项表结束：码 0、长 0
	// ★ 尾巴上再写一遍总长（规范要求的自检格）：u 这时还装着 total，正是该重复的那个数。
	buf = append(buf, u[:]...)
	return buf, nil
}

// Writer 往一个可写的地方写 pcapng。
//
// 一次 NewWriter 是一个段（section）。规范允许段串起来（工具追加写就是这么来的），
// 所以这里不写「文件结束」那类标记，也不需要 Close 收尾。
type Writer struct {
	w       *bufio.Writer
	ifaces  []Interface
	ifindex map[string]int
	err     error
}

// NewWriter 建一个写手：先落一条 SHB，再把每个口各落一条 IDB。
// ★ IDB 的先后就是这个文件里的 interface id，读侧靠序号对应回来，所以不许重排。
func NewWriter(w io.Writer, ifaces []Interface) (*Writer, error) {
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("capture: 至少得有一个口（哪怕是个虚拟的）")
	}
	bw := bufio.NewWriter(w)
	ww := &Writer{w: bw, ifindex: map[string]int{}}
	hdr, err := shbBlock()
	if err != nil {
		return nil, err
	}
	if _, err := bw.Write(hdr); err != nil {
		return nil, err
	}
	for i, inf := range ifaces {
		if inf.tsUnit == 0 {
			inf.tsUnit = DefaultTSUnit
		}
		blk, err := idbBlock(inf)
		if err != nil {
			return nil, err
		}
		if _, err := bw.Write(blk); err != nil {
			return nil, err
		}
		ww.ifaces = append(ww.ifaces, inf)
		if inf.Name != "" {
			ww.ifindex[inf.Name] = i
		}
	}
	// ★ 段头与接口描述要立刻落下去，不能攒在缓冲里：现场「采集进程被杀了、文件只剩头」
	//   是常事，那份文件得能开、能看出「一个包都没落到」，而不是成一个谁都读不开的字节流。
	return ww, bw.Flush()
}

// InterfaceIndex 按名字找那条 IDB 的序号；没见过就当场补一条 IDB 再返回新序号。
// 给「先起采集、后才知道口叫什么」那一路用；已知序号的调用方直接用 WritePacket。
// ★ 出错时序号照旧返回、错误记在写手上（下一次 Write 才吐出来）：
//
//	采集那一路不该为了「写不下」丢掉刚抓到的包，但绝不该假装写成了。
func (w *Writer) InterfaceIndex(name string, linkType uint16) int {
	if i, ok := w.ifindex[name]; ok {
		return i
	}
	inf := Interface{Name: name, LinkType: linkType, tsUnit: DefaultTSUnit}
	blk, err := idbBlock(inf)
	if err == nil {
		_, err = w.w.Write(blk)
	}
	if err != nil && w.err == nil {
		w.err = err
	}
	// ★ 半途加 IDB 规范允许，但读侧必须先见过它才认得这个序号，所以立刻落盘、不攒着。
	w.ifaces = append(w.ifaces, inf)
	w.ifindex[name] = len(w.ifaces) - 1
	return len(w.ifaces) - 1
}

// Interfaces 回这个写手已经登记过的口。
func (w *Writer) Interfaces() []Interface { return append([]Interface(nil), w.ifaces...) }

// WritePacket 写一个包。origLen 是线上那份的长度（截短过才知道丢了多少）。
func (w *Writer) WritePacket(ifIndex int, ts time.Time, data []byte, origLen int) error {
	return w.writePacket(ifIndex, ts, data, origLen, "")
}

// WritePacketComment 多带一条选项里的注释：这一格是给人（也给界面）看的落点，
// 比如「这一包按默认口径脱过敏」。
func (w *Writer) WritePacketComment(ifIndex int, ts time.Time, data []byte, origLen int, comment string) error {
	return w.writePacket(ifIndex, ts, data, origLen, comment)
}

func (w *Writer) writePacket(ifIndex int, ts time.Time, data []byte, origLen int, comment string) error {
	if w.err != nil {
		return w.err
	}
	if ifIndex < 0 || ifIndex >= len(w.ifaces) {
		w.err = fmt.Errorf("capture: 包挂在不存在的口序号 %d（这个文件只登记了 %d 条 IDB）", ifIndex, len(w.ifaces))
		return w.err
	}
	inf := w.ifaces[ifIndex]
	if uint64(len(data)) > math.MaxUint32 {
		w.err = fmt.Errorf("capture: 这一包 %d 字节，超出了一个块能记下的长度", len(data))
		return w.err
	}
	if origLen < len(data) {
		origLen = len(data) // 线上长度不可能比留下那份还短
	}
	body := make([]byte, 20+paddedLen(len(data)))
	binary.LittleEndian.PutUint32(body[0:], uint32(ifIndex))
	ticks := ticksFor(inf.TSUnit(), ts)
	binary.LittleEndian.PutUint32(body[4:], uint32(ticks>>32))
	binary.LittleEndian.PutUint32(body[8:], uint32(ticks))
	binary.LittleEndian.PutUint32(body[12:], uint32(len(data)))
	binary.LittleEndian.PutUint32(body[16:], uint32(origLen))
	copy(body[20:], data)

	var opts []option
	if comment != "" {
		opts = append(opts, option{code: optComment, value: []byte(comment)})
	}
	blk, err := buildBlock(blockEPB, body, opts)
	if err != nil {
		w.err = err
		return err
	}
	if _, err := w.w.Write(blk); err != nil {
		w.err = err
		return err
	}
	return nil
}

// Flush 把攒着的块推下去。采集那一路要按秒催一次，不然界面看到的是「文件在长、包没到」。
func (w *Writer) Flush() error {
	if w.err != nil {
		return w.err
	}
	return w.w.Flush()
}

// shbBlock 拼一条段头：字节序魔数 + 1.0 + 段长度 -1（未知）。
func shbBlock() ([]byte, error) {
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[0:], byteOrderMagic)
	binary.LittleEndian.PutUint16(body[4:], 1) // 主版本
	binary.LittleEndian.PutUint16(body[6:], 0) // 次版本
	// ★ 段长度写 -1 而不是猜一个：这个数按规范是「本段总字节数」，
	//   边抓边写的文件根本不知道会有多大；填了个猜的数，读侧拿它跳段就会跳到半路。
	binary.LittleEndian.PutUint64(body[8:], ^uint64(0))
	return buildBlock(blockSHB, body, nil)
}

// idbBlock 拼一条接口描述。
func idbBlock(inf Interface) ([]byte, error) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:], inf.LinkType)
	// body[2:4] 按规范留 0（Reserved）：这里是靠切片的零值填的，别当漏写。
	binary.LittleEndian.PutUint32(body[4:], inf.SnapLen) // 0 按规范就是「不限长」，不是「一个字节都不写」
	var opts []option
	if inf.Name != "" {
		opts = append(opts, option{code: optIfaceName, value: []byte(inf.Name)})
	}
	if inf.Description != "" {
		opts = append(opts, option{code: optIfaceDesc, value: []byte(inf.Description)})
	}
	if unit := inf.tsUnit; unit != 0 && unit != DefaultTSUnit {
		opts = append(opts, option{code: optIfaceTSResol, value: []byte{tsResolByte(unit)}})
	}
	return buildBlock(blockIDB, body, opts)
}

// ticksFor 按这个口声明的刻度折算时间戳。
//
// ★ 不按「传进来的就是微秒」直接切：写成纳秒的 IDB 配微秒的数，读回来所有包挤在同一毫秒里，
//
//	而报表上看着仍然是一条顺畅的时间线。
func ticksFor(unit time.Duration, ts time.Time) uint64 {
	if ts.IsZero() {
		return 0
	}
	perSec, ok := ticksPerSecond(unit)
	if !ok {
		// 刻度除不尽一秒：这不是合法的 if_tsresol。宁可按缺省写下去，
		// 也不要造出一个「读回来乘不回去」的数 —— 读侧同一份折算函数会同样退回缺省。
		unit, perSec = DefaultTSUnit, 1e6
	}
	return uint64(ts.Unix())*perSec + uint64(ts.Nanosecond())/uint64(unit)
}

// timeFromTicks 是 ticksFor 的反向：读别人的块时把整数还原成时刻。
func timeFromTicks(unit time.Duration, ticks uint64) time.Time {
	perSec, ok := ticksPerSecond(unit)
	if !ok {
		unit, perSec = DefaultTSUnit, 1e6
	}
	return time.Unix(int64(ticks/perSec), int64(ticks%perSec)*int64(unit))
}

// tsResolByte 把刻度换成 IDB 那一格的写法：高位是 1 按 2 的幂，否则按 10 的幂。
func tsResolByte(unit time.Duration) byte {
	for n := 0; n <= 9; n++ {
		if d := decimalUnit(n); d == unit {
			return byte(n)
		}
	}
	// ★ 落不到十进制那一档（纳秒能，15.625 毫秒也能）就按 2 的幂：0x80|n 表示 2^-n 秒。
	if n, ok := powerOfTwoExponent(unit); ok {
		return byte(0x80 | n)
	}
	return byte(6) // 认不出来就退回规范缺省，读侧至少不会把数放大一千倍
}

// decimalUnit 是 10^-n 秒（n=0..9）：0 秒、0.1、0.01 …… 1 微秒（n=6）、100 纳秒、10 纳秒、1 纳秒。
func decimalUnit(n int) time.Duration {
	d := time.Second
	for i := 0; i < n; i++ {
		d /= 10
	}
	return d
}

func powerOfTwoExponent(unit time.Duration) (int, bool) {
	perSec, ok := ticksPerSecond(unit)
	if !ok || perSec == 0 || perSec&(perSec-1) != 0 {
		return 0, false // 一秒里的格数不是 2 的幂，这一档就没法按 0x80|n 写
	}
	return bits.TrailingZeros64(perSec), true
}

// ticksPerSecond 回「这个刻度一秒有多少格」；除不尽的一律不算（规范里不存在这种写法）。
func ticksPerSecond(unit time.Duration) (uint64, bool) {
	if unit <= 0 || uint64(time.Second)%uint64(unit) != 0 {
		return 0, false
	}
	return uint64(time.Second) / uint64(unit), true
}
