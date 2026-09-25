package capture

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 写一遍、读回来一格不差。
// 覆盖最容易写歪的三处：奇数长度要补到 4 字节、注释选项、非缺省刻度。
func Test写出去再读回来一格不差(t *testing.T) {
	var buf bytes.Buffer
	ts0 := time.Date(2026, 3, 4, 5, 6, 7, 890123456, time.UTC)
	w, err := NewWriter(&buf, []Interface{
		{Name: "eth0", Description: "有线", LinkType: LinkTypeEN10MB, SnapLen: 262144},
		{Name: "any", LinkType: LinkTypeLinuxSLL, tsUnit: time.Nanosecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	pkts := []struct {
		ifIndex int
		at      time.Duration
		data    []byte // 长度故意含 1、2、3、4 各一种，把补零那一格逼出来
		comment string
	}{
		{0, 0, []byte{0xAA}, ""},
		{0, time.Millisecond, []byte{0xBB, 0xCC}, "这一包按默认口径脱过敏"},
		{1, 2 * time.Millisecond, []byte{1, 2, 3}, ""},
		{1, 3 * time.Millisecond, []byte{4, 5, 6, 7}, "四字节正好对齐"},
		{0, 4 * time.Millisecond, bytes.Repeat([]byte{0x45}, 1400), ""},
	}
	for i, p := range pkts {
		if err := w.WritePacketComment(p.ifIndex, ts0.Add(p.at), p.data, len(p.data)+i, p.comment); err != nil {
			t.Fatalf("写第 %d 包：%v", i, err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	r, err := Open(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	ifaces := r.Ifaces()
	if len(ifaces) != 2 {
		t.Fatalf("读回来 %d 个口，写的时候是 2 个", len(ifaces))
	}
	if ifaces[0].Name != "eth0" || ifaces[0].Description != "有线" || ifaces[0].SnapLen != 262144 {
		t.Errorf("第一个口的描述丢了：%+v", ifaces[0])
	}
	if ifaces[0].LinkType != LinkTypeEN10MB {
		t.Errorf("第一个口链路类型 %d", ifaces[0].LinkType)
	}
	if ifaces[1].TSUnit() != time.Nanosecond {
		t.Errorf("第二个口的刻度是 %v，写的是纳秒 —— 刻度丢了会把时间线压平一千倍", ifaces[1].TSUnit())
	}
	for i, p := range pkts {
		got, err := r.Read()
		if err != nil {
			t.Fatalf("读第 %d 包：%v", i, err)
		}
		if !bytes.Equal(got.Data, p.data) {
			t.Errorf("第 %d 包正文不对：写 %d 字节，读回 %d 字节", i, len(p.data), len(got.Data))
		}
		if got.InterfaceIndex != p.ifIndex {
			t.Errorf("第 %d 包挂在口 %d，写的是 %d", i, got.InterfaceIndex, p.ifIndex)
		}
		if got.OrigLen != len(p.data)+i {
			t.Errorf("第 %d 包线上长度 %d，写的是 %d —— 截短了多少就看丢了多少", i, got.OrigLen, len(p.data)+i)
		}
		if got.Comment != p.comment {
			t.Errorf("第 %d 包注释读回来是 %q，写的是 %q", i, got.Comment, p.comment)
		}
		// ★ 写进哪个口就按哪个口的刻度截一次再比：eth0 是微秒刻度，纳秒尾巴本就该落不进块里。
		//   拿纳秒原值去比，测出来的「时刻不对」是测试的错，不是折算的错。
		unit := ifaces[p.ifIndex].TSUnit()
		want := ts0.Add(p.at).Truncate(unit)
		if !got.Timestamp.Equal(want) {
			t.Errorf("第 %d 包时刻 %v，写的若是 %v（刻度 %v，差 %v）", i, got.Timestamp, want, unit, got.Timestamp.Sub(want))
		}
	}
	if _, err := r.Read(); err != io.EOF {
		t.Errorf("读完应该见尾，拿到的是 %v", err)
	}
	if r.Pkts() != len(pkts) {
		t.Errorf("计数 %d，实际 %d 包", r.Pkts(), len(pkts))
	}
}

// 块总长在头上与尾巴各写一遍，读侧靠头上那个数跳块。
// 这两格一旦来自两个表达式，写出来的文件自己读得开、Wireshark 报「块长度不一致」——
// 所以这里钉的是字节，不是「读回来对不对」。
func Test写出来的块长度与魔数按字节钉死(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewWriter(&buf, []Interface{{Name: "lo0", LinkType: LinkTypeNull}}); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes() // NewWriter 之后段头与接口描述已经落进缓冲
	if len(b) < 32 {
		t.Fatalf("连段头都没写出来：%d 字节", len(b))
	}
	if !bytes.Equal(b[0:4], []byte{0x0A, 0x0D, 0x0D, 0x0A}) {
		t.Fatalf("段头起始字节是 % x，规范是 0a 0d 0d 0a", b[:4])
	}
	shb := binary.LittleEndian.Uint32(b[4:])
	if got := binary.LittleEndian.Uint32(b[shb-4:]); got != shb {
		t.Errorf("段头总长头上 %d、尾巴 %d 不一致", shb, got)
	}
	if !bytes.Equal(b[8:12], []byte{0x4D, 0x3C, 0x2B, 0x1A}) {
		t.Errorf("字节序魔数写成 % x，小端应是 4d 3c 2b 1a", b[8:12])
	}
	if shb < 32 || shb%4 != 0 {
		t.Errorf("段头总长 %d（规范最小 32，且必须是 4 的倍数）", shb)
	}
	if got := binary.LittleEndian.Uint64(b[16:]); got != ^uint64(0) {
		t.Errorf("段长度写成 %d，边抓边写只能给 -1（不知道整份多大）", got)
	}
	idb := b[shb:]
	if got := binary.LittleEndian.Uint32(idb); got != blockIDB {
		t.Fatalf("段头之后第二块类型是 %#010x，应是接口描述 %#010x", got, blockIDB)
	}
	n := binary.LittleEndian.Uint32(idb[4:])
	if n < 20 || n%4 != 0 {
		t.Errorf("接口描述块总长 %d（应 ≥20 且为 4 的倍数）", n)
	}
	if got := binary.LittleEndian.Uint32(idb[n-4:]); got != n {
		t.Errorf("接口描述块总长头上 %d、尾巴 %d 不一致", n, got)
	}
	if got := binary.LittleEndian.Uint16(idb[8:]); got != LinkTypeNull {
		t.Errorf("链路类型写成 %d，应是 %d", got, LinkTypeNull)
	}
	if got := binary.LittleEndian.Uint16(idb[10:]); got != 0 {
		t.Errorf("接口描述块留 0 那格（Reserved）写成了 %d", got)
	}
	// 口名要按 if_name 选项落在块里：码 2、长 3，值后面补一个 0 抬到 4 字节边界。
	if !bytes.Contains(idb, []byte{0x02, 0x00, 0x03, 0x00, 'l', 'o', '0', 0x00}) {
		t.Errorf("口名没按 if_name 选项落进去：% x", idb)
	}
}

// 补零必须补在正文尾巴上、块总长要跟着算进去：少补一个字节，读侧下一块就从半个字开始。
func Test奇数长度包把块补到四字节边界(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{0, 1, 2, 3, 4, 5}
	for _, n := range sizes {
		if err := w.WritePacket(0, time.Unix(1700000000, 0), bytes.Repeat([]byte{0x11}, n), n); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	off := 0
	for i := 0; i < 2; i++ { // 段头 + 一条接口描述
		off += int(binary.LittleEndian.Uint32(b[off+4:]))
	}
	for i, n := range sizes {
		total := int(binary.LittleEndian.Uint32(b[off+4:]))
		if want := 12 + 20 + paddedLen(n) + 4; total != want { // 头 + 定长 + 补零后的正文 + 选项表结束
			t.Errorf("第 %d 包（%d 字节）块总长 %d，应是 %d", i, n, total, want)
		}
		if total%4 != 0 {
			t.Errorf("第 %d 包块总长 %d 没对齐", i, total)
		}
		if got := binary.LittleEndian.Uint32(b[off+total-4:]); got != uint32(total) {
			t.Errorf("第 %d 包尾巴上的总长是 %d，头上写的是 %d", i, got, total)
		}
		off += total
	}
}

// 大端段（老设备导出的、SPARC 上抓的）：读侧要靠字节序魔数自己翻过来。
func Test读大端的pcapng(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 6e8, time.UTC)
	file := beFile(t, beOptions{
		iface: Interface{Name: "gi0", LinkType: LinkTypeRaw, SnapLen: 9000, tsUnit: time.Nanosecond},
		ts:    ts,
		data:  []byte{0x45, 0x00, 0x00, 0x3c},
		orig:  60,
	})
	r, err := Open(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("大端文件读不开：%v", err)
	}
	got := r.Ifaces()
	if len(got) != 1 || got[0].Name != "gi0" || got[0].SnapLen != 9000 || got[0].TSUnit() != time.Nanosecond {
		t.Fatalf("大端文件的口读歪了：%+v", got)
	}
	p, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Timestamp.Equal(ts) {
		t.Errorf("大端时刻读成 %v，写的是 %v", p.Timestamp, ts)
	}
	if p.OrigLen != 60 || !bytes.Equal(p.Data, []byte{0x45, 0x00, 0x00, 0x3c}) {
		t.Errorf("大端这一包 cap=% x orig=%d", p.Data, p.OrigLen)
	}
}

// 整份翻过字节序的文件（拿小端那份硬翻出来的赝品）必须拒着读。
// ★ 钉的是读侧真按总长在跳块：翻完之后魔数看着还是合法的，但段头自称 2GB ——
//
//	不认这一格的话就会拿它当正常文件往下读，读出来全是乱码包。
func Test整份翻字节序的文件拒着读(t *testing.T) {
	var le bytes.Buffer
	w, _ := NewWriter(&le, []Interface{{Name: "eth0", LinkType: LinkTypeEN10MB, SnapLen: 9000}})
	_ = w.WritePacket(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4)
	_ = w.Flush()
	if _, err := Open(bytes.NewReader(swapBytes(le.Bytes()))); err == nil {
		t.Error("把小端文件每段 4 字节都翻了序，竟然还开得下来 —— 说明段头那个总长没被当回事")
	}
}

// 文件在半路断（采集机被拔电、scp 没传完）是现场最常见的坏法。
// ★ 必须报「断了」而不是假装读完了：装着读完的报表会少算一半的包，还看着像「就这么点流量」。
func Test断在半路的文件报断不报读完(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	for i := 0; i < 5; i++ {
		if err := w.WritePacket(0, time.Unix(1700000000, int64(i)*int64(time.Millisecond)), bytes.Repeat([]byte{byte(i)}, 40), 40); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Flush()
	full := buf.Bytes()
	for _, cut := range []int{1, 6, 20, 40, 80, 120, len(full) - 20, len(full) - 2} {
		r, err := Open(bytes.NewReader(full[:cut]))
		if err != nil {
			continue // 断在段头里：开就开不开，也算如实报了
		}
		var read int
		for {
			_, err := r.Read()
			if err == nil {
				read++
				if read > 5 {
					t.Fatalf("截到 %d 字节却读出了 %d 包", cut, read)
				}
				continue
			}
			if err == io.EOF {
				t.Errorf("截到 %d 字节却「正常读完」（%d 包）—— 断文件不能装成完整文件", cut, read)
			} else if !strings.Contains(err.Error(), "断") && !strings.Contains(err.Error(), "对不上") {
				t.Errorf("截到 %d 字节，报错不像在说断掉：%v", cut, err)
			}
			break
		}
	}
}

// 认不出的块要跳过而不是停下：Wireshark 会往里塞名字解析块、接口选项块。
func Test认不出的块跳过去接着读包(t *testing.T) {
	var a, b bytes.Buffer
	wa, _ := NewWriter(&a, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	_ = wa.WritePacket(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4)
	_ = wa.Flush()
	wb, _ := NewWriter(&b, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	_ = wb.WritePacket(0, time.Unix(1700000001, 0), []byte{9, 8, 7, 6}, 4)
	_ = wb.Flush()

	junk := buildUnknownBlock(0xDEADBEEF, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	// 把第二份的段头和接口描述剪掉，只留它那个包块，接在假块后面。
	merged := append([]byte(nil), a.Bytes()...)
	merged = append(merged, junk...)
	merged = append(merged, bodyAfterHeaders(t, b.Bytes())...)

	r, err := Open(bytes.NewReader(merged))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(); err != nil {
		t.Fatalf("第一包：%v", err)
	}
	p, err := r.Read()
	if err != nil {
		t.Fatalf("假块之后的第二包读不到：%v", err)
	}
	if !bytes.Equal(p.Data, []byte{9, 8, 7, 6}) {
		t.Errorf("跳过假块之后读到的是 % x", p.Data)
	}
}

// 刻度那一格：十进制档与二进制档都得能来回，写出去和读回来要用同一份折算。
func Test刻度来回对得上(t *testing.T) {
	cases := []struct {
		resol byte
		unit  time.Duration
	}{
		{0x00, time.Second},
		{0x03, time.Millisecond},
		{0x06, time.Microsecond},
		{0x07, 100 * time.Nanosecond},
		{0x09, time.Nanosecond},
		{0x86, time.Second / 64},
		{0x80 | 30, time.Second / (1 << 30)},
	}
	for _, c := range cases {
		if got := tsUnitFromResol(c.resol); got != c.unit {
			t.Errorf("if_tsresol %#02x 解成 %v，应是 %v", c.resol, got, c.unit)
		}
	}
	// ★ 规范只到 10^-9（纳秒）：越界的格要退回缺省，不能按猜的往下解。
	if got := tsUnitFromResol(0x0a); got != DefaultTSUnit {
		t.Errorf("if_tsresol 0x0a 越界，解成 %v，应退回缺省 %v", got, DefaultTSUnit)
	}
	for _, c := range cases {
		if c.resol&0x80 != 0 {
			continue
		}
		if got := tsResolByte(c.unit); got != c.resol {
			t.Errorf("刻度 %v 写成 %#02x，规范里是 %#02x", c.unit, got, c.resol)
		}
	}
	if got := tsResolByte(time.Second / 64); got != 0x86 {
		t.Errorf("2^-6 秒写成 %#02x —— 二进制档要走高位 1", got)
	}
	// 非缺省刻度必须真的落到选项里：不写就等于告诉读侧「按微秒来」。
	var buf bytes.Buffer
	if _, err := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB, tsUnit: time.Nanosecond}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte{optIfaceTSResol, 0x00, 0x01, 0x00, 0x09}) {
		t.Errorf("纳秒刻度没写进 if_tsresol：% x", buf.Bytes())
	}
}

// 简单包块里没有时刻：只能如实说「这一包没带时间」，不许拿前一包的凑。
func Test简单包块不带时刻就明说(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	_ = w.WritePacket(0, time.Unix(1700000000, 0), []byte{0xAA, 0xBB, 0xCC, 0xDD}, 4)
	_ = w.Flush()
	pbb := buildUnknownBlock(blockPBB, []byte{0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44})
	merged := append(buf.Bytes(), pbb...)
	r, err := Open(bytes.NewReader(merged))
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.Read()
	if err != nil || !first.HasTimestamp {
		t.Fatalf("第一包本该带时刻：%v", err)
	}
	second, err := r.Read()
	if err != nil {
		t.Fatalf("简单包块读不到：%v", err)
	}
	if second.HasTimestamp {
		t.Errorf("简单包块里没有时间戳，却报了「带时刻」：%v", second.Timestamp)
	}
	if !second.Timestamp.IsZero() {
		t.Errorf("没时刻却填了一个 %v —— 不许拿前一包的凑", second.Timestamp)
	}
	if !bytes.Equal(second.Data, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("简单包块正文读成 % x", second.Data)
	}
}

// 包挂在一个从没描述过的口序号上：这是文件缺 IDB，得说清「这一包挂不到任何口」。
func Test包挂在没见过的口上单独报错(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	_ = w.WritePacket(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4)
	_ = w.Flush()
	b := buf.Bytes()
	for off := 0; off+12 <= len(b); {
		total := int(binary.LittleEndian.Uint32(b[off+4:]))
		if binary.LittleEndian.Uint32(b[off:]) == blockEPB {
			binary.LittleEndian.PutUint32(b[off+8:], 7) // 改成从没描述过的第 7 个口
		}
		off += total
	}
	r, err := Open(bytes.NewReader(b))
	if err == nil {
		_, err = r.Read()
	}
	if err == nil || !strings.Contains(err.Error(), "IDB") {
		t.Errorf("缺 IDB 的文件没按「挂不到口」报，拿到的是：%v", err)
	}
}

// 块总长两处不一致（尾巴被改过）：这是文件断过的硬证据，不能当正常块跳过去。
func Test块总长两处不一致要报错(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	_ = w.WritePacket(0, time.Unix(1700000000, 0), bytes.Repeat([]byte{2}, 60), 60)
	_ = w.Flush()
	b := buf.Bytes()
	off := 0
	for i := 0; i < 2; i++ {
		off += int(binary.LittleEndian.Uint32(b[off+4:]))
	}
	total := int(binary.LittleEndian.Uint32(b[off+4:]))
	binary.LittleEndian.PutUint32(b[off+total-4:], uint32(total)+4) // 只改尾巴那一格
	err := func() error {
		r, err := Open(bytes.NewReader(b))
		if err != nil {
			return err // 开文件时要把口表读齐，结构错可能在这一步就报出来
		}
		_, err = r.Read()
		return err
	}()
	if err == nil || !strings.Contains(err.Error(), "对不上") {
		t.Errorf("两处总长不一致却没报错：%v", err)
	}
}

// 半路加口：新名字要当场补一条 IDB，读回来序号还得对上。
func Test半途补的口读回来序号不变(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "eth0", LinkType: LinkTypeEN10MB}})
	_ = w.WritePacket(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4)
	second := w.InterfaceIndex("wlan0", LinkTypeIEEE80211)
	if second != 1 {
		t.Fatalf("新口序号 %d，应是 1", second)
	}
	if again := w.InterfaceIndex("wlan0", LinkTypeIEEE80211); again != second {
		t.Errorf("同一个名字两次拿到 %d 和 %d —— 换号就等于把一条流算成两条", again, second)
	}
	if err := w.WritePacket(second, time.Unix(1700000001, 0), []byte{0x88, 0x02, 0x00, 0x00}, 1200); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()
	r, err := Open(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(); err != nil {
		t.Fatal(err)
	}
	p, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	// 第二条 IDB 是排在第一个包之后的（半途才知道口名），所以要读到那一带才见得到。
	if got := r.Ifaces(); len(got) != 2 || got[1].Name != "wlan0" || got[1].LinkType != LinkTypeIEEE80211 {
		t.Fatalf("第二个口没读回来：%+v", got)
	}
	if p.InterfaceIndex != 1 || p.OrigLen != 1200 {
		t.Errorf("后一包挂在口 %d、线上长度 %d", p.InterfaceIndex, p.OrigLen)
	}
}

// 一个口都没有：写侧直接拒绝，不许产出一个谁都读不开的文件。
func Test一个口都没有就拒着写(t *testing.T) {
	if _, err := NewWriter(io.Discard, nil); err == nil {
		t.Error("零个口居然写出了文件")
	}
	if _, err := NewWriter(io.Discard, []Interface{{Name: "e"}}); err != nil {
		t.Errorf("一个口是合法的：%v", err)
	}
}

// 注释选项长过 65535（块里那一格只记到 16 位）：要报错，不能悄悄截掉。
func Test选项正文超长要报错不截断(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	long := strings.Repeat("一", 40000) // UTF-8 三字节一个，正好超 65535
	if err := w.WritePacketComment(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4, long); err == nil {
		t.Fatal("超长注释居然写成功了 —— 读回来的会是被截过的半截话")
	}
	if err := w.WritePacket(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4); err == nil {
		t.Error("上一次写失败之后，这个写手还该一直报同一个错")
	}
}

// ==================== 与真产物的字节级对照 ====================
//
// testdata 里那三份都是从一次性容器（--rm，没碰本机那几台在跑的）里现抓的：
// dumpcap / editcap / tcpdump 各一份，内容全是回环上的 ICMP —— 没有内网地址、没有口令。
// ★ 这三份是「别人写的文件我们读得开」的凭据，不是自己跟自己对表：
//   自己写自己读，块总长算错两位也能对上。
//
// 三份各逼一处不一样的写法（真工具之间本来就不一致，规范只说「可以这样」）：
//   dumpcap-lo.pcapng —— 刻度是纳秒，IDB 带 if_name，EPB 里没有选项表结束那一格；
//   editcap-lo.pcapng —— 刻度退回微秒，IDB 连 if_name 都没有（从老 pcap 转出来的就是这样）；
//   tcpdump-lo.pcap   —— 不是 pcapng，是 24 字节全局头的老格式，时刻拆成「秒 + 微秒」两格。

func Test读真产物的pcapng(t *testing.T) {
	cases := []struct {
		file     string
		pkts     int
		linkType uint16
		name     string
		snap     uint32
		unit     time.Duration
		firstTS  string // 与 capinfos / tcpdump -tt 报的那个时刻对着钉
	}{
		{"dumpcap-lo.pcapng", 30, LinkTypeEN10MB, "lo", 262144, time.Nanosecond, "2026-09-26 02:25:08.612264594 CST"},
		{"editcap-lo.pcapng", 40, LinkTypeEN10MB, "", 262144, time.Microsecond, "2026-09-26 02:25:02.605346 CST"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", c.file))
			if err != nil {
				t.Skipf("没有参照件（%v）—— 只影响这条对照测试", err)
			}
			defer f.Close()
			r, err := Open(f)
			if err != nil {
				t.Fatal(err)
			}
			inf := r.Ifaces()
			if len(inf) != 1 {
				t.Fatalf("这份文件里有 %d 个口", len(inf))
			}
			if inf[0].LinkType != c.linkType {
				t.Errorf("链路类型 %d，应是 %d（以太网）", inf[0].LinkType, c.linkType)
			}
			if inf[0].Name != c.name {
				t.Errorf("口名读成 %q，真产物写的是 %q", inf[0].Name, c.name)
			}
			if inf[0].SnapLen != c.snap {
				t.Errorf("抓拍长度 %d，capinfos 报的是 %d", inf[0].SnapLen, c.snap)
			}
			if inf[0].TSUnit() != c.unit {
				t.Errorf("刻度 %v，capinfos 报的是 %v", inf[0].TSUnit(), c.unit)
			}
			var n, totalBytes int
			var first Packet
			for {
				p, err := r.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("第 %d 包读不下去：%v", n, err)
				}
				if n == 0 {
					first = p
				}
				totalBytes += len(p.Data)
				n++
			}
			if n != c.pkts {
				t.Errorf("读出 %d 包，capinfos 报 %d 包", n, c.pkts)
			}
			if totalBytes != c.pkts*98 {
				t.Errorf("正文合计 %d 字节，每包都该是 98（回环上的 ICMP，含链路头）", totalBytes)
			}
			got := first.Timestamp.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05.999999999 MST")
			if got != c.firstTS {
				t.Errorf("第一包时刻 %v，capinfos 报的是 %v", got, c.firstTS)
			}
			// 以太网头 + IPv4：这一格真读出来了，才叫「链路类型没解错」。
			if len(first.Data) < 14 || first.Data[12] != 0x08 || first.Data[13] != 0x00 {
				t.Errorf("第一包的以太类型不是 IPv4：% x", first.Data)
			}
			if first.OrigLen != 98 {
				t.Errorf("线上长度 %d，真产物写的是 98", first.OrigLen)
			}
		})
	}
}

// 多段文件（追加写出来的）：新段的段头要重认字节序，口序号不能串到上一段去。
func Test多段串在一起也能读(t *testing.T) {
	var one bytes.Buffer
	w, _ := NewWriter(&one, []Interface{{Name: "eth0", LinkType: LinkTypeEN10MB}})
	_ = w.WritePacket(0, time.Unix(1700000000, 0), []byte{1, 2, 3, 4}, 4)
	_ = w.Flush()
	var two bytes.Buffer
	w2, _ := NewWriter(&two, []Interface{{Name: "wlan0", LinkType: LinkTypeIEEE80211}})
	_ = w2.WritePacket(0, time.Unix(1700000001, 0), []byte{5, 6, 7, 8}, 8)
	_ = w2.Flush()
	merged := append(append([]byte(nil), one.Bytes()...), two.Bytes()...)

	r, err := Open(bytes.NewReader(merged))
	if err != nil {
		t.Fatal(err)
	}
	p1, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := r.Read()
	if err != nil {
		t.Fatalf("第二段那个包读不到：%v", err)
	}
	if got := r.Ifaces(); len(got) != 2 {
		t.Fatalf("两段一共 %d 个口：%+v", len(got), got)
	}
	if p1.InterfaceIndex == p2.InterfaceIndex {
		t.Errorf("两段的包都挂在口 %d —— 段内序号 0 串到一起了，两个不同的口会被并成一条流", p1.InterfaceIndex)
	}
	if got := r.Ifaces()[p2.InterfaceIndex].Name; got != "wlan0" {
		t.Errorf("第二段的包挂在 %q", got)
	}
	if !p2.Timestamp.After(p1.Timestamp) {
		t.Errorf("跨段时刻倒流：%v 早于 %v", p2.Timestamp, p1.Timestamp)
	}
}

// 老 pcap（libpcap 原生格式）：没有口表，链路类型与快照长度都在文件头那 24 字节里。
func Test读真产物的老pcap(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "tcpdump-lo.pcap"))
	if err != nil {
		t.Skipf("没有参照件（%v）", err)
	}
	defer f.Close()
	r, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	inf := r.Ifaces()
	if len(inf) != 1 || inf[0].LinkType != LinkTypeEN10MB {
		t.Fatalf("文件头里的链路类型读歪了：%+v", inf)
	}
	if inf[0].SnapLen != 262144 {
		t.Errorf("快照长度 %d，文件头写的是 262144", inf[0].SnapLen)
	}
	var n int
	var prev time.Time
	var first Packet
	for {
		p, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("第 %d 包：%v", n, err)
		}
		if n == 0 {
			first = p
			if p.Timestamp.Year() < 2026 {
				t.Errorf("第一包时刻 %v，年份读歪了", p.Timestamp)
			}
			if !bytes.Contains(p.Data, []byte{0x7f, 0x00, 0x00, 0x01}) {
				t.Errorf("正文里找不到 127.0.0.1：% x", p.Data)
			}
		}
		if p.Timestamp.Before(prev) {
			t.Errorf("第 %d 包时刻倒流：%v 早于 %v", n, p.Timestamp, prev)
		}
		prev = p.Timestamp
		n++
	}
	if n == 0 {
		t.Error("一包都没读到")
	}
	if !first.HasTimestamp {
		t.Error("老 pcap 每一包都带时刻")
	}
}

// 同一批包，pcapng 与老 pcap 两份参照件（editcap 互转得来）要读出同样的正文。
func Test两种格式读出来的包正文一致(t *testing.T) {
	a := readAllForTest(t, filepath.Join("testdata", "editcap-lo.pcapng"))
	b := readAllForTest(t, filepath.Join("testdata", "tcpdump-lo.pcap"))
	if len(a) == 0 || len(b) == 0 {
		t.Skip("缺参照件")
	}
	if len(a) != len(b) {
		t.Fatalf("两份读出 %d 与 %d 包 —— editcap 是同一批包互转的", len(a), len(b))
	}
	for i := range a {
		if !bytes.Equal(a[i].Data, b[i].Data) {
			t.Errorf("第 %d 包两份正文不一致", i)
		}
		if !a[i].Timestamp.Equal(b[i].Timestamp) {
			t.Errorf("第 %d 包两份时刻不一致：%v / %v", i, a[i].Timestamp, b[i].Timestamp)
		}
	}
}

func readAllForTest(t *testing.T, path string) []Packet {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("缺参照件：%v", err)
	}
	defer f.Close()
	r, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []Packet
	for {
		p, err := r.Read()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
}

// 不是抓包文件的字节流：要一句话说明白，别当空文件糊过去。
func Test不像抓包文件的就直说(t *testing.T) {
	for _, b := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\n\r\n"),
		{0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01},
	} {
		_, err := Open(bytes.NewReader(b))
		if err == nil {
			t.Errorf("%q 竟然被当成抓包文件开了", b)
			continue
		}
		if !strings.Contains(err.Error(), "不像") {
			t.Errorf("报错不像在说「这不是抓包文件」：%v", err)
		}
	}
	// 空文件不是「有零个包」：现场「文件在、0 字节」是采集器没落盘，得说清。
	if _, err := Open(bytes.NewReader(nil)); err == nil {
		t.Error("空文件居然开成功了")
	} else if !strings.Contains(err.Error(), "EOF") {
		t.Errorf("空文件的报错不像「啥都没有」：%v", err)
	}
}

// 写手的错误是「一旦坏了就一直坏」：不能第一包失败、第二包假装成功。
func Test写失败之后不会假装后面都成功(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, []Interface{{Name: "e", LinkType: LinkTypeEN10MB}})
	if err := w.WritePacket(9, time.Unix(1700000000, 0), []byte{1}, 1); err == nil {
		t.Fatal("挂在没登记过的口序号上却写成功了")
	} else if !strings.Contains(err.Error(), "只登记了 1 条") {
		t.Errorf("报错没说清登记了几条：%v", err)
	}
	if err := w.WritePacket(0, time.Unix(1700000000, 0), []byte{1}, 1); err == nil {
		t.Error("已经坏了的写手第二次写竟然成功了 —— 文件里会多出一包没人认领的字节")
	}
}

// ==================== 测试脚手架 ====================

func buildUnknownBlock(typ uint32, body []byte) []byte {
	total := uint32(12 + len(body) + 4)
	var b bytes.Buffer
	var u [4]byte
	binary.LittleEndian.PutUint32(u[:], typ)
	b.Write(u[:])
	binary.LittleEndian.PutUint32(u[:], total)
	b.Write(u[:])
	b.Write(body)
	b.Write([]byte{0, 0, 0, 0})
	b.Write(u[:])
	return b.Bytes()
}

func bodyAfterHeaders(t *testing.T, b []byte) []byte {
	t.Helper()
	off := 0
	for i := 0; i < 2; i++ {
		if off+8 > len(b) {
			t.Fatal("文件连段头和一条接口描述都没有")
		}
		off += int(binary.LittleEndian.Uint32(b[off+4:]))
	}
	return b[off:]
}

// swapBytes 把每一段 4 字节整体翻序：只为造一份赝品文件（真大端件由 beFile 按规范逐字段写）。
func swapBytes(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := 0; i+4 <= len(out); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = out[i+3], out[i+2], out[i+1], out[i]
	}
	return out
}

func Test读大端时选项里的两个16位也要跟着翻(t *testing.T) {
	// 这里的参照件由 beFile 现场生成：口名走 if_name 选项，
	// 翻错了读回来的就是半截名加两个乱码字节。
	file := beFile(t, beOptions{
		iface: Interface{Name: "ge0", LinkType: LinkTypeEN10MB, SnapLen: 1500},
		ts:    time.Unix(1700000000, 0),
		data:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		orig:  4,
	})
	r, err := Open(newBytesReader(file))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Ifaces()[0].Name; got != "ge0" {
		t.Errorf("大端口名读成 %q（% x）", got, []byte(got))
	}
}

func newBytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// 反方向的对照：真工具（tshark、capinfos）读不读得开我们写手产出的那份。
//
// ★ 只测「我们自己的 reader 读得开」是循环论证 —— 两边同一套误解照样全绿。
//
//	所以这台机器上有 Wireshark 那套命令时，就把写出去的文件原样递过去验：
//	包数、每一包的截取长度、时刻、挂在哪个口、注释，一项项对。
//	没有这套命令的机器（CI、纯 Linux 服务器）跳过并说清跳过了哪半边，不装成通过。
func Test真工具读我们写手产出的文件(t *testing.T) {
	tshark := findTool(t, "tshark")
	if tshark == "" {
		t.Skip("这台机器上没有 tshark：反方向对照没做，只做了「我们读真产物」那半边")
	}
	file, want := writeWithOurWriter(t)

	// 3.6 的 tshark 没有「这一包挂在哪个口」这一格可读字段，口名与注释只能由 capinfos 报。
	// 两长都要对上：cap_len 是落进文件的正文长，len 是线上那份的原长 ——
	// 后一格才是「这包被截过」的凭据，只能写对一次才算数。
	out, err := exec.Command(tshark, "-r", file, "-T", "fields",
		"-E", "separator=|", "-e", "frame.number", "-e", "frame.cap_len",
		"-e", "frame.len", "-e", "frame.time_epoch").Output()
	if err != nil {
		t.Fatalf("%s 读不开我们写出去的文件：%v\n%s", tshark, err, stderrOf(err))
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("tshark 报 %d 包，我们写的是 %d 包", len(lines), len(want))
	}
	for i, line := range lines {
		f := strings.Split(line, "|")
		w := want[i]
		if got := f[1]; got != strconv.Itoa(w.caplen) {
			t.Errorf("第 %d 包 tshark 报截取长 %s，我们写的正文长是 %d", i+1, got, w.caplen)
		}
		if got := f[2]; got != strconv.Itoa(w.orig) {
			t.Errorf("第 %d 包 tshark 报线上长 %s，我们写的 origLen 是 %d（这一格错了就是「截过」没标出来）", i+1, got, w.orig)
		}
		if got := epochSeconds(t, f[3]); got != w.ts.Unix() {
			t.Errorf("第 %d 包时刻 tshark 报 %s，我们写的是 %v", i+1, f[3], w.ts)
		}
	}

	capinfos := findTool(t, "capinfos")
	if capinfos == "" {
		return // 口名与注释这两格只有 capinfos 报，缺了就说清少验了一格。
	}
	info, err := exec.Command(capinfos, file).Output()
	if err != nil {
		t.Fatalf("%s 读不开：%v\n%s", capinfos, err, stderrOf(err))
	}
	notes := string(info)
	for _, s := range []string{
		"Name = eth0", "Name = lo0", "Name = wlan0",
		"Number of packets = 25", // 半途补的那条 IDB 上只有 1 包，eth0 是 25
		"Packet 1 Comment:",
	} {
		if !strings.Contains(notes, s) {
			t.Errorf("capinfos 的报告里没有 %q：\n%s", s, notes)
		}
	}
}

type ourFrame struct {
	caplen int
	orig   int
	ts     time.Time
}

// writeWithOurWriter 用自家写手往临时目录落一份：两条 IDB 打底、半途再补一条，
// 每包带注释，origLen 一律比正文长 —— 那是「被截过」那一格，真工具要能照出来。
func writeWithOurWriter(t *testing.T) (string, []ourFrame) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "ours.pcapng")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	w, err := NewWriter(f, []Interface{
		{Name: "eth0", Description: "对照用", LinkType: LinkTypeEN10MB, SnapLen: 262144},
		{Name: "lo0", Description: "Loopback", LinkType: LinkTypeNull, SnapLen: 262144},
	})
	if err != nil {
		t.Fatal(err)
	}
	var want []ourFrame
	base := time.Unix(1770000000, 0).UTC()
	frame := ethTestFrame()
	for i := 0; i < 25; i++ {
		ts := base.Add(time.Duration(i) * 17 * time.Millisecond)
		if err := w.WritePacketComment(0, ts, frame, 1500, "由 netkit 写手产出"); err != nil {
			t.Fatal(err)
		}
		want = append(want, ourFrame{caplen: len(frame), orig: 1500, ts: ts})
	}
	// 半途补的那条 IDB：真工具得认，包也要跟着挂过去。
	idx := w.InterfaceIndex("wlan0", LinkTypeRadioTap)
	ts := base.Add(time.Second)
	if err := w.WritePacket(idx, ts, frame[:20], 1500); err != nil {
		t.Fatal(err)
	}
	want = append(want, ourFrame{caplen: 20, orig: 1500, ts: ts})
	// lo0 上一包都不放：capinfos 要能报出「这个口登记了、一个包没落到」，
	// 这正是现场「起口就被杀」那份文件该有的样子。
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return name, want
}

func ethTestFrame() []byte {
	b := make([]byte, 54)
	copy(b, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00})
	b[14] = 0x45
	b[16], b[17] = 0x00, 0x28
	b[22], b[23] = 0x40, 0x06
	copy(b[26:], []byte{127, 0, 0, 1, 127, 0, 0, 1})
	return b
}

// findTool 先按 PATH 找，再翻 macOS 上「装了图形版但命令没挂 PATH」那几个落点。
func findTool(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{
		"/Applications/Wireshark.app/Contents/MacOS/",
		"/usr/local/bin/",
		"/opt/homebrew/bin/",
	} {
		p := dir + name
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func stderrOf(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return string(ee.Stderr)
	}
	return ""
}

func epochSeconds(t *testing.T, s string) int64 {
	t.Helper()
	sec, _, found := strings.Cut(s, ".")
	if !found {
		t.Fatalf("时刻字段没有小数秒那一段：%q", s)
	}
	n, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		t.Fatalf("时刻字段读不成秒：%q", s)
	}
	return n
}
