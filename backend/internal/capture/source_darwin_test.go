//go:build darwin

package capture

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// 这份文件里的测试分两档：
//   - 不要权限的那一堆：记录头怎么走、步长怎么算、号码表跟量出来的结构体长度对不对得上、
//     布局对不上时停不停得下来。这些拿「按 cc 实测偏移手搭出来的缓冲」跑，
//     因为那本来就是最容易错的地方。
//   - 要 root 的那一条：真开一台 /dev/bpfn、真绑一个口。这一档在这台机器上**跑不了**
//     （设备表是 crw------- root wheel，而 sudo 要密码），所以只验「非特权用户拿到的是
//     哪一句」——见最后那一条。真机上抓到的包与 tcpdump 逐包对账，留到装 ChmodBPF 之后补。

var native = binary.NativeEndian

// ==================== 手搭记录的桩 ====================

// bpfRec 按实测那张表（bh_tstamp 在 0、caplen 在 8、datalen 在 12、hdrlen 在 16，
// 整个头 20 字节）搭一条记录。hdrlen 由调用方给：内核就是拿它带补齐的。
func bpfRec(hdrlen int, ts time.Time, caplen, datalen int, data []byte) []byte {
	rec := make([]byte, bpfWordAlign(hdrlen+caplen))
	native.PutUint32(rec[bpfSecOff:], uint32(int32(ts.Unix())))
	native.PutUint32(rec[bpfUsecOff:], uint32(ts.Nanosecond()/int(time.Microsecond)))
	native.PutUint32(rec[bpfCaplenOff:], uint32(caplen))
	native.PutUint32(rec[bpfDatalenOn:], uint32(datalen))
	native.PutUint16(rec[bpfHdrLenOff:], uint16(hdrlen))
	copy(rec[hdrlen:], data)
	return rec
}

// ==================== 那张表的出处 ====================

// ioctl 号码本身就编着「内核那一格要几个字节」（xnu 的 _IOR/_IOW/_IOWR 把 sizeof 写进了
// 号码的 16..28 位）。所以这张表能自己检查自己：号码里那个长度和 cc 量出来的
// sizeof 对不上，就是我们递进去的结构体长短不对 —— 那种错内核不报错，
// 它只会读到半句然后拿剩下的字节当参数用。
func Test那一族ioctl号码编着的长度等于量出来的结构体长度(t *testing.T) {
	// xnu sys/ioccom.h：IOCPARM_SHIFT=16、IOCPARM_MASK=0x1fff、group 在 8..15。
	lenOf := func(n int) int { return (n >> 16) & 0x1fff }
	groupOf := func(n int) byte { return byte((n >> 8) & 0xff) }
	dirOf := func(n int) uint32 { return uint32(n) & 0xe0000000 }

	// 每一格长度都拿 /tmp/bpfprobe 里那份 cc 程序对着这台机器的 SDK 头量过。
	cases := []struct {
		name string
		ioc  int
		want int // 期望编着的长度：0 = 不带参数
	}{
		{"BIOCSBLEN", iocSetBlen, 4},
		{"BIOCGBLEN", iocGetBlen, 4},
		{"BIOCSETIF", iocSetIf, ifreqSize},
		{"BIOCGETIF", iocGetIf, ifreqSize},
		{"BIOCGDLT", iocGetDlt, 4},
		{"BIOCFLUSH", iocFlush, 0},
		{"BIOCPROMISC", iocPromisc, 0},
		{"BIOCSRTIMEOUT", iocSetRTO, int(unsafe.Sizeof(syscall.Timeval{}))},
		{"BIOCGSTATS", iocStats, bpfStatSize},
		{"BIOCIMMEDIATE", iocImmed, 4},
		{"BIOCVERSION", iocVersion, 4},
	}
	for _, c := range cases {
		if got := lenOf(c.ioc); got != c.want {
			t.Errorf("%s = %#x 编着长度 %d，量出来是 %d —— 递进去的结构体长短不对", c.name, c.ioc, got, c.want)
		}
		if g := groupOf(c.ioc); g != 'B' {
			t.Errorf("%s = %#x 的组号是 %q，不是 'B' —— 号码抄错行或抄错表了", c.name, c.ioc, g)
		}
		switch dirOf(c.ioc) {
		case iocDirVoid, iocDirOut, iocDirIn, iocDirInOut:
		default:
			t.Errorf("%s = %#x 的方向位是 %#x，四个取值里没有这一档", c.name, c.ioc, dirOf(c.ioc))
		}
	}
}

// xnu ioccom.h 那四个方向位（旧 BSD 那一套，不是 4.4 的 0/1/2/3 左移版）。
const (
	iocDirVoid  = 0x20000000 // IOC_VOID：_IO，不带参数
	iocDirOut   = 0x40000000 // IOC_OUT：_IOR，内核写回给用户
	iocDirIn    = 0x80000000 // IOC_IN：_IOW，用户递进内核
	iocDirInOut = 0xc0000000 // IOC_IN|IOC_OUT：_IOWR，同一格先读后写
)

// 同一个子系统里并存着两种 timeval，这一条把它钉死：
// BIOCSRTIMEOUT 那一格是 native timeval（16 字节，号码里就写着 0x10），
// 而记录头里的 bh_tstamp 是 timeval32（秒占 4 字节）。
// 按 native 那一份读记录头，包头就成了 30 字节 —— 「caplen」读到的是微秒那一格，
// 时刻飞到几十年后，而包数、长度全对得上，这种账最难查。
func Test记录头里的时刻是timeval32不是本机timeval(t *testing.T) {
	if secField := bpfCaplenOff - bpfSecOff; secField != 8 {
		t.Errorf("记录头里时刻那一格是 %d 字节（秒@%d、微秒@%d），不是 timeval32 的 8", secField, bpfSecOff, bpfUsecOff)
	}
	if tv := unsafe.Sizeof(syscall.Timeval{}); tv != 16 {
		t.Errorf("本机 timeval 是 %d 字节 —— 这一档按 64 位那一份算，摆法要重核", tv)
	}
	if unsafe.Sizeof(syscall.Timeval{}) == uintptr(bpfCaplenOff-bpfSecOff) {
		t.Fatal("两种 timeval 变成同一种了：这条测试的出处（macOS 15.x SDK 的 #if defined(__LP64__)）不再成立")
	}

	ts := time.Unix(1790000000, 123456000)
	buf := bpfRec(20, ts, 4, 4, []byte{0xde, 0xad, 0xbe, 0xef})
	rec, err := nextBpfRecord(buf)
	if err != nil {
		t.Fatalf("读一条正常记录：%v", err)
	}
	if !rec.ts.Equal(ts) {
		t.Errorf("时刻读成 %v，要的是 %v", rec.ts, ts)
	}
	// 同一份字节按 native timeval 读会读成什么：算出来给大家看，别只说「会错」。
	asNativeSec := int64(native.Uint64(buf[0:]))
	if asNativeSec == ts.Unix() {
		t.Fatal("这份样本换不出差别 —— 按错的方式读也算不出秒，断言等于没断")
	}
	if wrong := time.Unix(asNativeSec, 0).UTC().Year(); wrong < 2100 {
		t.Errorf("按 native timeval 读，2026 年的戳会变成哪一年？样本给的是 %d，没跳出一个世纪", wrong)
	}
}

// 时刻那一格只占 8 字节（秒 4 + 微秒 4）：这一条钉的是「只读这么宽」。
// 判别用的不是年份 —— 2038 年之前有符号与无符号读出来完全一样，拿它当凭据等于没断；
// 用的是一格微秒：秒那一格要是读宽了一格，微秒那个 1 就成了秒的高位，
// 时刻当场多出 2^32 秒。
func Test秒那一格只占四字节(t *testing.T) {
	oneUsec := time.Unix(1790000000, 1000)
	buf := bpfRec(20, oneUsec, 4, 4, []byte("ABCD"))
	rec, err := nextBpfRecord(buf)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !rec.ts.Equal(oneUsec) {
		t.Errorf("一格微秒读成了 %v，要 %v —— 秒那一格被读宽了", rec.ts, oneUsec)
	}
	if off := rec.ts.Sub(oneUsec); off > time.Second || off < -time.Second {
		t.Errorf("偏了 %v：读宽一格就是偏 2^32 秒这个量级", off)
	}

	// 32 位秒数绕回去那一格，按声明的 int32 解释（与 libpcap 同一读法：它也是直接从
	// struct timeval32 取的）。这一段是这个格式自己带不动的年份，不是我们读错。
	wrapped := time.Unix(-1<<31, 0)
	native.PutUint32(buf[bpfSecOff:], 0x80000000)
	native.PutUint32(buf[bpfUsecOff:], 0)
	rec2, err := nextBpfRecord(buf)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !rec2.ts.Equal(wrapped) {
		t.Errorf("秒位 0x80000000 读成 %v，按 int32 该是 %v", rec2.ts, wrapped)
	}
}

// ==================== 缓冲里怎么走 ====================

// 记录之间是按 BPF_WORDALIGN(hdrlen+caplen) 跳的，不是按头大小一格一格跳：
// hdrlen 本身就带补齐，而 caplen 后面还要再补到整格。
// 数错了不报错，只会把上一包的尾巴当成下一包的开头（Linux 那一档同一个脾性）。
func Test缓冲里按补齐后的步长走(t *testing.T) {
	first := bpfRec(24, time.Unix(1790000000, 0), 5, 5, []byte("一二三")) // 24+5=29 → 补到 32
	// bpf 那一格时刻只到微秒：这一格就按微秒写，别用「500000」这种看着像微秒其实是纳秒的数
	// （第一版就在这儿把自己绕了一次）。
	secTS := time.Unix(1790000001, 500*int64(time.Microsecond))
	second := bpfRec(20, secTS, 3, 9, []byte("ABC"))
	buf := append(append([]byte(nil), first...), second...)
	if got := bpfWordAlign(24 + 5); got != 32 {
		t.Fatalf("桩搭错了：第一条记录的步长应是 %d", got)
	}

	a, err := nextBpfRecord(buf)
	if err != nil {
		t.Fatalf("第一条：%v", err)
	}
	if a.stride != 32 {
		t.Errorf("第一条步长 %d，要 32", a.stride)
	}
	if string(a.data) != "一二三\x00\x00"[:5] {
		t.Errorf("第一条数据 %q", a.data)
	}
	b, err := nextBpfRecord(buf[a.stride:])
	if err != nil {
		t.Fatalf("第二条：%v", err)
	}
	if string(b.data) != "ABC" {
		t.Errorf("第二条数据 %q —— 按固定头长走就会读到上一包补齐那三字节", b.data)
	}
	if b.datalen != 9 {
		t.Errorf("第二条线上长度 %d，要 9（留了 3，线上 9：这是一条被截过的包）", b.datalen)
	}
	if !b.ts.Equal(secTS) {
		t.Errorf("第二条时刻 %v，要 %v（这一档只到微秒）", b.ts, secTS)
	}
}

// 布局对不上的那几种样子，每一种都得停下来，不许按猜的往下读。
func Test记录对不上这张表就停下来(t *testing.T) {
	good := bpfRec(20, time.Unix(1790000000, 0), 4, 4, []byte("ABCD"))
	cases := []struct {
		名 string
		搭 func() []byte
		要 string
	}{
		{"缓冲不足一头", func() []byte { return good[:bpfHdrSize-1] }, "连一条记录头"},
		{"包头短于表", func() []byte {
			b := append([]byte(nil), good...)
			native.PutUint16(b[bpfHdrLenOff:], 12) // 比 sizeof(bpf_hdr) 还短
			return b
		}, "比这张表理解的记录头"},
		{"留的比线上长", func() []byte {
			b := append([]byte(nil), good...)
			native.PutUint32(b[bpfCaplenOff:], 5)
			return b
		}, "留长不可能比原文还长"},
		{"数据越过缓冲尾", func() []byte {
			b := append([]byte(nil), good...)
			native.PutUint32(b[bpfDatalenOn:], 100)
			return b[:22] // 头里说留 4，实际只剩 2 字节
		}, "这一半是断的"},
		// 长度那两格从头到尾按 u32 读、按 int64 比，中途不落进 int：
		// macOS 这一档只有 64 位（Go 早就不出 darwin/386），落进 int 眼下不会绕，
		// 但那一挡就变成只有部分平台生效的判定 —— 而且这一格真到 4GB 时，
		// 「线上一包 4GB」会被原样写进报表，看着像个天文数字的大包而不是「读的不是记录头」。
		{"线上长度超出能记的那一格", func() []byte {
			b := append([]byte(nil), good...)
			native.PutUint32(b[bpfDatalenOn:], 0xffffffff)
			return b
		}, "超出这一档能记账"},
		{"留长那一格大到绕回负数", func() []byte {
			b := append([]byte(nil), good...)
			native.PutUint32(b[bpfCaplenOff:], 0x80000000)
			native.PutUint32(b[bpfDatalenOn:], 0xffffffff)
			return b
		}, "超出这一档能记账"}, // 先被线上长度那一挡接住（顺序就是判定的先后）
		{"微秒那一格不像是时刻", func() []byte {
			b := append([]byte(nil), good...)
			native.PutUint32(b[bpfUsecOff:], 1000000) // 内核写的微秒永远 < 1e6
			return b
		}, "时刻的形状"},
	}
	for _, c := range cases {
		_, err := nextBpfRecord(c.搭())
		if err == nil {
			t.Errorf("%s：居然读成功了", c.名)
			continue
		}
		if want := c.要; !strings.Contains(err.Error(), want) {
			t.Errorf("%s：报的是 %q，里头找不到 %q", c.名, err, want)
		}
	}
}

// 坏掉的那一路只报同一个错：不许第一遍报错、后面几遍装成「这一轮没包」继续跑。
// 后者在界面上就是「抓包停了但没说要停」。
func Test坏掉的那一路每次回同一个错(t *testing.T) {
	bad := bpfRec(20, time.Unix(1790000000, 0), 4, 4, []byte("ABCD"))
	native.PutUint16(bad[bpfHdrLenOff:], 8)
	d := &bpfDev{name: "en0", fd: -1, snap: 1600, blen: len(bad), buf: bad, n: len(bad)}
	first, _, err := d.takeBuffered()
	if err == nil {
		t.Fatalf("第一遍就放过去了：%+v", first)
	}
	for i := 0; i < 3; i++ {
		if _, ok, err2 := d.takeBuffered(); err2 != err {
			t.Errorf("第 %d 遍回的是 %v，要的第一遍那句 %v", i+2, err2, err)
		} else if ok {
			t.Errorf("第 %d 遍还交出了包", i+2)
		}
	}
	// 游标不许在报错那一步往前挪：挪了就等于把断掉的那一半跳过去当成没发生。
	if d.pos != 0 {
		t.Errorf("出错后游标挪到了 %d，要留在 0", d.pos)
	}
}

// 留长这一档是本地截的（内核那一头要 cBPF 过滤器，这一档不下），
// 所以「线上多长」必须照原样报 —— 截了却不吭声，界面上就成了「这个包就这么大」。
func Test留长在本地截而线上长度照实报(t *testing.T) {
	frame := []byte("0123456789abcdefghij")
	rec := bpfRec(20, time.Unix(1790000000, 0), len(frame), 1500, frame)
	d := &bpfDev{name: "en0", fd: -1, snap: 8, blen: len(rec), buf: rec, n: len(rec), ifIdx: 2}
	p, ok, err := d.takeBuffered()
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(p.Data) != 8 {
		t.Errorf("留下 %d 字节，要按留长截到 8", len(p.Data))
	}
	if p.OrigLen != 1500 {
		t.Errorf("线上长度报 %d，要 1500 —— 这一格是用来算「截掉的那一份丢了几字节」的", p.OrigLen)
	}
	if p.InterfaceIndex != 2 {
		t.Errorf("口序号 %d，要 2", p.InterfaceIndex)
	}
	if !p.HasTimestamp {
		t.Error("HasTimestamp 没置上")
	}
	// 截到刚好一整包时不许多截一刀。
	d2 := &bpfDev{name: "en0", fd: -1, snap: len(frame), blen: len(rec), buf: rec, n: len(rec)}
	if p2, _, err := d2.takeBuffered(); err != nil || len(p2.Data) != len(frame) {
		t.Errorf("留长给够时截短了：%d 字节 err=%v", len(p2.Data), err)
	}
	// 交完一条就该说「这一轮没了」，而不是把补齐那几字节当第二包。
	if _, ok, err := d2.takeBuffered(); ok || err != nil {
		t.Errorf("缓冲见底还交出东西：ok=%v err=%v", ok, err)
	}
}

// 关掉的那一路再读：ErrClosed，不 panic，也不去碰一个已经填 -1 的 fd。
func Test关掉之后refill回ErrClosed(t *testing.T) {
	d := &bpfDev{name: "lo0", fd: -1, buf: make([]byte, 4096), blen: 4096}
	if err := d.refill(); !errors.Is(err, ErrClosed) {
		t.Errorf("refill 回的是 %v，要 ErrClosed", err)
	}
	s := &darwinSource{}
	if _, err := s.Next(); !errors.Is(err, ErrClosed) {
		t.Errorf("关了还在 Next，回的是 %v，要 ErrClosed", err)
	}
}

// ==================== 那张表的另一头 ====================

// DLT_* 与 LINKTYPE_* 不是同一套号：DLT_RAW 是 12 而 LINKTYPE_RAW 是 101，
// DLT_PPP 是 9 而 LINKTYPE_PPP 是 15。认不出的如实说认不下 ——
// 写错号不会报错，只会让上层把裸 IP 当以太网解，解出来的「源地址」是链路头的前四字节。
func TestDLT表按量出来的号翻(t *testing.T) {
	// cc 在这台机器上量出来的那几个号（见 /tmp/bpfprobe）。
	if dltNull != 0 || dltEN10MB != 1 || dltRaw != 12 || dltIEEE802 != 105 || dltRadioTap != 127 {
		t.Fatalf("DLT 常量与实测不符：%d %d %d %d %d", dltNull, dltEN10MB, dltRaw, dltIEEE802, dltRadioTap)
	}
	// ★ 这两个是「按名字以为一样」最容易栽的地方，各钉一条。
	if got, ok := linkTypeOfDLT(12); !ok || got != LinkTypeRaw {
		t.Errorf("DLT_RAW 12 翻成 %d/%v，要 %d", got, ok, LinkTypeRaw)
	}
	if got, ok := linkTypeOfDLT(0); !ok || got != LinkTypeNull {
		t.Errorf("DLT_NULL 0 翻成 %d/%v，要 %d（macOS 的 lo0 与 utun 全是它）", got, ok, LinkTypeNull)
	}
	// 认不下的：DLT_PPP=9（号与 LINKTYPE_PPP=15 不同，直接照抄就是个假账）、
	// DLT_LOOP=108（FreeBSD 的回环，macOS 用不上）、DLT_LINUX_SLL=113。
	for _, dlt := range []uint16{9, 108, 113, 8, 107, 9999} {
		if got, ok := linkTypeOfDLT(dlt); ok {
			t.Errorf("DLT %d 居然认成了 %d —— 这一档没验过那种链路头，宁可不抓", dlt, got)
		}
	}
}

// 读缓冲那一格不许自己挑：内核会改成它允许的那一档（所以最终按 BIOCGBLEN 读回来的数分配），
// 而我们要的那一格至少得装得下「一条记录头 + 用户要留的那一份」——
// 不然用户要 1600、内核给到 1500，那是替用户改了他下的口径。
func Test读缓冲至少装得下一条完整记录(t *testing.T) {
	// 默认档：留长 1600 → 一条记录 20+1600=1620 → 补到 1620（4 的整倍数）。
	want, err := planBpfBuf(0, 0)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if need := bpfWordAlign(bpfHdrSize + DefaultSnapLen); want < need {
		t.Errorf("默认要 %d 字节，装不下一条留长 %d 的记录（要 %d）", want, DefaultSnapLen, need)
	}
	// 小留长顶到下限：一条记录装得下，但缓冲再小就成了「一次 read 只够半包」。
	if got, err := planBpfBuf(0, 64); err != nil || got < bpfBufFloor {
		t.Errorf("留长 64 要 %d 字节 err=%v，不低于下限 %d", got, err, bpfBufFloor)
	}
	// 缓冲比一条记录还小不是用户的真意（那是明确要「截一半照样报」），按最小可用顶上。
	// 顶上的是「一条记录那么大」与下限里更大的那一格 —— 留长 4000 时要 4020，而下限是 4096。
	if got, err := planBpfBuf(1024, 4000); err != nil {
		t.Fatalf("%v", err)
	} else {
		if need := bpfWordAlign(bpfHdrSize + 4000); got < need {
			t.Errorf("缓冲 1024 而留长 4000：顶上来是 %d，比一条记录（%d）还小", got, need)
		}
		if got != bpfBufFloor {
			t.Errorf("留长 4000 时顶到 %d，要下限 %d（一条记录 %d 字节，比下限还小）", got, bpfBufFloor, bpfWordAlign(bpfHdrSize+4000))
		}
	}
	// 留长大到一条记录就顶穿上限：当场拒，不许绕成负数后顶到下限、再让内核悄悄截。
	if _, err := planBpfBuf(0, bpfBufCeil); err == nil {
		t.Errorf("留长 %d 字节（一条记录就超出上限 %d）居然放过去了", bpfBufCeil, bpfBufCeil)
	}
	// 大数挡住，别去试那一下（内核只回一句 EINVAL，看不出是哪一格挤的）。
	if _, err := planBpfBuf(bpfBufCeil+1, 1600); err == nil {
		t.Error("要 32MB 以上的读缓冲居然放过去了")
	}
	// 负数是明确要一个不可能的值，当场拒。
	if _, err := planBpfBuf(-1, 1600); err == nil {
		t.Error("负缓冲放过去了")
	}
	if _, err := planBpfBuf(4096, -1); err == nil {
		t.Error("负留长放过去了")
	}
	if bpfWordAlign(24+5) != 32 || bpfWordAlign(20) != 20 || bpfWordAlign(21) != 24 {
		t.Errorf("补齐算错了：align(29)=%d align(20)=%d align(21)=%d", bpfWordAlign(29), bpfWordAlign(20), bpfWordAlign(21))
	}
}

// 内核把读缓冲改小是合法行为（手册页：closest allowable size will be set and returned），
// 不是失败。这一条钉的就是「改小要改到什么程度才算错」——
// 早期版本拿「比我们要的少」当错，那就等于把一件内核明说允许的事报成「这个口起不来」。
// 这台机器上内核自己那几格是 debug.bpf_bufsize=4096、debug.bpf_maxbufsize=524288、
// debug.bpf_bufsize_cap=33554432（哪一格管用户请求这一头 bpf(4) 没写，而 BIOCSBLEN 要 root
// 才实测得了）—— 所以「拿回来的比要的小」是随时可能发生的事，不许当失败。
func Test内核改小读缓冲要分两种(t *testing.T) {
	// 要 4MB、内核给 512KB：留长 1600 的一条记录才 1620 字节，装得下，照着走。
	if got, err := settleBpfBuf(4<<20, 524288, DefaultSnapLen, "en0"); err != nil || got != 524288 {
		t.Errorf("内核给 512KB 而我们要 4MB：%d/%v —— 改小是合法的，该照内核那一份分配", got, err)
	}
	// 小到装不下一条记录：这才是错，且要说清「装不下的是留长那一格」。
	if _, err := settleBpfBuf(4<<20, 1024, DefaultSnapLen, "en0"); err == nil {
		t.Error("内核只给 1024 字节（一条留长 1600 的记录要 1620）居然放过去了")
	} else if !strings.Contains(err.Error(), "装不下一条留长") {
		t.Errorf("报的是 %v，要说清是装不下记录", err)
	}
	// 小留长时下限顶的是那 4096（内核默认那一份），不是「一条记录那么大」。
	if got, err := settleBpfBuf(4<<20, 4096, 64, "en0"); err != nil || got != 4096 {
		t.Errorf("留长 64、内核给 4096：%d/%v，要按下限放行", got, err)
	}
	if _, err := settleBpfBuf(4<<20, 4095, 64, "en0"); err == nil {
		t.Error("比下限还小的一格放过去了 —— read 会 EINVAL，界面上就是「这个口一个包都没有」")
	}
	// 内核一个数都没写回来（0 / 负）：不许拿它去 make 缓冲。
	// 这一档单独报一句「内核把读缓冲报成 0 字节」而不是并入「装不下」：
	// 前一句说的是我们这一头的调用方式不对（那一格长短摆错了），后一句说的是这台机器给不起
	// —— 两句话的下一步不在同一个地方，所以断言断的是这句话，不是「有没有错」。
	for _, got := range []int{0, -1} {
		_, err := settleBpfBuf(4<<20, got, DefaultSnapLen, "en0")
		if err == nil {
			t.Errorf("内核报 %d 字节还放过去了", got)
			continue
		}
		if !strings.Contains(err.Error(), "内核把读缓冲报成") {
			t.Errorf("内核报 %d 字节，回的是 %v —— 这一句该点名「没写回来」，不是「给小了」", got, err)
		}
	}
	// 给得比我们要的还多：照内核那一份走，不许裁回我们要的数（裁了就又是一次大小不符的 read）。
	if got, err := settleBpfBuf(4096, 8192, DefaultSnapLen, "en0"); err != nil || got != 8192 {
		t.Errorf("内核给多了：%d/%v，要 8192", got, err)
	}
}

// 硬件时刻这一档当场拒，不等开了设备再说：bpf 那一格时刻是包过过滤器时内核打的，
// 压根没有网卡打戳这条路。也不许悄悄退成软件时刻 —— 拿它算出来的延迟会差一截，
// 而报表上完全看不出来。
func Test要硬件时刻当场拒(t *testing.T) {
	for _, name := range []string{"lo0", "en0", ""} {
		_, err := OpenSource(Options{Interface: name, Timestamp: TSHardware})
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("口 %q 要硬件时刻：回的是 %v，要 ErrUnsupported", name, err)
		}
		// 这句必须落在「认不下这一档」上，不许被后面的权限那一档盖过去 ——
		// 提了权之后同一句话会变，那种会变的判定没法写进界面。
		if errors.Is(err, ErrNeedPrivilege) {
			t.Errorf("口 %q：硬件时刻那句被「要 root」盖住了", name)
		}
	}
	// 负数同样在开设备之前就挡住。
	if _, err := OpenSource(Options{SnapLen: -1}); err == nil {
		t.Error("负留长放过去了")
	}
	if _, err := OpenSource(Options{BufferSize: -1}); err == nil {
		t.Error("负缓冲放过去了")
	}
}

// 点名的口不存在时直接报，不许退化成「那就全抓」：现场最常见的误判就是
// 「抓了半天没有对方的包」，因为抓的是另一块网卡。这一条不要权限。
func Test点名的口不存在就直说(t *testing.T) {
	_, err := OpenSource(Options{Interface: "netkit-does-not-exist"})
	if !errors.Is(err, ErrNoSuchInterface) {
		t.Fatalf("回的是 %v，要 ErrNoSuchInterface", err)
	}
}

// ==================== 要 root 的那一条 ====================

// 非特权用户在这台机器上起采集，拿到的必须是一句「要 root」—— 这是这一档唯一
// 不需要权限就能验的现场事实：/dev/bpfn 是 crw------- root wheel，
// 连 Wireshark 自带的 dumpcap 不提权也是一句 Permission denied。
//
// ★ 反过来（真开一台设备、真抓自己的包、与 tcpdump 逐包对账）在这台机器上跑不了：
//
//	sudo 要密码。那一条等装了 ChmodBPF 再补，这里不许拿「编译过了」冒充「抓过了」。
func Test非特权用户起采集只要一句要root(t *testing.T) {
	if os.Geteuid() == 0 {
		// 真在有权限的人手上跑：起一路、验那张脸、收干净。
		s, err := OpenSource(Options{Interface: "lo0"})
		if err != nil {
			t.Fatalf("root 还起不来：看这一句是不是真因（不是「要 root」那句）：%v", err)
		}
		defer s.Close()
		if got := s.Interfaces(); len(got) != 1 || got[0].Name != "lo0" || got[0].tsUnit != time.Microsecond {
			t.Errorf("Interfaces() = %+v，要一条 lo0、戳单位微秒", got)
		}
		t.Skip("这一条断言的是「非特权」那一句：现在是 root，跳过去，别把两种现场混成一条绿")
	}
	for _, name := range []string{"lo0", "en0"} {
		_, err := OpenSource(Options{Interface: name})
		if err == nil {
			t.Fatalf("非特权用户真把 %s 抓起来了 —— 这台机器的设备表不是 0600 root，那条权限话得改", name)
		}
		if !errors.Is(err, ErrNeedPrivilege) {
			t.Errorf("口 %s 起不来回的是 %v，要一句包着 ErrNeedPrivilege 的话", name, err)
		}
		// 「一台被别人占着」与「压根没这台」是两句话，都不该在第一个口上出现；
		// 出现了就是找空闲设备的循环走错了分支，那种错会把「去提权」报成「换块网卡」。
		if errors.Is(err, ErrNoSuchInterface) {
			t.Errorf("口 %s：权限那一档被「这个口不存在」顶掉了：%v", name, err)
		}
	}
}

// 一台设备只能绑一个口，所以「所有口」是开一堆设备。这台机器上动辄几十块（utun 一人一条），
// 权限都没要到就先去绕一圈，界面上会是「点了以后卡很久才说要 root」——
// 这一条钉住：非特权用户第一台就回话，不绕满 maxBpfDevices 台。
func Test没权限时不去绕完所有设备(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 手上这一条没有对应现场：一台就能占上")
	}
	start := time.Now()
	_, err := OpenSource(Options{})
	elapsed := time.Since(start)
	if err != nil && !errors.Is(err, ErrNeedPrivilege) {
		t.Fatalf("回的是 %v，要 ErrNeedPrivilege", err)
	}
	// 真去 open 256 台的话，每次都是一个系统调用：这里给一个宽到只会抓住「绕圈」的门槛。
	if elapsed > 5*time.Second {
		t.Errorf("一句「要 root」等了 %v —— 是不是绕着设备表在试？", elapsed)
	}
}

// 计数口径与 Linux 那档有一处必须说清的差别（这一条钉的是代码里那句注释不失效）：
// BIOCGSTATS 是「自打开或重置以来」的累计数，不是读一次清一次，
// 所以 Stats 里是 Store 而不是 Add —— 累一遍就成了越问越大的假数。
// 这里没设备可问，只能验「问不到时不许编一个 0 说没丢」。
func Test问不到计数就不报(t *testing.T) {
	d := &bpfDev{name: "en0", fd: -1}
	if drops, ok := d.kernelDrops(); ok || drops != 0 {
		t.Errorf("关着的路问出 %d/%v —— 拿不到就要如实说拿不到，报个 0 会被读成「没丢」", drops, ok)
	}
	s := &darwinSource{devs: []*bpfDev{d}}
	if st := s.Stats(); st.Dropped != 0 || st.Lossy {
		t.Errorf("计数问不到时 Stats 报的是 %+v，两格都该留在「没说」那一档", st)
	}
}
