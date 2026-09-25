//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// 这份文件里的测试分两档：
//   - 不要权限的那一堆：环的算术、块里怎么走、布局对不上时停不停得下来。
//     这些拿「按实测偏移手搭出来的环」跑，因为那本来就是最容易错的地方。
//   - 要 CAP_NET_RAW 的那一条：真起一个口、真收自己发的 TCP、真解出地址与端口。
//     起不来就明写跳过 —— 别让「绿了」冒充「这条也验过了」。

var native = binary.NativeEndian

// ==================== 手搭环的桩 ====================

type synthPkt struct {
	data  []byte
	orig  int // 线上长度（留长截短时它比 len(data) 大）
	ts    time.Time
	lossy bool
	swTS  bool // 内核在这一包上标了「戳是内核打的」
	hwTS  bool // 标了「戳是网卡打的」
}

// fillV3Block 按实测口径摆一块：块头 48 字节，第一包从 48 开始，
// 每一包的链路副本从帧首 +82 起，下一包紧挨着上一包（步长 = align(82 + 这一包长度)）。
// ★ 步长这一条是踩出来的：内核那边给的帧大小是 1696，块里两包的实测步长却是 184 ——
//
//	拿帧大小当步长走，第二包就读到上一包后面那片空字节去了。
func fillV3Block(blockSize int, pkts []synthPkt) []byte {
	b := make([]byte, blockSize)
	off := tpacketBlockHdrLen
	n := len(pkts)
	for i, p := range pkts {
		stride := tpacketAlign(tpacketMinPktSpan + len(p.data))
		next := stride
		if i == n-1 {
			next = 0 // 最后一包的步长给 0（内核就是这么给的）
		}
		ph := b[off:]
		native.PutUint32(ph[t3NextOffset:], uint32(next))
		native.PutUint32(ph[t3Sec:], uint32(p.ts.Unix()))
		native.PutUint32(ph[t3Nsec:], uint32(p.ts.Nanosecond()))
		native.PutUint32(ph[t3Snaplen:], uint32(len(p.data)))
		orig := p.orig
		if orig < len(p.data) {
			orig = len(p.data)
		}
		native.PutUint32(ph[t3Len:], uint32(orig))
		st := uint32(tpStatusUser)
		if p.lossy {
			st |= tpStatusLosing
		}
		if p.swTS {
			st |= tpStatusTSSoftware
		}
		if p.hwTS {
			st |= tpStatusTSRawHW
		}
		native.PutUint32(ph[t3Status:], st)
		native.PutUint16(ph[t3Mac:], tpacketMinPktSpan)
		native.PutUint16(ph[t3Net:], tpacketMinPktSpan+14)
		copy(ph[tpacketMinPktSpan:], p.data)
		off += stride
	}
	native.PutUint32(b[blkNumPkts:], uint32(n))
	native.PutUint32(b[blkFirstPkt:], tpacketBlockHdrLen)
	native.PutUint32(b[blkLen:], uint32(off)) // 块头 + 每一包的整格
	native.PutUint32(b[blkStatus:], tpStatusUser)
	return b
}

// newSynthRing 起一路不碰 socket 的环，专门喂上面那块假字节。
func newSynthRing(t *testing.T, blockSize, blockNr, frameSize int, blocks ...[]byte) *ifaceRing {
	t.Helper()
	mmap := make([]byte, blockSize*blockNr)
	for i, b := range blocks {
		if len(b) != blockSize {
			t.Fatalf("第 %d 块 %d 字节，块大小应是 %d", i, len(b), blockSize)
		}
		copy(mmap[i*blockSize:], b)
	}
	return &ifaceRing{
		name: "synth0", fd: -1, mmap: mmap,
		blockSize: blockSize, blockNr: blockNr, frameSize: frameSize,
		framesPerBlock: blockSize / frameSize,
		cur:            -1,
	}
}

func ethFrame(payload string) []byte {
	f := make([]byte, 0, 14+len(payload))
	f = append(f,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 目的
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // 源
		0x08, 0x00) // 以太类型：IPv4
	return append(f, payload...)
}

// ==================== 环的算术 ====================

func Test环的算术(t *testing.T) {
	cases := []struct {
		what      string
		buf, snap int
		page      int
	}{
		{what: "默认档：4MB 环、留长 1600、4K 页", buf: 0, snap: 0, page: 4096},
		{what: "留长很小：一包 64 字节", buf: 1 << 20, snap: 64, page: 4096},
		{what: "留长很大：Jumbo 9000", buf: 8 << 20, snap: 9000, page: 4096},
		{what: "64K 页的机器（ARM 服务器常见）", buf: 4 << 20, snap: 1600, page: 65536},
		{what: "环小到只够一块：得顶到两块", buf: 1024, snap: 1600, page: 4096},
		{what: "留长 1 字节也别算出个零帧", buf: 1 << 20, snap: 1, page: 4096},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			snap := c.snap
			if snap == 0 {
				snap = DefaultSnapLen
			}
			blockSize, blockNr, frameSize, frameNr, err := ringPlan(c.buf, c.snap, c.page)
			if err != nil {
				t.Fatalf("算不出来：%v", err)
			}
			// 内核那几条硬要求，一格都不能少 —— 少了就只有那句什么都不细说的 EINVAL。
			if blockSize%c.page != 0 {
				t.Errorf("块大小 %d 不是页（%d）的整数倍", blockSize, c.page)
			}
			if want := (blockSize / frameSize) * blockNr; frameNr != want {
				t.Errorf("帧数 %d，内核要的是「每块帧数 × 块数」= %d", frameNr, want)
			}
			if frameSize < tpacketAlign(tpacket3HdrLen) {
				t.Errorf("帧大小 %d，比内核给的下限 %d 还小", frameSize, tpacketAlign(tpacket3HdrLen))
			}
			if blockSize < frameSize+tpacketBlockHdrLen {
				t.Errorf("块 %d 字节，装不下一帧（%d）加块头（%d）", blockSize, frameSize, tpacketBlockHdrLen)
			}
			if blockSize/frameSize < 1 {
				t.Errorf("块 %d / 帧 %d = 0，一块连一包都放不下", blockSize, frameSize)
			}
			if blockNr < 2 {
				t.Errorf("块数 %d：只有一块的话，用户没读完新包就得干等", blockNr)
			}
			// 实测那一包吃掉「链路副本起点 82 + 留长」：帧大小不许比这个数小，
			// 否则内核往块里写到第二包时就踩进上一包的格子。
			if need := tpacketMinPktSpan + snap; frameSize < need {
				t.Errorf("帧 %d 字节，装不下「链路副本起点 %d + 留长 %d」= %d", frameSize, tpacketMinPktSpan, snap, need)
			}
		})
	}
	t.Run("负数与超大档要报错而不是硬算", func(t *testing.T) {
		if _, _, _, _, err := ringPlan(1<<20, -1, 4096); err == nil {
			t.Error("留长为负，居然算出了一份环")
		}
		if _, _, _, _, err := ringPlan(-5, 1600, 4096); err == nil {
			t.Error("环为负，居然算出了一份环")
		}
		// 留长顶到 1GB：环的总长会冲出 int32。这一档要挡在这里，
		// 别去撞内核那句看不出所以然的 EINVAL。
		if _, _, _, _, err := ringPlan(1<<30, 1<<30, 4096); err == nil {
			t.Error("留长 1GB 也算得出来 —— 那道上限没起作用")
		}
	})
	t.Run("默认档的数钉住（改了要说得出为什么）", func(t *testing.T) {
		blockSize, blockNr, frameSize, frameNr, err := ringPlan(DefaultBufferSize, DefaultSnapLen, 4096)
		if err != nil {
			t.Fatal(err)
		}
		if frameSize != 1696 {
			t.Errorf("帧大小 %d，这一档实测是 1696（96 + 1600，正好在 16 的格上）", frameSize)
		}
		if blockSize != 4096 {
			t.Errorf("块大小 %d，4K 页上这一档是 4096", blockSize)
		}
		if blockNr != 1024 || frameNr != 2048 {
			t.Errorf("块数 %d / 帧数 %d，这一档应是 1024 块、2048 帧", blockNr, frameNr)
		}
	})
}

func Test链路类型表(t *testing.T) {
	cases := []struct {
		arphrd uint16
		want   uint16
		ok     bool
	}{
		{arphrdEthernet, LinkTypeEN10MB, true},
		{arphrdLoopback, LinkTypeEN10MB, true}, // lo 带 14 字节假以太网头，dumpcap 也这么写
		{arphrdPPP, LinkTypeRaw, true},
		{arphrdIEEE80211, LinkTypeIEEE80211, true},
		{arphrdRadioTap, LinkTypeRadioTap, true},
		// 认不出的必须回 false：写错号不报错，只会让上层把裸 IP 当以太网解。
		{778, 0, false},   // ARPHRD_TUNNEL
		{65534, 0, false}, // ARPHRD_NONE
		{1, LinkTypeEN10MB, true},
	}
	for _, c := range cases {
		got, ok := linkTypeOfARPHRD(c.arphrd)
		if ok != c.ok || got != c.want {
			t.Errorf("ARPHRD_%d 解成 (%d,%v)，应是 (%d,%v)", c.arphrd, got, ok, c.want, c.ok)
		}
	}
}

func Test退休时长那一格不许给零(t *testing.T) {
	// 0 在内核那边是「装满才交」：低流量时包躺在块里出不来，界面上就像没流量。
	cases := []struct {
		in   time.Duration
		want int
	}{
		{0, 100},                  // 没填 → 默认那一档
		{-time.Second, 100},       // 负数也按默认，不许传下去
		{time.Millisecond / 2, 1}, // 不到一毫秒的顶到 1，不许顶成 0
		{250 * time.Millisecond, 250},
		{3 * time.Second, 3000},
		{time.Second, 1000},
	}
	for _, c := range cases {
		if got := retireMillis(c.in); got != c.want {
			t.Errorf("retireMillis(%v) = %d，应是 %d", c.in, got, c.want)
		}
	}
}

func Test错误分类(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{syscall.EPERM, ErrNeedPrivilege},
		{syscall.EACCES, ErrNeedPrivilege},
		{syscall.ENODEV, ErrNoSuchInterface},
		{syscall.ENXIO, ErrNoSuchInterface},
		{errors.New("别的"), nil}, // 别的错不硬套分类：套错了界面上会给错建议
	}
	for _, c := range cases {
		got := wrapSocketErr("eth0", c.err)
		if c.want == nil {
			if errors.Is(got, ErrNeedPrivilege) || errors.Is(got, ErrNoSuchInterface) {
				t.Errorf("把「%v」说成了要权限或没这个口：%v", c.err, got)
			}
			continue
		}
		if !errors.Is(got, c.want) {
			t.Errorf("%v 应归到 %v，实际归到 %v", c.err, c.want, got)
		}
		if !strings.Contains(got.Error(), "eth0") {
			t.Errorf("报错里没带上口名，现场不知道说的是哪一路：%v", got)
		}
	}
}

func Test点名的口不存在就直说(t *testing.T) {
	// 这一条不许退化成「那就全抓」：现场最常见的误判就是抓了半天没有对方的包，
	// 因为抓的是另一块网卡。
	if _, err := sourceIfaces("netkit-不存在的口-9x"); !errors.Is(err, ErrNoSuchInterface) {
		t.Errorf("got %v，应是 ErrNoSuchInterface", err)
	}
	ifs, err := sourceIfaces("")
	if err != nil {
		t.Fatalf("列所有口失败：%v", err)
	}
	if len(ifs) == 0 {
		t.Fatal("一个口都列不出来")
	}
	got, err := sourceIfaces(ifs[0])
	if err != nil || len(got) != 1 || got[0] != ifs[0] {
		t.Errorf("点名 %s 拿回 %v / %v", ifs[0], got, err)
	}
}

// ==================== 块里怎么走 ====================

func Test块里按步长走不是按帧大小(t *testing.T) {
	// 三包，长度各不相同。按帧大小（这里给 1696）走的话第二包会读到上一包后面的空字节，
	// 这一条就是钉住「步长用内核给的 tp_next_offset」。
	blockSize, frameSize := 8192, 1696
	base := time.Unix(1790000000, 0)
	d3 := ethFrame("第三个")
	pkts := []synthPkt{
		{data: ethFrame("第一个包"), orig: 4096, ts: base},
		{data: ethFrame("第二个包长一些"), orig: 60, ts: base.Add(7*time.Millisecond + 123*time.Nanosecond)},
		{data: d3, orig: len(d3), ts: base.Add(19 * time.Millisecond)},
	}
	r := newSynthRing(t, blockSize, 2, frameSize, fillV3Block(blockSize, pkts))

	for i, want := range pkts {
		p, ok, err := r.takePacket()
		if err != nil {
			t.Fatalf("第 %d 包读不下去：%v", i, err)
		}
		if !ok {
			t.Fatalf("读到第 %d 包就说没包了（这一块 num_pkts 报的是 %d）", i, len(pkts))
		}
		if string(p.Data) != string(want.data) {
			t.Errorf("第 %d 包正文对不上（步长走错了就会读到别人的格子）：%q", i, p.Data)
		}
		if !p.Timestamp.Equal(want.ts) {
			t.Errorf("第 %d 包时刻 %v，应是 %v（秒与纳秒那两格读错了位置）", i, p.Timestamp, want.ts)
		}
		if p.OrigLen != want.orig {
			t.Errorf("第 %d 包线上长度 %d，应是 %d —— 截没截过就看不出来了", i, p.OrigLen, want.orig)
		}
		if p.InterfaceIndex != 0 {
			t.Errorf("第 %d 包挂在口 %d，这一路只有 0 号", i, p.InterfaceIndex)
		}
		if !p.HasTimestamp {
			t.Errorf("第 %d 包说没有时刻", i)
		}
	}
	// 读完这一块：要还给内核，并且不再从这一块捞第二遍。
	if _, ok, err := r.takePacket(); err != nil || ok {
		t.Fatalf("读完三包后还 %v/%v，应是拿不到包、也不报错", ok, err)
	}
	if r.cur != -1 {
		t.Errorf("手上还留着块 %d：块没交还给内核，下一轮就是实打实的丢包", r.cur)
	}
	if got := native.Uint32(r.mmap[blkStatus:]); got != tpStatusKernel {
		t.Errorf("第一块的 block_status = %d，应写回 %d（TP_STATUS_KERNEL）", got, tpStatusKernel)
	}
	if r.readIdx != 1 {
		t.Errorf("读游标停在 %d，应前进到 1", r.readIdx)
	}
	if r.bad != nil {
		t.Errorf("一路正常读居然报错：%v", r.bad)
	}
}

func Test空块也要跨过去不许当布局错了(t *testing.T) {
	// 到点交出来一块、里面零包：低流量时的常态。当成错就会把整路打死。
	blockSize, frameSize := 4096, 1696
	empty := make([]byte, blockSize)
	native.PutUint32(empty[blkStatus:], tpStatusUser)
	native.PutUint32(empty[blkNumPkts:], 0)
	native.PutUint32(empty[blkFirstPkt:], tpacketBlockHdrLen)
	native.PutUint32(empty[blkLen:], tpacketBlockHdrLen)
	r := newSynthRing(t, blockSize, 3, frameSize, empty)
	// 第二块放一包真货：跨过那块空的也得能读到它。
	want := ethFrame("跨过空块的那一包")
	copy(r.mmap[blockSize:], fillV3Block(blockSize, []synthPkt{{data: want, orig: len(want), ts: synthTS()}}))

	if !r.adoptBlock() {
		t.Fatalf("认块认不动（第一块是空的，应跨过去看第二块）：%v", r.bad)
	}
	if r.cur != 1 {
		t.Errorf("手上是块 %d，应是 1 —— 那块空的没被跨过去", r.cur)
	}
	p, ok, err := r.takePacket()
	if err != nil || !ok {
		t.Fatalf("取包 %v/%v", ok, err)
	}
	if string(p.Data) != string(want) {
		t.Errorf("读到了别的东西：%q", p.Data)
	}
	if got := native.Uint32(r.mmap[blkStatus:]); got != tpStatusKernel {
		// 查的是环里那一份：empty 只是搭块时的母本，拷进 mmap 之后内核（这里是环）
		// 改的是环里那一格，翻母本等于什么都没验。
		t.Errorf("那块空块的 status = %d：没还给内核，环会越填越满", got)
	}
}

func Test布局对不上就停下来(t *testing.T) {
	// 每一条都是「内核给的那一格和这张表理解的不是一回事」。
	// 这类错不许绿着过去，也不许按猜的继续读 —— 那只会产出一份看着很正常的错账。
	cases := []struct {
		what   string
		block  func(b []byte)
		wantIn string
	}{
		{
			what:   "有效长度比块还大",
			block:  func(b []byte) { native.PutUint32(b[blkLen:], uint32(len(b)+1)) },
			wantIn: "有效长度",
		},
		{
			what:   "包数多到这一块的字节兜不住",
			block:  func(b []byte) { native.PutUint32(b[blkNumPkts:], 9999) },
			wantIn: "一格放不下这么多",
		},
		{
			what:   "第一包落在块头之前",
			block:  func(b []byte) { native.PutUint32(b[blkFirstPkt:], 8) },
			wantIn: "落在块头",
		},
		{
			what: "第一包落在有效长度之外",
			block: func(b []byte) {
				native.PutUint32(b[blkFirstPkt:], native.Uint32(b[blkLen:])+16)
			},
			wantIn: "之外",
		},
		{
			what: "还剩两包，步长却给了 0",
			block: func(b []byte) {
				// 认块那一步得先放行，不然报的是「兜不住这么多包」，走不到步长那一格：
				// 把有效长度抬成两格的量（一格 = 包头到链路副本 + 这一包正文）。
				native.PutUint32(b[blkNumPkts:], 2)
				stride := tpacketAlign(tpacketMinPktSpan + len(ethFrame("正常的一包")))
				native.PutUint32(b[blkLen:], uint32(tpacketBlockHdrLen+2*stride))
			},
			wantIn: "步长",
		},
		{
			what: "链路头偏移被算到块外",
			block: func(b []byte) {
				native.PutUint16(b[tpacketBlockHdrLen+t3Mac:], 4000)
			},
			wantIn: "兜不进这一块",
		},
		{
			what: "留长比块还大",
			block: func(b []byte) {
				native.PutUint32(b[tpacketBlockHdrLen+t3Snaplen:], uint32(len(b)))
			},
			wantIn: "兜不进这一块",
		},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			blockSize, frameSize := 4096, 1696
			one := ethFrame("正常的一包")
			b := fillV3Block(blockSize, []synthPkt{{data: one, orig: len(one), ts: synthTS()}})
			c.block(b)
			r := newSynthRing(t, blockSize, 2, frameSize, b)
			var err error
			for i := 0; i < 6; i++ { // 取到错为止：有的错在认块那一步，有的在读包那一步
				if _, _, err = r.takePacket(); err != nil {
					break
				}
			}
			if err == nil {
				t.Fatal("布局对不上却一路读下去了")
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Errorf("报的是「%v」，没说清 %s", err, c.what)
			}
			if !strings.Contains(err.Error(), "synth0") {
				t.Errorf("报错里没带上口名：%v", err)
			}
			if r.bad == nil {
				t.Error("错没落到 bad 上：下一次读还会重新猜一遍，报错会飘")
			}
			// 落定之后每次读都回同一个错，不许换个说法。
			if _, _, err2 := r.takePacket(); err2 == nil || err2.Error() != err.Error() {
				t.Errorf("第二遍读回的是 %v，应与第一遍同一个错", err2)
			}
		})
	}
}

func Test读不出环外与块外(t *testing.T) {
	blockSize, frameSize := 4096, 1696
	one := ethFrame("块里的唯一一包")
	b := fillV3Block(blockSize, []synthPkt{{data: one, orig: len(one), ts: synthTS()}})

	t.Run("包头顶到 mmap 之外", func(t *testing.T) {
		r := newSynthRing(t, blockSize, 2, frameSize, b)
		if !r.adoptBlock() {
			t.Fatal("认块认不动")
		}
		r.left = 2
		r.off = len(r.mmap) - 8 // 这一包的包头只有 8 字节可读了
		if _, _, err := r.takePacket(); err == nil {
			t.Fatal("读出了环外还没报错：那是拿越界的字节当包头")
		} else if !strings.Contains(err.Error(), "环外") {
			t.Errorf("报的是 %v", err)
		}
	})
	t.Run("包头顶到有效长度之外", func(t *testing.T) {
		r := newSynthRing(t, blockSize, 2, frameSize, b)
		if !r.adoptBlock() {
			t.Fatal("认块认不动")
		}
		r.left = 2
		r.off = r.end - 20 // 环里还有地方，但内核说这一块只到这儿
		if _, _, err := r.takePacket(); err == nil {
			t.Fatal("读出了这一块的有效长度还没报错")
		} else if !strings.Contains(err.Error(), "有效长度") {
			t.Errorf("报的是 %v", err)
		}
	})
}

func Test包上的丢包标记要留下(t *testing.T) {
	blockSize, frameSize := 4096, 1696
	one := ethFrame("带标记的一包")
	b := fillV3Block(blockSize, []synthPkt{{data: one, orig: len(one), ts: synthTS(), lossy: true}})
	r := newSynthRing(t, blockSize, 2, frameSize, b)
	if _, _, err := r.takePacket(); err != nil {
		t.Fatal(err)
	}
	if !r.lossy.Load() {
		t.Error("TP_STATUS_LOSING 这一格没看：内核说了丢过，报表上就成了没丢")
	}
	if _, ok := r.kernelDrops(); ok {
		t.Error("fd 是 -1 还能问到内核计数？")
	}
	st := (&linuxSource{rings: []*ifaceRing{r}}).Stats()
	if !st.Lossy {
		t.Error("这一路的 Lossy 没报到 Stats 上")
	}
	if st.Dropped != 0 {
		t.Errorf("问不到内核时 Dropped 应老实报 0，报的是 %d", st.Dropped)
	}
}

func Test边抓边问账各走一条路时不许互相撕(t *testing.T) {
	// #92 那一档的界面是「一边抓一边看丢了几包」：Next 与 Stats 天生在两条 goroutine 上跑。
	// 这两格用普通字段的话，那边刚把一个 TP_STATUS_LOSING 写下去、这边读到旧的 false ——
	// 报表上就成了「内核没说丢过」，而它明明说了。所以这一条配 -race 跑就是奔着这个去的。
	const rounds = 400
	blockSize, frameSize := 4096, 1696
	f := ethFrame("边抓边问")
	for n := 0; n < rounds; n++ {
		var blocks [][]byte
		for i := 0; i < 8; i++ {
			blocks = append(blocks, fillV3Block(blockSize, []synthPkt{{data: f, orig: len(f), ts: synthTS(), lossy: true}}))
		}
		r := newSynthRing(t, blockSize, 8, frameSize, blocks...)
		src := &linuxSource{rings: []*ifaceRing{r}}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				if _, _, err := r.takePacket(); err != nil {
					t.Errorf("第 %d 包读坏了：%v", i, err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = src.Stats()
			}
		}()
		wg.Wait()
		if !src.Stats().Lossy {
			t.Fatalf("第 %d 轮：八包全带着 TP_STATUS_LOSING，问账却问出「没丢过」", n)
		}
	}

	// 内核那份计数读一次清一次，所以报给界面的是自己累起来的那一份 —— 累起来的数不许第二次问就变 0。
	r := newSynthRing(t, blockSize, 2, frameSize)
	src := &linuxSource{rings: []*ifaceRing{r}}
	r.drops.Add(7)
	if got := src.Stats().Dropped; got != 7 {
		t.Errorf("第一次问账报 %d，要的是累起来的 7", got)
	}
	if got := src.Stats().Dropped; got != 7 {
		t.Errorf("第二次问账报 %d —— 内核那份计数读一次清一次，累起来那一份丢了就等于「上一秒还在丢、这一秒没丢」", got)
	}
}

func Test要硬件时刻而内核给的是软件戳就停下来(t *testing.T) {
	// 这一条盯的是「setsockopt 成功了 ≠ 拿得到硬件戳」：容器里实测，一块给不了硬件戳的
	// 网卡上把 SOF_TIMESTAMPING_* 递进去内核照样回成功，之后每个包亮的全是软件时刻那一位。
	// 那一档要是照常往下算延迟，报表上完全看不出来 —— 所以戳的来源逐个包核对，对不上就停。
	blockSize, frameSize := 4096, 1696
	mk := func(sw, hw bool) *ifaceRing {
		f := ethFrame("硬件戳核对")
		b := fillV3Block(blockSize, []synthPkt{{data: f, orig: len(f), ts: synthTS(), swTS: sw, hwTS: hw}})
		r := newSynthRing(t, blockSize, 2, frameSize, b)
		r.wantHW = true
		return r
	}

	t.Run("标了软件戳", func(t *testing.T) {
		r := mk(true, false)
		_, _, err := r.takePacket()
		if err == nil {
			t.Fatal("要的是硬件戳，给的是软件戳，居然读过去了")
		}
		if !strings.Contains(err.Error(), "硬件时刻") {
			t.Errorf("报的是 %v，得说清是硬件时刻拿不到", err)
		}
		if r.bad == nil {
			t.Error("这一路没落 bad：下一包还会照着软件戳算下去")
		}
		if _, _, err2 := r.takePacket(); err2 == nil || err2.Error() != err.Error() {
			t.Errorf("第二次读回 %v，应与第一次同一句（%v）", err2, err)
		}
	})

	t.Run("内核压根没标来源", func(t *testing.T) {
		// 没标也算拿不到：这一档不能替内核猜「没标大概就是硬件打的吧」。
		r := mk(false, false)
		if _, _, err := r.takePacket(); err == nil {
			t.Fatal("戳的来源说不清也读过去了")
		}
	})

	t.Run("真给了硬件戳就照走", func(t *testing.T) {
		r := mk(false, true)
		p, ok, err := r.takePacket()
		if err != nil || !ok {
			t.Fatalf("内核标了硬件戳还回 (%v,%v)，这一路把要来的东西挡掉了", ok, err)
		}
		if p.Data == nil {
			t.Error("零字节")
		}
		if r.bad != nil {
			t.Errorf("落了什么 bad：%v", r.bad)
		}
	})

	// 反过来也要钉住：不要硬件戳的（默认档）看见软件戳不许当错误。
	f := ethFrame("默认档")
	b := fillV3Block(blockSize, []synthPkt{{data: f, orig: len(f), ts: synthTS(), swTS: true}})
	plain := newSynthRing(t, blockSize, 2, frameSize, b)
	if _, ok, err := plain.takePacket(); !ok || err != nil {
		t.Errorf("默认档带着软件戳读不过去（%v）—— 只有硬要硬件戳的那一路才该挑这一格", err)
	}
}

// ==================== 等包那一格（ppoll 的超时真的在等） ====================

func Test等包真的等到点为止(t *testing.T) {
	// 盯的是 kernelTimespec 那两格的落点：写错长度或写反秒与纳秒，不会报错，
	// 只会变成「不等的空转」—— 界面上一圈一圈地转、CPU 吃满、一个包也没多等到。
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	rings := []*ifaceRing{{name: "pipe0", fd: int(pr.Fd()), cur: -1}}

	const want = 250 * time.Millisecond
	// 被信号打断要重等：Go 的运行时常往线程上扔 SIGURG，ppoll 回来一句
	// interrupted system call 不算事。生产那一路（waitReady）就是这么走的，
	// 这里跟着同一口径 —— 拿一次 EINTR 就当失败，测试会在负载高的机器上偶发红。
	poll := func(ms int) (int, time.Duration, error) {
		start := time.Now()
		for {
			n, err := pollRings(rings, ms)
			if err == syscall.EINTR {
				start = time.Now() // 打断的那一段不算等到的：重起一格
				continue
			}
			return n, time.Since(start), err
		}
	}

	n, waited, err := poll(int(want / time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("管道里什么都没写，等到 %d 路有事", n)
	}
	if waited < want*4/5 {
		t.Errorf("要等 %v，实际只等了 %v —— 超时那两格的落点不对（变成不等了）", want, waited)
	}
	if waited > 3*time.Second {
		t.Errorf("要等 %v，实际等了 %v —— 超时那一格被读成了天荒地老", want, waited)
	}

	// 另一端写一个字节：这回应当立刻就有动静，且报出「一路」。
	// 没有这一步的话，「一直返回 0」和「压根没把 fd 递进去」看着是一样的。
	if _, err := pw.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		n, _, err := poll(1000)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("写了一个字节进去，ppoll 还是报「没动静」—— fd 那一格递的不是要等的那一路")
}

func Test关掉之后再读要回ErrClosed(t *testing.T) {
	s := &linuxSource{} // 没有 socket 也照样要走完这套口径
	if err := s.Close(); err != nil {
		t.Fatalf("空口关掉报错：%v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("关第二次报错：%v（关两次不算一次错）", err)
	}
	if _, err := s.Next(); !errors.Is(err, ErrClosed) {
		t.Errorf("关了还在读，回的是 %v，应是 ErrClosed", err)
	}
	if st := s.Stats(); st.Interfaces != 0 || st.Dropped != 0 || st.Packets != 0 {
		t.Errorf("空口的账应是全 0，拿到 %+v", st)
	}
	if got := s.Interfaces(); len(got) != 0 {
		t.Errorf("空口报出 %d 个口", len(got))
	}
}

func Test关掉之后不许再拿失效的fd去等(t *testing.T) {
	// fd 填 -1 是 Close 干的：pollRings 得跳过那一路，
	// 否则那个号可能已经被别的 socket 用了，等到的是别人的动静。
	s := &linuxSource{rings: []*ifaceRing{{name: "eth0", fd: -1, cur: -1}}}
	n, err := pollRings(s.rings, 0)
	if err != nil || n != 0 {
		t.Errorf("全关着的环 poll 回 (%d,%v)，应是 (0,nil) 直接放行", n, err)
	}
}

// ==================== 真起一个口（要 CAP_NET_RAW） ====================

func Test真抓回环并解出自己发的那一条(t *testing.T) {
	src, err := OpenSource(Options{Interface: "lo", SnapLen: 200})
	if err != nil {
		t.Skipf("这一档要 CAP_NET_RAW，这台机器上起不来（%v）—— 现场抓包这一条没验过", err)
	}
	defer src.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	marker := fmt.Sprintf("netkit-回环自证-%d", time.Now().UnixNano()%100000)
	srv := make(chan error, 1)
	go echoOnce(ln, srv)
	cli := make(chan error, 1)
	go func() { cli <- knockClient(ln.Addr().String(), marker) }()

	deadline := time.Now().Add(10 * time.Second)
	var (
		got  Packet
		seen []Packet
		n    int
		prev time.Time
	)
	for time.Now().Before(deadline) && got.Data == nil {
		p, err := src.Next()
		if err != nil {
			t.Fatalf("第 %d 包读不下去：%v", n, err)
		}
		n++
		if n > 1 && p.Timestamp.Before(prev) {
			t.Errorf("第 %d 包的时刻 %v 比上一包 %v 还早 —— 时刻那两格读反了？", n, p.Timestamp, prev)
		}
		prev = p.Timestamp
		if d := time.Since(p.Timestamp); d > time.Minute || d < -time.Minute {
			t.Errorf("第 %d 包的时刻 %v 离现在 %v，差得太远（秒与纳秒的落点不对）", n, p.Timestamp, d)
		}
		if len(p.Data) == 0 {
			t.Errorf("第 %d 包零字节：snaplen 那一格读错了", n)
		}
		if p.OrigLen < len(p.Data) {
			t.Errorf("第 %d 包留了 %d 字节、线上却只 %d 字节：截没截过就反过来了", n, len(p.Data), p.OrigLen)
		}
		if len(p.Data) > 200 {
			t.Errorf("第 %d 包留了 %d 字节，比要求的留长 200 还多", n, len(p.Data))
		}
		if len(seen) < 400 { // 攒下来往文件里写：Next 会一直等，不许在那儿卡着收工
			seen = append(seen, p)
		}
		if strings.Contains(string(p.Data), marker) {
			got = p
		}
	}
	if got.Data == nil {
		t.Fatalf("读了 %d 包没找到自己发的那一条（标记 %q）", n, marker)
	}
	if err := <-cli; err != nil {
		t.Fatalf("自己跟自己连那一路就坏了：%v", err)
	}
	if err := <-srv; err != nil {
		t.Fatalf("回环上的服务那头坏了：%v", err)
	}

	// 到这里才是正题：包是从内核的环里读出来的，解一遍得是我们发的那一条。
	inf := src.Interfaces()
	if len(inf) != 1 {
		t.Fatalf("这一路有 %d 个口", len(inf))
	}
	if inf[0].Name != "lo" || inf[0].LinkType != LinkTypeEN10MB {
		t.Errorf("口报成 %s / 链路类型 %d", inf[0].Name, inf[0].LinkType)
	}
	if inf[0].TSUnit() != time.Nanosecond {
		t.Errorf("刻度 %v，V3 的戳应是纳秒一格", inf[0].TSUnit())
	}
	ip, err := parseIPv4OverEthernet(got.Data)
	if err != nil {
		t.Fatalf("链路头/网络头解不开（mac 与 net 那两格读错了就会这样）：%v", err)
	}
	if ip.src.String() != "127.0.0.1" || ip.dst.String() != "127.0.0.1" {
		t.Errorf("地址是 %s → %s，回环上自己连自己应是 127.0.0.1 两头", ip.src, ip.dst)
	}
	tcp, err := parseTCP(ip.body)
	if err != nil {
		t.Fatalf("TCP 解不开：%v", err)
	}
	if tcp.src != uint16(port) && tcp.dst != uint16(port) {
		t.Errorf("端口是 %d → %d，这一路只有 %d 这一个在听", tcp.src, tcp.dst, port)
	}
	if !strings.Contains(string(tcp.payload), marker) {
		t.Errorf("TCP 正文里没有那条标记：%q", tcp.payload)
	}

	// 现场抓的 → 我们的写手 → 我们的读手：这一条通了，「抓一份」和「读一份」才是同一套口径。
	dir := t.TempDir()
	name := filepath.Join(dir, "netkit-lo.pcapng")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWriter(f, inf)
	if err != nil {
		t.Fatalf("建写手失败：%v", err)
	}
	wrote := seen
	for i, p := range wrote {
		if err := w.WritePacket(p.InterfaceIndex, p.Timestamp, p.Data, p.OrigLen); err != nil {
			t.Fatalf("写第 %d 包失败：%v", i, err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rf, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	rd, err := Open(rf)
	if err != nil {
		t.Fatal(err)
	}
	back := rd.Ifaces()
	if len(back) != 1 || back[0].Name != "lo" || back[0].LinkType != LinkTypeEN10MB {
		t.Errorf("读回来的口是 %+v", back)
	}
	var k int
	for {
		p, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("读回自己写的文件，第 %d 包坏了：%v", k, err)
		}
		if k >= len(wrote) {
			t.Fatalf("读回来 %d 包，只写了 %d 包", k+1, len(wrote))
		}
		want := wrote[k]
		if string(p.Data) != string(want.Data) {
			t.Errorf("第 %d 包正文对不上：文件里 %d 字节，环里 %d 字节", k, len(p.Data), len(want.Data))
		}
		if !p.Timestamp.Equal(want.Timestamp) {
			t.Errorf("第 %d 包时刻 %v，环里是 %v（纳秒那一格在写读之间丢了）", k, p.Timestamp, want.Timestamp)
		}
		if p.OrigLen != want.OrigLen {
			t.Errorf("第 %d 包线上长度 %d，环里是 %d", k, p.OrigLen, want.OrigLen)
		}
		k++
	}
	if k != len(wrote) {
		t.Errorf("读回来 %d 包，写进去 %d 包", k, len(wrote))
	}

	st := src.Stats()
	if st.Packets == 0 {
		t.Error("读了这么多包，Stats 说一包没递出去")
	}
	if st.Interfaces != 1 {
		t.Errorf("Interfaces %d，这一路只有一个口", st.Interfaces)
	}
	t.Logf("读了 %d 包，自证那条 %d 字节 / 线上 %d 字节；内核计数：递出 %d、丢掉 %d、标过丢包 %v",
		n, len(got.Data), got.OrigLen, st.Packets, st.Dropped, st.Lossy)
}

func synthTS() time.Time { return time.Unix(1790000000, 123456789) }

// echoOnce 只接一条、原样回声、对面关掉就收工。
// ★ 不许在 Accept 上无限等：那一路挂了整条测试就卡在那儿，看不出是抓包坏了。
func echoOnce(ln net.Listener, done chan<- error) {
	c, err := ln.Accept()
	if err != nil {
		done <- err
		return
	}
	defer c.Close()
	buf := make([]byte, 512)
	for {
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		n, err := c.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				done <- nil // 对面收工了（或磨到超时）：这一路的账已经记完
				return
			}
			done <- err
			return
		}
		if _, err := c.Write(append([]byte("回声："), buf[:n]...)); err != nil {
			done <- err
			return
		}
	}
}

// knockClient 在本机回环上连一条 TCP，把标记发过去再读回来。
// 不引外部命令：这一条要能在最小容器里跑起来。
func knockClient(addr, marker string) error {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		if _, err := c.Write([]byte(fmt.Sprintf("%s 第%d趟", marker, i))); err != nil {
			return err
		}
		buf := make([]byte, 512)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Read(buf); err != nil {
			return err
		}
		time.Sleep(40 * time.Millisecond)
	}
	return nil
}

// ==================== 只解到够钉住偏移的那一层 ====================

type ipHdr struct {
	src, dst net.IP
	body     []byte
}

// parseIPv4OverEthernet 只解到够验证链路头那两格（mac / net）为止。
// 这一步在测试里手搓而不是用上层，是因为上层（按流聚合）还没写：
// 这一档要先自己站住，才知道聚合那一层能不能信它。
func parseIPv4OverEthernet(b []byte) (*ipHdr, error) {
	if len(b) < 14 {
		return nil, fmt.Errorf("整包只有 %d 字节，连 14 字节链路头都不够", len(b))
	}
	if b[12] != 0x08 || b[13] != 0x00 {
		return nil, fmt.Errorf("以太类型是 %02x %02x，不是 IPv4（08 00）—— 链路头起点读错了", b[12], b[13])
	}
	ip := b[14:]
	if len(ip) < 20 {
		return nil, fmt.Errorf("链路头后面只有 %d 字节，IPv4 头都不够", len(ip))
	}
	if v := ip[0] >> 4; v != 4 {
		return nil, fmt.Errorf("IP 版本是 %d，不是 4 —— 网络头起点读错了", v)
	}
	hdr := int(ip[0]&0x0f) * 4
	if hdr < 20 || hdr > len(ip) {
		return nil, fmt.Errorf("IP 头长 %d，比这一包 %d 字节还长", hdr, len(ip))
	}
	if p := ip[9]; p != 6 {
		return nil, fmt.Errorf("上层协议是 %d，不是 TCP（我们发的是 TCP）", p)
	}
	return &ipHdr{src: net.IP(ip[12:16]), dst: net.IP(ip[16:20]), body: ip[hdr:]}, nil
}

type tcpSeg struct {
	src, dst uint16
	payload  []byte
}

func parseTCP(b []byte) (*tcpSeg, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("TCP 头只有 %d 字节，不到 20", len(b))
	}
	hdr := int(b[12]>>4) * 4
	if hdr < 20 || hdr > len(b) {
		return nil, fmt.Errorf("TCP 头长 %d，比这一段 %d 字节还长（端口那几格八成读到了正文）", hdr, len(b))
	}
	return &tcpSeg{
		src:     uint16(b[0])<<8 | uint16(b[1]),
		dst:     uint16(b[2])<<8 | uint16(b[3]),
		payload: b[hdr:],
	}, nil
}
