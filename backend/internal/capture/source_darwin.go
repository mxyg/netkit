//go:build darwin

// macOS / FreeBSD 系这一档：/dev/bpfn 裸设备 + ioctl，纯 syscall，不链 libpcap。
//
// 口径与 Linux 那一条一样：libpcap 本身就是这一层的封装，不必再带一份第三方二进制；
// 但每一格都得有出处。这一档的出处是这台机器上的两份东西：
//
//  1. cc 对着 SDK 的 <net/bpf.h> 把 sizeof/offsetof 各量了一遍（每一格是多少、
//     ioctl 号码里编着的结构体长度是多少，见 source_darwin_test.go 里那条自查）；
//  2. 随机附带的 bpf(4) 手册页（macOS 15.6）。里面把「读缓冲必须正好是 BIOCGBLEN 那一格」
//     「BIOCSBLEN 要在 BIOCSETIF 之前」「记录之间用 BPF_WORDALIGN(hdrlen+caplen) 跳」
//     「BIOCGSTATS 是『自打开或重置以来』的累计数」都写死了。
//
// ★ 这一档最容易做错的一处，是时刻那一格长什么样：
//
//	头文件里写着 `#if defined(__LP64__) #define BPF_TIMEVAL timeval32` ——
//	64 位 macOS 上 bpf 记录头里的 tv_sec 是 **4 字节**，不是本机的 time_t（8 字节）。
//	按 native timeval 读，包头就成了 8+8+4+4+2 = 30 字节（真值是 20），
//	于是「caplen」读到的是微秒那一格、「datalen」读到的是 caplen，
//	时刻飞到几十年后 —— 一份看着完全合理的错账。
//	同一个子系统里两个 timeval 形状并存：记录头里是 timeval32（8 字节），
//	而 BIOCSRTIMEOUT 那个 ioctl 的参数是 native timeval（16 字节 —— 号码里那格长度就是 0x10）。
//
// ★ 第二处：读缓冲的大小不许自己挑。手册页的 BUGS 那一节写得很直白
//
//	「The read buffer must be of a fixed size (returned by the BIOCGBLEN ioctl)」，
//	BIOCSBLEN 那一节还补了一句：传进去的字节数不对，read 直接 EINVAL。
//	所以先要 BIOCSBLEN、再 BIOCSETIF（顺序也是手册页定的），
//	再拿 BIOCGBLEN 把内核最终认下来的那一格读回来，按它分配。
package capture

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// bpf 记录头（struct bpf_hdr）的落点。全部由 cc 对着这台机器的 SDK 头量出来：
// sizeof(bpf_hdr)=20、BPF_ALIGNMENT=4、sizeof(BPF_TIMEVAL)=8。
const (
	bpfHdrSize   = 20 // sizeof(struct bpf_hdr)：tstamp(8) + caplen(4) + datalen(4) + hdrlen(2) + 补(2)
	bpfSecOff    = 0  // bh_tstamp.tv_sec —— int32，不是 int64
	bpfUsecOff   = 4  // bh_tstamp.tv_usec —— 微秒
	bpfCaplenOff = 8  // bh_caplen：留下多少那一份
	bpfDatalenOn = 12 // bh_datalen：线上那一份
	bpfHdrLenOff = 16 // bh_hdrlen：这一条记录的头（含补齐），u16

	bpfAlignment = 4 // BPF_ALIGNMENT = sizeof(int32_t)
)

// 那一族 ioctl 的号码。号码是 _IOR/_IOW/_IOWR 算出来的，里面就编着方向与结构体长度
// （比如 BIOCSETIF=0x8020426c → 长度格 0x20=32，正好 sizeof(struct ifreq)），
// 所以这张表能自查，不必信任何人的记忆 —— 见测试里那条按号码反量长度的。
const (
	iocSetBlen = 0xc0044266 // BIOCSBLEN（_IOWR，u_int）：必须在 BIOCSETIF 之前设
	iocGetBlen = 0x40044266 // BIOCGBLEN（_IOR，u_int）：内核认下来的读缓冲大小
	iocSetIf   = 0x8020426c // BIOCSETIF（_IOW，struct ifreq）
	iocGetIf   = 0x4020426b // BIOCGETIF（_IOR，struct ifreq）
	iocGetDlt  = 0x4004426a // BIOCGDLT（_IOR，u_int）：这个口的链路类型号
	iocSetFlt  = 0x80104267 // BIOCSETF（_IOW，struct bpf_program）：这一档不下过滤器
	iocFlush   = 0x20004268 // BIOCFLUSH（_IO）：清缓冲，顺带把 BIOCGSTATS 那两份计数归零
	iocPromisc = 0x20004269 // BIOCPROMISC（_IO）
	iocSetRTO  = 0x8010426d // BIOCSRTIMEOUT（_IOW，struct timeval —— native 那一份）
	iocStats   = 0x4008426f // BIOCGSTATS（_IOR，struct bpf_stat：bs_recv/bs_drop 各 u32）
	iocImmed   = 0x80044270 // BIOCIMMEDIATE（_IOW，u_int）
	iocVersion = 0x40044271 // BIOCVERSION（_IOR，struct bpf_version：major/minor 各 u16）

	bpfMajorVersion = 1 // BPF_MAJOR_VERSION：记录格式那一版

	ifreqSize    = 32 // sizeof(struct ifreq)：名字 16 + 那片 union（放 sockaddr）16
	ifreqNameOff = 0
	ifreqAddrOff = 16 // ifr_addr 的落点（内核只认名字，那两格按结构摆好即可）

	bpfStatSize = 8 // sizeof(struct bpf_stat)

	dltNull     = 0   // DLT_NULL：macOS 的 lo0 与 utun 都是它（前面四字节是地址族）
	dltEN10MB   = 1   // DLT_EN10MB
	dltRaw      = 12  // DLT_RAW（★ 不等于 LINKTYPE_RAW 那个 101）
	dltIEEE802  = 105 // DLT_IEEE802_11
	dltRadioTap = 127 // DLT_IEEE802_11_RADIO
)

// maxBpfDevices 是找空闲 bpf 设备的上限。手册页说最后一台次要设备被打开时内核会按需再造一台，
// 总数由 debug.bpf_maxdevices 管着（这台机器上实测就是 256）—— 所以这个上限只是
// 「别绕圈绕到天荒地老」，真正的数由内核说了算；撞上去了报错时把那一格的名字写进话里，
// 人才知道去哪儿看。
const maxBpfDevices = 256

// bpfBufFloor/bpfBufCeil 是要内核开的读缓冲那一格的上下限。两个数都不是挑的，
// 是这台机器上 sysctl 读回来的内核自己那几格：
//
//	debug.bpf_bufsize     = 4096      内核默认那一份（比这还小就是让内核自己定，没必要）
//	debug.bpf_maxbufsize  = 524288
//	debug.bpf_bufsize_cap = 33554432  要超过它不是「慢一点」，是白要
//
// ★ 中间那一格管不管用户请求，bpf(4) 没写，而 BIOCSBLEN 要 root 才实测得了 ——
//
//	所以这里只取最靠得住的那一条：内核**有权**把我们要的数改小（手册页：closest
//	allowable size will be set and returned），改小不是错。这一档只在改小到
//	「装不下一条我们要留的记录」时才拦（见 settleBpfBuf）。
const (
	bpfBufFloor = 4096
	bpfBufCeil  = 32 << 20
)

// maxBpfWireLen 是「线上长度」那一格还肯记账的上限。
// 挡的不是溢出，是形状：真实帧长（Jumbo 也就 9K 那一档）远够不着这个数，
// 够得着的都是「我们把别的东西当成记录头读了」—— 与其把 4GB 当一包写进报表，
// 不如在这儿停下。取 2^31-1 还有一层保险：Packet.OrigLen 是 int，
// 这一格永远在正数范围内，将来出 32 位档也不会绕。
const maxBpfWireLen = 1<<31 - 1

func bpfWordAlign(n int) int { return (n + bpfAlignment - 1) &^ (bpfAlignment - 1) }

// pollEvery 是一轮等的上限：Close 靠这一格把正阻塞在 Next 上的那一路放出去。
const pollEvery = 100 * time.Millisecond

// OpenSource 起一路采集。Interface 为空 = 这台机器上所有口，各起一路。
// 一路一个 bpf 设备是刻意的：一台设备只能绑一个口，而记录里压根没有「这一包来自哪个口」那一格。
func OpenSource(opt Options) (Source, error) {
	if opt.SnapLen < 0 || opt.BufferSize < 0 {
		return nil, fmt.Errorf("capture: 留长与缓冲大小不能为负（留长 %d、缓冲 %d）", opt.SnapLen, opt.BufferSize)
	}
	if opt.Timestamp == TSHardware {
		// 当场说，不等开了设备再说：bpf 那一格时刻是包过过滤器时内核打的，压根没有网卡打戳这条路。
		// 也不许退成软件时刻 —— 拿它算出来的延迟会差一截，而报表上完全看不出来。
		return nil, fmt.Errorf("capture: 这一档给不了硬件时刻（bpf 的戳一律是内核收包时打的），不换软件时刻凑数：%w", ErrUnsupported)
	}
	names, err := sourceIfaces(opt.Interface)
	if err != nil {
		return nil, err
	}
	kq, err := syscall.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("capture: 开不出等包用的 kqueue：%w", err)
	}
	s := &darwinSource{kq: kq}
	for i, name := range names {
		d, err := newBpfDev(name, i, opt)
		if err != nil {
			// 半开的口留在原地，就是「说没起来、实际还在收」那种最难查的账。
			s.Close()
			return nil, err
		}
		// 注册一次就够：kqueue 记着这一份清单，后面每轮只问「谁有事」。
		if _, err := syscall.Kevent(kq, []syscall.Kevent_t{readInterest(d.fd)}, nil, nil); err != nil {
			s.Close()
			return nil, fmt.Errorf("capture: 口 %s 挂不上等包的那张清单：%w", name, err)
		}
		s.devs = append(s.devs, d)
		s.ifaces = append(s.ifaces, d.iface)
	}
	return s, nil
}

func readInterest(fd int) syscall.Kevent_t {
	var k syscall.Kevent_t
	syscall.SetKevent(&k, fd, syscall.EVFILT_READ, syscall.EV_ADD)
	return k
}

type darwinSource struct {
	devs   []*bpfDev
	ifaces []Interface
	kq     int
	closed atomic.Bool
	pkts   atomic.Uint64
	mu     sync.Mutex
}

// bpfDev 是一个口一台 bpf 设备。缓冲里的游标只在 Next 那一条路上走（这一路不加锁），
// mu 只用来让 Close 别抢在一个正读着的 fd 上。
type bpfDev struct {
	name  string
	fd    int
	iface Interface
	ifIdx int
	snap  int

	blen int    // 内核认下来的读缓冲大小：read 必须正好要这么多字节
	buf  []byte // 复用一份，长度恒等于 blen
	pos  int    // buf 里下一条记录的起点
	n    int    // buf 里这一次读上来的有效字节数

	drops atomic.Uint64 // bs_drop 那一份（自打开以来的累计数，手册页定了口径）
	bad   error         // 一落下就停下：这一版内核的记录格式跟我们这张表对不上
	mu    sync.Mutex
}

func newBpfDev(name string, idx int, opt Options) (*bpfDev, error) {
	fd, err := openBpfDevice()
	if err != nil {
		return nil, fmt.Errorf("capture: 口 %s 起不来：%w", name, err)
	}
	d := &bpfDev{fd: fd, name: name, ifIdx: idx, snap: opt.SnapLen}
	if d.snap == 0 {
		d.snap = DefaultSnapLen
	}
	fail := func(err error) (*bpfDev, error) {
		syscall.Close(fd)
		return nil, err
	}
	want, err := planBpfBuf(opt.BufferSize, d.snap)
	if err != nil {
		return fail(err)
	}
	// 顺序是手册页定的：BIOCSBLEN 必须在绑口之前（「The buffer must be set before
	// the file is attached to an interface with BIOCSETIF」）。反过来设不会报错，
	// 只会让内核按默认那一格分配，我们再按自己要的数去 read —— EINVAL。
	if _, errno := ioctlUint(fd, iocSetBlen, uint32(want)); errno != 0 {
		return fail(fmt.Errorf("capture: 口 %s 要 %d 字节读缓冲失败：%w", name, want, errno))
	}
	if err := attachIface(fd, name); err != nil {
		return fail(err)
	}
	// 内核可能把我们要的数改成它允许的那一格（「closest allowable size will be set and
	// returned」），所以最终按 BIOCGBLEN 读回来的这个数分配 —— 不是按我们要的数。
	blen, errno := ioctlUint(fd, iocGetBlen, 0)
	if errno != 0 {
		return fail(fmt.Errorf("capture: 问不到口 %s 的读缓冲大小：%w", name, errno))
	}
	settled, err := settleBpfBuf(want, int(blen), d.snap, name)
	if err != nil {
		return fail(err)
	}
	if err := checkBpfVersion(fd, name); err != nil {
		return fail(err)
	}
	dlt, errno := ioctlUint(fd, iocGetDlt, 0)
	if errno != 0 {
		return fail(fmt.Errorf("capture: 问不到口 %s 的链路类型：%w", name, errno))
	}
	linkType, ok := linkTypeOfDLT(uint16(dlt))
	if !ok {
		return fail(fmt.Errorf("capture: 口 %s 的链路类型号是 %d，这一档还认不下（宁可不抓，也别把它当以太网解）", name, dlt))
	}
	// 每来一包就让 read 能拿到（默认是关的）。不打开这一格的话，低流量时包一直躺在内核缓冲里，
	// 界面上就是「抓到了但看不见」，看着像网络没流量 —— 这一格在这档上就是 Linux 那档的「块退休」。
	// ★ 也正因为开了它，Options.BlockRetire 在这一档没有对应物：不是忽略了它，
	//   是这一档本来就做到「来一包给一包」，比那个上限更快。
	if _, errno := ioctlUint(fd, iocImmed, 1); errno != 0 {
		return fail(fmt.Errorf("capture: 口 %s 开不来了即收：%w", name, errno))
	}
	// 读超时那一格给的是 native timeval（16 字节），不是记录头里那份 timeval32：
	// 两件事别混 —— ioctl 号码里那格长度就是 0x10，摆 8 字节进去内核读到的是半句。
	to := syscall.NsecToTimeval(int64(pollEvery))
	if errno := ioctlPtr(fd, iocSetRTO, unsafe.Pointer(&to)); errno != 0 {
		return fail(fmt.Errorf("capture: 口 %s 定不成读超时：%w", name, errno))
	}
	if opt.Promisc {
		if errno := ioctlNone(fd, iocPromisc); errno != 0 {
			return fail(fmt.Errorf("capture: 口 %s 开不成混杂模式：%w", name, errno))
		}
	}
	d.blen = settled
	d.buf = make([]byte, d.blen)
	d.iface = Interface{
		Name:        name,
		Description: "netkit 采集口",
		LinkType:    linkType,
		SnapLen:     uint32(d.snap),
		tsUnit:      time.Microsecond, // 记录头里那一格就是微秒
	}
	return d, nil
}

// planBpfBuf 定「要内核开多大的读缓冲」。
//
// ★ 这里的口径和 Linux 那档不是一回事，别说混了：Linux 那一格是整条环（好多块），
//
//	这一档的一格是「一次 read 能拿上来的那一大块」。包比这一格大时内核会截
//	（手册页：an individual packet larger than this size is necessarily truncated），
//	所以这一格至少要装得下「一条记录头 + 我们要留的那一份」——
//	不然用户要 1600、内核只给截到 1500，那是替用户改了他下的口径。
func planBpfBuf(bufferSize, snapLen int) (int, error) {
	if snapLen < 0 {
		return 0, fmt.Errorf("capture: 留长不能为负（%d）", snapLen)
	}
	if bufferSize < 0 {
		return 0, fmt.Errorf("capture: 缓冲大小不能为负（%d）", bufferSize)
	}
	if snapLen == 0 {
		snapLen = DefaultSnapLen
	}
	// 留长单独先挡一道：不挡的话下面那句「缓冲至少装得下一条记录」会把留长顶成缓冲，
	// 报错就变成「读缓冲要 40 亿字节，超过上限」——名字不对的那一格被拿去挨骂。
	// 这一格是界面上能填的（#92），所以在门口就要按「留长」这个名字把它拒了。
	if int64(bpfHdrSize)+int64(snapLen) > bpfBufCeil {
		return 0, fmt.Errorf("capture: 留长 %d 字节，连一条记录都超出这一档的上限 %d", snapLen, bpfBufCeil)
	}
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	need := bpfWordAlign(bpfHdrSize + snapLen)
	if need < bpfBufFloor {
		need = bpfBufFloor
	}
	if bufferSize < need {
		bufferSize = need // 「缓冲比一条记录还小」不是用户的真意，按最小可用顶上
	}
	if bufferSize > bpfBufCeil {
		return 0, fmt.Errorf("capture: 读缓冲要 %d 字节，超过这一档的上限 %d（留长 %d）", bufferSize, bpfBufCeil, snapLen)
	}
	return bufferSize, nil
}

// settleBpfBuf 认「内核最终给的那一格读缓冲」。
//
// ★ 内核把数改小是合法行为，不是失败：手册页写得很明白 —— 「如果请求的那一档容不下，
//
//	就把最接近的可用值设回去并通过参数返回」。所以这里唯一该拦的是
//	「小到装不下一条我们要留的记录」——那种情况下 read 会 EINVAL，
//	而界面上看着就是「这个口一个包都没有」。
//	比我们要的小但仍装得下记录，就照内核那一份走：这一档的 read 必须按内核那格要字节，
//	按自己原来要的数去读才是真出事（BUGS 那一节：不是这个大小的缓冲，read 直接 EINVAL）。
//
// 拆成函数而不是留在 newBpfDev 里，是因为这一格判断不要权限，能测。
func settleBpfBuf(want, got, snapLen int, name string) (int, error) {
	if got <= 0 {
		return 0, fmt.Errorf("capture: 口 %s 上内核把读缓冲报成 %d 字节 —— 这一档没法按这个数去 read", name, got)
	}
	need := bpfWordAlign(bpfHdrSize + snapLen)
	if need < bpfBufFloor {
		need = bpfBufFloor
	}
	if got < need {
		return 0, fmt.Errorf("capture: 口 %s 上内核只肯给 %d 字节读缓冲，装不下一条留长 %d 的记录（要 %d）—— 不退成「截一半照样报」",
			name, got, snapLen, need)
	}
	return got, nil
}

// openBpfDevice 找一台空闲的 bpf 设备。/dev/bpfn 每一台只能被一个进程占着，占了就 EBUSY；
// 而最后一台被打开时内核会按需再造一台（总数看 debug.bpf_maxdevices）。
func openBpfDevice() (int, error) {
	lastErr := error(syscall.ENOENT)
	for i := 0; i < maxBpfDevices; i++ {
		path := "/dev/bpf" + strconv.Itoa(i)
		fd, err := syscall.Open(path, syscall.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		lastErr = err
		switch {
		case err == syscall.EBUSY:
			continue // 这台被别人占着，试下一台
		case err == syscall.EACCES || err == syscall.EPERM:
			// ★ 设备表是 crw------- root wheel：非特权用户第一台就打不开。
			//   这里不绕圈试到 256 台 —— 那不是「换一台就通了」，那是一句不用往下走的「要 root」。
			return -1, fmt.Errorf("%s 打不开（要 root）：%w", path, ErrNeedPrivilege)
		case err == syscall.ENOENT || err == syscall.ENXIO:
			// 这一台压根没造出来。内核会按需造，但我们不替它造系统改动（那是 root 的活），
			// 所以到此为止，并把去哪儿看上限这句话给人。
			return -1, fmt.Errorf("空闲设备用完了（试到 %s，%v）—— 能用的台数由内核那一格 debug.bpf_maxdevices 管着", path, lastErr)
		default:
			// 别的一律如实回（EMFILE/ENFILE 这类）：绕满 256 台会把「打开的文件太多了」
			// 报成「256 台设备都没占上」，人拿着这句去查谁在抓包，而真因在别处。
			return -1, fmt.Errorf("%s 打不开：%w", path, err)
		}
	}
	return -1, fmt.Errorf("%d 台设备都没占上（最后一句：%v）—— 有没有别的东西在抓同样的口", maxBpfDevices, lastErr)
}

// attachIface 用 BIOCSETIF 把这台设备绑到口名上：内核只认 ifr_name 那 16 字节。
func attachIface(fd int, name string) error {
	if len(name) >= 16 {
		return fmt.Errorf("capture: 口名 %q 太长，这一档的 ifreq 只装得下 15 个字符", name)
	}
	var req [ifreqSize]byte
	copy(req[ifreqNameOff:], name)
	if errno := ioctlPtr(fd, iocSetIf, unsafe.Pointer(&req[0])); errno != 0 {
		return fmt.Errorf("capture: 口 %s 绑不上（%w）", name, wrapIfaceErr(errno))
	}
	return nil
}

func wrapIfaceErr(err error) error {
	switch err {
	case syscall.EACCES, syscall.EPERM:
		return fmt.Errorf("要 root：%w", ErrNeedPrivilege)
	case syscall.ENODEV:
		return fmt.Errorf("这台机器上没有这个口：%w", ErrNoSuchInterface)
	}
	return err
}

// checkBpfVersion 问一句「内核写记录头的这一版还是不是我们这张表」。
// 对不上就停下：读错格式不会崩，只会把链路头的第二个字节当成时刻的低位，
// 于是一份错账绿着通过。
func checkBpfVersion(fd int, name string) error {
	var v [4]byte
	if errno := ioctlPtr(fd, iocVersion, unsafe.Pointer(&v[0])); errno != 0 {
		return fmt.Errorf("capture: 问不到口 %s 的 bpf 版本：%w", name, errno)
	}
	if major := binary.NativeEndian.Uint16(v[0:]); major != bpfMajorVersion {
		return fmt.Errorf("capture: 口 %s 上的内核说的是 bpf 记录格式第 %d 版，这一档只认第 %d 版 —— 停下来，别按猜的读",
			name, major, bpfMajorVersion)
	}
	return nil
}

// linkTypeOfDLT 把 BSD 的 DLT_* 换成 pcapng 的链路类型号。
//
// ★ 别按「数字一样」推：这两处就是不一样的 —— DLT_RAW 是 12 而 LINKTYPE_RAW 是 101，
//
//	DLT_PPP 是 9 而 LINKTYPE_PPP 是 15。认不出的如实返回 false：
//	写错号不会报错，只会让上层把裸 IP 当以太网解，解出来的「源地址」是链路头的前四字节。
func linkTypeOfDLT(dlt uint16) (uint16, bool) {
	switch dlt {
	case dltNull:
		return LinkTypeNull, true
	case dltEN10MB:
		return LinkTypeEN10MB, true
	case dltRaw: // BSD 的 12 号 → pcapng 的 101 号
		return LinkTypeRaw, true
	case dltIEEE802:
		return LinkTypeIEEE80211, true
	case dltRadioTap:
		return LinkTypeRadioTap, true
	}
	return 0, false
}

// ==================== ioctl 那一层 ====================
//
// 三个入口按「内核那一格要几个字节」分开：号码里已经编着长度，所以调用处只递指针；
// 长度留在注释与测试里对账（见 Test 里那条按 ioctl 号码反量结构体长度的）。

func ioctlPtr(fd, request int, arg unsafe.Pointer) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(arg))
	return errno
}

func ioctlNone(fd, request int) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(request), 0)
	return errno
}

// ioctlUint 处理 u_int 那一族。BIOCSBLEN 是 _IOWR：内核会把最终认下来的数写回同一格，
// 所以递指针进去、把返回的数读回来，不能拿自己要的那个数当答案。
func ioctlUint(fd, request int, in uint32) (uint32, syscall.Errno) {
	v := in
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(unsafe.Pointer(&v)))
	return v, errno
}

// ==================== 取包 ====================

// bpfRecord 是缓冲里一条「记录头 + 数据」的落点。
type bpfRecord struct {
	ts      time.Time
	caplen  int
	datalen int
	data    []byte
	stride  int // 到下一条记录要走多少字节
}

// nextBpfRecord 读缓冲开头那一条记录，并算出到下一条的步长。
//
// 步长是手册页给的式子：BPF_WORDALIGN(bh_hdrlen + bh_caplen) —— 每一包都补齐到整格，
// 所以「一条记录多大」只能问内核给的那两格，不能按 sizeof(头) 一格一格数。
// 数错了不报错，只会把上一包的尾巴当成下一包的开头（Linux 那档同一个脾性）。
func nextBpfRecord(buf []byte) (bpfRecord, error) {
	if len(buf) < bpfHdrSize {
		return bpfRecord{}, fmt.Errorf("capture: 缓冲里只剩 %d 字节，连一条记录头（%d 字节）都放不下", len(buf), bpfHdrSize)
	}
	// 这几格是内核按本机字节序写的（手册页：values are stored in host order），不是网络序。
	sec := int32(binary.NativeEndian.Uint32(buf[bpfSecOff:]))
	usec := int32(binary.NativeEndian.Uint32(buf[bpfUsecOff:]))
	caplenU := binary.NativeEndian.Uint32(buf[bpfCaplenOff:])
	datalenU := binary.NativeEndian.Uint32(buf[bpfDatalenOn:])
	hdrlen := int(binary.NativeEndian.Uint16(buf[bpfHdrLenOff:]))

	// ★ 长度那两格从头到尾按 u32 读、按 int64 比，中途不换成 int 再判。
	//   这一档只有 64 位（Go 早就不出 darwin/386），落进 int 眼下不会绕回负数 ——
	//   但那样「比缓冲还长」那一挡就成了只有部分平台生效的判定，
	//   而 0xffffffff 那一格会被当成 4294967295 原样写进报表里的「线上长度」：
	//   看着像一个说不清的巨型包，而它真正的意思是「读的压根不是记录头」。
	//   所以先按 u32 挡住，再把过完挡的那一对换算成 int（这一对在哪个平台都装得下）。
	if hdrlen < bpfHdrSize {
		return bpfRecord{}, fmt.Errorf("capture: 这一包的包头只有 %d 字节，比这张表理解的记录头（%d）还短 —— 布局和我们对不上，停下来",
			hdrlen, bpfHdrSize)
	}
	if usec < 0 || usec >= int32(time.Second/time.Microsecond) {
		// 内核写的微秒永远在 [0,1e6)。这一格对不上，读到的就不是 timeval32 那一份形状
		// （把 native timeval 当它读，微秒那格就成了 caplen）—— 与其产出一份时刻飞到
		// 几十年外、而包数和长度全对的账，不如在这儿停下来说「布局对不上」。
		return bpfRecord{}, fmt.Errorf("capture: 这一包的微秒那一格是 %d，落在 [0,%d) 之外 —— 时刻的形状与我们这张表对不上，停下来",
			usec, int32(time.Second/time.Microsecond))
	}
	if int64(datalenU) > maxBpfWireLen {
		return bpfRecord{}, fmt.Errorf("capture: 这一包的线上长度是 %d 字节，超出这一档能记账的那一格（%d）—— 真帧长远够不着这个数，落在这儿说明读的不是记录头，停下来",
			datalenU, maxBpfWireLen)
	}
	if caplenU > datalenU {
		// 手册页定了 caplen = min(过滤器要的那一份, 线上长度)，这条永远该成立；
		// 不成立就是这一版内核的记录不是我们认的那一种。
		return bpfRecord{}, fmt.Errorf("capture: 这一包留了 %d 字节，线上却只有 %d —— 留长不可能比原文还长，停下来", caplenU, datalenU)
	}
	if int64(hdrlen)+int64(caplenU) > int64(len(buf)) {
		return bpfRecord{}, fmt.Errorf("capture: 这一包说留了 %d 字节、头占 %d，缓冲里只剩 %d —— 这一半是断的，不许拼出去",
			caplenU, hdrlen, len(buf))
	}
	caplen, datalen := int(caplenU), int(datalenU) // 过完上面那几挡，这一对换算在哪个平台都装得下。
	return bpfRecord{
		// 秒那一格只占 4 字节（timeval32 里声明的就是 int32），按有符号扩位：
		// 与 libpcap 那一份读法一致（它也是直接从 struct timeval32 取的）。
		// 2038 年之前两种读法一模一样，差别只在 32 位秒数绕回去之后 —— 那是这一份
		// 记录格式自己的上限，不是我们读错；真到那一年，全机用 timeval32 的都一起偏。
		ts:      time.Unix(int64(sec), int64(usec)*int64(time.Microsecond)),
		caplen:  caplen,
		datalen: datalen,
		data:    buf[hdrlen : hdrlen+caplen],
		stride:  bpfWordAlign(hdrlen + caplen),
	}, nil
}

func (s *darwinSource) Next() (Packet, error) {
	for {
		if s.closed.Load() {
			return Packet{}, ErrClosed
		}
		for _, d := range s.devs {
			p, ok, err := d.takeBuffered()
			if err != nil {
				return Packet{}, err
			}
			if ok {
				s.pkts.Add(1)
				return p, nil
			}
		}
		i, err := s.waitReady()
		if err != nil {
			return Packet{}, err
		}
		if i < 0 {
			continue // 到点：什么都没有，回头再看一眼是不是要关
		}
		if err := s.devs[i].refill(); err != nil {
			return Packet{}, err
		}
	}
}

// waitReady 用 kqueue 问「哪一路有动静」，最多等 pollEvery。回 -1 = 到点（到点不算错：Close 靠这一格放行）。
//
// ★ 用 kqueue 不用 select：select 那份 fd_set 只到 1024 号，而 macOS 上「所有口」动辄几十块
//
//	（utun 一人一条），第 1025 个 fd 会被静默漏掉 —— 表现为「某一路的包永远不来」，
//	比报错难查。另一条：注册清单在 OpenSource 里一次挂好，这里只问不挂，
//	免得每轮把整张清单重报一遍（那是白花的系统调用）。
func (s *darwinSource) waitReady() (int, error) {
	s.mu.Lock()
	kq := s.kq
	s.mu.Unlock()
	if kq < 0 {
		return 0, ErrClosed
	}
	ev := make([]syscall.Kevent_t, len(s.devs))
	to := syscall.NsecToTimespec(int64(pollEvery))
	n, err := syscall.Kevent(kq, nil, ev, &to)
	if err != nil {
		switch err {
		case syscall.EINTR:
			return -1, nil // 被信号打断不算事：这一轮当到点，回头再看要不要关
		case syscall.EBADF:
			return 0, ErrClosed // Close 抢先了：本来就不要再等
		}
		return 0, fmt.Errorf("capture: 等包等坏了：%w", err)
	}
	for _, e := range ev[:n] {
		for i, d := range s.devs {
			if int64(e.Ident) == int64(d.fd) {
				return i, nil
			}
		}
	}
	return -1, nil
}

// refill 从内核拿一大块（read 必须正好要 blen 字节，手册页在 BUGS 那一节写死了），
// 然后把游标放到第一条记录上。
func (d *bpfDev) refill() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fd < 0 {
		return ErrClosed
	}
	if d.bad != nil {
		return d.bad
	}
	d.pos, d.n = 0, 0
	n, err := syscall.Read(d.fd, d.buf)
	switch {
	case err == syscall.EINTR, err == syscall.EAGAIN:
		return nil // 被打断 / 这一轮没东西：回头再等
	case err == syscall.EIO:
		// 等超时了这一格是 BSD 那一族的老脾气，只在「没等到包」时出，所以算一轮空手，
		// 不算这一路坏了。
		// ★ 这一条没在这台机器上核过：bpf(4)（macOS 15.6）压根没写超时回什么 errno，
		//   而 /dev/bpf 要 root 才打得开。写在这儿是按「只在不给包时出来」讲的，不敢当已证。
		return nil
	case err != nil:
		d.bad = fmt.Errorf("capture: 口 %s 读坏了：%w", d.name, err)
		return d.bad
	}
	if n == 0 {
		return nil
	}
	if n > d.blen {
		d.bad = fmt.Errorf("capture: 口 %s 一次读上来 %d 字节，比内核自己说的缓冲（%d）还多 —— 这一档的账没法记了",
			d.name, n, d.blen)
		return d.bad
	}
	d.n = n
	return nil
}

// takeBuffered 交一条已经在手上的记录。
func (d *bpfDev) takeBuffered() (Packet, bool, error) {
	if d.bad != nil {
		return Packet{}, false, d.bad
	}
	if d.pos >= d.n {
		return Packet{}, false, nil
	}
	rec, err := nextBpfRecord(d.buf[d.pos:d.n])
	if err != nil {
		d.bad = err
		return Packet{}, false, err
	}
	data := make([]byte, rec.caplen)
	copy(data, rec.data)
	if d.snap > 0 && len(data) > d.snap {
		// ★ 这一档的留长是本地截的，不像 Linux 那档由内核按帧大小留：bpf 要按留长截得写过滤器
		//   （BIOCSETF 那一段 cBPF），这一档不下 —— 所以「线上多长」照原样报（OrigLen），
		//   只是不把比留长多的那一份递给上层。两种口径在报表上是同一句话，不能装成一种。
		data = data[:d.snap]
	}
	stride := rec.stride
	d.pos += stride
	return Packet{
		InterfaceIndex: d.ifIdx,
		Timestamp:      rec.ts,
		HasTimestamp:   true,
		Data:           data,
		OrigLen:        rec.datalen,
	}, true, nil
}

// Stats 报这一路的账。
//
// ★ 口径与 Linux 那档有一处必须说清的差别：BIOCGSTATS 那两份是「自打开或重置以来」的
//
//	累计数（bpf(4) 原文：since opened or reset），不是读一次清一次。
//	所以这里直接报，不再自己累 —— 累一遍就成了越问越大的假数。
//	而「重置」那一头是 BIOCFLUSH，它顺带把已经收着的包一起清掉，所以我们绝不调它：
//	为了一个计数丢掉真抓到的包，是本末倒置。
//
// Lossy 这一格在这档上如实留 false：bpf 没有「在这一包上标个丢过」的机制，只有上面那份计数。
// 拿 bs_drop>0 去填它，等于同一个数报两遍、还冒充了另一种凭据。
func (s *darwinSource) Stats() Stats {
	st := Stats{Interfaces: len(s.devs), Packets: s.pkts.Load()}
	for _, d := range s.devs {
		if drops, ok := d.kernelDrops(); ok {
			d.drops.Store(drops)
		}
		st.Dropped += d.drops.Load()
	}
	return st
}

// kernelDrops 问 bs_drop。拿不到就如实回 ok=false —— 这一格不许猜：
// 报个 0 说是「没丢」，现场就会照着这句去查网卡。
func (d *bpfDev) kernelDrops() (uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fd < 0 {
		return 0, false
	}
	var b [bpfStatSize]byte
	if errno := ioctlPtr(d.fd, iocStats, unsafe.Pointer(&b[0])); errno != 0 {
		return 0, false
	}
	return uint64(binary.NativeEndian.Uint32(b[4:])), true
}

func (s *darwinSource) Interfaces() []Interface {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Interface(nil), s.ifaces...)
}

func (s *darwinSource) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // 关两次不算一次错
	}
	s.mu.Lock()
	kq := s.kq
	s.kq = -1
	s.mu.Unlock()

	var firstErr error
	if kq >= 0 {
		if err := syscall.Close(kq); err != nil {
			firstErr = fmt.Errorf("capture: 等包那张清单关不掉：%w", err)
		}
	}
	for _, d := range s.devs {
		d.mu.Lock() // 有 read 在飞就等这一轮完（最多 pollEvery），不抢在 fd 被人用着时关掉
		if d.fd >= 0 {
			if err := syscall.Close(d.fd); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("capture: 口 %s 关不掉：%w", d.name, err)
			}
			d.fd = -1
		}
		d.mu.Unlock()
	}
	return firstErr
}
