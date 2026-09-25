//go:build linux

// Linux 这一档：AF_PACKET 裸 socket + TPACKET_V3 环，纯 syscall，不链 libpcap。
//
// 口径（docs/设计.md「抓包引擎自研方案」）：libpcap 本身就是这一层的封装，
// 不必再依赖它 —— 但行为要照着它核对，因为现场给的参照就是 tcpdump 抓的那一份。
//
// ★ 三处最容易做错的，都在这份文件里，且都是拿容器里内核真填出来的环对出来的：
//  1. 环的那四个数（块大小 / 块数 / 帧大小 / 帧数）算错，内核只回一句 EINVAL，
//     什么都不细说 —— 所以全在 ringPlan 里先按「块是页的整数倍、帧数=每块帧数×块数」算对。
//  2. V3 是按块退休的：块没装满就不交给用户。低流量时界面会「抓到了但看不见」，
//     看着就像网络没流量 —— 所以 retire 那一档必须给非 0 的值，且不许当 0 用。
//  3. 块里的包是按 tp_next_offset 紧挨着排的，不是按帧大小一格一格排的
//     （实测：帧大小 1680，块里两包的步长是 184）。拿帧大小当步长走，
//     第二包就读到上一包后面那片空字节去了 —— 不报错，只是解出来一堆乱码。
//
// 另有一条：环里的字节是内核按本机字节序写的（不是网络序，也不是 pcapng 那套小端）。
// 读错端序不报错，只会把「秒」读成一个巨大的数、时刻飞到几十年后。
package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// 内核 uapi（linux/if_packet.h）里那些字节的落点。
//
// ★ 为什么手写偏移而不带 golang.org/x/sys：这一层不许有第三方依赖。
//
//	代价是读错偏移不会崩 —— 它只会把「链路头的第二个字节」当成时刻的高位，
//	于是一份错账绿着通过。所以每一格都用内核真填出来的环对过一遍，
//	见 source_linux_test.go 里那条「用现场环字节钉住这张表」的测试。
const (
	t3NextOffset = 0  // tp_next_offset：块里到下一包的步长（最后一包给 0）
	t3Sec        = 4  // tp_sec：时刻的秒
	t3Nsec       = 8  // tp_nsec：纳秒（V3 的戳就是纳秒一格）
	t3Snaplen    = 12 // 落进环的那一份长度
	t3Len        = 16 // 线上那一份长度 —— 截过才知道丢了多少
	t3Status     = 20 // TP_STATUS_* 位
	t3Mac        = 24 // 链路头相对这一包包头的偏移（u16，实测 82）
	t3Net        = 26 // 网络头相对包头的偏移（u16，实测 96 = 82+14）

	blkStatus   = 8  // block_status：低位为 1 = 这块已退休、归用户
	blkNumPkts  = 12 // 这一块里塞了几包
	blkFirstPkt = 16 // 第一包相对块首的偏移（实测 48，正好接在块头后面）
	blkLen      = 20 // 这一块有效的字节数（= 48 + 各包步长之和）
)

// 环与状态位的取值（同一份头文件）。
//
// ★ 状态位统一按 uint32 摆：TP_STATUS_TS_RAW_HARDWARE 就是 1<<31，写成 int 常量
//
//	在 32 位上直接编译不过（linux/386 要过闸门），而在 int 里比较又会把它当负数。
const (
	tpacketV3 = 2 // enum tpacket_versions 里的 V3（不是 3，别按名字猜）

	tpStatusKernel     uint32 = 0
	tpStatusUser       uint32 = 1 << 0  // 内核写完、交给用户
	tpStatusLosing     uint32 = 1 << 2  // 这一路丢过包（和 PACKET_STATISTICS 那份计数互相印证）
	tpStatusBlkTmo     uint32 = 1 << 5  // 这一块是超时强制交出来的，不是装满的
	tpStatusTSSoftware uint32 = 1 << 29 // 这一包的戳是内核打的（软件时刻）
	tpStatusTSRawHW    uint32 = 1 << 31 // 这一包的戳是网卡打的（硬件时刻）

	packetVersion       = 0xa  // PACKET_VERSION
	packetRxRing        = 0x5  // PACKET_RX_RING
	packetStatistics    = 0x6  // PACKET_STATISTICS：{收了多少, 丢了多少}，读一次内核就清一次
	packetTimestamp     = 0x11 // PACKET_TIMESTAMP
	packetAddMembership = 0x1
	packetMrPromisc     = 0x1
	ethPAAll            = 0x0003 // 送进 socket 前要按网络序翻一次（htons）

	// PACKET_TIMESTAMP 那一格收的是 linux/net_tstamp.h 里的 SOF_TIMESTAMPING_*，
	// 不是上面那几个 TP_STATUS_TS_* 位 —— 这两个名字只差几个字，塞错了内核不报错，
	// 它只是什么都不做（容器里实测：把 1<<29 塞进去一样回「成功」，抓到的包仍然是
	// 默认那一份戳）。所以两件事分开定：要哪一份戳按 SOF_* 说，戳是谁打的读 tp_status。
	tstampRxSoftware  = 8  // SOF_TIMESTAMPING_RX_SOFTWARE
	tstampRxHardware  = 4  // SOF_TIMESTAMPING_RX_HARDWARE
	tstampRawHardware = 64 // SOF_TIMESTAMPING_RAW_HARDWARE
)

// OpenSource 起一路采集。Interface 为空 = 这台机器上所有口，各起一路。
// 名字带着 Source 是因为 Open 那一格已经被「读一份现成的文件」占了 ——
// 两件事在界面上是两句话，函数名也不许共用一个。
//
// ★ 一路一个 socket 是刻意的：V3 的环里不带「这一包来自哪个口」那个号，
//
//	绑到 all 上会把 lo 和网卡的包混成一串，聚合出的流就说不清是哪条链路上的了。
func OpenSource(opt Options) (Source, error) {
	if opt.SnapLen < 0 || opt.BufferSize < 0 {
		return nil, fmt.Errorf("capture: 留长与环大小不能为负（留长 %d、环 %d）", opt.SnapLen, opt.BufferSize)
	}
	names, err := sourceIfaces(opt.Interface)
	if err != nil {
		return nil, err
	}
	pg := os.Getpagesize()
	s := &linuxSource{}
	for i, name := range names {
		ring, err := newIfaceRing(name, i, opt, pg)
		if err != nil {
			// 一路起不来就把已经起好的收干净：留半开的口在，界面上就是
			// 「说没起来、实际还在收」，那种账最难查。
			s.Close()
			return nil, err
		}
		s.rings = append(s.rings, ring)
		s.ifaces = append(s.ifaces, ring.iface)
	}
	return s, nil
}

// pollEvery 是一轮等的上限。Close 靠这一格把正阻塞在 Next 上的那一路放出去 ——
// 不去 close 一个正被 poll 着的 fd（那会和内核里的引用打架，读到的可能是别的 fd 的号）。
const pollEvery = 100 * time.Millisecond

type linuxSource struct {
	rings  []*ifaceRing
	ifaces []Interface
	closed atomic.Bool
	pkts   atomic.Uint64
	mu     sync.Mutex
}

// ifaceRing 是一个口一份环。环里的读游标只在 Next 那一条路上走（这一路不加锁），
// Close 只碰 fd 与 mmap，两边靠「fd 填 -1 + 每步做边界检查」而不是靠锁。
type ifaceRing struct {
	name    string
	fd      int
	mmap    []byte
	iface   Interface
	ifIdx   int // 这一路在 Interfaces() 里的序号，包里的 InterfaceIndex 就是它
	snapLen int

	blockSize      int
	blockNr        int
	frameSize      int
	framesPerBlock int // 容量的名义口径（内核按步长塞，实际能塞更多）

	readIdx int // 下一个要认的块号
	cur     int // 正在读的块号，-1 = 手上没有块
	off     int // 下一个要读的包头，相对块首
	left    int // 当前块还剩几包没交
	end     int // 当前块的有效字节数（内核给的 blk_len）

	// ★ 这两格是原子写的，不是风格问题：Stats 与 Next 各在一条路上跑 —— 界面要的正是
	//   「一边抓一边看丢了几包」，用普通字段就是数据竞争（丢包数被撕成一半，
	//   lossy 那一格更坏：读到旧的 false，就把「确实丢过」报成「没丢」）。
	drops  atomic.Uint64 // 自己累起来的丢包数：内核那份计数读一次清一次，不累就只能报「上次到现在」
	lossy  atomic.Bool   // 内核在包上标过 TP_STATUS_LOSING
	wantHW bool          // 这一路要的是硬件时刻：逐个包核对内核标的戳是谁打的

	// bad 一旦落下就是「环的布局和我们这张表对不上」：后面每次读都回同一个错，
	// 不许继续按猜的往下走（那只会产出一份看着很正常的错账）。
	bad error
}

func newIfaceRing(name string, idx int, opt Options, pageSize int) (*ifaceRing, error) {
	ifIndex, arphrd, err := ifaceIndexAndType(name)
	if err != nil {
		return nil, err
	}
	linkType, ok := linkTypeOfARPHRD(arphrd)
	if !ok {
		return nil, fmt.Errorf("capture: 口 %s 的链路类型号是 %d，这一档还认不下（宁可不抓，也别把它当以太网解）", name, arphrd)
	}
	snapLen := opt.SnapLen
	if snapLen == 0 {
		snapLen = DefaultSnapLen
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htons(ethPAAll))
	if err != nil {
		return nil, wrapSocketErr(name, err)
	}
	r := &ifaceRing{
		fd:      fd,
		name:    name,
		ifIdx:   idx,
		snapLen: snapLen,
		cur:     -1,
		iface: Interface{
			Name:        name,
			Description: "netkit 采集口",
			LinkType:    linkType,
			SnapLen:     uint32(snapLen),
			tsUnit:      time.Nanosecond, // V3 的戳就是纳秒一格
		},
	}
	fail := func(err error) (*ifaceRing, error) {
		syscall.Munmap(r.mmap)
		r.mmap = nil
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetVersion, tpacketV3); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: 口 %s 定不成 TPACKET_V3：%w", name, err)
	}
	switch opt.Timestamp {
	case TSHardware:
		// ★ 要硬件时刻就只能硬要。但内核不在这里把关（容器里实测：一块给不了硬件戳的
		//   回环口，setsockopt 一样回成功，之后每个包上亮的全是软件时刻那一位），
		//   所以这一档把「要硬件戳」记在环上，读包时逐个核对 tp_status ——
		//   对不上就停下来报错，绝不退成软件时刻：拿它算出来的延迟会差一截，
		//   而报表上完全看不出来。
		if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetTimestamp,
			tstampRxHardware|tstampRawHardware); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("capture: 口 %s 定不成硬件时刻：%w", name, err)
		}
		r.wantHW = true
	case TSSoftware:
		if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetTimestamp, tstampRxSoftware); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("capture: 口 %s 定不成软件时刻：%w", name, err)
		}
	}
	blockSize, blockNr, frameSize, frameNr, err := ringPlan(opt.BufferSize, snapLen, pageSize)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: 口 %s 的环算不出来（留长 %d、环 %d 字节）：%w", name, snapLen, opt.BufferSize, err)
	}
	if err := setRxRing(fd, blockSize, blockNr, frameSize, frameNr, opt.BlockRetire); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: 口 %s 要环失败（块 %d×%d、帧 %d、留长 %d）：%w", name, blockSize, blockNr, frameSize, snapLen, err)
	}
	mmapBytes, err := syscall.Mmap(fd, 0, blockSize*blockNr, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: 口 %s 映不上环（%d 字节）：%w", name, blockSize*blockNr, err)
	}
	r.mmap, r.blockSize, r.blockNr, r.frameSize = mmapBytes, blockSize, blockNr, frameSize
	r.framesPerBlock = blockSize / frameSize
	// Halen 填 6：绑口时留了硬件地址长度，内核才会把这一路当「收这个口的全部包」。
	// 填 0 配上 Addr 全零，某些内核版本会按「只收发给全零地址的」过滤掉 —— 那就是一个包都没有。
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: uint16(htons(ethPAAll)),
		Ifindex:  ifIndex,
		Halen:    6,
	}); err != nil {
		return fail(fmt.Errorf("capture: 口 %s 绑不上（%w）", name, wrapSocketErr(name, err)))
	}
	if opt.Promisc {
		if err := setPromisc(fd, ifIndex); err != nil {
			return fail(fmt.Errorf("capture: 口 %s 开不成混杂模式：%w", name, err))
		}
	}
	return r, nil
}

func wrapSocketErr(name string, err error) error {
	switch err {
	case syscall.EPERM, syscall.EACCES:
		return fmt.Errorf("capture: 口 %s 起不来（要 root 或 CAP_NET_RAW）：%w", name, ErrNeedPrivilege)
	case syscall.ENODEV:
		return fmt.Errorf("capture: 口 %s 不在这台机器上：%w", name, ErrNoSuchInterface)
	case syscall.ENXIO:
		return fmt.Errorf("capture: 口 %s 没有对应的设备：%w", name, ErrNoSuchInterface)
	}
	return fmt.Errorf("capture: 口 %s 起不来：%w", name, err)
}

// setRxRing 把内核要的那 28 字节按 struct tpacket_req3 摆好。
// 自己摆字节是为了不给这一层带依赖，也为了把「哪一格是多少」写在明面上。
func setRxRing(fd, blockSize, blockNr, frameSize, frameNr int, retire time.Duration) error {
	var req [28]byte
	binary.NativeEndian.PutUint32(req[0:], uint32(blockSize))
	binary.NativeEndian.PutUint32(req[4:], uint32(blockNr))
	binary.NativeEndian.PutUint32(req[8:], uint32(frameSize))
	binary.NativeEndian.PutUint32(req[12:], uint32(frameNr))
	binary.NativeEndian.PutUint32(req[16:], uint32(retireMillis(retire)))
	// req[20:] 起是 sizeof_priv 与 feature_req_word，都留 0：
	// 不要私有区，也不要 VLAN 硬件卸载那些会让「抓到的帧」和线上不一致的花活。
	return setsockoptBytes(fd, syscall.SOL_PACKET, packetRxRing, req[:])
}

// retireMillis 把「一块最多攒多久」换成内核那一格的毫秒数。
// 0 是不允许的语义（装满才交），所以默认档顶上；负数一律按默认。
func retireMillis(d time.Duration) int {
	if d <= 0 {
		return int(DefaultBlockRetire / time.Millisecond)
	}
	ms := int(d / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	return ms
}

func setPromisc(fd, ifIndex int) error {
	// struct packet_mreq { int mr_ifindex; ushort mr_type; ushort mr_alen; ulong mr_address[] }
	// 只前两格要用得到，后两格留 0（混杂模式不看地址）。
	var mreq [12]byte
	binary.NativeEndian.PutUint32(mreq[0:], uint32(ifIndex))
	binary.NativeEndian.PutUint16(mreq[4:], packetMrPromisc)
	return setsockoptBytes(fd, syscall.SOL_PACKET, packetAddMembership, mreq[:])
}

// setsockoptBytes / getsockoptBytes 走的是「按口号叫内核」那一路（SOL_PACKET 的
// PACKET_RX_RING 要递 struct，标准库没有导出的对口函数）。真正的系统调用入口按架构分开：
// i386 上 socket 那一族只有一个门（socketcall），别的架构有各自的口号 ——
// 见 source_linux_386.go 与 source_linux_sock.go。
func setsockoptBytes(fd, level, opt int, b []byte) error {
	if len(b) == 0 {
		return syscall.EINVAL
	}
	if errno := rawSetsockopt(fd, level, opt, unsafe.Pointer(&b[0]), uintptr(len(b))); errno != 0 {
		return errno
	}
	return nil
}

// getsockoptBytes 回实际填了多少字节 —— 长度那一格是内核写给用户的，
// 拿它才知道这一版内核的 struct 比我们的表长还是短。
func getsockoptBytes(fd, level, opt int, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, syscall.EINVAL
	}
	n := uint32(len(b))
	if errno := rawGetsockopt(fd, level, opt, unsafe.Pointer(&b[0]), unsafe.Pointer(&n)); errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// sourceIfaces 把「要哪个口」落成口名列表。空 = 所有口
// （含 lo：现场往往只有回环上的东西抓得到，比如本机服务自己连自己）。
func sourceIfaces(want string) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("capture: 列不出网卡：%w", err)
	}
	if want == "" {
		out := make([]string, 0, len(ifs))
		for _, in := range ifs {
			out = append(out, in.Name)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("capture: 这台机器上一个口都列不出来")
		}
		return out, nil
	}
	for _, in := range ifs {
		if in.Name == want {
			return []string{want}, nil
		}
	}
	// ★ 点名的口不存在时直接报，不许退化成「那就全抓」：
	//   现场最常见的误判就是「抓了半天没有对方的包」，因为抓的是另一块网卡。
	return nil, fmt.Errorf("capture: 这台机器上没有叫 %q 的口（%w）", want, ErrNoSuchInterface)
}

// ifaceIndexAndType 找口的序号与 ARPHRD 类型。
// 类型走 ioctl(SIOCGIFHWADDR)：net 包把这一格藏起来了，而它决定了链路头怎么解 ——
// 拿「有没有 MAC 地址」猜，tun 口就会被当成以太网，解出来的源地址是一段随机字节。
func ifaceIndexAndType(name string) (ifIndex int, arphrd uint16, err error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, 0, fmt.Errorf("capture: 列不出网卡：%w", err)
	}
	for _, in := range ifs {
		if in.Name != name {
			continue
		}
		t, err := hwAddrType(name)
		if err != nil {
			return 0, 0, err
		}
		return in.Index, t, nil
	}
	return 0, 0, fmt.Errorf("capture: 这台机器上没有叫 %q 的口（%w）", name, ErrNoSuchInterface)
}

// hwAddrType 走 SIOCGIFHWADDR 拿 ARPHRD_*。
// ★ 单独开一个 socket 问，不与取序号共用一份 ifreq：那两格在 ifreq 里是同一片 union，
//
//	问完类型再回去读序号，拿到的是 MAC 地址的前四个字节（探针在这儿摔过一次）。
func hwAddrType(name string) (uint16, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, fmt.Errorf("capture: 开不出问网卡类型用的 socket：%w", err)
	}
	defer syscall.Close(fd)
	// struct ifreq：名字 16 字节，后面跟着 struct sockaddr（sa_family 在偏移 16 起那两字节）。
	var req [40]byte
	copy(req[:16], name)
	if err := ioctl(uintptr(fd), ioctlGifHWAddr, uintptr(unsafe.Pointer(&req[0]))); err != nil {
		return 0, fmt.Errorf("capture: 问不出口 %s 的链路类型：%w", name, err)
	}
	return binary.NativeEndian.Uint16(req[16:]), nil
}

const ioctlGifHWAddr = 0x8927 // SIOCGIFHWADDR

func ioctl(fd, request, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func (s *linuxSource) Next() (Packet, error) {
	for {
		if s.closed.Load() {
			return Packet{}, ErrClosed
		}
		for _, r := range s.rings {
			p, ok, err := r.takePacket()
			if err != nil {
				return Packet{}, err
			}
			if ok {
				s.pkts.Add(1)
				return p, nil
			}
		}
		if err := s.waitReady(); err != nil {
			return Packet{}, err
		}
	}
}

// waitReady 等任意一路有动静，最多等 pollEvery。到点不算错：Close 就靠这一格放行。
//
// ★ 用 poll 不用 select：select 那份 fd_set 只到 1024 号，而容器里一开就是几十个口，
//
//	第 1025 个 fd 会被静默漏掉 —— 表现为「某一路的包永远不来」，比报错更难查。
func (s *linuxSource) waitReady() error {
	for {
		_, err := pollRings(s.rings, int(pollEvery/time.Millisecond))
		if err == nil {
			return nil
		}
		if err == syscall.EINTR {
			continue // 被信号打断不算事（这一路里可能只是刚有别的东西动过）
		}
		if err == syscall.EBADF {
			return ErrClosed // Close 抢先了：这一路本来就不要再等
		}
		return fmt.Errorf("capture: 等包等坏了：%w", err)
	}
}

// pollfd 与 kernelTimespec 是内核那两格（struct pollfd / struct timespec）。
type pollfd struct {
	fd      int32
	events  int16
	revents int16
}

// kernelTimespec 的格子用 int 而不是 int64：内核那一格是 long ——
// 64 位上是 8 字节、32 位（linux/386 这类）上是 4 字节。写死 int64 的话，
// 32 位上内核读到的超时是「0 秒 0 纳秒」，poll 就变成不等的空转，
// CPU 吃满、包一个没等到，界面上看着像网络没流量。
type kernelTimespec struct {
	sec  int
	nsec int
}

const pollIn = 0x0001 // POLLIN：环里有退休的块时，这个 socket 就可读

// pollRings 调一次 ppoll(2)。标准库没把 Poll 摆出来（只在 net 包内部有），
// 所以照着内核的签名裸调一次 —— 传的是数组指针与长度，没有别的口径。
//
// ★ 用 ppoll 不用 poll：poll(2) 在 linux/arm64 上根本没有这个口号
//
//	（aarch64 只给 ppoll），照 poll 写就编不过 64 位 ARM 那一档。
//	信号掩码传 NULL、长度传 0，意思是「别动本线程的掩码」，与不挡信号等价。
//
// 返回的 n 是「有几路说有事」，0 就是到点了；这一层不靠它决定读谁，只靠块的状态位。
func pollRings(rings []*ifaceRing, ms int) (int, error) {
	pf := make([]pollfd, 0, len(rings))
	for _, r := range rings {
		if r.fd < 0 {
			continue // 已经关了的那一路：不许再拿一个失效的 fd 去等
		}
		pf = append(pf, pollfd{fd: int32(r.fd), events: pollIn})
	}
	if len(pf) == 0 {
		return 0, nil
	}
	var to kernelTimespec
	to.sec = ms / 1000
	to.nsec = (ms % 1000) * int(time.Millisecond)
	var top *kernelTimespec
	if ms >= 0 {
		top = &to
	} // ms < 0 = 一直等到有动静为止（这一层不用，Close 靠到点放行）
	// ★ 用 Syscall6 不用 RawSyscall6：这一格是容器里量出来的，不是风格问题。
	//   RawSyscall 那条路不进 entersyscall，运行时的异步抢占信号（SIGURG）就一直挂着，
	//   ppoll 每次都被它打断 —— 实测两秒内「到点 0 次、EINTR 86 次」，
	//   换成 Syscall6 是「到点 8 次、EINTR 0 次」。
	//   外面那圈 waitReady 见 EINTR 就重等一格，配上 RawSyscall 就成了名副其实的空转：
	//   CPU 吃满、一个包也没多等到，界面上看着像网络没流量。
	r1, _, errno := syscall.Syscall6(syscall.SYS_PPOLL,
		uintptr(unsafe.Pointer(&pf[0])), uintptr(len(pf)),
		uintptr(unsafe.Pointer(top)), 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

// takePacket 从这一路的环里取下一包。
//
// ★ 取完一块要把所有权还给内核（block_status 写回 0），不还的话环看着是满的，
//
//	下一轮就是实打实的丢包 —— 而内核报出来的丢包数会把我们自己的错算到网卡头上。
func (r *ifaceRing) takePacket() (Packet, bool, error) {
	if r.bad != nil {
		return Packet{}, false, r.bad
	}
	for {
		if r.cur >= 0 && r.left > 0 {
			p, err := r.readPacket()
			if err != nil {
				r.bad = err
				return Packet{}, false, err
			}
			return p, true, nil
		}
		if r.cur >= 0 {
			r.releaseBlock()
		}
		if !r.adoptBlock() {
			if r.bad != nil {
				return Packet{}, false, r.bad
			}
			return Packet{}, false, nil
		}
	}
}

// adoptBlock 认下一块已经退休的块；手上拿不到就回 false（不许在这里等，等是 poll 那一层的事）。
func (r *ifaceRing) adoptBlock() bool {
	for {
		base := r.readIdx * r.blockSize
		if base+tpacketBlockHdrLen > len(r.mmap) {
			r.bad = fmt.Errorf("capture: 口 %s 第 %d 块的块头落在环外（环 %d 字节，块大小 %d）", r.name, r.readIdx, len(r.mmap), r.blockSize)
			return false
		}
		if binary.NativeEndian.Uint32(r.mmap[base+blkStatus:])&tpStatusUser == 0 {
			return false // 内核还在往这块里写
		}
		num := int(binary.NativeEndian.Uint32(r.mmap[base+blkNumPkts:]))
		length := int(binary.NativeEndian.Uint32(r.mmap[base+blkLen:]))
		first := int(binary.NativeEndian.Uint32(r.mmap[base+blkFirstPkt:]))
		if num == 0 {
			// 空块也会退休（到点交出来、这段时间没包）：还给内核，看下一块。
			binary.NativeEndian.PutUint32(r.mmap[base+blkStatus:], tpStatusKernel)
			r.readIdx = (r.readIdx + 1) % r.blockNr
			continue
		}
		if err := r.checkBlock(num, length, first); err != nil {
			r.bad = err
			return false
		}
		r.cur, r.left, r.off, r.end = r.readIdx, num, first, length
		r.readIdx = (r.readIdx + 1) % r.blockNr
		return true
	}
}

// checkBlock 是「内核给的这三格互相兜不兜得住」。
// 对不上就是这一版内核的布局和这张表理解的不是一回事 —— 停下来报错，
// 比按猜的往下读负责：后者只会产出一份看着很正常的错账。
func (r *ifaceRing) checkBlock(num, length, first int) error {
	if length <= 0 || length > r.blockSize {
		return fmt.Errorf("capture: 口 %s 这一块报了有效长度 %d 字节，块大小才 %d", r.name, length, r.blockSize)
	}
	if first < tpacketBlockHdrLen || first >= length {
		return fmt.Errorf("capture: 口 %s 这一块第一包偏移 %d，落在块头（%d）与有效长度（%d）之外",
			r.name, first, tpacketBlockHdrLen, length)
	}
	// 一包最少要吃掉「包头 + 到链路副本」那么一格（实测 82），装不下 num 包就是数对不上。
	if int64(num)*tpacketMinPktSpan > int64(length) {
		return fmt.Errorf("capture: 口 %s 这一块说塞了 %d 包，有效长度只有 %d 字节，一格放不下这么多",
			r.name, num, length)
	}
	return nil
}

func (r *ifaceRing) releaseBlock() {
	if r.cur < 0 {
		return
	}
	base := r.cur * r.blockSize
	if base+blkStatus+4 <= len(r.mmap) {
		binary.NativeEndian.PutUint32(r.mmap[base+blkStatus:], tpStatusKernel) // 还给内核
	}
	r.cur, r.left, r.off, r.end = -1, 0, 0, 0
}

func (r *ifaceRing) readPacket() (Packet, error) {
	base := r.cur * r.blockSize
	hdrAbs := base + r.off
	if hdrAbs+tpacket3HdrSize > len(r.mmap) {
		return Packet{}, fmt.Errorf("capture: 口 %s 这一包的包头落在环外（块 %d 偏移 %d，环 %d 字节）",
			r.name, r.cur, r.off, len(r.mmap))
	}
	if r.off+tpacket3HdrSize > r.end {
		return Packet{}, fmt.Errorf("capture: 口 %s 这一包的包头落在这一块的有效长度外（偏移 %d，块有效 %d 字节）",
			r.name, r.off, r.end)
	}
	hdr := r.mmap[hdrAbs : hdrAbs+tpacket3HdrSize]
	order := binary.NativeEndian
	snap := int(order.Uint32(hdr[t3Snaplen:]))
	orig := int(order.Uint32(hdr[t3Len:]))
	mac := int(order.Uint16(hdr[t3Mac:]))
	status := order.Uint32(hdr[t3Status:])
	next := int(order.Uint32(hdr[t3NextOffset:]))
	if status&tpStatusLosing != 0 {
		r.lossy.Store(true)
	}
	if r.wantHW && status&tpStatusTSRawHW == 0 {
		// 内核收下了「要硬件戳」，实际给的却是软件戳（或者压根没标来源）—— 这是这块网卡
		// 或这个驱动给不了。停下来如实说，比继续算出一份「看着像延迟、其实是软件戳」的账负责。
		why := "内核没在这一包上标戳的来源"
		if status&tpStatusTSSoftware != 0 {
			why = "内核给这一包打的是软件时刻"
		}
		r.bad = fmt.Errorf("capture: 口 %s 拿不到硬件时刻（%s，包上状态 0x%08x）—— 这块网卡或这个驱动不支持，不换软件时刻凑数",
			r.name, why, status)
		return Packet{}, r.bad
	}
	if snap < 0 || mac < 0 || r.off+mac+snap > r.end {
		return Packet{}, fmt.Errorf("capture: 口 %s 这一包留 %d 字节、链路头在偏移 %d，兜不进这一块（有效 %d 字节）",
			r.name, snap, mac, r.end)
	}
	if next < 0 || (r.left > 1 && next == 0) {
		return Packet{}, fmt.Errorf("capture: 口 %s 这一块还剩 %d 包没读，内核给的下一包步长却是 %d —— 步长表对不上，停下来",
			r.name, r.left, next)
	}
	if orig < snap {
		orig = snap // 线上长度不可能比留下那份还短：内核不会给这种数，给了就当没截过
	}
	data := make([]byte, snap)
	copy(data, r.mmap[base+r.off+mac:base+r.off+mac+snap])
	// 游标先按内核给的步长前进：V3 块里的包是紧挨着排的，这个数不是帧大小。
	r.off += next
	r.left--
	sec := int64(order.Uint32(hdr[t3Sec:]))
	nsec := int64(order.Uint32(hdr[t3Nsec:]))
	return Packet{
		InterfaceIndex: r.ifIdx,
		Timestamp:      time.Unix(sec, nsec),
		HasTimestamp:   true,
		Data:           data,
		OrigLen:        orig,
	}, nil
}

// Stats 报这一路的账。
//
// ★ 丢包数问的是内核（PACKET_STATISTICS），不是「我们读到了多少」：
//
//	环小了丢的那些，只有内核那份计数知道。而那一格读一次就清零，
//	所以这里自己累成「开这一路以来一共丢了几包」—— 界面要的是这个数。
func (s *linuxSource) Stats() Stats {
	st := Stats{Interfaces: len(s.rings), Packets: s.pkts.Load()}
	for _, r := range s.rings {
		if drops, ok := r.kernelDrops(); ok && drops > 0 {
			r.drops.Add(drops)
		}
		st.Dropped += r.drops.Load()
		if r.lossy.Load() {
			st.Lossy = true
		}
	}
	return st
}

// kernelDrops 回「上一次问到现在」的丢包数。拿不到就如实回 ok=false：
// 这一格不许猜 —— 报个 0 说是「没丢」，现场就会照着这句去查网卡。
func (r *ifaceRing) kernelDrops() (uint64, bool) {
	if r.fd < 0 {
		return 0, false
	}
	// struct tpacket_stats { unsigned int tp_packets; unsigned int tp_drops; }
	// V3 那份是 12 字节（多一格 tp_tp_copies），前两格的落点一样，读 8 字节两版都兜得住。
	var buf [8]byte
	n, err := getsockoptBytes(r.fd, syscall.SOL_PACKET, packetStatistics, buf[:])
	if err != nil || n < 8 {
		return 0, false
	}
	return uint64(binary.NativeEndian.Uint32(buf[4:])), true
}

func (s *linuxSource) Interfaces() []Interface {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Interface(nil), s.ifaces...)
}

func (s *linuxSource) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // 关两次不算一次错
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for _, r := range s.rings {
		if len(r.mmap) > 0 {
			if err := syscall.Munmap(r.mmap); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("capture: 口 %s 的环还不掉：%w", r.name, err)
			}
			r.mmap = nil
		}
		if r.fd >= 0 {
			if err := syscall.Close(r.fd); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("capture: 口 %s 的 socket 关不掉：%w", r.name, err)
			}
			r.fd = -1
		}
	}
	return firstErr
}

func htons(v uint16) int { return int(v<<8 | v>>8) }
