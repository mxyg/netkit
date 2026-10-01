//go:build windows

package throughput

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// Windows 这一侧走 iphlpapi 的每连接扩展统计（Get/SetPerTcpConnectionEStats），
// 全程 raw syscall、无 cgo —— 和 capture/elevate_windows.go 同一套 NewLazyDLL 打法，
// 因为每个出货目标都是 CGO_ENABLED=0 编的（scripts/build-release.sh）。
//
// ★★ 为什么要「先开再读」：这些统计默认不采，Get 回来的 Rw.EnableCollection=FALSE 时
//
//	Rod 里是随机数（MSDN 明说）。开统计（Set）这一步只有管理员做得到，所以现场十次有
//	九次在未提权的会话里开不起来 —— 那就老实地报「这台没开起来、要管理员」，绝不把随机数
//	当成「往返 0.3 ms、零重传」报出去，那是最坏的假账。
//
// ★ 认连接用的是这条活 socket 自己的四元组（getsockopt 现问），不是去扫 TCP 表再挑一行：
//
//	扫表要按 owner PID 分「哪行才是我们这条」，多线程下会认错；现问的那一条必然对得上
//	「只在连接还开着时取」这个前提（probe.go 里 tcpInfoOf 就是卡着这一点）。
var (
	iphlpapi                      = syscall.NewLazyDLL("iphlpapi.dll")
	procGetPerTcpConnectionEStats = iphlpapi.NewProc("GetPerTcpConnectionEStats")
	procSetPerTcpConnectionEStats = iphlpapi.NewProc("SetPerTcpConnectionEStats")
)

// TCP_INFO 这个 getsockopt 选项号（winsock.h 里的 TCP_INFO， IPPROTO_TCP 层）。
// 只借它一次问回本机与对端的 SOCKADDR_IN；不读它的 TCP_INFO 结构本身（那才是同名不同物，不猜）。
const tcpInfoOption = 4

// 缓冲放大的硬顶：装不下就是这份 VERSION_0 结构比我们核对过的还大，宁可报缺也别猜偏移。
const eStatsMaxBuf = 8192

// 两条要说清楚的收场：连接在两次取样之间关了（对测里正常），以及这台没开起来（要管理员）。
var (
	errNoConnClosed    = errors.New("这条连接在两次取样之间已经关了（对测跑完就会关，不算毛病）")
	errStatsNotEnabled = errors.New("这台机器上这条连接的每连接统计没开起来——开它要管理员权限，以管理员运行 netkitd 再测")
)

// socketTCPInfo 问这条活连接的内核账。填的是：SrttMs、RttvarMs、RetransSegments、
// SndCwndBytes、MaxSegBytes（都取到了才 Given=true）。取不到就交回一条明确的错，让上层写「没问出来」。
func socketTCPInfo(fd uintptr) (TCPInfo, error) {
	h := syscall.Handle(fd)
	row, err := buildRow(fd)
	if err != nil {
		return TCPInfo{}, err
	}

	pathRod, pathEnabled, err := getRod(h, &row, estatsPath, int(unsafe.Sizeof(pathRodV0{})))
	if err != nil {
		return TCPInfo{}, err
	}
	if !pathEnabled {
		return TCPInfo{}, errStatsNotEnabled
	}

	congRod, congEnabled, err := getRod(h, &row, estatsSndCong, int(unsafe.Sizeof(sndCongRodV0{})))
	if err != nil {
		return TCPInfo{}, err
	}
	if !congEnabled {
		return TCPInfo{}, errStatsNotEnabled
	}

	var info TCPInfo
	// 两份都要解得动才给真账：少一份（比如拥塞窗口没落全）就整格不报，
	// 省得拿一个 0 拥塞窗口去和真实往返拼出一个假「顶速」。
	if !parsePathROD(pathRod, &info) {
		return TCPInfo{}, fmt.Errorf("Path 那份回得太短（%d 字节），连 CurMss 那格都不齐", len(pathRod))
	}
	if !parseSndCongROD(congRod, &info) {
		return TCPInfo{}, fmt.Errorf("SndCong 那份回得太短（%d 字节），够不到 CurCwnd", len(congRod))
	}
	// SndBufBytes 这一格 Windows 不给：它把发送缓冲拆成 CurAppWQueue（还没首传的）与
	// CurRetxQueue（重传队列里的），跟 macOS 那一格「含在途」的单一 sndbuf 不是同一个量，
	// 拿两者相加冒充 macOS 的 sndbuf 就是「拿不同的量凑一个数」，所以留空（见下面注释同一口径）。
	info.Source = "Windows iphlpapi TCP_ESTATS（Path＋SndCong，需管理员开启）"
	return info, nil
}

// enableTCPStats 在握手刚成、还没开打时就 best-effort 把这两组统计的采集开关打开。
// 这一步只有管理员做得成；成不成这里都不报（真正的「有没有开起来」在读的时候按
// EnableCollection 判）。早开是为了让 PktsRetrans 这种「自开启起累加」的计数覆盖整段传输，
// 而不是只数最后那几帧。
func enableConnTCPStats(fd uintptr) {
	row, err := buildRow(fd)
	if err != nil {
		return
	}
	setEnable(syscall.Handle(fd), &row, estatsPath)
	setEnable(syscall.Handle(fd), &row, estatsSndCong)
}

// buildRow 用这条 socket 自己的本机/对端地址端口拼 MIB_TCPROW。
func buildRow(fd uintptr) (mibTCPRow, error) {
	local, remote, err := connEndpoints(fd)
	if err != nil {
		return mibTCPRow{}, err
	}
	return endpointToRow(local, remote)
}

// connEndpoints 现问这条连接的本端与对端 SOCKADDR_IN 原始字节。
func connEndpoints(fd uintptr) (local, remote []byte, err error) {
	h := syscall.Handle(fd)
	var lbuf, rbuf [128]byte
	ln := int32(len(lbuf))
	if e := syscall.Getsockopt(h, syscall.IPPROTO_TCP, tcpInfoOption, &lbuf[0], &ln); e != nil {
		return nil, nil, fmt.Errorf("问本机这条连接的本端地址没问到（getsockopt TCP_INFO）：%w", e)
	}
	rn := int32(len(rbuf))
	if e := syscall.Getsockopt(h, syscall.IPPROTO_TCP, tcpInfoOption, &rbuf[0], &rn); e != nil {
		return nil, nil, fmt.Errorf("问本机这条连接的对端地址没问到（getsockopt TCP_INFO）：%w", e)
	}
	if ln <= 0 || rn <= 0 || int(ln) > len(lbuf) || int(rn) > len(rbuf) {
		return nil, nil, fmt.Errorf("getsockopt 回写的地址长度不成话（本端 %d、对端 %d）", ln, rn)
	}
	return lbuf[:ln], rbuf[:rn], nil
}

// getRod 问某一组统计的 Rod，并报告这一组此刻开没开。缓冲太小（ERROR_MORE_DATA /
// ERROR_INSUFFICIENT_BUFFER / Win7 的 ERROR_INVALID_USER_BUFFER）就放大重问，带上限。
func getRod(h syscall.Handle, row *mibTCPRow, typ uint32, want int) (rod []byte, enabled bool, err error) {
	size := want
	if size < 1 {
		size = 1
	}
	for {
		buf := make([]byte, size)
		var rw rwEnable
		code := callGet(row, typ, &rw, buf)
		switch code {
		case estatInsufficientBuf, estatInvalidUsrBuf:
			// 我们按核对过的 VERSION_0 尺寸给缓冲还嫌小 —— 说明这台返回的比那份大。
			// 放大重问一次，到顶还装不下就报缺，不猜多出来的字段落在哪。
			if size >= eStatsMaxBuf/2 {
				return nil, false, fmt.Errorf("每连接统计这一组回 %d 字节还装不下，到上限 %d 也没问全", size, eStatsMaxBuf)
			}
			size *= 2
			continue
		case estatNoError:
			return buf, rw.enableCollection != 0, nil
		default:
			return nil, false, estatsCodeErr(code)
		}
	}
}

// setEnable 打开某一组的采集。best-effort：这里的错不往上抛（读的时候按 EnableCollection 判真伪）。
func setEnable(h syscall.Handle, row *mibTCPRow, typ uint32) {
	rw := rwEnable{enableCollection: 1}
	_ = callSet(row, typ, &rw)
}

// callGet 打一次 GetPerTcpConnectionEStats：只填 Rod（Ros 传 NULL/0），Rw 用来看开没开。
func callGet(row *mibTCPRow, typ uint32, rw *rwEnable, rod []byte) uint32 {
	if len(rod) == 0 {
		return estatInvalidParameter
	}
	r1, _, _ := procGetPerTcpConnectionEStats.Call(
		uintptr(unsafe.Pointer(row)),
		uintptr(typ),
		uintptr(unsafe.Pointer(rw)), uintptr(0), uintptr(unsafe.Sizeof(*rw)), // Rw，版本 0
		0, uintptr(0), uintptr(0), // Ros：不要，NULL + 版本 0 + 尺寸 0
		uintptr(unsafe.Pointer(&rod[0])), uintptr(0), uintptr(len(rod)), // Rod，版本 0
	)
	// 调用的这段里 row/rw/rod 都得活着：unsafe 的取地址在 Call 期间由 runtime 兜着，
	// 但 rod 是我们 make 的切片，跨 syscall 边界显式钉一下最省心。
	runtime.KeepAlive(row)
	runtime.KeepAlive(rw)
	runtime.KeepAlive(rod)
	return uint32(r1)
}

// callSet 打一次 SetPerTcpConnectionEStats 开某一组（Offset 参数文档说必须 0）。
func callSet(row *mibTCPRow, typ uint32, rw *rwEnable) uint32 {
	r1, _, _ := procSetPerTcpConnectionEStats.Call(
		uintptr(unsafe.Pointer(row)),
		uintptr(typ),
		uintptr(unsafe.Pointer(rw)), uintptr(0), uintptr(unsafe.Sizeof(*rw)), // Rw，版本 0
		uintptr(0), // Offset：当前未用，必须 0
	)
	runtime.KeepAlive(row)
	runtime.KeepAlive(rw)
	return uint32(r1)
}

// estatsCodeErr 把 Get/Set 回来的状态码翻成一句分得清原因的话。NOT_FOUND 单独一档：
// 那在对测里是「连接跑完就关了」的正常收场，不该长得像失败。
func estatsCodeErr(code uint32) error {
	switch code {
	case estatNotFound:
		return errNoConnClosed
	case estatAccessDenied:
		return fmt.Errorf("问每连接统计被拒——这一问要管理员（错误码 %d）", code)
	case estatNotSupported:
		return fmt.Errorf("这台系统不认这个统计版本/参数（错误码 %d）", code)
	case estatInvalidParameter:
		return fmt.Errorf("查这条连接的参数不成话（错误码 %d）", code)
	default:
		return fmt.Errorf("每连接统计问失败（错误码 %d）", code)
	}
}
