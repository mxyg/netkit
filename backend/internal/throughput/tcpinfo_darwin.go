//go:build darwin

package throughput

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// macOS 把这份账挂在 TCP_CONNECTION_INFO 上，结构体是 tcp_connection_info。
//
// ★ 下面的偏移不是抄来的猜测：是本机拿编译器对着 SDK 的 <netinet/tcp.h>
//
//	一个个 offsetof 打出来的（macOS 15.6 随附 SDK，sizeof = 112）。
//	内核只会往我们给的缓冲里写它认得的那一段，并把实际写入的字节数写回长度参数，
//	所以哪一版把字段挪走或还没长到那么长时，我们看到的是「长度不够」这一格报缺，
//	而不是拿一个错位读出来的数去下判定。
const (
	sockoptTCPConnectionInfo = 0x106
	tcpConnectionInfoSize    = 112

	offState         = 0
	offMaxSeg        = 16
	offSndCwnd       = 24
	offSndBuf        = 32
	offSrtt          = 44
	offRttvar        = 48
	offTxRetransPkt  = 104
	minNeededSrttSeg = offRttvar + 4 // srtt/rttvar 之后到这一格都齐了
)

func socketTCPInfo(fd uintptr) (TCPInfo, error) {
	var b [tcpConnectionInfoSize]byte
	l := uint32(len(b))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
		uintptr(syscall.IPPROTO_TCP), sockoptTCPConnectionInfo,
		uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return TCPInfo{}, fmt.Errorf("问内核要这条连接的账没问到：%w", syscall.Errno(errno))
	}
	got := int(l)
	if got < minNeededSrttSeg {
		return TCPInfo{}, fmt.Errorf("这台 macOS 只回了 %d 字节，连 srtt 那一段都不齐", got)
	}
	// 内核按本机字节序填这一份结构体（macOS 只跑小端机器），不是网络序。
	has := func(off, size int) bool { return got >= off+size }
	u32 := func(off int) int64 { return int64(binary.LittleEndian.Uint32(b[off:])) }
	info := TCPInfo{
		Source:   "macOS TCP_CONNECTION_INFO",
		SrttMs:   float64(u32(offSrtt)),
		RttvarMs: float64(u32(offRttvar)),
	}
	if has(offState, 1) {
		info.State = tcpStateName(b[offState])
	}
	if has(offSndCwnd, 4) {
		info.SndCwndBytes = u32(offSndCwnd)
	}
	if has(offMaxSeg, 4) {
		info.MaxSegBytes = u32(offMaxSeg)
	}
	// macOS 这里既有字节数也有包数；取包数，好和 Linux 那侧的「段」对齐。
	if has(offTxRetransPkt, 8) {
		info.RetransSegments = int64(binary.LittleEndian.Uint64(b[offTxRetransPkt:]))
	}
	if has(offSndBuf, 4) {
		n := u32(offSndBuf)
		info.SndBufBytes = &n
	}
	return info, nil
}
