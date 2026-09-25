//go:build linux && !386

package throughput

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Linux 这一侧用内核的 TCP_INFO。结构体直接拿标准库里按内核头文件生成的那一份，
//
// 不自己数偏移 —— 自己数一遍就是把同一个字段在两个地方各猜一次。
func socketTCPInfo(fd uintptr) (TCPInfo, error) {
	var ti syscall.TCPInfo
	l := uint32(unsafe.Sizeof(ti))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
		uintptr(syscall.SOL_TCP), uintptr(syscall.TCP_INFO),
		uintptr(unsafe.Pointer(&ti)), uintptr(unsafe.Pointer(&l)), 0)
	if errno != 0 {
		return TCPInfo{}, fmt.Errorf("问内核要这条连接的账没问到：%w", syscall.Errno(errno))
	}
	if int(l) < int(unsafe.Sizeof(ti)) {
		// 内核少写了字节 = 后面那些字段是空的零值，把它们当「0 次重传」报出去是假账。
		return TCPInfo{}, fmt.Errorf("这台内核只回了 %d 字节，不够 srtt/拥塞窗口那一段", l)
	}
	// 内核这两个 RTT 数单位是微秒；结果里统一按毫秒说话。
	return TCPInfo{
		Source:   "Linux TCP_INFO",
		State:    tcpStateName(ti.State),
		SrttMs:   float64(ti.Rtt) / 1000,
		RttvarMs: float64(ti.Rttvar) / 1000,
		// Total_retrans 是这条连接从头算起来的「重传过的段数」，
		// 与 macOS 那侧的 txretransmitpackets 同为计数，可以直接对照。
		RetransSegments: int64(ti.Total_retrans),
		SndCwndBytes:    int64(ti.Snd_cwnd),
		MaxSegBytes:     int64(ti.Snd_mss),
	}, nil
}
