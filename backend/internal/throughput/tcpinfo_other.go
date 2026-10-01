//go:build !(linux && !386) && !darwin && !windows

package throughput

import "errors"

// 这一档 covering 我们没核对过内核结构体的系统（含 linux/386）。Windows 不在这里 ——
// 它那一档走 iphlpapi 的每连接扩展统计（见 tcpinfo_windows.go），不是猜 TCP_INFO 的偏移。
//
// ★ 不去猜偏移：猜错不是少一个数，是多一个假数。这一层的账在这台上给不了，
// 判定只能靠外层的往返与曲线，结果里会把「这一格没问出来」写明白。
func socketTCPInfo(fd uintptr) (TCPInfo, error) {
	return TCPInfo{}, errors.New("这台机器的系统我们没核对过这份账的结构，取不了")
}
