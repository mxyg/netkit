//go:build !(linux && !386) && !darwin

package throughput

import "errors"

// 这一档 covering Windows（含 Win7 那一份 386）以及我们没核对过内核结构体的系统。
//
// ★ 不去猜偏移：Windows 的 TCP_INFO 和 Linux 的那个同名不同物，猜错不是少一个数，
// 是多一个假数。这一层的账在这台上给不了，判定只能靠外层的往返与曲线，
// 结果里会把「这一格没问出来」写明白。
func socketTCPInfo(fd uintptr) (TCPInfo, error) {
	return TCPInfo{}, errors.New("这台机器的系统我们没核对过这份账的结构，取不了")
}
