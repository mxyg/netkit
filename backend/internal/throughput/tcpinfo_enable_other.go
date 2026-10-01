//go:build !windows

package throughput

// enableConnTCPStats 在非 Windows 上是空操作：macOS/Linux 那份账（TCP_INFO /
// TCP_CONNECTION_INFO）用 getsockopt 现取现得，不需要「先开采集开关」这一步，
// 也就没有「没开起来」这一档要防。真正的开关与统计累加起点在 tcpinfo_windows.go。
func enableConnTCPStats(fd uintptr) {}
