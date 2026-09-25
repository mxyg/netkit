//go:build linux && !386

// 除 i386 之外的 linux：setsockopt / getsockopt 各有一个直接口号。
//
// 这一档上 SYS_SETSOCKOPT / SYS_GETSOCKOPT 都由 syscall 包导出（arm64 / amd64 / arm
// 都在这条路上，实测编译过），所以这里只是把参数按内核的签名摆一遍。
// 为什么非要自己摆：SOL_PACKET 的 PACKET_RX_RING 要递一整个 struct，标准库没有对口的
// 导出函数（它只到 SetsockoptInt 那一格），而这一层不许带第三方依赖。
package capture

import (
	"syscall"
	"unsafe"
)

func rawSetsockopt(fd, level, opt int, val unsafe.Pointer, n uintptr) syscall.Errno {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(val), n, 0)
	return errno
}

func rawGetsockopt(fd, level, opt int, val unsafe.Pointer, lenp unsafe.Pointer) syscall.Errno {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(val), uintptr(lenp), 0)
	return errno
}
