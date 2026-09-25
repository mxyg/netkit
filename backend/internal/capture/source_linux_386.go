//go:build linux && 386

// i386 上 socket 那一族没有各自的口号：整族都从 socketcall(2) 这一个门进去，
// 参数是先摆一个「六个字」的数组、再把数组指针交给内核。Go 自己的 syscall 包在
// 这一档上也是这么走的（SYS_SETSOCKOPT 在 linux/386 上根本没导出，编译会当场失败 ——
// 这一档就是为那个失败写的）。
//
// ★ 那两个请求号（14 / 15）不是按名字猜的：它们得和内核 net/socket.c 里
//
//	sys_socketcall 的分支表一致，猜错不会崩，只会把 setsockopt 变成另一次调用。
//	这里取的是 Go 标准库自己在 linux/386 上用的那一套（GOROOT 的
//	syscall/syscall_linux_386.go：_SETSOCKOPT=14、_GETSOCKOPT=15），
//	标准库的 net 包在 i386 上是常年跑着的，这一份表跟着它走最稳。
package capture

import (
	"syscall"
	"unsafe"
)

const (
	scSetsockopt = 14
	scGetsockopt = 15
	scArgWords   = 6 // 内核按六个字从用户态拷这一串
)

func rawSetsockopt(fd, level, opt int, val unsafe.Pointer, n uintptr) syscall.Errno {
	args := [scArgWords]uintptr{uintptr(fd), uintptr(level), uintptr(opt), uintptr(val), n, 0}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, scSetsockopt, uintptr(unsafe.Pointer(&args[0])), 0)
	return errno
}

func rawGetsockopt(fd, level, opt int, val unsafe.Pointer, lenp unsafe.Pointer) syscall.Errno {
	args := [scArgWords]uintptr{uintptr(fd), uintptr(level), uintptr(opt), uintptr(val), uintptr(lenp), 0}
	_, _, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, scGetsockopt, uintptr(unsafe.Pointer(&args[0])), 0)
	return errno
}
