//go:build windows

// 「这一路起不来，是不是因为没提权 —— 界面能不能就这么说」这一问的凭据。
//
// 只做一件事：把当前进程令牌的提权位读一遍。它是**建议性**的 ——
// 问不出来（那个 class 不认、写回来的长度不对）就当不知道，绝不拿「不知道」当「没提权」用：
// 套错了 ErrNeedPrivilege，界面会叫用户去提权，而那台机器可能早就提过了。
//
// 为什么不去读 pktmon 说的话：它是系统消息，中文系统上整句是中文
// （见 source_windows.go 顶上第 11 条），而提权位在令牌里，跟显示语言无关。
//
// 用到的两格（TOKEN_ELEVATION 的大小、那个 class 号）是按 winnt.h 那一份写的。
// 读错不会崩：GetTokenInformation 要么回一句「不认这个 class」，要么填回来一个别的长度，
// 两样都被下面挡成「问不出来」。但「挡住了」不等于「量对了」，所以测试里另拿一个
// 不依赖语言的旁证对了一遍 —— 见 elevate_windows_test.go 那条「与 net session 的退出码对得上」。
// 那一条只有真机跑得到，这台机器之外没核过。
package capture

import (
	"syscall"
	"unsafe"
)

const (
	tokenQuery                     = 0x0008 // TOKEN_QUERY
	tokenInformationClassElevation = 20     // TOKEN_INFORMATION_CLASS 里的 TokenElevation
	// tokenElevationSize 是 TOKEN_ELEVATION 的大小：里面就一个 ULONG TokenIsElevated。
	tokenElevationSize = 4
)

var (
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

// probeElevated 回 1 提过权、0 没提过、-1 问不出来。
func probeElevated() int8 {
	// 当前进程那个伪句柄是 (HANDLE)-1：不用开，也不用关。
	var tok syscall.Handle
	if r, _, _ := procOpenProcessToken.Call(^uintptr(0), uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&tok))); r == 0 {
		return -1
	}
	defer syscall.CloseHandle(tok)

	var elev, got uint32
	if r, _, _ := procGetTokenInformation.Call(uintptr(tok), tokenInformationClassElevation,
		uintptr(unsafe.Pointer(&elev)), tokenElevationSize,
		uintptr(unsafe.Pointer(&got))); r == 0 {
		return -1
	}
	if int(got) != tokenElevationSize {
		// 它说它写了别的长度：这一格就不认，别拿一个说不清的数去填界面上那句结论。
		return -1
	}
	if elev == 0 {
		return 0
	}
	return 1
}
