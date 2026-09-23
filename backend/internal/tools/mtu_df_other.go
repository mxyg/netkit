//go:build !linux && !darwin && !windows

package tools

import (
	"runtime"
	"syscall"
)

// 其余平台（BSD 各家、plan9、wasm 之类）没有对得上的「不许分片」选项。
// ★ 这里**不许**退化成「不设选项照样发」：那样内核会自己把大包切开，
//
//	谁都不报错，量出来的「路径 MTU」等于没上限 —— 一个假数字比测不出来坏得多。
//	所以直接给一句明确的：这一栏在这台机器上测不了。
const dfEngine = "unsupported"

func dfControl(bool) (func(network, address string, c syscall.RawConn) error, error) {
	return nil, otsErrNoDF()
}

func otsErrNoDF() error {
	return &dfUnsupportedError{goos: runtime.GOOS}
}

type dfUnsupportedError struct{ goos string }

func (e *dfUnsupportedError) Error() string {
	return "这个平台（" + e.goos + "）没有对得上的「不许分片」套接字选项，路径 MTU 测不了"
}
