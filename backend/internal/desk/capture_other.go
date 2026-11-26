//go:build !windows

package desk

import "errors"

var errNeedToken = errors.New("共享屏幕必须带令牌")

// FrameJPEG 非 Windows 还不能当被控端。
func FrameJPEG() ([]byte, error) { return FrameJPEGOpts(82, 1280) }

// FrameJPEGOpts 非 Windows 同上（参数先收着，将来补采集）。
func FrameJPEGOpts(quality, maxWidth int) ([]byte, error) {
	_, _ = quality, maxWidth
	return nil, errors.New("这台系统还不能共享屏幕")
}

// Apply 非 Windows 不接收键鼠。
func Apply(Event) error { return errors.New("这台系统还不能接收键鼠") }

// Cursor 非 Windows 没有远端光标。
func Cursor() CursorInfo { return CursorInfo{} }

func notifySharing() error { return nil }
