//go:build !darwin && !linux && !windows

package tools

import (
	"context"
	"fmt"
	"runtime"
)

// 其余平台（BSD 各家等）没有一个「一定装在这台机器上」的读法：
// lsof 在 BSD 上格式相同但默认不装，/proc 各家不一样。
// ★ 这里**不许**退化成跑一条命令凑合 —— 指错进程的代价比说「读不到」大得多。
func readLocalPorts(context.Context) ([]portUse, bool, error) {
	return nil, false, fmt.Errorf("%w：这个平台（%s）", errPortSource, runtime.GOOS)
}
