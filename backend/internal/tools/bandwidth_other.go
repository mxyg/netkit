//go:build !darwin && !linux && !windows

package tools

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// 其余平台（BSD 各家等）没有一个「一定装在这台机器上」的字节计数读法。
//
// ★ 这里**不许**退化成跑一条命令凑合：BSD 各家 netstat -ib 的列确实差不多，
// 但字节数是链路层还是协议层、有没有 64 位计数器，各家不同 ——
// 拿一个不准的分母去除，得出的「这个进程吃了 80%」是彻底假的。
func readLinkCounters(context.Context) ([]linkCount, error) {
	return nil, fmt.Errorf("%w：这个平台（%s）没有可靠的每网卡字节计数读法", errBandwidthSource, runtime.GOOS)
}

func readProcBytes(context.Context, time.Duration) (procSample, error) {
	return procSample{attribution: bwAttribNone,
		reason: "这个平台（" + runtime.GOOS + "）没有确定的按进程字节计数读法",
		next:   "要查谁在吃，请用这台机器自带的工具"}, nil
}
