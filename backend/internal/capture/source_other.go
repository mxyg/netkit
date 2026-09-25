//go:build !linux

// 还没做采集档的平台走这里：能读写文件，不能现场抓。
//
// ★ 这一档不许悄悄退回「用 tcpdump 代抓」：安装包零专有依赖是硬口径，
//
//	而现场装没装过 tcpdump/Npcap 我们说了不算 —— 不如如实说这一档还没有。
package capture

import "fmt"

func OpenSource(opt Options) (Source, error) {
	return nil, fmt.Errorf("capture: 这个平台还不能现场抓包（读现成的 pcapng 可以）：%w", ErrUnsupported)
}
