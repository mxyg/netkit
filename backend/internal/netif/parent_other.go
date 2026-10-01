//go:build !darwin && !linux

package netif

// parents 这些平台（Windows、FreeBSD、Android 上的非标准运行时……）没有实现查法。
//
// ★ 返回 nil 是**明写「不知道」**，不是「没有父子关系」：
//
//	Windows 上网卡桥（Hyper-V 虚拟交换机、NIC 组队）确实存在，
//	但要查到父设备得走 WMI / `Get-NetAdapter` 那一路，还没做。
//	拓扑层看到 parent 为空就不折叠端口 —— 宁可图上多两个谁都认得出的方块，
//	也不多抹掉一块真实的口。
func parents() map[string]string { return nil }
