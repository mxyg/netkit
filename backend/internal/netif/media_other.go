//go:build !darwin && !linux && !windows

package netif

// kinds 其它平台（FreeBSD、Android 上的非标准运行时……）问不到系统，
// 一律回落到按名字猜。★ 返回 nil 而不是空 map 也行，这里显式写出来
// 是为了说明：**这不是"没查到"，是"这个平台我们还没实现查法"**。
func kinds() map[string]string { return nil }
