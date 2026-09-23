//go:build windows

package tools

import "syscall"

// Windows 上「不许分片」是 IP_DONT_FRAGMENT（v6 是 IPV6_DONTFRAG），选项号来自
// ws2ipdef.h：IP_DONT_FRAGMENT=7、IPV6_DONTFRAG=14。Go 的 syscall 包没导出这两个名字，
// 所以这里自己写死，并把出处留在注释里 —— 写错一个数字不会报错，只会让探测悄悄失真。
//
// ★★ 这一条路**没在 Windows 真机上验过**（开发机是 macOS）。不确定点有两处：
//
//	Go 的 net 在 Windows 上会不会真的回调 Control，以及这个选项在非管理员权限下能不能设上。
//	所以这一栏不在编译期假设它成立：探测的第一步就是拿一个明显超限的包自查
//	（超限的包被内核直接拒 = 选项真的生效；反倒发得出去 = 内核自己分片了），
//	后者一律判 mtu-df-unsupported 并说清是这台机器测不了，不端出一个分过片的假 MTU。
const dfEngine = "ip_dont_fragment"

const (
	ipProtoIPv4Win = 0  // IPPROTO_IP
	ipProtoIPv6Win = 41 // IPPROTO_IPV6
	optDontFragWin = 7
	optDontFrag6   = 14
)

func dfControl(v6 bool) (func(network, address string, c syscall.RawConn) error, error) {
	level, opt := ipProtoIPv4Win, optDontFragWin
	if v6 {
		level, opt = ipProtoIPv6Win, optDontFrag6
	}
	return func(_, _ string, c syscall.RawConn) error {
		var inner error
		if err := c.Control(func(fd uintptr) {
			inner = syscall.SetsockoptInt(syscall.Handle(fd), level, opt, 1)
		}); err != nil {
			return err
		}
		return inner
	}, nil
}
