//go:build linux

package tools

import "syscall"

// Linux 上用 IP_MTU_DISCOVER 的 DO 档。★ 不是「设个标志位」就完事：这一档同时决定了
// 内核在本地要不要拒绝发超过下一跳 MTU 的包（拒绝才谈得上「测得出限制」），
// 而另一档 IP_PMTUDISC_INTERFACE 只在本地拦、路上被挡了不吭声 —— 拿那个测出来的数会偏大。
const dfEngine = "ip_mtu_discover"

const (
	ipProtoIPv4Linux = 0  // IPPROTO_IP
	ipProtoIPv6Linux = 41 // IPPROTO_IPV6
	// linux/in.h：IP_MTU_DISCOVER=10、IPV6_MTU_DISCOVER=23、IP_PMTUDISC_DO=2
	optMTUDiscoverV4 = 10
	optMTUDiscoverV6 = 23
	pmtuDontFragment = 2
)

func dfControl(v6 bool) (func(network, address string, c syscall.RawConn) error, error) {
	level, opt := ipProtoIPv4Linux, optMTUDiscoverV4
	if v6 {
		level, opt = ipProtoIPv6Linux, optMTUDiscoverV6
	}
	return func(_, _ string, c syscall.RawConn) error {
		var inner error
		if err := c.Control(func(fd uintptr) {
			inner = syscall.SetsockoptInt(int(fd), level, opt, pmtuDontFragment)
		}); err != nil {
			return err
		}
		return inner
	}, nil
}
