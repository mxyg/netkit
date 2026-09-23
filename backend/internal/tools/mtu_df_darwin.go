//go:build darwin

package tools

import "syscall"

// macOS / BSD 上没有 Linux 那个 MTU_DISCOVER 开关，对应的是 IP_DONTFRAG：
// 设上之后本机发不出超过下一跳 MTU 的数据报，收上来的 ICMP「需要分片」也会以
// EMSGSIZE 顶到下一次收发 —— 正是这一栏要的信号。
//
// ★ 选项号是从 x/sys/unix 的生成表里核对的（IP_DONTFRAG=0x1c=28、IPV6_DONTFRAG=0x3e=62），
//
//	不是凭印象写的。而且这一栏不靠编译期假设它真的生效 —— 见 mtu.go 里
//	「连最小包都被挡住就判 df-unsupported」那条分支。
const dfEngine = "ip_dontfrag"

const (
	ipProtoIPv4  = 0  // IPPROTO_IP
	ipProtoIPv6  = 41 // IPPROTO_IPV6
	optDontFrag  = 28 // IP_DONTFRAG
	optDontFrag6 = 62 // IPV6_DONTFRAG
	dontFragOn   = 1
)

func dfControl(v6 bool) (func(network, address string, c syscall.RawConn) error, error) {
	level, opt := ipProtoIPv4, optDontFrag
	if v6 {
		level, opt = ipProtoIPv6, optDontFrag6
	}
	return func(_, _ string, c syscall.RawConn) error {
		var inner error
		if err := c.Control(func(fd uintptr) {
			inner = syscall.SetsockoptInt(int(fd), level, opt, dontFragOn)
		}); err != nil {
			return err
		}
		return inner
	}, nil
}
