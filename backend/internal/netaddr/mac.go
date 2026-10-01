package netaddr

// MAC 的写法归一。
//
// ★★ 为什么这一份要放在 netaddr 而不是各探测里各写一遍：同一块网卡在
//   一台机器上能被四五个来源说出来，写法各平台全不一样 ——
//   ARP 是 aa:bb:cc:dd:ee:ff、BSD 的 arp/ifconfig 把每段前导零省了写成 f2:f:38:df:d2:68、
//   Windows 是 aa-bb-cc-dd-ee-ff、华为/H3C 的 CLI 是 aabb.ccdd.eeff、
//   LLDP 的 chassisId 里那六个字节又被打成大写。
//   不归一的后果不是难看：**同一台设备在图上变成两个方块**，
//   而「这台 MAC 在不在我们网里」要人自己对着字符串比大小写。
//   更坏的是 net.ParseMAC 直接拒绝 BSD 那种省零写法，
//   于是 MAC 悄悄变成空 —— 少了一栏比多画一个方块更难被发现。

import (
	"net"
	"strings"
)

const hexDigits = "0123456789abcdef"

// CanonicalMAC 把认得出来的 48 位 MAC 归一成小写冒号写法（aa:bb:cc:dd:ee:ff）。
// 认不出来返回空串 —— 空串是**信号**：调用方要么原样带着这段文本并说明读不懂，
// 要么丢掉这一条，不许猜一个补上去。
func CanonicalMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// 先按标准写法问一次：这条能接住 aa:bb:cc:dd:ee:ff、大写、以及带连字符的 Windows 写法。
	if h, err := net.ParseMAC(s); err == nil && len(h) == 6 {
		return h.String()
	}
	// BSD 的省零写法（每段 1–2 位）。★ 必须在裸十六进制那一条**之前**补，
	// 因为把冒号去掉之后 "f2:f:38:df:d2:68" 只剩 11 个字符，裸解那条也接不住。
	if padded, ok := padMACGroups(s); ok {
		if h, err := net.ParseMAC(padded); err == nil && len(h) == 6 {
			return h.String()
		}
	}
	// 裸十六进制与点分（cisco 的 aabb.ccdd.eeff）。
	raw := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ', '\t':
			return -1
		}
		return r
	}, strings.ToLower(s))
	if b, err := net.ParseMAC(raw); err == nil && len(b) == 6 {
		return b.String()
	}
	return ""
}

// padMACGroups 把「六段、每段 1–2 位十六进制」补成每段两位。
//
// ★ 形状卡死在六段：拿「看起来像」就补齐，会把 `1:2:3` 这类根本不是 MAC 的
// 串喂进 MAC 那一栏，而多出来的是图上、表里一个不存在的设备。
func padMACGroups(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return "", false
	}
	out := make([]string, 6)
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return "", false
		}
		for _, r := range p {
			if !strings.ContainsRune(hexDigits, r) {
				return "", false
			}
		}
		if len(p) == 1 {
			p = "0" + p
		}
		out[i] = p
	}
	return strings.Join(out, ":"), true
}
