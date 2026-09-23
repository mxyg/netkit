package netif

import (
	"encoding/json"
	"strings"
)

// DefaultRoute 一条默认路由（某个地址族「出不了本网时往哪走」）。
//
// ★ 为什么双栈体检非读它不可：现场最难查的那类 v6 问题是
//
//	「有地址、有默认路由，却出不了外网」—— 没有默认路由这一项，
//	就分不清到底是「压根没路」还是「有路但上游不通」，结论会差很远。
//
//	Gateway 对 v6 链路本地网关会带 zone（fe80::1%en0），原样存，
//	显示和 Dial 时再按平台拼（见 netaddr.Addr）。
type DefaultRoute struct {
	Family  string `json:"family"`  // ipv4 / ipv6
	Gateway string `json:"gateway"` // 下一跳地址；为空表示没有网关（比如点对点链路）
	Iface   string `json:"iface"`   // 出口网卡名（Windows 上 PowerShell 给的是别名）
}

// DefaultRoutes 每个地址族的默认路由。没有就给空切片，不当错误 ——
// 「没有默认路由」本身是体检要报告的一个状态，不是读取失败。
func DefaultRoutes() ([]DefaultRoute, error) { return defaultRoutes() }

// ── 下面是各平台命令输出的**纯解析**，不带 build tag，好让测试在任何机器上都能跑全部平台 ──

// parseNetstatDefault 解析 BSD/macOS 的 `netstat -rn -f inet|inet6`：
//
//	Destination        Gateway            Flags        Netif Expire
//	default            192.168.1.1        UGSc           en0
//
// family 由调用方按 -f 参数给定（输出里不带族信息）。
func parseNetstatDefault(out, family string) []DefaultRoute {
	var rs []DefaultRoute
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != "default" {
			continue
		}
		r := DefaultRoute{Family: family, Gateway: f[1]}
		// Netif 一般在第 4 列（Destination Gateway Flags Netif），但列数会浮动，
		// 取最后一个像网卡名的字段更稳：从后往前找第一个不是纯数字（Expire）的。
		for i := len(f) - 1; i >= 2; i-- {
			if strings.Trim(f[i], "0123456789") != "" {
				r.Iface = f[i]
				break
			}
		}
		rs = append(rs, r)
	}
	return rs
}

// parseIPRouteDefault 解析 Linux 的 `ip -4|-6 route show default`：
//
//	default via 192.168.1.1 dev en0 proto dhcp src 192.168.1.50 metric 600
//
// 可能有多条（多网卡 / 多 metric），全收，family 由调用方给定。
func parseIPRouteDefault(out, family string) []DefaultRoute {
	var rs []DefaultRoute
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		var r DefaultRoute
		r.Family = family
		for i := 0; i < len(f); i++ {
			switch f[i] {
			case "via":
				if i+1 < len(f) {
					r.Gateway = f[i+1]
				}
			case "dev":
				if i+1 < len(f) {
					r.Iface = f[i+1]
				}
			}
		}
		rs = append(rs, r)
	}
	return rs
}

// windowsRouteJSON 对应 PowerShell Get-NetRoute 选出来的字段。
type windowsRouteJSON struct {
	DestinationPrefix string `json:"DestinationPrefix"`
	NextHop           string `json:"NextHop"`
	InterfaceAlias    string `json:"InterfaceAlias"`
}

// parseGetNetRoute 解析 Windows 上
// `Get-NetRoute -DestinationPrefix 0.0.0.0/0,::/0 | Select ... | ConvertTo-Json` 的输出。
//
// ★ ConvertTo-Json 只有一条时给对象、多条时给数组，两种都要认 ——
//
//	只认数组的话单网卡机器上一条默认路由都读不到。
func parseGetNetRoute(out string) []DefaultRoute {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var many []windowsRouteJSON
	if err := json.Unmarshal([]byte(out), &many); err != nil {
		var one windowsRouteJSON
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil
		}
		many = []windowsRouteJSON{one}
	}
	var rs []DefaultRoute
	for _, w := range many {
		fam := ""
		switch w.DestinationPrefix {
		case "0.0.0.0/0":
			fam = "ipv4"
		case "::/0":
			fam = "ipv6"
		default:
			continue
		}
		rs = append(rs, DefaultRoute{Family: fam, Gateway: w.NextHop, Iface: w.InterfaceAlias})
	}
	return rs
}
