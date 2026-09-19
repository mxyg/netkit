package tools

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// neighbor 邻居表里的一条。
type neighbor struct {
	Addr   string `json:"addr"`
	MAC    string `json:"mac,omitempty"`
	Iface  string `json:"iface,omitempty"`
	Family string `json:"family"` // ipv4 / ipv6
	State  string `json:"state,omitempty"`
}

var neighborsTool = ots.Tool{
	Name:  "net.neighbors",
	Class: ots.ClassRead,
	Summary: "读本机的邻居表，列出最近打过交道的同网段设备：IP、MAC、走哪块网卡。" +
		"★ IPv4 读的是 ARP 表，IPv6 读的是 NDP 邻居表 —— 是两张不同的表，这里一并给出。" +
		"现场用它快速回答「这个网段上都有谁」「某个 MAC 对应哪个 IP」，" +
		"比扫描快得多且不打扰设备（纯读本机缓存，不发任何包）。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "family": {"type": "string", "enum": ["ipv4", "ipv6", "both"],
	      "description": "只看哪一族，默认 both。"},
	    "iface": {"type": "string", "description": "只看某块网卡，如 en0 / eth0。"}
	  }
	}`),
	Invoke: readNeighbors,
}

type neighArgs struct {
	Family string `json:"family,omitempty"`
	Iface  string `json:"iface,omitempty"`
}

func readNeighbors(ctx context.Context, raw json.RawMessage) (any, error) {
	var a neighArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	switch a.Family {
	case "", "both", "ipv4", "ipv6":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument, "family 只能是 ipv4 / ipv6 / both，给的是 %q", a.Family)
	}
	want4 := a.Family == "" || a.Family == "both" || a.Family == "ipv4"
	want6 := a.Family == "" || a.Family == "both" || a.Family == "ipv6"

	var out []neighbor
	var failed []string
	if want4 {
		n, err := neighborsV4(ctx)
		if err != nil {
			failed = append(failed, "IPv4："+err.Error())
		}
		out = append(out, n...)
	}
	if want6 {
		n, err := neighborsV6(ctx)
		if err != nil {
			failed = append(failed, "IPv6："+err.Error())
		}
		out = append(out, n...)
	}
	if a.Iface != "" {
		var f []neighbor
		for _, n := range out {
			if n.Iface == a.Iface {
				f = append(f, n)
			}
		}
		out = f
	}
	if out == nil {
		out = []neighbor{}
	}

	res := map[string]any{"neighbors": out, "count": len(out)}
	if len(failed) > 0 {
		// ★ 一族读失败不该把另一族的结果也丢掉 —— 双栈机器上很常见的情况是
		//   v6 那张表读不到（系统没开 v6 或命令不在），v4 的结果照样有用。
		//   所以如实报告哪一族没读到，而不是整个失败。
		res["unavailable"] = failed
	}
	return res, nil
}

// run 跑一个只读命令，拿标准输出。
//
// ★ 这几个命令都是**只读**的系统工具（arp/ip/ndp/netsh show），
// 归 read 类 [OTS-4.1]。不接受任何来自调用方的字符串拼进命令行 ——
// 参数过滤在上层做，这里只跑固定的命令。
func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.Output()
	return string(b), err
}

func neighborsV4(ctx context.Context) ([]neighbor, error) {
	switch runtime.GOOS {
	case "linux":
		if s, err := run(ctx, "ip", "-4", "neigh", "show"); err == nil {
			return parseIPNeigh(s, "ipv4"), nil
		}
		s, err := run(ctx, "arp", "-an")
		if err != nil {
			return nil, err
		}
		return parseArpAn(s), nil
	case "darwin":
		s, err := run(ctx, "arp", "-an")
		if err != nil {
			return nil, err
		}
		return parseArpAn(s), nil
	case "windows":
		s, err := run(ctx, "arp", "-a")
		if err != nil {
			return nil, err
		}
		return parseWinArp(s), nil
	}
	return nil, ots.Errf(ots.ErrNotSupported, "%s 上还没实现读 ARP 表", runtime.GOOS)
}

func neighborsV6(ctx context.Context) ([]neighbor, error) {
	switch runtime.GOOS {
	case "linux":
		s, err := run(ctx, "ip", "-6", "neigh", "show")
		if err != nil {
			return nil, err
		}
		return parseIPNeigh(s, "ipv6"), nil
	case "darwin":
		s, err := run(ctx, "ndp", "-an")
		if err != nil {
			return nil, err
		}
		return parseNdpAn(s), nil
	case "windows":
		s, err := run(ctx, "netsh", "interface", "ipv6", "show", "neighbors")
		if err != nil {
			return nil, err
		}
		return parseNetshNeighbors(s), nil
	}
	return nil, ots.Errf(ots.ErrNotSupported, "%s 上还没实现读 NDP 表", runtime.GOOS)
}

// parseIPNeigh 解 Linux `ip neigh show`：
//
//	192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
func parseIPNeigh(s, family string) []neighbor {
	var out []neighbor
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		n := neighbor{Addr: f[0], Family: family}
		for i := 1; i < len(f)-1; i++ {
			switch f[i] {
			case "dev":
				n.Iface = f[i+1]
			case "lladdr":
				n.MAC = f[i+1]
			}
		}
		n.State = f[len(f)-1]
		// ★ FAILED / INCOMPLETE 的条目留着但标出来 —— 它们本身就是有用的信息
		//   （「这个地址试过但没人应」），删掉反而丢了线索。
		out = append(out, n)
	}
	return out
}

// parseArpAn 解 BSD/macOS `arp -an`：
//
//	? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
func parseArpAn(s string) []neighbor {
	var out []neighbor
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		i, j := strings.Index(l, "("), strings.Index(l, ")")
		if i < 0 || j <= i {
			continue
		}
		n := neighbor{Addr: l[i+1 : j], Family: "ipv4"}
		f := strings.Fields(l[j+1:])
		for k := 0; k < len(f)-1; k++ {
			switch f[k] {
			case "at":
				if f[k+1] != "(incomplete)" {
					n.MAC = f[k+1]
				} else {
					n.State = "incomplete"
				}
			case "on":
				n.Iface = f[k+1]
			}
		}
		out = append(out, n)
	}
	return out
}

// parseNdpAn 解 macOS `ndp -an`：
//
//	Neighbor          Linklayer Address  Netif Expire    St Flgs Prbs
//	fe80::1%en0       aa:bb:cc:dd:ee:ff  en0   23h59m50s R  R
func parseNdpAn(s string) []neighbor {
	var out []neighbor
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || strings.HasPrefix(line, "Neighbor") {
			continue
		}
		// ★ 地址可能带 zone（fe80::1%en0）。统一走 netaddr 解，
		//   接口名从 zone 里取 —— 手工切 % 迟早切错。
		n := neighbor{Family: "ipv6"}
		if a, err := netaddr.Parse(f[0]); err == nil {
			n.Addr = a.String()
			n.Iface = a.Zone
		} else {
			n.Addr = f[0]
		}
		if strings.Contains(f[1], ":") {
			n.MAC = f[1]
		}
		if n.Iface == "" && len(f) >= 3 {
			n.Iface = f[2]
		}
		if len(f) >= 5 {
			n.State = f[4]
		}
		out = append(out, n)
	}
	return out
}

// parseWinArp 解 Windows `arp -a`：
//
//	接口: 192.168.1.10 --- 0xb
//	  Internet 地址         物理地址              类型
//	  192.168.1.1           aa-bb-cc-dd-ee-ff     动态
func parseWinArp(s string) []neighbor {
	var out []neighbor
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || !strings.Contains(f[1], "-") {
			continue
		}
		if _, err := netaddr.Parse(f[0]); err != nil {
			continue
		}
		n := neighbor{Addr: f[0], MAC: strings.ReplaceAll(f[1], "-", ":"), Family: "ipv4"}
		if len(f) >= 3 {
			n.State = f[2]
		}
		out = append(out, n)
	}
	return out
}

// parseNetshNeighbors 解 Windows `netsh interface ipv6 show neighbors`。
func parseNetshNeighbors(s string) []neighbor {
	var out []neighbor
	iface := ""
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Interface ") || strings.HasPrefix(t, "接口 ") {
			if i := strings.Index(t, ":"); i > 0 {
				iface = strings.TrimSpace(strings.Trim(t[i+1:], " -"))
			}
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		a, err := netaddr.Parse(f[0])
		if err != nil || !a.Is6() {
			continue
		}
		n := neighbor{Addr: a.String(), Family: "ipv6", Iface: iface}
		if strings.Contains(f[1], "-") {
			n.MAC = strings.ReplaceAll(f[1], "-", ":")
		}
		if len(f) >= 3 {
			n.State = f[len(f)-1]
		}
		out = append(out, n)
	}
	return out
}
