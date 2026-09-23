package netif

import (
	"encoding/json"
	"regexp"
	"strings"
)

// DNSServer 一台 DNS 服务器，以及它是哪块网卡配上的。
//
// ★ 为什么要连网卡一起报：现场问「DNS 配的谁」，答案常常是**好几个**（Wi-Fi 一个、
//
//	有线一个、VPN 又一个），而系统按顺序去试 —— 只报第一个会让人以为机器上就配了一个，
//	于是「为什么解析到了内网地址」这种问题永远查不下去。
type DNSServer struct {
	Addr  string `json:"addr"`
	Iface string `json:"iface,omitempty"`
}

// SystemDNSServers 这台机器现在在问哪些 DNS 服务器，按系统给出的顺序。
func SystemDNSServers() ([]DNSServer, error) { return systemDNSServers() }

// ── 各平台命令/文件输出的**纯解析**（不带 build tag，任何机器上都能测全部平台） ──

var scutilServer = regexp.MustCompile(`^\s*nameserver\[\d+\]\s*:\s*(\S+)\s*$`)
var scutilIface = regexp.MustCompile(`^\s*if_(?:name|index)\s*:\s*\S+(?:\s*\((\S+)\))?`)
var scutilResolver = regexp.MustCompile(`^\s*resolver\s*#\d+\s*$`)

// parseScutilDNS 解析 macOS 的 `scutil --dns`。
//
// ★ 为什么不用 /etc/resolv.conf：macOS 上那个文件**不代表系统真正在用的 DNS**
//
//	（网络配置走 SystemConfiguration，resolv.conf 可能根本不存在或是别的上游写的）。
//	按 resolv.conf 读会读出个错的结论。
//
// ★ 网卡那一行必须按**整块**读完再归属：真机输出里它是**跟在 nameserver 后面**的
//
//	（`if_index : 14 (en0)`，接口名在括号里），按「先见到接口名再见到服务器」来解析
//	会一块也归属不上去 —— 这种顺序假设只有真机输出能纠正。
//
// 按 `resolver #N` 分块：一块里可能有接口名，也可能没有（全局 resolver 就没有）。
// mDNS 那几块（domain local / options mdns）没有 nameserver，天然被跳过。
func parseScutilDNS(out string) []DNSServer {
	var res []DNSServer
	seen := map[string]bool{}
	var blockAddrs []string
	blockIface := ""

	flush := func() {
		for _, a := range blockAddrs {
			if seen[a] {
				continue // 多个 resolver 指向同一台服务器时不重复报
			}
			seen[a] = true
			res = append(res, DNSServer{Addr: a, Iface: blockIface})
		}
		blockAddrs, blockIface = nil, ""
	}

	for _, ln := range strings.Split(out, "\n") {
		switch {
		case scutilResolver.MatchString(ln):
			flush()
		case scutilIface.MatchString(ln):
			m := scutilIface.FindStringSubmatch(ln)
			if m[1] != "" {
				blockIface = m[1]
			}
		case scutilServer.MatchString(ln):
			blockAddrs = append(blockAddrs, scutilServer.FindStringSubmatch(ln)[1])
		}
	}
	flush()
	return res
}

// parseResolvConf 解析 Linux 的 /etc/resolv.conf（`nameserver <addr>` 一行一个）。
//
// ★ 只认 nameserver：options/search/domain 这些和「问谁」无关，混进来会变成噪音。
//
//	systemd-resolved 的机器上这里往往是 127.0.0.53 存根 —— 如实报出来，
//	不偷偷替它展开成真实上游（那会让「本机在问存根」这个重要事实消失）。
func parseResolvConf(text string) []DNSServer {
	var res []DNSServer
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		res = append(res, DNSServer{Addr: f[1]})
	}
	return res
}

// parseWinDNSServer 解析 Windows 上
// `Get-DnsClientServerAddress | Where ServerAddresses | Select InterfaceAlias,ServerAddresses | ConvertTo-Json`。
//
// ★ ConvertTo-Json 的坑和路由那边一样：**只有一个接口时给对象、多个时给数组**，
//
//	ServerAddresses 只有一条时又可能是字符串而不是数组。三种形态都要认，
//	只认一种的症状是「有时读得到有时读不到」，最难查。
func parseWinDNSServer(out string) []DNSServer {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var rows []winDNSServerJSONRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		var one winDNSServerJSONRow
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil
		}
		rows = []winDNSServerJSONRow{one}
	}
	var res []DNSServer
	seen := map[string]bool{}
	for _, r := range rows {
		for _, a := range r.addrList() {
			if a == "" || seen[a] {
				continue
			}
			seen[a] = true
			res = append(res, DNSServer{Addr: a, Iface: r.InterfaceAlias})
		}
	}
	return res
}

// winDNSServerJSONRow 是中间结构，专门用来吸收 ServerAddresses 的两种形态。
type winDNSServerJSONRow struct {
	InterfaceAlias  string          `json:"InterfaceAlias"`
	ServerAddresses json.RawMessage `json:"ServerAddresses"`
}

func (r winDNSServerJSONRow) addrList() []string {
	if len(r.ServerAddresses) == 0 {
		return nil
	}
	var many []string
	if err := json.Unmarshal(r.ServerAddresses, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(r.ServerAddresses, &one); err == nil {
		return []string{one}
	}
	return nil
}
