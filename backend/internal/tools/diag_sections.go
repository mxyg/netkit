package tools

// 诊断包里每一项的渲染。★ 每一项都是「原文 + 一句怎么读」，不是结论的复述：
// 包是给**不在现场的人**看的，他手上没有这台机器，所以应该比现场信息更多，不是更少。
//
// 判定分三档，界线是「读不到是这台机器的问题，还是调用方的选择」：
//
//	secRead       —— 读到了。内容可以为空，空也是一种答案（比如「没配系统代理」）
//	secUnreadable —— 想读但读不到：权限不够、平台没这个读法、命令没装。必须进包写明原因
//	secSkipped    —— 调用方让它别跑（skipLive）

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
)

// renderSection 跑一项，返回写进包里的文本、这一项的判定、以及一句给界面看的原因。
//
// ★ 读不到不当错误返回：它是包的内容之一。err 只留给参数不合法这类真失败。
func renderSection(ctx context.Context, name string, a bundleArgs, src bundleSources,
	now time.Time) (text, code, reason string, err error) {
	switch name {
	case secSystem:
		return renderSystem(src, now)
	case secNIC:
		return renderNICs(src)
	case secRoutes:
		return renderRoutes(src)
	case secNeighbors:
		return renderNeighbors(ctx, src)
	case secDNS:
		return renderDNS(src)
	case secHosts:
		return renderHosts(src)
	case secProxy:
		return renderProxy(ctx, src)
	case secPorts:
		return renderPorts(ctx, src)
	case secJournal:
		return renderJournal(src)
	case secCheckup:
		return renderCheckup(ctx, a, src)
	}
	return "", secUnreadable, "不认识的项：" + name, nil
}

func renderSystem(src bundleSources, now time.Time) (string, string, string, error) {
	var b strings.Builder
	_, offset := now.Zone()
	b.WriteString("这台机器的身份与时间。日志对不上，多半就是这一页的事。\n\n")
	if hn, err := src.hostname(); err == nil {
		fmt.Fprintf(&b, "主机名：%s\n", hn)
	} else {
		fmt.Fprintf(&b, "主机名：没读到 —— %s\n", err)
	}
	fmt.Fprintf(&b, "平台：%s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "NetKit 版本：%s\n", netkitVersion())
	fmt.Fprintf(&b, "打这个包的本地时间：%s（时区 %s，UTC 偏移 %+d 秒）\n",
		now.Format("2006-01-02 15:04:05"), now.Format("MST"), offset)
	fmt.Fprintf(&b, "同一时刻的 UTC：%s\n", now.UTC().Format(time.RFC3339))
	if dir, err := src.outDir(); err == nil {
		fmt.Fprintf(&b, "包的输出目录：%s\n", dir)
	}
	if priv := privilegeLine(); priv != "" {
		fmt.Fprintf(&b, "权限：%s\n", priv)
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · 时钟偏了会让证书校验、日志排序、鉴权全部出错。这一台的时间准不准，\n")
	b.WriteString("    看「02 连通性/连通性体检.txt」里 clock 那一项 —— 它是拿权威时间源对出来的。\n")
	b.WriteString("  · 权限那一行决定了后面几项为什么读得到、读不到：邻居表、进程名、hosts\n")
	b.WriteString("    在非管理员下经常读不全，那不是这台机器没配。\n")
	return b.String(), secRead, "", nil
}

// privilegeLine 一句「现在是不是高权限」。
//
// ★ Windows 上不猜：判断是否管理员要动 token API，猜错的代价是把所有「读不到」都归因成权限，
//
//	所以那边留空，让人看每一项自己写的原因。
func privilegeLine() string {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Geteuid() == 0 {
			return "root（邻居表、进程名、hosts 都读得到）"
		}
		return fmt.Sprintf("普通用户（euid %d）—— 有几项可能读不到，以每一项自己写的原因为准", os.Geteuid())
	}
	return ""
}

func renderNICs(src bundleSources) (string, string, string, error) {
	nics, err := src.nics()
	if err != nil {
		return "", secUnreadable, fmt.Sprintf(
			"网卡与地址读不到：%s\n"+
				"★ 这不是「这台没有网卡」。这一页是别的所有项的地基，它读不到时，"+
				"包里的路由、邻居、体检都是按残缺的网卡清单得出的。", err), nil
	}
	var b strings.Builder
	b.WriteString("每块网卡一段，地址列在它下面。★ v6 一块卡上天生有好几个地址，别按「一卡一 IP」读。\n\n")
	if len(nics) == 0 {
		b.WriteString("（一块网卡都没读到 —— 系统调用通了，返回是空的）\n")
		return b.String(), secRead, "", nil
	}
	for _, n := range nics {
		fmt.Fprintf(&b, "%s  index %d  %s  mtu %d%s\n", n.Name, n.Index, linkState(n), n.MTU, virtualMark(n))
		if n.MAC != "" {
			fmt.Fprintf(&b, "    MAC    %s\n", n.MAC)
		}
		fmt.Fprintf(&b, "    介质   %s\n", kindLine(n))
		fmt.Fprintf(&b, "    判定   %s\n", string(n.Verdict.Code))
		if len(n.Verdict.Networks) > 0 {
			fmt.Fprintf(&b, "    网段   %s\n", strings.Join(n.Verdict.Networks, "、"))
		}
		for _, ad := range n.Addrs {
			fmt.Fprintf(&b, "    %s\n", addrLine(ad, n.Name))
		}
		if len(n.Addrs) == 0 {
			b.WriteString("    （一个地址都没有）\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("怎么读这一页：\n")
	b.WriteString("  · 介质写着「按网卡名猜的」那条不是系统告诉的 —— 现场照这一列去插线时先看它。\n")
	b.WriteString("  · 「启用了但没连上」和「没启用」是两件事：前者是线/信号的问题，后者是被谁关了。\n")
	return b.String(), secRead, "", nil
}

func linkState(n netif.NIC) string {
	switch {
	case n.Loop:
		return "环回"
	case !n.Up:
		return "没启用"
	case !n.Running:
		return "启用了，但没连上"
	default:
		return "启用且插着线"
	}
}

func virtualMark(n netif.NIC) string {
	if n.Loop || !n.Virtual {
		return ""
	}
	return "  虚拟（容器/虚拟机/VPN 建的）"
}

func kindLine(n netif.NIC) string {
	switch {
	case n.Kind == "":
		return "不知道"
	case n.KindSrc == "name":
		return n.Kind + "（按网卡名猜的，系统没说）"
	case n.KindSrc == "":
		return n.Kind
	default:
		return n.Kind + "（来源：" + n.KindSrc + "）"
	}
}

// addrLine 一个地址一行，把「这地址能不能当身份」写在同一行里。
//
// ★ v6 的隐私临时地址会定期换：现场把它抄进白名单、登记表，过两天就对不上号了 ——
//
//	这一句必须跟在地址后面，而不是写在文档里。
func addrLine(ad netaddr.Addr, ifname string) string {
	s := ad.IP.String()
	if ad.Prefix > 0 {
		s += fmt.Sprintf("/%d", ad.Prefix)
	}
	fam := "inet "
	if ad.Is6() {
		fam = "inet6"
	}
	switch {
	case ad.Is6() && ad.IP.IsLinkLocalUnicast():
		s += fmt.Sprintf("  链路本地（每台都有，不能当身份；要带 %%%s 才连通）", ifname)
	case ad.Is6() && ad.IP.IsPrivate():
		// netip 对 v6 的 IsPrivate 认的就是 fc00::/7（ULA）
		s += "  ULA（内网自配，出不了公网）"
	case ad.Is6() && ad.Temporary:
		s += "  ★ 隐私临时地址，会定期换 —— 别拿去绑定、登记、进白名单"
	case !ad.Is6() && ad.IP.IsLoopback():
		s += "  环回"
	}
	return fam + "  " + s
}

func renderRoutes(src bundleSources) (string, string, string, error) {
	routes, err := src.routes()
	if err != nil {
		return "", secUnreadable, fmt.Sprintf(
			"整张路由表读不到：%s\n★ 默认路由是另一档读法；如果下面那一段读到了，"+
				"说明只是整表读不全，「去往 X 走哪块网卡」仍然可以判。", err), nil
	}
	defs, derr := src.defRoute()
	var b strings.Builder
	b.WriteString("去往哪个地址走哪条路，全在这一页。默认路由排在最前面。\n\n")
	if derr != nil {
		fmt.Fprintf(&b, "（默认路由没能单独读到：%s —— 下面按整张表里的 0.0.0.0/0 与 ::/0 认）\n\n", derr)
	}
	b.WriteString("默认路由：\n")
	if len(defs) == 0 {
		defs = defaultsFromTable(routes)
	}
	if len(defs) == 0 {
		b.WriteString("  （一条都没有：这台除了本网段哪都去不了 —— 这就是「上不去」的直接原因）\n")
	}
	for _, d := range defs {
		if d.Gateway == "" {
			fmt.Fprintf(&b, "  %-5s 出口 %-14s （没有下一跳：点对点或按前缀直连）\n", d.Family, orDash(d.Iface))
		} else {
			fmt.Fprintf(&b, "  %-5s 下一跳 %-18s 出口 %s\n", d.Family, d.Gateway, orDash(d.Iface))
		}
	}
	if !hasFamily(defs, "ipv6") {
		b.WriteString("  ★ 没有 v6 默认路由：这台出不了 v6，双栈应用会先卡在 v6 上再回落。\n")
	}
	if !hasFamily(defs, "ipv4") {
		b.WriteString("  ★ 没有 v4 默认路由：v4 那边哪都去不了。\n")
	}
	b.WriteString("\n整张表：\n")
	shown := limitRoutes(routes, maxRouteLines)
	trunc := len(routes) > maxRouteLines
	for _, r := range shown {
		fmt.Fprintf(&b, "  %-5s %-22s 下一跳 %-18s 出口 %-12s metric %-4s%s%s\n",
			r.Family, r.Destination, orDash(r.Gateway), orDash(r.Iface), metricCell(r.Metric),
			directMark(r), srcMark(r))
	}
	if trunc {
		fmt.Fprintf(&b, "  ……（还有 %d 条没列：包有大小上限，全部要看用 net.routes 单独查一次）\n",
			len(routes)-maxRouteLines)
	}
	if len(routes) == 0 {
		b.WriteString("  （表是空的 —— 系统调用通了但一条路都没有，这本身就是结论）\n")
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · metric 越小越优先；macOS 的读法不给 metric，那边这一栏全是 0 不是没配。\n")
	b.WriteString("  · 标了「直连」的是本网段的路，不经网关；其余才谈得上「出不出得去」。\n")
	return b.String(), secRead, "", nil
}

// defaultsFromTable 默认路由那一档读不到时，从整张表里认 0.0.0.0/0 与 ::/0。
//
// ★ 只拿来兜底，兜出来的东西照样进包并写明是兜的 —— 两条读法不一致本身就是线索。
func defaultsFromTable(routes []netif.Route) []netif.DefaultRoute {
	var out []netif.DefaultRoute
	for _, r := range routes {
		if r.Destination != "0.0.0.0/0" && r.Destination != "::/0" {
			continue
		}
		out = append(out, netif.DefaultRoute{Family: r.Family, Gateway: r.Gateway, Iface: r.Iface})
	}
	return out
}

func limitRoutes(rs []netif.Route, n int) []netif.Route {
	sorted := sortedRoutes(rs) // 复用 net.routes 的排序：默认路由与 v4 在前
	if len(sorted) > n {
		return sorted[:n]
	}
	return sorted
}

func hasFamily(defs []netif.DefaultRoute, fam string) bool {
	for _, d := range defs {
		if d.Family == fam {
			return true
		}
	}
	return false
}

func metricCell(m int) string {
	if m == 0 {
		return "0?"
	}
	return fmt.Sprintf("%d", m)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func directMark(r netif.Route) string {
	if r.Direct {
		return "  直连"
	}
	return ""
}

func srcMark(r netif.Route) string {
	if r.Src == "" {
		return ""
	}
	return "  src " + r.Src
}

func renderNeighbors(ctx context.Context, src bundleSources) (string, string, string, error) {
	v4, e4 := src.neigh4(ctx)
	v6, e6 := src.neigh6(ctx)
	if e4 != nil && e6 != nil {
		return "", secUnreadable, fmt.Sprintf(
			"邻居表两族都没读到。\n  IPv4（ARP）：%s\n  IPv6（NDP）：%s\n"+
				"★ 这两张表是分开的读法，一个失败不代表另一个也没有；这里两个都失败，"+
				"通常是这台没有 arp/ndp 的读法或者要 root。别当成「这个网段没有别的设备」。", e4, e6), nil
	}
	var b strings.Builder
	b.WriteString("本机最近打过交道的同网段设备。IPv4 是 ARP 表，IPv6 是 NDP 邻居表，两张不同的表。\n\n")
	if e4 != nil {
		fmt.Fprintf(&b, "IPv4 这一半没读到：%s\n\n", e4)
	}
	if e6 != nil {
		fmt.Fprintf(&b, "IPv6 这一半没读到：%s\n\n", e6)
	}
	b.WriteString(neighTable("IPv4 / ARP", v4, false))
	b.WriteString("\n")
	b.WriteString(neighTable("IPv6 / NDP", v6, true))
	if len(v4) == 0 && len(v6) == 0 && e4 == nil && e6 == nil {
		b.WriteString("\n（两张表都是空的：这台刚重启、或者从没跟同网段说过话 ——" +
			"缓存里只记说过话的，所以这不是「网段里没有设备」）\n")
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · MAC 为空是正常的（有些状态不带 MAC，或者读的时候缓存刚被清）。\n")
	b.WriteString("  · 想找「某个 MAC 是哪台设备」，这一页比扫描快，而且不打扰设备（纯读本机缓存）。\n")
	return b.String(), secRead, "", nil
}

func neighTable(title string, ns []neighbor, wide bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s：%d 条\n", title, len(ns))
	shown := ns
	if len(shown) > maxNeighLines {
		shown = shown[:maxNeighLines]
	}
	for _, n := range shown {
		if wide {
			fmt.Fprintf(&b, "  %-40s %-20s %-14s %s\n", n.Addr, orDash(n.MAC), orDash(n.Iface), n.State)
			continue
		}
		fmt.Fprintf(&b, "  %-24s %-20s %-14s %s\n", n.Addr, orDash(n.MAC), orDash(n.Iface), n.State)
	}
	if len(ns) > maxNeighLines {
		fmt.Fprintf(&b, "  ……（还有 %d 条没列：包有大小上限）\n", len(ns)-maxNeighLines)
	}
	return b.String()
}

func renderDNS(src bundleSources) (string, string, string, error) {
	servers, err := src.dns()
	if err != nil {
		return "", secUnreadable, fmt.Sprintf(
			"系统配的 DNS 服务器读不到：%s\n★ 读不到不等于「没配」：这台可能从 DHCP 拿到了，"+
				"只是这一档读法看不见。", err), nil
	}
	var b strings.Builder
	b.WriteString("这台机器问谁解析域名。★ 这只是配置，不等于解析得出来 —— 那要看体检里的 dns 一项。\n\n")
	if len(servers) == 0 {
		b.WriteString("（一条都没读到：这台没配 DNS，或者系统把它放在了这个读法看不到的地方）\n")
		return b.String(), secRead, "", nil
	}
	for _, s := range servers {
		line := "  " + s.Addr
		if s.Iface != "" {
			line += "  只走 " + s.Iface
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · 顺序就是尝试顺序：第一台慢，全部查询都跟着慢，哪怕第二台是好的。\n")
	b.WriteString("  · 「只走某块网卡」是按网卡分开的服务器（VPN 常见的分流）；没有这栏就是全局的。\n")
	return b.String(), secRead, "", nil
}

func renderHosts(src bundleSources) (string, string, string, error) {
	path, text, err := src.hosts()
	if err != nil {
		return "", secUnreadable, fmt.Sprintf(
			"hosts 文件读不到（%s）：%s\n★ 现场最常见的场景正是「有人在本机 hosts 里指过一条」，"+
				"这一页读不到就得手动去看那个文件。", path, err), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "路径：%s\n\n", path)
	lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
	active := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			active++
		}
	}
	fmt.Fprintf(&b, "一共 %d 行，其中生效的条目 %d 行（其余是注释与空行）。\n\n", len(lines), active)
	shown := lines
	if len(shown) > maxHostsLines {
		shown = shown[:maxHostsLines]
	}
	for _, l := range shown {
		b.WriteString("  " + strings.TrimRight(l, "\r") + "\n")
	}
	if len(lines) > maxHostsLines {
		fmt.Fprintf(&b, "  ……（还有 %d 行没列：这个文件太长，包有大小上限）\n", len(lines)-maxHostsLines)
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · hosts 排在 DNS 之前：这里指了一条，DNS 配得再对也不会生效。" +
		"「解析出来为什么是那个地址」常常就出在这里。\n")
	return b.String(), secRead, "", nil
}

func renderProxy(ctx context.Context, src bundleSources) (string, string, string, error) {
	summary, vals := src.proxy(ctx)
	var b strings.Builder
	b.WriteString("系统代理。★ 这里只有 host:port：带账号密码的代理地址从来不进结果，" +
		"省掉的是别人的口令，不是这条线索。\n\n")
	if summary == "" && len(vals) == 0 {
		b.WriteString("（没配系统代理）\n")
		return b.String(), secRead, "", nil
	}
	if summary != "" {
		fmt.Fprintf(&b, "生效的：%s\n", summary)
	}
	for _, k := range sortedFactKeys(vals) {
		fmt.Fprintf(&b, "  %-18s %s\n", k, factValue(vals[k]))
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · 命令行工具看 http_proxy 这类环境变量，浏览器看系统设置 —— 两边不一致时，" +
		"「浏览器能开、程序连不上」就是这么来的。\n")
	return b.String(), secRead, "", nil
}

func renderPorts(ctx context.Context, src bundleSources) (string, string, string, error) {
	uses, partial, err := src.ports(ctx)
	if err != nil {
		return "", secUnreadable, fmt.Sprintf(
			"本机端口占用读不到：%s\n★ 「去起服务会不会撞口」这一类问题，这一页是唯一的答案。", err), nil
	}
	var b strings.Builder
	b.WriteString("谁在听哪个口、以及已经连出去了哪些。★ 同一个口 v4 与 v6 各听一遍是两种毛病，分开列。\n\n")
	if partial {
		b.WriteString("（部分条目的进程名或用户没读到：这台不是 root，或者那条 socket 属于别的用户。\n" +
			"端口与状态还是准的。）\n\n")
	}
	var listen, other []portUse
	for _, u := range uses {
		if u.listening() {
			listen = append(listen, u)
		} else {
			other = append(other, u)
		}
	}
	fmt.Fprintf(&b, "在听的：%d 条\n", len(listen))
	writePorts(&b, listen)
	fmt.Fprintf(&b, "\n已建立或其他状态：%d 条\n", len(other))
	writePorts(&b, other)
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · 只听在 ::（v6）上的服务，v4 那边可能让给了别的进程 ——" +
		"这是「同一个口两个答案」的常见来源。\n")
	b.WriteString("  · syn-recv 也算被占着：那是半开的监听队列，去起服务照样撞口。\n")
	return b.String(), secRead, "", nil
}

func writePorts(b *strings.Builder, us []portUse) {
	shown := us
	if len(shown) > maxPortLines {
		shown = shown[:maxPortLines]
	}
	for _, u := range shown {
		line := fmt.Sprintf("  %-4s %-6s %s:%-6d %s", u.Proto, u.Family, orDash(u.Local), u.Port, orDash(u.State))
		if u.Foreign != "" {
			line += "  → " + u.Foreign
		}
		b.WriteString(line + "  " + whoLine(u) + "\n")
	}
	if len(us) > maxPortLines {
		fmt.Fprintf(b, "  ……（还有 %d 条没列：包有大小上限）\n", len(us)-maxPortLines)
	}
}

func whoLine(u portUse) string {
	parts := []string{}
	if u.Process != "" {
		parts = append(parts, u.Process)
	}
	if u.User != "" {
		parts = append(parts, "用户 "+u.User)
	}
	if u.Pid > 0 {
		parts = append(parts, fmt.Sprintf("pid %d", u.Pid))
	}
	if len(parts) == 0 {
		return "进程名没读到"
	}
	return strings.Join(parts, "、")
}

func renderJournal(src bundleSources) (string, string, string, error) {
	entries := src.journal()
	var b strings.Builder
	b.WriteString("NetKit 在这台上改过什么、还原了没有。★ 现场排障第一问经常是「谁改的、改回了吗」，" +
		"这一页就是那个答案。\n\n")
	if len(entries) == 0 {
		b.WriteString("（没有登记过的改动：这台没启用改系统的功能，或者从来没动过配置。）\n")
		return b.String(), secRead, "", nil
	}
	start := 0
	if len(entries) > maxJournalLines {
		start = len(entries) - maxJournalLines
	}
	for _, e := range entries[start:] {
		fmt.Fprintf(&b, "  %s  %s  [%s]  %s\n", e.At.Format("2006-01-02 15:04:05"), e.Kind, e.Status, e.What)
		if e.Note != "" {
			fmt.Fprintf(&b, "      备注     %s\n", e.Note)
		}
		fmt.Fprintf(&b, "      改之前   %s\n", briefJSON(e.Before))
		fmt.Fprintf(&b, "      改成     %s\n", briefJSON(e.After))
	}
	if start > 0 {
		fmt.Fprintf(&b, "\n……（只列最近 %d 笔，一共 %d 笔：更早的已经被后来的覆盖了）\n",
			maxJournalLines, len(entries))
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · pending 表示登记了但没做完（上次崩在中间），applied 是生效中，reverted 是已还原。\n")
	b.WriteString("  · 还留着 applied 的那些，就是这台与出厂不一样的地方 —— 先想着还原，再查别的。\n")
	return b.String(), secRead, "", nil
}

// briefJSON 账本里的 Before/After 原样收进来会很长，压成一行并截断。
// ★ 只截断不改写：这一页是拿回去比对「原来是什么」的，改写它就没用了。
func briefJSON(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return "（原来没有这一项）"
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxValueLineChar {
		return fmt.Sprintf("%s ……（共 %d 字节，完整内容用对应的工具单独查）",
			s[:maxValueLineChar], len(s))
	}
	return s
}

// renderCheckup 把一键体检的八项原文收进来。★ 这一项要发探测包，调用方可以要求跳过；
// 但跳过了也要在包里留一行 —— 不然对方会把「没跑」读成「跑了什么都没跑出来」。
func renderCheckup(ctx context.Context, a bundleArgs, src bundleSources) (string, string, string, error) {
	if a.SkipLive {
		return "（这一项按调用方要求跳过：它要发探测包。）\n" +
			"★ 所以这个包里没有「到网关丢不丢、DNS 解析得出来吗、出不出得去公网」的实测答案，只有配置。\n" +
			"  要看行为，去掉 skipLive 再打一次包。\n", secSkipped, "skipped-live", nil
	}
	items, notes, err := src.checkup(ctx, bundleCheckupArgs(a), 6, 2*time.Second, src.probes())
	if err != nil {
		return "", secUnreadable, fmt.Sprintf(
			"体检没跑成：%s\n★ 配置那几页仍然在包里；缺的这一页是「实测」，不是「没配」。", err), nil
	}
	top, first := rollup(items)
	var b strings.Builder
	b.WriteString("按排查顺序跑的八项。★ 顶层只说第一个坏掉的是哪一步 —— 顺序有意义：网关丢包时，\n")
	b.WriteString("后面 DNS 和出口的慢都是链路的、不是服务的，所以不能从中间开始查。\n\n")
	fmt.Fprintf(&b, "顶层判定：%s\n", top)
	if first != "" {
		fmt.Fprintf(&b, "第一个坏掉的步骤：%s\n", first)
	}
	b.WriteString("\n")
	for _, it := range items {
		fmt.Fprintf(&b, "  %-9s %-24s %s\n", it.Step, it.Code, it.Severity)
		for _, k := range sortedFactKeys(it.Facts) {
			fmt.Fprintf(&b, "      %-22s %s\n", k, factValue(it.Facts[k]))
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n体检附带的值：\n")
		for _, k := range sortedFactKeys(notes) {
			fmt.Fprintf(&b, "  %-22s %s\n", k, factValue(notes[k]))
		}
	}
	b.WriteString("\n怎么读这一页：\n")
	b.WriteString("  · severity 是 bad 的才需要现在动手；warn 是「值得看一眼，但不必停在这」。\n")
	b.WriteString("  · 网关那一项 warn 不一定是毛病：现场很多路由器默认拦 ICMP。\n")
	return b.String(), secRead, top, nil
}

// bundleCheckupArgs 补齐体检的默认值。★ 与 net.checkup 里那一份必须一致，
// 否则「包里的体检」和「界面上那一体检」会给出不同答案 —— 两边都有人看，谁都不知道该信谁。
func bundleCheckupArgs(a bundleArgs) checkupArgs {
	ca := checkupArgs{
		Domain:    a.Domain,
		LanProbes: 6,
		TimeoutMS: 2000,
	}
	if ca.Domain == "" {
		ca.Domain = "www.cloudflare.com"
	}
	return ca
}

func sortedFactKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// factValue 一个事实值写成一行。★ 嵌套的结构压成紧凑 JSON，不铺开：
// 铺开的文本在记事本里没法看，而这一栏存在的理由正是「在记事本里也能看」。
func factValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		return oneLine(t)
	case bool:
		if t {
			return "是"
		}
		return "否"
	default:
		blob, err := json.Marshal(t)
		if err != nil {
			return oneLine(fmt.Sprintf("%v", v))
		}
		return oneLine(string(blob))
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " ……（多行，完整版用对应的工具单独查）"
	}
	if len(s) > maxValueLineChar {
		return s[:maxValueLineChar] + " ……"
	}
	return s
}

// readHostsFile 读本机的 hosts。★ 只读那一个文件，不去读「类似的」别的东西：
// 现场要知道的就是这个名字的东西里写了什么。
func readHostsFile() (string, string, error) {
	path := hostsPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return path, "", err
	}
	return path, string(b), nil
}

// hostsPath 各平台 hosts 的位置。Windows 上 %SystemRoot% 拿不到时退回默认装机路径 ——
// 留这个退路是因为读不到的原因文本里要把路径说给人看，不能写一个空字符串。
func hostsPath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}
