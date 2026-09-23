package tools

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.subnet.scan 的测试 ──
//
// ★ 这里测的是「清单是怎么来的」和「每台凭什么被判在线」。
//   真发 ICMP 的部分只打在回环上（必然有回执）和保留段（必然没回执），
//   两种凑齐了就不用伪造网络状况。

func mustPfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("%s：%v", s, err)
	}
	return p.Masked()
}

func addrsOf(xs []netip.Addr) []string {
	out := make([]string, len(xs))
	for i, a := range xs {
		out[i] = a.String()
	}
	return out
}

// ── 要问哪些地址 ──

// ★ 网络地址和广播地址都不问：前者不是主机地址，后者会引来整段设备一起答，
//
//	那张表就没法读了（而且最容易被当成攻击流量）。
func Test网段展开时两头都不问(t *testing.T) {
	got := addrsOf(hostList([]netip.Prefix{mustPfx(t, "192.168.1.0/30")}))
	if strings.Join(got, ",") != "192.168.1.1,192.168.1.2" {
		t.Errorf("展开成 %v，应该只有 .1 .2（.0 是网段地址、.3 是广播）", got)
	}
	all := hostList([]netip.Prefix{mustPfx(t, "10.0.0.0/24")})
	if len(all) != 254 {
		t.Errorf("/24 展开了 %d 个地址，应该 254", len(all))
	}
	if all[0].String() != "10.0.0.1" || all[len(all)-1].String() != "10.0.0.254" {
		t.Errorf("两头是 %s 和 %s", all[0], all[len(all)-1])
	}
}

func Test按地址数值排序(t *testing.T) {
	got := addrsOf(hostList([]netip.Prefix{mustPfx(t, "10.0.0.0/29")}))
	want := "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6"
	if strings.Join(got, ",") != want {
		t.Errorf("排成 %v，应该按数值（%s）", got, want)
	}
}

// 多个网段交叉时不许重复问同一个地址：一台设备在表里出现两回，人就不信这张表了。
func Test交叉网段去重(t *testing.T) {
	got := addrsOf(hostList([]netip.Prefix{
		mustPfx(t, "192.168.1.0/30"), mustPfx(t, "192.168.1.0/29")}))
	if strings.Join(got, ",") != "192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5,192.168.1.6" {
		t.Errorf("去重后 %v", got)
	}
}

func Test自己的地址不列进发现清单(t *testing.T) {
	nics := []netif.NIC{
		{Name: "en0", Up: true, Running: true, Addrs: []netaddr.Addr{
			{IP: netip.MustParseAddr("192.168.1.7"), Prefix: 24}}},
		// ★ 回环上的地址不算「本机的设备地址」：算进去会把 127.0.0.1 从清单里剔掉，
		//   而回环那一段本来就是拿来验证发包链路能不能通的。
		{Name: "lo0", Loop: true, Up: true, Running: true, Addrs: []netaddr.Addr{
			{IP: netip.MustParseAddr("127.0.0.1"), Prefix: 8}}},
	}
	own := ownV4Addrs(nics)
	if !own["192.168.1.7"] {
		t.Fatal("本机地址没认出来")
	}
	if own["127.0.0.1"] {
		t.Error("回环地址不该算成本机设备地址")
	}
	targets := hostList([]netip.Prefix{mustPfx(t, "192.168.1.0/30")})
	left, self := dropOwn(targets, map[string]bool{"192.168.1.1": true})
	if len(self) != 1 || self[0] != "192.168.1.1" {
		t.Errorf("没把自己挑出来：%v", self)
	}
	for _, a := range left {
		if a.String() == "192.168.1.1" {
			t.Error("自己的地址还在要问的清单里 —— 问自己必然有回执，每台机器扫完都会多一行")
		}
	}
}

// ── 网段是不是本机真的连着的那一段 ──

func testPfx(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = mustPfx(t, s)
	}
	return out
}

func Test路由过来的网段要认出来(t *testing.T) {
	local := testPfx(t, "192.168.1.0/24")
	if !coveredByAny(testPfx(t, "192.168.1.0/24"), local) {
		t.Error("扫自己所在的 /24 该判成本机链路")
	}
	if coveredByAny(testPfx(t, "10.20.30.0/24"), local) {
		t.Error("扫别的网段不该判成本机链路 —— 那种地方 ARP 表里只有网关，扫不到人才是正常")
	}
	// 本机是 /16 时，扫其中的一个 /24 仍然在链路上
	if !coveredByAny(testPfx(t, "10.5.0.0/24"), testPfx(t, "10.5.0.0/16")) {
		t.Error("大网段包住小网段时应该算在链路上")
	}
	if coveredByAny(nil, local) {
		t.Error("一个网段都没有时不许判成「在链路上」")
	}
}

// ★★ 不填 cidr 时扫哪些段，是这张表最容易被污染的地方：
//
//	没插线的、只有 169.254 的、容器和 VPN 那块虚拟网卡，扫它们都只会得到一片空结果，
//	而空结果在现场会被读成「这个网段没人」——那是把人往错方向引。
//	所以排除掉的那些必须逐个说出原因，不能悄悄少扫。
func Test本机网段只挑真能扫的(t *testing.T) {
	nic := func(name string, loop, virtual, up, running bool, cidr string) netif.NIC {
		a, err := netaddr.Parse(cidr)
		if err != nil {
			t.Fatalf("%s：%v", cidr, err)
		}
		return netif.NIC{Name: name, Loop: loop, Virtual: virtual, Up: up, Running: running,
			Addrs: []netaddr.Addr{a}}
	}
	nics := []netif.NIC{
		nic("en0", false, false, true, true, "192.168.1.7/24"),
		nic("en1", false, false, false, false, "192.168.2.7/24"), // 没插线
		nic("en3", false, false, true, true, "169.254.7.7/16"),   // DHCP 没要到地址
		nic("bridge100", false, true, true, true, "10.5.0.1/24"), // 虚拟网卡
		nic("lo0", true, false, true, true, "127.0.0.1/8"),       // 回环
		nic("en4", false, false, true, true, "203.0.113.9/32"),   // 掩码长过 /30
	}
	local, skipped := localV4Subnets(nics, "")
	if len(local) != 1 || local[0].String() != "192.168.1.0/24" {
		t.Errorf("扫的是 %v，应该只有 en0 那段", local)
	}
	joined := strings.Join(skipped, "；")
	for _, want := range []string{"en1", "没插线", "en3", "link-local", "bridge100", "虚拟"} {
		if !strings.Contains(joined, want) {
			t.Errorf("跳过说明 %q 里少了 %s", joined, want)
		}
	}
	// 回环和 /32 不该占跳过说明的位置：一个压根不是设备地址，一个没有别的设备可问
	if strings.Contains(joined, "lo0") || strings.Contains(joined, "en4") {
		t.Errorf("跳过了不该跳的：%s", joined)
	}

	// iface 指名时只看那一块
	if got, _ := localV4Subnets(nics, "EN0"); len(got) != 1 {
		t.Errorf("指名 en0（大小写不同）得到 %v", got)
	}
	if got, _ := localV4Subnets(nics, "不存在的网卡"); len(got) != 0 {
		t.Errorf("指名不存在的网卡得到 %v", got)
	}
}

// ── 每台凭什么算在线 ──

func nb(addr, mac, iface string) neighbor {
	return neighbor{Addr: addr, MAC: mac, Iface: iface}
}

// ★★ 「它应了 ARP 但拦了 ICMP」是这一栏最容易被漏掉的一档：
//
//	只看 ICMP 回执的扫描工具，在现场会漏掉一半摄像头。
func Test拦了ping的设备靠ARP那条路捞回来(t *testing.T) {
	targets := hostList([]netip.Prefix{mustPfx(t, "10.1.1.0/29")})
	hosts := map[string]*scanHost{}
	before := map[string]neighbor{}
	markCache(hosts, targets, before)
	markReplies(hosts, map[string]int64{"10.1.1.1": 3}) // 只有 .1 应 ping
	markARP(hosts, targets, map[string]neighbor{        // 而 ARP 表里 .2 也冒出来了
		"10.1.1.1": nb("10.1.1.1", "aa:bb:cc:dd:ee:01", "en0"),
		"10.1.1.2": nb("10.1.1.2", "AA:BB:CC:DD:EE:02", "en0"),
	})
	live := aliveList(hosts)
	if len(live) != 2 {
		t.Fatalf("只列出 %d 台：%+v", len(live), live)
	}
	if live[0].Evidence != evICMP || live[0].MAC == "" {
		t.Errorf(".1 应该按 icmp 记并带上 MAC：%+v", live[0])
	}
	if live[1].Addr != "10.1.1.2" || live[1].Evidence != evARP {
		t.Errorf(".2 应该按 arp 记：%+v", live[1])
	}
	// MAC 一律规整过小写：两台设备的 MAC 大小写不一，界面排序和 OUI 查询都会错
	if live[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("MAC 没规整：%s", live[1].MAC)
	}
}

// ★★ ARP 表里「解析失败」的占位条目不算在线 —— 这条是真机扫自己网段时打出来的 bug：
//
//	一轮 ICMP 把整段 253 个地址都塞成了 <incomplete>（没有 MAC），
//	按「表里有这一行」来算，结果就是一张全是鬼的清单。
func Test解析失败的ARP条目不算在线(t *testing.T) {
	ns := []neighbor{
		nb("192.168.0.1", "44:f9:71:a1:e3:58", "en0"),
		{Addr: "192.168.0.2", Iface: "en0", State: "incomplete"}, // 没有 MAC：问了，它没应
		{Addr: "192.168.0.3", MAC: "(incomplete)", Iface: "en0"}, // 有的平台把占位串写在 MAC 那一栏
		{MAC: "aa:bb:cc:dd:ee:ff"},                               // 连地址都没有
		nb("192.168.0.4", "3c:6d:66:ba:3:f7", "en0"),             // macOS 不补零，规整过才能比对
	}
	got := neighborsByAddr(ns)
	if len(got) != 2 {
		t.Fatalf("留下了 %d 条：%+v", len(got), got)
	}
	if _, ok := got["192.168.0.2"]; ok {
		t.Error("占位条目被当成在线了")
	}
	if n := got["192.168.0.4"]; n.MAC != "3c:6d:66:ba:03:f7" {
		t.Errorf("MAC 没规整：%s", n.MAC)
	}

	// 端到端一点：把现场那个形状（整段全是占位行）分别喂给「发包前先看缓存」
	// 和「发完再看一遍」两档 —— 一个连 ICMP 都没答的网段必须一台都不列。
	targets := hostList([]netip.Prefix{mustPfx(t, "192.168.0.0/30")})
	ghosts := []neighbor{
		{Addr: "192.168.0.1", Iface: "en0", State: "incomplete"},
		{Addr: "192.168.0.2", Iface: "en0", State: "incomplete"},
	}
	hosts := map[string]*scanHost{}
	markCache(hosts, targets, neighborsByAddr(ghosts))
	markReplies(hosts, map[string]int64{}) // 一个回执都没收到
	markARP(hosts, targets, neighborsByAddr(ghosts))
	if live := aliveList(hosts); len(live) != 0 {
		t.Errorf("凭空活了：%+v", live)
	}

	// 同一段里真有一台答了 ARP 时，清单上就只有它 —— 修复不是「一律不信 ARP」。
	hosts = map[string]*scanHost{}
	markCache(hosts, targets, neighborsByAddr(ghosts))
	markARP(hosts, targets, neighborsByAddr(append([]neighbor{
		nb("192.168.0.2", "44:f9:71:a1:e3:58", "en0")}, ghosts...)))
	live := aliveList(hosts)
	if len(live) != 1 || live[0].Addr != "192.168.0.2" || live[0].Evidence != evARP {
		t.Errorf("该只列出应了 ARP 的那台：%+v", live)
	}
}

// 发包前缓存里就有的那条，不许在 ICMP 回来之后再算成第二台。
func Test缓存里的旧记录不重复计一台(t *testing.T) {
	targets := hostList([]netip.Prefix{mustPfx(t, "10.2.2.0/30")})
	hosts := map[string]*scanHost{}
	before := map[string]neighbor{"10.2.2.1": nb("10.2.2.1", "00:11:22:33:44:55", "en0")}
	markCache(hosts, targets, before)
	if hosts["10.2.2.1"].Evidence != evCache {
		t.Fatalf("先记成 %s，应该 arp-cache", hosts["10.2.2.1"].Evidence)
	}
	markReplies(hosts, map[string]int64{"10.2.2.1": 2})
	markARP(hosts, targets, before)
	live := aliveList(hosts)
	if len(live) != 1 {
		t.Fatalf("表里有 %d 行，一台设备不该出现两回", len(live))
	}
	// ★ ICMP 是最硬的证据，收到回执就必须盖过「缓存里本来有」
	if live[0].Evidence != evICMP {
		t.Errorf("证据是 %s，应该被 icmp 盖过去", live[0].Evidence)
	}
}

// 只有「没回话」的地址不许凑成一台。
func Test没信号的记不进来(t *testing.T) {
	targets := hostList([]netip.Prefix{mustPfx(t, "10.3.3.0/30")})
	hosts := map[string]*scanHost{}
	markCache(hosts, targets, map[string]neighbor{})
	markReplies(hosts, map[string]int64{})
	markARP(hosts, targets, map[string]neighbor{})
	if len(aliveList(hosts)) != 0 {
		t.Errorf("凭空活了：%+v", hosts)
	}
	if n := len(missingHosts(hosts, targets)); n != 2 {
		t.Errorf("待兜底 %d 个，应该 2", n)
	}
}

// TCP 兜底：连上和明确被拒（RST）都算在线；没发过包就没有证据。
func TestTCP兜底只认有回执的(t *testing.T) {
	open := listenTCP(t)
	// 127.0.0.1 归本机；那个没人监听的端口必然吃 RST。两种回执都说明主机在。
	targets := []netip.Addr{netip.MustParseAddr("127.0.0.1")}

	hosts := map[string]*scanHost{}
	markTCP(context.Background(), hosts, targets, nil, time.Second)
	if len(aliveList(hosts)) != 0 {
		t.Fatal("没给端口却记了在线")
	}

	hosts = map[string]*scanHost{}
	markTCP(context.Background(), hosts, targets, []int{open, closedPort(t)}, 2*time.Second)
	live := aliveList(hosts)
	if len(live) != 1 {
		t.Fatalf("本机应答的端口都没记下来：%+v", live)
	}
	if live[0].Evidence != evTCP || !strings.Contains(live[0].Detail, strconv.Itoa(open)) {
		t.Errorf("TCP 证据不对：%+v", live[0])
	}

	// ★ 已经收到 ICMP 回执的那台不该被 TCP 改写掉：证据越硬越要留着，
	//   把 icmp 换成 tcp 会让人以为只能靠端口猜。
	hosts = map[string]*scanHost{"127.0.0.1": {Addr: "127.0.0.1", Evidence: evICMP}}
	markTCP(context.Background(), hosts, targets, []int{open}, 2*time.Second)
	if hosts["127.0.0.1"].Evidence != evICMP {
		t.Errorf("硬证据被盖成 %s 了", hosts["127.0.0.1"].Evidence)
	}
}

func Test证据汇总写了各档几台(t *testing.T) {
	s := evidenceSummary([]scanHost{
		{Addr: "10.0.0.1", Evidence: evICMP}, {Addr: "10.0.0.2", Evidence: evARP},
		{Addr: "10.0.0.3", Evidence: evARP}, {Addr: "10.0.0.4", Evidence: evCache},
	})
	for _, want := range []string{"arp 2 台", "arp-cache 1 台", "icmp 1 台"} {
		if !strings.Contains(s, want) {
			t.Errorf("汇总 %q 里少了 %s", s, want)
		}
	}
	// 顺序固定：同一份结果每次跑出来的那句说明要一样，否则日志没法比对
	if !strings.HasPrefix(s, "arp 2 台") {
		t.Errorf("汇总没按证据名排序：%s", s)
	}
}

// ── 参数 ──

func subnetRun(t *testing.T, args map[string]any) (ots.Verdict, error) {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doSubnetScan(context.Background(), b)
	if err != nil {
		return ots.Verdict{}, err
	}
	ver, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", v)
	}
	return ver, nil
}

// ★ 没写前缀长度时不许猜：猜成 /24 还是 /8，结果会差几个数量级，
//
//	而症状是「扫出来的人比实际少」—— 这种错在现场看不出来。
func TestCIDR不写前缀长度就拒(t *testing.T) {
	for _, bad := range []string{"192.168.1.7", "  10.0.0.0 ", "abc", "192.168.1.0/33", "192.168.1.0/x"} {
		_, err := parseScanCIDR(bad)
		if err == nil {
			t.Errorf("%q 收下了", bad)
			continue
		}
		if !strings.Contains(err.Error(), "cidr") {
			t.Errorf("%q 的报错没点明是哪个参数：%v", bad, err)
		}
	}
	p, err := parseScanCIDR(" 10.20.30.40/22 ")
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "10.20.28.0/22" {
		t.Errorf("没抹成网络地址：%s", p)
	}
}

// v6 单独一档说明：不是「参数错了」这么简单，得说清为什么不能这么扫、该用什么。
func TestV6网段指路discover(t *testing.T) {
	_, err := parseScanCIDR("fe80::/64")
	if err == nil {
		t.Fatal("v6 收下了")
	}
	msg := err.Error()
	if !strings.Contains(msg, "net.discover") || !strings.Contains(msg, "1.8") {
		t.Errorf("报错没交代为什么：%v", err)
	}
}

// ★ 超过上限时**直接拒**，不许悄悄只扫前 N 个：
//
//	被截断的那些会被读成「不在」，那是凭空造的结论。
func Test网段太大直接拒不悄悄截断(t *testing.T) {
	_, err := subnetRun(t, map[string]any{"cidr": "10.0.0.0/16", "maxHosts": 8})
	if err == nil {
		t.Fatal("扫 65534 个地址收下了")
	}
	msg := err.Error()
	if !strings.Contains(msg, "maxHosts") || !strings.Contains(msg, "扫描器") {
		t.Errorf("报错没给出路：%v", err)
	}
	if strings.Contains(msg, "hosts-found") {
		t.Error("拒了就别给结果")
	}
}

// /31 和 /32 这种点线路上没有别的设备，直接指去单点工具。
func Test过长的掩码指去单点工具(t *testing.T) {
	for _, s := range []string{"10.0.0.0/31", "10.0.0.1/32"} {
		_, err := subnetRun(t, map[string]any{"cidr": s})
		if err == nil {
			t.Errorf("%s 收下了", s)
			continue
		}
		if !strings.Contains(err.Error(), "net.ping") {
			t.Errorf("%s 的报错没指下一步：%v", s, err)
		}
	}
}

// 本机没有可扫的网段时说清楚为什么，并列出跳过了哪些网卡。
func Test本机没网段时说得清(t *testing.T) {
	_, err := subnetRun(t, map[string]any{"iface": "肯定不存在的一块网卡"})
	if err == nil {
		t.Log("这块机器上真有同名网卡？那这条跳过")
		return
	}
	if !strings.Contains(err.Error(), "cidr") {
		t.Errorf("没给出路：%v", err)
	}
}

// ── 真跑 ──

// 回环上必然有一台会答（127.0.0.1 由本机内核应答）。★ 用它证明「一个套接字、一发多收、
// 按源地址认回复」这条链真的通，而不是只测纯函数。
//
// ★★ 只断言「127.0.0.1 该在」，不断言「只有它在」：macOS 默认只把 127.0.0.1 认成自己的地址，
//
//	同段别的应用地址要配了别名才答；Linux 则整段 127/8 都答。写死条数就变成一台机器上过、
//	换台机器就红的测试 —— 而那个红是操作系统的差别，不是这条逻辑错了。
func Test回环这一段问得到人(t *testing.T) {
	ver, err := subnetRun(t, map[string]any{"cidr": "127.0.0.0/29", "waitMs": 1200, "tcpPorts": "1"})
	if err != nil {
		t.Fatalf("报错：%v", err)
	}
	if ver.Code != scanNetFound {
		t.Fatalf("判成 %s（%s）", ver.Code, ver.Note)
	}
	hosts := ver.Values["hosts"].([]scanHost)
	if len(hosts) == 0 {
		t.Fatal("回环上一个都没问到")
	}
	var self *scanHost
	for i := range hosts {
		if hosts[i].Addr == "" {
			t.Errorf("有条记录没地址：%+v", hosts[i])
		}
		if hosts[i].Addr == "127.0.0.1" {
			self = &hosts[i]
		}
	}
	if self == nil {
		t.Fatalf("清单里没有 127.0.0.1：%+v", hosts)
	}
	if self.Evidence != evICMP {
		t.Errorf("127.0.0.1 记成 %s，该是 icmp（本机内核必然答应 ICMP 回显）", self.Evidence)
	}
	if n, _ := ver.Values["asked"].(int); n != 6 {
		t.Errorf("asked = %v，/29 该问 6 个", ver.Values["asked"])
	}
	// ★ 剩下那几个没答的必须算「没问到」，不能被抹成「不在线」，也不能凭空消失：
	//   alive + noSignal 要等于问过的总数，不然这张表对不上账。
	alive, _ := ver.Values["alive"].(int)
	noSignal, _ := ver.Values["noSignal"].(int)
	if alive+noSignal != 6 {
		t.Errorf("账对不上：alive=%d noSignal=%d，一共问了 6 个", alive, noSignal)
	}
}

// ★★ 保留段：一个信号都收不到，但**不许**说成「这段是空的」。
//
//	而且这段不是本机链路，说明里必须点出 ARP 用不上、该带 tcpPorts 再来。
func Test全没回执时不说是空的(t *testing.T) {
	ver, err := subnetRun(t, map[string]any{"cidr": "240.0.0.8/29", "waitMs": 300, "tcpPorts": "1"})
	if err != nil {
		t.Fatalf("没信号是判定不是错误：%v", err)
	}
	if ver.Code != scanNetEmpty {
		t.Fatalf("判成 %s，应该 %s", ver.Code, scanNetEmpty)
	}
	if strings.Contains(ver.Note, "是空的") && !strings.Contains(ver.Note, "不能当成") {
		t.Errorf("把「没问到」说成了「没有」：%s", ver.Note)
	}
	if ver.Values["onLink"] != false {
		t.Errorf("这段不是本机链路：%v", ver.Values)
	}
	if !strings.Contains(ver.Note, "tcpPorts") {
		t.Errorf("路由过来的网段该指出 ARP 用不上：%s", ver.Note)
	}
	if ver.Values["alive"] != 0 || ver.Values["noSignal"] != 6 {
		t.Errorf("计数不对：alive=%v noSignal=%v", ver.Values["alive"], ver.Values["noSignal"])
	}
}

// 取消要立刻收摊：人在界面上点了停，不能还在往里发包。
func Test取消时不再发包(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := icmpSweep(ctx, hostList([]netip.Prefix{mustPfx(t, "240.0.0.8/29")}), 5*time.Second)
	if err != nil {
		t.Fatalf("报错：%v", err)
	}
	if len(got) != 0 {
		t.Errorf("取消了还收到 %d 条：%v", len(got), got)
	}
}

func Test网段扫描工具声明(t *testing.T) {
	if subnetScanTool.Class != ots.ClassRead {
		t.Errorf("分类是 %v，扫描只是发流量观察 [OTS-4.3]", subnetScanTool.Class)
	}
	for _, code := range []string{scanNetFound, scanNetEmpty} {
		if !strings.Contains(string(subnetScanTool.Summary), code) {
			t.Errorf("说明里没列 %s", code)
		}
	}
	for _, ev := range []string{evICMP, evARP, evCache, evTCP} {
		if !strings.Contains(string(subnetScanTool.Summary), ev) {
			t.Errorf("说明里没交代证据种类 %s —— 调用方（AI）读结果时不知道这些码是什么意思", ev)
		}
	}
}
