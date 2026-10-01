package tools

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// ── 测试用的真机输出样本 ──
//
// ★★ 这些样本一律是**真机上跑真命令**抄回来的，不是按文档编的：
//
//	macOS 的 netstat -ibn / nettop 来自这台 macOS（2026-09-25），/proc/net/dev 与 ss 的
//	形状来自 Docker Desktop 的 LinuxVM（iproute2 6.9.0）。
//	按记忆编样本的风险很具体：列的位置、有没有那一列，正是三个平台彼此不同的地方。

// macOS `netstat -ibn` 的节选。★ 三件事都在样本里：同一块网卡按地址重复出现、
// <Link#1> 那一行没有 Address 列（整行比别人少一列，所以只能从行尾数列）、
// gif0 名字带 * 后缀。★ 必须是 -ibn 的样本：不带 -n 时这一列被反解成主机名，
// 真机上那条命令要跑 30 秒，而它夹在两次采样中间。
const netstatIBSample = `Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                      229400012     0 1701599120326 229400012     0 1701599120326     0
lo0        16384 127           127.0.0.1       229400012     - 1701599120326 229400012     - 1701599120326     -
lo0        16384 ::1/128     ::1               229400012     - 1701599120326 229400012     - 1701599120326     -
lo0        16384 fe80::1%lo0 fe80:1::1         229400012     - 1701599120326 229400012     - 1701599120326     -
gif0*      1280  <Link#2>                             0     0          0        0     0          0     0
anpi0      1500  <Link#4>    2e:87:0a:7f:82:a7        0     0          0        0     0          0     0
en0        1500  <Link#14>   a2:ed:bf:52:e6:9a 99467531     0 35450763500 147862344     0 143748137992     0
en0        1500  fe80::6:807 fe80:e::6:807d:9d 99467531     - 35450763500 147862344     - 143748137992     -
en0        1500  192.168.0     192.168.0.107   99467531     - 35450763500 147862344     - 143748137992     -
llw0       1500  <Link#17>   d2:19:2e:92:95:aa     2588     0     456709       26     0       3120     0
utun1      1380  <Link#19>                            0     0          0      195     0      37034     0
`

// macOS `nettop -P -x -d -L 2 -s 2` 的真实形状。★ 第一块是**累计值**（这台机器
// 开机以来 mDNSResponder 收过 6951 万字节），第二块才是这一窗的增量 ——
// 取错块的症状就是把开机账当成本窗，报出「mDNSResponder 吃了 500 Mbps」。
const nettopSample = `time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
22:14:53.130702,syslogd.131,,,0,3390,0,0,0,,,,,,,,,,,,
22:14:53.130705,mDNSResponder.219,,,69555258,24841089,0,0,0,,,,,,,,,,,,
22:14:53.130706,com.apple.WebKit.Networking.4321,,,100,200,0,0,0,,,,,,,,,,,,
time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,rtt_avg,rcvsize,tx_win,tc_class,tc_mgt,cc_algo,P,C,R,W,arch,
22:14:55.114051,mDNSResponder.219,,,5399,4774,0,0,0,,,,,,,,,,,,
22:14:55.114058,cloudflared.473,,,198,503,0,0,0,,,,,,,,,,,,
22:14:55.114065,node.6405,,,1435,0,0,0,0,,,,,,,,,,,,
22:14:55.114089,WeChat.587,,,0,0,0,0,0,,,,,,,,,,,,
`

// Linux /proc/net/dev（Docker Desktop 的 LinuxVM 真实输出节选）。
// ★ 名字右对齐补空格、超过七列就顶到冒号；下面同时有两种。
const procNetDevSample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     196       2    0    0    0     0          0         0      196       2    0    0    0     0       0          0
  eth0: 16315388   38615    0    0    0     0          0         0 23924927   44392    0    0    0     0       0          0
 tunl0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
gretap0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
docker0:  152497    2859    0    0    0     0          0         0  5809667    2928    0   23    0     0       0          0
br-2648e5d290be:    5438      46    0    0    0     0          0         0    12529      35    0    2    0     0       0          0
`

// Linux `ss -H -tinp state established`（iproute2 6.9.0 真机节选）。
// ★ 一条连接两行：第二行缩进，bytes_sent / bytes_received 写在里面。
// 这一份的 Process 列是空的（容器看不到宿主进程）—— 正好是「认不出主人」那一档的样本。
const ssNoOwnerSample = `ESTAB      0      0       192.168.65.3:59596 199.232.114.132:443
	 cubic wscale:7,7 rto:3425 rtt:590.719/701.718 ato:166 mss:65483 pmtu:65535 rcvmss:4200 advmss:65483 cwnd:10 bytes_sent:1222 bytes_acked:1223 bytes_received:2443531 segs_out:1173 segs_in:1205 data_segs_out:6 data_segs_in:1198 send 8868244bps lastsnd:14317 lastrcv:431 app_limited busy:1ms
`

// Linux `ss -H -tinp -a` 里认得出主人的样子（同一台机器上自己起的两条回环连接）。
const ssOwnedSample = `ESTAB 0      0      127.0.0.1:49866       127.0.0.1:9999   users:(("nc",pid=61,fd=3))
	 cubic wscale:7,7 rto:204 rtt:0.042/0.021 mss:65483 pmtu:65535 rcvmss:1448 advmss:65483 cwnd:10 bytes_sent:234881024 bytes_acked:234881025 bytes_received:0 segs_out:3608 segs_in:1807 data_segs_out:3603 send 124729523808bps app_limited
ESTAB 0      0          127.0.0.1:9999    127.0.0.1:49866   users:(("nc",pid=59,fd=4))
	 cubic wscale:7,7 rto:204 mss:65483 pmtu:65535 rcvmss:1448 advmss:65483 cwnd:10 bytes_sent:0 bytes_acked:1 bytes_received:234881024 segs_out:1 segs_in:3608 data_segs_in:3603 last-data-seg
LISTEN 0      1            0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=41,fd=3))
	 cubic wscale:7,7 mss:1448 rcvmss:536 advmss:1448 cwnd:10 bytes_sent:4096 bytes_received:512
`

// Windows `Get-NetAdapterStatistics | ConvertTo-Json -Compress` 的形状。
// ★ 这份是**按 PowerShell 的输出规则写的，不是真机抄的**（本轮没有 Windows 真机）：
// 所以只有解析层敢用它，任何「Windows 上量对得上」的说法都不建立在这份样本上。
const netAdapterStatsArray = `[{"Name":"WLAN","ReceivedBytes":123456789,"SentBytes":98765432},
{"Name":"以太网","ReceivedBytes":1000,"SentBytes":2000}]`

const netAdapterStatsSingle = `{"Name":"WLAN","ReceivedBytes":123456789,"SentBytes":98765432}`

// ── 网卡计数解析 ──

func Test一块网卡按地址重复出现时只算一次(t *testing.T) {
	got := parseNetstatIB(netstatIBSample)
	m := map[string]linkCount{}
	for _, c := range got {
		if _, dup := m[c.Name]; dup {
			t.Fatalf("%s 出现了两次 —— 三个地址会被算成三份流量", c.Name)
		}
		m[c.Name] = c
	}
	if m["en0"].Rx != 35450763500 || m["en0"].Tx != 143748137992 {
		t.Errorf("en0 读成 %d/%d，应为 35450763500/143748137992", m["en0"].Rx, m["en0"].Tx)
	}
	if len(got) != 6 {
		t.Errorf("解析出 %d 块网卡，应为 6：%+v", len(got), got)
	}
}

func Test缺Address列时也从行尾取字节(t *testing.T) {
	// lo0 那行没有 Address 列：从行首按列号数会把 Ipkts 当成 Ibytes。
	got := parseNetstatIB(netstatIBSample)
	var lo linkCount
	for _, c := range got {
		if c.Name == "lo0" {
			lo = c
		}
	}
	if lo.Rx != 1701599120326 || lo.Tx != 1701599120326 {
		t.Errorf("lo0 读成 %d/%d，应为 1701599120326（两样都是）", lo.Rx, lo.Tx)
	}
}

func Test网卡名后面的状态星号不当名字(t *testing.T) {
	got := parseNetstatIB(netstatIBSample)
	for _, c := range got {
		if strings.HasSuffix(c.Name, "*") {
			t.Errorf("网卡名 %q 带着状态标记", c.Name)
		}
		if c.Name == "gif0" && bwLinkKind(c.Name) != bwKindTunnel {
			t.Errorf("gif0 应该算隧道一类（它是 IPv6 over IPv4 的配置接口），实际 %s", bwLinkKind(c.Name))
		}
	}
}

func Test表头与没有数字的行不当记录(t *testing.T) {
	if got := parseNetstatIB("Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll\n"); len(got) != 0 {
		t.Errorf("表头被当成记录：%+v", got)
	}
	if got := parseNetstatIB(""); len(got) != 0 {
		t.Errorf("空输出解出 %+v", got)
	}
}

func TestLinux的procNetDev两张位置都取对(t *testing.T) {
	got := parseProcNetDev(procNetDevSample)
	m := map[string]linkCount{}
	for _, c := range got {
		m[c.Name] = c
	}
	// docker0 的名字顶到冒号（没有补空格），eth0 的补了 —— 两种都要认。
	if m["eth0"].Rx != 16315388 || m["eth0"].Tx != 23924927 {
		t.Errorf("eth0 读成 %+v", m["eth0"])
	}
	if m["docker0"].Rx != 152497 || m["docker0"].Tx != 5809667 {
		t.Errorf("docker0 读成 %+v", m["docker0"])
	}
	if m["br-2648e5d290be"].Rx != 5438 {
		t.Errorf("长名字那块桥读成 %+v", m["br-2648e5d290be"])
	}
	if len(got) != 6 {
		t.Errorf("解出 %d 块，应为 5（表头两行不算）", len(got))
	}
}

func Test内核预留的口不当出网口(t *testing.T) {
	for _, n := range []string{"lo", "lo0", "tunl0", "gretap0", "utun4", "ppp0", "wg0", "sit0", "ip_vti0",
		// ★ Windows 给的是整句别名，不是 unix 那种短前缀 —— 这几条是拿真机
		// Get-NetAdapterStatistics 的名字形状钉的：漏一条就把回环/隧道的量加进出网总量。
		"Loopback Pseudo-Interface 1", "Teredo Tunneling Pseudo-Interface",
		"isatap.{3F1A2B3C-4D5E-6F70-8192-A3B4C5D6E7F8}", "WAN Miniport (IP)"} {
		if k := bwLinkKind(n); k == bwKindLink {
			t.Errorf("%s 被判成普通网卡（%s）—— 它进总量会把别的流量再算一遍", n, k)
		}
	}
	if k := bwLinkKind("Loopback Pseudo-Interface 1"); k != bwKindLoopback {
		t.Errorf("Windows 的回环认成了 %s —— 该单独列出来，不该并进隧道那一档", k)
	}
	for _, n := range []string{"eth0", "en0", "wlan0", "docker0", "br-2648e5d290be", "veth99d33e5",
		"以太网", "Wi-Fi", "Local Area Connection* 12", "vEthernet (WSL)"} {
		if k := bwLinkKind(n); k != bwKindLink {
			t.Errorf("%s 应该算普通网卡，实际 %s", n, k)
		}
	}
}

func Test计数被清零的那一段不许演成有人在吃(t *testing.T) {
	// 第二次比第一次小：接口重建 / 计数清零。差值会是个巨大的正数或者绕走的负数。
	first := []linkCount{{Name: "en0", Rx: 1000, Tx: 500}, {Name: "lo0", Rx: 9, Tx: 9}}
	second := []linkCount{{Name: "en0", Rx: 12, Tx: 900}, {Name: "lo0", Rx: 20, Tx: 20},
		{Name: "utun9", Rx: 1e9, Tx: 1e9}} // 窗口中途才出现的口
	ds := diffLinkCounts(first, second)
	var en0, lo0, utun9 *linkDelta
	for i := range ds {
		switch ds[i].Name {
		case "en0":
			en0 = &ds[i]
		case "lo0":
			lo0 = &ds[i]
		case "utun9":
			utun9 = &ds[i]
		}
	}
	if en0 == nil || !en0.Reset || en0.Rx != 0 {
		t.Errorf("清零的 en0 没被标出来：%+v", en0)
	}
	if lo0 == nil || lo0.Reset || lo0.Rx != 11 {
		t.Errorf("正常的 lo0 差值算错：%+v", lo0)
	}
	if utun9 == nil || !utun9.Reset {
		t.Errorf("窗口中途出现的口没标 Reset：%+v", utun9)
	}
}

func Test窗口中途消失的网卡留下名字(t *testing.T) {
	ds := diffLinkCounts([]linkCount{{Name: "ppp0", Rx: 5000, Tx: 400}}, nil)
	if len(ds) != 1 || !ds[0].Reset || ds[0].Name != "ppp0" {
		t.Fatalf("消失的网卡应该留一条带 Reset 的记录，实际 %+v", ds)
	}
	// ★ 症状核对：不留这条，界面会显示「这个口一秒没动」，而它其实是断了。
}

// ── 进程归属解析 ──

func TestNettop只取最后一块的增量(t *testing.T) {
	got := parseNettopCSV(nettopSample)
	if len(got) != 4 {
		t.Fatalf("解出 %d 条，应为第二块的 4 条：%+v", len(got), got)
	}
	for _, p := range got {
		if p.Process == "mDNSResponder" {
			if p.Rx != 5399 || p.Tx != 4774 {
				t.Errorf("mDNSResponder 读成 %+v，应为第二块的 5399/4774 而不是累计值", p)
			}
			if p.Pid != 219 {
				t.Errorf("PID 读成 %d", p.Pid)
			}
			return
		}
	}
	t.Error("没看到 mDNSResponder")
}

func TestNettop按列名取字节不按位置(t *testing.T) {
	// 把 bytes_in / bytes_out 挪到表头末尾（换版式），按列号取的写法会读错列。
	shuffled := "time,,interface,state,rx_dupe,rx_ooo,re-tx,bytes_in,bytes_out,\n" +
		"12:00:00.1,x,,,0,0,0,777,888,\n" +
		"time,,interface,state,rx_dupe,rx_ooo,re-tx,bytes_in,bytes_out,\n" +
		"12:00:01.1,x,,,0,0,0,40,50,\n"
	got := parseNettopCSV(shuffled)
	if len(got) != 1 || got[0].Rx != 40 || got[0].Tx != 50 {
		t.Fatalf("换列序后读成 %+v", got)
	}
}

func TestNettop表头没有字节列就不报(t *testing.T) {
	// 有的版本 -P 的列里没这两列：宁可不报，也不按位置猜一个数当字节。
	if got := parseNettopCSV("time,,interface,state,foo,\n12:00:00.1,x,,,1,2\n"); got != nil {
		t.Errorf("没有字节列还解出 %+v", got)
	}
}

func Test进程名自己带点时按最后一个点拆PID(t *testing.T) {
	got := parseNettopCSV(nettopSample)
	var webkit, node procBytes
	for _, p := range got {
		switch p.Pid {
		case 6405:
			node = p
		case 4321:
			webkit = p
		}
	}
	if node.Process != "node" {
		t.Errorf("node 读成 %q", node.Process)
	}
	// 第一块里的 com.apple.WebKit.Networking.4321：名字不许被砍成 "com"
	if webkit.Pid != 0 {
		t.Errorf("第二块里没有 4321，PID 串台了：%+v", webkit)
	}
	if name, pid := splitNettopName("com.apple.WebKit.Networking.4321"); name != "com.apple.WebKit.Networking" || pid != 4321 {
		t.Errorf("拆成 %q/%d", name, pid)
	}
	if name, pid := splitNettopName("no-dot"); name != "no-dot" || pid != 0 {
		t.Errorf("没有点的名字应该整段留下，实际 %q/%d", name, pid)
	}
	if name, pid := splitNettopName("Chrome.0"); name != "Chrome.0" || pid != 0 {
		t.Errorf("PID 是 0 就当没有：%q/%d", name, pid)
	}
}

func TestSS的续行归给上一条记录(t *testing.T) {
	socks, total := parseSSInetDiag(ssOwnedSample, "tcp")
	if total != 3 {
		t.Fatalf("一共 %d 条，应为 3", total)
	}
	if len(socks) != 3 {
		t.Fatalf("认出主人 %d 条，应为 3：%+v", len(socks), socks)
	}
	for _, s := range socks {
		switch s.Process {
		case "nc":
			if s.Sent+s.Recv == 0 {
				t.Errorf("%s 的字节数没接到续行上：%+v", s.Key, s)
			}
			if s.Pid != 61 && s.Pid != 59 {
				t.Errorf("PID 认成 %d", s.Pid)
			}
		case "sshd":
			if s.Sent != 4096 || s.Recv != 512 {
				t.Errorf("sshd 读成 %+v", s)
			}
		}
	}
}

func Test看不到主人的连接算进认不出那一档(t *testing.T) {
	socks, total := parseSSInetDiag(ssNoOwnerSample, "tcp")
	if total != 1 {
		t.Fatalf("记录数 %d，应为 1", total)
	}
	if len(socks) != 0 {
		t.Fatalf("这条没有 users，不该被认出来：%+v", socks)
	}
	// ★ 判 partial 的依据就是 total 与认出的条数差 —— 差一条就不许说「没人在吃」。
}

func TestSS两次读数做差并按进程加总(t *testing.T) {
	first, _ := parseSSInetDiag(strings.Replace(ssOwnedSample,
		"bytes_sent:234881024", "bytes_sent:200000000", 1), "tcp")
	second, _ := parseSSInetDiag(ssOwnedSample, "tcp")
	got := ssDelta(first, second)
	var byName = map[string]procBytes{}
	for _, p := range got {
		byName[p.Process+":"+itoa(p.Pid)] = p
	}
	sent := byName["nc:61"]
	if sent.Tx != 34881024 {
		t.Errorf("发送侧差值算成 %d，应为 34881024", sent.Tx)
	}
	if sent.Rx != 0 {
		t.Errorf("没收过东西却算了 %d", sent.Rx)
	}
}

func Test计数回退时按零算不冤枉进程(t *testing.T) {
	// 第二次比第一次小（连接重建、同四元组复用）：不许变成一个巨大的正数。
	// ★ 也不把第二次的读数整个算进窗口：那是这条新连接**建立以来**的累计，
	// 我们不知道它是窗口里哪一刻建立的，多算就是冤枉人。宁可少算这一路。
	first := []ssSocket{{Key: "tcp|a:1|b:2", Process: "nc", Pid: 1, Sent: 9000, Recv: 8000}}
	second := []ssSocket{{Key: "tcp|a:1|b:2", Process: "nc", Pid: 1, Sent: 10, Recv: 20}}
	got := ssDelta(first, second)
	if len(got) != 1 || got[0].Rx != 0 || got[0].Tx != 0 {
		t.Fatalf("回退应算成 0，实际 %+v", got)
	}
}

func TestWindows的网卡统计单条与多条都解(t *testing.T) {
	got, err := parseNetAdapterStats(netAdapterStatsArray)
	if err != nil || len(got) != 2 || got[0].Rx != 123456789 {
		t.Fatalf("多条解错：%+v %v", got, err)
	}
	// ★ 一条网卡时 ConvertTo-Json 不给方括号 —— 只按数组解会在「本机只剩一块网卡」那天失效
	one, err := parseNetAdapterStats(netAdapterStatsSingle)
	if err != nil || len(one) != 1 || one[0].Name != "WLAN" || one[0].Tx != 98765432 {
		t.Fatalf("单条解错：%+v %v", one, err)
	}
	if _, err := parseNetAdapterStats(""); err == nil {
		t.Error("空输出应该报错，不能当成「这块机器没网卡流量」")
	}
}

// ── 判定层：六种判定各钉一条 ──

func bwLink(rx, tx uint64) []linkDelta {
	return []linkDelta{{Name: "en0", Rx: rx, Tx: tx}, {Name: "lo0", Rx: 4e9, Tx: 4e9}}
}

func callBandwidth(ps procSample, deltas []linkDelta, egress string, top int) ots.Verdict {
	return bandwidthReport(ps, deltas, egress, 10*time.Second, 10*time.Second, top)
}

func Test有人在吃就点名(t *testing.T) {
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "zlmediakit", Pid: 88, Rx: 3e6, Tx: 1e6}},
		attribution: bwAttribFull,
	}, bwLink(3e6, 1e6), "en0", 10)
	if got.Code != bwBusy {
		t.Fatalf("判定成 %s，应为 %s", got.Code, bwBusy)
	}
	if !strings.Contains(got.Note, "zlmediakit") || !strings.Contains(got.Note, "PID 88") {
		t.Errorf("没点名到进程：%s", got.Note)
	}
	if !strings.Contains(got.Note, "不相减") {
		t.Errorf("没提醒两份口径不能相减：%s", got.Note)
	}
}

func Test网卡和进程都没量时说不忙(t *testing.T) {
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "WeChat", Pid: 587, Rx: 12, Tx: 30}},
		attribution: bwAttribFull,
	}, bwLink(12, 30), "en0", 10)
	if got.Code != bwIdle {
		t.Fatalf("判定成 %s，应为 %s", got.Code, bwIdle)
	}
	if !strings.Contains(got.Note, "这只说明这一段") {
		t.Errorf("没提醒「刚才那次卡」推不出来：%s", got.Note)
	}
}

func Test回环上的量不进出网总量(t *testing.T) {
	// lo0 上 4 GB/s（本机实测这个值很常见：mDNSResponder 与各种本地服务），
	// 出网口 en0 空着 —— 判成「有人在吃带宽」就是把回环当成了网。
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "node", Pid: 6405, Rx: 4e9, Tx: 4e9}},
		attribution: bwAttribFull,
	}, []linkDelta{{Name: "lo0", Rx: 4e9, Tx: 4e9}, {Name: "en0", Rx: 100, Tx: 100}}, "en0", 10)
	if v, _ := got.Values["linkTotalBytes"].(uint64); v != 200 {
		t.Errorf("出网总量算成 %d，应为 200（回环不进这个数）", v)
	}
	if v, _ := got.Values["loopbackTotalBytes"].(uint64); v != 8e9 {
		t.Errorf("回环总量算成 %d", v)
	}
}

func Test隧道不重复计一遍(t *testing.T) {
	// VPN 在 utun4 上收的包，物理口 en0 会再数一遍：两块都进总量就成双倍。
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "cloudflared", Pid: 473, Rx: 5e6, Tx: 1e6}},
		attribution: bwAttribFull,
	}, []linkDelta{{Name: "en0", Rx: 5e6, Tx: 1e6}, {Name: "utun4", Rx: 5e6, Tx: 1e6}}, "en0", 10)
	if v, _ := got.Values["linkTotalBytes"].(uint64); v != 6e6 {
		t.Errorf("总量 %d，应为 6000000（en0 一份，utun 单独一栏，不双计）", v)
	}
	if v, _ := got.Values["tunnelTotalBytes"].(uint64); v != 6e6 {
		t.Errorf("隧道量没单独给：%d", v)
	}
}

func Test网卡很忙而本机进程对不上时说不归本机(t *testing.T) {
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "WeChat", Pid: 587, Rx: 3e4, Tx: 1e4}},
		attribution: bwAttribFull,
	}, bwLink(3e7, 1e7), "en0", 10)
	if got.Code != bwNotMine {
		t.Fatalf("判定成 %s，应为 %s", got.Code, bwNotMine)
	}
	for _, want := range []string{"转发", "容器", "谁在借这台机器走"} {
		if !strings.Contains(got.Note, want) {
			t.Errorf("下一步没提到 %s：%s", want, got.Note)
		}
	}
}

func Test差得不够远就不说不归本机(t *testing.T) {
	// 两份口径本来对不齐：差 2 倍只是一句废话，不该产生一个结论。
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "nginx", Pid: 900, Rx: 2e7, Tx: 6e6}},
		attribution: bwAttribFull,
	}, bwLink(3e7, 1e7), "en0", 10)
	if got.Code == bwNotMine {
		t.Fatal("只差两倍就判成「不归本机」，太急了")
	}
}

func Test数不到进程时只报网卡那一栏(t *testing.T) {
	got := callBandwidth(procSample{
		attribution: bwAttribNone,
		reason:      "Windows 上按进程数网络字节要管理员权限",
		next:        "先看网卡这一栏",
	}, bwLink(3e7, 1e7), "en0", 10)
	if got.Code != bwLinkOnly {
		t.Fatalf("判定成 %s，应为 %s", got.Code, bwLinkOnly)
	}
	// ★ 症状核对：数不到进程绝不能落到 idle —— 那是把「我看不见」说成「没人在吃」。
	if strings.Contains(got.Note, "没有") && strings.Contains(got.Note, "任何") &&
		strings.Contains(got.Note, "现在") {
		t.Errorf("给出了「现在没人在吃」这类结论：%s", got.Note)
	}
	if !strings.Contains(got.Note, "数不到不等于没人在吃") {
		t.Errorf("没提醒这一栏不许读成没问题：%s", got.Note)
	}
	if !strings.Contains(got.Note, "先看网卡这一栏") {
		t.Errorf("下一步没带上：%s", got.Note)
	}
}

func Test只数到一部分而网卡在动时不许说没人吃(t *testing.T) {
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "WeChat", Pid: 587, Rx: 100, Tx: 50}},
		attribution: bwAttribPart,
		reason:      "有 12 条 TCP 连接看不到是哪个进程的（非管理员）",
		next:        "要用管理员权限再问一次",
	}, bwLink(3e7, 1e7), "en0", 10)
	if got.Code != bwPartial {
		t.Fatalf("判定成 %s，应为 %s", got.Code, bwPartial)
	}
	if !strings.Contains(got.Note, "不能读成「没人吃」") {
		t.Errorf("没拦住那句误读：%s", got.Note)
	}
	if !strings.Contains(got.Note, "12 条") {
		t.Errorf("没说清看不见多少条：%s", got.Note)
	}
}

func Test数不全但网卡也没动时可以说现在不忙(t *testing.T) {
	// 出网口自己就没过字节 —— 这时候看不见别人的进程不影响结论。
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "WeChat", Pid: 587, Rx: 100, Tx: 50}},
		attribution: bwAttribPart,
		reason:      "有 12 条 TCP 连接看不到是哪个进程的",
	}, bwLink(80, 40), "en0", 10)
	if got.Code != bwIdle {
		t.Fatalf("判定成 %s，应为 %s", got.Code, bwIdle)
	}
}

func Test认不出出口网卡时改用忙的那块并说明(t *testing.T) {
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "nginx", Pid: 900, Rx: 3e6, Tx: 1e6}},
		attribution: bwAttribFull,
	}, []linkDelta{{Name: "docker0", Rx: 2e7, Tx: 1e7}, {Name: "eth0", Rx: 3e6, Tx: 1e6}}, "ppp0", 10)
	if v, _ := got.Values["egress"].(string); v != "docker0" {
		t.Errorf("egress = %v，应退到最忙的那块", v)
	}
	if got.Code != bwBusy {
		t.Errorf("判定成 %s", got.Code)
	}
}

func Test清零的口不参与总量也不当出口(t *testing.T) {
	got := callBandwidth(procSample{
		procs:       []procBytes{{Process: "nginx", Pid: 900, Rx: 3e6, Tx: 1e6}},
		attribution: bwAttribFull,
	}, []linkDelta{{Name: "en0", Reset: true}, {Name: "eth0", Rx: 3e6, Tx: 1e6}}, "en0", 10)
	if v, _ := got.Values["linkTotalBytes"].(uint64); v != 4e6 {
		t.Errorf("清零的口进了总量：%d（应为 eth0 自己的 3e6+1e6）", v)
	}
	if v, _ := got.Values["egress"].(string); v != "eth0" {
		t.Errorf("读不到的 en0 还被当成出口：%v", v)
	}
	found := false
	for _, r := range got.Values["interfaces"].([]map[string]any) {
		if r["name"] == "en0" {
			found = true
			if r["kind"] != "unreadable" {
				t.Errorf("清零的口在表里被说成 %v", r["kind"])
			}
		}
	}
	if !found {
		t.Error("清零的口从表里消失了 —— 那是把「读不到」藏成「没过东西」")
	}
}

// ── 工具层 ──

func bwCall(t *testing.T, args string) ots.Verdict {
	t.Helper()
	out, err := doBandwidthTop(context.Background(), json.RawMessage(args))
	if err != nil {
		t.Fatalf("调用失败：%v", err)
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", out)
	}
	return v
}

func withReaders(link linkRead, procs procsRead, egress string) func() {
	ol, op, oe := localLink, localProcs, egressIface
	localLink, localProcs, egressIface = link, procs, func() string { return egress }
	return func() { localLink, localProcs, egressIface = ol, op, oe }
}

func Test端到端把两次采样接起来(t *testing.T) {
	var n int
	restore := withReaders(
		func(context.Context) ([]linkCount, error) {
			n++
			if n == 1 {
				return []linkCount{{Name: "en0", Rx: 1e6, Tx: 5e5}, {Name: "lo0", Rx: 7, Tx: 7}}, nil
			}
			return []linkCount{{Name: "en0", Rx: 6e6, Tx: 3e6}, {Name: "lo0", Rx: 9, Tx: 9}}, nil
		},
		func(_ context.Context, w time.Duration) (procSample, error) {
			if w < time.Second {
				t.Errorf("窗口只有 %v", w)
			}
			return procSample{
				procs:       []procBytes{{Process: "mDNSResponder", Pid: 219, Rx: 5e6, Tx: 2e6}},
				attribution: bwAttribFull,
			}, nil
		},
		"en0")
	defer restore()
	got := bwCall(t, `{}`)
	if got.Code != bwBusy {
		t.Fatalf("判定成 %s", got.Code)
	}
	if v, _ := got.Values["linkTotalBytes"].(uint64); v != 7500000 {
		t.Errorf("窗口里 en0 过了 %d，应为 (6e6-1e6)+(3e6-5e5)", v)
	}
	if len(got.Values["interfaces"].([]map[string]any)) != 2 {
		t.Error("网卡表少了行")
	}
	// [OTS-5.3] Values 带账、[OTS-5.4] Note 给得出一句人话
	if got.Note == "" {
		t.Error("没有 Note")
	}
}

func Test数不到进程时端到端照样给网卡那一栏(t *testing.T) {
	restore := withReaders(
		func(context.Context) ([]linkCount, error) {
			return []linkCount{{Name: "en0", Rx: 0, Tx: 0}}, nil
		},
		func(_ context.Context, _ time.Duration) (procSample, error) {
			return procSample{attribution: bwAttribNone, reason: "这台没有 ss", next: "装上再问"}, nil
		},
		"en0")
	defer restore()
	got := bwCall(t, `{"windowSeconds":2}`)
	if got.Code != bwLinkOnly {
		t.Fatalf("判定成 %s", got.Code)
	}
	if got.Values["attributionNote"] != "这台没有 ss" || got.Values["attributionNext"] != "装上再问" {
		t.Errorf("原因与下一步没进 Values：%v / %v", got.Values["attributionNote"], got.Values["attributionNext"])
	}
}

func Test读不到字节计数时给的是数不了(t *testing.T) {
	restore := withReaders(
		func(context.Context) ([]linkCount, error) {
			return nil, errBandwidthSource
		},
		func(_ context.Context, _ time.Duration) (procSample, error) {
			t.Error("连网卡都读不到时不该再去跑进程那一路")
			return procSample{}, nil
		},
		"en0")
	defer restore()
	got := bwCall(t, `{}`)
	if got.Code != bwNoSource {
		t.Fatalf("判定成 %s", got.Code)
	}
	if !strings.Contains(got.Note, "不是「没人在吃」") {
		t.Errorf("没把「数不了」和「没有」分开：%s", got.Note)
	}
}

func Test进程条数设顶并说清截断(t *testing.T) {
	procs := make([]procBytes, 0, 30)
	for i := 0; i < 30; i++ {
		procs = append(procs, procBytes{Process: "node", Pid: 1000 + i, Rx: uint64(30-i) * 1e5, Tx: 100})
	}
	restore := withReaders(
		func(context.Context) ([]linkCount, error) { return []linkCount{{Name: "en0"}}, nil },
		func(_ context.Context, _ time.Duration) (procSample, error) {
			return procSample{procs: procs, attribution: bwAttribFull}, nil
		}, "en0")
	defer restore()
	got := bwCall(t, `{"top":5}`)
	rows := got.Values["processes"].([]map[string]any)
	if len(rows) != 5 {
		t.Fatalf("给了 %d 条，应为 5", len(rows))
	}
	if got.Values["truncated"] != true || got.Values["processCount"] != 30 {
		t.Errorf("截断没标出来：%v / %v", got.Values["truncated"], got.Values["processCount"])
	}
	if rows[0]["process"] != "node" || rows[0]["pid"].(int) != 1000 {
		t.Errorf("排序错了：%+v", rows[0])
	}
}

func Test窗口与条数越界当场拒(t *testing.T) {
	// ★ 先把读法换掉再问越界参数：万一哪天校验漏了，这条测试会去跑真机命令，
	// 慢不说，还会让人以为「测试过了」其实是「真机上恰好没报错」。
	restore := withReaders(
		func(context.Context) ([]linkCount, error) { return []linkCount{{Name: "en0"}}, nil },
		func(_ context.Context, _ time.Duration) (procSample, error) {
			return procSample{attribution: bwAttribNone}, nil
		}, "en0")
	defer restore()
	for _, args := range []string{`{"windowSeconds":31}`, `{"windowSeconds":-1}`, `{"top":51}`, `{"top":-1}`} {
		if _, err := doBandwidthTop(context.Background(), json.RawMessage(args)); err == nil {
			t.Errorf("%s 没被拒", args)
		}
	}
	// 0 当「没填」，走默认窗口（schema 的 minimum 就是 1，正经客户端不会给 0）。
	got := bwCall(t, `{"windowSeconds":0}`)
	if v, _ := got.Values["windowSec"].(int); v != bwDefaultWindowSeconds {
		t.Errorf("windowSeconds 给 0 时窗口是 %d 秒，应为默认的 %d", v, bwDefaultWindowSeconds)
	}
}

// ── 判定码合规与界面登记 ──

func Test带宽的判定码都合规(t *testing.T) {
	codes := []string{bwBusy, bwIdle, bwNotMine, bwLinkOnly, bwPartial, bwNoSource}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("判定码 %s 重复了 —— 两种病共用一个码，界面上就分不开", c)
		}
		seen[c] = true
		if !strings.HasPrefix(c, "bandwidth-") {
			t.Errorf("%s 没以工具用词开头（[OTS-5.5]）", c)
		}
		if strings.ToLower(c) != c || strings.ContainsAny(c, "_ ") {
			t.Errorf("%s 不是小写连字符的形状", c)
		}
		if !ots.ValidVerdictCode(c) {
			t.Errorf("%s 不合判定码规范（[OTS-5.5]）", c)
		}
	}
	// ★ 「数不到进程」和「看不见一部分」必须是两个码：下一步一个在换工具、一个在提权。
	if bwLinkOnly == bwPartial {
		t.Error("两种「数不全」合并了")
	}
}

func Test带宽的判定码界面上都有人话(t *testing.T) {
	js := readUI(t)
	block := jsBlock(js, "const BANDWIDTH_STATE = {")
	if block == "" {
		t.Fatal("界面里找不到码表 BANDWIDTH_STATE")
	}
	for _, code := range []string{bwBusy, bwIdle, bwNotMine, bwLinkOnly, bwPartial, bwNoSource} {
		at := strings.Index(block, "'"+code+"': [")
		if at < 0 {
			t.Errorf("表里没有 %s —— 界面上会直接印出这个码", code)
			continue
		}
		rest := block[at+1+len(code)+len("': ["):] // 跳过头上那个引号
		if phrase, ok := jsPhrase(rest); !ok {
			t.Errorf("%s 那一行不像 ['人话', '档色']：%s", code, rest)
		} else if phrase == "" {
			t.Errorf("%s 没配人话（或那句是空的）", code)
		}
	}
}

func Test带宽工具登记了且是只读(t *testing.T) {
	found := false
	for _, tl := range localTools {
		if tl.Name != "net.bandwidth.top" {
			continue
		}
		found = true
		if tl.Class != ots.ClassRead {
			t.Errorf("这一路只是读计数，_class 应该是只读：%v", tl.Class)
		}
		if tl.Describe != nil {
			t.Error("只读工具不需要批准文案")
		}
	}
	if !found {
		t.Fatal("没登记进 localTools —— 注册表和排查路线都问不到它")
	}
}

// readUI 读出界面那份 JS。★ 为什么后端测试要读前端：这一路的一切数都由后端给，
// 界面只负责把码翻成人话 —— 码加了、表没加，人看到的就是一串英文，
// 那种错在 Go 的编译器和前端的 node --check 里都抓不到。
func readUI(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面文件：%v", err)
	}
	return string(b)
}

// jsPhrase 取出码表里 `code': [` 之后的那一句「人话」。
//
// 两种形状都认：`'有进程在吃'` 与 `t('有进程在吃')`。后者是多语种那层（i18n-codemod）
// 包上去的 —— 这道守卫判的是「这一档到底配没配句子」，包没包 t() 不是它关心的事。
// ★ 不许把它改成只认裸引号：那样一来「给界面加了 i18n」会把守卫弄成红的，
//
//	而下一个人为了让它变绿最可能的做法是删掉这一条，判定码没配人话这件事就再没人管了。
func jsPhrase(rest string) (string, bool) {
	if s, ok := strings.CutPrefix(rest, "t("); ok {
		rest = s
	}
	if !strings.HasPrefix(rest, "'") {
		return "", false
	}
	end := strings.Index(rest[1:], "'")
	if end <= 0 {
		return "", false
	}
	return rest[1 : 1+end], true
}
