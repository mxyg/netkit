package snmp_test

import (
	"net"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
	"os/exec"
	"strings"
	"testing"
)

// 拿系统自带的 Net-SNMP 客户端打我们这台假设备。
//
// ★★ 这一条是整套测试里最值钱的：对面是一个完全独立的实现，
//
//	它肯认我们的回包，才说明「字节层面是对的」，而不是「自己写的编码器自己看得懂」。
//	macOS 自带 snmpget / snmpwalk / snmpbulkwalk；没有的话跳过（CI 上会红在那儿，
//	所以这里显式 Skip，让「没测到」这件事写在日志里，而不是假装通过）。
func snmpTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath("/usr/bin/" + name)
	if err != nil {
		t.Skipf("这台机器上没有 %s（Net-SNMP），这一条互测跳过", name)
	}
	return p
}

// runSNMP 跑一个 Net-SNMP 客户端去打 d。
func runSNMP(t *testing.T, bin, version, target, oid string) string {
	t.Helper()
	cmd := exec.Command(bin, "-v", version, "-c", "public", "-On", "-t", "2", "-r", "1", target, oid)
	out, err := cmd.CombinedOutput()
	s := string(out)
	if err != nil {
		t.Fatalf("%s %s 打 %s 失败了：%v\n%s", bin, version, oid, err, s)
	}
	return s
}

func TestNetSNMP肯认我们拼的回包(t *testing.T) {
	// 一台设备的 sysDescr / 计数器 / IP 地址 / 运行时长，四种类型各一栏。
	// 对面按类型读出来的值必须和填进去的一模一样 —— 类型标签或补零错一位，
	// 这里就会读到 "Wrong Type" 或者一个差了符号的数。
	d := snmptest.Start(t, "public", map[string]snmptest.Value{
		"1.3.6.1.2.1.1.1.0":        snmptest.Str("H3C S5560-28C-EI, Release 2432"),
		"1.3.6.1.2.1.1.3.0":        snmptest.Ticks(98765432),
		"1.3.6.1.2.1.15.3.1.2.1":   snmptest.Addr(net.ParseIP("192.168.1.10")),
		"1.3.6.1.2.1.31.1.1.1.6.1": snmptest.Count64(1234567890123),
		"1.3.6.1.2.1.2.2.1.8.1":    snmptest.Int(1),
	})
	bin := snmpTool(t, "snmpget")
	target := d.Addr()
	for _, c := range []struct{ oid, want string }{
		{".1.3.6.1.2.1.1.1.0", "STRING: H3C S5560-28C-EI, Release 2432"},
		{".1.3.6.1.2.1.1.3.0", "Timeticks: (98765432)"},
		{".1.3.6.1.2.1.15.3.1.2.1", "IpAddress: 192.168.1.10"},
		// ★ 这一栏是 64 位的：Counter64 的标签写错、或者高字节没补 0，
		//   对面会读成负数或直接拒收。
		{".1.3.6.1.2.1.31.1.1.1.6.1", "Counter64: 1234567890123"},
		// 对面带着 IF-MIB，所以它按枚举把 1 显示成 up(1) —— 这也顺带证明了
		// 我们给的是 INTEGER 而不是别的类型。
		{".1.3.6.1.2.1.2.2.1.8.1", "INTEGER: up(1)"},
	} {
		got := runSNMP(t, bin, "2c", target, c.oid)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s 对面读成：%s（要含 %q）", c.oid, got, c.want)
		}
	}
}

func TestNetSNMP用v1也能读到我们(t *testing.T) {
	// 老交换机只认 v1，这一档的回包格式又不完全一样（没有 noSuchInstance 那些）。
	// 这一条只验「对面认我们的包」，异常值那套留在客户端侧测。
	d := snmptest.Start(t, "public", map[string]snmptest.Value{
		"1.3.6.1.2.1.1.1.0": snmptest.Str("old-catalyst 2950"),
		"1.3.6.1.2.1.1.3.0": snmptest.Ticks(1000),
	})
	got := runSNMP(t, snmpTool(t, "snmpget"), "1", d.Addr(), ".1.3.6.1.2.1.1.1.0")
	if !strings.Contains(got, "STRING: old-catalyst 2950") {
		t.Errorf("v1 读成：%s", got)
	}
}

func TestNetSNMP走我们的树能收口(t *testing.T) {
	// walk / bulkwalk 各自走一遍：走不完是超时（CombinedOutput 会带回非 0），
	// 少走几栏是数字对不上。两个工具的收口路径不一样，都要过。
	d := testDevice(t)
	target := d.Addr()
	want := 6
	for _, c := range []struct{ bin, version string }{
		{"snmpwalk", "2c"}, {"snmpbulkwalk", "2c"}, {"snmpwalk", "1"},
	} {
		bin := snmpTool(t, c.bin)
		got := runSNMP(t, bin, c.version, target, ".1.3.6.1.2.1.2.2.1")
		lines := 0
		for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
			if strings.HasPrefix(line, ".") {
				lines++
			}
		}
		if lines != want {
			t.Errorf("%s -v %s 走了 %d 栏，要 %d：\n%s", c.bin, c.version, lines, want, got)
		}
	}
}

func Test团体名不对时NetSNMP也拿不到东西(t *testing.T) {
	// 这一条是对「团体名错了不答」那个设计的旁证：真设备就是这么干的，
	// 所以界面上「没回话」必须同时怀疑团体名，而不是只怀疑防火墙。
	d := snmptest.Start(t, "secret", map[string]snmptest.Value{"1.3.6.1.2.1.1.1.0": snmptest.Str("not-for-you")})
	bin := snmpTool(t, "snmpget")
	cmd := exec.Command(bin, "-v", "2c", "-On", "-c", "public", "-t", "1", "-r", "0",
		d.Addr(), ".1.3.6.1.2.1.1.1.0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("团体名不对还读到了东西：%s", out)
	}
	if !strings.Contains(string(out), "Timeout") {
		t.Errorf("对面看到的不是超时而是别的：%s", out)
	}
}

func Test正确的团体名读得到(t *testing.T) {
	// 上一条的对照：同一台设备、换一个团体名就读得到 —— 证明失败是因为团体名，
	// 不是因为测试本身跑不通。
	d := snmptest.Start(t, "secret", map[string]snmptest.Value{"1.3.6.1.2.1.1.1.0": snmptest.Str("got-it")})
	bin := snmpTool(t, "snmpget")
	out, err := exec.Command(bin, "-v", "2c", "-c", "secret", "-On", "-t", "2", "-r", "1",
		d.Addr(), ".1.3.6.1.2.1.1.1.0").CombinedOutput()
	if err != nil {
		t.Fatalf("团体名对上了还读不到：%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "STRING: got-it") {
		t.Errorf("读成：%s", out)
	}
}
