package snmp_test

import (
	"context"
	"errors"
	"net"
	"net.yuhox.com/netkit/internal/snmp"
	"net.yuhox.com/netkit/internal/snmp/snmptest"
	"strings"
	"testing"
	"time"
)

// 一台像样的假交换机：sys 那几栏 + ifTable 两行 + 一个 64 位计数器。
//
// ★ 填的是真 MIB 的 OID，不是随手编号 —— 这一层的意义就在于
//
//	「按编号顺序走树」，编号编错了测不出 walk 的毛病。
func testMIB() map[string]snmptest.Value {
	return map[string]snmptest.Value{
		"1.3.6.1.2.1.1.1.0":        snmptest.Str("H3C S5560-28C-EI, Release 2432"),
		"1.3.6.1.2.1.1.3.0":        snmptest.Ticks(98765432),
		"1.3.6.1.2.1.1.5.0":        snmptest.Str("core-switch-01"),
		"1.3.6.1.2.1.2.1.0":        snmptest.Int(3),
		"1.3.6.1.2.1.2.2.1.1.1":    snmptest.Int(1),
		"1.3.6.1.2.1.2.2.1.1.2":    snmptest.Int(2),
		"1.3.6.1.2.1.2.2.1.2.1":    snmptest.Str("GigabitEthernet1/0/1"),
		"1.3.6.1.2.1.2.2.1.2.2":    snmptest.Str("GigabitEthernet1/0/2"),
		"1.3.6.1.2.1.2.2.1.8.1":    snmptest.Int(1), // up
		"1.3.6.1.2.1.2.2.1.8.2":    snmptest.Int(2), // down
		"1.3.6.1.2.1.31.1.1.1.6.1": snmptest.Count64(1234567890123),
		"1.3.6.1.2.1.15.3.1.2.1":   snmptest.Addr(net.IPv4(192, 168, 1, 10)),
	}
}

func testDevice(t *testing.T) *snmptest.Device {
	t.Helper()
	return snmptest.Start(t, "public", testMIB())
}

func clientTo(d *snmptest.Device) *snmp.Client {
	return &snmp.Client{
		Addr:      d.Addr(),
		Community: "public",
		Timeout:   150 * time.Millisecond,
		Retries:   2,
	}
}

func opened(t *testing.T, d *snmptest.Device) *snmp.Client {
	t.Helper()
	c := clientTo(d)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// ── GET ──

func Test一次GET问几栏就只发一个请求(t *testing.T) {
	// 端口状态那一屏有十几栏：一栏一个请求的话，界面要等十几趟，
	// 而且中间任何一趟丢了就出现「半屏有值半屏没有」。
	d := testDevice(t)
	vs, err := opened(t, d).Get(ctx(t),
		"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.2.2.1.8.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 {
		t.Fatalf("回来 %d 栏", len(vs))
	}
	if vs[0].Str() != "H3C S5560-28C-EI, Release 2432" || vs[1].Str() != "core-switch-01" {
		t.Errorf("值串位了：%v / %v", vs[0].Str(), vs[1].Str())
	}
	if n := vs[2].IntOr0(); n != 1 {
		t.Errorf("ifOperStatus 读成 %d，要 1（up）", n)
	}
	if got := d.Reqs(); got != 1 {
		t.Errorf("三栏发了 %d 个请求，要 1", got)
	}
	// 回来的顺序必须和问的顺序一致：工具那一侧是按位置取值的
	if vs[0].OID != "1.3.6.1.2.1.1.1.0" || vs[2].OID != "1.3.6.1.2.1.2.2.1.8.1" {
		t.Errorf("OID 顺序被打乱了：%s … %s", vs[0].OID, vs[2].OID)
	}
}

func Test每一种值按自己的类型读回来(t *testing.T) {
	d := testDevice(t)
	c := opened(t, d)
	one, err := c.GetOne(ctx(t), "1.3.6.1.2.1.31.1.1.1.6.1")
	if err != nil {
		t.Fatal(err)
	}
	// ★ 这个号超过了 32 位：按 Counter32 读会绕成一个小得多的数，
	//   界面上就是「一台跑了半年的设备只收了 287G」。
	if n := one.UintOr0(); n != 1234567890123 {
		t.Errorf("ifHCInOctets 读成 %d", n)
	}
	if one.TypeName() != "计数器(64)" {
		t.Errorf("类型认成了 %s", one.TypeName())
	}
	ip, err := c.GetOne(ctx(t), "1.3.6.1.2.1.15.3.1.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.IP(); got == nil || got.String() != "192.168.1.10" {
		t.Errorf("IpAddress 读成 %v", got)
	}
	up, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if up.UintOr0() != 98765432 {
		t.Errorf("sysUpTime 读成 %d", up.UintOr0())
	}
}

func Test没有这一栏时v1和v2c的说法分开处理(t *testing.T) {
	// v2c 在变量表里回 noSuchInstance；v1 是整个报文作废（noSuchName）。
	// 混起来的话，接老设备时「这台不支持这一栏」会被报成「查询失败」。
	missing := "1.3.6.1.2.1.253.1.1.1.1"
	v2 := opened(t, testDevice(t))
	got, err := v2.GetOne(ctx(t), missing)
	if err != nil {
		t.Fatalf("v2c 问一栏没有的居然失败了：%v", err)
	}
	if !got.Missing() {
		t.Errorf("没标成「没有这一栏」：%+v", got)
	}

	d := testDevice(t)
	d.SetV1Only(true)
	v1 := clientTo(d)
	v1.Version = snmp.V1
	defer v1.Close()
	if _, err := v1.GetOne(ctx(t), missing); err == nil {
		t.Error("v1 问一栏没有的却没报错（设备是整个报文作废的）")
	} else {
		var e *snmp.Error
		if !errors.As(err, &e) || e.Status != 2 {
			t.Errorf("v1 报的不是 noSuchName：%v", err)
		} else if !strings.Contains(e.Error(), "不给读") {
			t.Errorf("这句话没告诉人下一步：%s", e.Error())
		}
	}
}

// ── 重传、对不上号 ──

func Test丢两个包还能靠重传走通(t *testing.T) {
	// UDP 上没有重传。丢一个就放弃的话，界面上是「这台设备时好时坏」，
	// 而其实每次都是同一栏在同一个位置丢 —— 重传两次就稳了。
	d := testDevice(t)
	d.SetDropNext(2)
	v, err := opened(t, d).GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
	if err != nil {
		t.Fatalf("重传没走通：%v", err)
	}
	if v.Str() != "core-switch-01" {
		t.Errorf("值读成 %q", v.Str())
	}
	if got := d.Reqs(); got != 3 {
		t.Errorf("一共发了 %d 个请求，要 3（丢两个、第三个成）", got)
	}
}

func Test标识对不上时不许把别人的答案当自己的(t *testing.T) {
	// 重传之后，第一个请求的回包可能姗姗来迟从同一个口进来。
	// 认了它，界面显示的就是「上一次问的那一栏」，而人完全看不出来。
	d := testDevice(t)
	d.SetWrongID(true)
	_, err := opened(t, d).GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
	if !errors.Is(err, snmp.ErrNoReply) {
		t.Fatalf("认了对不上号的回包：%v", err)
	}
	// ★ 但也不能光说「没回话」：这台设备其实是**答了**的。
	//   少了这半句，人会去查防火墙和团体名，而问题在设备上（或者网上有第二台在抢答）。
	if !strings.Contains(err.Error(), "对不上") {
		t.Errorf("没说清「有回包但没算数」：%v", err)
	}
}

func Test设备回trap时不能算成没开SNMP(t *testing.T) {
	// 设备上把 trap 目标配成了我们这台时很常见：问一句它回一条告警。
	// 这既不是答案，也不是「没开」—— 话要说成第三种。
	d := testDevice(t)
	d.SetTrapOnly(true)
	_, err := opened(t, d).GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
	if !errors.Is(err, snmp.ErrNoReply) {
		t.Fatalf("trap 被当成答案了：%v", err)
	}
	if !strings.Contains(err.Error(), "不是响应报文") {
		t.Errorf("没说清来的是 trap：%v", err)
	}
	if d.Reqs() != 3 {
		t.Errorf("trap 不算答案，就该继续重传，实际问了 %d 次", d.Reqs())
	}
}

func Test回包不是那台设备答的一律不算(t *testing.T) {
	// UDP 的源地址是自己填的，谁都能答一句。认了别人答的，
	// 等于把网段里另一台设备的端口状态显示成这台设备的。
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	replied := make(chan struct{})
	go func() {
		buf := make([]byte, 2000)
		n, peer, err := target.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req, err := snmp.Parse(buf[:n])
		if err != nil {
			return
		}
		close(replied)
		resp := snmp.Packet{
			Version: snmp.Version2c, Community: "public", PDU: snmp.PDUGetResponse, ID: req.ID,
			VarBinds: []snmp.VarBind{{OID: "1.3.6.1.2.1.1.5.0", Tag: snmp.TagOctetString, Val: []byte("冒充的")}},
		}
		out, err := resp.Marshal()
		if err == nil {
			_, _ = other.WriteTo(out, peer) // 源端口不是 target 的
		}
	}()

	c := &snmp.Client{Addr: target.LocalAddr().String(), Community: "public",
		Timeout: 150 * time.Millisecond, Retries: 0}
	defer c.Close()
	_, err = c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
	if !errors.Is(err, snmp.ErrNoReply) {
		t.Fatalf("冒充的回包被认下了：%v", err)
	}
	if strings.Contains(err.Error(), "冒充") {
		t.Errorf("把冒充的值显示出来了：%v", err)
	}
	if !strings.Contains(err.Error(), "不是这台设备答的") {
		t.Errorf("没说清有别的源答过话：%v", err)
	}
	<-replied
}

// ── 请求标识 ──

func Test请求标识既不重复也不是负数(t *testing.T) {
	d := testDevice(t)
	c := opened(t, d)
	for i := 0; i < 20; i++ {
		if _, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0"); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[int32]bool{}
	for _, id := range d.IDs() {
		if id <= 0 {
			// ★ 最高位给 1 的话 BER 按补码读回是负数，跟我们记的对不上，
			//   表现成「每一次都超时」—— 最难查的一种，所以要钉住。
			t.Errorf("请求标识是 %d（必须为正）", id)
		}
		if seen[id] {
			t.Errorf("请求标识 %d 用了两次", id)
		}
		seen[id] = true
	}
	if len(seen) != 20 {
		t.Errorf("20 次问话只有 %d 个不同的标识", len(seen))
	}
}

// ── walk ──

func Test走GETBULK时一趟就能走完一棵子树(t *testing.T) {
	d := testDevice(t)
	vs, err := opened(t, d).Walk(ctx(t), "1.3.6.1.2.1.2.2.1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"1.3.6.1.2.1.2.2.1.1.1", "1.3.6.1.2.1.2.2.1.1.2",
		"1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2.1.2.2",
		"1.3.6.1.2.1.2.2.1.8.1", "1.3.6.1.2.1.2.2.1.8.2",
	}
	if len(vs) != len(want) {
		t.Fatalf("walk 回来 %d 栏，要 %d 栏：%v", len(vs), len(want), oidsOf(vs))
	}
	for i, v := range vs {
		if v.OID != want[i] {
			t.Errorf("第 %d 栏是 %s，要 %s", i, v.OID, want[i])
		}
	}
	// ★ 六栏一次问完：GETBULK 两趟就够（第二趟拿到树外的 OID 才收口）。
	//   变成六趟的话，一张 48 口的表要点四十多下，界面上就是「查端口状态很慢」。
	if got := d.Reqs(); got > 2 {
		t.Errorf("walk 一棵六个节点的小树用了 %d 个请求，GETBULK 没起作用", got)
	}
}

func Test设备不认GETBULK时退回一步一步走(t *testing.T) {
	// 一批老设备对 GETBULK 直接回 tooBig。整个 walk 失败的话，
	// 现场看到的是「这台交换机读不出端口表」，而其实只是快不起来。
	d := testDevice(t)
	d.SetNoBulk(true)
	vs, err := opened(t, d).Walk(ctx(t), "1.3.6.1.2.1.2.2.1")
	if err != nil {
		t.Fatalf("退回 GETNEXT 这条没走通：%v", err)
	}
	if len(vs) != 6 {
		t.Errorf("回来 %d 栏：%v", len(vs), oidsOf(vs))
	}
	for _, id := range d.IDs() {
		if id <= 0 {
			t.Error("重传路径上标识跑成了负数")
		}
	}
}

func Test设备把树外的子树递过来时walk要收口(t *testing.T) {
	// ★ 真毛病：走到末尾不发 endOfMibView，而是把隔壁子树的 OID 递过来。
	//   只认那个异常值的实现会一路读到整张 MIB —— 界面上是「转圈转不完」。
	d := testDevice(t)
	d.SetLeaky(true)
	vs, err := opened(t, d).Walk(ctx(t), "1.3.6.1.2.1.2.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if !snmp.OIDUnder(v.OID, "1.3.6.1.2.1.2.2.1") {
			t.Errorf("树外的一栏被收了进来：%s", v.OID)
		}
	}
	if len(vs) != 6 {
		t.Errorf("收口前多吃了几栏：%v", oidsOf(vs))
	}
}

func Test设备走不动时walk要停下来报错(t *testing.T) {
	// 没有这一条兜底就是死循环：现场表现为程序卡住，而不是「这台设备有问题」。
	for _, prefix := range []string{"1.3.6.1.2.1.2.2.1"} {
		d := testDevice(t)
		d.SetStuck(true)
		_, err := opened(t, d).Walk(ctx(t), prefix)
		if err == nil || !strings.Contains(err.Error(), "没有往前走") {
			t.Errorf("GETBULK 路径：%v", err)
		}

		d2 := testDevice(t)
		d2.SetStuck(true)
		d2.SetNoBulk(true) // 同一台设备，走 GETNEXT 那条
		_, err = opened(t, d2).Walk(ctx(t), prefix)
		if err == nil || !strings.Contains(err.Error(), "没有往前走") {
			t.Errorf("GETNEXT 路径：%v", err)
		}
	}
}

func Test只认v1的设备也能把表走完(t *testing.T) {
	// v1 没有 GETBULK，而且「走到头」是用 error-status=noSuchName 表达的。
	// 当成失败的话，每张表末尾都会白报一次错，界面上一律是「读不全」。
	d := testDevice(t)
	d.SetV1Only(true)
	c := clientTo(d)
	c.Version = snmp.V1
	defer c.Close()
	vs, err := c.Walk(ctx(t), "1.3.6.1.2.1.2.2.1")
	if err != nil {
		t.Fatalf("v1 walk 失败：%v", err)
	}
	if len(vs) != 6 {
		t.Errorf("v1 walk 回来 %d 栏：%v", len(vs), oidsOf(vs))
	}
	if vs[0].IntOr0() != 1 {
		t.Errorf("第一栏值读成 %d", vs[0].IntOr0())
	}
}

func Test前缀给空时不许去读整张MIB(t *testing.T) {
	// 前缀写成一栏标量（比如 1.3.6.1.2.1.1.1.0）时，
	// 它下面只有它自己后面的东西；不给前缀则当场拒绝，而不是从 1.0 走起。
	d := testDevice(t)
	c := opened(t, d)
	if _, err := c.Walk(ctx(t), ""); err == nil {
		t.Error("空前缀也走了起来")
	}
	if _, err := c.Walk(ctx(t), "."); err == nil {
		t.Error("整棵 MIB 根也算前缀")
	}
	vs, err := c.Walk(ctx(t), "1.3.6.1.2.1.2.2.1.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 {
		t.Errorf("只要名字那一列，回来 %d 栏：%v", len(vs), oidsOf(vs))
	}
}

// ── 地址、网卡、生命周期 ──

func Test没写端口时按161发并且把地址报全(t *testing.T) {
	// 设备的 SNMP 很多写死 161，界面上只让填 IP。
	// 报错时必须把「实际发去了 161」写出来，否则人以为端口是别的地方配错了。
	c := &snmp.Client{Addr: "127.0.0.1", Community: "public",
		Timeout: 60 * time.Millisecond, Retries: 0}
	defer c.Close()
	_, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
	if !errors.Is(err, snmp.ErrNoReply) {
		t.Fatalf("没人应答时报的是：%v", err)
	}
	if !strings.Contains(err.Error(), "127.0.0.1:161") {
		t.Errorf("话里没写补出来的端口：%v", err)
	}
}

func Test指定了本机地址却解不开时当场失败(t *testing.T) {
	// ★ 不许退化成「不绑网卡」：那等于这块网卡之外其余每一块都可能出去，
	//   而指定网卡的意义正是「别从办公口/公网口去问这台设备」。
	for _, la := range []string{"240.0.0.1", "这不是一个地址", "192.0.2.55"} {
		d := testDevice(t)
		c := clientTo(d)
		c.LocalAddr = la
		c.Retries = 0
		c.Timeout = 60 * time.Millisecond
		_, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
		if err == nil {
			t.Errorf("本机没有 %s 这个地址，却还是发出去了", la)
			continue
		}
		if !strings.Contains(err.Error(), la) {
			t.Errorf("%s 的报错没带上这个地址：%v", la, err)
		}
		if strings.Contains(err.Error(), "没有回话") {
			t.Errorf("退化成了「不绑网卡」，然后报超时：%v", err)
		}
	}
}

func Test本机地址绑得上时正常走通(t *testing.T) {
	// 上一那条不许退化，这一条要保证「能绑」时真的绑上去问了，
	// 否则「一律不绑」也能让两条测试都绿。
	d := testDevice(t)
	c := clientTo(d)
	c.LocalAddr = "127.0.0.1"
	defer c.Close()
	v, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0")
	if err != nil {
		t.Fatalf("绑了回环反而问不通：%v", err)
	}
	if v.Str() != "core-switch-01" {
		t.Errorf("值读成 %q", v.Str())
	}
}

func Test关掉之后不再往外发东西(t *testing.T) {
	d := testDevice(t)
	c := clientTo(d)
	if _, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0"); err != nil {
		t.Fatal(err)
	}
	before := d.Reqs()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.5.0"); err == nil {
		t.Error("关掉之后还问得动")
	}
	if err := c.Close(); err != nil {
		t.Errorf("重复 Close 报错：%v", err)
	}
	if d.Reqs() != before {
		t.Error("关掉之后设备还收到了请求")
	}
}

func Test上下文一取消就立刻回来(t *testing.T) {
	// 界面上「停止」按钮按下去要真的停：一个 walk 可能还有几十趟没走。
	d := testDevice(t)
	d.SetDropNext(1000) // 一台完全不答的设备
	c := clientTo(d)
	c.Timeout = 5 * time.Second
	c.Retries = 5
	defer c.Close()
	cctx, cancel := context.WithCancel(ctx(t))
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := c.GetOne(cctx, "1.3.6.1.2.1.1.5.0")
	if err == nil {
		t.Fatal("取消之后还「成功」了")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("报的是：%v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("等了 %v 才回来，取消没起作用", took)
	}
}

func Test一个客户端连着问不同形状的表(t *testing.T) {
	// 一条连接复用：源端口不变，设备的会话表不会把我们登记成一堆新管理器。
	d := testDevice(t)
	c := opened(t, d)
	if _, err := c.GetOne(ctx(t), "1.3.6.1.2.1.1.1.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Walk(ctx(t), "1.3.6.1.2.1.2.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx(t), "1.3.6.1.2.1.2.2.1.8.1", "1.3.6.1.2.1.2.2.1.8.2"); err != nil {
		t.Fatal(err)
	}
	// ★ 这里问的是「设备那边看到的源端口有几个」，不是私有字段。
	//   读 c.conn 只能证明「它存了一条连接」，证明不了没在每次问话时重拨 ——
	//   而现场在意的正是源端口变没变。
	if got := len(d.Ports()); got != 1 {
		t.Errorf("设备看到了 %d 个源端口，要 1（每次问话都重拨了一条连接）", got)
	}
}

func oidsOf(vs []snmp.VarBind) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.OID)
	}
	return out
}
