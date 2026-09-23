package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.ports.scan 的测试 ──
//
// ★ 全部打在 127.0.0.1 和保留地址上：127.0.0.1 上没监听端口会**立刻**回 RST（closed），
//   240.0.0.1 这类保留地址是**发了没人答**（filtered）。两种凑齐了，就不必伪造网络状况，
//   顶层判定的分支也能真的跑一遍而不是只测纯函数。

// listenTCP 起一个 TCP 监听，端口随机；测试里只要它「有人在听」。
func listenTCP(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close() // 关掉了才没人认领：连它必然吃 RST
	return p
}

func scanRun(t *testing.T, args map[string]any) (ots.Verdict, error) {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doPortsScan(context.Background(), b)
	return v.(ots.Verdict), err
}

func scanVals(t *testing.T, v ots.Verdict) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(v.Values)
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("values 反序列化不了：%v", err)
	}
	return m
}

// ── 端口列表解析 ──

func Test端口列表写法都认(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"22", []int{22}},
		{"22,80,443", []int{22, 80, 443}},
		{"79-81", []int{79, 80, 81}},
		{"22,8000-8002,443", []int{22, 443, 8000, 8001, 8002}}, // 结果按端口排序
		{" 22 , 80 ", []int{22, 80}},
		{"80,80,80", []int{80}},     // 重复的只扫一次
		{"1-1", []int{1}},           // 区间两头相同是合法的一个端口
		{"65535", []int{65535}},     // 边界
		{"22,22,23", []int{22, 23}}, // 交叉去重
		{"100-102,101-103", []int{100, 101, 102, 103}},
	}
	for _, c := range cases {
		got, err := parsePortList(c.in)
		if err != nil {
			t.Errorf("%q 解析报错：%v", c.in, err)
			continue
		}
		if strings.Join(mapS(got), ",") != strings.Join(mapS(c.want), ",") {
			t.Errorf("%q 解成 %v，应该 %v", c.in, got, c.want)
		}
	}
}

func mapS(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Itoa(x)
	}
	return out
}

// ★ 坏写法必须报错，不许「悄悄跳过」：少扫两个端口的后果是结果里写着「没有」，
//
//	而人会把「没有」当成「这台机器上没这个服务」。
func Test端口列表坏写法直接拒(t *testing.T) {
	for _, bad := range []string{
		"22,,80",  // 中间空一段
		",",       // 只有逗号
		"80-",     // 区间缺右半边
		"-80",     // 缺左半边
		"100-50",  // 反过来的区间
		"0",       // 端口 0 不存在
		"65536",   // 越界
		"http",    // 服务名在这里不通
		"22, 80x", // 混进非数字
		"1-70000", // 区间太大
		"1-3000",  // 超过单次上限
	} {
		if _, err := parsePortList(bad); err == nil {
			t.Errorf("%q 居然收下了", bad)
		}
	}
}

func Test留空用默认常用端口集(t *testing.T) {
	got, err := parsePortList("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 40 {
		t.Fatalf("默认集只有 %d 个端口，不像话", len(got))
	}
	// 现场最常问的几个必须在里面：RTSP、大华/海康 SDK、ONVIF、SIP、HTTP
	for _, want := range []int{554, 80, 8080, 37777, 8000, 2000, 5060, 22} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("默认集里少了 %d", want)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatal("默认集没排序")
		}
	}
}

// ── 顶层判定 ──

func Test顶层判定看整体形状(t *testing.T) {
	cases := []struct {
		name                            string
		total, open, closed, filt, noRt int
		want                            string
	}{
		{"有开着的", 10, 1, 3, 6, 0, scanSomeOpen},
		{"全关着：主机在", 10, 0, 10, 0, 0, scanAllClosed},
		// ★ 这条是扫描和单点探测最大的差别：九个端口被丢、一个端口回了拒绝，
		//   那一个拒绝就足够说明主机活着。报成「没回话」会让人去查一条根本没挡着的防火墙。
		{"一个拒绝也不许当没回话", 10, 0, 1, 9, 0, scanAllClosed},
		{"全被丢：判不出机器在不在", 10, 0, 0, 10, 0, scanNoResponse},
		{"只扫一个且没回话", 1, 0, 0, 1, 0, scanNoResponse},
		{"全是没路", 10, 0, 0, 0, 10, scanNoRoute},
		{"没路加杂错也算没路", 10, 0, 0, 0, 6, scanNoRoute}, // 剩下 4 个是 error
		{"有 closed 就不报没路", 10, 0, 2, 0, 6, scanAllClosed},
		{"有路但被丢不报没路", 10, 0, 0, 6, 4, scanNoResponse},
	}
	for _, c := range cases {
		got := scanCodeFor(c.total, c.open, c.closed, c.filt, c.noRt)
		if got != c.want {
			t.Errorf("%s：%d/%d/%d/%d 判成 %s，应该 %s", c.name,
				c.open, c.closed, c.filt, c.noRt, got, c.want)
		}
	}
}

// ── 真扫 ──

func Test扫到开着的端口并列出来(t *testing.T) {
	p1 := listenTCP(t)
	p2 := listenTCP(t)
	c := closedPort(t)
	v, err := scanRun(t, map[string]any{
		"addr": "127.0.0.1", "ports": strconv.Itoa(p1) + "," + strconv.Itoa(c) + "," + strconv.Itoa(p2),
		"timeoutMs": 800,
	})
	if err != nil {
		t.Fatalf("扫描报错：%v", err)
	}
	if v.Code != scanSomeOpen {
		t.Fatalf("判成 %s，应该 %s（note：%s）", v.Code, scanSomeOpen, v.Note)
	}
	vals := scanVals(t, v)
	if vals["open"] != float64(2) || vals["closed"] != float64(1) {
		t.Errorf("计数不对：%v / %v", vals["open"], vals["closed"])
	}
	raw, _ := json.Marshal(vals["openPorts"])
	if string(raw) != "["+strconv.Itoa(p1)+","+strconv.Itoa(p2)+"]" {
		t.Errorf("openPorts 是 %s，应该是 [%d,%d]（按端口排序）", raw, p1, p2)
	}
	if !strings.Contains(v.Note, strconv.Itoa(p1)) || !strings.Contains(v.Note, strconv.Itoa(p2)) {
		t.Errorf("备注里没把开着的端口写出来：%s", v.Note)
	}
}

// 全关着时的判定要说「主机是活的」——这是这次扫描真正买到的结论。
func Test全关着时报主机活着(t *testing.T) {
	c1, c2 := closedPort(t), closedPort(t)
	v, err := scanRun(t, map[string]any{"addr": "127.0.0.1",
		"ports": strconv.Itoa(c1) + "," + strconv.Itoa(c2), "timeoutMs": 800})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != scanAllClosed {
		t.Fatalf("判成 %s，应该 %s", v.Code, scanAllClosed)
	}
	if !strings.Contains(v.Note, "主机是活的") {
		t.Errorf("备注没给出「主机活着」这个结论：%s", v.Note)
	}
}

// 一个端口都不回话时，**不许**说主机活着，也不许说端口关着。
// 240.0.0.0/4 是保留段：发出去真的没人答（实测 i/o timeout）。
func Test全没回话时不指认主机状态(t *testing.T) {
	v, err := scanRun(t, map[string]any{"addr": "240.0.0.1",
		"ports": "80,443", "timeoutMs": 400})
	if err != nil {
		t.Fatalf("扫描本身不该报错：%v", err)
	}
	if v.Code != scanNoResponse {
		t.Fatalf("判成 %s，应该 %s（本机可能没到保留段的路，那样这条该跳过而不是硬判：%s）",
			v.Code, scanNoResponse, v.Note)
	}
	vals := scanVals(t, v)
	if vals["filtered"] != float64(2) {
		t.Errorf("两个端口都该记成被丢：%v", vals)
	}
	if strings.Contains(v.Note, "主机是活的") {
		t.Errorf("一个回执都没有，不许说主机活着：%s", v.Note)
	}
	if !strings.Contains(v.Note, "net.ping") {
		t.Errorf("该指一步下一步去 ping：%s", v.Note)
	}
}

// 明细的取舍：扫得少就逐端口给，扫得多只给汇总，免得两千条 closed 把开着的几个埋掉。
// ★ 开着的那个监听口要落在被扫的区间里 —— 省掉明细不能省掉结论。
func Test扫得多时只给汇总不给明细(t *testing.T) {
	p := listenTCP(t)
	v, err := scanRun(t, map[string]any{"addr": "127.0.0.1",
		"ports": "1-250," + strconv.Itoa(p), "timeoutMs": 600})
	if err != nil {
		t.Fatal(err)
	}
	vals := scanVals(t, v)
	// 1-250 去重后 250 个；随机监听口极少数会正好落在这个区间里，所以看下界。
	if n, _ := vals["scanned"].(float64); int(n) < 250 {
		t.Fatalf("scanned = %v，应该至少 250", vals["scanned"])
	}
	if vals["portsOmitted"] != true {
		t.Errorf("250 个端口还带着逐端口明细：%v", keysOf(vals))
	}
	if _, has := vals["ports"]; has {
		t.Error("明细该省掉")
	}
	if vals["warning"] != "many-connections" {
		t.Errorf("扫 250 个端口没给「连接数太多」的提醒：%v", vals["warning"])
	}
	// 省掉明细不能省掉结论：开着的那个端口必须还在 openPorts 里
	if open := fmtS(vals["openPorts"]); !strings.Contains(open, strconv.Itoa(p)) {
		t.Errorf("openPorts 里没有 %d：%s", p, open)
	}
	if v.Code != scanSomeOpen {
		t.Fatalf("判成 %s", v.Code)
	}
}

func Test扫得少时逐端口明细带着状态(t *testing.T) {
	p := listenTCP(t)
	c := closedPort(t)
	v, _ := scanRun(t, map[string]any{"addr": "127.0.0.1",
		"ports": strconv.Itoa(p) + "," + strconv.Itoa(c), "timeoutMs": 800})
	vals := scanVals(t, v)
	rows, ok := vals["ports"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("没拿到两条逐端口明细：%v", vals["ports"])
	}
	st := map[int]string{}
	for _, r := range rows {
		m := r.(map[string]any)
		st[int(m["port"].(float64))] = m["status"].(string)
	}
	if st[p] != verdictOpen {
		t.Errorf("%d 记成 %q，应该 open", p, st[p])
	}
	if st[c] != verdictClosed {
		t.Errorf("%d 记成 %q，应该 closed", c, st[c])
	}
}

// ★ 并发池的意义不是快，是有界：不控并发扫两千个端口就是瞬间造两千个套接字。
// 这里用「保留地址必然等满超时」把耗时变成可读的证据：
// 12 个端口、并发 4、每个 250ms → 三批，约 750ms；不限并发会是一次 250ms，串行是 3s。
func Test并发真的被限制住(t *testing.T) {
	addr, _ := netaddr.Parse("240.0.0.1")
	ports := make([]int, 0, 12)
	for i := 0; i < 12; i++ {
		ports = append(ports, 80)
	}
	start := time.Now()
	res := scanPorts(context.Background(), addr, ports, 250*time.Millisecond, 4, "test")
	el := time.Since(start)
	if len(res) != 12 {
		t.Fatalf("结果条数 %d，应该 12", len(res))
	}
	for _, r := range res {
		if r.Status != verdictFiltered {
			t.Fatalf("状态是 %q，12 个都该是被丢", r.Status)
		}
	}
	if el < 600*time.Millisecond {
		t.Errorf("12 个端口并发 4 只用了 %v —— 并发没限住", el)
	}
	if el > 1600*time.Millisecond {
		t.Errorf("用了 %v，比预期的三批（约 750ms）慢太多 —— 像在串行", el)
	}
}

func Test取消就收摊不留着等超时(t *testing.T) {
	addr, _ := netaddr.Parse("240.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	res := scanPorts(ctx, addr, []int{80, 81, 82, 83}, 5*time.Second, 2, "test")
	if time.Since(start) > 4*time.Second {
		t.Fatalf("取消了还跑了 %v", time.Since(start))
	}
	var cancelled int
	for _, r := range res {
		if r.Status == scanError && strings.Contains(r.Detail, "取消") {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Errorf("没有任何端口记成「取消了」：%+v", res)
	}
}

// 「没路」和「发了没人答」是两件事：前者查自己的网卡和路由，后者查对端。
func Test没路与被丢分得开(t *testing.T) {
	for _, s := range []string{
		"connect: no route to host",
		"dial tcp: connect: network is unreachable",
		"A socket operation was attempted to an unreachable network.",
		"cannot assign requested address",
	} {
		if !isNoRoute(errors.New(s)) {
			t.Errorf("%q 该认成没路", s)
		}
	}
	for _, s := range []string{
		"dial tcp 240.0.0.1:80: i/o timeout", // 被丢：包出去了没人答
		"connect: connection refused",        // 拒绝：主机在
	} {
		if isNoRoute(errors.New(s)) {
			t.Errorf("%q 不该认成没路", s)
		}
	}
}

func Test扫描只收IP并指路DNS(t *testing.T) {
	for _, a := range []string{"cam.local", "hub.example.com"} {
		b, _ := json.Marshal(map[string]any{"addr": a})
		if _, err := doPortsScan(context.Background(), b); err == nil {
			t.Errorf("%q 收下了", a)
		} else if !strings.Contains(err.Error(), "net.dns.query") {
			t.Errorf("%q 的报错没指下一步：%v", a, err)
		}
	}
}

func Test扫描没给地址(t *testing.T) {
	b, _ := json.Marshal(map[string]any{})
	if _, err := doPortsScan(context.Background(), b); err == nil {
		t.Error("没给 addr 该拒")
	}
}

// 备注里端口太多要折叠，不然一行 Note 全是数字。
func Test备注里端口列长了会折叠(t *testing.T) {
	many := make([]int, 20)
	for i := range many {
		many[i] = 1000 + i
	}
	s := joinPorts(many)
	if !strings.Contains(s, "等 20 个") {
		t.Errorf("没折叠：%s", s)
	}
	if strings.Contains(s, "1019") {
		t.Errorf("折叠了还全列出来：%s", s)
	}
	if got := joinPorts(nil); got != "无" {
		t.Errorf("空列表写成 %q", got)
	}
}

func keysOf(m map[string]any) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ",")
}

func fmtS(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
