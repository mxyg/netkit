package tools

import (
	"context"
	"encoding/json"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

func traceRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doTrace(context.Background(), b)
	if err != nil {
		t.Fatalf("trace(%v) 报错：%v", args, err)
	}
	out, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("trace 没返回判定，返回 %T", v)
	}
	return out
}

func famOf(t *testing.T, v ots.Verdict) []traceFamily {
	t.Helper()
	raw, err := json.Marshal(v.Values["traces"])
	if err != nil {
		t.Fatalf("traces 序列化不了：%v", err)
	}
	var fs []traceFamily
	if err := json.Unmarshal(raw, &fs); err != nil {
		t.Fatalf("traces 反序列化不了：%v", err)
	}
	return fs
}

// 目标以 - 开头必须拒掉：它会被当成 traceroute 自己的选项吃掉。
func Test目标以横杠开头直接拒(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"host": "-f"})
	if _, err := doTrace(context.Background(), b); err == nil {
		t.Fatal("`-f` 被当成目标放过去了 —— 它会变成外部命令的选项")
	}
	// 尾巴上的空白不算（先 TrimSpace 再校验，切不出参数注入）；**中间**有空白才是注入。
	for _, host := range []string{"a b", "example.com -f", "--back"} {
		b, _ := json.Marshal(map[string]any{"host": host})
		if _, err := doTrace(context.Background(), b); err == nil {
			t.Errorf("%q 也该拒", host)
		}
	}
}

func Test没给目标(t *testing.T) {
	b, _ := json.Marshal(map[string]any{})
	if _, err := doTrace(context.Background(), b); err == nil {
		t.Fatal("空参数该报错")
	}
}

// ---------- 解析：三种命令各自的真实输出形状 ----------

const macTraceroute = `traceroute to example.com (93.184.216.34), 30 hops max, 40 byte packets
 1  192.168.1.1 (192.168.1.1)  1.955 ms  1.246 ms  1.108 ms
 2  10.10.0.1 (10.10.0.1)  8.123 ms  7.998 ms  8.011 ms
 3  * * *
 4  172.16.5.5 (172.16.5.5)  22.4 ms !X
 5  93.184.216.34 (example.com)  31.208 ms  30.9 ms  31.5 ms
`

func Test解析macOS的traceroute(t *testing.T) {
	hops := parseNumberedHops(macTraceroute)
	if len(hops) != 5 {
		t.Fatalf("5 跳，解析出 %d：%+v", len(hops), hops)
	}
	if hops[0].Addr != "192.168.1.1" || len(hops[0].RTTMs) != 3 {
		t.Errorf("第一跳： %+v", hops[0])
	}
	// ★ 整行 * 是一跳「没回」，不是没有这一跳 —— 丢掉它就看不出断在哪
	if hops[2].Addr != "" || hops[2].Lost != 3 {
		t.Errorf("第三跳该记成丢了 3 个：%+v", hops[2])
	}
	if hops[3].Mark != "!X" {
		t.Errorf("`!X`（禁止转发）丢了：%+v", hops[3])
	}
	if hops[4].Addr != "93.184.216.34" {
		t.Errorf("带域名的行取第一个地址：%+v", hops[4])
	}
}

const winTracert = `Tracing route to example.com [93.184.216.34] over a maximum of 30 hops:
  1     2 ms     1 ms     1 ms  192.168.1.1
  2    12 ms    11 ms     9 ms  10.20.30.40
  3     *        *        *     请求超时。
  4     8 ms     7 ms    <1 ms  93.184.216.34

Trace complete.
`

func Test解析windows的tracert(t *testing.T) {
	hops := parseNumberedHops(winTracert)
	if len(hops) != 4 {
		t.Fatalf("4 跳，解析出 %d：%+v", len(hops), hops)
	}
	// ★ `<1` 是亚毫秒的写法，不是坏数据；按 0.5 记，别把这一跳丢掉
	if hops[3].RTTMs[2] != 0.5 {
		t.Errorf("`<1 ms` 该记 0.5：%v", hops[3].RTTMs)
	}
	if hops[2].Addr != "" || hops[2].Lost != 3 {
		t.Errorf("超时行：%+v", hops[2])
	}
}

const linuxTracepath = `tracepath to 8.8.8.8:
 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1         	0.512ms
 2:  10.0.0.1            		 3.201ms
 8:  8.8.8.8             	55.581ms !
     Resume: 1
`

func Test解析tracepath(t *testing.T) {
	hops := parseTracepath(linuxTracepath)
	if len(hops) != 3 {
		t.Fatalf("3 跳（本机那条说明行不算数），解析出 %d：%+v", len(hops), hops)
	}
	if hops[0].Hop != 1 || hops[0].Addr != "192.168.1.1" {
		t.Errorf("本机那行 `1?: [LOCALHOST]` 把真正的第 1 跳冒充了：%+v", hops[0])
	}
	if hops[0].RTTMs[0] != 0.512 {
		t.Errorf("0.512ms：%v", hops[0].RTTMs)
	}
}

// tracepath 会把同一跳印两遍（banner + 正式行），合并后不能变两跳。
func Test同一跳印两遍要合并(t *testing.T) {
	hops := mergeHops([]traceHop{
		{Hop: 1, Lost: 1},
		{Hop: 1, Addr: "192.168.1.1", RTTMs: []float64{0.5}},
		{Hop: 2, Addr: "10.0.0.1"},
	})
	if len(hops) != 2 {
		t.Fatalf("合并成 %+v", hops)
	}
	if hops[0].Addr != "192.168.1.1" || hops[0].Lost != 1 || len(hops[0].RTTMs) != 1 {
		t.Errorf("合并把信息弄丢了：%+v", hops[0])
	}
}

func TestV6地址不被切坏(t *testing.T) {
	out := " 2  2001:db8::1  18.2 ms\n 3  fe80::1%eth0  1.2 ms\n"
	hops := parseNumberedHops(out)
	if len(hops) != 2 || hops[0].Addr != "2001:db8::1" {
		t.Fatalf("%+v", hops)
	}
	if hops[1].Addr != "fe80::1" {
		t.Errorf("带 %%eth0 的地址：%q", hops[1].Addr)
	}
}

// ---------- 判定：一族的跳表 → 码 ----------

func goalAddrs(t *testing.T, ss ...string) []netaddr.Addr {
	t.Helper()
	var out []netaddr.Addr
	for _, s := range ss {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, netaddr.Addr{IP: ip})
	}
	return out
}

func Test判定到没到终点(t *testing.T) {
	cases := []struct {
		name  string
		hops  []traceHop
		goals []string
		want  string
	}{
		{"有一跳就是目标，到了",
			[]traceHop{{Hop: 1, Addr: "1.1.1.1"}, {Hop: 2, Addr: "93.184.216.34"}},
			[]string{"93.184.216.34"}, traceReached},
		{"一个都没回：说不通路断没断",
			[]traceHop{{Hop: 1, Lost: 1}, {Hop: 2, Lost: 1}},
			[]string{"93.184.216.34"}, traceNoResponse},
		{"走到第 5 跳之后全黑：断在中间",
			[]traceHop{{Hop: 1, Addr: "1.1.1.1"}, {Hop: 5, Addr: "2.2.2.2"}, {Hop: 6, Lost: 1}},
			[]string{"93.184.216.34"}, traceStalled},
		{"一路都有回应，只是跳数用完",
			[]traceHop{{Hop: 29, Addr: "2.2.2.2"}, {Hop: 30, Addr: "3.3.3.3"}},
			[]string{"93.184.216.34"}, traceMaxHops},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := &traceFamily{Family: "ipv4"}
			judgeTrace(res, c.hops, c.goals, 30)
			if res.Code != c.want {
				t.Fatalf("判定 %q，期望 %q", res.Code, c.want)
			}
		})
	}
}

// 中途个别跳不回是常态：不能据此说断在那儿。
func Test中间丢两跳不算断(t *testing.T) {
	res := &traceFamily{Family: "ipv4"}
	judgeTrace(res, []traceHop{
		{Hop: 1, Addr: "192.168.1.1"}, {Hop: 2, Lost: 1}, {Hop: 3, Lost: 1},
		{Hop: 4, Addr: "10.0.0.1"}, {Hop: 5, Addr: "93.184.216.34"},
	}, []string{"93.184.216.34"}, 30)
	if res.Code != traceReached {
		t.Fatalf("走到了终点还该判 reached，判成 %q", res.Code)
	}
	if !res.Hops[4].IsGoal {
		t.Error("终点那一跳要标出来，界面靠它把最后一行分开画")
	}
	if res.HopsSeen != 5 {
		t.Errorf("最大跳号 %d", res.HopsSeen)
	}
}

// ★ 超时截断时不能说「跳数用完」：那会把人支使去调 maxHops，该调的是超时。
func Test被截断的不算跳数用完(t *testing.T) {
	res := &traceFamily{Family: "ipv4", Partial: true}
	judgeTrace(res, []traceHop{{Hop: 30, Addr: "2.2.2.2"}}, []string{"93.184.216.34"}, 30)
	if res.Code != traceTimedOut {
		t.Fatalf("判成 %q", res.Code)
	}
}

// ---------- 顶层：两族怎么合 ----------

func Test两族并排的顶层判定(t *testing.T) {
	cases := []struct {
		name string
		fs   []traceFamily
		want string
	}{
		{"都好", []traceFamily{{Code: traceReached}, {Code: traceReached}}, pathOK},
		{"v4 到、v6 断在半路",
			[]traceFamily{{Code: traceReached}, {Code: traceStalled}}, pathPartial},
		{"两族都没到",
			[]traceFamily{{Code: traceStalled}, {Code: traceNoRoute}}, pathBroken},
		{"两族都说不清（ICMP 全被限速）",
			[]traceFamily{{Code: traceNoResponse}, {Code: traceNoResponse}}, pathIncomplete},
		// ★ 跳数用完/说不清都**不是**「路断了」的证据：该做的动作是调大 maxHops，
		//   不是查路由器。报成 path-broken 就会把人支使去查一条没坏的路。
		{"v4 跳数用完、v6 确定没路",
			[]traceFamily{{Code: traceMaxHops}, {Code: traceNoRoute}}, pathBroken},
		{"v4 到了、v6 只是跳数用完",
			[]traceFamily{{Code: traceReached}, {Code: traceMaxHops}}, pathIncomplete},
		{"两族都跳数用完",
			[]traceFamily{{Code: traceMaxHops}, {Code: traceMaxHops}}, pathIncomplete},
		// ★ 这台机器缺 v6 的命令：结论只覆盖跑成的那族，不能报成「路是坏的」，
		//   也不能因为 v4 到了就报成「路是好的」。
		{"一族没跑成",
			[]traceFamily{{Code: traceStalled}, {Code: traceNoCommand}}, pathIncomplete},
		{"一族要 root",
			[]traceFamily{{Code: traceReached}, {Code: tracePrivileged}}, pathIncomplete},
		{"两族都没跑成",
			[]traceFamily{{Code: traceNoCommand}, {Code: traceNoCommand}}, traceNoCommand},
		{"只有一族（目标只有 A 记录）",
			[]traceFamily{{Code: traceNoRoute}}, traceNoRoute},
		{"只有一族且到了",
			[]traceFamily{{Code: traceReached}}, pathOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := topTraceCode(c.fs); got != c.want {
				t.Fatalf("顶层判定 %q，期望 %q", got, c.want)
			}
		})
	}
}

func Test备注只给码和事实(t *testing.T) {
	fs := []traceFamily{
		{Family: "ipv4", Code: traceStalled, HopsSeen: 6, LastAddr: "10.10.0.1"},
		{Family: "ipv6", Code: traceNoRoute},
	}
	n := traceNote(pathBroken, fs)
	if !strings.Contains(n, "ipv4=stalled hops=6 last=10.10.0.1") || !strings.Contains(n, "ipv6=no-route") {
		t.Fatalf("备注：%q", n)
	}
}

// ---------- 命令选择：三个平台的差异都在这 ----------

func Test各平台用哪条命令(t *testing.T) {
	cases := []struct {
		goos, family string
		want0        []string
	}{
		{"darwin", "v4", []string{"traceroute", "-n", "-m", "30", "-q", "1", "h"}},
		// ★ macOS 的 traceroute 不认 -6，v6 是另一个程序
		{"darwin", "v6", []string{"traceroute6", "-n", "-m", "30", "-q", "1", "h"}},
		{"linux", "v6", []string{"traceroute", "-n", "-m", "30", "-q", "1", "-6", "h"}},
		{"windows", "v4", []string{"tracert", "-d", "-4", "-h", "30", "-w", "1000", "h"}},
		{"windows", "v6", []string{"tracert", "-d", "-6", "-h", "30", "-w", "1000", "h"}},
	}
	for _, c := range cases {
		t.Run(c.goos+"/"+c.family, func(t *testing.T) {
			got := traceCommands(c.goos, c.family, 30, 1, "h")[0]
			if strings.Join(got, " ") != strings.Join(c.want0, " ") {
				t.Fatalf("命令 %q，期望 %q", strings.Join(got, " "), strings.Join(c.want0, " "))
			}
			for _, a := range got[:len(got)-1] {
				if a == c.goos {
					t.Fatal("参数里漏进了 GOOS")
				}
			}
		})
	}
}

// 非 darwin 的 v6 有 tracepath6 兜底；mac 上没装 traceroute 时退哪条不重要，
// 重要的是别退成一个不存在的 tracepath6。
func Test退路命令按族选(t *testing.T) {
	if got := traceCommands("linux", "v6", 30, 1, "h")[1][0]; got != "tracepath6" {
		t.Errorf("v6 退路是 %q", got)
	}
	if got := traceCommands("linux", "v4", 30, 1, "h")[1][0]; got != "tracepath" {
		t.Errorf("v4 退路是 %q", got)
	}
}

// ---------- 「本机没路」和「没权限」必须分开 ----------

func Test命令跑不起来分得开(t *testing.T) {
	cases := []struct{ text, want string }{
		{"traceroute to x: Destination Host Unreachable\nNo route to host", traceNoRoute},
		{"Network is unreachable", traceNoRoute},
		{"recvfrom: Operation not permitted", tracePrivileged},
		{"ERROR: receiving packet: Operation not permitted", tracePrivileged},
		{"Cannot assign requested address", traceNoRoute},
		{"some unknown garbage", ""},
	}
	for _, c := range cases {
		code, _ := classifyTraceRun(context.Background(), nil, c.text)
		if code != c.want {
			t.Errorf("%q → %q，期望 %q", c.text, code, c.want)
		}
	}
}

// 超时截断：ctx 到期且已经走出跳，得把跳带回来 + 判成 trace-timeout，
// 而不是把整条结果丢掉。
func Test超时把已走到的跳带回来(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond)
	code, detail := classifyTraceRun(ctx, nil, " 1  192.168.1.1  1 ms\n")
	if code != traceTimedOut {
		t.Fatalf("超时判成 %q（%s）", code, detail)
	}
}

// ---------- 真机：只在本机确实装了命令时跑 ----------

func skipWithoutTrace(t *testing.T) {
	t.Helper()
	for _, argv := range traceCommands(runtime.GOOS, "v4", 5, 1, "127.0.0.1") {
		if _, err := exec.LookPath(argv[0]); err == nil {
			return
		}
	}
	t.Skip("这台机器上没有可用的追踪命令")
}

func Test追本机(t *testing.T) {
	skipWithoutTrace(t)
	v := traceRun(t, map[string]any{"host": "127.0.0.1", "family": "v4", "maxHops": 3})
	fs := famOf(t, v)
	if len(fs) != 1 || fs[0].Family != "ipv4" {
		t.Fatalf("指定 v4 只该有一族：%+v", fs)
	}
	// 回环第一跳就是目标（或整条 * —— 有的系统不给回环发 ICMP 超时）
	switch fs[0].Code {
	case traceReached, traceNoResponse, traceStalled, traceMaxHops:
	default:
		t.Fatalf("回环判成 %q：%s", fs[0].Code, fs[0].Detail)
	}
	if fs[0].Command == "" {
		t.Error("要如实写用的是哪条命令")
	}
}

func Test指定v6但目标没v6记录(t *testing.T) {
	v := traceRun(t, map[string]any{"host": "127.0.0.1", "family": "v6"})
	if v.Code != tlsNameUnresolved {
		t.Fatalf("该如实说「没这一族的记录」，判成 %q", v.Code)
	}
	if !strings.Contains(v.Note, "v6") {
		t.Errorf("备注要点名 v6：%q", v.Note)
	}
}

func Test域名解析不出来(t *testing.T) {
	v := traceRun(t, map[string]any{"host": "no-such-host.invalid", "family": "v4"})
	if v.Code != tlsNameUnresolved {
		t.Fatalf("判成 %q", v.Code)
	}
}

// 超时很短：不能 hang，也不能报错 —— 已经走到的部分要回来。
func Test超时给部分结果不报错(t *testing.T) {
	skipWithoutTrace(t)
	v := traceRun(t, map[string]any{"host": "1.1.1.1", "family": "v4",
		"maxHops": 30, "timeoutMs": 2000})
	if v.Code == "" {
		t.Fatal("没判定")
	}
	fs := famOf(t, v)
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
}
