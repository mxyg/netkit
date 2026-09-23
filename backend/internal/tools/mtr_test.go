package tools

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

func mtrReport(t *testing.T, v ots.Verdict) []mtrFamily {
	t.Helper()
	raw, err := json.Marshal(v.Values["reports"])
	if err != nil {
		t.Fatalf("reports 序列化不了：%v", err)
	}
	var fs []mtrFamily
	if err := json.Unmarshal(raw, &fs); err != nil {
		t.Fatalf("reports 反序列化不了：%v", err)
	}
	return fs
}

func mtrRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doMtr(context.Background(), b)
	if err != nil {
		t.Fatalf("mtr(%v) 报错：%v", args, err)
	}
	out, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("mtr 没返回判定，返回 %T", v)
	}
	return out
}

func TestMtr目标写法(t *testing.T) {
	for _, host := range []string{"-f", "--report-wide", "a b", ""} {
		b, _ := json.Marshal(map[string]any{"host": host})
		if _, err := doMtr(context.Background(), b); err == nil {
			t.Errorf("%q 该被拒：它会被当成外部命令的选项", host)
		}
	}
}

// hop(n, snt, lost, avg) 造一跳。
func qhop(n int, snt, lost int, avg float64, addrs ...string) mtrHop {
	h := mtrHop{Hop: n, Snt: snt, Lost: lost, Rounds: 1}
	if len(addrs) > 0 {
		h.Addr = addrs[0]
		h.Addrs = addrs
	}
	if snt > 0 {
		h.LossPct = float64(lost) / float64(snt) * 100
	}
	h.AvgMs, h.BestMs, h.WorstMs = avg, avg, avg
	return h
}

// ★★ 这一组是这一栏的核心：同样一行「中段 80% 丢包」，下游收得到就是没事，
// 下游也丢就是拥塞点。只看单跳丢包率做判定，就会让人去查一台正常工作的路由器。
func TestMtr丢包是不是真的(t *testing.T) {
	cases := []struct {
		name string
		hops []mtrHop
		goal bool
		want string
	}{
		{"都不丢", []mtrHop{qhop(1, 20, 0, 3), qhop(2, 20, 0, 8, "9.9.9.9")}, true, qualityOK},
		{"中段丢、终点全收到 = 那台不爱回话，不是故障",
			[]mtrHop{qhop(1, 20, 0, 3), qhop(2, 20, 16, 40), qhop(3, 20, 0, 9, "9.9.9.9")}, true, qualitySilent},
		{"从第 2 跳起一路丢到终点 = 真拥塞点",
			[]mtrHop{qhop(1, 20, 0, 3), qhop(2, 20, 16, 40), qhop(3, 20, 15, 45, "9.9.9.9")}, true, qualityLoss},
		{"只有终点丢 = 路是通的，是终点不吭声",
			[]mtrHop{qhop(1, 20, 0, 3), qhop(2, 20, 0, 8), qhop(3, 20, 6, 30, "9.9.9.9")}, true, qualityTargetLoss},
		{"只丢一发不算丢（样本少的时候一发是常态）",
			[]mtrHop{qhop(1, 8, 0, 3), qhop(2, 8, 1, 30, "9.9.9.9")}, true, qualityOK},
		{"样本太少不给丢包结论",
			[]mtrHop{qhop(1, 2, 2, 3), qhop(2, 2, 2, 30, "9.9.9.9")}, true, qualityNoResponse},
		{"一次都没走到终点、可测的跳不丢 = 说不清",
			[]mtrHop{qhop(1, 20, 0, 3), qhop(2, 20, 0, 8)}, false, qualityNoResponse},
		{"同一跳见过两个地址 = 路径在翻动",
			[]mtrHop{qhop(1, 20, 0, 3), qhop(2, 20, 0, 8, "a.example", "b.example")}, true, qualityPathMoved},
		{"真丢包优先于路径翻动",
			[]mtrHop{qhop(1, 20, 0, 3, "x", "y"), qhop(2, 20, 18, 40), qhop(3, 20, 16, 55, "9.9.9.9")}, true, qualityLoss},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hops := append([]mtrHop{}, c.hops...)
			if c.goal {
				hops[len(hops)-1].IsGoal = true // 真流水线里由 buildHops 按地址比对标上
			}
			res := &mtrFamily{Family: "ipv4", Hops: hops, GoalSeen: c.goal, Rounds: 1, RoundsDone: 1}
			judgeMtr(res)
			if res.Code != c.want {
				t.Fatalf("判定 %q，期望 %q", res.Code, c.want)
			}
		})
	}
}

// 拥塞点要点名到跳号：只说「有丢包」等于让人自己再去表里找一遍。
func TestMtr点名拥塞点(t *testing.T) {
	res := &mtrFamily{Family: "ipv4", Rounds: 1, RoundsDone: 1, Hops: []mtrHop{
		qhop(1, 20, 0, 3), qhop(2, 20, 0, 5), qhop(3, 20, 14, 60), qhop(4, 20, 12, 70, "9.9.9.9")}}
	judgeMtr(res)
	if res.Code != qualityLoss {
		t.Fatalf("判定 %q", res.Code)
	}
	if res.StartHop != 3 {
		t.Fatalf("拥塞点该在第 3 跳之前，报成 %d", res.StartHop)
	}
	if res.Hops[2].Flag != flagSource {
		t.Errorf("起点那跳的注记是 %q", res.Hops[2].Flag)
	}
	if res.Hops[3].Flag != flagSource {
		t.Errorf("一路延续的跳也要标出来（第 4 跳：%q）", res.Hops[3].Flag)
	}
}

// 抬升：比上一跳慢 30ms 以上、且**到了终点还这么慢**才算。
func TestMtr往返抬升从哪跳开始(t *testing.T) {
	cases := []struct {
		name string
		hops []mtrHop
		want string
	}{
		{"第 3 跳起慢 80ms 并延续到终点",
			[]mtrHop{qhop(1, 20, 0, 4), qhop(2, 20, 0, 6), qhop(3, 20, 0, 90), qhop(4, 20, 0, 95, "9.9.9.9")}, qualityLatency},
		// 只有一跳慢、下一跳回到原样：是那台设备的 ICMP 优先级低，不是链路慢了
		{"中间一跳慢但后面 recovered，不算",
			[]mtrHop{qhop(1, 20, 0, 4), qhop(2, 20, 0, 90), qhop(3, 20, 0, 8, "9.9.9.9")}, qualityOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := &mtrFamily{Family: "ipv4", Hops: c.hops, GoalSeen: true, Rounds: 1, RoundsDone: 1}
			judgeMtr(res)
			if res.Code != c.want {
				t.Fatalf("判定 %q，期望 %q", res.Code, c.want)
			}
		})
	}
	res := &mtrFamily{Family: "ipv4", GoalSeen: true, Rounds: 1, RoundsDone: 1, Hops: []mtrHop{
		qhop(1, 20, 0, 4), qhop(2, 20, 0, 6), qhop(3, 20, 0, 90), qhop(4, 20, 0, 95, "9.9.9.9")}}
	judgeMtr(res)
	if res.SlowHop != 3 {
		t.Errorf("抬升起点该是第 3 跳，报成 %d", res.SlowHop)
	}
}

// ---------- 聚合：分母不许虚高 ----------

func TestMtr分母只算问过的轮(t *testing.T) {
	aggs := map[int]*hopAgg{}
	// 第 1 轮走到第 3 跳；第 2 轮在第 2 跳就断了 —— 第 3 跳在第二轮**根本没被问过**
	absorbRound(aggs, traceFamily{Hops: []traceHop{
		{Hop: 1, Addr: "1.1.1.1", RTTMs: []float64{2}},
		{Hop: 2, Addr: "2.2.2.2", RTTMs: []float64{5}},
		{Hop: 3, Addr: "3.3.3.3", RTTMs: []float64{9}},
	}}, []string{"9.9.9.9"})
	absorbRound(aggs, traceFamily{Hops: []traceHop{
		{Hop: 1, Addr: "1.1.1.1", RTTMs: []float64{2}},
		{Hop: 2, Lost: 1},
	}}, []string{"9.9.9.9"})
	res := &mtrFamily{Family: "ipv4", Rounds: 2, RoundsDone: 2}
	buildHops(res, aggs, []string{"9.9.9.9"})
	if len(res.Hops) != 3 {
		t.Fatalf("%+v", res.Hops)
	}
	// ★ 第 3 跳：2 轮里只被印出 1 次，分母是 1 不是 2 —— 虚高的丢包率会让人去查一条没走过的路
	if res.Hops[2].Rounds != 1 || res.Hops[2].Snt != 1 || res.Hops[2].Lost != 0 {
		t.Errorf("第 3 跳统计被编出来了：%+v", res.Hops[2])
	}
	if res.Hops[1].Snt != 2 || res.Hops[1].Lost != 1 {
		t.Errorf("第 2 跳： %+v", res.Hops[1])
	}
}

// 终点那一跳不一样：某一轮压根没印出它，就是那一轮没走到终点，算丢。
func TestMtr没走到终点算终点的丢(t *testing.T) {
	aggs := map[int]*hopAgg{}
	absorbRound(aggs, traceFamily{Hops: []traceHop{
		{Hop: 1, Addr: "1.1.1.1", RTTMs: []float64{2}},
		{Hop: 2, Addr: "9.9.9.9", RTTMs: []float64{9, 9, 9}},
	}}, []string{"9.9.9.9"})
	absorbRound(aggs, traceFamily{Hops: []traceHop{
		{Hop: 1, Addr: "1.1.1.1", RTTMs: []float64{2}},
	}}, []string{"9.9.9.9"})
	res := &mtrFamily{Family: "ipv4", Rounds: 2, RoundsDone: 2}
	buildHops(res, aggs, []string{"9.9.9.9"})
	goal := res.Hops[1]
	if !goal.IsGoal {
		t.Fatal("终点没标出来")
	}
	// 第二轮没印到第 2 跳：按它自己的历史（一轮 3 个探测）补成丢了 3 发
	if goal.Snt != 6 || goal.Lost != 3 {
		t.Errorf("终点分母/丢包 = %d/%d，期望 6/3", goal.Snt, goal.Lost)
	}
	if !res.GoalSeen {
		t.Error("走到过一次就该记 goalSeen")
	}
}

// 同一跳换了地址：要留成两个地址，不能只报「最后一个」把翻动藏起来。
func TestMtr同一跳多个地址(t *testing.T) {
	aggs := map[int]*hopAgg{}
	for _, a := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.1"} {
		absorbRound(aggs, traceFamily{Hops: []traceHop{{Hop: 2, Addr: a, RTTMs: []float64{5}}}}, nil)
	}
	res := &mtrFamily{Family: "ipv4", Rounds: 3, RoundsDone: 3}
	buildHops(res, aggs, nil)
	h := res.Hops[0]
	if h.Addr != "10.0.0.1" {
		t.Errorf("主地址该是见得最多的那个：%q", h.Addr)
	}
	if len(h.Addrs) != 2 {
		t.Errorf("两个地址都得留着：%v", h.Addrs)
	}
}

// ---------- mtr 命令与 JSON 解析 ----------

func TestMtr命令按族选(t *testing.T) {
	v4 := strings.Join(mtrCommands("v4", 24, 30, "h"), " ")
	if !strings.Contains(v4, "--json") || !strings.Contains(v4, "-4") || !strings.Contains(v4, "-c 24") {
		t.Errorf("v4 命令：%s", v4)
	}
	v6 := strings.Join(mtrCommands("v6", 8, 30, "h"), " ")
	if !strings.Contains(v6, "-6") {
		t.Error("v6 命令没带 -6")
	}
}

// mtr 的真实 JSON 报告形状（--json）：每跳一条，带 sent/rcv/loss/best/avg/worst 和 IPs 数组。
const mtrJSON = `{"report":{"mtr":{"host":"local","src":"192.168.1.5","dst":"9.9.9.9","psize":"64","reflected":24,"max_ttl":4},
"report":[
 {"tier":1,"loss":0.0,"rcv":24,"sent":24,"best":1.9,"last":2.2,"avg":2.4,"worst":4.1,"stddev":0.3,"IPs":["192.168.0.1"],"name":"192.168.0.1"},
 {"tier":2,"loss":25.0,"rcv":18,"sent":24,"best":8.1,"last":9.9,"avg":9.5,"worst":22.4,"stddev":1.2,"IPs":["10.45.0.1"],"name":"10.45.0.1"},
 {"tier":3,"loss":100.0,"rcv":0,"sent":24,"best":0.0,"last":0.0,"avg":0.0,"worst":0.0,"stddev":0.0,"IPs":[],"name":"???"},
 {"tier":4,"loss":4.2,"rcv":23,"sent":24,"best":31.2,"last":33.0,"avg":33.6,"worst":41.0,"stddev":1.9,"IPs":["9.9.9.9"],"name":"9.9.9.9"}
]}}`

func Test解析mtr的JSON报告(t *testing.T) {
	hops, ok := parseMtrJSON(mtrJSON)
	if !ok {
		t.Fatal("mtr 的标准形状解析不出来")
	}
	if len(hops) != 4 {
		t.Fatalf("4 跳，解析出 %d：%+v", len(hops), hops)
	}
	if hops[1].Snt != 24 || hops[1].Lost != 6 || hops[1].LossPct != 25 {
		t.Errorf("第 2 跳统计错了：%+v", hops[1])
	}
	if hops[1].Addr != "10.45.0.1" || hops[1].BestMs != 8.1 || hops[1].WorstMs != 22.4 {
		t.Errorf("第 2 跳：%+v", hops[1])
	}
	// ★ 全丢的那跳一个地址都没有：不许编一个地址出来，留空让界面写「没回」
	if hops[2].Addr != "" || hops[2].Lost != 24 {
		t.Errorf("全丢的一跳：%+v", hops[2])
	}
	if hops[3].AvgMs != 33.6 || hops[3].LastMs != 33 || hops[3].Spread != 9.8 {
		t.Errorf("终点那跳：%+v", hops[3])
	}
}

// 同一跳被拆成多条（等价路径各一条）：按探测数加权合并，不是取最后一条。
func Test解析mtr同一跳多条(t *testing.T) {
	const doc = `{"report":{"report":[
	 {"tier":1,"rcv":10,"sent":10,"avg":2.0,"best":1.0,"worst":3.0,"last":2.0,"IPs":["10.0.0.1"]},
	 {"tier":1,"rcv":30,"sent":30,"avg":8.0,"best":4.0,"worst":9.0,"last":8.0,"IPs":["10.0.0.2"]},
	 {"tier":2,"rcv":40,"sent":40,"avg":20.0,"best":19.0,"worst":21.0,"last":20.0,"IPs":["9.9.9.9"]}
	]}}`
	hops, ok := parseMtrJSON(doc)
	if !ok {
		t.Fatal("解析不出来")
	}
	if hops[0].Snt != 40 {
		t.Fatalf("分母该是 40：%+v", hops[0])
	}
	// (2*10 + 8*30) / 40 = 6.5
	if hops[0].AvgMs != 6.5 {
		t.Errorf("加权平均 %v，期望 6.5", hops[0].AvgMs)
	}
	if hops[0].BestMs != 1 || hops[0].WorstMs != 9 {
		t.Errorf("最好/最差取两端：%+v", hops[0])
	}
	if len(hops[0].Addrs) != 2 {
		t.Errorf("等价路径的两个地址都要留着：%v", hops[0].Addrs)
	}
}

// 按轮分组的嵌套形状也认；拿不到分母的形状一律退回多轮 traceroute，不硬编。
func Test解析mtr的其他形状(t *testing.T) {
	nested := `{"report":{"report":[[{"tier":1,"rcv":4,"sent":4,"avg":3.0,"IPs":["1.1.1.1"]}],
		[{"tier":2,"rcv":4,"sent":4,"avg":9.0,"IPs":["9.9.9.9"]}]]}}`
	hops, ok := parseMtrJSON(nested)
	if !ok || len(hops) != 2 {
		t.Fatalf("嵌套形状没认出来：%v %+v", ok, hops)
	}
	for _, bad := range []string{"", "not json", `{"report":{"report":[]}}`,
		// 没有 sent：拿不到分母就当不认识
		`{"report":{"report":[{"tier":1,"loss":0.0,"IPs":["1.1.1.1"]}]}}`} {
		if _, ok := parseMtrJSON(bad); ok {
			t.Errorf("这形状该退回多轮 traceroute，却认了：%s", bad)
		}
	}
}

// ---------- 两族并排的顶层 ----------

func TestMtr顶层判定(t *testing.T) {
	cases := []struct {
		name string
		fs   []mtrFamily
		want string
	}{
		{"都好", []mtrFamily{{Code: qualityOK}, {Code: qualityOK}}, qualityOK},
		{"v4 好、v6 真丢包", []mtrFamily{{Code: qualityOK}, {Code: qualityLoss}}, qualityLoss},
		{"v4 沉默丢包、v6 只是路径翻动", []mtrFamily{{Code: qualitySilent}, {Code: qualityPathMoved}}, qualitySilent},
		{"v4 到、v6 本机没路", []mtrFamily{{Code: qualityOK}, {Code: traceNoRoute}}, traceNoRoute},
		// ★ 缺命令的那族不算「坏了」，也不算「好了」：结论只覆盖跑成的那族
		{"一族没跑成", []mtrFamily{{Code: qualityOK}, {Code: traceNoCommand}}, pathIncomplete},
		{"两族都没跑成", []mtrFamily{{Code: traceNoCommand}, {Code: tracePrivileged}}, traceNoCommand},
		{"只有一族", []mtrFamily{{Code: qualitySilent}}, qualitySilent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := topMtrCode(c.fs); got != c.want {
				t.Fatalf("顶层判定 %q，期望 %q", got, c.want)
			}
		})
	}
}

func TestMtr备注只给码和事实(t *testing.T) {
	fs := []mtrFamily{{Family: "ipv4", Code: qualityLoss, RoundsDone: 6, Rounds: 8, StartHop: 3, Engine: "mtr"}}
	n := mtrNote(qualityLoss, fs)
	if !strings.Contains(n, "rounds=6/8") || !strings.Contains(n, "lossFromHop=3") || !strings.Contains(n, "engine=mtr") {
		t.Fatalf("备注：%q", n)
	}
}

// ---------- 真机：装了命令就真跑一遍 ----------

func TestMtr真跑本机(t *testing.T) {
	if _, err := exec.LookPath("traceroute"); err != nil {
		t.Skip("这台机器上没有 traceroute，跑不了")
	}
	v := mtrRun(t, map[string]any{"host": "127.0.0.1", "family": "v4",
		"rounds": 2, "perHop": 2, "maxHops": 3, "timeoutMs": 15000})
	fs := mtrReport(t, v)
	if len(fs) != 1 || fs[0].Family != "ipv4" {
		t.Fatalf("指定 v4 只该有一族：%+v", fs)
	}
	if fs[0].Engine == "" {
		t.Error("要如实写用的哪个引擎")
	}
	switch fs[0].Code {
	case qualityOK, qualitySilent, qualityPathMoved, qualityLatency,
		qualityTargetLoss, qualityLoss, qualityNoResponse, traceNoRoute,
		traceNoCommand, tracePrivileged, traceTimedOut:
	default:
		t.Fatalf("回环判成没定义过的码 %q", fs[0].Code)
	}
}

func TestMtr指定v6但目标没v6记录(t *testing.T) {
	v := mtrRun(t, map[string]any{"host": "127.0.0.1", "family": "v6"})
	if v.Code != tlsNameUnresolved {
		t.Fatalf("该如实说没这一族记录，判成 %q", v.Code)
	}
}
