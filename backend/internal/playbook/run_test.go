package playbook

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fake 一个替身执行器：把每条命令的回话事先备好。
//
// 没有它就只能拿真机器测判定 —— 而「机器断了」「等超时了」这两格
// 在真机器上几乎复现不出来，正是最需要复现的。
type fake struct {
	out   map[string]Result
	errs  map[string]error
	calls []string
}

func (f *fake) Exec(ctx context.Context, cmd string, _ time.Duration) (Result, error) {
	f.calls = append(f.calls, cmd)
	if err := f.errs[cmd]; err != nil {
		// 真执行器在机器断了的时候会立刻回错；这里也照一样办。
		return Result{}, err
	}
	r := f.out[cmd]
	return r, nil
}

func ok(out string) Result { return Result{Stdout: out, ExitCode: 0} }

func step(name, run string) Step {
	return Step{Name: name, Run: run, Why: "问 " + name}
}

func Test全都问到_判定就是问到了(t *testing.T) {
	f := &fake{out: map[string]Result{"a": ok("A"), "b": ok("B")}, errs: map[string]error{}}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("一", "a"), step("二", "b")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Verdict != "playbook-ok" {
		t.Errorf("四条都问到了，判定却是 %q", r.Verdict)
	}
	if r.Counts.Ran != 2 || r.Counts.Total != 2 {
		t.Errorf("账记错了：%+v", r.Counts)
	}
	for i, s := range r.Steps {
		if s.Status != StatusRan || s.Output == "" {
			t.Errorf("第 %d 步：%+v", i+1, s)
		}
	}
	if len(f.calls) != 2 {
		t.Errorf("命令敲了 %d 下，应该 2 下", len(f.calls))
	}
}

// 同一问在不同系统上命令不同，所以并排写两条、各标各的系统。
// 不合系统的那条要安静跳过并接着跑 —— 不许因为一条不搭就把整本停住。
func Test系统不搭的那几条跳过去接着跑(t *testing.T) {
	linuxStep := step("看监听", "ss -ltn")
	winStep := step("看监听（Windows）", "netstat -ano")
	winStep.OS = []string{Windows}
	f := &fake{out: map[string]Result{"ss -ltn": ok("LISTEN")}, errs: map[string]error{}}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{winStep, linuxStep}}
	r := Run(context.Background(), p, Darwin, f.Exec)

	if r.Steps[0].Status != StatusSkippedPlatform {
		t.Errorf("Windows 那条在 darwin 上该跳，状态却是 %q", r.Steps[0].Status)
	}
	if r.Steps[1].Status != StatusRan {
		t.Errorf("被前一条带累了：%q", r.Steps[1].Status)
	}
	if len(f.calls) != 1 || f.calls[0] != "ss -ltn" {
		t.Errorf("跳过的那条不该敲命令，实际敲了 %v", f.calls)
	}
	if r.Counts.SkippedPlatform != 1 {
		t.Errorf("跳过的没记账：%+v", r.Counts)
	}
	// 跳掉一条但仍问到了别的 —— 这不算跑砸，但账上必须看得见少问了。
	if r.Verdict != "playbook-ok" {
		t.Errorf("还问到了别的，判定却是 %q", r.Verdict)
	}
	if !strings.Contains(r.VerdictNote, "跳过") {
		t.Errorf("判定那句话没提跳过的：%q", r.VerdictNote)
	}
}

// ★ 这一条是「没问到」和「问了没问题」的分界：
//
//	一本全是别的系统的剧本跑起来一步都没问，界面上说「一切正常」就是骗人。
func Test一条都问不出去时不能说一切正常(t *testing.T) {
	s := step("只有的", "dir")
	s.OS = []string{Windows}
	f := &fake{out: map[string]Result{}, errs: map[string]error{}}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{s}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Verdict != "playbook-platform-skipped" {
		t.Errorf("一条都没问却给了 %q", r.Verdict)
	}
	if n := r.VerdictNote; strings.Contains(n, "正常") || !strings.Contains(n, "没问到") {
		t.Errorf("那句话把「没问到」说成好话了：%q", n)
	}
	if len(f.calls) != 0 {
		t.Errorf("一条都没问出去，命令却敲了 %v", f.calls)
	}
}

func Test跑砸一条要落在判定里(t *testing.T) {
	f := &fake{
		out:  map[string]Result{"a": {Stdout: "", ExitCode: 3}, "b": ok("B")},
		errs: map[string]error{},
	}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("一", "a"), step("二", "b")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Verdict != "playbook-step-failed" {
		t.Errorf("有一条什么都没回，判定却是 %q", r.Verdict)
	}
	if r.Steps[0].Status != StatusFailed || r.Steps[0].ExitCode != 3 {
		t.Errorf("跑砸那步： %+v", r.Steps[0])
	}
	// 一条跑砸不停整本 —— 后面的照样问，砸的那条是线索不是终点。
	if r.Steps[1].Status != StatusRan {
		t.Errorf("后面的被停了：%q", r.Steps[1].Status)
	}
	if !strings.Contains(r.VerdictNote, "1 条") {
		t.Errorf("判定没说清砸了几条：%q", r.VerdictNote)
	}
}

// ★ systemctl is-active 在服务停着时回 "inactive" + 退出码 3，
//
//	这是答案不是故障。一律按退出码判砸的话，内置那本每次跑都「有步失败」，
//	人就看不上这个判定了。
func Test回了非零但把话说明白了就算问到(t *testing.T) {
	f := &fake{
		out:  map[string]Result{"is-active": {Stdout: "inactive\n", ExitCode: 3}},
		errs: map[string]error{},
	}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("服务在不在跑", "is-active")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Steps[0].Status != StatusRan {
		t.Errorf("命令照实回了话，却判成 %q", r.Steps[0].Status)
	}
	if r.Verdict != "playbook-ok" {
		t.Errorf("一条都问到了，判定却是 %q", r.Verdict)
	}
	if r.Steps[0].ExitCode != 3 || !strings.Contains(r.Steps[0].Note, "退出码 3") {
		t.Errorf("退出码没留在账上：%+v", r.Steps[0])
	}
}

// 机器断了：这一步之后全没法问。标成「没问到」而不是「跑砸」，
// 因为让人去改命令是白跑一趟 —— 该做的是重新连上去。
func Test机器断了后面几条标成没问到(t *testing.T) {
	f := &fake{
		out:  map[string]Result{"a": ok("A"), "b": ok("B"), "c": ok("C")},
		errs: map[string]error{"b": fmt.Errorf("ssh 会话没了: %w", ErrUnreachable)},
	}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("一", "a"), step("二", "b"), step("三", "c")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Verdict != "playbook-unreachable" {
		t.Errorf("机器断了判定却是 %q", r.Verdict)
	}
	if r.Steps[1].Status != StatusAborted || r.Steps[2].Status != StatusAborted {
		t.Errorf("断了之后的步没标成没问到：%q / %q", r.Steps[1].Status, r.Steps[2].Status)
	}
	if r.Steps[2].Error != "" {
		t.Errorf("没执行的那步编出了错话：%q", r.Steps[2].Error)
	}
	if len(f.calls) != 2 {
		t.Errorf("断了还接着敲：%v", f.calls)
	}
	if !strings.Contains(r.VerdictNote, "停在第 2 条（前面问到 1 条）") {
		t.Errorf("没说清问到哪儿：%q", r.VerdictNote)
	}
}

// 断线之前有按系统跳过的条时，那句「问到几条」不许把它们算进去 ——
// 跳过的条没问过那台机器，说成问到了就是把结论做得比证据多。
func Test断线那句不把跳过的条算成问到(t *testing.T) {
	win := step("windows 的那一问", "w")
	win.OS = []string{Windows}
	f := &fake{
		out:  map[string]Result{"a": ok("A"), "c": ok("C")},
		errs: map[string]error{"c": fmt.Errorf("ssh 会话没了: %w", ErrUnreachable)},
	}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("一", "a"), win, step("三", "c"), step("四", "d")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if !strings.Contains(r.VerdictNote, "前面问到 1 条") {
		t.Errorf("把跳过的那条算成问到了：%q", r.VerdictNote)
	}
	if !strings.Contains(r.VerdictNote, "停在第 3 条") {
		t.Errorf("停在第几条数错了（跳过的那条也占位置）：%q", r.VerdictNote)
	}
	if !strings.Contains(r.VerdictNote, "后面 2 条没问到") {
		t.Errorf("没问到的条数不对：%q", r.VerdictNote)
	}
	if strings.Contains(r.VerdictNote, "问到 2 条") {
		t.Errorf("跳过的条被算进「问到」：%q", r.VerdictNote)
	}
}

func Test等超时单独记账(t *testing.T) {
	slow := step("慢的一条", "sleep")
	slow.TimeoutSec = 1
	var calls []string
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{slow, step("二", "b")}}
	r := Run(context.Background(), p, Linux, func(ctx context.Context, cmd string, _ time.Duration) (Result, error) {
		calls = append(calls, cmd)
		if cmd == "sleep" {
			<-ctx.Done()
			return Result{}, ctx.Err()
		}
		return ok("B"), nil
	})

	if r.Steps[0].Status != StatusTimeout {
		t.Errorf("超时标成了 %q", r.Steps[0].Status)
	}
	if r.Counts.TimedOut != 1 {
		t.Errorf("超时没进账：%+v", r.Counts)
	}
	if r.Steps[0].Output != "" {
		t.Errorf("超时那步该只有超时那句，不该有半截输出：%q", r.Steps[0].Output)
	}
	if !strings.Contains(r.Steps[0].Error, "1 秒") {
		t.Errorf("超时没说等了多久：%q", r.Steps[0].Error)
	}
	// 超时只砸这一步，后面的照样问 —— 一条挂住的命令不该拖掉整本。
	if r.Steps[1].Status != StatusRan || len(calls) != 2 {
		t.Errorf("后面的步被超时带累了：%q / %v", r.Steps[1].Status, calls)
	}
	if r.Verdict != "playbook-step-failed" {
		t.Errorf("有步超时却判成 %q", r.Verdict)
	}
}

// ★ 关键词按全文数，显示才截断。反过来做的话，
//
//	「日志里那句丢帧」正好落在没显示的那半截里，界面就成了「没提到丢帧」。
func Test截断不吞命中(t *testing.T) {
	var lines []string
	for i := 0; i < MaxOutputLines+49; i++ {
		lines = append(lines, fmt.Sprintf("第 %d 行 一切如常", i))
	}
	// 命中那一行故意排在截断线之后：只按显示的那截数，它就消失了。
	lines = append(lines, "pool exhausted: frame pool too small")
	full := strings.Join(lines, "\n")

	s := step("日志", "journalctl")
	s.Marks = []Mark{{Match: `frame pool|pool exhausted`, Say: "帧池不够 —— 看解码服务的通道数是否超过许可"}}
	f := &fake{out: map[string]Result{"journalctl": ok(full)}, errs: map[string]error{}}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{s}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if len(r.Steps[0].Hits) != 1 {
		t.Fatalf("命中没数出来：%+v", r.Steps[0].Hits)
	}
	h := r.Steps[0].Hits[0]
	if h.Lines != 1 {
		t.Errorf("全文里明明有一行，数成 %d 行", h.Lines)
	}
	if h.Say == "" {
		t.Errorf("命中没带那句说明 —— 界面上就只是字变红")
	}
	if len(h.Sample) == 0 || !strings.Contains(h.Sample[0], "pool exhausted") {
		t.Errorf("命中没留原话：%v", h.Sample)
	}
	if r.Steps[0].Truncated <= 0 {
		t.Errorf("输出没截断（截断了才要留话）：%d", r.Steps[0].Truncated)
	}
	if !strings.Contains(r.Steps[0].Note, fmt.Sprintf("还有 %d 行没显示", r.Steps[0].Truncated)) {
		t.Errorf("截断没留话：%q", r.Steps[0].Note)
	}
	if !strings.Contains(r.Steps[0].Note, "关键词按全文数的") {
		t.Errorf("截断那句没交代计数口径：%q", r.Steps[0].Note)
	}
	// 开头那一截要留着，命中的那一行也得露出来 ——
	// 只把命中放进 Sample、输出里看不到原话，人还得再问一遍「它到底怎么写的」。
	if !strings.Contains(r.Steps[0].Output, "第 1 行") {
		t.Errorf("输出被截没了开头：%q", r.Steps[0].Output)
	}
	if !strings.Contains(r.Steps[0].Output, "pool exhausted") {
		t.Errorf("命中那行落在没显示的那截里，就再也不露脸了")
	}
	if r.Steps[0].Truncated != 50 {
		t.Errorf("少说了没显示的行数：%d", r.Steps[0].Truncated)
	}
}

func Test没命令的剧本说没得问(t *testing.T) {
	f := &fake{out: map[string]Result{}, errs: map[string]error{}}
	for _, p := range []*Playbook{nil, {ID: "x", Name: "n"}} {
		r := Run(context.Background(), p, Linux, f.Exec)
		if r.Verdict != "playbook-empty" {
			t.Errorf("空剧本判成了 %q", r.Verdict)
		}
		if !strings.Contains(r.VerdictNote, "一步都没") {
			t.Errorf("空剧本那句话没说清：%q", r.VerdictNote)
		}
	}
}

// ★ 判定只从那几个数里推出来。把这段和上面的 counts 分开写就等于
//
//	允许有人以后拿另一个来源算判定，界面出现「账上有砸的、判定却一切正常」。
func Test给定几个数判定只能有一个(t *testing.T) {
	cases := []struct {
		what string
		c    Counts
		want string
	}{
		{"都问到了", Counts{Total: 3, Ran: 3}, "playbook-ok"},
		{"问到但跳了几条", Counts{Total: 5, Ran: 3, SkippedPlatform: 2}, "playbook-ok"},
		{"一条没问到", Counts{Total: 2, SkippedPlatform: 2}, "playbook-platform-skipped"},
		{"有砸的", Counts{Total: 3, Ran: 2, Failed: 1}, "playbook-step-failed"},
		{"有超时的", Counts{Total: 3, Ran: 2, TimedOut: 1}, "playbook-step-failed"},
		{"机器断了", Counts{Total: 9, Ran: 2, Aborted: 7}, "playbook-unreachable"},
		{"零条", Counts{}, "playbook-empty"},
	}
	for _, c := range cases {
		if got := verdictOf(c.c); got != c.want {
			t.Errorf("%s：%q 该判 %q，实际 %q", c.what, c.what, c.want, got)
		}
	}
}

func Test带旗子的条数要单独记(t *testing.T) {
	w := step("重启服务", "systemctl restart x")
	w.Write = true
	f := &fake{out: map[string]Result{"uptime": ok("up"), "systemctl restart x": ok("ok")}, errs: map[string]error{}}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("看活了多久", "uptime"), w}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Counts.WriteRan != 1 {
		t.Errorf("会改东西的那条没进账：%+v", r.Counts)
	}
	if !r.Steps[1].Write || r.Steps[0].Write {
		t.Errorf("旗子传丢了：%+v / %+v", r.Steps[0], r.Steps[1])
	}
}

func Test每步都留下命令和耗时(t *testing.T) {
	f := &fake{out: map[string]Result{"uptime": ok("up")}, errs: map[string]error{}}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("看活了多久", "uptime")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if got := r.Steps[0]; got.Command != "uptime" || got.Name != "看活了多久" || got.Why == "" {
		t.Errorf("这一步的账缺项：%+v", got)
	}
	if r.Goos != Linux || r.PlaybookID != "x" || r.PlaybookName != "n" {
		t.Errorf("抬头缺项：%+v", r)
	}
}

func Test执行器报错但不算断线也算砸(t *testing.T) {
	f := &fake{
		out:  map[string]Result{},
		errs: map[string]error{"a": errors.New("permission denied")},
	}
	p := &Playbook{ID: "x", Name: "n", Steps: []Step{step("一", "a")}}
	r := Run(context.Background(), p, Linux, f.Exec)

	if r.Steps[0].Status != StatusFailed {
		t.Errorf("回错了却标成 %q", r.Steps[0].Status)
	}
	if !strings.Contains(r.Steps[0].Error, "permission denied") {
		t.Errorf("把错话丢了：%q", r.Steps[0].Error)
	}
	if r.Verdict != "playbook-step-failed" {
		t.Errorf("判定 %q", r.Verdict)
	}
}
