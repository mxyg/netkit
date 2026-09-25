package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/playbook"
	"net.yuhox.com/netkit/internal/remote"
)

// fakeDeviceExec 一个替身：把每条命令的回话事先备好。
// 有了它，「哪几条算问到」「输出里不能带口令」这两条不接真机器也验得了。
type fakeDeviceExec struct {
	out   map[string]*remote.Output
	errs  map[string]error
	calls []string
	waits []time.Duration
}

func (f *fakeDeviceExec) run(ctx context.Context, command string, wait time.Duration) (playbook.Result, error) {
	f.calls = append(f.calls, command)
	f.waits = append(f.waits, wait)
	if err := f.errs[command]; err != nil {
		return playbook.Result{}, err
	}
	o := f.out[command]
	if o == nil {
		return playbook.Result{}, nil
	}
	return playbook.Result{Stdout: o.Stdout, Stderr: o.Stderr, ExitCode: o.ExitCode}, nil
}

func newBook(steps ...playbook.Step) *playbook.Playbook {
	return &playbook.Playbook{ID: "test-book", Name: "测试那本", Steps: steps}
}

func bookStep(name, run string) playbook.Step {
	return playbook.Step{Name: name, Run: run, Why: "问 " + name}
}

func Test列剧本把几条会改东西说清楚(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	raw, _ := json.Marshal(map[string]any{})
	out, err := remotePlaybookListTool.Invoke(context.Background(), raw)
	if err != nil {
		t.Fatalf("列剧本失败：%v", err)
	}
	v := out.(ots.Verdict)
	entries, _ := v.Values["playbooks"].([]map[string]any)
	if len(entries) == 0 {
		t.Fatalf("一本剧本都没列出来")
	}
	var box map[string]any
	for _, e := range entries {
		if e["id"] == playbook.BuiltinBoxCheck {
			box = e
		}
	}
	if box == nil {
		t.Fatalf("内置那本 %s 没在清单里", playbook.BuiltinBoxCheck)
	}
	if box["builtIn"] != true {
		t.Errorf("内置那本没标成内置：%v", box["builtIn"])
	}
	if n, _ := box["writeSteps"].(int); n == 0 {
		t.Errorf("批准屏要念「几条会改东西」，清单里却没数出来：%v", box["writeSteps"])
	}
	stepCount, _ := box["stepCount"].(int)
	if stepCount == 0 {
		t.Errorf("步数没报：%v", box["stepCount"])
	}
	if steps, _ := box["steps"].([]map[string]any); len(steps) != stepCount {
		t.Errorf("报了 %d 条，steps 里却有 %d 条 —— 批准屏会少念几条", stepCount, len(steps))
	}
	if dir, _ := v.Values["storeDir"].(string); dir == "" {
		t.Errorf("没说剧本存在哪儿 —— 人没法备份、没法发给同事")
	}
}

func Test给了设备就按那台的系统数问得出去几条(t *testing.T) {
	dir := t.TempDir()
	SetPlaybook(playbook.NewStore(t.TempDir()))
	m, err := remote.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	SetRemote(m)
	t.Cleanup(func() { SetRemote(nil); SetPlaybook(nil) })

	d, err := m.AddDevice(remote.Device{Host: "10.0.0.9", User: "ops", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	d.OS = "windows"
	if err := m.UpdateDevice(d); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(map[string]any{"device": d.ID})
	v := callList(t, raw)
	entries, _ := v.Values["playbooks"].([]map[string]any)
	for _, e := range entries {
		if e["id"] != playbook.BuiltinBoxCheck {
			continue
		}
		steps, _ := e["steps"].([]map[string]any)
		if len(steps) == 0 {
			t.Fatalf("内置那本一步都没列出来")
		}
		// ★ 总数必须等于逐条数出来的：批准屏上一处报数、一处列表，
		//	两边各算一次就会差一条给少念一条。
		tallied, sawWindowsVariant, sawLinux := 0, 0, 0
		for _, st := range steps {
			if on, _ := st["appliesToDevice"].(bool); on {
				tallied++
			}
			os, _ := st["os"].([]string)
			for _, o := range os {
				switch o {
				case "windows":
					sawWindowsVariant++
				case "linux":
					sawLinux++
				}
			}
		}
		if n, _ := e["appliesOnDevice"].(int); n != tallied {
			t.Errorf("这本在 Windows 上报了 %d 条问得出去，逐条数出来 %d 条", n, tallied)
		}
		if tallied == 0 {
			t.Errorf("Windows 设备上一条都问不出去 —— 内置那本该有 Windows 变体")
		}
		if sawWindowsVariant == 0 || sawLinux == 0 {
			t.Errorf("内置那本没把两种系统的问法并排写全：windows 变体 %d 条、linux 条 %d 条", sawWindowsVariant, sawLinux)
		}
		return
	}
	t.Fatalf("没找到内置那本")
}

func callList(t *testing.T, raw json.RawMessage) ots.Verdict {
	t.Helper()
	out, err := remotePlaybookListTool.Invoke(context.Background(), raw)
	if err != nil {
		t.Fatalf("列剧本失败：%v", err)
	}
	return out.(ots.Verdict)
}

// ★ 批准屏上那段话是唯一一次「人看到将要敲什么」的机会。
// 只写「要跑一本剧本」等于没让人批准。
func Test批准那段话把命令一条条念出来(t *testing.T) {
	dir := t.TempDir()
	st := playbook.NewStore(dir)
	SetPlaybook(st)
	t.Cleanup(func() { SetPlaybook(nil) })
	linuxOnly := bookStep("只看 Linux 的那条", "ss -ltn")
	linuxOnly.OS = []string{"linux"}
	book := newBook(
		bookStep("看活了多久", "uptime"),
		playbook.Step{Name: "重启服务", Run: "systemctl restart x", Why: "改状态", Write: true},
		linuxOnly,
	)
	if bad := playbook.Validate(book); len(bad) > 0 {
		t.Fatalf("测试用的剧本不合式：%v", bad)
	}
	if err := st.Save(*book, false); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(map[string]any{"device": "ops@10.0.0.9", "playbook": "test-book"})
	d := remotePlaybookRunTool.Describe(raw)
	for _, want := range []string{"uptime", "systemctl restart x", "★会改东西", "[linux]", "1 条会改"} {
		if !strings.Contains(d, want) {
			t.Errorf("批准那段话里没念到 %q：%s", want, d)
		}
	}
	missing := remotePlaybookRunTool.Describe(json.RawMessage(`{"device":"x","playbook":"没这本"}`))
	if !strings.Contains(missing, "没这本") {
		t.Errorf("剧本不存在时批准屏该说命令列不出来：%s", missing)
	}
}

func Test没探过系统的设备不给跑剧本(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	m, err := remote.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	SetRemote(m)
	t.Cleanup(func() { SetRemote(nil); SetPlaybook(nil) })

	if _, err := m.AddDevice(remote.Device{Host: "127.0.0.1", User: "ops", Password: "x"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"device": "ops@127.0.0.1", "playbook": playbook.BuiltinBoxCheck})
	_, err = remotePlaybookRunTool.Invoke(context.Background(), raw)
	if err == nil {
		t.Fatalf("系统还不知道就放行了 —— 那些分系统的条会被判成「没问到」，理由还是猜的")
	}
	if !strings.Contains(err.Error(), "probe") {
		t.Errorf("没说先跑 probe：%v", err)
	}
}

func Test剧本不存在时说清去哪儿看有哪些本(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	m, err := remote.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	SetRemote(m)
	t.Cleanup(func() { SetPlaybook(nil); SetRemote(nil) })
	// 设备要先登记好、系统要探过 —— 不然先撞上的是那道拦子，看不到这一条
	if _, err := m.AddDevice(remote.Device{Host: "h", User: "ops", Password: "x", OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"device": "ops@h", "playbook": "nope"})
	if _, err := remotePlaybookRunTool.Invoke(context.Background(), raw); err == nil ||
		!strings.Contains(err.Error(), "remote.playbook.list") {
		t.Errorf("错误没说怎么列出有哪些本：%v", err)
	}
}

// fakeSSH 顶上 remote.SSHExecer：让 execOnDevice 这一段（断线判断、审计、
// 超时归类）不接真机器也跑得起来。
type fakeSSH struct {
	out  map[string]*remote.Output
	errs map[string]error
}

func (f *fakeSSH) Exec(ctx context.Context, d *remote.Device, cmd string, t time.Duration) (*remote.Output, error) {
	if err := f.errs[cmd]; err != nil {
		return nil, err
	}
	return f.out[cmd], nil
}

func useMgr(t *testing.T) *remote.Manager {
	t.Helper()
	m, err := remote.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	SetRemote(m)
	t.Cleanup(func() { SetRemote(nil) })
	return m
}

// ★ 结果会发给 AI、也可能被打进诊断包 —— 剧本里那些 cat 配置、journalctl
// 正是最容易把口令带回来的命令。审计文件是给二线看的，同理。
func Test带回来的结果里没有凭据(t *testing.T) {
	useMgr(t)
	x := &fakeSSH{
		out: map[string]*remote.Output{
			"cat /etc/x.conf": {Stdout: "server 1.2.3.4\npassword: hunter2\n"},
		},
	}
	d := &remote.Device{ID: "ops@h"}
	rep := runPlaybook(context.Background(), newBook(bookStep("看配置", "cat /etc/x.conf")),
		"linux", 0, execOnDevice(x, d, "test"))
	v := playbookVerdict(rep, d)
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "hunter2") {
		t.Errorf("口令原样回到了结果里：%s", blob)
	}
	if !strings.Contains(string(blob), "password:") {
		t.Errorf("键名该留着（那是「配了口令、没给你看」，不是「没配口令」）：%s", blob)
	}
	red, _ := v.Values["redacted"].(map[string]int)
	n := 0
	for _, c := range red {
		n += c
	}
	if n == 0 {
		t.Errorf("抹掉了东西却没记账：%v", v.Values["redacted"])
	}
	if how, _ := v.Values["redactedHow"].(string); !strings.Contains(how, "共抹掉") {
		t.Errorf("redactedHow 不是给人看的那句：%v", how)
	}
	// 同一句口令也不许留在审计里
	audit := fmt.Sprint(mgr.AuditTail(20))
	if strings.Contains(audit, "hunter2") {
		t.Errorf("口令进了审计：%s", audit)
	}
	if !strings.Contains(audit, "playbook.step") {
		t.Errorf("每一条命令没进审计：%s", audit)
	}
}

func Test判定与账在出口处还对得上(t *testing.T) {
	f := &fakeDeviceExec{
		out:  map[string]*remote.Output{"a": {Stdout: "ok\n"}},
		errs: map[string]error{"b": fmt.Errorf("command not found")},
	}
	book := newBook(bookStep("一", "a"), bookStep("二", "b"))
	rep := runPlaybook(context.Background(), book, "linux", 0, f.run)
	v := playbookVerdict(rep, &remote.Device{ID: "ops@h"})
	if v.Code != "playbook-step-failed" {
		t.Errorf("有一条没问到答案，判定却是 %q", v.Code)
	}
	counts, _ := v.Values["counts"].(playbook.Counts)
	if counts.Failed != 1 {
		t.Errorf("判定说有砸的，账上却记 %d 条", counts.Failed)
	}
	if next, _ := v.Values["nextStep"].(string); next == "" || !strings.Contains(next, "1 条") {
		t.Errorf("下一步没接着那个数说：%q", next)
	}
}

// 连接断了要报成「没问到」，不是「这条命令跑砸了」—— 后者会让人去改剧本。
// 用的错话是 x/crypto/ssh 真会说的那句（它把 io.EOF 包成了自己的字符串）。
func Test断线报成没问到(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	useMgr(t)
	t.Cleanup(func() { SetPlaybook(nil) })
	x := &countingSSH{
		out:  map[string]*remote.Output{"a": {Stdout: "A\n"}, "c": {Stdout: "C\n"}},
		errs: map[string]error{"b": fmt.Errorf("ssh: rejected: connect failed (Connection reset by peer)")},
	}
	book := newBook(bookStep("一", "a"), bookStep("二", "b"), bookStep("三", "c"))
	d := &remote.Device{ID: "ops@h"}
	rep := runPlaybook(context.Background(), book, "linux", 0, execOnDevice(x, d, "test"))
	v := playbookVerdict(rep, d)
	if v.Code != "playbook-unreachable" {
		t.Errorf("断了却判成 %q", v.Code)
	}
	if x.calls != 2 {
		t.Errorf("断了之后还敲了 %d 条", x.calls)
	}
	if a := fmt.Sprint(mgr.AuditTail(20)); !strings.Contains(a, "断了") {
		t.Errorf("断线这件事没进审计：%s", a)
	}
}

type countingSSH struct {
	out   map[string]*remote.Output
	errs  map[string]error
	calls int
}

func (c *countingSSH) Exec(ctx context.Context, d *remote.Device, cmd string, t time.Duration) (*remote.Output, error) {
	c.calls++
	if err := c.errs[cmd]; err != nil {
		return nil, err
	}
	return c.out[cmd], nil
}

func Test哪些错算这台机器不答话(t *testing.T) {
	cases := []struct {
		err  error
		want bool
		what string
	}{
		{io.EOF, true, "对端关了"},
		{fmt.Errorf("read tcp: connection reset by peer"), true, "连接被重置"},
		{&ssh.ExitMissingError{}, true, "没回退出码就断了"},
		{fmt.Errorf("ssh: handshake failed: no authentication methods"), false, "认证问题（连接没断）"},
		{fmt.Errorf("exit status 127"), false, "命令本身跑砸"},
	}
	for _, c := range cases {
		if got := connBroken(c.err); got != c.want {
			t.Errorf("%s：%v 该判 %v", c.what, got, c.want)
		}
	}
	if connBroken(nil) {
		t.Errorf("没出错也算断线")
	}
}

// 单条命令的等待秒数：剧本自己标的优先，参数只兜住没标的。
func Test等待秒数谁说了算(t *testing.T) {
	quick := bookStep("快的", "uptime")
	slow := bookStep("慢的", "journalctl")
	slow.TimeoutSec = 90
	book := newBook(quick, slow)
	f := &fakeDeviceExec{
		out:  map[string]*remote.Output{"uptime": {Stdout: "up\n"}, "journalctl": {Stdout: "log\n"}},
		errs: map[string]error{},
	}
	runPlaybook(context.Background(), book, "linux", 5, f.run)
	want := []time.Duration{5 * time.Second, 90 * time.Second}
	for i, w := range want {
		if f.waits[i] != w {
			t.Errorf("第 %d 条给了 %s，该是 %s（没标的用参数、标了用自己的）", i+1, f.waits[i], w)
		}
	}
	// 不许把原剧本改掉：内置那本是共用的
	if book.Steps[0].TimeoutSec != 0 {
		t.Errorf("把调用方给的秒数写回剧本里了：%d", book.Steps[0].TimeoutSec)
	}
}

func Test每种判定都带下一步(t *testing.T) {
	cases := []struct{ code, want string }{
		{"playbook-ok", "都问到了"},
		{"playbook-step-failed", "没"},
		{"playbook-unreachable", "重连"},
		{"playbook-platform-skipped", "系统"},
		{"playbook-empty", "空"},
	}
	for _, c := range cases {
		got := playbookNextStep(c.code, playbook.Counts{Total: 3, Ran: 2, Failed: 1, TimedOut: 1, Aborted: 1, SkippedPlatform: 1, HitLines: 2})
		if got == "" || !strings.Contains(got, c.want) {
			t.Errorf("%s 的下一步没说清（希望出现「%s」）：%q", c.code, c.want, got)
		}
	}
	// 一切正常且有命中时，那句该把人指向命中，而不是泛泛说「没问题」
	yes := playbookNextStep("playbook-ok", playbook.Counts{Total: 3, Ran: 3, HitLines: 4})
	if !strings.Contains(yes, "4 处") {
		t.Errorf("有命中却没指到命中：%q", yes)
	}
	ran := playbookNextStep("playbook-ok", playbook.Counts{Total: 3, Ran: 3, WriteRan: 2})
	if !strings.Contains(ran, "2 条") || !strings.Contains(ran, "审计") {
		t.Errorf("跑了改东西的条却没让人去核审计：%q", ran)
	}
}

func Test保存与删除的四道拦子(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	t.Cleanup(func() { SetPlaybook(nil) })

	save := func(book map[string]any, replace bool) error {
		raw, _ := json.Marshal(map[string]any{"playbook": book, "replace": replace})
		_, err := remotePlaybookSaveTool.Invoke(context.Background(), raw)
		return err
	}
	good := map[string]any{
		"id": "mine", "name": "我记的那本",
		"steps": []map[string]any{{"name": "看活了多久", "run": "uptime", "why": "它多久没重启了"}},
	}
	if err := save(good, false); err != nil {
		t.Fatalf("存一本合式的该过：%v", err)
	}
	// 1 合式不过
	if err := save(map[string]any{"id": "bad", "name": "缺步的", "steps": []any{}}, false); err == nil ||
		!strings.Contains(err.Error(), "不合式") {
		t.Errorf("空剧本存进来了：%v", err)
	}
	// 2 不许盖内置
	book := map[string]any{
		"id": playbook.BuiltinBoxCheck, "name": "顶掉官方",
		"steps": []map[string]any{{"name": "x", "run": "y", "why": "z"}},
	}
	if err := save(book, true); err == nil || !strings.Contains(err.Error(), "内置") {
		t.Errorf("盖内置那本存进来了：%v", err)
	}
	// 3 撞编号不许悄悄顶掉
	if err := save(good, false); err == nil || !strings.Contains(err.Error(), "已经有一本") {
		t.Errorf("别人发来一本撞号的，默认顶掉了人家那本：%v", err)
	}
	if err := save(good, true); err != nil {
		t.Errorf("明说「保存修改」后被拦了：%v", err)
	}
	// 4 删：内置删不掉，没存的删不了，存过的删得掉
	del := func(id string) error {
		raw, _ := json.Marshal(map[string]any{"playbook": id})
		_, err := remotePlaybookDeleteTool.Invoke(context.Background(), raw)
		return err
	}
	if err := del(playbook.BuiltinBoxCheck); err == nil || !strings.Contains(err.Error(), "内置") {
		t.Errorf("内置那本删掉了：%v", err)
	}
	if err := del("../etc/passwd"); err == nil || !strings.Contains(err.Error(), "不合式") {
		t.Errorf("会跑出目录的编号没拦住：%v", err)
	}
	if err := del("没存过的"); err == nil {
		t.Errorf("删一本没存的，居然报成功")
	}
	if err := del("mine"); err != nil {
		t.Errorf("删自己存的那本被拦了：%v", err)
	}
}

// 存进去的得能列出来 —— 不然「保存成功」只是一句空话。
func Test存进去的剧本列得出来(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	t.Cleanup(func() { SetPlaybook(nil) })
	raw, _ := json.Marshal(map[string]any{"playbook": map[string]any{
		"id": "imported", "name": "同事发来的", "note": "他那边是 40 路的盒子",
		"steps": []map[string]any{{"name": "看帧池", "run": "journalctl -u argus | tail",
			"why":   "丢帧那句话在这儿",
			"marks": []map[string]any{{"match": "frame pool", "say": "帧池不够，看通道数"}}}},
	}})
	if _, err := remotePlaybookSaveTool.Invoke(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	v := callList(t, json.RawMessage(`{}`))
	entries, _ := v.Values["playbooks"].([]map[string]any)
	var found map[string]any
	for _, e := range entries {
		if e["id"] == "imported" {
			found = e
		}
	}
	if found == nil {
		t.Fatalf("存了却列不出来：%v", v.Values["playbooks"])
	}
	steps, _ := found["steps"].([]map[string]any)
	if len(steps) != 1 {
		t.Fatalf("步数不对：%v", found)
	}
	marks, _ := steps[0]["marks"].([]playbook.Mark)
	if len(marks) != 1 || marks[0].Say == "" {
		t.Errorf("高亮和它那句说明丢了：%v", steps[0]["marks"])
	}
}

// ── 声明 ──

// 存完 / 删完那两句报的是名字，不是编号：人在界面上认的是那本的名字。
// 自己敲进去的编号，删错了都看不出删的是谁。
func Test存删那两句报的是剧本名字(t *testing.T) {
	SetPlaybook(playbook.NewStore(t.TempDir()))
	t.Cleanup(func() { SetPlaybook(nil) })

	saveRaw, _ := json.Marshal(map[string]any{"playbook": map[string]any{
		"id": "mine-01", "name": "门口那台盒子",
		"steps": []map[string]any{{"name": "看活了多久", "run": "uptime", "why": "它多久没重启了"}}}})
	saved, err := remotePlaybookSaveTool.Invoke(context.Background(), saveRaw)
	if err != nil {
		t.Fatal(err)
	}
	if n := saved.(ots.Verdict).Note; !strings.Contains(n, "门口那台盒子") {
		t.Errorf("存完那句没报名字：%q", n)
	}

	delRaw, _ := json.Marshal(map[string]any{"playbook": "mine-01"})
	// 批准框上就那一句，人点头时看到的是它 —— 念编号等于没告诉他动的是哪本。
	if d := remotePlaybookDeleteTool.Describe(delRaw); !strings.Contains(d, "门口那台盒子") {
		t.Errorf("批准框上念的是编号：%q", d)
	}
	deleted, err := remotePlaybookDeleteTool.Invoke(context.Background(), delRaw)
	if err != nil {
		t.Fatal(err)
	}
	if n := deleted.(ots.Verdict).Note; !strings.Contains(n, "门口那台盒子") {
		t.Errorf("删完那句没报名字：%q", n)
	}
}

// 剧本目录没就绪时，批准框那段话不能把进程问倒 —— 拿不到名字就照原样念编号。
func Test剧本目录没就绪时删除那段话照样念得出来(t *testing.T) {
	SetPlaybook(nil)
	s := remotePlaybookDeleteTool.Describe(json.RawMessage(`{"playbook":"mine-01"}`))
	if !strings.Contains(s, "mine-01") {
		t.Errorf("没剧本目录时那段话把编号弄丢了：%q", s)
	}
}

func Test剧本四个工具的声明(t *testing.T) {
	r := ots.NewRegistry(true)
	RegisterPlaybooks(r)
	for _, name := range []string{"remote.playbook.list", "remote.playbook.run",
		"remote.playbook.save", "remote.playbook.delete"} {
		got, ok := r.Lookup(name)
		if !ok {
			t.Fatalf("%s 没注册进注册表", name)
		}
		if !json.Valid(got.Schema) {
			t.Errorf("%s 的 schema 不是合法 JSON", name)
		}
		if got.Class == ots.ClassMutate && got.Describe == nil {
			t.Errorf("%s 是 mutate 却没有 Describe —— 批准框上会空白一片", name)
		}
	}
	// 只有「有哪些本」是只读的：另外三个要么往设备上敲命令、要么写本机文件
	if tool, _ := r.Lookup("remote.playbook.list"); tool.Class != ots.ClassRead {
		t.Errorf("列剧本被判成 %q", tool.Class)
	}
	for _, name := range []string{"remote.playbook.run", "remote.playbook.save", "remote.playbook.delete"} {
		tool, _ := r.Lookup(name)
		if tool.Class != ots.ClassMutate {
			t.Errorf("%s 是 %q —— 关在 mutate 总开关外面才拦得住", name, tool.Class)
		}
	}
	// 判定码集合不许漂：漂了界面上就是一片没有颜色的空
	codes := []string{playbook.VerdictOK, playbook.VerdictStepFailed, playbook.VerdictPlatformSkipped,
		playbook.VerdictEmpty, playbook.VerdictUnreachable}
	for _, c := range codes {
		if !otsCodeRE.MatchString(c) {
			t.Errorf("判定码 %q 不合 [OTS-5.5]（只能小写字母数字连字符）", c)
		}
	}
}

var otsCodeRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
