package tools

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/quality"
	"net.yuhox.com/netkit/internal/state"
)

// 这一栏的测试不开真套接字：一路探测的「怎么发、多久发一发」走 qualityProber 这个变量，
// 所以「什么时候该自己停下、断档算得对不对、被截过看不看得出来」都能当场验，
// 不必真等几分钟、还得碰上一个恰好会抖的网络。
//
// ★ 但有一条不能只靠注入：按窗落账那条路必须用**生产的刻度**跑一遍
//   （间隔 500ms、窗口 5s）。注入的小窗口验的是循环，真刻度验的是参数闸到循环之间
//   那段接线 —— 那段一断，界面上就是「开了半天一窗都没有」。

func fixQualityEnv(t *testing.T) (dir string) {
	t.Helper()
	oldDir, oldJ := qualityDir, journal
	base := t.TempDir()
	j, err := state.Open(filepath.Join(base, "changes.json"))
	if err != nil {
		t.Fatalf("开不了测试账本：%v", err)
	}
	dir = filepath.Join(base, "quality")
	qualityDir, journal = dir, j
	t.Cleanup(func() {
		live.mu.Lock()
		s := live.smp
		live.smp, live.entryID = nil, ""
		live.mu.Unlock()
		if s != nil && s.alive() {
			s.stop()
		}
		qualityDir, journal = oldDir, oldJ
	})
	return dir
}

// fixQualityProber 换掉「开一路探测」这件事，并且记下换了几次。
// ★ 计数是有用的：预热一条套接字、采集器另一条，两次之间如果谁忘了关，
//
//	这里就能看见（cleanup 的调用数对不上 opens）。
func fixQualityProber(t *testing.T, probe func(seq int) (time.Duration, string, error), err error) (opens *int, closes *int) {
	t.Helper()
	old := qualityProber
	var o, c int
	qualityProber = func(qualityPlan) (watchProbe, func() error, error) {
		if err != nil {
			return nil, nil, err
		}
		o++
		cc := &c
		once := make(chan struct{})
		return probe, func() error {
			select {
			case <-once:
			default:
				*cc++
				close(once)
			}
			return nil
		}, nil
	}
	t.Cleanup(func() { qualityProber = old })
	return &o, &c
}

func steadyProbe(rtt time.Duration) watchProbe {
	return func(int) (time.Duration, string, error) { return rtt, verdictReachable, nil }
}

func silentProbe() watchProbe {
	return func(int) (time.Duration, string, error) { return 0, watchNoReply, nil }
}

// barredProbe 前 n 发正常，之后每一发都是「本机没有路」。
// ★ 这正是现场那一幕：开着开着有人拔了网线 / 路由被改走了。
func barredProbe(n int, why string) watchProbe {
	var calls int
	return func(int) (time.Duration, string, error) {
		calls++
		if calls <= n {
			return 3 * time.Millisecond, verdictReachable, nil
		}
		return 0, "error", errors.New(why)
	}
}

func qualityArgs(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func callQuality(t *testing.T, tool ots.Tool, m map[string]any) ots.Verdict {
	t.Helper()
	out, err := tool.Invoke(context.Background(), qualityArgs(t, m))
	if err != nil {
		t.Fatalf("%s 直接报错：%v", tool.Name, err)
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("%s 返回的不是判定：%T", tool.Name, out)
	}
	return v
}

func verdictValue(t *testing.T, v ots.Verdict, key string) any {
	t.Helper()
	got, ok := v.Values[key]
	if !ok {
		t.Fatalf("判定里没有 %s：%v", key, v.Values)
	}
	return got
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等不到「%s」", what)
}

// ── 前置闸 ──

func Test没装留痕目录就不许开监测(t *testing.T) {
	dir := fixQualityEnv(t)
	fixQualityProber(t, steadyProbe(2*time.Millisecond), nil)
	qualityDir = ""
	t.Cleanup(func() { qualityDir = dir })
	_, err := qualityWatchTool.Invoke(context.Background(), qualityArgs(t, map[string]any{"addr": "10.0.0.1"}))
	if err == nil || !strings.Contains(err.Error(), "没地方存") {
		t.Fatalf("记不下来的监测不该放行：%v", err)
	}
}

func Test没有改动账本就不许开监测(t *testing.T) {
	fixQualityEnv(t)
	fixQualityProber(t, steadyProbe(2*time.Millisecond), nil)
	old := journal
	journal = nil
	t.Cleanup(func() { journal = old })
	_, err := qualityWatchTool.Invoke(context.Background(), qualityArgs(t, map[string]any{"addr": "10.0.0.1"}))
	if err == nil || !strings.Contains(err.Error(), "账本") {
		t.Fatalf("没账本就不该开始一直发包：%v", err)
	}
}

func Test一窗排不下四发就当场拒绝(t *testing.T) {
	fixQualityEnv(t)
	fixQualityProber(t, steadyProbe(2*time.Millisecond), nil)
	_, err := qualityWatchTool.Invoke(context.Background(), qualityArgs(t, map[string]any{
		"addr": "10.0.0.1", "intervalMs": 30000, "windowMs": 60000}))
	if err == nil || !strings.Contains(err.Error(), "排不下") {
		t.Fatalf("一窗只有两发的账没有统计意义，得拦住：%v", err)
	}
}

func Test间隔与窗口的边界写成话(t *testing.T) {
	fixQualityEnv(t)
	fixQualityProber(t, steadyProbe(2*time.Millisecond), nil)
	for _, tc := range []struct {
		name string
		m    map[string]any
		want string
	}{
		{"打太密", map[string]any{"addr": "10.0.0.1", "intervalMs": 100}, "intervalMs"},
		{"窗口太长", map[string]any{"addr": "10.0.0.1", "windowMs": 99999999}, "windowMs"},
		{"没目标", map[string]any{}, "addr"},
	} {
		_, err := qualityWatchTool.Invoke(context.Background(), qualityArgs(t, tc.m))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s：错误里没提 %s：%v", tc.name, tc.want, err)
		}
	}
}

// ── 采集器本身 ──

func Test按窗落账并且序号一路排下去(t *testing.T) {
	dir := fixQualityEnv(t)
	var cleanupCalls int
	probe := steadyProbe(2 * time.Millisecond)
	store := openQualityStore(t, dir, "10.0.0.1")
	plan := qualityPlan{target: "10.0.0.1", interval: 10 * time.Millisecond, window: 150 * time.Millisecond}
	smp := newQualitySampler(plan, store, probe, func() error { cleanupCalls++; return nil })
	smp.start()
	waitFor(t, "落三窗", func() bool { return store.Count() >= 3 })
	smp.stop()

	recs := store.Records()
	if len(recs) < 3 {
		t.Fatalf("只落了 %d 窗", len(recs))
	}
	for i, r := range recs {
		if want := i + 1; r.Seq != want {
			t.Fatalf("第 %d 条的 seq 是 %d，序号必须一格不差", i, r.Seq)
		}
		if r.Sent < 4 {
			t.Errorf("第 %d 窗只发了 %d 发", r.Seq, r.Sent)
		}
		if r.Recv != r.Sent {
			t.Errorf("第 %d 窗回了 %d/%d，注入的是发发都回", r.Seq, r.Recv, r.Sent)
		}
		if r.Target != "10.0.0.1" || r.WindowMS != 150 || r.IntervalMS != 10 {
			t.Errorf("第 %d 窗的口径没跟着落盘：%+v", r.Seq, r)
		}
		if i > 0 {
			prev := recs[i-1]
			if !r.StartAt.After(prev.EndAt) || r.EndAt.Before(r.StartAt) {
				t.Fatalf("第 %d 窗和第 %d 窗在时间上叠住了：%v %v", r.Seq, prev.Seq, prev.EndAt, r.StartAt)
			}
		}
	}
	if smp.alive() {
		t.Fatal("stop 之后采集器还活着")
	}
	if cleanupCalls != 1 {
		t.Errorf("套接字关了几次：%d（应当恰好一次）", cleanupCalls)
	}
	if got := smp.snapshot().mine; got != len(recs) {
		t.Errorf("这一路自报写了 %d 窗，文件里 %d 窗", got, len(recs))
	}
}

func Test包发不出去这一路自己收手(t *testing.T) {
	dir := fixQualityEnv(t)
	store := openQualityStore(t, dir, "10.0.0.1")
	plan := qualityPlan{target: "10.0.0.1", interval: 10 * time.Millisecond, window: 120 * time.Millisecond}
	smp := newQualitySampler(plan, store, barredProbe(0, "connect: no route to host"), func() error { return nil })
	// ★ 和生产同一个先后：先挂到 live 上再放出去，不然状态那一问看到的是一路没人知道的采集器。
	live.mu.Lock()
	live.smp = smp
	live.mu.Unlock()
	smp.start()
	waitFor(t, "自己停下", func() bool { return !smp.alive() })

	recs := store.Records()
	if len(recs) != 1 {
		t.Fatalf("停下前只该留下一窗（就是发现没路那一窗），实际 %d 窗", len(recs))
	}
	if recs[0].Blocked == "" {
		t.Fatal("这一窗必须写着「包没出去」，不然图上就是一条说不清来源的全丢线")
	}
	if recs[0].Recv != 0 {
		t.Fatalf("全丢才是这一窗的真相：%+v", recs[0])
	}
	v, err := statusQualityWatch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(ots.Verdict)
	if got.Code != verdictQualityBarred {
		t.Fatalf("自己停的要说成自己停的：%s｜%s", got.Code, got.Note)
	}
	if !strings.Contains(got.Note, "不是") || !strings.Contains(got.Note, "一切正常") {
		t.Errorf("note 要挡掉「没新窗=没问题」这个读法：%s", got.Note)
	}
	if !strings.Contains(got.Note, "网卡的链路") {
		t.Errorf("包发不出去这一档要给「查路」这一步：%s", got.Note)
	}
	if kind := got.Values["blockedKind"]; kind != blockedRoute {
		t.Errorf("这一档的 blockedKind 该是 route，实际 %s", kind)
	}
}

// ★ 自己收手有两种病，而这两种病的下一步不在同一个地方：
//
//	包发不出去要查路由和网卡，账写不下去要查磁盘、权限和那个目录。
//	合成一个码，等于把第二个人支去 ping 网关 —— 所以他有自己的码。
func Test账写不下去这一路自己收手(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("这一场拿「这个账号写不了那个文件」当失败，root 写什么都成 —— 以 root 跑时验不出东西")
	}
	dir := fixQualityEnv(t)
	store := openQualityStore(t, dir, "10.0.0.1")
	path := store.Path()
	plan := qualityPlan{target: "10.0.0.1", interval: 10 * time.Millisecond, window: 120 * time.Millisecond}
	smp := newQualitySampler(plan, store, steadyProbe(2*time.Millisecond), func() error { return nil })
	live.mu.Lock()
	live.smp = smp
	live.mu.Unlock()
	smp.start()
	waitFor(t, "第一窗落账", func() bool { return store.Count() >= 1 })

	// ★ 现场那一幕就是这么来的：账本还在、还读得动，只是这个账号写不进去了
	//   （被人改过权限、目录挂成了只读、盘满，都会走到这条失败上）。
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	waitFor(t, "写不下去时自己停下", func() bool { return !smp.alive() })

	if got := smp.snapshot().windows; got != 1 {
		t.Fatalf("写失败的那一窗不许算进账上（会造出假跳号）：%d 窗", got)
	}
	v, err := statusQualityWatch(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(ots.Verdict)
	if got.Code != verdictQualityLedgerBlocked {
		t.Fatalf("账写不下去要有自己的码：%s｜%s", got.Code, got.Note)
	}
	if !strings.Contains(got.Note, "留痕写不下去") {
		t.Errorf("要点名是「写不下去」：%s", got.Note)
	}
	if !strings.Contains(got.Note, "盘满") || !strings.Contains(got.Note, "写的权力") {
		t.Errorf("这一档要给「查盘和权限」这一步，不该把人支去查网络：%s", got.Note)
	}
	if !strings.Contains(got.Note, "一切正常") {
		t.Errorf("这句照样要挡掉「没新窗=没问题」：%s", got.Note)
	}
	vals := got.Values
	if vals["blockedKind"] != blockedLedger {
		t.Errorf("blockedKind 该是 ledger，实际 %v", vals["blockedKind"])
	}
	// ★ 停掉之前那几窗就是现场：这里必须给得出「读这本账」的那份清单。
	if ls, ok := vals["ledgers"].([]map[string]any); !ok || len(ls) == 0 {
		t.Errorf("自己停了也要把盘上那本账列出来（给读这本账的入口）：%#v", vals["ledgers"])
	}
}

func Test序号接着上一次留下的账写(t *testing.T) {
	dir := fixQualityEnv(t)
	store := openQualityStore(t, dir, "10.0.0.1")
	t0 := time.Now().Add(-time.Hour)
	if err := store.Append(qrec(7, t0, 30*time.Second, 30, 30)); err != nil {
		t.Fatal(err)
	}
	plan := qualityPlan{target: "10.0.0.1", interval: 10 * time.Millisecond, window: 120 * time.Millisecond}
	smp := newQualitySampler(plan, store, steadyProbe(2*time.Millisecond), func() error { return nil })
	if got := smp.nextSeq(); got != 8 {
		t.Fatalf("下一窗该是第 8 窗，实际说 %d —— 从 1 重排会把上一次的窗混进来", got)
	}
	smp.start()
	waitFor(t, "写进第 8 窗", func() bool { return store.Count() >= 8 })
	smp.stop()
	recs := store.Records()
	if recs[1].Seq != 8 {
		t.Fatalf("上一次留下的那一窗后面，该接着写第 8 窗，实际写着第 %d 窗 —— 从 1 重排就把上一次的窗混进来了", recs[1].Seq)
	}
	if got := smp.snapshot().mine; got != len(recs)-1 {
		t.Errorf("这一路只该算自己写的窗（%d 窗），实际说 %d", len(recs)-1, got)
	}
}

// ── 四个问 ──

func Test监测开起来会落账停掉只停采集(t *testing.T) {
	dir := fixQualityEnv(t)
	fixQualityProber(t, steadyProbe(2*time.Millisecond), nil)
	v := callQuality(t, qualityWatchTool, map[string]any{"addr": "10.0.0.1", "intervalMs": 500, "windowMs": 5000})
	if v.Code != verdictQualityRunning {
		t.Fatalf("开起来该判在跑：%s｜%s", v.Code, v.Note)
	}
	path, _ := verdictValue(t, v, "file").(string)
	if !strings.HasPrefix(path, dir) {
		t.Fatalf("账落在了留痕目录外面：%s", path)
	}
	if !strings.Contains(v.Note, "一直跑到") || !strings.Contains(v.Note, "停掉不删账") {
		t.Errorf("开跑这句要把「会一直发、停了不删账」说在前面：%s", v.Note)
	}

	st := callQuality(t, qualityStatusTool, map[string]any{})
	if st.Code != verdictQualityRunning || verdictValue(t, st, "running") != true {
		t.Fatalf("状态该说在跑：%s", st.Code)
	}
	// ★ 生产刻度：间隔与窗口都取参数允许的最小值（500ms / 5s），真等一窗落盘。
	waitFor(t, "第一窗按生产刻度落账", func() bool {
		s, err := quality.Open(path, 0)
		return err == nil && s.Count() >= 1
	})

	sp := callQuality(t, qualityStopTool, map[string]any{})
	if sp.Code != verdictQualityStopped {
		t.Fatalf("停掉该判 quality-stopped：%s", sp.Code)
	}
	if !strings.Contains(sp.Note, "没有删") {
		t.Errorf("停这句必须说清账还在：%s", sp.Note)
	}
	s, err := quality.Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() == 0 {
		t.Fatal("停了之后账被清了 —— 那本账就是开这一路的目的")
	}
	after := callQuality(t, qualityStatusTool, map[string]any{})
	if after.Code != verdictQualityIdle {
		t.Fatalf("停了之后状态该判没在跑：%s", after.Code)
	}
	var found *state.Entry
	all := journal.All()
	for i, e := range all {
		if e.Kind == "quality-watch" {
			found = &all[i]
		}
	}
	if found == nil {
		t.Fatal("开过一路监测却没在改动账本里留下")
	}
	if found.Status != state.StatusReverted {
		t.Errorf("停掉要把这笔了结，不能留着「还在生效」：%s", found.Status)
	}
	if !strings.Contains(found.Note, "10.0.0.1") {
		t.Errorf("这笔了结要写清停的是哪一路：%s", found.Note)
	}
}

func Test开跑前就发不出去宁可不加(t *testing.T) {
	dir := fixQualityEnv(t)
	opens, closes := fixQualityProber(t, func(int) (time.Duration, string, error) {
		return 0, "error", errors.New("no route to host")
	}, nil)
	v := callQuality(t, qualityWatchTool, map[string]any{"addr": "10.0.0.99"})
	if v.Code != verdictQualityBarred {
		t.Fatalf("本机没路要当场判出来：%s｜%s", v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "查自己") {
		t.Errorf("这一档的下一步在自已这台机器，note 要说：%s", v.Note)
	}
	// ★ 没开就是没开：不许留文件、不许记账、套接字要关掉。
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("被拒的这一趟留下了 %d 个文件：%v", len(ents), ents)
	}
	for _, e := range journal.All() {
		if e.Kind == "quality-watch" {
			t.Error("没开成的监测不该记账")
		}
	}
	if *opens == 0 || *closes != *opens {
		t.Errorf("套接字开了 %d 次关了 %d 次，预热那条不能漏", *opens, *closes)
	}
}

func Test同时只许一路在跑(t *testing.T) {
	fixQualityEnv(t)
	fixQualityProber(t, steadyProbe(2*time.Millisecond), nil)
	callQuality(t, qualityWatchTool, map[string]any{"addr": "10.0.0.1"})
	_, err := qualityWatchTool.Invoke(context.Background(), qualityArgs(t, map[string]any{"addr": "10.0.0.2"}))
	if err == nil {
		t.Fatal("第二路也放行了 —— 界面上那颗「停」就不知道停的是哪一路")
	}
	if !strings.Contains(err.Error(), "已经有一路") || !strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("要指名现在在跑的是谁：%v", err)
	}
}

func Test没留痕时报表不许说没问题(t *testing.T) {
	fixQualityEnv(t)
	v := callQuality(t, qualityReportTool, map[string]any{"addr": "10.0.0.1"})
	if v.Code != verdictQualityIdle {
		t.Fatalf("没账可判：%s", v.Code)
	}
	// ★ 扫的是这句话本身，不是文件路径 —— 临时目录里带着测试函数名，
	//   拿整条 note 去比会把「…不许说没问题」当成结论说过一遍。
	note := strings.ReplaceAll(v.Note, verdictValue(t, v, "file").(string), "留痕文件")
	for _, bad := range []string{"稳定", "没问题", "正常"} {
		if strings.Contains(note, bad) {
			t.Errorf("一窗都没采到的报表里出现了「%s」：%s", bad, note)
		}
	}
	if !strings.Contains(note, "没采过") {
		t.Errorf("要把「这一段根本没问」说死：%s", note)
	}
}

func Test没在跑时状态要盘出还有几本账(t *testing.T) {
	dir := fixQualityEnv(t)
	for _, target := range []string{"10.0.0.1", "10.0.0.2"} {
		s := openQualityStore(t, dir, target)
		t0 := time.Now().Add(-time.Minute)
		for i := 1; i <= 3; i++ {
			r := qrec(i, t0.Add(time.Duration(i-1)*30*time.Second), 30*time.Second, 30, 30)
			r.Target = target
			if err := s.Append(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	v := callQuality(t, qualityStatusTool, map[string]any{})
	if v.Code != verdictQualityIdle {
		t.Fatalf("该判没在跑：%s", v.Code)
	}
	// ★ 按 JSON 走一遍再看：界面上拿到的就是这份编码后的样子，
	//   直接断 Go 的 []map 会把「UI 读不读得出来」这个真问题漏掉。
	b, err := json.Marshal(verdictValue(t, v, "ledgers"))
	if err != nil {
		t.Fatal(err)
	}
	var ledgers []any
	if err := json.Unmarshal(b, &ledgers); err != nil {
		t.Fatal(err)
	}
	if len(ledgers) != 2 {
		t.Fatalf("盘上两本账，状态只看到 %s", b)
	}
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "net.quality.report"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("note 里没有 %q：%s", want, v.Note)
		}
	}
}

func Test只读那一路自己的账(t *testing.T) {
	dir := fixQualityEnv(t)
	a := openQualityStore(t, dir, "10.0.0.1")
	b := openQualityStore(t, dir, "10.0.0.2")
	t0 := time.Now().Add(-time.Hour)
	for i := 1; i <= 6; i++ {
		ra := qrec(i, t0.Add(time.Duration(i-1)*30*time.Second), 30*time.Second, 30, 30)
		ra.Target = "10.0.0.1"
		_ = a.Append(ra)
		recv := 30
		// 那台是「通一段断一段」，不是从头到尾没通 —— 两档的下一步完全不同。
		if i == 2 || i == 3 || i == 5 || i == 6 {
			recv = 0
		}
		rb := qrec(i, t0.Add(time.Duration(i-1)*30*time.Second), 30*time.Second, 30, recv)
		rb.Target = "10.0.0.2"
		_ = b.Append(rb)
	}
	v := callQuality(t, qualityReportTool, map[string]any{"addr": "10.0.0.1"})
	if v.Code != verdictQualityStable {
		t.Fatalf("这台是干净的，账却串了：%s｜%s", v.Code, v.Note)
	}
	v2 := callQuality(t, qualityReportTool, map[string]any{"addr": "10.0.0.2"})
	if v2.Code != verdictQualityFlapping {
		t.Fatalf("另一台全是丢包：%s", v2.Code)
	}
}

// ── 报表判定 ──

func Test报表判定按证据先后走(t *testing.T) {
	t0 := time.Now()
	w := 30 * time.Second
	mk := func(n int, fn func(i int, r *quality.Record)) []quality.Record {
		var out []quality.Record
		for i := 1; i <= n; i++ {
			r := qrec(i, t0.Add(time.Duration(i-1)*w), w, 30, 30)
			if fn != nil {
				fn(i, &r)
			}
			out = append(out, r)
		}
		return out
	}
	flat := func(_ int, r *quality.Record) { r.MedianMS, r.MaxMS, r.JitterMS = 4, 6, 1 }

	cases := []struct {
		name    string
		recs    []quality.Record
		broken  bool
		want    string
		wantSub string
	}{
		{
			name: "全程稳", recs: mk(8, flat), want: verdictQualityStable, wantSub: "没丢包",
		},
		{
			name: "有窗丢包",
			recs: mk(8, func(i int, r *quality.Record) {
				flat(i, r)
				if i == 5 {
					r.Recv, r.LossPercent = 27, 10
				}
			}),
			want: verdictQualityLoss, wantSub: "第 5 窗",
		},
		{
			name: "通断交替",
			recs: mk(8, func(i int, r *quality.Record) {
				flat(i, r)
				switch i {
				case 2, 3, 6, 7:
					r.Recv, r.LossPercent = 0, 100
				}
			}),
			want: verdictQualityFlapping, wantSub: "通断交替",
		},
		{
			name: "往返抬升",
			recs: mk(8, func(i int, r *quality.Record) {
				r.JitterMS, r.MaxMS = 1, 6
				if i <= 4 {
					r.MedianMS = 5
				} else {
					r.MedianMS = 60
				}
			}),
			want: verdictQualityRTTRise, wantSub: "往上走",
		},
		{
			name: "断档优先于稳定",
			recs: append(mk(3, flat), mk(3, func(i int, r *quality.Record) {
				flat(i, r)
				r.Seq = i + 20
				r.StartAt = t0.Add(time.Duration(20+i) * w)
				r.EndAt = r.StartAt.Add(w)
			})...),
			want: verdictQualityGap, wantSub: "留痕有断档",
		},
		{
			name:    "被截过",
			recs:    mk(6, func(i int, r *quality.Record) { flat(i, r); r.Seq = i + 40 }),
			want:    verdictQualityTruncated,
			wantSub: "不是全程",
		},
		{
			name:    "上次没写干净",
			recs:    mk(6, flat),
			broken:  true,
			want:    verdictQualityTruncated,
			wantSub: "没写完",
		},
		{
			name: "发不出去",
			recs: mk(4, func(i int, r *quality.Record) {
				r.Recv, r.LossPercent = 0, 100
				r.Blocked = "这个地址本机没有路由"
			}),
			want: verdictQualityBarred, wantSub: "查自己这台",
		},
		{
			// ★ 一窗说不出「一直」：丢包问得出，抖、变慢、中间断过都要两窗以上才问得出。
			name: "只有一窗", recs: mk(1, flat), want: verdictQualityStable, wantSub: "只有这一窗",
		},
	}
	for _, tc := range cases {
		aud := quality.AuditOf(tc.recs, time.Time{})
		code, note := qualityReportVerdict(tc.recs, aud, false, tc.broken)
		if code != tc.want {
			t.Errorf("%s：判成 %s，应当 %s\n%s", tc.name, code, tc.want, note)
			continue
		}
		if !strings.Contains(note, tc.wantSub) {
			t.Errorf("%s：note 里没写到 %q：%s", tc.name, tc.wantSub, note)
		}
		// 这一档的 note 是人抄进工单的那一句，连着两个分隔号等于没校对过。
		if strings.Contains(note, "；；") {
			t.Errorf("%s：note 里有两个连着的分号：%s", tc.name, note)
		}
	}
}

func Test断档那一段不能把人支去说全程稳定(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	w := 30 * time.Second
	var recs []quality.Record
	for i := 1; i <= 4; i++ {
		r := qrec(i, t0.Add(time.Duration(i-1)*w), w, 30, 30)
		r.MedianMS, r.MaxMS, r.JitterMS = 4, 6, 1
		recs = append(recs, r)
	}
	// 中间睡过去十分钟
	for i := 5; i <= 8; i++ {
		r := qrec(i, t0.Add(time.Duration(i-1)*w+10*time.Minute), w, 30, 30)
		r.MedianMS, r.MaxMS, r.JitterMS = 4, 6, 1
		recs = append(recs, r)
	}
	code, note := qualityReportVerdict(recs, quality.AuditOf(recs, time.Time{}), false, false)
	if code != verdictQualityGap {
		t.Fatalf("有十分钟没采到却报「稳」，就是在替现场作伪证：%s｜%s", code, note)
	}
	for _, want := range []string{"没采到", "不等于没出事", "全程稳定"} {
		if !strings.Contains(note, want) {
			t.Errorf("note 里少了 %q：%s", want, note)
		}
	}
}

func Test停下来的账尾部那段不算断档(t *testing.T) {
	// 这一路两小时前就停了：账「多久没长」当然是两小时，但那不是洞。
	t0 := time.Now().Add(-2 * time.Hour)
	w := 30 * time.Second
	var recs []quality.Record
	for i := 1; i <= 6; i++ {
		r := qrec(i, t0.Add(time.Duration(i-1)*w), w, 30, 30)
		r.MedianMS, r.MaxMS, r.JitterMS = 4, 6, 1
		recs = append(recs, r)
	}
	aud := quality.AuditOf(recs, time.Now()) // 传了「现在」，StaleMS 会很大
	if aud.StaleMS < int64(time.Hour/time.Millisecond) {
		t.Fatalf("这条测试的前提没了：%d", aud.StaleMS)
	}
	code, note := qualityReportVerdict(recs, aud, false, false)
	if code != verdictQualityStable {
		t.Fatalf("停了的账不该因为「没再长」就判断档：%s｜%s", code, note)
	}
	// 同一份账，如果采集器还活着，就必须判断档。
	code2, _ := qualityReportVerdict(recs, quality.AuditOf(recs, time.Now()), true, false)
	if code2 != verdictQualityGap {
		t.Fatalf("还在跑却不长账 = 断档，实际判了 %s", code2)
	}
}

func Test报表只搬要的那几窗(t *testing.T) {
	dir := fixQualityEnv(t)
	s := openQualityStore(t, dir, "10.0.0.1")
	t0 := time.Now().Add(-time.Hour)
	for i := 1; i <= 50; i++ {
		if err := s.Append(qrec(i, t0.Add(time.Duration(i-1)*30*time.Second), 30*time.Second, 30, 30)); err != nil {
			t.Fatal(err)
		}
	}
	v := callQuality(t, qualityReportTool, map[string]any{"addr": "10.0.0.1", "windows": 10})
	got, _ := verdictValue(t, v, "windows").([]quality.Record)
	if len(got) != 10 || got[9].Seq != 50 || got[0].Seq != 41 {
		t.Fatalf("要最近 10 窗，拿回 %d 窗（%v…%v）", len(got), got[0].Seq, got[len(got)-1].Seq)
	}
	if total := verdictValue(t, v, "totalWindows"); total != 50 {
		t.Errorf("整本账 50 窗要如实报，实际 %v", total)
	}
}

func Test报表参数有闸(t *testing.T) {
	fixQualityEnv(t)
	if _, err := qualityReportTool.Invoke(context.Background(), qualityArgs(t, map[string]any{})); err == nil {
		t.Error("没给 addr 也放行了")
	}
	_, err := qualityReportTool.Invoke(context.Background(),
		qualityArgs(t, map[string]any{"addr": "10.0.0.1", "windows": 999999}))
	if err == nil || !strings.Contains(err.Error(), "windows") {
		t.Errorf("一次搬太多要有闸：%v", err)
	}
}

// ── 合规与文案 ──

func Test持续质量的判定码都合规(t *testing.T) {
	for _, code := range []string{
		verdictQualityRunning, verdictQualityIdle, verdictQualityStopped, verdictQualityBarred,
		verdictQualityLedgerBlocked,
		verdictQualityStable, verdictQualityLoss, verdictQualityFlapping, verdictQualityRTTRise,
		verdictQualityGap, verdictQualityTruncated,
	} {
		if !ots.ValidVerdictCode(code) {
			t.Errorf("判定码 %q 不合 [OTS-5.5]", code)
		}
		if !strings.HasPrefix(code, "quality-") {
			t.Errorf("判定码 %q 没带工具前缀，会和别栏的码撞上", code)
		}
	}
	// ★ 自己收手的两种病必须是两个码：一种查路，一种查盘，合成一个就把人支错地方。
	if verdictQualityBarred == verdictQualityLedgerBlocked {
		t.Error("包发不出去和账写不下去共用一个码，界面就没法给两种下一步")
	}
}

// ★ 后端只出码，中文得有人写。钉的是**那两张码表**：光「app.js 里出现过这个码」不够 ——
//
//	码在提示文字里露一次就能把测试骗绿，而界面上那一格会直接印出 quality-ledger-blocked。
func Test持续质量的判定码界面上都有人话(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面文件：%v", err)
	}
	js := string(b)
	for _, tbl := range []struct {
		head  string
		what  string
		codes []string
	}{
		{"const QUALITY_STATE = {", "这一路现在什么状态", []string{
			verdictQualityRunning, verdictQualityIdle, verdictQualityStopped,
			verdictQualityBarred, verdictQualityLedgerBlocked,
		}},
		{"const QUALITY_READ = {", "这一本账怎么说", []string{
			verdictQualityStable, verdictQualityLoss, verdictQualityFlapping,
			verdictQualityRTTRise, verdictQualityGap, verdictQualityTruncated,
			verdictQualityBarred, verdictQualityIdle,
		}},
	} {
		block := jsBlock(js, tbl.head)
		if block == "" {
			t.Fatalf("界面里找不到码表 %s", tbl.head)
		}
		for _, code := range tbl.codes {
			at := strings.Index(block, "'"+code+"': [")
			if at < 0 {
				t.Errorf("%s 那张表里没有 %s —— 界面上会直接印出这个码", tbl.what, code)
				continue
			}
			rest := block[at+len("'")+len(code)+len("': ["):]
			if !strings.HasPrefix(rest, "'") {
				t.Errorf("%s 在 %s 里那一行不像 ['人话', '档色'] 的样子：%s", code, tbl.head, rest)
				continue
			}
			if end := strings.Index(rest[1:], "'"); end <= 0 {
				t.Errorf("%s 在 %s 里没配人话（或那句是空的）", code, tbl.head)
			}
		}
	}
}

func Test开与停是mutate看是read(t *testing.T) {
	for _, tc := range []struct {
		tool  ots.Tool
		class ots.Class
	}{
		{qualityWatchTool, ots.ClassMutate},
		{qualityStopTool, ots.ClassMutate},
		{qualityStatusTool, ots.ClassRead},
		{qualityReportTool, ots.ClassRead},
	} {
		if tc.tool.Class != tc.class {
			t.Errorf("%s 标成了 %s，应当 %s", tc.tool.Name, tc.tool.Class, tc.class)
		}
	}
	if qualityWatchTool.Describe == nil || qualityStopTool.Describe == nil {
		t.Fatal("mutate 工具没有 Describe [OTS-7.2]")
	}
}

func Test批准说明写清刻度文件和会一直跑(t *testing.T) {
	fixQualityEnv(t)
	s := describeQualityWatch(qualityArgs(t, map[string]any{
		"addr": "192.168.1.1", "intervalMs": 1000, "windowMs": 60000}))
	for _, want := range []string{"192.168.1.1", "1 秒", "1 分钟", "net.quality.stop", "quality-"} {
		if !strings.Contains(s, want) {
			t.Errorf("批准说明里没有 %q：\n%s", want, s)
		}
	}
	if !strings.Contains(s, "一直跑") {
		t.Errorf("人不点头就后台发包到明天，这句必须在批准框里：\n%s", s)
	}
}

func Test留痕目录没装时报表和状态都直说(t *testing.T) {
	dir := fixQualityEnv(t)
	qualityDir = ""
	t.Cleanup(func() { qualityDir = dir })
	st := callQuality(t, qualityStatusTool, map[string]any{})
	if st.Code != verdictQualityIdle || !strings.Contains(st.Note, "没地方存") {
		t.Errorf("要说清目录没装：%s", st.Note)
	}
	if _, err := qualityReportTool.Invoke(context.Background(),
		qualityArgs(t, map[string]any{"addr": "10.0.0.1"})); err == nil {
		t.Error("没有目录还放行报表")
	}
}

func Test重启只了结那笔账不自动重开(t *testing.T) {
	fixQualityEnv(t)
	e, err := journal.Register("quality-watch", "开了一路监测", map[string]any{"watching": false},
		map[string]any{"watching": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkApplied(e); err != nil {
		t.Fatal(err)
	}
	restoreQualityWatch(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, x := range journal.Outstanding() {
		if x.Kind == "quality-watch" {
			t.Fatal("重启后这笔账还挂着「在生效」—— 下一个看账的人会去查一个早就不跑的监测")
		}
	}
	live.mu.Lock()
	s := live.smp
	live.mu.Unlock()
	if s != nil {
		t.Fatal("重启就自己开始对外发包了 —— 人不在场")
	}
}

// ── 小工具 ──

// Test人话时长 一段账的总长是 note 里最后一格读数。
// 盯了 3 分 45 秒的账写成「225063 毫秒」，等于让现场的人自己做除法。
func Test人话时长(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "500 毫秒"},
		{5 * time.Second, "5 秒"},
		{2500 * time.Millisecond, "2.5 秒"},
		{59999 * time.Millisecond, "59.9 秒"},
		{30 * time.Second, "30 秒"},
		{180 * time.Second, "3 分钟"},
		{225063 * time.Millisecond, "3 分 45 秒"},
		{3600 * time.Second, "1 小时"},
		{3720 * time.Second, "1 小时 2 分"},
	} {
		if got := humanDur(tc.d); got != tc.want {
			t.Errorf("humanDur(%s) = %q，想要 %q", tc.d, got, tc.want)
		}
	}
}

func openQualityStore(t *testing.T, dir, target string) *quality.Store {
	t.Helper()
	s, err := quality.Open(quality.PathFor(dir, target), 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func qrec(seq int, start time.Time, window time.Duration, sent, recv int) quality.Record {
	return quality.Record{
		Seq: seq, StartAt: start, EndAt: start.Add(window), Target: "10.0.0.1",
		IntervalMS: 1000, WindowMS: int(window / time.Millisecond),
		Sent: sent, Recv: recv, LossPercent: (sent - recv) * 100 / max(sent, 1),
		MedianMS: 4.2, MaxMS: 9.9, JitterMS: 1.1,
	}
}
