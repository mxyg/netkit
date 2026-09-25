package quality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rec(seq int, start time.Time, window time.Duration, sent, recv int) Record {
	return Record{
		Seq: seq, StartAt: start, EndAt: start.Add(window), Target: "10.0.0.1",
		IntervalMS: 1000, WindowMS: int(window / time.Millisecond),
		Sent: sent, Recv: recv, LossPercent: (sent - recv) * 100 / max(sent, 1),
		MedianMS: 4.2, MaxMS: 9.9, JitterMS: 1.1,
	}
}

func Test留痕一行一条读回来和写进去的一模一样(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	s, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Truncate(time.Millisecond)
	want := []Record{rec(1, t0, 30*time.Second, 30, 30), rec(2, t0.Add(30*time.Second), 30*time.Second, 30, 28)}
	for _, r := range want {
		if err := s.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	again, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := again.Records()
	if len(got) != len(want) {
		t.Fatalf("读回来 %d 窗，写进去 %d 窗", len(got), len(want))
	}
	for i := range want {
		a, b := want[i], got[i]
		if a.Seq != b.Seq || a.Target != b.Target || !a.StartAt.Equal(b.StartAt) ||
			!a.EndAt.Equal(b.EndAt) || a.Sent != b.Sent || a.Recv != b.Recv ||
			a.LossPercent != b.LossPercent || a.MedianMS != b.MedianMS {
			t.Fatalf("第 %d 窗对不上：%+v vs %+v", i, a, b)
		}
	}
	if again.TailBroken() || again.Skipped() != 0 {
		t.Fatalf("干净的账不该报破损：%v %d", again.TailBroken(), again.Skipped())
	}
}

func Test上一进程写到一半被杀不许整本判死(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	t0 := time.Now().Truncate(time.Millisecond)
	s, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := s.Append(rec(i, t0.Add(time.Duration(i-1)*30*time.Second), 30*time.Second, 30, 30)); err != nil {
			t.Fatal(err)
		}
	}
	// 模拟写到一半就没命：最后半行不是合法 JSON
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"seq":4,"startAt":"2026-0`)
	_ = f.Close()

	again, err := Open(path, 0)
	if err != nil {
		t.Fatalf("半行字就该让整本读不了？%v", err)
	}
	if got := again.Count(); got != 3 {
		t.Fatalf("只该丢掉那半行，剩下 %d 窗要留得住", got)
	}
	if !again.TailBroken() {
		t.Fatal("丢过尾行必须留个说法：这是「上次没停干净」唯一的证据")
	}
}

func Test留痕到上限滚掉最早的要问得出来(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	s, err := Open(path, 6)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Truncate(time.Millisecond)
	for i := 1; i <= 20; i++ {
		if err := s.Append(rec(i, t0.Add(time.Duration(i-1)*30*time.Second), 30*time.Second, 30, 30)); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.Count(); n > 6 {
		t.Fatalf("上限 6 却留着 %d 窗", n)
	}
	again, err := Open(path, 6)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Count(); got > 6 {
		t.Fatalf("文件里 %d 行，比上限还多", got)
	}
	first, _ := again.First()
	if first.Seq == 1 {
		t.Fatal("明明滚掉过，首条序号却还是 1 —— 截断就没证据了")
	}
	a := again.AuditOf(time.Time{})
	if !a.Truncated || a.Dropped != first.Seq-1 {
		t.Fatalf("截断要报得出来：%+v", a)
	}
}

func Test断档要分得清是没采还是跳号(t *testing.T) {
	t0 := time.Now()
	w := 30 * time.Second
	// 1..2 连着，3 晚了五分钟才来（机器睡过去），4 紧跟着，6 直接缺席（跳号）
	recs := []Record{
		rec(1, t0, w, 30, 30),
		rec(2, t0.Add(w), w, 30, 30),
		rec(3, t0.Add(w*2+5*time.Minute), w, 30, 30),
		rec(4, t0.Add(w*3+5*time.Minute), w, 30, 30),
		rec(6, t0.Add(w*5+5*time.Minute), w, 30, 30),
	}
	a := AuditOf(recs, time.Time{})
	if len(a.Holes) != 1 {
		t.Fatalf("只该有一段空洞：%+v", a.Holes)
	}
	h := a.Holes[0]
	if h.From.Sub(t0.Add(2*w)) != 0 {
		t.Fatalf("空洞起点要接在第二窗结束那刻：%v", h.From)
	}
	if h.MS < int64(5*time.Minute/time.Millisecond) {
		t.Fatalf("空洞长度算小了：%d ms", h.MS)
	}
	if h.Windows < 10 {
		t.Fatalf("这段时间按窗口本该有 %d 窗", h.Windows)
	}
	if a.Missing != 1 {
		t.Fatalf("第 5 窗缺席，Missing 要数得出：%d", a.Missing)
	}
}

func Test等距的账不许报断档(t *testing.T) {
	t0 := time.Now()
	w := 30 * time.Second
	var recs []Record
	for i := 1; i <= 8; i++ {
		start := t0.Add(time.Duration(i-1) * w)
		recs = append(recs, rec(i, start, w, 30, 30))
	}
	a := AuditOf(recs, t0.Add(8*w))
	if len(a.Holes) != 0 || a.Missing != 0 {
		t.Fatalf("一路好好跑出来的账被读成有洞：%+v", a)
	}
	if a.Truncated {
		t.Fatal("没滚过就别报截断")
	}
}

func Test连着全丢要成段单窗不算段(t *testing.T) {
	t0 := time.Now()
	w := 30 * time.Second
	recs := []Record{
		rec(1, t0, w, 30, 30),
		rec(2, t0.Add(w), w, 30, 0),
		rec(3, t0.Add(2*w), w, 30, 0),
		rec(4, t0.Add(3*w), w, 30, 29),
		rec(5, t0.Add(4*w), w, 30, 0), // 单窗全丢：只是丢包，不是一段
	}
	a := AuditOf(recs, time.Time{})
	if len(a.Silent) != 1 {
		t.Fatalf("只该挑出一段连着全丢：%+v", a.Silent)
	}
	if len(a.Silent[0].Seqs) != 2 {
		t.Fatalf("那一段该是第 2、3 窗：%+v", a.Silent[0])
	}
}

func Test包发不出去的全丢段要另说一种病(t *testing.T) {
	t0 := time.Now()
	w := 30 * time.Second
	r1, r2 := rec(1, t0, w, 30, 0), rec(2, t0.Add(w), w, 30, 0)
	r1.Blocked, r2.Blocked = "这个地址本机没有路由（connect: no network）", ""
	a := AuditOf([]Record{r1, r2}, time.Time{})
	if len(a.Silent) != 1 || !a.Silent[0].Block {
		t.Fatalf("这一段的成因是本机没路，必须标出来：%+v", a.Silent)
	}
}

func Test文件里的路径不能跟着目标名跑出去(t *testing.T) {
	dir := t.TempDir()
	for _, target := range []string{"../../etc/passwd", "10.0.0.1", "fe80::1%eth0", "fe80::1%ens1", ""} {
		p := PathFor(dir, target)
		if filepath.Dir(p) != dir {
			t.Fatalf("目标 %q 的文件落在了 %s，跳出留痕目录了", target, filepath.Dir(p))
		}
		if strings.Contains(filepath.Base(p), "..") {
			t.Fatalf("目标 %q 写出来的文件名还留着穿越：%s", target, filepath.Base(p))
		}
	}
	if PathFor(dir, "fe80::1%eth0") == PathFor(dir, "fe80::1%ens1") {
		t.Fatal("两个不同 zone 的地址撞成同一个文件，两台的账会写进一本")
	}
	if PathFor(dir, "10.0.0.1") == PathFor(dir, "10.0.0.10") {
		t.Fatal("相邻两台撞成同一个文件")
	}
}

func Test每一窗落盘的都是合法JSON一行(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.jsonl")
	s, _ := Open(path, 0)
	if err := s.Append(rec(1, time.Now(), 30*time.Second, 30, 30)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("一窗就该是一行：%q", string(b))
	}
	var r Record
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Seq != 1 {
		t.Fatalf("行里读回的序号不对：%+v", r)
	}
}
