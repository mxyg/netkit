// Package quality 是「持续质量监测」的那本账：按窗聚合的 RTT / 丢包 / 抖动，一窗一行落在磁盘上。
//
// ★★ 为什么必须有一本账，而不是一张当场画的图：
//
//	现场那句「有时候卡一下」，多数发生在人回到电脑之前那几分钟。当场采十秒等于永远抓不到 ——
//	采到的每一窗都得留下来，人回来问「刚才那半小时到底什么样」才答得出来。
//	这个包只管账，不管怎么采：怎么发icmp、多久发一发，是工具层的事。
//
// ★ 为什么是一行一条 JSON 追加，不是一个大 JSON 覆盖写：
//
//	采集器随时会没命 —— 界面关了、进程崩了、机器睡了。追加写坏只坏最后一行，
//	覆盖写坏一次整本没了，而丢掉的恰恰是最需要的那段现场。
//	读回来时尾部那条解不开的按「丢掉并且说一声」处理，不整本判死。
//
// ★ 为什么序号（seq）跟着落盘，而不是让人拿时间戳自己数：
//
//	断档有两种，必须分得开 —— 那段时间整个没采（机器睡了、进程被停过），
//	和序号跳了号（本该有这一窗，采集器没交出来）。只看时间戳会把后一种画成一条连续的线，
//	看的人就当成「那段时间是平稳的」。序号只增不减：首条不是 1 就说明前面被滚掉了。
//	留痕有上限，被截过这件事必须问得出来，不许拿被截过的账当全程。
package quality

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultLimit 一个目标最多留多少窗。★ 留痕必须有上限：一路监测天天跑下去，
// 文件会把配置目录撑满，而那时先坏掉的是别的记账（改动账本、设备登记）。
// 5000 窗配默认 30 秒的窗口是四十来小时，够一个现场追一整夜的毛病。
const DefaultLimit = 5000

// Record 一个窗口的账 —— 文件里的一行。
//
// ★ 数值只存这一份，界面上画的线、CLI 说的那句话、判定用的数，全都读这里。
//
//	一处两份写法（图上一份、文字里一份）迟早对不上，对不上的时候人信图。
type Record struct {
	Seq        int       `json:"seq"`
	StartAt    time.Time `json:"startAt"`
	EndAt      time.Time `json:"endAt"`
	Target     string    `json:"target"`
	IntervalMS int       `json:"intervalMs"`
	WindowMS   int       `json:"windowMs"`

	Sent        int `json:"sent"`
	Recv        int `json:"recv"`
	Unreachable int `json:"unreachable,omitempty"`
	LossPercent int `json:"lossPercent"`

	MinMS    float64 `json:"minMs,omitempty"`
	MedianMS float64 `json:"medianMs,omitempty"`
	P95MS    float64 `json:"p95Ms,omitempty"`
	MaxMS    float64 `json:"maxMs,omitempty"`
	JitterMS float64 `json:"jitterMs,omitempty"`

	// Spikes 这一窗里明显偏离中位数的那几发的窗口内序号。
	// ★ 留着它，人才可以从「这一窗抖」往下一步问到「抖在几分几秒的哪一发」。
	Spikes []int `json:"spikes,omitempty"`

	// Blocked 这一窗包根本没出去的原因。
	// ★ 非空的窗不等于「一个都没回」：曲线两者都长成 100% 丢包，
	//   但处理方向完全相反 —— 一个去查对端防火墙，一个查自己这边有没有路。
	Blocked string `json:"blocked,omitempty"`
}

// Hole 留痕里的一段时间空洞：from 到 to 之间一个窗都没有。
type Hole struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	MS      int64     `json:"ms"`
	Windows int       `json:"expectedWindows"` // 按窗口宽度，这段时间本该采到多少窗
	Missing int       `json:"missingSeqs"`     // 序号跳掉了几窗（0 = 那段时间压根没在采）
}

// Audit 一份留痕的整体账 —— 报表和判定都读它，不在两边各算一遍。
type Audit struct {
	Windows int           `json:"windows"`
	Targets []string      `json:"targets"`
	From    time.Time     `json:"from"`
	To      time.Time     `json:"to"`
	SpanMS  int64         `json:"spanMs"`
	Holes   []Hole        `json:"holes,omitempty"`
	Missing int           `json:"missingSeqs"` // 跳号跳掉的窗数（这一路采集器自己没交出来的）
	Silent  []SilentRange `json:"silent,omitempty"`
	// Truncated 最早那几窗已经滚出文件了（首条 seq 不是 1）。
	Truncated bool `json:"truncated"`
	Dropped   int  `json:"droppedWindows"` // 被滚掉了多少窗（= 首条 seq - 1）
	// StaleMS 最新一窗结束到现在过了多久。★ 这一段和「在跑但这一窗还没到点」是同一种长相，
	// 所以光有它不够，必须跟「本机有没有采集器活着」一起读 —— 见工具层。
	StaleMS int64 `json:"staleMs"`
}

// SilentRange 一段「采到了，但一发都没回」的窗。
//
// ★ 它和 Hole 是两种病，不能混：Hole 是「没问到」，Silent 是「问到了、答案是全丢」。
//
//	图上两种都长得像断线，但前者要查采集器，后者要查链路。
type SilentRange struct {
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	MS    int64     `json:"ms"`
	Seqs  []int     `json:"seqs,omitempty"`
	Block bool      `json:"blocked,omitempty"` // 里面有包根本发不出去的窗
}

// DefaultDir 留痕落在哪儿 —— 和改动账本、远程设备登记同一个配置目录下。
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("找不到用户配置目录，留痕没地方存：%w", err)
	}
	return filepath.Join(base, "yuhox-netkit", "quality"), nil
}

// PathFor 一路监测一个文件。
//
// ★ 为什么不是一本总账：换目标接着写的话，图上两条线会接在同一根时间轴上，
//
//	「刚才那半小时」就说不清是哪一台的半小时了。
//
// ★ 文件名尾巴上带目标本身的散列：光把非法字符替掉会撞 ——
//
//	fe80::1%eth0 和 fe80::1%ens1 替完是同一个名字，两台的账写进一个文件。
func PathFor(dir, target string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r == ':':
			return '_'
		default:
			return '~'
		}
	}, target)
	const keep = 48
	if len(safe) > keep {
		safe = safe[:keep]
	}
	// ★ 点号留着（10.0.0.1 这种名字人要认得），但连续两个必须打掉：
	//   目标名是调用方填的， "../../x" 替掉斜杠后还留着 ".." 段，
	//   将来谁把这个文件名再拼回别的路径里就是一次穿越。
	safe = strings.ReplaceAll(safe, "..", "~")
	h := fnv.New32a()
	_, _ = h.Write([]byte(target))
	return filepath.Join(dir, fmt.Sprintf("quality-%s-%08x.jsonl", safe, h.Sum32()))
}

// Store 一路留痕：内存里一份，文件里一份，写只追加。
//
// 它自己带锁 —— 采集器在后台goroutine里一窗一窗地写，
// 界面每两秒来读一次尾巴，两边都不必知道对方的存在。
type Store struct {
	path  string
	limit int

	mu   sync.Mutex
	recs []Record

	// 下面两个是「这份文件上一次怎么没的」的痕迹，读回来时顺带算好。
	tailBroken bool
	skipped    int
}

// Open 读回一份已有留痕。文件不存在不算错 —— 第一次跑就是没有。
//
// limit <= 0 用 DefaultLimit。
func Open(path string, limit int) (*Store, error) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	s := &Store{path: path, limit: limit}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("读不了留痕文件 %s：%w", path, err)
	}
	lines := strings.Split(string(b), "\n")
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var r Record
		if uerr := json.Unmarshal([]byte(ln), &r); uerr != nil {
			// ★ 尾部那条解不开 = 上一次写到一半进程就没了。丢掉它、记住丢过，
			//   别整本判死：为了半行字把前面几百窗扔掉，等于把人要的现场删了。
			if i == len(lines)-1 || strings.TrimSpace(strings.Join(lines[i+1:], "")) == "" {
				s.tailBroken = true
				continue
			}
			s.skipped++
			continue
		}
		s.recs = append(s.recs, r)
	}
	return s, nil
}

// Path 账落在哪个文件。界面上要说得出路径，人才能把这份账发给同事。
func (s *Store) Path() string { return s.path }

// TailBroken 上一次是不是没写完整就断了（进程被杀、机器断电）。
func (s *Store) TailBroken() bool { return s.tailBroken }

// Skipped 文件里有多少行解不开（手工改坏、磁盘写坏）。
func (s *Store) Skipped() int { return s.skipped }

// Append 记一窗。★ 写盘失败必须报错，不许只往内存里加：
// 内存里加上了、文件里没有，下次启动就凭空少一段，而那正是「断档」的定义。
func (s *Store) Append(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		// 0700：这份账写的是内网里有哪些机器、它们此刻什么状态，不给同机其他账号看。
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("建不了留痕目录：%w", err)
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("这一窗记不下来：%w", err)
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("打不开留痕文件 %s：%w", s.path, err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("留痕写不进去：%w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("留痕收尾失败：%w", err)
	}
	s.recs = append(s.recs, r)
	s.tailBroken = false
	if len(s.recs) > s.limit {
		return s.rotateLocked()
	}
	return nil
}

// rotateLocked 把最早的窗滚掉，重写整个文件。
//
// ★ 序号保留：滚掉的是内容不是编号 —— 首条 seq 大于 1 就是「这份账被截过」的证据，
//
//	读的人据此知道前面还有过东西。要是把序号也重排，截断就变得看不出来了，
//	那等于把「我看到的不是全程」这件事藏掉。
//	临时文件加改名：宁可重写时被杀掉留下旧账，也不要一个空文件。
func (s *Store) rotateLocked() error {
	// 一次滚到上限的八成，不是刚好滚到上限：留着上限的话每来一窗都要重写整本，
	// 采集器会因为自己的账本卡一下 —— 而那一下会被记成下一窗的抖动。
	drop := len(s.recs) - s.limit*4/5
	if drop <= 0 {
		return nil
	}
	s.recs = append([]Record(nil), s.recs[drop:]...)
	tmp := s.path + ".tmp"
	var sb strings.Builder
	for _, r := range s.recs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Records 全部留痕，按窗口序号先后。返回副本 —— 拿的人改不动账本。
func (s *Store) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.recs))
	copy(out, s.recs)
	return out
}

// Tail 最近 n 窗（n<=0 给全部）。界面画图用这个，不必把几千窗都搬过去。
func (s *Store) Tail(n int) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs := s.recs
	if n > 0 && len(recs) > n {
		recs = recs[len(recs)-n:]
	}
	out := make([]Record, len(recs))
	copy(out, recs)
	return out
}

// Last 最新一窗。
func (s *Store) Last() (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recs) == 0 {
		return Record{}, false
	}
	return s.recs[len(s.recs)-1], true
}

// First 最早还留着的那一窗。★ 报表第一句要问的就是「这份账从什么时候开始」。
func (s *Store) First() (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recs) == 0 {
		return Record{}, false
	}
	return s.recs[0], true
}

// Count 现在留着多少窗。
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}

// AuditOf 对着这份账算总账。now 传现在（算尾部停了多久），零值表示还没有「现在」可比。
func (s *Store) AuditOf(now time.Time) Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return audit(s.recs, now)
}

// AuditOf 一份留痕的总账（不经文件，测试和纯算的地方直接调它）。
func AuditOf(recs []Record, now time.Time) Audit { return audit(recs, now) }

func audit(recs []Record, now time.Time) Audit {
	a := Audit{Windows: len(recs)}
	if len(recs) == 0 {
		return a
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if r.Target != "" && !seen[r.Target] {
			seen[r.Target] = true
			a.Targets = append(a.Targets, r.Target)
		}
	}
	sort.Strings(a.Targets)
	a.From = recs[0].StartAt
	a.To = recs[len(recs)-1].EndAt
	if a.To.Before(a.From) {
		a.To = a.From
	}
	a.SpanMS = a.To.Sub(a.From).Milliseconds()
	// ★ 截断从序号上看，不从条数上看：条数等于上限未必是被截过（刚好跑了那么久），
	//   首条 seq 大于 1 才是「前面有过东西、被滚掉了」。
	if recs[0].Seq > 1 {
		a.Truncated = true
		a.Dropped = recs[0].Seq - 1
	}
	for i := 1; i < len(recs); i++ {
		prev, next := recs[i-1], recs[i]
		cadence := time.Duration(prev.WindowMS) * time.Millisecond
		if cadence <= 0 {
			cadence = time.Duration(next.WindowMS) * time.Millisecond
		}
		if cadence <= 0 {
			continue
		}
		if d := next.Seq - prev.Seq - 1; d > 0 {
			a.Missing += d
		}
		gap := next.StartAt.Sub(prev.EndAt)
		// 1.5 倍而不是 1 倍：窗口本身按绝对时刻排，晚一点开始是常态
		// （上一窗最后一发等回包等满了），把「晚到」报成断档就太吵了。
		if gap*2 > cadence*3 {
			a.Holes = append(a.Holes, Hole{
				From: prev.EndAt, To: next.StartAt, MS: gap.Milliseconds(),
				Windows: int(gap / cadence), Missing: next.Seq - prev.Seq - 1,
			})
		}
	}
	a.Silent = silent(recs)
	if !now.IsZero() {
		last := recs[len(recs)-1]
		if d := now.Sub(last.EndAt); d > 0 {
			a.StaleMS = d.Milliseconds()
		}
	}
	return a
}

// silent 找出连着「一发都没回」的那几窗，合成段。
//
// ★ 只把全丢的窗并成段，不报单窗：单窗全丢在 loss 里看得见，
//
//	而「连着 20 分钟一个都没回」是另一回事 —— 那台关机了，跟抖不抖没关系。
//	一条都没回的窗里，包发不出去的（blocked）单独标出来：那是自己这边没路。
func silent(recs []Record) []SilentRange {
	var out []SilentRange
	var cur *SilentRange
	flush := func() {
		if cur != nil && len(cur.Seqs) >= 2 {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, r := range recs {
		if r.Sent > 0 && r.Recv == 0 {
			if cur == nil {
				cur = &SilentRange{From: r.StartAt, To: r.EndAt}
			}
			cur.To = r.EndAt
			cur.MS = cur.To.Sub(cur.From).Milliseconds()
			cur.Seqs = append(cur.Seqs, r.Seq)
			if r.Blocked != "" {
				cur.Block = true
			}
			continue
		}
		flush()
	}
	flush()
	return out
}
