package playbook

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 一步跑完后的样子。五种，界面上一种一色。
const (
	// StatusRan 问到了 —— 命令回了话，哪怕它回的是「没在跑」。
	StatusRan = "ran"
	// StatusFailed 没问到答案：回错、或者什么都没说就走了。
	StatusFailed = "failed"
	// StatusTimeout 等到等待秒数没了还没回话。
	StatusTimeout = "timeout"
	// StatusSkippedPlatform 这一条标了别的系统，在这台机器上问不出。
	StatusSkippedPlatform = "skipped-platform"
	// StatusAborted 机器中途不搭理了，这一条起后面都没问。
	StatusAborted = "aborted"
)

// 判定码。★ 只从 Counts 推出来（见 verdictOf），不许另起一处算，
// 否则界面会出现「账上有砸的、判定却一切正常」。
const (
	VerdictOK              = "playbook-ok"
	VerdictStepFailed      = "playbook-step-failed"
	VerdictPlatformSkipped = "playbook-platform-skipped"
	VerdictEmpty           = "playbook-empty"
	VerdictUnreachable     = "playbook-unreachable"
)

// DefaultStepTimeoutSec 一条没标等待秒数时等多久。
// 现场 journalctl 碰上磁盘卡住会一直挂着，不兜住的话整本跑不到头。
const DefaultStepTimeoutSec = 20

// MaxOutputLines 一步最多留多少行给人看。
// 关键词计数一律按全文，这里只裁显示 —— 见 Run 里那段说明。
const MaxOutputLines = 200

// ErrUnreachable 执行器用它表示「这台机器问不出去了」（ssh 断了、主机不可达）。
//
// 和「这条命令跑砸」分开是有意的：砸了要去看命令，断了要先重连，
// 混成一个判定会让人在设备上白转一圈。
var ErrUnreachable = errors.New("unreachable")

// Result 一条命令的回话。
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Executer 由调用方注入 —— 本地执行、SSH 执行都满足它。
// 这个包因此不碰网络，也不碰 exec。
//
// ★ 为什么把等待时长也递过去：调用方那层（SSH）自己也要设一个超时，
// 两边各设一个就会打架 —— 外层先撒手的话，这一步看着像「跑砸」，
// 而真相是「等不到」。所以时长由这一处说了算，往下传。
type Executer func(ctx context.Context, command string, wait time.Duration) (Result, error)

// Hit 一条关键词在这一步里的下落。
type Hit struct {
	Match string `json:"match"`
	// Say 命中了要不要紧、下一步往哪儿看 —— 界面上直接跟在变红的那几行后面。
	Say string `json:"say"`
	// Lines 全文里命中的行数。0 也要留：「日志里没提到丢帧」是线索，不是空白。
	Lines int `json:"lines"`
	// Sample 命中的原话（最多三行），给人对着看，不用重跑一遍。
	Sample []string `json:"sample,omitempty"`
}

// StepResult 一步的账。
type StepResult struct {
	Name    string `json:"name"`
	Why     string `json:"why,omitempty"`
	Command string `json:"command"`
	Status  string `json:"status"`
	// Write 这条会改那台机器的东西 —— 界面上单独一色，别和只读的混成一句「跑完了」。
	Write     bool   `json:"write,omitempty"`
	ExitCode  int    `json:"exitCode,omitempty"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	Truncated int    `json:"truncatedLines,omitempty"`
	Note      string `json:"note,omitempty"`
	Hits      []Hit  `json:"hits,omitempty"`
	ElapsedMs int64  `json:"elapsedMs"`
}

// Counts 整本的账。判定、界面上那行小字、下面的明细三处都读它。
type Counts struct {
	Total           int `json:"total"`
	Ran             int `json:"ran"`
	Failed          int `json:"failed"`
	TimedOut        int `json:"timedOut"`
	SkippedPlatform int `json:"skippedPlatform"`
	Aborted         int `json:"aborted"`
	// WriteRan 真跑过的「会改东西」那条的条数 —— 批准时念给人听的就是它。
	WriteRan int `json:"writeRan"`
	HitLines int `json:"hitLines"`
}

// Report 一本剧本跑一遍的结果。
type Report struct {
	PlaybookID   string `json:"playbookId"`
	PlaybookName string `json:"playbookName"`
	Goos         string `json:"goos"`

	Steps  []StepResult `json:"steps"`
	Counts Counts       `json:"counts"`

	Verdict     string `json:"verdict"`
	VerdictNote string `json:"verdictNote"`
	ElapsedMs   int64  `json:"elapsedMs"`
}

// Run 挨条跑一本剧本，把每一步的下落记全。
//
// goos 是那台机器的系统（不是我们这台）：剧本里标了别的系统的条会跳过去。
// 一台机器问到一半断了，剩下的标 aborted 而不是 failed —— 那没问过。
func Run(ctx context.Context, p *Playbook, goos string, exec Executer) *Report {
	started := time.Now()
	rep := &Report{Goos: goos}
	var steps []Step
	if p != nil {
		rep.PlaybookID, rep.PlaybookName, steps = p.ID, p.Name, p.Steps
	}

	rep.Counts.Total = len(steps)
	// 一条问到一半机器断了：之后的条一概不敲，只记「没问到」。
	brokeOff := false
	brokeAt := 0 // 断在哪一条上（从 1 数）：那句判定要说停在哪儿

	for i, s := range steps {
		sr := StepResult{Name: s.Name, Why: s.Why, Command: s.Run, Write: s.Write}
		switch {
		case brokeOff:
			sr.Status = StatusAborted
			sr.Note = "这台机器已经不答话了，这一条没问"
		case !s.AppliesTo(goos):
			sr.Status = StatusSkippedPlatform
			sr.Note = "这一条是 " + strings.Join(s.OS, " / ") + " 上的问法，这台机器上问不出"
		default:
			runStep(ctx, exec, s, goos, &sr)
			if sr.Status == StatusAborted {
				brokeOff = true
				brokeAt = i + 1
			}
		}
		tally(&rep.Counts, sr)
		rep.Steps = append(rep.Steps, sr)
	}

	rep.Counts.WriteRan = countWriteRan(steps, rep.Steps)
	rep.Counts.HitLines = countHitLines(rep.Steps)
	rep.Verdict = verdictOf(rep.Counts)
	rep.VerdictNote = noteOf(rep.Verdict, rep.Counts, goos, brokeAt)
	rep.ElapsedMs = time.Since(started).Milliseconds()
	return rep
}

func runStep(ctx context.Context, exec Executer, s Step, goos string, sr *StepResult) {
	if exec == nil {
		sr.Status = StatusFailed
		sr.Error = "没给执行的法子 —— 这一条没敲出去"
		return
	}
	sec := s.TimeoutSec
	if sec <= 0 {
		sec = DefaultStepTimeoutSec
	}
	stepCtx, cancel := context.WithTimeout(ctx, time.Duration(sec)*time.Second)
	defer cancel()

	began := time.Now()
	res, err := exec(stepCtx, s.Run, time.Duration(sec)*time.Second)
	sr.ElapsedMs = time.Since(began).Milliseconds()

	if err != nil {
		switch {
		case errors.Is(err, ErrUnreachable):
			sr.Status = StatusAborted
			sr.Error = err.Error()
		case errors.Is(err, context.DeadlineExceeded) && stepCtx.Err() != nil && ctx.Err() == nil:
			sr.Status = StatusTimeout
			sr.Error = fmt.Sprintf("等了 %d 秒没回话", sec)
		default:
			sr.Status = StatusFailed
			sr.Error = err.Error()
		}
		return
	}

	text := combine(res)
	// ★ 退出码非 0 不算「没问到」：is-active 在服务停着时回 inactive + 退出码 3，
	//	这是答案。只有既没回话又非 0 才是真砸了。
	if res.ExitCode != 0 && strings.TrimSpace(text) == "" {
		sr.Status = StatusFailed
		sr.ExitCode = res.ExitCode
		sr.Error = fmt.Sprintf("什么都没说就走了（退出码 %d）—— 这一问没问到", res.ExitCode)
		return
	}
	sr.Status = StatusRan
	sr.ExitCode = res.ExitCode
	if res.ExitCode != 0 {
		sr.Note = fmt.Sprintf("退出码 %d（命令照实回了话，按问到算）", res.ExitCode)
	}
	hits, hitNos := scanMarks(s.Marks, text)
	sr.Hits = hits
	sr.Output, sr.Truncated = clip(text, hitNos)
	if sr.Truncated > 0 {
		sr.Note = joinNote(sr.Note, fmt.Sprintf("还有 %d 行没显示（关键词按全文数的，命中的那几行单独列在下面）", sr.Truncated))
	}
}

// scanMarks 按全文逐行匹关键词，一行对一个高亮只算一次。
// 回的第二项是全部命中的行号，clip 用它把落在截断线之后的那几行补回显示。
func scanMarks(marks []Mark, text string) ([]Hit, []int) {
	if len(marks) == 0 {
		return nil, nil
	}
	lines := strings.Split(text, "\n")
	hits := make([]Hit, 0, len(marks))
	var nos []int
	for _, m := range marks {
		h := Hit{Match: m.Match, Say: m.Say}
		re, err := regexp.Compile(m.Match)
		if err != nil {
			// Validate 会拦这种剧本；跑到这儿说明有人没校验就跑了。
			// 与其闷着不数，不如把话说在 Sample 里，别让它看着像「没命中」。
			h.Sample = []string{"这条高亮的正则编不出来，没参与匹配：" + m.Match}
			hits = append(hits, h)
			continue
		}
		for i, ln := range lines {
			if re.MatchString(ln) {
				h.Lines++
				nos = append(nos, i)
				if len(h.Sample) < 3 {
					h.Sample = append(h.Sample, strings.TrimSpace(ln))
				}
			}
		}
		hits = append(hits, h)
	}
	return hits, nos
}

// clip 留开头那截，另外把落在截断线之后的命中行按原文顺序补回来。
func clip(text string, hitNos []int) (string, int) {
	lines := strings.Split(text, "\n")
	if len(lines) <= MaxOutputLines {
		return text, 0
	}
	sort.Ints(hitNos)
	var extra []string
	seen := map[int]bool{}
	for _, n := range hitNos {
		if n < MaxOutputLines || n >= len(lines) || seen[n] {
			continue
		}
		seen[n] = true
		if len(extra) < maxExtraHitLines {
			extra = append(extra, lines[n])
		}
	}
	out := strings.Join(lines[:MaxOutputLines], "\n")
	if len(extra) > 0 {
		out += "\n\n—— 下面是命中关键词的行（它们本来落在没显示的那截里）——\n" + strings.Join(extra, "\n")
	}
	return out, len(lines) - MaxOutputLines
}

const maxExtraHitLines = 6

func combine(res Result) string {
	switch {
	case res.Stdout == "":
		return res.Stderr
	case res.Stderr == "":
		return res.Stdout
	default:
		return res.Stdout + "\n" + res.Stderr
	}
}

func tally(c *Counts, sr StepResult) {
	switch sr.Status {
	case StatusRan:
		c.Ran++
	case StatusFailed:
		c.Failed++
	case StatusTimeout:
		c.TimedOut++
	case StatusSkippedPlatform:
		c.SkippedPlatform++
	case StatusAborted:
		c.Aborted++
	}
}

func countWriteRan(steps []Step, results []StepResult) int {
	n := 0
	for i, sr := range results {
		if i < len(steps) && steps[i].Write && sr.Status != StatusSkippedPlatform && sr.Status != StatusAborted {
			n++
		}
	}
	return n
}

func countHitLines(results []StepResult) int {
	n := 0
	for _, sr := range results {
		for _, h := range sr.Hits {
			n += h.Lines
		}
	}
	return n
}

func verdictOf(c Counts) string {
	switch {
	case c.Total == 0:
		return VerdictEmpty
	case c.Aborted > 0:
		return VerdictUnreachable
	case c.Ran == 0 && c.SkippedPlatform > 0:
		return VerdictPlatformSkipped
	case c.Failed > 0 || c.TimedOut > 0:
		return VerdictStepFailed
	default:
		return VerdictOK
	}
}

// noteOf 那一句给人看的判定。数字全部来自 c，不另算。
func noteOf(verdict string, c Counts, goos string, brokeAt int) string {
	switch verdict {
	case VerdictEmpty:
		return "这本剧本一步都没有 —— 一步都没得问，先给它加几条"
	case VerdictUnreachable:
		// ★ 「断在第几条」和「问到几条」是两个数：中间有按系统跳过的条，
		//   把它们算进「问到」就等于替那台机器多答了几条。
		return fmt.Sprintf("这台机器问到一半不答话了：停在第 %d 条（前面问到 %d 条），后面 %d 条没问到 —— 先重连，再谈结论",
			brokeAt, c.Ran, c.Aborted)
	case VerdictPlatformSkipped:
		return fmt.Sprintf("这本剧本在 %s 上一条都没问到：%d 条是按别的系统写的 —— 不是没问题，是没问到", goos, c.SkippedPlatform)
	case VerdictStepFailed:
		return fmt.Sprintf("%d 条没问到答案（跑砸 %d 条、超时 %d 条），%d 条问到了",
			c.Failed+c.TimedOut, c.Failed, c.TimedOut, c.Ran)
	default:
		s := fmt.Sprintf("%d 条全问到了", c.Ran)
		if c.SkippedPlatform > 0 {
			s += fmt.Sprintf("，%d 条按系统跳过", c.SkippedPlatform)
		}
		if c.HitLines > 0 {
			s += fmt.Sprintf("，关键词命中 %d 处", c.HitLines)
		}
		if c.WriteRan > 0 {
			s += fmt.Sprintf("；其中 %d 条改了那台机器的东西", c.WriteRan)
		}
		return s
	}
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "；" + b
}
