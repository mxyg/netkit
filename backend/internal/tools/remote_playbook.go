package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/diag"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/playbook"
	"net.yuhox.com/netkit/internal/remote"
)

// pbs 体检剧本的存放处（内置的在代码里，自定义的在这目录）。由 main 装进来。
var pbs *playbook.Store

// SetPlaybook 装上剧本目录。没装的话剧本工具一律拒绝执行。
func SetPlaybook(s *playbook.Store) { pbs = s }

func needPlaybook() error {
	if pbs == nil {
		return ots.Errf(ots.ErrInternal, "体检剧本的目录没初始化，用不了")
	}
	return nil
}

// RegisterPlaybooks 把剧本相关的四个问装进注册表。
func RegisterPlaybooks(r *ots.Registry) {
	r.MustRegister(
		remotePlaybookListTool, remotePlaybookRunTool,
		remotePlaybookSaveTool, remotePlaybookDeleteTool,
	)
}

// ── remote.playbook.list（读：把有哪些本、每本问什么、几条会改东西说清楚）──

var remotePlaybookListTool = ots.Tool{
	Name:  "remote.playbook.list",
	Class: ots.ClassRead,
	Summary: "列出可用的体检剧本（内置的 + 自己存的）：每本问哪几问、哪几条会改那台机器、" +
		"分别适配哪种系统。跑之前先看这一问 —— 尤其是「改东西那几条」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "device": {"type": "string", "description": "可选：给了就顺带标出这一本在那台机器上有几条问得出去"}
	  }
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needPlaybook(); err != nil {
			return nil, err
		}
		var a struct {
			Device string `json:"device"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		goos := ""
		if a.Device != "" {
			if err := needRemote(); err != nil {
				return nil, err
			}
			d, err := mgr.Get(a.Device)
			if err != nil {
				return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
			}
			goos = d.OS
		}
		list := pbs.All()
		out := make([]map[string]any, 0, len(list))
		for _, p := range list {
			out = append(out, playbookEntry(p, goos))
		}
		code := "playbooks-listed"
		note := fmt.Sprintf("%d 本：%d 内置、%d 自存", len(out), countBuiltin(out), len(out)-countBuiltin(out))
		if goos != "" {
			note += fmt.Sprintf("；按设备系统 %s 数了每本问得出去的条数", goos)
		} else if a.Device != "" {
			// 认不出系统就不数：报了数人会当成「那台真是这样」。
			code = "playbooks-listed-os-unknown"
			note += "；但那台机器的系统还没探过，每本问得出去几条没数 —— 先跑一次 remote.device.probe"
		}
		return ots.Verdict{Code: code, Values: map[string]any{
			"playbooks":  out,
			"storeDir":   pbs.Dir(),
			"device":     a.Device,
			"deviceOs":   goos,
			"totalSteps": countSteps(list),
		}, Note: note}, nil
	},
}

func countBuiltin(entries []map[string]any) int {
	n := 0
	for _, e := range entries {
		if b, _ := e["builtIn"].(bool); b {
			n++
		}
	}
	return n
}

func countSteps(list []playbook.Playbook) int {
	n := 0
	for _, p := range list {
		n += len(p.Steps)
	}
	return n
}

// playbookEntry 一本剧本的清单条目。★ 步全文也带上：批准那一屏要逐条列出命令，
// 不让人「先跑一本才知道它要敲什么」。
func playbookEntry(p playbook.Playbook, goos string) map[string]any {
	writes, applies := 0, 0
	steps := make([]map[string]any, 0, len(p.Steps))
	for _, s := range p.Steps {
		if s.Write {
			writes++
		}
		onThis := s.AppliesTo(goos)
		if onThis && goos != "" {
			applies++
		}
		steps = append(steps, map[string]any{
			"name": s.Name, "run": s.Run, "why": s.Why,
			"os": s.OS, "write": s.Write, "timeoutSec": s.TimeoutSec,
			"marks": s.Marks, "appliesToDevice": onThis && goos != "",
		})
	}
	return map[string]any{
		"id": p.ID, "name": p.Name, "note": p.Note, "builtIn": p.BuiltIn,
		"steps": steps, "stepCount": len(p.Steps),
		"writeSteps": writes, "appliesOnDevice": applies,
	}
}

// ── remote.playbook.run（mutate：一条命令就能改那台机器，必须逐条批准 + 留痕）──

var remotePlaybookRunTool = ots.Tool{
	Name:  "remote.playbook.run",
	Class: ots.ClassMutate,
	Summary: "连上一台登记过的设备，照剧本把那一串命令逐条跑一遍，回来时每一条都带「问到没问到」" +
		"和关键词命中处。★ 整本一次批准（批准屏逐条列出要敲的命令，并念出几条会改东西）；" +
		"每条命令单独进审计；输出里的凭据先抹掉再回 —— 结果会发给 AI，也可能被打进诊断包。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["device", "playbook"],
	  "properties": {
	    "device":     {"type": "string", "description": "设备 ID（user@host）或 host"},
	    "playbook":   {"type": "string", "description": "剧本编号，见 remote.playbook.list"},
	    "timeoutSec": {"type": "integer", "minimum": 1, "maximum": 600, "description": "单条命令的等待秒数。剧本里每条自己标的优先，这个只兜住没标的；默认 20"}
	  }
	}`),
	// ★ 批准屏上那一段话：把每一条要敲的命令都念出来，并数清几条会改东西。
	//	只说「要跑一本剧本」等于没让人批准 —— 人批的是那些命令。
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Device   string `json:"device"`
			Playbook string `json:"playbook"`
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		if pbs == nil {
			return fmt.Sprintf("在设备 %s 上跑剧本 %s（剧本目录没就绪，命令列不出来）", a.Device, a.Playbook)
		}
		p, ok := pbs.Find(a.Playbook)
		if !ok {
			return fmt.Sprintf("在设备 %s 上跑剧本 %s（没这本，命令列不出来）", a.Device, a.Playbook)
		}
		var b strings.Builder
		writes := 0
		fmt.Fprintf(&b, "在设备 %s 上跑剧本「%s」（%s），共 %d 条：\n", a.Device, p.Name, p.ID, len(p.Steps))
		for i, s := range p.Steps {
			flag := ""
			if s.Write {
				flag = " ★会改东西"
				writes++
			}
			osTag := ""
			if len(s.OS) > 0 {
				osTag = " [" + strings.Join(s.OS, "/") + "]"
			}
			fmt.Fprintf(&b, "  %d. %s：%s%s%s\n", i+1, s.Name, s.Run, osTag, flag)
		}
		fmt.Fprintf(&b, "其中 %d 条会改那台机器的东西。输出会收回本机并记入审计。", writes)
		return b.String()
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needPlaybook(); err != nil {
			return nil, err
		}
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device     string `json:"device"`
			Playbook   string `json:"playbook"`
			TimeoutSec int    `json:"timeoutSec"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		p, ok := pbs.Find(a.Playbook)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "没有编号 %q 的剧本 —— remote.playbook.list 能列出有哪些本", a.Playbook)
		}
		// 先查登记再连接：系统没探过就不跑 —— 剧本里那些分系统的条会全被跳掉，
		// 跳掉的理由还是「这台不是 windows」这种猜出来的话。
		// （跑一遍剧本比连一次贵得多，不能连上了才发现问不出。）
		want, err := mgr.Get(a.Device)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		if want.OS == "" || want.OS == "unknown" {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"设备 %s 的系统还没探出来 —— 先跑一次 remote.device.probe 再跑剧本（不猜系统，猜错会把整本判成「没问到」）", want.ID)
		}
		// dial 里已经带了「连不上分哪种」的判定和 connect 审计
		d, c, x, err := dial(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		caller := ots.CallerFrom(ctx)
		mgr.Audit(caller, "playbook.run", d.ID,
			fmt.Sprintf("%s（%d 条，%d 条会改东西）", p.ID, len(p.Steps), countWrites(p)), "开始")

		rep := runPlaybook(ctx, &p, d.OS, a.TimeoutSec, execOnDevice(x, d, caller))
		mgr.Audit(caller, "playbook.run", d.ID, p.ID,
			fmt.Sprintf("结束：%s（问到 %d/%d 条）", rep.Verdict, rep.Counts.Ran, rep.Counts.Total))
		return playbookVerdict(rep, d), nil
	},
}

func countWrites(p playbook.Playbook) int {
	n := 0
	for _, s := range p.Steps {
		if s.Write {
			n++
		}
	}
	return n
}

// runPlaybook 在设备上跑一本剧本。
//
// fallbackSecs 是调用方给的「单条命令等多久」，只兜住剧本里没自己标的条 ——
// 剧本自己标的优先（journalctl 那条天生比 uptime 慢）。
func runPlaybook(ctx context.Context, p *playbook.Playbook, goos string, fallbackSecs int, exec playbook.Executer) *playbook.Report {
	return playbook.Run(ctx, withStepWaits(p, fallbackSecs), goos, exec)
}

// withStepWaits 把没标等待秒数的那些条填上调用方给的秒数。
// 抄一份填，不改原剧本 —— 内置那本是大家共用的。
func withStepWaits(p *playbook.Playbook, secs int) *playbook.Playbook {
	if secs <= 0 {
		return p
	}
	clone := *p
	clone.Steps = make([]playbook.Step, len(p.Steps))
	for i, s := range p.Steps {
		if s.TimeoutSec == 0 {
			s.TimeoutSec = secs
		}
		clone.Steps[i] = s
	}
	return &clone
}

// execOnDevice 真往设备上敲那一条。断了要报成「这台机器不答话了」，
// 不能报成「这条命令跑砸了」—— 后者会让人去改剧本，而该做的是重连。
//
// ★ 审计记的是命令和字节数，**不记输出**：输出里可能有口令，
//
//	而审计文件会被发给二线（它本身就是「别人能读的东西」）。
func execOnDevice(x remote.SSHExecer, d *remote.Device, caller string) playbook.Executer {
	return func(ctx context.Context, command string, wait time.Duration) (playbook.Result, error) {
		out, err := x.Exec(ctx, d, command, wait)
		if err != nil {
			if connBroken(err) {
				// ★ 这一条要留在审计里：「问到第几条断的」正是回头查那次现场要看的东西。
				mgr.Audit(caller, "playbook.step", d.ID, command, "断了，后面没问："+err.Error())
				return playbook.Result{}, fmt.Errorf("%w：%s", playbook.ErrUnreachable, err)
			}
			// 等到点没跑完：SSH 那层是超时，别的错才是这条命令有毛病。
			// ctx 那一路是给整体取消留的口子（remote.Exec 的超时现在带 %w，走前一判）。
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				mgr.Audit(caller, "playbook.step", d.ID, command,
					fmt.Sprintf("timeout: 没在 %s 内跑完", wait))
				return playbook.Result{}, fmt.Errorf("命令没在 %s 内跑完：%w", wait, context.DeadlineExceeded)
			}
			mgr.Audit(caller, "playbook.step", d.ID, command, "failed: "+err.Error())
			return playbook.Result{}, err
		}
		mgr.Audit(caller, "playbook.step", d.ID, command,
			fmt.Sprintf("exit=%d stdout=%dB stderr=%dB", out.ExitCode, len(out.Stdout), len(out.Stderr)))
		return playbook.Result{Stdout: out.Stdout, Stderr: out.Stderr, ExitCode: out.ExitCode}, nil
	}
}

// connBroken 分清「这台机器不答话了」和「这条命令跑砸了」。
//
// x/crypto/ssh 把底层连接错误包成了它自己的 wire 错误类型，errors.Is 到不了
// io.EOF —— 只看包装类型就会把一个真断线判成「命令有毛病」，
// 于是人去改剧本、改等待秒数，而该做的是重连。所以这里连文本一起认。
func connBroken(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	var ee *ssh.ExitMissingError
	if errors.As(err, &ee) {
		// 没回退出码就断了：会话是被掐的，不是命令跑砸的。
		return true
	}
	s := strings.ToLower(err.Error())
	// ssh: rejected: ... = 通道开不起来了（对端把会话撤了）；
	// 光认包装类型不够，x/crypto/ssh 把底层错误转成了它自己的字符串。
	for _, kw := range []string{"connection lost", "client has been closed", "broken pipe",
		"connection reset", "use of closed", "no such remote", "eof", "rejected: ",
		"server closed", "operation timed out"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// playbookVerdict 把执行结果整理成 OTS 的返回。★ 出去之前先脱敏：
// 剧本里常有 cat 配置、journalctl 这类会把口令带出来的命令。
func playbookVerdict(rep *playbook.Report, d *remote.Device) ots.Verdict {
	hits := scrubReport(rep)
	values := map[string]any{
		"device":        d.ID,
		"os":            rep.Goos,
		"playbook":      rep.PlaybookID,
		"playbookName":  rep.PlaybookName,
		"steps":         rep.Steps,
		"counts":        rep.Counts,
		"verdictNote":   rep.VerdictNote,
		"seconds":       float64(rep.ElapsedMs) / 1000,
		"writeStepsRan": rep.Counts.WriteRan,
		"askedSteps":    rep.Counts.Ran,
		"redacted":      hits,
		"redactedHow":   diag.HitList(hits),
		"nextStep":      playbookNextStep(rep.Verdict, rep.Counts),
	}
	return ots.Verdict{Code: rep.Verdict, Values: values, Note: rep.VerdictNote}
}

// playbookNextStep 每种判定下一步上哪儿。★ 判定说完不说这儿，
// 人拿着一个码还是不知道手往哪儿放。
func playbookNextStep(verdict string, c playbook.Counts) string {
	switch verdict {
	case playbook.VerdictEmpty:
		return "这本是空的 —— 用 remote.playbook.save 存几条评论再跑"
	case playbook.VerdictUnreachable:
		return "先重连那台机器（remote.device.probe），连上了再跑一遍；已问到的那几条不用重敲，结果里都在"
	case playbook.VerdictPlatformSkipped:
		return "这一本的条子全是按别的系统写的 —— 换一本对得上系统的，或者把那台机器的系统条补进剧本"
	case playbook.VerdictStepFailed:
		if c.TimedOut > 0 {
			return fmt.Sprintf("%d 条没跑完：加大等待秒数，或者把那条命令换成更窄的（journalctl 加 -n）再跑", c.TimedOut)
		}
		return fmt.Sprintf("%d 条什么都没回：多半是那台机器上没有这个命令（换写法）或者账号没权限（换账号）—— 明细里每条都留了退出码", c.Failed)
	default:
		if c.HitLines > 0 {
			return fmt.Sprintf("该问的都问到了，关键词命中 %d 处 —— 先看命中那几行后面那句「往哪儿看」，那是这本剧本录下来的经验", c.HitLines)
		}
		if c.WriteRan > 0 {
			return fmt.Sprintf("该问的都问到了；注意有 %d 条改了那台机器的东西，去审计里核对一下", c.WriteRan)
		}
		return "该问的都问到了，关键词一处没命中。症状还在就换一本更对症的剧本，或者走 net.troubleshoot 按症状问"
	}
}

// scrubReport 就地抹掉结果里可能带凭据的那几处，返回每类命中几次。
func scrubReport(rep *playbook.Report) map[string]int {
	total := map[string]int{}
	scrub := func(text string) string {
		clean, hits := diag.Scrub(text)
		for k, n := range hits {
			total[k] += n
		}
		return clean
	}
	for i := range rep.Steps {
		s := &rep.Steps[i]
		s.Command = scrub(s.Command)
		s.Output = scrub(s.Output)
		s.Error = scrub(s.Error)
		s.Note = scrub(s.Note)
		for j := range s.Hits {
			for k := range s.Hits[j].Sample {
				s.Hits[j].Sample[k] = scrub(s.Hits[j].Sample[k])
			}
		}
	}
	rep.VerdictNote = scrub(rep.VerdictNote)
	return total
}

// ── remote.playbook.save（mutate：往本机配置目录写一本剧本）──

var remotePlaybookSaveTool = ots.Tool{
	Name:  "remote.playbook.save",
	Class: ots.ClassMutate,
	Summary: "把一本剧本存进本机配置目录（新建、改自己那本、导入别人发来的都走它）。" +
		"★ 只写本机那一个 0600 的文件，不碰任何远程设备；内置那本不许覆盖。" +
		"内容不合式会把每一处毛病列出来，不只说「不合法」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["playbook"],
	  "properties": {
	    "playbook": {"type": "object", "description": "整本剧本：id、name、note、steps[]（每步 name/run/why/os/marks/write/timeoutSec）"},
	    "replace":  {"type": "boolean", "description": "改自己已存在的那本时给 true。默认 false —— 撞编号时不悄悄顶掉别人那本"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Playbook playbook.Playbook `json:"playbook"`
			Replace  bool              `json:"replace"`
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		writes := countWrites(a.Playbook)
		what := "新建一本"
		if a.Replace {
			what = "覆盖已有那一本"
		}
		return fmt.Sprintf("往本机剧本目录%s「%s」（%s，%d 条，其中 %d 条以后会改别的机器上的东西）。只写本机一个文件，不碰设备。",
			what, a.Playbook.Name, a.Playbook.ID, len(a.Playbook.Steps), writes)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needPlaybook(); err != nil {
			return nil, err
		}
		var a struct {
			Playbook playbook.Playbook `json:"playbook"`
			Replace  bool              `json:"replace"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if bad := playbook.Validate(&a.Playbook); len(bad) > 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument, "这本剧本不合式：%s", strings.Join(bad, "；"))
		}
		if err := pbs.Save(a.Playbook, a.Replace); err != nil {
			// 错误码集合是封闭的（[OTS 10.2]），没有 conflict —— 分别说在话里。
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		mgrNote := ""
		if mgr != nil {
			mgr.Audit(ots.CallerFrom(ctx), "playbook.save", a.Playbook.ID,
				fmt.Sprintf("%d 条，%d 条标了会改东西", len(a.Playbook.Steps), countWrites(a.Playbook)), "ok")
			mgrNote = "（已记入审计）"
		}
		return ots.Verdict{Code: "playbook-saved", Values: map[string]any{
			"playbook": a.Playbook.ID, "name": a.Playbook.Name,
			"stepCount": len(a.Playbook.Steps), "writeSteps": countWrites(a.Playbook),
			"storeDir": pbs.Dir(),
		}, Note: fmt.Sprintf("已存好「%s」，在「挑一本」那个下拉里就能找到它 %s", a.Playbook.Name, mgrNote)}, nil
	},
}

// ── remote.playbook.delete（mutate：删本机那一个文件）──

var remotePlaybookDeleteTool = ots.Tool{
	Name:  "remote.playbook.delete",
	Class: ots.ClassMutate,
	Summary: "删掉一本自己存的剧本（只删本机配置目录里那一个文件）。内置那本删不掉 —— " +
		"要改它的内容，把内容另存成新的一本。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["playbook"],
	  "properties": {
	    "playbook": {"type": "string", "description": "要删的剧本编号"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Playbook string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		name := a.Playbook
		if pbs != nil {
			if b, ok := pbs.Find(a.Playbook); ok {
				name = b.Name
			}
		}
		return fmt.Sprintf("删掉本机剧本目录里的「%s」（只删本机文件，不碰任何设备）", name)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needPlaybook(); err != nil {
			return nil, err
		}
		var a struct {
			Playbook string `json:"playbook"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		// 名字要在删之前拿：删完了再问，那句「已删掉 X」就只能报编号，
		// 而人在界面上认的是那本的名字。
		name := a.Playbook
		if b, ok := pbs.Find(a.Playbook); ok {
			name = b.Name
		}
		if err := pbs.Delete(a.Playbook); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		if mgr != nil {
			mgr.Audit(ots.CallerFrom(ctx), "playbook.delete", a.Playbook, "删本机剧本文件", "ok")
		}
		return ots.Verdict{Code: "playbook-deleted", Values: map[string]any{
			"playbook": a.Playbook, "name": name,
		}, Note: fmt.Sprintf("已删掉「%s」这本（内置的那些一直在）", name)}, nil
	},
}
