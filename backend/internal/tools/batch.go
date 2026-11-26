package tools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
)

// ═══════════════════════════════════════════════════════════════════════
// 设备分组/标签（remote.device.group）与批量任务（remote.task.*）
//
// 分组：现场 30 台设备一锅粥 —— 标签只写 NetKit 自己的登记簿（read 档，
// 同 device.add 先例），不碰任何机器。
//
// 批量：对多台跑同一条命令，并行收结果。run 起任务立刻回 taskId（不阻塞），
// status 拉进度和每台的结果 —— 一排摄像头盒子逐台点等于浪费时间。
// 每台的执行与审计同 remote.exec 一条不省；批准框把机器清单摊开。
// ═══════════════════════════════════════════════════════════════════════

// ── remote.device.group（read 档：只动 NetKit 的登记簿）──

var deviceGroupTool = ots.Tool{
	Name:  "remote.device.group",
	Class: ots.ClassRead,
	Summary: "给设备打/摘标签（如「3F 机柜」「回传流」「演示」）。只写 NetKit 自己的登记簿，不碰任何机器。" +
		"设备列表按标签过滤，批量任务也能按标签圈机器。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {
	    "device": {"type": "string", "description": "设备 ID 或 host；批量打标签用 device.list 里查到的 ID"},
	    "add": {"type": "array", "items": {"type": "string"}, "description": "要打的标签（重复的自动忽略）"},
	    "remove": {"type": "array", "items": {"type": "string"}, "description": "要摘掉的标签"},
	    "clear": {"type": "boolean", "description": "true = 清空这台的全部标签"}
	  }
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device string
			Add    []string
			Remove []string
			Clear  bool
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		d, err := mgr.Get(a.Device)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
		}
		before := append([]string(nil), d.Tags...)
		switch {
		case a.Clear:
			d.Tags = nil
		default:
			set := map[string]bool{}
			for _, t := range d.Tags {
				set[t] = true
			}
			for _, t := range a.Remove {
				delete(set, t)
			}
			for _, t := range a.Add {
				t = strings.TrimSpace(t)
				if t != "" {
					set[t] = true
				}
			}
			d.Tags = nil
			for t := range set {
				d.Tags = append(d.Tags, t)
			}
		}
		if err := mgr.UpdateDevice(d); err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "device.group", d.ID,
			fmt.Sprintf("标签 %v → %v", before, d.Tags), "ok")
		return ots.Verdict{Code: "tagged", Values: map[string]any{
			"device": d.ID, "tags": d.Tags,
		}, Note: fmt.Sprintf("%s 的标签：%v", d.ID, d.Tags)}, nil
	},
}

// ── 批量任务登记簿 ──

type batchTask struct {
	ID       string
	Devices  []string
	Command  string
	Timeout  int
	Mu       sync.Mutex
	Status   string // running | done
	Started  time.Time
	Finished time.Time
	Results  []batchResult
}

type batchResult struct {
	Device   string `json:"device"`
	OK       bool   `json:"ok"`
	Code     string `json:"code"`
	ExitCode int    `json:"exitCode,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Err      string `json:"err,omitempty"`
	Seconds  float64 `json:"seconds,omitempty"`
}

var batchTasks = struct {
	mu sync.Mutex
	m  map[string]*batchTask
	order []string
}{m: map[string]*batchTask{}}

func batchTaskOf(id string) (*batchTask, bool) {
	batchTasks.mu.Lock()
	defer batchTasks.mu.Unlock()
	t, ok := batchTasks.m[id]
	return t, ok
}

// batchKeep 只留最近 20 条，防登记簿无界长。
func batchKeep(id string) {
	batchTasks.mu.Lock()
	defer batchTasks.mu.Unlock()
	batchTasks.order = append(batchTasks.order, id)
	for len(batchTasks.order) > 20 {
		old := batchTasks.order[0]
		batchTasks.order = batchTasks.order[1:]
		delete(batchTasks.m, old)
	}
}

// ── remote.task.run（mutate）──

var taskRunTool = ots.Tool{
	Name:  "remote.task.run",
	Class: ots.ClassMutate,
	Summary: "对**多台**设备跑同一条命令，并行收结果（最多 4 台同时在跑）。立刻回 taskId 不阻塞；" +
		"用 remote.task.status 拉进度和每台的输出。也可以只给 tag，对打了那个标签的所有设备跑。" +
		"★ 命令能干什么不可预知，批准框会把机器清单摊开 —— 每台的执行与审计同 remote.exec。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false,
	  "properties": {
	    "devices": {"type": "array", "items": {"type": "string"}, "description": "设备 ID/host 清单。和 tag 二选一"},
	    "tag": {"type": "string", "description": "对打了这个标签的所有设备跑（remote.device.group 打标签）"},
	    "command": {"type": "string", "description": "每台都跑同一条这个"},
	    "timeoutSec": {"type": "integer", "minimum": 1, "maximum": 3600, "description": "每台的超时秒数，默认 60"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Devices []string
			Tag     string
			Command string
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		who := strings.Join(a.Devices, "、")
		if a.Tag != "" {
			who = "打了「" + a.Tag + "」标签的全部设备"
		}
		return fmt.Sprintf("在 %s 上各执行同一条命令：%s（每台的输出收回、逐台审计）", who, a.Command)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Devices   []string
			Tag       string
			Command   string
			TimeoutSec int
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if strings.TrimSpace(a.Command) == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument, "command 不能是空的")
		}
		targets := a.Devices
		if a.Tag != "" {
			targets = nil
			for _, m := range mgr.Devices() {
				if id, _ := m["id"].(string); id != "" {
					if d, err := mgr.Get(id); err == nil && hasTag(d.Tags, a.Tag) {
						targets = append(targets, id)
					}
				}
			}
			if len(targets) == 0 {
				return nil, ots.Errf(ots.ErrInvalidArgument, "没有打了「%s」标签的设备", a.Tag)
			}
		}
		if len(targets) == 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument, "devices 和 tag 至少给一个 —— 不知道对哪些机器跑")
		}
		if len(targets) > 50 {
			return nil, ots.Errf(ots.ErrInvalidArgument, "一次最多 50 台（%d 台）。分批跑", len(targets))
		}
		if a.TimeoutSec <= 0 {
			a.TimeoutSec = 60
		}
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id := "task-" + hex.EncodeToString(b)[:8]
		t := &batchTask{
			ID: id, Devices: targets, Command: a.Command,
			Timeout: a.TimeoutSec, Status: "running", Started: time.Now(),
		}
		batchTasks.mu.Lock()
		batchTasks.m[id] = t
		batchTasks.mu.Unlock()
		batchKeep(id)

		// 并行跑，最多 4 台同时连（再多就是对自己的出口带宽和对方的 sshd 同时施压）
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		caller := ots.CallerFrom(ctx)
		for _, target := range targets {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				r := runOne(ctx, target, a.Command, a.TimeoutSec)
				t.Mu.Lock()
				t.Results = append(t.Results, r)
				t.Mu.Unlock()
				if r.OK {
					mgr.Audit(caller, "task.exec", target,
						fmt.Sprintf("批量[%s] %s", id, a.Command),
						fmt.Sprintf("exit=%d stdout=%dB", r.ExitCode, len(r.Stdout)))
				} else {
					mgr.Audit(caller, "task.exec", target,
						fmt.Sprintf("批量[%s] %s", id, a.Command),
						"failed: "+firstNonEmpty(r.Err, r.Stderr))
				}
			}(target)
		}
		go func() {
			wg.Wait()
			t.Mu.Lock()
			t.Status = "done"
			t.Finished = time.Now()
			t.Mu.Unlock()
		}()
		return ots.Verdict{Code: "task-started", Values: map[string]any{
			"task": id, "count": len(targets), "command": a.Command,
		}, Note: fmt.Sprintf("批量任务 %s 已起：%d 台并行在跑。remote.task.status 拉进度。", id, len(targets))}, nil
	},
}

// runOne 对一台执行，结果收进 batchResult（不 panic、超时算失败不炸整个任务）。
func runOne(ctx context.Context, device, command string, timeoutSec int) batchResult {
	d, c, _, err := dial(ctx, device)
	if err != nil {
		return batchResult{Device: device, OK: false, Code: "connect-failed", Err: err.Error()}
	}
	defer c.Close()
	out, err := remote.Exec(ctx, c, d, command, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		return batchResult{Device: d.ID, OK: false, Code: "exec-failed", Err: err.Error()}
	}
	r := batchResult{
		Device: d.ID, OK: out.ExitCode == 0,
		Code: "exec-ok", ExitCode: out.ExitCode,
		Stdout: out.Stdout, Stderr: out.Stderr, Seconds: out.Seconds,
	}
	if out.ExitCode != 0 {
		r.Code = "exec-nonzero"
	}
	return r
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// ── remote.task.status（read）──

var taskStatusTool = ots.Tool{
	Name:  "remote.task.status",
	Class: ots.ClassRead,
	Summary: "拉一个批量任务的进度：跑完几台、每台的退出码和输出。done=true 就是全部跑完。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["task"],
	  "properties": {"task": {"type": "string", "description": "remote.task.run 回来的任务 ID"}}
	}`),
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct{ Task string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		t, ok := batchTaskOf(a.Task)
		if !ok {
			return nil, ots.Errf(ots.ErrInvalidArgument, "没有这个任务（只留最近 20 条）：先 remote.task.run")
		}
		t.Mu.Lock()
		defer t.Mu.Unlock()
		okCount := 0
		for _, r := range t.Results {
			if r.OK {
				okCount++
			}
		}
		return map[string]any{
			"task": t.ID, "command": t.Command,
			"devices": t.Devices, "total": len(t.Devices),
			"finished": len(t.Results), "ok": okCount,
			"status": t.Status, "done": t.Status == "done",
			"started": t.Started.Format(time.RFC3339),
			"results": t.Results,
		}, nil
	},
}
