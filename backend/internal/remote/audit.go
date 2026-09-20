package remote

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// AuditEntry 一条审计记录。
//
// ★★ 设计里两条不随 remote.notify_target 变的规矩之一：
//
//	**审计日志照记**。静默模式只关目标机屏幕上的提示，不关留痕 ——
//	出了事要能查得出谁在什么时候连过谁。这也是购买方履行
//	告知义务时的凭据（docs/设计.md「责任归属」）。
type AuditEntry struct {
	At     string `json:"at"`
	Actor  string `json:"actor"`  // 谁调的：http:127.0.0.1:xxx / mcp / 界面
	Action string `json:"action"` // 干了什么：exec / file.push / desktop.open …
	Target string `json:"target"` // 对哪台设备
	Detail string `json:"detail"` // 具体参数（命令、路径 —— 已脱敏，无凭据）
	Result string `json:"result"` // 结果如何
}

func (m *Manager) auditPath() string { return filepath.Join(m.dir, "audit.jsonl") }

// Audit 追加一条审计。JSONL 追加写：进程崩了也只丢正在写的那一行，
// 已落盘的记录都在。
func (m *Manager) Audit(actor, action, target, detail, result string) {
	if actor == "" {
		actor = "unknown"
	}
	e := AuditEntry{
		At: time.Now().Format(time.RFC3339), Actor: actor,
		Action: action, Target: target, Detail: detail, Result: result,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := os.OpenFile(m.auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// AuditTail 取最近 n 条（时间正序返回）。n<=0 取全部（封顶 1000）。
func (m *Manager) AuditTail(n int) []AuditEntry {
	if n <= 0 || n > 1000 {
		n = 1000
	}
	f, err := os.Open(m.auditPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}
