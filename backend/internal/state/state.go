// Package state 是「改系统之前先登记，崩了下次启动先还原」的那本账。
//
// ★★ 为什么所有会改系统的功能都必须先过这里（docs/设计.md 原则 2）：
//
//	现场改网络最怕的不是改错，是**改到一半断了**。
//	程序崩了、机器断电、用户拔了电源 —— 改动做了一半，
//	而"原来是什么样"只存在于那个已经没了的进程的内存里。
//	客户的机器就停在一个谁也不知道该怎么还原的状态上。
//
//	所以顺序必须是：**先把"原来是什么"落到盘上，再动手**。
//	反过来（先动手、成功了再记账）在崩溃窗口里等于没记。
//
// 这套模式在 relay 的 state/ 上验证过（程序崩了也能还原），这里是它的重写。
//
// ★ 对应 Ops Tool Spec [OTS-7.5]：改动应当在执行前持久化记录、执行后可回退，
// 使得批准与完成之间发生的中断留下可恢复的状态。
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Status 一笔改动的状态。
type Status string

const (
	// StatusPending 已登记、**还没动手**。
	// ★ 启动时看到它 = 上次崩在动手前后之间，必须按 Before 还原。
	StatusPending Status = "pending"
	// StatusApplied 已生效。还原时用 Before 回滚。
	StatusApplied Status = "applied"
	// StatusReverted 已还原，这笔账翻篇了。
	StatusReverted Status = "reverted"
)

// Entry 一笔改动。
type Entry struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // 改的是什么：dhcp-server / route / firewall ...
	// What 给人看的一句话：**批准框里显示的就是它**。
	// ★ [OTS-7.2] 批准请求必须说明将要作出的更改 —— 这一栏就是那句话的来源。
	What string `json:"what"`
	// Before 改之前是什么样。还原时照它恢复。
	// ★ 允许为空（表示"原来没有这个东西"），还原就是"把它删掉"。
	Before json.RawMessage `json:"before,omitempty"`
	// After 打算改成什么样。
	After  json.RawMessage `json:"after,omitempty"`
	Status Status          `json:"status"`
	At     time.Time       `json:"at"`
	Note   string          `json:"note,omitempty"`
}

// Journal 一本账。落在磁盘上，进程重启后还在。
type Journal struct {
	mu   sync.Mutex
	path string
	// entries 全部账目，按写入顺序。
	entries []Entry
}

// Open 打开（或新建）一本账。
func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("建账本目录失败：%w", err)
	}
	j := &Journal{path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return j, nil
		}
		return nil, fmt.Errorf("读账本失败：%w", err)
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &j.entries); err != nil {
			// ★ 账本坏了不能当成"没有账"：那会把"上次改了什么"整个丢掉。
			//   保留原文件另存一份，让人能人工恢复。
			bak := path + ".broken-" + time.Now().Format("20060102-150405")
			_ = os.WriteFile(bak, b, 0o600)
			return nil, fmt.Errorf("账本解不开（原文已另存到 %s，别删）：%w", bak, err)
		}
	}
	return j, nil
}

// flush 把账写回磁盘。
//
// ★ 先写临时文件再改名：直接覆盖写的话，写到一半断电就得到一个**半截的账本**，
// 而那比没有账本更糟 —— 它会被当成完整的读进来。
func (j *Journal) flush() error {
	b, err := json.MarshalIndent(j.entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("写账本失败：%w", err)
	}
	return os.Rename(tmp, j.path)
}

// Register 登记一笔**还没动手**的改动。返回它的 ID。
//
// ★★ 必须在真正动手**之前**调用，并且等它返回成功再动手。
// 顺序反了，崩溃窗口里这笔改动就是无账可查的。
func (j *Journal) Register(kind, what string, before, after any) (string, error) {
	bb, err := toRaw(before)
	if err != nil {
		return "", fmt.Errorf("登记失败（before 序列化不了）：%w", err)
	}
	ab, err := toRaw(after)
	if err != nil {
		return "", fmt.Errorf("登记失败（after 序列化不了）：%w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	e := Entry{
		ID:   fmt.Sprintf("%d-%d", time.Now().UnixNano(), len(j.entries)),
		Kind: kind, What: what, Before: bb, After: ab,
		Status: StatusPending, At: time.Now(),
	}
	j.entries = append(j.entries, e)
	if err := j.flush(); err != nil {
		// 落盘失败就**不要动手** —— 宁可这次改不成，也不要改了却没账
		j.entries = j.entries[:len(j.entries)-1]
		return "", err
	}
	return e.ID, nil
}

// MarkApplied 标记这笔改动已经生效。
func (j *Journal) MarkApplied(id string) error { return j.setStatus(id, StatusApplied, "") }

// MarkReverted 标记这笔改动已经还原。
func (j *Journal) MarkReverted(id, note string) error { return j.setStatus(id, StatusReverted, note) }

// Drop 丢掉一笔登记了但**没动手**的改动（比如用户点了取消、或者执行前就失败了）。
func (j *Journal) Drop(id, why string) error { return j.setStatus(id, StatusReverted, why) }

func (j *Journal) setStatus(id string, s Status, note string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.entries {
		if j.entries[i].ID == id {
			j.entries[i].Status = s
			if note != "" {
				j.entries[i].Note = note
			}
			return j.flush()
		}
	}
	return fmt.Errorf("账本里没有 %s 这笔", id)
}

// Outstanding 还没了结的账：pending（崩在动手前后之间）和 applied（生效中）。
//
// ★★ 启动时拿它来决定要不要还原。两种都要管：
//   - pending  上次崩在"登记了但不知道动没动手"，**必须当成动过**去还原
//     （当成没动过的话，真动过的那次就永远还原不了了）
//   - applied  正在生效中的改动，用户重启程序时按配置决定是否自动还原
func (j *Journal) Outstanding() []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []Entry
	for _, e := range j.entries {
		if e.Status == StatusPending || e.Status == StatusApplied {
			out = append(out, e)
		}
	}
	return out
}

// All 全部账目（只读副本）。
func (j *Journal) All() []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]Entry(nil), j.entries...)
}

func toRaw(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
