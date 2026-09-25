// Package playbook 把「连上一台设备，挨个问那几问」录成一份能看、能改、能给的剧本。
//
// 为什么要它：现场最常见的做法是一个人 ssh 上去把 uptime、ss、journalctl 挨敲一遍，
// 换个人敲的顺序就不一样了，敲完也没留下「问过什么」。设计里点名要把
// 2026-09-19 那一路（盒子 40 路只出 11 路）原样录成内置剧本 ——
// 录下来的东西得能跑、能改、能发给同事，所以这里只留声明式的剧本，
// 不留任何「跑到一半再让 AI 想下一步」。
//
// 这个包一概不碰网络：执行由调用方注入（见 Runner），它只管剧本长什么样、
// 合不合式、存在哪儿。
package playbook

import (
	"fmt"
	"regexp"
	"strings"
)

// 一步在哪些系统上问得出去。空 = 哪都一样。
const (
	Linux   = "linux"
	Darwin  = "darwin"
	Windows = "windows"
)

// Mark 一条日志上的关键词和「命中了说明什么」。
//
// ★ 那句 Say 不是装饰：没有它，界面上就只是几个字变红，
//
//	人还是不知道命中的东西要不要紧。它必须说下一步该往哪儿看。
type Mark struct {
	Match string `json:"match"`
	Say   string `json:"say"`
}

// Step 剧本里的一条：一句给人看的名字、一条要敲的命令、为什么问它。
type Step struct {
	Name string `json:"name"`
	Run  string `json:"run"`
	Why  string `json:"why,omitempty"`

	// OS 限定这一条只在哪类系统上问。同一问在 Linux 和 Windows 上
	// 命令不同，与其在代码里分支，不如并排写两条、各标各的系统。
	OS []string `json:"os,omitempty"`

	Marks []Mark `json:"marks,omitempty"`

	// Write 旗子：这一条会改那台机器的东西（重启服务、清缓存、导包）。
	//	★ 界面上它单独一色，批准那一步会把带旗子的条数一并念给人听。
	Write bool `json:"write,omitempty"`

	TimeoutSec int `json:"timeoutSec,omitempty"`
}

// Playbook 一本剧本。
type Playbook struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Note  string `json:"note,omitempty"`
	Steps []Step `json:"steps"`

	// BuiltIn 由包填，不从 JSON 来 —— 让人手写的剧本没法自称内置。
	BuiltIn bool `json:"-"`
}

// AppliesTo 这一条要不要在这类系统上问。
func (s Step) AppliesTo(goos string) bool {
	if len(s.OS) == 0 {
		return true
	}
	for _, o := range s.OS {
		if strings.EqualFold(o, goos) {
			return true
		}
	}
	return false
}

// 剧本 id 会被拼进落盘路径，所以只许最朴素的那批字符。
func validID(id string) bool {
	if id == "" || len(id) > 64 || id == "." || id == ".." {
		return false
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// Validate 一次把毛病列全，返回的都是给人看的话。
//
// ★ 不许只回「不合法」：这些句子会原样出现在界面上，
//
//	人得知道改哪一行。
func Validate(p *Playbook) []string {
	var bad []string
	if p.ID == "" {
		bad = append(bad, "没给剧本编号（保存和分享都靠它）")
	} else if !validID(p.ID) {
		bad = append(bad, fmt.Sprintf("编号 %q 不合式 —— 只用字母、数字和 - _ .，不许有路径分隔符（它会被拼进文件名）", p.ID))
	}
	if p.Name == "" {
		bad = append(bad, "没给剧本名字")
	}
	if len(p.Steps) == 0 {
		bad = append(bad, "这本剧本一步都没有 —— 跑它等于什么都没问")
		return bad
	}
	for i, s := range p.Steps {
		at := fmt.Sprintf("第 %d 步", i+1)
		if s.Name != "" {
			at = fmt.Sprintf("第 %d 步「%s」", i+1, s.Name)
		}
		if s.Name == "" {
			bad = append(bad, at+"没有名字 —— 界面上那一行就只剩裸命令")
		}
		if strings.TrimSpace(s.Run) == "" {
			bad = append(bad, at+"没有命令")
		}
		if s.Why == "" {
			bad = append(bad, at+"没写为什么问这一条")
		}
		for _, o := range s.OS {
			switch strings.ToLower(o) {
			case Linux, Darwin, Windows:
			default:
				bad = append(bad, fmt.Sprintf("%s 写了不认得的系统 %q（只有 linux / darwin / windows）", at, o))
			}
		}
		for j, m := range s.Marks {
			if _, err := regexp.Compile(m.Match); err != nil {
				bad = append(bad, fmt.Sprintf("%s 第 %d 条高亮的正则编不出来：%v", at, j+1, err))
			}
			if strings.TrimSpace(m.Say) == "" {
				bad = append(bad, fmt.Sprintf("%s 第 %d 条高亮没给说明：命中了要往哪儿看", at, j+1))
			}
		}
		if s.TimeoutSec < 0 {
			bad = append(bad, at+"的等待秒数是负数")
		}
	}
	return bad
}
