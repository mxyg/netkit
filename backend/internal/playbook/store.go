package playbook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Store 是落在用户配置目录里的那些自定义剧本。
//
// 一本一个文件：分享就是发那个文件（或者界面上复制的那段 JSON），
// 坏了只坏一本，不会像一个大文件那样一处解不开就全没了。
type Store struct {
	dir string
}

func NewStore(dir string) *Store { return &Store{dir: dir} }

// DefaultDir 剧本该落在哪儿 —— 和远程设备登记、诊断包同一个配置目录下。
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("找不到用户配置目录，剧本没地方存：%w", err)
	}
	return filepath.Join(base, "yuhox-netkit", "playbooks"), nil
}

// Dir 剧本落在哪个目录。界面上要说清文件在哪儿，人才知道怎么发给同事、
// 怎么备份 —— 只说「已保存」等于把人锁在我们的界面里。
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

// All 内置在前，已保存的按名字排后面。
func (s *Store) All() []Playbook {
	out := Builtins()
	byID := map[string]bool{}
	for _, p := range out {
		byID[p.ID] = true
	}
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p, err := s.read(filepath.Join(s.dir, e.Name()))
		if err != nil || byID[p.ID] {
			// 解不开的那本直接跳过：界面上「有一本读不出来」比整页打不开好，
			// 坏文件留在原地等人看，不悄悄删。
			continue
		}
		out = append(out, p)
		byID[p.ID] = true
	}
	return out
}

// Find 按编号取一本（内置和已保存都算）。
func (s *Store) Find(id string) (Playbook, bool) {
	for _, p := range s.All() {
		if p.ID == id {
			return p, true
		}
	}
	return Playbook{}, false
}

// Save 存一本自定义剧本。
//
// ★ 两道拦子：不许盖内置（否则「照着官方那本跑」会变成假的）；
//
//	以及同编号已经有一本时，得由调用方明说「我是改这一本」（replace=true）。
//	别人发来一本恰好撞编号的，默认不许把人家那本悄悄换掉 ——
//	「新建」和「编辑」在界面上是两个动作，到这里就该是两个参数。
func (s *Store) Save(p Playbook, replace bool) error {
	if bad := Validate(&p); len(bad) > 0 {
		return errors.New(strings.Join(bad, "；"))
	}
	for _, b := range Builtins() {
		if b.ID == p.ID {
			return fmt.Errorf("编号 %q 是内置剧本的 —— 自定义的换一个，内置那本不改", p.ID)
		}
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("建剧本目录失败：%w", err)
	}
	file := s.path(p.ID)
	// 路径再核一遍：id 的校验已经挡住了分隔符，这一道是给以后的改动兜底的
	cleaned := filepath.Clean(file)
	if rel := filepath.Base(cleaned); rel != p.ID+".json" || filepath.Dir(cleaned) != filepath.Clean(s.dir) {
		return fmt.Errorf("编号 %q 落不到剧本目录里", p.ID)
	}
	if _, err := os.Stat(cleaned); err == nil && !replace {
		had, rerr := s.read(cleaned)
		if rerr != nil {
			return fmt.Errorf("已有剧本文件读不出来，先别存：%w", rerr)
		}
		return fmt.Errorf("编号 %q 已经有一本了（%s）—— 要改它就选「保存修改」，别用新建顶掉它", p.ID, had.Name)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("看剧本目录失败：%w", err)
	}
	p.BuiltIn = false
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := cleaned + ".tmp"
	// 0600：剧本里可能写着「只在这台机器上管用」的口令或 token
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("写剧本失败：%w", err)
	}
	return os.Rename(tmp, cleaned)
}

// Delete 删掉一本自定义剧本；内置的删不了。
func (s *Store) Delete(id string) error {
	if !validID(id) {
		return fmt.Errorf("编号 %q 不合式", id)
	}
	for _, b := range Builtins() {
		if b.ID == id {
			return fmt.Errorf("%q 是内置剧本，删不掉 —— 要改它就把内容另存成一本", id)
		}
	}
	file := s.path(id)
	if filepath.Base(filepath.Clean(file)) != id+".json" || filepath.Dir(filepath.Clean(file)) != filepath.Clean(s.dir) {
		return fmt.Errorf("编号 %q 落不到剧本目录里", id)
	}
	if err := os.Remove(file); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("没有编号 %q 的自定义剧本", id)
		}
		return err
	}
	return nil
}

func (s *Store) read(file string) (Playbook, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return Playbook{}, err
	}
	var p Playbook
	if err := json.Unmarshal(b, &p); err != nil {
		return Playbook{}, fmt.Errorf("%s 解不开：%w", filepath.Base(file), err)
	}
	if bad := Validate(&p); len(bad) > 0 {
		return Playbook{}, fmt.Errorf("%s 不合式：%v", filepath.Base(file), bad)
	}
	return p, nil
}
