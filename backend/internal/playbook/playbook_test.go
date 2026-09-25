package playbook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ 这个包的全部价值在于「原样录下来、别人拿去照着跑」。
//
//	内置那本因此不只是内容，它还得自己过校验 —— 内置过不了校验，
//	界面一开就是一片红，等于把我们的样板戏演砸了。
func Test内置剧本自己得过校验(t *testing.T) {
	for _, p := range Builtins() {
		if bad := Validate(&p); len(bad) > 0 {
			t.Errorf("内置「%s」没过校验：%v", p.Name, bad)
		}
	}
}

func Test每一步都有名字和为什么(t *testing.T) {
	for _, p := range Builtins() {
		if len(p.Steps) == 0 {
			t.Fatalf("内置「%s」一步都没有", p.Name)
		}
		for i, s := range p.Steps {
			if s.Name == "" {
				t.Errorf("%s 第 %d 步没名字 —— 界面上那一行就只有裸命令", p.Name, i+1)
			}
			if s.Why == "" {
				t.Errorf("%s「%s」没写为什么问这一条", p.Name, s.Name)
			}
		}
	}
}

// ★★ 那一路的结论是「帧池容量按 1080p 建、相机实际出 2K，40 路只出 11 路」。
//
//	这条要钉的是：剧本跑完之后，人在日志里能不能一眼看到那句话。
//	没有这一条高亮，跑完还得人去 grep —— 那本剧本就白录了。
func Test内置那一路必须把帧池那一问问出来(t *testing.T) {
	var pb *Playbook
	for i, p := range Builtins() {
		if p.ID == BuiltinBoxCheck {
			pb = &Builtins()[i]
		}
	}
	if pb == nil {
		t.Fatal("没有内置的盒子体检剧本")
	}
	var hit *Step
	for i, s := range pb.Steps {
		for _, m := range s.Marks {
			if strings.Contains(m.Say, "帧池") {
				hit = &pb.Steps[i]
			}
		}
	}
	if hit == nil {
		t.Fatal("整本里没有一条高亮说到帧池 —— 那一路的主症状没录进来")
	}
	if !strings.Contains(hit.Run, "argus") && !strings.Contains(hit.Run, "engine") {
		t.Errorf("命中帧池的那一条问的不是服务日志：%q", hit.Run)
	}
	// 显存/GPU 占用那一问也得在：那次就是靠它对上「池子建小了」
	var gpu bool
	for _, s := range pb.Steps {
		if strings.Contains(s.Name, "GPU") || strings.Contains(s.Name, "NPU") {
			gpu = true
		}
	}
	if !gpu {
		t.Error("没有 GPU/NPU 占用那一问 —— 设计里点名要的一项")
	}
}

// 会改东西的那几条必须单独标出来：批准口径和界面颜色都跟着这个旗子走。
func Test写操作那几条必须标出来(t *testing.T) {
	for _, p := range Builtins() {
		var writes int
		for _, s := range p.Steps {
			if s.Write && (s.Name == "" || !strings.Contains(s.Why, "改")) {
				t.Errorf("%s「%s」标了会改东西，却没写清改的是什么", p.Name, s.Name)
			}
			if s.Write {
				writes++
			}
		}
		if writes == 0 {
			t.Errorf("内置「%s」一条写操作都没有 —— 设计里点名要有「常用一键动作」", p.Name)
		}
	}
}

func Test校验拒绝的几种写法(t *testing.T) {
	ok := Step{Name: "看一眼", Run: "uptime", Why: "它多久没重启了"}
	cases := []struct {
		what string
		p    Playbook
		want string // 错误里必须出现的词
	}{
		{"编不出的正则", Playbook{ID: "a", Name: "n", Steps: []Step{
			{Name: "x", Run: "y", Why: "z", Marks: []Mark{{Match: "(", Say: "命中"}}}}}, "正则"},
		{"高亮没说明", Playbook{ID: "a", Name: "n", Steps: []Step{
			{Name: "x", Run: "y", Why: "z", Marks: []Mark{{Match: "err", Say: ""}}}}}, "说明"},
		{"没命令的一步", Playbook{ID: "a", Name: "n", Steps: []Step{{Name: "x", Why: "z"}}}, "命令"},
		{"没名字的一步", Playbook{ID: "a", Name: "n", Steps: []Step{{Run: "y", Why: "z"}}}, "名字"},
		{"不认得的系统", Playbook{ID: "a", Name: "n", Steps: []Step{
			{Name: "x", Run: "y", Why: "z", OS: []string{"solaris"}}}}, "系统"},
		{"一条都没有", Playbook{ID: "a", Name: "n"}, "一步"},
		{"没名字这本", Playbook{ID: "a", Name: ""}, ""}, // 只要非空即可，具体词不钉
	}
	for _, c := range cases {
		got := Validate(&c.p)
		if len(got) == 0 {
			t.Errorf("%s：该校验出来却放过了", c.what)
			continue
		}
		if c.want != "" && !strings.Contains(strings.Join(got, "|"), c.want) {
			t.Errorf("%s：错话说不到点上：%v（希望出现「%s」）", c.what, got, c.want)
		}
	}
	// 正反例：一条合式的必须过
	if bad := Validate(&Playbook{ID: "a", Name: "n", Steps: []Step{ok}}); len(bad) > 0 {
		t.Errorf("合式的剧本被拦了：%v", bad)
	}
}

// ★ id 会拼进文件路径：不拦住 `../../etc/passwd` 这种，
//
//	一个别人发来的剧本就能写到我们配置目录外面去。
func Test校验拦住会跑出目录的id(t *testing.T) {
	for _, id := range []string{"../x", "a/b", "..", "中文名", ""} {
		p := Playbook{ID: id, Name: "n", Steps: []Step{{Name: "x", Run: "y", Why: "z"}}}
		if len(Validate(&p)) == 0 {
			t.Errorf("id %q 放过了 —— 它会被拼进落盘路径", id)
		}
	}
}

func Test存进去读得出来(t *testing.T) {
	s := NewStore(t.TempDir())
	p := Playbook{ID: "my-check", Name: "我那本", Steps: []Step{{Name: "看一眼", Run: "uptime", Why: "多久没重启"}}}
	if err := s.Save(p, false); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Find("my-check")
	if !ok {
		t.Fatal("存了读不着")
	}
	if got.Name != p.Name || len(got.Steps) != 1 || got.BuiltIn {
		t.Errorf("往返不一致：%+v", got)
	}
	all := s.All()
	if len(all) != len(Builtins())+1 {
		t.Errorf("一共 %d 本，期望内置 %d + 保存 1", len(all), len(Builtins()))
	}
}

func Test落盘只能自己看得见(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Save(Playbook{ID: "x1", Name: "n", Steps: []Step{{Name: "a", Run: "b", Why: "c"}}}, false); err != nil {
		t.Fatal(err)
	}
	var found string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			found = p
			if fi.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s 的权限 %o —— 剧本里可能带着口令，同组和其他人读不到",
					filepath.Base(p), fi.Mode().Perm())
			}
		}
		return nil
	})
	if found == "" {
		t.Error("没落盘")
	}
}

func Test内置那本不许覆盖也不许删(t *testing.T) {
	s := NewStore(t.TempDir())
	b := Builtins()[0]
	if err := s.Save(b, true); err == nil {
		t.Error("保存盖掉了内置 —— 界面就会有一本「看着是官方、其实是改过的」")
	}
	if err := s.Delete(b.ID); err == nil {
		t.Error("内置被删了")
	}
	if err := s.Delete("没有这一本"); err == nil {
		t.Error("删一本不存在的说成功了")
	}
}

// 两本不同的剧本撞同一个 id：必须报错，不许悄悄把人家那本换掉。
func Test撞名不许顶掉别人那本(t *testing.T) {
	s := NewStore(t.TempDir())
	first := Playbook{ID: "same", Name: "第一本", Steps: []Step{{Name: "a", Run: "b", Why: "c"}}}
	if err := s.Save(first, false); err != nil {
		t.Fatal(err)
	}
	// 新建的口（replace=false）撞编号必须报错 —— 别人发来一本恰好同编号的，
	// 不能把人家那本悄悄换掉
	if err := s.Save(Playbook{ID: "same", Name: "第二本", Steps: first.Steps}, false); err == nil {
		t.Error("另一本顶了上来 —— 保存得写明它是改自己还是新建")
	}
	// 「保存修改」那个口（replace=true）放行，内容确实换掉
	edited := first
	edited.Name = "第一本（改过）"
	if err := s.Save(edited, true); err != nil {
		t.Errorf("编辑自己那本被拦了：%v", err)
	}
	if got, _ := s.Find("same"); got.Name != "第一本（改过）" {
		t.Errorf("编辑没落下去：%+v", got)
	}
}

func Test剧本能用JSON来回(t *testing.T) {
	// 「可分享」的载体就是这份 JSON：界面复制出去、别人粘回来，必须一模一样
	s := NewStore(t.TempDir())
	p := Playbook{ID: "share-me", Name: "给人看的那本", Note: "现场录的",
		Steps: []Step{{Name: "日志", Run: "journalctl -u argus -n 200",
			Why: "看有没有丢帧", OS: []string{"linux"},
			Marks: []Mark{{Match: "帧池|丢帧", Say: "命中就是池子小了"}},
			Write: false, TimeoutSec: 30}}}
	if err := s.Save(p, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "share-me.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back Playbook
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("分享的文本解不开：%v", err)
	}
	if back.Steps[0].Marks[0].Say == "" || back.Steps[0].OS[0] != "linux" {
		t.Errorf("来回丢了东西：%+v", back)
	}
}
