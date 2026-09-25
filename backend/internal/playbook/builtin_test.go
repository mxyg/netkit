package playbook

import (
	"regexp"
	"strings"
	"testing"
)

// 内置剧本的高亮是正则：正则漏一段，界面上就是「没提到」而不是「命中」，
// 而那正是最容易被当成「没问题」的一种错法。所以每条都要在**现场那种读数**上打得着。
func Test内置高亮在真实读数上打得着(t *testing.T) {
	// 每条高亮配一段真会出现在那台机器上的原文。
	want := []struct{ step, match, text string }{
		{"它是谁、多久没重启了", `load average:`, " 10:12:33 up 41 days, 2:11, 1 user, load average: 14.02, 12.90, 11.44"},
		{"CPU 与内存此刻多少", `argus`, "   2213 argus     20   0 2714756 402180  98.7 12.4 argus-engine"},
		{"磁盘还剩多少、日志把盘写满没有", `100%`, "/dev/mmcblk0p1   57G   55G     0 100% /var"},
		{"服务在不在、有没有正在失败的单元", `failed`, "● argus-watchdog.service loaded failed failed 看门狗"},
		{"它在听哪些端口", `:554`, "LISTEN 0 128 0.0.0.0:554 0.0.0.0:* users:(\"argus-engine\")"},
		{"跟平台之间连上了几条", `estab`, "TCP:   38 (estab 3, closed 20, orphaned 0, timewait 12)"},
		{"日志里最近有没有丢帧那句原话", `帧池`, "argus-engine[2213]: 帧池 frame pool exhausted: no available frame for chn=12"},
		{"配置里的通道数与许可上限", `channel`, "  channels: 16"},
	}
	byName := map[string]Step{}
	for _, p := range Builtins() {
		for _, s := range p.Steps {
			byName[p.ID+"|"+s.Name] = s
		}
	}
	for _, w := range want {
		s, ok := byName[BuiltinBoxCheck+"|"+w.step]
		if !ok {
			t.Fatalf("内置剧本里没有这条：%s", w.step)
		}
		var m *Mark
		for i := range s.Marks {
			if strings.Contains(s.Marks[i].Match, w.match) {
				m = &s.Marks[i]
				break
			}
		}
		if m == nil {
			t.Errorf("「%s」没有哪条高亮认得出 %q —— 那一问命中不了", w.step, w.match)
			continue
		}
		re, err := regexp.Compile(m.Match)
		if err != nil {
			t.Errorf("%s 的高亮 %q 不是合法 Go 正则：%v（跑不到界面上）", w.step, m.Match, err)
			continue
		}
		if !re.MatchString(w.text) {
			t.Errorf("「%s」的高亮 %q 打不中现场那种读数：\n  %q", w.step, m.Match, w.text)
		}
		if strings.TrimSpace(m.Say) == "" {
			t.Errorf("「%s」的高亮没配说明", w.step)
		}
	}
}

// 反着来的一半：负载只有 0.08 时不许报「整体过载」——
// 高亮命中了就是一句结论，误报的代价和漏报一样是有人照着它去查。
func Test低负载不许被说成过载(t *testing.T) {
	for _, p := range Builtins() {
		for _, s := range p.Steps {
			for _, m := range s.Marks {
				if !strings.Contains(m.Match, "load average") {
					continue
				}
				re := regexp.MustCompile(m.Match)
				for _, low := range []string{
					"load average: 0.08, 0.12, 0.10",
					"load average: 1.02, 0.90, 0.44",
					"load average: 2.00, 1.10, 1.05",
				} {
					if re.MatchString(low) {
						t.Errorf("%q 不算过载，却被 %q 命中了", low, m.Match)
					}
				}
				for _, high := range []string{
					"load average: 3.40, 2.90, 1.44",
					"load average: 10.02, 9.90, 8.44",
					"load average: 14.02, 12.90, 11.44",
					"load average: 27.5, 25.0, 20.1",
					"load average: 105.3, 99.0, 90.2",
				} {
					if !re.MatchString(high) {
						t.Errorf("%q 已经该报过载，却没被 %q 命中", high, m.Match)
					}
				}
				return
			}
		}
	}
	t.Fatal("内置剧本里没有负载那条高亮")
}

// 高亮那句说明是一份结论。读数落在说明的范围外就不许命中，
// 否则界面上会出现「明明四百多条连接、却说只拉了个位数」这种话。
func Test高亮不许把读数说成它没说的范围(t *testing.T) {
	cases := []struct{ step, match, text string }{
		{"跟平台之间连上了几条", `estab`, "TCP:   412 (estab 412, closed 20, orphaned 0)"},
		{"跟平台之间连上了几条", `estab`, "TCP:   30 (estab 30, closed 2, orphaned 0)"},
	}
	for _, p := range Builtins() {
		for _, s := range p.Steps {
			if s.Name != cases[0].step {
				continue
			}
			for _, m := range s.Marks {
				if !strings.Contains(m.Match, cases[0].match) {
					continue
				}
				re := regexp.MustCompile(m.Match)
				for _, c := range cases {
					if re.MatchString(c.text) {
						t.Errorf("%q 不在「%s」说的范围内，却被 %q 命中了",
							c.text, m.Say, m.Match)
					}
				}
				return
			}
		}
	}
	t.Fatal("没找到那条高亮")
}

// 高亮的正则必须能编译：Go 的 regexp 不支持 (?=)、\1 这类写法，
// 而剧本里那些 pattern 是人手写的，写错了不会报错，只会永远命中不了。
func Test所有高亮都是合法正则(t *testing.T) {
	for _, p := range Builtins() {
		for _, s := range p.Steps {
			for j, m := range s.Marks {
				if _, err := regexp.Compile(m.Match); err != nil {
					t.Errorf("%s / %s 第 %d 条高亮 %q 编译不过：%v", p.ID, s.Name, j+1, m.Match, err)
				}
			}
		}
	}
}
