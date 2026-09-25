package tools

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// jsDict 取 app.js 里 `const NAME = { ... }` 那一段正文（到配对的那个 `};` 为止）。
// 只按「行首的 const NAME」和「顶格的 }」来配对 —— 这个文件里的字典都是这么写的。
func jsDict(t *testing.T, js, name string) string {
	t.Helper()
	start := regexp.MustCompile(`(?m)^const ` + regexp.QuoteMeta(name) + ` = \{`).FindStringIndex(js)
	if start == nil {
		return ""
	}
	rest := js[start[1]:]
	end := regexp.MustCompile(`(?m)^\}`).FindStringIndex(rest)
	if end == nil {
		return ""
	}
	return rest[:end[0]]
}

// TestTreeStepVerdictsHaveAWord 钉的是这件事：树里每一步露出来的判定码，
// 界面必须能在**那一步所查的那本字典**里找到说法。
//
// ★★ 光「这个码在 app.js 里出现过」是不够的 —— media.hls.probe 那十个码在 HLS 卡
//
//	自己的字典里好好的，却忘了挂进树的步骤字典（TREE_CODE_OF），结果推理路径那一栏
//	直接露出 hls-stalled 这种英文码。同一个码，两张卡一个说人话一个说码，
//	说的那一句还未必是这一步问出来的。
func TestTreeStepVerdictsHaveAWord(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面源码，这一项就等于没查：%v", err)
	}
	js := string(b)
	of := jsDict(t, js, "TREE_CODE_OF")
	if of == "" {
		t.Fatal("界面里没有 TREE_CODE_OF 这本步骤字典")
	}
	// 每个步骤 id 对应哪几本字典：`hls: [HLS_CODE],`（一行里可能写了好几条，别按行首锚）
	dictsOf := map[string][]string{}
	for _, m := range regexp.MustCompile(`'?([a-z][a-z0-9-]*)'?\s*:\s*\[([^\]]*)\]`).FindAllStringSubmatch(of, -1) {
		var names []string
		for _, n := range strings.Split(m[2], ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		dictsOf[m[1]] = names
	}
	for _, plan := range TreePlans() {
		for _, ps := range plan.steps {
			id := ps.node.id
			names, has := dictsOf[id]
			if !has || len(names) == 0 {
				t.Errorf("%s 树的「%s」那一步没挂进 TREE_CODE_OF —— 判定栏会露出英文码",
					plan.symptom, id)
				continue
			}
			var bodies []string
			for _, n := range names {
				d := jsDict(t, js, n)
				if d == "" {
					t.Errorf("步骤「%s」指着字典 %s，可 app.js 里读不到它", id, n)
					continue
				}
				bodies = append(bodies, d)
			}
			for code := range ps.by {
				found := false
				for _, d := range bodies {
					// 键的两种写法都认：'broken-at-route': 与 hls-ok:（合法标识符可以不写引号）
					re := regexp.MustCompile(`(^|\s|\{|'|")` + regexp.QuoteMeta(code) + `["']?\s*:`)
					if re.MatchString(d) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("步骤「%s」的判定码 %q 在它挂的那几本字典里都没有说法", id, code)
				}
			}
		}
	}
}
