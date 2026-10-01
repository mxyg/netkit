package tools

// ── 这一支测试只管一件事：后端每发一个 topo-* 判定码，界面上就得有一句话接着它 ──
//
// ★ 为什么要把它钉在 Go 这一侧：判定码是后端发的、句子是 app.js 里那张 TOPO_CODE 表给的，
//
//	两边隔着一层 HTTP。加一个码而忘了给句子时，界面上那一格会打出裸的
//	「topo-hub-suspect」—— 而那一格是全界面最该看懂的话（下一步该查什么）。
//	人眼在真机上很难正好撞上新码，所以这里用**源码里出现过的字面量**当分母：
//	新增一个 topo-* 而没在这张表里给它句子，这一支就红。
//
// ★ 分母不是手抄的清单：手抄的清单会在加第二个码时悄悄少一项（那等于把洞写进判据里）。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/topo"
)

func TestTopo每个判定码在界面上都有一句话(t *testing.T) {
	// ★ 路径可以换：反证这一支测试时不许去改**正在被别人编辑的** ui/src/app.js
	//   （改回去的那一刻正好盖掉另一个 agent 的新改动）。给一份 /tmp 里的拷贝就够变异了。
	path := os.Getenv("NETKIT_APP_JS")
	if path == "" {
		path = filepath.Join("..", "..", "..", "ui", "src", "app.js")
	}
	app, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 %s：%v", path, err)
	}
	start := strings.Index(string(app), "const TOPO_CODE = {")
	if start < 0 {
		t.Fatal("app.js 里没有 const TOPO_CODE —— 判定码表整个没了，界面上每个码都会打出裸字符串")
	}
	rest := string(app)[start:]
	end := strings.Index(rest, "\n};")
	if end < 0 {
		t.Fatal("const TOPO_CODE 找不到结尾的 \"};\"，这一支按整张表来数，不敢猜")
	}
	block := rest[:end]

	// 分母①：internal/topo 的源码里写过的每一个 "topo-*" 字面量。
	hardcoded := codesInDir(t, filepath.Join("..", "topo"))
	if len(hardcoded) == 0 {
		t.Fatal("在 internal/topo 里一个 topo-* 字面量都没找到 —— 提取口径坏了，不是后端干净了")
	}
	// 分母②：导出的那一组常量。两个分母必须互相盖住，否则「加了常量没发」
	// 和「发了字符串没进常量」这两种漏法各有一种抓不到。
	consts := map[string]bool{
		topo.CodeOK: true, topo.CodeNoIfaces: true, topo.CodeL2Blind: true,
		topo.CodeHubSuspect: true, topo.CodeIsland: true, topo.CodeNoGateway: true,
		topo.CodeDualStackSkew: true, topo.CodeSegmentConflict: true,
	}
	for c := range hardcoded {
		if !consts[c] {
			t.Errorf("internal/topo 里发了 %q，但没有对应的 Code* 常量（这一支的清单要同步加一项）", c)
		}
	}

	for c := range hardcoded {
		key := "'" + c + "':"
		i := strings.Index(block, key)
		if i < 0 {
			t.Errorf("判定码 %s 在 app.js 的 TOPO_CODE 里没有那一句 —— 界面上这一格会打出裸码", c)
			continue
		}
		seg := block[i+len(key):]
		if next := strings.Index(seg, "'topo-"); next >= 0 {
			seg = seg[:next]
		}
		// 标题一定是一个 t('…')；除 topo-ok 外还必须带「下一步该干什么」（第二个 t('…')）。
		// ★ 不给 ok 也要求两条：它本来就是「这张图我们没有理由怀疑它」，没有下一步。
		n := strings.Count(seg, "t('")
		want := 2
		if c == topo.CodeOK {
			want = 1
		}
		if n < want {
			t.Errorf("判定码 %s 那一句只有 %d 段文案，要有 %d 段（标题 + 下一步）：%s",
				c, n, want, strings.ReplaceAll(seg[:min(120, len(seg))], "\n", " "))
		}
	}
}

// topoVarRe 只认**独立成串**的判定码字面量：'topo-ok' / "topo-ok"。
// 注释里出现的 topo-* 也算 —— 宁可把清单撑大（那只会多要求几句界面文案），
// 也不许因为「写在注释里」而少一句。
var topoVarRe = regexp.MustCompile(`"(topo-[a-z][a-z-]*)"`)

func codesInDir(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("列 %s 下的 .go 文件失败或为空：%v", dir, err)
	}
	out := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue // 测试里写死的对照不算后端会发的码
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读 %s：%v", f, err)
		}
		for _, m := range topoVarRe.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
	}
	return out
}

func min(a, b int) int { if a < b { return a }; return b }
