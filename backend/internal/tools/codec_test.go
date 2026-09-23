package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

// net.codec.convert 的测试钉四件事：
//
//	① 五种会把人带偏的路径各有归属：解出二进制 / 像 GBK 的中文 / 字母表与填充 /
//	   URL 里的 `+` / 一段串几种读法都成立 —— 每一条都要有专属断言，
//	   因为它们各自的处置不一样，混成「解码失败」就等于没答；
//	② 工具替人放宽了什么必须留在 normalized 里。悄悄改数据比不解更坏：
//	   从 URL 里抄的 base64，那个空格原本可能是 `+`；
//	③ 多种读法不许替人挑一个 —— 结果要两份都给，最多加一句「多半是哪种」和理由；
//	④ Note 里不许出现解出来的内容：那可能是设备密码，而 Note 会进日志、会发给 AI。

func codecRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doCodecConvert(context.Background(), b)
	if err != nil {
		t.Fatalf("跑不动：%v", err)
	}
	res, ok := v.(ots.Verdict)
	if !ok {
		t.Fatalf("回来的不是判定（%T）", v)
	}
	return res
}

func codecRunErr(t *testing.T, args map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(args)
	_, err := doCodecConvert(context.Background(), b)
	if err == nil {
		t.Fatalf("本该报错，却给通过了")
	}
	return err.Error()
}

func codecText(t *testing.T, v ots.Verdict) string {
	t.Helper()
	s, ok := v.Values["text"].(string)
	if !ok {
		t.Fatalf("结果里没有文本（%T），判定是 %s", v.Values["text"], v.Code)
	}
	return s
}

func codecStr(v ots.Verdict, key string) string {
	s, _ := v.Values[key].(string)
	return s
}

func codecFixes(v ots.Verdict) []string {
	out, _ := v.Values["normalized"].([]string)
	return out
}

// ── 认字母表和填充 ──

func Test标准base64解出文本(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "aGVsbG8="})
	if v.Code != codecDecodedText {
		t.Fatalf("判定成了 %s，本该是 %s", v.Code, codecDecodedText)
	}
	if got := codecText(t, v); got != "hello" {
		t.Errorf("解出来是 %q，本该 hello", got)
	}
	if got := codecStr(v, "encoding"); got != "base64" {
		t.Errorf("认出的编码是 %q", got)
	}
}

func Test不带填充也要能解(t *testing.T) {
	// 现场从配置文件里抄出来的 base64，十次有八次末尾那个 = 掉了
	v := codecRun(t, map[string]any{"text": "aGVsbG8"})
	if v.Code != codecDecodedText || codecText(t, v) != "hello" {
		t.Fatalf("没填充就解不开：%s / %v", v.Code, v.Values["text"])
	}
	if !strings.Contains(strings.Join(codecFixes(v), ","), "padding-added") {
		t.Errorf("放宽过填充却没记在 normalized 里：%v", codecFixes(v))
	}
}

func TestURL安全字母表认得(t *testing.T) {
	// 4 个下划线 = 全 1 的 24 位，标准字母表里根本没有 _ 这个字符
	v := codecRun(t, map[string]any{"text": "____"})
	if codecStr(v, "encoding") != "base64url" {
		t.Fatalf("没认出 URL 安全字母表，判定 %s / 编码 %v", v.Code, v.Values["encoding"])
	}
	if !strings.Contains(strings.Join(codecFixes(v), ","), "url-safe-alphabet") {
		t.Errorf("换了字母表没记下来：%v", codecFixes(v))
	}
	if !strings.Contains(codecStr(v, "hexDump"), "ff ff ff") {
		t.Errorf("解出的字节不对：%v", v.Values["hexDump"])
	}
}

func Test两种字母表混在一起要拦下(t *testing.T) {
	// 这种写法几乎总是「两段值粘成了一行」，硬解会得到一个谁都不是的字节串
	v := codecRun(t, map[string]any{"text": "+__/"})
	if v.Code != codecPlainText {
		t.Fatalf("混了字母表还给了判定 %s，本该按「没在编码」处理", v.Code)
	}
	why := codecStr(v, "why")
	if !strings.Contains(why, "粘成") {
		t.Errorf("没说破为什么没按 base64 读：%q", why)
	}
}

func Test长度对不上的要说破不是base64(t *testing.T) {
	msg := codecRunErrText(t, map[string]any{"text": "abcde", "op": "decode", "encoding": "base64"})
	if !strings.Contains(msg, "不可能出现") {
		t.Errorf("报的是解不开，但没说到点子上：%q", msg)
	}
	if strings.Contains(msg, "非法字符") {
		t.Errorf("4n+1 跟字符合不合法无关，别用「非法字符」糊人：%q", msg)
	}
}

func codecRunErrText(t *testing.T, args map[string]any) string {
	t.Helper()
	v := codecRun(t, args)
	if v.Code != codecNotDecodable {
		t.Fatalf("判定是 %s，本该 %s", v.Code, codecNotDecodable)
	}
	return codecStr(v, "why")
}

func Test坏字符要点名到第几个(t *testing.T) {
	why := codecRunErrText(t, map[string]any{"text": "aGVsbG8!", "op": "decode", "encoding": "base64"})
	if !strings.Contains(why, "第 8 个字符") || !strings.Contains(why, "!") {
		t.Errorf("没定位到坏的那个字符：%q", why)
	}
}

// ── 折行与分隔写法 ──

func Test折行的base64能解并记下让步(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "aGVs\nbG8="})
	if v.Code != codecDecodedText || codecText(t, v) != "hello" {
		t.Fatalf("折行解不开：%s / %v", v.Code, v.Values["text"])
	}
	if !strings.Contains(strings.Join(codecFixes(v), ","), "line-wrapped") {
		t.Errorf("去掉了换行却没记：%v", codecFixes(v))
	}
}

func Test十六进制的0x与分隔写法都认(t *testing.T) {
	for _, in := range []string{"0x68656c6c6f", "68 65 6c 6c 6f", "68:65:6c:6c:6f"} {
		v := codecRun(t, map[string]any{"text": in, "op": "decode", "encoding": "hex"})
		if v.Code != codecDecodedText {
			t.Errorf("%q 判定成了 %s", in, v.Code)
			continue
		}
		if got := codecText(t, v); got != "hello" {
			t.Errorf("%q 解成 %q，本该 hello", in, got)
		}
	}
}

func Test奇数个十六进制字符不当hex读(t *testing.T) {
	why := codecRunErrText(t, map[string]any{"text": "abc", "op": "decode", "encoding": "hex"})
	if !strings.Contains(why, "不是偶数") {
		t.Errorf("没说清为什么凑不成整字节：%q", why)
	}
}

// ── 多种读法：不替人挑 ──

func Test同时是hex和base64时两种结果都给(t *testing.T) {
	// "61626364" 既是 "abcd" 的十六进制写法，也是一段合法 base64
	v := codecRun(t, map[string]any{"text": "61626364"})
	if v.Code != codecAmbiguous {
		t.Fatalf("判定 %s —— 这段确实两种读法都成立，不许替人挑一个", v.Code)
	}
	rs, _ := v.Values["readings"].([]map[string]any)
	if len(rs) != 2 {
		t.Fatalf("给了 %d 份结果，本该两份", len(rs))
	}
	if codecStr(v, "mostLikely") != "hex" {
		t.Errorf("两份都解不出文本时，倾向该按频率排：%v", v.Values["mostLikely"])
	}
	if !strings.Contains(codecStr(v, "why"), "只有一种") {
		t.Errorf("说了倾向就得给理由：%q", codecStr(v, "why"))
	}
}

func TestMD5那种串按hex在前(t *testing.T) {
	// 空串的 MD5：32 个字符同时是合法 base64（解出 24 个二进制字节）
	v := codecRun(t, map[string]any{"text": "d41d8cd98f00b204e9800998ecf8427e"})
	if v.Code != codecAmbiguous {
		t.Fatalf("判定 %s，本该是两种读法都成立", v.Code)
	}
	if codecStr(v, "mostLikely") != "hex" {
		t.Errorf("这种串按十六进制读在前才对，倾向给的是 %v", v.Values["mostLikely"])
	}
}

// ── URL 百分号转义 ──

func Test百分号转义解出中文(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "%E5%AF%86%E7%A0%81"})
	if v.Code != codecDecodedText || codecText(t, v) != "密码" {
		t.Fatalf("没解出中文：%s / %v", v.Code, v.Values["text"])
	}
}

func TestURL里的加号两种读法都给(t *testing.T) {
	// ★ 这一条钉的是「密码里有 +」那个经典故障：查询串里 + 是空格，路径里 + 是加号本身
	v := codecRun(t, map[string]any{"text": "ab+cd%20ef"})
	if v.Code != codecDecodedText {
		t.Fatalf("判定 %s", v.Code)
	}
	if v.Values["plusAmbiguous"] != true {
		t.Fatalf("含 + 的转义串必须两种读法都摆出来：%v", v.Values)
	}
	if got := codecStr(v, "asQuery"); got != "ab cd ef" {
		t.Errorf("按查询串读是 %q，本该「ab cd ef」", got)
	}
	if got := codecStr(v, "asPath"); got != "ab+cd ef" {
		t.Errorf("按路径读是 %q，本该保留加号", got)
	}
}

func Test残缺的百分号点名位置(t *testing.T) {
	why := codecRunErrText(t, map[string]any{"text": "a%E5%Z", "op": "decode", "encoding": "url"})
	if !strings.Contains(why, "第 5 个字符") {
		t.Errorf("没定位到坏的那个 %%：%q", why)
	}
}

func Test解一次还剩编码要说双重编码(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "%2520"})
	if v.Code != codecStillEncoded {
		t.Fatalf("判定 %s —— 双重编码要单独一档，不然人以为解出来就是 %s", v.Code, "%20")
	}
	if !strings.Contains(v.Note, "两遍") {
		t.Errorf("note 没指向下一步：%q", v.Note)
	}
}

// ── 解出来不是文本 ──

func Test解出二进制不当成失败(t *testing.T) {
	in := base64.StdEncoding.EncodeToString([]byte{0x00, 0x1f, 0x80, 0xff, 0x02, 0x07})
	v := codecRun(t, map[string]any{"text": in})
	if v.Code != codecDecodedBytes {
		t.Fatalf("判定 %s，本该是「解出二进制」", v.Code)
	}
	if !strings.Contains(v.Note, "解码没失败") {
		t.Errorf("必须说清这不是失败，否则人去换工具：%q", v.Note)
	}
	if _, ok := v.Values["text"]; ok {
		t.Errorf("二进制的结果里不许出现 text 字段：%v", v.Values["text"])
	}
}

func TestGBK中文不说成二进制(t *testing.T) {
	// 「中文」的 GBK 写法：既不是合法 UTF-8，也不是随机二进制
	in := base64.StdEncoding.EncodeToString([]byte{0xd6, 0xd0, 0xce, 0xc4})
	v := codecRun(t, map[string]any{"text": in})
	if v.Code != codecDecodedBytes {
		t.Fatalf("判定 %s", v.Code)
	}
	if v.Values["looksLikeGbk"] != true {
		t.Fatalf("没点出这像 GBK 中文：%v", v.Values)
	}
	if !strings.Contains(v.Note, "GBK") {
		t.Errorf("note 没提 GBK：%q", v.Note)
	}
	if strings.Contains(v.Note, "失败") {
		t.Errorf("说成失败人就去看设备坏没坏：%q", v.Note)
	}
}

func TestUTF8合法但全是控制字符不算文本(t *testing.T) {
	// \x01 是合法 UTF-8。只看 utf8.Valid 就会把一坨控制流当文本给人
	in := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	v := codecRun(t, map[string]any{"text": in})
	if v.Code != codecDecodedBytes {
		t.Fatalf("判定 %s —— 控制字符不该走文本那一档", v.Code)
	}
	if v.Values["utf8"] != true {
		t.Errorf("utf8 这一栏要照实给（它确实合法），歧义在可打印：%v", v.Values["utf8"])
	}
}

// ── 转义写法 ──

func TestU转义含代理对(t *testing.T) {
	v := codecRun(t, map[string]any{"text": `\u5bc6\u7801 \ud83d\ude00`, "op": "decode", "encoding": "unicode"})
	if v.Code != codecDecodedText {
		t.Fatalf("判定 %s / %v", v.Code, v.Values)
	}
	if got := codecText(t, v); got != "密码 😀" {
		t.Errorf("解成 %q，本该「密码 😀」—— 代理对拆开就会解成两个孤立代理字符", got)
	}
}

func Test落单的低代理不硬解(t *testing.T) {
	why := codecRunErrText(t, map[string]any{"text": `\ude00`, "op": "decode", "encoding": "unicode"})
	if !strings.Contains(why, "代理") {
		t.Errorf("没说到代理对：%q", why)
	}
}

func TestWindows路径不当转义串(t *testing.T) {
	v := codecRun(t, map[string]any{"text": `C:\newfolder\x41`})
	if v.Code != codecPlainText {
		t.Fatalf("判定 %s —— 路径里的 \\n 是真字符，解出来就成了一个换行加个假路径", v.Code)
	}
}

// ── 签名令牌 ──

func Test签名令牌分两段解出且不验签(t *testing.T) {
	// jwt.io 页面上那个公开示例
	const tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	v := codecRun(t, map[string]any{"text": tok})
	if v.Code != codecDecodedText {
		t.Fatalf("判定 %s，本该把载荷解成文本", v.Code)
	}
	if codecStr(v, "shape") != "jwt" {
		t.Errorf("没认出这是签名令牌：%v", v.Values["shape"])
	}
	if !strings.Contains(codecStr(v, "header"), "HS256") {
		t.Errorf("头部没解出来：%v", v.Values["header"])
	}
	if !strings.Contains(codecText(t, v), "John Doe") {
		t.Errorf("载荷不对：%v", v.Values["text"])
	}
	if !strings.Contains(v.Note, "没验签") {
		t.Errorf("★ 必须说清没验签，否则人拿它当「校验通过」：%q", v.Note)
	}
}

// ── 正向编码 ──

func Test明文顺手给五种写法(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "hello"})
	if v.Code != codecPlainText {
		t.Fatalf("hello 五个字符是 4n+1，不是 base64，判定该是 %s，给了 %s", codecPlainText, v.Code)
	}
	for _, k := range []string{"base64", "base64url", "hex", "url", "unicode"} {
		if codecStr(v, k) == "" {
			t.Errorf("少了 %s 这一种写法", k)
		}
	}
	if got := codecStr(v, "base64"); got != "aGVsbG8=" {
		t.Errorf("base64 编错：%q", got)
	}
	if got := codecStr(v, "plainText"); got != "hello" {
		t.Errorf("原文没回给人：%q", got)
	}
}

func Test本来带填充的不许认成我们补的(t *testing.T) {
	// ★ normalized 是对外承诺「做过什么让步」。实机验证时抓到过一次假承诺：
	// 输入明明带着 = 填充，却因为实现先按「去掉填充后的长度」判断而报成 padding-added
	v := codecRun(t, map[string]any{"text": "aGVsbG8="})
	for _, f := range codecFixes(v) {
		if f == "padding-added" {
			t.Errorf("人家本来就带填充，却报成我们补的：normalized=%v", codecFixes(v))
		}
	}
}

func Test编码可以指死一种(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "密", "op": "encode", "encoding": "url"})
	if codecStr(v, "result") != "%E5%AF%86" {
		t.Errorf("URL 编码给的是 %v", v.Values["result"])
	}
	if _, ok := v.Values["base64"]; ok {
		t.Errorf("指了一种还把所有写法都塞回来：%v", v.Values)
	}
}

func Test转义写法按UTF16出代理对(t *testing.T) {
	v := codecRun(t, map[string]any{"text": "😀", "op": "encode", "encoding": "unicode"})
	if got := codecStr(v, "result"); got != `\ud83d\ude00` {
		t.Errorf("emoji 要出代理对，给了 %q —— 单个 \\u 装不下 U+1F600", got)
	}
}

// ── 边界与安全 ──

func Test不认的编码当场拒(t *testing.T) {
	// ★ 指错了写法是**调用方说错了**，不是「这段用那种写法解不开」——
	// 两条路都得当场报错，混成 not-decodable 会让 AI 以为换一种编码再试就有结果
	for _, op := range []string{"encode", "decode"} {
		msg := codecRunErr(t, map[string]any{"text": "ab", "op": op, "encoding": "jwt"})
		if !strings.Contains(msg, "base64url") {
			t.Errorf("op=%s 的报错要把可选值列出来：%q", op, msg)
		}
	}
}

func Test自动档给的五种写法必须编的是清理过的那一份(t *testing.T) {
	// ★ 界面上显示「你的原文是 hello world!」、给出的 base64 却是带引号和尾空格编的 ——
	// 两个结果看着都像对的，人拿去贴的就是他嘴上说不要的那个值
	v := codecRun(t, map[string]any{"text": `"hello world!" `})
	want := base64.StdEncoding.EncodeToString([]byte("hello world!"))
	if got := codecStr(v, "base64"); got != want {
		t.Errorf("base64 编的是没清理的那一份：%q，应为 %q", got, want)
	}
	if n, _ := v.Values["normalized"].([]string); len(n) == 0 {
		t.Error("替人去过引号和空格，却不写进 normalized —— 承诺漏了一条")
	}
}

func Test字母表无从区分时指哪一种都算(t *testing.T) {
	// 这段里既没有 +/ 也没有 -_，两派解出的字节一模一样，拒绝解等于把人往「串坏了」上带
	v := codecRun(t, map[string]any{"text": "aGVsbG8", "op": "decode", "encoding": "base64url"})
	if v.Code != codecDecodedText || codecText(t, v) != "hello" {
		t.Fatalf("判定 %s / 文本 %q —— 无从区分时要把结果照常解出来", v.Code, v.Values["text"])
	}
	if v.Values["alphabetUnclaimed"] != true {
		t.Error("要标出「这一指其实无从验证」，界面好说明为什么两种写法结果相同")
	}
}

func Test填充个数对不上要说破是抄漏了(t *testing.T) {
	// 两个方向分开钉：少一个 = 漏抄，多一个 = 多带 —— 只断言「认出来了」，
	// 把方向说反（该配 2 个说成 0 个）也算通过，而那恰好是最害人的错法
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"QQ=", "该配 2 个"},   // 正确的写法是 QQ==，抄掉了一个字符
		{"AAAA=", "该配 0 个"}, // 4 的倍数不需要填充，多出来的 = 是抄串了尾巴
	} {
		v := codecRun(t, map[string]any{"text": tc.in, "op": "decode", "encoding": "base64"})
		if v.Code != codecNotDecodable {
			t.Errorf("%s 判定 %s —— 填充个数不对就该拦下", tc.in, v.Code)
			continue
		}
		if why := codecStr(v, "why"); !strings.Contains(why, tc.want) {
			t.Errorf("%s 没说清%s：%q", tc.in, tc.want, why)
		}
	}
}

func Test文本里恰好带转义不算第二层编码(t *testing.T) {
	// 解出来是 "rate = 50%0D and %41" —— 看见 %XX 就判「还套一层」，人再解一次
	// 就把一段好端端的文本解出控制字符出来
	in := base64.StdEncoding.EncodeToString([]byte("rate = 50%0D and %41"))
	v := codecRun(t, map[string]any{"text": in})
	if v.Code != codecDecodedText {
		t.Errorf("判定 %s —— 转义旁边还有词在，那是文本里带着转义，不是双重编码", v.Code)
	}
}

func Test空格凑出来的base64解出二进制时按文本读(t *testing.T) {
	// "  hello world  " 剔掉空格能凑成 base64，解出来却是二进制；
	// 这时报「解出来是二进制」等于把一段文本判成坏数据
	v := codecRun(t, map[string]any{"text": "  hello world  "})
	if v.Code != codecPlainText {
		t.Fatalf("判定 %s —— 该按文本原样读", v.Code)
	}
	if why := codecStr(v, "why"); !strings.Contains(why, "base64") || !strings.Contains(why, "二进制") {
		t.Errorf("要写清「试过 base64、因为解出来是二进制所以不这么读」，不能只说没认出编码：%q", why)
	}
}

func Test反斜杠编得出去也要解得回来(t *testing.T) {
	// 不把 `\` 自己编掉，`前\后` 编出去还是 `前\后`，再解回来就撞在「认不出的转义开头」上
	enc := codecRun(t, map[string]any{"text": `前\后`, "op": "encode", "encoding": "unicode"})
	got := codecStr(enc, "result")
	if !strings.Contains(got, `\u005c`) {
		t.Errorf(`反斜杠没被编掉：%q`, got)
	}
	back := codecRun(t, map[string]any{"text": got, "op": "decode"})
	if codecText(t, back) != `前\后` {
		t.Errorf("转一圈回来变了：%q", back.Values["text"])
	}
}

func Test输入上限按字符算而不是字节(t *testing.T) {
	// 中文一个字三个字节：按字节数拦，报错里写的「字符」就是假的，而且拦得比说的早
	// codecRun 一遇到 error 就 fail：3000 个中文字符 = 9000 字节，按字节拦就是误伤
	codecRun(t, map[string]any{"text": strings.Repeat("中", 3000)})
	msg := codecRunErr(t, map[string]any{"text": strings.Repeat("中", maxCodecInput+1)})
	if !strings.Contains(msg, "8193 字符") {
		t.Errorf("个数要按字符算（8193 个中文字符是 24579 字节，报那个数等于说谎）：%q", msg)
	}
}

func Test超长输入指向文件服务而不是硬解(t *testing.T) {
	msg := codecRunErr(t, map[string]any{"text": strings.Repeat("A", maxCodecInput+10)})
	if !strings.Contains(msg, "文件") {
		t.Errorf("该说清这条界线在哪：%q", msg)
	}
}

func Test空输入当场拒(t *testing.T) {
	if msg := codecRunErr(t, map[string]any{"text": "   "}); !strings.Contains(msg, "text") {
		t.Errorf("报错没点名参数：%q", msg)
	}
}

func TestNote里不许出现解出的内容(t *testing.T) {
	// ★ Note 会进日志、会发给 AI；解出来的东西可能是设备密码
	in := base64.StdEncoding.EncodeToString([]byte("Sup3rS3cr3tPassw0rd"))
	v := codecRun(t, map[string]any{"text": in})
	if strings.Contains(v.Note, "Sup3rS3cr3tPassw0rd") {
		t.Errorf("note 里复述了内容：%q", v.Note)
	}
	if codecText(t, v) != "Sup3rS3cr3tPassw0rd" {
		t.Errorf("values 里必须给全（用户要的就是这个）：%v", v.Values["text"])
	}
}

func Test编码方向不许出现两个来源字段(t *testing.T) {
	// 指死一种时只给 result；同时给全套会让界面两栏打架
	v := codecRun(t, map[string]any{"text": "ab", "op": "encode", "encoding": "base64"})
	if codecStr(v, "result") != base64.StdEncoding.EncodeToString([]byte("ab")) {
		t.Errorf("result 不对：%v", v.Values["result"])
	}
}

func Test编解码能转回来(t *testing.T) {
	for _, s := range []string{"hello", "密码", "a+b c", "line\nbreak", "😀"} {
		enc := codecStr(codecRun(t, map[string]any{"text": s, "op": "encode", "encoding": "base64"}), "result")
		back := codecRun(t, map[string]any{"text": enc, "op": "decode", "encoding": "base64"})
		if back.Code != codecDecodedText || codecText(t, back) != s {
			t.Errorf("%q 转一圈回来成了 %q（判定 %s）", s, back.Values["text"], back.Code)
		}
	}
	// \u 那一档单独转一遍：反斜杠、盘符路径、控制字符是它的三个坑
	for _, s := range []string{`C:\new`, `前\后`, "a\tb", "密😀码"} {
		enc := codecStr(codecRun(t, map[string]any{"text": s, "op": "encode", "encoding": "unicode"}), "result")
		back := codecRun(t, map[string]any{"text": enc, "op": "decode", "encoding": "unicode"})
		if got := codecText(t, back); got != s {
			t.Errorf("%q 编成 %q，解回来成了 %q —— 编得出去解不回来，这一档在 Windows 路径上就是坏的", s, enc, got)
		}
	}
}

func Test自动档给出去的写法要能原样解回清理过的原文(t *testing.T) {
	// 贴进来的是带引号的一段（从配置文件里抄的常态）：显示的是清理过的原文，
	// 那五种写法就必须都是这一段编出来的，否则人贴走的是另一个值
	const cleaned = "hello world!"
	v := codecRun(t, map[string]any{"text": `"` + cleaned + `" `})
	for key, want := range map[string]string{
		"base64": base64.StdEncoding.EncodeToString([]byte(cleaned)),
		"hex":    hex.EncodeToString([]byte(cleaned)),
	} {
		got := codecStr(v, key)
		if got != want {
			t.Errorf("%s 编的不是显示的那一份：%q，应为 %q", key, got, want)
		}
		back := codecRun(t, map[string]any{"text": got, "op": "decode", "encoding": key})
		if codecText(t, back) != cleaned {
			t.Errorf("%s 解回来不是原文：%q", key, back.Values["text"])
		}
	}
}

func Test指死字母表时按串里的字符分该不该拦(t *testing.T) {
	// 串里出现了 + 就是标准字母表：这时指 base64url 要拦（- 会被当成别的字），
	// 而 _ 反过来 —— 这一拦一放才有意义，全放等于没在指
	for _, tc := range []struct {
		in, enc string
		ok      bool
	}{
		{"aGVsbG8+", "base64", true},
		{"aGVsbG8+", "base64url", false},
		{"aGVsbG8_", "base64url", true},
		{"aGVsbG8_", "base64", false},
	} {
		v := codecRun(t, map[string]any{"text": tc.in, "op": "decode", "encoding": tc.enc})
		if tc.ok && v.Code != codecDecodedText {
			t.Errorf("%s 指成 %s 本该解得开：%s / %v", tc.in, tc.enc, v.Code, v.Values["why"])
		}
		if !tc.ok {
			if v.Code != codecNotDecodable {
				t.Errorf("%s 指成 %s 是笔误，不拦下来人就拿着错值去对设备了（判定 %s）", tc.in, tc.enc, v.Code)
				continue
			}
			if why := codecStr(v, "why"); !strings.Contains(why, "字母表") {
				t.Errorf("要说破分歧在哪：%q", why)
			}
		}
	}
}

func TestCodec工具声明(t *testing.T) {
	if codecTool.Name != "net.codec.convert" || codecTool.Class != ots.ClassRead {
		t.Fatalf("声明不对：%s %v", codecTool.Name, codecTool.Class)
	}
	var schema map[string]any
	if err := json.Unmarshal(codecTool.Schema, &schema); err != nil {
		t.Fatalf("schema 不是合法 JSON：%s", err)
	}
	for _, key := range []string{"text", "op", "encoding"} {
		props, _ := schema["properties"].(map[string]any)
		if _, ok := props[key]; !ok {
			t.Errorf("schema 少了 %s", key)
		}
	}
}

func Test每个判定都有人话(t *testing.T) {
	// 一个码要在三处齐：后端的常量、Summary（AI 只看得到这个）、界面 CC_CODE（客户只看得到这个）。
	// 只查前两处等于没查 —— 码没打错字这件事，恒真。
	wanted := []string{codecDecodedText, codecDecodedBytes, codecStillEncoded,
		codecAmbiguous, codecPlainText, codecNotDecodable, codecEncoded}
	src, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面源码，这一项就漏了：%v", err)
	}
	seen := map[string]bool{}
	for _, c := range wanted {
		if seen[c] {
			t.Errorf("判定码重复了：%s", c)
		}
		seen[c] = true
		if !strings.Contains(codecTool.Summary, c) {
			t.Errorf("Summary 里没提到 %s，AI 看不见这一档", c)
		}
		if !strings.Contains(string(src), c) {
			t.Errorf("界面里没有 %s —— 客户会看见一个裸码", c)
		}
	}
}
