// 见 bundle.go 的包注释：脱敏为什么在这个包里做，而不是让每个工具自己注意。

package diag

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rule 一类要抹掉的东西。Name 会进包的清单：看了包的人得知道**这里改过字**，
// 不能让他以为读到的是原文。
type rule struct {
	Name string
	RE   *regexp.Regexp
	// Val 是要抹掉的正则分组号；0 表示整段命中都抹掉。
	// ★ 为什么键名要留着：把「proxy_password=…」整行删掉，读包的人会判成
	//   「这台没配代理认证」—— 而真相是「配了，口令没给你看」。这两种情况下一步查的地方不同。
	Val int
	// Quoted 表示值有三种写法（双引号 / 单引号 / 裸着），分组 2、3、4，取非空的那个。
	// 引号本身留下：「这个字段带不带引号」也是配置的一部分。
	Quoted bool
	// Mask 换成什么。空 = ***。
	Mask string
}

// rules 的次序是算过的：先把整块的私钥换掉，再去拆「键=值」——
// 否则 PEM 里那些 base64 行会被值匹配吃掉一半，两边都判不准。
var rules = []rule{
	{
		Name: "私钥（整块移除）",
		RE: regexp.MustCompile(`(?s)` +
			`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		Val:  0,
		Mask: "[已移除：一段私钥]",
	},
	{
		Name: "URL 里的口令",
		// scheme://user:pass@host —— 只抹 pass：user 常常是设备名，是排障要看的。
		RE:  regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*://[^\s/@:]*:([^\s/@]*)@`),
		Val: 1,
	},
	{
		Name: "HTTP Authorization 头",
		RE:   regexp.MustCompile(`(?im)(authori[sz]ation[ \t]*[:=][ \t]*(?:basic|bearer|token|digest)[ \t]+)([^\s"',;，；]+)`),
		Val:  2,
	},
	{
		Name: "Cookie",
		RE:   regexp.MustCompile(`(?im)^([ \t]*cookie[ \t]*[:=][ \t]*)([^\n]+)`),
		Val:  2,
	},
	{
		Name:   "键值形式的口令/团体名/令牌",
		RE:     regexp.MustCompile(keyValueRE),
		Quoted: true,
	},
	{
		// 排成列的配置：键名单独占一列，值靠列间空格隔开，既没有冒号也没有等号。
		// ★ 单独一条的理由：诊断包自己的页就把代理设置按列排出来 —— 只认「键: 值」的话，
		//   包会把别人的配置读出来的同时把口令也一起带出去。
		//   要求两个以上空格：正文里的「口令 是 …」只有一个空格，那是句子不是列。
		Name:   "排成列的口令/团体名",
		RE:     regexp.MustCompile(keyColumnRE),
		Quoted: true,
	},
	{
		Name: "命令行的 -c 团体名",
		// snmpwalk -v2c -c public 10.0.0.5 —— 只抹紧跟 -c 的那个词。
		// ★ 为什么要求这一行里有 snmp：光看「-c 后面那个词」分不出 SNMP 的团体名和
		//   curl -c cookies.txt 里的文件名。抹错一个词的代价是命令抄不对、照着敲不通，
		//   所以宁可窄一点。
		RE:  regexp.MustCompile(`(?i)([^\n]*snmp[^\n]*?[ \t]-c[ \t]+)(\S+)`),
		Val: 2,
	},
	{
		Name: "配置里的 snmp-server 团体名",
		// 交换机配置里这一句的值就是口令：既没有冒号也没有等号，键值那条抓不到它。
		RE:  regexp.MustCompile(`(?i)(snmp-server[ \t]+communit(?:y|ies)[ \t]+)(\S+)`),
		Val: 2,
	},
	{
		Name: "带口令的命令行写法",
		// sshpass -p 'x' host / net user alice P@ss —— 这两种是把口令直接敲在行里。
		RE:  regexp.MustCompile(`(?i)(sshpass[ \t]+-p[ \t]+|net[ \t]+user[ \t]+"?[^\s"]+"?[ \t]+)(\S+)`),
		Val: 2,
	},
}

// secretKeys 左边那些键名要盖住中英两种写法：hosts、配置文件、命令回显里都可能出现。
const secretKeys = `communit(?:y|ies)|团体名|社区名|passwo?r?d|passwd|pwd|口令|密码|` +
	`secret|token|api[-_ ]?key|access[-_ ]?key|private[-_ ]?key|credential|凭据|鉴权[口令密码]*`

// keyValueRE 认「键: 值」「键 = 值」。键可以带引号 —— JSON 里的键一定带，
// 而改动账本里那份「改之前长什么样」就是 JSON。
//
// ★ 分隔符两边只用「空格与制表符」，不能用 \s —— 用 \s 的话，
//
//	「密码:」（值漏写了、后面跟着换行）会跨过换行去把**下一行**的正文当成口令抹掉，
//	抹掉的正是人家要看的配置。
const keyValueRE = `(?i)(["']?(?:` + secretKeys + `)["']?[ \t]*[:=＝：][ \t]*)` +
	`(?:"([^"]*)"|'([^']*)'|([^\s"',;，；]+))`

// keyColumnRE 认排成列的键值：整行只有「键 + 两个以上空格 + 值」。
// 分组号故意和 keyValueRE 对齐（值仍在 2、3、4），Quoted 那条取法只写一遍。
const keyColumnRE = `(?i)(?m)^([ \t]*[^\s:=＝：]*(?:` + secretKeys + `)["']?)[ \t]{2,}` +
	`(?:"([^"]*)"|'([^']*)'|([^\s"',;，；]+))`

const defaultMask = "***"

// Scrub 把文本里已知形态的凭据换成掩码，并返回每一类命中几次。
//
// ★ 计数是**给看包的人**的，不是调试日志：包里那句「脱敏 4 处（团体名 1、URL 口令 2、…）」
//
//	既说明「这里改过字，别按原文对配置」，也是一条线索 ——
//	「这台机器上有人把口令写进了会被读出来的地方」本身就是现场想知道的事。
func Scrub(text string) (string, map[string]int) {
	hits := map[string]int{}
	out := text
	for _, r := range rules {
		spans := valueSpans(out, r)
		if len(spans) == 0 {
			continue
		}
		hits[r.Name] += len(spans)
		out = maskSpans(out, spans, orMask(r.Mask))
	}
	return out, hits
}

func orMask(m string) string {
	if m == "" {
		return defaultMask
	}
	return m
}

// valueSpans 找出一段文本里该被抹掉的字节区间。
func valueSpans(text string, r rule) [][2]int {
	var spans [][2]int
	for _, m := range r.RE.FindAllStringSubmatchIndex(text, -1) {
		switch {
		case r.Quoted:
			for _, g := range []int{2, 3, 4} {
				if s, ok := group(m, g); ok {
					spans = append(spans, s)
					break
				}
			}
		case r.Val > 0:
			if s, ok := group(m, r.Val); ok {
				spans = append(spans, s)
			}
		default:
			spans = append(spans, [2]int{m[0], m[1]})
		}
	}
	return spans
}

// group 取第 i 个分组的区间；没参与匹配（负数）或空匹配都算「没有」。
func group(m []int, i int) ([2]int, bool) {
	if 2*i+1 >= len(m) || m[2*i] < 0 || m[2*i+1] <= m[2*i] {
		return [2]int{}, false
	}
	return [2]int{m[2*i], m[2*i+1]}, true
}

// maskSpans 从后往前替换，避免前面那次替换把后面的下标挪位。
func maskSpans(text string, spans [][2]int, mask string) string {
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] > spans[j][0] })
	out := text
	nextFree := len(out) + 1
	for _, s := range spans {
		if s[1] > nextFree {
			continue // 已经落在上一次抹掉的范围里
		}
		out = out[:s[0]] + mask + out[s[1]:]
		nextFree = s[0]
	}
	return out
}

// HitList 把命中计数写成一行给人看的话。一处没命中也要说清楚，
// 免得读的人以为「没写这一句」=「没查过」。
func HitList(hits map[string]int) string {
	if len(hits) == 0 {
		return "没发现已知形态的口令、团体名、令牌或私钥"
	}
	names := make([]string, 0, len(hits))
	total := 0
	for n, c := range hits {
		names = append(names, n)
		total += c
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, n+" "+strconv.Itoa(hits[n])+" 处")
	}
	return "共抹掉 " + strconv.Itoa(total) + " 处：" + strings.Join(parts, "、")
}
