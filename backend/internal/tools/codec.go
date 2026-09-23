package tools

// ── net.codec.convert ──
//
// ★★ 「把这段 base64 解一下」看着没有风险，实际有五条会把人带偏的路：
//
//  1. **解出来是二进制** —— 多数工具把这报成「解码失败」或吐一串乱码，人就以为数据坏了。
//     实际上数据完好：要么它是加密 / 压缩过的字节（解出来本来就不该是可读文本），
//     要么它压根不是 base64。这两种处置完全不同，必须分开说
//  2. **老设备固件里的中文是 GBK** —— 解出来的字节既不是合法 UTF-8 也不是随机二进制，
//     而是中文。这一档要是只说「二进制」，人就去查设备是不是坏了
//  3. **字母表和填充** —— 现在发出来的 token、设备云接口的字段，绝大多数是 URL 安全字母表
//     且不带 `=` 填充（`eyJhbGciOi...`）。拿标准解码器解这种串必然报错，
//     而报错文案一律写成「非法字符」，人就顺着「字符不对」去查复制粘贴
//  4. **URL 里的 `+`** —— 在查询串里 `+` 是空格，在路径里 `+` 就是加号本身。
//     密码里有 `+`，从地址栏抄下来贴进配置，解出来差一个字符，症状是「密码明明是对的却登不上」
//  5. **一段字符串同时是好几种编码** —— 32 个十六进制字符既是合法 hex 也是合法 base64，
//     而这两种读法出来的字节毫无关系。工具替人挑一个就是替他猜，猜错了人还拿那个结果去对设备
//
// ★ 所以顶层判定按**「这个结果能不能直接拿去用」**分档，不按「认出的是哪种编码」分档：
//	解出文本 / 解出二进制 / 还没解干净（双重编码）/ 多种读法要你指一个 / 它没在编码 /
//	这种编码解不开。其中 ambiguous-encoding 必须把各读法的结果都摆出来 ——
//	宁可让人多看一眼再选，也不替他决定。
//
// ★★ Note 里不许复述解出来的内容：那可能是设备密码或 token，而 Note 会进日志、会发给 AI。
//
//	内容只在 values 里 —— 那是调用方自己贴进来的东西，他要的就是这个。

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"net.yuhox.com/netkit/internal/ots"
)

const (
	codecDecodedText  = "decoded-text"       // 解出来是可读文本，能直接用
	codecDecodedBytes = "decoded-binary"     // ★ 解出来是二进制：数据没坏，是它本来就不该当文本读
	codecStillEncoded = "still-encoded"      // 解了一次还剩编码，多半是被编了两遍
	codecAmbiguous    = "ambiguous-encoding" // ★ 好几种读法都成立，各给一份结果，得人指一个
	codecPlainText    = "plain-text"         // 它没在编码，原样就是它自己
	codecNotDecodable = "not-decodable"      // 这种编码解不开，点名坏在第几个字符、为什么
	codecEncoded      = "encoded"            // 正向编码的产出
)

const (
	maxCodecInput = 8192 // 再长就不是「一段字符串」了，那是文件的事
	maxCodecText  = 1024 // 结果里回显文本的上限
	maxCodecHex   = 96   // 十六进制预览的字节数
)

var codecWindowsPath = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

const (
	base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	hexDigits      = "0123456789abcdefABCDEF"
)

// codecReading 一种读法：按某种编码解出来的字节，以及途中替人放宽了什么。
//
// ★ 返回值第二个是**为什么解不开**（带字符位置），不是布尔。
// 自动判断和指死一种两条路共用同一份诊断 —— 「第 17 个字符不在字母表里」
// 这种话只在指死时才算，恰恰是自动判断那档最需要知道的（否则它只会说「不是 base64」）。
type codecReading struct {
	Encoding string
	Data     []byte
	Fixes    []string
	Extra    map[string]any
}

var codecTool = ots.Tool{
	Name:  "net.codec.convert",
	Class: ots.ClassRead,
	Summary: "解一段字符串是怎么写的（Base64 / Base64URL / 十六进制 / URL 百分号转义 / \\u 转义），或者反过来编进去。" +
		"★ 顶层判定说的是**结果能不能直接拿去用**：decoded-text（可读文本）/ decoded-binary" +
		"（解出来是二进制 —— 解码没失败，是这些字节本来就不该当文本读）/ still-encoded（解一次还剩编码，" +
		"多半被编了两遍）/ ambiguous-encoding（几种读法都成立，各给一份结果和「多半是哪种」，得你指一个）/ " +
		"plain-text（这段没在编码）/ not-decodable（解不开，点名坏在第几个字符、为什么）/ encoded。" +
		"★ 会替人放宽几处并全部记在 normalized 里：补 `=` 填充、认 URL 安全字母表、去掉折行空白、去 0x 前缀 —— " +
		"从 URL 里抄来的 base64，那个空格原本可能是 `+`，不记下来就是悄悄改了数据。" +
		"URL 里有 `+` 时按「查询串」和「路径」两种读法分开给（同一段字符串两个答案，密码抄错的经典根因）。" +
		"解出来不是合法 UTF-8 但字节范围落在 GBK 里时点明「像老设备固件的中文」，不并到二进制里。" +
		"看到签名令牌（eyJ… 三段）会把头部和载荷分开解出来，★ 只解码不验签。纯字符串运算：不发任何包，不碰文件系统。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "text": {"type": "string", "description": "要处理的字符串，最长 8192 字符。整段贴进来即可，首尾引号和空白会自动去掉，并记在 normalized 里。"},
	    "op": {"type": "string", "enum": ["auto", "decode", "encode"], "description": "auto（默认）：判断这段是怎么写的并解开；它没在编码就顺手给正向写法。decode：只要解开。encode：只要编进去。"},
	    "encoding": {"type": "string", "enum": ["base64", "base64url", "hex", "url", "unicode"], "description": "指死按哪一种读或编，不猜。留空则自动判断；判断出多种成立会各给一份结果并要你指一个。"}
	  },
	  "required": ["text"]
	}`),
	Invoke: doCodecConvert,
}

type codecArgs struct {
	Text     string `json:"text"`
	Op       string `json:"op,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

func doCodecConvert(_ context.Context, raw json.RawMessage) (any, error) {
	var a codecArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	if strings.TrimSpace(a.Text) == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "text 是空的 —— 没有要解的东西")
	}
	if len(a.Text) > maxCodecInput {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"输入 %d 字符，超过 %d 的上限 —— 这是给一段字符串用的，要整份文件那是文件服务的事", len(a.Text), maxCodecInput)
	}
	switch a.Op {
	case "", "auto":
		return codecAuto(a.Text, a.Encoding)
	case "decode":
		return codecDecode(a.Text, a.Encoding)
	case "encode":
		if a.Encoding != "" {
			return codecEncodePinned(a.Text, a.Encoding)
		}
		return codecEncodeAll(a.Text), nil
	}
	return nil, ots.Errf(ots.ErrInvalidArgument, "op 只认 auto / decode / encode，给的是 %q", a.Op)
}

// codecAuto 不指编码时：能解就解，解不出就把正向写法给全 ——
// 贴进来一段明文的人，十有八九是要编出去（贴进 URL、贴进配置文件）。
func codecAuto(text, pinned string) (any, error) {
	v, err := codecDecode(text, pinned)
	if err != nil {
		return nil, err
	}
	res, ok := v.(ots.Verdict)
	if !ok || res.Code != codecPlainText {
		return v, nil
	}
	values := codecEncodeAll(text).Values
	values["plainText"] = res.Values["text"]
	values["why"] = res.Values["why"]
	return ots.Verdict{
		Code:   codecPlainText,
		Values: values,
		Note:   res.Note + "；顺手给出五种写法",
	}, nil
}

// ── 解码 ──

func codecDecode(text, pinned string) (any, error) {
	body, fixes := codecCleanInput(text)
	if body == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "去掉首尾空白和引号之后什么都不剩 —— 检查一下是不是只贴了个引号")
	}
	if pinned != "" {
		r, problem := codecReadPinned(body, pinned)
		if problem != "" {
			return ots.Verdict{
				Code: codecNotDecodable,
				Values: map[string]any{"encoding": pinned, "why": problem,
					"normalized": fixes, "input": codecPreview(body)},
				Note: fmt.Sprintf("按 %s 解不开：%s", pinned, problem),
			}, nil
		}
		out := codecVerdictFromReading(r, body, fixes)
		out.Values["candidates"] = []string{r.Encoding}
		return out, nil
	}
	cands, notes := codecCandidates(body)
	switch len(cands) {
	case 0:
		return ots.Verdict{
			Code: codecPlainText,
			Values: map[string]any{
				"text":       body,
				"charLen":    len([]rune(body)),
				"byteLen":    len(body),
				"why":        codecJoin(notes, "这段没有编码 —— 没有百分号转义，也不是合法的 base64 / 十六进制 / 转义写法"),
				"normalized": fixes,
			},
			Note: fmt.Sprintf("没认出编码（%d 字符）", len([]rune(body))),
		}, nil
	case 1:
		out := codecVerdictFromReading(cands[0], body, fixes)
		out.Values["candidates"] = []string{cands[0].Encoding}
		return out, nil
	}
	// ★ 多种读法：各给一份结果，再给一个「多半是哪种」+ 理由，但**不替人决定**。
	// 只给一个结果的工具，人就会拿那个结果去对设备；给两份，人自己看得出哪份讲得通
	readings := make([]map[string]any, 0, len(cands))
	var textReadings []string
	for _, c := range cands {
		info, readable := codecBytesInfo(c.Data)
		r := map[string]any{
			"encoding": c.Encoding, "normalized": c.Fixes,
			"readable": readable, "byteLen": info["byteLen"],
		}
		if readable {
			r["text"] = info["text"]
			textReadings = append(textReadings, c.Encoding)
		} else {
			r["hexDump"] = info["hexDump"]
		}
		readings = append(readings, r)
	}
	best, why := cands[0].Encoding, "几种读法按现场出现频率排序，结果都摆着，自己看一眼哪个讲得通"
	if len(textReadings) == 1 {
		// 只有一种解得出文本：点出来不是替人猜，是把唯一讲得通的那份指出来（理由照给）
		best, why = textReadings[0], "这几种读法里只有一种解得出可读文本，其余解出来是二进制"
	}
	return ots.Verdict{
		Code: codecAmbiguous,
		Values: map[string]any{
			"readings":   readings,
			"mostLikely": best,
			"why":        why,
			"normalized": fixes,
			"input":      codecPreview(body),
		},
		Note: fmt.Sprintf("%d 种读法都成立（%s），已各给一份结果；多半是 %s：%s",
			len(cands), codecEncodingList(cands), best, why),
	}, nil
}

// codecCleanInput 去掉首尾空白和成对引号，把让步记下来。
func codecCleanInput(text string) (string, []string) {
	var fixes []string
	s := text
	if t := strings.TrimSpace(s); t != s {
		fixes = append(fixes, "outer-whitespace")
		s = t
	}
	for _, q := range []string{`"`, "'", "`"} {
		if len(s) > 2 && strings.HasPrefix(s, q) && strings.HasSuffix(s, q) {
			s = strings.TrimSuffix(strings.TrimPrefix(s, q), q)
			fixes = append(fixes, "quotes-trimmed")
			break
		}
	}
	return s, fixes
}

// codecCandidates 给出所有讲得通的读法，顺序即倾向（越靠前越像现场真正的那个）。
func codecCandidates(s string) ([]codecReading, []string) {
	var out []codecReading
	var notes []string

	if r, _ := codecReadJWT(s); r != nil {
		return []codecReading{*r}, nil
	}
	if r, _ := codecReadURL(s); r != nil {
		out = append(out, *r)
	}
	if r, _ := codecReadUnicode(s); r != nil {
		out = append(out, *r)
	}
	hr, hprob := codecReadHex(s)
	br, bprob := codecReadBase64(s)
	if bprob != "" && strings.Contains(bprob, "又有") {
		notes = append(notes, bprob+"，所以没按 base64 读")
	}
	switch {
	case hprob == "" && bprob == "":
		out = append(out, *hr, *br)
	case hprob == "":
		out = append(out, *hr)
	case bprob == "":
		out = append(out, *br)
	}
	return out, notes
}

func codecReadPinned(s, enc string) (codecReading, string) {
	var (
		r       *codecReading
		problem string
	)
	switch enc {
	case "base64", "base64url":
		r, problem = codecReadBase64(s)
		if problem == "" && r.Encoding != enc {
			// ★ 两种字母表只在串里真出现 +/ 或 -_ 时才分得出。指错了要说破为什么无所谓 / 有什么要紧
			return codecReading{}, fmt.Sprintf(
				"这段按 %s 读才对（串里出现的字符决定字母表），指成 %s 会把 %s 当成别的字", r.Encoding, enc, enc)
		}
	case "hex":
		r, problem = codecReadHex(s)
	case "url":
		r, problem = codecReadURL(s)
	case "unicode":
		r, problem = codecReadUnicode(s)
	default:
		return codecReading{}, fmt.Sprintf("encoding 只认 base64 / base64url / hex / url / unicode，给的是 %q", enc)
	}
	if problem != "" {
		return codecReading{}, problem
	}
	return *r, ""
}

// codecReadBase64 认标准 / URL 安全两种字母表，并且允许没有填充。
//
// ★★ 不许收窄成「只认 StdEncoding」：不带 `=` 填充的 URL 安全串是现在的常态，
// 只认标准字母表的话这类输入会一律报「非法字符」，而人看到的症状是
// 「这串明明写着 base64 却解不开」。
//
// ★ 4n+1 这种长度单独说破：base64 每 4 个字符出 3 个字节，4n+1 在数学上不可能存在 ——
// 报「非法字符」是浪费人时间，真相是「它不是 base64」。
func codecReadBase64(s string) (*codecReading, string) {
	hasStd := strings.ContainsAny(s, "+/")
	hasURL := strings.ContainsAny(s, "-_")
	if hasStd && hasURL {
		return nil, "既有 +/ 又有 -_：标准字母表和 URL 安全字母表不会同时出现在一个值里，多半是两段值粘成了一行"
	}
	core := strings.TrimRight(s, "=")
	if core == "" {
		return nil, "去掉末尾的填充符之后什么都不剩 —— 只有 `=`，没有内容"
	}
	var fixes []string
	if strings.ContainsAny(core, " \t\r\n") {
		if strings.ContainsAny(core, "\r\n") {
			fixes = append(fixes, "line-wrapped") // openssl / `base64` 命令行每 76 列折一行
		} else {
			fixes = append(fixes, "inner-whitespace")
		}
		core = strings.Join(strings.Fields(core), "")
	}
	if len(core)%4 == 1 {
		return nil, fmt.Sprintf("去掉填充后 %d 个字符 —— base64 每 4 个字符出 3 个字节，4n+1 这种长度不可能出现，所以它不是 base64", len(core))
	}
	urlSafe := strings.ContainsAny(core, "-_")
	for i := 0; i < len(core); i++ {
		if core[i] == '-' || core[i] == '_' {
			continue
		}
		if strings.IndexByte(base64Alphabet, core[i]) < 0 {
			return nil, fmt.Sprintf("第 %d 个字符 %q 不在 base64 字母表里", i+1, string(core[i]))
		}
	}
	enc := base64.RawStdEncoding
	name := "base64"
	if urlSafe {
		enc = base64.RawURLEncoding
		name = "base64url"
		fixes = append(fixes, "url-safe-alphabet")
	}
	if len(core)%4 != 0 && !strings.HasSuffix(s, "=") {
		// ★ 只看去掉填充之后的长度会把「本来带填充」的串也报成「我替你补了填充」——
		// normalized 是对外承诺做过什么让步，报错了就等于凭空认下一桩没做过的事
		fixes = append(fixes, "padding-added")
	}
	data, err := enc.DecodeString(core)
	if err != nil {
		return nil, fmt.Sprintf("按 %s 解不开：%s", name, err)
	}
	if len(data) == 0 {
		return nil, "解出来是零字节"
	}
	return &codecReading{Encoding: name, Data: data, Fixes: dedupeStrings(fixes)}, ""
}

// codecReadHex 认 `48656c6c6f`、`48 6c …`、`0x486…`。
//
// ★ 不把 `-` 当分隔符：`ab-cd` 也可能是 base64url，把连字符吃掉就替人抹掉了一处歧义。
// 要按分隔写法读，用空格 / 冒号 / 点。
func codecReadHex(s string) (*codecReading, string) {
	var fixes []string
	core := s
	if len(core) > 2 && (strings.HasPrefix(core, "0x") || strings.HasPrefix(core, "0X")) {
		core = core[2:]
		fixes = append(fixes, "hex-0x-prefix")
	}
	if strings.ContainsAny(core, " \t\r\n:.") {
		fixes = append(fixes, "separators-removed")
		core = strings.Join(strings.FieldsFunc(core, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ':' || r == '.'
		}), "")
	}
	if core == "" {
		return nil, "去掉 0x 和分隔符之后什么都不剩"
	}
	if len(core)%2 != 0 {
		return nil, fmt.Sprintf("十六进制字符是 %d 个，奇数 —— 一个字节占两位，凑不成整字节", len(core))
	}
	for i := 0; i < len(core); i++ {
		if strings.IndexByte(hexDigits, core[i]) < 0 {
			return nil, fmt.Sprintf("第 %d 个字符 %q 不是十六进制", i+1, string(core[i]))
		}
	}
	data, err := hex.DecodeString(strings.ToLower(core))
	if err != nil {
		return nil, fmt.Sprintf("按十六进制解不开：%s", err)
	}
	return &codecReading{Encoding: "hex", Data: data, Fixes: dedupeStrings(fixes)}, ""
}

// codecReadURL 按百分号转义读。★ `+` 的两种意思分开给，不选一个。
func codecReadURL(s string) (*codecReading, string) {
	if !strings.Contains(s, "%") {
		return nil, "没有百分号转义（找不到 %）"
	}
	if i := firstBadPercent(s); i >= 0 {
		return nil, fmt.Sprintf("第 %d 个字符处的 %% 后面不是两位十六进制 —— 多半是抄漏了一位", i+1)
	}
	strict, err := url.PathUnescape(s)
	if err != nil {
		return nil, fmt.Sprintf("按 URL 转义解不开：%s", err)
	}
	if strict == "" {
		return nil, "解出来是空串"
	}
	var fixes []string
	extra := map[string]any{}
	// ★ 查询串里 `+` 是空格，路径里 `+` 就是加号：同一段字符串两个答案。
	// 密码里带 `+`、从地址栏抄下来就是这种局，只给一个等于替人猜一个密码
	if strings.Contains(s, "+") {
		asQuery, err := url.PathUnescape(strings.ReplaceAll(s, "+", " "))
		if err == nil && asQuery != strict {
			extra["plusAmbiguous"] = true
			extra["asQuery"] = codecPreview(asQuery)
			extra["asPath"] = codecPreview(strict)
			fixes = append(fixes, "plus-in-url")
		}
	}
	return &codecReading{Encoding: "url", Data: []byte(strict), Fixes: fixes, Extra: extra}, ""
}

// firstBadPercent 找到第一个「% 后面不是两位十六进制」的位置；没有则 -1。
func firstBadPercent(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) || strings.IndexByte(hexDigits, s[i+1]) < 0 || strings.IndexByte(hexDigits, s[i+2]) < 0 {
			return i
		}
	}
	return -1
}

// codecReadUnicode 认 `\xNN` 和 `\uNNNN`（含 UTF-16 代理对）。Windows 路径不算转义。
func codecReadUnicode(s string) (*codecReading, string) {
	if !strings.Contains(s, `\x`) && !strings.Contains(s, `\u`) {
		return nil, "没有 \\x 或 \\u 转义"
	}
	if codecWindowsPath.MatchString(s) {
		return nil, `看着像 Windows 路径（开头是盘符），不当转义串解 —— 那种 \newfolder 里的 \n 是真字符`
	}
	var out []byte
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out = append(out, s[i])
			i++
			continue
		}
		switch {
		case i+3 < len(s) && s[i+1] == 'x' &&
			strings.IndexByte(hexDigits, s[i+2]) >= 0 && strings.IndexByte(hexDigits, s[i+3]) >= 0:
			v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
			if err != nil {
				return nil, fmt.Sprintf("第 %d 个字符处的 \\x 后面不是两位十六进制", i+1)
			}
			out = append(out, byte(v))
			i += 4
		case i+5 < len(s) && s[i+1] == 'u':
			r, n, ok := scanUnicodeEscape(s[i:])
			if !ok {
				return nil, fmt.Sprintf("第 %d 个字符处的 \\u 不完整（代理对要高代理紧跟低代理）", i+1)
			}
			out = append(out, string(r)...)
			i += n
		default:
			return nil, fmt.Sprintf("第 %d 个字符处是个认不出的转义开头", i+1)
		}
	}
	if len(out) == 0 {
		return nil, "解出来是零字节"
	}
	return &codecReading{Encoding: "unicode", Data: out}, ""
}

// scanUnicodeEscape 按 UTF-16 算：★ 高代理必须接一个低代理，两个合起来才是一个字。
// 只解单个 \uXXXX 的话，emoji 和生僻字会解成两个孤立的代理字符。
func scanUnicodeEscape(s string) (rune, int, bool) {
	if len(s) < 6 {
		return 0, 0, false
	}
	hi, err := strconv.ParseUint(s[2:6], 16, 32)
	if err != nil {
		return 0, 0, false
	}
	switch {
	case hi >= 0xD800 && hi <= 0xDBFF:
		if len(s) < 12 || s[6] != '\\' || s[7] != 'u' {
			return 0, 0, false
		}
		lo, err := strconv.ParseUint(s[8:12], 16, 32)
		if err != nil || lo < 0xDC00 || lo > 0xDFFF {
			return 0, 0, false
		}
		return rune(hi-0xD800)<<10 + rune(lo-0xDC00) + 0x10000, 12, true
	case hi >= 0xDC00 && hi <= 0xDFFF:
		return 0, 0, false // 落单的低代理不是一个字
	}
	return rune(hi), 6, true
}

// codecReadJWT 认出「这是一个签名令牌」。★ 只解码，不验签 —— 验签要密钥，那是鉴权的事。
func codecReadJWT(s string) (*codecReading, string) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || !strings.HasPrefix(s, "ey") {
		return nil, "不是 eyJ… 开头三段点分的写法"
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Sprintf("第一段按 URL 安全 base64 解不开：%s", err)
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Sprintf("第二段按 URL 安全 base64 解不开：%s", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(h)), "{") || !strings.HasPrefix(strings.TrimSpace(string(p)), "{") {
		return nil, "三段虽然各自能解，但前两节不是 JSON，不是签名令牌"
	}
	return &codecReading{
		Encoding: "jwt",
		Data:     p, // 载荷是人都要看的那一段，走通用的「是不是文本」判定
		Extra:    map[string]any{"shape": "jwt", "header": codecPreview(string(h))},
	}, ""
}

// ── 结果分档 ──

func codecVerdictFromReading(r codecReading, body string, fixes []string) ots.Verdict {
	info, readable := codecBytesInfo(r.Data)
	values := map[string]any{
		"encoding":   r.Encoding,
		"normalized": append(append([]string{}, fixes...), r.Fixes...),
		"input":      codecPreview(body),
	}
	for k, v := range r.Extra {
		values[k] = v
	}
	for k, v := range info {
		values[k] = v
	}
	code := codecDecodedText
	note := fmt.Sprintf("按 %s 解出 %d 字节，是可读文本", r.Encoding, len(r.Data))
	switch {
	case r.Encoding == "jwt":
		note = fmt.Sprintf("认出签名令牌：解出载荷 %d 字节（★ 没验签，也不该在这里验）", len(r.Data))
	case readable && stillHasEncoding(string(r.Data)):
		code = codecStillEncoded
		note = "解出来还剩一层编码 —— 多半是被编了两遍，再解一次"
	case !readable:
		code = codecDecodedBytes
		if values["looksLikeGbk"] == true {
			note = fmt.Sprintf("按 %s 解出 %d 字节：不是合法 UTF-8，但字节范围像 GBK 中文（老设备固件常见）", r.Encoding, len(r.Data))
		} else {
			note = fmt.Sprintf("按 %s 解出 %d 字节：不是文本。★ 解码没失败，是这些字节本来就不该当文本读", r.Encoding, len(r.Data))
		}
	}
	if len(r.Fixes) > 0 {
		note += "；途中放宽过 " + strings.Join(r.Fixes, "、")
	}
	return ots.Verdict{Code: code, Values: values, Note: note}
}

// codecBytesInfo 判「这批字节能不能当文本读」，并给出各种写法。
//
// ★ 合法 UTF-8 和「可打印」是两件事：只看 utf8.Valid 会把一坨控制字符（它们合法！）
// 当成文本给人；只看非 UTF-8 又会把老设备里的 GBK 中文说成「二进制」—— 这几种处置不一样。
func codecBytesInfo(data []byte) (map[string]any, bool) {
	out := map[string]any{"byteLen": len(data)}
	weird := 0
	for _, b := range data {
		if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') || b == 0x7f {
			weird++
		}
	}
	isUTF8 := utf8.Valid(data)
	readable := isUTF8 && float64(weird)/float64(len(data)) <= 0.05
	out["utf8"] = isUTF8
	if looksLikeGBK(data) {
		out["looksLikeGbk"] = true
	}
	if readable {
		text := string(data)
		if len(text) > maxCodecText {
			text = string([]rune(text)[:maxCodecText]) // ★ 按字切，别把一个字砍成半个
			out["textTruncated"] = true
		}
		out["text"] = text
	} else {
		out["hexDump"] = codecHexDump(data)
	}
	return out, readable
}

// looksLikeGBK 只判断「像不像」，不解码：项目不引字符表依赖，
// 而硬解出来的中文是猜的 —— 猜出来的中文比乱码更容易被人当成事实。
func looksLikeGBK(data []byte) bool {
	if len(data) == 0 || utf8.Valid(data) {
		return false
	}
	pairs := 0
	for i := 0; i+1 < len(data); {
		lead, trail := data[i], data[i+1]
		if lead >= 0x81 && lead <= 0xfe && trail >= 0x40 && trail <= 0xfe && trail != 0x7f {
			pairs++
			i += 2
			continue
		}
		if lead < 0x80 {
			i++
			continue
		}
		return false
	}
	return pairs >= 2
}

func codecHexDump(data []byte) string {
	limit := min(len(data), maxCodecHex)
	rows := make([]string, 0, limit/16+1)
	for i := 0; i < limit; i += 16 {
		end := min(i+16, limit)
		cells := make([]string, 0, end-i)
		for _, b := range data[i:end] {
			cells = append(cells, fmt.Sprintf("%02x", b))
		}
		rows = append(rows, strings.Join(cells, " "))
	}
	s := strings.Join(rows, "\n")
	if limit < len(data) {
		s += fmt.Sprintf("\n… 还有 %d 字节没显示", len(data)-limit)
	}
	return s
}

// stillHasEncoding 解完一次还剩百分号或 \\x —— 双重编码。★ 只认「还能再解」，不去猜要解几遍。
func stillHasEncoding(s string) bool {
	if strings.Contains(s, "%") && firstBadPercent(s) == -1 && strings.Count(s, "%") >= 1 {
		return true
	}
	return strings.Contains(s, `\x`) || strings.Contains(s, `\u`)
}

// ── 正向编码 ──

func codecEncodeAll(text string) ots.Verdict {
	return ots.Verdict{
		Code: codecEncoded,
		Values: map[string]any{
			"base64":    base64.StdEncoding.EncodeToString([]byte(text)),
			"base64url": base64.RawURLEncoding.EncodeToString([]byte(text)),
			"hex":       hex.EncodeToString([]byte(text)),
			"url":       url.PathEscape(text),
			"unicode":   codecEscapeUnicode(text),
			"charLen":   len([]rune(text)),
			"byteLen":   len(text),
		},
		// ★ Note 不复述内容：那是密码的可能性太高，而 Note 会进日志、会发给 AI
		Note: fmt.Sprintf("编好了（%d 字 / %d 字节）。★ base64 不是加密，别拿它藏密码", len([]rune(text)), len(text)),
	}
}

func codecEncodePinned(text, enc string) (any, error) {
	switch enc {
	case "base64", "base64url", "hex", "url", "unicode":
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"encoding 只认 base64 / base64url / hex / url / unicode，给的是 %q", enc)
	}
	all := codecEncodeAll(text).Values
	return ots.Verdict{
		Code:   codecEncoded,
		Values: map[string]any{"encoding": enc, "result": all[enc], "byteLen": all["byteLen"]},
		Note:   fmt.Sprintf("按 %s 编好了，%v 字节", enc, all["byteLen"]),
	}, nil
}

// codecEscapeUnicode 把非 ASCII 编成 \uXXXX。★ 中文按 UTF-16 走：
// 生僻字和 emoji 在 UTF-16 里是代理对，只写一个 \uXXXX 的设备会解出半个字。
func codecEscapeUnicode(text string) string {
	var sb strings.Builder
	for _, r := range text {
		switch {
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&sb, `\u%04x`, r)
		case r < 0x7f:
			sb.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			v := r - 0x10000
			fmt.Fprintf(&sb, `\u%04x\u%04x`, 0xD800+(v>>10), 0xDC00+(v&0x3FF))
		}
	}
	return sb.String()
}

// ── 杂项 ──

func codecPreview(s string) string {
	r := []rune(s)
	if len(r) <= 120 {
		return s
	}
	return string(r[:80]) + fmt.Sprintf("…（共 %d 字符）", len(r))
}

func codecEncodingList(rs []codecReading) string {
	names := make([]string, 0, len(rs))
	for _, r := range rs {
		names = append(names, r.Encoding)
	}
	return strings.Join(names, " / ")
}

func codecJoin(notes []string, def string) string {
	if len(notes) == 0 {
		return def
	}
	return strings.Join(notes, "；")
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
