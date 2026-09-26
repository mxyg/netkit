package flow

// 脱敏。这一格是硬闸门，不是可选项。
//
// 为什么默认就脱敏：这张表会被序列化成 JSON 发给界面、打进诊断包、
// 也可能被现场的人整段贴给 AI。抓包文件里躺着的是设备的账号密码、
// SNMP 团体名、国标平台的 digest response —— 这些一旦跟着结果出去，
// 就不是「泄露了一次」，是「泄露给每一个拿到这份文件的人，且永远收不回来」。
//
// ★ 三条口径：
//
//  1. 凭据的**值**一律不出这一层，连截断形式都不给（截一半的密码还是密码的一部分）。
//     只给「有 / 没有」加形状（长度），因为「设备根本没带 Authorization」与
//     「带了但平台不认」是两种病，这一格必须能分开。
//  2. **用户名/设备编号留着**。现场要问的就是「哪个账号被拒了」，
//     把用户名也糊掉等于把这功能废了；它本身不是秘密（国标编号是公开编址）。
//  3. **自由文本过一道再出去**。地址里的 user:pass@、SOAP 头里的 Password、
//     SDP 里的 a=crypto 与 a=key-*（SDES 密钥），这些是「藏在文本里的凭据」，
//     浅一层正则洗不干净 —— 所以洗的是**具体那几格**，不是一把正则扫全文。

import (
	"fmt"
	"strings"
)

// 头的本地名（小写、去前缀）里出现这些词的，值一律当凭据。
var secretNameParts = []string{
	"authorization", "proxy-authorization", "www-authenticate-secret",
	"password", "passwd", "pwd", "psk", "secret", "token", "apikey", "api-key",
	"nonce", "opaque", "response", "cnonce", "digest",
	"community", "credential", "key-param", "crypto", "session-key", "aes-key",
	"usertoken", "authtoken", "cookie", "set-cookie", "privatekey", "private-key",
}

// 明确可以留名的身份格。★ 它们不许被上面那张表顺手打掉，不然排查就断在这一步：
// 「谁」被拒了，和「他带的钥匙」对不对，是两件事。
var identityNames = map[string]bool{
	"username": true, "user": true, "userid": true, "user-id": true,
	"deviceid": true, "device-id": true, "id": true, "from": true, "to": true,
	"contact": true, "call-id": true, "to-tag": true, "from-tag": true,
}

// localName 把 "WSSE:Password"、"Proxy-Authorization" 洗成 "password"、"proxy-authorization"。
func localName(name string) string {
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// isSecretName 问这一格的名字算不算凭据。
func isSecretName(name string) bool {
	n := localName(name)
	if identityNames[n] {
		return false
	}
	for _, p := range secretNameParts {
		if n == p || strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// shape 只留形状：长度。★ 不给前几个字节 —— "eyJhbGciOi..." 这种开头就够把人认出来是 JWT，
// 而「看出来了」和「拿到了」在泄露这件事上是同一个后果。
func shape(s string) string {
	if s == "" {
		return "（空）"
	}
	return fmt.Sprintf("***（%d 字节）", len(s))
}

// secretField 造一个「这格是凭据，值不留」的字段。
func secretField(name, value string) Field {
	if value == "" {
		return Field{K: name, V: "（没带）", Redacted: true}
	}
	return Field{K: name, V: shape(value), Redacted: true}
}

// field 造一个普通字段：名字算凭据的自动走脱敏那条路。
//
// ★ 所有构造 Field 的地方都要过这一格。手搓 Field{K,V} 是最容易漏的一处：
// 十格里九格是地址，漏的那一格是密码。
func field(name, value string) Field {
	if isSecretName(name) {
		return secretField(name, value)
	}
	return Field{K: name, V: value}
}

// fields 一次造一串。
func fields(kv ...string) []Field {
	var out []Field
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, field(kv[i], kv[i+1]))
	}
	return out
}

// digestFields 拆 Authorization / WWW-Authenticate 那一串。
//
// 留下的：scheme、realm、算法、qop、用户名、URI、nonce 的数量与形状。
// 去掉的：response、nonce、opaque、cnonce 的值 —— response 是密码的替身，
// 拿到它能离线撞库，所以它和密码同罪。
func digestFields(name, value string) ([]Field, int) {
	if value == "" {
		return nil, 0
	}
	scheme, rest := value, ""
	if i := strings.IndexByte(value, ' '); i > 0 {
		scheme, rest = value[:i], value[i+1:]
	}
	out := []Field{{K: name + " 方式", V: scheme}}
	n := 0
	for _, part := range splitAuthParams(rest) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = localName(k)
		v = strings.Trim(v, `"`)
		if isSecretName(k) {
			out = append(out, secretField(k, v))
			n++
			continue
		}
		out = append(out, Field{K: k, V: v})
	}
	return out, n
}

// splitAuthParams 按逗号切，但引号里的逗号不算分隔 —— digest 的 realm 里带逗号是真事，
// 切坏了会把一个参数拆成两个，界面上就多出个凭据格子。
func splitAuthParams(s string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote bool
	)
	for _, r := range s {
		switch {
		case r == '"':
			quote = !quote
			cur.WriteRune(r)
		case r == ',' && !quote:
			if t := strings.TrimSpace(cur.String()); t != "" {
				out = append(out, t)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}

// scrubURI 把 rtsp://user:pass@host、sip:alice@sip.example 里的 userinfo 打掉。
//
// ★ 只打 userinfo：路径与主机是排查必需的（「流地址写错了」就看这一段），
// 而 userinfo 从来不是排查必需的 —— 它存在的唯一意义就是把凭据带到每一跳。
func scrubURI(s string) string {
	i := strings.Index(s, "://")
	from := 0
	if i < 0 {
		if !strings.HasPrefix(strings.ToLower(s), "sip:") && !strings.HasPrefix(strings.ToLower(s), "sips:") {
			return s
		}
		from = strings.IndexByte(s, ':') + 1
	} else {
		from = i + 3
	}
	// userinfo 到下一个 / ; ? 或空白 之前，且这一段里必须有 @。
	end := len(s)
	for j := from; j < len(s); j++ {
		switch s[j] {
		case '/', ';', '?', '>', '"', '\'', ' ', '\t', '\r', '\n':
			end = j
			j = len(s)
		}
	}
	at := strings.LastIndexByte(s[from:end], '@')
	if at < 0 {
		return s
	}
	return s[:from] + "***" + s[from+at:]
}

// scrubText 给自由文本（摘要、错误原因、XML 里顺手带出来的那句）兜底。
//
// 这是一道**补漏的**闸，不是主闸：主闸在上面那几格具体的字段里。
// 只洗这几样：userinfo、常见的 key=value 形式的密码、以及 base64 长串（digest response
// 与 JWT 都是这个形状）。宁可多打一处码，不可漏一处凭据。
func scrubText(s string) string {
	// 1) 任意处的 scheme://user:pass@ 与 sip:user@
	s = scrubUserinfo(s)
	// 2) password=xxx / passwd: xxx / key="xxx" 这一类藏在文本里的
	for _, kv := range []struct{ key, sep string }{
		{"password", "="}, {"passwd", "="}, {"pwd", "="}, {"psk", "="}, {"secret", "="},
		{"token", "="}, {"community", "="}, {"key-param", "="}, {"crypto", "="},
		{"password", ":"}, {"passwd", ":"}, {"secret", ":"}, {"token", ":"}, {"psk", ":"},
	} {
		s = scrubKV(s, kv.key, kv.sep)
	}
	// 3) 20 位以上的 base64 样串（digest response、JWT 的三段、PSK 的编码形式）
	s = scrubLongB64(s)
	return s
}

// scrubUserinfo 打掉文本里每一处 userinfo。
//
// 这里刻意不用「找到一处、替换、再从头找」的写法：没有 @ 的那一处会被再找一遍，
// 循环就走不出去了（写过一次，测试里 2 秒超时才抓住）。
func scrubUserinfo(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		k := strings.Index(s[i:], "://")
		if k < 0 {
			break
		}
		start := i + k // s[start] 是 ':'
		j := start + 3
		for j < len(s) && !uriBreak(s[j]) {
			j++
		}
		seg := s[start+3 : j]
		if at := strings.IndexByte(seg, '@'); at >= 0 {
			b.WriteString(s[i : start+3])
			b.WriteString("***")
			b.WriteString(seg[at:]) // @ 之后是主机，那是排查要用的，留
		} else {
			b.WriteString(s[i:j])
		}
		i = j
	}
	if i < len(s) {
		b.WriteString(s[i:])
	}
	out := b.String()
	// sip: / sips: 的形状没有 "//"， 单独走一遍（ 国标与 VoIP 的设备编号就在这儿）。
	for _, scheme := range []string{"sip:", "sips:"} {
		out = scrubSchemeAt(out, scheme)
	}
	return out
}

func uriBreak(c byte) bool {
	switch c {
	case '/', ' ', '\t', '\r', '\n', '"', '\'', ';', '>', '<', ',', ')', '(':
		return true
	}
	return false
}

func scrubSchemeAt(s, scheme string) string {
	var b strings.Builder
	i := 0
	for {
		k := indexFold(s[i:], scheme)
		if k < 0 {
			break
		}
		at := i + k + len(scheme)
		j := at
		for j < len(s) && !uriBreak(s[j]) {
			j++
		}
		seg := s[at:j]
		b.WriteString(s[i:at])
		if u := strings.IndexByte(seg, '@'); u >= 0 {
			b.WriteString("***")
			b.WriteString(seg[u:])
		} else {
			b.WriteString(seg)
		}
		i = j
	}
	if i < len(s) {
		b.WriteString(s[i:])
	}
	return b.String()
}

func scrubKV(s, key, sep string) string {
	needle := strings.ToLower(key) + sep
	var b strings.Builder
	i := 0
	for {
		k := indexFold(s[i:], needle)
		if k < 0 {
			break
		}
		at := i + k + len(needle) // 值的起点（ 可能先有空白与引号）
		j := at
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '"' || s[j] == '\'') {
			j++
		}
		end := j
		for end < len(s) && s[end] != ' ' && s[end] != ',' && s[end] != ';' && s[end] != '"' &&
			s[end] != '\'' && s[end] != '\r' && s[end] != '\n' && s[end] != '&' && s[end] != '<' && s[end] != '>' {
			end++
		}
		b.WriteString(s[i:j])
		if end > j {
			b.WriteString("***") // 有值：整格打掉， 不留长度以外的任何东西
		} else {
			b.WriteString(s[j:end]) // 本来就是空的：原样留（「没带」这件事本身是答案）
		}
		i = end
	}
	b.WriteString(s[i:])
	return b.String()
}

func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), sub)
}

// scrubLongB64 把「长得像凭据」的那一段连续 base64 样串打掉。
//
// ★ 这一道是补漏的闸，不是主闸：主闸是按字段名洗的那一层，以及 password= 那几种形状。
//
//	  补漏的闸最容易犯的错不是漏一处，是**把排查要用的那一格吃掉，还让人以为脱敏成功了** ——
//	  所以这里的三条口径都是为了让「误伤」不再顺手打死第一手证据：
//
//		① 点号不算 base64 的字符。base64 与 base64url 的字母表里没有 '.'，JWT 拿它分段
//		   （每一段自己就够长，照样打掉）。把 '.' 收进来，"10.0.0.9/Streaming/Channels/101"
//		   就凑成一个 31 格的「密钥」：流地址正是「地址写错了」那一问要读的那一格，
//		   而同一包在 uri 那一格（走按字段的洗法）却完好 —— 同一份包两个说法，
//		   现场就会信那个被吃掉的。
//		② 门槛 32。digest response 是 32 位十六进制，JWT 三段与 PSK 的编码都在 36 以上；
//		   24 那一档恰好把路径段捞进来。短于 32 的凭据归上面那两道闸管。
//		③ 带斜杠的那一段还要再看一眼：真凭据是「一整坨」，斜杠两边的块都长；
//		   路径是「好几个短词」，每个斜杠段都短。所以带斜杠时要求最长的一段够长，
//		   否则当成路径留着。
//
// 仍然会误伤：一段长 OID、base64 的证书链。这里的取舍没变 —— 误伤少一格信息，
// 漏一处泄一份凭据，而凭据一旦跟着结果出去就永远收不回来。
func scrubLongB64(s string) string {
	const minRun = 32
	var b strings.Builder
	run := 0
	start := 0
	flush := func(end int) {
		if run >= minRun && looksLikeBlob(s[start:end]) {
			b.WriteString("***")
		} else {
			b.WriteString(s[start:end]) // 原样还回去：没判定成凭据就不许吃掉一个字
		}
		run = 0
	}
	isB64 := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
	}
	for i := 0; i < len(s); {
		if isB64(s[i]) {
			if run == 0 {
				start = i
			}
			run++
			i++
			continue
		}
		flush(i)
		b.WriteByte(s[i])
		i++
	}
	flush(len(s))
	return b.String()
}

// looksLikeBlob 问这一段够不够像一坨编码出来的凭据。
//
// 斜杠是 base64 的合法字符，也是路径的分隔符 —— 光看字符分不开，看形状分得开：
// 44 字节的 PSK 编码里斜杠是零星的（一坨长块），而流地址是几个短词。
func looksLikeBlob(seg string) bool {
	if !strings.ContainsRune(seg, '/') {
		return true
	}
	longest := 0
	for _, p := range strings.Split(seg, "/") {
		if len(p) > longest {
			longest = len(p)
		}
	}
	return longest >= 16
}
