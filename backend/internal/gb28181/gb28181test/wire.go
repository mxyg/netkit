// Package gb28181test 是只用于测试的假设备与假平台。
//
// ★ 它刻意不 import internal/gb28181：假的这一台如果和探测端共用同一套
//
//	SIP 序列化、同一个 digest 公式，两边一起写错的地方就永远测不出来 ——
//	digest 的拼接顺序、Via 的 branch 前缀、正文的 Content-Length，
//	恰恰是「两边都错就互相圆上了」的那几处。这里按规范另写一份，
//	只实现探测与注册会碰到的那几种报文。
//
// ★ 每一种模式都对得上现场一种毛病、也就对得上一个判定码。
//
//	看这里列的模式就能数出「这条线要分几档」，反过来说也一样：
//	新增一档判定，这里就得有一种模式来验它。
package gb28181test

import (
	"crypto/md5" // #nosec G501 —— digest 规定的就是 MD5
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// msg 是一条自己解析出来的 SIP 报文（只到测试用得上的那份程度）。
type msg struct {
	IsRequest bool
	Method    string
	URI       string
	Status    int
	Reason    string
	Headers   [][2]string
	Body      []byte
}

// parse 独立实现一遍解析：行分隔按 \n 切再吃 \r，头名大小写无关。
func parse(raw []byte) (msg, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	head, body, _ := strings.Cut(text, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return msg{}, fmt.Errorf("空报文")
	}
	first := strings.TrimSpace(lines[0])
	var m msg
	if strings.HasPrefix(first, "SIP/2.0 ") {
		rest := strings.TrimSpace(strings.TrimPrefix(first, "SIP/2.0 "))
		sp := strings.IndexByte(rest, ' ')
		digits, reason := rest, ""
		if sp > 0 {
			digits, reason = rest[:sp], strings.TrimSpace(rest[sp+1:])
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return m, fmt.Errorf("状态码不像数字：%q", digits)
		}
		m.Status, m.Reason = n, reason
	} else {
		i := strings.LastIndex(first, " SIP/2.0")
		if i <= 0 {
			return m, fmt.Errorf("起始行不像 SIP：%q", first)
		}
		method, uri, _ := strings.Cut(first[:i], " ")
		m.IsRequest, m.Method, m.URI = true, method, uri
	}
	for _, ln := range lines[1:] {
		name, value, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		m.Headers = append(m.Headers, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	m.Body = []byte(body)
	return m, nil
}

func (m msg) header(name string) string {
	want := strings.ToLower(name)
	for _, h := range m.Headers {
		if strings.ToLower(h[0]) == want {
			return h[1]
		}
	}
	return ""
}

func (m msg) headers(name string) []string {
	want := strings.ToLower(name)
	var out []string
	for _, h := range m.Headers {
		if strings.ToLower(h[0]) == want {
			out = append(out, h[1])
		}
	}
	return out
}

// param 从一条头里取 ";key=value"，包括尖括号里那种不合规位置上的。
func param(headerValue, key string) string {
	want := strings.ToLower(key)
	for _, p := range strings.Split(strings.ReplaceAll(headerValue, ">", ""), ";") {
		k, v, ok := strings.Cut(p, "=")
		if ok && strings.ToLower(strings.TrimSpace(k)) == want {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// build 序列化。★ 请求行版本号在最后、响应行在最前 —— 这一条要是和探测端
// 一起写反了，两边就永远测不出来。正文按原始字节接上去（GBK 那几种模式要用）。
func build(start string, headers [][2]string, body []byte) []byte {
	var b strings.Builder
	b.WriteString(start)
	b.WriteString("\r\n")
	for _, h := range headers {
		b.WriteString(h[0])
		b.WriteString(": ")
		b.WriteString(h[1])
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return append([]byte(b.String()), body...)
}

// withCL 建一条带正文的报文，Content-Length 自己算。
func withCL(start string, headers [][2]string, body []byte) []byte {
	hs := append(append([][2]string{}, headers...), [2]string{"Content-Length", strconv.Itoa(len(body))})
	return build(start, hs, body)
}

func cseqOf(m msg) (uint64, string) {
	v := m.header("CSeq")
	seq, method, _ := strings.Cut(v, " ")
	n, _ := strconv.ParseUint(strings.TrimSpace(seq), 10, 64)
	return n, strings.TrimSpace(method)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401
	return hex.EncodeToString(sum[:])
}

// digestResponse 是自己按 RFC 2617 那份公式独立算的（跟探测端那份对不上就是错）。
func digestResponse(user, realm, pw, nonce, method, uri, qop, nc, cnonce string) string {
	ha1 := md5hex(user + ":" + realm + ":" + pw)
	ha2 := md5hex(method + ":" + uri)
	if qop == "" {
		return md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	return md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// authorization 从一条应答头里把参数取出来（大小写无关）。
func authorization(m msg) map[string]string {
	v := strings.TrimSpace(strings.TrimPrefix(m.header("Authorization"), "Digest"))
	out := map[string]string{}
	for _, part := range strings.Split(v, ",") {
		k, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(val), `"`)
	}
	return out
}
