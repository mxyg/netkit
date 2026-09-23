// ── net.mac.random ──
//
// ★★ 「随机 MAC」看着是随便凑六个字节，凑错了当场就有两种病，而且症状都不指向 MAC：
//
//  1. 忘了清组播位（第一个字节最低位）—— 这不是一个设备地址，交换机学到这种地址会丢帧，
//     表现是「配上了能发出去、回包收不到」，人第一反应去查对端防火墙
//  2. 忘了置本机管理位（第 2 低位）—— 那是在**别人名下的 OUI 里造地址**。
//     真设备就在那一段里活着，撞上了就是两台机器同一个 MAC：ARP 表来回翻，
//     症状是「两个人同时时通时不通」，比配不上难查十倍
//
// ★ 但「保留厂商前缀去克隆」是现场真需求（有些系统的授权绑在 MAC 前缀上），
//
//	所以这一档不能不给 —— 给的前提是把话说破：这时置的是别人的地址段，
//	随机部分只剩 24 位，撞真设备的概率是**算得出来的**，工具要把这个数摆出来让人自己决定。
//	「别拿风险砍功能范围」在这儿的落地就是：风险用「算给你看 + 说清是谁名下的」来处置，不是少做。
package tools

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"net.yuhox.com/netkit/internal/ots"
)

const (
	macRandomGenerated = "random-generated" // 本机管理 + 单播，随便用
	macCloneGenerated  = "clone-generated"  // ★ 保留了别人名下的厂商前缀
	maxRandomMACs      = 10                 // 再多就是批量造地址池，那是 DHCP 的事
)

var macRandomTool = ots.Tool{
	Name:  "net.mac.random",
	Class: ots.ClassRead,
	Summary: "生成随机的以太网地址（MAC）：默认置本机管理位、清组播位，保证能当设备源地址用，" +
		"且每次调用都不同（用系统随机源，不是可复现的伪随机）。" +
		"给了 prefix 就是克隆模式：保留前几个字节不动、其余随机，判定码 clone-generated，" +
		"并算出随机部分剩多少位、和该段真设备撞上的量级 —— 保留厂商前缀等于在别人名下的地址段里造地址。" +
		"判定码：random-generated（本机管理 + 单播，安全）/ clone-generated（含厂商前缀，有撞车面）。" +
		"★ 只生成字符串，不碰任何网卡；要改本机地址得自己去系统里改。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "count": {"type": "integer", "description": "生成几个，1~10，默认 1。一批里不会重复。"},
	    "prefix": {"type": "string", "description": "要保留的前几个字节（1~5 字节，如 00:1a:2b，也可以直接给一个完整 MAC 取它的前三段）。给了就是克隆模式：随机部分只剩后几个字节。"}
	  }
	}`),
	Invoke: doMACRandom,
}

type macRandomArgs struct {
	Count  int    `json:"count,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

// parseMACPrefix 收 1~5 个字节的前缀，也收一个完整 MAC（取前三段）。
func parseMACPrefix(s string) ([]byte, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		// ★ 不许悄悄退化成纯随机：给了 prefix 又当没看见，人拿去的就是一个
		// 「不像那台设备」的地址，而排查方向会被带到授权系统上去
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"prefix 给了但内容是空的 —— 要克隆就把前几个字节写全，不要就整个去掉这个参数")
	}
	// 整段地址是现场最常见的用法：抄下目标设备的 MAC，我取它的前三段
	if !strings.ContainsAny(text, ":-.") {
		b, err := hexBytes(strings.ToLower(text))
		if err != nil || len(b) == 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"prefix %q 看不懂：要 1~5 个字节（00:1a:2b 或 001a2b），或者直接给一个完整 MAC", text)
		}
		if len(b) >= 6 {
			b = b[:3]
		}
		return checkPrefixBytes(b, text)
	}
	// ★ 首尾就是分隔符的要拒：`00:` 十有八九是「两段只抄了一段」，
	// 当成一段用等于把别人的地址段换错一位
	if strings.HasPrefix(text, ":") || strings.HasSuffix(text, ":") ||
		strings.HasPrefix(text, "-") || strings.HasSuffix(text, "-") ||
		strings.HasPrefix(text, ".") || strings.HasSuffix(text, ".") {
		return nil, ots.Errf(ots.ErrInvalidArgument, "prefix %q 首尾多了个分隔符 —— 是要几段就写几段，别少抄一段", text)
	}
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ':' || r == '-' || r == '.' })
	if len(fields) >= 6 {
		full, err := parseMAC(text)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "prefix 看不懂：%s", err)
		}
		return full[:3], nil
	}
	if len(fields) == 0 || len(fields) > 5 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"prefix 给的是 %d 段：%s —— 要 1~5 个字节（如 00:1a:2b），或者直接给一个完整 MAC", len(fields), text)
	}
	bs := make([]byte, 0, len(fields))
	for _, f := range fields {
		if len(f) > 2 {
			return nil, ots.Errf(ots.ErrInvalidArgument, "prefix 的 %q 超过一个字节（两位十六进制）", f)
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "prefix 的 %q 不是十六进制", f)
		}
		bs = append(bs, byte(v))
	}
	return checkPrefixBytes(bs, text)
}

// checkPrefixBytes ★ 组播位置着的前缀直接拒：那种段（`33:33`、`01:00:5e`…）本来就不是
// 设备地址段，照它克隆出来的东西不能当源地址 —— 宁可不给，也不给一个用不了的成品。
func checkPrefixBytes(bs []byte, text string) ([]byte, error) {
	if bs[0]&0x01 != 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"prefix %s 的第一个字节 %02x 组播位是 1 —— 那是组播地址段，不是设备地址段，"+
				"照它生成出来的地址不能当源地址用。换成目标设备真实的前三段，或者去掉 prefix 要纯随机地址",
			text, bs[0])
	}
	return bs, nil
}

func doMACRandom(ctx context.Context, raw json.RawMessage) (any, error) {
	var a macRandomArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	n := a.Count
	if n == 0 {
		n = 1
	}
	if n < 0 || n > maxRandomMACs {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"count 要 1~%d（给的是 %d）—— 要一批几十个地址池，那是 DHCP 的事，不是这里", maxRandomMACs, n)
	}
	prefix := []byte(nil)
	code := macRandomGenerated
	if a.Prefix != "" { // ★ 不是 TrimSpace：只给了空格的 prefix 也要报错，不许悄悄退化成纯随机
		p, err := parseMACPrefix(a.Prefix)
		if err != nil {
			return nil, err
		}
		prefix = p
		code = macCloneGenerated
	}
	macs, err := randomMACs(prefix, n)
	if err != nil {
		return nil, err
	}
	values := map[string]any{
		"count":   len(macs),
		"macs":    macs,
		"mode":    map[bool]string{true: "clone", false: "random"}[code == macCloneGenerated],
		"formats": macFormats(macs[0]),
	}
	bits := 40
	if code == macCloneGenerated {
		bits = (6 - len(prefix)) * 8
		values["prefix"] = formatMAC(prefix, ":")
		if prefix[0]&0x02 == 0 {
			values["vendorBlock"] = true // ★ 这个前缀在 IEEE 的登记名下，不是本机管理段
		}
	} else {
		// 第一个字节是特意凑出来的：清掉最低位（组播）、置上第 2 低位（本机管理）
		values["firstOctetPolicy"] = "组播位清 0、本机管理位置 1，其余 6 位随机"
	}
	values["randomBits"] = bits
	values["space"] = new(big.Int).Lsh(big.NewInt(1), uint(bits)).String()
	return ots.Verdict{Code: code, Values: values, Note: macRandomNote(code, values)}, nil
}

// randomMACs 生成 n 个不重复的地址。
//
// ★★ 用 crypto/rand，不许换 math/rand：math/rand 不播种时每次进程启动序列一样，
//
//	两台机器同时用这个工具就会配出**同一个** MAC，而那正是这个功能要防的事。
//	随机位里剔掉全零 / 全一：那两个值在链路层各有特殊含义，不是设备地址。
func randomMACs(prefix []byte, n int) ([]string, error) {
	seen := make(map[string]bool, n)
	out := make([]string, 0, n)
	for len(out) < n {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			return nil, ots.Errf(ots.ErrInternal, "系统随机源取不到：%s", err)
		}
		copy(buf, prefix)
		if len(prefix) == 0 {
			buf[0] = buf[0]&0xFC | 0x02 // 清组播位、置本机管理位
		}
		if allSame(buf, 0x00) || allSame(buf, 0xff) {
			continue
		}
		s := formatMAC(buf, ":")
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

func macFormats(m string) map[string]string {
	buf, err := hexBytes(strings.ReplaceAll(m, ":", ""))
	if err != nil {
		return map[string]string{"colon": m}
	}
	return map[string]string{
		"colon": formatMAC(buf, ":"), "dash": formatMAC(buf, "-"),
		"dot": formatDotMAC(buf), "bare": formatMAC(buf, ""),
	}
}

func macRandomNote(code string, v map[string]any) string {
	first, _ := v["macs"].([]string)
	one := ""
	if len(first) > 0 {
		one = first[0]
	}
	switch code {
	case macRandomGenerated:
		return fmt.Sprintf("生成了 %d 个 %s 这类地址：**本机管理位置着、组播位清着**，"+
			"所以能安全当源地址用，也不在任何厂商名下的地址段里。随机部分 40 位，局域网里撞不上真设备。"+
			"★ 只是字符串，网卡地址没动", v["count"], one)
	case macCloneGenerated:
		warn := ""
		if v["vendorBlock"] == true {
			warn = "。★ 前缀 " + v["prefix"].(string) + " 的本机管理位是清的，等于**在 IEEE 登记给某家厂商的段里造地址**：" +
				"这个段里的真设备是活着的，随机部分只剩 " + fmt.Sprint(v["randomBits"]) + " 位（" +
				fmt.Sprint(v["space"]) + " 个组合），撞上就是两台机器同一个 MAC —— " +
				"那种故障是「几台机器同时时通时不通」，比配不上难查得多"
		}
		return fmt.Sprintf("按前缀 %v 生成了 %d 个地址（如 %s）：前几个字节原样保留，其余随机%s",
			v["prefix"], v["count"], one, warn)
	}
	return ""
}
