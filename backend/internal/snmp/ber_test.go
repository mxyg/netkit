package snmp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// ── 整数 ──

func Test整数按最少字节的补码编(t *testing.T) {
	// 逐个钉死：多一个 0x00 或少一个 0xff 都会让个别实现比长度比不过。
	cases := []struct {
		v    int64
		want string
	}{
		{0, "00"},
		{1, "01"},
		{127, "7f"},
		{128, "0080"},     // 128 的最高位是 1，必须补 0 前缀，否则读成 -128
		{-1, "ff"},        //
		{-128, "80"},      // 一字节就够，不该写成 0xffffff80
		{-129, "ff7f"},    //
		{255, "00ff"},     //
		{256, "0100"},     //
		{-256, "ff00"},    //
		{65535, "00ffff"}, //
		{math.MaxInt32, "7fffffff"},
		{math.MinInt32, "80000000"},
		{math.MaxInt64, "7fffffffffffffff"},
		{math.MinInt64, "8000000000000000"},
	}
	for _, c := range cases {
		got := intContent(c.v)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%d 编成了 %s，要 %s", c.v, hex.EncodeToString(got), c.want)
		}
		back, err := AsInt(got)
		if err != nil {
			t.Errorf("%d 回读失败：%v", c.v, err)
			continue
		}
		if back != c.v {
			t.Errorf("%d 回读成 %d", c.v, back)
		}
	}
}

func Test无符号域高位置一时补前导零(t *testing.T) {
	// ★ 4294967295 是 Counter32 绕回前的最后一个值，也是这条最容易踩的号：
	//   不补 0 前缀的话 AsInt 把它读成 -1，界面上就是「流量是负的」。
	cases := []struct {
		v    uint64
		want string
	}{
		{0, "00"},
		{1, "01"},
		{127, "7f"},
		{128, "0080"},
		{255, "00ff"},
		{65535, "00ffff"},
		{4294967295, "00ffffffff"},
		{4294967296, "0100000000"},
		{18446744073709551615, "00ffffffffffffffff"},
	}
	for _, c := range cases {
		got := uintContent(c.v)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%d 编成了 %s，要 %s", c.v, hex.EncodeToString(got), c.want)
		}
		back, err := AsUint(got)
		if err != nil {
			t.Errorf("%d 回读失败：%v", c.v, err)
			continue
		}
		if back != c.v {
			t.Errorf("%d 回读成 %d", c.v, back)
		}
	}
	// 补零这件事只针对无符号：有符号那边同一个号是 -1，不许被补成 00ff。
	if hex.EncodeToString(intContent(-1)) != "ff" {
		t.Error("有符号的 -1 被动过了")
	}
}

// ── OID ──

func TestOID的头两节合成一字节(t *testing.T) {
	// internet = 1.3.6 是 SNMP 里出现最多的开头，第一字节必须是 40*1+3 = 43 = 0x2b。
	c, err := OIDContent("1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(c) != "2b06010201010100" {
		t.Errorf("1.3.6.1.2.1.1.1.0 编成 %s", hex.EncodeToString(c))
	}
	back, err := AsOID(c)
	if err != nil {
		t.Fatal(err)
	}
	if back != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("回读成 %s", back)
	}
}

func TestOID的大节按128进制带续位(t *testing.T) {
	// 一个节 >127 时要拆成多字节、除最后一字节外都置 0x80。
	// 这些号在真 MIB 里就有：企业私有 OID、ifIndex 拼出来的行号。
	cases := []struct {
		oid  string
		want string
	}{
		{"1.3.6.1.4.1.9.9.23", "2b06010401090917"},
		// 2011 = 15*128+91 → 0x8f 0x5b；华为的私有 MIB 就挂在这个号下
		{"1.3.6.1.4.1.2011.2.23.3", "2b060104018f5b021703"},
		// 63377 = 3*16384 + 111*128 + 17 → 三字节，前两字节都带续位
		{"1.3.6.1.4.1.63377.1", "2b0601040183ef1101"},
		// 头两节合成 40*1+0 = 40 = 0x28：别按 "2b" 硬编，那是 1.3 专用
		{"1.0.0", "2800"},
	}
	for _, c := range cases {
		got, err := OIDContent(c.oid)
		if err != nil {
			t.Errorf("%s 编码失败：%v", c.oid, err)
			continue
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s 编成 %s，要 %s", c.oid, hex.EncodeToString(got), c.want)
			continue
		}
		back, err := AsOID(got)
		if err != nil {
			t.Errorf("%s 回读失败：%v", c.oid, err)
			continue
		}
		if back != c.oid {
			t.Errorf("%s 回读成 %s", c.oid, back)
		}
	}
}

func TestOID编不出的几种输入(t *testing.T) {
	bad := []string{
		"",                         // 空
		"1",                        // 只有一节：40*a+b 至少要两节
		"1.abc",                    // 不是数
		"3.1.2",                    // 第一字节装不下 a=3
		"1.40.2",                   // b 只能 0..39
		"1.-2.3",                   // 负节
		"99999999999999999999.1.2", // 超出 uint64
	}
	for _, s := range bad {
		if _, err := appendOID(nil, s); err == nil {
			t.Errorf("%q 居然编出来了", s)
		} else if !errors.Is(err, ErrBadOID) {
			t.Errorf("%q 报的是另一种错：%v", s, err)
		}
	}
}

func TestOID最后一节带续位算截断(t *testing.T) {
	// 末尾还挂着 0x80 说明这一节被切掉了，不许当成一个正常的节读出来。
	if _, err := AsOID([]byte{0x2b, 0x86}); err == nil {
		t.Error("被截断的 OID 读成功了")
	}
	if _, err := AsOID(nil); err == nil {
		t.Error("空内容的 OID 读成功了")
	}
}

// ── OID 顺序 ──

func TestOID按节比数值不是比字符串(t *testing.T) {
	// walk 全靠「下一个 OID」的顺序，比错一次就漏一整棵子树。
	// 字符串序里 "10" 排在 "9" 前面 —— 这一条就是那条分界线。
	ascending := []string{
		"1.3.6.1.2.1.1",
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.2.2.1.1.1",
		"1.3.6.1.2.1.2.2.1.1.2",
		"1.3.6.1.2.1.2.2.1.1.10",
		"1.3.6.1.2.1.31.1.1.1.6.1",
	}
	for i := 0; i < len(ascending)-1; i++ {
		a, b := ascending[i], ascending[i+1]
		if CmpOID(a, b) >= 0 {
			t.Errorf("%s 应该排在 %s 前面", a, b)
		}
		if CmpOID(b, a) <= 0 {
			t.Errorf("%s 应该排在 %s 后面", b, a)
		}
	}
	if CmpOID("1.3.6.1.2.1.1", "1.3.6.1.2.1.1") != 0 {
		t.Error("同一个 OID 比出了大小")
	}
	// 带不带前导点都一样
	if CmpOID(".1.3.6", "1.3.6") != 0 {
		t.Error("前导点影响了顺序")
	}
}

func TestOIDUnder只看子树不看字符串前缀(t *testing.T) {
	yes := [][2]string{{"1.3.6.1.2.1.2.2.1.1.3", "1.3.6.1.2.1.2.2.1"}}
	no := [][2]string{
		{"1.3.6.1.2.1.31.1.1.1.6.3", "1.3.6.1.2.1.2.2.1.1"},
		// 这条最容易混：22 那一棵在字符串上以 "2" 打头的树里
		{"1.3.6.1.2.1.22.1.1.1", "1.3.6.1.2.1.2"},
		// 前缀本身不算「在这棵子树里」—— walk 收口要用它
		{"1.3.6.1.2.1.2", "1.3.6.1.2.1.2"},
	}
	for _, p := range yes {
		if !OIDUnder(p[0], p[1]) {
			t.Errorf("%s 明明在 %s 下面", p[0], p[1])
		}
	}
	for _, p := range no {
		if OIDUnder(p[0], p[1]) {
			t.Errorf("%s 被误判成在 %s 下面", p[0], p[1])
		}
	}
}

// ── TLV 拆解 ──

func Test长度域长格式也认(t *testing.T) {
	// 一个 sysDescr 超 127 字节时设备就用 0x81 这一档，再长是 0x82。
	// 只认短格式的话症状是「有的设备一读就报错」，而描述串恰恰是最容易超 127 的那一栏。
	for _, n := range []int{1, 127, 128, 300, 70000} {
		body := bytes.Repeat([]byte{'x'}, n)
		var raw []byte
		switch {
		case n < 128:
			raw = append([]byte{TagOctetString, byte(n)}, body...)
		case n <= 0xff:
			raw = append([]byte{TagOctetString, 0x81, byte(n)}, body...)
		case n <= 0xffff:
			raw = append([]byte{TagOctetString, 0x82, byte(n >> 8), byte(n)}, body...)
		default:
			raw = append([]byte{TagOctetString, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
		}
		e, rest, err := Read(raw)
		if n > maxPDULen {
			if !errors.Is(err, ErrTooLarge) {
				t.Errorf("超长的一栏 %d 字节报的是 %v，要 ErrTooLarge", n, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%d 字节的读失败：%v", n, err)
			continue
		}
		if len(rest) != 0 || len(e.Val) != n {
			t.Errorf("%d 字节的读成了 %d，剩 %d", n, len(e.Val), len(rest))
		}
	}
}

func Test坏包一律报错不许panic(t *testing.T) {
	// 对端是一台来路不明的设备：它说什么长度都不能按它说的去切。
	cases := map[string]string{
		"空":           "",
		"只有一字节":       "30",
		"不定长":         "30800000",
		"长度说明后面没有字节":  "3082",
		"声明比实际长":      "30050201",
		"最外层不是序列":     "020100",
		"长度说明占的字节数离谱": "308f0102030405060708090a0b0c0d0e",
		"超长长度":        "30847fffffff0102",
		"截断的整数":       "30030203",
		"零长度的整数":      "30020200",
		"九个字节的整数":     "30090209010203040506070809",
	}
	for name, s := range cases {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("%s 的测试数据本身写错了：%v", name, err)
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s 解析时 panic 了：%v", name, p)
				}
			}()
			if _, err := Parse(b); err == nil {
				t.Errorf("%s 居然解析成功了", name)
			}
		}()
	}
}

func Test随机垃圾喂进来也只是报错(t *testing.T) {
	// 不是挑几个样本，而是真的乱敲：一个解析器只要能在随机输入上 panic，
	// 就一定能在现场某个设备的怪包上 panic。
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		n := rng.Intn(40)
		b := make([]byte, n)
		rng.Read(b)
		if n > 3 { // 前几个字节按 BER 的头改一改，提高命中深度
			b[0] = byte(rng.Intn(256))
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("随机输入 %x 让解析 panic 了：%v", b, p)
				}
			}()
			_, _ = Parse(b)
			_, _, _ = Read(b)
			_, _ = AsOID(b)
			_, _ = AsInt(b)
			_, _ = AsUint(b)
		}()
	}
}

func Test整数与OID的输入边界(t *testing.T) {
	if _, err := AsInt(nil); !errors.Is(err, ErrBadInt) {
		t.Error("空内容的整数没报错")
	}
	if _, err := AsInt(make([]byte, 9)); !errors.Is(err, ErrBadInt) {
		t.Error("九字节的整数没报错（会溢出）")
	}
	if _, err := AsUint(make([]byte, 10)); !errors.Is(err, ErrBadInt) {
		t.Error("十字节的无符号数没报错（uint64 装不下）")
	}
	// 九字节只认「一个 0x00 前缀 + 八字节」这一种写法：
	// 那是 Counter64 满值的样子，绕过去的（比如 00 00 + 七字节）就是乱编的长度。
	if n, err := AsUint(append([]byte{0}, bytes.Repeat([]byte{0xff}, 8)...)); err != nil || n != math.MaxUint64 {
		t.Errorf("Counter64 满值读成 %v/%v", n, err)
	}
	if _, err := AsUint(append([]byte{0, 0}, bytes.Repeat([]byte{0xff}, 7)...)); err == nil {
		t.Error("两个前导零也照收了，长度域就没人守了")
	}
	// 负数计数器：有的老设备会把 Counter32 绕回写成 -1，读出来要能看出是 -1，
	// 不能悄悄变 4294967295 —— 那会算出一个天文数字的速率。
	if n, err := AsInt([]byte{0xff, 0xff, 0xff, 0xff}); err != nil || n != -1 {
		t.Errorf("ff ff ff ff 读成 %v/%v，要 -1", n, err)
	}
}

func Test异常标签三种要分开认(t *testing.T) {
	// 走到树末尾是 walk 的正常收口，"没有这一栏" 是该换 OID 继续问。
	if !IsException(TagEndOfMibView) || !IsException(TagNoSuchInstance) || !IsException(TagNoSuchObject) {
		t.Error("三种「没有」有一种没认出来")
	}
	if IsException(TagNull) || IsException(TagOctetString) {
		t.Error("普通类型被当成异常了")
	}
	if !(VarBind{Tag: TagNoSuchInstance}).Missing() || (VarBind{Tag: TagNoSuchInstance}).EndOfMib() {
		t.Error("noSuchInstance 和 endOfMibView 混成了一种")
	}
	if !(VarBind{Tag: TagEndOfMibView}).EndOfMib() || (VarBind{Tag: TagEndOfMibView}).Missing() {
		t.Error("endOfMibView 和 noSuchInstance 混成了一种")
	}
	if !strings.Contains((VarBind{Tag: TagCounter64}).TypeName(), "64") {
		t.Error("Counter64 的类型名没带上位宽，界面上和 Counter32 分不开")
	}
}
