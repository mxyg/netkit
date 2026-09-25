package media

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
)

// AMF0 的单元测试。★ 这里盯的是「对端说了算的那些长度」：
// 假服务器的好话端到端测着就够，恶意或写坏的计数得单独一档证明挡得住。

// decodeAll 把整段字节当一串值读（不走命令那格的裸 double 特例）。
func decodeAll(b []byte) ([]AMFValue, error) {
	var out []AMFValue
	for len(b) > 0 {
		v, rest, err := amf0DecodeOne(b, 0)
		if err != nil {
			return out, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

func Test编一圈再解回来一模一样(t *testing.T) {
	vals := []any{
		"connect",
		float64(1),
		map[string]any{"app": "live", "tcUrl": "rtmp://10.0.0.5/live", "flashVer": "LNX.11,1,0,175"},
		map[string]any{"level": "status", "code": "NetStream.Play.Start", "description": "Started playing stream"},
		true,
		false,
		nil,
		[]any{"a", float64(2), nil},
	}
	b, err := AMF0Encode(vals...)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeAll(b)
	if err != nil {
		t.Fatalf("自己编的自己解不回来：%v", err)
	}
	if len(out) != len(vals) {
		t.Fatalf("参数个数不对：%d vs %d", len(out), len(vals))
	}
	if out[0] != "connect" || out[2].(map[string]any)["app"] != "live" {
		t.Errorf("解回来对不上：%+v", out[0:3])
	}
	if out[3].(map[string]any)["code"] != "NetStream.Play.Start" {
		t.Errorf("onStatus 那一段解错了：%+v", out[3])
	}
	arr, ok := out[7].([]any)
	if !ok || len(arr) != 3 || arr[0] != "a" || arr[1] != float64(2) || arr[2] != nil {
		t.Errorf("strict array 解错了：%+v", out[7])
	}

	// 过 65535 的字符串必须换 long string，不能把长度截成两字节写出去
	long := strings.Repeat("x", 70000)
	lb, err := AMF0Encode(long)
	if err != nil {
		t.Fatal(err)
	}
	if lb[0] != amf0LongString {
		t.Errorf("超 65535 的字符串没走 long string，标记是 0x%02x", lb[0])
	}
	lo, err := decodeAll(lb)
	if err != nil {
		t.Errorf("long string 解不回来：%v", err)
	}
	if len(lo) != 1 || lo[0] != long {
		t.Errorf("long string 解回来不对：%d 个", len(lo))
	}

	// ★ 两字节长度字段的边界：65535 走普通 string，65536 起才换 long string。
	//   门槛写错一位的话，长度回绕，整条命令从这一格开始错位，而报错会说成
	//   「认不出的标记」—— 现场看着像是服务器的问题。
	justFits, err := AMF0Encode(strings.Repeat("y", 0xffff))
	if err != nil {
		t.Fatal(err)
	}
	if justFits[0] != amf0String {
		t.Errorf("65535 字节的字符串该走普通 string，标记是 0x%02x", justFits[0])
	}
	overByOne, err := AMF0Encode(strings.Repeat("y", 0xffff+1))
	if err != nil {
		t.Fatal(err)
	}
	if overByOne[0] != amf0LongString {
		t.Errorf("65536 字节的字符串该走 long string，标记是 0x%02x", overByOne[0])
	}
	if got, err := decodeAll(overByOne); err != nil || len(got) != 1 || got[0] != strings.Repeat("y", 0xffff+1) {
		t.Errorf("65536 字节的字符串过了一圈变了样：%v %v", err, len(got))
	}
}

// 属性名没有「长」这一说：两字节写不下的就该报错，不能回绕。
func Test属性名过长时报错而不是截长度(t *testing.T) {
	_, err := AMF0Encode(map[string]any{strings.Repeat("k", 0xffff+1): "v"})
	if err == nil {
		t.Fatal("65536 字节的属性名居然编出去了")
	}
	if _, err := AMF0Encode(map[string]any{strings.Repeat("k", 0xffff): "v"}); err != nil {
		t.Errorf("刚好 65535 的属性名不该报错：%v", err)
	}
}

// 同一份输入必须编出同一份字节：属性乱序写的话，测试与日志都会跟着抖。
func Test对象按key排序写所以字节固定(t *testing.T) {
	obj := map[string]any{"z": "1", "a": "2", "m": "3"}
	first, err := AMF0Encode(obj)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := AMF0Encode(obj)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("第 %d 次编码和第一次不一样", i)
		}
	}
	idxA := strings.Index(string(first), "a")
	idxM := strings.Index(string(first), "m")
	idxZ := strings.Index(string(first), "z")
	if !(idxA < idxM && idxM < idxZ) {
		t.Errorf("属性没按 key 排序写：a@%d m@%d z@%d", idxA, idxM, idxZ)
	}
}

// 自称天文数字的长度必须先挡住：不然大头还没到，内存先没了。
func Test自称超长的字符串与数组直接被拒(t *testing.T) {
	var hugeArr []byte
	hugeArr = append(hugeArr, amf0StrictArray)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], amf0MaxElem)
	hugeArr = append(hugeArr, n[:]...)

	cases := []struct {
		name string
		in   []byte
	}{
		{"string 自称 65535 却没正文", []byte{amf0String, 0xff, 0xff, 'a'}},
		{"long string 自称 40 亿", append([]byte{amf0LongString, 0xff, 0xff, 0xff, 0xff}, 'a')},
		{"array 自称 40 亿", []byte{amf0StrictArray, 0xff, 0xff, 0xff, 0xff}},
		{"array 自称 6 万条却没正文", hugeArr},
		{"属性名自称 65535 却没正文", []byte{amf0Object, 0xff, 0xff, 'k', amf0Null}},
	}
	for _, c := range cases {
		if _, _, err := amf0DecodeOne(c.in, 0); err == nil {
			t.Errorf("%s：居然解开了", c.name)
		}
	}
}

// 一条命令里参数与属性的硬上限：对端连着写也不能把探测端撑爆。
func Test对象属性条数与参数个数有上限(t *testing.T) {
	var b []byte
	b = append(b, amf0Object)
	for i := 0; i < amf0MaxProps+5; i++ {
		b = append(b, amf0RawString(fmt.Sprintf("k%d", i))...)
		b = append(b, amf0Number, 0, 0, 0, 0, 0, 0, 0, 1)
	}
	if _, _, err := amf0DecodeOne(b, 0); err == nil {
		t.Error("属性条数超上限却解开了")
	}

	var args []byte
	for i := 0; i < amf0MaxCmdArgs+3; i++ {
		args = append(args, amf0Number, 0, 0, 0, 0, 0, 0, 0, 1)
	}
	out, err := AMF0DecodeArgs(args)
	if err == nil {
		t.Errorf("参数个数超上限却没报错（解出 %d 个）", len(out))
	}
	if len(out) > amf0MaxCmdArgs {
		t.Errorf("报错之前读过头了：%d > %d", len(out), amf0MaxCmdArgs)
	}
}

// 嵌套太深直接报错，不顺着对端给的层级往栈上钻。
func Test嵌套超过上限直接报错(t *testing.T) {
	var b []byte
	for i := 0; i < amf0MaxDepth+2; i++ {
		b = append(b, amf0Object)
		b = append(b, amf0RawString("n")...)
	}
	b = append(b, amf0Number, 0, 0, 0, 0, 0, 0, 0, 1)
	for i := 0; i < amf0MaxDepth+2; i++ {
		b = append(b, 0x00, 0x00, amf0ObjectEnd)
	}
	if _, _, err := amf0DecodeOne(b, 0); err == nil || !strings.Contains(err.Error(), "嵌套") {
		t.Errorf("深嵌套没按「嵌套超过」报出来：%v", err)
	}
}

// 截断：砍在任何位置都不许凑出完整的那一串参数（半截值当成完整的更糟）。
func Test读到一半就到底了不许当读完了(t *testing.T) {
	full, err := AMF0Encode("onStatus", float64(0), nil,
		map[string]any{"code": "NetStream.Play.Start", "level": "status"}, []any{"a", float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(full); cut++ {
		out, err := AMF0DecodeArgs(full[:cut])
		if err == nil && len(out) == 5 {
			t.Errorf("砍到 %d 字节却解出了完整的 5 个参数", cut)
		}
	}
	out, err := AMF0DecodeArgs(full)
	if err != nil {
		t.Fatalf("完整的一份反倒解不开：%v", err)
	}
	if len(out) != 5 {
		t.Fatalf("完整的一份只解出 %d 个：%+v", len(out), out)
	}
}

// 认不出的标记照实报错（AMF3 的那几种 0x0d~0x10 之类），不猜。
func Test认不出的标记照实报错(t *testing.T) {
	for _, m := range []byte{0x0b, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x41} {
		if _, _, err := amf0DecodeOne([]byte{m, 0x00}, 0); err == nil ||
			!strings.Contains(err.Error(), "认不出") {
			t.Errorf("标记 0x%02x 没按「认不出」报错：%v", m, err)
		}
	}
}

// ecma array：那 4 字节计数各家写法不一，读到哪儿以 end marker 为准。
func TestECMA数组的计数不作数(t *testing.T) {
	var b []byte
	b = append(b, amf0ECMAArray)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], 999) // 乱写的计数
	b = append(b, n[:]...)
	b = append(b, amf0RawString("code")...)
	b = append(b, amf0String)
	b = append(b, amf0RawString("NetStream.Play.Start")...)
	b = append(b, 0x00, 0x00, amf0ObjectEnd)
	v, rest, err := amf0DecodeOne(b, 0)
	if err != nil {
		t.Fatalf("计数写歪就解不开了：%v", err)
	}
	if len(rest) != 0 {
		t.Errorf("没读完：%d 字节剩着", len(rest))
	}
	if v.(map[string]any)["code"] != "NetStream.Play.Start" {
		t.Errorf("解错了：%+v", v)
	}
}

// 对象里某个属性值写坏：报错要带上是哪个属性，不然现场无从下手。
func Test属性解不开时说清是哪个属性(t *testing.T) {
	var b []byte
	b = append(b, amf0Object)
	b = append(b, amf0RawString("good")...)
	b = append(b, amf0String)
	b = append(b, amf0RawString("ok")...)
	b = append(b, amf0RawString("broken")...)
	b = append(b, amf0String, 0x00, 0x05, 'x') // 自称 5 字节只有 1
	if _, _, err := amf0DecodeOne(b, 0); err == nil ||
		!strings.Contains(err.Error(), "broken") {
		t.Errorf("没把出问题的属性名带出来：%v", err)
	}
}

// 引用型（0x07）：不还原对象，但也不能报错把整条命令丢掉。
func Test引用标记不报错(t *testing.T) {
	v, _, err := amf0DecodeOne([]byte{amf0Reference, 0x00, 0x02}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(map[string]any)
	if !ok || m["__ref"] != float64(2) {
		t.Errorf("reference 解得不对：%+v", v)
	}
}

// ★ 命令的第二格（transaction id）常见两种写法：带 0x00 标记，或干脆 8 个裸
//
//	double 字节。两种都要吃得下，而且不能把后面的对象当成数字吞掉。
func Test裸double序号与带标记序号都吃得下(t *testing.T) {
	marked, err := AMF0Encode("_result", float64(2), map[string]any{"f": float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	bare := []byte{amf0String}
	bare = append(bare, amf0RawString("_result")...)
	var tx [8]byte
	binary.BigEndian.PutUint64(tx[:], math.Float64bits(2))
	bare = append(bare, tx[:]...)
	rest, err := AMF0Encode(map[string]any{"f": float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	bare = append(bare, rest...)

	for _, c := range []struct {
		name string
		in   []byte
	}{
		{"带标记", marked},
		{"裸 double", bare},
	} {
		out, err := AMF0DecodeArgs(c.in)
		if err != nil {
			t.Errorf("%s：%v", c.name, err)
			continue
		}
		if len(out) != 3 || out[0] != "_result" || out[1] != float64(2) {
			t.Errorf("%s：前两格不对：%+v", c.name, out)
			continue
		}
		obj, ok := out[2].(map[string]any)
		if !ok || obj["f"] != float64(1) {
			t.Errorf("%s：第三格被当成数字吞了：%+v", c.name, out[2])
		}
	}
}

// 第二格已经是合法的 AMF0 标记时，不许按裸 double 猜 —— 那是另一种错位。
func Test第二格有标记时不按裸double猜(t *testing.T) {
	in := []byte{amf0String, 0x00, 0x04, 'n', 'a', 'm', 'e', amf0Boolean, 0x01}
	out, err := AMF0DecodeArgs(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[1] != true {
		t.Errorf("带标记的第二格被读成数字了：%+v", out)
	}
}

// 数字边界：Inf 与极小值过一圈不许变形（判定里「0 字节」和「没这个字段」是分开的）。
func Test数字边界不奇怪(t *testing.T) {
	b, err := AMF0Encode(math.Inf(-1), math.SmallestNonzeroFloat64, math.MaxFloat64)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0] != math.Inf(-1) || out[1] != math.SmallestNonzeroFloat64 ||
		out[2] != math.MaxFloat64 {
		t.Errorf("数字过了一圈变形了：%+v", out)
	}
}

// 编不了的类型要报错，不能默默写成别的东西。
func Test编不了的类型直接报错(t *testing.T) {
	if _, err := AMF0Encode(struct{ A int }{1}); err == nil {
		t.Error("结构体居然编出去了")
	}
	if _, err := AMF0Encode(map[string]any{"bad": make(chan int)}); err == nil {
		t.Error("对象里塞 channel 居然编出去了")
	}
}

// amf0SliceCap：自称几万个元素也只能先预留 64 格。
func Test数组预留不超过64格(t *testing.T) {
	if got := amf0SliceCap(1 << 20); got != 64 {
		t.Errorf("上限没守住：%d", got)
	}
	if got := amf0SliceCap(3); got != 3 {
		t.Errorf("小的该照给：%d", got)
	}
}
