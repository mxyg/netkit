package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

// net.mac.random 的测试钉三件事：
//
//	① 生成出来的必须**能当源地址**：组播位清着、本机管理位置着 —— 错一位的症状
//	   都不是「生成失败」，而是配上去之后收不到回包或撞真设备，很难往这儿想；
//	② 克隆模式必须把风险算出来给人看（随机剩几位、是不是在厂商名下），
//	   而不是默默给一个「看起来一样」的地址；
//	③ 随机源不许换成可复现的伪随机：两台机器配出同一个 MAC 是这个功能的存在理由的反面。

func rndRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doMACRandom(context.Background(), b)
	if err != nil {
		t.Fatalf("跑不动：%v", err)
	}
	return v.(ots.Verdict)
}

func rndMACs(t *testing.T, v ots.Verdict) []string {
	t.Helper()
	m, ok := v.Values["macs"].([]string)
	if !ok {
		t.Fatalf("macs 不在或类型不对（%T）", v.Values["macs"])
	}
	return m
}

func firstByte(t *testing.T, mac string) byte {
	t.Helper()
	b, err := hexBytes(strings.Replace(mac, ":", "", 1)[0:2])
	if err != nil {
		t.Fatalf("%q 第一段不是十六进制：%v", mac, err)
	}
	return b[0]
}

// ── 默认（本机管理 + 单播）──

func Test默认生成的一定是单播且本机管理(t *testing.T) {
	v := rndRun(t, map[string]any{"count": 10})
	for _, m := range rndMACs(t, v) {
		b := firstByte(t, m)
		if b&0x01 != 0 {
			t.Errorf("%s 组播位没清（首字节 %02x）—— 这种地址不能当源地址", m, b)
		}
		if b&0x02 == 0 {
			t.Errorf("%s 本机管理位没置（首字节 %02x）—— 那是在别人名下的 OUI 里造地址", m, b)
		}
	}
}

func Test一批里不许重复(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range rndMACs(t, rndRun(t, map[string]any{"count": 10})) {
		if seen[m] {
			t.Fatalf("一批里出现了两遍 %s", m)
		}
		seen[m] = true
	}
	if len(seen) != 10 {
		t.Errorf("count=10 只给出 %d 个", len(seen))
	}
}

// ★ 这一条钉的是随机源：换成一播种就固定的伪随机，两台机器会配出同一个地址。
func Test两次调用不许给出一样的地址(t *testing.T) {
	a := rndMACs(t, rndRun(t, nil))[0]
	b := rndMACs(t, rndRun(t, nil))[0]
	if a == b {
		t.Fatalf("两次都给出 %s —— 随机源像是可复现的", a)
	}
}

func Test生成的地址自己判自己是本机管理(t *testing.T) {
	m := rndMACs(t, rndRun(t, nil))[0]
	a := macAsk(t, m)
	if got := a.Values["administered"]; got != "local" {
		t.Errorf("%s 自检 administered = %v", m, got)
	}
	if a.Code != macLocal && a.Code != macVirtual {
		t.Errorf("%s 自检判定 = %s，随机地址不该判成厂商地址", m, a.Code)
	}
}

func Test不填参数就是给一个(t *testing.T) {
	v := rndRun(t, nil)
	if v.Code != macRandomGenerated {
		t.Errorf("判定 = %s", v.Code)
	}
	if len(rndMACs(t, v)) != 1 {
		t.Errorf("macs = %v", v.Values["macs"])
	}
}

// ── 克隆模式 ──

func Test克隆保留前缀并算出随机位(t *testing.T) {
	v := rndRun(t, map[string]any{"prefix": "00:1a:2b"})
	if v.Code != macCloneGenerated {
		t.Fatalf("判定 = %s", v.Code)
	}
	if got := v.Values["randomBits"]; got != 24 {
		t.Errorf("randomBits = %v", got)
	}
	if got := v.Values["space"]; got != "16777216" {
		t.Errorf("space = %v，三段固定就是 24 位、16777216 个组合", got)
	}
	if v.Values["vendorBlock"] != true {
		t.Error("00:1a:2b 的机器管理位是清的 —— 必须在别人名下这一档里标出来")
	}
	for _, m := range rndMACs(t, v) {
		if !strings.HasPrefix(m, "00:1a:2b:") {
			t.Errorf("%s 没保留前缀", m)
		}
	}
	if !strings.Contains(v.Note, "时通时不通") {
		t.Errorf("note 没把撞车的症状说清：%s", v.Note)
	}
}

// 前缀本身是本机管理段（比如从 Docker 桥上抄的 02:42）就不算冒充厂商。
func Test本机管理前缀不算冒充厂商(t *testing.T) {
	v := rndRun(t, map[string]any{"prefix": "02:42"})
	if v.Code != macCloneGenerated {
		t.Fatalf("判定 = %s", v.Code)
	}
	if _, ok := v.Values["vendorBlock"]; ok {
		t.Error("02: 开头是本机管理段，不在任何厂商名下，不该标 vendorBlock")
	}
	if got := v.Values["randomBits"]; got != 32 {
		t.Errorf("randomBits = %v", got)
	}
}

// 抄整台设备的地址当 prefix 是最顺手的用法：取前三段，不能拿六个字节当前缀
// （那样随机位是 0，等于把人家地址原样复制，还自称「随机」）。
func Test给完整MAC只取前三段(t *testing.T) {
	v := rndRun(t, map[string]any{"prefix": "00:1A:2B:3C:4D:5E"})
	if got := v.Values["prefix"]; got != "00:1a:2b" {
		t.Errorf("prefix = %v", got)
	}
	if got := v.Values["randomBits"]; got != 24 {
		t.Errorf("randomBits = %v，后三段必须还是随机的", got)
	}
	m := rndMACs(t, v)[0]
	if m == "00:1a:2b:3c:4d:5e" {
		t.Error("整段照抄了，那不是随机地址")
	}
}

func Test裸写前缀也认(t *testing.T) {
	v := rndRun(t, map[string]any{"prefix": "001a2b"})
	if got := v.Values["prefix"]; got != "00:1a:2b" {
		t.Errorf("prefix = %v", got)
	}
}

// ★ 组播段的前缀做出来的东西不能当源地址：宁可不给，也不给一个用不了的成品。
func Test组播段前缀当场拒(t *testing.T) {
	for _, p := range []string{"33:33", "01:00:5e", "ff"} {
		b, _ := json.Marshal(map[string]any{"prefix": p})
		_, err := doMACRandom(context.Background(), b)
		if err == nil {
			t.Errorf("%s 是组播段，不该收", p)
			continue
		}
		if !strings.Contains(err.Error(), "组播") {
			t.Errorf("%s 的报错没说是组播段：%v", p, err)
		}
	}
}

// 给了 prefix 又写空，退化成纯随机是最坏的处理：人以为在克隆。
func TestPrefix只给空格不许悄悄退化成随机(t *testing.T) {
	b, _ := json.Marshal(map[string]any{"prefix": "   "})
	if _, err := doMACRandom(context.Background(), b); err == nil {
		t.Fatal("空 prefix 被当成「没给」，悄悄给了一个纯随机地址")
	}
}

func Test前缀段数和字节数都有限制(t *testing.T) {
	// 一段到五段都该收：五段就是「只随机最后一个字节」，换一台设备的身份够用
	for _, p := range []string{"00", "00:11", "00:11:22:33:44"} {
		b, _ := json.Marshal(map[string]any{"prefix": p})
		if _, err := doMACRandom(context.Background(), b); err != nil {
			t.Errorf("%q 该收：%v", p, err)
		}
	}
	for _, p := range []string{"zz:zz", "00:", ":00", "000:11", "00:11:22:33:44:55:66"} {
		b, _ := json.Marshal(map[string]any{"prefix": p})
		if _, err := doMACRandom(context.Background(), b); err == nil {
			t.Errorf("%q 该拒", p)
		}
	}
}

func Test数量越界当场拒(t *testing.T) {
	for _, n := range []int{-1, -5, 11, 9999} {
		b, _ := json.Marshal(map[string]any{"count": n})
		if _, err := doMACRandom(context.Background(), b); err == nil {
			t.Errorf("count=%d 收下了", n)
		}
	}
	b, _ := json.Marshal(map[string]any{"count": 10})
	if _, err := doMACRandom(context.Background(), b); err != nil {
		t.Errorf("count=10 是该收的上限：%v", err)
	}
}

func Test未知参数不许放行(t *testing.T) {
	var sch map[string]any
	if err := json.Unmarshal(macRandomTool.Schema, &sch); err != nil {
		t.Fatal(err)
	}
	if sch["additionalProperties"] != false {
		t.Error("schema 许了未知参数")
	}
}

// 前缀几乎填满六个字节时，随机位只剩 8 —— 一批里容易撞自己，必须仍然给足且不重复
func Test窄前缀下一批仍不重复且非全零(t *testing.T) {
	v := rndRun(t, map[string]any{"prefix": "00:00:00:00:00", "count": 10})
	seen := map[string]bool{}
	for _, m := range rndMACs(t, v) {
		if seen[m] {
			t.Fatalf("重复：%s", m)
		}
		seen[m] = true
		if m == "00:00:00:00:00:00" {
			t.Error("全零不是设备地址")
		}
	}
}

// ── 输出形态 ──

func Test几种写法对得上第一个地址(t *testing.T) {
	v := rndRun(t, nil)
	m := rndMACs(t, v)[0]
	f, ok := v.Values["formats"].(map[string]string)
	if !ok {
		t.Fatalf("formats 类型不对（%T）", v.Values["formats"])
	}
	if f["colon"] != m {
		t.Errorf("formats.colon = %q，第一个地址是 %q", f["colon"], m)
	}
	if f["bare"] != strings.ReplaceAll(m, ":", "") {
		t.Errorf("连写对不上：%q", f["bare"])
	}
}

func Test随机MAC工具声明(t *testing.T) {
	if macRandomTool.Name != "net.mac.random" {
		t.Errorf("name = %s", macRandomTool.Name)
	}
	if macRandomTool.Class != ots.ClassRead {
		t.Errorf("只生成字符串，class = %s", macRandomTool.Class)
	}
	for _, code := range []string{macRandomGenerated, macCloneGenerated} {
		if !strings.Contains(macRandomTool.Summary, code) {
			t.Errorf("Summary 里没提 %s", code)
		}
	}
	if !strings.Contains(macRandomTool.Summary, "不碰任何网卡") {
		t.Error("必须说清它不改本机地址，否则 AI 会以为生成完就生效了")
	}
}

func Test两种判定都有人话(t *testing.T) {
	for _, args := range []map[string]any{nil, {"prefix": "00:1a:2b"}} {
		v := rndRun(t, args)
		if v.Note == "" {
			t.Errorf("%v 没给人话", args)
		}
	}
}
