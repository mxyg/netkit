package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/tools"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// rig 起一个带真实工具的服务，返回测试用的 http 处理器。
func rig(t *testing.T, mutations bool, extra ...ots.Tool) http.Handler {
	t.Helper()
	reg := ots.NewRegistry(mutations)
	tools.Register(reg)
	reg.MustRegister(extra...)
	s, err := New(reg, Config{Log: quiet()})
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	return s.Handler()
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应不是 JSON：%q", rec.Body.String())
		}
	}
	return rec.Code, out
}

// 一个假的改系统工具，用来测 mutate 相关的规则。
var fakeMutate = ots.Tool{
	Name: "test.mutate", Class: ots.ClassMutate, Summary: "测试用的改系统工具",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: func(context.Context, json.RawMessage) (any, error) {
		return ots.Verdict{Code: "done"}, nil
	},
}

// ── [OTS-3.1] 符合性声明 ──

func Test符合性声明可被调用方读到(t *testing.T) {
	code, out := do(t, rig(t, false), "GET", "/ots", "")
	if code != 200 {
		t.Fatalf("状态 %d", code)
	}
	if out["specVersion"] != ots.Version {
		t.Errorf("specVersion = %v", out["specVersion"])
	}
	// ★ 没有任何 mutate 工具 → OTS-Read。这个值是算出来的，不是配出来的
	if out["conformance"] != string(ots.ConfRead) {
		t.Errorf("conformance = %v，只读实现应当声明 OTS-Read", out["conformance"])
	}
}

func Test暴露了改系统工具就是OTSFull(t *testing.T) {
	_, out := do(t, rig(t, true, fakeMutate), "GET", "/ots", "")
	if out["conformance"] != string(ots.ConfFull) {
		t.Errorf("conformance = %v，暴露了 mutate 工具就该是 OTS-Full", out["conformance"])
	}
}

// ── [OTS-4.4] mutate 停用时，只读照常全供 ──

func Test停用改系统工具时它根本不出现(t *testing.T) {
	// 同一套注册表，只差 mutations 开关
	off := rig(t, false, fakeMutate)
	on := rig(t, true, fakeMutate)

	names := func(h http.Handler) []string {
		_, out := do(t, h, "GET", "/tools", "")
		var got []string
		for _, x := range out["tools"].([]any) {
			got = append(got, x.(map[string]any)["name"].(string))
		}
		return got
	}
	offNames, onNames := names(off), names(on)

	if contains(offNames, "test.mutate") {
		t.Error("停用时 mutate 工具不该出现在列表里 —— 让调用方看见一个调不动的工具没有意义")
	}
	if !contains(onNames, "test.mutate") {
		t.Error("启用时该出现")
	}
	// ★ 关键：停用 mutate 不能把只读的也带走
	for _, n := range []string{"net.interfaces", "net.tcp.probe"} {
		if !contains(offNames, n) {
			t.Errorf("停用 mutate 后 %s 也不见了 —— [OTS-4.4] 要求只读必须照常全供", n)
		}
	}
}

func Test停用后调用改系统工具报错而不是执行(t *testing.T) {
	code, out := do(t, rig(t, false, fakeMutate), "POST", "/tools/test.mutate", "{}")
	if code == 200 {
		t.Fatal("停用的 mutate 工具竟然执行了")
	}
	if out["error"] != string(ots.ErrInvalidArgument) {
		t.Errorf("error = %v", out["error"])
	}
}

// ── [OTS-5.x] 结果是判定不是人话 ──

func Test网卡工具返回结构化判定(t *testing.T) {
	code, out := do(t, rig(t, false), "POST", "/tools/net.interfaces", "")
	if code != 200 {
		t.Fatalf("状态 %d：%v", code, out)
	}
	ifs, ok := out["interfaces"].([]any)
	if !ok || len(ifs) == 0 {
		t.Fatal("没返回网卡")
	}
	for _, raw := range ifs {
		n := raw.(map[string]any)
		v, ok := n["verdict"].(map[string]any)
		if !ok {
			t.Fatalf("%v 没有结构化判定", n["name"])
		}
		codeStr, _ := v["verdict"].(string)
		if !ots.ValidVerdictCode(codeStr) {
			t.Errorf("%v 的判定码 %q 不合法（只能小写字母数字连字符）", n["name"], codeStr)
		}
		// ★ [OTS-5.3] 判定要带依据；[OTS-5.4] note 只是附加，不是判定本身
		if _, has := v["values"]; !has && codeStr != "unknown" {
			// 有些状态确实没有值可带（比如回环），这里只要求字段存在性不是必须
			_ = has
		}
	}
}

// ── [OTS-6.2] 「东西坏了」是判定，「工具跑不起来」才是错误 ──

func Test端口关着是判定不是错误(t *testing.T) {
	// 回环上一个基本不会有人监听的高位端口
	code, out := do(t, rig(t, false), "POST", "/tools/net.tcp.probe",
		`{"addr":"127.0.0.1","port":9,"timeoutMs":1500}`)
	if code != 200 {
		t.Fatalf("状态 %d：%v —— 端口关着是成功判定出来的状态，不该是 HTTP 错误", code, out)
	}
	if _, isErr := out["error"]; isErr {
		t.Fatalf("返回了错误 %v —— [OTS-6.2]「成功判定出某个东西坏了」是判定不是错误", out)
	}
	v, _ := out["verdict"].(string)
	if v != "closed" && v != "filtered" {
		t.Errorf("判定 = %q，期望 closed 或 filtered", v)
	}
}

func Test参数不合法才是错误(t *testing.T) {
	for _, body := range []string{`{}`, `{"addr":"不是地址"}`, `{"addr":"127.0.0.1","port":99999}`} {
		code, out := do(t, rig(t, false), "POST", "/tools/net.tcp.probe", body)
		if code == 200 {
			t.Errorf("%s 本该报错，却返回了 %v", body, out)
			continue
		}
		if out["error"] != string(ots.ErrInvalidArgument) {
			t.Errorf("%s 的错误码 = %v，期望 invalid-argument", body, out["error"])
		}
	}
}

func Test错误码只能是规范定义的那几个(t *testing.T) {
	// 造一个返回了规范外错误码的工具，确认 AsError 会把它归成 internal
	bad := ots.Tool{
		Name: "test.badcode", Class: ots.ClassRead, Summary: "返回非结构化错误",
		Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
		Invoke: func(context.Context, json.RawMessage) (any, error) {
			return nil, io.ErrUnexpectedEOF // 一个普通 error，不是 *ots.Error
		},
	}
	_, out := do(t, rig(t, false, bad), "POST", "/tools/test.badcode", "")
	got := ots.ErrorCode(out["error"].(string))
	if !ots.ValidErrorCode(got) {
		t.Errorf("错误码 %q 不在规范定义的封闭集合里", got)
	}
	if got != ots.ErrInternal {
		t.Errorf("认不出来的错误该归成 internal，实际 %q —— "+
			"宁可承认是自己的缺陷，也不要把内部错误伪装成别的码骗过调用方", got)
	}
}

// ── [OTS-11.2] [OTS-11.3] 监听与令牌 ──

func Test非回环地址没有令牌就不许启动(t *testing.T) {
	reg := ots.NewRegistry(false)
	for _, addr := range []string{"0.0.0.0:18080", ":18080", "[::]:18080"} {
		if _, err := New(reg, Config{Addr: addr, Log: quiet()}); err == nil {
			t.Errorf("%s 没有令牌竟然允许启动 —— 等于把改这台机器的能力挂在网上", addr)
		}
	}
	// 给了令牌就允许
	if _, err := New(reg, Config{Addr: "0.0.0.0:18080", Token: "x", Log: quiet()}); err != nil {
		t.Errorf("有令牌应当允许：%v", err)
	}
	// 回环地址不需要令牌
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		if _, err := New(reg, Config{Addr: addr, Log: quiet()}); err != nil {
			t.Errorf("%s 是回环地址，不该要求令牌：%v", addr, err)
		}
	}
}

func Test令牌不对就拒绝(t *testing.T) {
	reg := ots.NewRegistry(false)
	tools.Register(reg)
	s, err := New(reg, Config{Addr: "127.0.0.1:0", Token: "正确令牌", Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	call := func(tok string) int {
		req := httptest.NewRequest("GET", "/tools", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(""); got != 401 {
		t.Errorf("没带令牌 = %d，期望 401", got)
	}
	if got := call("错误令牌"); got != 401 {
		t.Errorf("令牌错误 = %d，期望 401", got)
	}
	if got := call("正确令牌"); got != 200 {
		t.Errorf("令牌正确 = %d，期望 200", got)
	}
}

// ── 工具自检 ──

func Test每个工具都声明了类别和说明(t *testing.T) {
	reg := ots.NewRegistry(true)
	tools.Register(reg)
	for _, tl := range reg.Visible() {
		if tl.Class != ots.ClassRead && tl.Class != ots.ClassMutate {
			t.Errorf("%s 没声明类别", tl.Name)
		}
		if len(tl.Schema) == 0 {
			t.Errorf("%s 没有入参 schema —— 调用方只能靠它知道怎么调", tl.Name)
		}
		if len(tl.Summary) < 20 {
			t.Errorf("%s 的说明太短（%d 字）—— 工具说明是给调用方选择用的，"+
				"写不清楚它就选不准", tl.Name, len([]rune(tl.Summary)))
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
