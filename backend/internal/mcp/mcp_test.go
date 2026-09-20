package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/tools"
)

// talk 把几条请求喂给 stdio 服务，逐条返回解好的响应。
func talk(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	reg := ots.NewRegistry(false)
	tools.Register(reg)
	s := New(reg, "昱弘网通 NetKit", "test")

	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("ServeStdio：%v", err)
	}
	var got []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("响应不是 JSON：%q", l)
		}
		got = append(got, m)
	}
	return got
}

func result(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	if e, bad := m["error"]; bad {
		t.Fatalf("返回了错误：%v", e)
	}
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("没有 result：%v", m)
	}
	return r
}

// ── server/discover：规范要求服务端必须实现 ──

func TestServerDiscover(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	r := result(t, got[0])

	if r["resultType"] != "complete" {
		t.Errorf("resultType = %v", r["resultType"])
	}
	vs, _ := r["supportedVersions"].([]any)
	if len(vs) == 0 || vs[0] != "2026-07-28" {
		t.Errorf("supportedVersions = %v，最新的应当排第一", vs)
	}
	caps, _ := r["capabilities"].(map[string]any)
	if _, has := caps["tools"]; !has {
		t.Error("没声明 tools 能力")
	}
	// serverInfo 在 _meta 里（2026-07-28 的形状）
	m, _ := r["_meta"].(map[string]any)
	si, _ := m["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if si["name"] == nil {
		t.Errorf("_meta 里没有 serverInfo：%v", m)
	}
}

// ── 版本协商 ──

func Test不支持的版本要明确回32022并列出支持的(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}`)
	e, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("本该报版本错误：%v", got[0])
	}
	if e["code"].(float64) != codeUnsupportedVersion {
		t.Errorf("错误码 = %v，期望 %d", e["code"], codeUnsupportedVersion)
	}
	// ★ 要列出支持的版本，客户端才能自己降级重试 —— 光报个错等于让它没法继续
	d, _ := e["data"].(map[string]any)
	if sup, _ := d["supported"].([]any); len(sup) == 0 {
		t.Errorf("没列出支持的版本：%v", d)
	}
	if d["requested"] != "1900-01-01" {
		t.Errorf("没回显请求的版本：%v", d)
	}
}

func Test老客户端的initialize握手仍然能用(t *testing.T) {
	// 2025-11-25 及更早走 initialize。现场客户端版本参差不齐，不能只认新协议。
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`)
	r := result(t, got[0])
	if r["protocolVersion"] != "2025-06-18" {
		t.Errorf("该沿用客户端提的版本，实际 %v", r["protocolVersion"])
	}
	if r["serverInfo"] == nil {
		t.Error("老握手要回 serverInfo")
	}
}

func Test老客户端提了我们不认的版本时回落到最新(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-01-01"}}`)
	// 老握手里版本不匹配不是硬错误：回我们支持的，让客户端自己决定
	r, ok := got[0]["result"].(map[string]any)
	if !ok {
		e := got[0]["error"].(map[string]any)
		if e["code"].(float64) != codeUnsupportedVersion {
			t.Fatalf("意外的错误：%v", e)
		}
		return // 回 -32022 也是合规的
	}
	if r["protocolVersion"] != supportedVersions[0] {
		t.Errorf("回落版本 = %v", r["protocolVersion"])
	}
}

// ── tools/list ──

func TestToolsList(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	r := result(t, got[0])
	list, _ := r["tools"].([]any)
	if len(list) < 2 {
		t.Fatalf("工具太少：%v", list)
	}
	var names []string
	for _, x := range list {
		tl := x.(map[string]any)
		names = append(names, tl["name"].(string))
		if tl["description"] == "" || tl["description"] == nil {
			t.Errorf("%v 没有 description", tl["name"])
		}
		// ★ inputSchema 必须是合法的 JSON Schema 对象，不能是 null
		sc, ok := tl["inputSchema"].(map[string]any)
		if !ok {
			t.Errorf("%v 的 inputSchema 不是对象：%v", tl["name"], tl["inputSchema"])
			continue
		}
		if sc["type"] != "object" {
			t.Errorf("%v 的 inputSchema.type = %v，MCP 要求是 object", tl["name"], sc["type"])
		}
	}
	// ★ 顺序要确定：客户端会缓存工具列表，顺序一变缓存就失效
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Errorf("工具顺序不确定：%v", names)
			break
		}
	}
}

// ── tools/call ──

func TestToolsCall返回结构化内容与文本两份(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"net.interfaces","arguments":{}}}`)
	r := result(t, got[0])

	if r["isError"] != false {
		t.Errorf("isError = %v", r["isError"])
	}
	if r["structuredContent"] == nil {
		t.Error("没有 structuredContent —— 机器读的是这个")
	}
	// ★ 规范要求同时给一份序列化后的 JSON 文本，照顾不支持结构化输出的客户端
	content, _ := r["content"].([]any)
	if len(content) == 0 {
		t.Fatal("没有 content")
	}
	c0 := content[0].(map[string]any)
	if c0["type"] != "text" {
		t.Errorf("content[0].type = %v", c0["type"])
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(c0["text"].(string)), &parsed); err != nil {
		t.Errorf("content 里的文本不是能解开的 JSON：%v", err)
	}
	if parsed["interfaces"] == nil {
		t.Error("文本内容和结构化内容对不上")
	}
}

// ★ 工具执行失败要走 isError 的结果，不走 JSON-RPC 错误 ——
// 这是 MCP 刻意的设计：让模型看得见失败内容、能自己改参数重试。
func Test工具失败走isError而不是协议错误(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"net.tcp.probe","arguments":{"addr":"不是地址"}}}`)
	if _, bad := got[0]["error"]; bad {
		t.Fatalf("不该是 JSON-RPC 错误：%v —— 模型看不见内容就没法自己改参数重试", got[0])
	}
	r := got[0]["result"].(map[string]any)
	if r["isError"] != true {
		t.Errorf("isError = %v，期望 true", r["isError"])
	}
	// ★ 结构化错误码要原样给出去，模型据此判断是自己参数错了还是环境问题
	sc, _ := r["structuredContent"].(map[string]any)
	if sc["error"] != string(ots.ErrInvalidArgument) {
		t.Errorf("没把结构化错误码给出去：%v", sc)
	}
}

func Test调不存在的工具(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"没这个工具","arguments":{}}}`)
	r := got[0]["result"].(map[string]any)
	if r["isError"] != true {
		t.Errorf("isError = %v", r["isError"])
	}
}

// ── JSON-RPC 基本规矩 ──

func Test通知不回复(t *testing.T) {
	// 没有 id 就是通知。回了就违反 JSON-RPC。
	got := talk(t,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":9,"method":"ping","params":{}}`)
	if len(got) != 1 {
		t.Fatalf("收到 %d 条响应，期望 1 条（通知不该回）：%v", len(got), got)
	}
	if string(mustJSON(got[0]["id"])) != "9" {
		t.Errorf("回错了消息：%v", got[0])
	}
}

func Test坏JSON与未知方法(t *testing.T) {
	got := talk(t, `{这不是 JSON`, `{"jsonrpc":"2.0","id":2,"method":"不存在/方法","params":{}}`)
	if len(got) != 2 {
		t.Fatalf("收到 %d 条", len(got))
	}
	if e := got[0]["error"].(map[string]any); e["code"].(float64) != codeParseError {
		t.Errorf("坏 JSON 的错误码 = %v", e["code"])
	}
	if e := got[1]["error"].(map[string]any); e["code"].(float64) != codeMethodNotFound {
		t.Errorf("未知方法的错误码 = %v", e["code"])
	}
}

// ★ 只读实现不该暴露任何 mutate 工具 —— 这一条在 MCP 层也要成立，
// 否则「停用 mutate」只在 HTTP API 上有效，AI 那条路成了后门。
func TestMCP层也不暴露停用的改系统工具(t *testing.T) {
	reg := ots.NewRegistry(false)
	tools.Register(reg)
	reg.MustRegister(ots.Tool{
		Name: "test.mutate", Class: ots.ClassMutate, Summary: "测试用的改系统工具",
		Schema:   json.RawMessage(`{"type":"object","additionalProperties":false}`),
		Describe: func(json.RawMessage) string { return "测试用：不会真改任何东西" },
		Invoke:   func(context.Context, json.RawMessage) (any, error) { return ots.Verdict{Code: "done"}, nil },
	})
	s := New(reg, "t", "t")
	var out bytes.Buffer
	_ = s.ServeStdio(context.Background(),
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`+"\n"), &out)
	if strings.Contains(out.String(), "test.mutate") {
		t.Error("停用的 mutate 工具出现在 MCP 的工具列表里 —— AI 那条路成了后门")
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
