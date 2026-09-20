// Package mcp 把 NetKit 的工具经 Model Context Protocol 暴露给 AI。
//
// ★★ 这是一层**薄封装**，不许在这里加业务逻辑（见 docs/设计.md「AI 接口」）。
// 它只做一件事：把 ots.Registry 里的工具翻译成 MCP 认识的形状。
// 加了业务逻辑就等于又分叉出一套能力，界面和 AI 看到的东西会开始不一样。
//
// 实现对齐 MCP 修订 2026-07-28（2026-09-19 查证于 modelcontextprotocol.io）：
//   - 版本协商改为**每请求**经 _meta 携带，不再是一次性握手
//   - 服务端 MUST 实现 server/discover
//   - 版本不支持时回 -32022 UnsupportedProtocolVersionError，并列出支持的版本
//   - 结果带 resultType: "complete"
//
// 同时兼容 2025-11-25 及更早那些走 initialize 握手的客户端 —— 现场装的客户端
// 版本参差不齐，只认新协议等于把老客户端挡在门外。
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"net.yuhox.com/netkit/internal/ots"
)

// 本服务支持的协议版本，新的排前面。
//
// ★ 老版本一并留着：现场的客户端版本参差不齐，只认最新的等于把人挡在门外。
var supportedVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}

const (
	metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	metaServerInfo      = "io.modelcontextprotocol/serverInfo"

	// codeUnsupportedVersion 是 MCP 定义的版本不支持错误码。
	codeUnsupportedVersion = -32022
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeInternal           = -32603
	codeParseError         = -32700
)

// Server 一个 MCP 服务。
type Server struct {
	reg  *ots.Registry
	name string
	ver  string
}

// New 建一个 MCP 服务，把注册表里的工具暴露出去。
func New(reg *ots.Registry, name, version string) *Server {
	return &Server{reg: reg, name: name, ver: version}
}

// ── JSON-RPC 2.0 ──

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // 没有 id = 通知，不用回
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// meta 是每个请求都带的 _meta。
type meta struct {
	ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion"`
}

// ServeStdio 在 stdin/stdout 上跑一个 MCP 服务，直到 stdin 关闭。
//
// ★ 每行一条 JSON-RPC 消息（stdio 传输的规定）。写出去要加锁 ——
// 将来加了通知/异步任务，多个 goroutine 会同时往 stdout 写，不加锁就会串行错乱。
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	write := func(v any) error {
		mu.Lock()
		defer mu.Unlock()
		return enc.Encode(v)
	}

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = write(response{JSONRPC: "2.0", ID: json.RawMessage("null"),
				Error: &rpcError{Code: codeParseError, Message: "解不开的 JSON"}})
			continue
		}
		resp, notification := s.handle(ctx, &req)
		if notification {
			continue // 通知不回
		}
		if err := write(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

// handle 处理一条消息。第二个返回值为 true 表示这是通知，不需要回。
func (s *Server) handle(ctx context.Context, req *request) (response, bool) {
	if len(req.ID) == 0 {
		return response{}, true // 通知：initialized、cancelled 之类，收下不回
	}
	resp := response{JSONRPC: "2.0", ID: req.ID}

	// ★ 版本协商：每请求检查一次。认不出来的版本要明确回 -32022 并列出支持的，
	//   让客户端能自己降级重试 —— 比笼统报个错强得多。
	if v := requestedVersion(req.Params); v != "" && !supports(v) {
		resp.Error = &rpcError{
			Code: codeUnsupportedVersion, Message: "Unsupported protocol version",
			Data: map[string]any{"supported": supportedVersions, "requested": v},
		}
		return resp, false
	}

	switch req.Method {
	case "server/discover":
		resp.Result = s.discover()
	case "initialize":
		// 老客户端（2025-11-25 及更早）的握手。兼容着，不然老客户端连不上。
		resp.Result = s.initialize(req.Params)
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = s.toolsList()
	case "tools/call":
		r, e := s.toolsCall(ctx, req.Params)
		resp.Result, resp.Error = r, e
	default:
		resp.Error = &rpcError{Code: codeMethodNotFound, Message: "没有这个方法：" + req.Method}
	}
	return resp, false
}

func requestedVersion(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var p struct {
		Meta            *meta  `json:"_meta"`
		ProtocolVersion string `json:"protocolVersion"` // 老握手把版本放在这里
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	if p.Meta != nil && p.Meta.ProtocolVersion != "" {
		return p.Meta.ProtocolVersion
	}
	return p.ProtocolVersion
}

func supports(v string) bool {
	for _, x := range supportedVersions {
		if x == v {
			return true
		}
	}
	return false
}

// discover 回应 server/discover。服务端 MUST 实现。
func (s *Server) discover() map[string]any {
	return map[string]any{
		"resultType":        "complete",
		"supportedVersions": supportedVersions,
		"capabilities":      map[string]any{"tools": map[string]any{}},
		"_meta": map[string]any{
			metaServerInfo: map[string]any{"name": s.name, "version": s.ver},
		},
		"instructions": s.instructions(),
	}
}

// initialize 老客户端的握手。
func (s *Server) initialize(params json.RawMessage) map[string]any {
	// 客户端提的版本我们支持就用它，不支持就回我们最新的，让它自己决定要不要继续。
	v := requestedVersion(params)
	if !supports(v) {
		v = supportedVersions[0]
	}
	return map[string]any{
		"protocolVersion": v,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": s.name, "version": s.ver},
		"instructions":    s.instructions(),
	}
}

// instructions 给模型的使用说明。
//
// ★ 这里要讲清楚**结果怎么读**：工具返回的是判定码不是人话，
// 不说清楚，模型会去读 note 字段然后当成结论 —— 那正是我们要避免的。
func (s *Server) instructions() string {
	return "昱弘网通 NetKit：现场网络诊断工具。\n\n" +
		"工具返回的是**结构化判定**：verdict 字段是稳定的判定码，values 是作出判定的依据。\n" +
		"note 字段只是渲染好的中文，供日志查看，**不要拿它当结论**，请读 verdict。\n\n" +
		"地址支持 IPv4 与 IPv6。IPv6 写不写方括号都认；链路本地地址（fe80:: 开头）必须带 zone，" +
		"例如 fe80::1%en0。\n\n" +
		"当前只提供只读工具：它们会发探测流量，但不会改动任何机器的配置。"
}

// toolsList 列出工具。
//
// ★ 顺序是确定的（注册表按名字排序）—— 规范建议这么做，
// 因为客户端要缓存工具列表，顺序一变缓存就失效。
func (s *Server) toolsList() map[string]any {
	vis := s.reg.Visible()
	list := make([]map[string]any, 0, len(vis))
	for _, t := range vis {
		list = append(list, map[string]any{
			"name":        t.Name,
			"description": t.Summary,
			"inputSchema": json.RawMessage(t.Schema),
		})
	}
	return map[string]any{"resultType": "complete", "tools": list}
}

// toolsCall 调一个工具。
func (s *Server) toolsCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "参数解不开：" + err.Error()}
	}
	if p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "没给工具名"}
	}

	out, oerr := s.reg.Invoke(ots.WithCaller(ctx, "mcp"), p.Name, p.Arguments)
	if oerr != nil {
		// ★ 工具执行失败走 isError 的结果，不走 JSON-RPC 错误 ——
		//   这是 MCP 刻意的设计：让模型能看见失败内容并自己调整，
		//   而不是把错误吞在协议层、模型只知道"调用失败了"。
		//   ★ 结构化错误码原样给出去，模型据此判断是自己参数错了还是环境问题。
		return callResult(oerr, true), nil
	}
	return callResult(out, false), nil
}

// callResult 造 MCP 的 CallToolResult。
//
// ★ structuredContent 给机器读，content 里的 JSON 文本给不支持结构化输出的老客户端 ——
// 规范明确要求两个都给（"SHOULD also return the serialized JSON in a TextContent block"）。
func callResult(v any, isErr bool) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(fmt.Sprintf("%q", fmt.Sprint(v)))
	}
	return map[string]any{
		"resultType":        "complete",
		"structuredContent": v,
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"isError":           isErr,
	}
}
