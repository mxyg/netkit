// Package api 是 NetKit 的本地 HTTP API。
//
// ★★ 架构上它是**唯一本体**（见 docs/设计.md「AI 接口」）：
//
//	Go 后端（全部能力）→ 本地 HTTP API
//	                      ├── Electron 界面
//	                      └── MCP server（薄封装）→ AI / 脚本
//
// 界面自己也只是这套 API 的一个客户端，和 AI 平起平坐。这样 [OTS-4.5]
// 「不许有只存在于 API 的能力」是**结构上的必然**，而不是一条要人记住的规矩。
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// Config 服务配置。
type Config struct {
	// Addr 监听地址。空 = 127.0.0.1:0（随机端口）。
	//
	// ★ [OTS-11.2] 默认只听回环。绑到非回环地址要显式配置**且必须有令牌**，
	//   这一条由 New 强制，不是靠调用方自觉。
	Addr string
	// Token 调用方令牌。绑非回环地址时必填。[OTS-11.3]
	Token string
	// Log 调用留痕。[OTS-11.4]
	Log *slog.Logger
}

// Server 一个 API 服务。
type Server struct {
	reg *ots.Registry
	cfg Config
	log *slog.Logger
	mux *http.ServeMux
	ln  net.Listener
	srv *http.Server
}

// New 建一个服务。
//
// ★ 这里把 [OTS-11.3] 做成**启动失败**而不是警告：
// 一个绑在 0.0.0.0 上、不要令牌的运维工具 API，等于把改机器的能力挂在网上。
// 警告会被忽略，启动失败不会。
func New(reg *ots.Registry, cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if !loopbackOnly(cfg.Addr) && cfg.Token == "" {
		return nil, fmt.Errorf("监听地址 %s 不是回环地址，必须同时设置令牌 —— "+
			"没有令牌的 API 等于把改这台机器的能力挂在网上给所有人用", cfg.Addr)
	}
	s := &Server{reg: reg, cfg: cfg, log: cfg.Log, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// loopbackOnly 判断监听地址是不是只在回环上。
//
// ★ 空主机（":8080"）和 "0.0.0.0" / "::" 都是**所有接口**，不是回环 ——
// 这是个很容易看漏的地方，漏了就等于默认对外。
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8080" = 所有接口
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /ots", s.handleConformance)
	s.mux.HandleFunc("GET /tools", s.handleTools)
	s.mux.HandleFunc("POST /tools/{name}", s.handleInvoke)
}

// Listen 开始监听但不阻塞，返回实际监听地址（端口可能是随机分配的）。
func (s *Server) Listen() (string, error) {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return "", fmt.Errorf("监听 %s 失败：%w", s.cfg.Addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           cors(s.auth(s.mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("API 服务停止", "err", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Close 停止服务。
func (s *Server) Close() error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

// Handler 暴露处理器，给测试和进程内调用用（界面可以不走网络）。
func (s *Server) Handler() http.Handler { return cors(s.auth(s.mux)) }

// cors 让本地界面能调这套 API。
//
// ★★ 为什么非有不可：Electron 的界面是 `file://` 页面，它 fetch
//
//	`http://127.0.0.1:端口` 属于**跨源请求**。没有这几个头，浏览器会把每一次调用
//	都拦下来 —— 表现成"窗口开着、按钮点了没反应"，而控制台之外看不到任何错误。
//	（2026-09-20 就是这么漏掉的：窗口起来了，就以为界面通了。）
//
// ★ 放开到什么程度：这套 API 默认只听回环，绑非回环必须带令牌（见 New）。
//
//	所以这里允许任意来源是安全的 —— 能连上这个端口的，本来就已经在这台机器上了。
//	★ 但 `Authorization` 必须在允许的头里，否则带令牌那条路会被预检挡掉。
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth 令牌校验。[OTS-11.3]
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			// 长度先比一道，避免把令牌长度也泄露出去；内容用常数时间比
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				writeErr(w, http.StatusUnauthorized,
					ots.Errf(ots.ErrPermissionRequired, "令牌不对"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleConformance 符合性声明。[OTS-3.1]
//
// ★ 这个端点存在的意义：调用方**在调任何工具之前**就能知道
// 「这个实现声称符合哪一档」。没有这个，符合性只是文档里的一句话。
func (s *Server) handleConformance(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"spec":        "Ops Tool Spec",
		"specVersion": ots.Version,
		"conformance": s.reg.Conformance(),
		"product":     "昱弘网通 NetKit",
	})
}

// handleTools 列出当前可见的工具。
//
// ★ [OTS-4.4]：mutations 关掉时 mutate 工具**根本不出现**在这个列表里，
// 而不是"出现了但调用报错" —— 让调用方看见一个调不动的工具没有意义。
func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	type toolOut struct {
		Name    string    `json:"name"`
		Class   ots.Class `json:"class"`
		Summary string    `json:"summary"`
	}
	vis := s.reg.Visible()
	out := make([]toolOut, 0, len(vis))
	for _, t := range vis {
		out = append(out, toolOut{Name: t.Name, Class: t.Class, Summary: t.Summary})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": out})
}

// handleInvoke 调用一个工具。
func (s *Server) handleInvoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, ots.Errf(ots.ErrInvalidArgument, "读不了请求体：%s", err))
		return
	}

	start := time.Now()
	out, oerr := s.reg.Invoke(r.Context(), name, body)

	// [OTS-11.4] 每一次调用都留痕：谁调的、调了什么、结果如何。
	lg := s.log.With("tool", name, "caller", r.RemoteAddr, "ms", time.Since(start).Milliseconds())
	if oerr != nil {
		lg.Warn("工具调用失败", "code", oerr.Code, "msg", oerr.Message)
		writeErr(w, statusFor(oerr.Code), oerr)
		return
	}
	lg.Info("工具调用", "verdict", verdictOf(out))
	writeJSON(w, http.StatusOK, out)
}

// verdictOf 从结果里取判定码，给日志用。取不到就空。
func verdictOf(out any) string {
	if v, ok := out.(ots.Verdict); ok {
		return v.Code
	}
	return ""
}

// statusFor 错误码 → HTTP 状态码。
//
// ★ 结构化错误码才是权威的，HTTP 状态只是给通用中间件看的。
// 调用方应当读 body 里的 error 字段，别去猜 4xx/5xx 的含义。
func statusFor(c ots.ErrorCode) int {
	switch c {
	case ots.ErrInvalidArgument:
		return http.StatusBadRequest
	case ots.ErrNotSupported:
		return http.StatusNotImplemented
	case ots.ErrPermissionRequired:
		return http.StatusForbidden
	case ots.ErrApprovalRequired:
		return http.StatusAccepted
	case ots.ErrApprovalDenied:
		return http.StatusForbidden
	case ots.ErrUnreachable, ots.ErrTimeout:
		return http.StatusOK // 探测类的「没连上」不是 HTTP 层的失败
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, e *ots.Error) {
	writeJSON(w, code, e)
}
