// Package ots 实现 Ops Tool Spec (OTS) 核心规范 v0.1。
//
// 规范正文在另一个公开仓（CC BY 4.0 / Apache-2.0），NetKit 是它的参考实现。
// 本包只做**规范里与领域无关的那部分**：工具注册、判定、错误、符合性声明。
// 具体有哪些工具由 internal/tools 定义。
//
// ★ 这个包存在的理由：把规范里**能用代码强制的条款直接强制掉**，
// 而不是写进文档指望人记住。凡是靠自觉遵守的规则，迟早有人不自觉。
// 每条实现了的要求都在注释里标了 [OTS-n.m]，便于逐条对照。
package ots

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Version 本实现对齐的规范版本。[OTS-3.1]
const Version = "0.1"

// Class 工具类别。[OTS-4.1]
type Class string

const (
	// ClassRead 只观察。除实现自身的缓存、日志、任务记录外什么都不改。
	// ★ [OTS-4.3]：**以观察为目的发流量算只读** —— ping、端口探测、取流探测都是 read。
	ClassRead Class = "read"
	// ClassMutate 会改某台主机/网络/设备上的状态。受第 7 节管。
	ClassMutate Class = "mutate"
)

// Conformance 符合性类别。[OTS-3.1]
type Conformance string

const (
	ConfRead Conformance = "OTS-Read" // 不暴露任何 mutate 工具
	ConfFull Conformance = "OTS-Full"
)

// ── 判定 [OTS-5.1] [OTS-5.3] ──

// Verdict 一个判定：判定码 + 作出判定所依据的取值。
//
// ★ [OTS-5.2] 结果不得仅以人话表达判定。所以 Code 是必填的，
// 而 Note 只是可选的附加字段 —— 见 Note 字段的说明。
type Verdict struct {
	// Code 判定码。小写字母、数字、连字符。[OTS-5.5]
	Code string `json:"verdict"`
	// Values 作出这个判定所依据的取值。[OTS-5.3]
	Values map[string]any `json:"values,omitempty"`
	// Note 已渲染的人话，**可选**。[OTS-5.4]
	//
	// ★ 调用方不得依赖它是否存在、内容、或语言 —— 它是给日志和命令行看的。
	//   界面要显示什么，由界面按当前语言渲染 Code。
	Note string `json:"note,omitempty"`
}

// CodeUnknown 判定出了一个本实现没有对应判定码的状态。[OTS-5.7]
//
// ★ 规范要求这种情况**返回 unknown 加上已获取的取值**，
// 而不是临时编一句人话糊过去。
const CodeUnknown = "unknown"

// Unknown 造一个 unknown 判定，带上已经拿到的东西。[OTS-5.7]
func Unknown(values map[string]any) Verdict {
	return Verdict{Code: CodeUnknown, Values: values}
}

// validCode 判定码只能是小写字母、数字、连字符。[OTS-5.5]
func validCode(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// ── 错误 [OTS-6.1] ──

// ErrorCode 错误码。集合是封闭的，加新的要改规范。[OTS 第 10.2 节]
type ErrorCode string

const (
	ErrInvalidArgument    ErrorCode = "invalid-argument"
	ErrNotSupported       ErrorCode = "not-supported"
	ErrPermissionRequired ErrorCode = "permission-required"
	ErrApprovalRequired   ErrorCode = "approval-required"
	ErrApprovalDenied     ErrorCode = "approval-denied"
	ErrUnreachable        ErrorCode = "unreachable"
	ErrTimeout            ErrorCode = "timeout"
	ErrInternal           ErrorCode = "internal"
)

var errorCodes = map[ErrorCode]bool{
	ErrInvalidArgument: true, ErrNotSupported: true, ErrPermissionRequired: true,
	ErrApprovalRequired: true, ErrApprovalDenied: true, ErrUnreachable: true,
	ErrTimeout: true, ErrInternal: true,
}

// Error 结构化错误。
//
// ★ [OTS-6.2] 划了一条容易含糊的界线：**「成功地判断出某个东西坏了」是判定，不是错误**。
// 端口关着 → 判定 closed；探测本身跑不起来（参数非法、没权限）→ 才是错误。
// 混为一谈的后果是调用方分不清「目标有问题」和「工具有问题」。
type Error struct {
	Code    ErrorCode `json:"error"`
	Message string    `json:"message,omitempty"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

// Errf 造一个结构化错误。
func Errf(code ErrorCode, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// AsError 把任意 error 归一成结构化错误。认不出来的一律 internal ——
// ★ 宁可承认是自己的缺陷，也不要把内部错误伪装成别的码骗过调用方。
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if ok := asOTS(err, &e); ok {
		return e
	}
	return &Error{Code: ErrInternal, Message: err.Error()}
}

func asOTS(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ── 工具与注册表 ──

// Tool 一个工具。
type Tool struct {
	// Name 工具名。稳定，别改 —— 改了等于换了一个工具。
	Name string
	// Class read 还是 mutate。[OTS-4.1]
	Class Class
	// Summary 一句话说明。这是给调用方（AI）看的说明书，写清楚点。
	Summary string
	// Schema 入参的 JSON Schema。
	//
	// ★ 必填，不许留空。理由和 Summary 一样：调用方（尤其是 AI）**只能靠它知道怎么调**。
	//   没有 schema 的工具，调用方只能猜参数名，猜错了就是一串莫名其妙的失败。
	//   没有参数的工具写 {"type":"object","additionalProperties":false}。
	Schema json.RawMessage
	// Invoke 执行。args 是原始 JSON，由工具自己解。
	// 返回值会被 JSON 序列化；返回 error 时应当是 *ots.Error。
	Invoke func(ctx context.Context, args json.RawMessage) (any, error)
}

// Registry 工具注册表。
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
	// mutations 是否允许暴露 mutate 工具。
	// ★ [OTS-4.4] 实现必须能在全部 mutate 停用的情况下继续提供全部 read。
	//   所以这是个总开关，而不是「注册时决定」。
	mutations bool
}

// NewRegistry 建一个注册表。mutations=false 时 mutate 工具一律不对外提供。
func NewRegistry(mutations bool) *Registry {
	return &Registry{tools: map[string]Tool{}, mutations: mutations}
}

// Register 注册一个工具。
//
// ★ 这里就把规范能查的条款查掉，注册不上就是编译期之后最早的一道拦截。
func (r *Registry) Register(t Tool) error {
	if t.Name == "" {
		return fmt.Errorf("工具没有名字")
	}
	if t.Class != ClassRead && t.Class != ClassMutate {
		// [OTS-4.1] 每个工具必须声明类别。漏了不许默认成 read ——
		// 默认成只读，正好把"忘了声明"的改系统工具放行，那是最坏的默认值。
		return fmt.Errorf("工具 %s 没有声明类别（read / mutate）—— 不许默认，"+
			"默认成 read 会正好放行一个忘了声明的改系统工具", t.Name)
	}
	if t.Invoke == nil {
		return fmt.Errorf("工具 %s 没有实现", t.Name)
	}
	if t.Summary == "" {
		// 工具描述就是给 AI 的说明书。没有描述的工具，AI 选不准。
		return fmt.Errorf("工具 %s 没有说明 —— 说明是给调用方看的选择依据，不是可选项", t.Name)
	}
	if len(t.Schema) == 0 {
		return fmt.Errorf("工具 %s 没有入参 schema —— 调用方只能靠它知道怎么调，"+
			"没有就只能猜参数名。没有参数的工具写 {\"type\":\"object\",\"additionalProperties\":false}", t.Name)
	}
	if !json.Valid(t.Schema) {
		return fmt.Errorf("工具 %s 的 schema 不是合法 JSON", t.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.tools[t.Name]; dup {
		return fmt.Errorf("工具 %s 重复注册", t.Name)
	}
	r.tools[t.Name] = t
	return nil
}

// MustRegister 注册，失败就 panic。给初始化用。
func (r *Registry) MustRegister(ts ...Tool) {
	for _, t := range ts {
		if err := r.Register(t); err != nil {
			panic(err)
		}
	}
}

// Visible 当前对外可见的工具，按名字排序。
//
// ★ [OTS-4.4]：mutations 关掉时，mutate 工具**根本不出现**，
// 不是"出现了但调用时报错" —— 让调用方看见一个调不动的工具没有意义。
func (r *Registry) Visible() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		if t.Class == ClassMutate && !r.mutations {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup 找一个当前可见的工具。
func (r *Registry) Lookup(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	if !ok || (t.Class == ClassMutate && !r.mutations) {
		return Tool{}, false
	}
	return t, true
}

// Conformance 当前符合性类别。[OTS-3.1]
//
// ★ 不暴露任何 mutate 工具就是 OTS-Read，暴露了才是 OTS-Full。
// 这个值是**算出来的**，不是配置出来的 —— 配置出来的符合性声明等于自己说自己合格。
func (r *Registry) Conformance() Conformance {
	for _, t := range r.Visible() {
		if t.Class == ClassMutate {
			return ConfFull
		}
	}
	return ConfRead
}

// Invoke 调用一个工具，返回结果或结构化错误。
func (r *Registry) Invoke(ctx context.Context, name string, args json.RawMessage) (any, *Error) {
	t, ok := r.Lookup(name)
	if !ok {
		return nil, Errf(ErrInvalidArgument, "没有叫 %s 的工具", name)
	}
	out, err := t.Invoke(ctx, args)
	if err != nil {
		return nil, AsError(err)
	}
	if v, ok := out.(Verdict); ok && !validCode(v.Code) {
		// [OTS-5.5] 判定码只能是小写字母数字连字符。
		// 在出口处拦一道，免得一个手滑的码流到调用方那里变成事实上的接口。
		return nil, Errf(ErrInternal, "工具 %s 返回了非法判定码 %q", name, v.Code)
	}
	return out, nil
}

// ValidErrorCode 报告是不是规范定义的错误码。集合封闭。[OTS 第 10.2 节]
func ValidErrorCode(c ErrorCode) bool { return errorCodes[c] }

// ValidVerdictCode 报告判定码格式对不对。[OTS-5.5]
func ValidVerdictCode(s string) bool { return validCode(s) }
