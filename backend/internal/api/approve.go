package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// HTTPApprover 把批准请求发给界面，等人点。
//
// ★★ [OTS-7.1] 授权只能来自**人在界面上的那一下点击**。
//
//	这个类型做的事非常少，而且必须一直这么少：把要改什么原样送过去，
//	把人的选择原样带回来。**不许在这里替人做任何判断** ——
//	一旦这里出现"这个看起来没风险就自动同意"，整条闸就废了。
//
// ★ 界面没连上 = 没有批准渠道 = 改系统的工具一律拒绝（见 Registry.Invoke）。
// 不是默认放行 —— 那正好在"没人看着"的时候把闸打开。
type HTTPApprover struct {
	// URL 界面开的批准端点
	URL string
	// Timeout 等人点多久。★ 要足够长：人可能正在看那段说明、
	//   或者去问了一句同事。超时太短会把"人还没决定"变成"拒绝"。
	Timeout time.Duration
}

type approveAsk struct {
	Tool   string          `json:"tool"`
	What   string          `json:"what"`
	Args   json.RawMessage `json:"args,omitempty"`
	Caller string          `json:"caller,omitempty"`
}

// Approve 实现 ots.Approver。
func (a *HTTPApprover) Approve(ctx context.Context, tool, what string, args json.RawMessage) (bool, error) {
	if a.URL == "" {
		return false, fmt.Errorf("没有配置批准端点")
	}
	to := a.Timeout
	if to <= 0 {
		to = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	body, _ := json.Marshal(approveAsk{Tool: tool, What: what, Args: args})
	req, err := http.NewRequestWithContext(ctx, "POST", a.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// ★ 问不到人就是**没有批准**，不是"算了就执行吧"
		return false, fmt.Errorf("没能把确认请求送到界面：%w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Approved bool `json:"approved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("界面的回应读不懂：%w", err)
	}
	return out.Approved, nil
}

var _ ots.Approver = (*HTTPApprover)(nil)
