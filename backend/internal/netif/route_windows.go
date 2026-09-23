//go:build windows

package netif

import (
	"context"
	"os/exec"
	"time"
)

// defaultRoutes Windows：PowerShell 问 Get-NetRoute，一次拿回 v4/v6 两条默认路由的 JSON。
//
// ★ 不用 `netstat -rn`：它的 IPv6 表列宽和 v4 不一致、还本地化表头，按列号解析容易错。
//
//	Get-NetRoute 给的是结构化对象，稳。
func defaultRoutes() ([]DefaultRoute, error) {
	script := "Get-NetRoute -DestinationPrefix 0.0.0.0/0,::/0 -ErrorAction SilentlyContinue | " +
		"Select-Object DestinationPrefix,NextHop,InterfaceAlias | ConvertTo-Json -Compress"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return nil, nil // 读不到就当没有，不当错误：体检会如实报「拿不到默认路由」
	}
	return parseGetNetRoute(string(b)), nil
}
