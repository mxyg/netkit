//go:build darwin

package netif

import (
	"context"
	"os/exec"
	"time"
)

// parents 问一次 `ifconfig -a`，把「这块口是哪个桥的成员」读出来。
//
// ★ 整机问一次、不进循环（同 kinds()）：macOS 上这一步要起子进程。
// ★ 问不到就返回 nil。这时候调用方**不折叠**任何端口 ——
//
//	「没问到」和「它不是成员」在图上必须是两回事：拿没问到当没发生，
//	表现是把一块真实的物理口从图上抹掉。
func parents() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ifconfig", "-a").Output()
	if err != nil {
		return nil
	}
	return parseIfconfigParents(string(out))
}
