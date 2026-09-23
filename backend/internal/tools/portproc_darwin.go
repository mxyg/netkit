//go:build darwin

package tools

import (
	"context"
	"os/exec"
	"strings"
)

// readLocalPorts macOS：读 lsof。
//
// ★ 用 -F 的机器可读格式而不是默认表格：COMMAND 列可以含空格（"Google Chrome"），
//
//	按空白切列会把 PID 和进程名错配到隔壁进程上 —— 那种错不报错，只是偶尔指错人。
//	-i 只要互联网套接字；-n -P 关掉两份反查（DNS 与端口名），否则每个端口都会被翻译成
//	服务名，「554」就查不到了。
func readLocalPorts(ctx context.Context) ([]portUse, bool, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-i", "-FpcuLtTPn").Output()
	if err != nil {
		// lsof 列到一半某个进程消失了也会非零退出。★ 有正文就当它成功，
		// 否则症状是「有时整栏报读不到」，而数据明明在手里。
		if len(strings.TrimSpace(string(out))) == 0 {
			return nil, false, err
		}
	}
	return parseLsofFields(string(out)), false, nil
}
