//go:build windows

package tools

import (
	"context"
	"os/exec"
	"syscall"
)

// readLocalPorts Windows：netstat -ano 拿「谁在哪个口」，tasklist 拿 PID → 进程名。
//
// ★ 两条命令都要，因为 netstat 只给 PID。★ 都不带任何用户名/参数信息：
//
//	中文控制台输出是 GBK，带中文的列会解成乱码，所以只取 ASCII 的那几列。
//	HideWindow 是必须的：图形界面下不藏的话，每查一次弹一个黑框闪一下。
func readLocalPorts(ctx context.Context) ([]portUse, bool, error) {
	ns, err := runQuiet(ctx, "netstat", "-ano")
	if err != nil {
		return nil, false, err
	}
	uses := parseNetstatWindows(ns)
	tl, err := runQuiet(ctx, "tasklist", "/fo", "csv", "/nh")
	if err == nil {
		uses = attachNames(uses, parseTasklistCSV(tl))
	}
	// 拿不到 tasklist 时名字是空的，但「哪个 PID 占着」这个结论照样成立。
	// ★ 不因此报 partial：partial 说的是「可能还有别的进程在听，我看不见」，
	// 和「看得见但少一个字段」是两件事，混在一起会让人白跑一次管理员权限。
	return uses, false, nil
}

func runQuiet(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	return string(out), err
}
