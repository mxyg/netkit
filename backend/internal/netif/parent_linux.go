//go:build linux

package netif

import (
	"os"
	"path/filepath"
	"strings"
)

const sysNetClass = "/sys/class/net"

// parents 读 /sys/class/net/<口>/master —— 内核把父子关系直接做成了一个符号链接，
// 指向父设备那个目录（`../bridge0`）。
//
// ★ 为什么不走 `ip -d link`：那是 fork 一个子进程去解析文本，而这里是枚举热路径
//
//	（24 块网卡一台工控机）。文件里已经写好的东西不必再让命令拼一遍。
//
// ★ 这个链接在 4.17 以前的内核上没有（bridge 端口那时只有 `brport` 目录，
//
//	而 `brport` 里不写父设备叫什么）。那种内核上这里就是「不知道」，调用方不折叠。
func parents() map[string]string {
	entries, err := os.ReadDir(sysNetClass)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		link, err := os.Readlink(filepath.Join(sysNetClass, e.Name(), "master"))
		if err != nil {
			continue
		}
		parent := filepath.Base(strings.TrimSpace(link))
		if parent == "" || parent == "." || parent == "/" || parent == ".." {
			continue
		}
		out[e.Name()] = parent
	}
	return out
}
