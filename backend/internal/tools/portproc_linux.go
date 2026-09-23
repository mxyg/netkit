//go:build linux

package tools

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procNetFiles 内核暴露的四张 socket 表。★ tcp 和 tcp6 是两张表，
// 只读 v4 会把「只听在 :: 上的服务」漏掉 —— 那正好是最常见的部署方式。
var procNetFiles = []struct {
	path, proto string
}{
	{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
	{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
}

// readLocalPorts Linux：socket 表 + /proc/<pid>/fd 反查归属。
//
// ★ 不用 ss / netstat：两处都可能在精简系统上没有，而 /proc 一定在。
//
//	代价是非管理员看不到别人进程的 fd 目录 —— 这时必须报 partial，
//	绝不能把「看不到」说成「没人用」。
func readLocalPorts(ctx context.Context) ([]portUse, bool, error) {
	var socks []procSocket
	for _, f := range procNetFiles {
		b, err := os.ReadFile(f.path)
		if err != nil {
			continue // 没启用 IPv6 的机器上没有 tcp6，这不是失败
		}
		socks = append(socks, parseProcNetSOCK(string(b), f.proto)...)
	}
	if len(socks) == 0 {
		return nil, false, os.ErrNotExist
	}
	owners := scanProcOwners()
	uses, partial := socketsToPortUses(socks, owners)
	return uses, partial, nil
}

// scanProcOwners 扫 /proc/<pid>/fd，把 socket inode 归到进程上。
//
// ★ 只读 comm，不读 cmdline：命令行里常有口令和 token，而这份结果会发给 AI。
func scanProcOwners() map[string]procOwner {
	owners := map[string]procOwner{}
	ds, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, d := range ds {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", d.Name(), "fd"))
		if err != nil {
			continue // 不是自己的进程且没权限：这条留给 partial 说
		}
		var inodes []string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", d.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if in, ok := socketInode(link); ok {
				inodes = append(inodes, in)
			}
		}
		if len(inodes) == 0 {
			continue
		}
		o := procOwner{Pid: pid, Process: procComm(pid), Inodes: inodes}
		for _, in := range inodes {
			owners[in] = o
		}
	}
	return owners
}

// socketInode 从 `socket:[12345]` 取出 12345。
func socketInode(link string) (string, bool) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return "", false
	}
	return link[len("socket:[") : len(link)-1], true
}

func procComm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
