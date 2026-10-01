package netif

import "strings"

// parseIfconfigParents 从 `ifconfig -a` 的输出里读出「这块口挂在谁下面」。
//
// ★ 只认桥的那一行 `member:`：这是本机实测到的格式（bridge0 那一段里有三行
//
//	`member: en1 flags=3<LEARNING,DISCOVER>`）。
//	macOS 的 ifconfig 二进制里**没有**印 VLAN 父口的字符串（strings 扫过），
//	所以这里不猜 VLAN 的写法 —— 猜出来的父子关系会直接变成图上少画的一个端口，
//	而现场是照着这张图去拔线的。
//
// 认不出来就是不在这张表里（调用方据此不折叠），绝不给一个「看着合理」的父口。
func parseIfconfigParents(out string) map[string]string {
	parents := map[string]string{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// 顶格那一行是新的一块网卡：`en0: flags=8863<...> mtu 1500`
			cur = ""
			i := strings.IndexByte(line, ':')
			if i <= 0 {
				continue
			}
			name := strings.TrimSpace(line[:i])
			if name != "" && !strings.ContainsAny(name, " \t") {
				cur = name
			}
			continue
		}
		if cur == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "member:" {
			continue
		}
		member := fields[1]
		if strings.ContainsAny(member, "<>,:") {
			continue
		}
		parents[member] = cur
	}
	return parents
}
