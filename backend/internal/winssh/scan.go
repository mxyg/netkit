package winssh

import (
	"regexp"
	"sort"
)

var (
	reParen = regexp.MustCompile(`\(([^)]+)\)`)
	reBare  = regexp.MustCompile(`(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$)`)
)

// ParseNeighbors 从 arp / ip neigh 的文本里抽出 IPv4。
// macOS 是 "? (169.254.1.2) at …"，Windows 是一行开头的地址，Linux ip neigh 也是地址开头。
func ParseNeighbors(text string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(ip string) {
		if ip == "" || ip == "255.255.255.255" {
			return
		}
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	for _, m := range reParen.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	if len(out) == 0 {
		for _, m := range reBare.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
	}
	sort.Strings(out)
	return out
}
