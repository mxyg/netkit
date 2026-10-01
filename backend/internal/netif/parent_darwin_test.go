//go:build darwin

package netif

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

// ★ 这一条不是测解析器（上面那些夹具管解析），是**防格式漂移**：
// 独立数一遍真机输出里出现 `member:` 的行数，和折叠表里的条数比。
// 哪天 ifconfig 换了写法（换缩进、改 `port:`、进 JSON 模式），解析器会静默返回空表，
// 表现是「拓扑图上多出一堆本不该单立的方块」—— 没人会想起是这里断了，所以钉在测试里。
// 反过来，要是 `member:` 出现在别的地方（新命令、新说明），这条也会红：那正是要人看一眼。
func Test父母口这台机器上量到的条数与原文一致(t *testing.T) {
	out, err := exec.Command("ifconfig", "-a").Output()
	if err != nil {
		t.Fatalf("ifconfig -a 跑不起来，这台机器没法核对：%v", err)
	}
	lines := 0
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "member:") {
			lines++
		}
	}
	got := parents()
	if lines != len(got) {
		t.Fatalf("原文里有 %d 行带 member:，折叠表里 %d 条 —— 解析漏了或多了：\n%v", lines, len(got), got)
	}
}

// 父子关系必须落在真存在的口上，且不许自己当自己的父口。
func Test父母口每条都对得上真实网卡(t *testing.T) {
	got := parents()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("枚举网卡失败：%v", err)
	}
	names := make(map[string]bool, len(ifs))
	for _, in := range ifs {
		names[in.Name] = true
	}
	for child, parent := range got {
		if child == parent {
			t.Fatalf("%s 成了自己的父口：%v", child, got)
		}
		if !names[child] {
			t.Errorf("折叠表里的子口 %s 不在系统网卡列表里（读重了或名字变了）", child)
		}
		if !names[parent] {
			t.Errorf("折叠表里的父口 %s 不在系统网卡列表里", parent)
		}
	}
}
