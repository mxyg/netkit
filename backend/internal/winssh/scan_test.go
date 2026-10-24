package winssh

import "testing"

func TestParseNeighbors(t *testing.T) {
	mac := "? (169.254.231.87) at 0:e0:4c:2e:54:18 on en10 ifscope [ethernet]\n? (192.168.1.1) at 34:f7:16:8b:36:63 on en0\n"
	got := ParseNeighbors(mac)
	if len(got) != 2 || got[0] != "169.254.231.87" {
		t.Fatalf("macOS arp: %v", got)
	}
	win := "Interface: 169.254.215.108 --- 0x1c\n  169.254.231.87        00-e0-4c-2e-54-18     dynamic\n"
	got = ParseNeighbors(win)
	if len(got) != 2 {
		t.Fatalf("windows arp: %v", got)
	}
}

func TestScriptNames(t *testing.T) {
	s := scriptPS1("169.254.215.108:8770")
	if contains(s, "function R") {
		t.Fatal("函数名 R 会撞上 Invoke-History")
	}
	if !contains(s, "function Note") || !contains(s, "169.254.215.108:8770") {
		t.Fatal(s[:80])
	}
	if !contains(scriptCMD("10.0.0.2:8770"), "http://10.0.0.2:8770/go.ps1") {
		t.Fatal("cmd host")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
