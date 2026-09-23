package tools

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

// 这套测试不开真网卡、也不走批准：两个读取口（网卡列表 / 默认路由）都能换，
// 端到端那几条走 127.0.0.1（显式给地址这条路不经网卡），
// 所以挂着 VPN 的机器和干净机器上跑出来一模一样。
//
// ★ 为什么必须能换：这一张是 mutate 工具，跑到真网卡上就等于在测试里
//   把测试机的目录开给整个网段看 —— 那是拿别人当测试床。

func fixShareNICs(nics []netif.NIC, err error) func() {
	old := fileshareNICs
	fileshareNICs = func() ([]netif.NIC, error) { return nics, err }
	return func() { fileshareNICs = old }
}

func fixShareRoutes(rs []netif.DefaultRoute, err error) func() {
	old := fileshareRoutes
	fileshareRoutes = func() ([]netif.DefaultRoute, error) { return rs, err }
	return func() { fileshareRoutes = old }
}

// upNIC 插着线、带这些地址的一块网卡。
func upNIC(t *testing.T, name string, cidrs ...string) netif.NIC {
	t.Helper()
	n := netif.NIC{Name: name, Up: true, Running: true, Kind: "ethernet", KindSrc: "name"}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		n.Addrs = append(n.Addrs, netaddr.Addr{IP: p.Addr(), Prefix: p.Bits()})
	}
	return n
}

func shareJournal(t *testing.T) *state.Journal {
	t.Helper()
	j, err := state.Open(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := journal
	journal = j
	t.Cleanup(func() { journal = old })
	return j
}

// shareReset 保证下一个测试看到的「当前共享」是空的。
//
// ★ 这个槽是全局的（全场只允许一个共享），忘了清的话后面每条测试
//
//	都会莫名撞上「已经有一个共享在跑」，而报错看着像是被测代码的问题。
func shareReset(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		fileshare.mu.Lock()
		defer fileshare.mu.Unlock()
		if fileshare.srv != nil {
			fileshare.srv.Stop()
			fileshare.srv = nil
		}
		fileshare.entryID = ""
		fileshare.plan = filesharePlan{}
	})
}

// shareDir 建一个要共享出去的目录（在 t.TempDir 下面，测试完自动没了）。
func shareDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "firmware")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func callShare(t *testing.T, tool ots.Tool, args map[string]any) (ots.Verdict, error) {
	t.Helper()
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	out, err := tool.Invoke(context.Background(), raw)
	if err != nil {
		return ots.Verdict{}, err
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("%s 返回的不是判定：%T", tool.Name, out)
	}
	return v, nil
}

// freePort 先占一个号再放开，拿它当测试端口。
//
// ★ 测试不许都挤在 8080 上：这台机器上多半正跑着别的东西，
//
//	撞上去的失败看着像是被测代码坏了。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// serveLocal 走「显式给地址」这条路起一个只在回环上能读到的共享，给端到端测试用。
func serveLocal(t *testing.T, dir string, extra map[string]any) ots.Verdict {
	t.Helper()
	args := map[string]any{"root": dir, "addrs": []string{"127.0.0.1"}, "port": freePort(t)}
	for k, v := range extra {
		args[k] = v
	}
	v, err := callShare(t, fileshareServeTool, args)
	if err != nil {
		t.Fatalf("起共享失败：%v", err)
	}
	return v
}

func shareURL(v ots.Verdict) string {
	urls, _ := v.Values["urls"].([]string)
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

func statusSnapshot(t *testing.T) map[string]any {
	t.Helper()
	v, err := callShare(t, fileshareStatusTool, map[string]any{})
	if err != nil {
		t.Fatalf("看状态失败：%v", err)
	}
	b, _ := json.Marshal(v.Values["status"])
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("状态解不开：%v", err)
	}
	return m
}

func recentPaths(m map[string]any) []string {
	raw, _ := m["recent"].([]any)
	var out []string
	for _, r := range raw {
		tf, _ := r.(map[string]any)
		out = append(out, tf["path"].(string)+"|"+tf["status"].(string))
	}
	return out
}

func hasRecent(m map[string]any, path, status string) bool {
	raw, _ := m["recent"].([]any)
	for _, r := range raw {
		tf, _ := r.(map[string]any)
		if tf["path"] == path && tf["status"] == status {
			return true
		}
	}
	return false
}

// ── 参数与目录 ──

func Test不给目录当场拒(t *testing.T) {
	shareReset(t)
	_, err := callShare(t, fileshareServeTool, map[string]any{"addrs": []string{"127.0.0.1"}})
	if err == nil || !strings.Contains(err.Error(), "没给要共享的目录") {
		t.Fatalf("该直接说要共享的目录：%v", err)
	}
}

func Test整个根目录不共享(t *testing.T) {
	shareReset(t)
	// ★ 写当前平台的根分隔符：Windows 上 filepath.Abs("/") 会带上盘符，
	//   拿字面量 "/" 断言会测到一个假失败。
	_, err := callShare(t, fileshareServeTool, map[string]any{
		"root": string(filepath.Separator), "addrs": []string{"127.0.0.1"},
	})
	if err == nil || !strings.Contains(err.Error(), "不接受把整个根目录") {
		t.Fatalf("整盘端出去该直接拒：%v", err)
	}
}

func Test不是目录时说不是目录(t *testing.T) {
	shareReset(t)
	f := filepath.Join(t.TempDir(), "fw.bin")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := callShare(t, fileshareServeTool, map[string]any{"root": f})
	if err == nil || !strings.Contains(err.Error(), "不是目录") {
		t.Fatalf("%v", err)
	}
}

func Test读不到目录时报的是打不开(t *testing.T) {
	// ★ 说「打不开」不说「不存在」：权限不够时两者长得一模一样，
	//   而该做的下一步完全不同（一个去建目录，一个去查权限）。
	shareReset(t)
	_, err := callShare(t, fileshareServeTool, map[string]any{
		"root": filepath.Join(t.TempDir(), "nope-dir"),
	})
	if err == nil {
		t.Fatal("该报错")
	}
	if !strings.Contains(err.Error(), "打不开") {
		t.Errorf("该说「打不开」（权限不够时长得一样），拿到：%v", err)
	}
	if strings.Contains(err.Error(), "不存在") {
		t.Errorf("不许断定不存在：%v", err)
	}
}

func Test绑通配地址一律当场拒(t *testing.T) {
	defer fixShareNICs(nil, nil)()
	for _, x := range []string{"0.0.0.0", "::", "*"} {
		_, err := planFileShare(fileshareArgs{Root: "/tmp", Addrs: []string{x}})
		if err == nil || !strings.Contains(err.Error(), "所有网卡") {
			t.Errorf("%s 该被拒并说明为什么：%v", x, err)
		}
	}
}

func Test给的不是地址当场拒(t *testing.T) {
	defer fixShareNICs(nil, nil)()
	for _, x := range []string{"10.0.0.999", "固件目录", ""} {
		_, err := planFileShare(fileshareArgs{Root: "/tmp", Addrs: []string{x}})
		if err == nil {
			t.Errorf("%q 竟然收了", x)
			continue
		}
		if !strings.Contains(err.Error(), "地址") {
			t.Errorf("%q 的说法看不懂：%v", x, err)
		}
	}
}

// ── 挑网卡 ──

func Test两块网卡时不许猜(t *testing.T) {
	defer fixShareRoutes(nil, nil)()
	defer fixShareNICs([]netif.NIC{
		upNIC(t, "en0", "192.168.1.20/24"),
		upNIC(t, "en5", "10.6.0.8/24"),
	}, nil)()
	_, err := planFileShare(fileshareArgs{Root: "/tmp"})
	if err == nil {
		t.Fatal("两块都能开时该让人指，不该猜")
	}
	for _, want := range []string{"2 块", "en0", "en5", "iface", "下载失败"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("说法里少了 %s：%v", want, err)
		}
	}
}

func Test只有一块可用网卡时直接用它(t *testing.T) {
	// 问不到默认路由（各平台命令不一样，这是完全可能的一步）时，
	// 靠「全场只有一块」这一条也还能定下来。
	defer fixShareRoutes(nil, errors.New("这台机器问不到默认路由"))()
	tun := upNIC(t, "utun4", "192.168.99.5/24")
	tun.Virtual = true // VPN 建的口，不能拿它当共享出口
	defer fixShareNICs([]netif.NIC{
		{Name: "lo0", Loop: true, Up: true, Running: true},
		tun,
		upNIC(t, "en0", "192.168.1.20/24"),
	}, nil)()
	plan, err := planFileShare(fileshareArgs{Root: "/tmp"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if plan.iface != "en0" {
		t.Errorf("挑了 %s", plan.iface)
	}
	if !strings.Contains(plan.ifaceWhy, "只有一块") {
		t.Errorf("没说清是怎么定的：%s", plan.ifaceWhy)
	}
}

func Test默认路由那块优先于唯一判据(t *testing.T) {
	defer fixShareRoutes([]netif.DefaultRoute{{Family: "ipv4", Gateway: "10.6.0.1", Iface: "en5"}}, nil)()
	defer fixShareNICs([]netif.NIC{
		upNIC(t, "en0", "192.168.1.20/24"),
		upNIC(t, "en5", "10.6.0.8/24"),
	}, nil)()
	plan, err := planFileShare(fileshareArgs{Root: "/tmp"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if plan.iface != "en5" || len(plan.addrs) != 1 || plan.addrs[0] != "10.6.0.8" {
		t.Errorf("没按默认路由那块：%+v", plan)
	}
	if !strings.Contains(plan.ifaceWhy, "默认路由") {
		t.Errorf("%s", plan.ifaceWhy)
	}
}

func Test六的默认路由不算四的事(t *testing.T) {
	// 两块网卡、只有 v6 的默认路由：v4 该开在哪块仍然说不清，不能拿 v6 那块当答案。
	defer fixShareRoutes([]netif.DefaultRoute{{Family: "ipv6", Gateway: "fe80::1", Iface: "en0"}}, nil)()
	defer fixShareNICs([]netif.NIC{
		upNIC(t, "en0", "192.168.1.20/24"),
		upNIC(t, "en5", "10.6.0.8/24"),
	}, nil)()
	if _, err := planFileShare(fileshareArgs{Root: "/tmp"}); err == nil {
		t.Fatal("不该照着 v6 默认路由猜 v4 的口")
	}
}

func Test没有一块能开共享时说清楚(t *testing.T) {
	defer fixShareRoutes(nil, nil)()
	defer fixShareNICs([]netif.NIC{
		{Name: "lo0", Loop: true, Up: true, Running: true, Addrs: []netaddr.Addr{{IP: netip.MustParseAddr("127.0.0.1")}}},
		{Name: "en0", Up: true}, // 没插线
		upNIC(t, "en8", "169.254.3.4/16"),
	}, nil)()
	_, err := planFileShare(fileshareArgs{Root: "/tmp"})
	if err == nil || !strings.Contains(err.Error(), "没有一块") {
		t.Fatalf("%v", err)
	}
}

func Test指定的网卡不存在时列出别的(t *testing.T) {
	defer fixShareNICs([]netif.NIC{upNIC(t, "en0", "192.168.1.20/24")}, nil)()
	_, err := planFileShare(fileshareArgs{Root: "/tmp", Iface: "eth3"})
	if err == nil || !strings.Contains(err.Error(), "eth3") || !strings.Contains(err.Error(), "net.interfaces") {
		t.Fatalf("%v", err)
	}
}

func Test指定的网卡上没有可用地址(t *testing.T) {
	defer fixShareNICs([]netif.NIC{upNIC(t, "en0", "169.254.1.2/16")}, nil)()
	_, err := planFileShare(fileshareArgs{Root: "/tmp", Iface: "en0"})
	if err == nil || !strings.Contains(err.Error(), "没有一个可用的地址") {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "169.254") {
		t.Errorf("该点破 169.254 是 DHCP 没要到地址：%v", err)
	}
}

func Test共享地址里不带链路本地(t *testing.T) {
	// 设备不会照着 fe80::…%en0 去填下载地址，带上只会多一栏没人看得懂的。
	n := upNIC(t, "en0", "192.168.1.20/24", "169.254.9.9/16", "fe80::1234/64", "fd00::5/64", "203.0.113.9/32")
	got := shareAddrs(n)
	want := []string{"192.168.1.20", "203.0.113.9", "fd00::5"} // v4 在前，v6 在后
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("拿到 %v", got)
	}
}

func Test公网地址要提醒(t *testing.T) {
	defer fixShareRoutes([]netif.DefaultRoute{{Family: "ipv4", Iface: "en0"}}, nil)()
	defer fixShareNICs([]netif.NIC{upNIC(t, "en0", "203.0.113.9/24")}, nil)()
	plan, err := planFileShare(fileshareArgs{Root: "/tmp"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	// ★ 不按下标取：提醒有两条来源（密钥、公网地址），谁先谁后不是给人的约定，
	//   只要这条在就行。
	if len(plan.warnings) == 0 {
		t.Fatalf("一条提醒都没有")
	}
	var found bool
	for _, w := range plan.warnings {
		if strings.Contains(w, "公网") {
			found = true
		}
	}
	if !found {
		t.Errorf("没提醒这是直接开在互联网上：%v", plan.warnings)
	}
}

// ── 看目录 ──

func Test数目录只到第二层(t *testing.T) {
	dir := shareDir(t, map[string]string{
		"a.bin":       "1",
		"b.bin":       "22",
		"sub/c.bin":   "333",
		"sub/x/d.bin": "4444", // ★ 第三层不该被数进来
	})
	files, dirs, bytes, _, err := surveyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if files != 3 || dirs != 1 || bytes != 6 {
		t.Errorf("files=%d dirs=%d bytes=%d", files, dirs, bytes)
	}
}

func Test只看文件名不读内容(t *testing.T) {
	dir := shareDir(t, map[string]string{
		"id_rsa":        "PRIVATE KEY MATERIAL 不要读我",
		"server.pem":    "PEM 不要读我",
		"firmware.bin":  "固件",
		"readme.md":     "说明",
		"sub/.env":      "TOKEN=abc",
		"sub/notes.txt": "笔记",
	})
	_, _, _, secrets, err := surveyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(secrets, ",")
	for _, want := range []string{".env", "id_rsa", "server.pem"} {
		if !strings.Contains(got, want) {
			t.Errorf("少了 %s：%s", want, got)
		}
	}
	for _, no := range []string{"firmware", "readme", "notes"} {
		if strings.Contains(got, no) {
			t.Errorf("不该报 %s：%s", no, got)
		}
	}
	for _, content := range []string{"PRIVATE", "TOKEN=abc", "PEM"} {
		if strings.Contains(got, content) {
			t.Errorf("把文件内容读进来了：%s", got)
		}
	}
}

func Test密钥判定按名字给全(t *testing.T) {
	yes := []string{"id_rsa", "id_ed25519.pub", "ca.pem", "srv.key", "p.p12", "p.pfx",
		"pw.kdbx", "trust.jks", ".env", ".netrc", ".htpasswd", "passwd", "shadow", "credentials"}
	for _, n := range yes {
		if !looksSecret(n) {
			t.Errorf("%s 该认出来", n)
		}
	}
	no := []string{"firmware_v2.3.1.bin", "app.hex", "config.json", "README.md", "flash.s19", "key_note.txt"}
	for _, n := range no {
		if looksSecret(n) {
			t.Errorf("%s 不该被当成密钥", n)
		}
	}
}

func Test体积说人话(t *testing.T) {
	for _, c := range []struct {
		n    int64
		want string
	}{{0, "0 字节"}, {999, "999 字节"}, {2048, "2 KB"}, {5 << 20, "5.0 MB"}, {3 << 30, "3.0 GB"}} {
		if got := humanSize(c.n); got != c.want {
			t.Errorf("humanSize(%d)=%s，应为 %s", c.n, got, c.want)
		}
	}
}

// ── 端到端：起 → 取 → 看 → 停 ──

func Test起共享到停共享走通一遍(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw-v2.3.bin": strings.Repeat("A", 4096)})
	v := serveLocal(t, dir, nil)
	if v.Code != verdictShareServing {
		t.Fatalf("该是 %s，拿到 %s", verdictShareServing, v.Code)
	}
	url := shareURL(v)
	if !strings.HasPrefix(url, "http://127.0.0.1:") || strings.HasSuffix(url, ":0/") {
		t.Fatalf("URL 没法用：%s", url)
	}
	body, err := http.Get(url + "fw-v2.3.bin")
	if err != nil {
		t.Fatalf("本机取自己的共享失败：%v", err)
	}
	b, _ := io.ReadAll(body.Body)
	body.Body.Close()
	if len(b) != 4096 {
		t.Fatalf("取回 %d 字节", len(b))
	}

	// ★ 为什么要轮：这笔账是 handler 收尾时记的，客户端读完响应体时服务端
	//   可能还差那一笔。睡固定时长会在慢机器上偶发失败，轮询不会。
	var st map[string]any
	for i := 0; i < 60; i++ {
		st = statusSnapshot(t)
		if hasRecent(st, "/fw-v2.3.bin", "ok") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hasRecent(st, "/fw-v2.3.bin", "ok") {
		t.Fatalf("没记上这一笔：%v", recentPaths(st))
	}
	if st["running"] != true {
		t.Errorf("running=%v", st["running"])
	}
	if v := st["bytes"]; v != float64(4096) {
		t.Errorf("bytes=%v", v)
	}

	sv, err := callShare(t, fileshareStopTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if sv.Code != verdictShareStopped {
		t.Errorf("停掉该给 %s，拿到 %s", verdictShareStopped, sv.Code)
	}
	// 停干净了：端口该放掉，状态该说没在跑
	if _, err := http.Get(url + "fw-v2.3.bin"); err == nil {
		t.Error("停了之后还读得到")
	}
	iv, err := callShare(t, fileshareStatusTool, map[string]any{})
	if err != nil || iv.Code != verdictShareIdle {
		t.Fatalf("停了之后该说没开：%v %+v", err, iv.Code)
	}
}

func Test没在跑时状态先给一条(t *testing.T) {
	shareReset(t)
	v, err := callShare(t, fileshareStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != verdictShareIdle {
		t.Errorf("%s", v.Code)
	}
	if !strings.Contains(v.Note, "没有开文件共享") {
		t.Errorf("%s", v.Note)
	}
	if _, err := callShare(t, fileshareStopTool, map[string]any{}); err != nil {
		t.Errorf("没在跑时停一次不该报错：%v", err)
	}
}

func Test上传试都不许试(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	v := serveLocal(t, dir, nil)
	url := shareURL(v)
	resp, err := http.Post(url+"up.bin", "application/octet-stream", strings.NewReader("恶意上传"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST 拿到 %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dir, "up.bin")); err == nil {
		t.Fatal("★ 目录里真的多出了文件 —— 只读破功了")
	}
	st := statusSnapshot(t)
	if !hasRecent(st, "/up.bin", "denied") {
		t.Errorf("有人试上传却没记一笔：%v", recentPaths(st))
	}
	// ★ 这一笔进的是「被拒」那个数，不许和「文件名没对上」混在同一个计数里
	if got := st["denied"]; got != float64(1) {
		t.Errorf("denied=%v", got)
	}
	if got := st["notFound"]; got != float64(0) {
		t.Errorf("没人写错文件名却记了 %v 笔", got)
	}
}

func Test同时只允许一个共享(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	serveLocal(t, dir, nil)
	_, err := callShare(t, fileshareServeTool, map[string]any{
		"root": dir, "addrs": []string{"127.0.0.1"}, "port": freePort(t),
	})
	if err == nil || !strings.Contains(err.Error(), "已经有一个共享在跑") {
		t.Fatalf("第二个该被拒：%v", err)
	}
	if !strings.Contains(err.Error(), "stop") {
		t.Errorf("该说下一步怎么停：%v", err)
	}
	// 停掉之后才允许开新的
	if _, err := callShare(t, fileshareStopTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	serveLocal(t, dir, nil)
}

func Test端口被别的服务占了时报的是被占(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	// ★ 先拿一个号占住，假装那是别人家的服务：报的该是「已经被别的服务占了」，
	//   不是「起不来」这种没法接着查的话，也不该是「要更高权限」那种劝人去 sudo 的话。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	dir := shareDir(t, nil)
	_, err = callShare(t, fileshareServeTool, map[string]any{
		"root": dir, "addrs": []string{"127.0.0.1"}, "port": port,
	})
	if err == nil {
		t.Fatal("同端口该起不来")
	}
	if !strings.Contains(err.Error(), "已经被别的服务占了") {
		t.Errorf("%v", err)
	}
	if !strings.Contains(err.Error(), "端口占用") {
		t.Errorf("该给下一步去哪查：%v", err)
	}
	// 起不来就不许留下半个共享：留下的话下一次调用会被自己挡住
	fileshare.mu.Lock()
	defer fileshare.mu.Unlock()
	if fileshare.srv != nil {
		t.Error("报错了还把共享挂在槽里")
	}
}

func Test关列表时给的是完整文件名(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	v := serveLocal(t, dir, map[string]any{"listing": false})
	if v.Values["listing"] != false {
		t.Errorf("结果里没跟着说列表关没关：%v", v.Values["listing"])
	}
	url := shareURL(v)
	// 翻目录：给 403，并且说清「不是没有，是不给翻」
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("关列表后翻目录拿到 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "完整文件名") {
		t.Errorf("该教下一步怎么填：%s", body)
	}
	// 知道文件名照样取得走：关列表收的是「翻」，不是「取」
	resp2, err := http.Get(url + "fw.bin")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || string(b2) != "abc" {
		t.Errorf("关列表后取文件拿到 %d / %q", resp2.StatusCode, b2)
	}
}

func Test穿越路径取不到根外的东西(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	v := serveLocal(t, dir, nil)
	url := shareURL(v)
	// ★ 光靠 "../" 在 URL 里看不出问题（客户端会先折叠掉），所以几种写法都试一遍，
	//   包括编码过的 —— 这一条守的是「不管怎么拼都出不了这个目录」。
	for _, probe := range []string{"..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
		"fw.bin/../../etc/hosts", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"} {
		resp, err := http.Get(url + probe)
		if err != nil {
			t.Fatalf("%s：%v", probe, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			n := len(body)
			if n > 60 {
				n = 60
			}
			t.Errorf("%s 竟然取到了共享目录外面的东西：%s", probe, body[:n])
		}
	}
	// 这些折叠回来是「根里没有这个文件」，记成 not-found 而不是被拒：
	// ★ 文件名写错是现场常态，记成被拒会把一个干净的共享搞得像被攻击过。
	st := statusSnapshot(t)
	if !hasRecent(st, "/../../etc/passwd", "not-found") {
		t.Errorf("该记成没有这个文件：%v", recentPaths(st))
	}
	// 折叠回根内 = 文件名没对上，进 notFound 这个数；
	// 记成被拒的话，一个干净的共享会被读数搞得像被人打过。
	if got := st["denied"]; got != float64(0) {
		t.Errorf("一次越界都没发生，被拒却是 %v", got)
	}
	if got := st["notFound"]; got == float64(0) {
		t.Errorf("文件名没对上的那些该有个数：%v", st["notFound"])
	}
	if strings.Contains(recentStrings(st), "denied") {
		t.Errorf("越界没发生却记成了被拒：%v", recentPaths(st))
	}
}

func recentStrings(m map[string]any) string {
	return strings.Join(recentPaths(m), " ")
}

// ── 账本与批准说明 ──

func Test没有账本就不开共享(t *testing.T) {
	shareReset(t)
	old := journal
	journal = nil
	t.Cleanup(func() { journal = old })
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	_, err := callShare(t, fileshareServeTool, map[string]any{
		"root": dir, "addrs": []string{"127.0.0.1"}, "port": 0,
	})
	if err == nil || !strings.Contains(err.Error(), "账本") {
		t.Fatalf("没有账本时该拒绝动手：%v", err)
	}
	fileshare.mu.Lock()
	defer fileshare.mu.Unlock()
	if fileshare.srv != nil {
		t.Error("拦下来了就不该有监听器留着")
	}
}

func Test开着的这一会儿账上挂着一笔(t *testing.T) {
	shareReset(t)
	j := shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	serveLocal(t, dir, nil)

	all := j.All()
	if len(all) != 1 {
		t.Fatalf("账上 %d 笔", len(all))
	}
	e := all[0]
	if e.Kind != "file-share" {
		t.Errorf("kind=%s", e.Kind)
	}
	for _, want := range []string{dir, "只读"} {
		if !strings.Contains(e.What, want) {
			t.Errorf("批准说明里没有 %s：%s", want, e.What)
		}
	}
	// ★ 长期在跑的服务跟唤醒那种一次性动作不一样：开着的时候该是 applied，
	//   挂在这本账上，人停掉它才翻篇。
	if e.Status != state.StatusApplied {
		t.Errorf("状态=%s，开着的时候该是 applied", e.Status)
	}
	if len(j.Outstanding()) != 1 {
		t.Errorf("没在跑却把账了结了")
	}
	if !strings.Contains(string(e.After), "\"root\"") {
		t.Errorf("账上没记开的哪个目录：%s", e.After)
	}
}

func Test停掉后这笔账翻篇(t *testing.T) {
	shareReset(t)
	j := shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	serveLocal(t, dir, nil)
	if _, err := callShare(t, fileshareStopTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if n := len(j.Outstanding()); n != 0 {
		t.Errorf("停了还剩 %d 笔没 of 结", n)
	}
	e := j.All()[0]
	if e.Status != state.StatusReverted || !strings.Contains(e.Note, "停") {
		t.Errorf("这一笔记得不像话：%+v", e)
	}
}

func Test重启时了结上次没停的账但不自动重开(t *testing.T) {
	j := shareJournal(t)
	for _, kind := range []string{"file-share", "dhcp-server"} {
		id, err := j.Register(kind, "上一次开的服务", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.MarkApplied(id); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	restoreFileShare(log)

	var fs, dhcp state.Entry
	for _, e := range j.All() {
		if e.Kind == "file-share" {
			fs = e
		} else {
			dhcp = e
		}
	}
	if fs.Status != state.StatusReverted {
		t.Errorf("上次没停的共享账没翻篇：%+v", fs)
	}
	if !strings.Contains(fs.Note, "重启") {
		t.Errorf("没说是因为重启结的账：%s", fs.Note)
	}
	// ★ 别的 kinds 不归这里管：动了它， DHCP 那套还原逻辑就找不到自己那笔了
	if dhcp.Status != state.StatusApplied {
		t.Errorf("把别的 kinds 的账也结了：%+v", dhcp)
	}
	fileshare.mu.Lock()
	defer fileshare.mu.Unlock()
	if fileshare.srv != nil {
		t.Error("不许人不在场就把目录重开出去")
	}
}

func Test结果里不带文件内容也不带目录以外的路径(t *testing.T) {
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{
		"fw.bin": "SUPERSECRET-FIRMWARE-BLOB-0123456789",
		".env":   "TOKEN=zzz-never-show-this",
	})
	v := serveLocal(t, dir, nil)
	url := shareURL(v)
	resp, err := http.Get(url + "fw.bin")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sv, _ := callShare(t, fileshareStopTool, map[string]any{})

	for label, x := range map[string]any{"serve": v, "stop": sv} {
		b, _ := json.Marshal(x)
		s := string(b)
		for _, leak := range []string{"SUPERSECRET", "zzz-never-show-this", "PRIVATE KEY"} {
			if strings.Contains(s, leak) {
				t.Errorf("%s 的结果里出现了文件内容 %s", label, leak)
			}
		}
	}
	// 文件名该出现（人要知道哪个文件像密钥），内容不该
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), ".env") {
		t.Errorf("该提醒 .env 这个名字能被下载：%s", b)
	}
}

func Test批准说明说得清开到哪块口(t *testing.T) {
	defer fixShareRoutes([]netif.DefaultRoute{{Family: "ipv4", Iface: "en5"}}, nil)()
	defer fixShareNICs([]netif.NIC{upNIC(t, "en5", "10.6.0.8/24")}, nil)()
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	s := describeFileShare(json.RawMessage(`{"root":"` + dir + `"}`))
	for _, want := range []string{"只读", "不能上传", "en5", "10.6.0.8", "8080", dir} {
		if !strings.Contains(s, want) {
			t.Errorf("批准说明里没有 %s：%s", want, s)
		}
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("fixture 目录就该是绝对路径")
	}
	// 相对路径要写成绝对的：批准的人看的是同一个目录，不能是「相对于谁的工作目录」
	wd, _ := os.Getwd()
	rel, err := filepath.Rel(wd, dir)
	if err == nil && !filepath.IsAbs(rel) && strings.Contains(s, wd) {
		t.Errorf("相对路径没落成绝对：%s", s)
	}
}

func Test批准说明里带上密钥提醒(t *testing.T) {
	defer fixShareNICs([]netif.NIC{upNIC(t, "en0", "192.168.1.20/24")}, nil)()
	dir := shareDir(t, map[string]string{"id_rsa": "x"})
	s := describeFileShare(json.RawMessage(`{"root":"` + dir + `","port":80}`))
	if !strings.Contains(s, "id_rsa") || !strings.Contains(s, "密钥") {
		t.Errorf("点批准的人看不到这个目录里有密钥：%s", s)
	}
}

func Test空参数也要有一句批准说明(t *testing.T) {
	s := describeFileShare(nil)
	if !strings.Contains(s, "没给目录") {
		t.Errorf("%s", s)
	}
}

// ── 判定码与界面 ──

func Test共享每个判定都有人话(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Skipf("读不到界面源码：%v", err)
	}
	js := string(b)
	for _, code := range []string{verdictShareServing, verdictShareStopped, verdictShareIdle} {
		if !strings.Contains(js, `"`+code+`"`) && !strings.Contains(js, `'`+code+`'`) {
			t.Errorf("界面里没有 %s 的说法", code)
		}
	}
	// 取用状态也要一种说法有一份：这几种的处置完全不同，
	// 界面上并成一句「失败」就等于让人瞎猜。
	for _, st := range []string{"ok", "partial", "denied", "not-found", "head", "range", "list"} {
		if !strings.Contains(js, `'`+st+`'`) && !strings.Contains(js, `"`+st+`"`) &&
			!strings.Contains(js, "\n  "+st+": [") {
			t.Errorf("界面里没有取用状态 %s 的说法", st)
		}
	}
}

// 整张注册表过一遍闸门。
//
// ★ 这一条是这次自己被咬出来的：schema 里串进了一段 Go 的字符串拼接（写在反引号里，
//
//	编译过、其它测试全绿），一直到起服务时才炸。Register 里那些闸门
//	（类别、说明、批准说明、schema 合法）只在启动 panic 时看得见，
//	而注册表这种东西本来就该在测试里就拦下来。
func Test整张注册表每一项都合格(t *testing.T) {
	r := ots.NewRegistry(true)
	Register(r) // 不合格就是 panic，测试直接红
	list := r.Visible()
	if len(list) < 20 {
		t.Fatalf("只注册上 %d 个工具，注册表本身出问题了", len(list))
	}
	var loose []string
	for _, tool := range list {
		var m map[string]any
		if err := json.Unmarshal(tool.Schema, &m); err != nil {
			t.Errorf("%s 的 schema 解析不了：%v", tool.Name, err)
			continue
		}
		// 不写这一条的调用方多打一个字段就静默按默认值跑，
		// 对 mutate 工具尤其危险（多点一个键等于多同意一件事）。
		if m["additionalProperties"] != false {
			loose = append(loose, tool.Name)
		}
	}
	if len(loose) > 0 {
		t.Errorf("这些工具的 schema 放过没写的参数：%s", strings.Join(loose, "、"))
	}
}

func Test共享判定码格式(t *testing.T) {
	for _, code := range []string{verdictShareServing, verdictShareStopped, verdictShareIdle} {
		if !ots.ValidVerdictCode(code) {
			t.Errorf("%s 不是合法判定码", code)
		}
	}
}

func Test状态刷新不丢开共享时那几行(t *testing.T) {
	// ★ 界面上台账每 3 秒自己刷一次；刷的那一次走的是 status。
	//   要是 status 只带地址和计数器，「开在哪块口、这口怎么挑中的、目录里那个
	//   id_rsa 还挂着」就只活三秒 —— 多网卡机器上人回头再看，
	//   已经说不清这个口是默认路由那块还是别的，也就想不起要停。
	shareReset(t)
	shareJournal(t)
	defer fixShareNICs([]netif.NIC{upNIC(t, "en0", "192.168.0.101/24")}, nil)()
	defer fixShareRoutes(nil, nil)()
	dir := shareDir(t, map[string]string{"fw.bin": "abc", "id_rsa": "private"})

	if _, err := callShare(t, fileshareServeTool, map[string]any{"root": dir}); err != nil {
		t.Fatalf("起共享失败：%v", err)
	}
	v, err := callShare(t, fileshareStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Values["iface"]; got != "en0" {
		t.Errorf("status 里没带网卡：%v", got)
	}
	if got, _ := v.Values["ifaceWhy"].(string); !strings.Contains(got, "只有一块") {
		t.Errorf("没说清是怎么定的：%q", got)
	}
	// ★ 目录规模和密钥提醒也要跟着刷：这两行是「要不要现在停掉」的依据，
	//   开的时候亮一下、三秒后自己消失，等于把人最需要看的那句话藏起来了。
	if got, _ := v.Values["entries"].(int); got == 0 {
		t.Errorf("刷一次状态目录里有多少就没了：%v", v.Values["entries"])
	}
	warns, _ := v.Values["warnings"].([]string)
	var hasSecret bool
	for _, w := range warns {
		if strings.Contains(w, "密钥") {
			hasSecret = true
		}
	}
	if !hasSecret {
		t.Errorf("状态里没有那条密钥提醒：%v", v.Values["warnings"])
	}
	// 停掉之后这两个字段要跟着清掉，否则下次 status 会说一个没在跑的网卡
	if _, err := callShare(t, fileshareStopTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	after, err := callShare(t, fileshareStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if after.Values["iface"] != nil || after.Code != verdictShareIdle {
		t.Errorf("停了还留着网卡信息：%+v", after.Values)
	}
}

func Test批准说明里要写明多开了TFTP这一件事(t *testing.T) {
	// ★ 人点头的是批准说明那一句「整体」。只写 http 的话，他并不知道
	//   自己同时同意了一个 UDP 口 —— 而防火墙对 UDP 的默认放行往往更松。
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	off := describeFileShare(json.RawMessage(`{"root":"` + dir + `"}`))
	// ★ 这里比对的是那句原话，不是「TFTP」这个单词 —— 目录路径里带着测试名，
	//   测试名里就有这三个字母，比单词的话这条会一直假绿。
	if strings.Contains(off, "TFTP 端口") || strings.Contains(off, "同时开 TFTP") {
		t.Errorf("没开 TFTP 的批准说明里冒出了一句 TFTP：%s", off)
	}
	on := describeFileShare(json.RawMessage(`{"root":"` + dir + `","tftp":true,"tftpPort":6933}`))
	if !strings.Contains(on, "TFTP 端口") || !strings.Contains(on, "UDP") {
		t.Errorf("开了 TFTP 的批准说明没把这件事说出来：%s", on)
	}
	if !strings.Contains(on, "6933") {
		t.Errorf("批准说明里没写开在哪个口：%s", on)
	}
	if !strings.Contains(on, "只读") {
		t.Errorf("没说清 TFTP 这一侧同样只读：%s", on)
	}
}

func Test只填端口不开TFTP时先问一句(t *testing.T) {
	// 静默忽略 tftpPort 的话，人会以为端口生效了，然后回去查设备为什么连不上。
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	v, err := callShare(t, fileshareServeTool, map[string]any{
		"root": dir, "addrs": []string{"127.0.0.1"}, "port": freePort(t), "tftpPort": 6933})
	if err == nil {
		t.Fatalf("只填了 tftpPort 也起了起来：%+v", v)
	}
	if !strings.Contains(err.Error(), "tftp") {
		t.Errorf("报错没落在 tftp 上：%v", err)
	}
}

func Test开了TFTP时结果里给出tftp地址(t *testing.T) {
	// 老设备的升级页面要的就是 tftp://ip/文件名 这一串；没带回来的话，
	// 这个功能等于只多开了一个口。
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	v, err := callShare(t, fileshareServeTool, map[string]any{
		"root": dir, "addrs": []string{"127.0.0.1"}, "port": freePort(t),
		"tftp": true, "tftpPort": freeUDPPort(t)})
	if err != nil {
		t.Fatalf("起共享失败：%v", err)
	}
	urls, _ := v.Values["tftpUrls"].([]string)
	if len(urls) == 0 || !strings.HasPrefix(urls[0], "tftp://127.0.0.1:") {
		t.Fatalf("没给出可贴的 tftp 地址：%v", v.Values["tftpUrls"])
	}
	proto, _ := v.Values["protocols"].([]string)
	if len(proto) != 2 || proto[1] != "tftp" {
		t.Errorf("协议一栏没说两种都开着：%v", v.Values["protocols"])
	}
	// ★ note 里也要有：批准的人看的就是这句话，起完之后只剩 http 等于事后看不出
	if !strings.Contains(v.Note, "TFTP") {
		t.Errorf("落账那句没提 TFTP：%s", v.Note)
	}
	// 状态刷新时这两条都得还在（界面上它每 3 秒刷一次）
	st, err := callShare(t, fileshareStatusTool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if su, _ := st.Values["tftpUrls"].([]string); len(su) == 0 {
		t.Errorf("刷一次状态就没有 tftp 地址了：%v", st.Values["tftpUrls"])
	}
	if st.Values["tftp"] != true {
		t.Errorf("状态里没说 TFTP 开着：%v", st.Values["tftp"])
	}
	if _, err := callShare(t, fileshareStopTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	after, _ := callShare(t, fileshareStatusTool, map[string]any{})
	if au, _ := after.Values["tftpUrls"].([]string); len(au) != 0 {
		t.Errorf("停了还报着 tftp 地址：%v", au)
	}
}

func TestTFTP绑不上时不留一个只开了http的共享(t *testing.T) {
	// ★ 批准的是「http + tftp」这个整体：TFTP 起不来却把 http 留着，
	//   等于偷偷改了人点头的那件事 —— 而且界面上一眼看不出少了什么。
	shareReset(t)
	shareJournal(t)
	dir := shareDir(t, map[string]string{"fw.bin": "abc"})
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.LocalAddr().(*net.UDPAddr).Port

	_, err = callShare(t, fileshareServeTool, map[string]any{
		"root": dir, "addrs": []string{"127.0.0.1"}, "port": freePort(t),
		"tftp": true, "tftpPort": port})
	if err == nil {
		t.Fatal("tftp 端口被占却起了起来")
	}
	if !strings.Contains(err.Error(), "已经被别的服务占了") && !strings.Contains(err.Error(), "绑不上") {
		t.Errorf("报错没落在端口上：%v", err)
	}
	st, e2 := callShare(t, fileshareStatusTool, map[string]any{})
	if e2 != nil {
		t.Fatal(e2)
	}
	if st.Code != verdictShareIdle {
		t.Errorf("半个共享留在了机上：%+v", st.Values)
	}
	// 那个 http 端口也要放掉：占着不用最坏
	fileshare.mu.Lock()
	srv := fileshare.srv
	fileshare.mu.Unlock()
	if srv != nil {
		t.Error("回滚没做干净，http 还在听")
	}
}
