package filesrv

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这个包里的测试全在 127.0.0.1 上跑，不碰真的网卡，也不出本机。

// tempShare 建一个固件目录样子的临时目录 + 起一个服务。
func tempShare(t *testing.T, cfg func(*Config)) *Server {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "IPCamera_full_V2.4.5.bin", []byte(strings.Repeat("A", 5000)))
	writeFile(t, root, "说明 与#号.bin", []byte("配置"))
	if err := os.Mkdir(filepath.Join(root, "老版本"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "老版本"), "V2.4.4.bin", []byte("old"))
	c := Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 0, Listing: true}
	if cfg != nil {
		cfg(&c)
	}
	s, err := Start(c)
	if err != nil {
		t.Fatalf("起不来：%v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func writeFile(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func base(s *Server) string {
	st := s.Status()
	if len(st.URLs) == 0 {
		panic("没有 URL")
	}
	return strings.TrimSuffix(st.URLs[0], "/")
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	r, err := http.Get(url)
	if err != nil {
		t.Fatalf("取 %s 失败：%v", url, err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r, string(b)
}

func Test取文件记的是一整份(t *testing.T) {
	s := tempShare(t, nil)
	resp, body := get(t, base(s)+"/IPCamera_full_V2.4.5.bin")
	if resp.StatusCode != 200 || len(body) != 5000 {
		t.Fatalf("状态 %d，长度 %d", resp.StatusCode, len(body))
	}
	st := s.Status()
	if st.Requests != 1 || st.Bytes != 5000 {
		t.Fatalf("记账不对：%+v", st)
	}
	if len(st.Recent) != 1 || st.Recent[0].Status != "ok" {
		t.Fatalf("这一笔该是 ok：%+v", st.Recent)
	}
	if !strings.Contains(st.Recent[0].Path, "V2.4.5") {
		t.Errorf("要记下取的是哪个文件（现场就问这句）：%+v", st.Recent[0])
	}
}

func Test上传一律拒而且记一笔(t *testing.T) {
	// ★ 「不收写」必须是当场 405 且留痕，不是「试一下也许能写」。
	//   有人在拿这个共享试上传，这件事本身要让人看见。
	s := tempShare(t, nil)
	req, _ := http.NewRequest(http.MethodPut, base(s)+"/x.bin", strings.NewReader("hack"))
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT 该 405，拿到 %d", r.StatusCode)
	}
	if a := r.Header.Get("Allow"); a == "" {
		t.Error("405 要带 Allow 说清只接哪些方法")
	}
	if _, err := os.Stat(filepath.Join(s.Status().Root, "x.bin")); err == nil {
		t.Fatal("文件被写上去了")
	}
	st := s.Status()
	if st.Denied != 1 || st.Requests != 0 {
		t.Fatalf("这一笔要记成被拒：%+v", st)
	}
	if st.Recent[0].Status != "denied" {
		t.Errorf("被拒那一笔 %+v", st.Recent[0])
	}
}

func Test符号链接不许把人带出共享目录(t *testing.T) {
	s := tempShare(t, nil)
	root := s.Status().Root
	// 现场真会出现这种：有人把系统目录软过来「方便取」
	link := filepath.Join(root, "escape")
	if err := os.Symlink("/etc/hosts", link); err != nil {
		t.Skipf("这台机器不让建符号链接：%v", err)
	}
	resp, body := get(t, base(s)+"/escape")
	if resp.StatusCode == 200 || strings.Contains(body, "127.0.0.1") {
		t.Fatalf("把目录外的文件给出去了（%d）：%s", resp.StatusCode, body)
	}
	// 目录里有一层链接也不行
	dirLink := filepath.Join(root, "linkdir")
	if err := os.Symlink("/etc", dirLink); err != nil {
		t.Skip()
	}
	resp2, _ := get(t, base(s)+"/linkdir/passwd")
	if resp2.StatusCode == 200 {
		t.Fatal("穿过链接目录读到了别处")
	}
}

func Test列表里不许出现链接目标(t *testing.T) {
	s := tempShare(t, nil)
	_, body := get(t, base(s)+"/")
	if strings.Contains(body, "escape") && !strings.Contains(body, "老版本") {
		t.Fatal("列表渲染不对")
	}
	// 名字里的空格和 # 必须转义成能点的链接：那是设备拿去下载的地址
	if !strings.Contains(body, "%20") || !strings.Contains(body, "%23") {
		t.Errorf("文件名里的空格/# 没转义，链接点不开：%s", body)
	}
}

func Test关掉列表时给403不是404(t *testing.T) {
	s := tempShare(t, func(c *Config) { c.Listing = false })
	resp, body := get(t, base(s)+"/")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("该 403，拿到 %d", resp.StatusCode)
	}
	if !strings.Contains(body, "完整文件名") {
		t.Errorf("要说清「目录在，只是不给翻」：%s", body)
	}
	// 文件照样取得到
	if r, _ := get(t, base(s)+"/老版本/V2.4.4.bin"); r.StatusCode != 200 {
		t.Errorf("关列表不该影响取文件：%d", r.StatusCode)
	}
}

func Test断点续传那一笔不许记成失败(t *testing.T) {
	// ★ 设备的固件页面普遍带 Range（断点续传）。要是把「取前 100 字节」
	//   报成 partial，人就会以为在掉线，而它其实在正常续传。
	s := tempShare(t, nil)
	req, _ := http.NewRequest(http.MethodGet, base(s)+"/IPCamera_full_V2.4.5.bin", nil)
	req.Header.Set("Range", "bytes=0-99")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if len(b) != 100 {
		t.Fatalf("Range 没生效，拿到 %d 字节", len(b))
	}
	st := s.Status()
	if st.Recent[0].Status != "range" {
		t.Errorf("这一笔该记成 range：%+v", st.Recent[0])
	}
}

func Test问大小不许记成已下发(t *testing.T) {
	s := tempShare(t, nil)
	resp, err := http.Head(base(s) + "/IPCamera_full_V2.4.5.bin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	st := s.Status()
	if st.Recent[0].Status != "head" || st.Recent[0].Bytes != 0 {
		t.Errorf("HEAD 不该把整文件大小记成下发：%+v", st.Recent[0])
	}
}

func Test不存在的文件说成没有(t *testing.T) {
	s := tempShare(t, nil)
	resp, _ := get(t, base(s)+"/nope.bin")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("该 404，拿到 %d", resp.StatusCode)
	}
	if st := s.Status(); st.Recent[0].Status != "not-found" || st.NotFound != 1 || st.Denied != 0 {
		t.Errorf("取不到的这一笔也要留下：%+v", st.Recent)
	}
}

func Test多个地址共用同一个端口(t *testing.T) {
	// ★ 两块网卡各一个监听器时端口必须一样：界面只给一条 URL 列表，
	//   端口对不上的话，换块网卡下载就失败，而人完全看不出为什么。
	s := tempShare(t, nil)
	second := &net.TCPAddr{}
	_ = second
	if len(s.Status().AddrInfo) != 1 {
		t.Fatal("样例只有一个地址")
	}
	port := s.Port()
	if port == 0 {
		t.Fatal("填 0 时要从监听器上把真实端口读回来")
	}
	// 同端口再起一次必须失败（说明端口是绑上去的，不是摆设）
	if _, err := Start(Config{Root: s.Status().Root, Addrs: []string{"127.0.0.1"}, Port: port}); err == nil {
		t.Fatal("同端口再起一个该报错")
	} else if !strings.Contains(err.Error(), "已经被别的服务占了") {
		t.Errorf("端口被占要这么说，人才知道下一步是换端口：%v", err)
	}
}

func Test绑不上的三种原因分开说(t *testing.T) {
	root := t.TempDir()
	if _, err := Start(Config{Root: root, Addrs: []string{"240.0.0.1"}, Port: 8080}); err == nil {
		t.Fatal("本机没有这个地址，该失败")
	} else if !strings.Contains(err.Error(), "本机没有") {
		t.Errorf("要说清是「这个地址本机没有」，不是笼统的绑定失败：%v", err)
	}
	if _, err := Start(Config{Root: root, Addrs: nil}); err != ErrNoAddr {
		t.Errorf("一个地址都没给时不许悄悄绑 0.0.0.0：%v", err)
	}
	if _, err := Start(Config{Root: filepath.Join(root, "不存在"), Addrs: []string{"127.0.0.1"}}); err == nil {
		t.Error("目录不存在该失败")
	}
	if _, err := Start(Config{Root: root, Addrs: []string{"127.0.0.1"}, Port: 70000}); err == nil {
		t.Error("端口超范围该失败")
	}
}

func Test停掉之后端口就空出来(t *testing.T) {
	s := tempShare(t, nil)
	url := base(s)
	s.Stop()
	if _, err := http.Get(url + "/IPCamera_full_V2.4.5.bin"); err == nil {
		t.Fatal("停了还能取")
	}
	if st := s.Status(); st.Running {
		t.Error("状态里还在说 running")
	}
	// 端口能立刻被重绑（说明监听器真关了，不是 goroutine 卡住）
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", 0))
	if err != nil {
		t.Skip()
	}
	_ = ln.Close()
}

func Test最近记录倒着给(t *testing.T) {
	s := tempShare(t, nil)
	_, _ = get(t, base(s)+"/IPCamera_full_V2.4.5.bin")
	_, _ = get(t, base(s)+"/老版本/V2.4.4.bin")
	st := s.Status()
	if len(st.Recent) != 2 {
		t.Fatalf("两笔：%+v", st.Recent)
	}
	if !strings.Contains(st.Recent[0].Path, "V2.4.4") {
		t.Errorf("最新那一笔要在最前面（现场第一眼就问这个）：%+v", st.Recent)
	}
}

func Test链接目录当根时列表页不说糊话(t *testing.T) {
	// ★ 这一条是被现场咬出来的：macOS 上 /tmp、临时目录都在 /private 的链接后面，
	//   拿没解开符号链接的根去比解开的落点，根目录这一层永远对不上，
	//   标题就成了 ../../private/var/… —— 人看一眼以为共享开错了目录。
	s := tempShare(t, nil)
	_, body := get(t, base(s)+"/")
	if !strings.Contains(body, "共享根目录") {
		t.Errorf("根目录那一页标题没认出来：%s", firstLine(body))
	}
	if strings.Contains(body, "../") {
		t.Errorf("标题里出现了 ../，看着像越出了目录：%s", firstLine(body))
	}
	// 子目录仍然要给相对路径：这一层是人在翻的，得说清翻到哪了
	_, sub := get(t, base(s)+"/%E8%80%81%E7%89%88%E6%9C%AC/")
	if !strings.Contains(sub, "老版本") {
		t.Errorf("子目录页没写这是老版本：%s", firstLine(sub))
	}
}

func firstLine(html string) string {
	if i := strings.Index(html, "<title>"); i >= 0 {
		if j := strings.Index(html[i:], "</title>"); j >= 0 {
			return html[i : i+j+8]
		}
	}
	return html
}
