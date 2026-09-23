package filesrv

import (
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// 只读的 HTTP 这一侧：路径怎么解析才算安全、目录列表长什么样、
// 以及「谁来取走了哪个文件」这一笔怎么记。

func (s *Server) handler() http.Handler { return http.HandlerFunc(s.serve) }

// countWriter 数我们真写出去多少字节。
//
// ★ 故意不实现 ReadFrom：实现了 http.ServeContent 就走 splice，那一步我们数不到，
//
//	现场就会出现「传完了但记账是 0」。
type countWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		peer = h
	}
	// ★ 只接 GET/HEAD。写方法当场 405 并且记一笔 —— 有人在拿它试上传，
	//   这件事本身就是要让人看见的。
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Status: "denied"})
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "只读共享：不收文件", http.StatusMethodNotAllowed)
		return
	}

	fi, full, why, err := s.resolve(r.URL.Path)
	if err != nil {
		// ★ 「够不着」和「没有」必须分开：越出目录是有人在试，得记成被拒；
		//   文件名写错是常态，记成被拒会把这共享搞得像被攻击过一样。
		code, status := http.StatusNotFound, "not-found"
		if why == "outside" {
			code, status = http.StatusForbidden, "denied"
		}
		s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Status: status})
		http.Error(w, httpReason(why), code)
		return
	}

	if fi.IsDir() {
		if !s.cfg.Listing {
			// 关列表时给 403 而不是 404：让人知道「目录在，只是不给翻」，
			// 否则会以为是地址写错了，在那儿反复改 URL 里的斜杠。
			s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Status: "denied"})
			http.Error(w, "这个共享关掉了目录列表：请直接填完整文件名", http.StatusForbidden)
			return
		}
		s.serveList(w, r, peer, full)
		return
	}

	f, err := os.Open(full)
	if err != nil {
		s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Status: "denied"})
		http.Error(w, "这个文件读不出来", http.StatusForbidden)
		return
	}
	defer f.Close()

	cw := &countWriter{ResponseWriter: w}
	// ServeContent 带上 Range 和 Last-Modified：设备的升级程序多半支持断点续传，
	// 不支持也没关系（它按整文件读）。
	http.ServeContent(cw, r, fi.Name(), fi.ModTime(), f)

	// 这一笔记的是什么：
	//   head   —— 只问了大小，没取内容（设备升级前常见）
	//   range  —— 按 Range 取了一段（断点续传在跑，不是失败）
	//   ok     —— 整文件都发完了
	//   partial—— 说好了要整份，中途断了  ★ 现场要的就是这一笔
	status := "ok"
	switch {
	case r.Method == http.MethodHead:
		status = "head"
	case r.Header.Get("Range") != "":
		status = "range"
	case fi.Size() > 0 && cw.n < fi.Size():
		status = "partial"
	}
	s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Bytes: cw.n, Status: status})
}

// resolve 把 URL 路径落到磁盘上，并且确认它**没有越出根目录**。
//
// ★ 两道检查各有各的用处：
//
//	filepath.Join 会自己吃掉 ../，所以只看拼接后的字符串永远看不出问题；
//	真正危险的是根目录里（或子目录里）有一个**符号链接**指向别处 ——
//	那种链接在现场太常见了（有人把 /Users 下某个目录软过来当固件目录）。
//	所以先逐段 Lstat 拒绝任何符号链接，再用 EvalSymlinks 复核落点确实在根里。
func (s *Server) resolve(urlPath string) (os.FileInfo, string, string, error) {
	clean := path.Clean("/" + strings.TrimPrefix(urlPath, "/"))
	full := filepath.Join(s.cfg.Root, filepath.FromSlash(clean))
	if err := noSymlink(s.cfg.Root, full); err != nil {
		return nil, "", "outside", err
	}
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, "", "missing", err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, "", "outside", fmt.Errorf("这是个符号链接，不提供")
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, "", "missing", err
	}
	// ★ 用启动时算好的 rootReal：这里每次再 EvalSymlinks 一遍，比的却是另一个值，
	//   目录页标题就会跟「谁是根」对不上（/tmp 和 /private/tmp 那种）。
	if !inside(s.rootReal, real) {
		return nil, "", "outside", fmt.Errorf("这个文件在共享目录之外")
	}
	return fi, real, "", nil
}

// noSymlink 从根往下逐段看，任何一段是符号链接就拒。
func noSymlink(root, full string) error {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return fmt.Errorf("这个路径不在共享目录里")
	}
	// ★ 判「跑出去了」必须带上分隔符：只 HasPrefix("..") 的话，
	//   一个真叫 `..草稿.bin` 的文件会被当成越界拒掉 —— 三个协议一起误伤，
	//   而报的那句是「这个路径不在共享目录里」，没人想得起来是文件名的锅。
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("这个路径不在共享目录里")
	}
	cur := root
	if rel == "." {
		return nil
	}
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if err != nil {
			return nil // 不存在交给后面判 404：这里不猜
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("路径里有一层是符号链接（%s），不提供 —— 否则会读到共享目录外面的文件", filepath.Base(cur))
		}
	}
	return nil
}

// inside 判断 target 是否真在 root 之下。
//
// ★ 不能只 HasPrefix：/firmware 是 /firmware-secret 的前缀，
//
//	那样写会把隔壁那个目录也当成「在根里」。补上分隔符再比。
func inside(root, target string) bool {
	if target == root {
		return true
	}
	return strings.HasPrefix(target, root+string(filepath.Separator))
}

func httpReason(why string) string {
	switch why {
	case "outside":
		return "这个路径不在共享目录里（或者中间有一层符号链接）"
	case "missing":
		return "没有这个文件"
	}
	return "读不到"
}

var listTmpl = template.Must(template.New("list").Parse(`<!doctype html><meta charset="utf-8">
<title>{{.Title}}</title>
<style>
 body{font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:24px;background:#fbfbfa;color:#222}
 a{text-decoration:none;color:#0b5cad}
 table{border-collapse:collapse;min-width:520px}
 td,th{padding:4px 14px 4px 0;text-align:left;font-weight:normal}
 th{color:#777;font-size:12px;border-bottom:1px solid #ddd}
 .s{font-variant-numeric:tabular-nums;color:#555}
 .d{color:#999;font-size:12px}
 .note{margin:0 0 18px;padding:10px 12px;background:#fff8e6;border:1px solid #e6d9a8;border-radius:6px;font-size:13px}
</style>
<p class="note">这是 <b>{{.Root}}</b> 的<b>只读</b>共享：能下载，不能上传、不能改名、不能删。
 同一网段的任何设备都能读到这里的文件 —— 用完请在 NetKit 里停掉。</p>
<h2>{{.Title}}</h2>
<table><tr><th>名字</th><th>大小</th><th>改动时间</th></tr>
{{range .Items}}<tr><td><a href="{{.Href}}">{{.Name}}</a></td>
 <td class="s">{{.Size}}</td><td class="d">{{.Mod}}</td></tr>
{{end}}</table>
<p class="d">NetKit · 只读共享 · 目录列表只到这一层</p>
`))

type listEntry struct {
	Name, Href, Size, Mod string
	Dir                   bool
}

func (s *Server) serveList(w http.ResponseWriter, r *http.Request, peer, dir string) {
	des, err := os.ReadDir(dir)
	if err != nil {
		s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Status: "denied"})
		http.Error(w, "这个目录读不出来", http.StatusForbidden)
		return
	}
	// 目录在前、名字排序：现场是在一堆文件里找一个固件名，
	// 按时间排会把要找的那个埋在中间。
	sort.Slice(des, func(i, j int) bool {
		di, dj := des[i].IsDir(), des[j].IsDir()
		if di != dj {
			return di
		}
		return des[i].Name() < des[j].Name()
	})
	var items []listEntry
	for _, de := range des {
		name := de.Name()
		href := urlEsc(name)
		size := ""
		if !de.IsDir() {
			if info, err := de.Info(); err == nil {
				size = humanBytes(info.Size())
			}
		}
		mod := ""
		if info, err := de.Info(); err == nil {
			mod = info.ModTime().Format("2006-01-02 15:04")
		}
		if de.IsDir() {
			href += "/"
			name += "/"
		}
		items = append(items, listEntry{Name: name, Href: href, Size: size, Mod: mod, Dir: de.IsDir()})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = listTmpl.Execute(w, map[string]any{
		"Title": dirTitle(s.rootReal, dir),
		"Root":  s.cfg.Root,
		"Items": items,
	})
	s.Record(Transfer{Peer: peer, Proto: "http", Path: r.URL.Path, Status: "list"})
}

func dirTitle(root, dir string) string {
	if dir == root {
		return "共享根目录"
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "子目录"
	}
	return rel
}

// urlEsc 文件名里可能有空格、中文、#、%。用 PathEscape 而不是手工替空格：
// 手写的替换早晚在某个带 + 或 % 的文件名上把链接拼错，而那正是设备拿去下载的地址。
func urlEsc(name string) string {
	return (&url.URL{Path: name}).EscapedPath()
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return strconv.FormatInt(n, 10) + " B"
}
