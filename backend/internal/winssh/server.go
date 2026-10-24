package winssh

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Port = 8770

// Peer 网线或同一网段上 arp 看见的一台机器，以及 22 端口是否已开。
type Peer struct {
	IP  string `json:"ip"`
	SSH bool   `json:"ssh"`
}

// Snapshot 给界面看的当前状态。
type Snapshot struct {
	Running bool     `json:"running"`
	Port    int      `json:"port,omitempty"`
	URLs    []string `json:"urls,omitempty"`
	Lines   []string `json:"lines,omitempty"`
	Peers   []Peer   `json:"peers,omitempty"`
	User    string   `json:"user,omitempty"`
	Done    bool     `json:"done"`
}

// Hub 在本机若干地址上提供「给 Windows 装 OpenSSH」的页面。全场只开一个。
type Hub struct {
	mu    sync.Mutex
	lns   []net.Listener
	urls  []string
	lines []string
	srv   *http.Server
}

var Default = &Hub{}

// Start 在每块非回环 IPv4 上听 Port。已经在听则直接返回当前地址。
func (h *Hub) Start() (Snapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.lns) > 0 {
		return h.snapshotLocked(), nil
	}
	addrs, err := ipv4Addrs()
	if err != nil {
		return Snapshot{}, err
	}
	if len(addrs) == 0 {
		return Snapshot{}, fmt.Errorf("这台机器没有可用的 IPv4 地址")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.serve)
	h.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	var lns []net.Listener
	var urls []string
	for _, ip := range addrs {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(Port)))
		if err != nil {
			continue
		}
		lns = append(lns, ln)
		urls = append(urls, "http://"+ln.Addr().String()+"/")
		go h.srv.Serve(ln)
	}
	if len(lns) == 0 {
		return Snapshot{}, fmt.Errorf("端口 %d 绑不上（可能已经被占用）", Port)
	}
	h.lns = lns
	h.urls = urls
	h.lines = nil
	return h.snapshotLocked(), nil
}

// Stop 关掉页面。
func (h *Hub) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ln := range h.lns {
		_ = ln.Close()
	}
	h.lns = nil
	h.urls = nil
	if h.srv != nil {
		_ = h.srv.Close()
		h.srv = nil
	}
}

// Status 当前页面、日志，以及 arp 里看见的机器。
func (h *Hub) Status() Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshotLocked()
}

// URLs 批准框要用的地址列表。没开时按「将会绑定的地址」算。
func (h *Hub) URLs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.urls) > 0 {
		return append([]string(nil), h.urls...)
	}
	addrs, _ := ipv4Addrs()
	var urls []string
	for _, ip := range addrs {
		urls = append(urls, "http://"+net.JoinHostPort(ip, strconv.Itoa(Port))+"/")
	}
	return urls
}

func (h *Hub) snapshotLocked() Snapshot {
	s := Snapshot{
		Running: len(h.lns) > 0,
		URLs:    append([]string(nil), h.urls...),
		Lines:   append([]string(nil), h.lines...),
		Peers:   peers(),
	}
	if s.Running {
		s.Port = Port
	}
	for _, line := range s.Lines {
		if strings.HasPrefix(line, "admin ") {
			s.User = strings.TrimPrefix(line, "admin ")
		}
		if line == "DONE" {
			s.Done = true
		}
	}
	return s
}

func (h *Hub) addLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if len(line) > 500 {
		line = line[:500]
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, line)
	if len(h.lines) > 80 {
		h.lines = h.lines[len(h.lines)-80:]
	}
}

func (h *Hub) serve(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	switch {
	case r.URL.Path == "/log" && r.Method == http.MethodPost:
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		h.addLine(string(b))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	case r.URL.Path == "/go.ps1":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, scriptPS1(host))
	case strings.HasSuffix(r.URL.Path, ".cmd") && strings.HasPrefix(r.URL.Path, "/nk-ssh-"):
		name := strings.TrimPrefix(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		_, _ = io.WriteString(w, scriptCMD(host))
	default:
		name := "nk-ssh-" + time.Now().Format("20060102-150405") + ".cmd"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>打开 SSH</title>
<body style="font-family:sans-serif;max-width:36rem;margin:2rem auto;line-height:1.5">
<h1>打开这台 Windows 的 SSH</h1>
<p>下载后双击 <b>%s</b>。文件名里的数字是下载时间，重新打开本页再下一次，名字会变，用来确认拿到的是新的。</p>
<p>若浏览器提示已阻止，点保留。若问是否允许更改，点是。窗口出现 log sent 即可。</p>
<p><a href="%s">下载 %s</a></p>
</body>`, name, name, name)
	}
}

func ipv4Addrs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLoopback() {
				continue
			}
			out = append(out, ipnet.IP.String())
		}
	}
	return out, nil
}

func peers() []Peer {
	text := arpText()
	var out []Peer
	for _, ip := range ParseNeighbors(text) {
		if !wantPeer(ip) {
			continue
		}
		out = append(out, Peer{IP: ip, SSH: portOpen(ip, 22)})
		if len(out) >= 12 {
			break
		}
	}
	return out
}

func wantPeer(ip string) bool {
	return strings.HasPrefix(ip, "169.254.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.")
}

func portOpen(ip string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func arpText() string {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a")
	case "linux":
		cmd = exec.Command("ip", "neigh")
	default:
		cmd = exec.Command("arp", "-an")
	}
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(b)
}
