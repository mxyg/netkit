package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DialTimeout 建连超时。局域网里 10 秒还连不上，就是不通或没开 SSH。
const DialTimeout = 10 * time.Second

// Output 一次远程执行的输出。
type Output struct {
	Stdout   string  `json:"stdout"`
	Stderr   string  `json:"stderr"`
	ExitCode int     `json:"exitCode"`
	Seconds  float64 `json:"seconds"`
}

// Dial 连一台设备。
//
// ★ 主机密钥 TOFU：首连记下，之后**变了就拒绝**并说清后果。
//
//	悄悄接受变化的主机密钥等于给中间人开门；而现场换机器/重装系统
//	确实会变，所以报错里要写明"确认是重装/换机才继续"的操作路径。
func (m *Manager) Dial(ctx context.Context, d *Device) (*ssh.Client, error) {
	port := d.Port
	if port == 0 {
		port = 22
	}
	hostKeyOK, err := m.hostKeyCallback(d)
	if err != nil {
		return nil, err
	}
	var auths []ssh.AuthMethod
	if d.KeyPath != "" {
		b, err := os.ReadFile(d.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("读不了私钥 %s：%w", d.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("私钥 %s 解不开（带口令的私钥暂不支持，用无口令私钥或口令登录）：%w", d.KeyPath, err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if d.Password != "" {
		auths = append(auths,
			ssh.Password(d.Password),
			// 不少设备（交换机、老 NAS）只开 keyboard-interactive
			ssh.KeyboardInteractive(func(name, instr string, q []string, echo []bool) ([]string, error) {
				a := make([]string, len(q))
				for i := range a {
					a[i] = d.Password
				}
				return a, nil
			}),
		)
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("设备 %s 没有任何凭据（登记时给 password 或 keyPath）", d.ID)
	}

	cfg := &ssh.ClientConfig{
		User:            d.User,
		Auth:            auths,
		HostKeyCallback: hostKeyOK,
		Timeout:         DialTimeout,
	}
	addr := net.JoinHostPort(d.Host, fmt.Sprint(port))
	// ★ d.Host 可能是带 zone 的 fe80:: —— Go 的 Dial 认 fe80::1%en0 这种标准写法。
	//   用 net.Dialer 而不是 ssh.Dial，为了 ctx 取消真的能中断建连。
	conn, err := (&net.Dialer{Timeout: DialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, humanDialError(d, addr, err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, humanDialError(d, addr, err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

// humanDialError 把连接失败翻成人话，尤其是认证失败。
//
// ★ docs/设计.md「设备信息自动获取」：连接失败要给人话 ——
//
//	「22 通了但认证被拒」和「根本连不上」是两回事，处置完全不同。
func humanDialError(d *Device, addr string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods remain"):
		hint := fmt.Sprintf("能连上 %s 的 22 端口，但认证被拒 —— 多半是账号名或凭据不对。"+
			"当前用的是 %s。常见账号：Administrator(admin)、root；"+
			"Windows 上不确定账号名时，在那台机器上跑一句 whoami", addr, d.User)
		if d.Identity != nil && d.Identity.Hostname != "" &&
			!strings.EqualFold(d.Identity.Hostname, d.User) {
			hint += fmt.Sprintf("。上次连它时回报的主机名是 %s（Windows 账号常是 主机名\\用户名）", d.Identity.Hostname)
		}
		return fmt.Errorf("%s", hint)
	case strings.Contains(msg, "connection refused"):
		return fmt.Errorf("%s 拒绝了连接 —— 那台机器上多半没开 SSH 服务（Windows 要装 OpenSSH Server）", addr)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "no route to host"):
		return fmt.Errorf("%s 连不通 —— 先 ping 一下确认在不在线、网线/防火墙有没有拦 22 端口", addr)
	}
	return err
}

// hostKeyCallback 造 TOFU 回调。
func (m *Manager) hostKeyCallback(d *Device) (ssh.HostKeyCallback, error) {
	m.mu.Lock()
	known := d.HostKey
	m.mu.Unlock()
	return func(addr string, _ net.Addr, key ssh.PublicKey) error {
		got := key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
		if known == "" {
			d.HostKey = got // 首连：记下，连接成功后由调用方 UpdateDevice 落盘
			return nil
		}
		if known != got {
			return fmt.Errorf("★ %s 的主机密钥和首次连接时不一样了 —— 要么那台机器重装/换机了，"+
				"要么中间有人冒充它。确认是自己人重装了，再用 remote.device.forget-hostkey 清掉旧记录重连；"+
				"不确定就别连", addr)
		}
		return nil
	}, nil
}

// Exec 在设备上跑一条命令，收全部输出。
//
// ★★ Windows 中文编码（docs/设计.md「远程控制三件套」实测坑）：
//
//	SSH 到中文 Windows 上，回来的中文全是乱码（DESKTOP-SOSO9N7 上实测）。
//	**现场报错信息乱码 = 等于没有报错信息**，所以每条命令前都垫 chcp 65001。
func Exec(ctx context.Context, c *ssh.Client, d *Device, cmd string, timeout time.Duration) (*Output, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	full := cmd
	if d.OS == "windows" {
		full = winUTF8Preamble + " & " + cmd
	}

	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	start := time.Now()
	errCh := make(chan error, 1)
	go func() { errCh <- sess.Run(full) }()
	select {
	case err := <-errCh:
		out := &Output{
			Stdout: stdout.String(), Stderr: stderr.String(),
			ExitCode: 0, Seconds: time.Since(start).Seconds(),
		}
		var ee *ssh.ExitError
		if err != nil && !asExit(err, &ee) {
			return out, err
		}
		if ee != nil {
			out.ExitCode = ee.ExitStatus()
		}
		return out, nil
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return nil, fmt.Errorf("命令超过 %s 没跑完，已中止", timeout)
	}
}

// winUTF8Preamble 每条 Windows 命令前垫的编码协商。
const winUTF8Preamble = `chcp 65001 >nul`

// SSHExecer 最小执行接口。测试里好替换，不用起真 SSH 服务器也能测逻辑。
type SSHExecer interface {
	Exec(ctx context.Context, d *Device, cmd string, timeout time.Duration) (*Output, error)
}

// Execer 把 *ssh.Client 包成 SSHExecer。
func Execer(c *ssh.Client) SSHExecer { return clientExecer{c} }

type clientExecer struct{ c *ssh.Client }

func (e clientExecer) Exec(ctx context.Context, d *Device, cmd string, t time.Duration) (*Output, error) {
	return Exec(ctx, e.c, d, cmd, t)
}

func asExit(err error, target **ssh.ExitError) bool {
	if e, ok := err.(*ssh.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// DetectOS 探目标系统。uname 在 Windows cmd 上不存在 —— 报错就是 Windows。
func DetectOS(ctx context.Context, c *ssh.Client) string {
	sess, err := c.NewSession()
	if err != nil {
		return "unknown"
	}
	defer sess.Close()
	out, err := sess.CombinedOutput("uname -s")
	if err != nil {
		return "windows"
	}
	switch s := strings.ToLower(strings.TrimSpace(string(out))); {
	case strings.Contains(s, "linux"):
		return "linux"
	case strings.Contains(s, "darwin"):
		return "darwin"
	default:
		return s
	}
}

// CollectIdentity 连上之后自动把身份问清楚（docs/设计.md「设备信息自动获取」）。
//
// 一次 exec 拿全：主机名、账号、系统版本、网卡地址、时区、监听端口 ——
// 现场那次「不知道账号名」的事不该再让人来回传话。
func CollectIdentity(ctx context.Context, c *ssh.Client, os string) (*Identity, error) {
	// ★ 分隔符里不能有 shell 元字符：早先用 "---8<---"，那个 "<" 被 /bin/sh
	//   当成重定向，每段 echo 都报 "No such file or directory"，身份字段全被污染。
	const sep = "---netkit-snip---"
	var cmd string
	if os == "windows" {
		cmd = "hostname & echo " + sep + " & ver & echo " + sep + " & whoami & echo " + sep +
			" & ipconfig & echo " + sep + " & tzutil /g & echo " + sep + " & netstat -an"
	} else {
		cmd = `hostname; echo ` + sep + `; uname -sr; echo ` + sep +
			`; (grep PRETTY_NAME /etc/os-release 2>/dev/null || sw_vers -productVersion 2>/dev/null); echo ` + sep +
			`; whoami; echo ` + sep + `; (ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null); echo ` + sep +
			`; date +%Z; echo ` + sep +
			// ★ macOS：没有 ss，而它的 netstat -ltn **不报错**（退出码 0）
			//   但输出里根本没有 LISTEN 行 —— 会把 || 链堵死。所以第二级直接 netstat -an，
			//   Linux/macOS 的「本地地址」都在第 3 列，extractListening 认得。
			`; (ss -ltn 2>/dev/null || netstat -an 2>/dev/null)`
	}
	out, err := Exec(ctx, c, &Device{OS: os}, cmd, 30*time.Second)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(out.Stdout, sep)
	trim := func(i int) string {
		if i < len(parts) {
			return strings.TrimSpace(parts[i])
		}
		return ""
	}
	id := &Identity{At: time.Now().Format(time.RFC3339), OS: os}
	if os == "windows" {
		id.Hostname, id.OSDetail, id.User = trim(0), trim(1), trim(2)
		id.Addrs = extractAddrs(trim(3))
		id.Timezone = trim(4)
		id.Listening = extractListening(trim(5), true)
	} else {
		id.Hostname, id.OSDetail, id.User = trim(0), trim(1)+" "+trim(2), trim(3)
		id.Addrs = extractAddrs(trim(4))
		id.Timezone = trim(5)
		id.Listening = extractListening(trim(6), false)
	}
	return id, nil
}

// ★ IPv6 的 %zone 要整个收进来（fe80::1%en0）：zone 里有 g、n 这类非十六进制字母，
//
//	早先的字符集到 % 后第一个字母就停，捞回来一堆 "fe80::1%" 半截地址。
var reAddr = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F:]{2,}::?[0-9a-fA-F:.]+(?:%[0-9a-zA-Z._-]+)?`)

// extractAddrs 从 ipconfig / ip addr 输出里捞地址。宁可多捞（去重后人能看），
// 不许编 —— 这里每一个地址都会被人拿去当连接目标。
func extractAddrs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		lower := strings.ToLower(ln)
		if strings.Contains(lower, "ipv4") || strings.Contains(lower, "inet ") ||
			strings.Contains(lower, "ipv6") || strings.Contains(lower, "inet6") {
			for _, m := range reAddr.FindAllString(ln, -1) {
				m = strings.TrimRight(m, ".")
				if !seen[m] && !strings.HasPrefix(m, "127.") && m != "::1" {
					seen[m] = true
					out = append(out, m)
				}
			}
		}
	}
	return out
}

// extractListening 从 netstat / ss 输出里捞 LISTEN 端口。
func extractListening(s string, windows bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if !strings.Contains(ln, "LISTEN") {
			continue
		}
		f := strings.Fields(ln)
		// windows netstat: Proto Local Foreign State；unix ss: State Recv-Q Send-Q Local Peer
		idx := 1
		if !windows {
			idx = 3
		}
		if idx < len(f) {
			addr := f[idx]
			// Linux/Windows 端口用冒号分；★ macOS 的 netstat 用点分（127.0.0.1.22 / *.22）
			cut := strings.LastIndex(addr, ":")
			if cut < 0 {
				cut = strings.LastIndex(addr, ".")
			}
			port := addr[cut+1:]
			// ★ 全数字才收：这里的端口会被人当成「那台机器开着什么服务」的依据，
			//   宁可少一个，不能把半个地址当端口报出去
			if port == "" || strings.Trim(port, "0123456789") != "" || seen[port] {
				continue
			}
			seen[port] = true
			out = append(out, port)
		}
	}
	return out
}
