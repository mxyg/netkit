package tools

import (
	"encoding/csv"
	"net"
	"strconv"
	"strings"
)

// ── 各平台「谁在用端口」的读法：纯解析部分 ──
//
// ★★ 这些函数一律**只吃文本、不碰系统**。三个平台的输出格式互不相通，
//
//	而错法各不相同：字段错位不报错，只会把「没人用」说成「被占着」。
//	所以解析单独一层，用各平台**真实命令输出**当测试样本，在任何一台机器上都能测全部三个平台。

// procSocket Linux /proc/net/{tcp,udp} 的一行。inode 是唯一的归属线索：
// /proc/<pid>/fd 里的 socket:[inode] 指回进程。
type procSocket struct {
	Proto  string
	Family string // ipv4 / ipv6 —— 由地址列的长度判，不靠文件名（少一处能写错的地方）
	Local  string
	Port   int
	State  string
	Inode  string
	UID    string
}

// parseProcNetSOCK 解析 /proc/net/tcp|tcp6|udp|udp6 的正文。
//
// ★ 表头那一行必须跳过：它的 inode 列写着 "inode"，转成数字是 0，
// 于是「谁都没占」的记录会被归到 inode 0 上 —— 那种错看不出来，只会偶发。
func parseProcNetSOCK(text, proto string) []procSocket {
	var out []procSocket
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[0] == "sl" {
			continue
		}
		local, port, family, ok := decodeProcAddr(f[1])
		if !ok {
			continue
		}
		st := strings.ToLower(procState(f[3]))
		if proto == "udp" && st != "established" {
			// ★ UDP 没有「监听」这个状态位：/proc/net/udp 里一个绑好在等包的 socket
			// 写的是 07（close），被 connect 过的才写 01。照原样留给判定层，
			// 一个跑着的 UDP 服务会被说成「本机连出去占的口，别去停它」——正好反了。
			st = ""
		}
		s := procSocket{
			Proto: proto, Family: family, Local: local, Port: port, State: st,
			Inode: f[9], UID: f[7],
		}
		// TIME_WAIT / CLOSE_WAIT 这些既不是监听也不是活连接，但确实还占着本地端口，
		// 一律留着 —— 「刚停掉服务马上起不来」查的就是这几条。
		out = append(out, s)
	}
	return out
}

// decodeProcAddr 解 `0100007F:1F90`（v4）或 32 位十六进制的 v6。
//
// ★ 字节序是**小端**，不反就解出 127.0.0.1 → 127.0.0.1 之外的错数：
//
//	`00000000` 是「所有地址」，写成 0.0.0.0 才对；`0100007F` 才是 127.0.0.1。
func decodeProcAddr(s string) (string, int, string, bool) {
	i := strings.LastIndex(s, ":")
	if i < 1 {
		return "", 0, "", false
	}
	port, err := strconv.ParseInt(s[i+1:], 16, 32)
	if err != nil {
		return "", 0, "", false
	}
	hex := s[:i]
	switch len(hex) {
	case 8:
		v, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return "", 0, "", false
		}
		var b [4]byte
		for k := 0; k < 4; k++ {
			b[k] = byte(v >> (8 * k)) // 小端
		}
		ip := net.IPv4(b[0], b[1], b[2], b[3])
		if hex == "00000000" {
			return "*", int(port), "ipv4", true
		}
		return ip.String(), int(port), "ipv4", true
	case 32:
		if hex == strings.Repeat("0", 32) {
			return "*", int(port), "ipv6", true
		}
		var b [16]byte
		for k := 0; k < 4; k++ {
			v, err := strconv.ParseUint(hex[k*8:(k+1)*8], 16, 32)
			if err != nil {
				return "", 0, "", false
			}
			for j := 0; j < 4; j++ {
				b[k*4+j] = byte(v >> (8 * j))
			}
		}
		return net.IP(b[:]).String(), int(port), "ipv6", true
	}
	return "", 0, "", false
}

// procState 把内核的状态码翻成和其它工具同一套词（小写、连字符）。
func procState(hexCode string) string {
	if v, err := strconv.ParseUint(hexCode, 16, 8); err == nil {
		if s, ok := procStates[uint8(v)]; ok {
			return s
		}
	}
	return hexCode // 认不得的照原样给，别编一个「未知」把信息吃掉
}

var procStates = map[uint8]string{
	0x01: "established", 0x02: "syn-sent", 0x03: ppStateSynRecv,
	0x04: "fin-wait1", 0x05: "fin-wait2", 0x06: "time-wait",
	0x07: "close", 0x08: "close-wait", 0x09: "last-ack",
	0x0a: ppStateListen, 0x0b: "closing",
}

// procOwner 一个进程占住的 socket inode 集合。
type procOwner struct {
	Pid     int
	Process string
	User    string
	Inodes  []string
}

// socketsToPortUses 按 inode 把 socket 归到进程上。
//
// ★ 返回的 partial 是这条判定的命门：非管理员看不到别人 /proc/<pid>/fd 里的链接，
//
//	于是有一堆 socket 找不到主人。这时候**绝不能说「没人用」**，
//	要说「只读到一部分」—— 否则人会去起服务，撞上「地址已在使用」再回头骂工具。
func socketsToPortUses(socks []procSocket, owners map[string]procOwner) ([]portUse, bool) {
	var out []portUse
	partial := false
	for _, s := range socks {
		u := portUse{Proto: s.Proto, Family: s.Family, Local: s.Local, Port: s.Port, State: s.State}
		switch o, ok := owners[s.Inode]; {
		case ok:
			u.Pid, u.Process, u.User = o.Pid, o.Process, o.User
		case s.Inode == "0":
			// ★ 内核里的 TIME_WAIT / CLOSE_WAIT 根本没有 inode —— 不是「看不到主人」，
			// 是本来就没有主人（套接字还没交给任何进程）。把它算成读不全，
			// 这台机器就永远查不出 free，而 free 恰恰是「这个口能腾出来」的那个答案。
		default:
			partial = true // 问到了 socket，认不出主人
		}
		out = append(out, u)
	}
	return out, partial
}

// parseLsofFields 解析 `lsof -nP -i -FpcuLtTPn` 的机器可读输出。
//
// ★ 不用默认那份表格：COMMAND 列本身可以含空格（"Google Chrome"），
//
//	按空白切列就会串位，症状是进程名和 PID 对不上。`-F` 是一行一个字段、
//	首字符是字段名，没有歧义。
//	字段：p=PID，c=命令名，u=UID，L=登录名，f=文件描述符（开一条新记录），
//	P=协议，t=文件类型（IPv4/IPv6），n=地址，T=TCP/TPI 信息（里面有 ST=状态）。
func parseLsofFields(out string) []portUse {
	var (
		uses       []portUse
		pid        int
		cmd, login string
		cur        portUse
		open       bool
	)
	flush := func() {
		if open {
			uses = append(uses, cur)
		}
		cur, open = portUse{}, false
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		key, val := line[0], line[1:]
		switch key {
		case 'p':
			pid, _ = strconv.Atoi(val)
			cmd, login = "", ""
		case 'c':
			cmd = val
		case 'L':
			if open {
				cur.User = val
			} else {
				login = val
			}
		case 'f':
			flush()
			cur, open = portUse{Pid: pid, Process: cmd, User: login}, true
		case 'P':
			cur.Proto = strings.ToLower(val)
		case 't':
			// lsof 的文件类型列写 IPv4 / IPv6 —— 有它才能把「同一进程在 v4 和 v6 上各听一遍」
			// 分开显示；没它的话两条记录长得一模一样，看着像工具重复输出。
			cur.Family = strings.ToLower(val)
		case 'n':
			cur.Local, cur.Foreign, cur.Port = splitLsofAddr(val)
		case 'T':
			if v, ok := lsofSubField(val, "ST"); ok {
				cur.State = strings.ToLower(v)
			}
		}
	}
	flush()
	return uses
}

// splitLsofAddr 拆 `*:554`、`[fe80::1]:554->[fe80::2]:9`、`127.0.0.1:53`。
func splitLsofAddr(s string) (local, foreign string, port int) {
	local, foreign = s, ""
	if i := strings.Index(s, "->"); i >= 0 {
		local, foreign = s[:i], s[i+2:]
	}
	i := strings.LastIndex(local, ":")
	if i < 0 {
		return local, foreign, 0
	}
	p, err := strconv.Atoi(local[i+1:])
	if err != nil {
		p = 0
	}
	host := local[:i]
	if host == "[::]" || host == "0.0.0.0" || host == "*" {
		host = "*"
	}
	return host, foreign, p
}

// lsofSubField 取 `ST=LISTEN` 这类子字段，值里可能再带逗号分隔的多个子字段。
func lsofSubField(s, want string) (string, bool) {
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if ok && k == want {
			return v, true
		}
	}
	return "", false
}

// parseNetstatWindows 解析 `netstat -ano` 的正文。
//
// ★ UDP 那几行**没有状态列**，所以列数会少一个：直接按下标取 PID 会把
//
//	`*:*` 当成 PID。这里一律从行尾取 PID，状态按协议判有没有。
func parseNetstatWindows(out string) []portUse {
	var uses []portUse
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		proto := strings.ToUpper(f[0])
		if proto != "TCP" && proto != "UDP" {
			continue // 表头（英文 "Active Connections" / 中文「活动连接」）和各种说明行都从这挡住
		}
		pid, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			continue
		}
		local, _, port := splitLsofAddr(f[1])
		u := portUse{Proto: strings.ToLower(proto), Family: winFamily(f[1]), Local: local, Port: port, Pid: pid}
		if proto == "TCP" {
			u.State = winState(f[3])
			if len(f) > 4 {
				u.Foreign = f[2]
			}
		}
		uses = append(uses, u)
	}
	return uses
}

// winState 把 Windows 的状态词翻成和 Linux / 其余工具同一套码。
//
// ★★ 这一层不能省：Windows 写的是 LISTENING，Linux 的 ss/proc 写 LISTEN。
//
//	直接小写原文，「在听」就被判成「没在听」—— 顶层会说 free，人去起服务才撞口。
var winStateTable = map[string]string{
	"LISTENING": ppStateListen, "ESTABLISHED": "established",
	"SYN_SENT": "syn-sent", "SYN_RECEIVED": ppStateSynRecv,
	"FIN_WAIT_1": "fin-wait1", "FIN_WAIT_2": "fin-wait2",
	"CLOSE_WAIT": "close-wait", "CLOSING": "closing", "LAST_ACK": "last-ack",
	"TIME_WAIT": "time-wait", "CLOSED": "closed",
}

func winState(s string) string {
	if v, ok := winStateTable[strings.ToUpper(s)]; ok {
		return v
	}
	return strings.ToLower(s) // 认不得的照原样给，不编一个「未知」把信息吃掉
}

// winFamily 从原始地址列判地址族：netstat 用 `[...]` 包 v6，v4 写 0.0.0.0。
// ★ 必须在把 0.0.0.0 / [::] 收成 `*` **之前**判，收完两族就分不出来了。
func winFamily(addr string) string {
	if strings.HasPrefix(addr, "[") {
		return "ipv6"
	}
	return "ipv4"
}

// parseTasklistCSV 解析 `tasklist /fo csv /nh`，只要 PID → 进程名。
//
// ★ 不取「用户名」那一列：中文 Windows 的控制台输出是 GBK，
//
//	带中文的列会解成乱码 —— 而它恰恰是用户名列。少给一个字段，
//	比给一个错字段好。
func parseTasklistCSV(out string) map[int]string {
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		return nil
	}
	names := map[int]string{}
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(r[1]))
		if err != nil {
			continue
		}
		names[pid] = strings.TrimSpace(r[0])
	}
	return names
}

// attachNames 把 PID → 进程名合进 netstat 的结果里。
func attachNames(uses []portUse, names map[int]string) []portUse {
	for i := range uses {
		if n, ok := names[uses[i].Pid]; ok {
			uses[i].Process = n
		}
	}
	return uses
}
