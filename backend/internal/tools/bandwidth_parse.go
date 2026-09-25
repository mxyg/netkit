package tools

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ── 各平台「网卡过了多少字节 / 谁在吃」的读法：纯解析部分 ──
//
// ★★ 和 portproc_parse.go 同一套理由：这些函数一律**只吃文本、不碰系统**。
//
//	三个平台的格式互不相通，而错法一样 —— 列错位不报错，只会把「没人在吃」
//	说成「这个进程在吃」。所以解析单独一层，拿各平台真实命令输出当测试样本，
//	在任何一台机器上都能把三个平台的解析都跑一遍。

// parseNetstatIB 解析 macOS/BSD 的 `netstat -ibn`。
//
// ★ 计数一律**从行尾数**，不从行首数：Address 那一列时有时无
//
//	（lo0 的 <Link#1> 行就没有），从左边按列号取会把 Ipkts 当成 Ibytes。
//	行尾七列固定是 Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll。
//
// ★ 同一块网卡会按地址重复出现好几行，每行都带着同一份计数 —— 必须按名字去重，
//
//	否则一块有 v4、v6、链路本地三个地址的网卡会被算成三份流量。
func parseNetstatIB(text string) []linkCount {
	seen := map[string]bool{}
	var out []linkCount
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		name := strings.TrimSuffix(f[0], "*") // 名字后面的 * 是状态标记，不是网卡名的一部分
		if name == "" || name == "Name" || seen[name] {
			continue
		}
		n := len(f)
		rx, okRx := parseUint(f[n-5]) // Ibytes
		tx, okTx := parseUint(f[n-2]) // Obytes
		if !okRx || !okTx {
			continue
		}
		seen[name] = true
		out = append(out, linkCount{Name: name, Rx: rx, Tx: tx})
	}
	return out
}

// parseProcNetDev 解析 Linux 的 /proc/net/dev。
//
// 表头两行是画出来的竖线（Inter-| ... |  Transmit 与 face |bytes packets...），
// 字段名转不成数字，天然被 parseUint 挡住；这里还是显式认一下冒号，
// 因为**接口名里可以带冒号以外的怪名字**，只信列数会漏。
func parseProcNetDev(text string) []linkCount {
	var out []linkCount
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		f := strings.Fields(line[i+1:])
		if name == "" || len(f) < 16 {
			continue
		}
		rx, okRx := parseUint(f[0]) // Receive 的 bytes
		tx, okTx := parseUint(f[8]) // Transmit 的 bytes
		if !okRx || !okTx {
			continue
		}
		out = append(out, linkCount{Name: name, Rx: rx, Tx: tx})
	}
	return out
}

// parseNettopCSV 解析 macOS 的 `nettop -P -x -d -L n -s n`。
//
// ★ 只取**最后一块**：-d（delta）模式下第一块打的是累计值（这个进程从开机到现在
//
//	收发了多少），后面每一块才是这一秒的增量。取错块的症状是「微信吃了 60 GB」，
//	而它其实只是开机以来一直在收。
//
// ★ 列位置从**这一块自己的表头**里找：bytes_in 在第几列随 macOS 版本变，
//
//	而 nettop 不会因为你没读表头就跟你商量。
func parseNettopCSV(text string) []procBytes {
	blocks := splitNettopBlocks(text)
	if len(blocks) == 0 {
		return nil
	}
	return nettopBlockRows(blocks[len(blocks)-1])
}

// nettopBlocksSeen 这一份输出里一共几块 —— 判定层要拿它说「窗口没跑满」。
func nettopBlocksSeen(text string) int { return len(splitNettopBlocks(text)) }

func splitNettopBlocks(text string) [][]string {
	var blocks [][]string
	var cur []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "time,") || strings.HasPrefix(line, "time") && strings.Contains(line, ",bytes_in,") {
			if len(cur) > 1 {
				blocks = append(blocks, cur)
			}
			cur = []string{line}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 1 {
		blocks = append(blocks, cur)
	}
	return blocks
}

func nettopBlockRows(block []string) []procBytes {
	rd := csv.NewReader(strings.NewReader(strings.Join(block, "\n")))
	rd.FieldsPerRecord = -1
	recs, err := rd.ReadAll()
	if err != nil || len(recs) < 2 {
		return nil
	}
	rx, tx := -1, -1
	for i, h := range recs[0] {
		switch strings.TrimSpace(h) {
		case "bytes_in":
			rx = i
		case "bytes_out":
			tx = i
		}
	}
	if rx < 0 || tx < 0 {
		return nil // 表头里没有这两列：宁可不报，也不按位置猜一个数字当成字节
	}
	out := make([]procBytes, 0, len(recs)-1)
	for _, r := range recs[1:] {
		if len(r) <= rx || len(r) <= tx {
			continue
		}
		// 第二列是进程名.PID —— 表头里它是空的（nettop 就没给这一列起名）。
		in, ok1 := parseUint(strings.TrimSpace(r[rx]))
		ex, ok2 := parseUint(strings.TrimSpace(r[tx]))
		if !ok1 || !ok2 {
			continue
		}
		name, pid := splitNettopName(r[1])
		out = append(out, procBytes{Process: name, Pid: pid, Rx: in, Tx: ex})
	}
	return out
}

// splitNettopName 把 `mDNSResponder.219` 拆成名字和 PID。
//
// ★ 按**最后一个**点拆：进程名自己可以带点（`com.apple.WebKit.Networking.4321`），
// 按第一个点拆会把名字砍成 "com"。尾巴不是数字就当它没有 PID。
func splitNettopName(field string) (string, int) {
	field = strings.TrimSpace(field)
	i := strings.LastIndex(field, ".")
	if i <= 0 || i == len(field)-1 {
		return field, 0
	}
	pid, err := strconv.Atoi(field[i+1:])
	if err != nil || pid <= 0 {
		return field, 0
	}
	return field[:i], pid
}

// ssSocket 一条 `ss -tinp` 记录里能认领的部分。
type ssSocket struct {
	Key     string // proto + 本地 + 对端：两次读数之间靠它把同一条连接对上
	Process string
	Pid     int
	Sent    uint64 // bytes_sent：这个套接字发出去的数据字节
	Recv    uint64 // bytes_received：应用收到的数据字节
}

// parseSSInetDiag 解析 Linux 的 `ss -tinp` / `ss -unap` 输出。
//
// ★ 一条连接是**两行**：第一行是五元组和 users:(...)，缩进的续行才写着
//
//	bytes_sent / bytes_received。按行独立解析的结果是「谁在用」和「用了多少」
//	永远配不到一起 —— 所以这里带状态地走，续行归给上一条记录。
//
// ★ 只认得出 users:(...) 的记录才算数：非管理员跑 ss 时，别人进程的套接字没有
//
//	这一段。调用方拿「认出的条数 / 总条数」去报 partial。
func parseSSInetDiag(text, proto string) (socks []ssSocket, total int) {
	var cur *ssSocket
	flush := func() {
		if cur != nil {
			socks = append(socks, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if cur == nil {
				continue
			}
			for _, tok := range strings.Fields(line) {
				k, v, ok := strings.Cut(tok, ":")
				if !ok {
					continue
				}
				n, ok := parseUint(v)
				if !ok {
					continue
				}
				switch k {
				case "bytes_sent":
					cur.Sent = n
				case "bytes_received":
					cur.Recv = n
				}
			}
			continue
		}
		flush()
		f := strings.Fields(line)
		if len(f) < 5 || f[0] == "State" || f[0] == "Netid" {
			continue
		}
		total++
		// ★ 本地与对端固定在第 4、5 列。State / Recv-Q / Send-Q 这三列 ss 一定给
		//	（-H 只去掉表头，不改变列），而那些会浮动的 tcp 信息（bytes_sent、rtt…）
		//	全在缩进的续行上。按「从行尾往前找两个像地址的列」反而错：未连接的
		//	UDP 对端是 `*:*`，没有端口数字，认出来就把整条记录丢了。
		local, peer := f[3], f[4]
		s := ssSocket{Key: proto + "|" + local + "|" + peer}
		if name, pid, ok := ssUser(line); ok {
			s.Process, s.Pid = name, pid
			cur = &s
		}
		continue
	}
	flush()
	return socks, total
}

// ssUser 从 `users:(("curl",pid=12,fd=5))` 里取出进程名与 PID。
//
// ★ 一个套接字可能挂在多个进程上（fork 出来的子进程共享 fd）。取第一个并让
// 后面的继续留在同一行里 —— 这里不试图把字节分给多个进程：分给谁都是猜。
func ssUser(line string) (string, int, bool) {
	i := strings.Index(line, `users:(`)
	if i < 0 {
		return "", 0, false
	}
	rest := line[i+len(`users:(`):]
	name := ""
	if q := strings.Index(rest, `"`); q >= 0 {
		e := strings.Index(rest[q+1:], `"`)
		if e > 0 {
			name = rest[q+1 : q+1+e]
		}
	}
	if name == "" {
		return "", 0, false
	}
	k := strings.Index(rest, "pid=")
	if k < 0 {
		return name, 0, true
	}
	digits := rest[k+len("pid="):]
	j := strings.IndexFunc(digits, func(r rune) bool {
		return r < '0' || r > '9'
	})
	if j > 0 {
		digits = digits[:j]
	}
	pid, err := strconv.Atoi(digits)
	if err != nil {
		return name, 0, true
	}
	return name, pid, true
}

// ssDelta 两次 ss 读数的差，按进程加总。
//
// ★ 后一次比前一次小（连接断了又新建、同四元组复用）时按 0 算：
// 少算一个进程的字节只是不够精确，多算会变成「冤枉谁在吃」。
func ssDelta(first, second []ssSocket) []procBytes {
	type agg struct{ rx, tx uint64 }
	before := map[string]ssSocket{}
	for _, s := range first {
		b := before[s.Key]
		b.Sent, b.Recv = b.Sent+s.Sent, b.Recv+s.Recv
		b.Process, b.Pid = s.Process, s.Pid
		before[s.Key] = b
	}
	byProc := map[string]*agg{}
	keyOf := func(p string, pid int) string { return p + "|" + strconv.Itoa(pid) }
	for _, s := range second {
		b := before[s.Key]
		rx, tx := s.Recv, s.Sent
		if b.Recv > rx {
			rx = 0
		} else {
			rx -= b.Recv
		}
		if b.Sent > tx {
			tx = 0
		} else {
			tx -= b.Sent
		}
		k := keyOf(s.Process, s.Pid)
		a := byProc[k]
		if a == nil {
			a = &agg{}
			byProc[k] = a
		}
		a.rx += rx
		a.tx += tx
	}
	out := make([]procBytes, 0, len(byProc))
	for k, a := range byProc {
		name, pidStr, _ := strings.Cut(k, "|")
		pid, _ := strconv.Atoi(pidStr)
		out = append(out, procBytes{Process: name, Pid: pid, Rx: a.rx, Tx: a.tx})
	}
	return out
}

// parseNetAdapterStats 解析 Windows PowerShell `ConvertTo-Json -Compress` 的那份数组。
//
// ★ 单独拆出来（而且放在不带构建标记的这一层）：PowerShell 一条一个对象时不给方括号
//
//	（`{"Name":...}`），多条才给（`[{...},{...}]`）—— 只按数组解的写法在
//	「本机只剩一块网卡」那天会失效，而那一天只会在现场出现，测试机上永远是多条。
func parseNetAdapterStats(text string) ([]linkCount, error) {
	body := strings.TrimSpace(text)
	if body == "" {
		return nil, fmt.Errorf("输出是空的（多半是这台机器上 PowerShell 被禁了）")
	}
	if !strings.HasPrefix(body, "[") {
		body = "[" + body + "]"
	}
	var rows []struct {
		Name          string `json:"Name"`
		ReceivedBytes uint64 `json:"ReceivedBytes"`
		SentBytes     uint64 `json:"SentBytes"`
	}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, fmt.Errorf("解不开网卡统计的 JSON：%s", err)
	}
	var out []linkCount
	for _, r := range rows {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			continue
		}
		out = append(out, linkCount{Name: name, Rx: r.ReceivedBytes, Tx: r.SentBytes})
	}
	return out, nil
}

// parseUint 只认纯十进制非负数，认不出来就返回 false（调用方跳过这一行）。
//
// ★ 不用 strconv.ParseUint 直接判错误：`-` 也要能认出来是「这一列不是数字」。
func parseUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
