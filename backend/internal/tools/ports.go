package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.ports.scan ──
//
// ★ 单次探测交给 net.tcp.probe，这一栏管的是「一口气看一片」。
// 两者的区别不只在数量：扫完一片之后，「这些端口全都关着」和「这些端口一个都没回话」
// 是完全不同的两件事 —— 前者说明主机活着、只是没服务，后者连机器在不在都不知道。
// 顶层判定就干这一件事。

const (
	scanSomeOpen   = "ports-open"        // 至少一个端口连上了
	scanAllClosed  = "ports-closed"      // 没有一个开，但有端口明确回了 RST → 主机在
	scanNoResponse = "ports-no-response" // 没有一个开，也一个都没回话 → 分不清机器不在还是全被丢
	scanNoRoute    = "ports-no-route"    // 连路由都没有，包压根出不去
)

// 单端口状态。open / closed / filtered 直接沿用 net.tcp.probe 那三个码，
// 界面和体检项因此只有一套词。
const (
	scanUnroutable = "no-route" // 没有到目标的路 / 网卡没起来
	scanError      = "error"    // 其它失败原因，detail 里留着原文
)

// 默认端口集：现场最常要问的那一批，其中摄像头/录像机相关的（554/80/8080/
// 37777 大华 SDK / 8000、8200 海康 SDK / 2000 ONVIF 常用 / 5060 SIP / 1883 MQTT）
// 排在前面，让「这台设备开着什么」这个问题一次问完。
var defaultScanPorts = []int{
	21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445,
	514, 548, 554, 631, 873, 993, 995, 1433, 1521, 1720, 1883, 1900, 2000, 2049,
	2181, 3000, 3128, 3306, 3389, 5060, 5432, 5544, 5900, 6379, 8000, 8080, 8200,
	8443, 8888, 9000, 9200, 11211, 27017, 37777, 49152,
}

// 一次最多扫多少个端口。★ 这条不是性能考虑，是**别让人把这一栏当扫描器使**：
// 一次几万个连接，既会把现场的网络设备打到限速，也很容易被摄像头的防爆破拉黑来源。
const maxScanPorts = 2048

// 结果里最多带多少条逐端口明细（再多就只给汇总和 openPorts）。
const maxPortDetailRows = 200

var portsScanTool = ots.Tool{
	Name:  "net.ports.scan",
	Class: ots.ClassRead,
	Summary: "对**一台**主机批量做 TCP 连接探测，列出哪些端口开着。端口可以写单个、逗号分隔、" +
		"或区间（如 22,80,443,8000-8010），留空扫一批现场常用的端口（含 RTSP/ONVIF/各厂商 SDK 端口）。" +
		"★ 顶层判定看的是整体形状：ports-open（有开着的）、ports-closed（全关着但有端口回了拒绝，" +
		"所以主机是活的）、ports-no-response（一个都没回话，连机器在不在都不知道）、ports-no-route（连路都没有）。" +
		"UDP 端口一个一个用 net.udp.probe 问，批量扫 UDP 判不出东西来（没连接、没回执）。" +
		"注意：一次连接太多端口，有些摄像机会把它当成爆破，把来源 IP 临时锁掉。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string",
	      "description": "目标地址，只收 IP（可带端口，但端口以 ports 为准）。IPv6 带不带方括号都认，链路本地地址必须带 zone。"},
	    "ports": {"type": "string",
	      "description": "要扫哪些端口：\"22,80\"、\"70-80\"、混着写 \"22,8000-8010\" 都行。留空用默认常用端口集。"},
	    "timeoutMs": {"type": "integer", "minimum": 50, "maximum": 5000,
	      "description": "单个端口等多久，默认 500。扫一大片时这个值乘上去就是总耗时，别填太大。"},
	    "maxConcurrency": {"type": "integer", "minimum": 1, "maximum": 128,
	      "description": "同时最多发多少个连接，默认 32。调小是对被扫设备客气一点。"}
	  }
	}`),
	Invoke: doPortsScan,
}

type scanArgs struct {
	Addr           string `json:"addr"`
	Ports          string `json:"ports,omitempty"`
	TimeoutMS      int    `json:"timeoutMs,omitempty"`
	MaxConcurrency int    `json:"maxConcurrency,omitempty"`
}

// portResult 是单个端口的观测结果。
type portResult struct {
	Port      int    `json:"port"`
	Status    string `json:"status"`
	ElapsedMS int64  `json:"elapsedMs,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func doPortsScan(ctx context.Context, raw json.RawMessage) (any, error) {
	var a scanArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	addr, _, err := netaddr.SplitHostPort(a.Addr)
	if err != nil {
		if host, ok := addrLooksLikeName(a.Addr); ok {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%q 不是 IP —— 这里只收 IP，域名先用 net.dns.query 查出地址再来扫", host)
		}
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	ports, err := parsePortList(a.Ports)
	if err != nil {
		return nil, err
	}
	timeout := 500 * time.Millisecond
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	concurrency := a.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 32
	}

	results := scanPorts(ctx, addr, ports, timeout, concurrency, runtime.GOOS)

	var open, closed, filtered, noRoute, other int
	for _, r := range results {
		switch r.Status {
		case verdictOpen:
			open++
		case verdictClosed:
			closed++
		case verdictFiltered:
			filtered++
		case scanUnroutable:
			noRoute++
		default:
			other++
		}
	}
	values := map[string]any{
		"target":   addr.String(),
		"family":   udpFamily(addr),
		"scanned":  len(results),
		"open":     open,
		"closed":   closed,
		"filtered": filtered,
		"noRoute":  noRoute,
	}
	openList := make([]int, 0, open)
	for _, r := range results {
		if r.Status == verdictOpen {
			openList = append(openList, r.Port)
		}
	}
	values["openPorts"] = openList
	// ★ 逐端口明细只在端口不算多的时候给。结果是要发给 AI 的（也可能进诊断包）：
	//   两千条 closed 记录里没有一条是信息，但足以把上下文挤满，把真开着的几个端口埋掉。
	if len(results) <= maxPortDetailRows {
		values["ports"] = results
	} else {
		values["portsOmitted"] = true
	}
	// ★ 扫得多就要提示：这不是客套，是现场真会踩的坑 —— 不少摄像头和录像机
	//   把短时间内的批量连接当成爆破，直接把这个来源 IP 锁几分钟。
	if len(results) > 64 {
		values["warning"] = "many-connections"
	}

	code := scanCodeFor(len(results), open, closed, filtered, noRoute)
	switch code {
	case scanSomeOpen:
		return ots.Verdict{Code: code, Values: values,
			Note: fmt.Sprintf("%s 开着 %d 个端口：%s", addr.String(), open, joinPorts(openList))}, nil
	case scanAllClosed:
		return ots.Verdict{Code: code, Values: values,
			Note: fmt.Sprintf("%s 上没有端口开着，但有 %d 个端口明确回了拒绝 —— 主机是活的，"+
				"只是这些端口没服务（另有 %d 个端口没回话，那几个是丢了还是被单独拦了，单个端口再问）",
				addr.String(), closed, filtered)}, nil
	case scanNoRoute:
		return ots.Verdict{Code: code, Values: values,
			Note: "到 " + addr.String() + " 没有路 —— 包根本没出去，先确认本机网卡和路由（net.interfaces / net.dualstack.check）"}, nil
	default:
		return ots.Verdict{Code: code, Values: values,
			Note: fmt.Sprintf("%s 上没有任何端口回话（扫了 %d 个，全被静默丢掉）—— "+
				"分不清是机器不在还是防火墙整段丢，先用 net.ping 看主机在不在",
				addr.String(), len(results))}, nil
	}
}

// scanCodeFor 把一片端口的观测汇总成一个顶层判定。**这一层才是扫描和单点探测的区别**：
//
//	「全关着」和「全都没回话」在结果上都是零个开放端口，但下一步完全相反 ——
//	前者说明主机活着、可以去核对服务清单，后者连机器在不在都不知道。
//	所以只要有任意一个端口回了拒绝，就不许报成「没回话」。
func scanCodeFor(total, open, closed, filtered, noRoute int) string {
	other := total - open - closed - filtered - noRoute
	switch {
	case open > 0:
		return scanSomeOpen
	case closed > 0:
		return scanAllClosed
	case noRoute > 0 && noRoute+other == total:
		return scanNoRoute
	default:
		return scanNoResponse
	}
}

// scanPorts 用固定大小的并发池扫一遍。★ 并发池的意义不是快，是**有界**：
// 不控并发时扫两千个端口就是瞬间造两千个套接字，本机端口和文件描述符都会先耗尽。
func scanPorts(ctx context.Context, addr netaddr.Addr, ports []int, timeout time.Duration,
	concurrency int, goos string) []portResult {
	results := make([]portResult, len(ports))
	next := make(chan int)
	var wg sync.WaitGroup
	if concurrency > len(ports) {
		concurrency = len(ports)
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range next {
				// ctx 取消时在 connect 之外再看一眼：Go 的 net.Dialer 会自己把
				// "operation was canceled" 改写成 poll.ErrCancelled，用 errors.Is 认不出来。
				if ctx.Err() != nil {
					results[idx] = portResult{Port: ports[idx], Status: scanError, Detail: "取消了"}
					continue
				}
				results[idx] = scanOne(ctx, addr, ports[idx], timeout, goos)
			}
		}()
	}
	for i := range ports {
		next <- i
	}
	close(next)
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

// scanOne 探单个端口。★ 一个端口失败不是错误：整个扫描不会因为一个端口判不出来而失败，
// 那个端口只是带着自己的状态和 detail 留在结果里（[OTS-6.2]）。
func scanOne(ctx context.Context, addr netaddr.Addr, port int, timeout time.Duration, goos string) portResult {
	target, err := addr.HostPort(port, goos)
	if err != nil {
		return portResult{Port: port, Status: scanError, Detail: err.Error()}
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	conn, derr := d.DialContext(cctx, "tcp", target)
	elapsed := time.Since(start).Milliseconds()
	if derr == nil {
		conn.Close()
		return portResult{Port: port, Status: verdictOpen, ElapsedMS: elapsed}
	}
	detail := derr.Error()
	if isNoRoute(derr) {
		return portResult{Port: port, Status: scanUnroutable, ElapsedMS: elapsed, Detail: detail}
	}
	switch code := classify(derr); code {
	case verdictClosed:
		return portResult{Port: port, Status: verdictClosed, ElapsedMS: elapsed}
	case verdictFiltered:
		return portResult{Port: port, Status: verdictFiltered, ElapsedMS: elapsed}
	}
	return portResult{Port: port, Status: scanError, ElapsedMS: elapsed, Detail: detail}
}

// isNoRoute 认「包根本没出去」这一类。★ 必须和 filtered 分开：filtered 是发了没人答，
// no-route 是本机连一条路都没有 —— 后者要查的是自己的网卡和路由，不是对端的防火墙。
//
// errno 各平台不统一（Linux 给 ENETUNREACH，macOS 常给 EHOSTUNREACH，Windows 是
// WSAEHOSTUNREACH），而且有的包装层不透出 errno，所以两边都认。
func isNoRoute(err error) bool {
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	s := strings.ToLower(err.Error())
	for _, k := range []string{"no route to host", "network is unreachable",
		"unreachable network", "cannot assign requested address"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// parsePortList 解析 "22,80,8000-8010" 这种写法。宽进但严格：
// 反过来的区间、越界的数字、空的片段都直接报错，不许悄悄丢掉几个端口 ——
// 悄悄少扫两个端口的后果是「扫出来没有」，而人会把那个结论当成「主机上没有这个服务」。
func parsePortList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultScanPorts, nil
	}
	seen := map[int]bool{}
	out := []int{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument, "端口列表里有一段是空的：%q", s)
		}
		lo, hi, isRange := part, "", false
		if i := strings.Index(part, "-"); i >= 0 {
			lo = strings.TrimSpace(part[:i])
			hi = strings.TrimSpace(part[i+1:])
			isRange = true
			if hi == "" {
				return nil, ots.Errf(ots.ErrInvalidArgument, "区间 %q 缺了右半边", part)
			}
		}
		l, err := parsePort(lo, part)
		if err != nil {
			return nil, err
		}
		if !isRange {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
			continue
		}
		h, err := parsePort(hi, part)
		if err != nil {
			return nil, err
		}
		if h < l {
			return nil, ots.Errf(ots.ErrInvalidArgument, "区间 %q 是反的（%d 在 %d 后面）", part, l, h)
		}
		for p := l; p <= h; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "端口列表是空的")
	}
	if len(out) > maxScanPorts {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"一次扫 %d 个端口太多了（上限 %d）—— 分几段扫，或者用网段扫描那一栏", len(out), maxScanPorts)
	}
	sort.Ints(out)
	return out, nil
}

func parsePort(s, raw string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, ots.Errf(ots.ErrInvalidArgument, "端口 %q 写错了（来自 %q）", s, raw)
	}
	if n < 1 || n > 65535 {
		return 0, ots.Errf(ots.ErrInvalidArgument, "端口 %d 不在 1-65535 之间", n)
	}
	return n, nil
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "无"
	}
	if len(ports) > 12 {
		return fmt.Sprintf("%s 等 %d 个", headPorts(ports, 12), len(ports))
	}
	return headPorts(ports, len(ports))
}

func headPorts(ports []int, n int) string {
	if n > len(ports) {
		n = len(ports)
	}
	ps := make([]string, n)
	for i, p := range ports[:n] {
		ps[i] = strconv.Itoa(p)
	}
	return strings.Join(ps, "、")
}
