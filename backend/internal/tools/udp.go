package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// ── net.udp.probe ──
//
// UDP 没有连接这个概念，所以「探一个端口」这件事在这里天生比 TCP 模糊：
// 没人回你，可能是端口开着但服务不答你这句它不认识的话，也可能是防火墙把包丢了。
// 这两个在现场要查的方向完全不同，所以这个工具**不许**把它们揉成一个码，
// 并且要靠一次对照探测把它们分开（见 udpSilentAlive / udpSilent）。

const (
	udpResponsive = "udp-responsive" // 收到回包 —— 那里确实有个会说话的服务
	udpClosed     = "udp-closed"     // 收到 ICMP 端口不可达 —— 主机在，这个端口没服务
	// 端口没答，但**对照组**有反应（回了不可达或者也回了包）：
	// 说明这台机器活着、而且它发得出 ICMP 错误 —— 那目标端口为什么不出声，
	// 就只剩「端口开着但不答这句话」和「这条端口被单独拦了」两种，仍然分不清，
	// 至少能排除「整台机器/整条路径不对」。
	udpSilentAlive = "udp-silent-alive"
	// 端口和对照组都没反应 —— 整条路径对 UDP 静默，连机器在不在都不知道
	udpSilent = "udp-silent"
)

// 对照组打在哪个端口：一个几乎不会有服务、也几乎不会被专门放行的高端口。
// 可以由 controlPort 覆盖（现场要是知道这台设备上哪个端口肯定是空的，填那个更准）。
const defaultUDPControlPort = 50000

var udpProbeTool = ots.Tool{
	Name:  "net.udp.probe",
	Class: ots.ClassRead,
	Summary: "向一个 UDP 端口发一个数据报，看它答不答。" +
		"★ UDP 没有连接，所以结果比 TCP 模糊，这个工具把模糊处如实分开写：" +
		"udp-responsive（有回包，确定有服务）、udp-closed（收到 ICMP 端口不可达，主机在但端口没服务）、" +
		"udp-silent-alive（端口不出声，但对照组出声，所以能排除整机不对）、" +
		"udp-silent（端口和对照组都不出声，整条路径对 UDP 静默，什么都判不出）。" +
		"多数服务不认识空包，所以只想知道「通不通」建议带一句协议里真实的话；" +
		"只想确认端口开不开，用 net.tcp.probe 更准。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {
	      "type": "string",
	      "description": "目标地址。可以只写地址（192.168.1.1、fd00::1、fe80::1%en0），也可以带端口（192.168.1.1:5060、[fd00::1]:53）。IPv6 带不带方括号都认。链路本地地址（fe80::）必须带 zone。"
	    },
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "端口。addr 里已经带了端口就不用填。"},
	    "payload": {"type": "string", "description": "要发的内容，按 UTF-8 原样发出去。不填就是空包（有些服务对空包直接不理，那就什么都判不出来）。"},
	    "payloadHex": {"type": "string",
	      "description": "要发的内容的十六进制写法（如 00010000），发二进制协议报文用这个。给了 payloadHex 就不再看 payload。"},
	    "timeoutMs": {"type": "integer", "minimum": 100, "maximum": 15000,
	      "description": "等多久算不答，默认 1500。要跑对照组的话最坏时间是这个值的两倍。"},
	    "controlPort": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "对照组打在哪个端口，默认 50000。填成目标端口等于不跑对照。"},
	    "noControl": {"type": "boolean",
	      "description": "只发目标端口这一发，不做对照探测。对照只多一个包，但它打在你没点名的端口上，生产设备上要保守就关掉。"}
	  }
	}`),
	Invoke: doUDPProbe,
}

type udpArgs struct {
	Addr        string `json:"addr"`
	Port        int    `json:"port,omitempty"`
	Payload     string `json:"payload,omitempty"`
	PayloadHex  string `json:"payloadHex,omitempty"`
	TimeoutMS   int    `json:"timeoutMs,omitempty"`
	ControlPort int    `json:"controlPort,omitempty"`
	NoControl   bool   `json:"noControl,omitempty"`
}

func doUDPProbe(ctx context.Context, raw json.RawMessage) (any, error) {
	var a udpArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	// ★ 这一层只收 IP，和 net.tcp.probe、net.ping 一致：域名先用 net.dns.query 查。
	//   报错要说清楚下一步干什么，光说「看不懂地址」会让人以为是写法问题。
	addr, port, err := netaddr.SplitHostPort(a.Addr)
	if err != nil {
		if host, ok := udpLooksLikeName(a.Addr); ok {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%q 不是 IP —— 这里只收 IP，域名先用 net.dns.query 查出地址再来探", host)
		}
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if port == 0 {
		port = a.Port
	}
	if port <= 0 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "端口 %d 不在 1-65535 之间", port)
	}
	payload, err := udpPayload(a)
	if err != nil {
		return nil, err
	}
	target, err := addr.HostPort(port, runtime.GOOS)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}

	timeout := 1500 * time.Millisecond
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}

	values := map[string]any{
		"target": target,
		"port":   port,
		"family": udpFamily(addr),
	}

	res := udpAsk(ctx, target, payload, timeout)
	values["elapsedMs"] = res.elapsed.Milliseconds()
	values["bytes"] = res.bytes
	if res.detail != "" {
		values["detail"] = res.detail
	}

	switch res.code {
	case udpResponsive:
		values["answered"] = true
		return ots.Verdict{Code: udpResponsive, Values: values,
			Note: target + " 答了（回包 " + itoa(res.bytes) + " 字节）—— 这个端口后面确实有服务"}, nil
	case udpClosed:
		values["answered"] = false
		return ots.Verdict{Code: udpClosed, Values: values,
			Note: target + " 回了 ICMP 端口不可达 —— 主机在，这个端口没服务"}, nil
	}

	// ★ 「包根本没发出去」和「发出去了没人答」是两件事：前者判不出端口开不开，
	//   揉进 udp-silent 会让人去查防火墙。
	if res.err != nil {
		values["sent"] = false
		return ots.Unknown(values), nil
	}

	// 目标端口没出声。这一步才是这个工具值钱的地方：
	// 再打一个「肯定没人监听」的端口当对照，用它的反应把「这台机器不对」和
	// 「只是这个端口的事」分开。对照组只取出不出声，不判它开没开。
	code := udpSilent
	ctrlRan, ctrlPort := false, 0
	if !a.NoControl {
		cp := a.ControlPort
		if cp == 0 {
			cp = defaultUDPControlPort
		}
		if ctrl, err := addr.HostPort(cp, runtime.GOOS); err == nil && cp != port {
			ctrlRan, ctrlPort = true, cp
			cres := udpAsk(ctx, ctrl, nil, timeout)
			control := map[string]any{
				"port":      cp,
				"answered":  cres.code != "",
				"elapsedMs": cres.elapsed.Milliseconds(),
			}
			if cres.code != "" {
				control["code"] = cres.code
				code = udpSilentAlive
			} else if cres.detail != "" {
				control["detail"] = cres.detail
			}
			values["control"] = control
		}
	}

	switch {
	case code == udpSilentAlive:
		return ots.Verdict{Code: udpSilentAlive, Values: values,
			Note: target + " 没出声，但同一台机器的对照端口 " + itoa(ctrlPort) + " 出声了 —— 主机活着，" +
				"这个端口要么是开着但不答这句话，要么是被单独拦了，这两种还得往下查"}, nil
	case ctrlRan:
		return ots.Verdict{Code: udpSilent, Values: values,
			Note: target + " 和对照端口 " + itoa(ctrlPort) + " 都没出声 —— 这条路对 UDP 是静默的，" +
				"分不清是机器不在、还是 UDP 整段被丢，先用 net.ping 看机器在不在"}, nil
	default:
		// ★ 没跑对照就不能说「对照也没出声」：那只说我们真做过的事。
		//   少了对照，「机器不在」和「这个端口不答这句话」这两种本来就分不开。
		return ots.Verdict{Code: udpSilent, Values: values,
			Note: target + " 没出声。这次没跑对照探测，所以分不清是机器不在、" +
				"还是这个端口开着但不答你这句话 —— 去掉 noControl 再问一次就能分开"}, nil
	}
}

func udpFamily(addr netaddr.Addr) string {
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

// udpLooksLikeName 从 addr 里剥出地址部分，判断它是不是「写了个域名」。
// 只为了一句能对上下一步的报错 —— SplitHostPort 只会说「看不懂地址」。
func udpLooksLikeName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	} else if strings.Count(s, ":") == 1 {
		host = s[:strings.Index(s, ":")]
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if _, err := netip.ParseAddr(host); err == nil {
		return host, false
	}
	return host, strings.Contains(host, ".")
}

// udpPayload 取要发的字节。★ 空包是真的会发一个零长数据报出去的（Go 在连好的
// UDP 套接字上确实会下发这一发），所以不填 payload 不是「什么都没干」。
func udpPayload(a udpArgs) ([]byte, error) {
	if a.PayloadHex != "" {
		s := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
				return -1
			}
			return r
		}, a.PayloadHex)
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "payloadHex 不是合法的十六进制：%s", err)
		}
		return b, nil
	}
	if a.Payload != "" {
		return []byte(a.Payload), nil
	}
	return nil, nil
}

type udpProbeResult struct {
	code    string // udp-responsive / udp-closed / 空 = 没等到任何反应
	bytes   int
	detail  string
	elapsed time.Duration
	// err 只放「这一发到底有没有出去」那一类问题（解析失败、发不出去）。
	// ★ 传的是 error 而不是文本：[OTS-6.2] 的界线要靠 errors.As 认得出来，
	//   拿文本 substring 去猜「no such host」，换个平台措辞就漏了。
	err error
}

// udpAsk 对一个目标发一发 UDP 并等回音。
//
// 连好的 UDP 套接字是唯一能拿到 ICMP 端口不可达的写法（不连的话收不到 ICMP 差错，
// 除非开 raw socket，那要管理员权限）。代价是：**它也会把回包按源端口过滤掉**，
// 所以服务从别的端口回你，这里就当没收到 —— 宁可不判，也不误判成 closed。
func udpAsk(ctx context.Context, target string, payload []byte, timeout time.Duration) udpProbeResult {
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", target)
	if err != nil {
		// 到这一步还没发出去：多半是地址根本不通（比如 zone 指的接口没了）。
		// [OTS-6.2] 这是观测没做成，不是「端口不通」，交回上层按原因分开处理。
		return udpProbeResult{detail: err.Error(), elapsed: time.Since(start), err: err}
	}
	defer conn.Close()

	// ★ 读是阻塞的，光在循环头上看 ctx 等于没看：取消要能立刻把这次探测掐掉，
	//   所以拿一个看门狗把套接字关掉，让阻塞中的 Read 马上带错误回来。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	if _, err := conn.Write(payload); err != nil {
		// 上一发的 ICMP 错误可能压在这次 write 上才浮出来
		if classify(err) == verdictClosed {
			return udpProbeResult{code: udpClosed, detail: err.Error(), elapsed: time.Since(start)}
		}
		return udpProbeResult{detail: "发不出去：" + err.Error(), elapsed: time.Since(start), err: err}
	}

	deadline := start.Add(timeout)
	buf := make([]byte, 65536)
	resent := false
	for {
		if err := ctx.Err(); err != nil {
			return udpProbeResult{detail: "取消了：" + err.Error(), elapsed: time.Since(start), err: err}
		}
		if time.Now().After(deadline) {
			break
		}
		// ★ 每次读都把截止点对到同一个绝对时间，别让第二发白等一个 timeout
		if err := conn.SetReadDeadline(deadline); err != nil {
			return udpProbeResult{detail: err.Error(), elapsed: time.Since(start), err: err}
		}
		n, err := conn.Read(buf)
		if err == nil {
			return udpProbeResult{code: udpResponsive, bytes: n, elapsed: time.Since(start)}
		}
		// 看门狗关套接字会让 Read 带一个「连接已关闭」回来 —— 那是取消，不是没反应
		if cerr := ctx.Err(); cerr != nil {
			return udpProbeResult{detail: "取消了：" + cerr.Error(), elapsed: time.Since(start), err: cerr}
		}
		// 看门狗关掉套接字之后 Read 报的是「use of closed network connection」，
		// 那既不是回包也不是不可达 —— 真实原因是这次探测被取消了。
		if cerr := ctx.Err(); cerr != nil {
			return udpProbeResult{detail: "探测被取消：" + cerr.Error(),
				elapsed: time.Since(start), err: cerr}
		}
		// UDP 上这个 errno 的来源是 ICMP 端口不可达（不是 TCP 的 RST），
		// 含义一样：对方主机在，只是这个端口没人监听，所以 classify 直接复用。
		if classify(err) == verdictClosed {
			return udpProbeResult{code: udpClosed, detail: err.Error(), elapsed: time.Since(start)}
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if resent {
				break
			}
			// 补一发：不少平台上 ICMP 差错要在下一次收发才浮出来，
			// 只发一次会把 closed 误读成「没反应」。
			resent = true
			if _, werr := conn.Write(payload); werr != nil {
				if classify(werr) == verdictClosed {
					return udpProbeResult{code: udpClosed, detail: werr.Error(), elapsed: time.Since(start)}
				}
			}
			continue
		}
		return udpProbeResult{detail: err.Error(), elapsed: time.Since(start), err: err}
	}
	return udpProbeResult{detail: "等了 " + timeout.String() + " 没回话",
		elapsed: time.Since(start)}
}
