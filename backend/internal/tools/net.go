// Package tools 是 NetKit 暴露给调用方的工具集合。
//
// ★ 每个工具都对应界面上的一个按钮 —— [OTS-4.5]。
// 实现上这条基本自动成立，因为界面也是调同一套 API 的（见 docs/设计.md「AI 接口」）。
// 要守住的是反过来那半句：**不许为 AI 单开一个界面上没有的能力**。
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// Register 把本包的工具装进注册表。
func Register(r *ots.Registry) {
	r.MustRegister(interfacesTool, tcpProbeTool, udpProbeTool, portsScanTool, subnetScanTool, pingTool, pingWatchTool, rtspProbeTool, neighborsTool, discoverTool,
		dualStackTool, checkupTool, portProcTool, dnsQueryTool, tlsCheckTool, httpProbeTool, traceTool, mtrTool, mtuPathTool, timeCheckTool, subnetCalcTool, macAnalyzeTool)
	RegisterAddress(r)
	RegisterDHCP(r)
	RegisterRemote(r)
}

// ── net.interfaces ──

var interfacesTool = ots.Tool{
	Name:  "net.interfaces",
	Class: ots.ClassRead,
	Summary: "列出本机全部网卡：地址（IPv4 与 IPv6 一并给出，含链路本地）、网段、MAC、MTU、" +
		"状态，以及每块网卡的判定（双栈正常 / 只有 v4 / 只有 v6 / 只有链路本地 / 没拿到地址 等）。" +
		"排查「这台机器接在哪个网里」「为什么没网」的起点。",
	// 没有参数。additionalProperties:false 是明确拒收多余字段，不是省略。
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: func(ctx context.Context, args json.RawMessage) (any, error) {
		nics, err := netif.Interfaces()
		if err != nil {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		out := make([]nicOut, 0, len(nics))
		for _, n := range nics {
			out = append(out, toNICOut(n))
		}
		return map[string]any{"interfaces": out}, nil
	},
}

// nicOut 是一块网卡对外的形状。
//
// ★ 判定是结构化的 [OTS-5.1]，不是一句话 —— 界面按当前语言渲染 verdict，
// note 只是给日志和命令行的附加字段 [OTS-5.4]。
type nicOut struct {
	Name    string      `json:"name"`
	Index   int         `json:"index"`
	MAC     string      `json:"mac,omitempty"`
	MTU     int         `json:"mtu,omitempty"`
	Up      bool        `json:"up"`
	Running bool        `json:"running"`
	Virtual bool        `json:"virtual,omitempty"`
	Loop    bool        `json:"loopback,omitempty"`
	Kind    string      `json:"kind,omitempty"`
	KindSrc string      `json:"kindSrc,omitempty"`
	Addrs   []addrOut   `json:"addrs"`
	Verdict ots.Verdict `json:"verdict"`
}

type addrOut struct {
	Addr   string `json:"addr"`   // 带 zone 的展示写法，如 fe80::1%en0
	CIDR   string `json:"cidr"`   //
	Family string `json:"family"` // ipv4 / ipv6
	Scope  string `json:"scope"`  // loopback / link-local / private / global / multicast
	Zone   string `json:"zone,omitempty"`
	ZoneID int    `json:"zoneID,omitempty"`
}

func toNICOut(n netif.NIC) nicOut {
	addrs := make([]addrOut, 0, len(n.Addrs))
	for _, a := range n.Addrs {
		fam := "ipv4"
		if a.Is6() {
			fam = "ipv6"
		}
		addrs = append(addrs, addrOut{
			Addr: a.String(), CIDR: a.CIDR(), Family: fam,
			Scope: string(a.Scope()), Zone: a.Zone, ZoneID: a.ZoneID,
		})
	}
	v := n.Verdict
	return nicOut{
		Name: n.Name, Index: n.Index, MAC: n.MAC, MTU: n.MTU,
		Up: n.Up, Running: n.Running, Virtual: n.Virtual, Loop: n.Loop,
		Kind: n.Kind, KindSrc: n.KindSrc,
		Addrs: addrs,
		Verdict: ots.Verdict{
			Code:   string(v.Code),
			Values: map[string]any{"networks": v.Networks, "usb": v.USB},
			Note:   v.NoteZH(),
		},
	}
}

// ── net.tcp.probe ──

// ★ [OTS-4.3]：发流量去**观察**，是 read 不是 mutate。
// 这条容易被想反 —— 但探测不改任何人的状态，把它归成 mutate 会导致
// 一次 ping 都要弹框确认，没人受得了，最后的结果是大家把确认关掉。
var tcpProbeTool = ots.Tool{
	Name:  "net.tcp.probe",
	Class: ots.ClassRead,
	Summary: "对一个地址和端口做 TCP 连接探测，判断端口是开着、关着、还是被丢包（无响应）。" +
		"地址支持 IPv4 与 IPv6，IPv6 写不写方括号都认，链路本地地址要带 zone（如 fe80::1%en0）。" +
		"排查「服务到底起没起」「是不是防火墙拦了」用这个。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {
	      "type": "string",
	      "description": "目标地址。可以只写地址（192.168.1.1、fd00::1、fe80::1%en0），也可以带端口（192.168.1.1:80、[fd00::1]:80）。IPv6 带不带方括号都认。链路本地地址（fe80::）必须带 zone。"
	    },
	    "port": {
	      "type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "端口。addr 里已经带了端口就不用填。"
	    },
	    "timeoutMs": {
	      "type": "integer", "minimum": 1, "maximum": 60000,
	      "description": "超时毫秒数，默认 3000。"
	    }
	  }
	}`),
	Invoke: probeTCP,
}

type probeArgs struct {
	Addr      string `json:"addr"`                // 地址，或 host:port
	Port      int    `json:"port,omitempty"`      // addr 里没带端口时用这个
	TimeoutMS int    `json:"timeoutMs,omitempty"` // 默认 3000
}

// 判定码。★ 这三个是**领域判定码**，将来要进 NetKit 的领域规范。
// [OTS-5.8]：扁平命名空间，不加前缀，自己负责不撞车。
const (
	verdictOpen     = "open"     // 连上了
	verdictClosed   = "closed"   // 对方明确拒绝（RST）——**说明主机在**，只是这个端口没服务
	verdictFiltered = "filtered" // 没有任何响应，超时。多半是防火墙静默丢包
)

func probeTCP(ctx context.Context, raw json.RawMessage) (any, error) {
	var a probeArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}

	// ★ 宽进：addr 可以是 "192.168.1.1"、"[fd00::1]:80"、"fe80::1%en0" 等等，
	//   port 单独给也行。解析统一走 netaddr，不在这里手搓字符串。
	addr, port, err := netaddr.SplitHostPort(a.Addr)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if port == 0 {
		port = a.Port
	}
	if port <= 0 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "端口 %d 不在 1-65535 之间", port)
	}

	// ★ 这一步是双栈地基真正派上用场的地方：
	//   链路本地地址要按**本平台**的写法拼 zone（Linux/macOS 用接口名，Windows 用接口索引），
	//   IPv6 还要加方括号。拼错了不会报错，只会连到一个不存在的地方然后超时。
	target, err := addr.HostPort(port, runtime.GOOS)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}

	timeout := 3 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	family := "ipv4"
	if addr.Is6() {
		family = "ipv6"
	}
	values := map[string]any{"target": target, "family": family, "port": port}

	start := time.Now()
	var d net.Dialer
	conn, derr := d.DialContext(ctx, "tcp", target)
	values["elapsedMs"] = time.Since(start).Milliseconds()

	if derr == nil {
		conn.Close()
		return ots.Verdict{Code: verdictOpen, Values: values,
			Note: target + " 端口开着"}, nil
	}

	// ★ [OTS-6.2] 这里是那条界线的实际落点：
	//   「端口关着」「被丢包」是**成功判定出来的状态**，是判定不是错误。
	//   只有工具自己跑不起来（参数非法、权限不够）才是错误。
	values["detail"] = derr.Error()
	switch classify(derr) {
	case verdictClosed:
		return ots.Verdict{Code: verdictClosed, Values: values,
			Note: target + " 端口关着（对方明确拒绝，说明主机是在的）"}, nil
	case verdictFiltered:
		return ots.Verdict{Code: verdictFiltered, Values: values,
			Note: target + " 没有任何响应（多半是防火墙静默丢包）"}, nil
	}
	// ★ [OTS-5.7] 判定不出来就老实返回 unknown 加上已有证据，
	//   不许编一句人话糊过去。
	return ots.Unknown(values), nil
}

// classify 把 dial 的错误归成判定码。认不出来返回空串（调用方转 unknown）。
func classify(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return verdictFiltered
	}
	// 连接被拒绝 = 对方回了 RST = **主机是在的**，只是这个端口没服务。
	// 这个区分对现场很要紧：closed 说明机器活着，filtered 连机器在不在都不知道。
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return verdictClosed
	}
	// 兜底：某些平台/包装层不透出 errno，只能看文本
	if s := err.Error(); strings.Contains(s, "refused") || strings.Contains(s, "reset") {
		return verdictClosed
	}
	return ""
}
