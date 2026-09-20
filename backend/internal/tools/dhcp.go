package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/dhcp"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

// DHCP 的判定码。
const (
	verdictNoDHCP     = "no-dhcp"    // 探了一圈没人应 —— 这个网确实没人发地址
	verdictDHCPFound  = "dhcp-found" // ★ 已经有人在发地址了。再起一个就是事故
	verdictServing    = "serving"    // 我们的服务起来了
	verdictStopped    = "stopped"    //
	verdictNotServing = "not-serving"
)

// running 当前跑着的那个 DHCP 服务。
//
// ★ 一台机器同时只允许跑一个：DHCP 绑的是固定端口 67，
// 而且"这台机器正在给哪个网发地址"这件事必须是唯一的、说得清的。
var running struct {
	mu      sync.Mutex
	srv     *dhcp.Server
	cfg     *dhcp.Config
	entryID string // state 账本里的那一笔
	since   time.Time
}

// journal 改系统的账本。由 main 装进来。
var journal *state.Journal

// SetJournal 装上账本。没装的话改系统的工具一律拒绝执行。
func SetJournal(j *state.Journal) { journal = j }

// RegisterDHCP 把 DHCP 相关工具装进注册表。
func RegisterDHCP(r *ots.Registry) {
	r.MustRegister(dhcpProbeTool, dhcpDefaultsTool, dhcpServeTool,
		dhcpLeasesTool, dhcpEventsTool, dhcpBindTool, dhcpSetIPTool, dhcpStopTool)
}

// ── net.dhcp.probe（只读）──

var dhcpProbeTool = ots.Tool{
	Name:  "net.dhcp.probe",
	Class: ots.ClassRead,
	Summary: "问一句「这个网里有人在自动发 IP 吗」：广播一个 DHCP 探测包，收集所有回应，" +
		"给出谁在发、发的是什么网段、网关是什么。" +
		"★ 打算自己开 DHCP 之前**必须先跑这个**——网里已经有 DHCP 时再起一个，" +
		"两边同时发地址会造成地址冲突和间歇性不通，是最难查的一类故障。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["iface"],
	  "properties": {
	    "iface": {"type": "string", "description": "在哪块网卡上探，如 en0 / eth0。用 net.interfaces 看有哪些。"},
	    "waitMs": {"type": "integer", "minimum": 500, "maximum": 20000, "description": "等回应多久，默认 3000。"}
	  }
	}`),
	Invoke: probeDHCP,
}

type dhcpProbeArgs struct {
	Iface  string `json:"iface"`
	WaitMS int    `json:"waitMs,omitempty"`
}

func probeDHCP(ctx context.Context, raw json.RawMessage) (any, error) {
	var a dhcpProbeArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	iface, err := findIface(a.Iface)
	if err != nil {
		return nil, err
	}
	wait := time.Duration(a.WaitMS) * time.Millisecond
	found, err := dhcp.Probe(ctx, iface, wait)
	if err != nil {
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}
	values := map[string]any{"iface": iface.Name, "servers": found, "count": len(found)}
	if len(found) == 0 {
		return ots.Verdict{Code: verdictNoDHCP, Values: values,
			Note: iface.Name + " 上没人应答 —— 这个网里目前没有自动发地址的服务"}, nil
	}
	return ots.Verdict{Code: verdictDHCPFound, Values: values,
		Note: fmt.Sprintf("%s 上已经有 %d 个 DHCP 在发地址 —— 再起一个会冲突", iface.Name, len(found))}, nil
}

// ── net.dhcp.serve（改系统）──

var dhcpServeTool = ots.Tool{
	Name:  "net.dhcp.serve",
	Class: ots.ClassMutate,
	Summary: "把这台电脑变成 DHCP 服务器，给同一个交换机上的设备自动分配 IP。" +
		"适用场景：一堆设备插在哑交换机上、没有路由器、没人发地址，只能一台台手工设静态 IP。" +
		"★ 启动前会自动先探一遍网里有没有别的 DHCP，探到了就拒绝启动（可用 force 覆盖，但请先想清楚）。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["iface"],
	  "properties": {
	    "iface": {"type": "string", "description": "在哪块网卡上服务。这块网卡要先有一个静态 IP。"},
	    "start": {"type": "string", "description": "地址池起始。★ 不填就按本机网段自动算（见 net.dhcp.defaults），并且会避开本机地址和网段头几个常被路由器占用的地址。"},
	    "end":   {"type": "string", "description": "地址池结束。不填同上，自动算。"},
	    "router":{"type": "string", "description": "下发给设备的网关。★ 没有出口就别填——填一个通不了的网关，设备会把它当默认路由，表现成「拿到地址了却什么都访问不了」。"},
	    "dns":   {"type": "array", "items": {"type": "string"}, "description": "下发的 DNS，可不填"},
	    "leaseHours": {"type": "integer", "minimum": 1, "maximum": 8760, "description": "租期小时数，默认 12"},
	    "reserved": {"type": "object", "additionalProperties": {"type": "string"},
	      "description": "固定绑定：MAC → IP，如 {\"aa:bb:cc:dd:ee:ff\": \"192.168.1.50\"}。现场靠它把摄像机钉在固定地址上"},
	    "force": {"type": "boolean", "description": "网里已经有别的 DHCP 时仍然启动。★ 默认 false，开之前请想清楚会不会把网搞乱"}
	  }
	}`),
	Describe: describeServe,
	Invoke:   serveDHCP,
}

type dhcpServeArgs struct {
	Iface      string            `json:"iface"`
	Start      string            `json:"start"`
	End        string            `json:"end"`
	Router     string            `json:"router,omitempty"`
	DNS        []string          `json:"dns,omitempty"`
	LeaseHours int               `json:"leaseHours,omitempty"`
	Reserved   map[string]string `json:"reserved,omitempty"`
	Force      bool              `json:"force,omitempty"`
}

// describeServe 批准框里显示的那句话。[OTS-7.2]
//
// ★ 要把**会改什么**说清楚，不是复述工具名。人看完这句话就该知道自己在同意什么。
func describeServe(raw json.RawMessage) string {
	var a dhcpServeArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	s := fmt.Sprintf("在网卡 %s 上启动 DHCP 服务，给这个网里的设备自动分配 %s–%s 的地址",
		a.Iface, a.Start, a.End)
	if a.Router != "" {
		s += "，并告诉它们网关是 " + a.Router
	} else {
		s += "，不下发网关（设备只能在本网段内通信）"
	}
	if n := len(a.Reserved); n > 0 {
		s += fmt.Sprintf("，其中 %d 台按 MAC 固定地址", n)
	}
	if a.Force {
		s += "。★ 你勾了「强制」：即使网里已经有别的 DHCP 也照样启动，这可能让整个网的地址乱掉"
	}
	return s
}

func serveDHCP(ctx context.Context, raw json.RawMessage) (any, error) {
	var a dhcpServeArgs
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	if journal == nil {
		// ★ 没有账本就不许改系统：改了却记不下来，崩溃后没人知道要还原什么
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝改系统")
	}

	running.mu.Lock()
	defer running.mu.Unlock()
	if running.srv != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"这台机器上已经有一个 DHCP 服务在 %s 上跑着了，先停掉再开", running.cfg.Iface.Name)
	}

	iface, err := findIface(a.Iface)
	if err != nil {
		return nil, err
	}
	// ★ 地址池不填就自动算（老板 2026-09-20：「dhcp 有默认参数，可以修改」）。
	//   让人自己算池子，等于让他当场判断"哪一段没被占""会不会把自己发出去"，
	//   而填错的后果不是报错、是整网乱掉。机器算得比人准。
	if a.Start == "" || a.End == "" {
		d, derr := DHCPDefaults(iface.Name)
		if derr != nil {
			return nil, derr
		}
		if a.Start == "" {
			a.Start = d.Start
		}
		if a.End == "" {
			a.End = d.End
		}
		if a.LeaseHours == 0 {
			a.LeaseHours = d.LeaseHours
		}
	}
	cfg, err := buildCfg(a, iface)
	if err != nil {
		return nil, err
	}

	// ★★ 保命步骤：先探一遍。这不是体检项，是这条功能能不能安全开的前提。
	found, perr := dhcp.Probe(ctx, iface, 3*time.Second)
	if perr == nil && len(found) > 0 && !a.Force {
		return ots.Verdict{
			Code:   verdictDHCPFound,
			Values: map[string]any{"iface": iface.Name, "servers": found, "count": len(found)},
			Note: fmt.Sprintf("没有启动：%s 上已经有 %d 个 DHCP 在发地址。"+
				"再起一个会造成地址冲突和间歇性不通。确认那些是要被取代的，再用 force 启动。",
				iface.Name, len(found)),
		}, nil
	}

	// ★ [OTS-7.5] 先登记再动手。顺序反了，崩溃窗口里这笔改动就无账可查。
	id, err := journal.Register("dhcp-server", describeServe(raw),
		map[string]any{"serving": false},
		map[string]any{"iface": iface.Name, "start": a.Start, "end": a.End,
			"router": a.Router, "leaseHours": a.LeaseHours})
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "登记改动失败，没有动手：%s", err)
	}

	srv, err := dhcp.NewServer(*cfg, slog.Default())
	if err != nil {
		_ = journal.Drop(id, "配置不合法，没有动手："+err.Error())
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if err := srv.Start(); err != nil {
		_ = journal.Drop(id, "起不来，没有改动："+err.Error())
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}
	_ = journal.MarkApplied(id)

	running.srv, running.cfg, running.entryID, running.since = srv, cfg, id, time.Now()
	return ots.Verdict{
		Code: verdictServing,
		Values: map[string]any{
			"iface": iface.Name, "serverIp": cfg.ServerIP.String(),
			"pool": cfg.Start.String() + "–" + cfg.End.String(), "poolSize": cfg.PoolSize(),
			"leaseHours": int(cfg.Lease / time.Hour),
			"router":     routerOf(cfg), "forced": a.Force,
		},
		Note: fmt.Sprintf("已在 %s 上开始发地址（池 %s–%s，共 %d 个）",
			iface.Name, cfg.Start, cfg.End, cfg.PoolSize()),
	}, nil
}

func routerOf(c *dhcp.Config) string {
	if c.Router.IsValid() {
		return c.Router.String()
	}
	return ""
}

// ── net.dhcp.leases（只读）──

var dhcpLeasesTool = ots.Tool{
	Name:  "net.dhcp.leases",
	Class: ots.ClassRead,
	Summary: "看本机 DHCP 服务已经把哪些地址发给了谁：IP、MAC、设备报上来的主机名、到期时间。" +
		"开了 DHCP 之后用它确认设备是不是都拿到地址了。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: func(context.Context, json.RawMessage) (any, error) {
		running.mu.Lock()
		defer running.mu.Unlock()
		if running.srv == nil {
			return ots.Verdict{Code: verdictNotServing,
				Values: map[string]any{}, Note: "本机没有在跑 DHCP 服务"}, nil
		}
		ls := running.srv.Leases()
		return ots.Verdict{Code: verdictServing,
			Values: map[string]any{
				"iface": running.cfg.Iface.Name, "leases": ls, "count": len(ls),
				"poolSize": running.cfg.PoolSize(),
				"since":    running.since.Format(time.RFC3339),
			},
			Note: fmt.Sprintf("已发出 %d 个地址（池子共 %d 个）", len(ls), running.cfg.PoolSize()),
		}, nil
	},
}

// ── net.dhcp.events（只读）──

var dhcpEventsTool = ots.Tool{
	Name:  "net.dhcp.events",
	Class: ots.ClassRead,
	Summary: "取 DHCP 的接入事件：哪台设备**刚刚**接入、续租、释放了地址。" +
		"★ 和 net.dhcp.leases 的区别：租约表回答「现在有谁」，事件回答「刚才多了谁」——" +
		"现场插上一台新设备，要的就是它出现的那一下。" +
		"按 sinceSeq 增量取，不会漏也不会重。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "sinceSeq": {"type": "integer", "minimum": 0,
	      "description": "上次取到的序号，只返回它之后的。第一次传 0 或不传。"}
	  }
	}`),
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			SinceSeq int64 `json:"sinceSeq"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		running.mu.Lock()
		srv := running.srv
		running.mu.Unlock()
		if srv == nil {
			return ots.Verdict{Code: verdictNotServing, Note: "本机没有在跑 DHCP 服务"}, nil
		}
		evs, last := srv.Events(a.SinceSeq)
		newly := 0
		for _, e := range evs {
			if e.Kind == "new" {
				newly++
			}
		}
		note := "这段时间没有新动静"
		if len(evs) > 0 {
			note = fmt.Sprintf("%d 条新事件，其中 %d 台是**新接入**的设备", len(evs), newly)
		}
		return ots.Verdict{Code: verdictServing,
			Values: map[string]any{"events": evs, "lastSeq": last, "newDevices": newly},
			Note:   note}, nil
	},
}

// ── net.dhcp.bind（改系统）──

var dhcpBindTool = ots.Tool{
	Name:  "net.dhcp.bind",
	Class: ots.ClassMutate,
	Summary: "把某个 MAC 固定到某个 IP：以后这台设备每次来都拿同一个地址。" +
		"现场用它把摄像机、盒子钉在固定地址上，免得换了地址还要回平台改一遍配置。" +
		"★ 如果这台设备当前拿着别的地址，绑定后它的租约会被作废，下次续租时换到新地址。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["mac", "ip"],
	  "properties": {
	    "mac": {"type": "string", "description": "设备 MAC，如 aa:bb:cc:dd:ee:ff。可以从 net.dhcp.leases 或 net.neighbors 里拿"},
	    "ip":  {"type": "string", "description": "固定给它的 IP。要在地址池所在网段里"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ MAC, IP string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("把设备 %s 固定到地址 %s：以后它每次接入都拿这个地址。"+
			"如果它现在拿着别的地址，当前租约会被作废、下次续租时换过来", a.MAC, a.IP)
	},
	Invoke: func(_ context.Context, raw json.RawMessage) (any, error) {
		var a struct {
			MAC string `json:"mac"`
			IP  string `json:"ip"`
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		hw, err := net.ParseMAC(a.MAC)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "MAC 看不懂：%s", a.MAC)
		}
		ip, err := netip.ParseAddr(a.IP)
		if err != nil || !ip.Is4() {
			return nil, ots.Errf(ots.ErrInvalidArgument, "IP 看不懂或不是 IPv4：%s", a.IP)
		}
		running.mu.Lock()
		srv, cfg := running.srv, running.cfg
		running.mu.Unlock()
		if srv == nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "本机没有在跑 DHCP 服务，先开起来再绑定")
		}
		// ★ 绑到池子外面去是常见笔误，发出去设备跟谁都不通。当场拦住
		if ip.Less(cfg.Start) || cfg.End.Less(ip) {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%s 不在地址池 %s–%s 里 —— 绑一个池外地址，设备拿到后跟谁都不通",
				ip, cfg.Start, cfg.End)
		}
		if journal != nil {
			id, jerr := journal.Register("dhcp-bind",
				fmt.Sprintf("把 %s 固定到 %s", hw, ip), nil,
				map[string]any{"mac": hw.String(), "ip": ip.String()})
			if jerr == nil {
				_ = journal.MarkApplied(id)
			}
		}
		srv.SetReserved(hw.String(), ip)
		return ots.Verdict{Code: "bound",
			Values: map[string]any{"mac": hw.String(), "ip": ip.String(), "reserved": srv.Reserved()},
			Note:   fmt.Sprintf("%s 已固定到 %s", hw, ip)}, nil
	},
}

// ── net.dhcp.setip（改系统）──

var dhcpSetIPTool = ots.Tool{
	Name:  "net.dhcp.setip",
	Class: ots.ClassMutate,
	Summary: "把某台已经拿到地址的设备改成另一个 IP。" +
		"例：设备现在是 192.168.1.123，想让它变成 192.168.1.122，直接改，不用去设备上动。" +
		"可以用当前 IP 指定设备（from），也可以用 MAC。" +
		"★ 生效时机见返回说明：DHCP 是设备主动来要的协议，服务端推不动，" +
		"所以是在设备下次续租时换过去；想立刻生效就把设备网线拔插一下。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["to"],
	  "properties": {
	    "from": {"type": "string", "description": "设备现在的 IP，如 192.168.1.123。和 mac 二选一"},
	    "mac":  {"type": "string", "description": "设备 MAC。和 from 二选一"},
	    "to":   {"type": "string", "description": "要改成的新 IP，如 192.168.1.122"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ From, MAC, To string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		who := a.From
		if who == "" {
			who = a.MAC
		}
		return fmt.Sprintf("把设备 %s 的地址改成 %s，并固定下来。"+
			"设备会在下次续租时换到新地址（想立刻生效就拔插一下网线）", who, a.To)
	},
	Invoke: setIP,
}

func setIP(_ context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		From string `json:"from"`
		MAC  string `json:"mac"`
		To   string `json:"to"`
	}
	if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	to, err := netip.ParseAddr(a.To)
	if err != nil || !to.Is4() {
		return nil, ots.Errf(ots.ErrInvalidArgument, "新地址看不懂或不是 IPv4：%s", a.To)
	}
	running.mu.Lock()
	srv, cfg := running.srv, running.cfg
	running.mu.Unlock()
	if srv == nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "本机没有在跑 DHCP 服务")
	}
	if to.Less(cfg.Start) || cfg.End.Less(to) {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%s 不在地址池 %s–%s 里 —— 发出去设备跟谁都不通", to, cfg.Start, cfg.End)
	}

	// 找出是哪台设备
	mac := ""
	if a.MAC != "" {
		hw, err := net.ParseMAC(a.MAC)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "MAC 看不懂：%s", a.MAC)
		}
		mac = hw.String()
	} else if a.From != "" {
		for _, l := range srv.Leases() {
			if l.IP == a.From {
				mac = l.MAC
				break
			}
		}
		if mac == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"地址 %s 现在没有对应的设备（用 net.dhcp.leases 看都发给了谁）", a.From)
		}
	} else {
		return nil, ots.Errf(ots.ErrInvalidArgument, "要么给 from（设备当前 IP），要么给 mac")
	}

	// ★ 新地址被别人占着就当场拦下 —— 硬改过去就是两台设备抢一个地址
	for _, l := range srv.Leases() {
		if l.IP == to.String() && l.MAC != mac {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%s 已经发给了 %s，先把那台挪开再改", to, l.MAC)
		}
	}

	if journal != nil {
		id, jerr := journal.Register("dhcp-setip",
			fmt.Sprintf("把 %s 的地址改成 %s", mac, to),
			map[string]any{"mac": mac, "ip": a.From},
			map[string]any{"mac": mac, "ip": to.String()})
		if jerr == nil {
			_ = journal.MarkApplied(id)
		}
	}
	srv.SetReserved(mac, to)

	// ★★ 如实说生效时机。DHCP 服务端**推不动**地址，只能等客户端来要。
	//   承诺"立刻生效"然后设备半小时不变，比一开始就说清楚糟得多。
	half := int(cfg.Lease.Hours() * 60 / 2)
	return ots.Verdict{
		Code: "ip-changed",
		Values: map[string]any{
			"mac": mac, "from": a.From, "to": to.String(),
			"effectiveWithinMinutes": half,
		},
		Note: fmt.Sprintf("已把 %s 固定到 %s。设备会在下次续租时换过去"+
			"（最长约 %d 分钟）；想立刻生效，把这台设备的网线拔插一下或重启它。"+
			"在它换过来之前，它继续用旧地址、不会掉线。", mac, to, half),
	}, nil
}

// ── net.dhcp.stop（改系统）──

var dhcpStopTool = ots.Tool{
	Name:    "net.dhcp.stop",
	Class:   ots.ClassMutate,
	Summary: "停掉本机的 DHCP 服务。停了之后这个网里就没人自动发地址了，已经发出去的地址在租期内仍然有效。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string {
		running.mu.Lock()
		defer running.mu.Unlock()
		if running.srv == nil {
			return "停掉 DHCP 服务（当前没有在跑）"
		}
		return fmt.Sprintf("停掉网卡 %s 上的 DHCP 服务。停了之后这个网里没人自动发地址，"+
			"新接入的设备将拿不到 IP；已经发出去的地址在租期内仍然有效", running.cfg.Iface.Name)
	},
	Invoke: func(context.Context, json.RawMessage) (any, error) {
		running.mu.Lock()
		defer running.mu.Unlock()
		if running.srv == nil {
			return ots.Verdict{Code: verdictNotServing, Note: "本机没有在跑 DHCP 服务"}, nil
		}
		name := running.cfg.Iface.Name
		running.srv.Stop()
		if journal != nil && running.entryID != "" {
			_ = journal.MarkReverted(running.entryID, "用户停止了服务")
		}
		running.srv, running.cfg, running.entryID = nil, nil, ""
		return ots.Verdict{Code: verdictStopped,
			Values: map[string]any{"iface": name},
			Note:   name + " 上的 DHCP 服务已停"}, nil
	},
}

// RestoreOnStart 启动时按账本还原。
//
// ★★ 账本里还留着 pending/applied 的 dhcp-server，说明上次**没有正常停**
// （崩了、被杀了、断电了）。我们**不自动把服务再起起来** —— 那等于
// 用户没在场的情况下又往网里发地址。正确的做法是把账**了结**并告诉人。
func RestoreOnStart(log *slog.Logger) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind != "dhcp-server" {
			continue
		}
		log.Warn("上次退出时 DHCP 服务没有正常停止 —— 本次启动不会自动重开，"+
			"如需继续请在界面上重新开启", "改动", e.What, "时间", e.At.Format(time.RFC3339))
		_ = journal.MarkReverted(e.ID, "进程重启：服务已随上次进程退出而停止")
	}
}

// ── 小工具 ──

func nonEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

func findIface(name string) (*net.Interface, error) {
	if name == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给网卡名")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没有叫 %s 的网卡（用 net.interfaces 看有哪些）", name)
	}
	return iface, nil
}

// buildCfg 把参数变成 DHCP 配置，并从网卡上取出本机地址与掩码。
func buildCfg(a dhcpServeArgs, iface *net.Interface) (*dhcp.Config, error) {
	nics, err := netif.Interfaces()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "%s", err)
	}
	var serverIP netip.Addr
	var mask net.IPMask
	for _, n := range nics {
		if n.Name != iface.Name {
			continue
		}
		for _, ad := range n.Addrs {
			// ★ 要一个能用来通信的 v4 地址。169.254 那种"没要到地址"的不算 ——
			//   拿它当 DHCP 服务器地址，发出去的整段都是废的。
			if ad.Is4() && (ad.Scope() == "private" || ad.Scope() == "global") {
				serverIP = ad.IP
				if ad.Prefix > 0 {
					mask = net.CIDRMask(ad.Prefix, 32)
				}
				break
			}
		}
	}
	if !serverIP.IsValid() {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"网卡 %s 上没有可用的 IPv4 地址 —— 要先给它设一个固定 IP，"+
				"DHCP 服务器自己必须有地址才能发地址给别人", iface.Name)
	}
	if len(mask) == 0 {
		mask = net.CIDRMask(24, 32)
	}
	start, err := netip.ParseAddr(a.Start)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "起始地址看不懂：%s", a.Start)
	}
	end, err := netip.ParseAddr(a.End)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "结束地址看不懂：%s", a.End)
	}
	cfg := &dhcp.Config{
		Iface: iface, ServerIP: serverIP, Mask: mask,
		Start: start, End: end,
		Lease: time.Duration(a.LeaseHours) * time.Hour,
	}
	if a.Router != "" {
		r, err := netip.ParseAddr(a.Router)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "网关地址看不懂：%s", a.Router)
		}
		cfg.Router = r
	}
	for _, d := range a.DNS {
		x, err := netip.ParseAddr(d)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "DNS 地址看不懂：%s", d)
		}
		cfg.DNS = append(cfg.DNS, x)
	}
	if len(a.Reserved) > 0 {
		cfg.Reserved = map[string]netip.Addr{}
		for mac, ip := range a.Reserved {
			hw, err := net.ParseMAC(mac)
			if err != nil {
				return nil, ots.Errf(ots.ErrInvalidArgument, "固定绑定里的 MAC 看不懂：%s", mac)
			}
			x, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, ots.Errf(ots.ErrInvalidArgument, "固定绑定里的 IP 看不懂：%s", ip)
			}
			cfg.Reserved[hw.String()] = x
		}
	}
	return cfg, nil
}
