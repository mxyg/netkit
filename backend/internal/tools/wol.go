package tools

// ── net.wol ──
//
// ★★ 「叫醒一台机器」在现场是三步，每一步都会错，而这三种错的表象是同一个：
//
//	发了，没醒，没人报错。所以每一步都得当场拦：
//	1. **MAC 抄错一格** —— 帧照发不误，发给一个不存在的地址。
//	   所以先严格验地址，并且把组播 / 广播挡在门外：
//	   ff:ff:ff:ff:ff:ff 会让整个网段每台机器都被踹一脚，那不叫唤醒
//	2. **发错地方** —— 255.255.255.255 是从**默认路由那块网卡**出去的，
//	   笔记本同时插着有线、连着 Wi-Fi、挂着 VPN 时，它吵到的往往不是盯着的那台。
//	   所以默认只往「选定网卡自己网段」的定向广播发，那块网卡由三步推出：
//	   用户指定 → 这个 MAC 是从哪块网卡学到的（邻居表）→ IPv4 默认路由
//	3. **发出去不等于醒了** —— 醒没醒要看它后面有没有重新出现在邻居表里。
//	   所以判定分开给：一栏说「从哪发到哪」，一栏说「这一刻它在不在表里」，
//	   绝不用「已发送」冒充「已开机」
//
// ★ 为什么归 mutate 而不像探测那样归 read [OTS-4.3]：探测只是观察，不改别人的状态；
//
//	魔术帧会让一台关着的机器开起来 —— 那是**改变了那台机器的状态**，
//	必须让人看清「你要叫醒的是哪一台、从哪儿发出去的」再点头。
//	所以一次调用只唤醒一台，批准框里说的就是那一台。
//
// ★ 凭据纪律：SecureOn 口令只在这一次发包里存在 —— 不进结果、不进日志、
//
//	不进账本，连校验失败的报错里都不回显内容（结果会被发给 AI）。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// 判定码。
const (
	verdictWOLSent      = "sent-broadcast" // 已往本机网段的定向广播发出去
	verdictWOLForwarded = "sent-unicast"   // 已单播转发到指定地址（能不能醒看路由器）
	verdictWOLAwake     = "likely-awake"   // ★ 邻居表里此刻还有它：刚才大概率醒着，所以先不发
)

// 魔术帧：6 字节全 F 同步流 + 目标 MAC 重复 16 次（+ 可选 SecureOn 口令）。
const (
	wolSyncBytes   = 6
	wolRepeats     = 16
	wolMaxRepeat   = 5 // 一次调用最多连发几枚
	wolDefaultPort = 9 // 标准端口；7 也有设备在用，两个都是登记过的
	wolGap         = 200 * time.Millisecond
)

// 「这块网卡是怎么定下来的」—— 界面按这个码渲染中文，后端不给句子 [OTS-5.2]。
const (
	wolIfaceGiven    = "given"
	wolIfaceNeighbor = "neighbor-table"
	wolIfaceRoute    = "default-route"
	wolIfaceOnly     = "only-usable-v4"
)

const (
	wolDstDirected = "directed-broadcast"
	wolDstForward  = "forwarded-unicast"
)

var wolTool = ots.Tool{
	Name:  "net.wol",
	Class: ots.ClassMutate,
	Summary: "给一个 MAC 发 Wake-on-LAN 魔术帧，把睡着的机器叫起来。" +
		"★ 一次调用只唤醒一台：这是 mutate 类，批准框里说的就是那一台，点了才发。" +
		"默认往**选定网卡自己网段**的定向广播发（如 192.168.0.255），不用 255.255.255.255 —— " +
		"那一发会从默认路由那块网卡出去，多网卡或挂着 VPN 时吵到的不是你盯着的那台。" +
		"网卡不用填也行：先看这个 MAC 在邻居表里是哪块网卡学到的，再看 IPv4 默认路由。" +
		"跨网段唤醒填 host（目标网段的广播地址或网关），并说清这一发要靠路由器开 " +
		"directed broadcast / WOL relay，多数路由器默认关着。" +
		"★ 发出去不等于醒了：判定分两栏，一栏是「从哪块网卡发到哪个地址」，" +
		"一栏是「这一刻目标 MAC 在不在邻居表里」。已经在表里就先不发（force 才发）—— " +
		"醒着的机器再收一枚，部分主机会走一次开机流程，等于把它复位。" +
		"拒收组播位为 1 的地址和 ff:ff:ff:ff:ff:ff，也拒收 8 字节的 EUI-64（魔术帧里只有 6 字节那一格）。" +
		"SecureOn 口令只用于本次发送：不进结果、不进日志、不进账本。零专有依赖，不需要管理员权限。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["mac"],
	  "properties": {
	    "mac": {"type": "string",
	      "description": "要唤醒的设备 MAC。写法都认：aa:bb:cc:dd:ee:ff、AA-BB-... 、aabb.ccdd.eeff、连写 12 位。组播 / 广播 / 全零会被拒。"},
	    "iface": {"type": "string",
	      "description": "从哪块网卡发（en0 / eth0）。不填就自己定：这个 MAC 在邻居表里是哪块网卡学到的 → IPv4 默认路由那块。"},
	    "host": {"type": "string",
	      "description": "跨网段唤醒时发到哪个 IPv4 地址：通常是目标网段的广播地址（如 192.168.5.255），也可以是该网段的网关。★ 这一发能不能到，取决于路由器有没有开 directed broadcast 转发。不填就是本机网段的定向广播。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "魔术帧端口，默认 9。有的设备固件监听 7，两个都是标准端口。"},
	    "repeats": {"type": "integer", "minimum": 1, "maximum": 5,
	      "description": "连发几枚，默认 1。无线链路或交换机刚重启时可以加到 3；★ 目标已经开着时多发的每一枚都可能被部分主机当成一次开机请求。"},
	    "secureOn": {"type": "string",
	      "description": "SecureOn 口令（hex，可带分隔符）：只有 4 字节（低两字节必须为 0）和 6 字节两种合法长度。★ 只在本次发送里用，不写进任何输出。"},
	    "force": {"type": "boolean",
	      "description": "目标此刻就在邻居表里（刚才醒着）时仍然发送。★ 默认 false。"}
	  }
	}`),
	Describe: describeWOL,
	Invoke:   sendWOL,
}

type wolArgs struct {
	MAC      string `json:"mac"`
	Iface    string `json:"iface,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Repeats  int    `json:"repeats,omitempty"`
	SecureOn string `json:"secureOn,omitempty"`
	Force    bool   `json:"force,omitempty"`
}

// describeWOL 批准框里那句话。[OTS-7.2]
//
// ★ 说清**要改动什么**：叫醒哪一台、从哪块网卡、发到哪个地址。
//
//	不写「执行 net.wol」—— 那人看完不知道自己同意了什么。
func describeWOL(raw json.RawMessage) string {
	var a wolArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	target := strings.TrimSpace(a.MAC)
	if mac, err := parseMAC(a.MAC); err == nil && len(mac) == 6 {
		target = formatMAC(mac, ":")
	}
	where := "本机网段的定向广播地址（发送前按网卡算出）"
	if a.Host != "" {
		where = a.Host
	}
	s := fmt.Sprintf("给设备 %s 发 Wake-on-LAN 魔术帧把它唤醒：从网卡 %s 发往 %s",
		target, wolOrUnset(a.Iface, "自动选（邻居表 → 默认路由）"), where)
	if a.Repeats > 1 {
		s += fmt.Sprintf("，连发 %d 枚", a.Repeats)
	}
	if strings.TrimSpace(a.SecureOn) != "" {
		s += "（带 SecureOn 口令，口令本身不会被记录）"
	}
	if a.Force {
		s += "。★ 你勾了「邻居表里有它也照发」：这台机器刚才大概率是醒着的，" +
			"再收一枚魔术帧对部分主机会触发一次开机流程，等于把它重启"
	}
	return s
}

func wolOrUnset(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

func sendWOL(ctx context.Context, raw json.RawMessage) (any, error) {
	var a wolArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	mac, err := wolTargetMAC(a.MAC)
	if err != nil {
		return nil, err
	}
	port := a.Port
	if port == 0 {
		port = wolDefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "port 是 %d，不在 1-65535 之间", port)
	}
	if a.Repeats < 0 || a.Repeats > wolMaxRepeat {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"repeats 只能是 1~%d（不填按 1）—— 一次调用只踹一台机器几下，不许拿它当泛洪", wolMaxRepeat)
	}
	repeats := a.Repeats
	if repeats == 0 {
		repeats = 1
	}
	pass, err := parseWOLPassword(a.SecureOn)
	if err != nil {
		return nil, err
	}
	if journal == nil {
		// ★ 没有账本就不动手：唤醒了哪台、从哪儿发的必须留得下痕
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝动手")
	}

	nics, err := netif.Interfaces()
	if err != nil {
		return nil, ots.Errf(ots.ErrInternal, "读本机网卡失败：%s", err)
	}
	// 自家网卡的地址挡掉：从表里粘错行时这是最常见的拿错对象 —— 给自己发唤醒帧。
	for _, n := range nics {
		m, perr := parseMAC(n.MAC)
		if perr == nil && len(m) == 6 && string(m) == string(mac) {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%s 是你自己网卡 %s 的地址 —— 要唤醒的不是这台机器。回去核对该抄哪一行",
				formatMAC(mac, ":"), n.Name)
		}
	}

	routes, _ := netif.DefaultRoutes() // 「没有默认路由」是要报告的状态，不是读取失败
	neigh := wolNeighbors(ctx)         // 读不到只是少两栏证据，不拦这次发送

	plan, err := wolPlan(nics, routes, neigh, mac, a.Iface, a.Host)
	if err != nil {
		return nil, err
	}

	// ★ 表里还有它 = 刚才醒着。这不是铁证（条目要几分钟才过期），所以判定码是
	//   likely-awake 而不是 awake —— 但默认仍然不发，因为「重启一台正在用的机器」
	//   比「少叫一次」糟得多。
	seen, isSeen := wolSeenAt(neigh, mac)
	if isSeen && !a.Force {
		return ots.Verdict{
			Code: verdictWOLAwake,
			Values: map[string]any{
				"mac": formatMAC(mac, ":"), "seenAt": seen.Addr, "seenIface": seen.Iface,
				// ★ 没发也要把人家的行程说全：本来会从哪块网卡发到哪个地址。
				//   只给「没发」是不完整的回答 —— 人接着要问的就是「那本来会发到哪」。
				"iface": plan.Iface, "ifaceFrom": plan.IfaceFrom, "ifaceKind": plan.Kind,
				"ifaceVirtual": plan.Virtual, "src": plan.Src.String(), "subnet": plan.Src.CIDR(),
				"dst": plan.Dst.String(), "dstKind": plan.DstKind, "needsRelay": plan.NeedsRelay,
				"port": port, "sends": repeats, "sent": 0,
			},
			Note: fmt.Sprintf("%s 此刻在邻居表里（%s 上有它的条目，来自 %s）—— 刚才大概率醒着，没有发送。"+
				"确定它是关着的、还要发，就带 force",
				formatMAC(mac, ":"), plan.Iface, seen.Addr),
		}, nil
	}

	frame := wolFrame(mac, pass)
	sent, cerr := wolCommit(ctx, describeWOL(raw), mac, plan, frame, port, repeats)
	if cerr != nil {
		return nil, cerr
	}

	values := map[string]any{
		"mac":          formatMAC(mac, ":"),
		"iface":        plan.Iface,
		"ifaceFrom":    plan.IfaceFrom,
		"ifaceKind":    plan.Kind,
		"ifaceVirtual": plan.Virtual,
		"src":          plan.Src.String(),
		"subnet":       plan.Src.CIDR(),
		"dst":          plan.Dst.String(),
		"dstKind":      plan.DstKind,
		"needsRelay":   plan.NeedsRelay,
		"port":         port,
		"sends":        repeats,
		"sent":         sent,
		"frameBytes":   len(frame),
		"frame":        wolMagicHex(mac, pass),
		"seenAt":       wolSeenAddr(isSeen, seen),
	}
	if len(pass) > 0 {
		values["passwordUsed"] = true
	}
	code := verdictWOLSent
	if plan.DstKind == wolDstForward {
		code = verdictWOLForwarded
	}
	note := fmt.Sprintf("从 %s（%s）往 %s:%d 发了 %d 枚魔术帧，目标 %s",
		plan.Iface, plan.Src, plan.Dst, port, sent, formatMAC(mac, ":"))
	if plan.NeedsRelay {
		note += " —— ★ 目标地址不在本机任何网段里，这一发要经路由器转发，" +
			"而多数路由器默认丢弃定向广播"
	}
	if !isSeen {
		note += fmt.Sprintf("；发之前 %s 不在邻居表里。过一两分钟再跑一次 net.neighbors，"+
			"它回来了才叫醒了", formatMAC(mac, ":"))
	}
	return ots.Verdict{Code: code, Values: values, Note: note}, nil
}

// wolCommit 先登记、再发、当场了结。[OTS-7.5]
//
// ★ 拆成独立一步，是为了能在**一个包都不发出去**的情况下测到记账 ——
//
//	测试里真发一枚唤醒帧，等于拿别人家的机器当测试床。
func wolCommit(ctx context.Context, what string, mac []byte, plan wolRoute,
	frame []byte, port, repeats int) (int, error) {
	if journal == nil {
		return 0, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝动手")
	}
	id, err := journal.Register("wake-on-lan", what, nil, map[string]any{
		"mac": formatMAC(mac, ":"), "iface": plan.Iface, "dst": plan.Dst.String(), "port": port,
	})
	if err != nil {
		return 0, ots.Errf(ots.ErrInternal, "登记改动失败，没有动手：%s", err)
	}
	sent, serr := wolDispatch(ctx, plan, port, frame, repeats)
	if serr != nil {
		_ = journal.Drop(id, "没发出去："+serr.Error())
		return sent, serr
	}
	_ = journal.MarkApplied(id)
	// ★ 唤醒是一次性的，本机没有因此改变的状态可还原；但这笔账不能挂着 ——
	//   Outstanding() 把 pending / applied 都当成「还在生效」报出去，下次启动的
	//   还原流程会去认领一个不存在的东西。当场了结，留痕照旧在账本里。
	_ = journal.MarkReverted(id, "一次性动作：帧已发出，本机没有需要还原的状态")
	return sent, nil
}

// wolDispatch 真发包那一步。做成 var 只为了测试能换成假装的。
var wolDispatch = wolSend

func wolSeenAddr(ok bool, n neighbor) string {
	if !ok {
		return ""
	}
	return n.Addr
}

// wolTargetMAC 解析并**筛掉不能当唤醒目标的地址**。
//
// ★ 这里不放宽：parseMAC 认 8 字节的 EUI-64（MAC 分析那边邻居表里确实有），
//
//	但魔术帧的载荷里只有 6 字节那一格的位置，拿 8 字节发出去没有设备会认。
func wolTargetMAC(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"没给 mac —— 要唤醒的那台设备网卡的 MAC，写法如 aa:bb:cc:dd:ee:ff")
	}
	mac, err := parseMAC(s)
	if err != nil {
		return nil, err
	}
	canon := formatMAC(mac, ":")
	if len(mac) != 6 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%s 是 %d 字节的 EUI-64：魔术帧里只有 6 字节的位置，这样发出去没有设备会应答。"+
				"要唤醒的是它前 6 字节那块网卡", canon, len(mac))
	}
	switch {
	case allSame(mac, 0x00):
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%s 六个字节全零：这不是一台设备的地址（MAC 没烧进去或没读出来），唤醒帧没有目标", canon)
	case allSame(mac, 0xff):
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%s 是广播地址：整个网段每一台都会被踹一脚，那是无差别开机，不是唤醒一台。这里拒收", canon)
	case mac[0]&0x01 != 0:
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%s 第一个字节最低位是 1，是组播地址，本来就不是一台设备的地址 —— "+
				"从邻居表里粘错一格就会拿到这种（如 33:33:… 是 IPv6 组播）", canon)
	}
	return mac, nil
}

// parseWOLPassword 解 SecureOn 口令。
//
// ★★ 长度校验不是形式主义：标准里只有 4 字节和 6 字节两种，而发错长度的表现是
//
//	「设备一声不吭」—— 那种查一整天的故障，当场拒掉比什么都有用。
//	4 字节那一档低两字节必须是 0（口令要和 MAC 的后 4 字节比对，ether-wake 同样这么校验）。
//	**报错里不回显口令内容**：结果会被发给 AI。
func parseWOLPassword(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	clean := strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(s))
	if len(clean)%2 != 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"secureOn 口令去掉分隔符后是 %d 个字符，不是偶数 —— 十六进制两个字符一个字节", len(clean))
	}
	// ★ 不走 hexBytes：它会把坏掉的那两位原文带进报错，而这一栏的内容是口令
	for i := 0; i < len(clean); i++ {
		if strings.IndexByte("0123456789abcdef", clean[i]) < 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"secureOn 口令第 %d 位不是十六进制字符 —— 口令内容这里不复述", i+1)
		}
	}
	b, err := hexBytes(clean)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "secureOn 口令解不开，内容不复述：%s", err)
	}
	switch len(b) {
	case 4:
		if b[2] != 0 || b[3] != 0 {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"secureOn 给了 4 字节，但这一档要求最后两字节是 00 00（口令要和 MAC 的后 4 字节比对）。"+
					"要么它不是 SecureOn 口令，要么该按 6 字节给 —— 口令内容这里不复述")
		}
	case 6:
	default:
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"secureOn 口令是 %d 字节：只有 4 字节和 6 字节两种合法长度。★ 口令内容这里不复述", len(b))
	}
	return b, nil
}

// wolFrame 拼魔术帧：6×FF + 16×MAC（+ 口令）。
func wolFrame(mac, pass []byte) []byte {
	f := make([]byte, wolSyncBytes+wolRepeats*len(mac)+len(pass))
	for i := 0; i < wolSyncBytes; i++ {
		f[i] = 0xff
	}
	for i := 0; i < wolRepeats; i++ {
		copy(f[wolSyncBytes+i*len(mac):], mac)
	}
	copy(f[wolSyncBytes+wolRepeats*len(mac):], pass)
	return f
}

// wolMagicHex 给界面留一格「发出去的到底是什么」，好和别的工具对拍。
//
// ★ 只编不含口令的那一份，带口令时用省略号收尾 —— 帧形对得上，口令不外泄。
func wolMagicHex(mac, pass []byte) string {
	s := hex.EncodeToString(wolFrame(mac, nil))
	if len(pass) > 0 {
		s += "…"
	}
	return s
}

// wolRoute 一次唤醒「从哪块网卡、以哪个源地址、发到哪个地址」，以及这个选择是怎么来的。
type wolRoute struct {
	Iface      string
	IfaceFrom  string
	Kind       string
	Virtual    bool
	Src        netaddr.Addr
	Dst        netip.Addr
	DstKind    string
	NeedsRelay bool
}

// wolPlan 定出发点和目标地址。**纯函数**：网卡、路由、邻居表都从参数进来 ——
// 这样「多网卡选哪块」「点对点段该拒」能在任何机器上测到，不必真插三块网卡。
func wolPlan(nics []netif.NIC, routes []netif.DefaultRoute, neigh []neighbor,
	mac []byte, wantIface, wantHost string) (wolRoute, error) {

	var p wolRoute
	p.Iface = strings.TrimSpace(wantIface)
	if p.Iface != "" {
		p.IfaceFrom = wolIfaceGiven
	}
	if h := strings.TrimSpace(wantHost); h != "" {
		dst, err := wolHostAddr(h)
		if err != nil {
			return wolRoute{}, err
		}
		p.Dst, p.DstKind = dst, wolDstForward
	}

	if p.Iface == "" {
		// 只有定向广播才有「选网卡」这个问题；填了 host 时按默认路由出即可。
		if p.DstKind == "" {
			if n, ok := wolNeighborIface(neigh, mac); ok {
				p.Iface, p.IfaceFrom = n, wolIfaceNeighbor
			}
		}
		if p.Iface == "" {
			for _, r := range routes {
				if r.Family == "ipv4" && r.Iface != "" {
					p.Iface, p.IfaceFrom = r.Iface, wolIfaceRoute
					break
				}
			}
		}
		// ★ 没有邻居命中也没有默认路由（设备网段常见：那块网卡压根不上外网）。
		//   这时只有**一块**带可用 v4 地址的网卡才敢自动选 —— 两块就列出来让人指，
		//   猜错的代价是叫醒一层楼里另一台。
		if p.Iface == "" {
			var cands []string
			var only string
			for _, n := range nics {
				if n.Loop || n.Virtual {
					continue
				}
				if _, ok := wolUsableV4(n); !ok {
					continue
				}
				cands = append(cands, n.Name)
				only = n.Name
			}
			if len(cands) == 1 {
				p.Iface, p.IfaceFrom = only, wolIfaceOnly
			} else {
				return wolRoute{}, ots.Errf(ots.ErrInvalidArgument,
					"定不出该从哪块网卡发：这个 MAC 不在邻居表里，本机也没有 IPv4 默认路由"+
						"（带可用 IPv4 的网卡有 %s）。用 iface 指定一块，或用 host 直接填目标网段的广播地址",
					strings.Join(wolQuoteAll(cands), "、"))
			}
		}
	}

	var nic *netif.NIC
	for i := range nics {
		if nics[i].Name == p.Iface {
			nic = &nics[i]
			break
		}
	}
	if nic == nil {
		return wolRoute{}, ots.Errf(ots.ErrInvalidArgument,
			"没有叫 %s 的网卡（用 net.interfaces 看有哪些）", p.Iface)
	}
	p.Kind, p.Virtual = nic.Kind, nic.Virtual

	src, ok := wolUsableV4(*nic)
	if !ok {
		return wolRoute{}, ots.Errf(ots.ErrInvalidArgument,
			"%s 上没有能用的 IPv4 地址（169.254 那种「没要到地址」不算）—— 魔术帧是 IPv4/UDP 承载的。"+
				"先给这块网卡配上地址，或换 iface / 用 host 指定发到哪", p.Iface)
	}
	p.Src = src

	if p.DstKind == "" {
		pfx, ok := src.Network()
		if !ok {
			return wolRoute{}, ots.Errf(ots.ErrInvalidArgument,
				"%s 的地址 %s 读不到前缀长度，算不出这个网段的广播地址 —— 用 host 直接填",
				p.Iface, src.CIDR())
		}
		if pfx.Bits() >= 31 {
			// ★ /31、/32 没有广播地址（RFC 3021 的点对点互联口）。硬算会把「它自己」
			//   当广播发出去，表现是「发了没反应」，而这恰恰是没人会怀疑的一步。
			return wolRoute{}, ots.Errf(ots.ErrInvalidArgument,
				"%s 的网段是 %s —— 这么小的段是点对点链路，没有广播地址，定向广播发不出去。"+
					"跨网段唤醒请用 host 填目标网段的广播地址", p.Iface, src.CIDR())
		}
		p.Dst, p.DstKind = lastAddr(pfx), wolDstDirected
	}
	p.NeedsRelay = !wolInLocalNetworks(nics, p.Dst)
	return p, nil
}

func wolQuoteAll(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, "\""+s+"\"")
	}
	return out
}

// wolHostAddr 校验跨网段那一发的目标。
//
// ★★ 255.255.255.255 一律拒。不是它发不出去，是它**从默认路由那块网卡**出去 ——
//
//	而填了 iface 的人以为自己在指定网卡。两个语义撞在一起，最后一定有人被
//	意外吵醒一整层楼。要说清发到哪，就把目标网段的定向广播地址填进来。
func wolHostAddr(s string) (netip.Addr, error) {
	if strings.Contains(s, "%") {
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"host 不需要 zone：魔术帧走 IPv4，%q 里那个 %%en0 是 IPv6 链路本地才用的写法", s)
	}
	if strings.ContainsAny(s, ":[]") {
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"host 要填 IPv4 地址（如目标网段的广播地址 192.168.5.255）：%q 看着像 IPv6 或带了端口。"+
				"IPv6 没有广播地址，v6 网段的唤醒要靠网卡自己的定时唤醒", s)
	}
	a, err := netaddr.Parse(s)
	if err != nil {
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument, "host 不是一个地址：%q —— %s", s, err)
	}
	ip := a.IP.Unmap()
	switch {
	case !ip.Is4():
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument, "host %s 不是 IPv4 地址", ip)
	case ip.String() == "255.255.255.255":
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"host 不要填 255.255.255.255：那一发从默认路由那块网卡出去，和 iface 指定的未必是同一块，"+
				"而且会把那一层楼全吵一遍。唤醒本机网段就别填 host（按网卡算定向广播）；"+
				"跨网段就填目标网段的广播地址")
	case ip.IsMulticast():
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument,
			"host %s 是组播地址：魔术不发到组播组。填目标网段的广播地址或该网段的网关", ip)
	case ip.IsLoopback():
		return netip.Addr{}, ots.Errf(ots.ErrInvalidArgument, "host %s 是本机回环，醒不了别人", ip)
	}
	return ip, nil
}

// wolUsableV4 这块网卡上「能拿去通信」的 v4 地址，判据和 netif.HasUsableV4 一致。
func wolUsableV4(n netif.NIC) (netaddr.Addr, bool) {
	for _, a := range n.Addrs {
		if !a.Is4() {
			continue
		}
		switch a.Scope() {
		case netaddr.ScopePrivate, netaddr.ScopeGlobal:
			return a, true
		}
	}
	return netaddr.Addr{}, false
}

// wolInLocalNetworks 目标地址落不落在本机某块网卡的网段里。
// 不在 = 这一发要靠路由器转发，得说破。
func wolInLocalNetworks(nics []netif.NIC, dst netip.Addr) bool {
	for _, n := range nics {
		for _, a := range n.Addrs {
			if p, ok := a.Network(); ok && p.Contains(dst) {
				return true
			}
		}
	}
	return false
}

// wolNeighbors 读邻居表；读不到给空。它只提供两栏证据（选网卡、在不在表里），
// 少一栏不该拦下这次唤醒。
func wolNeighbors(ctx context.Context) []neighbor {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out []neighbor
	if n, err := neighborsV4(c); err == nil {
		out = append(out, n...)
	}
	if n, err := neighborsV6(c); err == nil {
		out = append(out, n...)
	}
	return out
}

// wolSeenAt 目标 MAC 此刻在不在邻居表里。
//
// ★★ 口径：表里有它 = **刚才**见过它，不等于「现在醒着」—— 一台机器睡下去，
//
//	它的 ARP 条目还要留几分钟到几十分钟才过期。所以判定码是 likely-awake（推测），
//	不是 awake（事实）。手工绑的静态条目更不算：那一格是配置，不是有人应答过。
func wolSeenAt(neigh []neighbor, mac []byte) (neighbor, bool) {
	want := formatMAC(mac, ":")
	for _, n := range neigh {
		if n.MAC == "" || !wolNeighborAlive(n.State) {
			continue
		}
		m, err := parseMAC(n.MAC)
		if err != nil || len(m) != 6 {
			continue
		}
		if formatMAC(m, ":") == want {
			return n, true
		}
	}
	return neighbor{}, false
}

// wolNeighborIface 这个 MAC 是从哪块网卡学到的。
// Windows 的 arp -a 不带接口名，拿不到就交回上层走默认路由 —— 不猜。
func wolNeighborIface(neigh []neighbor, mac []byte) (string, bool) {
	n, ok := wolSeenAt(neigh, mac)
	if !ok || n.Iface == "" {
		return "", false
	}
	return n.Iface, true
}

// wolNeighborAlive 这条邻居记录算不算「有人应答过」。
func wolNeighborAlive(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", "reachable", "stale", "delay", "probe", "dynamic", "动态":
		// ★ stale 也算：它只表示「条目老了但还没判死」，恰恰是「刚才还在」的形态。
		return true
	case "incomplete", "failed", "static", "permanent", "none", "永久", "静态":
		return false
	}
	return true // macOS 的 ndp 给的是 R / S 这类单字母缩写，认不全就留着，界面上原样显示
}

// wolSend 真的发出去。
//
// ★ 绑源地址再发：不绑的话内核自己选出口网卡，用户填的 iface 就成了建议 ——
//
//	笔记本上「填了有线却从 Wi-Fi 出去」就是这么来的。
//	Go 对 UDP socket 自己就置 SO_BROADCAST（各平台都一样），所以这里不需要管理员权限，
//	也不需要 Npcap 那类专有依赖。
func wolSend(ctx context.Context, p wolRoute, port int, frame []byte, repeats int) (int, error) {
	cfg := net.ListenConfig{}
	conn, err := cfg.ListenPacket(ctx, "udp", p.Src.IP.String()+":0")
	if err != nil {
		return 0, ots.Errf(ots.ErrPermissionRequired,
			"以 %s 为源地址在 %s 上开发送口失败：%s", p.Src, p.Iface, err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.IP(p.Dst.AsSlice()), Port: port}
	sent := 0
	for i := 0; i < repeats; i++ {
		if ctx.Err() != nil {
			break // 取消了就不再补发，已经发出去的那几枚如实报
		}
		if _, err := conn.WriteTo(frame, dst); err != nil {
			msg := fmt.Sprintf("从 %s 往 %s 发魔术帧失败：%s", p.Iface, dst, err)
			if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "denied") {
				// Go 已经置过 SO_BROADCAST，走到这里就是系统层面不让 —— 说清该查什么
				msg += "。★ 系统拦住了往广播地址发包：看本机防火墙，或换一块网卡（iface）"
				return sent, ots.Errf(ots.ErrPermissionRequired, "%s", msg)
			}
			return sent, ots.Errf(ots.ErrUnreachable, "%s", msg)
		}
		sent++
		if i < repeats-1 {
			select {
			case <-ctx.Done():
			case <-time.After(wolGap):
			}
		}
	}
	return sent, nil
}
