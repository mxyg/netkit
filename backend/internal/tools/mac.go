package tools

// ── net.mac.analyze ──
//
// ★★ MAC 这一栏现场问的不是「它是谁」，是**「这个地址能不能当设备身份用」**。
//
//	拿着 MAC 去认设备有四条岔路，走错了后面每一步都白干：
//	1. 全零 —— 设备根本没烧 MAC，或驱动没读出来。这时查厂商必然查不到，
//	   而人会以为「厂商库缺这一条」，接着换库、换工具，其实该去查那块网卡
//	2. 组播位为 1（`01:…`、`33:33:…`、`ff:…`）—— **这压根不是某台设备的地址**，
//	   是发给一组地址的。从邻居表里粘错一格就会拿到这种
//	3. 本机管理位被置（`02:`、`52:`、`da:`…）—— 地址**不是厂商发的**：iOS / Android 的
//	   私有 Wi-Fi 地址、Windows 随机 MAC、MAC 克隆、虚拟机网卡都在这一类。
//	   拿它当设备唯一标识的后果是**同一台设备每次连上都变成新设备**，
//	   「这台设备掉线几次」的统计跟着一起废
//	4. 剩下才是真厂商地址 —— 而厂商名要查 IEEE 注册表，那张表是 CC BY-NC-SA（不许商用分发），
//	   所以**安装包不带全量表**：自带的只有几条能指名道姓说清出处的约定前缀（协议 / 虚拟化 / 容器），
//	   剩下的如实说「要厂商名得挂你自己下载的表」，并给出怎么挂
//
// ★ 判定按「能不能当身份」分档，不按「认不认识厂商」分：认不出厂商名不影响这个地址是好身份；
//
//	反过来，一眼认出 `02:42:` 是 Docker 恰恰说明它**不能**当硬件身份 —— 它是软件造出来的。
//	把「查到名字」当成这一栏的成败，就会为了显得有结果而把推测写成事实。

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"net.yuhox.com/netkit/internal/ots"
)

const (
	macUnset     = "mac-unset"            // 全零：没烧 MAC / 没读到
	macBroadcast = "mac-broadcast"        // 全一：只用于发，不许当源地址
	macGroup     = "protocol-group"       // 组播：不是某台设备的地址
	macVirtual   = "virtual-nic"          // 命中已知虚拟化 / 容器约定前缀（★ 推测）
	macLocal     = "locally-administered" // 本机管理位：不是厂商地址，别当身份
	macDevice    = "device-address"       // 厂商发的单播地址，可以当身份
)

// ouiFileEnvVar 操作者自备的厂商表路径。
//
// ★★ 走环境变量而不是入参：入参等于让 AI（或任何调 API 的一方）读本机任意文件，
//
//	而这张表是部署时决定一次的事，不该出现在每次调用里。
const ouiFileEnvVar = "NETKIT_OUI_FILE"

var macAnalyzeTool = ots.Tool{
	Name:  "net.mac.analyze",
	Class: ots.ClassRead,
	Summary: "问一个 MAC / 以太网地址的来路：写法归一、组播还是单播、厂商发的还是软件造的，" +
		"命中已知虚拟化前缀时点名是谁（QEMU / Docker / VMware / Xen / Hyper-V），" +
		"Docker 网桥地址能从后四字节反推出容器的 IPv4，并给出对应的 IPv6 接口标识（EUI-64）。" +
		"★ 顶层判定说的是**这个地址能不能当设备身份用**：" +
		"mac-unset（全零，设备没烧 MAC 或驱动没读到）、mac-broadcast（全一，只用于发）、" +
		"protocol-group（组播，本来就不是一台设备）、virtual-nic（几乎肯定是虚机或容器，属推测）、" +
		"locally-administered（本机管理位置着 → 不是厂商发的地址，同一台设备每次可能换一个）、" +
		"device-address（厂商发的单播地址，可以当身份）。" +
		"★ 厂商名默认不报：IEEE 的注册表是 CC BY-NC-SA，不能打进安装包；要把这一栏填上，" +
		"把环境变量 NETKIT_OUI_FILE 指到你从 ieee.org 下的 oui.txt。纯解析，不发任何包。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "mac": {"type": "string",
	      "description": "要问的 MAC / 以太网地址。写法都认：02:42:ac:11:00:02、02-42-ac-11-00-02、0242.ac11.0002（交换机写法）、0242ac110002（连写），大小写不分。8 字节的 EUI-64 也认。"}
	  },
	  "required": ["mac"]
	}`),
	Invoke: doMACAnalyze,
}

type macArgs struct {
	MAC string `json:"mac"`
}

// macPrefix 一条「我们敢指名道姓」的前缀。
//
// ★★ 这里**不放 IEEE 注册表里的厂商**：那张表是 CC BY-NC-SA，商业分发不合规，
//
//	抄几条进来同样是复制受许可保护的内容。放的是两类能自己说清出处的东西：
//	1. 协议规定的组播 / 保留地址 —— 事实来自公开的 RFC 与 802 标准，出处写标准号
//	2. 软件自己约定的前缀 —— 出处是那个软件自己的默认行为。这类必须标 kind=convention：
//	   它是「看着像」，不是登记，界面上归「推测」那一栏
type macPrefix struct {
	prefix []byte
	name   string
	kind   string // protocol | convention
	src    string
	why    string
}

var macPrefixes = []macPrefix{
	{prefix: hx("01:00:5e"), name: "IPv4 组播（IGMP）", kind: "protocol", src: "RFC 1112",
		why: "这是路由器在问「谁要收组播」，不是一台设备。问厂商没意义，问它从哪个口进来有意义"},
	{prefix: hx("33:33"), name: "IPv6 组播（NDP / MLD）", kind: "protocol", src: "RFC 4291",
		why: "RS / RA / NS / NA 都发到这里。链路上看到它只说明 v6 在动，不说明来了一台新设备"},
	{prefix: hx("01:80:c2"), name: "桥接组地址（STP / BPDU / 802.1X）", kind: "protocol", src: "IEEE 802.1D",
		why: "交换机自己的协议帧，标准规定**不许转发**，所以能收到就说明设备就在本地这一段"},
	{prefix: hx("01:00:0c:cc"), name: "Cisco 二层协议（CDP / VTP / DTP）", kind: "protocol", src: "厂商公开文档",
		why: "交换机在报「我是谁、我哪个口、邻居是谁」—— 问邻居关系时这一条比 SNMP 直接。" +
			"★ 目的地是 `01:00:0c:cc:cc:cc`（组播位在那儿），别把它当成一台 Cisco 设备"},
	{prefix: hx("52:54:00"), name: "QEMU / KVM 虚拟网卡", kind: "convention", src: "QEMU 默认地址段",
		why: "几乎肯定是虚机或容器宿主。★ 本机管理位本来就是置着的，它天生不带厂商身份"},
	{prefix: hx("02:42"), name: "Docker 网桥网卡", kind: "convention", src: "Docker libnetwork 默认地址段",
		why: "后四字节通常就是容器拿到的 IPv4，这里已经顺手反推出来了"},
	{prefix: hx("00:0c:29"), name: "VMware 虚拟机（Workstation / ESXi 客户机）", kind: "convention", src: "VMware 默认地址段",
		why: "看着像硬件其实是虚机。按 MAC 做接入策略时，它随虚机迁移、快照回滚而变"},
	{prefix: hx("00:50:56"), name: "VMware ESXi 自身（vmklinux）", kind: "convention", src: "VMware 默认地址段",
		why: "宿主机的服务端口（管理 / vMotion / NFS），不是它上面跑的访客虚机"},
	{prefix: hx("00:16:3e"), name: "Xen 虚拟网卡", kind: "convention", src: "Xen 默认地址段",
		why: "虚机"},
	{prefix: hx("00:15:5d"), name: "Hyper-V 虚拟网卡", kind: "convention", src: "微软公开文档",
		why: "虚机。★ 在 Windows 上「两块网卡 MAC 一样」常常是把虚拟交换机地址和物理地址混着看了"},
}

func doMACAnalyze(ctx context.Context, raw json.RawMessage) (any, error) {
	var a macArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if strings.TrimSpace(a.MAC) == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"mac 不能是空的 —— 写法如 02:42:ac:11:00:02、02-42-ac-11-00-02、0242.ac11.0002、0242ac110002")
	}
	mac, err := parseMAC(a.MAC)
	if err != nil {
		return nil, err
	}
	values := macFacts(a.MAC, mac)
	code := macRead(mac, values)
	return ots.Verdict{Code: code, Values: values, Note: macNote(code, values)}, nil
}

// macFacts 一个 MAC 的全部读法。
//
// ★★ group 和 administered 必须**分开给**，不许并成一个「类型」：
//
//	`02:…` 是本机管理 + 单播（Docker、手机私有地址），`01:…` 是全局 + 组播（协议地址）。
//	合成一栏就会有人以为「组播 = 随机地址」，那是两件不相干的事。
func macFacts(given string, mac []byte) map[string]any {
	first := mac[0]
	admin := "global"
	if first&0x02 != 0 {
		admin = "local"
	}
	out := map[string]any{
		"input":         strings.TrimSpace(given),
		"canonical":     formatMAC(mac, ":"),
		"dashForm":      formatMAC(mac, "-"),
		"dotForm":       formatDotMAC(mac),
		"bareForm":      formatMAC(mac, ""),
		"octets":        len(mac),
		"family":        "mac-48",
		"firstOctet":    fmt.Sprintf("%02x", first),
		"firstOctetBin": fmt.Sprintf("%08b", first),
		"group":         first&0x01 != 0,
		"individual":    first&0x01 == 0,
		"administered":  admin,
	}
	if len(mac) == 8 {
		out["family"] = "eui-64"
	}
	if len(mac) >= 6 {
		// ★ 前段 / 后段分开给：两台设备「MAC 很像」时要说的是像在哪半截 ——
		// 前 3 段相同只说明同厂商，后 3 段也相同才可能是克隆或地址冲突
		out["oui"] = formatMAC(mac[:3], ":")
		out["nic"] = formatMAC(mac[3:], ":")
	}
	switch {
	case allSame(mac, 0x00):
		out["special"] = "all-zero"
	case allSame(mac, 0xff):
		out["special"] = "all-one"
	}
	// ★ 组播地址不配 IID：`33:33:…` 推出来的接口标识没有任何意义，
	// 但它长得像真的，会让人拿它去对 NDP 表。全零 / 全一同理。
	if first&0x01 == 0 && out["special"] == nil {
		if iid, ok := eui64IID(mac); ok {
			out["iid"] = iid
		}
	}
	if ip, ok := derivedIPv4(mac); ok {
		out["derivedIPv4"] = ip
	}
	return out
}

// macRead 填上「这是谁 / 为什么这么判」并给出判定码。
func macRead(mac []byte, v map[string]any) string {
	first := mac[0]
	p, matched := matchPrefix(mac)
	if matched {
		v["who"] = p.name
		v["whoKind"] = p.kind
		v["whoSrc"] = p.src
		v["whoWhy"] = p.why
		// 协议地址的出处是标准文本，是**事实**；软件约定是**推测**，两条不许混成一栏
		v["whoBasis"] = map[string]string{"protocol": "standard", "convention": "guess"}[p.kind]
	}
	switch {
	case allSame(mac, 0x00):
		return macUnset
	case allSame(mac, 0xff):
		return macBroadcast
	case first&0x01 != 0:
		return macGroup
	case matched && p.kind == "convention":
		return macVirtual
	case first&0x02 != 0:
		return macLocal
	}
	// 厂商地址：能报的名字只可能来自操作者自备的表
	name, src, ok := lookupVendor(mac)
	if ok {
		v["who"] = name
		v["whoKind"] = src
		v["whoBasis"] = "registry"
		v["whoWhy"] = "来自你挂上的厂商表，按前 3 字节（MA-L，24 位）匹配。" +
			"IEEE 另有 32 / 40 位前缀的 MA-M / MA-S，它们的前 3 字节可能和别家撞，" +
			"所以这一栏是「多半是这家」，不是「确定」"
	} else {
		v["vendorWhy"] = ouiWhy()
	}
	return macDevice
}

func ouiWhy() string {
	t := loadOUI()
	if t.err == "" && t.entries > 0 {
		return fmt.Sprintf("你挂的表（%s）里没有这个前缀，一共 %d 条", t.path, t.entries)
	}
	return "厂商名要查 IEEE 的注册表，而那张表是 CC BY-NC-SA（非商业许可），" +
		"所以安装包不带它。你从 ieee.org 下载 oui.txt 后，" +
		"把 netkitd 的环境变量 NETKIT_OUI_FILE 指到那个文件，这一栏就有名字了"
}

// eui64IID 按 RFC 4291 从 6 字节 MAC 推出 IPv6 接口标识。
//
// ★ 中间插 ff:fe，再把第一个字节的第 2 低位**取反**。是「翻转」不是「置 1」：
//
//	IEEE 802 的地址那一位是 0，IPv6 侧要求是 1，所以取反；从本机管理的 MAC 推时
//	反过来会变成 0 —— 这符合 RFC，但人常当成 bug，所以注释钉在这。
func eui64IID(mac []byte) (string, bool) {
	var b []byte
	switch len(mac) {
	case 6:
		b = append(append(append([]byte{}, mac[:3]...), 0xff, 0xfe), mac[3:]...)
	case 8:
		b = append([]byte{}, mac...)
	default:
		return "", false
	}
	b[0] ^= 0x02
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]), true
}

// derivedIPv4 Docker 网桥地址里藏着容器的 IPv4：02:42 + 四个地址字节。
//
// ★ 只在 6 字节且前缀正好是 02:42 时才给。别的软件也用本机管理段，
//
//	照着「后四字节当地址」去推会推出一个看着像真的的假地址。
func derivedIPv4(mac []byte) (string, bool) {
	if len(mac) != 6 || mac[0] != 0x02 || mac[1] != 0x42 {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", mac[2], mac[3], mac[4], mac[5]), true
}

func allSame(mac []byte, b byte) bool {
	for _, x := range mac {
		if x != b {
			return false
		}
	}
	return true
}

func formatMAC(mac []byte, sep string) string {
	parts := make([]string, 0, len(mac))
	for _, b := range mac {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, sep)
}

// formatDotMAC 交换机写法：每四位一组，如 0242.ac11.0002。
func formatDotMAC(mac []byte) string {
	s := formatMAC(mac, "")
	var parts []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, ".")
}

func hx(s string) []byte {
	b, err := hexBytes(strings.NewReplacer(":", "", "-", "", ".", "").Replace(s))
	if err != nil {
		panic("macPrefixes 里写了非法十六进制: " + s)
	}
	return b
}

// hexBytes 纯十六进制串转字节，报错说清是第几位。
func hexBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("长度是 %d 个字符，不是偶数", len(s))
	}
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("第 %d~%d 位 %q 不是十六进制", i+1, i+2, s[i:i+2])
		}
		out = append(out, byte(v))
	}
	return out, nil
}

// parseMAC 宽进严出：现场几种写法都认，认不出的说清为什么。
//
// ★★ 混用分隔符直接拒。理由不是洁癖 —— 从 `arp -a`、交换机 CLI、设备标签上抄下来的
//
//	地址各是一个格式，混写通常意味着**两行被粘成了一行**，那正是查错设备的开头。
func parseMAC(s string) ([]byte, error) {
	text := strings.Trim(strings.TrimSpace(s), "\"'[]")
	if text == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "mac 不能是空的")
	}
	if looksLikeIPv4(text) {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%q 是 IPv4 地址的写法，不是 MAC。MAC 是 6 组两位十六进制（如 02:42:ac:11:00:02）", text)
	}
	sep := ""
	for _, c := range text {
		if c != ':' && c != '-' && c != '.' && c != ' ' && c != '_' {
			continue
		}
		if sep == "" {
			sep = string(c)
		} else if string(c) != sep {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%q 里混了两种分隔符（%s 和 %c）—— 多半是两行地址粘成了一行", text, sep, c)
		}
	}
	clean := text
	if sep != "" {
		clean = strings.ReplaceAll(text, sep, "")
	}
	clean = strings.ToLower(clean)
	if len(clean) != 12 && len(clean) != 16 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"%q 去掉分隔符后是 %d 个字符：MAC 要 12 个（6 字节），EUI-64 是 16 个。"+
				"认得的写法：02:42:ac:11:00:02、02-42-ac-11-00-02、0242.ac11.0002、0242ac110002",
			text, len(clean))
	}
	mac, err := hexBytes(clean)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%q %s", text, err)
	}
	return mac, nil
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// matchPrefix 在自带前缀表里找**最长**匹配。
//
// ★ 最长匹配：`00:00:0c:cc`（4 字节）必须赢过任何 3 字节的 `00:00:0c`，
//
//	否则就会拿一个更宽的前缀去命名一个更具体的地址。
func matchPrefix(mac []byte) (macPrefix, bool) {
	var best macPrefix
	found := false
	for _, p := range macPrefixes {
		n := len(p.prefix)
		if n > len(mac) {
			continue
		}
		if string(mac[:n]) == string(p.prefix) && (!found || n > len(best.prefix)) {
			best, found = p, true
		}
	}
	return best, found
}

// ── 操作者自备的厂商表 ──

type ouiTable struct {
	path    string
	entries int
	by24    map[string]string
	err     string
}

var (
	ouiOnce  sync.Once
	ouiCache *ouiTable
)

// loadOUI 读 IEEE 格式的 oui.txt（也吃 nmap 那类一行 6 位hex 的表）。
//
// ★★ 做成 var 是为了测试能换掉：不换就得真造一个文件才走得到「有表」那条路，
//
//	而「有表」和「没表」给的是两种完全不同的答案。
var loadOUI = func() *ouiTable {
	ouiOnce.Do(func() { ouiCache = readOUIFile(os.Getenv(ouiFileEnvVar)) })
	return ouiCache
}

func readOUIFile(path string) *ouiTable {
	t := &ouiTable{path: strings.TrimSpace(path), by24: map[string]string{}}
	if t.path == "" {
		t.err = "没挂厂商表"
		return t
	}
	f, err := os.Open(t.path)
	if err != nil {
		t.err = fmt.Sprintf("打不开 %s：%s", t.path, err)
		return t
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 32<<20 {
		t.err = fmt.Sprintf("%s 有 %d 字节，不像 oui.txt，不读", t.path, st.Size())
		return t
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		pfx, name, ok := parseOUILine(sc.Text())
		if !ok {
			continue
		}
		// ★ 同一个前缀在 IEEE 的文件里会出现两遍（一条 (hex)、一条 (base 16)）。
		// 只认第一条：后一条不是更正，是重复。
		if _, dup := t.by24[pfx]; !dup {
			t.entries++
			t.by24[pfx] = name
		}
	}
	if e := sc.Err(); e != nil {
		t.err = e.Error()
	}
	return t
}

// parseOUILine 认两种行：
//
//	AC-DE-48   (hex)\t\tCompany Name      IEEE 官网原样
//	ACDE48 Company Name                     nmap 的 mac-prefixes 那类
func parseOUILine(line string) (string, string, bool) {
	text := strings.TrimSpace(line)
	if text == "" || strings.HasPrefix(text, "#") {
		return "", "", false
	}
	head, name := text, ""
	if i := strings.Index(text, "(hex)"); i >= 0 {
		head = strings.TrimSpace(text[:i])
		name = strings.TrimSpace(text[i+len("(hex)"):])
	} else {
		fields := strings.SplitN(text, " ", 2)
		head = fields[0]
		if len(fields) == 2 {
			name = strings.TrimSpace(fields[1])
		}
	}
	head = strings.NewReplacer("-", "", ":", "", ".", "", " ", "").Replace(head)
	if len(head) != 6 {
		return "", "", false
	}
	if _, err := hexBytes(head); err != nil {
		return "", "", false
	}
	if name == "" {
		return "", "", false
	}
	k := strings.ToLower(head[:2] + ":" + head[2:4] + ":" + head[4:])
	return k, name, true
}

func lookupVendor(mac []byte) (string, string, bool) {
	if len(mac) < 3 {
		return "", "", false
	}
	t := loadOUI()
	if t == nil || len(t.by24) == 0 {
		return "", "", false
	}
	name, ok := t.by24[formatMAC(mac[:3], ":")]
	return name, "registry", ok
}

func macNote(code string, v map[string]any) string {
	who, _ := v["who"].(string)
	canon, _ := v["canonical"].(string)
	switch code {
	case macUnset:
		return fmt.Sprintf("**%s 不是一个设备的地址**：六个字节全零。要么这台设备的 MAC 没烧进去，"+
			"要么驱动没把 MAC 读上来。先去查网卡本身，别再拿它去查厂商 —— 查不到不是库的问题", canon)
	case macBroadcast:
		return fmt.Sprintf("**%s 是广播地址**：只能用来发，不许配成任何设备的源地址", canon)
	case macGroup:
		if who != "" {
			return fmt.Sprintf("%s 是组播地址（%s，出处 %s）—— %s", canon, who, v["whoSrc"], v["whoWhy"])
		}
		return fmt.Sprintf("%s 第一个字节 %s 的最低位是 1，说明它是**组播地址**，不是一台设备的地址。"+
			"它出现在邻居表里通常是协议帧被顺手记下来了", canon, v["firstOctet"])
	case macVirtual:
		return fmt.Sprintf("%s 命中 %s 的默认地址段（%s）—— %s。★ 这是**推测**，不是登记信息",
			canon, who, v["whoSrc"], v["whoWhy"])
	case macLocal:
		return fmt.Sprintf("%s 的本机管理位（第一个字节 %s 的第 2 低位）是置着的：这个地址**不是厂商发的**。"+
			"手机私有 Wi-Fi 地址、随机 MAC、MAC 克隆都在这里。**别拿它当设备唯一标识** —— "+
			"同一台设备换了网络可能就换一个，用它做统计会把一台数成好几台", canon, v["firstOctet"])
	case macDevice:
		if who != "" {
			return fmt.Sprintf("%s 是厂商发的单播地址，可以当设备身份。厂商：多半是 %s（按前 3 字节查你挂的表）", canon, who)
		}
		return fmt.Sprintf("%s 是厂商发的单播地址，可以当设备身份。%s", canon, v["vendorWhy"])
	}
	return ""
}
