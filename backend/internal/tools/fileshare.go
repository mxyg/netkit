package tools

// ── net.fileshare.serve / .status / .stop ──
//
// 把本机一个目录开成**只读**的 HTTP 共享，给设备升级固件、给交换机回传配置文件用。
//
// ★ 为什么这一张要 mutate + 点头：它改的不是本机的配置，而是**这台机器对外的可见面**——
//
//	一开就是「同一网段任何设备不必登录就能把这个目录整个读走」。
//	这类改动最坏的情况是长期忘了关：现场把整台机器的主目录当固件目录开一下午，
//	这种事在别的工具里出过。所以每次启动都要有人看一眼批准说明，并且记一笔账。
//
// ★ 为什么只读：设备只要「取」。一旦允许上传，本机就成了任意人可写的盘，
//
//	而这个功能的使用场景（对着几十台设备的升级页面）恰好让「谁传了什么」无从追究。
//	写路径在这个包里一律不存在：HTTP 只接 GET/HEAD，不是「鉴权后允许写」。
//
// ★ 为什么不绑 0.0.0.0：那等于把目录从**所有**网卡上开放出去 ——
//
//	多网卡工控机上，另一块口连着办公网甚至公网。这里必须按网卡挑地址，
//	一个地址一个监听器，并且地址是谁、开在哪个口，全都在批准说明里。
//
// 凭据：结果里只有目录路径、地址、端口和取文件的记录（对端 IP + 文件名）。
// 目录里有什么内容不会被读进结果。

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/filesrv"
	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

const (
	verdictShareServing = "share-serving"
	verdictShareStopped = "share-stopped"
	verdictShareIdle    = "share-idle"
)

const fileshareDefaultPort = 8080

// 两个读取口走变量：测试因此不必真的有一块网卡，也不去看这台机器的默认路由。
var (
	fileshareNICs   = netif.Interfaces
	fileshareRoutes = netif.DefaultRoutes
)

// fileshare 当前在跑的共享。全场只允许一个：
// ★ 两个共享的界面要让人分清「停的是哪个」，而这件事在现场一定出错。
var fileshare = struct {
	mu      sync.Mutex
	srv     *filesrv.Server
	entryID string
	// ★ 开成功那一刻的事实要跟着 status 一起回：界面上的台账每 3 秒自己刷一次，
	//   只带地址和计数器的话，刷一次之后「开在哪块口、这口怎么挑中的、
	//   目录里那个 id_rsa 还挂着」全都没了 —— 而这些正是人决定
	//   「要不要现在就停掉」的依据，不能只活三秒。
	plan filesharePlan
}{mu: sync.Mutex{}}

type fileshareArgs struct {
	Root    string   `json:"root"`
	Iface   string   `json:"iface,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
	Port    int      `json:"port,omitempty"`
	Listing *bool    `json:"listing,omitempty"`
}

var fileshareServeTool = ots.Tool{
	Name:  "net.fileshare.serve",
	Class: ots.ClassMutate,
	Summary: "把本机一个目录开成**只读**的 HTTP 共享，给设备填固件下载地址用" +
		"（设备的升级页面要一个 http://…/xxx.bin，就是这个）。\n" +
		"★ 只读：只接 GET/HEAD，不收上传，改不了也删不了本机任何文件。\n" +
		"★ 只绑指定网卡上的地址，绝不绑 0.0.0.0 —— 多网卡机器上那等于把目录从办公网/公网口也开出去。\n" +
		"不填 iface 就按 IPv4 默认路由那块网卡挑；挑中了会在结果里说清是哪块、哪些地址、开在哪个端口。\n" +
		"结果里带目录里有多少个条目、多大，以及**目录里有疑似密钥文件时的提醒**（很多人顺手把整个用户目录端出来）。\n" +
		"同一时刻只允许一个共享。用完请调 net.fileshare.stop 停掉：这是无鉴权的，同网段谁都能读。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["root"],
	  "properties": {
	    "root": {"type": "string", "description": "要共享出去的目录（绝对路径）。★ 这个目录里的东西同网段都能读，只放固件/配置这类本来就要发的文件。"},
	    "iface": {"type": "string", "description": "开在哪块网卡（en0 / eth0 / WLAN）。不填按 IPv4 默认路由那块；只有一块可用网卡时用它。"},
	    "addrs": {"type": "array", "items": {"type": "string"},
	      "description": "直接指定绑哪些地址（覆盖 iface）。★ 不接受 0.0.0.0 / :: —— 那是要绕开按网卡挑地址这条线，请改成填 iface。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "端口，默认 8080。1024 以下要更高权限，起不来会直说。设备固件页面写死了 80 就填 80。"},
	    "listing": {"type": "boolean",
	      "description": "开不开目录列表，默认 true。开着=设备/人能翻文件名（固件版本号本身也是信息）；关掉就只能知道完整文件名才取到走。现场图快一般开着，要收口就关掉。"}
	  }
	}`),
	Describe: describeFileShare,
	Invoke:   serveFileShare,
}

var fileshareStatusTool = ots.Tool{
	Name:  "net.fileshare.status",
	Class: ots.ClassRead,
	Summary: "看本机现在有没有在开文件共享：目录、开在哪些地址和端口、" +
		"已经被取走多少、以及**最近谁在什么时间取走了哪个文件**（含传到一半断掉的那些）。\n" +
		"★ 排查「设备说下载失败」就看这一张：有没有人来取过、取到第几字节断的，" +
		"分得清是网断了、地址填错了、还是根本没来取。",
	Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Invoke: statusFileShare,
}

var fileshareStopTool = ots.Tool{
	Name:    "net.fileshare.stop",
	Class:   ots.ClassMutate,
	Summary: "停掉本机的文件共享。停了之后那些地址就读不到这个目录了；已经下载到设备里的文件不受影响。",
	Schema:  json.RawMessage(`{"type":"object","additionalProperties":false}`),
	Describe: func(json.RawMessage) string {
		return "停掉本机的文件共享（同一网段不再能读这个目录）"
	},
	Invoke: stopFileShare,
}

// ── 批准说明 [OTS-7.2] ──

// describeFileShare 要把**会改成什么**说到人能拍板：哪个目录、开在哪些地址、
// 谁能读、能不能写。
//
// ★ 这里尽量把网卡**当场算出来**写进句子：批准的人要是只看到「自动选网卡」，
// 他其实不知道自己是同意把目录开到哪块口上 —— 而那块口可能正连着办公网。
func describeFileShare(raw json.RawMessage) string {
	var a fileshareArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	root := a.Root
	if root == "" {
		root = "（没给目录）"
	} else if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	plan, err := planFileShare(a)
	port := a.Port
	if port == 0 {
		port = fileshareDefaultPort
	}
	s := fmt.Sprintf("把目录 %s 开成只读 HTTP 共享（不能上传、不能改），端口 %d", root, port)
	switch {
	case err != nil:
		s += fmt.Sprintf("；网卡没定下来：%s", err)
	case plan.iface == "":
		s += "；绑在这些地址上：" + strings.Join(plan.addrs, "、")
	default:
		s += fmt.Sprintf("；开在网卡 %s 上（%s），绑 %s",
			plan.iface, plan.ifaceWhy, strings.Join(plan.addrs, "、"))
	}
	if len(plan.warnings) > 0 {
		s += "。★ " + strings.Join(plan.warnings, "；")
	}
	return s
}

// ── 参数化成一份可执行的计划 ──

type filesharePlan struct {
	root     string
	entries  int
	dirs     int
	bytes    int64
	secrets  []string
	addrs    []string
	iface    string
	ifaceWhy string // 界面和批准说明都要说清是怎么定的（同 net.wol 的 ifaceFrom）
	port     int
	listing  bool
	warnings []string
}

func planFileShare(a fileshareArgs) (filesharePlan, error) {
	var p filesharePlan
	p.port = a.Port
	if p.port == 0 {
		p.port = fileshareDefaultPort
	}
	p.listing = a.Listing == nil || *a.Listing

	if strings.TrimSpace(a.Root) == "" {
		return p, ots.Errf(ots.ErrInvalidArgument, "没给要共享的目录")
	}
	abs, err := filepath.Abs(a.Root)
	if err != nil {
		return p, ots.Errf(ots.ErrInvalidArgument, "这个目录路径看不懂：%s", err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		// ★ 说「打不开」不说「不存在」：权限不够时两者长得一样，
		//   而该做的下一步完全不同（一个是去建目录，一个是去改权限）。
		return p, ots.Errf(ots.ErrInvalidArgument, "打不开这个目录：%s", err)
	}
	if !fi.IsDir() {
		return p, ots.Errf(ots.ErrInvalidArgument, "%s 不是目录", abs)
	}
	if filepath.Clean(abs) == string(filepath.Separator) {
		// 整盘端出去没有可用的现场场景：列出来的全是系统文件，
		// 而设备要的那个固件反而埋在几十行里。这一条直接拒，不靠人点头兜底。
		return p, ots.Errf(ots.ErrInvalidArgument,
			"不接受把整个根目录（%s）共享出去：只共享放固件的那个目录", abs)
	}
	p.root = abs

	n, d, total, secrets, err := surveyDir(abs)
	if err != nil {
		return p, ots.Errf(ots.ErrInvalidArgument, "看这个目录里有什么时出错：%s", err)
	}
	p.entries, p.dirs, p.bytes, p.secrets = n, d, total, secrets
	if len(secrets) > 0 {
		// ★ 这条必须在**批准说明**里，不能只写在结果里：点批准的人要当场看见
		//   「这个目录里有 id_rsa / .env，它们同样会被下载」，
		//   否则他点的是「共享一个固件目录」，实际放行的是「把这台机器的密钥挂到网上」。
		p.warnings = append(p.warnings, fmt.Sprintf(
			"目录里有 %d 个文件名看着像密钥（%s），它们同样能被下载",
			len(secrets), strings.Join(secrets, "、")))
	}

	nics, err := fileshareNICs()
	if err != nil {
		return p, ots.Errf(ots.ErrInternal, "读网卡列表失败：%s", err)
	}

	// 显式给了地址：只用给的这些，但仍然按地址性质给提醒。
	if len(a.Addrs) > 0 {
		var pub []string
		for _, x := range a.Addrs {
			x = strings.TrimSpace(x)
			if x == "" {
				continue
			}
			if x == "0.0.0.0" || x == "::" || x == "*" {
				return p, ots.Errf(ots.ErrInvalidArgument,
					"不接受绑 %s：那会把目录从本机所有网卡上开放出去，包括可能连着的办公网和公网。改成填 iface", x)
			}
			ad, perr := netaddr.Parse(x)
			if perr != nil {
				return p, ots.Errf(ots.ErrInvalidArgument, "%q 不是一个地址", x)
			}
			if !ad.IP.IsValid() {
				return p, ots.Errf(ots.ErrInvalidArgument, "%q 不是一个可用地址", x)
			}
			pub = append(pub, x)
			if ad.Scope() == netaddr.ScopeGlobal {
				p.warnings = append(p.warnings, fmt.Sprintf("%s 是公网可路由地址，这个目录等于对互联网开着", x))
			}
		}
		if len(pub) == 0 {
			return p, ots.Errf(ots.ErrInvalidArgument, "addrs 里没有有效地址")
		}
		p.addrs, p.iface, p.ifaceWhy = pub, "", "你直接给的地址"
		return p, nil
	}

	byName := map[string]netif.NIC{}
	for _, n := range nics {
		byName[n.Name] = n
	}

	var pick *netif.NIC
	switch {
	case a.Iface != "":
		n, ok := byName[a.Iface]
		if !ok {
			return p, ots.Errf(ots.ErrInvalidArgument,
				"没有叫 %s 的网卡（用 net.interfaces 看有哪些）", a.Iface)
		}
		pick = &n
		p.ifaceWhy = "你指定的网卡"
	default:
		cand, why, err := defaultShareNIC(nics)
		if err != nil {
			return p, err
		}
		pick = cand
		p.ifaceWhy = why
	}

	addrs := shareAddrs(*pick)
	if len(addrs) == 0 {
		return p, ots.Errf(ots.ErrInvalidArgument,
			"%s 上没有一个可用的地址（要有私网或公网地址；169.254 那种自动私有地址不能当共享地址）",
			pick.Name)
	}
	p.iface = pick.Name
	p.addrs = addrs
	for _, x := range addrs {
		if ad, err := netaddr.Parse(x); err == nil && ad.Scope() == netaddr.ScopeGlobal {
			p.warnings = append(p.warnings,
				fmt.Sprintf("%s（%s 上）是公网可路由地址，这个目录等于对互联网开着", x, pick.Name))
		}
	}
	return p, nil
}

// shareAddrs 这块网卡上能拿来绑定的地址：v4 在前（设备的固件页面几乎只填 v4），
// 再给 v6 的 ULA / 全局地址。
//
// ★ 刻意不给链路本地地址：设备不会照着 fe80::…%en0 去填升级地址，
//
//	带上它只会让界面多一栏没人看得懂的地址，还要人猜 zone 写哪。
func shareAddrs(n netif.NIC) []string {
	var v4, v6 []string
	for _, ad := range n.Addrs {
		switch ad.Scope() {
		case netaddr.ScopePrivate:
			if ad.Is4() {
				v4 = append(v4, ad.IP.String())
			} else {
				v6 = append(v6, ad.IP.String())
			}
		case netaddr.ScopeGlobal:
			if ad.Is4() {
				v4 = append(v4, ad.IP.String())
			} else {
				v6 = append(v6, ad.IP.String())
			}
		}
	}
	return append(v4, v6...)
}

// defaultShareNIC：默认路由那块 → 全场只有一块带可用 v4 的网卡 → 列候选让人指。
//
// ★★ 和 net.wol 的选网卡同一个纪律：**只有一块才敢自动选**。
//
//	两块都自动挑错的话，症状是「设备照着地址下载，一直失败」，
//	而人第一反应会去怀疑固件和网，不会怀疑我们挑错了口。
func defaultShareNIC(nics []netif.NIC) (*netif.NIC, string, error) {
	usable := func(n netif.NIC) bool {
		return !n.Loop && !n.Virtual && n.Up && n.Running && len(shareAddrs(n)) > 0
	}
	var one *netif.NIC
	var count int
	for i, n := range nics {
		if usable(n) {
			count++
			one = &nics[i]
		}
	}
	if rs, err := fileshareRoutes(); err == nil {
		for _, r := range rs {
			if r.Family != "ipv4" || r.Iface == "" {
				continue
			}
			for i, n := range nics {
				if n.Name == r.Iface && usable(n) {
					return &nics[i], "IPv4 默认路由走这块", nil
				}
			}
		}
	}
	if count == 1 {
		return one, "本机只有一块带可用 IPv4 的网卡", nil
	}
	var names []string
	for _, n := range nics {
		if usable(n) {
			names = append(names, fmt.Sprintf("%s(%s)", n.Name, strings.Join(shareAddrs(n), "+")))
		}
	}
	if count == 0 {
		return nil, "", ots.Errf(ots.ErrInvalidArgument,
			"本机没有一块带可用 IPv4 地址的网卡，共享不出去（先看看网线，或用 net.interfaces 确认地址）")
	}
	return nil, "", ots.Errf(ots.ErrInvalidArgument,
		"有 %d 块网卡都能开共享（%s），猜错口就是「设备一直下载失败」，请填 iface 指定其中一块",
		count, strings.Join(names, "、"))
}

// surveyDir 数一下这个目录里有多少东西，并且找出**看着像密钥**的文件名。
//
// ★ 只数一层（顶层 + 每个子目录一层），不递归：这是给人看规模用的，
//
//	不是磁盘统计，扫一个 10 万文件的目录毫无意义。
//	★ 只看文件名，永不读内容。
func surveyDir(root string) (files, dirs int, bytes int64, secrets []string, err error) {
	des, err := os.ReadDir(root)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	var walk []os.DirEntry
	for _, de := range des {
		walk = append(walk, de)
	}
	// 子目录再进去看一层就停
	top := len(walk)
	for i := 0; i < top; i++ {
		de := walk[i]
		if !de.IsDir() {
			continue
		}
		dirs++
		sub, serr := os.ReadDir(filepath.Join(root, de.Name()))
		if serr != nil {
			continue // 进不去的子目录不算错：它只是没被数进来
		}
		n := 0
		for _, s := range sub {
			if s.IsDir() {
				continue
			}
			walk = append(walk, s)
			if n++; n >= 200 {
				break // 一个目录里超过 200 个文件时，规模已经不用数了
			}
		}
	}
	for _, de := range walk {
		if de.IsDir() {
			continue
		}
		files++
		if info, ierr := de.Info(); ierr == nil {
			bytes += info.Size()
		}
		if looksSecret(de.Name()) {
			secrets = append(secrets, de.Name())
		}
	}
	sort.Strings(secrets)
	if len(secrets) > 8 {
		secrets = secrets[:8]
	}
	return files, dirs, bytes, secrets, nil
}

// looksSecret 按**文件名**判断，不读内容。
//
// ★ 这个检查存在的理由很实在：顺手把 ~/ 或一个仓库目录当固件目录共享出去的人不少，
//
//	而里面躺着 id_rsa / .env 是常态。我们不替人决定（也许那真是他要发的文件），
//	但必须把这件事放到批准说明里，让人自己看一眼再点头。
func looksSecret(name string) bool {
	n := strings.ToLower(name)
	for _, ext := range []string{".key", ".pem", ".p12", ".pfx", ".kdbx", ".pkcs12", ".jks"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	switch filepath.Base(n) {
	case "id_rsa", "id_ed25519", "id_dsa", ".netrc", ".htpasswd", ".env", "shadow", "passwd", "credentials":
		return true
	}
	if strings.HasPrefix(n, "id_rsa.") || strings.HasPrefix(n, "id_ed25519.") {
		return true // .pub 也在里面：公钥无所谓，但这一档宁可多问一句
	}
	return false
}

// ── serve ──

func serveFileShare(ctx context.Context, raw json.RawMessage) (any, error) {
	var a fileshareArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	plan, err := planFileShare(a)
	if err != nil {
		// 参数不对先说参数：这条错跟账本没关系，掺在一起人就跑去查配置了。
		return nil, err
	}
	if journal == nil {
		// ★ 没有账本就不许改：开着共享这件事记不下来，重启后谁都不知道它开过。
		//   拦在这里就还没动手 —— 一个监听器都不许留下。
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝开共享")
	}

	fileshare.mu.Lock()
	defer fileshare.mu.Unlock()
	if fileshare.srv != nil {
		st := fileshare.srv.Status()
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"已经有一个共享在跑了（目录 %s，端口 %d）。先用 net.fileshare.stop 停掉再开新的",
			st.Root, fileshare.srv.Port())
	}

	srv, err := filesrv.Start(filesrv.Config{
		Root: plan.root, Addrs: plan.addrs, Port: plan.port, Listing: plan.listing,
	})
	if err != nil {
		return nil, ots.Errf(ots.ErrPermissionRequired, "%s", err)
	}

	// ★ [OTS-7.5] 起都起来了才记账还来得及吗？来得及，但顺序要反过来才是对的：
	//   这里的「改动」就是本机在监听端口，进程一退就没了，没有需要还原的状态。
	//   记这笔是为了**留痕**（什么时候开过、开的哪个目录）+ 重启后能看见上次没停。
	if id, jerr := journal.Register("file-share", describeFileShare(raw),
		map[string]any{"serving": false},
		map[string]any{"root": plan.root, "iface": plan.iface, "addrs": plan.addrs,
			"port": plan.port, "listing": plan.listing}); jerr == nil {
		_ = journal.MarkApplied(id)
		fileshare.entryID = id
	}

	fileshare.srv = srv
	fileshare.plan = plan
	vals := map[string]any{
		"root":            plan.root,
		"entries":         plan.entries,
		"dirs":            plan.dirs,
		"bytes":           plan.bytes,
		"iface":           plan.iface,
		"ifaceWhy":        plan.ifaceWhy,
		"addrs":           plan.addrs,
		"port":            plan.port,
		"urls":            srv.URLs(),
		"listing":         plan.listing,
		"readOnly":        true,
		"possibleSecrets": plan.secrets,
		"warnings":        plan.warnings,
	}
	note := fmt.Sprintf("已在 %s 上把 %s 开成只读共享（端口 %d，%d 个条目约 %s）",
		plan.iface, plan.root, plan.port, plan.entries, humanSize(plan.bytes))
	if plan.iface == "" {
		note = fmt.Sprintf("已把 %s 开成只读共享（绑 %s，端口 %d，%d 个条目约 %s）",
			plan.root, strings.Join(plan.addrs, "、"), plan.port, plan.entries, humanSize(plan.bytes))
	}
	if len(plan.secrets) > 0 {
		note += fmt.Sprintf("；★ 目录里有 %d 个文件名看着像密钥（%s），它们同样能被下载",
			len(plan.secrets), strings.Join(plan.secrets, "、"))
	}
	return ots.Verdict{Code: verdictShareServing, Values: vals, Note: note}, nil
}

func statusFileShare(ctx context.Context, raw json.RawMessage) (any, error) {
	fileshare.mu.Lock()
	srv := fileshare.srv
	plan := fileshare.plan
	fileshare.mu.Unlock()
	if srv == nil {
		return ots.Verdict{
			Code:   verdictShareIdle,
			Values: map[string]any{"status": filesrv.IdleStatus()},
			Note:   "本机现在没有开文件共享",
		}, nil
	}
	st := srv.Status()
	vals := map[string]any{
		"status":    st,
		"protocols": []string{"http"},
		// 开那一刻算好的事实，跟着状态一起回，界面刷一次不丢行。
		"iface":           plan.iface,
		"ifaceWhy":        plan.ifaceWhy,
		"addrs":           plan.addrs,
		"entries":         plan.entries,
		"dirs":            plan.dirs,
		"bytes":           plan.bytes,
		"possibleSecrets": plan.secrets,
		"warnings":        plan.warnings,
	}
	note := fmt.Sprintf("目录 %s 正被 %d 个地址共享出去（端口 %d），已下发 %d 次、共 %s",
		st.Root, len(st.AddrInfo), srv.Port(), st.Requests, humanSize(st.Bytes))
	if st.Denied > 0 {
		// ★ 只算真被拒的那些（想上传、想翻出目录）。文件名没对上单独一句：
		//   混在一起的话，一个只是抄错了固件名的现场也会读成「有人在试这个共享」。
		note += fmt.Sprintf("，另有 %d 次被拒（想上传 / 想翻出目录）", st.Denied)
	}
	if st.NotFound > 0 {
		note += fmt.Sprintf("，%d 次是文件名没对上（设备上那个地址写错了）", st.NotFound)
	}
	return ots.Verdict{Code: verdictShareServing, Values: vals, Note: note}, nil
}

func stopFileShare(ctx context.Context, raw json.RawMessage) (any, error) {
	fileshare.mu.Lock()
	defer fileshare.mu.Unlock()
	if fileshare.srv == nil {
		return ots.Verdict{Code: verdictShareIdle, Values: map[string]any{"status": filesrv.IdleStatus()},
			Note: "本机没有在跑的文件共享"}, nil
	}
	st := fileshare.srv.Status()
	fileshare.srv.Stop()
	if journal != nil && fileshare.entryID != "" {
		_ = journal.MarkReverted(fileshare.entryID, "用户停掉了共享")
	}
	fileshare.srv, fileshare.entryID = nil, ""
	fileshare.plan = filesharePlan{}
	return ots.Verdict{
		Code: verdictShareStopped,
		Values: map[string]any{"root": st.Root, "urls": st.URLs, "requests": st.Requests,
			"bytes": st.Bytes},
		Note: fmt.Sprintf("共享已停：%s 不再对外可读（这中间一共被取走 %d 次、%s）",
			st.Root, st.Requests, humanSize(st.Bytes)),
	}, nil
}

// restoreFileShare 处理上次没停的共享账。
//
// ★★ 监听器是本进程持有的，进程退了端口就空了 —— **没有任何状态要还原**。
//
//	但这笔账必须了结：Outstanding() 会把它当「还在生效」报出来，
//	挂着不管，下次看账本的人就会去查一个早就不存在的共享。
//	也不自动重开：那等于人不在场就把一个目录开到网上去。
func restoreFileShare(log *slog.Logger) {
	if journal == nil {
		return
	}
	for _, e := range journal.Outstanding() {
		if e.Kind != "file-share" {
			continue
		}
		log.Warn("上次退出时文件共享没有正常停止 —— 本次启动不会自动重开（端口已随进程释放）",
			"改动", e.What, "时间", e.At.Format(time.RFC3339))
		_ = journal.MarkReverted(e.ID, "进程重启：监听器已随上次进程退出而释放")
	}
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d 字节", n)
}
