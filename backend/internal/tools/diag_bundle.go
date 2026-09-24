package tools

// ── net.diag.bundle 诊断包导出 ──
//
// ★★ 这一栏卖的不是「把结果存成文件」，是**让对方不必再问一遍**。
//
//	现场把屏幕上的结论截图发群里，对方一定会追问三句：
//	「网关是哪台」「这块网卡是 USB 转的还是板载的」「这台被谁改过配置」。
//	截图里没有这三句，于是来回两天。诊断包一次给全：每一项都带**读到的原文**，
//	读不到的也带着「为什么读不到」。
//
// ★ 为什么是 zip 而不是一个长文本：包里有十几段内容，混在一格里没法分段看；
//   而且对方要转给别人（厂商、二线），一个附件比十七段粘贴有用。
//   文件名一律 UTF-8（不许再出 GBK，见 internal/diag 的包注释）。
//
// ★ 为什么先脱敏再落盘，而不是「发之前自己看一眼」：
//   这个工具会被 AI 调用、也会被工程师在凌晨三点调用。
//   凭据一旦写进文件，它就等着被上传到工单系统了 —— 那道口子必须由代码守住。
//
// ★ 为什么算 ClassRead：它只在**自己的输出目录**里新建一个文件，
//   不改任何主机/网络/设备上的状态（对照 net.fileshare.serve —— 那个要开监听口，算 mutate）。
//   也正因为不占改系统的闸门，一期就能用。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/diag"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

// 包里的项名。界面与 only 参数用这些词，所以它们是对外的，不是内部编号。
const (
	secSystem    = "system"
	secNIC       = "nic"
	secRoutes    = "routes"
	secNeighbors = "neighbors"
	secDNS       = "dns"
	secHosts     = "hosts"
	secProxy     = "proxy"
	secPorts     = "ports"
	secJournal   = "journal"
	secCheckup   = "checkup"
)

// sectionOrder 就是排查顺序：先看这台是什么，再看配置，最后看活的行为。
var sectionOrder = []string{
	secSystem, secNIC, secRoutes, secNeighbors, secDNS, secHosts, secProxy, secPorts, secJournal, secCheckup,
}

// 每项中文名叫什么（界面上按这个说，不让用户去猜 secDNS 是哪一段）。
var sectionLabel = map[string]string{
	secSystem:    "系统与时间",
	secNIC:       "网卡与地址",
	secRoutes:    "路由表",
	secNeighbors: "邻居表（ARP 与 NDP）",
	secDNS:       "DNS 服务器",
	secHosts:     "hosts 文件",
	secProxy:     "代理设置",
	secPorts:     "本机端口占用",
	secJournal:   "NetKit 改过什么",
	secCheckup:   "连通性体检",
}

// 包内目录：两类内容分两个文件夹，解压出来第一眼分得清「配置」和「行为」。
var sectionDir = map[string]string{
	secSystem:    "",
	secNIC:       "01 本机配置",
	secRoutes:    "01 本机配置",
	secNeighbors: "01 本机配置",
	secDNS:       "01 本机配置",
	secHosts:     "01 本机配置",
	secProxy:     "01 本机配置",
	secPorts:     "01 本机配置",
	secJournal:   "01 本机配置",
	secCheckup:   "02 连通性",
}

const (
	bundleWritten    = "bundle-written"
	bundlePartial    = "bundle-partial"
	bundleNotWritten = "bundle-not-written"
	secRead          = "section-read"
	secUnreadable    = "section-unreadable"
	secSkipped       = "section-skipped"
)

// 限量：包是发人的，转发表的级别的内容不能整个塞进来。
// ★ 截断必须在文件里写明，不能让对方把「没有」读成「这台没配」。
const (
	maxHostsLines    = 200
	maxRouteLines    = 300
	maxNeighLines    = 300
	maxPortLines     = 300
	maxJournalLines  = 100
	maxValueLineChar = 200
)

var diagBundleTool = ots.Tool{
	Name:  "net.diag.bundle",
	Class: ots.ClassRead,
	Summary: "把本机网络的现状打成一个 zip 诊断包，发给不在现场的人。" +
		"★ 里面是**读到的原文**，不是截图：网卡与地址、路由表、邻居表（ARP 与 NDP 两张）、" +
		"DNS 服务器、hosts 文件、代理设置、本机端口占用、NetKit 改过什么（改动账本）、" +
		"以及一项按排查顺序跑的连通性体检；读不到的那一项也会留在包里，写明为什么读不到。" +
		"包落在用户配置目录下的 yuhox-netkit/诊断包/，只新建这一个文件，不改任何东西。" +
		"★ 落盘前统一脱敏：口令、团体名、令牌、私钥一律抹成 ***，键名留着" +
		"（所以「配了但没给你看」和「没配」在包里分得开），抹了几类几处写在包的第一页。" +
		"包内文件名一律 UTF-8。判定：bundle-written（全部项都在包里）、" +
		"bundle-partial（有项没读出来，缺哪几项在 missingItems 里）、" +
		"bundle-not-written（一个文件都没写出来，原因在 note —— 目录不可写、磁盘满这类）。" +
		"发之前注意：这个包里有内网地址、机器名、网卡名、进程名，发出去就等于把这些给了对方。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "properties": {
	    "label": {"type": "string", "maxLength": 40,
	      "description": "写在包名里的一段，建议填现场名，如「金宇建安-盒1」。路径分隔符与保留字符会被洗掉。"},
	    "only": {"type": "array", "items": {"type": "string",
	        "enum": ["system", "nic", "routes", "neighbors", "dns", "hosts", "proxy", "ports", "journal", "checkup"]},
	      "description": "只要其中几项，默认全给。对方只问了某件事时用这个，别把不相干的配置一起发出去。"},
	    "skipLive": {"type": "boolean",
	      "description": "不跑要发探测包的那一项（连通性体检），其余照旧。★ 网络已经彻底不通、或者这一趟只是要留个配置快照时用；那一项会在包里写明是按调用方要求跳过的。"},
	    "domain": {"type": "string",
	      "description": "体检那一项用哪个域名测 DNS 与出口，默认 www.cloudflare.com。内网填内网一定解析得到的名字。"}
	  }
	}`),
	Invoke: doDiagBundle,
}

type bundleArgs struct {
	Label    string   `json:"label,omitempty"`
	Only     []string `json:"only,omitempty"`
	SkipLive bool     `json:"skipLive,omitempty"`
	Domain   string   `json:"domain,omitempty"`
}

// bundleSources 是这一栏的「会碰系统」的部分。★ 全部抽成函数，理由和 checkProbes 一样：
// 判定层（哪些项算读不出来、缺了几项要给什么判定）不该只能靠把一台真机器搞坏来验。
type bundleSources struct {
	nics     func() ([]netif.NIC, error)
	routes   func() ([]netif.Route, error)
	defRoute func() ([]netif.DefaultRoute, error)
	neigh4   func(context.Context) ([]neighbor, error)
	neigh6   func(context.Context) ([]neighbor, error)
	dns      func() ([]netif.DNSServer, error)
	hosts    func() (path string, text string, err error)
	proxy    func(context.Context) (string, map[string]any)
	ports    portRead
	journal  func() []state.Entry
	hostname func() (string, error)
	outDir   func() (string, error)
	now      func() time.Time
	checkup  func(ctx context.Context, a checkupArgs, probes int, timeout time.Duration,
		pr checkProbes) ([]checkItem, map[string]any, error)
	// probes 是体检那一项要用的探测集。★ 单独一个字段：测试里换掉 checkup 就够了，
	// 但真要跑真体检的判定顺序时，得能只换发流量的一部分。
	probes func() checkProbes
}

func defaultBundleSources() bundleSources {
	return bundleSources{
		nics:     netif.Interfaces,
		routes:   netif.Routes,
		defRoute: netif.DefaultRoutes,
		neigh4:   neighborsV4,
		neigh6:   neighborsV6,
		dns:      netif.SystemDNSServers,
		hosts:    readHostsFile,
		proxy:    systemProxy,
		ports:    localPorts,
		journal: func() []state.Entry {
			if journal == nil {
				return nil
			}
			return journal.All()
		},
		hostname: os.Hostname,
		outDir:   diag.DefaultDir,
		now:      time.Now,
		checkup:  runCheckup,
		probes:   defaultProbes,
	}
}

// bundleItem 一项的结果，进结果的 sections 数组：界面按它列「哪几项在包里、哪项没读出来」。
type bundleItem struct {
	Item  string `json:"item"`
	Label string `json:"label"`
	Code  string `json:"code"`
	// File 是这一项在包里的路径（跳过的项也有，里面写的是为什么）。
	File   string `json:"file,omitempty"`
	Reason string `json:"reason,omitempty"`
	Lines  int    `json:"lines,omitempty"`
}

func doDiagBundle(ctx context.Context, raw json.RawMessage) (any, error) {
	var a bundleArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	want, err := pickSections(a.Only)
	if err != nil {
		return nil, err
	}
	return writeBundle(ctx, a, want, defaultBundleSources())
}

// pickSections 校验 only，并按排查顺序排回去。
//
// ★ 传进来的顺序不许照抄：调用方（包括 AI）可能按字母序或随手给，
//
//	而包里的项顺序是「对方先看什么」的一部分。
func pickSections(only []string) ([]string, error) {
	if len(only) == 0 {
		return append([]string{}, sectionOrder...), nil
	}
	set := map[string]bool{}
	for _, s := range only {
		switch s {
		case secSystem, secNIC, secRoutes, secNeighbors, secDNS, secHosts, secProxy, secPorts, secJournal, secCheckup:
		default:
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"only 里有不认识的项 %q，可选：%s", s, strings.Join(sectionOrder, " / "))
		}
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for _, s := range sectionOrder {
		if set[s] {
			out = append(out, s)
		}
	}
	return out, nil
}

// bundleSection 一项渲染出来的结果。
type bundleSection struct {
	item   bundleItem
	misses bool
}

func writeBundle(ctx context.Context, a bundleArgs, want []string, src bundleSources) (any, error) {
	started := src.now()
	dir, derr := src.outDir()
	if derr != nil {
		// 连往哪儿写都不知道：这时还没有文件，界面上要能直接说「这台写不出来」。
		return ots.Verdict{Code: bundleNotWritten, Values: map[string]any{"reason": derr.Error()},
			Note: fmt.Sprintf("没能出包：找不到输出目录 —— %s。"+
				"★ 一个文件都没写出来，别去那个目录找半截的包。下一步：看用户配置目录是否可写。", derr)}, nil
	}

	items := make([]bundleItem, 0, len(want))
	secs := make([]diag.Section, 0, len(want)+1)
	missing := []string{}
	var notes []string

	for _, name := range want {
		text, code, reason, err := renderSection(ctx, name, a, src, started)
		if err != nil {
			return nil, err
		}
		label := sectionLabel[name]
		file := sectionFile(name)
		switch code {
		case secUnreadable:
			missing = append(missing, name)
			text = reason // 读不到也要进包：写明为什么读不到
		}
		secs = append(secs, diag.Section{
			Name:    file,
			Text:    text + "\n",
			Missing: code == secUnreadable,
		})
		items = append(items, bundleItem{
			Item: name, Label: label, Code: code, File: file,
			Reason: reason, Lines: countLines(text),
		})
	}

	top := bundleWritten
	if len(missing) > 0 {
		top = bundlePartial
	}
	// ★ 「一项都没读出来」是照**这一趟要读的项**算的，不是照十项全缺算的：
	//   调用方用 only 只要了三项、三项全读不到，这个包同样是空壳。
	allMiss := len(missing) > 0 && len(missing) == len(want)
	if allMiss {
		notes = append(notes, "这一趟一项都没读出来：包里的内容全是「为什么读不到」。"+
			"通常是权限问题（这几项要 root 或管理员），不是这台机器没有配置。")
	}
	cu := checkupUserValues(items)
	hdr := diag.Header{
		Label:    a.Label,
		Created:  started,
		GOOS:     runtime.GOOS,
		GOARCH:   runtime.GOARCH,
		Version:  netkitVersion(),
		Rows:     rowsOf(items),
		Warnings: notes,
	}
	if hn, err := src.hostname(); err == nil {
		hdr.HostName = hn
	} else {
		hdr.Warnings = append(hdr.Warnings, "主机名没读到："+err.Error())
	}
	res, berr := diag.Build(dir, hdr, secs)
	if berr != nil {
		// 键名仍然叫 sections：内容都读到了，逐项判定照给 —— 界面上那张表照样摊得开，
		// 只是「哪一页」那一栏还没有包可指。换键名会让同一个字段在两种判定下叫两个名字。
		return ots.Verdict{Code: bundleNotWritten, Values: map[string]any{
			"dir": dir, "reason": berr.Error(), "sections": items},
			Note: fmt.Sprintf("内容都读到了，但包没写成：%s。\n★ 输出目录 %s —— 那里现在没有新文件，"+
				"别去翻半截的包。下一步：看这个目录还能不能写（磁盘满、目录被别的用户占有、"+
				"路径太深都会这样），或者用 only 少给几项再试一次。", berr, dir)}, nil
	}
	values := map[string]any{
		"path":         res.Path,
		"dir":          filepath.Dir(res.Path),
		"bytes":        res.Bytes,
		"entries":      len(res.Entries),
		"sections":     items,
		"missingItems": missing,
		"redacted":     res.Redactions,
		"redactedHow":  diag.HitList(res.Redactions),
		"truncated":    res.Truncated,
		"tookMs":       time.Since(started).Milliseconds(),
		// 界面不许自己数行来判断「这个包是不是空壳」：那正是本工具最不该被读错的一档。
		"nothingRead": allMiss,
	}
	if cu != nil {
		values["checkup"] = cu // 体检没跑（跳过 / 没跑成）时不给空壳：界面上那是一颗胶囊，空的也得有权不出现
	}
	return ots.Verdict{Code: top, Values: values,
		Note: bundleNote(top, items, missing, res, notes)}, nil
}

// bundleNote 复制得走的那一句：路径在最前面，因为对方第一句一定问「包在哪」。
func bundleNote(top string, items []bundleItem, missing []string, res diag.Result, notes []string) string {
	var b strings.Builder
	if top == bundleWritten {
		fmt.Fprintf(&b, "包已经写好：%s（%v 个文件，%s）。%v 项全在里面。\n",
			res.Path, len(res.Entries), humanBytes(res.Bytes), len(items))
	} else {
		fmt.Fprintf(&b, "包写好了，但缺 %v 项：%s。\n%s（%v 个文件，%s）。\n",
			len(missing), strings.Join(missing, "、"), res.Path, len(res.Entries), humanBytes(res.Bytes))
		fmt.Fprintf(&b, "★ 缺的那几项也在包里，各自写明为什么读不到 —— 那不是「这台没有」，"+
			"多半是没权限（邻居表、进程名、hosts 这几项在非管理员下读不全）。\n")
	}
	fmt.Fprintf(&b, "包内文件名是 UTF-8，macOS/Linux 直接解开就行；每一项都带原文，"+
		"所以对方不必再回来问「网关是哪台」这一类问题。\n")
	fmt.Fprintf(&b, "脱敏：%s。\n", diag.HitList(res.Redactions))
	if len(res.Truncated) > 0 {
		fmt.Fprintf(&b, "被截断的节：%s（原文太长，要看全文用对应的工具单独再查一次）。\n",
			strings.Join(res.Truncated, "、"))
	}
	for _, n := range notes {
		b.WriteString(strings.ReplaceAll(n, "**", "") + "\n")
	}
	b.WriteString("发之前过一眼：包里有内网地址、机器名、网卡名、进程名，发出去就等于把这些给了对方。")
	return b.String()
}

// humanBytes 给人看的字节数。★ 界面上不渲染这个字段（它渲染 bytes 自己格式化），
// 这一句是给 note 和日志用的 —— 一个 30000 字节的包和一个人能一口气读完的包，
// 在现场是两种东西。
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d 字节", n)
	}
}

func rowsOf(items []bundleItem) []diag.Row {
	out := make([]diag.Row, 0, len(items))
	for _, it := range items {
		out = append(out, diag.Row{
			Item:    it.Label,
			Code:    it.Code,
			Note:    it.Reason,
			Missing: it.Code == secUnreadable,
		})
	}
	return out
}

// checkupUserValues 把体检那一项的顶层判定单独提出来：界面要能在包的路径旁边
// 就说出「这一台是断在哪一步」。★ 只在真的跑过时给：跳过的项把 "skipped-live"
// 当判定送出去，界面上就成了一颗看着像结论的胶囊。
func checkupUserValues(items []bundleItem) map[string]any {
	for _, it := range items {
		if it.Item == secCheckup && it.Code == secRead && it.Reason != "" {
			return map[string]any{"top": it.Reason}
		}
	}
	return nil
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(strings.TrimRight(s, "\n"), "\n") + 1
}

func sectionFile(name string) string {
	dir := sectionDir[name]
	base := map[string]string{
		secSystem:    "系统与时间.txt",
		secNIC:       "网卡与地址.txt",
		secRoutes:    "路由表.txt",
		secNeighbors: "邻居表.txt",
		secDNS:       "DNS服务器.txt",
		secHosts:     "hosts文件.txt",
		secProxy:     "代理设置.txt",
		secPorts:     "端口占用.txt",
		secJournal:   "NetKit改动.txt",
		secCheckup:   "连通性体检.txt",
	}[name]
	if dir == "" {
		return base
	}
	return dir + "/" + base
}
