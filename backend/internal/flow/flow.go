package flow

// 按流聚合：把拆到底的包归到一条会话上，并把「这一条流怎么样」能说的话都在这里说清。
//
// 定口在三件事上：
//
//  1. **一条流一个键，两个方向共用**。A/B 取排序后的端点对，所以「相机 → NVR」与
//     「NVR → 相机」是同一条；TCP 上第一个 SYN 从哪一方来，就把那一方换到 A。
//     不做换向，表上就会出现「10.0.0.9:554 → 相机」这种反着的会话，现场照着去问错了的那台机器。
//  2. **IP 分片的后续片段归到首片那条流**。那一些包里没有端口，各记各的会把
//     「一条过了 1MB 的流」写成「3 包 180 字节」。
//  3. **拆不下去的一律进 Ledger 记一笔**，不许静悄悄丢（见包注释）。
//     三档采集的口径本来就不齐（Windows 那一档抓不到回环、`--comp nics` 没有混杂），
//     所以 Ledger 必须能和总包数对上 —— 对不上就说明有包被静悄悄丢了，
//     那这张表连「这里没流量」都不该说。

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Options 是聚合器的上限。为什么全是上限：一份脏包（或被人故意喂进来的包）能让
// 流的条数、每方向的缓冲、每条流的判定数无限制地长，而这张表是在现场给人看的 ——
// 长到把机器吃掉，看的人就什么都看不到了。
type Options struct {
	StreamCap   int // 每个方向留多少连续正文给上层解（<=0 = 默认 64KiB）
	MaxFlows    int // 流表上限（<=0 = 默认 4096）
	MaxMessages int // 每条流最多留几条应用层报文（<=0 = 默认 200）
	MaxFindings int // 每条流最多留几条判定（<=0 = 默认 24）
}

const (
	defaultStreamCap    = DefaultStreamCap
	defaultMaxFlows     = 4096
	defaultMaxMessages  = 200
	defaultMaxFindings  = 24
	defaultMaxFragFlows = 2048
	// 拆不下去的原因最多分几格：原因文本里带字节数与十六进制，不设上限光这一格就能吃内存。
	maxReasonKeys = 48
)

func (o Options) withDefaults() Options {
	if o.StreamCap <= 0 {
		o.StreamCap = defaultStreamCap
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = defaultMaxFlows
	}
	if o.MaxMessages <= 0 {
		o.MaxMessages = defaultMaxMessages
	}
	if o.MaxFindings <= 0 {
		o.MaxFindings = defaultMaxFindings
	}
	return o
}

// Packet 是聚合器要的那几格。刻意不直接收 capture.Packet：
// 那样这一层就只吃得下我们自己抓的东西，而「导入一份别人给的 pcapng」是同一张表的一半需求。
type Packet struct {
	Timestamp time.Time
	LinkType  uint16
	Data      []byte
	WireLen   int // 线上那份长度；0 = 不知道，按带回来的算
	Iface     string
}

// Traffic 是一个方向上的量。
type Traffic struct {
	Packets int
	Bytes   int
}

func (t Traffic) String() string { return fmt.Sprintf("%d 包 / %d 字节", t.Packets, t.Bytes) }

// HandshakeState 是 TCP 三次握手走到哪一步。空值那句说明最要紧：抓包是从中间开始的。
type HandshakeState string

const (
	HSNone        HandshakeState = ""
	HSSyn         HandshakeState = "syn"         // 只见到 SYN
	HSSplit       HandshakeState = "half-open"   // 见到 SYN/ACK，没见到第三次 ACK
	HSEstablished HandshakeState = "established" // 三次握手齐
	HSClosed      HandshakeState = "closed"      // 齐过，且 FIN 走完
	HSReset       HandshakeState = "reset"       // 被 RST 断掉
)

func (h HandshakeState) Meaning() string {
	switch h {
	case HSNone:
		return "这一段里没见到 SYN：会话起点不明"
	case HSSyn:
		return "只发出 SYN，没有回（对端没接，或中间有人挡）"
	case HSSplit:
		return "回了 SYN/ACK，发起方没确认"
	case HSEstablished:
		return "三次握手齐"
	case HSClosed:
		return "走完 FIN 正常关闭"
	case HSReset:
		return "被 RST 断掉"
	}
	return string(h)
}

// TCPStats 是 TCP 会话那几格时序与商量的数。
//
// 为什么单独一张：现场问的是「连上没有」「谁断的」「窗口是不是被收端压死了」，
// 这三句只能在一包一层数出来，事后从正文里翻不回来。
// 下标 0 = A→B 方向，1 = B→A 方向（谁发起的看 A）。
type TCPStats struct {
	Syn       [2]int
	SynAck    [2]int
	Rst       [2]int
	Fin       [2]int
	AckSeen   [2]bool // 这一侧有没有回过 ACK（判第三次握手用）
	ZeroWin   [2]int  // 收端窗口为 0 的带数据段
	MSS       [2]int  // 该方向声明的段大小
	Scale     [2]int  // 窗口缩放因子，-1 = 没带这个选项
	Handshake HandshakeState
}

// Retrans 与 Gaps 从两条拼流的状态汇总而来，不在这里重复记一份。
func (t *TCPStats) synRetrans() int {
	if t == nil || t.Syn[0] == 0 {
		return 0
	}
	if t.SynAck[1]+t.SynAck[0] > 0 {
		return 0 // 有过回了：后面再来的 SYN 是新建会话，不算重发
	}
	return t.Syn[0] - 1
}

// ICMPStats 是回声那一对的账，下标同 TCPStats（0 = A→B，1 = B→A）。
//
// 为什么不在总包数上做这篇文章：一条 icmp 流里混着请求、应答、以及「不可达」那几种
// 顺路飘回来的包，只比 AB/BA 的包数会把「A 问了 B 没答」说成「两边差不多」——
// 而现场要的那一句恰恰是「谁问了、谁没答」。
type ICMPStats struct {
	Req     [2]int
	Reply   [2]int
	Other   [2]int // 既不是请求也不是应答：不可达、超时、重定向、时间戳…
	Unreach [2]int // 目的地不可达那一种（Other 里的一个子集，单独一格因为它最有用）
}

// Flow 是一条会话在表上的样子。
type Flow struct {
	Key       string
	Proto     string // tcp / udp / icmp / icmpv6 / arp / frag / ip<proto> / eth:<类型>
	A, B      string // 端点：带端口写成 ip:port，没有端口写地址（icmp 用 #id 占端口那一格）
	AMAC      string
	BMAC      string
	VLANs     []int
	Iface     string // 第一包从哪块口进来的（pktmon 那份文件里根本没有这一格，就是空）
	IPVersion byte

	First, Last time.Time
	Packets     int
	Bytes       int
	AB, BA      Traffic

	FragPackets int // 归并进来的后续片段
	FragBytes   int

	TCP *TCPStats // 只有 TCP 会话有

	// ICMP 那几格只有回声数得清「谁问了谁没答」，别的类型各记各的（见 ICMPStats）。
	ICMP *ICMPStats

	// RTP 是按 SSRC 记的序号账，★ 不受 Messages 上限影响：
	// 「这一路丢了几包」是整条流的结论，而一条流可以有几十万包 RTP —— 报文列表只能留前几百条，
	// 账必须一直记下去，否则界面上就成了「前 200 包没丢，所以这条流没丢包」。
	RTP []*RTPAccount

	// RTPSkipped：SSRC 多到上限后没记账的包数。这一格必须能说出来，
	// 不然一张脏包喂进来的表会显示「只有一路、一路没丢」。
	RTPSkipped int

	App       string // 认出的是什么应用协议，空 = 认不出
	AppBy     string // "内容" / "端口"：只靠端口认出来的一律标上，不冒充拆过
	Messages  []Message
	Findings  []Finding
	Notes     []string
	Streams   [2]Stream // [0] = A→B，[1] = B→A
	Unrecog   int       // 拆到底认不出内容的包
	Truncated int       // 被剪过的包

	// 跨流的三格由 linkMedia 在整表算完之后填（见 cross.go）：
	// 信令与媒体本来是一件事的两半，各看各的都会看成「正常」。
	Media     []FlowRef // 这一条信令开出来的媒体流
	Signaling []FlowRef // 这一条媒体流是谁开出来的
	Missing   []string  // 信令里说好了、表上却没有的收流口

	owner       *Aggregator
	ab, ba      *streamState
	rtpState    map[uint32]*RTPAccount // 内部按 SSRC 找那一格的账，RTP 切片只是它的对外视图
	consumed    [2]int                 // 应用层已经切到哪一字节了（不重复出报文）
	seqMethod   map[string]string      // 「方向 + CSeq」→ 请求的方法：回包行没写方法，靠它补（见 app_emit.go）
	tcpSniffed  bool                   // TCP 上已经试过定口：不试第二次，那是每一包重看一遍开头
	maxMessages int
	maxFindings int
}

func (f *Flow) Duration() time.Duration {
	if f.First.IsZero() || f.Last.IsZero() {
		return 0
	}
	return f.Last.Sub(f.First)
}

// Endpoints 回 "A → B"，用在表头与导出里。
func (f *Flow) Endpoints() string { return f.A + " → " + f.B }

func (f *Flow) String() string {
	s := fmt.Sprintf("%s %s（%d 包 / %d 字节", f.Proto, f.Endpoints(), f.Packets, f.Bytes)
	if f.App != "" {
		s += "，" + f.App
	}
	if f.Proto == "tcp" && f.TCP != nil {
		s += "，握手 " + f.TCP.Handshake.Meaning()
	}
	return s + "）"
}

func (f *Flow) state(dir int) *streamState {
	if dir == 0 {
		return f.ab
	}
	return f.ba
}

// addNote 同一句话只记一次：一张表上重复三遍同样的说明，看的人会以为是三件事。
func (f *Flow) addNote(s string) {
	if s == "" {
		return
	}
	for _, have := range f.Notes {
		if have == s {
			return
		}
	}
	f.Notes = append(f.Notes, s)
}

// Finding 是一条带码的判定。码给工具层和界面用，句子给人看。
type Finding struct {
	Code string
	Text string
	At   time.Time
}

// Ledger 是「这一趟一共见了多少包，没拆的那些都为什么没拆」。
type Ledger struct {
	Total          int
	Decoded        int // 拆到 IP/ARP 及以上
	ByReason       map[string]int
	ByLink         map[uint16]int
	FlowsDropped   int // 撞到流表上限，有多少条流没建成
	PacketsDropped int // ★ 已拆到 IP/ARP、但因为流表到上限没进表的包：已经算在 Decoded 里
}

// Reconciles 回「各格加起来等不等于总包数」。false 就是有包被静悄悄丢了，
// 这一句必须能在界面上说出口 —— 宁可承认少算了，不许表上看着是齐的。
//
// 加进来的只有 ByReason（那些压根没拆开的）。PacketsDropped 不许在这里再加一遍：
// 那些包是拆开了却没地方放，Decoded 已经数过它们了，两处都数就是无中生有凑平账。
func (l Ledger) Reconciles() bool { return l.Total == l.Decoded+l.dropped() }

func (l Ledger) dropped() int {
	var n int
	for _, v := range l.ByReason {
		n += v
	}
	return n
}

func (l Ledger) String() string {
	var parts []string
	for _, r := range l.reasons() {
		parts = append(parts, fmt.Sprintf("%s×%d", r.key, r.n))
	}
	s := fmt.Sprintf("共 %d 包，拆到 IP/ARP %d 包", l.Total, l.Decoded)
	if len(parts) > 0 {
		s += "；没拆开的：" + strings.Join(parts, "， ")
	}
	if l.PacketsDropped > 0 {
		s += fmt.Sprintf("；另有 %d 包拆开了但流表已满（%d 条），没归进表", l.PacketsDropped, l.FlowsDropped)
	}
	if !l.Reconciles() {
		s += fmt.Sprintf("；★对不上账：少了 %d 包", l.Total-(l.Decoded+l.dropped()))
	}
	return s
}

type reasonRow struct {
	key string
	n   int
}

func (l Ledger) reasons() []reasonRow {
	out := make([]reasonRow, 0, len(l.ByReason))
	for k, v := range l.ByReason {
		out = append(out, reasonRow{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	return out
}

// ARPBinding 是一个地址在这一趟里被谁说过。
type ARPBinding struct {
	IP   string
	MACs []string // 出现过的源 MAC；多于一个就是地址冲突
}

// Aggregator 把包流聚成表。不是并发安全的：一趟抓包一个。
type Aggregator struct {
	opt    Options
	byKey  map[string]*Flow
	order  []*Flow
	led    Ledger
	frag   map[string]*Flow // 首片那条流：分片要能归回去
	fragAt []string         // 分片表的插入顺序，用来做先进先出淘汰
	arpMac map[string]map[string]int
	arpSeq []string
}

func NewAggregator(opt Options) *Aggregator {
	return &Aggregator{
		opt:    opt.withDefaults(),
		byKey:  map[string]*Flow{},
		frag:   map[string]*Flow{},
		arpMac: map[string]map[string]int{},
	}
}

// newFlow 建一条流并把按协议才开的内部格子备齐。
//
// 两个建流点（正常流、只有后续片段的那一条）共用一个：漏开一格就是
// 「从另一条路上来的包全记不进账」，而这种错在合成测试里往往只有某一条路径能撞上。
func (a *Aggregator) newFlow(proto, A, B string, ipVersion byte) *Flow {
	fl := &Flow{
		Proto: proto, A: A, B: B, IPVersion: ipVersion,
		ab: newStreamState(a.opt.StreamCap), ba: newStreamState(a.opt.StreamCap),
		owner: a, maxMessages: a.opt.MaxMessages, maxFindings: a.opt.MaxFindings,
	}
	switch proto {
	case "tcp":
		fl.TCP = &TCPStats{Scale: [2]int{-1, -1}} // 缩放因子没带 = 1，用 -1 才分得清「没有这一格」
	case "icmp", "icmpv6":
		fl.ICMP = &ICMPStats{}
	}
	return fl
}

// Add 拆一个包并归进表，回拆到底的那一份与拆不开时那句原因。
//
// 拆不开不算失败：账已经进 Ledger 了。调用方拿 err 只用来决定要不要打日志，
// 不许拿它去决定「这个包就不看了」—— 那样 Ledger 会开始骗人。
func (a *Aggregator) Add(p Packet) (Frame, error) {
	a.led.Total++
	if a.led.ByLink == nil {
		a.led.ByLink = map[uint16]int{}
	}
	a.led.ByLink[p.LinkType]++
	f, err := Decode(p.LinkType, p.Data)
	if err != nil {
		a.noteReason(reasonFor(err, p.LinkType))
		return f, err
	}
	if f.SrcIP == nil && f.EtherType != etypeARP && !f.Unrecognized {
		// 拆到底却没有地址：这一层还有没写到的链路类型，不能默默过去。
		a.noteReason("拆到链路层就停了（没有网络层地址）")
		return f, nil
	}
	a.led.Decoded++
	a.addARP(f)
	a.addFlow(f, p)
	return f, nil
}

// Ledger 回这份账的快照（拷一份，不让外面改内部计数）。
func (a *Aggregator) Ledger() Ledger {
	l := a.led
	l.ByReason = copyInts(a.led.ByReason)
	l.ByLink = copyLinks(a.led.ByLink)
	return l
}

// Flows 回按「第一次见到」排序的表，并把每条流的判定算一遍。
//
// 判定每次快照重算而不是追加：同一份状态必须算出同一组话，
// 界面刷一次多出一条重复判定是最好笑也最难查的那种 bug。
func (a *Aggregator) Flows() []*Flow {
	for _, f := range a.order {
		a.conclude(f)
	}
	// 整表算完才连：信令 ↔ 媒体要两头都在表上才连得出来，
	// 一条一条算的时候另一头可能还没见到（抓包就是从中间开始的）。
	a.linkMedia()
	out := make([]*Flow, 0, len(a.order))
	out = append(out, a.order...)
	return out
}

// Flow 按键取一条（工具层要「只给我看这一条流」时用）。
func (a *Aggregator) Flow(key string) (*Flow, bool) {
	f, ok := a.byKey[key]
	if !ok {
		return nil, false
	}
	// 整张表算一遍再回：只算这一条的话，它挂在别人身上的那一半（画面在另一条流上）
	// 就永远连不出来，而现场点的恰恰是这一条。
	a.Flows()
	return f, true
}

// ARPBindings 回「哪个地址被哪些 MAC 说过」。
func (a *Aggregator) ARPBindings() []ARPBinding {
	var out []ARPBinding
	for _, ip := range a.arpSeq {
		set := a.arpMac[ip]
		macs := make([]string, 0, len(set))
		for m := range set {
			macs = append(macs, m)
		}
		sort.Strings(macs)
		out = append(out, ARPBinding{IP: ip, MACs: macs})
	}
	return out
}

// ==================== 记账 ====================

// reasonFor 把拆不开的错并成一格。链路口编号直接问入参，不去从错文本里刨数字：
// 句子改一个字账就散成两格，这种绑法迟早坑人。
func reasonFor(err error, linkType uint16) string {
	if s := err.Error(); strings.Contains(s, "不拆这种链路口") {
		return fmt.Sprintf("链路口 %d 不拆", linkType)
	}
	return cleanReason(err)
}

// cleanReason 把原因文本里的数字并成一格：
// 「要 14 字节，这一包只有 3」与「…只有 5」是同一件事，不该占两格。
func cleanReason(err error) string {
	s := err.Error()
	if i := strings.Index(s, "0x"); i >= 0 {
		s = s[:i] // 十六进制样本长短不一，切在这里
	}
	var b strings.Builder
	prevDigit := false
	for _, r := range s {
		isDigit := r >= '0' && r <= '9'
		if isDigit && !prevDigit {
			b.WriteRune('#')
		} else if !isDigit {
			b.WriteRune(r)
		}
		prevDigit = isDigit
	}
	return strings.TrimSpace(b.String())
}

func (a *Aggregator) noteReason(s string) {
	if s == "" {
		s = "（空原因）"
	}
	if a.led.ByReason == nil {
		a.led.ByReason = map[string]int{}
	}
	if _, ok := a.led.ByReason[s]; !ok && len(a.led.ByReason) >= maxReasonKeys {
		s = "其他（原因种类已达上限）"
	}
	a.led.ByReason[s]++
}

func (a *Aggregator) addARP(f Frame) {
	if f.ARP == nil {
		return
	}
	// 只有「说了这个地址是谁的」算绑定：who-has 的提问方也带源 MAC，但那不是认领。
	ip := f.ARP.SenderIP
	if ip == nil || ip.IsUnspecified() || len(f.ARP.SenderMAC) == 0 {
		return
	}
	key := ip.String()
	set := a.arpMac[key]
	if set == nil {
		set = map[string]int{}
		a.arpMac[key] = set
		a.arpSeq = append(a.arpSeq, key)
	}
	set[f.ARP.SenderMAC.String()]++
}

func (a *Aggregator) addFlow(f Frame, p Packet) {
	wire := p.WireLen
	if wire <= 0 {
		wire = len(p.Data)
	}
	if f.Frag && !f.FirstFrag {
		a.addFragment(f, p, wire)
		return
	}
	proto, srcEP, dstEP := flowEndpoints(f)
	if proto == "" {
		return
	}
	key := proto + " " + srcEP + " <-> " + dstEP
	fl := a.byKey[key]
	if fl == nil {
		// 反方向的键先有过（先见到的是回包）：那条流就是它，A/B 已经定了。
		if rev := a.byKey[proto+" "+dstEP+" <-> "+srcEP]; rev != nil {
			fl = rev
		}
	}
	if fl == nil {
		if len(a.order) >= a.opt.MaxFlows {
			a.led.FlowsDropped++
			a.led.PacketsDropped++
			return
		}
		fl = a.newFlow(proto, srcEP, dstEP, f.IPVersion)
		fl.Key = key
		a.byKey[key] = fl
		a.order = append(a.order, fl)
	}
	if srcEP != fl.A && srcEP != fl.B {
		// 键与 A/B 对不上只可能是换过向：不能猜，猜了就是一条流被记到两条上。
		a.noteReason("端点与流表对不上（换向后又被反向命中）")
		return
	}
	dir := 0
	fromA := srcEP == fl.A
	if !fromA {
		dir = 1
	}
	// ★ 两端是同一个地址那一档（本机 ping 本机、在回环上抓到的那一条）：
	// 地址对分不出谁问谁答，每一包都会被算成「A 发出去的」，于是回包那一格永远是 0，
	// 「一个都没人答」这句假话就上了表 —— 而这份文件里明明每一问都有一答。
	// 这一档只能按报文自己的角色分方向：问 = 出去，答 = 回来。
	if fl.A == fl.B && f.ICMP != nil {
		v6 := f.Transport == "icmpv6"
		switch {
		case f.ICMP.IsEchoRequest(v6):
			dir, fromA = 0, true
		case f.ICMP.IsEchoReply(v6):
			dir, fromA = 1, false
		}
	}
	// ★ 第一个 SYN 决定谁是发起方。半道上不换：换了会把两边已经记下的账对调错。
	if !fromA && proto == "tcp" && f.TCP != nil && f.TCP.Get(FlagSYN) && !f.TCP.Get(FlagACK) && !fl.handshakeStarted() {
		fl.swap()
		fromA = true
		dir = 0
		fl.addNote("方向按第一个 SYN 那一方定：第一包不是 SYN，发起方是后面才见到的一方")
	}

	a.touch(fl, f, p, dir, fromA, wire)
	if f.FragID != 0 && f.Frag {
		a.rememberFrag(f, fl)
	}
}

// touch 落一个包到某条流的某一方向上。
func (a *Aggregator) touch(fl *Flow, f Frame, p Packet, dir int, fromA bool, wire int) {
	if fl.IPVersion == 0 {
		fl.IPVersion = f.IPVersion
	}
	if fl.Iface == "" {
		fl.Iface = p.Iface
	}
	if fl.First.IsZero() {
		fl.First = p.Timestamp
	}
	if p.Timestamp.After(fl.Last) {
		fl.Last = p.Timestamp
	}
	if fromA && fl.AMAC == "" {
		fl.AMAC = macOf(f.SrcMAC)
	} else if !fromA && fl.BMAC == "" {
		fl.BMAC = macOf(f.SrcMAC)
	}
	if len(fl.VLANs) == 0 && len(f.VLANs) > 0 {
		fl.VLANs = append([]int(nil), f.VLANs...)
	}
	fl.Packets++
	fl.Bytes += wire
	if fromA {
		fl.AB.Packets++
		fl.AB.Bytes += wire
	} else {
		fl.BA.Packets++
		fl.BA.Bytes += wire
	}
	// ★ 两处都得算：f.Truncated 是拆帧时看见「声明的长度比给到的长」（IP 分片只到了一段），
	// 而 p.WireLen > len(p.Data) 是采集那一头剪的（snaplen、pktmon 的段长）。
	// 只看前者的话，一份剪过的 pcapng 里每一包都「完整」，界面就不会说「正文不可信」。
	if f.Truncated || wire > len(p.Data) {
		fl.Truncated++
	}
	if f.Unrecognized {
		fl.Unrecog++
	}
	if f.ICMP != nil {
		a.countICMP(fl, f, dir)
	}

	st := fl.state(dir)
	switch {
	case f.TCP != nil:
		if got := st.add(f.TCP.Seq, f.Payload, p.Timestamp); got != nil {
			fl.scanApp(f, dir, got, p.Timestamp)
		}
		fl.Streams[dir] = st.st
		a.countTCP(fl, f, dir)
	case f.UDP != nil:
		a.countRTPFor(fl, f, dir, p.Timestamp)
		fl.scanApp(f, dir, f.Payload, p.Timestamp)
	default:
		// ARP、ICMP、只到地址的那些：应用层这一档不开。
		//
		// ★ 看着像「少解了一层」，其实是不该解：这一类流的正文不是报文，是别人的数据。
		// 一份真 ping 抓出来的回环包，正文头八字节是发包时刻、后面才是填充模式，
		// 而 0x84 开头 + 一个像载荷类型的字节，正好凑得过 RTP 那把形状刀 ——
		// 于是表上会写「127.0.0.1 上有一条 RTP 媒体流，载荷类型 60」，
		// 下面的丢包判定就跟着这句假话往下算。协议专解只挂在有端口的那两种上。
	}
}

func (a *Aggregator) countTCP(fl *Flow, f Frame, dir int) {
	t, st := f.TCP, fl.TCP
	if st == nil {
		return
	}
	switch {
	case t.Flags&FlagSYN != 0 && t.Flags&FlagACK == 0:
		st.Syn[dir]++
	case t.Flags&FlagSYN != 0 && t.Flags&FlagACK != 0:
		st.SynAck[dir]++
	case t.Flags&FlagRST != 0:
		st.Rst[dir]++
	case t.Flags&FlagFIN != 0:
		st.Fin[dir]++
	}
	if t.Flags&FlagACK != 0 && t.Flags&FlagSYN == 0 {
		st.AckSeen[dir] = true
	}
	// 窗口那一格：SYN 那包窗口本来就可能是 0，RST 之后没人等了 —— 都别算成「收不过来」。
	if t.Flags&(FlagSYN|FlagRST) == 0 && t.Window == 0 && len(f.Payload) > 0 {
		st.ZeroWin[dir]++
	}
	if m := t.MSS(); m > 0 && st.MSS[dir] == 0 {
		st.MSS[dir] = m
	}
	if sc, ok := t.WindowScale(); ok && st.Scale[dir] < 0 {
		st.Scale[dir] = sc
	}
}

func (fl *Flow) handshakeStarted() bool {
	if fl.TCP == nil {
		return false
	}
	t := fl.TCP
	return t.Syn[0]+t.Syn[1]+t.SynAck[0]+t.SynAck[1]+t.Rst[0]+t.Rst[1]+t.Fin[0]+t.Fin[1] > 0
}

// countICMP 数回声那一对，顺带把「不可达」单列一格。
//
// 为什么非切不可达单独一格：它带回来的那句「到不了谁」嵌在 Inside 里，
// 光看这条流的总包数会把它当成一次普通的 ping —— 现场就成了「ping 得通啊」。
func (a *Aggregator) countICMP(fl *Flow, f Frame, dir int) {
	st := fl.ICMP
	if st == nil {
		st = &ICMPStats{}
		fl.ICMP = st
	}
	v6 := f.Transport == "icmpv6"
	switch {
	case f.ICMP.IsEchoRequest(v6):
		st.Req[dir]++
	case f.ICMP.IsEchoReply(v6):
		st.Reply[dir]++
	default:
		st.Other[dir]++
		if icmpUnreachable(v6, f.ICMP.Type) {
			st.Unreach[dir]++
		}
	}
}

func icmpUnreachable(v6 bool, t byte) bool {
	if v6 {
		return t == 1 || t == 2 // 不可达 / 包太大（后者是 v6 独有的「Path MTU 太小」）
	}
	return t == 3
}

// swap 把 A/B 两侧（含两个方向的账与拼流状态与键）对调。
// 反向那条键上已经有别的流时不换：两股账并一股是最容易出错的那种「看起来更整齐」。
func (fl *Flow) swap() {
	a := fl.owner
	if a == nil {
		return
	}
	newKey := fl.Proto + " " + fl.B + " <-> " + fl.A
	if other, taken := a.byKey[newKey]; taken && other != fl {
		fl.addNote("想按 SYN 定方向，但那侧已有一条流：没敢合并，方向仍按第一包说")
		return
	}
	delete(a.byKey, fl.Key)
	fl.A, fl.B = fl.B, fl.A
	fl.AMAC, fl.BMAC = fl.BMAC, fl.AMAC
	fl.AB, fl.BA = fl.BA, fl.AB
	fl.ab, fl.ba = fl.ba, fl.ab
	fl.consumed[0], fl.consumed[1] = fl.consumed[1], fl.consumed[0]
	fl.Streams[0], fl.Streams[1] = fl.Streams[1], fl.Streams[0]
	if t := fl.TCP; t != nil {
		t.Syn[0], t.Syn[1] = t.Syn[1], t.Syn[0]
		t.SynAck[0], t.SynAck[1] = t.SynAck[1], t.SynAck[0]
		t.Rst[0], t.Rst[1] = t.Rst[1], t.Rst[0]
		t.Fin[0], t.Fin[1] = t.Fin[1], t.Fin[0]
		t.AckSeen[0], t.AckSeen[1] = t.AckSeen[1], t.AckSeen[0]
		t.ZeroWin[0], t.ZeroWin[1] = t.ZeroWin[1], t.ZeroWin[0]
		t.MSS[0], t.MSS[1] = t.MSS[1], t.MSS[0]
		t.Scale[0], t.Scale[1] = t.Scale[1], t.Scale[0]
	}
	fl.Key = newKey
	a.byKey[newKey] = fl
}

// addFragment 把后续片段记回首片那条流。找不到首片时单独开一条 IP 级的流，
// 而不是丢掉：首片没被抓到（或后面才到）是常事，而「没有首片」本身就是要说的结论。
func (a *Aggregator) addFragment(f Frame, p Packet, wire int) {
	k := fragKey(f)
	if fl := a.frag[k]; fl != nil {
		fl.FragPackets++
		fl.FragBytes += wire
		fl.Packets++
		fl.Bytes += wire
		if f.SrcIP.String() == fl.A {
			fl.AB.Packets++
			fl.AB.Bytes += wire
		} else {
			fl.BA.Packets++
			fl.BA.Bytes += wire
		}
		if fl.First.IsZero() {
			fl.First = p.Timestamp
		}
		if p.Timestamp.After(fl.Last) {
			fl.Last = p.Timestamp
		}
		return
	}
	sa, sb := sortedPair(f.SrcIP.String(), f.DstIP.String())
	key := fmt.Sprintf("frag %s <-> %s id=%d", sa, sb, f.FragID)
	fl, ok := a.byKey[key]
	if !ok {
		if len(a.order) >= a.opt.MaxFlows {
			a.led.FlowsDropped++
			a.led.PacketsDropped++
			return
		}
		fl = a.newFlow("frag", sa, sb, f.IPVersion)
		fl.Key = key
		fl.addNote("这一条只由后续片段拼成：首片没在这一段里，端口与上层协议无从得知")
		a.byKey[key] = fl
		a.order = append(a.order, fl)
	}
	fl.FragPackets++
	fl.FragBytes += wire
	fl.Packets++
	fl.Bytes += wire
	if fl.First.IsZero() {
		fl.First = p.Timestamp
	}
	if p.Timestamp.After(fl.Last) {
		fl.Last = p.Timestamp
	}
	a.rememberFrag(f, fl)
}

func (a *Aggregator) rememberFrag(f Frame, fl *Flow) {
	k := fragKey(f)
	if _, ok := a.frag[k]; ok {
		a.frag[k] = fl
		return
	}
	// 分片表也要有上限：一片一个键地长，等于给脏包开了个内存的口子。
	for len(a.fragAt) >= defaultMaxFragFlows {
		delete(a.frag, a.fragAt[0])
		a.fragAt = a.fragAt[1:]
	}
	a.frag[k] = fl
	a.fragAt = append(a.fragAt, k)
}

func fragKey(f Frame) string {
	sa, sb := sortedPair(f.SrcIP.String(), f.DstIP.String())
	return fmt.Sprintf("%s|%s|%d", sa, sb, f.FragID)
}

// flowEndpoints 定这条流的协议与两个端点（按包的方向给，排序由调用方做）。
// 回空协议表示「不知道该归哪儿」，调用方就不许造一条流出来。
func flowEndpoints(f Frame) (proto, srcEP, dstEP string) {
	switch {
	case f.Transport == "tcp" || f.Transport == "udp":
		return f.Transport, f.Src, f.Dst
	case f.Transport == "icmp" || f.Transport == "icmpv6":
		// 回声没有端口，能分开两条 ping 的只有那一格 id：拿它占端口的尾巴。
		id := 0
		if f.ICMP != nil {
			id = int(f.ICMP.ID)
		}
		return f.Transport, epID(f.SrcIP, id), epID(f.DstIP, id)
	case f.Transport == "arp":
		sa, sb := sortedPair(f.Src, f.Dst)
		return "arp", sa, sb
	case f.SrcIP != nil && f.DstIP != nil:
		// 到了 IP 却没有能分端口的那一层（加密的、隧道、只到地址的）。
		return "ip-" + transportName(f.IPProto), f.SrcIP.String(), f.DstIP.String()
	case f.Unrecognized && f.EtherType != 0:
		// 二层的东西（LLDP/PTP/802.1X）：不拆内容，但必须在表上出现，不能当没看见。
		sa, sb := sortedPair(macOf(f.SrcMAC), macOf(f.DstMAC))
		return "eth:" + ethTypeName(f.EtherType), sa, sb
	}
	return "", "", ""
}

func epID(ip net.IP, id int) string {
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%s#%d", ip, id)
}

func sortedPair(a, b string) (string, string) {
	if a <= b {
		return a, b
	}
	return b, a
}

func macOf(m net.HardwareAddr) string {
	if len(m) == 0 {
		return ""
	}
	return m.String()
}

func copyInts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyLinks(m map[uint16]int) map[uint16]int {
	out := make(map[uint16]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ==================== 判定 ====================

// conclude 按当前状态把这条流能说的话算一遍（整片重算，见 Flows 的说明）。
func (a *Aggregator) conclude(fl *Flow) {
	fl.Findings = fl.Findings[:0]
	// 跨流那三格跟着一起清：整表重算时连线会重新填，不清就是拿上一轮的账说话。
	fl.Media = fl.Media[:0]
	fl.Signaling = fl.Signaling[:0]
	fl.Missing = fl.Missing[:0]
	if t := fl.TCP; t != nil {
		t.Handshake = handshakeOf(fl, t)
		switch t.Handshake {
		case HSSyn:
			if n := t.synRetrans(); n > 0 {
				fl.addFinding("tcp-syn-retransmit", fl.Last,
					fmt.Sprintf("SYN 重发 %d 次没有一个回：%s → %s 没人接（服务没起、或中间有人丢）",
						t.Syn[0]+n, fl.A, fl.B))
			} else {
				fl.addFinding("tcp-no-synack", fl.Last,
					fmt.Sprintf("只见到 SYN，没有 SYN/ACK 也没有 RST：%s → %s 没人回（连拒都没有）", fl.A, fl.B))
			}
		case HSSplit:
			fl.addFinding("tcp-half-open", fl.Last,
				fmt.Sprintf("%s 回了 SYN/ACK，%s 这一侧没走完第三次 ACK（半开：常见于被防火墙放行 SYN 却丢了后面的包）",
					fl.B, fl.A))
		case HSNone:
			fl.addFinding("tcp-no-syn", fl.First,
				"这一段里没有 SYN：会话起点不明，「谁发起」只能按第一包说")
		case HSReset:
			who := fl.B
			if t.Rst[0] > t.Rst[1] {
				who = fl.A
			}
			fl.addFinding("tcp-reset", fl.Last,
				fmt.Sprintf("%s 发了 %d 包 RST 把会话断了（对端直接拒、或半道有人插包）", who, t.Rst[0]+t.Rst[1]))
		case HSClosed:
			// 正常关闭不是问题，但「连上就断」这个形状本身是答案（服务收了连接又不要数据）。
			if fl.AB.Bytes+fl.BA.Bytes <= fl.Packets*60 {
				fl.addFinding("tcp-instant-close", fl.Last,
					"握手齐了却几乎没过数据就正常关闭：连接建立成功不等于会话成功，去问应用层那一段")
			}
		}
		if t.ZeroWin[0]+t.ZeroWin[1] > 0 {
			side := fl.A
			if t.ZeroWin[1] >= t.ZeroWin[0] {
				side = fl.B
			}
			fl.addFinding("tcp-zero-window", fl.Last,
				fmt.Sprintf("%s 把窗口压到 0 共 %d 次：是这一端来不及收，不是网络不通",
					side, t.ZeroWin[0]+t.ZeroWin[1]))
		}
		var gaps, lost, retrans int
		for _, s := range fl.Streams {
			gaps += s.Gaps
			lost += s.Lost
			retrans += s.Retrans
		}
		if gaps > 0 {
			fl.addFinding("tcp-gap", fl.Last,
				fmt.Sprintf("序号跳了 %d 处、约 %d 字节：★这一档分不开「网上丢了」与「我们抓漏了」，"+
					"要定罪得对照两端的网卡计数", gaps, lost))
		}
		if retrans > 0 {
			fl.addFinding("tcp-retransmit", fl.Last,
				fmt.Sprintf("同一份数据重发 %d 段：%s ↔ %s", retrans, fl.A, fl.B))
		}
		if t.MSS[0] > 0 && t.MSS[1] > 0 && t.MSS[0] != t.MSS[1] {
			fl.addFinding("tcp-mss-mismatch", fl.First,
				fmt.Sprintf("两边各自声明的 MSS 不一样（%d / %d）：一边被 clamp 过就是「小包能过大包过不去」那类案的形状",
					t.MSS[0], t.MSS[1]))
		}
	}
	if fl.Proto == "udp" && fl.BA.Packets == 0 && fl.AB.Packets > 0 {
		fl.addFinding("udp-one-way", fl.Last,
			fmt.Sprintf("%s → %s 单向 %d 包，一个回包都没有：对端静默（丢弃或被挡）——"+
				"这两种在这一档分不开，别再往下推", fl.A, fl.B, fl.AB.Packets))
	}
	// 一问一答按方向配对：A 问的那一些，看 B 答了几个（反过来同理）。
	// ★ 不在 AB/BA 的总包数上做这篇文章：那条 icmp 流里混着请求、应答与「不可达」，
	// 只比总数会把「A 问了 B 没答」说成「两边差不多」，而后者才是现场要的那一句。
	// 两个方向各说各的，但一句里说完：判定按码去重，同一码发两遍只会剩一条。
	if s := fl.ICMP; s != nil {
		var noReply, partly []string
		for _, p := range []struct {
			req, got int
			who, foe string
		}{{s.Req[0], s.Reply[1], fl.A, fl.B}, {s.Req[1], s.Reply[0], fl.B, fl.A}} {
			switch {
			case p.req == 0:
			case p.got == 0:
				noReply = append(noReply, fmt.Sprintf("%s 发了 %d 个回声请求，%s 一个都没答", p.who, p.req, p.foe))
			case p.got < p.req:
				partly = append(partly, fmt.Sprintf("%s 问了 %d 次，%s 答了 %d 次", p.who, p.req, p.foe, p.got))
			}
		}
		if len(noReply) > 0 {
			fl.addFinding("icmp-no-reply", fl.Last,
				strings.Join(noReply, "；")+"（单向抓包时分不开「它没答」与「请求没到」，得去对照网卡计数）")
		}
		if len(partly) > 0 {
			fl.addFinding("icmp-loss", fl.Last,
				strings.Join(partly, "；")+"：这一条上过了几个来回才有一个没回")
		}
		if n := s.Unreach[0] + s.Unreach[1]; n > 0 {
			side, cnt := fl.A, s.Unreach[0]
			if s.Unreach[1] > s.Unreach[0] {
				side, cnt = fl.B, s.Unreach[1]
			}
			fl.addFinding("icmp-unreachable", fl.Last,
				fmt.Sprintf("%s 回了 %d 包「目的地不可达」：这是它开口说「到不了」，与超时那种没声音是两种病"+
					"（不可达里嵌着的那一条原始包，按 Inside 记在正文里）", side, cnt))
		}
	}
	if fl.Proto == "arp" {
		for _, bd := range a.ARPBindings() {
			if len(bd.MACs) > 1 && (bd.IP == fl.A || bd.IP == fl.B) {
				fl.addFinding("arp-conflict", fl.Last,
					fmt.Sprintf("%s 被 %d 个 MAC 说过（%s）：地址冲突或有人在抢，先查这两块网卡",
						bd.IP, len(bd.MACs), strings.Join(bd.MACs, " / ")))
				break
			}
		}
	}
	// 流一层的判定排在单包判定之前占格子：★ maxFindings 是先到先得，
	// 排在后面的「这条路走通没有」会被前面几十条「这一包怎么这样」挤掉，
	// 而现场要的恰恰是前一句。
	fl.concludeRTP()
	fl.concludeApp()
	for _, f := range fl.Messages {
		for _, fd := range f.Findings {
			fl.addFinding(fd.Code, f.At, fd.Text)
		}
	}
	if fl.Unrecog > 0 {
		fl.addFinding("payload-unrecognized", fl.Last,
			fmt.Sprintf("这一条里有 %d 包拆到底认不出内容（加密、或没写专解的协议）", fl.Unrecog))
	}
	if fl.Truncated > 0 {
		fl.addFinding("captured-truncated", fl.Last,
			fmt.Sprintf("有 %d 包带回来的比线上声明的短：留长剪过，正文与后面那半截字段不可信", fl.Truncated))
	}
	if fl.FragPackets > 0 {
		fl.addFinding("ip-fragments", fl.Last,
			fmt.Sprintf("归并了 %d 个后续片段（%d 字节）：那一些没有端口，单看会被当成另一条流",
				fl.FragPackets, fl.FragBytes))
	}
}

// handshakeOf 只看计数，不看时间序：抓到中间时「有 SYN/ACK 无 SYN」也是常态，
// 那种情况一律回 HSNone，不猜成 established。
func handshakeOf(fl *Flow, t *TCPStats) HandshakeState {
	_ = fl
	if t.Rst[0]+t.Rst[1] > 0 {
		return HSReset
	}
	syn := t.Syn[0] + t.Syn[1]
	synack := t.SynAck[0] + t.SynAck[1]
	switch {
	case syn == 0 && synack == 0:
		return HSNone
	case syn == 0:
		return HSNone // 只见到 SYN/ACK：这一段里发起那一方没露面，起点还是不明
	case t.AckSeen[0] && t.SynAck[0]+t.SynAck[1] > 0:
		if t.Fin[0]+t.Fin[1] >= 2 {
			return HSClosed
		}
		return HSEstablished
	case synack == 0:
		return HSSyn
	default:
		return HSSplit
	}
}

func (fl *Flow) addFinding(code string, at time.Time, text string) {
	for _, have := range fl.Findings {
		if have.Code == code {
			return
		}
	}
	if len(fl.Findings) >= fl.maxFindings {
		return
	}
	fl.Findings = append(fl.Findings, Finding{Code: code, Text: text, At: at})
}
