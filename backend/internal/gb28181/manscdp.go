package gb28181

// MANSCDP：装在 SIP MESSAGE / NOTIFY 正文里的那段 XML。
//
// ★ 解的一面宽容、建的一面严格：
//
//	现场的固件千奇百怪 —— 标签大小写不一致、多带一个没听过的字段、
//	DeviceList 写成 ItemList、末尾多一个换行。解的时候一项项硬要求，
//	结果就是「设备明明答了，工具说它没答」，那是最坏的一种诊断。
//	所以这里把顶层叶子全收进 Fields（键统一转小写），列表收进 Items，
//	认不出来的键不丢、原样留在账上，由工具层如实报「这台还回了这些字段」。
//
// ★ 不建强类型结构体映射：GB28181 各版本字段对不上，按某一份样例钉死一张表，
//
//	就会把「这台少回了 ChannelNum」看成「协议不兼容」。键名按收到的样子记账，
//	取的时候大小写无关 —— 宽松只用在「取」这个动作上，下结论用的还是数出来的条数。

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MANSCDP 的四种根。查询与应答靠这个区分（同一个 CmdType 在两边都会出现）。
const (
	RootQuery    = "Query"
	RootResponse = "Response"
	RootNotify   = "Notify"
	RootControl  = "Control"
)

// 这一层真用得上的 CmdType。
const (
	CmdDeviceInfo   = "DeviceInfo"
	CmdDeviceStatus = "DeviceStatus"
	CmdCatalog      = "Catalog"
	CmdKeepalive    = "Keepalive"
)

// Fields 是一条命令（或列表里一个条目）的叶子字段。键一律小写，理由见文件头。
type Fields map[string]string

// F 起一个字段，给建报文那边用。
type F struct {
	Name  string
	Value string
}

// Get 大小写无关地取值；没这条键给空串。
// ★ 调用方要靠 Has 区分「没回这个字段」和「回了一个空值」——
// 前者是能力缺，后者是它真的没名字，现场下一步不一样。
func (f Fields) Get(name string) string { return f[strings.ToLower(name)] }

func (f Fields) Has(name string) bool {
	_, ok := f[strings.ToLower(name)]
	return ok
}

// Keys 给出排序后的键名。顺序必须稳，不然同一份回包两次问出来的界面不一样，
// 人会以为是工具在抖。
func (f Fields) Keys() []string {
	out := make([]string, 0, len(f))
	for k := range f {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f Fields) Int(name string) (int, bool) {
	v := strings.TrimSpace(f.Get(name))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Cmd 是一条解开了的 MANSCDP 命令。
type Cmd struct {
	Root     string // Query / Response / Notify / Control
	CmdType  string
	SN       string
	DeviceID string
	Fields   Fields
	Items    []Fields // 列表里的条目（Catalog 的 DeviceList/Item 这一类）

	// Lists 记「哪个容器里数出多少条」。★ 按容器名记，不是只认 DeviceList：
	// 有的固件写成 ItemList，硬只认一个名字就会把数到的通道报成 0 条。
	Lists map[string]int
	// Repeated 记同一层里出现多次的键名。这是「这台设备的 XML 不规矩」的硬证据，
	// 静默取第一个就成了一个看不见的洞。
	Repeated []string
	// Ambiguous 记「只装了一条的容器」的名字。
	// ★ 一个壳里挂一个孩子，光看形状分不清是「容器里就这一台设备」还是
	//	「这条设备自己带着这堆字段」——这里按容器记账，但把这一笔留给判定端说话：
	//	现场「通道只有一条」和「把设备自己当成了通道」是两种下一步，不能让工具替人猜。
	Ambiguous []string
	// NonUTF8：正文里有按 UTF-8 解不出来的字节。
	// ★ 单独记一条：这类设备的中文名在界面上就是乱码，不写清楚人会以为是工具坏了。
	//   （本工具不内建转码，是否再按 GBK 解一遍由人决定。）
	NonUTF8 bool
}

// Get 先查那三条已经落在结构上的，再查 Fields。
func (c *Cmd) Get(name string) string {
	switch strings.ToLower(name) {
	case "cmdtype":
		return c.CmdType
	case "sn":
		return c.SN
	case "deviceid":
		return c.DeviceID
	}
	return c.Fields.Get(name)
}

// SumNum 是 Catalog 应答里它自己声明的通道总数。
// ★ 与「这一页数到多少条」分开拿：设备可以分页回，只报其中一个就是把账混了。
func (c *Cmd) SumNum() (int, bool) { return c.Fields.Int("sumnum") }

// ItemCount 数到的条目总数（跨所有列表容器）。
func (c *Cmd) ItemCount() int { return len(c.Items) }

// ItemDeviceIDs 取条目里的编号，缺编号的条目跳过但计数留在账上（Missing 那条）。
func (c *Cmd) ItemDeviceIDs() (ids []string, missing int) {
	for _, it := range c.Items {
		if id := strings.TrimSpace(it.Get("deviceid")); id != "" {
			ids = append(ids, id)
			continue
		}
		missing++
	}
	return ids, missing
}

// IsResponseTo 认这条正文是不是「刚才那一问」的答。
//
// CmdType 与 SN 两条都要比对：只比 CmdType 会把上一轮没答完、这会儿才飘回来的
// 旧回包算成本轮的（现场就成了「问了三次、屏幕上只有两次的账」）；
// 只比 SN 更糟 —— 有的平台 SN 全局自增，隔几秒再问同一句就撞号。
//
// sn 传空串表示只比 CmdType。★ 留这个口子是因为**有些设备压根不照抄 SN**，
// 现场碰到一次就该在判定里记一笔「这台不认 SN」，而不是每次都判它答错。
func (c *Cmd) IsResponseTo(cmdType, sn string) bool {
	if !strings.EqualFold(strings.TrimSpace(c.CmdType), strings.TrimSpace(cmdType)) {
		return false
	}
	if sn == "" {
		return true
	}
	return strings.TrimSpace(c.SN) == strings.TrimSpace(sn)
}

type mnode struct {
	name     string
	text     string
	children []mnode
}

// ParseCmd 解一段 MANSCDP 正文。
func ParseCmd(raw []byte) (*Cmd, error) {
	cmd := &Cmd{Fields: Fields{}, Lists: map[string]int{}}
	if !utf8.Valid(raw) {
		cmd.NonUTF8 = true
		// ★ 标准库的 XML 解码器碰到非法 UTF-8 字节是直接报错，不是替换。
		//	按 GBK 发中文名的设备在现场是真有的，照原样喂进去就只能报
		//	「这段 XML 读不下去」，而设备其实是答对了的 —— 那是最坏的一种诊断。
		//	这里把非法字节换成占位符再解：编号、条数、状态这些全是 ASCII，一条不丢；
		//	丢的只有中文名，而界面会按 NonUTF8 这一条说明「名字看着像乱码是设备发的编码」。
		raw = []byte(strings.ToValidUTF8(string(raw), "\uFFFD"))
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var root mnode
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, fmt.Errorf("正文里一个节点都没有")
		}
		if err != nil {
			return nil, fmt.Errorf("这段 XML 读不下去：%w", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			root.name = se.Name.Local
			break
		}
	}
	switch root.name {
	case RootQuery, RootResponse, RootNotify, RootControl:
	default:
		return nil, fmt.Errorf("根节点是 %q，不是 MANSCDP 的那四种（Query/Response/Notify/Control）", root.name)
	}
	cmd.Root = root.name
	if err := decodeInto(dec, &root); err != nil {
		return nil, err
	}
	// 先按小写键把同层的根孩子分堆。★ 分堆而不是逐个看：
	// 有的厂家把通道直接写成一层 <Item> 重复，没有外面那个 <DeviceList> 壳；
	// 逐个看会把每一条 <Item> 当成「一个列表容器」，于是它的每个字段各成一条通道 ——
	// 一份三条通道的表能读出九条来，这是会让现场照着一个不存在的表去配的分错。
	type group struct {
		name  string // 照收到的写法（记账用）
		leaf  []mnode
		treen []mnode
	}
	var order []string
	groups := map[string]*group{}
	for _, ch := range root.children {
		key := strings.ToLower(ch.name)
		g := groups[key]
		if g == nil {
			g = &group{name: ch.name}
			groups[key] = g
			order = append(order, key)
		}
		if len(ch.children) == 0 {
			g.leaf = append(g.leaf, ch)
			continue
		}
		g.treen = append(g.treen, ch)
	}
	for _, key := range order {
		g := groups[key]
		for _, ch := range g.leaf {
			v := strings.TrimSpace(ch.text)
			// ★ 同名兄弟只在**内容不一样**时才算「重复键」这条硬证据：自闭掉的标签
			//	（<Field/>）在解码器那儿就是成对的一次开一次闭，同值重复多半是噪声。
			//	把它们报成「这台设备的 XML 不规矩」，人就跟着去查一个不存在的问题。
			//	留哪个值的答案不变：一律留第一个。
			if prev, has := cmd.Fields[key]; has {
				if prev != v {
					cmd.Repeated = append(cmd.Repeated, g.name)
				}
				continue
			}
			cmd.Fields[key] = v
		}
		if len(g.treen) == 0 {
			continue
		}
		// 有孩子 => 列表。两种写法都要认：一个壳套多条条目，或者条目直接重复。
		for _, n := range g.treen {
			items, shell := entriesOf(n)
			for _, it := range items {
				cmd.Items = append(cmd.Items, flatten(it))
			}
			// ★ 容器名一律按小写记，与 Fields 同一口径：现场有 devicelist、
			//	DeviceList、DEVICELIST 三种写法，工具层照一个拼法去查就会把
			//	数到的通道报成 0 条 —— 那是最难看的一种错。
			cmd.Lists[key] += len(items)
			if !shell && len(g.treen) == 1 {
				// 这一层只出现一次、又没被当成壳：我们把它按「一条条目」记了数，
				//	但没有第二个同名兄弟来印证它确实是条目。通道表只有一条时，
				//	「这是一路通道」和「这是外层字段的一个包装」给出的内容一模一样，
				//	而下一步不同（前者去配通道编号，后者得先看它是不是设备自述）——
				//	这一笔不替人猜，留给判定端说话。
				cmd.Ambiguous = append(cmd.Ambiguous, g.name)
			}
		}
		if len(g.treen) > 1 {
			cmd.Repeated = append(cmd.Repeated, g.name)
		}
	}
	cmd.CmdType = cmd.Fields.Get("cmdtype")
	cmd.SN = cmd.Fields.Get("sn")
	cmd.DeviceID = cmd.Fields.Get("deviceid")
	return cmd, nil
}

// decodeInto 把一个已开始节点的子树读进 n（调用时 dec 正停在该节点的 StartElement 之后）。
func decodeInto(dec *xml.Decoder, n *mnode) error {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return fmt.Errorf("读到结尾也没等到 </%s>", n.name)
		}
		if err != nil {
			return fmt.Errorf("节点 %s 里面读不下去：%w", n.name, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child := mnode{name: t.Name.Local}
			if err := decodeInto(dec, &child); err != nil {
				return err
			}
			n.children = append(n.children, child)
		case xml.EndElement:
			return nil
		case xml.CharData:
			n.text += string(t)
		}
	}
}

// entriesOf 判一个节点是「装条目的壳」还是「条目本身」。
// ★ 先按名字定：规范里条目就叫 Item、容器一律以 List 结尾（DeviceList、以及现场写成
//
//	ItemList 的那一类）；名字落在这两类之外才照形状判 —— 孩子里有一个自己带着字段，
//	就当它是壳。
//
// 为什么要判这一眼：现场三种写法都有 —— 标准的 <DeviceList><Item>、换成 <ItemList> 的、
// 以及把外面那层壳省掉直接重复 <Item> 的。认死一种，另外两种就会把一条通道读成一堆字段
// （或者反过来把一堆字段读成一条通道），而读出来的那一份是拿去配点播地址的。
func entriesOf(n mnode) ([]mnode, bool) {
	if strings.EqualFold(n.name, "Item") {
		return []mnode{n}, false
	}
	if !strings.HasSuffix(strings.ToLower(n.name), "list") {
		for _, ch := range n.children {
			if len(ch.children) == 0 {
				return []mnode{n}, false // 孩子里有裸字段 => 这一层就是条目自己
			}
		}
	}
	return n.children, true
}

// flatten 收一个条目下面的全部叶子。同名键保留第一个，后出现的当噪声丢掉 ——
// 条目里不记 Repeated，因为「一条通道回了两个 Name」这件事在 Items 的长度上看不出来，
// 报了也没法对照是哪一条。
func flatten(n mnode) Fields {
	out := Fields{}
	var walk func(mnode)
	walk = func(x mnode) {
		if len(x.children) == 0 {
			k := strings.ToLower(x.name)
			if _, ok := out[k]; !ok {
				out[k] = strings.TrimSpace(x.text)
			}
			return
		}
		for _, c := range x.children {
			walk(c)
		}
	}
	walk(n)
	return out
}

// Builder 建一条 MANSCDP。★ 字段顺序按标准样例排（CmdType、SN、DeviceID 打头），
// 有些平台按顺序解析，顺序不对就当没这条。
type Builder struct {
	root     string
	cmdType  string
	sn       string
	deviceID string
	fields   []F
	listName string
	itemName string
	items    [][]F
}

func NewBuilder(root, cmdType, sn, deviceID string) *Builder {
	return &Builder{root: root, cmdType: cmdType, sn: sn, deviceID: deviceID}
}

// Set 追加一个顶层字段。空值也写：现场「它回了但回的是空的」是一条事实。
func (b *Builder) Set(name, value string) *Builder {
	b.fields = append(b.fields, F{Name: name, Value: value})
	return b
}

// SetIf 只在值非空时写，用于标准里可省的那几样（StartTime、Secrecy 这类）。
func (b *Builder) SetIf(name, value string) *Builder {
	if strings.TrimSpace(value) == "" {
		return b
	}
	return b.Set(name, value)
}

// List 声明条目用哪个容器与条目标签名。不调用就是 Catalog 那套 DeviceList/Item。
func (b *Builder) List(listName, itemName string) *Builder {
	if listName != "" {
		b.listName = listName
	}
	if itemName != "" {
		b.itemName = itemName
	}
	return b
}

// Item 追加一个条目。
func (b *Builder) Item(fields ...F) *Builder {
	b.items = append(b.items, fields)
	return b
}

// Bytes 序列化。
func (b *Builder) Bytes() []byte {
	var out bytes.Buffer
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	out.WriteString("\r\n")
	elem(&out, b.root, func() {
		elem(&out, "CmdType", b.cmdType)
		elem(&out, "SN", b.sn)
		if b.deviceID != "" {
			elem(&out, "DeviceID", b.deviceID)
		}
		for _, f := range b.fields {
			elem(&out, f.Name, f.Value)
		}
		if len(b.items) > 0 {
			list := b.listName
			if list == "" {
				list = "DeviceList"
			}
			item := b.itemName
			if item == "" {
				item = "Item"
			}
			out.WriteString("<" + list + ">")
			for _, it := range b.items {
				elem(&out, item, func() {
					for _, f := range it {
						elem(&out, f.Name, f.Value)
					}
				})
			}
			out.WriteString("</" + list + ">")
		}
	})
	return out.Bytes()
}

// elem 写一个元素。值走 xml.EscapeText，所以设备编号里混进 '<' 之类也炸不了报文。
func elem(w io.Writer, name string, content any) {
	fmt.Fprintf(w, "<%s>", name)
	switch c := content.(type) {
	case string:
		_ = xml.EscapeText(w, []byte(c))
	case func():
		c()
	}
	fmt.Fprintf(w, "</%s>", name)
}

// ── 现场真发出去的那几条 ──

// DeviceInfoQuery 问设备信息（本机当平台，或者拿 MESSAGE 直接问一台设备）。
func DeviceInfoQuery(sn, deviceID string) []byte {
	return NewBuilder(RootQuery, CmdDeviceInfo, sn, deviceID).Bytes()
}

// DeviceStatusQuery 问在离线。★ 与 DeviceInfo 分开：不少设备答得出前者、答不出后者，
// 合在一条查询里就只能得到一个「不支持」。
func DeviceStatusQuery(sn, deviceID string) []byte {
	return NewBuilder(RootQuery, CmdDeviceStatus, sn, deviceID).Bytes()
}

// CatalogQuery 问通道表。start 为 0 表示从头；count 为 0 表示不写这两条，让它整表回。
func CatalogQuery(sn, deviceID string, start, count int) []byte {
	b := NewBuilder(RootQuery, CmdCatalog, sn, deviceID)
	if start > 0 || count > 0 {
		b.Set("StartPoint", strconv.Itoa(start))
		b.Set("Count", strconv.Itoa(count))
	}
	return b.Bytes()
}

// KeepaliveNotify 是设备往平台上报心跳的那一条。本机扮设备时发一条，
// 用来验「注册之外这条路通不通」—— 注册是 TCP-like 的一次性动作，心跳才看长期。
func KeepaliveNotify(sn, deviceID, status string) []byte {
	return NewBuilder(RootNotify, CmdKeepalive, sn, deviceID).Set("Status", status).Bytes()
}

// DeviceInfoResponsePayload 是本机扮设备时回给平台的那一份自述。
// 字段名按标准样例写死在调用处 —— 这里只负责顺序与转义，不猜哪家固件的别名。
func DeviceInfoResponsePayload(sn, deviceID string, fields ...F) []byte {
	b := NewBuilder(RootResponse, CmdDeviceInfo, sn, deviceID)
	for _, f := range fields {
		b.Set(f.Name, f.Value)
	}
	return b.Bytes()
}

// CatalogResponsePayload 是本机扮设备时回的通道表。sum 是它要看的「一共多少条」。
func CatalogResponsePayload(sn, deviceID string, sum int, items [][]F) []byte {
	b := NewBuilder(RootResponse, CmdCatalog, sn, deviceID).Set("SumNum", strconv.Itoa(sum))
	for _, it := range items {
		b.Item(it...)
	}
	return b.Bytes()
}

// DeviceStatusResponsePayload 回在离线与时间。
func DeviceStatusResponsePayload(sn, deviceID, status, timeText string) []byte {
	return NewBuilder(RootResponse, CmdDeviceStatus, sn, deviceID).
		Set("Status", status).Set("Time", timeText).Bytes()
}

// BodyCmd 从一条报文里把正文按 MANSCDP 解出来。
//
// ★ 「没正文」与「正文不是 MANSCDP」分成两档：前者多半是这台只把 SIP 当心跳用
//
//	（200 但不答这句查询），后者是同一个口上跑着别的东西。
//	两者的下一步完全不同，糊成一条就白问了。
func BodyCmd(msg *Message) (*Cmd, error) {
	if len(bytes.TrimSpace(msg.Body)) == 0 {
		return nil, &Error{Stage: "body", Kind: KindNoBody, Detail: "这条报文没有正文"}
	}
	cmd, err := ParseCmd(msg.Body)
	if err != nil {
		return nil, &Error{Stage: "body", Kind: KindBadBody, Detail: err.Error(), Err: err}
	}
	return cmd, nil
}
