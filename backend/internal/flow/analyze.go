package flow

// 从「一份抓包」到「一张表」的入口：导入已有 pcapng 与实时抓包走同一张表。
//
// ★ 为什么两边必须共用：现场拿到的文件大半不是本机抓的（同事用 tcpdump 抓的、
//   摄像头导出的一段、Wireshark 转出来的），而「这一条流丢了几包」这句结论
//   不该因为包是从磁盘上读的还是从网卡上接的就换一套算法。
//   两套口径迟早会给出两个数，那时候这张表连自己都不如。
//
// 这一层只认 capture 交出来的那几格（口序号、时刻、字节、线上长度）。
// 链路类型按**口**查，不按包上写的查：pcapng 里链路类型本来就是口的属性，
// 一个文件里同一口的包换了链路类型是文件坏了，不是要支持的事。

import (
	"fmt"
	"io"
	"strconv"

	"net.yuhox.com/netkit/internal/capture"
)

// Table 是一张正在攒的表：聚合器 + 口表 + 这一份来源自己的毛病。
//
// 「这一份来源自己的毛病」必须单独攒：没带时刻、口表里没有这一号、包被截过 ——
// 这三种都不是某一条流的问题，是整张表的口径问题，
// 混进某一条流的判定里，看的人就会去查那台机器。
type Table struct {
	a         *Aggregator
	ifaces    []capture.Interface
	byReason  map[string]int
	noStamp   int // 没带时刻的包数
	badIface  int // 口序号在口表里找不到的包数
	truncated int // 带回来的比线上声明的短的包数
	total     int
}

func NewTable(opt Options) *Table {
	return &Table{a: NewAggregator(opt), byReason: map[string]int{}}
}

// Aggregator 露出聚合器：工具层要按键取一条流、或要直接喂 Packet 时用。
func (t *Table) Agg() *Aggregator { return t.a }

// SetInterfaces 落口表（文件读到的、或采集口刚开出来的那份）。
// 可以反复调：跨段的 pcapng 与实时抓包都会陆续见到新口。
func (t *Table) SetInterfaces(inf []capture.Interface) {
	if len(inf) == 0 {
		return
	}
	t.ifaces = append([]capture.Interface(nil), inf...)
}

// Add 收一个采集/文件那一头的包，翻成这一层的口径再进表。
//
// 回的不是「这个包不要」就是错误：读坏了一处（口表缺号）只记一笔账，
// 后面的包照进 —— 一份文件坏一段就整份不读，等于让现场重抓一遍。
func (t *Table) Add(p capture.Packet) error {
	t.total++
	if len(p.Data) == 0 {
		t.note("正文为空（0 字节）")
		return nil
	}
	if p.OrigLen > len(p.Data) {
		t.truncated++
		t.note("被截过：线上 " + strconv.Itoa(p.OrigLen) + " 字节，只带回来 " + strconv.Itoa(len(p.Data)))
	}
	if !p.HasTimestamp {
		// ★ 不拿零值当「1970 年抓的」，也不拿前一包的时刻凑：
		// 那会让「第 3 秒那一下丢包」看着成立，实际是抄来的。
		t.noStamp++
	}
	lt, err := t.linkType(p.InterfaceIndex)
	if err != nil {
		t.badIface++
		t.note(err.Error())
		return err
	}
	t.a.Add(Packet{
		Timestamp: p.Timestamp,
		LinkType:  lt,
		Data:      p.Data,
		WireLen:   p.OrigLen,
		Iface:     t.ifaceName(p.InterfaceIndex),
	})
	return nil
}

// linkType 按口查链路类型；口表里没有这一号就是硬错（不许猜一个以太网顶上）。
func (t *Table) linkType(idx int) (uint16, error) {
	if idx < 0 || idx >= len(t.ifaces) {
		return 0, fmt.Errorf("口表里没有第 %d 号口（这一份文件的 IDB 不齐或段头错位）", idx)
	}
	return t.ifaces[idx].LinkType, nil
}

func (t *Table) ifaceName(idx int) string {
	if idx < 0 || idx >= len(t.ifaces) {
		return ""
	}
	if n := t.ifaces[idx].Name; n != "" {
		return n
	}
	if d := t.ifaces[idx].Description; d != "" {
		return d
	}
	return "口 " + strconv.Itoa(idx)
}

func (t *Table) note(s string) { t.byReason[s]++ }

// ReadFile 把一份抓包文件整份读进来（导入已有 pcapng 那一半需求）。
//
// 上限交给调用方定：这里不设「最多读多少包」，因为「只读了前一半」这件事
// 一旦被忘掉，界面上就会把前一半的结论当成整份的。要限就在外面数着停。
func (t *Table) ReadFile(r io.Reader) (int, error) {
	rd, err := capture.Open(r)
	if err != nil {
		return 0, err
	}
	t.SetInterfaces(rd.Ifaces())
	n := 0
	for {
		p, err := rd.Read()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			t.SetInterfaces(rd.Ifaces()) // 坏在这儿之前可能又见到了新口
			return n, err
		}
		t.SetInterfaces(rd.Ifaces())
		n++
		if e := t.Add(p); e != nil {
			// 口表缺号这类错一路都会犯，不能一犯就停：
			// 停下等于把后面本来读得出来的包全扔了，而账上还写着「读完了」。
			continue
		}
	}
}

// Flows 出整张表（含跨流连线）。
func (t *Table) Flows() []*Flow { return t.a.Flows() }

// Ledger 回包数账。
func (t *Table) Ledger() Ledger { return t.a.Ledger() }

// Report 是整张表那一层的口径：这一份来源有什么毛病，一句话能说清。
//
// 每一条都要能指着数说 —— 不许出现「结果可能不准」这种没有凭据的话。
func (t *Table) Report() []string {
	var out []string
	l := t.Ledger()
	if !l.Reconciles() {
		out = append(out, fmt.Sprintf(
			"包数账对不上：共 %d 包，拆到 IP/ARP %d 包，各笔没拆开的加起来 %d 包，少了 %d 包。"+
				"★对不上账的表连「这里没流量」都不该说",
			l.Total, l.Decoded, l.dropped(), l.Total-(l.Decoded+l.dropped())))
	}
	if l.PacketsDropped > 0 {
		out = append(out, fmt.Sprintf(
			"流表撞到上限（%d 条）：%d 包拆开了却没地方归，这些包不在下面任何一条流里。"+
				"★这一张表看着齐，其实是不齐的 —— 要全就调大上限或加筛选器重抓",
			l.FlowsDropped, l.PacketsDropped))
	}
	if len(t.ifaces) == 0 {
		out = append(out, "整份一个口都没读到：包上的口序号没有可对的东西，链路类型只能按已读到的那些算")
	}
	if t.noStamp > 0 {
		out = append(out, fmt.Sprintf(
			"%d 包没带时刻：这些包只进得了「几条、几字节」那种数，进不了「什么时候、隔多久」那种结论"+
				"（★没有拿前一包的时刻替它们凑）", t.noStamp))
	}
	if t.badIface > 0 {
		out = append(out, fmt.Sprintf(
			"%d 包的口序号在口表里找不到：这一份文件的接口描述不齐，那一些包没进表", t.badIface))
	}
	if t.truncated > 0 {
		out = append(out, fmt.Sprintf(
			"%d 包带回来的比线上声明的短（抓的时候设了 snaplen 或被剪过）：正文与后面那半截字段不可信", t.truncated))
	}
	for s, n := range t.byReason {
		if s == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s ×%d", s, n))
	}
	return out
}
