package broadcast

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ── NetBIOS over TCP/IP（RFC 1002）──
//
// ★★ 这一路是四种口径里唯一能拿到 **MAC** 的：NODE STATUS 应答末尾那 6 个字节
//
//	是对方网卡自己报的 UNIT_ID。拿到 MAC 才接得上交换机那一侧 ——
//	「10.0.12.77 是谁」→「它的 MAC 是 xx:xx:xx」→「插在 3 号口」→「那根线到 X 柜」。
//	ARP 表也能给 MAC，但 ARP 只覆盖 v4 邻居，而 NetBIOS 还顺手把机器名与角色带回来。
//
// 名字编码是这里唯一的巧劲：一个 16 字节的 NetBIOS 名被写成 32 个字符，
// 每个原字符拆成两个半字节、各加 'A'（RFC 1002 §4.1 的 first-level encoding）。
// 第 16 个字符不是名字的一部分，是**服务编号**（这台机器上哪个服务在用这个名字）。

const nbQuery = 0x0020 // NAME QUERY
const nbStatus = 0x0021
const nbRespFlag = 0x8000

// NBName 一个解出来的 NetBIOS 名。
type NBName struct {
	Name    string `json:"name"`
	Suffix  int    `json:"suffix"` // 第 16 个字符：服务编号
	Group   bool   `json:"group"`  // 组名（不是唯一名）
	Active  bool   `json:"active"`
	Owner   string `json:"owner,omitempty"` // B / P / M 节点类型
	Service string `json:"service,omitempty"`
}

// encodeNBName 把 15 字符的名字 + 1 个服务编号编成 32 个字符（不含长度字节）。
func encodeNBName(name string, suffix byte) ([]byte, error) {
	if len(name) > 15 {
		return nil, fmt.Errorf("NetBIOS 名 %q 有 %d 个字符，超过 15 的上限", name, len(name))
	}
	if strings.ContainsAny(name, ".") {
		// 点会被当成标签分隔符，编码进去就解不回来了；宁可报错，不静默改写。
		return nil, fmt.Errorf("NetBIOS 名 %q 里有点：这个名字不能这么问", name)
	}
	padded := name + strings.Repeat(" ", 15-len(name))
	out := make([]byte, 0, 33)
	out = append(out, 0x20) // 长度字节固定 32
	for i := 0; i < 15; i++ {
		out = append(out, 'A'+(padded[i]>>4), 'A'+(padded[i]&0x0F))
	}
	out = append(out, 'A'+(suffix>>4), 'A'+(suffix&0x0F))
	return out, nil
}

// decodeNBName 反过来：32 个字符 → 15 字符名 + 服务编号。
func decodeNBName(b []byte) (string, byte, error) {
	if len(b) != 32 {
		return "", 0, fmt.Errorf("编码名有 %d 个字符，要 32 个", len(b))
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi, lo := b[2*i], b[2*i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "", 0, fmt.Errorf("编码名第 %d 段 %q 不在 A-P 范围内", i, string(b[2*i:2*i+2]))
		}
		raw[i] = (hi-'A')<<4 | (lo - 'A')
	}
	return strings.TrimRight(string(raw[:15]), " "), raw[15], nil
}

// NodeStatusRequest 拼一条「这台机器上有哪些名字、你的 MAC 是多少」。
//
// ★ 名字用通配符（'*' + 15 个空格，RFC 1002 §4.2.17）：这是 nbtstat -A 的问法。
//
//	用具体名字问只会拿到那一个名，MAC 也就跟着丢了。
//
// ★ 第 16 个字符也是**空格**，不是 0x00：那一栏在这里不当服务编号用。
//
//	头部也不置 RD（照 RFC 的图，NODE STATUS 那几位全 0，只有 NAME QUERY 才置 RD）。
func NodeStatusRequest(trnID uint16) ([]byte, error) {
	q, err := encodeNBName("*", ' ')
	if err != nil {
		return nil, err
	}
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], trnID)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT
	b = append(b, hdr...)
	b = append(b, q...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], nbStatus)
	binary.BigEndian.PutUint16(tail[2:4], classIN)
	return append(b, tail[:]...), nil
}

// NameQueryRequest 拼一条「这个名字对应的地址是多少」（广播问法）。
// 现在的用法是反过来核对：手上有名字、想知道它是哪台。
func NameQueryRequest(trnID uint16, name string, suffix byte) ([]byte, error) {
	q, err := encodeNBName(name, suffix)
	if err != nil {
		return nil, err
	}
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], trnID)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	b = append(b, hdr...)
	b = append(b, q...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], nbQuery)
	binary.BigEndian.PutUint16(tail[2:4], classIN)
	return append(b, tail[:]...), nil
}

// ErrNotNetBIOS 表示这一条不是能认的 NetBIOS 报文。
var ErrNotNetBIOS = errors.New("不是 NetBIOS 报文")

// NodeStatus 一条 NODE STATUS 应答。
type NodeStatus struct {
	Names   []NBName
	MAC     string
	Jumpers int
	Tests   int
}

// ParseNodeStatus 解一条 NODE STATUS 应答。
//
// ★★ 布局跟普通 DNS 不一样（RFC 1002 §4.2.18），这是这一路最容易读错的地方：
//
//	应答里 **QDCOUNT=0、ANCOUNT=1**，那一条 RR 的 RDLENGTH 位置上写的不是字节数，
//	而是 **NUM_NAMES（名字条数）**；名字数组后面紧跟着统计段，统计段的头 6 字节
//	就是 UNIT_ID，也就是这台的 MAC。照普通 DNS 去解会得到「一个名 + 一堆乱码」。
//	有的实现会把问题段带回来，所以问题段按 QDCOUNT 跳过，不假设它是 0。
func ParseNodeStatus(msg []byte) (*NodeStatus, error) {
	if len(msg) < 12 {
		return nil, ErrNotNetBIOS
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&nbRespFlag == 0 {
		return nil, ErrNotNetBIOS // 这是别人发的查询，不是应答
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	if qd+an > 8 {
		return nil, ErrNotNetBIOS
	}
	pos := 12
	for i := 0; i < qd; i++ { // 跳过问题段：里面的名字就是我们发出去的那个
		next, err := skipEncodedName(msg, pos)
		if err != nil {
			return nil, err
		}
		if next+4 > len(msg) {
			return nil, ErrNotNetBIOS
		}
		pos = next + 4 // 问题段只有 类型 + 类
	}
	ns := &NodeStatus{}
	numNames := 0
	for i := 0; i < an; i++ {
		next, err := skipEncodedName(msg, pos)
		if err != nil {
			return nil, err
		}
		if next+10 > len(msg) {
			return nil, ErrNotNetBIOS
		}
		if t := binary.BigEndian.Uint16(msg[next : next+2]); t != nbStatus {
			return nil, ErrNotNetBIOS // 不是 NBSTAT 的 RR：这不是我们要解的那种应答
		}
		numNames = int(binary.BigEndian.Uint16(msg[next+8 : next+10])) // 这一栏是 NUM_NAMES
		pos = next + 10
	}
	if numNames > MaxNamesPerNB {
		return nil, fmt.Errorf("一条应答里写了 %d 个名，超过 %d 的上限", numNames, MaxNamesPerNB)
	}
	whole := true // 名数组是否整读完了 —— 没读完就量不出统计段的起始位置
	for i := 0; i < numNames; i++ {
		if pos+34 > len(msg) {
			whole = false
			break // 名数组被截断：已经收到的那些仍然有用
		}
		name, suffix, err := decodeNBName(msg[pos : pos+32])
		if err != nil {
			return ns, nil
		}
		pos += 32
		f := binary.BigEndian.Uint16(msg[pos : pos+2])
		pos += 2
		ns.Names = append(ns.Names, NBName{
			Name: name, Suffix: int(suffix), Group: f&0x8000 != 0, Active: f&0x0400 != 0,
			Owner: ownerNode(f), Service: nbServiceName(suffix, f&0x8000 != 0),
		})
	}
	// 统计段第一个字段 UNIT_ID(6) 就是 MAC。★ 位置按名字数组算出来，不去报文里
	// 扫 6 个字节：MAC 出现在别处（比如某个名字的内容里）是有可能的，扫一次就报错一次。
	// 名数组没读完时同样不许给 —— 那时候算出来的位置是半个名，看上去像个 MAC。
	if whole && len(msg) >= pos+6 {
		ns.MAC = macString(msg[pos : pos+6])
		if len(msg) >= pos+10 {
			ns.Jumpers = int(binary.BigEndian.Uint16(msg[pos+6 : pos+8]))
			ns.Tests = int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		}
	}
	if len(ns.Names) == 0 {
		return nil, ErrNotNetBIOS
	}
	return ns, nil
}

// Reports 把一台机器的名字表摊成自报记录。
//
// ★ 只摊**活跃的唯一名**：组名（域、Workstation 组）一台机器上是十几个相同的字符串，
//
//	全摊出来的话，界面上那台机器有十几行、每行都叫同一个 WORKGROUP。
//	非活跃的名（它自己都没在用）也不算它现在是什么。
//
// ★ MAC 挂在每一条上而不是单独一条：工具层是按 IP 归并设备的，
//
//	单独一条没有名字的记录会被并成一个「只有 MAC 的设备」。
func (ns *NodeStatus) Reports(from string) []*Report {
	if ns == nil {
		return nil
	}
	var out []*Report
	for _, n := range ns.Names {
		if n.Group || !n.Active || n.Name == "" {
			continue
		}
		out = append(out, &Report{
			Source: SourceNetBIOS, From: from, Name: n.Name,
			MAC: ns.MAC, Service: n.Suffix, Detail: n.Service,
			Text: map[string]string{"owner": n.Owner},
		})
	}
	if len(out) == 0 && ns.MAC != "" {
		// 一个活跃唯一名都没有，MAC 还是那句「这台是谁」的答案，别丢。
		out = append(out, &Report{Source: SourceNetBIOS, From: from, MAC: ns.MAC})
	}
	return out
}

// skipEncodedName 跳过一个「长度字节 + 32 个字符」的编码名。
func skipEncodedName(msg []byte, pos int) (int, error) {
	if pos >= len(msg) {
		return 0, ErrNotNetBIOS
	}
	n := int(msg[pos])
	if n == 0 {
		return pos + 1, nil
	}
	if n != 32 || pos+1+n > len(msg) {
		return 0, ErrNotNetBIOS
	}
	return pos + 1 + n, nil
}

// ownerNode 把 NAME_FLAGS 的 ONT 两位翻成节点类型。
//
// ★ ONT 在整字的第 14、13 位（RFC 1002 那张图把位号从左边数，所以图上写的是
//
//	"1,2"）：00=B 广播节点、01=P 问 WINS、10=M 混合、11 保留。
//	为什么值得翻出来：B 节点说明这台靠局域网广播注册名字，Name Query 找得到它；
//	P 节点则可能只在 WINS 里注册，广播查不到 —— 那一句「查不到」的解释就不一样。
func ownerNode(f uint16) string {
	switch (f >> 13) & 0x03 {
	case 0:
		return "B"
	case 1:
		return "P"
	case 2:
		return "M"
	}
	return ""
}

// nbServiceName 第 16 个字符的服务编号 → 这个号在 RFC 1002 / Windows 里指什么服务。
//
// ★ 表只收录**公开定义清楚**的号，其余原样写「没有对得上的公开定义」。
//
//	为什么不猜、也不图全：同一台机器上 <00> 是工作站服务、<20> 是文件共享，
//	差一个号下一步要查的东西就不一样；编一个名字出来，人就照着错方向查下去。
func nbServiceName(suffix byte, group bool) string {
	switch suffix {
	case 0x00:
		if group {
			return "这台机器所属的工作组/域名"
		}
		return "计算机名（工作站服务）"
	case 0x01:
		if group {
			return "组消息服务（主浏览器候选组）"
		}
		return "消息服务"
	case 0x03:
		return "消息服务（唯一名）"
	case 0x06:
		return "RAS 服务器服务"
	case 0x1B:
		return "域主浏览器"
	case 0x1C:
		if group {
			return "域控制器组（这台所在的域里有 DC）"
		}
		return "域控制器（这台是 DC）"
	case 0x1D:
		return "本机是所在子网的主浏览器"
	case 0x1E:
		return "浏览器服务选举"
	case 0x1F:
		return "NetDDE 服务"
	case 0x20:
		return "服务器服务（这台开了文件与打印共享）"
	case 0x21:
		return "RAS 客户端服务"
	}
	return fmt.Sprintf("服务编号 0x%02X（这一版没有对得上的公开定义）", suffix)
}
