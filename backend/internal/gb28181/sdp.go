package gb28181

// SDP —— GB28181 里它只出现在 INVITE 的正文中，而且这一层**只读不写**。
//
// ★ 为什么只读：本软件不解码、不放播放器，也就不会真去收一路 RTP。
//
//	收到 INVITE 时最想说的那几句（它要哪个口、要哪一路流、要实时还是回放、
//	要发给谁）全在这段正文里，读出来就够了。回一条带自己 SDP 的 200 OK
//	等于答应建立媒体流 —— 那是播放器的活，不是探测工具的活。
//
// ★ 为什么不复用 RTSP 那一份 SDP 解析：那份在 internal/media 里，
// 跟着 RTSP 的事务与超时走，且只关心 sprop-parameter-sets 这类编码信息。
// 这里的关注点完全不同（口、地址、SSRC、方向），而且不能引 media 包
// （media 引了 net 之外的东西，SIP 这一层要保持纯标准库、零构建标记）。
//
// 容错口径（现场比 RFC 野）：行分隔认 CRLF 也认裸 LF；未知类型原样留着不报错；
// 会话级与媒体级都可能出现 c=/a=/y=，按位置分别记账。
// 报错只留给「读了也当没读过会更糟」的三种：没有 v=、行里没有 '='、m= 里的口不是数字。

import (
	"fmt"
	"strconv"
	"strings"
)

// Line 是一条按原样留下的 SDP 行。
type Line struct {
	Type    string // 单字母：v o s c t m a b k z y u q p …
	Value   string
	Session bool // true = 在第一条 m= 之前（会话级）
}

// Origin 是 o= 那六个字段。
type Origin struct {
	UserName   string
	SessionID  string
	SessionVer string
	NetType    string // IN
	AddrType   string // IP4 / IP6
	Address    string
	Extra      []string // 标准说六个字段，现场给过七个的也见过
}

// Conn 是 c=：网络类型、地址类型、地址（组播时后面还带 TTL）。
type Conn struct {
	NetType  string
	AddrType string // IP4 / IP6
	Address  string
	TTL      int
	HasTTL   bool
}

// Multicast 说这条路要发给的是组播地址。★ 现场一类难查的毛病是「点播发出去了、
// 播放器里没画面」，而流其实发到了一个组播组上，本机没加组 —— 这一条就是那句话的依据。
func (c Conn) Multicast() bool {
	i := strings.IndexByte(c.Address, '.')
	if i < 0 { // 组播 IPv6 是 ff 开头
		return strings.HasPrefix(strings.ToLower(c.Address), "ff")
	}
	n, err := strconv.Atoi(c.Address[:i])
	return err == nil && n >= 224 && n <= 239
}

// Media 是一段 m= 打头的媒体描述。
type Media struct {
	Type      string // audio / video / application …
	Port      int
	PortCount int      // 「口/数量」里那个数量，没写就是 1
	Proto     string   // RTP/AVP、RTP/SAVP …
	Formats   []string // 载荷类型，GB28181 里常见 96
	Conns     []Conn
	Attrs     []Attr
	Others    []Line
}

// Attr 是 a=，拆成名字与值（没有冒号时值留空，如 a=recvonly）。
type Attr struct {
	Name  string
	Value string
	Raw   string
}

// Session 是一份读完了的 SDP。
type Session struct {
	Origin      Origin
	SessionName string
	Conns       []Conn // 会话级的 c=
	Attributes  []Attr // 会话级的 a=
	Timing      []string
	Media       []Media
	Others      []Line   // 没单独建模的那些（b= k= y= u= z= q= p=…），按原顺序
	Lines       []Line   // 全部行，按原顺序 —— 「它到底发了什么」就报这个
	Unknown     []string // 认不出类型的行（★ 只记类型字母，别把内容带进结果）
}

// ParseSDP 读一份 SDP。
func ParseSDP(raw []byte) (*Session, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	var (
		s       = &Session{}
		inMedia = -1 // m= 之后才有媒体段
		seenV   = false
		lineNo  int
	)
	for _, ln := range strings.Split(text, "\n") {
		lineNo++
		ln = strings.TrimRight(ln, " \t\r")
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, " ") {
			// SDP 没有折行这一说；见到缩进就是上一条后面多出来的碎字节。
			// ★ 不能当新行读，也不能整个报错：记一笔就继续。
			s.Unknown = append(s.Unknown, "line "+strconv.Itoa(lineNo))
			continue
		}
		if len(ln) < 2 || ln[1] != '=' {
			return nil, fmt.Errorf("第 %d 行不成 SDP 的样子（要 x=内容）：%q", lineNo, clip(ln))
		}
		typ := ln[:1]
		val := ln[2:]
		if typ == "v" {
			if seenV {
				s.Unknown = append(s.Unknown, "line "+strconv.Itoa(lineNo))
				continue
			}
			seenV = true
			if _, err := strconv.Atoi(strings.TrimSpace(val)); err != nil {
				return nil, fmt.Errorf("v= 里的版本号不是数字：%q", clip(val))
			}
			continue
		}
		if !seenV {
			return nil, fmt.Errorf("第一行不是 v=（第 %d 行是 %q）", lineNo, clip(ln))
		}
		s.Lines = append(s.Lines, Line{Type: typ, Value: val, Session: inMedia < 0})
		switch typ {
		case "o":
			f := strings.Fields(val)
			if len(f) < 6 {
				return nil, fmt.Errorf("o= 只有 %d 个字段，标准要 6 个：%q", len(f), clip(val))
			}
			s.Origin = Origin{UserName: f[0], SessionID: f[1], SessionVer: f[2],
				NetType: f[3], AddrType: f[4], Address: f[5], Extra: f[6:]}
		case "s":
			s.SessionName = val
		case "t":
			s.Timing = append(s.Timing, val)
		case "c":
			c, err := parseConn(val)
			if err != nil {
				return nil, fmt.Errorf("c= 读不下去（第 %d 行）：%v", lineNo, err)
			}
			if inMedia < 0 {
				s.Conns = append(s.Conns, c)
			} else {
				s.Media[inMedia].Conns = append(s.Media[inMedia].Conns, c)
			}
		case "a":
			a := parseAttr(val)
			if inMedia < 0 {
				s.Attributes = append(s.Attributes, a)
			} else {
				s.Media[inMedia].Attrs = append(s.Media[inMedia].Attrs, a)
			}
		case "m":
			m, err := parseMedia(val)
			if err != nil {
				return nil, fmt.Errorf("m= 读不下去（第 %d 行）：%v", lineNo, err)
			}
			s.Media = append(s.Media, m)
			inMedia = len(s.Media) - 1
		default:
			if inMedia < 0 {
				s.Others = append(s.Others, Line{Type: typ, Value: val, Session: true})
			} else {
				s.Media[inMedia].Others = append(s.Media[inMedia].Others,
					Line{Type: typ, Value: val})
			}
			switch typ {
			case "b", "k", "y", "u", "z", "q", "p", "r":
			default:
				s.Unknown = append(s.Unknown, "line "+strconv.Itoa(lineNo)+" type "+typ)
			}
		}
	}
	if !seenV {
		return nil, fmt.Errorf("这份正文里没有 v=，不是 SDP")
	}
	return s, nil
}

func parseConn(val string) (Conn, error) {
	f := strings.Fields(val)
	if len(f) < 3 {
		return Conn{}, fmt.Errorf("字段不足：%q", clip(val))
	}
	c := Conn{NetType: f[0], AddrType: f[1]}
	// ★ 组播时地址那一栏本身就带斜杠：`224.5.0.1/127` 是「组地址 + TTL」，
	//	整栏当地址读出来就成了「要发给一个叫 224.5.0.1/127 的地址」，
	//	照它去加组必然失败 —— 而界面上只会显示一个看着没错的串。
	addr := f[2]
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		if n, err := strconv.Atoi(strings.SplitN(addr[i+1:], "/", 2)[0]); err == nil {
			c.TTL, c.HasTTL = n, true
		}
		addr = addr[:i]
	}
	c.Address = addr
	if len(f) > 3 { // 也有把 TTL 另起一栏写的
		n, err := strconv.Atoi(strings.SplitN(f[3], "/", 2)[0])
		if err == nil && !c.HasTTL {
			c.TTL, c.HasTTL = n, true
		}
	}
	return c, nil
}

func parseAttr(val string) Attr {
	name, value, _ := strings.Cut(val, ":")
	return Attr{Name: strings.TrimSpace(name), Value: strings.TrimSpace(value), Raw: val}
}

func parseMedia(val string) (Media, error) {
	f := strings.Fields(val)
	if len(f) < 3 {
		return Media{}, fmt.Errorf("字段不足（要 类型 口 协议 …）：%q", clip(val))
	}
	port, count, err := parsePort(f[1])
	if err != nil {
		return Media{}, err
	}
	m := Media{Type: f[0], Port: port, PortCount: count, Proto: f[2], Formats: f[3:]}
	return m, nil
}

// parsePort 认 "30000" 与 "30000/2"（RFC 4566 允许 口/数量）。
func parsePort(s string) (port, count int, err error) {
	count = 1
	if i := strings.IndexByte(s, '/'); i >= 0 {
		n, cerr := strconv.Atoi(s[i+1:])
		if cerr != nil || n <= 0 {
			return 0, 0, fmt.Errorf("口后面那个数量不是正数：%q", clip(s))
		}
		count = n
		s = s[:i]
	}
	if strings.ContainsRune(s, '-') { // 有些设备把口写成一段范围
		return 0, 0, fmt.Errorf("口写成了一段范围：%q，这一版只认单个口或 口/数量", clip(s))
	}
	n, cerr := strconv.Atoi(s)
	if cerr != nil {
		return 0, 0, fmt.Errorf("m= 里的口不是数字：%q", clip(s))
	}
	if n < 0 || n > 65535 {
		return 0, 0, fmt.Errorf("m= 里的口超出范围：%d", n)
	}
	return n, count, nil
}

// Connection 给会话级第一条 c=；没有再看第一段媒体。
// ★ 顺序按 RFC：媒体级 c= 覆盖会话级，所以两段都有时应取媒体级那一条 ——
// 但现场 INVITE 两条都带且不一致的固件我没法凭空写，这里只如实分开摆着，
// 由工具层把两条都报出来，不替现场猜哪一条算数。
func (s *Session) Connection() (Conn, bool) {
	if len(s.Conns) > 0 {
		return s.Conns[0], true
	}
	for _, m := range s.Media {
		if len(m.Conns) > 0 {
			return m.Conns[0], true
		}
	}
	return Conn{}, false
}

// MediaPort 是第一段媒体的口。
func (s *Session) MediaPort() (int, bool) {
	if len(s.Media) == 0 {
		return 0, false
	}
	if s.Media[0].Port <= 0 {
		// ★ 口写 0 在 SDP 里是「把这路流作废」，不是「用默认口」。
		//	当成 0 号口去解释，界面上就成了「它要往端口 0 发」这种不存在的事。
		return 0, false
	}
	return s.Media[0].Port, true
}

// Attribute 按名字取会话级 a=（大小写无关）。
func (s *Session) Attribute(name string) (string, bool) {
	for _, a := range s.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Value, true
		}
	}
	return "", false
}

// Attribute 按名字取这一段媒体里的 a=（名字只比冒号前那半段）。
func (m Media) Attribute(name string) (string, bool) {
	for _, a := range m.Attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Value, true
		}
	}
	return "", false
}

// Direction 给 a=sendrecv / recvonly / sendonly / inactive 那一条。
// ★ GB28181 的 INVITE 里设备是发流的一方，所以正常应看到 recvonly（平台收）。
// 反过来看到 sendonly 就说明这条不是点播 —— 别照着「点播」的思路去解释它。
func (s *Session) Direction() (string, bool) {
	for _, a := range s.Attributes {
		switch strings.ToLower(a.Name) {
		case "sendrecv", "recvonly", "sendonly", "inactive":
			return strings.ToLower(a.Name), true
		}
	}
	if len(s.Media) > 0 {
		for _, a := range s.Media[0].Attrs {
			switch strings.ToLower(a.Name) {
			case "sendrecv", "recvonly", "sendonly", "inactive":
				return strings.ToLower(a.Name), true
			}
		}
	}
	return "", false
}

// SSRC 取 y= 的第一个字段。
//
// ★ y= 是 GB28181 自己在 SDP 里加的扩展，用来点明这一路流的标识；
// 后面那一两个字段各家写法不同（有的带编码方式、有的带条数），
// 所以这里只取第一个字段，剩下的原样留在 Others 里 —— 不替厂家猜。
// 有实时/历史之分的说法在标准里是按首位 0/1 编进这个数值的，
// 但那是「读出来解释」的活，工具层要引哪一份口径得先钉死，故此处不分类。
func (s *Session) SSRC() (string, bool) {
	for _, l := range s.Others {
		if l.Type == "y" {
			if f := strings.Fields(l.Value); len(f) > 0 {
				return f[0], true
			}
		}
	}
	for _, m := range s.Media {
		for _, l := range m.Others {
			if l.Type == "y" {
				if f := strings.Fields(l.Value); len(f) > 0 {
					return f[0], true
				}
			}
		}
	}
	return "", false
}

// URI 取 u= 那一行（GB28181 用它带上这次点播对应的信令地址与时间）。
// 同样只原样给出，不解释格式 —— 各家写法差异见不到实样就不下结论。
func (s *Session) URI() (string, bool) {
	for _, l := range s.Others {
		if l.Type == "u" && strings.TrimSpace(l.Value) != "" {
			return strings.TrimSpace(l.Value), true
		}
	}
	return "", false
}

// BodySDP 从一条报文里取出正文并读成 SDP。
// ★ 复用了已有的两种错误种类：空正文是 no-body，正文不是 SDP 是 bad-body ——
// 工具层的判定码不必为每种正文各开一种「读不下去」。
func BodySDP(msg *Message) (*Session, error) {
	if msg == nil {
		return nil, &Error{Stage: "sdp", Kind: KindNoBody, Detail: "这条报文本身都没有"}
	}
	if len(msg.Body) == 0 {
		return nil, &Error{Stage: "sdp", Kind: KindNoBody, Detail: "它带的正文是空的"}
	}
	s, err := ParseSDP(msg.Body)
	if err != nil {
		return nil, &Error{Stage: "sdp", Kind: KindBadBody, Detail: err.Error(), Err: err}
	}
	return s, nil
}

// clip 只把控制字节换成可见符号并截短：这些文本会进结果与日志。
func clip(s string) string {
	return peekText([]byte(s))
}
