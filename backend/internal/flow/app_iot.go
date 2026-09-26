package flow

// 物联网与网管那几种：MQTT、DHCP、SNMP，还有大华那族私有协议。
//
// 为什么 MQTT 在一台网络排查工具里排得跟 RTSP 一样前：
// 楼宇、道闸、电梯、充电桩、消防那一整批设备现在全走 MQTT，
// 而「连不上 broker」在现场被说成「网络不通」的比率极高 ——
// 答案就在 CONNACK 那一个字节里（4 是账号密码不对，5 是没授权，3 是 broker 没起）。
// 不看这一格，这张表只能说「TCP 连上了」，而那正是把人引错方向的那半句。

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"net.yuhox.com/netkit/internal/dhcp"
	"net.yuhox.com/netkit/internal/snmp"
)

// ==================== MQTT ====================

// MQTT 报文类型。界面上出现的是这几个号后面的那句人话。
const (
	mqttConnect     = 1
	mqttConnAck     = 2
	mqttPublish     = 3
	mqttPubAck      = 4
	mqttPubRec      = 5
	mqttPubRel      = 6
	mqttPubComp     = 7
	mqttSubscribe   = 8
	mqttSubAck      = 9
	mqttUnsubscribe = 10
	mqttUnsubAck    = 11
	mqttPingReq     = 12
	mqttPingResp    = 13
	mqttDisconnect  = 14
)

// mqttMaxRemaining 是一条报文允许声明的最大长度。
// ★ 4 字节的剩余长度能表达到 256MB；不设这一格，一份脏包就能把这一方向的缓冲要到头。
const mqttMaxRemaining = 1 << 20

var mqttTypeNames = map[byte]string{
	mqttConnect: "CONNECT", mqttConnAck: "CONNACK", mqttPublish: "PUBLISH",
	mqttPubAck: "PUBACK", mqttPubRec: "PUBREC", mqttPubRel: "PUBREL",
	mqttPubComp: "PUBCOMP", mqttSubscribe: "SUBSCRIBE", mqttSubAck: "SUBACK",
	mqttUnsubscribe: "UNSUBSCRIBE", mqttUnsubAck: "UNSUBACK",
	mqttPingReq: "PINGREQ", mqttPingResp: "PINGRESP", mqttDisconnect: "DISCONNECT",
}

// CONNACK 的返回码。★ 这十六个字是这一档最值钱的一格：
// 现场问「为什么上不去」，答案常常就是这里的一个数字，
// 而没解开的抓包上看不出来 —— 字节流长得很像，端口也通。
var mqttConnAckText = map[byte]string{
	0: "受理（连上了）",
	1: "协议版本号不对（两端实现的 MQTT 版本不匹配：3.1 的客户端连 5.0 的 broker 常见这一句）",
	2: "客户端标识符被拒（ClientID 不合法，或这台 broker 不许这个名字）",
	3: "服务不可用（broker 自己在起、正在装载、或者前端挂了 —— 不是网络问题）",
	4: "用户名或口令不对",
	5: "没有授权（凭据是对的，但这个账号不许做这件事：权限那侧的问题）",
}

// cutMQTT 按 MQTT 的固定头切一条。回 (占多少字节, 是否已齐)。
//
// ★ 一条报文占的是「1 字节固定头 + n 字节剩余长度字段 + rem 字节正文」，
// 少了最前面那一个 1 就会每条都切短一字节：下一条从上一版的尾巴中间开始读，
// 于是一条都解不动，而表上只写着「没解出来」。
func cutMQTT(b []byte) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	rem, n, err := mqttRemainingLength(b[1:])
	if err != nil {
		return len(b), true // 剩余长度那一格本身就坏了：把这一段作废，别把整条流堵死
	}
	if rem > mqttMaxRemaining {
		return len(b), true // 声明得离谱：同上，跳过而不是等
	}
	if 1+n+rem > len(b) {
		return 0, false
	}
	return 1 + n + rem, true
}

// mqttRemainingLength 解那个 1~4 字节的变长整数。回 (值, 占了几字节, 错)。
func mqttRemainingLength(b []byte) (int, int, error) {
	var (
		multiplier = 1
		value      = 0
	)
	for i := 0; i < 4; i++ {
		if i >= len(b) {
			return 0, 0, fmt.Errorf("flow: MQTT 剩余长度还在继续，包已经到边了")
		}
		digit := int(b[i] & 0x7f)
		value += digit * multiplier
		if multiplier > 128*128*128 {
			return 0, 0, fmt.Errorf("flow: MQTT 剩余长度超过 4 字节能表的范围")
		}
		multiplier *= 128
		if b[i]&0x80 == 0 {
			if i == 3 && digit > 1 {
				return 0, 0, fmt.Errorf("flow: MQTT 剩余长度第 4 字节的低位不该大于 1（不最短编码）")
			}
			return value, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("flow: MQTT 剩余长度超过 4 字节")
}

// isMQTTPlausible 问这一份字节像不像一条完整的 MQTT 报文。
//
// ★ 要求「长度正好对上」才认：只看类型号的话，一堆二进制正文都会被判成 MQTT，
// 界面上就出现「一条 HTTP 上传里 CONNECT 了一个客户端」。
func isMQTTPlausible(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	typ := b[0] >> 4
	if typ < mqttConnect || typ > mqttDisconnect {
		return false
	}
	if !mqttFlagsValid(typ, b[0]&0x0f) {
		return false
	}
	rem, n, err := mqttRemainingLength(b[1:])
	if err != nil {
		return false
	}
	// 固定头那一个字节也要算进「正好一条」里：少算它就永远差一字节，
	// 于是一条真 MQTT 报文递到眼前，这一档却说「不像 MQTT」。
	return 1+n+rem == len(b)
}

// mqttFlagsValid 按规范检查每种类型的标志位。
// 这几条是写死在协议里的（不是「常见实现」），脏了就不该按 MQTT 解。
func mqttFlagsValid(typ, flags byte) bool {
	switch typ {
	case mqttConnect, mqttConnAck, mqttPubComp, mqttSubAck, mqttUnsubAck,
		mqttPingReq, mqttPingResp, mqttDisconnect:
		return flags == 0
	case mqttPublish:
		return flags&0x01 == 0 // 保留位里 bit0 必须是 0
	case mqttPubAck, mqttPubRec, mqttPubRel, mqttUnsubscribe:
		return flags == 0x02
	}
	return false
}

func decodeMQTT(raw []byte) (*Message, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("flow: MQTT 报文太短")
	}
	typ := raw[0] >> 4
	flags := raw[0] & 0x0f
	rem, hdr, err := mqttRemainingLength(raw[1:])
	if err != nil {
		return nil, err
	}
	// hdr 是「剩余长度那一格占了几字节」，正文从它后面开始 —— 前面还有固定头那一个字节。
	// 少算这一个 1，body 就以剩余长度那一格开头，协议名的两字节长度就成了 0x22 之类的数，
	// 每一条 CONNECT 都会带着「解不动」上屏。
	bodyStart := 1 + hdr
	if bodyStart+rem > len(raw) {
		return nil, fmt.Errorf("flow: MQTT 声明 %d 字节，实际只带回来 %d", rem, len(raw)-bodyStart)
	}
	body := raw[bodyStart : bodyStart+rem]
	m := &Message{Proto: "mqtt", Kind: "packet", Fields: []Field{}}
	switch typ {
	case mqttConnect:
		m.Kind = "request"
		m.Method = "CONNECT"
		decodeMQTTConnect(m, body)
	case mqttConnAck:
		m.Kind = "response"
		m.Method = "CONNACK"
		decodeMQTTConnAck(m, body)
	case mqttPublish:
		m.Kind = "notify"
		m.Method = "PUBLISH"
		decodeMQTTPublish(m, body, flags)
	case mqttPubAck, mqttPubRec, mqttPubRel, mqttPubComp:
		m.Kind = "response"
		m.Method = mqttTypeNames[typ]
		decodeMQTTID(m, body)
	case mqttSubscribe:
		m.Kind = "request"
		m.Method = "SUBSCRIBE"
		decodeMQTTSubscribe(m, body)
	case mqttSubAck:
		m.Kind = "response"
		m.Method = "SUBACK"
		decodeMQTTSubAck(m, body)
	case mqttUnsubscribe:
		m.Kind = "request"
		m.Method = "UNSUBSCRIBE"
		decodeMQTTID(m, body)
	case mqttUnsubAck:
		m.Kind = "response"
		m.Method = "UNSUBACK"
		decodeMQTTID(m, body)
	case mqttPingReq, mqttPingResp, mqttDisconnect:
		m.Kind = "packet"
		m.Method = mqttTypeNames[typ]
	default:
		return nil, fmt.Errorf("flow: MQTT 类型号 %d 没定义", typ)
	}
	if m.Summary == "" {
		m.Summary = m.Method
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

// mqttStr 取一个 UTF-8 字符串（前两字节是长度）。
func mqttStr(b []byte) (string, int, error) {
	if len(b) < 2 {
		return "", 0, fmt.Errorf("flow: MQTT 字符串声明越界")
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if 2+n > len(b) {
		return "", 0, fmt.Errorf("flow: MQTT 字符串声明 %d 字节，只剩 %d", n, len(b)-2)
	}
	return string(b[2 : 2+n]), 2 + n, nil
}

func decodeMQTTConnect(m *Message, b []byte) {
	name, n, err := mqttStr(b)
	if err != nil {
		m.Note = "CONNECT 解不动：" + err.Error()
		return
	}
	m.Fields = append(m.Fields, field("协议名", name))
	if n >= len(b) {
		return
	}
	level := b[n]
	n++
	m.Fields = append(m.Fields, field("协议版本", mqttVersionName(name, level)))
	if n >= len(b) {
		return
	}
	fl := b[n]
	n++
	if n+2 <= len(b) {
		// 保活秒数：现场「设备每隔一会儿掉一次线」那一案看的就是这一格，
		// 与 PINGREQ 的实际间隔对不对得上（对不上是那一头没发，不是网络）。
		m.Fields = append(m.Fields, field("保活秒数", strconv.Itoa(int(binary.BigEndian.Uint16(b[n:n+2])))))
		n += 2
	}
	if fl&0x01 != 0 {
		m.Fields = append(m.Fields, field("标志位", "bit0 不是 0（协议要求保留位为 0：这一条不合规）"))
	}
	if fl&0x02 != 0 {
		m.Fields = append(m.Fields, field("清理会话", "置上了（每次连都当新会话，broker 那边留的离线消息丢掉）"))
	} else {
		m.Fields = append(m.Fields, field("清理会话", "没置（broker 要替这台设备留着离线消息）"))
	}
	// 5.0 在这里多一串属性（变长整数表长度）；不跳过去，ClientID 就从属性中间开始读。
	if level == 5 {
		_, used, err := mqttRemainingLength(b[min(n, len(b)):])
		if err != nil {
			m.Note = "CONNECT 的 5.0 属性长度解不动，后面的客户端标识与凭据几格没读"
			return
		}
		n += used
	}
	if n > len(b) {
		return
	}
	id, used, err := mqttStr(b[n:])
	if err != nil {
		m.Note = "CONNECT 的客户端标识解不动：" + err.Error()
		return
	}
	// ★ 用户名留着、口令糊掉：现场要问的就是「哪个账号被拒了」。
	// 很多设备直接把 ClientID 当用户名，所以这一格连「是不是凭据」都算不上；
	// 而把用户名一起糊掉，等于把 CONNACK 的 4 与 5 那两句作废。
	m.Fields = append(m.Fields, field("客户端标识", id))
	rest := b[n+used:]

	// 遗嘱、用户名、口令这三格必须按标志位决定读不读：不照标志位走，
	// 就会把上一段字符串的尾巴当成下一段的开头长度，整条错位——
	// 错位之后界面上那格「用户名」其实是口令的前几个字，这是最坏的一种错。
	if fl&0x04 != 0 { // Will Flag
		if level == 5 {
			_, wu, err := mqttRemainingLength(rest)
			if err != nil {
				m.Note = "遗嘱属性长度解不动"
				return
			}
			rest = rest[wu:]
		}
		topic, wu, err := mqttStr(rest)
		if err != nil {
			m.Note = "遗嘱主题解不动"
			return
		}
		rest = rest[wu:]
		m.Fields = append(m.Fields, field("遗嘱主题", topic), field("遗嘱消息", mqttBytesText(rest)))
		rest = rest[min(len(rest), mqttLen(rest)):]
		m.Fields = append(m.Fields, field("遗嘱 QoS", strconv.Itoa(int((fl>>3)&3))))
		if fl&0x20 != 0 {
			m.Fields = append(m.Fields, field("遗嘱保留", "置上了（设备掉线后这条还挂在主题上）"))
		}
	}
	if fl&0x80 != 0 { // User Name
		user, uu, err := mqttStr(rest)
		if err != nil {
			m.Note = "带了用户名那一格，但这个字符串解不动"
			return
		}
		rest = rest[uu:]
		m.Fields = append(m.Fields, field("用户名", user))
	}
	if fl&0x40 != 0 { // Password
		m.Fields = append(m.Fields, secretField("口令", mqttBytesText(rest)))
		m.Creds++
	}
	m.Summary = "CONNECT 客户端标识 " + id
}

// mqttLen 回这一段开头那个两字节长度声明占到的总字节数（含前两字节）。
func mqttLen(b []byte) int {
	if len(b) < 2 {
		return len(b)
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if 2+n > len(b) {
		return len(b)
	}
	return 2 + n
}

// mqttBytesText 把一段字节变成能上屏的一句：整段可打印就给原文，否则只给长度。
func mqttBytesText(b []byte) string {
	n := mqttLen(b)
	if n < 2 {
		return "（没带）"
	}
	payload := b[2:n]
	if s, ok := printablePrefix(payload, 200); ok {
		return s
	}
	return fmt.Sprintf("%d 字节（不是可打印文本，没往表上塞）", len(payload))
}

func mqttVersionName(name string, level byte) string {
	switch {
	case strings.EqualFold(name, "MQIsdp") && level == 3:
		return "3.1"
	case strings.EqualFold(name, "MQTT") && level == 4:
		return "3.1.1"
	case strings.EqualFold(name, "MQTT") && level == 5:
		return "5.0"
	}
	return fmt.Sprintf("级别 %d（协议名 %s：这两个号配不上，至少有一端不合规）", level, name)
}

func decodeMQTTConnAck(m *Message, b []byte) {
	if len(b) < 2 {
		m.Note = "CONNACK 只带回来 " + strconv.Itoa(len(b)) + " 字节"
		return
	}
	m.Status = int(b[1])
	m.Fields = append(m.Fields, field("会话保留", map[bool]string{true: "有（旧会话还在）", false: "无（新会话）"}[b[0]&1 != 0]))
	m.Fields = append(m.Fields, field("返回码", strconv.Itoa(int(b[1]))))
	if s, ok := mqttConnAckText[b[1]]; ok {
		m.Summary = "CONNACK：" + s
		if b[1] != 0 {
			m.Findings = append(m.Findings, Finding{Code: "mqtt-connack-" + strconv.Itoa(int(b[1])), Text: s})
		}
		return
	}
	m.Summary = "CONNACK：返回码 " + strconv.Itoa(int(b[1])) + "（这一档没定义）"
	m.Findings = append(m.Findings, Finding{Code: "mqtt-connack-unknown",
		Text: "CONNACK 的返回码是 " + strconv.Itoa(int(b[1])) + "，不在协议定义的六个号里：broker 的实现不合规范"})
}

func decodeMQTTPublish(m *Message, b []byte, flags byte) {
	qos := (flags >> 1) & 3
	topic, n, err := mqttStr(b)
	if err != nil {
		m.Note = "PUBLISH 的主题解不动：" + err.Error()
		return
	}
	m.Method = "PUBLISH"
	m.URI = topic
	m.Fields = append(m.Fields, field("主题", topic), field("QoS", strconv.Itoa(int(qos))))
	if qos > 2 {
		m.Fields = append(m.Fields, field("QoS", "头里写着 "+strconv.Itoa(int(qos))+"（协议只到 2：这条不合规）"))
	}
	rest := b[n:]
	if qos > 0 {
		if len(rest) < 2 {
			m.Note = "QoS>0 却没有报文标识号那一格（这一条不合规）"
			return
		}
		m.Seq = strconv.Itoa(int(binary.BigEndian.Uint16(rest[0:2])))
		rest = rest[2:]
	}
	m.Fields = append(m.Fields, field("正文长度", strconv.Itoa(len(rest))))
	if s, ok := printablePrefix(rest, 200); ok {
		m.Fields = append(m.Fields, field("正文", s))
	}
	if retain := flags & 1; retain != 0 {
		m.Fields = append(m.Fields, field("保留位", "置上了（后来订阅的人也会收到这一条）"))
	}
}

func decodeMQTTID(m *Message, b []byte) {
	if len(b) < 2 {
		return
	}
	m.Seq = strconv.Itoa(int(binary.BigEndian.Uint16(b[0:2])))
	m.Fields = append(m.Fields, field("报文标识号", m.Seq))
	m.Summary = m.Method + " 对应标识号 " + m.Seq
}

func decodeMQTTSubscribe(m *Message, b []byte) {
	if len(b) < 2 {
		return
	}
	m.Seq = strconv.Itoa(int(binary.BigEndian.Uint16(b[0:2])))
	m.Fields = append(m.Fields, field("报文标识号", m.Seq))
	rest := b[2:]
	for i := 0; len(rest) > 0 && i < 32; i++ {
		topic, n, err := mqttStr(rest)
		if err != nil {
			m.Note = "订阅列表在第 " + strconv.Itoa(i+1) + " 个主题上解不动"
			return
		}
		qos := "?"
		if n < len(rest) {
			qos = strconv.Itoa(int(rest[n] & 0x03))
			rest = rest[n+1:]
		} else {
			rest = rest[n:]
		}
		m.Fields = append(m.Fields, field(fmt.Sprintf("订阅 %d", i+1), topic+" QoS "+qos))
	}
	if len(rest) > 0 {
		m.Fields = append(m.Fields, field("订阅", "还有若干条没列（上限 32）"))
	}
}

func decodeMQTTSubAck(m *Message, b []byte) {
	if len(b) < 3 {
		return
	}
	m.Seq = strconv.Itoa(int(binary.BigEndian.Uint16(b[0:2])))
	m.Fields = append(m.Fields, field("报文标识号", m.Seq))
	var codes []string
	for _, c := range b[2:] {
		switch {
		case c <= 2:
			codes = append(codes, "QoS"+strconv.Itoa(int(c)))
		case c == 0x80:
			codes = append(codes, "拒了（0x80）：这个主题它不许订，或订阅标识符用尽")
		default:
			codes = append(codes, "号 "+strconv.Itoa(int(c)))
		}
	}
	m.Fields = append(m.Fields, field("订阅结果", strings.Join(codes, "、")))
	m.Summary = "SUBACK：" + strings.Join(codes, "、")
	for _, c := range b[2:] {
		if c == 0x80 {
			m.Findings = append(m.Findings, Finding{Code: "mqtt-suback-refused",
				Text: "broker 明确拒了一个订阅（0x80）：订不到就是看不见数据，而连接本身是好的 —— 去查 ACL"})
			break
		}
	}
}

// printablePrefix 取正文前面可打印那一段。
//
// ★ 只取「前 200 字节 + 全是可打印字符」这一条件成立的那一份：
// 载荷是 protobuf 或图片时宁可只报长度，也不往表上塞一堆二进制乱码。
func printablePrefix(b []byte, n int) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if len(b) > n {
		b = b[:n]
	}
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f {
			return "", false
		}
	}
	return string(b), true
}

// ==================== DHCP ====================

// looksLikeDHCP 认 BOOTP 那一形状。
//
// ★ 要求长度至少到选项魔数（240）而且 htype=1/hlen=6：
// 「67/68 端口上的别的 UDP」不该被解成一次地址分配。
func looksLikeDHCP(b []byte) bool {
	if len(b) < 240 {
		return false
	}
	if b[0] != 1 && b[0] != 2 {
		return false
	}
	// htype=1 / hlen=6：以太网上就是这一对。别的（比如无线的 0/0、IB 的 32）
	// 形状对不上就别硬套 —— 「67/68 端口上的别的 UDP」不该被解成一次地址分配。
	return b[1] == 1 && b[2] == 6
}

func decodeDHCP(raw []byte) (*Message, error) {
	p, err := dhcp.Parse(raw)
	if err != nil {
		return nil, err
	}
	m := &Message{Proto: "dhcp", Kind: "packet", Fields: []Field{}}
	if p.Op == 1 {
		m.Kind = "request"
		m.Method = "BOOTREQUEST"
	} else {
		m.Kind = "response"
		m.Method = "BOOTREPLY"
	}
	m.Seq = strconv.Itoa(int(p.XID))
	m.Fields = append(m.Fields,
		field("事务号", strconv.Itoa(int(p.XID))),
		field("客户端 MAC", p.CHAddr.String()),
		field("客户端地址", ipOr(p.CIAddr, "（还没有）")),
		field("给它分的地址", ipOr(p.YIAddr, "（这一条里没给）")),
		field("下一个服务器", ipOr(p.SIAddr, "（没写）")),
		field("中继（网关）", ipOr(p.GIAddr, "（没经过中继）")),
	)
	msgType := p.MessageType()
	if name, ok := dhcpMessageTypeName(msgType); ok {
		m.Method = name
		m.Fields = append(m.Fields, field("DHCP 类型", name))
	} else if msgType != 0 {
		m.Fields = append(m.Fields, field("DHCP 类型", "编号 "+strconv.Itoa(int(msgType))+"（这一档没定义）"))
	}
	// 四格 IP 选项 + 租期：这五格就是「拿到地址之后能不能上网」的全部内容。
	for _, opt := range []struct {
		code  byte
		name  string
		multi bool // 一条选项里挤了几个地址（DNS 就是常见两个）
	}{
		{54, "提供这一份的服务器", false},
		{3, "默认网关", false},
		{6, "DNS 服务器", true},
		{15, "域名", false},
		{28, "广播地址", false},
		{42, "NTP 服务器", true},
		{121, "无路由选项（classless）", false},
	} {
		v := p.Options[opt.code]
		if len(v) == 0 {
			continue
		}
		if opt.multi && len(v)%4 == 0 {
			var ips []string
			for i := 0; i+4 <= len(v) && i/4 < 4; i += 4 {
				ips = append(ips, net.IP(v[i:i+4]).String())
			}
			m.Fields = append(m.Fields, field(opt.name, strings.Join(ips, "、")))
			continue
		}
		if !opt.multi && len(v)%4 == 0 && opt.code != 15 && opt.code != 121 {
			m.Fields = append(m.Fields, field(opt.name, net.IP(v).String()))
			continue
		}
		if opt.code == 15 || opt.code == 12 {
			m.Fields = append(m.Fields, field(opt.name, string(v)))
			continue
		}
		m.Fields = append(m.Fields, field(opt.name, fmt.Sprintf("%d 字节（这一格的编法这一档没解）", len(v))))
	}
	if v := p.Options[12]; len(v) > 0 {
		m.Fields = append(m.Fields, field("客户端主机名", string(v)))
	}
	if lr := p.Options[51]; len(lr) == 4 {
		m.Fields = append(m.Fields, field("租期", strconv.Itoa(int(binary.BigEndian.Uint32(lr)))+" 秒"))
	}
	if opts := dhcpOptionNames(p); opts != "" {
		m.Fields = append(m.Fields, field("带了哪些选项", opts))
	}
	m.Summary = dhcpSummary(m, p)
	if strings.Contains(m.Summary, "DISCOVER") {
		m.Findings = append(m.Findings, Finding{Code: "dhcp-discover-only",
			Text: "见到了一次 DISCOVER：这台机器在问有没有人给它地址。" +
				"只见到问、没见到回，是这一段里没有活的 DHCP 服务（或被中继挡住了）"})
	}
	m.Summary = scrubText(m.Summary)
	return m, nil
}

func ipOr(ip net.IP, ifEmpty string) string {
	if len(ip) == 0 || ip.IsUnspecified() {
		return ifEmpty
	}
	return ip.String()
}

func dhcpMessageTypeName(t byte) (string, bool) {
	switch t {
	case 1:
		return "DISCOVER", true
	case 2:
		return "OFFER", true
	case 3:
		return "REQUEST", true
	case 4:
		return "DECLINE", true
	case 5:
		return "ACK", true
	case 6:
		return "NAK", true
	case 7:
		return "RELEASE", true
	case 8:
		return "INFORM", true
	}
	return "", false
}

// dhcpOptionNames 列出带了哪些选项号（不长，够看出有没有 3/6/51 这几格）。
func dhcpOptionNames(p *dhcp.Packet) string {
	var out []string
	for c := range p.Options {
		if c == 255 || c == 0 {
			continue
		}
		out = append(out, strconv.Itoa(int(c)))
		if len(out) >= 24 {
			break
		}
	}
	return strings.Join(out, " ")
}

func dhcpSummary(m *Message, p *dhcp.Packet) string {
	name, ok := dhcpMessageTypeName(p.MessageType())
	if !ok {
		name = "BOOTP"
	}
	s := "DHCP " + name + "：" + p.CHAddr.String()
	if !p.YIAddr.IsUnspecified() && len(p.YIAddr) > 0 {
		s += " → 地址 " + p.YIAddr.String()
	}
	return s
}

// ==================== SNMP ====================

// looksLikeSNMP 认 SNMPv1/v2c 那个外壳：SEQUENCE { INTEGER 版本, OCTET STRING 团体名, ... }。
//
// ★ 三个条件都要过。只看 0x30 会把一整个 TLS 记录、一份 XML 都当成 SNMP。
func looksLikeSNMP(b []byte) bool {
	if len(b) < 8 || b[0] != 0x30 {
		return false
	}
	_, used, ok := berLength(b[1:])
	if !ok || 1+used+2 > len(b) {
		return false
	}
	i := 1 + used
	if b[i] != 0x02 { // 版本号是 INTEGER
		return false
	}
	vl, used2, ok := berLength(b[i+1:])
	if !ok || vl > 4 || i+1+used2+vl > len(b) {
		return false
	}
	v := 0
	for _, c := range b[i+1+used2 : i+1+used2+vl] {
		v = v<<8 | int(c)
	}
	if v < 0 || v > 3 { // v1=0 v2c=1 v3=3；2 是历史上没落地的 v2u
		return false
	}
	j := i + 1 + used2 + vl
	return j < len(b) && b[j] == 0x04 // 团体名是 OCTET STRING
}

func berLength(b []byte) (int, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, true
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 4 || len(b) < 1+n {
		return 0, 0, false
	}
	v := 0
	for _, c := range b[1 : 1+n] {
		v = v<<8 | int(c)
	}
	return v, 1 + n, true
}

func decodeSNMP(raw []byte) (*Message, error) {
	p, err := snmp.Parse(raw)
	if err != nil {
		return nil, err
	}
	m := &Message{Proto: "snmp", Fields: []Field{}}
	if p.Community != "" {
		// ★ 团体名就是 SNMP 的口令（v1/v2c 明文在每一包上）。
		// 抓一份边界设备的包就等于拿到它的读团体名 —— 这一格必须脱敏。
		m.Fields = append(m.Fields, secretField("团体名", p.Community))
		m.Creds++
	} else {
		m.Fields = append(m.Fields, field("团体名", "（空的：v3 或这一档没带）"))
	}
	m.Fields = append(m.Fields, field("版本", snmpVersionName(p.Version)))
	m.Seq = strconv.Itoa(int(p.ID))
	m.Fields = append(m.Fields, field("请求号", m.Seq))
	name, kind := snmpPDUName(p.PDU)
	m.Method = name
	m.Kind = kind
	if p.ErrStatus != 0 {
		m.Fields = append(m.Fields, field("错误", fmt.Sprintf("状态 %d、第 %d 个变量（%s）",
			p.ErrStatus, p.ErrIndex, snmpErrorText(p.ErrStatus))))
		m.Findings = append(m.Findings, Finding{Code: "snmp-error-" + strconv.Itoa(p.ErrStatus),
			Text: "设备回了一个错误：" + snmpErrorText(p.ErrStatus) + "（出在第 " + strconv.Itoa(p.ErrIndex) + " 个变量上）"})
	}
	writable := p.PDU == 0xa4 // SET：写方向整格脱敏（理由见 snmpValueField）
	if writable {
		m.Creds++
		m.Findings = append(m.Findings, Finding{Code: "snmp-set",
			Text: "有人在往这台设备**写**SNMP（SET）：配置被改过就是这一步，改的内容在这张表上按凭据处理了，" +
				"要还原得去设备自己的日志或上一份备份"})
	}
	for i, vb := range p.VarBinds {
		if i >= 32 {
			m.Fields = append(m.Fields, field("变量", "还有若干条没列（上限 32）"))
			break
		}
		m.Fields = append(m.Fields, snmpValueField(vb, writable))
	}
	m.Summary = snmpSummary(m, p)
	m.Summary = scrubText(m.Summary)
	return m, nil
}

func snmpVersionName(v int) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 2:
		return "v2u（历史上没落地的那一版）"
	case 3:
		return "v3（用户凭据在安全参数里，这一档没解）"
	}
	return "版本号 " + strconv.Itoa(v)
}

func snmpPDUName(t byte) (string, string) {
	switch t {
	case 0xa0:
		return "GET", "request"
	case 0xa1:
		return "GETNEXT", "request"
	case 0xa2:
		return "RESPONSE", "response"
	case 0xa4:
		return "SET", "request"
	case 0xa5:
		return "GETBULK", "request"
	case 0xa6:
		return "INFORM", "request"
	case 0xa7:
		return "TRAP", "notify"
	}
	return "PDU 编号 0x" + strconv.FormatUint(uint64(t), 16), "packet"
}

func snmpErrorText(s int) string {
	switch s {
	case 1:
		return "响应太长，装不下"
	case 2:
		return "请求里有个错误（OID 不存在或不可写）"
	case 3:
		return "有一个值没法加进表（只能写，写不进去）"
	case 4:
		return "拒绝（这一档 SNMP 不允许这个操作）"
	case 5:
		return "名字太长"
	case 6:
		return "这个值与那一格已有的类型不匹配"
	case 7:
		return "其他错误"
	}
	return "错误号 " + strconv.Itoa(s)
}

func snmpValueField(vb snmp.VarBind, writable bool) Field {
	if writable {
		// ★ SET 是把值**写进去**：现场用 SNMP 改的东西里就有团体名、口令、SNMP 用户的密钥，
		// 而没有 MIB 表就分不清这一格写的是口令还是端口描述。所以写方向整格糊掉 ——
		// 「谁在什么时候往设备上写了东西」这件事，长度加「有」已经足够回答。
		return secretField("OID "+vb.OID, vb.Str())
	}
	return Field{K: "OID " + vb.OID, V: strings.TrimSpace(vb.Str())}
}

func snmpSummary(m *Message, p snmp.Packet) string {
	s := "SNMP " + m.Method
	if len(p.VarBinds) > 0 {
		s += " " + p.VarBinds[0].OID
		if n := len(p.VarBinds); n > 1 {
			s += fmt.Sprintf(" 等 %d 格", n)
		}
	}
	if p.ErrStatus != 0 {
		s += "（设备回了错误）"
	}
	return s
}

// ==================== 大华那一族私有协议 ====================

// 大华的私有会话（37777 那一族，SDK / DSS / 智能平台之间走的都是它）没有公开规格。
//
// ★ 所以这里只做一件事：按帧头自洽性记账 —— 类型号在见过的那几个里、
// 而且帧头声明的长度与实际带回来的字节数对得上，才说「像一帧」。
// 长度对不上就不说，宁可不提。对上了，这一格也仍然只是「有这么一帧、多大」，
// 里面写了什么一概不说：猜出来的内容比空白更害人。
const (
	dahuaHeaderLen = 16
	dahuaMaxFrame  = 8 << 20
)

var dahuaProtoIDs = map[uint16]string{
	0x8001: "命令帧",
	0x8002: "应答帧",
	0x8008: "数据帧",
	0x8104: " ack/继续那一种",
	0x8206: "连接/登录那一种",
}

// looksLikeDH：这一族在链路上认得的形状。
func looksLikeDahua(b []byte) bool {
	if len(b) < dahuaHeaderLen {
		return false
	}
	if b[0] != 0 || b[1] != 0 {
		return false
	}
	id := binary.BigEndian.Uint16(b[2:4])
	if _, ok := dahuaProtoIDs[id]; !ok {
		return false
	}
	n := int(binary.BigEndian.Uint32(b[8:12]))
	return n >= dahuaHeaderLen && n <= dahuaMaxFrame && n <= len(b)
}

// cutDahua 按那一族自己的帧长切。够不了一条就等，绝不拿半帧去「解」。
func cutDahua(b []byte) (int, bool) {
	if len(b) < dahuaHeaderLen {
		if len(b) > dahuaMaxFrame {
			return len(b), true
		}
		return 0, false
	}
	n := int(binary.BigEndian.Uint32(b[8:12]))
	if n < dahuaHeaderLen || n > dahuaMaxFrame {
		return len(b), true // 长度那一格本身坏了：这一段作废，别把流堵在这
	}
	if n > len(b) {
		return 0, false
	}
	return n, true
}

func decodeDahua(raw []byte) (*Message, error) {
	if !looksLikeDahua(raw) {
		return nil, fmt.Errorf("flow: 不像大华私有协议的一帧（帧头自己就没对上）")
	}
	id := binary.BigEndian.Uint16(raw[2:4])
	name, ok := dahuaProtoIDs[id]
	if !ok {
		name = "类型号 0x" + strconv.FormatUint(uint64(id), 16) + "（这一族里没见过这个号）"
	}
	m := &Message{
		Proto: "dahua", Kind: "packet", Method: name,
		Fields: []Field{
			field("帧类型", fmt.Sprintf("0x%04x %s", id, name)),
			field("序号", strconv.Itoa(int(binary.BigEndian.Uint32(raw[4:8])))),
			field("帧长", strconv.Itoa(int(binary.BigEndian.Uint32(raw[8:12])))+" 字节"),
		},
	}
	m.Summary = "大华私有协议的一帧：" + name + "，" + strconv.Itoa(int(binary.BigEndian.Uint32(raw[8:12]))) + " 字节"
	m.Note = "这一族没有公开规格：这里只按帧头记账（类型、序号、长度），里面写了什么没有解。" +
		"要问内容，得拿设备那份 SDK 的说明来，这一档不猜"
	return m, nil
}
