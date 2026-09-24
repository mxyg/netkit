package snmp

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
)

// 这四条是从系统自带的 Net-SNMP 客户端上抓下来的**原始字节**
// （/usr/bin/snmpget、snmpwalk、snmpbulkwalk，团体名 public，目标 127.0.0.1）。
//
// ★★ 为什么要拿别人的实现钉自己：这一层的正确性没有第二种验证办法。
//
//	自己写、自己解，两边错到一处照样「测试全绿」，
//	而到了现场表现成「这台设备完全不应」—— 一个字节都不能差。
var goldens = []struct {
	name string
	hex  string
	// 期望解出来的字段
	version   int
	community string
	pdu       byte
	id        int32
	// nonRepeaters / maxRep 只在 GETBULK 有意义（同一格数字，两个意思）
	nr, mr int
	oids   []string
}{
	{
		name: "v2c GET sysDescr.0", version: Version2c, community: "public",
		pdu: PDUGetRequest, id: 0x670c0c53, oids: []string{"1.3.6.1.2.1.1.1.0"},
		hex: "302902010104067075626c6963a01c0204670c0c53020100020100300e300c06082b060102010101000500",
	},
	{
		// 版本 0 = v1。老交换机有一批只认这一档。
		name: "v1 GET sysUpTime.0", version: Version1, community: "public",
		pdu: PDUGetRequest, id: 0x52a7a29d, oids: []string{"1.3.6.1.2.1.1.3.0"},
		hex: "302902010004067075626c6963a01c020452a7a29d020100020100300e300c06082b060102010103000500",
	},
	{
		// walk 一步一步走的那一条：从 1.3.6.1.2.1.1 问「下一栏」。
		name: "v2c GETNEXT 1.3.6.1.2.1.1", version: Version2c, community: "public",
		pdu: PDUGetNextRequest, id: 0x4825ae5a, oids: []string{"1.3.6.1.2.1.1"},
		hex: "302702010104067075626c6963a11a02044825ae5a020100020100300c300a06062b06010201010500",
	},
	{
		// snmpbulkwalk -Cr25：non-repeaters 0、max-repetitions 25 = 0x19。
		// ★ 那两个数就是 PDU 里 error-status / error-index 那两格 —— 同一格两个意思，
		//   写反了的话设备每轮只给一行，walk 一棵大树慢几十倍还看不出为什么。
		name: "v2c GETBULK maxRep=25", version: Version2c, community: "public",
		pdu: PDUGetBulkRequest, id: 0x7bc7d8b6, nr: 0, mr: 25,
		oids: []string{"1.3.6.1.2.1.1"},
		hex:  "302702010104067075626c6963a51a02047bc7d8b6020100020119300c300a06062b06010201010500",
	},
}

func TestNetSNMP抓到的包能原样解开(t *testing.T) {
	for _, g := range goldens {
		b, err := hex.DecodeString(g.hex)
		if err != nil {
			t.Fatalf("%s 的样本本身写错了：%v", g.name, err)
		}
		p, err := Parse(b)
		if err != nil {
			t.Errorf("%s 解不开：%v", g.name, err)
			continue
		}
		if p.Version != g.version {
			t.Errorf("%s 版本 %d，要 %d", g.name, p.Version, g.version)
		}
		if p.Community != g.community {
			t.Errorf("%s 团体名 %q", g.name, p.Community)
		}
		if p.PDU != g.pdu {
			t.Errorf("%s PDU 0x%02x，要 0x%02x", g.name, p.PDU, g.pdu)
		}
		if p.ID != g.id {
			t.Errorf("%s 请求标识 %d，要 %d", g.name, p.ID, g.id)
		}
		// GETBULK 的那两格按 nr/mr 看，其余两种按 error-status/index 看，都必须是 0
		if g.pdu == PDUGetBulkRequest {
			if p.ErrStatus != g.nr || p.ErrIndex != g.mr {
				t.Errorf("%s non-repeaters=%d max-rep=%d，要 %d/%d",
					g.name, p.ErrStatus, p.ErrIndex, g.nr, g.mr)
			}
		} else if p.ErrStatus != 0 || p.ErrIndex != 0 {
			t.Errorf("%s 解出错误状态 %d/%d", g.name, p.ErrStatus, p.ErrIndex)
		}
		if len(p.VarBinds) != len(g.oids) {
			t.Errorf("%s 变量表 %d 栏，要 %d", g.name, len(p.VarBinds), len(g.oids))
			continue
		}
		for i, v := range p.VarBinds {
			if v.OID != g.oids[i] {
				t.Errorf("%s 第 %d 栏 OID %s，要 %s", g.name, i, v.OID, g.oids[i])
			}
			// ★ 请求里的值必须是 NULL：这一条不是格式洁癖，
			//   带了值过去，有些设备会照值比、直接把这一栏当已答。
			if v.Tag != TagNull {
				t.Errorf("%s 第 %d 栏的值类型是 0x%02x，请求里要 NULL", g.name, i, v.Tag)
			}
		}
	}
}

func Test我们拼的包和NetSNMP逐字节一样(t *testing.T) {
	// 上面的「解得开」只证明解的一端对；这一条才证明**发出去的那一串**对。
	for _, g := range goldens {
		var (
			p   Packet
			err error
		)
		switch g.pdu {
		case PDUGetRequest:
			p, err = NewGet(g.community, g.oids...)
		case PDUGetNextRequest:
			p, err = NewGetNext(g.community, g.oids...)
		case PDUGetBulkRequest:
			p, err = NewBulk(g.community, g.nr, g.mr, g.oids...)
		}
		if err != nil {
			t.Errorf("%s 拼不出来：%v", g.name, err)
			continue
		}
		p.Version = g.version
		p.ID = g.id
		out, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(out) != g.hex {
			t.Errorf("%s 拼成了\n%s\nNet-SNMP 是\n%s", g.name, hex.EncodeToString(out), g.hex)
		}
	}
}

func Test响应里的每一种值都按自己的类型读(t *testing.T) {
	// 一台真设备的 ifTable 一行里能同时出现这几类；统一转成 string 的话，
	// 「一个二进制 MAC」和「一个十进制计数器」在界面上就分不出来了。
	resp := Packet{
		Version: Version2c, Community: "public", PDU: PDUGetResponse, ID: 7,
		VarBinds: []VarBind{
			{OID: "1.3.6.1.2.1.1.1.0", Tag: TagOctetString, Val: []byte("H3C S5560")},
			{OID: "1.3.6.1.2.1.1.3.0", Tag: TagTimeTicks, Val: uintContent(123456)},
			{OID: "1.3.6.1.2.1.2.2.1.6.1", Tag: TagOctetString, Val: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
			{OID: "1.3.6.1.2.1.4.20.1.1", Tag: TagIPAddress, Val: []byte{192, 168, 1, 10}},
			{OID: "1.3.6.1.2.1.1.2.0", Tag: TagOID, Val: mustContent(t, "1.3.6.1.4.1.25506.1.516")},
			{OID: "1.3.6.1.2.1.2.2.1.8.1", Tag: TagInteger, Val: intContent(1)},
			{OID: "1.3.6.1.2.1.31.1.1.1.6.1", Tag: TagCounter64, Val: uintContent(9999999999)},
		},
	}
	b, err := resp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.VarBinds) != 7 {
		t.Fatalf("回来 %d 栏", len(got.VarBinds))
	}
	if s := got.VarBinds[0].Str(); s != "H3C S5560" {
		t.Errorf("sysDescr 读成 %q", s)
	}
	if n := got.VarBinds[1].UintOr0(); n != 123456 {
		t.Errorf("sysUpTime 读成 %d", n)
	}
	// ★ MAC 是二进制 OCTET STRING：这一栏绝不能被转成字符串，
	//   转完剩下的还是「一栏读不懂的乱码」，而它本该是「哪个口」。
	if mac := got.VarBinds[2].Val; len(mac) != 6 || mac[0] != 0x00 || mac[5] != 0x55 {
		t.Errorf("MAC 被改坏了：% x", mac)
	}
	if ip := got.VarBinds[3].IP(); ip == nil || ip.String() != "192.168.1.10" {
		t.Errorf("IpAddress 读成 %v", ip)
	}
	// 值本身是一个 OID：编的是内容那串，不是变量名。
	if s, err := AsOID(got.VarBinds[4].Val); err != nil || s != "1.3.6.1.4.1.25506.1.516" {
		t.Errorf("OID 值读成 %q/%v", s, err)
	}
	if n := got.VarBinds[5].IntOr0(); n != 1 {
		t.Errorf("ifOperStatus 读成 %d", n)
	}
	if n := got.VarBinds[6].UintOr0(); n != 9999999999 {
		t.Errorf("Counter64 读成 %d（超过 32 位就该用 64 位读）", n)
	}
}

func Test类型名每一种都有说法(t *testing.T) {
	// 界面上「这一栏是计数器还是瞬时值」决定要不要拿两次相减。
	// 露出「标签 0x41」这种，现场就只能回来问人。
	named := map[byte]string{
		TagInteger: "整数", TagOctetString: "字符串", TagOID: "OID",
		TagIPAddress: "IP 地址", TagCounter32: "计数器(32)", TagGauge32: "瞬时值",
		TagTimeTicks: "时间", TagOpaque: "不透明数据", TagCounter64: "计数器(64)",
		TagNoSuchObject: "没有这个对象", TagNoSuchInstance: "没有这一栏",
		TagEndOfMibView: "走到头",
	}
	for tag, want := range named {
		got := (VarBind{Tag: tag}).TypeName()
		if !strings.Contains(got, want) {
			t.Errorf("标签 0x%02x 的类型名 %q 里没有 %q", tag, got, want)
		}
	}
	// 私有标签（设备自己塞的）要原样报出来，别显示成空串
	if s := (VarBind{Tag: 0x66}).TypeName(); !strings.Contains(s, "66") {
		t.Errorf("没见过的标签报成 %q", s)
	}
}

func Test读值失败时要能看出来(t *testing.T) {
	// IntOr0 / UintOr0 是给「这一栏读不出来就少一栏」的统计用的，
	// 而 Int / Uint 这两条要能把失败原样报出去：一台设备把值写成十个字节时，
	// 静默给 0 比报错难查得多。
	tooBig := VarBind{Tag: TagCounter32, Val: make([]byte, 10)}
	if _, err := tooBig.Int(); err == nil {
		t.Error("十字节的整数没报错（会溢出）")
	}
	if _, err := tooBig.Uint(); err == nil {
		t.Error("十字节的无符号数没报错")
	}
	if n := tooBig.IntOr0(); n != 0 {
		t.Errorf("读不出来时 IntOr0 给了 %d", n)
	}
	// 六字节的 Counter32 是合法的（有些实现按 64 位发），这种要读得出来
	wide := VarBind{Tag: TagCounter32, Val: []byte{1, 2, 3, 4, 5, 6}}
	if n, err := wide.Uint(); err != nil || n != 0x010203040506 {
		t.Errorf("Counter32 按 6 字节发时读成 %d/%v", n, err)
	}
}

func TestIpAddress按长度读(t *testing.T) {
	if ip := (VarBind{Val: []byte{10, 0, 0, 1}}).IP(); ip.String() != "10.0.0.1" {
		t.Errorf("四字节读成 %v", ip)
	}
	// 十六字节也认：有的实现把 IPv6 塞进 Opaque 里回来
	if ip := (VarBind{Val: net.IPv6loopback}).IP(); ip == nil {
		t.Error("十六字节的地址没认出来")
	}
	// 长度对不上时给 nil，让上层按「这一栏读不懂」处理，
	// 而不是硬拼一个地址出来 —— 拼错的地址会被贴进设备配置里。
	if ip := (VarBind{Val: []byte{1, 2, 3}}).IP(); ip != nil {
		t.Errorf("三字节的垃圾被读成了 %v", ip)
	}
}

func mustContent(t *testing.T, oid string) []byte {
	t.Helper()
	c, err := OIDContent(oid)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func Test设备回一句不行要带出是哪一栏(t *testing.T) {
	// error-index 是 1 起的（RFC 3416），指到变量表的第 Index 栏。
	// 不换算这一格，界面上只能报「设备说不行」，人不知道换哪一栏。
	p := Packet{
		Version: Version2c, Community: "public", PDU: PDUGetResponse, ID: 1,
		ErrStatus: 5, ErrIndex: 2,
		VarBinds: []VarBind{{OID: "1.3.6.1.2.1.1.1.0"}, {OID: "1.3.6.1.2.1.2.2.1.1.1"}},
	}
	msg := &Error{Status: p.ErrStatus, Index: p.ErrIndex, OID: p.VarBinds[1].OID}
	if !strings.Contains(msg.Error(), "v1") {
		t.Errorf("wrongEncoding 的这句话没给出下一步：%s", msg.Error())
	}
	if !strings.Contains(msg.Error(), "1.3.6.1.2.1.2.2.1.1.1") {
		t.Errorf("没指出出错那一栏：%s", msg.Error())
	}
	// 设备没指出是哪一栏时（index 为 0 或越界），这句话不许自己再编一个「第 0 栏」
	if s := (&Error{Status: 2}).Error(); strings.Contains(s, "第") {
		t.Errorf("没给下标却报了栏位：%s", s)
	}
	// 每一种状态码都得有说法：露出「状态码 12」这种，现场就无从下手
	for n := 0; n <= 10; n++ {
		if s := StatusText(n); s == "" || strings.HasPrefix(s, "状态码") {
			t.Errorf("error-status %d 没有对应的话：%s", n, s)
		}
	}
}

func Test请求构造函数不许拼出写操作(t *testing.T) {
	// ★★ 这一层是「只读」的：整个包没有拼 SET 的入口，
	//   所以工具那一侧再怎么加参数也写不进设备 —— 靠结构保证，不靠记得校验。
	for _, tc := range []struct {
		name string
		p    Packet
	}{
		{"get", mustPacket(NewGet("public", "1.3.6.1.2.1.1.1.0"))},
		{"getnext", mustPacket(NewGetNext("public", "1.3.6.1.2.1.1"))},
		{"bulk", mustPacket(NewBulk("public", 0, 10, "1.3.6.1.2.1.2.2.1.1"))},
	} {
		if tc.p.PDU == PDUSetRequest || tc.p.PDU == PDUInformRequest {
			t.Errorf("%s 拼出来的是一个会改设备的报文 0x%02x", tc.name, tc.p.PDU)
		}
		if tc.p.Community != "public" {
			t.Errorf("%s 的团体名丢了", tc.name)
		}
		for _, v := range tc.p.VarBinds {
			if v.Tag != 0 {
				t.Errorf("%s 的请求栏带了值", tc.name)
			}
		}
	}
}

func Test参数不全时当场说清楚(t *testing.T) {
	if _, err := NewGet(""); err == nil || !strings.Contains(err.Error(), "团体名") {
		t.Errorf("空团体名报的是：%v", err)
	}
	if _, err := NewGet("public"); err == nil || !strings.Contains(err.Error(), "OID") {
		t.Errorf("一个 OID 都没给报的是：%v", err)
	}
	if _, err := NewGet("public", "  "); err == nil || !errors.Is(err, ErrBadOID) {
		t.Errorf("空白 OID 报的是：%v", err)
	}
	// 前后多余的点和空格是现场抄 OID 时最常见的
	p, err := NewGet("public", " .1.3.6.1.2.1.1.1.0 ")
	if err != nil {
		t.Fatalf("带点的 OID 没接受：%v", err)
	}
	if p.VarBinds[0].OID != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("前导点没去掉：%s", p.VarBinds[0].OID)
	}
}

func Test报文体外的垃圾一律不当数(t *testing.T) {
	// 每条都写清了**要错在哪一步**：只断言「报错了」的测试，
	// 会因为一个完全无关的原因通过，然后在那条真该拦的输入上漏掉。
	ok := mustPacket(NewGet("public", "1.3.6.1.2.1.1.1.0"))
	b, err := ok.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tail := append(append([]byte(nil), b...), 0x00)
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"尾巴上多一字节", tail, "尾巴"},
		// 顶层少了 PDU
		{"顶层只有两项", mustHex("3006020101040161"), "三项"},
		// 版本 9 从没定义过：认了它等于用一个不存在的编码去发请求
		{"版本号没见过", mustHex("3008020109040161a000"), "版本"},
		// 第三项是一个普通 INTEGER，不是构造类的 0xa0..0xa6
		{"第三项不是PDU", mustHex("300a02010104016104020500"), "PDU"},
		// 变量表里塞了一个整数（真设备上是被截断的一栏）
		{"变量表里不是序列", mustHex("3016020101040161a00e0201000201000201003003020100"), "不是序列"},
		// 变量表里只给了 OID 没给值
		{"变量表少一半", mustHex("3018020101040161a0100201000201000201003005300306012b"), "OID"},
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		if err == nil {
			t.Errorf("%s 居然解成功了", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s 报的是另一种错：%v（要话里带 %q）", c.name, err, c.want)
		}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustPacket(p Packet, err error) Packet {
	if err != nil {
		panic(err)
	}
	return p
}
