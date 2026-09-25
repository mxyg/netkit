package gb28181

import (
	"fmt"
	"strings"
	"testing"
)

func TestSIP请求序列化再解回来(t *testing.T) {
	req := NewRequest(MethodOptions, "sip:34020000002000000001@3402000000:5060",
		`<sip:34020000001110000001@192.168.1.50:5060>`, `<sip:34020000002000000001@3402000000:5060>`,
		"call-1@192.168.1.50", "SIP/2.0/UDP 192.168.1.50:5060;branch=z9hG4bKaa11", 1)
	req.Set(HUserAgent, "netkit")
	req.Body = []byte("<hello/>")
	raw := req.MustBytes()
	if !strings.Contains(string(raw), "Content-Length: 8\r\n") {
		t.Fatalf("正文非空却没补 Content-Length：\n%s", raw)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != MethodOptions || !got.IsRequest() {
		t.Fatalf("方法或方向不对：%+v", got)
	}
	if got.CallID() != "call-1@192.168.1.50" {
		t.Fatalf("Call-ID 丢了：%q", got.CallID())
	}
	seq, method, ok := got.CSeq()
	if !ok || seq != 1 || method != MethodOptions {
		t.Fatalf("CSeq 解错：%d %q %v", seq, method, ok)
	}
	if got.TopViaBranch() != "z9hG4bKaa11" {
		t.Fatalf("branch 解错：%q", got.TopViaBranch())
	}
	if string(got.Body) != "<hello/>" {
		t.Fatalf("正文不对：%q", got.Body)
	}
}

func TestSIP裸换行的报文也要认(t *testing.T) {
	// 不少固件发出来是裸 \n。只按 \r\n 切，等于把一条答得清清楚楚的回包判成「没答」。
	raw := "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\nFrom: <sip:a@b>;tag=t1\nTo: <sip:c@d>\nCall-ID: x\nCSeq: 7 OPTIONS\n\n"
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Status != 200 || msg.Reason != "OK" {
		t.Fatalf("状态行不对：%d %q", msg.Status, msg.Reason)
	}
	if !msg.IsResponse() {
		t.Fatal("被当成请求了")
	}
	if msg.Get("to") != "<sip:c@d>" {
		t.Fatalf("头没收到：%q", msg.Headers)
	}
}

func TestSIP正文按ContentLength截(t *testing.T) {
	// 末尾多一个换行的固件：多出来的那点不能被当成 XML 的一部分。
	body := "<Response><CmdType>Catalog</CmdType><SN>1</SN><DeviceID>34020000001110000001</DeviceID></Response>\r\n"
	msg := NewRequest(MethodMessage, "sip:a@b", "<sip:a@b>", "<sip:a@b>", "c1", "SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bKx", 1)
	msg.Body = []byte(body)
	msg.Set(HContentLength, fmt.Sprint(len(body)-2)) // 比正文短一截：按声明的长度截
	raw := msg.MustBytes()
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(body) - 2; len(got.Body) != want {
		t.Fatalf("没按 Content-Length 截：%d，想要 %d", len(got.Body), want)
	}
}

func TestSIP折行并到上一条(t *testing.T) {
	raw := "SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;\r\n branch=z9hG4bK776\r\nCall-ID: c\r\nCSeq: 3 OPTIONS\r\n\r\n"
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.TopViaBranch(); got != "z9hG4bK776" {
		t.Fatalf("折行没并进来：%q", msg.Get(HVia))
	}
}

func TestSIP紧凑头名展开(t *testing.T) {
	raw := "SIP/2.0 200 OK\r\nv: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK9\r\nf: <sip:a@b>;tag=1\nt: <sip:c@d>;tag=2\ni: call-9\nCSeq: 2 OPTIONS\nl: 0\r\n\r\n"
	msg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.CallID() != "call-9" {
		t.Fatalf("紧凑 i 没认出来：%q", msg.CallID())
	}
	if msg.TopViaBranch() != "z9hG4bK9" {
		t.Fatalf("紧凑 v 没认出来：%q", msg.Get(HVia))
	}
	if msg.To().Param("tag") != "2" {
		t.Fatalf("紧凑 t 没认出来：%q", msg.Get(HTo))
	}
}

func TestSIP起始行不像SIP就报错(t *testing.T) {
	for _, raw := range []string{"HTTP/1.1 400 Bad Request\r\n\r\n", "\r\n\r\n", "SIP/2.1 200 OK\r\n\r\n"} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("这条不该解成 SIP：%q", raw)
		}
	}
}

func TestSIP状态码越界与缺URI(t *testing.T) {
	if _, err := (&Message{Status: 7, Reason: "x"}).Bytes(); err == nil {
		t.Fatal("状态码 7 该报错")
	}
	if _, err := (&Message{Method: "OPTIONS"}).Bytes(); err == nil {
		t.Fatal("缺 Request-URI 该报错")
	}
}

func TestSIP地址解析的几种形状(t *testing.T) {
	cases := []struct {
		in     string
		user   string
		host   string
		port   string
		tag    string
		name   string
		errPos string
	}{
		{in: "sip:34020000001110000001@3402000000:5060", user: "34020000001110000001", host: "3402000000", port: "5060"},
		{in: "<sip:a@h>;tag=abc", user: "a", host: "h", tag: "abc"},
		{in: `"3号枪机" <sip:a@h:5060>;tag=abc`, user: "a", host: "h", port: "5060", tag: "abc", name: "3号枪机"},
		// 参数写在尖括号里面是不合规的，但现场有：拒掉就是把答对的报文当没答。
		{in: "<sip:a@h;tag=inline>", user: "a", host: "h", tag: "inline"},
		{in: "sips:a@h", user: "a", host: "h"},
		// 显示名里带分号：不能在那儿切一刀。
		{in: `"前;后" <sip:a@h>;tag=t`, user: "a", host: "h", tag: "t", name: "前;后"},
	}
	for _, c := range cases {
		a, err := ParseAddr(c.in)
		if err != nil {
			t.Fatalf("%q 解失败：%v", c.in, err)
		}
		if a.User != c.user || a.Host != c.host || a.Port != c.port {
			t.Fatalf("%q 解成 %+v", c.in, a)
		}
		if a.Param("tag") != c.tag {
			t.Fatalf("%q 的 tag = %q，想要 %q", c.in, a.Param("tag"), c.tag)
		}
		if a.DisplayName != c.name {
			t.Fatalf("%q 的显示名 = %q，想要 %q", c.in, a.DisplayName, c.name)
		}
	}
	for _, bad := range []string{"http://a/b", "sip:a@h:port", "sip:@", ""} {
		if _, err := ParseAddr(bad); err == nil {
			t.Fatalf("这条该报错：%q", bad)
		}
	}
}

func TestSIP地址序列化稳定(t *testing.T) {
	a := Addr{Scheme: "sip", User: "u", Host: "h", Port: "5060", Params: map[string]string{"tag": "t1", "user": "phone"}}
	first := a.String()
	for i := 0; i < 20; i++ {
		if a.String() != first {
			t.Fatalf("同一个地址两次拼出来不一样：%q / %q", first, a.String())
		}
	}
	if !strings.HasPrefix(first, "sip:u@h:5060;tag=t1;user=phone") {
		t.Fatalf("序列化形状不对：%q", first)
	}
}

func TestSIP响应照抄Via顺序并补tag(t *testing.T) {
	req, err := Parse([]byte("OPTIONS sip:h SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKtop\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKmine\r\n" +
		"From: <sip:a@h>;tag=ft\r\nTo: <sip:b@h>\r\nCall-ID: c\r\nCSeq: 5 REGISTER\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewResponseFor(req, 401, "")
	vias := resp.All(HVia)
	if len(vias) != 2 || !strings.Contains(vias[0], "z9hG4bKtop") || !strings.Contains(vias[1], "z9hG4bKmine") {
		t.Fatalf("Via 顺序或内容不对：%v", vias)
	}
	if resp.Reason != "Unauthorized" {
		t.Fatalf("原因短语没按状态码补：%q", resp.Reason)
	}
	to, err := ParseAddr(resp.Get(HTo))
	if err != nil {
		t.Fatal(err)
	}
	if to.Param("tag") == "" {
		t.Fatal("To 上没有 tag：缺 tag 的 401 会被设备当成没答，重发一趟")
	}
	if seq, method, ok := resp.CSeq(); !ok || seq != 5 || method != MethodRegister {
		t.Fatalf("CSeq 没照抄：%d %q", seq, method)
	}
	// 请求已经带 tag 时不能再补一个。
	req2 := &Message{Method: MethodOptions, URI: "sip:h"}
	req2.Add(HTo, "<sip:b@h>;tag=已有")
	if n := strings.Count(NewResponseFor(req2, 200, "").Get(HTo), "tag="); n != 1 {
		t.Fatalf("已有 tag 又被补了一个：%q", NewResponseFor(req2, 200, "").Get(HTo))
	}
}

func TestSIP的branch与tag(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		b := NewBranch()
		if !strings.HasPrefix(b, "z9hG4bK") {
			t.Fatalf("branch 没带魔术前缀（平台会当不合规报文丢掉）：%q", b)
		}
		if seen[b] {
			t.Fatalf("branch 撞号了：%q", b)
		}
		seen[b] = true
	}
	if len(NewTag()) < 8 {
		t.Fatal("tag 太短，容易撞")
	}
}

func TestSIP的Expires与CSeq缺了就说缺(t *testing.T) {
	msg := &Message{Method: MethodRegister, URI: "sip:h"}
	if _, ok := msg.Expires(); ok {
		t.Fatal("没这条头不该报有")
	}
	msg.Set(HExpires, "abc")
	if _, ok := msg.Expires(); ok {
		t.Fatal("非数字的 Expires 不该当成有效（这是「平台没给有效期」，不是「有效期是 0」）")
	}
	msg.Set(HExpires, "100")
	if n, ok := msg.Expires(); !ok || n != 100 {
		t.Fatalf("Expires 没读出来：%v %v", n, ok)
	}
	if _, _, ok := msg.CSeq(); ok {
		t.Fatal("没有 CSeq 却报了序号")
	}
}

func TestVia拼出去与读回来要往返一致(t *testing.T) {
	v := NewVia("127.0.0.1", "5060")
	v.Params["received"] = "10.0.0.2"
	v.Params["rport"] = ""
	s := v.String()
	want := "SIP/2.0/UDP 127.0.0.1:5060;branch=" + v.Param("branch") + ";received=10.0.0.2;rport="
	if s != want {
		t.Fatalf("拼出来的 Via 不是那个形状：\n got %q\nwant %q", s, want)
	}
	back, err := ParseVia(s)
	if err != nil {
		t.Fatalf("自己拼的 Via 自己读不回来：%v", err)
	}
	if back.Host != "127.0.0.1" || back.Port != "5060" || back.Transport != "UDP" {
		t.Errorf("往返后头几段变了：%+v", back)
	}
	if back.Param("branch") != v.Param("branch") || back.Param("received") != "10.0.0.2" {
		t.Errorf("往返后参数丢了：%+v", back.Params)
	}
	// ★ 同一份结构两次拼出的字节必须一样：重发的那一条要一字不差。
	if v.String() != s {
		t.Error("同一个 Via 两次拼出不一样 —— 重发就成两趟事务了")
	}
}
