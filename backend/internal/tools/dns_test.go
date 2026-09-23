package tools

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// ★ 这里钉的是 DNS 查询工具里**会把结论带偏**的那几处纯逻辑：
//   PTR 的反写名字、rcode → 判定码的映射、答案条数的口径。
//   发真包的通路交给真机实测，测试里不打网络。

func TestReverseName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.10", "10.1.168.192.in-addr.arpa"},
		{"1.2.3.4", "4.3.2.1.in-addr.arpa"},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
		{"fd00::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"},
		{"fe80::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"},
	}
	for _, c := range cases {
		got, err := reverseName(c.in)
		if err != nil {
			t.Errorf("%s：不该报错，%s", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s：\n想要 %s\n拿到 %s", c.in, c.want, got)
		}
	}
	// 查 PTR 填了域名 —— 必须当场拒，不能默默去查一个不存在的东西
	if _, err := reverseName("www.example.com"); err == nil {
		t.Error("填域名该报错，不该去查一个假 IP 的 PTR")
	}
}

func TestDNSVerdict(t *testing.T) {
	cases := []struct {
		rcode   dnsmessage.RCode
		n       int
		want    string
		explain string
	}{
		{dnsmessage.RCodeSuccess, 2, dnsResolved, "有答案"},
		// ★ NOERROR 但没有这类记录（NODATA）和「域名不存在」是两件事：
		// 前者域名是有的（只是没配这类记录），后者整个都不存在。处理办法完全不同。
		{dnsmessage.RCodeSuccess, 0, dnsNoRecord, "NODATA"},
		{dnsmessage.RCodeNameError, 0, dnsNXDomain, "NXDOMAIN"},
		{dnsmessage.RCodeServerFailure, 0, dnsServFail, "SERVFAIL"},
		{dnsmessage.RCodeRefused, 0, dnsRefused, "REFUSED"},
		{dnsmessage.RCodeFormatError, 0, dnsBadResponse, "其它 rcode 不许当成成功"},
	}
	for _, c := range cases {
		if got := dnsVerdict(c.rcode, c.n); got != c.want {
			t.Errorf("%s：想要 %s，拿到 %s", c.explain, c.want, got)
		}
	}
}

func TestAnswersOfType(t *testing.T) {
	as := []dnsAnswer{
		{Name: "a.example", Type: "CNAME", Value: "b.example"},
		{Name: "b.example", Type: "A", Value: "1.2.3.4"},
		{Name: "b.example", Type: "A", Value: "1.2.3.5"},
	}
	// ★ 查 A 时中间的 CNAME 也在答案段里，但不该算进「A 记录条数」——
	//   算进去会让一个只有 CNAME、没有 A 的域名被误判成 resolved。
	if got := len(answersOfType(as, "A")); got != 2 {
		t.Errorf("A 记录该 2 条，拿到 %d", got)
	}
	if got := len(answersOfType(as, "TXT")); got != 0 {
		t.Errorf("没有 TXT 该 0 条，拿到 %d", got)
	}
}

func TestDNSMessageType(t *testing.T) {
	if got, err := dnsMessageType(""); err != nil || got != dnsmessage.TypeA {
		t.Errorf("不给类型该按 A，拿到 %v %v", got, err)
	}
	if got, err := dnsMessageType("aaaa"); err != nil || got != dnsmessage.TypeAAAA {
		t.Errorf("大小写该无所谓，拿到 %v %v", got, err)
	}
	if _, err := dnsMessageType("CAA"); err == nil {
		t.Error("不认识的类型要当场说清，不能默默按 A 查")
	}
	// 名字要能转回去，formatAnswers 与 answersOfType 靠它对上
	for _, n := range []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV"} {
		tp, err := dnsMessageType(n)
		if err != nil {
			t.Fatalf("%s：解析失败 %s", n, err)
		}
		if back := dnsMessageTypeName(tp); back != n {
			t.Errorf("%s 转回来成了 %s", n, back)
		}
	}
}

func TestWithDNSPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"114.114.114.114", "114.114.114.114:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		// ★ 裸 IPv6 没有方括号时不能直接拼字符串：拨号会连到一个不存在的地址然后超时，
		//   表现成「这台 DNS 服务器坏了」，而真正的原因是我们自己没拼对。
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
		{"[fe80::1%en0]:53", "[fe80::1%en0]:53"},
	}
	for _, c := range cases {
		if got := withDNSPort(c.in); got != c.want {
			t.Errorf("%s：想要 %s，拿到 %s", c.in, c.want, got)
		}
	}
}

// TestBuildParseRoundTrip 自己造一份应答喂回解析器：
// 钉住「核对 ID」「核对问题名字」这两道关真的在起作用。
func TestBuildParseRoundTrip(t *testing.T) {
	msg, id, err := buildDNSQuery("www.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatalf("构造查询失败：%s", err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		t.Fatalf("自己造的报文都解不开：%s", err)
	}
	if hdr.RecursionDesired != true {
		t.Error("查询要带 RD，否则问公共解析器多半拿不到递归结果")
	}
	qs, err := p.AllQuestions()
	// ★ 报文里的名字是**绝对形式**（带根点）。测试一开始写成不带点，
	//   看着像代码错了，其实是断言按想象中的格式写的
	if err != nil || len(qs) != 1 || !sameDNSName(qs[0].Name.String(), "www.example.com") {
		t.Fatalf("问题段不对：%v %v", qs, err)
	}

	// 伪造一份应答：答案指向另一个域名，解析必须认出来并拒绝
	resp := fakeAnswer(t, id, "www.example.com", "93.184.216.34")
	if _, _, err := parseDNSResponse(resp, id, "www.example.com"); err != nil {
		t.Errorf("正常应答该解得开：%s", err)
	}
	// ID 对不上：不是我们问的那份，不能认
	if _, _, err := parseDNSResponse(resp, id^0xffff, "www.example.com"); !errors.Is(err, errBadDNS) {
		t.Errorf("ID 不匹配该拒，拿到 %v", err)
	}
	// 问的是 a 回的是 b：同样不能认
	if _, _, err := parseDNSResponse(resp, id, "www.other.com"); !errors.Is(err, errBadDNS) {
		t.Errorf("名字不匹配该拒，拿到 %v", err)
	}
}

// fakeAnswer 造一份「A 记录」应答报文，测试用。
func fakeAnswer(t *testing.T, id uint16, qname, ip string) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(fqdn(qname)) // 报文里要绝对形式（带根点）
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512),
		dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	var a [4]byte
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatal(err)
	}
	copy(a[:], addr.AsSlice())
	if err := b.AResource(dnsmessage.ResourceHeader{
		Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
	}, dnsmessage.AResource{A: a}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
