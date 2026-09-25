package gb28181

import (
	"strings"
	"testing"
)

// 一份「平台发来的实时点播」正文，按 GB28181 常见的形状写。
// ★ 每一行都要被读到，且读出来的位置（会话级还是媒体级）要对 ——
// 位置错了，方向、口、SSRC 就会串到另一段媒体上去。
const inviteLive = "v=0\r\n" +
	"o=34020000001110000001 20250101 1 IN IP4 192.168.1.66\r\n" +
	"s=Live\r\n" +
	"c=IN IP4 224.5.0.1/127\r\n" +
	"t=0 0\r\n" +
	"m=video 30000 RTP/AVP 96\r\n" +
	"a=recvonly\r\n" +
	"y=0100000000 0 0\r\n" +
	"a=rtpmap:96 PS/90000\r\n"

func TestParseSDPInvite(t *testing.T) {
	s, err := ParseSDP([]byte(inviteLive))
	if err != nil {
		t.Fatalf("读这份点播正文失败：%v", err)
	}
	if s.SessionName != "Live" {
		t.Errorf("s= 读成 %q，要 Live", s.SessionName)
	}
	if s.Origin.Address != "192.168.1.66" || s.Origin.AddrType != "IP4" {
		t.Errorf("o= 读错：%+v", s.Origin)
	}
	c, ok := s.Connection()
	if !ok {
		t.Fatal("c= 一条都没读到")
	}
	if c.Address != "224.5.0.1" {
		t.Errorf("c= 地址读成 %q", c.Address)
	}
	if !c.Multicast() {
		t.Error("224.5.0.1 是组播，Multicast 报了假 —— 「流发到组播组、本机没加组」这条就说不出口")
	}
	if !c.HasTTL || c.TTL != 127 {
		t.Errorf("c= 后面那个 TTL 读错：has=%v ttl=%d", c.HasTTL, c.TTL)
	}
	port, ok := s.MediaPort()
	if !ok || port != 30000 {
		t.Errorf("m= 里的口读成 %d ok=%v，要 30000", port, ok)
	}
	if len(s.Media) != 1 || s.Media[0].Proto != "RTP/AVP" || strings.Join(s.Media[0].Formats, ",") != "96" {
		t.Errorf("媒体段读错：%+v", s.Media)
	}
	dir, ok := s.Direction()
	if !ok || dir != "recvonly" {
		t.Errorf("方向读成 %q ok=%v，要 recvonly（a= 在 m= 之后，得算进那一段）", dir, ok)
	}
	if _, ok := s.Media[0].Attribute("rtpmap"); !ok {
		t.Error("m= 之后的第二条 a= 没归进媒体段")
	}
	ssrc, ok := s.SSRC()
	if !ok || ssrc != "0100000000" {
		t.Errorf("y= 的 SSRC 读成 %q ok=%v", ssrc, ok)
	}
	// ★ y= 写在 m= 之后，所以它属于那一段媒体，不能算进会话级那本账 ——
	//	放错了地方，多段媒体的点播就会互相顶掉 SSRC。
	if len(s.Others) != 0 {
		t.Errorf("会话级留了 %d 条没建模的行，这里应该一条都没有", len(s.Others))
	}
	if len(s.Media[0].Others) != 1 || s.Media[0].Others[0].Type != "y" {
		t.Errorf("媒体级没建模的行记错：%+v", s.Media[0].Others)
	}
}

// 会话级与媒体级各一条 c=：两条都要留着，不许互相覆盖。
// ★ 现场见过两段不一致的固件；替它挑一条就是猜。
func TestParseSDPConnectionBothLevels(t *testing.T) {
	body := "v=0\r\no=x 1 1 IN IP4 10.0.0.1\r\ns=Live\r\n" +
		"c=IN IP4 10.0.0.1\r\nt=0 0\r\n" +
		"m=video 40000 RTP/AVP 96\r\nc=IN IP4 10.0.0.9\r\na=recvonly\r\n"
	s, err := ParseSDP([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Conns) != 1 || s.Conns[0].Address != "10.0.0.1" {
		t.Errorf("会话级 c= 读错：%+v", s.Conns)
	}
	if len(s.Media[0].Conns) != 1 || s.Media[0].Conns[0].Address != "10.0.0.9" {
		t.Errorf("媒体级 c= 读错：%+v", s.Media[0].Conns)
	}
}

func TestParseSDPBareLF(t *testing.T) {
	s, err := ParseSDP([]byte(strings.ReplaceAll(inviteLive, "\r\n", "\n")))
	if err != nil {
		t.Fatalf("裸 LF 就读不下去：现场这种设备真不少：%v", err)
	}
	if p, ok := s.MediaPort(); !ok || p != 30000 {
		t.Errorf("裸 LF 读出的口是 %d", p)
	}
}

func TestParseSDPPortShapes(t *testing.T) {
	s, err := ParseSDP([]byte("v=0\r\no=x 1 1 IN IP4 h\r\ns=Live\r\nt=0 0\r\nm=video 30000/2 RTP/AVP 96\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Media[0].Port != 30000 || s.Media[0].PortCount != 2 {
		t.Errorf("口/数量 读成 %d/%d", s.Media[0].Port, s.Media[0].PortCount)
	}
	for _, bad := range []string{"30000-30010", "abc", "70000", "30000/x"} {
		body := "v=0\r\no=x 1 1 IN IP4 h\r\ns=Live\r\nt=0 0\r\nm=video " + bad + " RTP/AVP 96\r\n"
		if _, err := ParseSDP([]byte(body)); err == nil {
			t.Errorf("口写成 %q 居然读通了 —— 这种正文读成「口是 0」比报错难查十倍", bad)
		}
	}
}

func TestParseSDPErrors(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"第一行不是 v=", "o=x 1 1 IN IP4 h\r\ns=Live\r\n", "第一行不是 v="},
		{"v= 不在第一行", "s=Live\r\nv=0\r\n", "第一行不是 v="},
		{"v= 不是数字", "v=x\r\n", "版本号不是数字"},
		{"行里没有等号", "v=0\r\ngarbage\r\n", "不成 SDP"},
		{"o= 字段不足", "v=0\r\no=x 1 2\r\n", "o= 只有 3 个字段"},
		{"m= 字段不足", "v=0\r\no=x 1 1 IN IP4 h\r\ns=L\r\nm=video 30000\r\n", "字段不足"},
		{"c= 字段不足", "v=0\r\no=x 1 1 IN IP4 h\r\ns=L\r\nc=IN IP4\r\n", "c= 读不下去"},
	}
	for _, tc := range cases {
		if _, err := ParseSDP([]byte(tc.body)); err == nil {
			t.Errorf("%s：居然读通了", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s：报错说的是 %q，要它提到 %q", tc.name, err, tc.want)
		}
	}
}

// 未知类型只把行号与字母记进账，正文不进 —— 这一段会出现在结果里。
func TestParseSDPUnknownType(t *testing.T) {
	s, err := ParseSDP([]byte("v=0\r\no=x 1 1 IN IP4 h\r\ns=L\r\nt=0 0\r\nW=一些别的东西\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Unknown) != 1 || !strings.HasPrefix(s.Unknown[0], "line") {
		t.Fatalf("未知行没记账：%v", s.Unknown)
	}
	for _, u := range s.Unknown {
		if strings.Contains(u, "一些别的东西") {
			t.Errorf("未知行的内容被带进账里了：%q", u)
		}
	}
}

func TestParseSDPAttributesAndURI(t *testing.T) {
	s, err := ParseSDP([]byte("v=0\r\no=x 1 1 IN IP6 ::1\r\ns=Playback\r\n" +
		"u=34020000001110000001:20250101T000000\r\nc=IN IP6 ::1\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=sendonly\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Origin.AddrType != "IP6" {
		t.Errorf("地址类型读成 %q", s.Origin.AddrType)
	}
	u, ok := s.URI()
	if !ok || !strings.HasPrefix(u, "34020000001110000001") {
		t.Errorf("u= 读成 %q ok=%v", u, ok)
	}
	if dir, _ := s.Direction(); dir != "sendonly" {
		t.Errorf("方向读成 %q —— sendonly 的这条不是点播，别按点播解释", dir)
	}
	if _, ok := s.SSRC(); ok {
		t.Error("这份没带 y=，SSRC 不该报有")
	}
	if c, _ := s.Connection(); c.Multicast() {
		t.Error("::1 不是组播")
	}
	if c, _ := s.Connection(); c.AddrType != "IP6" {
		t.Errorf("c= 的地址类型读成 %q", c.AddrType)
	}
}

func TestBodySDPFromMessage(t *testing.T) {
	m := &Message{}
	if _, err := BodySDP(m); KindOf(err) != KindNoBody {
		t.Errorf("空正文报成 %q，要 no-body", KindOf(err))
	}
	m2 := &Message{Body: []byte("not an sdp at all")}
	if _, err := BodySDP(m2); KindOf(err) != KindBadBody {
		t.Errorf("坏正文报成 %q，要 bad-body", KindOf(err))
	}
	m3 := &Message{Body: []byte(inviteLive)}
	s, err := BodySDP(m3)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := s.MediaPort(); p != 30000 {
		t.Errorf("从报文里取的口是 %d", p)
	}
	if _, err := BodySDP(nil); KindOf(err) != KindNoBody {
		t.Error("传了个 nil 进来，该报 no-body 而不是崩")
	}
}
