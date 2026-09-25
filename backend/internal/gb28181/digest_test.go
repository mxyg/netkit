package gb28181

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// RFC 2617 例子里那两个中间量（HA1、HA2）是公开写在文上的，
// 拿它们当锚点：公式接错线（少一个冒号、qop 与 nc 换了位置）在这两步上就会露出来。
const (
	rfcHA1 = "939e7578ed9e3c518a452acee763bce9"
	rfcHA2 = "39aff3a2bab6126f332b942af96d3366"
)

func TestDigest按RFC2617那组量算(t *testing.T) {
	ch := &Challenge{Realm: "testrealm@host.com", Nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093", Algorithm: "MD5", QOP: []string{"auth"}}
	// 先把两个中间量单独验一遍（它们只依赖输入，不依赖拼接顺序）。
	if got := md5Hex("Mufasa:testrealm@host.com:Circle Of Life"); got != rfcHA1 {
		t.Fatalf("HA1 不对：%s", got)
	}
	if got := md5Hex("GET:/dir/index.html"); got != rfcHA2 {
		t.Fatalf("HA2 不对：%s", got)
	}
	got, err := ch.Response("Mufasa", "Circle Of Life", "GET", "/dir/index.html", "auth", "00000001", "0a4f113b")
	if err != nil {
		t.Fatal(err)
	}
	// 这一步的值由上面那两个量按 HA1:nonce:nc:cnonce:qop:HA2 拼出来，
	// 与独立实现（另一份哈希库）算出的结果对齐。
	if got != "6629fae49393a05397450978507c4ef1" {
		t.Fatalf("response 不对：%s", got)
	}
	noqop, err := ch.Response("Mufasa", "Circle Of Life", "GET", "/dir/index.html", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if noqop != "670fd8c2df070c60b045671b8b24ff02" {
		t.Fatalf("不带 qop 那条公式没对上：%s", noqop)
	}
}

func TestDigest缺realm不硬算(t *testing.T) {
	ch := &Challenge{Nonce: "n", Realm: ""}
	if _, err := ch.Response("u", "p", "REGISTER", "sip:x", "auth", "00000001", "c"); err == nil {
		t.Fatal("realm 空的时候算出来的 HA1 是凭空的，必须报错而不是给一个能用的串")
	}
}

func TestDigest挑战解析(t *testing.T) {
	cases := map[string]string{
		`Digest realm="3402000000", nonce="abc123", qop="auth", algorithm=MD5, opaque="op1"`: "3402000000",
		`realm="3402000000",nonce="abc123"`:                                                  "3402000000",
	}
	for in, wantRealm := range cases {
		c, err := ParseChallenge(in)
		if err != nil {
			t.Fatalf("%q：%v", in, err)
		}
		if c.Realm != wantRealm || c.Nonce != "abc123" {
			t.Fatalf("%q 解成 %+v", in, c)
		}
	}
	c, err := ParseChallenge(`Digest realm="r", nonce="n", qop="auth,auth-int", stale=TRUE`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.QOP) != 2 || !c.Stale {
		t.Fatalf("qop 列表或 stale 没解出来：%+v", c)
	}
	if _, err := ParseChallenge(`Digest realm="r", nonce="n"`); err != nil {
		t.Fatal("不带 scheme 前缀的挑战也要认（有些平台就是这么发的）")
	}
	if _, err := ParseChallenge(`Digest realm="r"`); err == nil {
		t.Fatal("没有 nonce 的挑战该报错（它答了 401 却没给出单子，下一步是查平台配置）")
	}
	if _, err := (&Challenge{QOP: []string{"auth-int"}}).PickQOP(); err == nil {
		t.Fatal("平台只给 auth-int 时要拒绝：按 auth 的公式算 auth-int 位置上的 response，是「认证失败」里最难查的一种")
	}
	if q, err := (&Challenge{QOP: []string{"auth-int", "auth"}}).PickQOP(); err != nil || q != "auth" {
		t.Fatalf("清单里有 auth 就该挑它：%q %v", q, err)
	}
}

func TestDigest挑战序列化再解回来(t *testing.T) {
	orig := &Challenge{Realm: "3402000000", Nonce: "n1", Opaque: "o1", Algorithm: "MD5", QOP: []string{"auth"}}
	got, err := ParseChallenge(orig.Header())
	if err != nil {
		t.Fatal(err)
	}
	if got.Realm != orig.Realm || got.Nonce != orig.Nonce || got.Opaque != orig.Opaque ||
		got.Algorithm != orig.Algorithm || strings.Join(got.QOP, ",") != "auth" {
		t.Fatalf("一圈回来变了： %+v -> %+v", orig, got)
	}
	// 没值的项不写出去：空 realm 发出去，设备会算出一个跟校验时对不上的 HA1。
	if h := (&Challenge{Realm: "r", Nonce: "n"}).Header(); strings.Contains(h, "opaque") || strings.Contains(h, "qop") || strings.Contains(h, "algorithm") {
		t.Fatalf("没给的项不该写出去：%q", h)
	}
}

func TestDigest客户端应答里不许带口令(t *testing.T) {
	ch := &Challenge{Realm: "3402000000", Nonce: "n", Algorithm: "MD5", QOP: []string{"auth"}}
	hdr, err := Authorize(ch, "34020000001110000001", "sup3rS3cret", MethodRegister, "sip:34020000002000000001@3402000000")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hdr, "sup3rS3cret") {
		t.Fatal("应答里出现了口令原文")
	}
	// 这条头会整份进结果、进日志、进诊断包，所以 Authorization 结构本身也不许带口令。
	a, err := ParseAuthorization(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Header(), "sup3rS3cret") {
		t.Fatal("重序列化时把口令带回去了")
	}
	if a.QOP != "auth" || a.NC != "00000001" || a.Realm != "3402000000" {
		t.Fatalf("应答字段不对：%+v", a)
	}
}

func TestDigest平台侧校验走完一遍(t *testing.T) {
	now := time.Unix(1800000000, 0)
	v := NewVerifier("3402000000", time.Minute)
	ch := v.Challenge(now)
	uri := "sip:34020000002000000001@3402000000"
	hdr, err := Authorize(ch, "34020000001110000001", "pw-correct", MethodRegister, uri)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthorization(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(a, MethodRegister, uri, "pw-correct", now); err != nil {
		t.Fatalf("正确口令没过：%v", err)
	}
	// 同一个 nc 再来一次：重复提交。
	if err := v.Verify(a, MethodRegister, uri, "pw-correct", now); !errors.Is(err, ErrDigestReplay) {
		t.Fatalf("nc 没往前走却放过了：%v", err)
	}
	// 口令错。
	bad := *a
	bad.QOP, bad.NC, bad.CNonce = "auth", "00000002", "cc"
	bad.Response = "00000000000000000000000000000000"
	if err := v.Verify(&bad, MethodRegister, uri, "pw-correct", now); !errors.Is(err, ErrDigestBadResponse) {
		t.Fatalf("假 response 该被拒：%v", err)
	}
}

// 换了一轮挑战，nc 就从 1 重头数 —— 这是注册到期后设备的一条正常路径。
// ★ 按编号记总账会把这条正常路径报成「重复提交」，现场看到的就成了
//
//	「口令没错、平台死活不给 200」，跟着去查一个根本不存在的毛病。
func TestDigest新一轮挑战上nc重头数(t *testing.T) {
	now := time.Unix(1800000000, 0)
	v := NewVerifier("3402000000", time.Minute)
	uri := "sip:34020000002000000001@3402000000"
	user := "34020000001110000001"
	answer := func(ch *Challenge) *Authorization {
		hdr, err := Authorize(ch, user, "pw-correct", MethodRegister, uri)
		if err != nil {
			t.Fatal(err)
		}
		a, err := ParseAuthorization(hdr)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if err := v.Verify(answer(v.Challenge(now)), MethodRegister, uri, "pw-correct", now); err != nil {
		t.Fatalf("第一轮没过：%v", err)
	}
	// 第二轮：设备拿新 nonce 从 1 重头数，这一条必须收。
	if err := v.Verify(answer(v.Challenge(now)), MethodRegister, uri, "pw-correct", now); err != nil {
		t.Fatalf("换了一轮挑战、nc 重头数被拒了：%v", err)
	}
	// 同一轮里 nc 不往前走还是要拦（上面那条没把重放保护放开）。
	replay := answer(v.Challenge(now))
	if err := v.Verify(replay, MethodRegister, uri, "pw-correct", now); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(replay, MethodRegister, uri, "pw-correct", now); !errors.Is(err, ErrDigestReplay) {
		t.Fatalf("同一 nonce 上重放没拦住：%v", err)
	}
}

func TestDigest平台侧把那几种错分开(t *testing.T) {
	now := time.Unix(1800000000, 0)
	v := NewVerifier("3402000000", time.Minute)
	ch := v.Challenge(now)
	uri := "sip:p@host"
	mk := func(mut func(*Authorization)) *Authorization {
		hdr, err := Authorize(ch, "dev", "pw", MethodRegister, uri)
		if err != nil {
			t.Fatal(err)
		}
		a, err := ParseAuthorization(hdr)
		if err != nil {
			t.Fatal(err)
		}
		mut(a)
		return a
	}
	if err := v.Verify(mk(func(a *Authorization) { a.Nonce = "不是我发的" }), MethodRegister, uri, "pw", now); !errors.Is(err, ErrDigestUnknownNonce) {
		t.Fatalf("陌生 nonce 该单独一档：%v", err)
	}
	if err := v.Verify(mk(func(a *Authorization) { a.Realm = "别的平台" }), MethodRegister, uri, "pw", now); !errors.Is(err, ErrDigestRealm) {
		t.Fatalf("realm 不对该单独一档（设备被配到过别的平台，单子还留着）：%v", err)
	}
	if err := v.Verify(mk(func(a *Authorization) { a.URI = "sip:other@host" }), MethodRegister, uri, "pw", now); !errors.Is(err, ErrDigestURI) {
		t.Fatalf("digestUri 算错了该单独一档：%v", err)
	}
	if err := v.Verify(mk(func(a *Authorization) { a.QOP = "auth-int" }), MethodRegister, uri, "pw", now); !errors.Is(err, ErrDigestQOP) {
		t.Fatalf("不支持的 qop 该拒绝而不是硬算：%v", err)
	}
	// nonce 过期：让设备重新走一趟，别报成口令错。
	stale := mk(func(a *Authorization) {})
	if err := v.Verify(stale, MethodRegister, uri, "pw", now.Add(time.Hour)); !errors.Is(err, ErrDigestStaleNonce) {
		t.Fatalf("过期 nonce 该报 stale：%v", err)
	}
	// 老固件不带 qop：按不带 qop 那条公式照样验得过（宽容），口令错则验不过。
	noqop := mk(func(a *Authorization) {
		a.QOP, a.NC, a.CNonce = "", "", ""
		a.Response, _ = (&Challenge{Realm: a.Realm, Nonce: a.Nonce}).Response("dev", "pw", MethodRegister, uri, "", "", "")
	})
	if err := v.Verify(noqop, MethodRegister, uri, "pw", now); err != nil {
		t.Fatalf("不带 qop 的老设备被拒了：%v", err)
	}
	if err := v.Verify(noqop, MethodRegister, uri, "错的口令", now); !errors.Is(err, ErrDigestBadResponse) {
		t.Fatalf("不带 qop 时口令错该照旧报出来：%v", err)
	}
}

func TestDigestMD5Sess那条路(t *testing.T) {
	ch := &Challenge{Realm: "r", Nonce: "n", Algorithm: "MD5-SESS", QOP: []string{"auth"}}
	v := NewVerifier("r", time.Minute)
	issued := v.Challenge(time.Now())
	issued.Algorithm = "MD5-SESS"
	if _, err := issued.Response("u", "p", MethodRegister, "sip:x", "", "", ""); err == nil {
		t.Fatal("MD5-sess 不带 qop/nc/cnonce 时不能算（算出来必然是错的），要拒绝")
	}
	hdr, err := Authorize(issued, "u", "p", MethodRegister, "sip:x")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthorization(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(a, MethodRegister, "sip:x", "p", time.Now()); err != nil {
		t.Fatalf("MD5-sess 两端对不上：%v", err)
	}
	if ch.Algorithm != "MD5-SESS" {
		t.Fatal("零散检查")
	}
}

func TestDigest从401里取挑战(t *testing.T) {
	msg := &Message{Status: 401, Reason: "Unauthorized"}
	if _, err := ChallengeFrom(msg); err == nil {
		t.Fatal("回了 401 却没带挑战，这一档必须单独报出来")
	}
	msg.Set(HWWWAuthenticate, `Digest realm="3402000000", nonce="n9", qop="auth"`)
	ch, err := ChallengeFrom(msg)
	if err != nil || ch.Nonce != "n9" {
		t.Fatalf("没取到挑战：%v %+v", err, ch)
	}
	// 挑战是中间那一跳加的（Proxy-Authenticate）也要认。
	msg2 := &Message{Status: 407}
	msg2.Add("Proxy-Authenticate", `Digest realm="r", nonce="pn"`)
	if ch2, err := ChallengeFrom(msg2); err != nil || ch2.Nonce != "pn" {
		t.Fatalf("Proxy-Authenticate 没认：%v %+v", err, ch2)
	}
	// 装进请求：method 与 uri 从请求身上取。
	req := NewRequest(MethodRegister, "sip:platform@host", "<sip:dev@host>", "<sip:platform@host>", "c", "SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK1", 2)
	if err := AuthorizeRequest(req, ch, "34020000001110000001", "pw"); err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthorization(req.Get(HAuthorization))
	if err != nil {
		t.Fatal(err)
	}
	if a.URI != req.URI || strings.Count(string(req.MustBytes()), "Authorization:") != 1 {
		t.Fatalf("应答里的 uri 没跟 Request-URI 对上：%q", a.URI)
	}
}
