package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// 证书判定全是**纯函数**里的事，所以这些测试不联网、也不碰本机信任列表：
// 链验证的结果当参数传进来。否则「这台机器恰好信什么」会混进断言里，
// 测试就变成了只在某几台机器上过的东西。

var tlsNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// tlsSelfSignedCert 造一颗自己给自己签的证书（现场内网设备的默认样子）。
func tlsSelfSignedCert(t *testing.T, cn string, sans []string, nb, na time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    nb, NotAfter: na,
		DNSNames:              sans,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	return tlsParse(t, tlsSign(t, tmpl, tmpl, &key.PublicKey, key))
}

// tlsIssuedCert 先造一张 CA 再签叶子 —— 「别人签的」要和「自签」分得开。
func tlsIssuedCert(t *testing.T, cn string, sans []string, nb, na time.Time) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "测试根 CA"},
		NotBefore:    nb.Add(-time.Hour), NotAfter: na.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER := tlsSign(t, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    nb, NotAfter: na,
		DNSNames: sans,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	// ★ 签名用 CA 的私钥，证书里放的却是叶子自己的公钥 —— 拿叶子的私钥签会直接报错
	der := tlsSign(t, leafTmpl, ca, &leafKey.PublicKey, caKey)
	return tlsParse(t, der)
}

// tlsSign 用 parent 的私钥给 tmpl 签名。★ 自签就是把模板自己当 parent 传进来。
func tlsSign(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate,
	pub any, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func tlsParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var tlsNotTrusted = x509.UnknownAuthorityError{}

func Test证书过期压倒其他一切问题(t *testing.T) {
	// 同时踩三条：过期 + 名字不对 + 自签不受信。现场只能修一件，先说最要紧的。
	c := tlsSelfSignedCert(t, "cam.local", []string{"other.example.com"},
		tlsNow.Add(-400*24*time.Hour), tlsNow.Add(-24*time.Hour))
	a := assessTLS(tlsNow, c, "cam.local", tls.VersionTLS12, 14, tlsNotTrusted)
	if a.Code != certExpired {
		t.Errorf("got %s, want %s", a.Code, certExpired)
	}
	if a.DaysLeft >= 0 {
		t.Errorf("过期证书剩余天数该是负数，got %d", a.DaysLeft)
	}
	if !a.SelfSigned || a.HostnameOK || a.Trusted {
		t.Errorf("其余几条也得如实记下：%+v", a)
	}
}

func Test证书还没生效(t *testing.T) {
	// ★ 这条几乎从来不是证书的错，是**设备时钟不对** —— 判出来要能往校时上引。
	c := tlsIssuedCert(t, "cam.local", []string{"cam.local"},
		tlsNow.Add(24*time.Hour), tlsNow.Add(300*24*time.Hour))
	a := assessTLS(tlsNow, c, "cam.local", tls.VersionTLS12, 14, nil)
	if a.Code != certNotYetValid {
		t.Errorf("got %s, want %s", a.Code, certNotYetValid)
	}
}

func Test名字不匹配优先于不受信(t *testing.T) {
	c := tlsIssuedCert(t, "other.example.com", []string{"other.example.com"},
		tlsNow.Add(-24*time.Hour), tlsNow.Add(300*24*time.Hour))
	a := assessTLS(tlsNow, c, "camera.local", tls.VersionTLS12, 14, tlsNotTrusted)
	if a.Code != certNameMismatch {
		t.Errorf("got %s, want %s", a.Code, certNameMismatch)
	}
	if a.HostnameOK {
		t.Error("名字不匹配要如实记下来，不能只留个判定码")
	}
}

func Test自签和缺中间证书要分开报(t *testing.T) {
	nb, na := tlsNow.Add(-24*time.Hour), tlsNow.Add(300*24*time.Hour)

	self := tlsSelfSignedCert(t, "cam.local", []string{"cam.local"}, nb, na)
	if a := assessTLS(tlsNow, self, "cam.local", tls.VersionTLS12, 14, tlsNotTrusted); a.Code != certSelfSigned {
		t.Errorf("自签 got %s, want %s", a.Code, certSelfSigned)
	}
	issued := tlsIssuedCert(t, "cam.local", []string{"cam.local"}, nb, na)
	if a := assessTLS(tlsNow, issued, "cam.local", tls.VersionTLS12, 14, tlsNotTrusted); a.Code != certUnknownAuthority {
		t.Errorf("别人签的 got %s, want %s", a.Code, certUnknownAuthority)
	}
	// ★ 自签但本机装着它的根（chainErr 为空）时，不该再喊自签 —— 那是已经处理完了的状态
	if a := assessTLS(tlsNow, self, "cam.local", tls.VersionTLS12, 14, nil); a.Code != certOK {
		t.Errorf("已导入信任列表的自签 got %s, want %s", a.Code, certOK)
	}
}

func Test快到期与老TLS的先后(t *testing.T) {
	ok := tlsIssuedCert(t, "cam.local", []string{"cam.local"},
		tlsNow.Add(-24*time.Hour), tlsNow.Add(5*24*time.Hour))
	if a := assessTLS(tlsNow, ok, "cam.local", tls.VersionTLS12, 14, nil); a.Code != certExpiringSoon {
		t.Errorf("got %s, want %s", a.Code, certExpiringSoon)
	}
	if got := ok.NotAfter.Sub(tlsNow) / 24 / time.Hour; got != 5 {
		t.Errorf("样本造错了，剩余应为 5 天，got %v", got)
	}
	// 证书只剩 5 天 + 只肯谈 TLS1.0：换证书这件更要紧的事先说
	if a := assessTLS(tlsNow, ok, "cam.local", tls.VersionTLS10, 14, nil); a.Code != certExpiringSoon {
		t.Errorf("got %s, want %s", a.Code, certExpiringSoon)
	} else if !a.WeakProtocol {
		t.Error("老版本 TLS 要如实记进 values")
	}
	// 证书健健康康，只有协议老 —— 这才是 cert-weak-protocol
	fresh := tlsIssuedCert(t, "cam.local", []string{"cam.local"},
		tlsNow.Add(-24*time.Hour), tlsNow.Add(300*24*time.Hour))
	if a := assessTLS(tlsNow, fresh, "cam.local", tls.VersionTLS11, 14, nil); a.Code != certWeakProtocol {
		t.Errorf("got %s, want %s", a.Code, certWeakProtocol)
	}
	if a := assessTLS(tlsNow, fresh, "cam.local", tls.VersionTLS13, 14, nil); a.Code != certOK {
		t.Errorf("got %s, want %s", a.Code, certOK)
	}
}

// Test自签叶子证书没CA标记也得认出来 ★ 现场设备的自签证书基本都是**叶子**证书，
// 不带 CA 标记。早先用 CheckSignatureFrom 判，症状是把自签报成「缺签发者」，
// 让人去装一张根本装不进去的根证书。
func Test自签叶子证书没CA标记也得认出来(t *testing.T) {
	nb, na := tlsNow.Add(-24*time.Hour), tlsNow.Add(300*24*time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "IPC-Web"},
		NotBefore:    nb, NotAfter: na,
		DNSNames: []string{"IPC-Web"},
		KeyUsage: x509.KeyUsageDigitalSignature, // 没有 CertSign，也没写 IsCA
	}
	c := tlsParse(t, tlsSign(t, tmpl, tmpl, &key.PublicKey, key))
	if !selfSigned(c) {
		t.Fatal("主题=签发者、签名自验通过，就该判自签")
	}
	a := assessTLS(tlsNow, c, "IPC-Web", tls.VersionTLS12, 14, tlsNotTrusted)
	if a.Code != certSelfSigned {
		t.Errorf("got %s, want %s", a.Code, certSelfSigned)
	}
}

func Test按IP核对证书看的是SAN里的地址(t *testing.T) {
	nb, na := tlsNow.Add(-24*time.Hour), tlsNow.Add(300*24*time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "192.168.1.64"},
		NotBefore:    nb, NotAfter: na,
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.64")},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	c := tlsParse(t, tlsSign(t, tmpl, tmpl, &key.PublicKey, key))
	if a := assessTLS(tlsNow, c, "192.168.1.64", tls.VersionTLS12, 14, nil); a.Code != certOK {
		t.Errorf("IP 写在 SAN 里就该认，got %s", a.Code)
	}
	if a := assessTLS(tlsNow, c, "192.168.1.65", tls.VersionTLS12, 14, nil); a.Code != certNameMismatch {
		t.Errorf("换了个 IP 就不在 SAN 里，got %s", a.Code)
	}
}

func Test挑一个最能说明问题的连接结果(t *testing.T) {
	cases := []struct {
		name  string
		tried []tlsAttempt
		want  string
	}{
		{"明文服务盖过其他", []tlsAttempt{
			{Code: verdictFiltered}, {Code: tlsNotTLS}}, tlsNotTLS},
		{"握手失败盖过端口关", []tlsAttempt{
			{Code: verdictClosed}, {Code: tlsHandshakeFailed}}, tlsHandshakeFailed},
		{"两族都只是连不上", []tlsAttempt{
			{Code: verdictFiltered}, {Code: dnsUnreachable}}, verdictFiltered},
		{"挑中谁就用谁的细节", []tlsAttempt{
			{Address: "[fd00::1]:443", Code: dnsUnreachable, Detail: "no route to host"},
			{Address: "1.2.3.4:443", Code: tlsNotTLS, Detail: "bad record header"}}, tlsNotTLS},
		{"空输入", nil, tlsHandshakeFailed},
	}
	for _, tc := range cases {
		if got := pickTLSCode(tc.tried).Code; got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func Test拆地址IP和域名都认(t *testing.T) {
	cases := []struct {
		in     string
		host   string
		ip     bool
		port   int
		wantEr bool
	}{
		{in: "192.168.1.64", host: "192.168.1.64", ip: true},
		{in: "192.168.1.64:8443", host: "192.168.1.64", ip: true, port: 8443},
		{in: "[fd00::1]:443", host: "fd00::1", ip: true, port: 443},
		{in: "fe80::1%en0", host: "fe80::1", ip: true}, // ★ zone 不进核对名
		{in: "camera.local", host: "camera.local"},
		{in: "cam.example.com:8443", host: "cam.example.com", port: 8443},
		{in: "cam.example.com:https", wantEr: true},
		{in: "a b", wantEr: true},
		{in: "https://cam.local", wantEr: true},
	}
	for _, tc := range cases {
		host, ip, port, err := splitTLSAddr(tc.in)
		if tc.wantEr {
			if err == nil {
				t.Errorf("%q: 该报错，却给了 %s:%d", tc.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %s", tc.in, err)
			continue
		}
		if host != tc.host || ip.IsValid() != tc.ip || port != tc.port {
			t.Errorf("%q: got (%s,%v,%d), want (%s,%v,%d)", tc.in, host, ip.IsValid(), port,
				tc.host, tc.ip, tc.port)
		}
	}
}

func Test验证失败的原因翻成人话(t *testing.T) {
	cases := []struct {
		err      error
		selfSign bool
		want     string
	}{
		{x509.UnknownAuthorityError{}, true, "自签证书"},
		{x509.UnknownAuthorityError{}, false, "签发它的那一级"},
		{x509.CertificateInvalidError{Reason: x509.Expired}, false, "不在有效期内"},
		{x509.CertificateInvalidError{Reason: x509.NameMismatch}, false, "名字对不上"},
		// macOS 走系统验证器，回来的只有文本没有类型
		{errors.New(`x509: “IPC-Web” certificate is not trusted`), true, "自签证书"},
		{errors.New(`x509: “IPC-Web” certificate is not trusted`), false, "签发它的那一级"},
	}
	for _, tc := range cases {
		got := verifyReason(tc.err, tc.selfSign)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%v: got %q, 想看到 %q", tc.err, got, tc.want)
		}
	}
}
