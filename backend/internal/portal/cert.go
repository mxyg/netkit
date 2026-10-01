package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// genCert 造一张自签证书，SAN 覆盖**所有会用来访问这个门户的名字**：
// 每个绑定地址（IP）、主机名、主机名.local、localhost。
//
// ★ 为什么当场造而不是让人准备：这个功能服务的场景是「机柜旁边只有手机」，
//
//	让人现场申请一张 SAN 正确的证书不现实。自签 + 手机点一次「继续」
//	是这套场景里唯一走得通的组合；证书本身也给得出去（Status.CertPEM），
//	真想消掉提示的人可以下载并信任它。
func (s *Service) genCert() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("造密钥失败：%s", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("造序列号失败：%s", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "NetKit 门户", Organization: []string{"昱弘网通 NetKit"}},
		NotBefore:    time.Now().Add(-time.Hour),
		// 30 天：门户本来就是临时开的服务，证书不许比服务活得久得多。
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, a := range s.cfg.Addrs {
		if ip := net.ParseIP(trimZone(a)); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.IPv6loopback)
	if hn := shortHost(s.hostName); hn != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, hn, hn+".local")
	}
	tmpl.DNSNames = append(tmpl.DNSNames, "localhost")

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("造证书失败：%s", err)
	}
	s.certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM)
	if err != nil {
		return err
	}
	s.tlsCert = tlsCert
	return nil
}

func (s *Service) tlsConfigForHTTP() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.tlsCert}, MinVersion: tls.VersionTLS12}
}

// wrapTLS 局域网监听器套上 TLS；回环口调用方传 nil（本机界面不必趟自签证书的坑）。
func wrapTLS(ln net.Listener, cfg *tls.Config) net.Listener {
	if cfg == nil {
		return ln
	}
	return tls.NewListener(ln, cfg)
}

// trimZone 去掉 fe80::…%en0 这种带区的尾巴，证书 SAN 里只要地址本体。
func trimZone(a string) string {
	if i := strings.IndexByte(a, '%'); i >= 0 {
		return a[:i]
	}
	return a
}
