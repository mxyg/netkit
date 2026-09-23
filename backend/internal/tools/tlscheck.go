package tools

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/ots"
)

// net.tls.check —— 证书体检。
//
// ★★ 现场有四件事全都长得像「打不开 / 连不上」，处理办法却完全不同：
//
//	证书过期了；证书上的名字和你访问的地址不一致；自签证书没进信任列表；
//	设备只支持 TLS1.0 而新浏览器/新平台不肯谈。
//	浏览器只给一句「您的连接不是私密连接」，工程师得自己拆开看是哪一种。
//
// ★ 这里**故意不做**严格校验就把握手跑完：先拿到证书，再自己判、自己说清为什么。
//
//	走标准校验的话，第一个失败原因会把后面的信息全挡住（过期时看不到域名也不匹配）。
var tlsCheckTool = ots.Tool{
	Name:  "net.tls.check",
	Class: ots.ClassRead,
	Summary: "连一个 TLS 服务（HTTPS、平台、摄像头的 Web 界面）检查它的证书：剩余天数、是否过期、" +
		"证书上的名字和你要访问的地址是否一致、是否自签、能否用本机信任列表验证通过，以及实际协商到的 TLS 版本与加密套件。" +
		"★ 用来分清四件现场最常见、又最容易混成一件事的问题：证书过期 / 名字不匹配 / 自签未受信 / 设备只支持老版本 TLS。" +
		"只握手、不读业务数据，属于只读。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr"],
	  "properties": {
	    "addr": {"type": "string",
	      "description": "地址或 host:port。可以是域名或 IP；链路本地 IPv6 要带 zone（fe80::1%en0）。"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
	      "description": "addr 里没带端口时用这个，默认 443。"},
	    "serverName": {"type": "string",
	      "description": "SNI 与核对证书用的名字。用 IP 访问、但想按证书上的域名核对时填这个。"},
	    "warnDays": {"type": "integer", "minimum": 0, "maximum": 365,
	      "description": "剩余天数少于多少算「快到期」，默认 14。"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 20000,
	      "description": "连接与握手最多等多久，默认 5000。"}
	  }
	}`),
	Invoke: doTLSCheck,
}

// 证书检查的判定码。★ 一个服务可能同时踩好几条：顶层给**最要紧的那一个**，其余都在 values 里如实列出。
const (
	certOK               = "cert-ok"
	certExpired          = "cert-expired"
	certNotYetValid      = "cert-not-yet-valid"
	certNameMismatch     = "cert-name-mismatch"
	certSelfSigned       = "cert-self-signed"
	certUnknownAuthority = "cert-unknown-authority"
	certExpiringSoon     = "cert-expiring-soon"
	certWeakProtocol     = "cert-weak-protocol" // 证书没问题，但设备只肯谈 TLS1.0/1.1
	tlsNotTLS            = "not-tls"            // 这个端口回的不是 TLS —— 多半是明文服务
	tlsHandshakeFailed   = "handshake-failed"
	tlsNoCert            = "no-certificate"  // 握手成了却没出示证书（匿名加密套件）
	tlsNameUnresolved    = "name-unresolved" // 域名压根没解析出地址，还没到证书那一步
)

// splitTLSAddr 把 addr 拆成主机名文本 + 地址 + 行内端口。
//
// ★ 先让 netaddr 试：它认方括号、zone、前缀这些**IP** 写法。
//
//	它不认的才是域名 —— 不能反过来用 strings.Split 切，
//	`fe80::1%en0` 这种一切就把地址切碎，症状是连到一个莫名其妙的地方。
func splitTLSAddr(s string) (host string, ip netaddr.Addr, port int, err error) {
	if a, p, e := netaddr.SplitHostPort(s); e == nil {
		return a.IP.String(), a, p, nil
	}
	// 域名写法：可能带 :端口，也可能裸着（裸着 net.SplitHostPort 会报「too few」）
	if h, ps, e := net.SplitHostPort(strings.TrimSpace(s)); e == nil {
		n, e2 := strconv.Atoi(ps)
		if e2 != nil {
			return "", netaddr.Addr{}, 0, fmt.Errorf("看不懂端口 %q：域名要写成 example.com:8443", ps)
		}
		return h, netaddr.Addr{}, n, nil
	}
	h := strings.TrimSpace(s)
	if h == "" || strings.ContainsAny(h, " \t@/[]") {
		return "", netaddr.Addr{}, 0, fmt.Errorf("看不懂地址 %q：填 IP、域名，或者它们的 :端口 写法", s)
	}
	return h, netaddr.Addr{}, 0, nil
}

// resolveTLSHost 解析域名，两族都要。返回 (地址, 失败说明)；失败说明为空表示成功。
//
// ★ 用 LookupNetIP("ip") 不用 LookupHost：它内部按 RFC 6724 排过序，
//
//	自己再排一次只会排错；返回的是 netip.Addr，正好直接进 netaddr。
func resolveTLSHost(ctx context.Context, host string) ([]netaddr.Addr, string) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, "DNS 回了这个域名不存在（NXDOMAIN）"
		}
		return nil, err.Error()
	}
	out := make([]netaddr.Addr, 0, len(addrs))
	for _, a := range addrs {
		// zone 只能由本机接口决定；解析出来的 v6 链路本地地址（正常不会出现）不带 zone，跳过
		if a.Zone() != "" {
			continue
		}
		out = append(out, netaddr.Addr{IP: a})
	}
	return out, ""
}

// pickTLSCode 从各地址的失败结果里挑**最能说明问题**的那一个，连它的细节一起带回。
//
// ★ 排序按「离证书这件事有多近」：明文服务 > 握手没谈成 > 端口关 > 丢包 > 到不了。
//
//	拿到 not-tls 就意味着端口给错了，比「这个地址族连不通」有用得多。
//	挑中谁就用谁的 detail，别拿最后一个的错去解释第一个的判定。
func pickTLSCode(tried []tlsAttempt) tlsAttempt {
	order := map[string]int{
		tlsNotTLS: 0, tlsHandshakeFailed: 1,
		verdictClosed: 2, verdictFiltered: 3, dnsUnreachable: 4,
	}
	best, rank := tlsAttempt{}, 1<<30
	for _, t := range tried {
		r, ok := order[t.Code]
		if !ok {
			r = 5
		}
		if r < rank {
			best, rank = t, r
		}
	}
	if best.Code == "" {
		best.Code = tlsHandshakeFailed
	}
	return best
}

// attempt 是一个候选地址的连接结果。★ 域名往往两族都有地址，把每一次尝试都列出来，
// 才能分清「v6 连不通但 v4 拿到了证书」和「两边都连不通」—— 后者才该往网络上查。
type tlsAttempt struct {
	Address string `json:"address"`
	Family  string `json:"family"`
	Code    string `json:"code"`
	Detail  string `json:"detail,omitempty"`
}

type tlsArgs struct {
	Addr       string `json:"addr"`
	Port       int    `json:"port,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	WarnDays   int    `json:"warnDays,omitempty"`
	TimeoutMS  int    `json:"timeoutMs,omitempty"`
}

func doTLSCheck(ctx context.Context, raw json.RawMessage) (any, error) {
	var a tlsArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	warnDays := a.WarnDays
	if warnDays == 0 {
		warnDays = 14
	}
	timeout := 5 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host, ip, port, err := splitTLSAddr(a.Addr)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if port == 0 {
		port = a.Port
	}
	if port == 0 {
		port = 443 // ★ 默认 443：现场拷进来的几乎总是 https 的地址，让人每次补端口是把活儿推回去
	}
	if port < 1 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "端口 %d 不在 1-65535 之间（HTTPS 一般是 443）", port)
	}

	// ★ SNI 只能放主机名，放 IP 会直接违反协议。用 IP 访问时不发 SNI，
	//   但仍然按这个 IP 去核对证书里有没有写 IP SAN —— 两件事分开。
	sni, checkName := a.ServerName, a.ServerName
	if sni == "" {
		checkName = host
		if !ip.IsValid() {
			sni = host
		}
	}

	values := map[string]any{"port": port}
	if sni != "" {
		values["serverName"] = sni
	}
	if checkName != "" {
		values["checkedName"] = checkName
	}
	// 要连的地址：给的是 IP 就直接用（链路本地按本平台拼 zone）；
	// 给的是域名就先解析。★ 域名两族都留着、挨个试到握手成功为止 ——
	//   只取解析结果第一个，会把「AAAA 排在前面但连不通」算成证书坏了。
	var cands []netaddr.Addr
	if ip.IsValid() {
		cands = []netaddr.Addr{ip}
	} else {
		addrs, fail := resolveTLSHost(ctx, host)
		if fail != "" {
			values["detail"] = fail
			return ots.Verdict{Code: tlsNameUnresolved, Values: values,
				Note: host + " 没能解析出地址，原因见 detail —— 还没到证书那一步"}, nil
		}
		if len(addrs) == 0 {
			values["detail"] = "DNS 回了成功，但一条地址都没有"
			return ots.Verdict{Code: tlsNameUnresolved, Values: values,
				Note: host + " 解析不到地址（NODATA）—— 这个域名只写了别的记录类型"}, nil
		}
		cands = addrs
		values["hostname"] = host
	}

	var (
		conn  *tls.Conn
		tried []tlsAttempt
	)
	for _, ad := range cands {
		target, terr := ad.HostPort(port, runtime.GOOS)
		if terr != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s", terr)
		}
		c, code, d := dialTLS(ctx, target, sni)
		if code != "" {
			tried = append(tried, tlsAttempt{Address: target, Family: familyOf(ad), Code: code, Detail: d})
			continue
		}
		conn = c
		values["target"] = target
		values["family"] = familyOf(ad)
		break
	}
	if conn == nil {
		best := pickTLSCode(tried)
		values["attempts"] = tried
		values["target"] = best.Address
		values["family"] = best.Family
		if best.Detail != "" {
			values["detail"] = best.Detail
		}
		return ots.Verdict{Code: best.Code, Values: values,
			Note: tlsDialNote(best.Code, best.Address, len(tried))}, nil
	}
	defer conn.Close()

	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		values["detail"] = "协商到了匿名加密套件，或它根本不是按 HTTPS 出证的"
		return ots.Verdict{Code: tlsNoCert, Values: values,
			Note: str(values["target"]) + " 完成了 TLS 握手却没有出示证书"}, nil
	}
	now := time.Now()
	leaf := st.PeerCertificates[0]
	values["protocol"] = tls.VersionName(st.Version)
	values["cipherSuite"] = tls.CipherSuiteName(st.CipherSuite)
	values["subject"] = certName(leaf.Subject)
	values["issuer"] = certName(leaf.Issuer)
	values["notBefore"] = leaf.NotBefore.Format(time.RFC3339)
	values["notAfter"] = leaf.NotAfter.Format(time.RFC3339)
	values["serial"] = leaf.SerialNumber.String()
	values["keyAlgorithm"] = leaf.PublicKeyAlgorithm.String()
	values["signatureAlgorithm"] = leaf.SignatureAlgorithm.String()
	if len(leaf.DNSNames) > 0 {
		values["san"] = leaf.DNSNames
	}
	if len(leaf.IPAddresses) > 0 {
		values["sanIP"] = ipStrings(leaf.IPAddresses)
	}
	if len(st.VerifiedChains) > 0 {
		values["chain"] = chainNames(st.VerifiedChains[0])
	} else {
		values["chain"] = chainNames(st.PeerCertificates)
	}

	// ★ 先验链再判定：verifyChain 用本机信任列表，结果原样交给 assessTLS，
	//   不让 assessTLS 自己去拿系统状态 —— 那样这条判定的测试只能靠运气。
	chainErr := verifyChain(now, leaf, checkName)
	assess := assessTLS(now, leaf, checkName, st.Version, warnDays, chainErr)
	values["daysLeft"] = assess.DaysLeft
	values["selfSigned"] = assess.SelfSigned
	values["hostnameMatch"] = assess.HostnameOK
	values["trusted"] = assess.Trusted
	values["weakProtocol"] = assess.WeakProtocol
	if len(assess.Reasons) > 0 {
		values["reason"] = strings.Join(assess.Reasons, "；")
	}
	return ots.Verdict{Code: assess.Code, Values: values,
		Note: tlsNote(assess.Code, values)}, nil
}

// dialTLS 把握手跑完。返回连接，或者一个判定码 + 细节（两者只有一个非空）。
//
// ★ MinVersion 放到 TLS1.0：不放的话，老设备（大量在网摄像头、老平台）会握手失败，
//
//	而我们收到的错误只说「协议版本不支持」，看不出到底它能谈到哪一层。
func dialTLS(ctx context.Context, target, sni string) (*tls.Conn, string, string) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		switch classify(err) {
		case verdictClosed:
			return nil, verdictClosed, ""
		case verdictFiltered:
			return nil, verdictFiltered, ""
		}
		var oe *net.OpError
		if errors.As(err, &oe) {
			return nil, dnsUnreachable, err.Error()
		}
		return nil, tlsHandshakeFailed, err.Error()
	}
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: sni,
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		s := err.Error()
		// ★ 「不像 TLS」是**判定**不是错误：这个端口很可能是明文 HTTP / RTSP，
		//   报成握手失败会让人去查证书，而真正的问题是端口给错了。
		if strings.Contains(s, "first record does not look like a TLS handshake") ||
			strings.Contains(s, "unsupported protocol") || strings.Contains(s, "bad record header") ||
			strings.Contains(s, "http response to https request") {
			return nil, tlsNotTLS, s
		}
		return nil, tlsHandshakeFailed, s
	}
	return conn, "", ""
}

// tlsAssess 是 assessTLS 的结果。★ 纯函数（不吃网络、不吃时钟外的一切），好逐条钉测试。
type tlsAssess struct {
	Code         string
	DaysLeft     int
	SelfSigned   bool
	HostnameOK   bool
	Trusted      bool
	WeakProtocol bool
	Reasons      []string
}

// assessTLS 判一颗证书。★ 纯函数：时间、协商到的协议版本、链验证结果全从参数进来，
// 不吃网络也不吃本机的状态 —— 否则这函数的测试就只能靠「这台机器恰好信什么」。
//
// 顺序就是现场的重要程度：先「过没过期」，再「名字对不对」，然后才轮到「受不受信」
// —— 因为前两条是**必须换证书**的，第三条往往只是本机没导入。
func assessTLS(now time.Time, leaf *x509.Certificate, checkName string, proto uint16,
	warnDays int, chainErr error) tlsAssess {
	a := tlsAssess{
		DaysLeft:     int(leaf.NotAfter.Sub(now).Hours() / 24),
		SelfSigned:   selfSigned(leaf),
		WeakProtocol: proto < tls.VersionTLS12,
		HostnameOK:   true,
		Trusted:      true,
	}
	// ★ reason 按「先能看出必须换证书、再看只是本机没导入」的顺序拼
	if now.After(leaf.NotAfter) {
		a.Reasons = append(a.Reasons, "证书已过期")
	}
	if now.Before(leaf.NotBefore) {
		a.Reasons = append(a.Reasons, "证书的生效时间还在未来")
	}
	if checkName != "" {
		if err := leaf.VerifyHostname(checkName); err != nil {
			a.HostnameOK = false
			a.Reasons = append(a.Reasons, "证书上的名字不包括「"+checkName+"」")
		}
	}
	if a.WeakProtocol {
		a.Reasons = append(a.Reasons, "只谈到了老版本 TLS（"+tls.VersionName(proto)+"）")
	}
	if chainErr != nil {
		a.Trusted = false
		a.Reasons = append(a.Reasons, verifyReason(chainErr, a.SelfSigned))
	}

	switch {
	case now.After(leaf.NotAfter):
		a.Code = certExpired
	case now.Before(leaf.NotBefore):
		a.Code = certNotYetValid
	case !a.HostnameOK:
		a.Code = certNameMismatch
	case !a.Trusted && a.SelfSigned:
		a.Code = certSelfSigned
	case !a.Trusted:
		a.Code = certUnknownAuthority
	case a.DaysLeft <= warnDays:
		a.Code = certExpiringSoon
	case a.WeakProtocol:
		a.Code = certWeakProtocol
	default:
		a.Code = certOK
	}
	return a
}

// selfSigned 判「自己给自己签」。★ 不能用 CheckSignatureFrom(leaf)：那条路顺带要求
// 这张证书有 CA 资格，而现场绝大多数设备的自签**叶子**证书恰恰没有 CA 标记 ——
// 表现是把自签报成「缺签发者的那一级」，把人往「装根证书」的反方向引（装不进去的）。
// 所以直接查两件事：主题与签发者同一个名字，且签名能被它自己的公钥验过。
func selfSigned(leaf *x509.Certificate) bool {
	if !bytes.Equal(leaf.RawSubject, leaf.RawIssuer) {
		return false
	}
	return leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
}

// verifyChain 用**本机**的信任列表验一遍。
//
// ★ 为什么要单独验：Go 把握手时的校验结果在 InsecureSkipVerify 下全丢了，
//
//	而「这台机器信不信它」正是现场要的那条信息（浏览器报错就是这条）。
func verifyChain(now time.Time, leaf *x509.Certificate, checkName string) error {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		// 拿不到系统信任列表时不判「不受信」——那是这台机器的读取问题，不是证书的问题
		return nil
	}
	opts := x509.VerifyOptions{
		CurrentTime: now, Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	// ★ 只有主机名才能进 DNSName；拿 IP 去填它会让 Verify 报一个看不懂的错
	if checkName != "" && net.ParseIP(checkName) == nil {
		opts.DNSName = checkName
	}
	_, err = leaf.Verify(opts)
	return err
}

func verifyReason(err error, selfSigned bool) string {
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		if selfSigned {
			return "自签证书（自己给自己签的），本机不认它的根"
		}
		return "验证不下去：本机信任列表里没有签发它的那一级"
	}
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) {
		// ★ Go 把「还没生效」和「已过期」都归到 Expired 这一个 reason，
		//   所以这里不能只翻译字面意思，得自己再对一次时间窗。
		switch ci.Reason {
		case x509.Expired:
			// ★ Go 把「还没生效」和「已过期」并成一个 reason，这里就不假装能分清；
			//   顶层判定码是按叶子证书的时间自己算的，要看具体是哪种查 notBefore/notAfter。
			return "证书链里有成员不在有效期内（过期，或生效时间还在未来）"
		case x509.NameMismatch:
			return "证书链上下级名字对不上（中间证书装错或发错设备）"
		case x509.NotAuthorizedToSign:
			return "签发它的那一级没有被标记为 CA，验不下去"
		}
		return "证书本身有问题：" + ci.Error()
	}
	var hc x509.HostnameError
	if errors.As(err, &hc) {
		return "证书上的名字不包括要访问的地址"
	}
	// ★ macOS 上 Go 把验证交给系统的 Security 框架，回来的是一条**纯文本**错误
	//   （没有结构化类型可断言）。不认文本的话，自签设备就会变成一句英文塞进 reason。
	if s := err.Error(); strings.Contains(s, "not trusted") || strings.Contains(s, "unknown authority") {
		if selfSigned {
			return "自签证书（自己给自己签的），本机不认它的根"
		}
		return "验证不下去：本机信任列表里没有签发它的那一级"
	}
	return "验证失败：" + err.Error()
}

// tlsDialNote 说清「没连上」是哪种没连上。★ where 用**挑中那个地址**，
// 域名两族都试过时会补一句去看 attempts —— 不然人只会看到一个地址，以为只试了它。
func tlsDialNote(code, where string, tried int) string {
	more := ""
	if tried > 1 {
		more = fmt.Sprintf("（%d 个地址都没成，逐个结果见 attempts）", tried)
	}
	switch code {
	case verdictClosed:
		return where + " 端口关着（对方明确拒绝）—— 这个端口上没有 TLS 服务" + more
	case verdictFiltered:
		return where + " 没有任何回应 —— 分不清端口是关着还是被静默丢了" + more
	case dnsUnreachable:
		return "连 " + where + " 都到不了 —— 先确认地址和路由" + more
	case tlsNotTLS:
		return where + " 回的不是 TLS —— 这个端口多半是明文服务（HTTP、RTSP）" + more
	case tlsHandshakeFailed:
		return where + " 连上了但 TLS 握手没谈成，原因见 detail" + more
	}
	return where + " 没能完成 TLS 连接" + more
}

func tlsNote(code string, values map[string]any) string {
	reason, _ := values["reason"].(string)
	subject, _ := values["subject"].(string)
	issuer, _ := values["issuer"].(string)
	switch code {
	case certOK:
		return subject + " 的证书有效（签发者：" + issuer + "）"
	case certExpired:
		return subject + " 的证书已过期（到期时间 " + str(values["notAfter"]) + "）—— 必须换证书"
	case certNotYetValid:
		return "证书还没到生效时间 —— 多半是**这台设备的时钟不对**，先校时间"
	case certNameMismatch:
		return "证书有效，但上面的名字和访问的地址对不上（检查的是 " + str(values["checkedName"]) +
			"，证书写的是 " + strings.Join(dnsNames(values), "、") + "）—— 要么按证书上的名字访问，要么重签"
	case certSelfSigned:
		return subject + " 用的是自签证书：本身没过期，只是本机不认它这个根 —— 内网设备很常见，" +
			"要么把它的根证书装进信任列表，要么换一张正规的"
	case certUnknownAuthority:
		return "本机验证不过这条证书链：签发者（" + issuer + "）不在信任列表里 —— 装上企业/设备的根证书"
	case certExpiringSoon:
		return subject + " 的证书只剩 " + str(values["daysLeft"]) + " 天，趁现在换掉，别等到现场报警"
	case certWeakProtocol:
		return "证书本身可用，但对方只肯谈 " + str(values["protocol"]) +
			" —— 新版浏览器/平台会直接拒绝连接，要升级设备的 TLS"
	}
	if reason != "" {
		return reason
	}
	return "证书检查完成"
}

func certName(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.String()
}

func chainNames(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, certName(c.Subject))
	}
	return out
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func dnsNames(values map[string]any) []string {
	san, _ := values["san"].([]string)
	return san
}
