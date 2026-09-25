package gb28181test

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 假平台的模式。
const (
	PlatformDigest      = "digest"       // 规矩的一轮：先 401 出挑战，再验应答
	PlatformOpen        = "open"         // 不认证就收（现场那种内网裸放的平台）
	PlatformReject      = "reject"       // 403：编号不在它的清单里
	PlatformNoChallenge = "no-challenge" // 回 401 却不带挑战 —— 设备侧只能干等
	PlatformSilent      = "silent"       // 收了不回（多半是中间被防火墙吃了）
	PlatformNotSIP      = "not-sip"      // 那个口上跑着别的东西
)

// Registration 是这台平台收到的一次注册。
type Registration struct {
	DeviceID    string // From 里那个用户部分
	ContactHost string
	ContactPort string
	Expires     int
	AuthOK      bool
	UA          string
	At          time.Time
}

// PlatformOptions 配一台假平台。
type PlatformOptions struct {
	Mode    string
	Realm   string
	Users   map[string]string // 编号 => 口令
	Nonce   string            // 固定 nonce，用于「设备把 nonce 算错」这类样本
	Expires int
	// QueryAfterRegister 为真时，注册成功之后平台主动发一条 Catalog 查询 ——
	// ★ 现场「平台说设备在线、可通道是空的」就死在这一步，所以这一条必须是可开的。
	QueryAfterRegister bool
	// InviteAfterRegister 为真时，平台在问过通道表之后再发一条 INVITE（正文是 SDP）。
	// ★ 这一条给的是「平台到底把这台设备当什么」的最硬证据：肯发点播，才是真认下了；
	//	而设备回 200 还是 486/603，现场是两种完全不同的下一步。
	// InviteBody 由调用方用 InviteSDP(...) 拼好传进来。★ 这里刻意不收一个
	//	SDPOptions 结构去由平台自己拼：拼 SDP 是「发」的那一半，
	//	这份假台只负责把事先写好的字节发出去，免得它反过来依赖解析端那份定义。
	InviteAfterRegister bool
	InviteBody          string
}

// Platform 是一台在 127.0.0.1 上等人注册的假平台。
type Platform struct {
	conn   *net.UDPConn
	opts   PlatformOptions
	nonces map[string]bool

	mu sync.Mutex
	// 两条 Call-ID 台账。★ 必须按 Call-ID 分流：设备的应答都是「一条响应」，
	// 谁来读这个套接字都可能先拿到 —— 不分流就会把「它答了点播」数成
	// 「它答了通道表」，那正是这套假台要分开的那两件事。
	catalogCallID string
	inviteCallIDs map[string]bool

	regs          []Registration
	catalogAsked  bool
	catalogItems  int
	inviteSent    int
	inviteAnswers []int // 设备对 INVITE 回的状态码
	unknownAnswer int   // 认不出是对哪一条问的应答（★ 不能默默数进上面任何一项）
	stop          chan struct{}
	done          chan struct{}
}

func StartPlatform(t *testing.T, opts PlatformOptions) *Platform {
	t.Helper()
	if opts.Mode == "" {
		opts.Mode = PlatformDigest
	}
	if opts.Realm == "" {
		opts.Realm = "3402000000"
	}
	if opts.Users == nil {
		opts.Users = map[string]string{"34020000001110000001": "correct-horse"}
	}
	if opts.Expires == 0 {
		opts.Expires = 3600
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("起假平台失败：%v", err)
	}
	p := &Platform{conn: conn, opts: opts, nonces: map[string]bool{},
		inviteCallIDs: map[string]bool{}, stop: make(chan struct{}), done: make(chan struct{})}
	go p.serve()
	t.Cleanup(p.Close)
	return p
}

func (p *Platform) Port() int { return p.conn.LocalAddr().(*net.UDPAddr).Port }

func (p *Platform) Registrations() []Registration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Registration{}, p.regs...)
}

// CatalogSeen 是平台查询本机通道表时数到的条目数（-1 表示没问到结果）。
func (p *Platform) CatalogSeen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.catalogAsked {
		return -1
	}
	return p.catalogItems
}

// InviteSent 是平台发出过多少条 INVITE（重发不另计）。
func (p *Platform) InviteSent() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inviteSent
}

// InviteAnswers 是设备对 INVITE 回的状态码，按到达顺序。
// ★ 空切片就是「它一个字都没回」—— 现场这有三种完全不同的下一步
//
//	（没答 / 486 忙 / 603 拒绝），所以这里只如实列，不折叠成一个布尔。
func (p *Platform) InviteAnswers() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int{}, p.inviteAnswers...)
}

// UnknownAnswers 是「认不出是对哪一条问的应答」的条数。★ 单列是因为这类东西
// 要是被顺手数进上面任何一项，测试就会绿在一个根本没发生的事实上。
func (p *Platform) UnknownAnswers() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unknownAnswer
}

func (p *Platform) Close() {
	select {
	case <-p.stop:
		return
	default:
		close(p.stop)
	}
	_ = p.conn.Close()
	<-p.done
}

func (p *Platform) serve() {
	defer close(p.done)
	buf := make([]byte, 65536)
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.stop:
				return
			default:
				continue
			}
		}
		p.handle(buf[:n], from)
	}
}

func (p *Platform) handle(raw []byte, from *net.UDPAddr) {
	m, err := parse(raw)
	if err != nil {
		return
	}
	if !m.IsRequest {
		// 这是设备对平台发起的问的应答 —— 按 Call-ID 分进哪一桩事务。
		p.recordAnswer(m)
		return
	}
	switch m.Method {
	case "OPTIONS":
		p.write(m, from, 200, "OK", nil, "Allow: REGISTER, MESSAGE")
		return
	case "MESSAGE":
		p.write(m, from, 200, "OK", nil)
		return
	case "REGISTER":
	default:
		p.write(m, from, 405, "Method Not Allowed", nil)
		return
	}

	switch p.opts.Mode {
	case PlatformSilent:
		return
	case PlatformNotSIP:
		_, _ = p.conn.WriteToUDP([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"), from)
		return
	case PlatformOpen:
		// ★ 一次都不查，直接收下。AuthOK 必须是假 —— 这一条就是「注册上了」与
		//	「注册上了因为它没查」之间唯一的区别，界面上要分得开。
		p.accept(m, from, uriUser(m.header("From")), false)
		return
	case PlatformReject:
		p.write(m, from, 403, "Forbidden", nil)
		return
	case PlatformNoChallenge:
		p.write(m, from, 401, "Unauthorized", nil) // 就是不带 WWW-Authenticate
		return
	}

	user := param(m.header("From"), "user")
	if u := uriUser(m.header("From")); u != "" {
		user = u
	}
	want, known := p.opts.Users[user]
	if !known {
		p.write(m, from, 403, "Forbidden", nil)
		return
	}
	auth := m.header("Authorization")
	if auth == "" {
		p.write(m, from, 401, "Unauthorized", nil, "WWW-Authenticate: "+p.challenge(false))
		return
	}
	a := authorization(m)
	qop := a["qop"]
	nonce := a["nonce"]
	fresh, known := p.nonceKnown(nonce)
	switch {
	case !known:
		p.write(m, from, 401, "Unauthorized", nil, "WWW-Authenticate: "+p.challenge(false))
		return
	case !fresh:
		// stale=TRUE：让设备拿新单子重走一趟，而不是当成口令错。
		p.write(m, from, 401, "Unauthorized", nil, "WWW-Authenticate: "+p.challenge(true))
		return
	}
	got := a["response"]
	calc := digestResponse(user, a["realm"], want, nonce, m.Method, m.URI, qop, a["nc"], a["cnonce"])
	if a["realm"] != p.opts.Realm || got != calc {
		p.write(m, from, 401, "Unauthorized", nil, "WWW-Authenticate: "+p.challenge(false))
		return
	}
	p.accept(m, from, user, true)
}

// accept 收下这一条注册：记账、回 200，然后按开关决定要不要回头问它两句。
// authOK 由调用方给（查过并通过才是真），★ 内网裸放的那类平台要记成假。
func (p *Platform) accept(m msg, from *net.UDPAddr, user string, authOK bool) {
	h, pt := contactHostPort(m.header("Contact"))
	p.mu.Lock()
	p.regs = append(p.regs, Registration{
		DeviceID: user, ContactHost: h, ContactPort: pt,
		Expires: atoiDefault(m.header("Expires"), p.opts.Expires), AuthOK: authOK,
		UA: m.header("User-Agent"), At: time.Now(),
	})
	p.mu.Unlock()
	p.write(m, from, 200, "OK", nil, "Expires: "+strconv.Itoa(p.opts.Expires))
	if h != "" && (p.opts.QueryAfterRegister || p.opts.InviteAfterRegister) {
		go p.probe(net.UDPAddr{IP: net.ParseIP(h), Port: atoiDefault(pt, 0)}, user)
	}
}

// probe 注册成功之后按顺序问两句：先通道表，再点播。
// ★ 顺序就是现场的含义 —— 先认编号再要点流，两句都有回音才谈得上「这台设备在播」。
func (p *Platform) probe(to net.UDPAddr, deviceID string) {
	if p.opts.QueryAfterRegister {
		p.askCatalog(to, deviceID)
	}
	if p.opts.InviteAfterRegister {
		p.invite(to, deviceID)
	}
}

// recordAnswer 按 Call-ID 把一条应答分进对应的那一桩事务。
func (p *Platform) recordAnswer(m msg) {
	cid := m.header("Call-ID")
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case cid != "" && cid == p.catalogCallID:
		p.catalogAsked = true
		p.catalogItems = strings.Count(string(m.Body), "<Item>")
	case cid != "" && p.inviteCallIDs[cid]:
		// ★ 只记第一个：重发的那几次不算设备答了多次。
		delete(p.inviteCallIDs, cid)
		p.inviteAnswers = append(p.inviteAnswers, m.Status)
	default:
		p.unknownAnswer++
	}
}

// askCatalog 在注册成功之后主动问一次通道表 —— 这是「平台到底认没认下这台设备」的最硬证据。
func (p *Platform) askCatalog(to net.UDPAddr, deviceID string) {
	callID := "plat-cat-" + randHex(6) + "@127.0.0.1"
	body := []byte(rootOpen("Query") + "<CmdType>Catalog</CmdType><SN>1001</SN><DeviceID>" +
		deviceID + "</DeviceID>" + rootClose("Query"))
	raw := withCL("MESSAGE sip:"+deviceID+"@127.0.0.1 SIP/2.0",
		p.hdrsFor(callID, deviceID, "MESSAGE", "Application/MANSCDP+xml"), body)
	p.mu.Lock()
	p.catalogCallID = callID
	p.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := p.conn.WriteToUDP(raw, &to); err != nil {
			return
		}
		if p.waitCatalog(700 * time.Millisecond) {
			return
		}
	}
}

// invite 发一条 INVITE（正文是调用方拼好的 SDP），并等设备的应答。
func (p *Platform) invite(to net.UDPAddr, deviceID string) {
	if p.opts.InviteBody == "" {
		return
	}
	callID := "plat-inv-" + randHex(6) + "@127.0.0.1"
	raw := withCL("INVITE sip:"+deviceID+"@127.0.0.1 SIP/2.0",
		p.hdrsFor(callID, deviceID, "INVITE", "application/sdp"), []byte(p.opts.InviteBody))
	p.mu.Lock()
	p.inviteCallIDs[callID] = true
	p.inviteSent++
	p.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := p.conn.WriteToUDP(raw, &to); err != nil {
			return
		}
		if p.waitInvite(callID, 700*time.Millisecond) {
			return
		}
	}
}

// hdrsFor 拼一条请求的头（Via 用这台平台自己的口，From/To 按 GB28181 的写法）。
func (p *Platform) hdrsFor(callID, deviceID, method, contentType string) [][2]string {
	return [][2]string{
		{"Via", "SIP/2.0/UDP 127.0.0.1:" + strconv.Itoa(p.Port()) + ";branch=z9hG4bK" + randHex(6)},
		{"From", "<sip:" + p.opts.Realm + "@127.0.0.1:" + strconv.Itoa(p.Port()) + ">;tag=" + randHex(5)},
		{"To", "<sip:" + deviceID + "@127.0.0.1>"},
		{"Call-ID", callID},
		{"CSeq", "1 " + method},
		{"Content-Type", contentType},
		{"User-Agent", "gb28181test-platform"},
	}
}

// waitCatalog / waitInvite 只是等：读这个套接字的是 serve 那一个 goroutine，
// ★ 两处都读就会互相抢包，谁拿到哪个全看调度 —— 那样「偶发不绿」是我造的，不是现场有的。
func (p *Platform) waitCatalog(d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		p.mu.Lock()
		done := p.catalogAsked
		p.mu.Unlock()
		if done {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (p *Platform) waitInvite(callID string, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		p.mu.Lock()
		done := !p.inviteCallIDs[callID]
		p.mu.Unlock()
		if done {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// challenge 出一个新 nonce（记进台账，用于认「这是不是本轮发出去的单子」）。
func (p *Platform) challenge(stale bool) string {
	nonce := p.opts.Nonce
	if nonce == "" {
		nonce = randHex(16)
	}
	p.mu.Lock()
	p.nonces[nonce] = true
	p.mu.Unlock()
	h := `Digest realm="` + p.opts.Realm + `", nonce="` + nonce + `", qop="auth", algorithm=MD5`
	if stale {
		h += `, stale=TRUE`
	}
	return h
}

func (p *Platform) nonceKnown(nonce string) (fresh, known bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// ★ 假平台一律按新鲜处理，除非模式明说要过期 —— 过期那条路另有测试专门走。
	return true, p.nonces[nonce]
}

func (p *Platform) write(m msg, from *net.UDPAddr, status int, reason string, body []byte, extra ...string) {
	seq, method := cseqOf(m)
	hdrs := [][2]string{{"Via", m.header("Via")}, {"From", m.header("From")}, {"To", withTag(m.header("To"))},
		{"Call-ID", m.header("Call-ID")}, {"CSeq", strconv.FormatUint(seq, 10) + " " + method}}
	for _, e := range extra {
		k, v, _ := strings.Cut(e, ":")
		hdrs = append(hdrs, [2]string{k, strings.TrimSpace(v)})
	}
	raw := build(fmt.Sprintf("SIP/2.0 %d %s", status, reason), hdrs, body)
	_, _ = p.conn.WriteToUDP(raw, from)
}

func uriUser(headerValue string) string {
	s := strings.Trim(headerValue, "<>")
	if i := strings.Index(s, ";"); i >= 0 {
		s = s[:i]
	}
	if !strings.Contains(s, ":") {
		return ""
	}
	_, rest, _ := strings.Cut(s, ":")
	user, _, _ := strings.Cut(rest, "@")
	return user
}

func contactHostPort(contact string) (host, port string) {
	s := strings.Trim(strings.TrimSpace(contact), "<>")
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, ";"); i >= 0 {
		s = s[:i]
	}
	host, port, _ = strings.Cut(s, ":")
	return host, port
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
