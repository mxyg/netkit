package gb28181

// RFC 2617 的 MD5 digest 认证，两端都用：本机扮设备时算应答，
// 本机当平台时出挑战并校验。
//
// ★ 为什么两头都要：现场问的是两种相反的 ——
//
//	「设备注册不上平台」要把本机当设备去走一遍，看是哪一步、哪一句回的话；
//	「平台说设备没上来」要把本机当平台开一个口，看设备到底往哪儿打。
//	只实现客户端就答不了后一半。
//
// ★★ 密码这条路只进 MD5，别的一律不出去：不进 Values、不进日志、不进错误文本，
//
//	也不进任何 String()。这份结果会整份发给 AI，也可能被打进诊断包。
//	所以这里没有「把凭据打出来看看」的口子 —— Credentials 只有字段，
//	没有任何方法会把 password 带出去。

import (
	"crypto/md5" // #nosec G501 —— digest 的算法就是 MD5，这是协议规定的，不是我们选的
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

const digestNonceTTL = 5 * time.Minute

// Challenge 是 WWW-Authenticate 里平台给的那一套参数。
type Challenge struct {
	Realm     string
	Nonce     string
	Opaque    string
	Algorithm string   // 空按 MD5 处理；MD5-sess 也认
	QOP       []string // 平台支持的 qop，常见只有 auth
	Stale     bool
}

// Authorization 是设备回的那一套（本机组装 / 本机校验同用）。
type Authorization struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Algorithm string
	QOP       string
	NC        string
	CNonce    string
	Response  string
	Opaque    string
}

// parseAuthParams 拆 'realm="a",nonce="b",qop="auth"'。
// ★ 键一律转小写：设备发的头里 Realm/realm、Nonce/nonce 都见过，
// 按大小写敏感的键取就等于随机地认不认。
func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	for _, part := range splitOutsideQuotes(s, ',') {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

// ParseChallenge 读 WWW-Authenticate 的值。"Digest " 前缀有没有都收。
func ParseChallenge(value string) (*Challenge, error) {
	v := strings.TrimSpace(value)
	if scheme, rest, ok := strings.Cut(v, " "); ok && strings.EqualFold(scheme, "digest") {
		v = strings.TrimSpace(rest)
	}
	if v == "" {
		return nil, fmt.Errorf("没有挑战参数")
	}
	p := parseAuthParams(v)
	if p["nonce"] == "" {
		return nil, fmt.Errorf("挑战里没有 nonce")
	}
	qop := []string{}
	if q := p["qop"]; q != "" {
		for _, x := range strings.Split(q, ",") {
			if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
				qop = append(qop, x)
			}
		}
	}
	algo := strings.ToUpper(p["algorithm"])
	if algo == "" {
		algo = "MD5"
	}
	return &Challenge{
		Realm:     p["realm"],
		Nonce:     p["nonce"],
		Opaque:    p["opaque"],
		Algorithm: algo,
		QOP:       qop,
		Stale:     strings.EqualFold(p["stale"], "true"),
	}, nil
}

// Header 把挑战序列化回 WWW-Authenticate 的值。★ 只写给过值的那几项：
// 空 realm 写出去会让设备算出一个跟校验时对不上的 HA1。
func (c *Challenge) Header() string {
	var b strings.Builder
	b.WriteString(`Digest realm="`)
	b.WriteString(c.Realm)
	b.WriteString(`", nonce="`)
	b.WriteString(c.Nonce)
	b.WriteString(`"`)
	if c.Opaque != "" {
		b.WriteString(`, opaque="`)
		b.WriteString(c.Opaque)
		b.WriteString(`"`)
	}
	if c.Algorithm != "" && c.Algorithm != "MD5" {
		b.WriteString(`, algorithm=`)
		b.WriteString(c.Algorithm)
	}
	if len(c.QOP) > 0 {
		b.WriteString(`, qop="`)
		b.WriteString(strings.Join(c.QOP, ","))
		b.WriteString(`"`)
	}
	if c.Stale {
		b.WriteString(`, stale=TRUE`)
	}
	return b.String()
}

// PickQOP 按平台给的清单挑一个我们算得动的。只有 auth 与「不给 qop」两种支持，
// 挑不出来时返回 qopAuthInt 这类不支持的值并报错 —— 宁可不答，
// 也别按 auth 的算法算一个 auth-int 位置上的 response，那是「认证失败」里最难查的一种。
func (c *Challenge) PickQOP() (string, error) {
	if len(c.QOP) == 0 {
		return "", nil
	}
	for _, q := range c.QOP {
		if q == "auth" {
			return "auth", nil
		}
	}
	return "", fmt.Errorf("平台只给了 %v 这一种 qop，本工具只实现 auth", strings.Join(c.QOP, ","))
}

// Response 算 response 字段。method 用请求方法，uri 用 Request-URI，
// body 只在 auth-int 下有意义（这里不支持，前面已经拦掉了）。
//
// ★ uri 必须用**发出去那一条请求**的 Request-URI，不能用「设备编号」或本机自己
//
//	拼的显示串：平台按它收到的 Request-URI 重算，差一个字符就是 401 死循环。
func (c *Challenge) Response(user, password, method, uri, qop, nc, cnonce string) (string, error) {
	if c.Realm == "" {
		return "", fmt.Errorf("挑战里没有 realm，算不出 HA1")
	}
	ha1 := md5Hex(user + ":" + c.Realm + ":" + password)
	if c.Algorithm == "MD5-SESS" {
		if qop == "" || nc == "" || cnonce == "" {
			return "", fmt.Errorf("MD5-sess 必须带 qop、nc、cnonce")
		}
		ha1 = md5Hex(ha1 + ":" + c.Nonce + ":" + cnonce)
	}
	ha2 := md5Hex(method + ":" + uri)
	if qop == "" {
		return md5Hex(ha1 + ":" + c.Nonce + ":" + ha2), nil
	}
	return md5Hex(ha1 + ":" + c.Nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2), nil
}

// ChallengeFrom 从一条 401/407 里取平台给的挑战。
// ★ 拿不到挑战时错误里说的是「没带挑战」—— 这一档的下一步是看平台侧配置，不是改口令。
//
// ★ WWW-Authenticate 与 Proxy-Authenticate 两种都读：绝大多数平台发前者，
// 少数级联结构里挑战是中间那一跳加的，用的是后者。只认一种就是把
// 「平台要认证」读成「平台没答」。
func ChallengeFrom(msg *Message) (*Challenge, error) {
	for _, name := range []string{HWWWAuthenticate, "Proxy-Authenticate"} {
		v := msg.Get(name)
		if v == "" {
			continue
		}
		ch, err := ParseChallenge(v)
		if err != nil {
			return nil, &Error{Stage: "auth", Kind: KindAuth,
				Detail: fmt.Sprintf("%s 这条头读不出挑战：%s", name, err), Err: err}
		}
		return ch, nil
	}
	return nil, &Error{Stage: "auth", Kind: KindAuth,
		Detail: "回了要求认证的响应，却没把挑战带上（缺 WWW-Authenticate）"}
}

// AuthorizeRequest 按挑战把 Authorization 装进这条请求（客户端方向，就地改）。
// ★ method 与 uri 一律从请求自己身上取，不从配置取：平台是按它**收到的**
// Request-URI 重算 HA2 的，这里差一个字符就成 401 死循环。
func AuthorizeRequest(req *Message, challenge *Challenge, user, password string) error {
	if req == nil {
		return &Error{Stage: "auth", Kind: KindLocal, Detail: "要签名的请求本身都没有"}
	}
	if challenge == nil {
		return &Error{Stage: "auth", Kind: KindLocal, Detail: "没有挑战可签（先拿到 401 里那条 WWW-Authenticate）"}
	}
	// ★ 响应上签名是一件看不见的错：它的 Method 与 URI 都是空串，
	// 于是 HA2 算的是 ":"，平台永远认不下，界面上只表现为「口令明明对，它就是 401」。
	if !req.IsRequest() {
		return &Error{Stage: "auth", Kind: KindLocal,
			Detail: "这是一条响应，签名只能装进请求"}
	}
	value, err := Authorize(challenge, user, password, req.Method, req.URI)
	if err != nil {
		return &Error{Stage: "auth", Kind: KindAuth, Detail: err.Error(), Err: err}
	}
	req.Set(HAuthorization, value)
	return nil
}

// Authorize 组一条 Authorization 头的值（客户端方向）。
func Authorize(challenge *Challenge, user, password, method, uri string) (string, error) {
	qop, err := challenge.PickQOP()
	if err != nil {
		return "", err
	}
	nc := "00000001"
	cnonce := randHex(12)
	resp, err := challenge.Response(user, password, method, uri, qop, nc, cnonce)
	if err != nil {
		return "", err
	}
	a := Authorization{
		Username:  user,
		Realm:     challenge.Realm,
		Nonce:     challenge.Nonce,
		URI:       uri,
		Algorithm: challenge.Algorithm,
		QOP:       qop,
		NC:        nc,
		CNonce:    cnonce,
		Response:  resp,
		Opaque:    challenge.Opaque,
	}
	return a.Header(), nil
}

// Header 序列化成本机应答（不写 password，也没有地方能写它）。
func (a Authorization) Header() string {
	var b strings.Builder
	b.WriteString(`Digest username="`)
	b.WriteString(a.Username)
	b.WriteString(`", realm="`)
	b.WriteString(a.Realm)
	b.WriteString(`", nonce="`)
	b.WriteString(a.Nonce)
	b.WriteString(`", uri="`)
	b.WriteString(a.URI)
	b.WriteString(`"`)
	if a.Algorithm != "" && a.Algorithm != "MD5" {
		b.WriteString(`, algorithm=` + a.Algorithm)
	}
	if a.QOP != "" {
		b.WriteString(`, qop=` + a.QOP + `, nc=` + a.NC + `, cnonce="` + a.CNonce + `"`)
	}
	b.WriteString(`, response="`)
	b.WriteString(a.Response)
	b.WriteString(`"`)
	if a.Opaque != "" {
		b.WriteString(`, opaque="` + a.Opaque + `"`)
	}
	return b.String()
}

// ParseAuthorization 读设备回的那一条。
func ParseAuthorization(value string) (*Authorization, error) {
	v := strings.TrimSpace(value)
	if scheme, rest, ok := strings.Cut(v, " "); ok && strings.EqualFold(scheme, "digest") {
		v = strings.TrimSpace(rest)
	}
	p := parseAuthParams(v)
	if p["username"] == "" || p["response"] == "" {
		return nil, fmt.Errorf("应答里没有 username 或 response")
	}
	algo := strings.ToUpper(p["algorithm"])
	if algo == "" {
		algo = "MD5"
	}
	return &Authorization{
		Username:  p["username"],
		Realm:     p["realm"],
		Nonce:     p["nonce"],
		URI:       p["uri"],
		Algorithm: algo,
		QOP:       p["qop"],
		NC:        p["nc"],
		CNonce:    p["cnonce"],
		Response:  strings.ToLower(p["response"]),
		Opaque:    p["opaque"],
	}, nil
}

// 校验失败的几种原因。★ 分开是因为现场下一步完全不一样：nonce 过期是让它重新走一趟，
// 口令不对是配错了，uri 不对是设备把 digestUri 算成了自己的地址（有些固件真这么干），
// realm 不对是这台设备被配到过别的平台上、单子还留着。
var (
	ErrDigestBadResponse  = fmt.Errorf("response 对不上，口令或算法不对")
	ErrDigestStaleNonce   = fmt.Errorf("nonce 已经过期")
	ErrDigestUnknownNonce = fmt.Errorf("nonce 不是这一轮发出去的")
	ErrDigestReplay       = fmt.Errorf("nc 没有往前走，这条应答是重复的")
	ErrDigestURI          = fmt.Errorf("应答里的 uri 跟请求的 Request-URI 不一致")
	ErrDigestRealm        = fmt.Errorf("应答里的 realm 跟这台发的挑战不一致")
	ErrDigestQOP          = fmt.Errorf("应答里的 qop 不是 auth")
)

// Nonces 是平台侧发出去、并且还要认的 nonce 清单。
//
// ★ 带 TTL 且不记内容只记发出时间：nonce 是平台选的单子，
// 设备拿旧 nonce 来答就要回 stale=TRUE，让它重新走一趟，而不是直接拒 ——
// 直接拒在界面上就成了「口令不对」，那是最难查的一种冤枉。
type Nonces struct {
	mu     sync.Mutex
	ttl    time.Duration
	issued map[string]time.Time
	realm  string
}

func NewNonces(realm string, ttl time.Duration) *Nonces {
	if ttl <= 0 {
		ttl = digestNonceTTL
	}
	return &Nonces{ttl: ttl, issued: map[string]time.Time{}, realm: realm}
}

// Issue 出一个挑战。opaque 跟 nonce 同值，用于「设备会不会把 opaque 原样带回来」
// 这一项检查（有些老设备吞了 opaque，某些平台因此死活认不下）。
func (n *Nonces) Issue(now time.Time) *Challenge {
	n.mu.Lock()
	defer n.mu.Unlock()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	value := hex.EncodeToString(raw)
	n.issued[value] = now
	for k, t := range n.issued { // 顺手清掉过期的，这个口一开就是几小时，别让它长
		if now.Sub(t) > n.ttl {
			delete(n.issued, k)
		}
	}
	return &Challenge{Realm: n.realm, Nonce: value, Opaque: value, Algorithm: "MD5", QOP: []string{"auth"}}
}

// Seen 认不认这个 nonce（不管过没过期）。
func (n *Nonces) Seen(nonce string, now time.Time) (known, fresh bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	t, ok := n.issued[nonce]
	return ok, ok && now.Sub(t) <= n.ttl
}

// NCSeen 记「这个编号在这个 nonce 上」用到哪一档了。
// ★ 只记最后一个，不记全 history —— 挡重复提交够用，
//
//	且不会因为来路不正的一串 nc 把内存吃了。
//
// ★ 键里必须带上 nonce：nc 是跟着一次挑战重头数的。设备在注册到期后拿新 nonce
//
//	重新从 1 数起是完全正常的一条路径，要是按编号记一笔总的，这条正常路径就会被
//	报成「重复提交」—— 现场看到的将是「口令没错、平台却死活不给 200」，
//	而人跟着去查一个根本不存在的毛病。nonce 本身先在 nonce 台账里认过，
//	所以按 nonce 分账并没有把重放的口子放开。
type NCSeen struct {
	mu sync.Mutex
	m  map[string]uint64
}

func NewNCSeen() *NCSeen { return &NCSeen{m: map[string]uint64{}} }

// Advance 要求 nc 比这个 nonce 上次看到的更大；第一次见到就收下。
func (s *NCSeen) Advance(nonce, user string, nc string) error {
	n, err := parseNC(nc)
	if err != nil {
		return err
	}
	key := nonce + "\x00" + user
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.m[key]; ok && n <= last {
		return ErrDigestReplay
	}
	s.m[key] = n
	return nil
}

// Prune 把 nonce 已经不在台账上的那些记账丢掉。
// ★ 按 nonce 分账就意味着一趟挑战留一笔：探测口一开几个小时，不清会一直长。
//
//	nonce 台账自己会清过期，这里跟着它清，账就对不齐不了 ——
//	一个已经不认的 nonce 再打进来，先撞上的是 unknown/stale nonce 那一条，用不到 nc。
func (s *NCSeen) Prune(alive func(nonce string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.m {
		nonce, _, _ := strings.Cut(k, "\x00")
		if !alive(nonce) {
			delete(s.m, k)
		}
	}
}

func parseNC(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("nc 不是十进制数字：%q", s)
		}
		n = n*10 + uint64(r-'0')
	}
	return n, nil
}

// Verifier 是平台侧那一坨台账：发出去的 nonce、用掉的 nc、这台认的 realm。
//
// ★ 合成一个类型而不是让调用方自己拿两个 map 配对：nonce 与 nc 张冠李戴
//
//	（换了台账实例）会表现成「设备死活注册不上」，而这种错查到最后是代码里
//		传错了参数，跟协议一点关系都没有。
type Verifier struct {
	realm  string
	nonces *Nonces
	nc     *NCSeen
}

func NewVerifier(realm string, ttl time.Duration) *Verifier {
	return &Verifier{realm: realm, nonces: NewNonces(realm, ttl), nc: NewNCSeen()}
}

// Realm 是这台报出去的挑战域名，工具层要把它显示出来 —— 设备配错 realm 时，
// 现场对照的就这几个字。
func (v *Verifier) Realm() string { return v.realm }

// Challenge 出一个新挑战（用于回 401），顺手把那些 nonce 已经不在账上的 nc 记账清掉。
func (v *Verifier) Challenge(now time.Time) *Challenge {
	c := v.nonces.Issue(now)
	v.nc.Prune(func(nonce string) bool { seen, _ := v.nonces.Seen(nonce, now); return seen })
	return c
}

// Verify 校验设备回的那一条应答。password 由调用方按 username 查出来递进来 ——
// ★ 这一层不认识「谁的口令是什么」，也不存任何东西，凭据的账留在工具层。
func (v *Verifier) Verify(a *Authorization, method, uri, password string, now time.Time) error {
	if a.Nonce == "" {
		return ErrDigestUnknownNonce
	}
	seen, fresh := v.nonces.Seen(a.Nonce, now)
	if !seen {
		return ErrDigestUnknownNonce
	}
	if !fresh {
		return ErrDigestStaleNonce
	}
	if a.Realm != v.realm {
		return ErrDigestRealm
	}
	if uri != "" && a.URI != uri {
		return ErrDigestURI
	}
	switch a.QOP {
	case "":
		// 老固件真有不带 qop 的：按不带 qop 的那条公式算，别当成口令错。
		// ★ 这里宽容、但账要留在工具层 —— 「这台设备没带 qop」本身是一条该看见的事实。
	case "auth":
		if err := v.nc.Advance(a.Nonce, a.Username, a.NC); err != nil {
			return err
		}
	default:
		return ErrDigestQOP
	}
	want, err := (&Challenge{Realm: v.realm, Nonce: a.Nonce, Algorithm: a.Algorithm}).
		Response(a.Username, password, method, uri, a.QOP, a.NC, a.CNonce)
	if err != nil {
		return err
	}
	// ★ 定长时间比较：这一条挡的不是探测，是「有人拿这个口当预言机一项项试」。
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(want)), []byte(a.Response)) != 1 {
		return ErrDigestBadResponse
	}
	return nil
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) // #nosec G401 —— 同上：digest 认证规定用 MD5
	return hex.EncodeToString(sum[:])
}
