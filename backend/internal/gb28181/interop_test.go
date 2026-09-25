package gb28181_test

// 两头对跑的测试：真的在回环 UDP 上发、真的收回来。
//
// ★ 为什么单开一份外部测试包：里面要同时引探测端（internal/gb28181）和
// 假对端（internal/gb28181/gb28181test），而假对端刻意不认识探测端。
// 单元那几份只验「自己拼的自己能读」，这里验的是「我拼的它读得动、它拼的我读得动」——
// 这一层真正的错全藏在这句话不成立的地方：起始行的顺序、Via 的 branch、
// digest 的拼接顺序、正文的 Content-Length、GBK 那几个字节。
//
// ★ 假对端每一种模式（= 现场一种毛病 = 一个判定码）在这里都必须有一条。

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/gb28181"
	"net.yuhox.com/netkit/internal/gb28181/gb28181test"
)

const (
	testDeviceID  = "34020000001110000001"
	testChannelID = "34020000001320000001"
	testRealm     = "3402000000"
	testPassword  = "correct-horse"
)

// ask 起一条请求发给对端并等回音。这套头集中在一处，是因为「Contact 要用本机
// 实际用到的那个口」这类错最容易在每个测试里各写一遍、各错一遍。
func ask(t *testing.T, c *gb28181.Client, method, user, host string, port int, body []byte, contentType string) (*gb28181.Reply, error) {
	t.Helper()
	return c.Request(newRequest(t, c, method, user, host, port, body, contentType), strings.ToLower(method), 2*time.Second)
}

func newRequest(t *testing.T, c *gb28181.Client, method, user, host string, port int, body []byte, contentType string) *gb28181.Message {
	t.Helper()
	sport := fmt.Sprint(port)
	uri := gb28181.SIPURI(user, host, sport)
	via := gb28181.NewVia(c.LocalHost(), c.LocalPort())
	req := gb28181.NewRequest(method, uri,
		"<"+gb28181.SIPURI(user, c.LocalHost(), c.LocalPort())+">",
		"<"+uri+">",
		"interop-"+via.Param("branch")+"@127.0.0.1",
		via.String(), c.NextCSeq())
	req.Set(gb28181.HContact, "<"+gb28181.SIPURI(user, c.LocalHost(), c.LocalPort())+">")
	req.Set(gb28181.HUserAgent, "netkit-interop")
	if method == gb28181.MethodRegister {
		req.Set(gb28181.HExpires, "3600")
	}
	if len(body) > 0 {
		req.Body = body
		req.Set(gb28181.HContentType, contentType)
	}
	return req
}

func dial(t *testing.T, host string, port int) *gb28181.Client {
	t.Helper()
	c, err := gb28181.DialClient(host, fmt.Sprint(port))
	if err != nil {
		t.Fatalf("连 %s:%d 就没成：%v", host, port, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// registerWithDigest 走完整一轮：发 → 401 出挑战 → 签名 → 再发 → 200。
func registerWithDigest(t *testing.T, c *gb28181.Client, host string, port int) (*gb28181.Reply, error) {
	t.Helper()
	req := newRequest(t, c, gb28181.MethodRegister, testDeviceID, host, port, nil, "")
	reply, err := c.Request(req, "register", 2*time.Second)
	if gb28181.StatusOf(err) != 401 {
		return reply, fmt.Errorf("第一趟本该拿到 401，实得 %v", err)
	}
	ch, cerr := gb28181.ChallengeFrom(reply.Final)
	if cerr != nil {
		return reply, fmt.Errorf("401 里的挑战读不出来：%w", cerr)
	}
	if aerr := gb28181.AuthorizeRequest(req, ch, testDeviceID, testPassword); aerr != nil {
		return reply, fmt.Errorf("按挑战签名失败：%w", aerr)
	}
	return c.Request(req, "register", 2*time.Second)
}

// Test问到关着的口与问到没人答的口必须分成两档 是这一层存在的全部理由：
// 前者去看设备配没配对地址，后者去看防火墙与白名单。
func Test问到关着的口与问到没人答的口必须分成两档(t *testing.T) {
	// 先占一个口再关掉，拿到一个「确定没人听」的口。
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()

	c := dial(t, "127.0.0.1", closed)
	_, err = ask(t, c, gb28181.MethodOptions, testDeviceID, "127.0.0.1", closed, nil, "")
	if gb28181.KindOf(err) != gb28181.KindRefused {
		t.Fatalf("关着的口报成了 %q（%v），要 refused —— 这一档报成超时，界面上就没人知道口是关的",
			gb28181.KindOf(err), err)
	}
	// 工具层按 errors.Is 认，不靠中文文本匹配。
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("refused 没把底层 errno 透出来，工具层就没法用 errors.Is 认：%v", err)
	}

	silent := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeSilent})
	c2 := dial(t, "127.0.0.1", silent.Port())
	reply, err := ask(t, c2, gb28181.MethodOptions, testDeviceID, "127.0.0.1", silent.Port(), nil, "")
	if gb28181.KindOf(err) != gb28181.KindTimeout {
		t.Fatalf("静默的口报成了 %q（%v），要 timeout", gb28181.KindOf(err), err)
	}
	// ★ 重发过才敢说「一个字节都没回」：只发一条就下结论，丢一个 UDP 包就冤枉一台设备。
	if reply == nil || reply.Sent < 2 {
		t.Errorf("这一问只发了 %+v 条，重发没生效", reply)
	}
	if reply != nil && reply.Sent > 8 {
		t.Errorf("2s 预算里重发了 %d 次，退让没起作用", reply.Sent)
	}
	if n := silent.Requests(); n < 2 {
		t.Errorf("假设备收到 %d 条请求，重发的没落到它那儿（那 timeout 就是本机自己造出来的）", n)
	}
}

func Test同一个口上跑着别的东西要说这不是SIP(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeNotSIP})
	c := dial(t, "127.0.0.1", d.Port())
	_, err := ask(t, c, gb28181.MethodOptions, testDeviceID, "127.0.0.1", d.Port(), nil, "")
	if gb28181.KindOf(err) != gb28181.KindNotSIP {
		t.Fatalf("报成了 %q（%v），要 not-sip", gb28181.KindOf(err), err)
	}
	if !strings.Contains(err.Error(), "HTTP/1.1") {
		t.Errorf("没把来路内容带上，现场就看不出那个口上跑的是什么：%v", err)
	}
}

func Test它在但这一刻不肯答应要带上状态码(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeBusy})
	c := dial(t, "127.0.0.1", d.Port())
	_, err := ask(t, c, gb28181.MethodOptions, testDeviceID, "127.0.0.1", d.Port(), nil, "")
	if gb28181.KindOf(err) != gb28181.KindStatus {
		t.Fatalf("报成了 %q（%v），要 status", gb28181.KindOf(err), err)
	}
	if got := gb28181.StatusOf(err); got != 503 {
		t.Errorf("状态码 %d，要 503（工具层按码分下一步）", got)
	}
}

func Test问设备自述要拿到真字段(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeOK})
	c := dial(t, "127.0.0.1", d.Port())
	const sn = "1"
	reply, err := ask(t, c, gb28181.MethodMessage, testDeviceID, "127.0.0.1", d.Port(),
		gb28181.DeviceInfoQuery(sn, testDeviceID), "Application/MANSCDP+xml")
	if err != nil {
		t.Fatalf("问自述失败：%v", err)
	}
	cmd, err := gb28181.BodyCmd(reply.Final)
	if err != nil {
		t.Fatalf("正文读不出来：%v", err)
	}
	if cmd.Root != "Response" {
		t.Errorf("根读成 %q，要 Response", cmd.Root)
	}
	if cmd.CmdType != "DeviceInfo" {
		t.Errorf("CmdType 读成 %q", cmd.CmdType)
	}
	if cmd.Get("DeviceName") != "测试枪机" {
		t.Errorf("DeviceName 读成 %q", cmd.Get("DeviceName"))
	}
	if cmd.DeviceID != testDeviceID {
		t.Errorf("DeviceID 读成 %q", cmd.DeviceID)
	}
	if !cmd.IsResponseTo("DeviceInfo", sn) {
		t.Error("IsResponseTo 认不出这是刚才那一问的答 —— 多问几句之后就分不清哪条对哪问了")
	}
	if cmd.IsResponseTo("Catalog", sn) {
		t.Error("CmdType 不对还被认成这一问的答")
	}
	if q := d.Queries(); len(q) != 1 || q[0] != "DeviceInfo" {
		t.Errorf("假设备那边记到的查询是 %v，要 [DeviceInfo]", q)
	}
}

func Test问通道表要数得出条目(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{
		Mode:     gb28181test.ModeOK,
		Channels: []gb28181test.Channel{{DeviceID: testChannelID, Name: "东门", Status: "ON"}},
	})
	c := dial(t, "127.0.0.1", d.Port())
	reply, err := ask(t, c, gb28181.MethodMessage, testDeviceID, "127.0.0.1", d.Port(),
		gb28181.CatalogQuery("7", testDeviceID, 1, 100), "Application/MANSCDP+xml")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := gb28181.BodyCmd(reply.Final)
	if err != nil {
		t.Fatal(err)
	}
	if sum, ok := cmd.SumNum(); !ok || sum != 1 {
		t.Errorf("SumNum 读成 %v/%v，要 1/true", sum, ok)
	}
	if cmd.ItemCount() != 1 {
		t.Fatalf("条目数 %d，要 1", cmd.ItemCount())
	}
	ids, missing := cmd.ItemDeviceIDs()
	if len(ids) != 1 || ids[0] != testChannelID || missing != 0 {
		t.Errorf("通道编号读成 %v 缺 %d", ids, missing)
	}
	code, err := gb28181.ParseCode(ids[0])
	if err != nil {
		t.Fatalf("通道编号 %q 按 20 位规则读不过：%v", ids[0], err)
	}
	if code.Type != "132" || code.Class() != "device" {
		t.Errorf("这条通道该是设备类的网络摄像机，读成 %+v class=%q", code, code.Class())
	}
	// 「它说有几条」与「数到几条」必须两本账都在：只报一个数就盖住了分页没做完。
	if cmd.Lists["devicelist"] != 1 {
		t.Errorf("容器记账读成 %v，要 devicelist:1", cmd.Lists)
	}
}

// 通道表那一句它就是不答：这是「能力缺」，与「口不通」是两种下一步。
func Test问通道表它不答要问得出是哪一句没答(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeNoCatalog})
	c := dial(t, "127.0.0.1", d.Port())
	if _, err := ask(t, c, gb28181.MethodMessage, testDeviceID, "127.0.0.1", d.Port(),
		gb28181.DeviceInfoQuery("1", testDeviceID), "Application/MANSCDP+xml"); err != nil {
		t.Fatalf("自述那一句本该答：%v", err)
	}
	_, err := ask(t, c, gb28181.MethodMessage, testDeviceID, "127.0.0.1", d.Port(),
		gb28181.CatalogQuery("2", testDeviceID, 0, 0), "Application/MANSCDP+xml")
	if gb28181.KindOf(err) != gb28181.KindTimeout {
		t.Fatalf("通道表报成 %q，要 timeout", gb28181.KindOf(err))
	}
	if q := d.Queries(); len(q) < 2 || q[len(q)-1] != "Catalog" {
		t.Errorf("假设备记到的查询是 %v，最后一条该是 Catalog", q)
	}
}

func Test答了200但正文是空的与正文是坏的必须两档分开(t *testing.T) {
	for _, tc := range []struct{ mode, kind string }{
		{gb28181test.ModeNoBody, gb28181.KindNoBody},
		{gb28181test.ModeBadXML, gb28181.KindBadBody},
	} {
		d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: tc.mode})
		c := dial(t, "127.0.0.1", d.Port())
		reply, err := ask(t, c, gb28181.MethodMessage, testDeviceID, "127.0.0.1", d.Port(),
			gb28181.CatalogQuery("3", testDeviceID, 0, 0), "Application/MANSCDP+xml")
		if err != nil {
			t.Fatalf("%s：它好歹回了 200：%v", tc.mode, err)
		}
		_, err = gb28181.BodyCmd(reply.Final)
		if gb28181.KindOf(err) != tc.kind {
			t.Errorf("%s：正文报成 %q（%v），要 %s", tc.mode, gb28181.KindOf(err), err, tc.kind)
		}
	}
}

// 中文名按非 UTF-8 发的那类老固件：编号与条数一个都不能丢，
// 只把「这个名字读不准」这件事本身报出来。
func Test中文名不是UTF8时其余字段一条不能丢(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{
		Mode: gb28181test.ModeGBK,
		Channels: []gb28181test.Channel{
			{DeviceID: testChannelID, Name: "东门", Status: "ON"},
			{DeviceID: "34020000001320000002", Name: "西门", Status: "ON"},
		},
	})
	c := dial(t, "127.0.0.1", d.Port())
	reply, err := ask(t, c, gb28181.MethodMessage, testDeviceID, "127.0.0.1", d.Port(),
		gb28181.CatalogQuery("4", testDeviceID, 0, 0), "Application/MANSCDP+xml")
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := gb28181.BodyCmd(reply.Final)
	if err != nil {
		t.Fatalf("非 UTF-8 就把整份正文判死，这台设备就成了「没有回包」：%v", err)
	}
	if !cmd.NonUTF8 {
		t.Error("没记下「这份正文不是 UTF-8」—— 现场要的是这句话，不是猜出来的名字")
	}
	if sum, ok := cmd.SumNum(); !ok || sum != 2 {
		t.Errorf("SumNum %v/%v，要 2/true", sum, ok)
	}
	if cmd.ItemCount() != 2 {
		t.Errorf("条目 %d，要 2", cmd.ItemCount())
	}
	ids, missing := cmd.ItemDeviceIDs()
	if len(ids) != 2 || ids[1] != "34020000001320000002" || missing != 0 {
		t.Errorf("编号读错：%v 缺 %d", ids, missing)
	}
}

func Test注册走digest一轮就认下(t *testing.T) {
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		Mode:  gb28181test.PlatformDigest,
		Realm: testRealm,
		Users: map[string]string{testDeviceID: testPassword},
	})
	c := dial(t, "127.0.0.1", p.Port())

	req := newRequest(t, c, gb28181.MethodRegister, testDeviceID, "127.0.0.1", p.Port(), nil, "")
	reply, err := c.Request(req, "register", 2*time.Second)
	if gb28181.KindOf(err) != gb28181.KindStatus || gb28181.StatusOf(err) != 401 {
		t.Fatalf("第一趟该拿到 401，实得 %v（kind=%q）", err, gb28181.KindOf(err))
	}
	// ★ 签名只能装进请求。对着 401 这条响应去签，Method 与 URI 都是空串，
	// HA2 算的就是 ":"，平台永远认不下 —— 界面上只表现为「口令明明对，它死活 401」。
	if ch0, cerr := gb28181.ChallengeFrom(reply.Final); cerr != nil {
		t.Fatal(cerr)
	} else if e := gb28181.AuthorizeRequest(reply.Final, ch0, testDeviceID, testPassword); gb28181.KindOf(e) != gb28181.KindLocal {
		t.Errorf("给响应签名没被拦住：%v", e)
	}
	ch, err := gb28181.ChallengeFrom(reply.Final)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Realm != testRealm {
		t.Errorf("realm 读成 %q，要 %q", ch.Realm, testRealm)
	}
	if q := ch.QOP; len(q) != 1 || q[0] != "auth" {
		t.Errorf("挑战里的 qop 读成 %v", q)
	}
	before := req.Get(gb28181.HVia) + "|" + req.CallID() + "|" + req.Get(gb28181.HCSeq)
	if err := gb28181.AuthorizeRequest(req, ch, testDeviceID, testPassword); err != nil {
		t.Fatalf("按挑战签名失败：%v", err)
	}
	// ★ 凭据不进报文：这条断言看着显然，坏在「顺手把 password 也塞进某个字段」
	// 一定会有人来加（调试方便），而结果是要发给 AI、也会打进诊断包的。
	if bytes.Contains(req.MustBytes(), []byte(testPassword)) {
		t.Fatal("发出去的报文里带着口令原文")
	}
	// 重发的是同一趟事务：Call-ID / CSeq / branch 都不许变。
	if got := req.Get(gb28181.HVia) + "|" + req.CallID() + "|" + req.Get(gb28181.HCSeq); got != before {
		t.Errorf("签名时把事务字段改动了：\n %q\n!=\n %q", got, before)
	}
	reply, err = c.Request(req, "register", 2*time.Second)
	if err != nil {
		t.Fatalf("签好名还是注册不上：%v", err)
	}
	if reply.Final.Status != 200 {
		t.Fatalf("注册回了 %d", reply.Final.Status)
	}
	if d, ok := reply.Final.Expires(); !ok || d != 3600 {
		t.Errorf("平台给的有效期读成 %v/%v，要 3600/true", d, ok)
	}
	regs := p.Registrations()
	if len(regs) != 1 {
		t.Fatalf("平台记到 %d 次注册，要 1", len(regs))
	}
	if !regs[0].AuthOK || regs[0].DeviceID != testDeviceID {
		t.Errorf("注册记成 %+v", regs[0])
	}
	if regs[0].Expires != 3600 {
		t.Errorf("平台看到的 Expires 是 %d", regs[0].Expires)
	}
	// Contact 必须是本机**实际用到**的那个口：写配置里那个，平台回包就发给没人听的地址。
	if regs[0].ContactHost != c.LocalHost() || regs[0].ContactPort != c.LocalPort() {
		t.Errorf("平台看到的 Contact 是 %s:%s，本机实际用的是 %s:%s",
			regs[0].ContactHost, regs[0].ContactPort, c.LocalHost(), c.LocalPort())
	}
}

func Test口令不对要停在401而不是被当成没答(t *testing.T) {
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		Mode:  gb28181test.PlatformDigest,
		Realm: testRealm,
		Users: map[string]string{testDeviceID: testPassword},
	})
	c := dial(t, "127.0.0.1", p.Port())
	req := newRequest(t, c, gb28181.MethodRegister, testDeviceID, "127.0.0.1", p.Port(), nil, "")
	reply, err := c.Request(req, "register", 2*time.Second)
	if gb28181.StatusOf(err) != 401 {
		t.Fatal(err)
	}
	ch, err := gb28181.ChallengeFrom(reply.Final)
	if err != nil {
		t.Fatal(err)
	}
	if err := gb28181.AuthorizeRequest(req, ch, testDeviceID, "wrong-horse"); err != nil {
		t.Fatal(err)
	}
	_, err = c.Request(req, "register", 2*time.Second)
	if gb28181.StatusOf(err) != 401 {
		t.Fatalf("错口令也注册上了？err=%v", err)
	}
	if n := len(p.Registrations()); n != 0 {
		t.Errorf("口令不对，平台那边却记下了 %d 次注册", n)
	}
}

func Test平台的三种不正常(t *testing.T) {
	t.Run("不认证就收", func(t *testing.T) {
		p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformOpen})
		c := dial(t, "127.0.0.1", p.Port())
		reply, err := ask(t, c, gb28181.MethodRegister, testDeviceID, "127.0.0.1", p.Port(), nil, "")
		if err != nil {
			t.Fatalf("裸放的平台该一次就过：%v", err)
		}
		if reply.Final.Status != 200 {
			t.Errorf("回了 %d，要 200", reply.Final.Status)
		}
		regs := p.Registrations()
		// ★ AuthOK 为假是这条判定的全部用处：「注册上了」与「注册上了因为它没查」
		// 在现场是两种整改方向，界面上必须分得开。
		if len(regs) != 1 || regs[0].AuthOK {
			t.Errorf("注册记成 %+v，要一条且 AuthOK 为假", regs)
		}
	})
	t.Run("编号不在它的清单里", func(t *testing.T) {
		p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformReject})
		c := dial(t, "127.0.0.1", p.Port())
		_, err := ask(t, c, gb28181.MethodRegister, testDeviceID, "127.0.0.1", p.Port(), nil, "")
		if gb28181.KindOf(err) != gb28181.KindStatus || gb28181.StatusOf(err) != 403 {
			t.Fatalf("报成 %q / %d（%v），要 status 403", gb28181.KindOf(err), gb28181.StatusOf(err), err)
		}
	})
	t.Run("回401却不带挑战", func(t *testing.T) {
		p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformNoChallenge})
		c := dial(t, "127.0.0.1", p.Port())
		reply, err := ask(t, c, gb28181.MethodRegister, testDeviceID, "127.0.0.1", p.Port(), nil, "")
		if gb28181.StatusOf(err) != 401 {
			t.Fatal(err)
		}
		_, cerr := gb28181.ChallengeFrom(reply.Final)
		if gb28181.KindOf(cerr) != gb28181.KindAuth {
			t.Fatalf("这一档要单独报成 auth（本机只能干等），实得 %v", cerr)
		}
		if !strings.Contains(cerr.Error(), "WWW-Authenticate") {
			t.Errorf("没说是缺哪一条头：%v", cerr)
		}
	})
	t.Run("平台那边静默", func(t *testing.T) {
		p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformSilent})
		c := dial(t, "127.0.0.1", p.Port())
		_, err := ask(t, c, gb28181.MethodRegister, testDeviceID, "127.0.0.1", p.Port(), nil, "")
		if gb28181.KindOf(err) != gb28181.KindTimeout {
			t.Fatalf("报成 %q（%v），要 timeout", gb28181.KindOf(err), err)
		}
	})
}

// 注册之后平台回头来问通道表 —— 现场「平台说设备在线、可通道是空的」就死在这一步。
func Test注册之后平台来问通道表本机要答得上来(t *testing.T) {
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		Mode:               gb28181test.PlatformDigest,
		Realm:              testRealm,
		Users:              map[string]string{testDeviceID: testPassword},
		QueryAfterRegister: true,
	})
	c := dial(t, "127.0.0.1", p.Port())
	if _, err := registerWithDigest(t, c, "127.0.0.1", p.Port()); err != nil {
		t.Fatalf("注册没走通，后面的通道表无从说起：%v", err)
	}
	var answered int
	got := c.WaitFor(4*time.Second, func(m *gb28181.Message) bool {
		if !m.IsRequest() || m.Method != gb28181.MethodMessage {
			return false
		}
		cmd, err := gb28181.BodyCmd(m)
		if err != nil {
			t.Errorf("平台发来的查询读不出来：%v", err)
			return false
		}
		if cmd.CmdType != "Catalog" {
			t.Errorf("平台来问的是 %q，这轮只等着 Catalog", cmd.CmdType)
			return false
		}
		if cmd.Root != "Query" {
			t.Errorf("根读成 %q，要 Query", cmd.Root)
		}
		body := gb28181.CatalogResponsePayload(cmd.Get("SN"), testDeviceID, 2, [][]gb28181.F{
			{{Name: "DeviceID", Value: testChannelID}, {Name: "Name", Value: "东门"}, {Name: "Status", Value: "ON"}},
			{{Name: "DeviceID", Value: "34020000001320000002"}, {Name: "Name", Value: "西门"}, {Name: "Status", Value: "OFF"}},
		})
		resp := gb28181.NewResponseFor(m, 200, "")
		resp.Body = body
		resp.Set(gb28181.HContentType, "Application/MANSCDP+xml")
		// ★ 连好的套接字只能写给对端，所以这里传 nil：来路就是那个对端。
		//	用 WriteToUDP 会被内核当场拒成 "use of WriteTo with pre-connected connection"。
		if err := c.Respond(resp, nil); err != nil {
			t.Errorf("答不动平台来问的这一句：%v", err)
			return false
		}
		answered++
		return true
	})
	if len(got) == 0 {
		t.Fatal("注册成功了，可平台来问通道表时本机什么都没收到 —— 前面那趟注册等于没验")
	}
	if answered != len(got) {
		t.Errorf("答了 %d 条，收到 %d 条，对不上", answered, len(got))
	}
	if n := waitFor(func() bool { return p.CatalogSeen() >= 0 }, 2*time.Second); !n {
		t.Fatal("平台一直没收到本机对通道表的应答（事务号或对端地址写错都会这样）")
	}
	if got := p.CatalogSeen(); got != 2 {
		t.Errorf("平台数到的通道 %d 条，要 2（本机答的正文没落到它那儿）", got)
	}
	if n := p.UnknownAnswers(); n != 0 {
		t.Errorf("有 %d 条应答对不上平台问过的任何一句 —— Call-ID 或 CSeq 写错了", n)
	}
}

// 平台肯发 INVITE 点播，才是「这台设备被当真认下了」的最硬证据；
// 而本机只读这段 SDP、绝不答应收流（本软件不放播放器、不解码）。
func Test点播来了要读得出它要哪个口哪一路流(t *testing.T) {
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		Mode:                gb28181test.PlatformDigest,
		Realm:               testRealm,
		Users:               map[string]string{testDeviceID: testPassword},
		InviteAfterRegister: true,
		InviteBody: gb28181test.InviteSDP(gb28181test.SDPOptions{
			SessionName: "Live",
			Address:     "224.5.0.1",
			TTL:         127,
			Port:        30002,
			SSRC:        "0100000000",
			ExtraY:      "0 0",
			URI:         testDeviceID + ":20260101T000000",
		}),
	})
	c := dial(t, "127.0.0.1", p.Port())
	if _, err := registerWithDigest(t, c, "127.0.0.1", p.Port()); err != nil {
		t.Fatalf("注册没走通：%v", err)
	}
	var (
		port      int
		multicast bool
		ttl       int
		ssrc      string
		dir       string
		uri       string
		sessionNm string
	)
	got := c.WaitFor(5*time.Second, func(m *gb28181.Message) bool {
		if !m.IsRequest() || m.Method != gb28181.MethodInvite {
			return false
		}
		s, err := gb28181.BodySDP(m)
		if err != nil {
			t.Errorf("INVITE 的正文读不出来：%v", err)
			return false
		}
		port, _ = s.MediaPort()
		if cn, ok := s.Connection(); ok {
			multicast = cn.Multicast()
			ttl = cn.TTL
		}
		ssrc, _ = s.SSRC()
		dir, _ = s.Direction()
		uri, _ = s.URI()
		sessionNm = s.SessionName
		// 本机不放播放器，所以回 486：它在、但这一路不收。
		resp := gb28181.NewResponseFor(m, 486, "")
		if err := c.Respond(resp, nil); err != nil {
			t.Errorf("回绝这条点播没回出去：%v", err)
		}
		return true
	})
	if len(got) == 0 {
		t.Fatal("一条 INVITE 都没收到（注册那趟是通的）—— 点播这一路等于没测")
	}
	if port != 30002 {
		t.Errorf("口读成 %d，要 30002", port)
	}
	if !multicast {
		t.Error("c= 是组播却没读出来 —— 「流发到组播组、本机没加组」这句话就说不出口")
	}
	if ttl != 127 {
		t.Errorf("组播 TTL 读成 %d，要 127", ttl)
	}
	if ssrc != "0100000000" {
		t.Errorf("SSRC 读成 %q，要 0100000000", ssrc)
	}
	if dir != "recvonly" {
		t.Errorf("方向读成 %q，要 recvonly（sendonly 的那条不是点播，别按点播解释）", dir)
	}
	if !strings.HasPrefix(uri, testDeviceID) {
		t.Errorf("u= 读成 %q", uri)
	}
	if sessionNm != "Live" {
		t.Errorf("s= 读成 %q", sessionNm)
	}
	if !waitFor(func() bool { return len(p.InviteAnswers()) > 0 }, 2*time.Second) {
		t.Fatal("设备回了 486，平台却没记到 —— 应答的 Call-ID 或 CSeq 不对")
	}
	if a := p.InviteAnswers(); len(a) != 1 || a[0] != 486 {
		t.Errorf("平台收到对点播的应答 %v，要 [486]（不答 / 486 / 603 在现场是三种病）", a)
	}
	if n := p.InviteSent(); n != 1 {
		t.Errorf("记了 %d 条 INVITE，重发不该另计", n)
	}
	if p.CatalogSeen() != -1 {
		t.Error("这轮没开 QueryAfterRegister，通道表那句不该有结果")
	}
}

// 本机当平台那一头：认证台与签名端虽然都是自家代码，但对不上就是
// 「设备死活注册不上」，而且现场只会看到 401 一个数。
func Test本机当平台时认证台收得下标准设备的签名(t *testing.T) {
	v := gb28181.NewVerifier(testRealm, time.Minute)
	ch := v.Challenge(time.Now())
	if ch.Realm != testRealm || ch.Nonce == "" {
		t.Fatalf("挑战没出对：%+v", ch)
	}
	req := &gb28181.Message{Method: gb28181.MethodRegister, URI: "sip:" + testRealm + "@127.0.0.1"}
	if err := gb28181.AuthorizeRequest(req, ch, testDeviceID, testPassword); err != nil {
		t.Fatal(err)
	}
	a, err := gb28181.ParseAuthorization(req.Get(gb28181.HAuthorization))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(a, req.Method, req.URI, testPassword, time.Now()); err != nil {
		t.Fatalf("自己出的挑战自己认不下：%v", err)
	}
	// 重复提交：nc 不往前走就要拦，否则同一条应答能被重放。
	if err := v.Verify(a, req.Method, req.URI, testPassword, time.Now()); !errors.Is(err, gb28181.ErrDigestReplay) {
		t.Errorf("重放没拦住：%v", err)
	}
	// 错口令要另起一轮挑战来验：nc 的账排在比对签名之前，拿同一条 nonce 再答一次
	// 会先撞上重放 —— 那是对的口径（重复提交绝不能报成口令错），但也就不像在验签名了。
	ch2 := v.Challenge(time.Now())
	req2 := &gb28181.Message{Method: gb28181.MethodRegister, URI: "sip:" + testRealm + "@127.0.0.1"}
	if err := gb28181.AuthorizeRequest(req2, ch2, testDeviceID, "口令写错了的那个"); err != nil {
		t.Fatal(err)
	}
	a2, err := gb28181.ParseAuthorization(req2.Get(gb28181.HAuthorization))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(a2, req2.Method, req2.URI, testPassword, time.Now()); !errors.Is(err, gb28181.ErrDigestBadResponse) {
		t.Errorf("错口令报成 %v，要 bad-response（现场这一档是「设备里的注册口令配错了」）", err)
	}
	otherRealm := *a
	otherRealm.Realm = "0000000000"
	if err := v.Verify(&otherRealm, req.Method, req.URI, testPassword, time.Now()); !errors.Is(err, gb28181.ErrDigestRealm) {
		t.Errorf("realm 不对报成 %v", err)
	}
	if err := v.Verify(a, req.Method, "sip:elsewhere@127.0.0.1", testPassword, time.Now()); !errors.Is(err, gb28181.ErrDigestURI) {
		t.Errorf("digestUri 不对报成 %v", err)
	}
	// 换一轮挑战之后再拿旧 nonce 来答：要报过期，不是「口令错」。
	fresh := v.Challenge(time.Now())
	stale := *a
	stale.Nonce = fresh.Nonce
	stale.Opaque = fresh.Opaque
	if err := v.Verify(&stale, req.Method, req.URI, testPassword, time.Now().Add(time.Hour)); !errors.Is(err, gb28181.ErrDigestStaleNonce) {
		t.Errorf("过期 nonce 报成 %v，要 stale", err)
	}
}

// Test本机当平台真的收下一条注册 走完套在 UDP 上的整条路：
// 未连的套接字收注册 → 出挑战 → 校验签名 → 回 200。
// ★ 服务端这一头刻意用 ListenUDP（谁都能打进来）而不是连好的套接字：
// 连好的那一头只收一对地址，那是探测端的取舍，不能反过来当服务端用。
func Test本机当平台真的收下一条注册(t *testing.T) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	port := l.LocalAddr().(*net.UDPAddr).Port

	c := dial(t, "127.0.0.1", port)
	v := gb28181.NewVerifier(testRealm, time.Minute)

	// 平台侧：两轮 —— 第一轮出 401 挑战，第二轮验签名。
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		var issued *gb28181.Challenge
		for round := 0; round < 2; round++ {
			_ = l.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, from, rerr := l.ReadFromUDP(buf)
			if rerr != nil {
				served <- fmt.Errorf("平台侧第 %d 轮没读到东西：%w", round+1, rerr)
				return
			}
			got, perr := gb28181.Parse(buf[:n])
			if perr != nil {
				served <- fmt.Errorf("平台侧读不懂这条报文：%w", perr)
				return
			}
			if got.Method != gb28181.MethodRegister {
				served <- fmt.Errorf("收到的不是注册：%q", got.Method)
				return
			}
			if got.Get(gb28181.HAuthorization) == "" {
				issued = v.Challenge(time.Now())
				resp := gb28181.NewResponseFor(got, 401, "")
				resp.Set(gb28181.HWWWAuthenticate, issued.Header())
				if _, werr := l.WriteToUDP(resp.MustBytes(), from); werr != nil {
					served <- fmt.Errorf("回 401 没发出去：%w", werr)
					return
				}
				continue
			}
			a, aerr := gb28181.ParseAuthorization(got.Get(gb28181.HAuthorization))
			if aerr != nil {
				served <- fmt.Errorf("设备带的应答读不出来：%w", aerr)
				return
			}
			if verr := v.Verify(a, got.Method, got.URI, testPassword, time.Now()); verr != nil {
				served <- fmt.Errorf("这条注册收不下：%w", verr)
				return
			}
			ok := gb28181.NewResponseFor(got, 200, "")
			ok.Set(gb28181.HExpires, "3600")
			if _, werr := l.WriteToUDP(ok.MustBytes(), from); werr != nil {
				served <- fmt.Errorf("回 200 没发出去：%w", werr)
				return
			}
			served <- nil
			return
		}
		served <- fmt.Errorf("两轮都没走到收签那一步")
	}()

	reply, err := registerWithDigest(t, c, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("本机当平台时，标准签名的注册没走通：%v", err)
	}
	if reply.Final.Status != 200 {
		t.Errorf("回了 %d，要 200", reply.Final.Status)
	}
	if d, ok := reply.Final.Expires(); !ok || d != 3600 {
		t.Errorf("有效期读成 %v/%v", d, ok)
	}
	if serr := <-served; serr != nil {
		t.Error(serr)
	}
}

func waitFor(cond func() bool, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// Test注册后平台从另一个口回话要如实报成没人答 把连好套接字那笔代价钉住：
// 界面上「timeout」的下一步必须包含「换个端口再问」。
func Test注册后平台从另一个口回话要如实报成没人答(t *testing.T) {
	// 一个假「从别的源地址回话」的平台：先用 A 口收，再用 B 口发。
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, from, rerr := a.ReadFromUDP(buf)
		if rerr != nil {
			return
		}
		got, perr := gb28181.Parse(buf[:n])
		if perr != nil {
			return
		}
		resp := gb28181.NewResponseFor(got, 200, "")
		resp.Set(gb28181.HAllow, "REGISTER, MESSAGE")
		// ★ 从另一个口发出去：连好的套接字会按内核的规则把这包丢掉。
		_, _ = b.WriteToUDP(resp.MustBytes(), from)
	}()

	c := dial(t, "127.0.0.1", a.LocalAddr().(*net.UDPAddr).Port)
	_, err = ask(t, c, gb28181.MethodOptions, testDeviceID, "127.0.0.1",
		a.LocalAddr().(*net.UDPAddr).Port, nil, "")
	<-done
	if gb28181.KindOf(err) != gb28181.KindTimeout {
		t.Fatalf("换了源端口回话报成了 %q（%v），要 timeout —— 这一档不能假装收得到", gb28181.KindOf(err), err)
	}
}
