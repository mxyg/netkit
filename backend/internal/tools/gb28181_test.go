package tools

// media.gb28181.probe / media.gb28181.register 的测试。
//
// ★ 口径：每一种假对端的模式（= 现场一种毛病）都必须落到一个自己的判定码，
//
//	而且下一句话得说清下一步去哪儿 —— 「没回应」这一句在现场值三天工。
//
// ★ 两头都在真的回环 UDP 上跑：这一层真正的错（起始行、Via 的 branch、
//
//	digest 的拼接顺序、正文的 Content-Length）只有真发真收才暴露得出来，
//	所以这里不 mock 底座，只用 gb28181test 那份「不认识探测端」的假对端。

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/gb28181"
	"net.yuhox.com/netkit/internal/gb28181/gb28181test"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

const (
	gbDev      = "34020000001110000001" // 假设备/假平台默认都认这一串
	gbChan     = "34020000001320000001"
	gbPlat     = "34020000002000000001"
	gbPass     = "correct-horse"
	gbRealm    = "3402000000"
	gbWrongPwd = "口令写错了的那一串"
)

// callGBProbe 走界面那条路：JSON 参数进、判定出。
func callGBProbe(t *testing.T, args map[string]any) (ots.Verdict, string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gbProbeTool.Invoke(t.Context(), raw)
	if err != nil {
		t.Fatalf("这一问本该出判定，却报了错：%s", err)
	}
	v, ok := got.(ots.Verdict)
	if !ok {
		t.Fatalf("回来的不是判定：%T", got)
	}
	blob, _ := json.Marshal(v)
	return v, string(blob)
}

func callGBRegister(t *testing.T, args map[string]any) (ots.Verdict, string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gbRegisterTool.Invoke(t.Context(), raw)
	if err != nil {
		t.Fatalf("这一趟本该出判定，却报了错：%s", err)
	}
	v, ok := got.(ots.Verdict)
	if !ok {
		t.Fatalf("回来的不是判定：%T", got)
	}
	blob, _ := json.Marshal(v)
	return v, string(blob)
}

func gbArgs(host string, port int, extra map[string]any) map[string]any {
	a := map[string]any{"host": host, "port": port, "deviceId": gbDev, "platformId": gbPlat}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

// gbQueries 把结果里那一叠「每问一招的账」过一遍 JSON 再读回来。
// ★ 不直接断言 map 里的类型：进结果集的通路是 JSON，类型在这里定生死。
func gbQueries(t *testing.T, v ots.Verdict) []gbAskResult {
	t.Helper()
	raw, err := json.Marshal(v.Values["queries"])
	if err != nil {
		t.Fatal(err)
	}
	var out []gbAskResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("queries 过不了 JSON：%v\n%s", err, raw)
	}
	return out
}

func gbAskOf(t *testing.T, v ots.Verdict, cmdType string) gbAskResult {
	t.Helper()
	for _, r := range gbQueries(t, v) {
		if r.CmdType == cmdType {
			return r
		}
	}
	t.Fatalf("账里没有 %s 这一问：%+v", cmdType, gbQueries(t, v))
	return gbAskResult{}
}

// gbJournal 换一个临时账本，并把「这一趟留没留下痕」交给调用方判。
func gbJournal(t *testing.T) *state.Journal {
	t.Helper()
	j, err := state.Open(t.TempDir() + "/journal.json")
	if err != nil {
		t.Fatal(err)
	}
	old := journal
	journal = j
	t.Cleanup(func() { journal = old })
	return j
}

// gbNum 读结果里的一格数。★ 工具直接返回时是 Go 的整数，经结果集过一遍 JSON 才是
// float64 —— 两种都认，断言才不会因为「从哪一头读」而假崩或假绿。
func gbNum(v ots.Verdict, key string) (int, bool) {
	switch n := v.Values[key].(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// gbWords 读结果里那一列字符串（Allow、平台来路那几格）。
func gbWords(v ots.Verdict, key string) []string {
	switch s := v.Values[key].(type) {
	case []string:
		return s
	case []any:
		var out []string
		for _, x := range s {
			if t, ok := x.(string); ok {
				out = append(out, t)
			}
		}
		return out
	}
	return nil
}

// ── 传输那一档：三种「没回应」必须分成三种下一步 ──

func Test探测问到关着的口与没人答的口分成两档(t *testing.T) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()

	v, blob := callGBProbe(t, map[string]any{"host": "127.0.0.1", "port": closed})
	wantCode(t, v, blob, verdictGBPortClosed)
	if !strings.Contains(v.Note, "开着没人答") {
		t.Errorf("关着的口这一档没把「和静默不是一回事」说出来：%s", v.Note)
	}

	silent := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeSilent})
	v2, blob2 := callGBProbe(t, map[string]any{"host": "127.0.0.1", "port": silent.Port()})
	wantCode(t, v2, blob2, verdictGBSilent)
	// ★ 重发过才敢说「一个字节都没回」：只发一条就下结论，丢一个包就冤枉一台设备。
	if got, ok := gbNum(v2, "optionsSent"); !ok || got < 2 {
		t.Errorf("静默这一档没证明重发过（optionsSent=%v）—— 没重发就没资格说「没人答」", v2.Values["optionsSent"])
	}
	if !strings.Contains(v2.Note, "另一个端口") {
		t.Errorf("超时这一档没写出第二种成因（它从别的口回话）：%s", v2.Note)
	}
}

func Test探测问到非SIP的口单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeNotSIP})
	v, blob := callGBProbe(t, map[string]any{"host": "127.0.0.1", "port": d.Port()})
	wantCode(t, v, blob, verdictGBNotSIP)
	if !strings.Contains(v.Note, "不是 SIP") {
		t.Errorf("这一档要说破「口上有东西、但跑的是别的服务」：%s", v.Note)
	}
}

// 「起始行是 SIP、这一条却读不成句」是另一种病：中间那台（SIP 网关、ALG）改了包，
// 或固件发的换行不对。★ 没有假设备供这一种，这个码就只存在于纸上 ——
// 而它与「不是 SIP」的下一步完全不同：一个去找中间那台，一个去核对口配错了服务。
func Test探测问到读不成句的SIP报文单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeBadSIP})
	v, blob := callGBProbe(t, map[string]any{"host": "127.0.0.1", "port": d.Port()})
	wantCode(t, v, blob, verdictGBUnreadable)
	if !strings.Contains(v.Note, "读不成句") {
		t.Errorf("这一档要说破「看着是 SIP 但这条报文读不下来」：%s", v.Note)
	}
	if !strings.Contains(v.Note, "ALG") {
		t.Errorf("这一档要给出去找中间那台的下一步（ALG/网关）：%s", v.Note)
	}
}

func Test探测问到忙碌的对端单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeBusy})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), nil))
	wantCode(t, v, blob, verdictGBBusy)
	if st, ok := gbNum(v, "status"); !ok || st != 503 {
		t.Errorf("忙这一档没把状态码留下（status=%v）—— 界面要靠它说话", v.Values["status"])
	}
}

// 同一个信令口回的状态码，下一步完全不同：403/404/405 都是「先核编号或核能力」，
// 480/486/500/503/504 都是「它在但这一刻腾不出手」。
// ★ 这几档没有假设备供着就只是纸上的码 —— 现场最常碰到的正是 405（不接 MESSAGE）与 404（编号不存在），
//
//	把它们并进「它不答」会让人去查防火墙，而真正要查的是那台上的名单。
func Test问到按状态码分档各自有码(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{403, verdictGBDenied},
		{404, verdictGBDenied},
		{405, verdictGBDenied},
		{501, verdictGBDenied},
		{480, verdictGBBusy},
		{486, verdictGBBusy},
		{500, verdictGBBusy},
		{504, verdictGBBusy},
	}
	for _, c := range cases {
		d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{MessageStatus: c.status})
		v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
		wantCode(t, v, blob, c.want)
		// ★ 状态码记在「这一问的账」上，不记在顶层：顶层那一格说的是 OPTIONS 答了什么，
		//   这一档里 OPTIONS 是答了 200 的 —— 挪到顶层就成了「它回的状态 403」这种冤账。
		var got int
		for _, q := range gbQueries(t, v) {
			if q.CmdType == gb28181.CmdCatalog {
				got = q.Status
			}
		}
		if got != c.status {
			t.Errorf("状态 %d 这一档没把码留在那一问的账上（读到 %d）—— 界面那一栏要靠它说话", c.status, got)
		}
		if !strings.Contains(v.Note, strconv.Itoa(c.status)) {
			t.Errorf("状态 %d 这一档得把码念出来，人才对得上抓包：%s", c.status, v.Note)
		}
	}
}

// OPTIONS 就被要凭据：这一档的下一步是走注册，与「去查防火墙」完全是两条路。
// ★ 没有这一条覆盖，auth-required 这个码只在纸上存在 —— 现场把它和「没回应」并成一档，
//
//	人就拿着「防火墙」的口径去查一台其实在收设备的平台。
func Test探测问到只认已注册对端的口单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeAuth})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
	wantCode(t, v, blob, verdictGBAuthRequired)
	if !strings.Contains(v.Note, "注册") {
		t.Errorf("这一档得把下一步指到注册那一条：%s", v.Note)
	}
	// ★ 它连 OPTIONS 都没让过，就不该有「某一问没答」那本账：那会把两句合成一句冤枉。
	if _, has := v.Values["queries"]; has {
		t.Errorf("OPTIONS 就被拒，却还记了逐问的账：%s", blob)
	}
	if got := d.Queries(); len(got) != 0 {
		t.Errorf("本机在没认证时发出了查询 %v —— 认证这一档应当止步于 OPTIONS", got)
	}
}

// ── 只问 OPTIONS ──

func Test只问到在就不能说它答得出查询(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{})
	v, blob := callGBProbe(t, map[string]any{"host": "127.0.0.1", "port": d.Port()})
	wantCode(t, v, blob, verdictGBAlive)
	if !strings.Contains(v.Note, "没问") {
		t.Errorf("「只问到它在」得说清哪几样没问：%s", v.Note)
	}
	allow := gbWords(v, "allow")
	if len(allow) == 0 {
		t.Fatalf("它报的 Allow 没进结果：%v", v.Values["allow"])
	}
	if _, has := v.Values["queries"]; has {
		t.Errorf("一问都没发却在结果里挂了 queries：%s", blob)
	}
	// ★ 假设备只收到 OPTIONS：一条注册、一条点播都没有。
	if got := d.Requests(); got != 1 {
		t.Errorf("探测一共打出 %d 条请求，本该只有 1 条 OPTIONS", got)
	}
}

func Test它不报能力时不许编一份能力清单(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{AllowList: []string{"REGISTER"}})
	v, blob := callGBProbe(t, map[string]any{"host": "127.0.0.1", "port": d.Port()})
	wantCode(t, v, blob, verdictGBAlive)
	if !strings.Contains(v.Note, "REGISTER") {
		t.Errorf("它只报了 REGISTER，这句话就得原样带上：%s", v.Note)
	}
}

// ── 三类查询：一类一个落点 ──

func Test三类查询都答了就把数到几条写清楚(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{
		Channels: []gb28181test.Channel{
			{DeviceID: gbChan, Name: "东门", Status: "ON"},
			{DeviceID: "34020000001320000002", Name: "西门", Status: "OFF"},
		},
	})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(),
		map[string]any{"ask": []string{"deviceInfo", "deviceStatus", "catalog"}}))
	wantCode(t, v, blob, verdictGBResponsive)

	info := gbAskOf(t, v, gb28181.CmdDeviceInfo)
	if info.Fields["manufacturer"] != "测试厂" {
		t.Errorf("设备自述的字段没读回来：%v", info.Fields)
	}
	if !info.Matches {
		t.Errorf("这一问的 CmdType/SN 与发出去的对不上，判定却说「问到内容了」：%s", blob)
	}
	cat := gbAskOf(t, v, gb28181.CmdCatalog)
	if gbItems(cat) != 2 {
		t.Errorf("通道数到 %d 条，本该 2 条", gbItems(cat))
	}
	if cat.SumNum == nil || *cat.SumNum != 2 {
		t.Errorf("它自己声明的路数没单独记账（sumNum=%v）—— 分页时这一格和数到的条数是两码事",
			cat.SumNum)
	}
	if len(cat.DeviceIDs) != 2 || cat.Missing != 0 {
		t.Errorf("通道编号没数全：%v（缺 %d）", cat.DeviceIDs, cat.Missing)
	}
	if !strings.Contains(v.Note, "2 路") {
		t.Errorf("判定那句话和账对不上：%s", v.Note)
	}
	// 三类各问一次：假设备收到的查询顺序就是发出去的顺序。
	got := strings.Join(d.Queries(), ",")
	if got != "DeviceInfo,DeviceStatus,Catalog" {
		t.Errorf("问出去的顺序/内容不对：%s", got)
	}
}

func Test它接了通道表却不答内容单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeNoCatalog})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
	wantCode(t, v, blob, verdictGBQuerySilent)
	// ★ 这一档最要紧的一句话：OPTIONS 答了，所以不是网络不通。
	if !strings.Contains(v.Note, "不是网络不通") {
		t.Errorf("「只有这一问没答」得说清网络是通的：%s", v.Note)
	}
	if got := gbAskOf(t, v, gb28181.CmdCatalog).Sent; got < 2 {
		t.Errorf("这一问发了 %d 次就下结论，本该重发过", got)
	}
}

func Test它回了200但正文是空的单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeNoBody})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"deviceInfo"}}))
	wantCode(t, v, blob, verdictGBEmptyBody)
	if !strings.Contains(v.Note, "注册") {
		t.Errorf("空正文这一档的下一步是给出口令走注册，那句话得说出来：%s", v.Note)
	}
}

func Test正文读不成MANSCDP单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeBadXML})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
	wantCode(t, v, blob, verdictGBBadBody)
	if !strings.Contains(v.Note, "读不成") {
		t.Errorf("这一档要说破「它答了，是那一份正文坏掉」：%s", v.Note)
	}
}

func Test答得清楚而通道是空的单独一档(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{
		Channels: []gb28181test.Channel{},
	})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
	wantCode(t, v, blob, verdictGBCatalogEmpty)
	if !strings.Contains(v.Note, "在线") {
		t.Errorf("这一档得接上现场那句话（平台说在线、通道是空的）：%s", v.Note)
	}
	// 它自己声明 0 路：这一格要如实写「声明 0 路」，不能和「没声明」并成一档。
	cat := gbAskOf(t, v, gb28181.CmdCatalog)
	if cat.SumNum == nil || *cat.SumNum != 0 {
		t.Errorf("SumNum 的账不对：声明 %v", cat.SumNum)
	}
	// ★ 0 是一个事实，不是一个「没说」。这两个数在过 JSON 之前确实存在，
	//   缺省掉一项就会在屏幕上落成「它自己声明 条」——判定说 0、账上是空的。
	if !strings.Contains(blob, `"items":0`) || !strings.Contains(blob, `"sumNum":0`) {
		t.Errorf("数到 0 条 / 声明 0 条没过 JSON 传到界面上：%s", blob)
	}
	if gbItems(cat) != 0 {
		t.Errorf("条数没按 0 记账：%v", cat.Items)
	}
}

func Test按GBK发的中文名说明是设备的编码不是工具坏了(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{
		Mode:     gb28181test.ModeGBK,
		Channels: []gb28181test.Channel{{DeviceID: gbChan, Name: "东门枪机", Status: "ON"}},
	})
	v, blob := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
	wantCode(t, v, blob, verdictGBResponsive)
	if !gbAskOf(t, v, gb28181.CmdCatalog).NonUTF8 {
		t.Fatalf("按 GBK 发的正文没被标成非 UTF-8：%s", blob)
	}
	if !strings.Contains(v.Note, "设备发的编码") {
		t.Errorf("乱码这一格不解释，人就会以为是工具坏了：%s", v.Note)
	}
}

func Test问到平台那一头也只问不动手(t *testing.T) {
	// ★ 反证：探测对着一个「会收注册、会发点播」的平台跑，跑完它一条注册都没收到。
	//	这一条守的是 probe 归 read 的整个前提 —— 点播会真占一路码流，那是改动。
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		Mode:                gb28181test.PlatformOpen,
		QueryAfterRegister:  true,
		InviteAfterRegister: true,
	})
	v, _ := callGBProbe(t, gbArgs("127.0.0.1", p.Port(), map[string]any{"ask": []string{"deviceInfo"}}))
	wantCode(t, v, "", verdictGBEmptyBody) // 这台平台对 MESSAGE 只回 200、不带正文
	if n := len(p.Registrations()); n != 0 {
		t.Errorf("探测往平台上打出了 %d 条注册 —— 那是改动，probe 一个字都不该注册", n)
	}
	if n := p.InviteSent(); n != 0 {
		t.Errorf("探测发出了 %d 条点播，占住了别人一路码流", n)
	}
}

// ── 参数与口径 ──

func Test参数不对就挡在门外并说清缺哪一样(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"没地址", map[string]any{}, "host"},
		{"要查询却没给平台编号", map[string]any{
			"host": "127.0.0.1", "deviceId": gbDev, "ask": []string{"catalog"}}, "platformId"},
		{"编号位数不对", map[string]any{"host": "127.0.0.1", "deviceId": "340200"}, "位"},
		{"问法不在清单里", map[string]any{"host": "127.0.0.1", "deviceId": gbDev,
			"platformId": gbPlat, "ask": []string{"recording"}}, "deviceInfo"},
		{"预算短到排不下一趟重发", map[string]any{"host": "127.0.0.1", "timeoutMs": 100}, "500"},
	}
	for _, tc := range cases {
		raw, _ := json.Marshal(tc.args)
		_, err := gbProbeTool.Invoke(t.Context(), raw)
		if err == nil {
			t.Errorf("%s 居然放行了", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s 的报错没指到 %q：%s", tc.name, tc.want, err)
		}
	}
}

func Test大小写不同的键按同一个参数认而不是当成没填(t *testing.T) {
	// Go 的 JSON 绑定对键名大小写不敏感：deviceID 会认进 deviceId。
	// ★ 这一条要钉住的是「认进来了就照它跑」——最怕的是键名对不上却被当成没填，
	//   于是拿一套半的参数跑出去，界面上看着像设备不对。
	raw := json.RawMessage(`{"host":"127.0.0.1","deviceID":"` + gbDev +
		`","platformId":"` + gbPlat + `"}`)
	got, err := gbProbeTool.Invoke(t.Context(), raw)
	if err != nil {
		t.Fatalf("这种写法本该认下来，却报错了：%s", err)
	}
	v := got.(ots.Verdict)
	if s, _ := v.Values["device"].(string); s != gbDev {
		t.Errorf("deviceID 没认进 deviceId（device=%v），半套参数就这么跑出去了", v.Values["device"])
	}
}

func Test预算太短时不许下没人答的结论(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeSilent})
	for _, ms := range []int{499, 60001, -1} {
		raw, _ := json.Marshal(map[string]any{"host": "127.0.0.1", "port": d.Port(), "timeoutMs": ms})
		if _, err := gbProbeTool.Invoke(t.Context(), raw); err == nil {
			t.Errorf("timeoutMs=%d 还放行 —— 那种预算里连一次重发都排不下，报出来的「没人答」是我们自己造的", ms)
		}
	}
}

// ── 注册：一条模式一个判定 ──

func Test注册走通一轮并且问完就注销(t *testing.T) {
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev,
		"password": gbPass, "watchMs": 200,
	})
	wantCode(t, v, blob, verdictGBRegistered)
	// ★ registered 是界面上「它回头问了吗 / 收回来没有」两栏的开关：注册没成的那一趟
	//   不许有它，否则屏幕上会凭空冒出一条压根没发生的改动。
	if reg, _ := v.Values["registered"].(bool); !reg {
		t.Errorf("注册上了却没记 registered：%s", blob)
	}
	if authenticated, _ := v.Values["authenticated"].(bool); !authenticated {
		t.Errorf("这一趟明明走了挑战与摘要，结果里却写成没收凭据：%s", blob)
	}
	if v.Values["realm"] != gbRealm {
		t.Errorf("它给的 realm 没记下来（realm=%v）—— 「配的 realm 与平台给的不是一个」全靠这一格", v.Values["realm"])
	}
	regs := p.Registrations()
	if len(regs) != 2 {
		t.Fatalf("平台上该有两条注册记录（注册 + 注销），实得 %d：%+v", len(regs), regs)
	}
	if !regs[0].AuthOK {
		t.Errorf("第一条注册在平台那边没过认证：%+v", regs[0])
	}
	if regs[1].Expires != 0 {
		t.Errorf("第二条不是注销（Expires=%d）—— 问完不留改动是这条工具的前提", regs[1].Expires)
	}
	if v.Values["deregistered"] != true {
		t.Errorf("结果里没记注销成没成：%s", blob)
	}
	if !strings.Contains(v.Note, "注销") {
		t.Errorf("判定那句话要说到注销：%s", v.Note)
	}
	// 它应允的时长与我们要的是两码事，必须读回来单列一格。
	if got, ok := gbNum(v, "expiresAccepted"); !ok || got != 3600 {
		t.Errorf("平台应允的注册时长没读回来（expiresAccepted=%v）—— 「每隔一分钟重注册」这类毛病就藏在这一格",
			v.Values["expiresAccepted"])
	}
}

func Test注册上了而平台回头问通道表是另一档(t *testing.T) {
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{QueryAfterRegister: true})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass, "watchMs": 1500,
	})
	wantCode(t, v, blob, verdictGBRegisteredAccepted)
	if !strings.Contains(v.Note, "Catalog") {
		t.Errorf("它回头问的就是通道表，这句话得说出口：%s", v.Note)
	}
	// ★ 我们不应答：编一路通道去答平台，等于凭空气下了一台设备。
	//   -1 就是「这台平台问了，却一个字的应答都没收到」——正好是我们要的样子。
	if n := p.CatalogSeen(); n != -1 {
		t.Errorf("本机替它编了 %d 条通道去应答 —— 这台不做真设备", n)
	}
	if n := p.UnknownAnswers(); n != 0 {
		t.Errorf("本机发出去 %d 条对不上号的应答", n)
	}
	if !strings.Contains(v.Note, "没答") {
		t.Errorf("它那几问没答，这句话不能让界面自己猜：%s", v.Note)
	}
}

func Test平台发来点播时只记证据不应答(t *testing.T) {
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		InviteAfterRegister: true,
		InviteBody: gb28181test.InviteSDP(gb28181test.SDPOptions{
			Address: "127.0.0.1", Port: 30000, SSRC: "0000000001",
		}),
	})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass, "watchMs": 1500,
	})
	wantCode(t, v, blob, verdictGBRegisteredAccepted)
	if invite, _ := v.Values["platformInvite"].(bool); !invite {
		t.Fatalf("它发来了点播，结果里却没这条最硬的证据：%s", blob)
	}
	if sdp, _ := v.Values["inviteSDP"].(string); !strings.Contains(sdp, "30000") {
		t.Errorf("点播正文里的媒体口没读回来（inviteSDP=%v）", v.Values["inviteSDP"])
	}
	if got := p.InviteAnswers(); len(got) != 0 {
		t.Errorf("本机对点播回了 %v —— 应答点播就是接下这一路流，那是改动", got)
	}
}

func Test注册到不收凭据的平台要说破是安全事实(t *testing.T) {
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformOpen})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass, "watchMs": 200,
	})
	wantCode(t, v, blob, verdictGBRegisteredNoAuth)
	if authenticated, _ := v.Values["authenticated"].(bool); authenticated {
		t.Errorf("它一个字都没查，结果却写成走了认证：%s", blob)
	}
	if !strings.Contains(v.Note, "没收口令") {
		t.Errorf("这一档的意思就是「这道门没收口令」：%s", v.Note)
	}
	// 没走过认证，注销那一发也就不带凭据 —— 但仍然必须发。
	regs := p.Registrations()
	if len(regs) == 0 || regs[len(regs)-1].Expires != 0 {
		t.Errorf("裸放平台上没做注销：%+v", regs)
	}
}

func Test编号不被认与口令不对分成两档(t *testing.T) {
	gbJournal(t)
	reject := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformReject})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": reject.Port(), "deviceId": gbDev, "password": gbPass,
	})
	wantCode(t, v, blob, verdictGBDenied)
	if !strings.Contains(v.Note, "清单") {
		t.Errorf("403 这一档的下一步是核授权名单，那句话得写出来：%s", v.Note)
	}
	// ★ 没注册上就不该有「这条注册会留在平台上」那两栏的料：界面拿 registered 开闸，
	//   这里留了 true，屏幕上就会凭空多出一条不存在的改动。
	if v.Values["registered"] != nil {
		t.Errorf("它回了 403，账上却记了注册成功：%s", blob)
	}
	if _, ok := v.Values["deregistered"]; ok {
		t.Errorf("没注册上却记了注销这一格（界面会跟着问「收回来了没」）：%s", blob)
	}

	// 编号在它清单里、口令填错了：这一档的下一步是去改口令，不是去查网络。
	bad := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{})
	v2, blob2 := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": bad.Port(), "deviceId": gbDev, "password": gbWrongPwd,
	})
	wantCode(t, v2, blob2, verdictGBCredentialRejected)
	if strings.Contains(blob2, gbWrongPwd) {
		t.Errorf("填错的口令被原样带进结果里了：%s", blob2)
	}
}

func Test回401却不带挑战是设备侧只能干等的一档(t *testing.T) {
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformNoChallenge})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass,
	})
	wantCode(t, v, blob, verdictGBChallengeMissing)
	if !strings.Contains(v.Note, "重复注册") {
		t.Errorf("这一档在现场的表现就是「一直重复注册」，得说出口：%s", v.Note)
	}
}

func Test注册时传输三档与探测同一个码(t *testing.T) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	gbJournal(t)
	cases := []struct {
		port int
		want string
	}{
		{closed, verdictGBPortClosed},
		{gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformSilent}).Port(), verdictGBSilent},
		{gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformNotSIP}).Port(), verdictGBNotSIP},
	}
	for _, tc := range cases {
		v, blob := callGBRegister(t, map[string]any{
			"host": "127.0.0.1", "port": tc.port, "deviceId": gbDev, "password": gbPass, "timeoutMs": 600,
		})
		wantCode(t, v, blob, tc.want)
	}
}

// ── 凭据与账本 ──

func Test口令不进结果不进账本也不进批准框(t *testing.T) {
	j := gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{})
	args := map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass, "watchMs": 200,
	}
	raw, _ := json.Marshal(args)
	if _, err := gbRegisterTool.Invoke(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
	// 批准框那句话
	if d := describeGB28181Register(raw); strings.Contains(d, gbPass) {
		t.Errorf("批准框里印出了口令：%s", d)
	} else if !strings.Contains(d, "口令") {
		t.Errorf("批准框该说「带口令（内容不记录）」，让人知道这一趟用了它：%s", d)
	}
	// 账本
	blob, err := json.Marshal(j.All())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), gbPass) {
		t.Errorf("口令进了改动账本：%s", blob)
	}
	// 结果
	v, vb := callGBRegister(t, args)
	if strings.Contains(vb, gbPass) {
		t.Errorf("口令进了结果：%s", vb)
	}
	// ★ 连「走了认证」这件事都不能靠口令本身说话
	if v.Code != verdictGBRegistered && v.Code != verdictGBRegisteredAccepted {
		t.Errorf("同一份参数第二次跑落到了 %s（%s）", v.Code, v.Note)
	}
}

func Test没给口令也照实走一趟(t *testing.T) {
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{
		Users: map[string]string{gbDev: ""}, // 真有一类平台收空口令
	})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "watchMs": 200,
	})
	wantCode(t, v, blob, verdictGBRegistered)
	if has, _ := v.Values["hasPassword"].(bool); has {
		t.Errorf("没填口令却记成带了口令：%s", blob)
	}
}

func Test没有账本就不往平台上注册(t *testing.T) {
	old := journal
	journal = nil
	t.Cleanup(func() { journal = old })
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformOpen})
	_, err := gbRegisterTool.Invoke(t.Context(), json.RawMessage(`{"host":"127.0.0.1","port":`+
		strconv.Itoa(p.Port())+`,"deviceId":"`+gbDev+`"}`))
	if err == nil || !strings.Contains(err.Error(), "账本") {
		t.Fatalf("没有账本时该拒绝动手：%v", err)
	}
	if n := len(p.Registrations()); n != 0 {
		t.Errorf("拒绝动手却还是往平台上注册了 %d 条", n)
	}
}

func Test注册这一趟要在账上留下痕(t *testing.T) {
	j := gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{})
	callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass, "watchMs": 200,
	})
	entries := j.All()
	if len(entries) != 1 {
		t.Fatalf("账上该一条记录，实得 %d", len(entries))
	}
	if entries[0].Status != state.StatusReverted {
		t.Errorf("改动状态 = %v，本该已还原（注销发过了）", entries[0].Status)
	}
	if !strings.Contains(entries[0].What, "国标注册") {
		t.Errorf("账上那句没说清这是往平台上挂一台设备：%s", entries[0].What)
	}
}

func Test注册没成时把账划掉而不是挂着(t *testing.T) {
	j := gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{Mode: gb28181test.PlatformReject})
	callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass,
	})
	entries := j.All()
	if len(entries) != 1 {
		t.Fatalf("账上该一条，实得 %d", len(entries))
	}
	if entries[0].Status != state.StatusReverted {
		t.Errorf("没成的改动该划掉，别让它下次启动时被当成「还在生效」：%v", entries[0].Status)
	}
}

func Test注销那一发也要走认证(t *testing.T) {
	// ★ 反证：这台平台管 nc —— 注销带着旧摘要会被拒一次，得拿它给的新单子重签再发。
	//	只做一发就报「注销没成」的话，那台平台上会挂一条本机收不回来的假在线设备，
	//	而现场的表现是「查完这台相机怎么掉线了」。
	gbJournal(t)
	p := gb28181test.StartPlatform(t, gb28181test.PlatformOptions{})
	v, blob := callGBRegister(t, map[string]any{
		"host": "127.0.0.1", "port": p.Port(), "deviceId": gbDev, "password": gbPass, "watchMs": 200,
	})
	wantCode(t, v, blob, verdictGBRegistered)
	if tries, ok := gbNum(v, "deregisterTries"); !ok || tries < 1 {
		t.Errorf("注销那一发的次数没记账：%v", v.Values["deregisterTries"])
	}
	regs := p.Registrations()
	last := regs[len(regs)-1]
	if last.Expires != 0 || !last.AuthOK {
		t.Errorf("平台上最后一条不是「过了认证的注销」：%+v", regs)
	}
}

// ── 判定与账同源 ──

func Test每一条判定里的数字都从账上来(t *testing.T) {
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{
		Channels: []gb28181test.Channel{
			{DeviceID: gbChan, Name: "东门"},
			{DeviceID: "", Name: "没编号的那条"},
		},
	})
	v, _ := callGBProbe(t, gbArgs("127.0.0.1", d.Port(), map[string]any{"ask": []string{"catalog"}}))
	cat := gbAskOf(t, v, gb28181.CmdCatalog)
	if cat.Missing != 1 {
		t.Errorf("有条条目没带编号却没数出来（missing=%d）", cat.Missing)
	}
	if !strings.Contains(v.Note, "没带编号") {
		t.Errorf("判定那句话没把这一格带上：%s", v.Note)
	}
}

func Test取消时问到哪儿就报哪儿(t *testing.T) {
	// 假设备只答自述，通道表那句不答：把预算卡在刚好够问完第一样的地方，
	// 第二问是被**我们自己的到点**掐断的 —— 报成「它不答这一问」就是一句冤枉。
	d := gb28181test.StartDevice(t, gb28181test.DeviceOptions{Mode: gb28181test.ModeNoCatalog})
	ctx, cancel := context.WithTimeout(t.Context(), 1200*time.Millisecond)
	defer cancel()
	raw, _ := json.Marshal(gbArgs("127.0.0.1", d.Port(),
		map[string]any{"ask": []string{"deviceInfo", "catalog"}, "timeoutMs": 5000}))
	got, err := gbProbeTool.Invoke(ctx, raw)
	if err != nil {
		t.Fatalf("到点该出「问到哪儿算哪儿」的判定，不该报错：%v", err)
	}
	v := got.(ots.Verdict)
	wantCode(t, v, "", verdictGBCutShort)
	if !strings.Contains(v.Note, "不是它不答") {
		t.Errorf("这一档必须说破「是我们没等够」：%s", v.Note)
	}
	if !strings.Contains(v.Note, "设备自述") {
		t.Errorf("问到哪儿了要说得出那一样问成了（前面那问的账没用到）：%s", v.Note)
	}
	cat := gbAskOf(t, v, gb28181.CmdCatalog)
	if cat.Kind != gbAskCut {
		t.Errorf("账里那一问记成了 %q，本该单列成被掐断", cat.Kind)
	}
	if info := gbAskOf(t, v, gb28181.CmdDeviceInfo); info.Kind != gbAskOK {
		t.Errorf("前面问成的那一问在账里丢了（kind=%q）", info.Kind)
	}
}
