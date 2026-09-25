package tools

// net.troubleshoot 的测试。★ 这一张卡的测试和别的工具不一样：
// 别的工具验「给定输入出对判定」，这里验的是**走法** ——
// 每一条分支停在哪儿、剩下的步骤是不是被记成「没去问」而不是「没问题」、
// 凭据有没有漏进结果。这些都不该只能靠把真网络搞坏来验，所以树里问的每一步都可以换成假的。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

// fakeCall 记下一个假工具被问过几次、各自收到过什么参数。
//
// ★ 「问过几次」在这张卡的测试里就是一半的结论：停在网关那一步时，
//
//	后面的 DNS 一次都不该发出去 —— 那条 DNS 的慢是链路的，会算错账。
type fakeCall struct {
	calls int
	args  []map[string]any
}

// fakeTools 把 treeCalls 换成一批按脚本回判定的假工具。
//
// codes：每个工具依次要回的判定码（用完最后一条就一直回最后一条）；
// vals：给它额外要带的取值。
func fakeTools(t *testing.T, codes map[string][]string, vals map[string]map[string]any) map[string]*fakeCall {
	t.Helper()
	// ★ 先备份再还原：treeCalls 是包级变量，装成假的之后别的测试就跑真工具了。
	old := treeCalls
	t.Cleanup(func() { treeCalls = old })
	treeCalls = map[string]treeCall{}
	tracker := map[string]*fakeCall{}
	for name, seq := range codes {
		n, seq := name, seq
		f := &fakeCall{}
		tracker[n] = f
		treeCalls[n] = func(ctx context.Context, raw json.RawMessage) (any, error) {
			var m map[string]any
			if len(raw) > 0 {
				_ = json.Unmarshal(raw, &m)
			}
			i := f.calls
			if i >= len(seq) {
				i = len(seq) - 1
			}
			f.calls++
			f.args = append(f.args, m)
			v := map[string]any{}
			for k, x := range vals[n] {
				v[k] = x
			}
			return ots.Verdict{Code: seq[i], Values: v}, nil
		}
	}
	return tracker
}

// fake 直接拿一个现成的结果当回答（要验报错、超时、形状不对时用）。
func fake(res any, err error) treeCall {
	return func(context.Context, json.RawMessage) (any, error) { return res, err }
}

func runTree(t *testing.T, args treeArgs) ots.Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	res, err := doTroubleshoot(context.Background(), raw)
	if err != nil {
		t.Fatalf("工具报错：%v", err)
	}
	v, ok := res.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", res)
	}
	return v
}

func stepsList(t *testing.T, v ots.Verdict) []*treeStepOut {
	t.Helper()
	b, err := json.Marshal(v.Values["steps"])
	if err != nil {
		t.Fatal(err)
	}
	var out []*treeStepOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func stepsOf(t *testing.T, v ots.Verdict) map[string]*treeStepOut {
	t.Helper()
	m := map[string]*treeStepOut{}
	for _, s := range stepsList(t, v) {
		if _, dup := m[s.Step]; dup {
			t.Errorf("步骤 %s 在路径里出现了两次", s.Step)
		}
		m[s.Step] = s
	}
	return m
}

// wantStatus 检查一步的状态。★ 每一步都必须有状态，空着一律算失败。
func wantStatus(t *testing.T, st map[string]*treeStepOut, id, status string) {
	t.Helper()
	s, ok := st[id]
	if !ok {
		t.Errorf("路径里没有 %s 这一步", id)
		return
	}
	if s.Status == "" {
		t.Errorf("%s 没有状态 —— 空栏会被读成「问了，没问题」", id)
		return
	}
	if s.Status != status {
		t.Errorf("%s 状态 = %s，想要 %s", id, s.Status, status)
	}
}

// answers 造一份「解析到了这些地址」的取值。
func answers(addrs ...string) map[string]any {
	out := make([]any, 0, len(addrs))
	for _, a := range addrs {
		typ := "A"
		if strings.Contains(a, ":") {
			typ = "AAAA"
		}
		out = append(out, map[string]any{"value": a, "type": typ})
	}
	return map[string]any{"answers": out, "server": "192.0.2.53", "elapsedMs": 12}
}

// hostFound 造一份「二层问到它、它是这么被问到的」的取值。
//
//	★ 清单里必须带上扫的是哪一段：树要看的是「人点的那一台在不在清单里」，
//	而「这段扫没扫到它」只有连着段一起给才读得出来 —— 少了段这一栏，
//	空清单既可能是「它不在」，也可能是「我们压根没问到那段」。
func hostFound(addr, evidence string) map[string]any {
	return map[string]any{"hosts": []any{map[string]any{
		"addr": addr, "evidence": evidence, "mac": "aa:bb:cc:dd:ee:ff"}},
		"subnets": []any{windowOf(addr)}, "alive": 1, "asked": 254}
}

// netWindowEmpty 造一份「这段扫过了、清单里没有它」的取值 —— 那才是「二层没有它」的证据。
func netWindowEmpty(addr string) map[string]any {
	return map[string]any{"hosts": []any{}, "subnets": []any{windowOf(addr)},
		"alive": 0, "asked": 254}
}

// windowOf 这个地址所在的那一段（测试里够用就行：真的段从路由那一步来）。
func windowOf(addr string) string {
	i := strings.LastIndex(addr, ".")
	if i < 0 {
		return addr + "/24"
	}
	return addr[:i] + ".0/24"
}

// everythingOK 是一批「什么都答得好」的假工具：单独验一条分支时别的步骤别来添乱。
// ★ 每个工具取它自己那份「正常」判定。
func everythingOK() map[string][]string {
	return map[string][]string{
		"net.checkup":         {topAllGood},
		"net.routes":          {verdictRouteFound},
		"net.ping.watch":      {watchStable},
		"net.dns.query":       {dnsResolved},
		"net.dualstack.check": {dsDualHealthy},
		"net.trace":           {traceReached},
		"net.mtr":             {qualityOK},
		"net.ping":            {verdictReachable},
		"net.tcp.probe":       {verdictOpen},
		"net.ports.scan":      {scanSomeOpen},
		"net.subnet.scan":     {scanNetFound},
		"net.tls.check":       {certOK},
		"net.http.probe":      {httpOK},
		"net.time.check":      {timeOK},
		"net.mtu.path":        {mtuCodeLocal},
		"media.rtsp.probe":    {verdictStreamOK},
		"media.onvif.info":    {verdictONVIFOK},
	}
}

// ── 出不了外网 ──

func TestTreeNoInternetStopsAtGateway(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topBrokenGateway}
	codes["net.ping.watch"] = []string{watchLoss}
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.checkup":    {"first": stepGateway},
		"net.routes":     {"count": 8, "defaults": []any{map[string]any{"family": "ipv4", "gateway": "192.0.2.1", "iface": "en0"}}},
		"net.ping.watch": {"lossPercent": 33, "sent": 6, "recv": 4, "jitterAvgMs": 4.2},
	})
	v := runTree(t, treeArgs{Symptom: symNoInternet})

	if v.Code != "cause-gateway-loss" {
		t.Fatalf("顶层 = %s，想要 cause-gateway-loss", v.Code)
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "checkup", treeAsked)
	wantStatus(t, st, "route-list", treeAsked)
	wantStatus(t, st, "gw-watch", treeAsked)
	// ★ 停在网关那一步了：后面的 DNS / 双栈 / 追踪必须是 skipped，
	//	而且要写明停在哪儿 —— 人要看的是「你们本来还打算问什么」。
	//	写的是那一步的人话名字，不是内部 id（id 进不了人话）。
	gateName := st["gw-watch"].StepName
	if gateName == "" {
		t.Fatal("那一步没给人话名字 —— skipped 的注会露出内部 id")
	}
	for _, id := range []string{"dns", "dualstack", "trace", "clock"} {
		wantStatus(t, st, id, treeSkipped)
		if !strings.Contains(st[id].Note, gateName) {
			t.Errorf("%s 的 skipped 没写明停在哪一步：%q", id, st[id].Note)
		}
	}
	if st["gw-watch"].Facts["lossPercent"] == nil {
		t.Error("停在网关那一步却没把丢包率带进结果 —— 人只看到「丢包」，不知道丢多少")
	}
	if v.Values["causeStep"] != "gw-watch" {
		t.Errorf("causeStep = %v，想要 gw-watch", v.Values["causeStep"])
	}
	if tracker["net.dns.query"].calls != 0 {
		t.Error("停在网关了还去问 DNS")
	}
}

// ★★ 「没问的不许读成问过」那条纪律的直接测试：缺信息问不成的那一步，
//
//	绝不能定根因，只能往前走，并且留下「缺什么」。
func TestTreeUnaskableStepNeverGivesCause(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topDegraded}
	codes["net.dns.query"] = []string{dnsTimeout}
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.checkup": {"first": stepGateway},
		// 路由表列出来了，但一条默认路由都没在里面 → 网关地址拿不到。
		"net.routes": {"count": 3},
	})
	v := runTree(t, treeArgs{Symptom: symNoInternet})

	st := stepsOf(t, v)
	wantStatus(t, st, "gw-watch", treeNotAsked)
	if !strings.Contains(st["gw-watch"].Note, "gateway") {
		t.Errorf("not-asked 没写明缺哪一条事实：%q", st["gw-watch"].Note)
	}
	if tracker["net.ping.watch"].calls != 0 {
		t.Errorf("没有网关地址还发了 %d 次持续探测", tracker["net.ping.watch"].calls)
	}
	// 跳过问不成的那一步，往后照样问得出 DNS，并且停在那儿。
	if v.Code != "cause-dns-server-dead" {
		t.Fatalf("顶层 = %s，想要 cause-dns-server-dead", v.Code)
	}
	wantStatus(t, st, "dns", treeAsked)
}

func TestTreeGatewaySilentIsItsOwnAnswer(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topDegraded}
	codes["net.ping.watch"] = []string{watchNoReply}
	fakeTools(t, codes, map[string]map[string]any{
		"net.checkup": {"first": stepGateway},
		"net.routes":  {"count": 5, "defaults": []any{map[string]any{"family": "ipv4", "gateway": "192.0.2.1", "iface": "en0"}}},
	})
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	if v.Code != "cause-gateway-silent" {
		t.Fatalf("顶层 = %s，想要 cause-gateway-silent", v.Code)
	}
	st := stepsOf(t, v)
	// ★ 「一个不吭」和「它自己拦 ICMP」是两件事，这一条得留在路径里给人看。
	if st["gw-watch"].Code != watchNoReply {
		t.Errorf("网关那一步的码丢了：%q", st["gw-watch"].Code)
	}
}

// 工具自己报错那一步记 failed：不能当成「这一项查过了没问题」，但路线得继续。
func TestTreeFailedStepKeepsGoing(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topDegraded}
	codes["net.routes"] = []string{verdictNoRoute}
	fakeTools(t, codes, map[string]map[string]any{
		"net.checkup": {"first": stepRoute},
		"net.routes":  {"count": 1, "defaults": []any{}},
	})
	treeCalls["net.checkup"] = fake(nil, ots.Errf(ots.ErrPermissionRequired, "这台机器上读不到"))
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	st := stepsOf(t, v)
	if st["checkup"].Status != treeFailed {
		t.Fatalf("checkup = %s，想要 failed", st["checkup"].Status)
	}
	if st["checkup"].Code != string(ots.ErrPermissionRequired) {
		t.Errorf("failed 那一步没记错误码：%q", st["checkup"].Code)
	}
	if st["route-list"].Status != treeAsked {
		t.Errorf("前一步报错后路线就断了：route-list = %s", st["route-list"].Status)
	}
	if v.Code != "cause-no-default-route" {
		t.Errorf("顶层 = %s，想要 cause-no-default-route", v.Code)
	}
}

// 表指到一个不存在的工具：这是我们写错了，得看得见，不许当成网络答的。
func TestTreeMissingToolIsVisible(t *testing.T) {
	fakeTools(t, nil, nil) // 什么都不给
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "nvr-3.example"})
	if v.Code != treeNothing {
		t.Errorf("顶层 = %s，想要 %s —— 一步都没问成，不能读成「查过了都没事」", v.Code, treeNothing)
	}
	if got := v.Values["asked"]; got != 0 {
		t.Errorf("asked = %v，想要 0", got)
	}
	st := stepsOf(t, v)
	if s := st["dns"]; s.Status != treeFailed || s.Code != "tool-missing" {
		t.Errorf("没这个工具时那一步 = %s/%s，想要 failed/tool-missing", s.Status, s.Code)
	}
}

// 结果里没有我们要的那一栏时落 unreadable，那一栏的名字必须写出来。
func TestTreeUnreadableNamesTheField(t *testing.T) {
	fakeTools(t, map[string][]string{"net.checkup": {topDegraded}}, nil)
	treeCalls["net.checkup"] = fake(ots.Verdict{Code: topDegraded}, nil) // 判定给了，first 没给
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	// ★ 读不到 first 时既不能编根因，也不能说「都好了」。
	if v.Code == topAllGood || strings.HasPrefix(v.Code, "cause-") {
		t.Errorf("少了一栏却下了结论：%s", v.Code)
	}
	st := stepsOf(t, v)
	if st["checkup"].Status != treeAsked {
		t.Errorf("判定码读到了，那一步就是 asked（少的是取值不是码）：%s", st["checkup"].Status)
	}
}

// 结果根本不是对象：那是我们读不到，不是网络没答。
func TestTreeNonObjectResultIsUnreadable(t *testing.T) {
	fakeTools(t, map[string][]string{"net.checkup": {topDegraded}}, nil)
	treeCalls["net.checkup"] = fake([]string{"不是对象"}, nil)
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	st := stepsOf(t, v)
	if st["checkup"].Status != treeUnreadable {
		t.Errorf("= %s，想要 unreadable", st["checkup"].Status)
	}
	if !strings.Contains(st["checkup"].Note, "我们") {
		t.Errorf("没写明是我们读不到：%q", st["checkup"].Note)
	}
	if v.Code != treeNothing {
		t.Errorf("顶层 = %s，想要 %s", v.Code, treeNothing)
	}
}

// ── 点名一台机器 ──

// 目标本来就是 IP 时解析那一步不必问 —— 但那一格必须留话，不许空着。
func TestTreeIPTargetSkipsDNSWithAReason(t *testing.T) {
	fakeTools(t, everythingOK(), map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.7", evICMP),
		"net.ports.scan":  {"open": 1, "scanned": 3},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7"})
	st := stepsOf(t, v)
	wantStatus(t, st, "dns", treeNotAsked)
	if st["dns"].Note == "" {
		t.Error("not-asked 没写为什么没问")
	}
	// ★ 填的是地址时后面几步照样要拿它去发包 —— 这条链路断不得。
	if st["ping"].Status != treeAsked {
		t.Errorf("ping 没问出去：%s（%s）", st["ping"].Status, st["ping"].Note)
	}
}

// IPv6 目标：这一族二层问不了，必须写明「问不了」，不许读成「同网段没有它」。
func TestTreeV6TargetDoesNotClaimOffLink(t *testing.T) {
	codes := everythingOK()
	codes["net.ping"] = []string{verdictNoReply}
	codes["net.trace"] = []string{traceNoResponse}
	fakeTools(t, codes, map[string]map[string]any{"net.ping": {"received": 0}})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "fd00::2a"})
	st := stepsOf(t, v)
	wantStatus(t, st, "on-link", treeNotAsked)
	if v.Code == "cause-target-off-link" || v.Code == "cause-device-off-link" {
		t.Errorf("v6 目标却判成「二层没有它」：%s —— 这一族压根没问，白跑一趟机房", v.Code)
	}
}

func TestTreeHostDownAliveButNoICMP(t *testing.T) {
	codes := everythingOK()
	codes["net.ping"] = []string{verdictNoReply}
	fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.7", evARP),
		"net.ping":        {"received": 0},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7"})
	// ★ 二层刚问过、它应了 ARP —— 那它活着，只是不理 ICMP。换个说法就是「去查它自己的防火墙」。
	if v.Code != "cause-target-alive-noicmp" {
		t.Fatalf("顶层 = %s，想要 cause-target-alive-noicmp", v.Code)
	}
}

// 只有 arp 缓存里的老记录不算「它刚才吭过一声」—— 那可能是很久以前留下的。
func TestTreeCacheAloneIsNotAlive(t *testing.T) {
	codes := everythingOK()
	codes["net.ping"] = []string{verdictNoReply}
	codes["net.trace"] = []string{traceNoResponse}
	fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.7", evCache),
		"net.ping":        {"received": 0},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7"})
	if v.Code == "cause-target-alive-noicmp" {
		t.Error("只有一条缓存记录就敢说「它活着只是不理 ping」")
	}
	if v.Code != "cause-target-no-reply" {
		t.Errorf("顶层 = %s，想要 cause-target-no-reply", v.Code)
	}
}

func TestTreeHostDownOffLink(t *testing.T) {
	codes := everythingOK()
	codes["net.subnet.scan"] = []string{scanNetEmpty}
	tracker := fakeTools(t, codes, map[string]map[string]any{
		// 扫的是它所在那一段，清单里却没有它 —— 这才敢说「二层没有它」。
		"net.subnet.scan": netWindowEmpty("192.0.2.7"),
		// 段从「去往它走哪条路」那一步来：直连，且那个段盖得住它。
		"net.routes": {"decision": map[string]any{"iface": "en0",
			"destination": "192.0.2.0/24", "direct": true, "from": "os"}},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7"})
	if v.Code != "cause-target-off-link" {
		t.Fatalf("顶层 = %s，想要 cause-target-off-link", v.Code)
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "trace", treeSkipped)
	wantStatus(t, st, "ports", treeSkipped)
	if got := st["on-link"].Args["cidr"]; got != "192.0.2.0/24" {
		t.Errorf("二层那一问扫的是 %v，想要路由给的那一段 —— 拿 /32 去问会被工具直接拒", got)
	}
	if tracker["net.ping"].calls != 0 {
		t.Error("二层都没有它，还去发 ping")
	}
}

// ★★ 扫的是别的段，就不许拿「清单里没有它」定它的罪。
//
//	现场真会走到这一条：目标要过网关、或者路由那一步没问出段来，
//	于是 net.subnet.scan 扫的是本机自己在的那几段。清单空着不等于它不在。
func TestTreeHostDownScanOfWrongNetIsNotOffLink(t *testing.T) {
	codes := everythingOK()
	codes["net.subnet.scan"] = []string{scanNetEmpty}
	fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": {"hosts": []any{}, "subnets": []any{"192.168.9.0/24"},
			"alive": 0, "asked": 254},
		"net.ports.scan": {"open": 1},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7"})
	if v.Code == "cause-target-off-link" {
		t.Fatal("扫的不是它那段，却也敢说「二层没有它」")
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "ping", treeAsked) // 问不成结论的那一步之后，路还得往下走
}

func TestTreeHostDownServiceClosed(t *testing.T) {
	codes := everythingOK()
	codes["net.ports.scan"] = []string{scanAllClosed}
	fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.7", evICMP),
		"net.ports.scan":  {"closed": 1, "open": 0},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7", Port: 8080})
	if v.Code != "cause-service-closed" {
		t.Fatalf("顶层 = %s，想要 cause-service-closed", v.Code)
	}
	// ★ 点了端口就得只扫那一个，不许拿默认清单交差。
	st := stepsOf(t, v)
	if got := st["ports"].Args["ports"]; got != "8080" {
		t.Errorf("端口扫描收到的 ports = %v，想要 8080", got)
	}
}

// 走到这儿网络和服务都没问题 —— 那也要说一句，不许默默走完。
func TestTreeHostDownEverythingFine(t *testing.T) {
	fakeTools(t, everythingOK(), map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.7", evICMP),
		"net.ports.scan":  {"open": 1},
	})
	v := runTree(t, treeArgs{Symptom: symHostDown, Target: "192.0.2.7", Port: 443})
	if v.Code != "cause-host-alive" {
		t.Fatalf("顶层 = %s，想要 cause-host-alive", v.Code)
	}
}

// ── 证书：最值钱的一步是先问时间再下结论 ──

func TestTreeCertExpiredButClockWrong(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{certExpired}
	codes["net.time.check"] = []string{timeWayOff}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.time.check": {"offsetMs": -400000000.0, "checkedWith": "pool.ntp.org"},
	})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	// ★★ 证书「过期」而钟慢了十几天：说「去续证书」会让人白跑一趟 CA，毛病在自己主机的任务栏上。
	if v.Code != "cause-clock-made-cert-bad" {
		t.Fatalf("顶层 = %s，想要 cause-clock-made-cert-bad", v.Code)
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "clock", treeAsked)
	if st["clock"].Facts["offsetMs"] == nil {
		t.Error("定成钟的锅，却没把偏了多少带进结果")
	}
}

func TestTreeCertExpiredAndClockFine(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{certExpired}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.time.check": {"offsetMs": 40.0},
	})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	if v.Code != "cause-cert-expired" {
		t.Fatalf("顶层 = %s，想要 cause-cert-expired", v.Code)
	}
}

// 钟慢到证书「还没生效」—— 同一台机器，方向反过来的同一个毛病。
func TestTreeCertNotYetValidFromSlowClock(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{certNotYetValid}
	codes["net.time.check"] = []string{timeSkewed}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.time.check": {"offsetMs": -90000000.0},
	})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	if v.Code != "cause-clock-made-cert-bad" {
		t.Fatalf("顶层 = %s，想要 cause-clock-made-cert-bad", v.Code)
	}
}

// 问不到时间源时只能按证书自己说的下结论 —— 但得留下「我们没验过钟」。
func TestTreeCertNoTimeSource(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{certExpired}
	codes["net.time.check"] = []string{timeNoResponse}
	fakeTools(t, codes, map[string]map[string]any{"net.dns.query": answers("203.0.113.9")})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	if v.Code != "cause-cert-expired" {
		t.Fatalf("顶层 = %s，想要 cause-cert-expired", v.Code)
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "clock", treeAsked)
	if st["clock"].Code != timeNoResponse {
		t.Errorf("时间那一步的码丢了：%q", st["clock"].Code)
	}
}

func TestTreeCertPlainPortWrittenAsHTTPS(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{tlsNotTLS}
	fakeTools(t, codes, map[string]map[string]any{"net.dns.query": answers("203.0.113.9")})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "printer.example"})
	// ★ 明文口写成 https：改个前缀就好，不是证书坏了。
	if v.Code != "cause-not-tls" {
		t.Fatalf("顶层 = %s，想要 cause-not-tls", v.Code)
	}
}

// 证书本身没毛病时不许硬编一个根因 —— 那条路上问不出更多就是问不出。
func TestTreeCertGoodCertStops(t *testing.T) {
	codes := everythingOK()
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query": answers("203.0.113.9"),
		"net.tls.check": {"protocol": "TLS 1.3", "daysLeft": 300},
	})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	if strings.HasPrefix(v.Code, "cause-cert") {
		t.Errorf("证书好好的却定了个证书根因：%s", v.Code)
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "clock", treeSkipped)
}

// ★ 人没点名目标时用的是对照组那个名字，证书那一步必须拿同一个名字去校验。
//
//	少了这一格就是「用 IP 连、又没带名字」，那张证书上的名字必然对不上 ——
//	那是我们自己造的假案，会让人白查一趟 CA。
func TestTreeCertDefaultTargetCarriesItsName(t *testing.T) {
	fakeTools(t, everythingOK(), map[string]map[string]any{
		"net.dns.query": answers("203.0.113.9"),
	})
	v := runTree(t, treeArgs{Symptom: symCert})
	st := stepsOf(t, v)
	if got := st["tls"].Args["serverName"]; got != defaultProbeDomain {
		t.Errorf("TLS 那一步的 serverName = %v，想要 %s（顶层 %s）",
			got, defaultProbeDomain, v.Code)
	}
}

// 老设备只肯谈 TLS1.0：握手失败那一条得归到协议上。
func TestTreeCertHandshakeFailedIsProtocol(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{tlsHandshakeFailed}
	fakeTools(t, codes, map[string]map[string]any{"net.dns.query": answers("203.0.113.9")})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "nvr-old.example"})
	if v.Code != "cause-cert-weak-protocol" {
		t.Fatalf("顶层 = %s，想要 cause-cert-weak-protocol", v.Code)
	}
}

// ── 慢 ──

func TestTreeSlowAttributedBySegment(t *testing.T) {
	cases := []struct {
		name   string
		timing map[string]any
		want   string
	}{
		{"解析慢", map[string]any{"lookupMs": 900.0, "totalMs": 1200.0}, "cause-dns-slow"},
		{"连接慢", map[string]any{"connectMs": 800.0, "totalMs": 1000.0}, "cause-connect-slow"},
		{"握手慢", map[string]any{"tlsMs": 900.0, "totalMs": 1100.0}, "cause-tls-slow"},
		{"服务端慢", map[string]any{"lookupMs": 20.0, "connectMs": 20.0, "tlsMs": 30.0,
			"serverMs": 1500.0, "totalMs": 1600.0}, "cause-app-slow"},
		// ★ 各段都利索时才轮得到逐跳：那一段的抬升是路上的，不是应用的。
		{"各段都不慢", map[string]any{"lookupMs": 20.0, "connectMs": 20.0, "tlsMs": 30.0,
			"serverMs": 30.0, "totalMs": 100.0}, "cause-path-latency"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codes := everythingOK()
			if tc.want == "cause-path-latency" {
				codes["net.mtr"] = []string{qualityLatency}
			}
			fakeTools(t, codes, map[string]map[string]any{
				"net.dns.query":  answers("203.0.113.9"),
				"net.http.probe": {"timings": tc.timing, "status": 200},
				// 各段都不慢时才会走到逐跳：这里给「从第 6 跳起往返抬升」。
				"net.mtr": {"reports": []any{map[string]any{"family": "ipv4",
					"latencyHop": 6, "roundsDone": 5}}},
			})
			v := runTree(t, treeArgs{Symptom: symSlow, Target: "app.example"})
			if v.Code != tc.want {
				t.Errorf("顶层 = %s，想要 %s", v.Code, tc.want)
			}
			if !IsTreeCause(v.Code) {
				t.Errorf("%s 没登记在 treeCauses 里", v.Code)
			}
		})
	}
}

// ★ 链路在丢包时读 HTTP 的分段耗时毫无意义 —— 那会把网线的账算到应用头上。
// 所以这棵树必须停在丢包那一步，后面的 HTTP 一次都不许问。
func TestTreeSlowStopsAtLinkLoss(t *testing.T) {
	codes := everythingOK()
	codes["net.ping.watch"] = []string{watchLoss}
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.ping.watch": {"lossPercent": 8},
	})
	v := runTree(t, treeArgs{Symptom: symSlow, Target: "app.example"})
	if v.Code != "cause-link-loss" {
		t.Fatalf("顶层 = %s，想要 cause-link-loss", v.Code)
	}
	if tracker["net.http.probe"].calls != 0 {
		t.Error("链路都在丢包了还去问 HTTP 分段耗时")
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "http", treeSkipped)
}

func TestTreeSlowV6Stall(t *testing.T) {
	codes := everythingOK()
	codes["net.dualstack.check"] = []string{dsEyeballsStall}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.http.probe": {"timings": map[string]any{"totalMs": 60.0}},
	})
	v := runTree(t, treeArgs{Symptom: symSlow, Target: "app.example"})
	if v.Code != "cause-v6-stall" {
		t.Fatalf("顶层 = %s，想要 cause-v6-stall", v.Code)
	}
}

// 明文口写成 https：那不是慢，是先撞了再重试。
func TestTreeSlowWrongSchemeSeparate(t *testing.T) {
	codes := everythingOK()
	codes["net.http.probe"] = []string{httpWrongScheme}
	fakeTools(t, codes, map[string]map[string]any{"net.dns.query": answers("203.0.113.9")})
	v := runTree(t, treeArgs{Symptom: symSlow, URL: "https://192.0.2.9/dashboard"})
	if v.Code != "cause-wrong-scheme" {
		t.Fatalf("顶层 = %s，想要 cause-wrong-scheme", v.Code)
	}
}

// ── 时好时坏 ──

func TestTreeFlakyRoundRobin(t *testing.T) {
	codes := everythingOK()
	codes["net.mtr"] = []string{qualitySilent}
	fakeTools(t, codes, map[string]map[string]any{
		// ★ 同一个名字解出两台，其中一台是坏的 —— 「时好时坏」最省钱的解释。
		"net.dns.query": answers("203.0.113.1", "203.0.113.2"),
	})
	v := runTree(t, treeArgs{Symptom: symFlaky, Target: "vip.example"})
	if v.Code != "cause-round-robin-bad" {
		t.Fatalf("顶层 = %s，想要 cause-round-robin-bad", v.Code)
	}
	st := stepsOf(t, v)
	wantStatus(t, st, "dns", treeAsked)
	wantStatus(t, st, "dns-multi", treeAsked)
	if st["dns-multi"].Facts["answers"] == nil {
		t.Error("第二次解析没把清单带进结果 —— 那正是这条结论的证据")
	}
}

func TestTreeFlakySingleAnswerKeepsGoing(t *testing.T) {
	codes := everythingOK()
	codes["net.mtr"] = []string{qualitySilent}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query": answers("203.0.113.1"),
		"net.routes":    {"count": 4},
	})
	v := runTree(t, treeArgs{Symptom: symFlaky, Target: "vip.example"})
	if v.Code == "cause-round-robin-bad" {
		t.Fatal("只解出一个地址也敢说轮询里有坏的")
	}
	wantStatus(t, stepsOf(t, v), "clock", treeAsked)
}

func TestTreeFlakyPathMoved(t *testing.T) {
	codes := everythingOK()
	codes["net.mtr"] = []string{qualityPathMoved}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query": answers("203.0.113.1"),
		"net.routes":    {"count": 9},
	})
	v := runTree(t, treeArgs{Symptom: symFlaky, Target: "vip.example"})
	if v.Code != "cause-path-moved" {
		t.Fatalf("顶层 = %s，想要 cause-path-moved", v.Code)
	}
}

func TestTreeFlakyTwoClocksDisagree(t *testing.T) {
	codes := everythingOK()
	codes["net.time.check"] = []string{timeDisagree}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.1"),
		"net.time.check": {"spreadMs": 4200.0},
	})
	v := runTree(t, treeArgs{Symptom: symFlaky, Target: "vip.example"})
	if v.Code != "cause-clock-disagree" {
		t.Fatalf("顶层 = %s，想要 cause-clock-disagree（日志对不上号就是这么来的）", v.Code)
	}
}

// ── 设备 ──

func TestTreeDeviceStreamMissing(t *testing.T) {
	codes := everythingOK()
	codes["media.rtsp.probe"] = []string{verdictNotFound}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":    answers("192.0.2.31"),
		"net.subnet.scan":  hostFound("192.0.2.31", evICMP),
		"net.ports.scan":   {"open": 1},
		"media.rtsp.probe": {"status": "404"},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "cam1", URL: "rtsp://192.0.2.31/live"})
	if v.Code != "cause-stream-missing" {
		t.Fatalf("顶层 = %s，想要 cause-stream-missing", v.Code)
	}
	wantStatus(t, stepsOf(t, v), "stream", treeAsked)
}

// 流在播：那「没画面」是那头的显示侧 —— 这条结论的价值是把人从机房劝回去。
func TestTreeDeviceStreamActuallyPlays(t *testing.T) {
	fakeTools(t, everythingOK(), map[string]map[string]any{
		"net.dns.query":    answers("192.0.2.31"),
		"net.subnet.scan":  hostFound("192.0.2.31", evICMP),
		"net.ports.scan":   {"open": 1},
		"media.rtsp.probe": {"codec": "H264", "width": 1920, "height": 1080, "trackCount": 2},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31", URL: "rtsp://192.0.2.31/live"})
	if v.Code != "cause-stream-ok" {
		t.Fatalf("顶层 = %s，想要 cause-stream-ok", v.Code)
	}
	st := stepsOf(t, v)
	if st["stream"].Facts["width"] == nil {
		t.Error("说得出画面在，却说不出是什么画面")
	}
}

// 没给取流地址、而 ONVIF 那一句回的不是可验的地址（各家确有只回 http 那一路的）：
// 验流那一步只能是被跳过，★ 而且停下的理由要写在「停在哪一步」上，
// 不许顺着往下走、再落一句「每一步都正常」—— 那会把我们问不出来读成网络没毛病。
func TestTreeDeviceNoURLLeavesStepVisible(t *testing.T) {
	codes := everythingOK() // media.onvif.info 回 onvif-ok，但没带出 rtsp 地址
	fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.31", evICMP),
		"net.ports.scan":  {"open": 1},
		"media.onvif.info": {"profileCount": 1.0,
			"mediaUri": "http://192.0.2.31/snap.jpg"}, // ★ 不是 rtsp，下一步问不出去
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31"})
	st := stepsOf(t, v)
	wantStatus(t, st, "onvif", treeAsked)
	wantStatus(t, st, "stream", treeSkipped)
	if !strings.Contains(st["stream"].Note, "停在") {
		t.Errorf("没写出停在哪儿：%q", st["stream"].Note)
	}
	if v.Code != "cause-onvif-no-media" {
		t.Fatalf("顶层 = %s，想要 cause-onvif-no-media", v.Code)
	}
	if strings.HasPrefix(v.Code, "cause-stream") {
		t.Errorf("没问过流却定了个流的根因：%s", v.Code)
	}
}

// 摄像头那棵树默认扫常用端口，而不是只问一个。
func TestTreeDeviceUsesCameraPorts(t *testing.T) {
	codes := everythingOK()
	codes["net.ports.scan"] = []string{scanAllClosed}
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.31", evICMP),
		"net.ports.scan":  {"closed": 3},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31"})
	if v.Code != "cause-device-no-service" {
		t.Fatalf("顶层 = %s，想要 cause-device-no-service", v.Code)
	}
	args := tracker["net.ports.scan"].args
	last := args[len(args)-1]
	if last["ports"] != defaultCamPorts {
		t.Errorf("设备那棵树没带上摄像头常用端口：%v", last["ports"])
	}
}

// 设备活着但不理 ping —— 摄像头十台九台这样，这一条要说得很轻、很有把握。
func TestTreeDeviceNoICMP(t *testing.T) {
	codes := everythingOK()
	codes["net.ping"] = []string{verdictNoReply}
	fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.31", evARP),
		"net.ping":        {"received": 0},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31"})
	if v.Code != "cause-device-no-icmp" {
		t.Fatalf("顶层 = %s，想要 cause-device-no-icmp", v.Code)
	}
}

// ── 手里没有取流地址：先向设备问一次 ──

// 「没地址」不等于查不动：ONVIF 问得出地址，问出来就接着去验流。
//
// ★★ 喂给下一步的那句地址里不许留着抹过口令的那一截。结果里的地址是
//
//	rtsp://admin（口令已隐去）@… 这种形状（凭据不进结果是硬规矩），
//	照原样发出去就等于拿「admin（口令已隐去）」当用户名去敲门 ——
//	设备回 401，我们把它读成「密码不对」，而密码正是调用方填对的那一份。
func TestTreeDeviceAsksONVIFForTheStreamURL(t *testing.T) {
	codes := everythingOK()
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.31", evICMP),
		"net.ports.scan":  {"open": 1},
		"media.onvif.info": {"manufacturer": "ACME", "model": "C-100",
			"mediaUri": "rtsp://admin%EF%BC%88%E5%8F%A3%E4%BB%A4%E5%B7%B2%E9%9A%90%E5%8E%BB%EF%BC%89@192.0.2.31:554/live"},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31",
		Username: "admin", Password: "Sup3rS3cret"})
	st := stepsOf(t, v)
	wantStatus(t, st, "onvif", treeAsked)
	wantStatus(t, st, "stream", treeAsked) // ★ 地址问出来了，最后那一步就问得出去
	if v.Code != "cause-stream-ok" {
		t.Fatalf("顶层 = %s，想要 cause-stream-ok", v.Code)
	}
	asked := tracker["media.onvif.info"].args[0]
	if asked["url"] != "http://192.0.2.31" {
		t.Errorf("没拿这台设备的地址去问它：%v", asked["url"])
	}
	if asked["password"] != "Sup3rS3cret" {
		t.Errorf("ONVIF 那一问没带上账号（多数相机匿名只回 Fault）：%v", asked["password"])
	}
	got := tracker["media.rtsp.probe"].args[0]
	if got["url"] != "rtsp://192.0.2.31:554/live" {
		t.Errorf("喂给验流那一步的地址不对：%v", got["url"])
	}
	blob := fmt.Sprint(v.Values)
	if strings.Contains(blob, "口令已隐去") || strings.Contains(blob, "%EF%BC%88") {
		t.Errorf("抹过口令的那一截被当成可用地址留下来了：%s", blob)
	}
	if strings.Contains(blob, "Sup3rS3cret") {
		t.Errorf("口令漏进结果了：%s", blob)
	}
}

// 问不出地址的那七种落法各有各的下一步：要账号、端口上不是 ONVIF、这台不接这一问、
// 它说没码流、媒体那一路问不出、连不上、连上不回话。
// ★ 每一档都停在**这一问自己**给的判定上 —— 放它走到下一步只会得到
//
//	「缺参数，没问出去」，再落一句「每一步都正常」，那是把我们的问不出说成没毛病。
func TestTreeDeviceOnvifStopsByItsOwnAnswer(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{
		{verdictONVIFAuth, "cause-onvif-auth"},
		{verdictONVIFNotOnvif, "cause-port-not-onvif"},
		{verdictONVIFFault, "cause-onvif-unsupported"},
		{verdictONVIFPartial, "cause-onvif-no-media"},
		{verdictONVIFNoProfile, "cause-onvif-no-profile"},
		{verdictONVIFNoRepl, "cause-onvif-silent"},
		{verdictONVIFUnreach, "cause-onvif-unreachable"},
	} {
		codes := everythingOK()
		codes["media.onvif.info"] = []string{tc.code}
		fakeTools(t, codes, map[string]map[string]any{
			"net.subnet.scan": hostFound("192.0.2.31", evICMP),
			"net.ports.scan":  {"open": 1},
		})
		v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31"})
		if v.Code != tc.want {
			t.Errorf("ONVIF 回 %s，顶层却停在 %s，想要 %s", tc.code, v.Code, tc.want)
		}
		if c := stepsOf(t, v)["onvif"].Code; c != tc.code {
			t.Errorf("那一步自己的判定没记下来：%v", c)
		}
	}
}

// 手里已经有地址时不必再多问一嘴 —— 但这一格要写明「为什么没问」，不许留空。
func TestTreeDeviceSkipsOnvifWhenURLGiven(t *testing.T) {
	codes := everythingOK()
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.subnet.scan": hostFound("192.0.2.31", evICMP),
		"net.ports.scan":  {"open": 1},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31",
		URL: "rtsp://192.0.2.31:554/live"})
	st := stepsOf(t, v)
	wantStatus(t, st, "onvif", treeNotAsked)
	if !strings.Contains(st["onvif"].Note, "已经有") {
		t.Errorf("没写出为什么没问：%q", st["onvif"].Note)
	}
	if tracker["media.onvif.info"].calls != 0 {
		t.Error("有地址却还去问了设备")
	}
	wantStatus(t, st, "stream", treeAsked)
}

// ── 顶层码 ──

// 这条路每步都正常时，必须说「症状不在我们问的里面」，不许说「网络正常」。
func TestTreeNoCauseCountsSteps(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topAllGood}
	fakeTools(t, codes, nil)
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	if v.Code != treeNoCause {
		t.Fatalf("顶层 = %s，想要 %s", v.Code, treeNoCause)
	}
	if v.Values["asked"] == nil {
		t.Error("没带 asked 计数 —— 人说「查了几步」得有个依据")
	}
	if !strings.Contains(v.Note, "不在") {
		t.Errorf("这句话没说出「没定位到」： %q", v.Note)
	}
}

// 中途取消：这份路径只到第几步，不能当成整条结论。
func TestTreeStoppedReportsPartial(t *testing.T) {
	fakeTools(t, everythingOK(), nil)
	treeCalls["net.checkup"] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 一进来就是取消状态
	raw, _ := json.Marshal(treeArgs{Symptom: symNoInternet})
	res, err := doTroubleshoot(ctx, raw)
	if err != nil {
		t.Fatalf("超时不该报错，该给一份残缺的路径：%v", err)
	}
	v, ok := res.(ots.Verdict)
	if !ok {
		t.Fatalf("返回的不是判定：%T", res)
	}
	if v.Code != treeStopped {
		t.Errorf("顶层 = %s，想要 %s", v.Code, treeStopped)
	}
}

// 表写错成环 / 指到不存在的步骤：立刻报错，不许转圈转到人以为在跑。
func TestTreeBadPlanErrorsOut(t *testing.T) {
	fakeTools(t, map[string][]string{"net.dns.query": {dnsResolved}},
		map[string]map[string]any{"net.dns.query": answers("203.0.113.9")})

	cycle := &treePlan{symptom: "test", steps: []planStep{
		{node: &treeNode{id: "a", tool: "net.dns.query"}, other: to("b")},
		{node: &treeNode{id: "b", tool: "net.dns.query"}, other: to("a")},
	}}
	if _, err := runTreePlan(context.Background(), cycle, newTreeState(treeArgs{}), lookupTreeCall); err == nil {
		t.Fatal("成环的表没报错")
	} else if !strings.Contains(err.Error(), "环") {
		t.Errorf("报错没说是环的问题：%v", err)
	}

	dangling := &treePlan{symptom: "test", steps: []planStep{
		{node: &treeNode{id: "a", tool: "net.dns.query"}, other: to("nowhere")},
	}}
	if _, err := runTreePlan(context.Background(), dangling, newTreeState(treeArgs{}), lookupTreeCall); err == nil {
		t.Fatal("指到不存在的步骤没报错")
	}
}

// ── 参数与错误 ──

func TestTreeSymptomRequired(t *testing.T) {
	for _, s := range []string{"", "打印机电不亮"} {
		raw, _ := json.Marshal(treeArgs{Symptom: s})
		_, err := doTroubleshoot(context.Background(), raw)
		if err == nil {
			t.Fatalf("症状 %q 居然收下了", s)
		}
		var oe *ots.Error
		if !asOtsError(err, &oe) || oe.Code != ots.ErrInvalidArgument {
			t.Fatalf("错误类型 = %v，想要 invalid-argument", err)
		}
		// ★ 报错必须把可选项列出来：这一栏的输入是人写的一句症状，选错等于走错树。
		if !strings.Contains(err.Error(), symNoInternet) {
			t.Errorf("报错里没列出可选症状：%v", err)
		}
	}
}

func asOtsError(err error, target **ots.Error) bool {
	e, ok := err.(*ots.Error)
	if ok {
		*target = e
	}
	return ok
}

func TestTreeArgumentBounds(t *testing.T) {
	fakeTools(t, everythingOK(), nil)
	for i, a := range []treeArgs{
		{Symptom: symHostDown, TimeoutMS: 100},
		{Symptom: symHostDown, TimeoutMS: 99999},
		{Symptom: symHostDown, MaxSeconds: 1},
		{Symptom: symHostDown, MaxSeconds: 9999},
	} {
		raw, _ := json.Marshal(a)
		if _, err := doTroubleshoot(context.Background(), raw); err == nil {
			t.Errorf("第 %d 个越界参数没收住", i)
		}
	}
}

// ── 事实归一 ──

// ★ 现场最常见的错法是把域名填进 ping 的参数里，症状变成「说不清是没解析还是不通」。
//
//	所以地址和域名在入口就分家，后面每一步各取各的。
func TestTreeTargetNormalized(t *testing.T) {
	cases := []struct {
		in              treeArgs
		ip, host, addr  string
		family, portStr string
	}{
		{in: treeArgs{Target: "192.0.2.7"}, ip: "192.0.2.7", addr: "192.0.2.7", family: "ipv4"},
		{in: treeArgs{Target: "fd00::2a"}, ip: "fd00::2a", addr: "fd00::2a", family: "ipv6"},
		// ★ 方括号是人在 URL 里抄来的写法，问下一跳时带着括号必错 —— 入口就洗掉。
		{in: treeArgs{Target: "[fd00::2a]"}, ip: "fd00::2a", addr: "fd00::2a", family: "ipv6"},
		{in: treeArgs{Target: "cam1.local"}, host: "cam1.local"},
		{in: treeArgs{Target: "www.example.com."}, host: "www.example.com"},
		{in: treeArgs{Target: "192.0.2.7", Port: 554}, ip: "192.0.2.7", addr: "192.0.2.7", family: "ipv4", portStr: "554"},
		// 网址里点名的是地址时同样要落成 addr：后面每一步都拿它去发包，只落 host 等于把它弄丢了。
		{in: treeArgs{URL: "rtsp://admin:pw@192.0.2.31:554/live"}, ip: "192.0.2.31", addr: "192.0.2.31", family: "ipv4", portStr: "554"},
	}
	for _, tc := range cases {
		st := newTreeState(tc.in)
		got := struct{ ip, host, addr, family, port string }{
			st.str("ip"), st.str("host"), st.str("addr"), st.str("family"), st.str("portStr")}
		want := struct{ ip, host, addr, family, port string }{
			tc.ip, tc.host, tc.addr, tc.family, tc.portStr}
		if got != want {
			t.Errorf("目标 %#v 归一成 %+v，想要 %+v", tc.in, got, want)
		}
	}
}

// ── 脱敏 ──

// ★★ 这一条是整个工具层最不能松的一条：推理路径要能发群里、进诊断包。
//
//	参数照抄一份进结果，等于每一次排查都在往外送口令。
func TestTreeCredentialsNeverInResult(t *testing.T) {
	const (
		urlPW   = "S3cr3tPW"
		formPW  = "AnotherSecret99"
		rtspURL = "rtsp://admin:" + urlPW + "@cam.example:554/stream1"
	)
	codes := everythingOK()
	codes["media.rtsp.probe"] = []string{verdictStreamOK}
	tracker := fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":    answers("192.0.2.31"),
		"net.subnet.scan":  hostFound("192.0.2.31", evICMP),
		"net.ports.scan":   {"open": 1},
		"media.rtsp.probe": {"codec": "H264"},
	})
	v := runTree(t, treeArgs{
		Symptom: symDeviceDown, Target: "cam.example",
		URL: rtspURL, Username: "viewer", Password: formPW,
	})
	b, _ := json.Marshal(v)
	s := string(b)
	for _, leak := range []string{urlPW, formPW} {
		if strings.Contains(s, leak) {
			t.Errorf("结果里漏出了凭据 %q", leak)
		}
	}
	// 问的是哪台必须看得出来，否则这条路径没法核对 —— 脱敏不该脱成猜谜。
	if !strings.Contains(s, "cam.example") {
		t.Error("结果里连问的是哪台都看不出来")
	}
	// ★ 发出去的那一份**必须**带着口令，否则根本问不出去 —— 脱的是进结果的那一份。
	sent := tracker["media.rtsp.probe"]
	if sent.calls == 0 {
		t.Fatal("根本没问过取流，这条测试什么都没验")
	}
	var gotPW bool
	for _, m := range sent.args {
		if m["password"] == formPW {
			gotPW = true
		}
	}
	if !gotPW {
		t.Error("发给工具的参数里没带口令 —— 结果脱了敏，问的时候却问不出去")
	}
}

func TestTreeCommunityRedacted(t *testing.T) {
	m := redactTreeArgs(map[string]any{"addr": "10.0.0.1",
		"community": "privateCommunity", "port": 161, "password": "x"})
	b, _ := json.Marshal(m)
	s := string(b)
	if strings.Contains(s, "privateCommunity") || strings.Contains(s, `"x"`) {
		t.Errorf("参数没洗：%s", s)
	}
	if !strings.Contains(s, "10.0.0.1") {
		t.Errorf("地址被一起洗掉了：%s", s)
	}
}

// 每一棵树的每一个节点，进结果的那份参数都不许带口令。
func TestTreeEveryNodeArgsRedacted(t *testing.T) {
	st := newTreeState(treeArgs{
		Symptom: symDeviceDown, Target: "192.0.2.7", Port: 554,
		URL: "rtsp://u:TopSecret1@h/x", Username: "u", Password: "TopSecret1",
		Community: "TopSecret2",
	})
	for _, p := range TreePlans() {
		for _, s := range p.steps {
			if s.node.args == nil {
				continue
			}
			m, err := s.node.args(st)
			if err != nil {
				continue
			}
			b, _ := json.Marshal(redactTreeArgs(m))
			for _, secret := range []string{"TopSecret1", "TopSecret2"} {
				if strings.Contains(string(b), secret) {
					t.Errorf("%s 进结果的参数带了口令：%s", s.node.id, b)
				}
			}
		}
	}
}

// ── 表本身的静态检查 ──
//
// ★ 这些测试一步都不跑，只审表。它们是唯一能在「网络还好好的」时候
//
//	就发现表写错了的东西 —— 走错一条分支的代价是有人白跑一趟机房。

func TestTreeStepIDsAreUnique(t *testing.T) {
	for _, plan := range TreePlans() {
		seen := map[string]bool{}
		for _, s := range plan.steps {
			if seen[s.node.id] {
				t.Errorf("%s：步骤 id %q 出现两次 —— 引擎按 id 找下一步，同 id 有一份永远走不到",
					plan.symptom, s.node.id)
			}
			seen[s.node.id] = true
		}
	}
}

// 每一条 next 都得指得到人：指到不存在的步骤，现场第一次跑到就炸。
func TestTreeNextTargetsExist(t *testing.T) {
	for _, plan := range TreePlans() {
		ids := map[string]bool{}
		for _, s := range plan.steps {
			ids[s.node.id] = true
		}
		for _, s := range plan.steps {
			check := func(from, to string) {
				if to != "" && !ids[to] {
					t.Errorf("%s：%s 指向不存在的步骤 %q", plan.symptom, from, to)
				}
			}
			for code, mv := range s.by {
				check(s.node.id+" 的 "+code, mv.next)
			}
			check(s.node.id+" 的 other", s.other.next)
		}
	}
}

// 根因和走法不能同时给（同时给时走法是死字）；根因码必须登记；不许指回自己。
func TestTreeMovesAreSane(t *testing.T) {
	for _, plan := range TreePlans() {
		for _, s := range plan.steps {
			one := func(where string, mv move) {
				if mv.cause != "" && (mv.next != "" || mv.end) {
					t.Errorf("%s：%s 既给了根因又给了走法，走法那半句永远不看", plan.symptom, where)
				}
				if mv.cause != "" && !IsTreeCause(mv.cause) {
					t.Errorf("%s：%s 定了根因 %q，但它没登记在 treeCauses 里", plan.symptom, where, mv.cause)
				}
				if mv.next == s.node.id {
					t.Errorf("%s：%s 指回自己，一跑到这儿就成环", plan.symptom, where)
				}
			}
			for code, mv := range s.by {
				one(s.node.id+" 的 "+code, mv)
			}
			one(s.node.id+" 的 other", s.other)
		}
	}
}

// 树里出现的每一个工具名都必须真的注册了、而且是只读的。
//
// ★ 这一条是那道闸的测试：树要是能指向一个改系统的工具，
//
//	人点「排查」就把系统改了。
func TestTreeToolsAreRegisteredAndReadOnly(t *testing.T) {
	read := map[string]bool{}
	for _, tool := range localTools {
		if tool.Class == ots.ClassRead {
			read[tool.Name] = true
		}
	}
	for _, plan := range TreePlans() {
		for _, s := range plan.steps {
			if !read[s.node.tool] {
				t.Errorf("%s 树里问了 %q，但它没注册或不是只读工具", plan.symptom, s.node.tool)
			}
			if s.node.id == "" {
				t.Errorf("%s 树里有个节点没 id", plan.symptom)
			}
		}
	}
}

// 每一棵树的入口和症状清单要对得上：加一棵忘了登记，界面就少一条路。
func TestTreePlansCoverSymptoms(t *testing.T) {
	for _, sym := range treeSymptoms {
		plan, ok := treePlanFor(sym)
		if !ok {
			t.Errorf("症状 %q 没有树", sym)
			continue
		}
		if plan.symptom != sym {
			t.Errorf("%q 的树自称 %q", sym, plan.symptom)
		}
		if len(plan.steps) == 0 {
			t.Errorf("%q 的树空着", sym)
		}
	}
	if len(TreePlans()) != len(treeSymptoms) {
		t.Errorf("TreePlans 给了 %d 棵，症状有 %d 种", len(TreePlans()), len(treeSymptoms))
	}
}

// 根因码的形状要稳定：界面按码渲染中文，漏一个就是一条回落成原文的判定。
func TestTreeCausesRegistered(t *testing.T) {
	list := TreeCauses()
	if len(list) < 40 {
		t.Fatalf("登记的根因码只有 %d 个，比六棵树该有的少得多", len(list))
	}
	seen := map[string]bool{}
	for _, c := range list {
		if !strings.HasPrefix(c, "cause-") {
			t.Errorf("根因码 %q 没带 cause- 前缀 —— 和顶层码混在一起界面就没法分开渲染", c)
		}
		if seen[c] {
			t.Errorf("根因码 %q 重复", c)
		}
		seen[c] = true
	}
}

// 每一个节点都得有人话名字：skipped 的注和「停在第几步」那句话要拿它写，
// 用内部 id 写就等于把 dualstack 这种人不会读的词塞进结果。
func TestTreeEveryNodeHasAName(t *testing.T) {
	seen := map[string]string{}
	for _, plan := range TreePlans() {
		for _, ps := range plan.steps {
			if ps.node.name == "" {
				t.Errorf("%s 树里的 %s（%s）没起名字", plan.symptom, ps.node.id, ps.node.tool)
				continue
			}
			if other, ok := seen[ps.node.id]; ok && other != ps.node.name {
				t.Errorf("步骤 %s 在两棵树里名字不一样：%q / %q", ps.node.id, other, ps.node.name)
			}
			seen[ps.node.id] = ps.node.name
		}
	}
}

// 界面必须把树上每一种读数都译成人话。
//
// ★★ 这张卡卖的就是那句人话：漏一个码，界面上就是一个裸的 cause-gateway-silent。
//
//	这里逐条问的是**树真的会吐出来**的那些 —— 表里 by 的键、根因清单、顶层读数、
//	步骤状态、症状名，而不是凭印象另列一份清单（清单会过期，表不会）。
func TestTreeReadingsAllTranslatedInUI(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面源码，这一项就等于没查：%v", err)
	}
	js := string(b)
	keyPos := func(code string) *regexp.Regexp {
		return regexp.MustCompile(`(^|\s|\{)` + regexp.QuoteMeta(code) + `\s*:`)
	}
	miss := func(what, code string) {
		// 三种出现方式都算数：字符串字面量、对象键（JS 字典里合法标识符的键不写引号）。
		if strings.Contains(js, `"`+code+`"`) || strings.Contains(js, `'`+code+`'`) || keyPos(code).MatchString(js) {
			return
		}
		t.Errorf("%s %q 在界面里没有说法", what, code)
	}
	for _, c := range TreeCauses() {
		miss("根因码", c)
	}
	for _, c := range []string{treeNoCause, treeStopped, treeNothing} {
		miss("顶层读数", c)
	}
	for _, s := range []string{treeAsked, treeNotAsked, treeSkipped, treeUnreadable, treeFailed} {
		miss("步骤状态", s)
	}
	for _, sym := range treeSymptoms {
		miss("症状", sym)
	}
	// 步骤的中文名由后端随结果一起给（stepName / causeName，见 treeNode.name）：
	// 界面不再存一份步骤表，所以这里只钉「它确实读的是那两栏」，
	// 而「每一步都有名字」由 TestTreeEveryNodeHasAName 钉着。
	for _, f := range []string{"stepName", "causeName"} {
		if !strings.Contains(js, f) {
			t.Errorf("界面没读结果里的 %s —— 那一栏会露出英文步骤 id", f)
		}
	}
	for _, plan := range TreePlans() {
		for _, ps := range plan.steps {
			for code := range ps.by {
				miss(plan.symptom+" 树「"+ps.node.id+"」那一步的判定码", code)
			}
		}
	}
}

// 不许出现空码分支（永远命中不了），也不许 by 和 other 都不给（走到就断）。
func TestTreeBranchesAreReachable(t *testing.T) {
	for _, plan := range TreePlans() {
		for _, s := range plan.steps {
			for code := range s.by {
				if code == "" {
					t.Errorf("%s：%s 有一条空码分支 —— 它永远不会命中", plan.symptom, s.node.id)
				}
			}
			if len(s.by) == 0 && s.decide == nil && s.other.next == "" && !s.other.end &&
				s.other.cause == "" {
				// 全空 = 按表的顺序往下走，线性路线里是有意这么写的。
				continue
			}
		}
	}
}

// ── 取值路径 ──

// toolValues 是每个工具**真的会给**的取值栏。★ 在这里抄一遍，
//
//	是为了让「树里读的那一栏根本不存在」在测试里就红，
//	而不是等到现场跑出一堆 unreadable 才发现。红了之后先想清楚是哪一边错：
//	是工具改了形状，还是树本来就读错了。
var toolValues = map[string][]string{
	"net.checkup":         {"first", "items"},
	"net.routes":          {"count", "multiDefault", "defaults", "decision"},
	"net.ping.watch":      {"lossPercent", "sent", "recv", "jitterAvgMs", "rttMaxMs", "spikes", "lostAt"},
	"net.dns.query":       {"answers", "server", "elapsedMs", "rcode"},
	"net.dualstack.check": {"eyeballs", "v4", "v6"},
	"net.trace":           {"traces", "engine", "families"},
	"net.mtr":             {"reports", "families"},
	"net.ping":            {"sent", "received", "lossPercent", "rttAvgMs"},
	"net.tcp.probe":       {"target", "elapsedMs"},
	"net.ports.scan":      {"open", "closed", "filtered", "scanned", "openPorts"},
	"net.subnet.scan":     {"hosts", "alive", "asked", "onLink", "subnets", "noSignal", "skippedSelf", "tcpProbed"},
	"net.tls.check":       {"notAfter", "notBefore", "issuer", "subject", "protocol", "daysLeft"},
	"net.http.probe":      {"status", "timings", "url"},
	"net.time.check":      {"offsetMs", "checkedWith", "agreeSources", "attribution"},
	"net.mtu.path":        {"pathMtu", "suggestion", "egress", "egressUnknown", "carriesAtLeast", "localMtuLimited", "steps", "warning", "dfVerified"},
	"media.rtsp.probe":    {"codec", "width", "height", "trackCount", "status"},
	"media.onvif.info":    {"manufacturer", "model", "profileCount", "mediaUri", "steps"},
}

func TestTreeShowsPathsExist(t *testing.T) {
	for _, p := range TreePlans() {
		for _, s := range p.steps {
			list, ok := toolValues[s.node.tool]
			if !ok {
				t.Errorf("树里问了 %q，这张表里没有它的取值清单", s.node.tool)
				continue
			}
			for _, path := range s.node.shows {
				if !strings.HasPrefix(path, "values.") {
					t.Errorf("%s 的取值路径 %q 不是从 values 起的", s.node.id, path)
					continue
				}
				head := strings.SplitN(strings.TrimPrefix(path, "values."), ".", 2)[0]
				if i := strings.Index(head, "["); i >= 0 {
					head = head[:i]
				}
				var hit bool
				for _, k := range list {
					if k == head {
						hit = true
					}
				}
				if !hit {
					t.Errorf("%s 读 %q，但 %s 给不出这一栏（清单：%s）",
						s.node.id, path, s.node.tool, strings.Join(list, " / "))
				}
			}
		}
	}
}

func TestTreeDig(t *testing.T) {
	m := map[string]any{
		"a": map[string]any{"b": []any{
			map[string]any{"c": "one"},
			map[string]any{"c": "two"},
		}},
	}
	if v, ok := digStr(m, "a.b[0].c"); !ok || v != "one" {
		t.Errorf("a.b[0].c = %v %v", v, ok)
	}
	if v, ok := digStr(m, "a.b[last].c"); !ok || v != "two" {
		t.Errorf("a.b[last].c = %v %v", v, ok)
	}
	if _, ok := digStr(m, "a.b[9].c"); ok {
		t.Error("越界下标不该取到值")
	}
	if _, ok := digStr(m, "nope.here"); ok {
		t.Error("不存在的键不该取到值")
	}
	if k := lastKey("values.traces[last].hopsSeen"); k != "hopsSeen" {
		t.Errorf("lastKey = %q", k)
	}
	if n, ok := num(map[string]any{"a": map[string]any{"b": 4.0}}, "a.b"); !ok || n != 4 {
		t.Errorf("num = %v %v，想要 4", n, ok)
	}
}

// ── 「同一项坏了」的几种坏法必须分开说 ──

// fakeCheckupIface 让体检在网卡那一步给出一个具体的坏法。
func fakeCheckupIface(code string) map[string]any {
	return map[string]any{
		"first": stepIface,
		"items": []any{map[string]any{"step": stepIface, "code": code, "severity": "bad"}},
	}
}

// 网卡开着、链路没起来：查线，不是查配置。★ 和「一块在用的网卡都没有」
// 差着一次出差 —— 后者要动这台机器，前者要去摸那个柜子。
func TestTreeLinkDownIsNotNoInterface(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topBrokenIface}
	tr := fakeTools(t, codes, map[string]map[string]any{"net.checkup": fakeCheckupIface("no-link")})
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	if v.Code != "cause-link-down" {
		t.Fatalf("顶层 = %s，想要 cause-link-down", v.Code)
	}
	if !strings.Contains(v.Note, "本机过一遍") {
		t.Errorf("note 没点名停在哪一步（中文）：%q", v.Note)
	}
	if tr["net.routes"].calls != 0 {
		t.Error("停在网卡了还去问路由表")
	}
}

// 链路好了却没地址：那是 DHCP / RA 那一头的事，又是另一双手。
func TestTreeLinkUpButNoAddress(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topBrokenIface}
	fakeTools(t, codes, map[string]map[string]any{"net.checkup": fakeCheckupIface("no-address")})
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	if v.Code != "cause-no-address" {
		t.Fatalf("顶层 = %s，想要 cause-no-address", v.Code)
	}
}

// 一个坏法都没给（items 缺栏）时回落到最保守的那条：不许凭空挑一种。
func TestTreeIfaceWithoutItemCodeFallsBack(t *testing.T) {
	codes := everythingOK()
	codes["net.checkup"] = []string{topBrokenIface}
	fakeTools(t, codes, map[string]map[string]any{"net.checkup": {"first": stepIface}})
	v := runTree(t, treeArgs{Symptom: symNoInternet})
	if v.Code != "cause-no-interface" {
		t.Fatalf("顶层 = %s，想要 cause-no-interface", v.Code)
	}
}

// 证书「还没生效」+ 钟是好的：那就是真没到点，不许再赖本机时钟。
// ★ 混起来的代价是反的 —— 让人去改自己主机的时间，而证书确实还没到有效期。
func TestTreeCertNotYetValidWithFineClock(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{certNotYetValid}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.tls.check":  {"notBefore": "2026-09-25T11:00:00Z"},
		"net.time.check": {"localTime": "2026-09-25T10:00:00Z", "offsetMs": 60000.0}, // 慢一分钟
	})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	if v.Code != "cause-cert-not-yet-valid" {
		t.Fatalf("顶层 = %s，想要 cause-cert-not-yet-valid（钟只差一分钟，冤枉不到它）", v.Code)
	}
}

// 同一个「还没生效」，钟慢两小时就翻成钟的锅：按标准时刻证书已经生效了。
func TestTreeCertNotYetValidMadeBySlowClock(t *testing.T) {
	codes := everythingOK()
	codes["net.tls.check"] = []string{certNotYetValid}
	codes["net.time.check"] = []string{timeSkewed}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":  answers("203.0.113.9"),
		"net.tls.check":  {"notBefore": "2026-09-25T11:00:00Z"},
		"net.time.check": {"localTime": "2026-09-25T10:00:00Z", "offsetMs": 7200000.0}, // 慢两小时
	})
	v := runTree(t, treeArgs{Symptom: symCert, Target: "video.example"})
	if v.Code != "cause-clock-made-cert-bad" {
		t.Fatalf("顶层 = %s，想要 cause-clock-made-cert-bad", v.Code)
	}
}

// 「设备应了但一轨都没有」不能算成「流是好的」：那会把人送去查下游。
func TestTreeStreamHasNoMediaTrack(t *testing.T) {
	codes := everythingOK()
	codes["media.rtsp.probe"] = []string{verdictStreamNoMed}
	fakeTools(t, codes, map[string]map[string]any{
		"net.dns.query":    answers("192.0.2.31"),
		"net.subnet.scan":  hostFound("192.0.2.31", evICMP),
		"net.ports.scan":   {"open": 1},
		"media.rtsp.probe": {"status": "200"},
	})
	v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31", URL: "rtsp://192.0.2.31/live"})
	if v.Code != "cause-stream-broken" {
		t.Fatalf("顶层 = %s，想要 cause-stream-broken", v.Code)
	}
}

// 取流那一步「连不上」和「接了却不回 RTSP」是两种病：前者是口被拦，后者是端口号错了。
func TestTreeStreamUnreachableVersusWrongPort(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{
		{verdictRTSPUnreach, "cause-service-filtered"},
		{verdictNoResponse, "cause-port-not-rtsp"},
	} {
		codes := everythingOK()
		codes["media.rtsp.probe"] = []string{tc.code}
		fakeTools(t, codes, map[string]map[string]any{
			"net.dns.query":    answers("192.0.2.31"),
			"net.subnet.scan":  hostFound("192.0.2.31", evICMP),
			"net.ports.scan":   {"open": 1},
			"media.rtsp.probe": {"status": "200"},
		})
		v := runTree(t, treeArgs{Symptom: symDeviceDown, Target: "192.0.2.31", URL: "rtsp://192.0.2.31/live"})
		if v.Code != tc.want {
			t.Errorf("%s 停在 %s，想要 %s", tc.code, v.Code, tc.want)
		}
	}
}

// ★ 登记处不许留「树里到不了的根因码」：那种码一被人读到就是编的。
//
//	这里按源码字面查码名 —— 走法表改了没同步登记处（或者登记了一条树里到不了的），
//	测试就得响。具体停得对不对，由上面每一条分支的行为测试钉着。
func TestTreeEveryCauseIsReachable(t *testing.T) {
	b, err := os.ReadFile("trees.go")
	if err != nil {
		t.Fatalf("读不到走法表，这一项就等于没查：%v", err)
	}
	src := string(b)
	for _, c := range TreeCauses() {
		if !strings.Contains(src, `"`+c+`"`) {
			t.Errorf("根因码 %s 登记了却没有任何一步会停在它上面 —— 要么接进树里，要么删掉", c)
		}
	}
}
