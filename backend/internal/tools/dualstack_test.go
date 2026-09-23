package tools

import "testing"

// ★ 这两个函数把「只有老手会做的判断」变成了码，是这一页的招牌价值，
//   所以逐条钉死：判定码选择、Happy Eyeballs 模拟。都是纯函数，不碰网络。

func fam(addr, route bool, egress string) familyResult {
	return familyResult{HasAddress: addr, HasRoute: route, Egress: egress}
}

func TestTopCode(t *testing.T) {
	cases := []struct {
		name   string
		v4, v6 familyResult
		want   string
	}{
		{"两族都没有地址和路由", fam(false, false, ""), fam(false, false, ""), dsNoAddress},
		{"两族都能出外网", fam(true, true, verdictOpen), fam(true, true, verdictOpen), dsDualHealthy},
		{"★招牌：v4 通、v6 出不了外网", fam(true, true, verdictOpen), fam(true, true, verdictFiltered), dsV6EgressBroken},
		{"v6 通、v4 出不了外网", fam(true, true, verdictClosed), fam(true, true, verdictOpen), dsV4EgressBroken},
		{"两族都有地址但都出不去", fam(true, true, verdictFiltered), fam(true, true, verdictNoReply), dsBothEgressBroken},
		{"只有 v4 且能出去", fam(true, true, verdictOpen), fam(false, false, ""), dsV4Only},
		{"只有 v4 但出不去", fam(true, true, egressNoRoute), fam(false, false, ""), dsSingleNoEgress},
		{"只有 v6 且能出去", fam(false, false, ""), fam(true, true, verdictOpen), dsV6Only},
		{"v6 只有路由没地址（VPN）也算在场，出不去→单族无出口",
			fam(false, false, ""), fam(false, true, verdictFiltered), dsSingleNoEgress},
	}
	for _, c := range cases {
		if got := topCode(c.v4, c.v6); got != c.want {
			t.Errorf("%s：想要 %s，拿到 %s", c.name, c.want, got)
		}
	}
}

func TestEyeballs(t *testing.T) {
	dom := func(a, aaaa []addrAttempt) domainResult {
		d := domainResult{A: []addrAttempt{}, AAAA: []addrAttempt{}}
		if a != nil {
			d.A = a
		}
		if aaaa != nil {
			d.AAAA = aaaa
		}
		return d
	}
	// 每族 connDelay 用 250
	const cd = int64(250)

	// v6 又快又通：应用直接用 v6，不卡
	r := eyeballs(dom([]addrAttempt{{Addr: "1.1.1.1", Code: verdictOpen, RTTMs: 10}},
		[]addrAttempt{{Addr: "2606::1", Code: verdictOpen, RTTMs: 12}}), cd)
	if r.Code != dsEyeballsOK || r.Winner != "ipv6" || r.WillStall {
		t.Errorf("v6 快通该 ok 且不卡，拿到 %+v", r)
	}

	// ★ 招牌：v6 被静默丢包（filtered）、v4 能连 —— 应用会先在 v6 上卡一下再回落
	r = eyeballs(dom([]addrAttempt{{Addr: "1.1.1.1", Code: verdictOpen, RTTMs: 20}},
		[]addrAttempt{{Addr: "2606::1", Code: verdictFiltered, RTTMs: 3000}}), cd)
	if r.Code != dsEyeballsStall || !r.WillStall || r.Winner != "ipv4" {
		t.Errorf("v6 卡住该判 stall、回落到 v4，拿到 %+v", r)
	}
	if r.StallMs <= cd {
		t.Errorf("HE 应用的卡顿时间该 ≥ connDelay+连接耗时，拿到 %d", r.StallMs)
	}
	if r.WorstMs < 3000 {
		t.Errorf("不守 HE 的应用最坏该卡到 v6 超时(3000)，拿到 %d", r.WorstMs)
	}

	// v6 通但慢、v4 通且快：HE 并行起 v4，谁快用谁 → winner v4，仍判 ok（不是卡）
	r = eyeballs(dom([]addrAttempt{{Addr: "1.1.1.1", Code: verdictOpen, RTTMs: 10}},
		[]addrAttempt{{Addr: "2606::1", Code: verdictOpen, RTTMs: 900}}), cd)
	if r.Code != dsEyeballsOK || r.Winner != "ipv4" {
		t.Errorf("v6 慢 v4 快该并行赢在 v4，拿到 %+v", r)
	}

	// 只有 A 记录：没得选，单栈
	r = eyeballs(dom([]addrAttempt{{Addr: "1.1.1.1", Code: verdictOpen, RTTMs: 10}}, nil), cd)
	if r.Code != dsEyeballsSingle || r.Winner != "ipv4" {
		t.Errorf("只有 A 该判 single/ipv4，拿到 %+v", r)
	}

	// 只有 AAAA 记录且连不上：两族都没连成，判 fail
	r = eyeballs(dom(nil, []addrAttempt{{Addr: "2606::1", Code: verdictFiltered, RTTMs: 2000}}), cd)
	if r.Code != dsEyeballsFail {
		t.Errorf("只有坏掉的 AAAA 该判 fail，拿到 %+v", r)
	}

	// 什么都没有（解析没出地址）
	if r := eyeballs(dom(nil, nil), cd); r.Code != dsEyeballsFail {
		t.Errorf("无记录该 fail，拿到 %+v", r)
	}
}

// TestReconcileEgress 钉住现场最重要的一条：固定出口探测点被单独拦掉时，
// 域名的连接证据必须把它翻回「通」，否则招牌场景会被误诊成「两族都坏」。
func TestReconcileEgress(t *testing.T) {
	// 现场真发生过的样子：1.1.1.1 被这个网络丢弃，但域名的 A 记录连上了（v4 其实正常），
	// AAAA 全连不上（v6 真的坏了）→ 修正后应为 v6-egress-broken。
	v4 := fam(true, true, verdictFiltered)
	v4.EgressTarget = "1.1.1.1:443"
	v6 := fam(true, true, egressError)
	v6.EgressTarget = "[2606:4700:4700::1111]:443"
	d := domainResult{
		Port: 443,
		A:    []addrAttempt{{Addr: "104.16.1.1", Code: verdictOpen, RTTMs: 487}, {Addr: "104.16.1.2", Code: verdictOpen, RTTMs: 493}},
		AAAA: []addrAttempt{{Addr: "2606:4700::1", Code: egressError}},
	}
	reconcileEgress(&v4, &v6, d)

	if !v4.egressOK() {
		t.Errorf("域名 v4 连接成功，出口必须判 open，拿到 %s", v4.Egress)
	}
	if v4.EgressRTTMs != 487 || v4.EgressTarget != "104.16.1.1:443" {
		t.Errorf("该取最快的那条证据，拿到 %d %s", v4.EgressRTTMs, v4.EgressTarget)
	}
	if v6.egressOK() {
		t.Error("AAAA 一个都没连上，v6 不许被翻成通")
	}
	if got := topCode(v4, v6); got != dsV6EgressBroken {
		t.Errorf("修正后顶层该是招牌码 v6-egress-broken，拿到 %s", got)
	}

	// 已经判通的不动它
	already := fam(true, true, verdictOpen)
	already.EgressTarget, already.EgressRTTMs = "1.1.1.1:443", 8
	reconcileEgress(&already, &familyResult{}, domainResult{Port: 443,
		A: []addrAttempt{{Addr: "104.16.1.1", Code: verdictOpen, RTTMs: 900}}})
	if already.EgressTarget != "1.1.1.1:443" || already.EgressRTTMs != 8 {
		t.Errorf("本来就通的该保持原样，拿到 %+v", already)
	}

	// 这一族不在场：不该被域名证据凭空点亮
	absent := fam(false, false, egressSkipped)
	reconcileEgress(&absent, &familyResult{}, d)
	if absent.Egress != egressSkipped {
		t.Errorf("不在场的族别乱改，拿到 %s", absent.Egress)
	}

	// 域名也没连上：保持原来的失败判定（诚实，不硬拗成通）
	none := fam(true, true, verdictFiltered)
	reconcileEgress(&none, &familyResult{}, domainResult{Port: 443,
		A: []addrAttempt{{Addr: "104.16.1.1", Code: verdictFiltered, RTTMs: 2500}}})
	if none.Egress != verdictFiltered {
		t.Errorf("没有任何连接证据时不许改判，拿到 %s", none.Egress)
	}
}
