package flow

// 流一层的判定：跨报文才看得出来的那几种。
//
// 报文一层的判定说的是「这一包怎么这样」，而现场问的是「这条路走通没有」：
// 「SETUP 回了 200 却一直没 PLAY」「REGISTER 连着两个 401」「CONNECT 发出去 CONNACK 没回来」
// 全都要在两条以上的报文之间比才看得出来。只看单包的工具会把这三种一起答成「报文都正常」，
// 而那正是「表上什么都没写，所以一定是设备的问题」这种误判的来源。
//
// ★ 这一层只说序号与状态码比出来的事，不猜原因：猜「十有八九是密码错」这种话
// 会把人支去改对不该改的地方。该说的上限是「同一个 CSeq 又问了一遍、回的还是 401」。

import (
	"fmt"
	"strings"
)

// concludeRTP 把每一路（按 SSRC）的序号账说成判定。
func (fl *Flow) concludeRTP() {
	for _, r := range fl.RTP {
		who := fl.A
		if r.Dir != 0 {
			who = fl.B
		}
		head := fmt.Sprintf("%s 发出的那一路（SSRC %08x，%d 包）", who, r.SSRC, r.Packets)
		if pct := r.LossPercent(); pct > 0 {
			fl.addFinding("rtp-loss", r.Last, fmt.Sprintf(
				"%s：按序号估丢 %.2f%%（收了 %d / 该有 %d，空位 %d 处）。%s",
				head, pct, r.Received(), r.Expected(), r.Gaps, rtpLossGrade(pct)))
		}
		if r.Jumps > 0 {
			fl.addFinding("rtp-seq-jump", r.Last, fmt.Sprintf(
				"%s：见到 %d 处序号大跳（跳过 %d 个号）。★这一格没算进丢包数："+
					"真丢一大片与「换了源 / 序号从头来」在包上长得一模一样，说成丢包就是没证实的话",
				head, r.Jumps, r.JumpSpan))
		}
		if r.Reorder > 0 {
			fl.addFinding("rtp-reorder", r.Last, fmt.Sprintf(
				"%s：%d 包到晚了（序号比已见的最高值小）。有的网卡两条队列本来就保不齐序，"+
					"这一格与丢包率一起看才知道要不要管", head, r.Reorder))
		}
		if r.Dupes > 0 {
			fl.addFinding("rtp-dup", r.Last, fmt.Sprintf(
				"%s：%d 包与上一包同号（重复）：链路重发、或有人在往同一路推第二份", head, r.Dupes))
		}
	}
	if fl.RTPSkipped > 0 {
		fl.addNote(fmt.Sprintf("这一条上 SSRC 多到 %d 个的上限，后面 %d 包没记账：不再往上加，也不假装数完了",
			maxRTPSources, fl.RTPSkipped))
	}
}

// rtpLossGrade 给一个量级的说法，但不藏数：数已经在句子里了，这一句只说「这个量意味着什么」。
//
// 为什么不设「报不报」的门槛：设了就等于把 0.3% 那种「有时候卡一下」的案底抹掉，
// 而现场要的恰恰是这一档。
func rtpLossGrade(pct float64) string {
	switch {
	case pct < 0.1:
		return "量很小：音频上一般听不出来，视频上多半看不出条纹"
	case pct < 1:
		return "量不大，但视频在快速运动时会开始出条纹、音频会偶发爆音"
	case pct < 5:
		return "这个量画面就会明显受损（马赛克、卡顿），得往「谁在丢」那一步查"
	default:
		return "丢得不少：这条链路当下承载不了这一路，先查带宽与无线质量，再谈设备"
	}
}

// concludeApp 跨报文比那几种形状。
//
// ★ 计数一律分清「请求」与「回包」：把一条 200 和它答的那次询问数成两次，
// 「发了 3 次 REGISTER」就变成了 6 次；而 RTSP 的回包行里根本没有方法名，
// 只能靠 CSeq 跟请求配上，不然「SETUP 成了 0 次」会是常态误判。
func (fl *Flow) concludeApp() {
	var (
		setupOK, playOK, playSeen, teardown int
		authFails, authed                   int
		connects, connacks                  int
		registers, registerReplies          int
		register401s, registerOKs           int
		keepalives, messageReplies          int
		invites, inviteReplies              int
		transport                           string // 最后一次 Transport/Server-Transport 说的走法
	)
	// 回包的方法名由 emit 那一步按 CSeq 补进 m.Method（见 app_emit.go），这里只管数。
	hasRTP := len(fl.RTP) > 0

	for i := range fl.Messages {
		m := &fl.Messages[i]
		if m.Transport != nil && m.Transport.Kind != "" {
			transport = m.Transport.Kind
		}
		switch m.Proto {
		case "rtsp", "http", "onvif", "soap":
			switch m.Status {
			case 401, 407:
				authFails++
			case 200:
				authed++
			}
			switch strings.ToUpper(m.Method) {
			case "SETUP":
				if m.Status == 200 {
					setupOK++
				}
			case "PLAY":
				if m.Kind == "request" {
					playSeen++
				}
				if m.Status == 200 {
					playOK++
				}
			case "TEARDOWN":
				teardown++
			}
		case "sip":
			// SIP 回包的方法由 decodeSIP 从 CSeq 补进 m.Method，这里直接分流数。
			if m.Kind == "request" {
				switch m.Method {
				case "REGISTER":
					registers++
				case "INVITE":
					invites++
				case "MESSAGE":
					if strings.EqualFold(m.CmdType, "keepalive") {
						keepalives++
					}
				}
				break
			}
			switch m.Method {
			case "REGISTER":
				registerReplies++
				switch {
				case m.Status == 401:
					register401s++
					authFails++
				case m.Status >= 200 && m.Status < 300:
					registerOKs++
					authed++
				}
			case "MESSAGE":
				// ★ 只看得出「答的是 MESSAGE」，答的是 Keepalive 还是 Catalog 看不出来
				//（回包正文通常不带 MANSCDP）。所以这里只数总回包，
				// 判定也只敢在「一条 MESSAGE 回包都没有」时下。
				messageReplies++
			case "INVITE":
				inviteReplies++
			}
		case "mqtt":
			if strings.EqualFold(m.Method, "CONNECT") {
				connects++
			}
			if strings.EqualFold(m.Method, "CONNACK") {
				connacks++
			}
		}
	}

	switch {
	case setupOK > 0 && playSeen == 0 && teardown == 0:
		fl.addFinding("rtsp-setup-no-play", fl.Last, fmt.Sprintf(
			"SETUP 成了 %d 次，之后既没有 PLAY 也没有 TEARDOWN：会话建起来了却没人要流。"+
				"这一种通常是取流的那一端在 SETUP 之后自己卡住或退出了，不是相机不回话", setupOK))
	case playOK > 0 && !hasRTP && transport != "udp":
		fl.addFinding("rtsp-play-no-rtp", fl.Last, fmt.Sprintf(
			"PLAY 成功 %d 次，这一条流上却没见到一个 RTP 包；协商走的是 %s。"+
				"走 TCP 复用还一个包都没有，就是设备端没往这条连接里复画面，不是「看的人没收到」",
			playOK, transportLabel(transport)))
	case playOK > 0 && !hasRTP && transport == "udp":
		// 这不是问题，是账不在这儿：说成判定会把人支去找一条根本不存在的丢包。
		fl.addNote("PLAY 成功了，但协商走 UDP：画面不在这条流上，去那条 RTP 流看（信令与媒体分家是 RTSP 的正常形状）")
	}
	if authFails >= 2 && authed == 0 {
		fl.addFinding("auth-loop", fl.Last, fmt.Sprintf(
			"同一条流上 %d 次「要认证」（401/407），一次都没通过：这是口令或身份对不上，"+
				"不是网络不通（网络不通的表现是没有人回，而不是回 401）", authFails))
	}
	if register401s >= 2 && registerOKs == 0 {
		fl.addFinding("gb28181-register-auth-loop", fl.Last, fmt.Sprintf(
			"REGISTER 被回 %d 次 401 且没有一次成功：国标的注册口令、"+
				"或者设备编号/平台编号（SIP URI 里那两段）对不上。这一条与「网络不通」是两件事，"+
				"能收到 401 说明路是通的", register401s))
	}
	if registers > 0 && registerReplies == 0 {
		fl.addFinding("gb28181-register-no-reply", fl.Last, fmt.Sprintf(
			"发了 %d 次 REGISTER，平台一个回包都没有：信令端口没人接（地址、端口或防火墙），"+
				"与口令错是两种下一步", registers))
	}
	if keepalives > 0 && messageReplies == 0 {
		fl.addFinding("gb28181-keepalive-no-reply", fl.Last, fmt.Sprintf(
			"设备发了 %d 条保活（Keepalive），%s 连一条 MESSAGE 回包都没有：它在喊，平台没答。"+
				"离线判定是平台侧做的，这一条上去查平台收没收，而不是查相机", keepalives, fl.B))
	}
	if connects > 0 && connacks == 0 {
		fl.addFinding("mqtt-connect-no-connack", fl.Last, fmt.Sprintf(
			"发了 %d 次 CONNECT，一次 CONNACK 都没回来：★这跟「回了 5（拒绝）」是两件事 ——"+
				"没回是端口没人接或半道被挡，回了 5 才是口令/授权不对", connects))
	}
	if invites > 0 && inviteReplies == 0 {
		fl.addFinding("sip-invite-no-reply", fl.Last, fmt.Sprintf(
			"INVITE 发了 %d 次，%s 一个回包都没有（连 Trying 都没有）：信令端口没接，"+
				"或者中间把那一个方向的 UDP 丢了", invites, fl.B))
	}
}

// transportLabel 把协商那一格说成人的走法；空 = 这一条里没见过 Transport 头，只能说「没写」。
func transportLabel(kind string) string {
	switch kind {
	case "udp":
		return "UDP 分流（画面在另一条流上）"
	case "tcp-interleaved":
		return "TCP 复用（interleaved，画面就该在这条流上复出来）"
	default:
		return "没写明的一种（Transport 头里没给走法）"
	}
}
