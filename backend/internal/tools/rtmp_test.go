package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/media/rtmptest"
	"net.yuhox.com/netkit/internal/ots"
)

// callRTMP 走的是界面那条路：JSON 参数进、判定出。
//
// ★ 不直接调 probeRTMP 的内部函数 —— 这一层要验的是「工具被这么问一句，
//
//	落到哪个判定、那份账带没带对」，绕开入口等于验了另一码事。
func callRTMP(t *testing.T, args map[string]any) (ots.Verdict, string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rtmpProbeTool.Invoke(t.Context(), raw)
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

func rtmpURL(s *rtmptest.Server, path string) string {
	return fmt.Sprintf("rtmp://%s:%d/%s", s.Host(), s.Port(), path)
}

// startFake 起一台假服务器，并把「查它收过什么命令」的收尾一起放进去。
//
// ★ 每一种模式都验一遍这条：探测离「往别人服务器上挂了一路流」只差一条命令。
func startFake(t *testing.T, mode string, tweak func(*rtmptest.Server)) *rtmptest.Server {
	t.Helper()
	s, err := rtmptest.StartConfigured(mode, tweak)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		joined := strings.Join(s.Commands(), ",")
		for _, forbidden := range []string{"publish", "FCPublish", "releaseStream", "deleteStream"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("%s 模式下探测发出了 %s —— 那是改动，不是问话（收到：%v）", mode, forbidden, s.Commands())
			}
		}
		if e := s.Err(); e != "" {
			t.Errorf("%s 模式下假服务器自己先出错了（那不是探测的判定）：%s", mode, e)
		}
		s.Close()
	})
	return s
}

func wantCode(t *testing.T, v ots.Verdict, blob, code string) {
	t.Helper()
	if v.Code != code {
		t.Fatalf("判定 = %s（%s），想要 %s\n整包：%s", v.Code, v.Note, code, blob)
	}
}

func intVal(v ots.Verdict, key string) (int, bool) {
	n, ok := v.Values[key].(int)
	return n, ok
}

// ── 十二个判定，一档一个模式 ──

func Test一路在推并且量出码率(t *testing.T) {
	s := startFake(t, rtmptest.ModeOK, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 1200})
	wantCode(t, v, blob, verdictRTMPOk)
	for _, k := range []string{"mediaBytes", "audioBytes", "videoBytes", "bitrateKbps",
		"bitrateBasis", "playCode", "server", "declaredWidth", "declaredVideoKbps"} {
		if v.Values[k] == nil {
			t.Errorf("判定说是「在推」，可账上少了 %s：%s", k, blob)
		}
	}
	if v.Values["playCode"] != "NetStream.Play.Start" {
		t.Errorf("play 的回包不对：%v", v.Values["playCode"])
	}
	// 元数据排在媒体前面：声明的那份分辨率是从 onMetaData 读的，不是猜出来的
	if v.Values["declaredWidth"] != 1920 || v.Values["declaredHeight"] != 1080 {
		t.Errorf("声明分辨率读错了：%v×%v", v.Values["declaredWidth"], v.Values["declaredHeight"])
	}
	if v.Values["declaredVideoCodec"] != "h264" {
		t.Errorf("视频编码编号没认出来：%v", v.Values["declaredVideoCodec"])
	}
	if v.Values["metadataSeen"] != true {
		t.Errorf("元数据没被数到（界面要分得开「在推」和「在推而且报了多大」）：%s", blob)
	}
	mb, _ := intVal(v, "mediaBytes")
	if want := s.MediaBurst * s.MediaSize; mb < want {
		t.Errorf("窗口里的媒体字节 %d 比假服务器发出来的 %d 少 —— 有消息没被数进去", mb, want)
	}
	// 码率与那份账必须同口径：字节 ÷ 真读了多久
	if kb, ok := intVal(v, "bitrateKbps"); ok {
		obsMs, _ := v.Values["observedMs"].(int64)
		wantKbps := float64(mb) * 8 / 1000 / (float64(obsMs) / 1000)
		if kb < int(wantKbps*0.9) || kb > int(wantKbps*1.1)+1 {
			t.Errorf("码率 %d kbps 与「%d 字节 ÷ %d 毫秒」算出的 %.0f 对不上：%s",
				kb, mb, obsMs, wantKbps, blob)
		}
	} else {
		t.Errorf("码率那一格不是整数：%v", v.Values["bitrateKbps"])
	}
}

func Test码率除以的是真读了多久(t *testing.T) {
	// 窗口要 3 秒，可字节只在前 ~400 毫秒到完，紧接着它就把连接断了。
	// 按 3 秒除是 21 kbps，按真读了多久除是 160 kbps 上下 —— 差一个数量级。
	s := startFake(t, rtmptest.ModeCloseAfterMedia, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 3000})
	wantCode(t, v, blob, verdictRTMPOk)
	kbps, ok := intVal(v, "bitrateKbps")
	if !ok || kbps < 120 || kbps > 220 {
		t.Errorf("码率 %v kbps 不在 120~220（每条 1000 字节、间隔 50 毫秒 = 160 kbps）——"+
			"分母八成用了想要的那 3 秒：%s", v.Values["bitrateKbps"], blob)
	}
	if v.Values["observedShort"] != true {
		t.Errorf("没读满窗口却没标 observedShort，这个码率看着像读满了的：%s", blob)
	}
}

func Test声明的码率与实测差得远要写在判定里(t *testing.T) {
	s := startFake(t, rtmptest.ModeOK, func(x *rtmptest.Server) { x.MediaBurst = 1 })
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 1000})
	wantCode(t, v, blob, verdictRTMPOk) // 「到了」是真话，判定不该改
	if !strings.Contains(v.Note, "★") || !strings.Contains(v.Note, "2000") {
		t.Errorf("「在推」这句里没带上声明与实测的落差：%s\n%s", v.Note, blob)
	}
}

func Test说有这路可一个字节都没到(t *testing.T) {
	s := startFake(t, rtmptest.ModeNoMedia, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPNoMedia)
	if v.Values["playCode"] != "NetStream.Play.Start" {
		t.Errorf("这一档要说清「它答应了」，可回包没留下：%s", blob)
	}
	// ★ 窗口太短时的「没在推」是我们没问出来，不是它真没有 —— 这句必须自己承认。
	if !strings.Contains(v.Note, "太短") {
		t.Errorf("800 毫秒的窗口，note 却没说这一条不能当结论：%s", v.Note)
	}
	if strings.Contains(blob, `"bitrateKbps"`) {
		t.Errorf("零字节也去除了个码率，那是凭空造数：%s", blob)
	}
}

func Test窗口够长时不必自我保留(t *testing.T) {
	s := startFake(t, rtmptest.ModeNoMedia, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 1500})
	wantCode(t, v, blob, verdictRTMPNoMedia)
	if strings.Contains(v.Note, "太短") {
		t.Errorf("1.5 秒的窗口不该再写「太短」—— 问了这么久没字节就是没在推：%s\n%s", v.Note, blob)
	}
}

func Test这个名字上根本没有流(t *testing.T) {
	s := startFake(t, rtmptest.ModeNotFound, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/typo"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPStreamAbsent)
	if !strings.Contains(fmt.Sprint(v.Values["playCode"]), "StreamNotFound") {
		t.Errorf("流名错的证据没留下：%s", blob)
	}
	if !strings.Contains(v.Note, "流名") {
		t.Errorf("这一档的下一步就是回去核流名，note 得说到：%s", v.Note)
	}
}

func Test名字认得可此刻没人推(t *testing.T) {
	s := startFake(t, rtmptest.ModeStreamGone, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPNotPublishing)
	// ★ 与「名字上没有」分开：这一档要去看推流端，那一档要改地址。
	if strings.Contains(v.Note, "多半写错") {
		t.Errorf("把「没人推」说成了「名字写错」，方向反了：%s", v.Note)
	}
	if codes, _ := v.Values["statusCodes"].([]string); len(codes) == 0 {
		t.Errorf("整条连接上收到过的状态码没留下：%s", blob)
	}
}

func Test没给流名时不许写成这路没问题(t *testing.T) {
	s := startFake(t, rtmptest.ModeOK, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPAppAccepted)
	if !strings.Contains(v.Note, "根本没问") {
		t.Errorf("「没问到」必须和「问了没问题」分开：%s", v.Note)
	}
	for _, c := range s.Commands() {
		if c == "play" || c == "createStream" {
			t.Errorf("没给流名却替调用方猜了一个流去问：%v", s.Commands())
		}
	}
	if strings.Contains(blob, `"mediaBytes"`) {
		t.Errorf("这一问根本没观测媒体，不该带媒体的账：%s", blob)
	}
}

func Test应用被拒(t *testing.T) {
	s := startFake(t, rtmptest.ModeRejected, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "wrongapp/cam1"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPAppRejected)
	if v.Values["connectReply"] != "onStatus" || v.Values["connectLevel"] != "error" {
		t.Errorf("connect 的回包没留在账上：%s", blob)
	}
	// 被拒之后就不该再往下走：后面那两条命令发出去只是给这台添活。
	for _, c := range s.Commands() {
		if c == "play" || c == "createStream" {
			t.Errorf("connect 都被拒了还发 %s：%v", c, s.Commands())
		}
	}
}

func Test只肯收推流的服务器(t *testing.T) {
	s := startFake(t, rtmptest.ModePublishOnly, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPAppRejected)
	if !strings.Contains(blob, "only accepts publishers") {
		t.Errorf("它说的那句理由该留下：%s", blob)
	}
}

func Test被拒的理由是缺口令(t *testing.T) {
	s := startFake(t, rtmptest.ModeAuth, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPAuth)
	if !strings.Contains(v.Note, "凭据") {
		t.Errorf("这一档的下一步是去补 key，note 得说到：%s", v.Note)
	}
}

// 各家拒绝理由的措辞千奇百怪：判成「要口令」还是「应用不对」不能只对着一种文案验。
func Test拒绝措辞换个说法也一样认(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"password error, tcUrl=rtmp://1.2.3.4:1935/live/cam1", verdictRTMPAuth},
		{"signature mismatch", verdictRTMPAuth},
		{"token expired", verdictRTMPAuth},
		{"denied by on_publish", verdictRTMPAuth},
		{"app 'live' not found", verdictRTMPAppRejected},
		{"stream exists but no publisher", verdictRTMPAppRejected},
	} {
		s := startFake(t, rtmptest.ModeRejected, func(x *rtmptest.Server) { x.RejectText = tc.text })
		v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 600})
		if v.Code != tc.want {
			t.Errorf("拒绝理由 %q 判成 %s，想要 %s\n整包：%s", tc.text, v.Code, tc.want, blob)
		}
	}
}

func Test握手通了可命令发出去不回话(t *testing.T) {
	s := startFake(t, rtmptest.ModeSilent, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "timeoutMs": 600})
	wantCode(t, v, blob, verdictRTMPCmdSilent)
	if v.Values["stage"] != "connect" {
		t.Errorf("没说清卡在哪一步（下一步要看是中间那台还是这台只肯收推流）：%s", blob)
	}
	if v.Values["handshakeMs"] == nil {
		t.Errorf("握手是通了的，这一格必须留下，不然与「端口不通」混成一句：%s", blob)
	}
}

func Test端口开着但回的不是RTMP(t *testing.T) {
	s := startFake(t, rtmptest.ModeJunk, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "timeoutMs": 900})
	wantCode(t, v, blob, verdictRTMPNotRTMP)
	if v.Values["looksLike"] != "http" {
		t.Errorf("只说「不是 RTMP」等于让人再猜一遍：%s", blob)
	}
	if v.Values["firstBytes"] == nil {
		t.Errorf("前几个字节没留下：%s", blob)
	}
}

func Test连上了可握手那一句到点没回(t *testing.T) {
	s := startFake(t, rtmptest.ModeHang, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "timeoutMs": 600})
	wantCode(t, v, blob, verdictRTMPTimeout)
	if v.Values["stage"] != "handshake" {
		t.Errorf("这一档与「命令不回话」的分别就在 stage 上：%s", blob)
	}
}

func Test刚问到一半它把连接断了(t *testing.T) {
	s := startFake(t, rtmptest.ModeCloseOnPlay, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 1500})
	wantCode(t, v, blob, verdictRTMPDropped)
	// ★ 断之前问到的要留着：「说要开始播然后就断」与「什么都没问到就断」是两种毛病。
	if v.Values["droppedAfter"] != "NetStream.Play.Start" {
		t.Errorf("断在哪儿没说清：%s", blob)
	}
	if !strings.Contains(v.Note, "NetStream.Play.Start") {
		t.Errorf("判定与它那句账不同源：%s\n%s", v.Note, blob)
	}
}

func Test口没开与没人答话分开(t *testing.T) {
	srv, err := rtmptest.Start(rtmptest.ModeOK)
	if err != nil {
		t.Fatal(err)
	}
	port := srv.Port()
	srv.Close()
	// 127.0.0.1 上没人监听会立刻回 RST：机器在、这个口没服务。
	v, blob := callRTMP(t, map[string]any{"url": fmt.Sprintf("rtmp://127.0.0.1:%d/live/cam1", port), "timeoutMs": 900})
	wantCode(t, v, blob, verdictRTMPUnreachable)
	if v.Values["reach"] != verdictClosed {
		t.Errorf("本机没人监听该判成 closed：%v\n%s", v.Values["reach"], blob)
	}
	if !strings.Contains(v.Note, "closed") {
		t.Errorf("note 没带上 reach 那一个词，界面上一句「连不上」就把分别抹掉了：%s", v.Note)
	}
}

// ── 凭据：只上线路，不进结果 ──

const (
	leakyParamKey  = "connectparamvalue9f2"
	leakyQueryKey  = "querykeyvalue7a1"
	leakyBasicPass = "basicauthpass4d3"
)

func Test口令只上线路不进结果(t *testing.T) {
	s := startFake(t, rtmptest.ModeOK, nil)
	u := fmt.Sprintf("rtmp://admin:%s@%s:%d/live/cam1?key=%s",
		leakyBasicPass, s.Host(), s.Port(), leakyQueryKey)
	v, blob := callRTMP(t, map[string]any{
		"url":           u,
		"watchMs":       1000,
		"connectParams": map[string]any{"key": leakyParamKey, "vhost": "tenant-a"},
	})
	wantCode(t, v, blob, verdictRTMPOk)
	// ★★ 判定本身先要能用，其次才是这三个值一个都不许出现在结果里
	for _, leak := range []string{leakyParamKey, leakyQueryKey, leakyBasicPass} {
		if strings.Contains(blob, leak) {
			t.Errorf("凭据 %s 进了结果 —— 这份结果会发给 AI、也会打进诊断包：\n%s", leak, blob)
		}
	}
	if v.Values["ignoredUserinfo"] != true {
		t.Errorf("地址上写了 user:pass，可 RTMP 没有 Basic 这一说 —— 得明说这一问没带上它：%s", blob)
	}
	if !strings.Contains(fmt.Sprint(v.Values["stream"]), "key=***") {
		t.Errorf("流名上那段 ?key= 该打码后留下（它是「这里挂的是口令还是签名」的证据）：%v", v.Values["stream"])
	}
	if v.Values["streamHasQuery"] != true {
		t.Errorf("没说明白这段参数是跟着 play 一起发出去的：%s", blob)
	}
	// 打码不等于没发：线路上那一份必须带着原值过去，否则这一档是「吞了参数」不是「打了码」
	if got := s.ConnectParams()["key"]; got != leakyParamKey {
		t.Errorf("connect 参数没发出去（服务器收到的是 %v）—— 打码成了吞参数", got)
	}
	if got := s.PlayStream(); !strings.HasSuffix(got, "key="+leakyQueryKey) {
		t.Errorf("play 里的流名没带上 ?key=…（服务器收到 %q）—— nginx-rtmp 那一族按整串校验，拆掉就等于把凭据丢了", got)
	}
	// 唯独 tcUrl 不带凭据：有些服务器会把 tcUrl 原样抄回描述里，而描述是要进结果的
	for _, k := range []string{"app", "tcUrl"} {
		if _, ok := s.ConnectParams()[k]; !ok {
			t.Errorf("connect 里少了 %s 这一格", k)
		}
	}
	tc, _ := s.ConnectParams()["tcUrl"].(string)
	if strings.Contains(tc, leakyQueryKey) || strings.Contains(tc, leakyBasicPass) {
		t.Errorf("tcUrl 带着凭据发出去了：%q", tc)
	}
}

func Test服务器把带口令的地址抄回描述里也要打码(t *testing.T) {
	s := startFake(t, rtmptest.ModeAuth, func(x *rtmptest.Server) {
		x.RejectText = "invalid key, tcUrl=rtmp://127.0.0.1:1935/live/cam1?key=s3cretInDescription"
	})
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 600})
	wantCode(t, v, blob, verdictRTMPAuth)
	if strings.Contains(blob, "s3cretInDescription") {
		t.Errorf("拒绝原文里那段地址没打码：%s", blob)
	}
	if !strings.Contains(fmt.Sprint(v.Values["connectDetail"]), "key=***") {
		t.Errorf("打码打成把整句证据删了，下一步就不知道该查哪边签名：%v", v.Values["connectDetail"])
	}
}

func Test它对这一路说的那句也要打码(t *testing.T) {
	// 真有这么答的服务器：play 回 onStatus(Play.Start)，描述里把整条带 key 的地址抄回来。
	s := startFake(t, rtmptest.ModeOK, func(x *rtmptest.Server) {
		x.PlayText = "playing rtmp://127.0.0.1:1935/live/cam1?token=abcInPlayDetail"
	})
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 800})
	wantCode(t, v, blob, verdictRTMPOk)
	if strings.Contains(blob, "abcInPlayDetail") {
		t.Errorf("play 那句描述没打码：%s", blob)
	}
	if d, _ := v.Values["playDetail"].(string); !strings.Contains(d, "token=***") {
		t.Errorf("打码要把参数名留着、只打掉值，好让人知道该去哪边补凭据：%q", d)
	}
}

func Test拒绝原文里的裸参数值得打码(t *testing.T) {
	// 各家把原因写在 description 里，格式全不统一；这一档验的是文本层那道闸。
	got := maskSecretText("auth failed for vhost=pub.example.com key=abc123def, " +
		"rtmp://x:1935/live/cam1?vhost=pub.example.com&key=abc123def\n第二行")
	for _, leak := range []string{"abc123def", "pub.example.com&", "pub.example.com "} {
		if strings.Contains(got, leak) {
			t.Errorf("%q 没被打码：%q", leak, got)
		}
	}
	if strings.Contains(got, "\n") {
		t.Errorf("控制字符得换成空格，不然一句判定被拆成两行：%q", got)
	}
	if !strings.Contains(got, "key=***") {
		t.Errorf("参数名要留着，只打掉值：%q", got)
	}
}

// ── 参数与地址拆法 ──

func Test别族的地址推到别的卡上(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"rtsp://1.2.3.4/cam", "media.rtsp.probe"},
		{"http://1.2.3.4/a.m3u8", "media.hls.probe"},
		{"https://1.2.3.4/a.m3u8", "media.hls.probe"},
		{"gopher://1.2.3.4/x", "只支持 rtmp"},
	} {
		raw, _ := json.Marshal(map[string]any{"url": tc.in})
		_, err := rtmpProbeTool.Invoke(t.Context(), raw)
		if err == nil {
			t.Errorf("%s 该挡在门外 —— 拿 RTMP 那一套去问别的族，答回来的判定是假的", tc.in)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s 的提示没指到 %s：%s", tc.in, tc.want, err)
		}
		if strings.Contains(err.Error(), "1.2.3.4") {
			t.Errorf("报错原文把内网地址整串抄回去了：%s", err)
		}
	}
}

func Test应用名与流名分开填(t *testing.T) {
	s := startFake(t, rtmptest.ModeOK, nil)
	v, blob := callRTMP(t, map[string]any{
		"url": rtmpURL(s, "weird"), "app": "live", "stream": "cam1", "watchMs": 1000,
	})
	wantCode(t, v, blob, verdictRTMPOk)
	if got, _ := s.ConnectParams()["app"].(string); got != "live" {
		t.Errorf("显式填的应用名没生效：%v", got)
	}
	if got := s.PlayStream(); got != "cam1" {
		t.Errorf("显式填的流名没生效：%q", got)
	}
}

func Test没有应用名就挡在门外(t *testing.T) {
	for _, in := range []string{"rtmp://1.2.3.4", "rtmp://1.2.3.4/", "rtmp://1.2.3.4//cam1"} {
		raw, _ := json.Marshal(map[string]any{"url": in})
		if _, err := rtmpProbeTool.Invoke(t.Context(), raw); err == nil {
			t.Errorf("%s 居然放行了 —— 应用名是地址的第一段，缺了它这一问不知道在连哪个应用", in)
		}
	}
}

func TestConnect参数只收标量(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"url": "rtmp://127.0.0.1:1/live/cam1",
		"connectParams": map[string]any{
			"app": "shouldbeignored", "tcUrl": "rtmp://evil/", "nested": map[string]any{"a": 1},
		},
	})
	if _, err := rtmpProbeTool.Invoke(t.Context(), raw); err == nil {
		t.Fatal("嵌套参数该挡在门外：一层都不收，不然发出去的东西调用方自己都说不清")
	}
	// app / tcUrl 由探测方自己算：填了不生效，但不算错
	params, err := rtmpConnectParams(map[string]any{
		"app": "x", "tcUrl": "y", "vhost": "z", "n": 1.0, "b": true, "nul": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := params["app"]; ok {
		t.Errorf("app 被调用方覆盖了 —— 那是这一问的路标，不是可调参数")
	}
	if _, ok := params["tcUrl"]; ok {
		t.Errorf("tcUrl 被调用方覆盖了")
	}
	if params["vhost"] != "z" || params["n"] != 1.0 || params["b"] != true {
		t.Errorf("标量参数没照原样收：%v", params)
	}
	if v, ok := params["nul"]; !ok || v != nil {
		t.Errorf("显式 null 是有意义的写法（有的服务器要这个键存在）：%v", params)
	}
}

func Test超时与窗口的边界要挡在门外(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		// ★ 短于半秒的窗口问不出「在不在推」，却会给出一个 rtmp-no-media ——
		//   那是我们没问到，不是它没在推。这种问法得挡在门外，不能靠 note 补一句。
		{"窗口过短", map[string]any{"url": "rtmp://127.0.0.1:1/live/c", "watchMs": 200}},
		{"窗口过长", map[string]any{"url": "rtmp://127.0.0.1:1/live/c", "watchMs": 60000}},
		{"一步超时过短", map[string]any{"url": "rtmp://127.0.0.1:1/live/c", "timeoutMs": 50}},
		{"一步超时过长", map[string]any{"url": "rtmp://127.0.0.1:1/live/c", "timeoutMs": 600000}},
	} {
		raw, _ := json.Marshal(tc.args)
		if _, err := rtmpProbeTool.Invoke(t.Context(), raw); err == nil {
			t.Errorf("%s 放行了：%v", tc.name, tc.args)
		}
	}
	// 不填（0）是「按默认 3 秒」，不是非法值：那一档要放行到真正去问
	raw2, err := json.Marshal(map[string]any{"url": "rtmp://127.0.0.1:1/live/c", "watchMs": 0})
	if err != nil {
		t.Fatal(err)
	}
	got, err := rtmpProbeTool.Invoke(t.Context(), raw2)
	if err != nil {
		t.Errorf("watchMs 填 0 被当成非法值了：%s", err)
	} else if v, ok := got.(ots.Verdict); ok && v.Code != verdictRTMPUnreachable {
		t.Errorf("放行了却判成 %s，想要 %s", v.Code, verdictRTMPUnreachable)
	}
}

func Test默认端口与rtmps(t *testing.T) {
	for _, tc := range []struct {
		in string
	}{
		{"rtmp://1.2.3.4/live/c"}, {"rtmps://1.2.3.4/live/c"}, {"rtmp://1.2.3.4:19350/live/c"},
	} {
		u, err := normalizeRTMPURL(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]int{"rtmp://1.2.3.4/live/c": 1935, "rtmps://1.2.3.4/live/c": 443,
			"rtmp://1.2.3.4:19350/live/c": 19350}[tc.in]
		if got := rtmpPort(u); got != want {
			t.Errorf("%s 的端口算成 %d，想要 %d", tc.in, got, want)
		}
	}
	// 不写前缀按 rtmp 认：现场抄下来的地址常常就没有前缀
	u, err := normalizeRTMPURL("192.168.1.20:1935/live/cam1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "rtmp" || u.Hostname() != "192.168.1.20" || rtmpPort(u) != 1935 {
		t.Errorf("裸地址拆错了：%+v", u)
	}
}

func Test判定码的写法与不重复(t *testing.T) {
	// ★ 判定码只能小写字母数字连字符 [OTS-5.5]，而且要带工具前缀，
	//   不然与 net.* 那一堆码在界面词典里撞上。
	want := []string{
		verdictRTMPOk, verdictRTMPNoMedia, verdictRTMPStreamAbsent, verdictRTMPNotPublishing,
		verdictRTMPAppAccepted, verdictRTMPAppRejected, verdictRTMPAuth, verdictRTMPCmdSilent,
		verdictRTMPNotRTMP, verdictRTMPUnreachable, verdictRTMPTimeout, verdictRTMPDropped,
	}
	seen := map[string]bool{}
	for _, c := range want {
		if seen[c] {
			t.Errorf("判定码 %s 重复了", c)
		}
		seen[c] = true
		if !strings.HasPrefix(c, "rtmp-") {
			t.Errorf("判定码 %s 没带工具前缀", c)
		}
		for _, r := range c {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				t.Errorf("判定码 %s 里有非法字符 %q", c, r)
			}
		}
	}
}

func Test探测工具是只读的(t *testing.T) {
	r := ots.NewRegistry(true)
	r.MustRegister(rtmpProbeTool)
	got, ok := r.Lookup("media.rtmp.probe")
	if !ok {
		t.Fatal("没注册进注册表")
	}
	if got.Class != ots.ClassRead {
		t.Errorf("被判成 %q —— 探测只发 connect / createStream / play，不改任何东西", got.Class)
	}
	if !json.Valid(got.Schema) {
		t.Error("schema 不是合法 JSON")
	}
	// ★ 摘要里那句「绝不发」不能漏：这一路离「往别人服务器上挂流」只差一条命令，
	//   调用方（包括 AI）是照这句话决定要不要用它的。
	if !strings.Contains(got.Summary, "绝不发 publish / FCPublish / releaseStream / deleteStream") {
		t.Errorf("摘要没写清不会发哪几条：%s", got.Summary)
	}
	if !strings.Contains(got.Summary, "只读") {
		t.Error("摘要里得写明只读")
	}
}

func Test窗口与实读时长都回填(t *testing.T) {
	s := startFake(t, rtmptest.ModeNoMedia, nil)
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "watchMs": 900})
	wantCode(t, v, blob, verdictRTMPNoMedia)
	if n, _ := intVal(v, "watchMs"); n != 900 {
		t.Errorf("窗口那一格没回填调用方要的长度：%v", v.Values["watchMs"])
	}
	obs, _ := v.Values["observedMs"].(int64)
	if obs < 850 {
		t.Errorf("真读了 %d 毫秒，比要的 900 短一截 —— 窗口没读完就下结论了：%s", obs, blob)
	}
	if basis, _ := v.Values["bitrateBasis"].(string); basis != "" {
		t.Errorf("零字节却给了一份码率口径：%s\n%s", basis, blob)
	}
}

func Test每一步的超时各算一次(t *testing.T) {
	// 握手通了、connect 不回：这一问该在「一步超时」的量级里回来，
	// 而不是把五步的总预算等满。
	s := startFake(t, rtmptest.ModeSilent, nil)
	started := time.Now()
	v, blob := callRTMP(t, map[string]any{"url": rtmpURL(s, "live/cam1"), "timeoutMs": 600})
	if v.Code != verdictRTMPCmdSilent {
		t.Fatalf("判定 = %s，想要 %s：%s", v.Code, verdictRTMPCmdSilent, blob)
	}
	if d := time.Since(started); d > 5*time.Second {
		t.Errorf("一步超时 600 毫秒，这一问却花了 %v —— 超时没按步给，是拿整体在等", d)
	}
	if v.Values["stage"] != "connect" {
		t.Errorf("stage = %v，想要 connect：%s", v.Values["stage"], blob)
	}
}
