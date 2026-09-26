package flow

// 脱敏的**整表**扫描。
//
// 前面每一份专解测试各自钉自己那一格（「nonce 的值漏在表上了」那种），
// 但真正的出口是整张表：它会被 json.Marshal 成结果发给界面、发给 AI、
// 打进诊断包、被现场的人整段贴到群里。逐格钉有一个改一个漏，
// 整表扫一次是把「任何一条流的任何一格都不许带凭据原文」钉成一条规矩 ——
// 新增一个专解、新增一格字段，只要它把凭据原文交出来，这个用例就红。
//
// ★ 两头都要钉：
//   - 值不许出：每一种凭据（digest 的 response/nonce/cnonce/opaque、Basic 的 base64、
//     流地址里的 userinfo、SOAP 的 WSSE 口令、MQTT 的口令、SNMP 的团体名、SDP 的 SDES 密钥）
//     的原文都不许出现在序列化之后的任何一个字节里。
//   - 身份必须留：用户名、客户端标识、设备编号要在。整表糊成一片星号也算「脱敏成功」，
//     那等于把这功能废了 —— 现场要问的第一句就是「哪个账号被拒了」。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/gb28181"
	"net.yuhox.com/netkit/internal/snmp"
)

// 这一批字符串是**故意**埋进去的凭据。挑的形状各不相同（带连字符、纯字母数字、
// 一长串 base64、URI 里的一段），因为漏点通常是某一类而不是某一行：
// 只埋一种形状的扫描，换个形状就照样漏。
const (
	rtspResponse  = "RtspDigestResponse-1a2b3c4d5e6f"
	rtspNonce     = "RtspNonceValue-9z8y7x6w5v4u"
	rtspCnonce    = "RtspCnonceValue-4a5b6c7d8e9f"
	rtspOpaque    = "RtspOpaqueValue-8f7e6d5c4b3a"
	rtspURIpw     = "PasswordInsideURI-778899"
	basicUser     = "rtsp-basic-user"
	basicPass     = "S3cr3t-Basic-Auth-Pw"
	onvifPW       = "Onvif-Pw-Plain-9182"
	onvifUser     = "onvif-admin"
	mqttPW        = "S3cr3t-MQTT-pw"
	mqttUser      = "iot-user"
	mqttClientID  = "cam-01"
	snmpCommunity = "Private-Community-9"
	sipDigestResp = "GbDigestResponse-5f4e3d2c1b0a"
	sipNonce      = "GbNonceValue-7a6b5c4d3e2f"
	sipDeviceID   = "34020000001320000001"
	sdesKey       = "StreamMasterKey-9876543210fedcba"
	sdesCrypto    = "U3RyZWFtTWFzdGVyS2V5LTk4NzY1NDMyMTBmZWRjYmE="
	kLineKey      = "OldStyleKeyLine-445566"
)

// redactTable 造一张把上面每一种凭据都见过一遍的表。
//
// 各协议各占一条流（源端口分开），这样漏的时候能说清是哪一条流的哪一格漏的 ——
// 全塞进一条流，报错就只剩「这张表里有密码」，还得人回去一条条翻。
func redactTable(t *testing.T) *Aggregator {
	t.Helper()
	a := NewAggregator(Options{})

	// ---- RTSP：digest 一份、Basic 一份、200 OK 带 SDP（SDES 密钥 + 旧式 k= 行）----
	rtsp := newTCPSession(t, a, 51234, 554)
	rtsp.ask(t, 3, "DESCRIBE rtsp://"+onvifUser+":"+rtspURIpw+"@10.0.0.9/live/1 RTSP/1.0\r\n"+
		"CSeq: 1\r\n"+
		"Authorization: Digest username=\""+onvifUser+"\", realm=\"cam\", nonce=\""+rtspNonce+"\", "+
		"uri=\"rtsp://10.0.0.9/live/1\", response=\""+rtspResponse+"\", cnonce=\""+rtspCnonce+"\", "+
		"opaque=\""+rtspOpaque+"\", qop=auth, nc=00000001\r\n\r\n")
	sdp := "v=0\r\n" +
		"o=" + sipDeviceID + " 0 0 IN IP4 10.0.0.9\r\n" +
		"s=Play\r\n" +
		"c=IN IP4 10.0.0.9\r\n" +
		"t=0 0\r\n" +
		"m=video 0 RTP/AVP 96\r\n" +
		"a=rtpmap:96 H264/90000\r\n" +
		"a=crypto:1 AES_CM_128_NULL_CIPHER_HMAC_SHA1_80 inline:" + sdesCrypto + "\r\n" +
		"k=mono " + kLineKey + "\r\n"
	rtsp.reply(t, 4, fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(sdp), sdp))
	rtsp.ask(t, 5, "SETUP rtsp://10.0.0.9/live/1/trackID=1 RTSP/1.0\r\nCSeq: 2\r\n"+
		"Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte(basicUser+":"+basicPass))+"\r\n"+
		"Transport: RTP/AVP;unicast;client_port=6970-6971\r\n\r\n")

	// ---- ONVIF：SOAP 头里的 WSSE 明文口令 ----
	onvif := newTCPSession(t, a, 51236, 80)
	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` +
		`xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">` +
		`<s:Header><wsse:Security><wsse:UsernameToken>` +
		`<wsse:Username>` + onvifUser + `</wsse:Username>` +
		`<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">` +
		onvifPW + `</wsse:Password>` +
		`</wsse:UsernameToken></wsse:Security></s:Header>` +
		`<s:Body><trt:GetStreamUri><trt:StreamSetup><tt:Stream xmlns:tt="http://www.onvif.org/ver10/schema">RTP-Unicast</tt:Stream></trt:StreamSetup></trt:GetStreamUri></s:Body></s:Envelope>`
	onvif.ask(t, 3, "POST /onvif/media_service HTTP/1.1\r\nHost: 10.0.0.9\r\n"+
		"Content-Type: application/soap+xml\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)

	// ---- MQTT：CONNECT 里的口令 ----
	mqtt := newTCPSession(t, a, 51238, 1883)
	mqtt.ask(t, 3, string(mqttBuildConnect(mqttClientID, mqttUser, mqttPW)))

	// ---- 国标 SIP：REGISTER 带 digest，401 带 challenge ----
	reg := sipRequest(t, gb28181.MethodRegister, 1)
	reg.Set(gb28181.HAuthorization, fmt.Sprintf(
		`Digest username="%s", realm="3402000000", nonce="%s", uri="sip:%s", response="%s", qop=auth, nc=00000001, cnonce="%s"`,
		sipDeviceID, sipNonce, sipDeviceID, sipDigestResp, rtspCnonce))
	if err := sipAsk(t, a, 20, reg); err != nil {
		t.Fatal(err)
	}
	if err := sipReply(t, a, 21, sipResponseOf(t, reg, 401)); err != nil {
		t.Fatal(err)
	}

	// ---- SNMP：团体名在每一包上 ----
	pk, err := snmp.NewGet(snmpCommunity, "1.3.6.1.2.1.1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pk.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := add(a, pkt{when: at(30), src: client, sp: 51240, dst: device, dp: 161, payload: raw}); err != nil {
		t.Fatal(err)
	}
	return a
}

// sipResponseOf 就是 app_test.go 里那个 sipResponse， 但那个名字已经被占了；
// 这里要的只有「给这份请求回一个带 challenge 的状态码」。
func sipResponseOf(t *testing.T, req *gb28181.Message, status int) *gb28181.Message {
	t.Helper()
	resp := gb28181.NewResponseFor(req, status, "")
	if status == 401 {
		ch := &gb28181.Challenge{Realm: "3402000000", Nonce: sipNonce, QOP: []string{"auth"}}
		resp.Set(gb28181.HWWWAuthenticate, ch.Header())
	}
	return resp
}

// tableText 把这张表会以多少种形态出去**全部**拼成一份：
// JSON（ 发界面、 发 AI）、 每一行的 String（ 打进诊断包的纯文本、 日志）、
// 账本（ 拆不动的原因里也可能带出原文）。
// 只扫 JSON 是最容易写也最容易骗自己的那一种： 界面走 JSON， 诊断包走文本。
func tableText(t *testing.T, a *Aggregator) string {
	t.Helper()
	flows := a.Flows()
	var b strings.Builder
	for _, fl := range flows {
		b.WriteString(flowText(t, fl))
		b.WriteString("\n")
	}
	ledger, err := json.Marshal(a.Ledger())
	if err != nil {
		t.Fatalf("账本序列化不了：%v", err)
	}
	b.Write(ledger)
	return b.String()
}

func flowText(t *testing.T, fl *Flow) string {
	t.Helper()
	var b strings.Builder
	raw, err := json.Marshal(fl)
	if err != nil {
		t.Fatalf("流 %s 序列化不了：%v", fl.Key, err)
	}
	b.Write(raw)
	b.WriteString("\n")
	b.WriteString(fl.String())
	for _, n := range fl.Notes {
		b.WriteString("\n" + n)
	}
	for _, f := range fl.Findings {
		b.WriteString("\n" + f.Text)
	}
	for _, m := range fl.Messages {
		b.WriteString("\n" + m.String())
		for _, f := range m.Findings {
			b.WriteString("\n" + f.Text)
		}
	}
	return b.String()
}

func Test整张表序列化之后一个字的凭据都不许在(t *testing.T) {
	a := redactTable(t)
	flows := a.Flows()
	if len(flows) < 5 {
		t.Fatalf("这张表只有 %d 条流， 没把该见的凭据都见过一遍（rtsp/onvif/mqtt/sip/snmp 各一条）", len(flows))
	}
	// 每一类协议都真的解出来了才算这一扫有效： 定口没定上就一条报文都没切，
	// 那是「没东西可漏」的假绿 —— 扫描全绿而底下根本没解。
	seen := map[string]bool{}
	var apps []string
	for _, fl := range flows {
		if !seen[fl.App] {
			seen[fl.App] = true
			apps = append(apps, fl.App)
		}
	}
	for _, want := range []string{"rtsp", "onvif", "mqtt", "sip", "snmp"} {
		if !seen[want] {
			t.Errorf("表上没有 %s 这条流：这一类凭据根本没进过解码器， 扫描等于没扫（有：%s）",
				want, strings.Join(apps, "、"))
		}
	}

	secrets := []struct{ name, value string }{
		{"RTSP digest response", rtspResponse},
		{"RTSP nonce", rtspNonce},
		{"RTSP cnonce", rtspCnonce},
		{"RTSP opaque", rtspOpaque},
		{"流地址里的口令", rtspURIpw},
		{"Basic 的 base64 整串", base64.StdEncoding.EncodeToString([]byte(basicUser + ":" + basicPass))},
		{"Basic 的口令", basicPass},
		{"WSSE 明文口令", onvifPW},
		{"MQTT 口令", mqttPW},
		{"SNMP 团体名", snmpCommunity},
		{"国标 digest response", sipDigestResp},
		{"国标 nonce", sipNonce},
		{"SDES 密钥（ base64）", sdesCrypto},
		{"SDES 密钥（ 解出来的样子）", sdesKey},
		{"旧式 k= 密钥行", kLineKey},
	}

	dump := tableText(t, a)
	for _, s := range secrets {
		if !strings.Contains(dump, s.value) {
			continue
		}
		// 报出到底是哪一条流的哪一条报文， 别让人拿着「表里有密码」再去一条条翻。
		t.Errorf("%s 的原文漏在整表上了：%q", s.name, s.value)
		for _, fl := range a.Flows() {
			if !strings.Contains(flowText(t, fl), s.value) {
				continue
			}
			t.Errorf("  漏点：%s %s/%s", fl.Key, fl.App, fl.AppBy)
			for _, m := range fl.Messages {
				raw, err := json.Marshal(m)
				if err != nil {
					t.Fatalf("报文序列化不了：%v", err)
				}
				if strings.Contains(string(raw), s.value) {
					t.Errorf("  漏点在这一条报文上：%s %s %s", m.Proto, m.Kind, m.Method)
				}
			}
		}
	}
}

func Test身份那几格不许被顺手打掉(t *testing.T) {
	dump := tableText(t, redactTable(t))
	// ★ 这些不是凭据， 是排查的第一手： 把用户名也糊掉， 「哪个账号被拒了」就答不出了。
	for _, id := range []string{onvifUser, mqttUser, mqttClientID, sipDeviceID} {
		if !strings.Contains(dump, id) {
			t.Errorf("%q 被打掉了：整表糊成一片星号也算「脱敏成功」的话， 这功能就废了", id)
		}
	}
}

func Test脱敏过的那几格自己承认脱过(t *testing.T) {
	// 值是打掉了， 但「打掉了」这件事必须留在表上：
	// 「设备根本没带 Authorization」与「带了但被拒了」是两种病， 界面要分得开。
	// 全打成空字符串， 现场就会照着「没带」去改配置， 而真正的病在口令上。
	a := redactTable(t)
	var redacted, credMsgs int
	for _, fl := range a.Flows() {
		for _, m := range fl.Messages {
			if m.Creds > 0 {
				credMsgs++
			}
			for _, fd := range m.Fields {
				if fd.Redacted {
					redacted++
					if !strings.Contains(fd.V, "字节") && !strings.Contains(fd.V, "没带") &&
						!strings.Contains(fd.V, "已脱敏") {
						t.Errorf("%s 标了已脱敏却没说形状：%q（ 只给「有/没有」加长度）", fd.K, fd.V)
					}
				}
			}
		}
	}
	if redacted < 8 {
		t.Errorf("整表只有 %d 格标了已脱敏：这一埋至少十几处（digest 四格 + WSSE + MQTT + 团体名 + challenge）", redacted)
	}
	if credMsgs < 4 {
		t.Errorf("只有 %d 条报文数出了凭据：Creds 没跟上， 界面就不敢说「这条已脱敏」", credMsgs)
	}
}

func Test反证整表扫描自己抓得住漏(t *testing.T) {
	// 这一条不测解码器， 测的是上面那个用例有没有牙：
	// 把一份凭据原文塞进任何一格， 扫描必须当场叫。
	// 没有这一条， 将来「secrets 列表写错了」「dump 拼错了」都能扫出一片绿。
	a := NewAggregator(Options{})
	s := newTCPSession(t, a, 51234, 554)
	s.ask(t, 3, "GET_PARAMETER rtsp://10.0.0.9/live/1 RTSP/1.0\r\nCSeq: 9\r\n"+
		"Session: 12345\r\nX-Custom-Note: keepalive with "+mqttPW+"\r\n\r\n")
	if !strings.Contains(tableText(t, a), mqttPW) {
		t.Fatal("反证失败：整表扫描连一处明知埋进去的凭据都没抓到， 那 Test整张表 那条绿不算数")
	}
}
