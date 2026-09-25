package tools

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// 一台会答话的假 ONVIF 设备。★ 它存在的意义是让「设备回了什么」在测试里钉死：
// 判定码怎么分，全看对岸回的是哪一种，而真相机既不可重复也不在手上。
type fakeONVIF struct {
	// 各家固件的应答长得不一样，这几段直接给原文，测试自己摆前缀。
	devXML, timeXML, capsXML, profilesXML, uriXML string
	faultXML                                      string // 非空 = 设备服务只回这一条
	requireAuth                                   bool   // 不带 Security 头就 401
	webPage                                       bool   // 端口上其实是设备的 Web 后台
	silent                                        bool   // 接了连接一声不响
	mediaSilent                                   bool   // 只有媒体服务一声不响
	paths                                         []string
}

const fakeDevOK = `<tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" ` +
	`xmlns:tt="http://www.onvif.org/ver10/schema">` +
	`<tds:Manufacturer>Dahua</tds:Manufacturer><tds:Model>IPC-HFW2439</tds:Model>` +
	`<tds:FirmwareVersion>2.800.0000000.0.R, Build 2024-06-18</tds:FirmwareVersion>` +
	`<tds:SerialNumber>6B2c1A9e7F3d1a0b</tds:SerialNumber>` +
	`<tds:HardwareId>3.100.0000000.0</tds:HardwareId>` +
	`</tds:GetDeviceInformationResponse>`

const fakeProfiles = `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` +
	`xmlns:tt="http://www.onvif.org/ver10/schema">` +
	`<trt:Profiles token="Profile001"><tt:Name>main</tt:Name>` +
	`<tt:VideoEncoderConfiguration><tt:Encoding>H264</tt:Encoding>` +
	`<tt:Resolution><tt:Width>2560</tt:Width><tt:Height>1440</tt:Height></tt:Resolution>` +
	`<tt:RateControl><tt:BitrateLimit>6144</tt:BitrateLimit></tt:RateControl>` +
	`</tt:VideoEncoderConfiguration></trt:Profiles>` +
	`<trt:Profiles token="Profile002"><tt:Name>sub</tt:Name></trt:Profiles>` +
	`</trt:GetProfilesResponse>`

func fakeTimeNow() string {
	now := time.Now().UTC()
	return `<tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema"><tt:SystemDateTime>` +
		`<tt:DateTimeType>NTP</tt:DateTimeType><tt:DaylightSavings>false</tt:DaylightSavings>` +
		`<tt:TimeZone><tt:TZ>CST-8</tt:TZ></tt:TimeZone>` +
		`<tt:UTC><tt:Time><tt:Date>` + now.Format("2006-01-02") + `</tt:Date>` +
		`<tt:Time>` + now.Format("15:04:05") + `</tt:Time></tt:Time></tt:UTC>` +
		`<tt:Ntp><tt:NtpManual><tt:NtpAddress>ntp.aliyun.com</tt:NtpAddress></tt:NtpManual></tt:Ntp>` +
		`</tt:SystemDateTime></tds:GetSystemDateAndTimeResponse>`
}

const fakeStreamURI = `<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` +
	`xmlns:tt="http://www.onvif.org/ver10/schema"><trt:MediaUri>` +
	`<tt:Uri>rtsp://127.0.0.1/cam/realmonitor?channel=1&amp;subtype=0</tt:Uri>` +
	`</trt:MediaUri></trt:GetStreamUriResponse>`

func soapWrap(inner string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
		`<s:Header></s:Header><s:Body>` + inner + `</s:Body></s:Envelope>`
}

func (f *fakeONVIF) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.paths = append(f.paths, r.URL.Path)
		if f.webPage {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Login</title></head>` +
				`<body><h1>web login</h1></body></html>`))
			return
		}
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		got := string(buf[:n])
		quiet := f.silent || (f.mediaSilent && strings.Contains(r.URL.Path, "media"))
		if quiet {
			// 接了连接但不回话：现场那种「端口开着、服务卡死」的样子
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("这个 ResponseWriter 不能 Hijack，造不出「不回话」")
				return
			}
			c, _, err := hj.Hijack()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(30 * time.Second)) // 别把测试挂死
			return
		}
		if f.requireAuth && !strings.Contains(got, "Security") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/soap+xml")
		switch {
		case f.faultXML != "":
			_, _ = w.Write([]byte(soapWrap(f.faultXML)))
		case strings.Contains(got, "GetDeviceInformation"):
			_, _ = w.Write([]byte(soapWrap(f.devXML)))
		case strings.Contains(got, "GetSystemDateAndTime"):
			_, _ = w.Write([]byte(soapWrap(f.timeXML)))
		case strings.Contains(got, "GetCapabilities"):
			_, _ = w.Write([]byte(soapWrap(f.capsXML)))
		case strings.Contains(got, "GetProfiles"):
			_, _ = w.Write([]byte(soapWrap(f.profilesXML)))
		case strings.Contains(got, "GetStreamUri"):
			_, _ = w.Write([]byte(soapWrap(f.uriXML)))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func askONVIF(t *testing.T, args string) (string, map[string]any, string) {
	t.Helper()
	out, err := probeONVIFInfo(context.Background(), json.RawMessage(args))
	if err != nil {
		t.Fatalf("问话本身出错了：%v", err)
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	v, _ := m["values"].(map[string]any)
	code, _ := m["verdict"].(string)
	note, _ := m["note"].(string)
	return code, v, note
}

func errONVIF(t *testing.T, args string) string {
	t.Helper()
	_, err := probeONVIFInfo(context.Background(), json.RawMessage(args))
	if err == nil {
		t.Fatal("本该当面拒掉，却问成功了")
	}
	return err.Error()
}

// stepOf 取某一步的账：问了 / 没问出去，以及那一句说明。
func stepOf(t *testing.T, v map[string]any, step string) (string, string) {
	t.Helper()
	steps, _ := v["steps"].([]any)
	for _, s := range steps {
		m, _ := s.(map[string]any)
		if m["step"] == step {
			state, _ := m["state"].(string)
			note, _ := m["note"].(string)
			return state, note
		}
	}
	t.Fatalf("结果里没有「%s」这一步的账：%+v", step, steps)
	return "", ""
}

// ★★ 这条是整个工具的支点：现场手里往往只有设备的 IP，取流地址问不出来。
// ONVIF 把「几路流」和「第一路什么地址」分成两问答，两问都问到才算成。
func Test问得出身份时间与取流地址(t *testing.T) {
	f := &fakeONVIF{
		devXML: fakeDevOK, timeXML: fakeTimeNow(), profilesXML: fakeProfiles, uriXML: fakeStreamURI,
	}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`","username":"admin","password":"pw"}`)
	if code != "onvif-ok" {
		t.Fatalf("都问到了该判成 onvif-ok，实得 %s / %s", code, note)
	}
	if v["manufacturer"] != "Dahua" || v["model"] != "IPC-HFW2439" {
		t.Errorf("身份字段没带全：%+v", v)
	}
	if v["firmwareVersion"] == "" || v["serialNumber"] != "6B2c1A9e7F3d1a0b" {
		t.Errorf("固件/序列号没带回来：%+v", v)
	}
	if v["profileCount"] != float64(2) {
		t.Errorf("两条码流没数对（profileCount=%v）", v["profileCount"])
	}
	if v["width"] != float64(2560) || v["height"] != float64(1440) {
		t.Errorf("2K 要认成 2K：%v×%v", v["width"], v["height"])
	}
	want := "rtsp://127.0.0.1/cam/realmonitor?channel=1&subtype=0"
	if v["mediaUri"] != want {
		t.Errorf("取流地址没带回来：%v，要 %s", v["mediaUri"], want)
	}
	if !strings.Contains(note, "rtsp://") {
		t.Errorf("note 里该有那个地址（现场要的就是这一格）：%s", note)
	}
	if n, ok := v["offsetMsVsLocal"].(float64); !ok || abs(n) > 5000 {
		t.Errorf("设备时间对得上却算出大偏移：%v", v["offsetMsVsLocal"])
	}
	if v["deviceTimeType"] != "NTP" {
		t.Errorf("它靠什么对时没带回来：%v", v["deviceTimeType"])
	}
	for _, step := range []string{"问它是谁", "问它现在几点", "问它有几路码流", "问它第一路的取流地址"} {
		if st, _ := stepOf(t, v, step); st != "asked" {
			t.Errorf("「%s」本该记成问了，实得 %s", step, st)
		}
	}
}

func Test要账号时不给和被挡分开答(t *testing.T) {
	f := &fakeONVIF{requireAuth: true, devXML: fakeDevOK, profilesXML: fakeProfiles}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`"}`)
	if code != "auth-required" {
		t.Fatalf("401 该判成要账号，实得 %s / %s", code, note)
	}
	if v["status"] != float64(401) {
		t.Errorf("状态码没带回来：%+v", v["status"])
	}
	// ★ 401 那一档也要留步骤账：界面上看不见「哪一步没问出去」，
	//	就会把「没问到」读成「问到一切正常」。
	if st, _ := stepOf(t, v, "问它是谁"); st != "not-asked" {
		t.Errorf("第一问的账没记上：%s", st)
	}
	// 带了账号就问到东西了 —— 这句是在说「401 不是设备坏了」
	code, _, note = askONVIF(t, `{"url":"`+base+`","username":"admin","password":"pw"}`)
	if code != "onvif-ok" {
		t.Fatalf("带了账号该问到东西，实得 %s / %s", code, note)
	}
}

func Test设备用Fault拒问时账号给没给是两件事(t *testing.T) {
	// 不给账号：设备说「缺 UsernameToken」—— 该去填账号
	f := &fakeONVIF{devXML: `<s:Fault xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
		`<s:Code><s:Value>s:Sender</s:Value></s:Code>` +
		`<s:Reason><s:Text>Missing UsernameToken</s:Text></s:Reason></s:Fault>`}
	base := f.start(t)
	code, _, note := askONVIF(t, `{"url":"`+base+`"}`)
	if code != "auth-required" || !strings.Contains(note, "要账号") {
		t.Fatalf("该判成「设备要账号」，实得 %s / %s", code, note)
	}
	// 给了账号还被挡，话要说不同：很多相机把 ONVIF 账号与 Web 登录账号分开管，
	// 拿后台密码来问 ONVIF 问不通是常态 —— 混成一句会让人去翻错的密码。
	code, _, note = askONVIF(t, `{"url":"`+base+`","username":"admin","password":"pw"}`)
	if code != "auth-required" {
		t.Fatalf("实得 %s", code)
	}
	if !strings.Contains(note, "分开管") && !strings.Contains(note, "用户列表") {
		t.Errorf("给了账号仍被挡，note 该指向「ONVIF 账号是另一套」：%s", note)
	}
}

func Test不接这一问不是密码不对(t *testing.T) {
	f := &fakeONVIF{devXML: `<s:Fault xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
		`<s:Code><s:Value>s:Receiver</s:Value></s:Code>` +
		`<s:Reason><s:Text>Action not supported</s:Text></s:Reason></s:Fault>`}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`","username":"a","password":"b"}`)
	if code != "onvif-fault" {
		t.Fatalf("「不会这一问」该单独一档，实得 %s / %s", code, note)
	}
	if strings.Contains(note, "密码不") && !strings.Contains(note, "不是密码不对") {
		t.Errorf("这一档不该把人推去翻密码：%s", note)
	}
	if v["faultReason"] != "Action not supported" {
		t.Errorf("设备原话没带回来：%+v", v["faultReason"])
	}
}

func Test端口上是设备的网页时不说它没回应(t *testing.T) {
	f := &fakeONVIF{webPage: true}
	base := f.start(t)
	code, _, note := askONVIF(t, `{"url":"`+base+`"}`)
	if code != "not-onvif" {
		t.Fatalf("回 HTML 该判成「这不是 ONVIF」，实得 %s / %s", code, note)
	}
	if !strings.Contains(note, "Web") {
		t.Errorf("note 该说出最可能是什么：%s", note)
	}
}

func Test回了SOAP却一句身份都没说也算不是ONVIF(t *testing.T) {
	f := &fakeONVIF{devXML: `<tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>`}
	base := f.start(t)
	code, _, note := askONVIF(t, `{"url":"`+base+`"}`)
	if code != "not-onvif" {
		t.Fatalf("实得 %s / %s", code, note)
	}
}

func Test连不上与连上不回话分开(t *testing.T) {
	code, _, note := askONVIF(t, `{"url":"http://127.0.0.1:1/onvif/device_service","timeoutMs":1500}`)
	if code != "unreachable" {
		t.Fatalf("没人听的端口该判成连不上，实得 %s / %s", code, note)
	}
	// 端口开着、服务卡死 —— 处理办法完全不同，所以是另一个码
	f := &fakeONVIF{silent: true}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`","timeoutMs":800}`)
	if code != "no-response" {
		t.Fatalf("实得 %s / %s", code, note)
	}
	if st, _ := stepOf(t, v, "问它是谁"); st != "not-asked" {
		t.Errorf("第一问没记上账：%s", st)
	}
}

func Test它说没有码流与媒体问不出是两档(t *testing.T) {
	f := &fakeONVIF{
		devXML: fakeDevOK,
		profilesXML: `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">` +
			`</trt:GetProfilesResponse>`,
	}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`","username":"a","password":"b"}`)
	if code != "onvif-no-profile" {
		t.Fatalf("「问到了而它说没有」该单独一档，实得 %s / %s", code, note)
	}
	if v["profileCount"] != float64(0) {
		t.Errorf("profileCount 该是 0（它说了没有），实得 %v", v["profileCount"])
	}
	if !strings.Contains(note, "没配") {
		t.Errorf("note 该指向「去设备上把码流配出来」：%s", note)
	}
}

func Test问不出媒体时那一步的账要留下(t *testing.T) {
	f := &fakeONVIF{devXML: fakeDevOK, timeXML: fakeTimeNow(), mediaSilent: true}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`","username":"a","password":"b","timeoutMs":700}`)
	if code != "onvif-partial" {
		t.Fatalf("媒体问不出该单独一档，实得 %s / %s", code, note)
	}
	if v["manufacturer"] != "Dahua" {
		t.Error("身份该照带回来，不能因为媒体问不出就整条丢掉")
	}
	if _, ok := v["profileCount"]; ok {
		t.Error("没问出去的一问不该留下一个数 —— 那是「没测」，不是「测了等于 0」")
	}
	st, n := stepOf(t, v, "问它有几路码流")
	if st != "not-asked" {
		t.Errorf("那一步的账没记上：%s / %s", st, n)
	}
	if !strings.Contains(n, "deadline") && !strings.Contains(n, "超时") && !strings.Contains(n, "timeout") {
		t.Errorf("那一步该说清为什么没问出去：%s", n)
	}
}

// ★ 设备自报的服务地址不能照着去敲：否则一台设备就能把探测工具支使去访问别的主机。
func Test它报的媒体地址不在这台时不去敲(t *testing.T) {
	f := &fakeONVIF{
		devXML: fakeDevOK,
		capsXML: `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" ` +
			`xmlns:tt="http://www.onvif.org/ver10/schema"><tds:Capabilities><tt:Media>` +
			`<tt:XAddr>http://169.254.169.254/latest/meta-data/onvif_media</tt:XAddr>` +
			`</tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>`,
		profilesXML: `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">` +
			`</trt:GetProfilesResponse>`,
	}
	base := f.start(t)
	code, v, note := askONVIF(t, `{"url":"`+base+`","username":"a","password":"b"}`)
	if code != "onvif-no-profile" {
		t.Fatalf("实得 %s / %s", code, note)
	}
	if _, ok := v["mediaService"]; ok {
		t.Errorf("照它自报的地址改了问话目标：%+v", v["mediaService"])
	}
	for _, p := range f.paths {
		if p != onvifDevPath && p != onvifMediaPath {
			t.Errorf("敲了没该敲的路径 %s —— 探测工具被设备支使去访问别人了", p)
		}
	}
	if _, n := stepOf(t, v, "问它服务挂在哪儿"); !strings.Contains(n, "没去问") {
		t.Errorf("那一步该写明「没去问」：%s", n)
	}
}

func Test它报的媒体地址在这台时跟着它走(t *testing.T) {
	f := &fakeONVIF{
		devXML: fakeDevOK,
		profilesXML: `<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">` +
			`</trt:GetProfilesResponse>`,
	}
	base := f.start(t)
	f.capsXML = `<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema"><tds:Capabilities><tt:Media>` +
		`<tt:XAddr>` + base + `/onvif/media_service</tt:XAddr></tt:Media></tds:Capabilities>` +
		`</tds:GetCapabilitiesResponse>`
	code, v, _ := askONVIF(t, `{"url":"`+base+`","username":"a","password":"b"}`)
	if code != "onvif-no-profile" {
		t.Fatalf("实得 %s", code)
	}
	if v["mediaService"] == nil {
		t.Error("它说了媒体服务挂在哪，却没用上 —— 只能退回猜路径")
	}
}

func Test只给本地时间时不换算成偏差(t *testing.T) {
	// 相机只报本地时间（没配时区也没开 NTP，很常见）。拿它减本机时刻会凭空差出
	// 几小时，然后界面上写「它时间不对」—— 那是我们造的假故障。
	f := &fakeONVIF{
		devXML: fakeDevOK,
		timeXML: `<tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" ` +
			`xmlns:tt="http://www.onvif.org/ver10/schema"><tt:SystemDateTime>` +
			`<tt:DateTimeType>Manual</tt:DateTimeType>` +
			`<tt:LocalTime><tt:Time><tt:Date>2020-01-01</tt:Date>` +
			`<tt:Time>08:00:00</tt:Time></tt:Time></tt:LocalTime>` +
			`</tt:SystemDateTime></tds:GetSystemDateAndTimeResponse>`,
		profilesXML: fakeProfiles,
	}
	base := f.start(t)
	code, v, _ := askONVIF(t, `{"url":"`+base+`","username":"a","password":"b"}`)
	if code != "onvif-ok" {
		t.Fatalf("实得 %s", code)
	}
	if v["deviceTime"] != "2020-01-01T08:00:00Z" {
		t.Errorf("它报的时刻该原样带回来：%v", v["deviceTime"])
	}
	if _, ok := v["offsetMsVsLocal"]; ok {
		t.Error("只有本地时间却算出了偏移 —— 那会把时区差算成设备的错")
	}
}

// ★ 凭据不进结果、不进日志：结果会发给 AI，也可能被打进诊断包。
func TestONVIF结果里不许出现口令(t *testing.T) {
	f := &fakeONVIF{
		devXML: fakeDevOK, profilesXML: fakeProfiles,
		// 设备把带口令的 RTSP 地址原样回给我们 —— 现场最常见的一种泄漏源
		uriXML: `<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" ` +
			`xmlns:tt="http://www.onvif.org/ver10/schema"><trt:MediaUri>` +
			`<tt:Uri>rtsp://admin:Sup3rS3cret@192.168.1.64:554/cam/realmonitor</tt:Uri>` +
			`</trt:MediaUri></trt:GetStreamUriResponse>`,
	}
	base := f.start(t)
	out, err := probeONVIFInfo(context.Background(), json.RawMessage(
		`{"url":"`+base+`","username":"admin","password":"Sup3rS3cret"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "Sup3rS3cret") {
		t.Error("口令漏进结果里了 —— 它会跟着诊断包和发给 AI 的那份文本出去")
	}
	if !strings.Contains(string(b), "rtsp://admin") {
		t.Errorf("地址本身要留着（现场要拿它去验流）：%s", b)
	}
	// ★ 留着给人看的那一句是**抹过口令**的，不能照着发给下一步：
	//	拿「admin（口令已隐去）」当用户名去敲门，设备回 401，
	//	我们把它读成「密码不对」，而密码正是调用方填对的那一份。
	v := out.(ots.Verdict)
	uri, _ := v.Values["mediaUri"].(string)
	if got := onvifStreamFor(uri); got != "rtsp://192.168.1.64:554/cam/realmonitor" {
		t.Errorf("喂给验流那一步的地址该只剩路径：%q → %q", uri, got)
	}
}

// 问出来的不是 RTSP 就当没有：下一步只会说 RTSP，喂一句 http 进去是给人看故障。
func Test转给验流那一步时只认RTSP(t *testing.T) {
	for _, in := range []string{"", "http://192.168.1.64/live", "rtsp://192.0.2.9"} {
		got := onvifStreamFor(in)
		if in == "rtsp://192.0.2.9" {
			if got != in {
				t.Errorf("好好的 rtsp 地址被改坏了：%q", got)
			}
			continue
		}
		if got != "" {
			t.Errorf("%q 不该翻成地址：%q", in, got)
		}
	}
}

func Test地址里的凭据在拼地址时就摘掉(t *testing.T) {
	got, err := onvifEndpoint("http://admin:pwd@192.168.1.64/onvif/device_service")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "pwd") || strings.Contains(got, "admin") {
		t.Errorf("地址里还带着凭据：%s", got)
	}
	if !strings.HasSuffix(got, onvifDevPath) {
		t.Errorf("路径丢了：%s", got)
	}
}

func Test只填主机就补出服务路径(t *testing.T) {
	got, err := onvifEndpoint("192.168.1.64")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://192.168.1.64" + onvifDevPath; got != want {
		t.Errorf("实得 %s，要 %s", got, want)
	}
}

func Test不认http以外的地址(t *testing.T) {
	// ★ 一个探测工具若照单接收 file://、gopher://，就等于替调用方去读本地文件。
	for _, bad := range []string{"file:///etc/passwd", "gopher://x/y", "ftp://1.2.3.4/"} {
		if msg := errONVIF(t, `{"url":"`+bad+`"}`); !strings.Contains(msg, "http") {
			t.Errorf("%s 该当面拒掉，实得：%s", bad, msg)
		}
	}
	if !strings.Contains(errONVIF(t, `{}`), "没给 url") {
		t.Error("空地址该报错")
	}
}

func Test这个工具只读且登记在案(t *testing.T) {
	r := ots.NewRegistry(false)
	Register(r)
	tool, ok := r.Lookup("media.onvif.info")
	if !ok {
		t.Fatal("media.onvif.info 没登记进注册表 —— 界面上就没这张卡")
	}
	if tool.Class != ots.ClassRead {
		t.Errorf("它只该是只读：%s", tool.Class)
	}
}

// 每一个判定码都得在界面上有中文：没译的码宁可原样显示，也不许留一栏空白。
func Test每个判定码在界面上都有人话(t *testing.T) {
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, code := range []string{verdictONVIFOK, verdictONVIFNoProfile, verdictONVIFPartial,
		verdictONVIFAuth, verdictONVIFFault, verdictONVIFNotOnvif, verdictONVIFNoRepl, verdictONVIFUnreach} {
		if !strings.Contains(src, `'`+code+`'`) {
			t.Errorf("判定码 %s 在界面上没有中文 —— 客户会看见一个码", code)
		}
	}
}

// ★ 判定与那一步的账必须说同一件事。401 时空应答在 Go 这边长成「回的不是 SOAP 应答」，
//
//	照原文记账就会出现「判定：要账号 / 记录：它回的不是 ONVIF」这种互相打脸的一行。
func Test挡下第一问时那一步的账要说挡了(t *testing.T) {
	f := &fakeONVIF{requireAuth: true, devXML: fakeDevOK}
	base := f.start(t)
	code, v, _ := askONVIF(t, `{"url":"`+base+`"}`)
	if code != "auth-required" {
		t.Fatalf("实得 %s", code)
	}
	st, note := stepOf(t, v, "问它是谁")
	if st != "not-asked" {
		t.Errorf("账没记上：%s", st)
	}
	if !strings.Contains(note, "挡") || !strings.Contains(note, "401") {
		t.Errorf("那一步该写「设备挡了这一问（401）」，实得 %q", note)
	}
	if strings.Contains(note, "不是 SOAP") || strings.Contains(note, "不是 ONVIF") {
		t.Errorf("401 的账里串进了别的档的说法：%q", note)
	}
}

// 连不上时原文才是有用的那一句（connection refused / no route to host 各指一个方向）。
func Test连不上时那一步把原文留下(t *testing.T) {
	code, v, _ := askONVIF(t, `{"url":"http://127.0.0.1:1/onvif/device_service","timeoutMs":1500}`)
	if code != "unreachable" {
		t.Fatalf("实得 %s", code)
	}
	if _, note := stepOf(t, v, "问它是谁"); !strings.Contains(note, "connection refused") {
		t.Errorf("连不上那一问该带回原文：%q", note)
	}
}
