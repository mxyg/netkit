package onvif

import (
	"strings"
	"testing"
)

// ★ 这一组是报文层的测试。ONVIF 的坑不在「会不会拼 XML」，而在各家固件的
//	前缀、嵌套层数、时间写法都不一致 —— 认窄了就会把「设备回了」读成「设备没回」，
//	那种错比报错更坏：人会顺着「没回」去查一个不存在的地方。

func Test摘要对得上规范给的算法(t *testing.T) {
	// Base64(SHA-1(nonce + created + password))。向量是拿另一份实现单独算出来钉住的：
	// 摘要一旦改动，所有相机的认证都会失效，而现场只会看到「密码不对」。
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	got := PasswordDigest(nonce, "2005-01-01T00:00:00Z", "secret")
	if want := "oHrqD7NswITlfvyQB0/dbsT2uEY="; got != want {
		t.Errorf("摘要算错了：得到 %s，要 %s", got, want)
	}
}

func Test安全头里不许出现明文密码(t *testing.T) {
	h := SecurityHeader(&Credential{Username: `ad"<min>`, Password: "S3cr3t-Pa55"})
	if strings.Contains(h, "S3cr3t-Pa55") {
		t.Error("密码以明文进了报文 —— 它会被写进日志，也可能被打进诊断包")
	}
	if !strings.Contains(h, "ad&quot;&#34;min&gt;") && !strings.Contains(h, "ad&#34;&lt;min&gt;") {
		t.Errorf("账号没被转义，报文会被账号里的尖括号撑坏：%s", h)
	}
	// ★ 没给账号就不该拼出半截 Security 头：带一个空 Token 过去，
	//	设备会当成「认证格式不对」直接 Fault，看起来像密码错。
	if SecurityHeader(&Credential{}) != "" {
		t.Error("没给账号却拼出了安全头")
	}
	if SecurityHeader(nil) != "" {
		t.Error("凭据为 nil 却拼出了安全头")
	}
}

// 三种前缀写法：真设备上 tds:/tt:/无前缀都碰得到。
var bodies = []string{
	`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
		`<s:Body><tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema">` +
		`<tds:Manufacturer>Dahua</tds:Manufacturer><tds:Model>IPC-HFW</tds:Model>` +
		`<tt:FirmwareVersion>2.800.0000000.0.R</tt:FirmwareVersion>` +
		`<tds:SerialNumber>1A2B3C</tds:SerialNumber>` +
		`</tds:GetDeviceInformationResponse></s:Body></s:Envelope>`,
	`<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body>` +
		`<GetDeviceInformationResponse xmlns="http://www.onvif.org/ver10/device/wsdl">` +
		`<Manufacturer>Dahua</Manufacturer><Model>IPC-HFW</Model>` +
		`<FirmwareVersion>2.800.0000000.0.R</FirmwareVersion>` +
		`<SerialNumber>1A2B3C</SerialNumber></GetDeviceInformationResponse>` +
		`</Body></Envelope>`,
	`<x:Envelope xmlns:x="http://www.w3.org/2003/05/soap-envelope"><x:Body>` +
		`<y:GetDeviceInformationResponse xmlns:y="http://www.onvif.org/ver10/device/wsdl">` +
		`<z:Manufacturer xmlns:z="http://www.onvif.org/ver10/schema">Dahua</z:Manufacturer>` +
		`<y:Model>IPC-HFW</y:Model><y:FirmwareVersion>2.800.0000000.0.R</y:FirmwareVersion>` +
		`<y:SerialNumber>1A2B3C</y:SerialNumber></y:GetDeviceInformationResponse>` +
		`</x:Body></x:Envelope>`,
}

func Test认设备信息时不许挑前缀(t *testing.T) {
	want := DeviceInfo{Manufacturer: "Dahua", Model: "IPC-HFW",
		Firmware: "2.800.0000000.0.R", Serial: "1A2B3C"}
	for i, b := range bodies {
		root, err := Parse([]byte(b))
		if err != nil {
			t.Fatalf("第 %d 种写法解不开：%v", i+1, err)
		}
		if got := DecodeDeviceInfo(root); got != want {
			t.Errorf("第 %d 种写法认成了 %+v，要 %+v", i+1, got, want)
		}
	}
}

func Test时间三种写法都要认(t *testing.T) {
	wrap := func(inner string) string {
		return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
			`xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>` +
			`<tds:GetSystemDateAndTimeResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">` +
			`<tt:SystemDateTime>` + inner + `</tt:SystemDateTime>` +
			`</tds:GetSystemDateAndTimeResponse></s:Body></s:Envelope>`
	}
	cases := []struct {
		name string
		in   string
		utc  string
	}{
		{"Date 与 Time 分两段", `<tt:DateTimeType>NTP</tt:DateTimeType>` +
			`<tt:TimeZone><tt:TZ>CST-8</tt:TZ></tt:TimeZone>` +
			`<tt:UTC><tt:Time><tt:Date>2026-09-25</tt:Date><tt:Time>03:04:05</tt:Time></tt:Time></tt:UTC>`,
			"2026-09-25T03:04:05Z"},
		{"整串 ISO 直接给", `<tt:UTC>2026-09-25T03:04:05Z</tt:UTC>`, "2026-09-25T03:04:05Z"},
		{"只有本地时间", `<tt:LocalTime><tt:Time><tt:Date>2026-09-25</tt:Date>` +
			`<tt:Time>11:04:05</tt:Time></tt:Time></tt:LocalTime>`, ""},
		{"日期都没给", `<tt:DateTimeType>Manual</tt:DateTimeType>`, ""},
	}
	for _, c := range cases {
		root, err := Parse([]byte(wrap(c.in)))
		if err != nil {
			t.Fatalf("%s：解不开 %v", c.name, err)
		}
		got := DecodeTime(root)
		if got.UTC != c.utc {
			t.Errorf("%s：UTC 认成 %q，要 %q", c.name, got.UTC, c.utc)
		}
		if c.name == "只有本地时间" && !got.LocalOnly() {
			t.Error("它只给了本地时间，却没被标成本地时间 —— 拿去算偏移会凭空多出几小时")
		}
	}
	// 时区与对时方式：这两格才是「它靠什么对时」的答案
	root, err := Parse([]byte(wrap(`<tt:DateTimeType>Manual</tt:DateTimeType>` +
		`<tt:DaylightSavings>false</tt:DaylightSavings>` +
		`<tt:TimeZone><tt:TZ>CST-8</tt:TZ></tt:TimeZone>` +
		`<tt:UTC><tt:Time><tt:Date>2026-09-25</tt:Date><tt:Time>03:04:05</tt:Time></tt:Time></tt:UTC>` +
		`<tt:Ntp><tt:NtpManual><tt:NtpAddress>ntp1.corp.local</tt:NtpAddress>` +
		`<tt:NtpAddress>10.0.0.9</tt:NtpAddress></tt:NtpManual>` +
		`<tt:Extension><tt:FromDHCP>false</tt:FromDHCP></tt:Extension></tt:Ntp>`)))
	if err != nil {
		t.Fatal(err)
	}
	tm := DecodeTime(root)
	if tm.DateTime != "Manual" || tm.Timezone != "CST-8" || tm.Dst != "false" {
		t.Errorf("对时口径没认全：%+v", tm)
	}
	if len(tm.NTPAddrs) != 2 || tm.NTPAddrs[0] != "ntp1.corp.local" {
		t.Errorf("NTP 地址没数全：%+v", tm.NTPAddrs)
	}
}

func Test服务地址认得出媒体那一条(t *testing.T) {
	root, err := Parse([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>` +
		`<tds:GetCapabilitiesResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">` +
		`<tds:Capabilities><tt:Device><tt:XAddr>http://192.168.1.64/onvif/device_service</tt:XAddr></tt:Device>` +
		`<tt:Media><tt:XAddr>http://192.168.1.64:8899/onvif/media_service</tt:XAddr>` +
		`<tt:StreamingCapabilities/></tt:Media></tds:Capabilities>` +
		`</tds:GetCapabilitiesResponse></s:Body></s:Envelope>`))
	if err != nil {
		t.Fatal(err)
	}
	want := "http://192.168.1.64:8899/onvif/media_service"
	if got := MediaXAddr(root); got != want {
		t.Errorf("媒体服务地址认成 %q，要 %q", got, want)
	}
}

func Test码流列表按token与规格认(t *testing.T) {
	root, err := Parse([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>` +
		`<trt:GetProfilesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">` +
		`<trt:Profiles token="Profile001" fixed="true">` +
		`<tt:Name>Profile 1</tt:Name>` +
		`<tt:VideoSourceConfiguration token="vsc"><tt:Source><tt:Framerate>25</tt:Framerate></tt:Source></tt:VideoSourceConfiguration>` +
		`<tt:VideoEncoderConfiguration token="vec"><tt:Name>enc1</tt:Name><tt:Encoding>H264</tt:Encoding>` +
		`<tt:Resolution><tt:Width>2560</tt:Width><tt:Height>1440</tt:Height></tt:Resolution>` +
		`<tt:RateControl><tt:Interval>1</tt:Interval><tt:BitrateLimit>6144</tt:BitrateLimit></tt:RateControl>` +
		`</tt:VideoEncoderConfiguration>` +
		`<tt:AudioEncoderConfiguration><tt:Encoding>G711</tt:Encoding></tt:AudioEncoderConfiguration>` +
		`</trt:Profiles>` +
		`<trt:Profiles token="Profile002"><tt:Name>Profile 2</tt:Name>` +
		`<tt:VideoEncoderConfiguration><tt:Encoding>MJPEG</tt:Encoding>` +
		`<tt:Resolution><tt:Width>704</tt:Width><tt:Height>576</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration>` +
		`</trt:Profiles>` +
		`</trt:GetProfilesResponse></s:Body></s:Envelope>`))
	if err != nil {
		t.Fatal(err)
	}
	ps := DecodeProfiles(root)
	if len(ps) != 2 {
		t.Fatalf("两条 profile 只认出 %d 条", len(ps))
	}
	// ★ profile 的名字挂在直接子层，编码器里也有一个同名元素 ——
	//	取错了就会把「enc1」当成 profile 名报出去。
	if ps[0].Name != "Profile 1" || ps[0].Token != "Profile001" {
		t.Errorf("第一条认成 %+v", ps[0])
	}
	if ps[0].Encoding != "H264" || ps[0].Width != "2560" || ps[0].Height != "1440" {
		t.Errorf("第一条规格不对（2K 要认成 2K）：%+v", ps[0])
	}
	if ps[0].Framerate != "25" || ps[0].Bitrate != "6144" || ps[0].Audio != "G711" {
		t.Errorf("第一条的帧率/码率/音频没取到：%+v", ps[0])
	}
	if ps[1].Name != "Profile 2" || ps[1].Token != "Profile002" {
		t.Errorf("第二条认成 %+v", ps[1])
	}
}

func TestFault分得清是不让问还是不会问(t *testing.T) {
	cases := []struct {
		in   string
		auth bool
	}{
		{`<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>` +
			`<s:Reason><s:Text>Subscription end does not have proper rights</s:Text></s:Reason></s:Fault>`, true},
		{`<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>` +
			`<s:Reason><s:Text>ter:ActionNotAuthorized</s:Text></s:Reason></s:Fault>`, true},
		{`<env:Fault><faultcode>env:Client</faultcode>` +
			`<faultstring>Missing UsernameToken</faultstring></env:Fault>`, true},
		{`<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>` +
			`<s:Reason><s:Text>Action not supported</s:Text></s:Reason></s:Fault>`, false},
	}
	for i, c := range cases {
		root, err := Parse([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
			`<s:Body>` + c.in + `</s:Body></s:Envelope>`))
		if err != nil {
			t.Fatalf("第 %d 条解不开：%v", i+1, err)
		}
		f := FaultOf(root)
		if f == nil {
			t.Fatalf("第 %d 条没认出 Fault", i+1)
		}
		if got := LooksAuthFault(f); got != c.auth {
			t.Errorf("第 %d 条归错类了（%q / %q）：认成 %v，要 %v", i+1, f.Code, f.Reason, got, c.auth)
		}
	}
	root, _ := Parse([]byte(bodies[1]))
	if FaultOf(root) != nil {
		t.Error("正常应答里认出了 Fault —— 会把好的报成坏的")
	}
}

func Test应答不能把探测工具拖死(t *testing.T) {
	// 对岸是我们控制不了的固件：回多深、回多大都没有承诺。
	deep := strings.Repeat(`<a>`, maxDepth+50) + strings.Repeat(`</a>`, maxDepth+50)
	if _, err := Parse([]byte(deep)); err == nil {
		t.Error("超深的应答被照单全收了")
	}
	wide := "<root>" + strings.Repeat(`<x>1</x>`, maxNodes+10) + "</root>"
	if _, err := Parse([]byte(wide)); err == nil {
		t.Error("超大的应答被照单全收了")
	}
	// 半截 XML 不能 panic：设备说到一半咽气是常事
	if _, err := Parse([]byte("<not even closed")); err != nil {
		t.Fatalf("垃圾应答本就该解出个空树，不该报错：%v", err)
	}
}

func Test自报文本再长也有上限(t *testing.T) {
	long := strings.Repeat("A", maxText*4)
	root, err := Parse([]byte(`<r><Manufacturer>` + long + `</Manufacturer></r>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := DecodeDeviceInfo(root).Manufacturer; len(got) > maxText*2 {
		t.Errorf("一段自报文本能撑无限长：%d 字符", len(got))
	}
}

func Test取流地址单独一问(t *testing.T) {
	root, err := Parse([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body>` +
		`<trt:GetStreamUriResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl">` +
		`<trt:MediaUri><tt:Uri>rtsp://192.168.1.64/cam/realmonitor?channel=1&amp;subtype=0</tt:Uri>` +
		`<tt:InvalidAfterConnect>false</tt:InvalidAfterConnect></trt:MediaUri>` +
		`</trt:GetStreamUriResponse></s:Body></s:Envelope>`))
	if err != nil {
		t.Fatal(err)
	}
	want := "rtsp://192.168.1.64/cam/realmonitor?channel=1&subtype=0"
	if got := DecodeStreamURI(root); got != want {
		t.Errorf("取流地址解成 %q，要 %q", got, want)
	}
	// ★ 问地址要点名哪一路：不带 token 设备回的是「参数不全」那句 Fault，
	//	而它在界面上和「这台不肯给地址」长得一模一样。
	q := StreamURICall(`P"1`)
	if !strings.Contains(q.Body, "<ProfileToken>P&#34;1</ProfileToken>") {
		t.Errorf("token 没带上或没转义：%s", q.Body)
	}
	if !strings.Contains(q.Body, "<Protocol>RTSP</Protocol>") {
		t.Errorf("没说要点 RTSP 那一套：%s", q.Body)
	}
}

func Test每次问话的摘要都是新算的(t *testing.T) {
	c := &Credential{Username: "admin", Password: "pw"}
	h1, h2 := SecurityHeader(c), SecurityHeader(c)
	if h1 == h2 {
		t.Error("两次问话拼出了同一份摘要 —— 设备的时间窗会挡掉第二个，看起来像密码错")
	}
	if !strings.Contains(h1, "PasswordDigest") {
		t.Error("没声明摘要类型，设备会拿明文去比")
	}
}
