package broadcast

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── WS-Discovery：收的时候只认本地名，前缀与命名空间两个版本都要认 ──

func TestProbe把前缀声明带上但不塞MatchBy(t *testing.T) {
	msg := string(WSDiscoveryProbe("dn:NetworkVideoTransmitter", "", "urn:uuid:abc"))
	// Types 的内容是「前缀:名字」，前缀没在这份报文里声明过就是解不开的死字。
	if !strings.Contains(msg, `xmlns:dn="`+onvifNetNS+`"`) {
		t.Errorf("缺 dn: 的命名空间声明：\n%s", msg)
	}
	if !strings.Contains(msg, "<d:Types") || !strings.Contains(msg, "dn:NetworkVideoTransmitter") {
		t.Errorf("Types 没写进去：\n%s", msg)
	}
	if !strings.Contains(msg, "urn:uuid:abc") {
		t.Errorf("MessageID：%s", msg)
	}
	// MatchBy 是 2009/01 才有的头。发出去可能让只实现 2005/04 的设备直接不回。
	if strings.Contains(msg, "MatchBy") {
		t.Errorf("不该发 MatchBy：\n%s", msg)
	}
	// 问所有设备时 Types 整个元素都不该出现（写了空 <d:Types/> 有些实现会当过滤条件）。
	empty := string(WSDiscoveryProbe("  ", "", ""))
	if strings.Contains(empty, "<d:Types") {
		t.Errorf("types 为空还写了 Types：%s", empty)
	}
	// 自己发出去的查询不是设备自报：解它等于把「别人也在找」算成「有一台设备」。
	if _, err := ParseWSDiscovery([]byte(empty), "10.0.0.9"); err != ErrNotWSD {
		t.Errorf("Probe 给了 %v，要按查询处理", err)
	}
}

func TestHello解出管理地址型号与名字(t *testing.T) {
	scopes := "onvif://www.onvif.org/name/AXIS%20M30 " +
		"onvif://www.onvif.org/hardware/M30-%204401 " +
		"onvif://www.onvif.org/location/3%E6%A5%BC%E4%B8%9C%E5%8D%97%E8%A7%92"
	msg := WSDHello("urn:uuid:camera-1", "dn:NetworkVideoTransmitter", scopes,
		[]string{"http://10.0.12.77:80/onvif/device_service"}, 1)
	r, err := ParseWSDiscovery(msg, "10.0.12.77")
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != SourceWSDiscovery || r.From != "10.0.12.77" {
		t.Errorf("%+v", r)
	}
	if r.URL != "http://10.0.12.77:80/onvif/device_service" {
		t.Errorf("XAddrs：%q", r.URL)
	}
	if r.UniqueID != "urn:uuid:camera-1" {
		t.Errorf("EndpointReference 的 uuid：%q", r.UniqueID)
	}
	if r.Name != "AXIS M30" {
		t.Errorf("ONVIF 把自己起的名字写在 scope 里，得到 %q", r.Name)
	}
	if r.Type != "dn:NetworkVideoTransmitter" {
		t.Errorf("Types：%q", r.Type)
	}
	if !LooksONVIF(r.Type) {
		t.Error("该认出这是网络视频设备")
	}
	// 前缀换回可读的部分，界面上不必出现 "dn:" 这种死字。
	if got := r.Text["typesNS"]; !strings.Contains(got, "ONVIF网络服务:NetworkVideoTransmitter") {
		t.Errorf("typesNS：%q", got)
	}
	if got := r.Text["scope:hardware"]; got != "M30- 4401" {
		t.Errorf("hardware：%q", got)
	}
	if got := r.Text["scope:location"]; got != "3楼东南角" {
		t.Errorf("location（要还原 %%E4 这些）：%q", got)
	}
	if r.Detail != "Hello" {
		t.Errorf("Detail：%q", r.Detail)
	}
	// Text 里不许留机器 token 当人话：原始 scope 串单独一栏。
	if !strings.Contains(r.Text["scopes"], onvifScopePrefix) {
		t.Errorf("scopes 原样栏：%q", r.Text["scopes"])
	}
	if b, err := json.Marshal(r); err != nil || strings.Contains(string(b), "U+FFFD") {
		t.Errorf("JSON：%s %v", b, err)
	}
}

func Test两个命名空间与随便什么前缀都要认(t *testing.T) {
	// 设备自己起名前缀（wsdd:）、用 2009/01 的命名空间、把 AppSequence 的
	// InstanceId 写成属性 —— 这三件事在市面上同时存在的不少。
	const ns2009 = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
	msg := []byte(`<?xml version="1.0"?>
<w:Envelope xmlns:w="` + ns2009 + `" xmlns:wsa="` + addNS2004 + `" xmlns:vid="` + onvifNetNS + `">
 <w:Header><wsa:Action>` + ns2009 + `/hello</wsa:Action></w:Header>
 <w:Body>
  <w:Hello>
   <w:EndpointReference><wsa:Address>urn:uuid:nas-9</wsa:Address></w:EndpointReference>
   <w:Types>vid:NetworkVideoTransmitter wsd:Printer</w:Types>
   <w:XAddrs>http://10.0.0.5:3702/</w:XAddrs>
   <w:AppSequence MessageNumber="3" InstanceId="42"/>
  </w:Hello>
 </w:Body></w:Envelope>`)
	r, err := ParseWSDiscovery(msg, "10.0.0.5")
	if err != nil {
		t.Fatalf("前缀与命名空间都不该挡住解码：%v", err)
	}
	if r.URL != "http://10.0.0.5:3702/" {
		t.Errorf("%q", r.URL)
	}
	if r.Type != "vid:NetworkVideoTransmitter" {
		t.Errorf("Types 取第一个：%q", r.Type)
	}
	if got := r.Text["types"]; got != "vid:NetworkVideoTransmitter wsd:Printer" {
		t.Errorf("多出来的 Types 要留着：%q", got)
	}
	// vid: 这个前缀报文里声明的是 ONVIF 网络那一套，换出来就该是中文栏。
	if got := r.Text["typesNS"]; !strings.Contains(got, "ONVIF网络服务:NetworkVideoTransmitter") {
		t.Errorf("typesNS：%q", got)
	}
	// wsd: 没声明过 —— 保留原样，不硬掰一个名字出来。
	if !strings.Contains(r.Text["typesNS"], "wsd:Printer") {
		t.Errorf("没声明的前缀要原样保留：%q", r.Text["typesNS"])
	}
	if got := r.Text["instanceID"]; got != "42" {
		t.Errorf("InstanceId 是属性不是子元素：%q", got)
	}
	if r.Detail != "Hello" {
		t.Errorf("%q", r.Detail)
	}
}

func TestXAddrs写两三个时第一个当管理地址其余留着(t *testing.T) {
	msg := WSDHello("urn:uuid:u", "dn:NetworkVideoTransmitter", "",
		[]string{"http://10.0.0.9:80/onvif/device_service", "https://10.0.0.9:443/onvif/device_service"}, 1)
	r, err := ParseWSDiscovery(msg, "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if r.URL != "http://10.0.0.9:80/onvif/device_service" {
		t.Errorf("%q", r.URL)
	}
	// 现场真的会碰到第一个是 80、第二个才是能用的那种设备，所以第二个不能丢。
	if got := r.Text["xaddrs"]; !strings.Contains(got, "https://10.0.0.9:443") {
		t.Errorf("第二个 XAddrs：%q", got)
	}
}

func Test别人的查询与告退与不是SOAP都不算一台设备(t *testing.T) {
	for _, kind := range []string{"Probe", "Resolve", "Bye"} {
		msg := wsdEnvelope(kind, "urn:uuid:x", "dn:NetworkVideoTransmitter", "",
			[]string{"http://10.0.0.9/onvif"}, 1, wsdNS2005)
		if _, err := ParseWSDiscovery(msg, "10.0.0.9"); err != ErrNotWSD {
			t.Errorf("%s：给了 %v", kind, err)
		}
	}
	for name, msg := range map[string]string{
		"空":         "",
		"纯文本":       "hello",
		"不是 SOAP":   `<html><body>路由器登录页</body></html>`,
		"Body 空":    `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`,
		"Body 里别的":  `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><Fault/></s:Body></s:Envelope>`,
		"Hello 全空":  `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><Hello/></s:Body></s:Envelope>`,
		"只有 Header": `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><a:Action>x</a:Action></s:Header></s:Envelope>`,
	} {
		if _, err := ParseWSDiscovery([]byte(msg), "10.0.0.9"); err != ErrNotWSD {
			t.Errorf("%s：给了 %v，要说不清", name, err)
		}
	}
}

func Test报文断在一半时留着已经认出来的那台(t *testing.T) {
	// 3702 上的 SOAP 常年被 IP 分片；后半截丢了不等于这台不存在。
	msg := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:d="` + wsdNS2005 + `"><s:Body><d:Hello>` +
		`<d:EndpointReference><a:Address xmlns:a="` + addNS2004 + `">urn:uuid:half</a:Address></d:EndpointReference>` +
		`<d:XAddrs>http://10.0.0.31:80/onvif/device_ser`)
	r, err := ParseWSDiscovery(msg, "10.0.0.31")
	if err != nil {
		t.Fatalf("断在后面不该整条丢：%v", err)
	}
	if r.UniqueID != "urn:uuid:half" {
		t.Errorf("%q", r.UniqueID)
	}
	if r.URL != "http://10.0.0.31:80/onvif/device_ser" {
		t.Errorf("读到多少算多少：%q", r.URL)
	}
}

func TestResolveMatch也当设备自报(t *testing.T) {
	msg := wsdEnvelope("ResolveMatch", "urn:uuid:rm-1", "dn:NetworkVideoTransmitter",
		"onvif://www.onvif.org/name/球机", []string{"http://10.0.0.77:80/onvif"}, 2, wsdNS2009)
	r, err := ParseWSDiscovery(msg, "10.0.0.77")
	if err != nil {
		t.Fatal(err)
	}
	if r.Detail != "ResolveMatch" || r.Name != "球机" {
		t.Errorf("%+v", r)
	}
	if got := r.Text["metadataVersion"]; got != "2" {
		t.Errorf("%q", got)
	}
}

func TestScope拆不出来的一律不猜(t *testing.T) {
	// 非 ONVIF 的 scope（打印机自己定义的 URI）：不拆，原样留在 scopes 栏。
	got := ONVIFScopes("http://example.com/printer/Model:XXX urn:other " +
		"onvif://www.onvif.org/name onvif://www.onvif.org/hardware/ " +
		"onvif://www.onvif.org/type/network_video_transmitter")
	if len(got) != 1 || got["type"] != "network_video_transmitter" {
		t.Errorf("%#v", got)
	}
	// 一条都没拆出来要返回 nil，不是空 map：界面拿 nil 才能写「这台没说」。
	if m := ONVIFScopes("urn:only:other"); m != nil {
		t.Errorf("%#v", m)
	}
	// '+' 在 URI 里是空格的另一种写法，两种都要还原。
	if m := ONVIFScopes("onvif://www.onvif.org/name/NVM+311+C"); m["name"] != "NVM 311 C" {
		t.Errorf("%#v", m)
	}
}
