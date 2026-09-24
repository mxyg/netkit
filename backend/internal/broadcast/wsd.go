package broadcast

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// ── WS-Discovery（ONVIF 摄像头、Windows 设备发现都走这一路）──
//
// ★ 为什么单独一路：SSDP 与 mDNS 是「谁在喊」，这一路是**监控设备自己报的户口**。
//
//	ONVIF 的 Hello / ProbeMatch 里带着 XAddrs（它的服务地址）和 Scopes，
//	而 Scopes 里写着型号、硬件版本、位置 —— 现场那句「这是不是 3 号楼那个球机」，
//	只有这一路答得上来。
//
// 报文是一个 SOAP Envelope，命名空间有两个版本在市面上并存（2005/04 与 2009/01）。
// 发的时候按 ONVIF 用的那个（2005/04 + 2004/08 地址），**收的时候两个都认**，
// 而且只按元素的本地名认 —— 真设备的前缀起名千奇百怪（wsd:、d:、wsdd:、无前缀都有），
// 照前缀匹配就会「明明回了，我们却当成没回」。

const (
	wsdNS2005  = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
	wsdNS2009  = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
	addNS2004  = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	onvifNetNS = "http://www.onvif.org/ver10/network/wsdl"
	onvifDevNS = "http://www.onvif.org/ver10/device/wsdl"

	// onvifScopePrefix ONVIF 的 scope 一律以这一串开头（规格里定死的）。
	onvifScopePrefix = "onvif://www.onvif.org/"
)

// ErrNotWSD 表示这一条不是 WS-Discovery 报文，或者是别人发出的查询。
var ErrNotWSD = errors.New("不是 WS-Discovery 报文")

// WSDiscoveryProbe 拼一条 Probe。types 传 "dn:NetworkVideoTransmitter" 这类
// 受限类型串（要带报文里声明过的前缀）；留空表示问所有设备。
//
// ★ <d:Types> 必须带 xmlns 声明：Types 的内容是「前缀:名字」，而前缀要在这份报文里
//
//	定义过才解得开。ONVIF 的摄像头看到没声明的 dn: 会认为匹配不上任何类型，
//	回都不回 —— 而「不回」在界面上和「不在线」长得一模一样。
//
//	★ 这一版**不发 MatchBy**：它是 2009/01 才有的头，而市面上大量 ONVIF 设备只实现
//	  2005/04，收到不认识的 mustUnderstand="1" 头会直接 Fault 甚至不回。
//	  不发顶多是问得宽一点，发了可能一条都收不到。
func WSDiscoveryProbe(types, scopes, messageID string) []byte {
	if messageID == "" {
		messageID = "urn:uuid:00000000-0000-0000-0000-000000000000"
	}
	t := ""
	if strings.TrimSpace(types) != "" {
		t = fmt.Sprintf(`<d:Types xmlns:dn="%s">%s</d:Types>`, onvifNetNS, xmlEscape(types))
	}
	s := ""
	if strings.TrimSpace(scopes) != "" {
		s = "<d:Scopes>" + xmlEscape(scopes) + "</d:Scopes>"
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:a="` + addNS2004 + `" xmlns:d="` + wsdNS2005 + `">`)
	b.WriteString("<s:Header>")
	fmt.Fprintf(&b, `<a:Action s:mustUnderstand="1">%s/probe</a:Action>`, wsdNS2005)
	fmt.Fprintf(&b, `<a:MessageID>%s</a:MessageID>`, xmlEscape(messageID))
	fmt.Fprintf(&b, `<a:To s:mustUnderstand="1">%s/multicast</a:To>`, wsdNS2005)
	b.WriteString("</s:Header><s:Body>")
	b.WriteString("<d:Probe>" + t + s + "</d:Probe>")
	b.WriteString("</s:Body></s:Envelope>")
	return []byte(b.String())
}

// WSDHello 拼一条 Hello（我们只收、一般不发）。
// 留着是为了测试里能造出设备那一侧的报文。
func WSDHello(address, types, scopes string, xaddrs []string, metadataVersion int) []byte {
	return wsdEnvelope("Hello", address, types, scopes, xaddrs, metadataVersion, wsdNS2005)
}

func wsdEnvelope(kind, address, types, scopes string, xaddrs []string, metaVersion int, ns string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:a="` + addNS2004 + `" xmlns:d="` + ns + `" xmlns:dn="` + onvifNetNS + `"><s:Header>`)
	fmt.Fprintf(&b, `<a:Action>%s/%s</a:Action>`, ns, strings.ToLower(kind))
	b.WriteString("</s:Header><s:Body>")
	b.WriteString(fmt.Sprintf("<d:%s>", kind))
	b.WriteString("<d:EndpointReference><a:Address>")
	b.WriteString(xmlEscape(address))
	b.WriteString("</a:Address></d:EndpointReference>")
	b.WriteString("<d:Types>" + xmlEscape(types) + "</d:Types>")
	b.WriteString("<d:Scopes>" + xmlEscape(scopes) + "</d:Scopes>")
	for _, x := range xaddrs {
		b.WriteString("<d:XAddrs>" + xmlEscape(x) + "</d:XAddrs>")
	}
	fmt.Fprintf(&b, "<d:MetadataVersion>%d</d:MetadataVersion>", metaVersion)
	if kind == "Hello" {
		b.WriteString(`<d:AppSequence InstanceId="1" MessageNumber="1"/>`)
	}
	b.WriteString(fmt.Sprintf("</d:%s></s:Body></s:Envelope>", kind))
	return []byte(b.String())
}

// ParseWSDiscovery 解一条设备自报（Hello / ProbeMatch / ResolveMatch）。
//
// ★ 查询（Probe / Resolve）不当结果：那和 SSDP 的 M-SEARCH 是同一件事 ——
//
//	别人也在找设备，不是有人自报。算进来的话，界面上会凭空多出一台不存在的机器。
func ParseWSDiscovery(msg []byte, from string) (*Report, error) {
	dec := xml.NewDecoder(strings.NewReader(string(msg)))
	dec.Strict = false // 真设备的 Envelope 常年不规范：少一个命名空间声明不该整条丢
	var (
		kind     string
		inBody   bool
		inEPR    bool
		match    *wsdMatch
		prefixes = map[string]string{} // 报文里声明过的前缀 → 命名空间
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// ★ 已经认出这是哪种自报了就把前面的留着：3702 上的 SOAP 常年被 IP 分片，
			//   后半截丢了不等于这台不存在。一条都没认出来的坏报文才按坏报文处理。
			if match != nil {
				break
			}
			return nil, ErrNotWSD
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			if e, isEnd := tok.(xml.EndElement); isEnd && e.Name.Local == "Body" {
				inBody = false
			}
			continue
		}
		// 前缀映射只能从 xmlns:xxx 这些属性里拿。★ 不用 el.Name.Space：那是解码器
		// 已经换算过的命名空间 URI，拿它反查不到「dn: 指哪个命名空间」这件事。
		for _, a := range el.Attr {
			if a.Name.Space == "xmlns" {
				prefixes[a.Name.Local] = a.Value
			} else if a.Name.Local == "xmlns" {
				prefixes[""] = a.Value
			}
		}
		local := el.Name.Local
		switch {
		case local == "Body":
			inBody = true
		case local == "Header", local == "Envelope":
		case inBody && match == nil:
			if !isWSDKind(local) {
				return nil, ErrNotWSD // Body 里第一个元素不是发现协议的那几种
			}
			kind = local
			match = &wsdMatch{kind: local}
		case match != nil && local == "EndpointReference":
			inEPR = true
		case match != nil && inEPR && local == "Address":
			match.address = text(dec, el)
			inEPR = false
		case match != nil && local == "Types":
			match.types = text(dec, el)
		case match != nil && local == "Scopes":
			match.scopes = text(dec, el)
		case match != nil && local == "XAddrs":
			match.xaddrs = append(match.xaddrs, text(dec, el))
		case match != nil && local == "MetadataVersion":
			match.meta = text(dec, el)
		case match != nil && local == "InstanceID": // 2009/01 的 AppSequence 里
			match.instance = text(dec, el)
		case match != nil && local == "AppSequence":
			// ★ 2009/01 把 InstanceId 写成**属性**，不是子元素：照子元素找就永远拿不到。
			for _, a := range el.Attr {
				if a.Name.Local == "InstanceId" && match.instance == "" {
					match.instance = a.Value
				}
			}
		default:
			_ = text(dec, el) // 不认识的一律读过丢掉，别让它把后面的挤掉
		}
	}
	if match == nil {
		return nil, ErrNotWSD
	}
	if kind == "Probe" || kind == "Resolve" || kind == "Bye" {
		// Bye 是「我下线了」：它不是在线证据，但也不该算成一台设备。
		return nil, ErrNotWSD
	}
	if len(match.xaddrs) == 0 && match.types == "" && match.address == "" {
		return nil, ErrNotWSD
	}
	return match.report(from, prefixes), nil
}

func isWSDKind(local string) bool {
	switch local {
	case "Hello", "Bye", "Probe", "ProbeMatch", "Resolve", "ResolveMatch":
		return true
	}
	return false
}

type wsdMatch struct {
	kind     string
	address  string
	types    string
	scopes   string
	xaddrs   []string
	meta     string
	instance string
}

func (m *wsdMatch) report(from string, prefixes map[string]string) *Report {
	r := &Report{Source: SourceWSDiscovery, From: from, UniqueID: clip(m.address, 200)}
	// XAddrs 可能写两三个（http 与 https 各一）。第一个当「管理地址」，其余留在 Text，
	// 因为现场真的会碰到第一个是 80、第二个才是能用的那种设备。
	if xs := cleanList(m.xaddrs); len(xs) > 0 {
		r.URL = clip(xs[0], MaxURLBytes)
		if len(xs) > 1 {
			r.Text = setText(r.Text, "xaddrs", clip(strings.Join(xs[1:], " "), MaxTXTBytes))
		}
	}
	if t := cleanList(strings.Fields(m.types)); len(t) > 0 {
		r.Type = clip(t[0], 200)
		if len(t) > 1 {
			r.Text = setText(r.Text, "types", clip(strings.Join(t, " "), MaxTXTBytes))
		}
		// dn: 这种前缀是报文里自己声明的；把它换回可读的部分，
		// 不然界面上是一串 "dn:NetworkVideoTransmitter"，而人要看的是"网络视频设备"。
		r.Text = setText(r.Text, "typesNS", clip(expandTypes(m.types, prefixes), MaxTXTBytes))
	}
	if s := strings.TrimSpace(m.scopes); s != "" {
		r.Text = setText(r.Text, "scopes", clip(s, MaxTXTBytes))
		for k, v := range ONVIFScopes(s) {
			r.Text = setText(r.Text, "scope:"+k, clip(v, 200))
		}
	}
	if m.meta != "" {
		r.Text = setText(r.Text, "metadataVersion", clip(m.meta, 20))
	}
	if m.instance != "" {
		r.Text = setText(r.Text, "instanceID", clip(m.instance, 40))
	}
	r.Name = r.Text["scope:name"] // ONVIF 把设备自己起的名字写在 scope 里
	r.Detail = m.kind
	return r
}

// ONVIFScopes 把 ONVIF 的 scope 串拆成键值。
//
// ★ 为什么值得拆：ONVIF 设备把型号、硬件版本、位置写成
//
//	onvif://www.onvif.org/name/AXIS%20M30  onvif://www.onvif.org/hardware/Q6218
//
//	这几项正是「这是不是那一台」的依据。不拆的话，界面上是一行谁也看不懂的 URI，
//	而现场问的是型号和位置。拆不出来的（不是 onvif:// 开头的）不猜，原样留在 scopes。
func ONVIFScopes(scopes string) map[string]string {
	out := map[string]string{}
	for _, s := range strings.Fields(scopes) {
		if !strings.HasPrefix(s, onvifScopePrefix) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(s, onvifScopePrefix), "/")
		if len(parts) < 2 {
			continue // 只写了类别没写值：没有可说的，不编
		}
		key := strings.ToLower(parts[0])
		val := strings.ReplaceAll(strings.Join(parts[1:], "/"), "+", " ")
		if u, err := url.PathUnescape(val); err == nil {
			val = u
		}
		if key != "" && val != "" {
			out[key] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// expandTypes 把 "dn:NetworkVideoTransmitter" 里的前缀换成报文自己声明的命名空间，
// 再对上一个可读的名字。认不出的保留原样。
func expandTypes(types string, prefixes map[string]string) string {
	var out []string
	for _, t := range strings.Fields(types) {
		pfx, local, has := strings.Cut(t, ":")
		if !has {
			out = append(out, t)
			continue
		}
		ns := prefixes[pfx]
		switch ns {
		case onvifNetNS:
			out = append(out, "ONVIF网络服务:"+local)
		case onvifDevNS:
			out = append(out, "ONVIF设备服务:"+local)
		default:
			out = append(out, t)
		}
	}
	return strings.Join(out, " ")
}

// LooksONVIF 判断这一串 Types 是不是 ONVIF 的网络视频设备。
//
// ★ 只做这一个判断，不猜别的：ONVIF 的 Types 里有 NetworkVideoTransmitter
//
//	就等于「这是一台摄像头/编码器」，这一句在现场直接决定下一步查码流还是查供电。
func LooksONVIF(types string) bool {
	return strings.Contains(types, "NetworkVideoTransmitter")
}

func cleanList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func setText(m map[string]string, k, v string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[k] = v
	return m
}

// text 读完一个元素的全部内容并把它的位置消费掉。
func text(dec *xml.Decoder, el xml.StartElement) string {
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return strings.TrimSpace(b.String())
		}
		switch v := tok.(type) {
		case xml.CharData:
			b.WriteString(string(v))
		case xml.EndElement:
			if v.Name == el.Name {
				return strings.TrimSpace(b.String())
			}
		case xml.StartElement: // 嵌套元素：里面的文字也算这一栏的
			_ = text(dec, v)
		}
	}
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
