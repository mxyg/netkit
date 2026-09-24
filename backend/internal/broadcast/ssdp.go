package broadcast

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// ── SSDP / UPnP ──
//
// ★ 设备发过来的有两种：回答 M-SEARCH 的 "HTTP/1.1 200 OK"，和它自己 periodic
//   喊的 "NOTIFY * HTTP/1.1"。两种的字段名不一样（ST 对 NT），要分开认：
//   把 NOTIFY 当应答读，就会读出一个空类型，界面上变成「这台报了但没说是什么」。

// ErrNotSSDP 表示这一条不是 SSDP 报文（或者是我们自己发出去的 M-SEARCH）。
var ErrNotSSDP = errors.New("不是 SSDP 报文")

// SSDPRequest 拼一条 M-SEARCH。st 传 "ssdp:all" 问全部，传具体设备类型问一类。
//
// ★ MAN 那一行是**必填且必须带引号**的：少了它，Windows 的 SSDP 服务直接丢弃整条，
//
//	而丢弃是无声的 —— 不问一台设备「你在不在」，问的是「你为什么不理我」。
func SSDPRequest(st string, mx int) []byte {
	if st == "" {
		st = "ssdp:all"
	}
	if mx < 1 || mx > 5 {
		mx = 2
	}
	var b bytes.Buffer
	b.WriteString("M-SEARCH * HTTP/1.1\r\n")
	fmt.Fprintf(&b, "HOST: %s:%d\r\n", McastSSDPv4, PortSSDP)
	b.WriteString("MAN: \"ssdp:discover\"\r\n")
	fmt.Fprintf(&b, "MX: %d\r\n", mx)
	fmt.Fprintf(&b, "ST: %s\r\n", st)
	b.WriteString("USERAGENT: netkit\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// ParseSSDP 解一条设备发来的 SSDP 报文。from 是应答来源地址（不带端口）。
//
// ★ 查询（M-SEARCH）不当结果：那是**别人也在找**，不是有人自报，
//
//	把它算进「找到的设备」，界面上就会凭空多出一台不存在的机器。
func ParseSSDP(msg []byte, from string) (*Report, error) {
	head, hdrs, err := splitMessage(msg)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasPrefix(head, "M-SEARCH"):
		return nil, ErrNotSSDP
	case strings.HasPrefix(head, "NOTIFY"):
		// 通告：类型在 NT，"要不要理它" 在 NTS。
		if nt := hdrs["nt"]; nt != "" {
			r := &Report{Source: SourceSSDP, From: from, Type: nt,
				UniqueID: hdrs["usn"], URL: hdrs["location"]}
			keepSSDPHeaders(r, hdrs)
			return r, nil
		}
		return nil, ErrNotSSDP
	case strings.Contains(head, "HTTP/"):
		if st := hdrs["st"]; st != "" {
			r := &Report{Source: SourceSSDP, From: from, Type: st,
				UniqueID: hdrs["usn"], URL: hdrs["location"]}
			keepSSDPHeaders(r, hdrs)
			return r, nil
		}
		return nil, ErrNotSSDP
	}
	return nil, ErrNotSSDP
}

// keepSSDPHeaders 留下对现场有用的几个头。★ 白名单而不是全留：
// 一条 NOTIFY 里能夹着厂商自己加的四五个长头，全塞进结果就变成日志倾倒，
// 而这一栏要回答的只有「是什么、管理页在哪、谁报的」。
func keepSSDPHeaders(r *Report, hdrs map[string]string) {
	keep := []string{"server", "bootid.upnp.org", "configid.upnp.org", "searchport", "nt"}
	for _, k := range keep {
		if v := hdrs[k]; v != "" {
			if r.Text == nil {
				r.Text = map[string]string{}
			}
			r.Text[k] = clip(v, MaxTXTBytes)
		}
	}
	// SERVER 头里通常带操作系统与产品（"Linux/5.15, UPnP/1.0, MiniDLNA/1.3"）：
	// 这一句在现场很有用，所以单独提出来，不埋进 Text。
	if s := hdrs["server"]; s != "" {
		r.Detail = clip(s, 200)
	}
}

// splitMessage 把文本协议报文拆成首行 + 小写键的头表。
func splitMessage(msg []byte) (string, map[string]string, error) {
	text := string(msg)
	if len(text) > MaxTXTBytes*4 {
		text = text[:MaxTXTBytes*4]
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", nil, ErrNotSSDP
	}
	hdrs := map[string]string{}
	for i, ln := range lines[1:] {
		if i >= MaxHeaderLines {
			break
		}
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue // 空行与不合法的行：跳过，不整条丢
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		if _, dup := hdrs[key]; dup {
			continue // 重复头取第一条：后面的可能是别人补的
		}
		hdrs[key] = clip(strings.TrimSpace(v), MaxTXTBytes)
	}
	return strings.TrimSpace(lines[0]), hdrs, nil
}

// ── UPnP 设备描述文件 ──

// Desc 从设备描述 XML 里解出来的东西。
//
// ★ 为什么值得多跑这一趟 HTTP：SSDP 只说「这里有个 MediaServer」，
//
//	而现场问的是「那是不是客厅那台」。friendlyName 是**人给它起的名字**，
//	型号与厂商是它自己报的 —— 这两句合起来才认得出是哪台。
type Desc struct {
	FriendlyName     string   `json:"friendlyName,omitempty"`
	Manufacturer     string   `json:"manufacturer,omitempty"`
	ModelName        string   `json:"modelName,omitempty"`
	ModelDescription string   `json:"modelDescription,omitempty"`
	DeviceType       string   `json:"deviceType,omitempty"`
	UDN              string   `json:"udn,omitempty"`
	PresentationURL  string   `json:"presentationURL,omitempty"`
	SerialNumber     string   `json:"serialNumber,omitempty"`
	Upstream         []string `json:"upstream,omitempty"` // 它自己说的上级设备 UDN（有嵌套时才非空）
	Services         []string `json:"services,omitempty"`
}

// xmlRoot 只声明要读的那几层。★ 用结构体而不是自由遍历：
// 描述文件里 <device> 可以嵌套（root device 里挂子设备），
// 递归结构配 xml:"device" 会把整棵树的 device 段压成一个切片，正好。
type xmlRoot struct {
	Device struct {
		FriendlyName     string `xml:"friendlyName"`
		Manufacturer     string `xml:"manufacturer"`
		ModelName        string `xml:"modelName"`
		ModelDescription string `xml:"modelDescription"`
		DeviceType       string `xml:"deviceType"`
		UDN              string `xml:"UDN"`
		SerialNumber     string `xml:"serialNumber"`
		PresentationURL  string `xml:"presentationURL"`
		DeviceList       struct {
			Devices []xmlDevice `xml:"device"`
		} `xml:"deviceList"`
		ServiceList struct {
			Services []struct {
				ServiceType string `xml:"serviceType"`
			} `xml:"service"`
		} `xml:"serviceList"`
	} `xml:"device"`
}

type xmlDevice struct {
	FriendlyName    string `xml:"friendlyName"`
	Manufacturer    string `xml:"manufacturer"`
	ModelName       string `xml:"modelName"`
	DeviceType      string `xml:"deviceType"`
	UDN             string `xml:"UDN"`
	PresentationURL string `xml:"presentationURL"`
}

// ParseDescription 解 UPnP/SSDP 设备描述文件。
func ParseDescription(body []byte) (*Desc, error) {
	if len(body) == 0 {
		return nil, errors.New("描述文件是空的")
	}
	if len(body) > MaxDescBytes {
		body = body[:MaxDescBytes]
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false // 现场设备的 XML 常年不规范：少一个引号不该整份读不出来
	dec.CharsetReader = charsetReader
	var x xmlRoot
	if err := dec.Decode(&x); err != nil && !isTruncatedXML(err) {
		if _, bad := err.(*xml.SyntaxError); bad {
			return nil, fmt.Errorf("描述文件的 XML 不规范，解不开：%w", err)
		}
		return nil, err // 编码不支持那一句要原样传出去：那是「我们读不动」，不是「它没说」
	}
	d := &Desc{
		FriendlyName:     cleanXMLText(x.Device.FriendlyName),
		Manufacturer:     cleanXMLText(x.Device.Manufacturer),
		ModelName:        cleanXMLText(x.Device.ModelName),
		ModelDescription: cleanXMLText(x.Device.ModelDescription),
		DeviceType:       cleanXMLText(x.Device.DeviceType),
		UDN:              cleanXMLText(x.Device.UDN),
		SerialNumber:     cleanXMLText(x.Device.SerialNumber),
		PresentationURL:  cleanXMLText(x.Device.PresentationURL),
	}
	for _, s := range x.Device.ServiceList.Services {
		if t := cleanXMLText(s.ServiceType); t != "" {
			d.Services = append(d.Services, clip(t, 200))
		}
	}
	for _, sub := range x.Device.DeviceList.Devices {
		if u := cleanXMLText(sub.UDN); u != "" {
			d.Upstream = append(d.Upstream, clip(u, 120))
		}
	}
	if d.FriendlyName == "" && d.DeviceType == "" && len(d.Services) == 0 {
		return nil, errors.New("描述文件里没有设备段：这不像一份 UPnP 设备描述")
	}
	return d, nil
}

// charsetReader 只认现场真会遇到的三种声明。
//
// ★ 为什么必须给：不少国产设备的描述文件写着 encoding="gb2312" 或 GBK，
//
//	go 的标准库默认不接非 UTF-8，不接的结果是**整份解不出来**，
//	界面上就变成「这台报了个地址，别的什么都没写」—— 而那是我们读不动，不是它没说。
func charsetReader(name string, r io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "utf-8", "utf8", "us-ascii", "ascii", "":
		return r, nil
	default:
		return nil, fmt.Errorf("描述文件声明了 %q 编码，这一版不接（不是设备没说，是我们读不动）", name)
	}
}

// isTruncatedXML 判断这个解码错误是不是「读到一半没了」。
//
// ★ 这种情况要留着已经解出来的部分，不能整份丢：一份几十 KB 的描述文件里，
//
//	friendlyName 与型号就在开头那几行，而截断往往是我们自己的 64 KiB 上限、
//	或者设备把连接在半路断了造成的。丢掉整份 = 界面上「这台报了个地址，别的没有」。
func isTruncatedXML(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return strings.Contains(se.Msg, "unexpected EOF")
	}
	return false
}

func cleanXMLText(s string) string {
	return clip(strings.Join(strings.Fields(s), " "), 200)
}

// DescReports 把描述文件里的内容摊成一条记录，挂在同一台设备下。
func (d *Desc) Reports(from, base string) *Report {
	if d == nil {
		return nil
	}
	r := &Report{Source: SourceSSDP, From: from, Name: d.FriendlyName,
		Type: d.DeviceType, UniqueID: d.UDN, URL: d.PresentationURL}
	if r.URL != "" && base != "" {
		r.URL = resolveURL(base, r.URL) // 描述文件里常常只写 "/web/" 这种相对路径
	}
	if d.Manufacturer != "" || d.ModelName != "" {
		r.Detail = strings.Join([]string{d.Manufacturer, d.ModelName}, " ")
		r.Detail = strings.TrimSpace(r.Detail)
	}
	if len(d.Services) > 0 {
		if r.Text == nil {
			r.Text = map[string]string{}
		}
		svc := append([]string(nil), d.Services...)
		sort.Strings(svc)
		r.Text["services"] = clip(strings.Join(svc, " "), MaxTXTBytes)
	}
	return r
}

// resolveURL 把描述文件里的相对地址补全。解不开就原样给回去，
// 因为「它自己写的是什么」本身也是现场要看的东西。
func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	u, err := b.Parse(ref)
	if err != nil {
		return ref
	}
	return u.String()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// ★ 按 rune 退到字符边界：截在半个 UTF-8 字符上，界面会渲染出一个乱码方块，
	//	而这一栏是给人抄进工单的。
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func utf8Start(c byte) bool { return c&0xC0 != 0x80 }
