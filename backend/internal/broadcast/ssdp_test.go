package broadcast

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMSEARCH带齐设备挑不掉的三个头(t *testing.T) {
	msg := string(SSDPRequest("", 0))
	for _, want := range []string{
		"M-SEARCH * HTTP/1.1\r\n",
		"HOST: 239.255.255.250:1900\r\n",
		`MAN: "ssdp:discover"` + "\r\n", // ★ 少了这一行 Windows 直接丢整条
		"MX: 2\r\n",
		"ST: ssdp:all\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("M-SEARCH 里少了 %q：\n%s", want, msg)
		}
	}
	if !strings.HasSuffix(msg, "\r\n\r\n") {
		t.Error("报文必须以空行收尾，否则设备会等正文")
	}
}

func TestMSEARCH的MX与类型收在合法范围(t *testing.T) {
	if got := string(SSDPRequest("urn:schemas-upnp-org:device:MediaServer:1", 99)); !strings.Contains(got, "MX: 2\r\n") {
		t.Errorf("MX 超上限没收回默认：%s", got)
	}
	if got := string(SSDPRequest("upnp:rootdevice", -5)); !strings.Contains(got, "MX: 2\r\n") ||
		!strings.Contains(got, "ST: upnp:rootdevice\r\n") {
		t.Errorf("MX 为负/类型没照给：%s", got)
	}
}

func Test应答与通告分开认(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\n" +
		"USN: uuid:00-11-32-xx::urn:schemas-upnp-org:device:MediaServer:1\r\nEXT:\r\n" +
		"LOCATION: http://10.0.12.9:8200/rootDesc.xml\r\nSERVER: Linux/5.15, UPnP/1.0, MiniDLNA/1.3\r\n\r\n")
	r, err := ParseSSDP(resp, "10.0.12.9")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "urn:schemas-upnp-org:device:MediaServer:1" || r.URL != "http://10.0.12.9:8200/rootDesc.xml" {
		t.Errorf("解错：type=%q url=%q", r.Type, r.URL)
	}
	if r.UniqueID == "" || r.Source != SourceSSDP || r.From != "10.0.12.9" {
		t.Errorf("USN/来源没解出来：%+v", r)
	}
	if r.Detail != "Linux/5.15, UPnP/1.0, MiniDLNA/1.3" {
		t.Errorf("SERVER 没提到 Detail：%q", r.Detail)
	}
	if r.Text["cache-control"] != "" {
		t.Error("白名单外的头不许进 Text（CACHE-CONTROL 对现场没用）")
	}

	not := []byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCAT: ssdp:all\r\n" +
		"NTS: ssdp:alive\r\nNT: upnp:rootdevice\r\nUSN: uuid:box::upnp:rootdevice\r\n" +
		"LOCATION: http://10.0.12.30:5000/desc.xml\r\nSERVER: Synology/NAS DSM\r\n\r\n")
	r2, err := ParseSSDP(not, "10.0.12.30")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Type != "upnp:rootdevice" {
		t.Errorf("NOTIFY 的类型要读 NT，读到 %q", r2.Type)
	}
	if r2.Detail != "Synology/NAS DSM" {
		t.Errorf("通告里的 SERVER 没提：%q", r2.Detail)
	}
}

func Test自己发出的查询不许算成一台设备(t *testing.T) {
	for _, msg := range []string{
		string(SSDPRequest("ssdp:all", 2)),
		"NOTIFY * HTTP/1.1\r\nNTS: ssdp:byebye\r\n\r\n",  // 没有 NT：不知道它在告退什么
		"GARBAGE\r\n\r\n",                                // 别的协议串了端口进来
		"\r\n",                                           // 空
		"HTTP/1.1 200 OK\r\nSERVER: only-server\r\n\r\n", // 应答但没报类型
	} {
		if _, err := ParseSSDP([]byte(msg), "1.1.1.1"); err != ErrNotSSDP {
			t.Errorf("这条不该算设备，却给了 %v：\n%s", err, msg)
		}
	}
}

func Test重复头取第一条(t *testing.T) {
	// 有的设备 BOOTID 会重复出现（厂商自己补了一遍）；后一条可能是别人伪造的。
	msg := []byte("HTTP/1.1 200 OK\r\nST: a\r\nST: b\r\nLOCATION: http://x/1\r\nLOCATION: http://y/2\r\n\r\n")
	r, err := ParseSSDP(msg, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "a" || r.URL != "http://x/1" {
		t.Errorf("重复头要取第一条，得到 type=%q url=%q", r.Type, r.URL)
	}
}

func Test换行两种写法都认(t *testing.T) {
	r, err := ParseSSDP([]byte("HTTP/1.1 200 OK\nST: x\nLOCATION: http://h/d\n"), "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "x" || r.URL != "http://h/d" {
		t.Errorf("只用 \\n 的报文没读出来：%+v", r)
	}
}

func Test头一栏有上限(t *testing.T) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\nST: x\r\n")
	for i := 0; i < 500; i++ {
		b.WriteString("X-JUNK: 长")
		b.WriteString(strings.Repeat("0", 300))
		b.WriteString("\r\n")
	}
	r, err := ParseSSDP([]byte(b.String()), "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "x" {
		t.Errorf("垃圾头堆太多反而丢了类型：%+v", r)
	}
}

const rootDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <friendlyName>客厅那台 NAS</friendlyName>
  <manufacturer>Synology</manufacturer>
  <modelName>DS220+</modelName>
  <modelDescription>网络存储</modelDescription>
  <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
  <UDN>uuid:nas-1</UDN>
  <serialNumber>12345</serialNumber>
  <presentationURL>/web/index.html</presentationURL>
  <serviceList>
   <service><serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType></service>
   <service><serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType></service>
  </serviceList>
  <deviceList>
   <device><friendlyName>子设备</friendlyName><UDN>uuid:nas-1:sub</UDN></device>
  </deviceList>
 </device>
</root>`

func Test描述文件把是哪一台说清楚(t *testing.T) {
	d, err := ParseDescription([]byte(rootDesc))
	if err != nil {
		t.Fatal(err)
	}
	if d.FriendlyName != "客厅那台 NAS" || d.Manufacturer != "Synology" || d.ModelName != "DS220+" {
		t.Errorf("解错：%+v", d)
	}
	if d.SerialNumber != "12345" || d.UDN != "uuid:nas-1" {
		t.Errorf("身份项没解出来：%+v", d)
	}
	if len(d.Services) != 2 {
		t.Errorf("服务 %d 个：%v", len(d.Services), d.Services)
	}
	if len(d.Upstream) != 1 || d.Upstream[0] != "uuid:nas-1:sub" {
		t.Errorf("嵌套子设备没读到：%v", d.Upstream)
	}
	r := d.Reports("10.0.12.9", "http://10.0.12.9:8200/rootDesc.xml")
	// ★ 描述文件里常常只写相对路径，直接显示等于不能点。
	if r.URL != "http://10.0.12.9:8200/web/index.html" {
		t.Errorf("相对地址没补全：%q", r.URL)
	}
	if r.Name != "客厅那台 NAS" || r.Detail != "Synology DS220+" {
		t.Errorf("归并用的字段不对：%+v", r)
	}
	if !strings.Contains(r.Text["services"], "ContentDirectory") {
		t.Errorf("服务清单没带：%v", r.Text)
	}
}

func Test描述文件的编码读不动要说明是谁的问题(t *testing.T) {
	gbk := []byte(`<?xml version="1.0" encoding="gb2312"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>NAS</friendlyName></device></root>`)
	_, err := ParseDescription(gbk)
	if err == nil {
		t.Fatal("gb2312 不该静默解出来")
	}
	if !strings.Contains(err.Error(), "我们读不动") {
		t.Errorf("错误要说清是读不动不是没说：%v", err)
	}
}

func Test不规范与残缺的描述文件(t *testing.T) {
	if _, err := ParseDescription(nil); err == nil {
		t.Error("空文件要报错")
	}
	// 少一个闭合标签：Strict=false 下能读到多少算多少，不许整个丢。
	d, err := ParseDescription([]byte(`<root><device><friendlyName>半截</friendlyName>`))
	if err != nil {
		t.Fatalf("半截的 XML 不该整份丢：%v", err)
	}
	if d.FriendlyName != "半截" {
		t.Errorf("读到了个什么：%q", d.FriendlyName)
	}
	if _, err := ParseDescription([]byte(`<html><body>这不是 XML</body></html>`)); err == nil {
		t.Error("结构完全不对的要报错，不许给一个空壳")
	}
	// 名字里连着空白与换行：翻成人话要收成一行。
	d2, err := ParseDescription([]byte("<root><device><friendlyName>  前\n\t后  </friendlyName></device></root>"))
	if err != nil {
		t.Fatal(err)
	}
	if d2.FriendlyName != "前 后" {
		t.Errorf("空白没收干净：%q", d2.FriendlyName)
	}
}

func Test描述文件与结果都必须是合法JSON文本(t *testing.T) {
	long := strings.Repeat("型", 500)
	d, err := ParseDescription([]byte("<root><device><friendlyName>" + long + "</friendlyName></device></root>"))
	if err != nil {
		t.Fatal(err)
	}
	r := d.Reports("10.0.0.1", "http://10.0.0.1/d.xml")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\ufffd") {
		t.Error("截断截在了半个汉字上")
	}
	if !utf8.ValidString(r.Name) {
		t.Errorf("剪完不是合法 UTF-8：%q", r.Name)
	}
}

func Test剪长度不许劈开汉字(t *testing.T) {
	s := "摄像头abc"
	if got := clip(s, 4); got != "摄…" {
		t.Errorf("clip(%q,4)=%q，要按字符边界退", s, got)
	}
	if got := clip(s, 100); got != s {
		t.Errorf("没超长不该动：%q", got)
	}
}
