// Package broadcast 解「设备自己喊自己是什么」那几种报文。
//
// ★★ 为什么要有这个包（docs/设计.md「三、扫描与发现」里的「设备识别」）：
//
//	现场问的是「刚插上那台东西是什么」，而答案**在设备自己喊的话里**：
//	摄像头喊 ONVIF（WS-Discovery），NAS、打印机、AirPlay 盒子喊 mDNS/DNS-SD，
//	Windows 机器喊 NetBIOS，媒体服务器与智能设备喊 SSDP/UPnP。
//	ARP、网段扫描、ping 只能回答「这个地址有人」，回答不了「它是谁」——
//	而现场真正卡住人的那一步，往往是「知道 10.0.12.77 有人，不知道那是哪台」。
//
// ★ 这一包**只做报文编解码**，不碰网卡：谁在哪个口上发、听多久、
//
//	收齐了怎么归并，都是工具层的事（那里把「发与收」做成注入点，
//	测试就打在替身上，不需要真有一台摄像头在场）。
//
// ★ 只放设备自己说过的话。没说的字段留空，由界面写「这台没说」——
//
//	「按 MAC 前缀猜是海康」这种猜测是这一栏最不该出现的东西：
//	猜对九次、错一次，人就顺着错的那一次去机房。OUI 那一栏想看有 net.mac.analyze。
package broadcast

// 四种自报口径的名字。★ 它们会出现在结果 JSON 与界面上，是对外的词。
const (
	SourceSSDP        = "ssdp"
	SourceMDNS        = "mdns"
	SourceWSDiscovery = "ws-discovery"
	SourceNetBIOS     = "netbios"
)

// 各协议的端口与组播组。
const (
	PortSSDP        = 1900
	PortMDNS        = 5353
	PortWSDiscovery = 3702
	PortNetBIOSName = 137

	McastSSDPv4        = "239.255.255.250"
	McastSSDPv6        = "ff02::c" // UPnP 规范里写作 ff0X::c，X 是作用域，链路上就是 2
	McastMDNSv4        = "224.0.0.251"
	McastMDNSv6        = "ff02::fb"
	McastWSDiscoveryv4 = "239.255.255.250"
	McastWSDiscoveryv6 = "ff02::c"
)

// 限量。★ 广播这件事一旦收起来是没有上界的：一个 /16 里几十台 NAS 各自
//
//	能报出上百个 DNS-SD 实例，而这一栏是给人一眼看完的，不是日志。
const (
	MaxReports     = 400  // 最多留几条自报记录
	MaxNamesPerNB  = 50   // 一台 NetBIOS 机器最多报几个名（正常 6~12）
	MaxTXTBytes    = 1024 // 单条 TXT / 头集合的原文上限
	MaxDescBytes   = 64 << 10
	MaxHeaderLines = 40
	MaxURLBytes    = 600 // 一条管理地址的上限（XAddrs 里能塞一串）

	// MaxTTLSeconds 是「这条自报还能信多久」这一栏的上限。
	// ★ 报文里写几十年是合法的字段值，但不是能给人看的数：这一栏决定界面要不要
	//   提示「过期了，再问一次」。
	MaxTTLSeconds = 24 * 3600
)

// Report 一条自报记录：某个地址在某个协议里说的一句话。
//
// ★ 一台设备会有好几条（SSDP 一条、mDNS 三条、NetBIOS 一条），
//
//	归并成「一台设备」是工具层的事，这里不合并 —— 合并要看 MAC、地址、
//	主机名三个口径，那些信息跨协议，放在解码层反而各自残缺。
type Report struct {
	Source string `json:"source"` // 上面四个之一
	From   string `json:"from"`   // 应答来自哪个地址（IP，不带端口）

	// Iface 是从哪块网卡收到这条的。★ 解码层不填、也填不出来 —— 它不碰网卡；
	// 由工具层在收包那一步盖上去。两块网卡接两个网段时，这一栏决定下一步查哪边。
	Iface string `json:"iface,omitempty"`

	Name     string `json:"name,omitempty"`     // 主机名 / friendlyName / NetBIOS 计算机名
	Instance string `json:"instance,omitempty"` // DNS-SD 的服务实例名，如 "3F-A1B2C3" 或 "网络摄像头 2"
	Type     string `json:"type,omitempty"`     // _rtsp._tcp.local / urn:schemas-upnp-org:device:MediaServer:1 / dn:NetworkVideoTransmitter
	URL      string `json:"url,omitempty"`      // SSDP LOCATION / ONVIF XAddrs / UPnP 管理页
	Host     string `json:"host,omitempty"`     // SRV 指向的那台机器的主机名
	Port     int    `json:"port,omitempty"`     // SRV 给的端口
	MAC      string `json:"mac,omitempty"`      // 只有 NetBIOS node status 给得出

	UniqueID string            `json:"uniqueId,omitempty"` // USN / UDN / EndpointReference 的 uuid
	TTL      int               `json:"ttl,omitempty"`      // 这条记录还能信多久（秒）；0 = 对方在告退
	Group    bool              `json:"group,omitempty"`    // NetBIOS：这个名是组名（不是唯一名）
	Service  int               `json:"service,omitempty"`  // NetBIOS 第 16 个字符的服务编号
	Text     map[string]string `json:"text,omitempty"`     // DNS-SD TXT / SSDP 与 UPnP 的杂项头

	// Detail 是解码时顺手算出来的、给人看的一句人话（比如 NetBIOS 那个服务编号是什么服务）。
	// ★ 只有协议自己定义过的词才进这里；没定义的写「这个号段没定义」。
	Detail string `json:"detail,omitempty"`
}

// macString 把报文里那 6 个**裸字节**写成界面上的 MAC。
//
// ★ 为什么在这儿自己拼一份：工具层已有的 normMAC 洗的是**文本**形式的 MAC
//
//	（人输入的、别的工具给的），而 UNIT_ID 是 6 个二进制字节 —— 直接 string()
//	出来是一段非法 UTF-8，进了 JSON 变成一串替换符，抄进工单就是废的。
func macString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0F])
	}
	return string(out)
}
