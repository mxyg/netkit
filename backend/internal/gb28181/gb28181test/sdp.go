package gb28181test

import (
	"strconv"
	"strings"
)

// SDPOptions 配一份「平台发来的点播 SDP」。
//
// ★ 这份构造与探测端那份解析各写各的：口、地址、y=、a= 的拼法要是两边一起写错，
//
//	「点播来了读不读得懂」这一条就永远测不出来。
type SDPOptions struct {
	SessionName string // Live / Playback
	AddrType    string // IP4 / IP6
	Address     string
	Port        int
	PortCount   int // 非 0 时口写成 口/数量
	Formats     []string
	Direction   string // recvonly / sendonly / sendrecv
	SSRC        string // y= 的第一个字段
	ExtraY      string // y= 后面那几个各家写法不同的字段（原样跟在后面）
	URI         string // u=
	TTL         int
	Bandwidth   string // b= 原文，用来验「没建模的行也得留着」
}

func (o SDPOptions) withDefaults() SDPOptions {
	if o.SessionName == "" {
		o.SessionName = "Live"
	}
	if o.AddrType == "" {
		o.AddrType = "IP4"
	}
	if o.Address == "" {
		o.Address = "127.0.0.1"
	}
	if o.Port == 0 {
		o.Port = 30000
	}
	if len(o.Formats) == 0 {
		o.Formats = []string{"96"}
	}
	if o.Direction == "" {
		o.Direction = "recvonly"
	}
	return o
}

// InviteSDP 按 RFC 4566 的行序（v o s c t m a…）拼一份 INVITE 正文。
// ★ 行序是错的常见来源之一：把 a= 放到 m= 之前就成了会话级的属性，读的人找不着方向。
func InviteSDP(o SDPOptions) string {
	o = o.withDefaults()
	var b strings.Builder
	b.WriteString("v=0\r\n")
	b.WriteString("o=34020000001110000001 20250101 1 IN " + o.AddrType + " 127.0.0.1\r\n")
	b.WriteString("s=" + o.SessionName + "\r\n")
	c := "c=IN " + o.AddrType + " " + o.Address
	if o.TTL > 0 {
		c += "/" + strconv.Itoa(o.TTL)
	}
	b.WriteString(c + "\r\n")
	b.WriteString("t=0 0\r\n")
	if o.Bandwidth != "" {
		b.WriteString("b=" + o.Bandwidth + "\r\n")
	}
	if o.URI != "" {
		b.WriteString("u=" + o.URI + "\r\n")
	}
	port := strconv.Itoa(o.Port)
	if o.PortCount > 0 {
		port += "/" + strconv.Itoa(o.PortCount)
	}
	b.WriteString("m=video " + port + " RTP/AVP " + strings.Join(o.Formats, " ") + "\r\n")
	b.WriteString("a=" + o.Direction + "\r\n")
	if o.SSRC != "" {
		y := "y=" + o.SSRC
		if o.ExtraY != "" {
			y += " " + o.ExtraY
		}
		b.WriteString(y + "\r\n")
	}
	b.WriteString("a=rtpmap:96 PS/90000\r\n")
	return b.String()
}
