package gb28181

// GB/T 28181 的 20 位编号（附录 D 那套）。
//
// ★ 为什么这一层只切不解释：公开资料对「1~8 / 9~10 / 11~13 / 14~20」这几段的
//
//	叫法就不一致（第 9~10 位有的写成行业编码、有的写网络标识；第 14 位有的实现
//	单独当网络标识、有的并到序号里）。这不是查得不细，是各家实现本身就没统一。
//	所以这里只对两件有把握的事下结论：长度 20 且全数字、第 11~13 位是设备类型标识。
//	其余只切段、不改名，界面上给的是「按位置切出来是这样」，不是「它一定是什么」。
//
// ★ 类型名只收多份来源一致的四个码，并且宁可少收：
//
//	131 在不同资料里一会儿是摄像机、一会儿是 DVR/NVR —— 这种冲突的码一律不解释，
//	取不到名字时工具层显示原样数字。编号这东西报错一个名字，人就照着那个名字去查设备，
//	比「不知道」更贵。

import (
	"fmt"
	"strings"
)

// CodeLen 是国标编号的长度。
const CodeLen = 20

// Code 是按位置切开的一段编号。
type Code struct {
	Raw      string
	Center   string // 1~8
	Industry string // 9~10
	Type     string // 11~13 类型标识
	Serial   string // 14~20
}

// 编号类型。★ 分成「设备类 / 中心类」是因为现场这一条最常错：
// 设备的编号栏里填了平台的编号，注册那一步照样回 200，
// 通道表却永远查不出来 —— 只有把类型切开看才抓得到。
const (
	CodeClassDevice  = "device"
	CodeClassCenter  = "center"
	CodeClassUnknown = "unknown"
)

// 有把握的类型码：码 => 名字。多来源对照过才进这张表。
var codeTypeNames = map[string]string{
	"111": "DVR",
	"118": "NVR",
	"132": "网络摄像机",
	"200": "中心信令控制服务器（平台）",
}

// ParseCode 切开一段编号。不是 20 位数字时返回 error，error 里说清差在哪：
// 「短了 3 位」和「中间有个字母」下一步完全不一样（前者多半是抄漏，后者多半是粘错）。
func ParseCode(s string) (Code, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Code{}, fmt.Errorf("编号是空的")
	}
	if len(raw) != CodeLen {
		return Code{}, fmt.Errorf("编号应当是 %d 位，这条是 %d 位", CodeLen, len(raw))
	}
	for i, r := range raw {
		if r < '0' || r > '9' {
			return Code{}, fmt.Errorf("编号第 %d 位是 %q，国标编号只允许数字", i+1, r)
		}
	}
	return Code{
		Raw:      raw,
		Center:   raw[0:8],
		Industry: raw[8:10],
		Type:     raw[10:13],
		Serial:   raw[13:20],
	}, nil
}

// ValidCode 只回答「像不像一段国标编号」，不返回切分。
func ValidCode(s string) bool { _, err := ParseCode(s); return err == nil }

// Class 按类型标识所在的数字区间分设备类与中心类。
// ★ 区间口径（111~199 为设备、200 起为中心/平台）是这几份资料都一致的部分；
// 落在区间外（比如 100、131 之外的未列码）返回 unknown，让界面明说「不知道」。
func (c Code) Class() string {
	n, err := atoi(c.Type)
	if err != nil {
		return CodeClassUnknown
	}
	switch {
	case n >= 111 && n <= 199:
		return CodeClassDevice
	case n >= 200 && n <= 299:
		return CodeClassCenter
	}
	return CodeClassUnknown
}

// TypeName 给出有把握的类型名；表里没有时 ok=false。
func (c Code) TypeName() (string, bool) {
	n, ok := codeTypeNames[c.Type]
	return n, ok
}

func atoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("空")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("非数字")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
