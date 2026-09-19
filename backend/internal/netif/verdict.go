package netif

// 网卡状态的**判定码**。
//
// ★★ 为什么不直接返回一句中文（老板 2026-09-19：要支持多语种，参考 stage）：
//
//	开工第一版的 describe() 是这么写的 ——
//	    return "IPv4 正常（IPv6 没有可用地址），网段 " + strings.Join(nets, "、")
//	三个毛病：
//	  ① 拼死的中文没法翻译
//	  ② **字符串拼接锁死了语序**。日语、俄语的语序和中文不一样，
//	     "…，网段 X" 这种结构翻译只能硬凑
//	  ③ 要多语种就得在 Go 里再做一套 i18n，和前端两套词典，必然走偏
//
//	所以后端只给**判定**，不给**句子**：一个判定码 + 一组参数，句子由前端渲染
//	（前端用 stage 那套「中文原文当 key」的词典，见 docs/设计.md「多语种」）。
//
// ★ 好处不止翻译：**判定码是能被程序消费的**。体检项、排障决策树、诊断报告导出、
// 以及 AI 交互要用的「现场事实」，要的都是「这块网卡处于哪种状态」，不是一句中文。
// 一句拼好的中文程序读不懂，只能回头拿正则去匹配它 —— 那是自找麻烦。
type VerdictCode string

const (
	VerdictLoopback  VerdictCode = "loopback"   // 本机回环
	VerdictVirtual   VerdictCode = "virtual"    // 虚拟网卡
	VerdictDown      VerdictCode = "down"       // 网卡已禁用
	VerdictNoCarrier VerdictCode = "no-carrier" // 已启用但没检测到连接
	VerdictDualStack VerdictCode = "dual-stack" // v4 v6 都有可用地址
	VerdictV4Only    VerdictCode = "v4-only"    // 只有 v4 可用（v6 没有可用地址）
	VerdictV6Only    VerdictCode = "v6-only"    // 只有 v6 可用（v4 没有可用地址）
	VerdictLinkLocal VerdictCode = "link-local" // 只有 fe80::：网卡是好的，但 DHCP 和 RA 都没给地址
	VerdictNoAddress VerdictCode = "no-address" // 一个地址都没拿到
)

// Verdict 一块网卡的判定结果。给界面、给体检、给 AI 用的都是它。
type Verdict struct {
	Code     VerdictCode `json:"code"`
	Networks []string    `json:"networks,omitempty"` // 所在网段，v4 v6 都在里面
	// USB 这块网卡看着像哪类 USB 设备（""/lan/4g）。
	// ★ 单独一个字段，不是拼在句子尾巴上的后缀 —— 原来那个 `+ usb` 的写法
	//   在语序不同的语言里根本没地方放。
	USB string `json:"usb,omitempty"`
}

// Judge 判定这块网卡处于什么状态。
//
// ★ 这里只做判断，一个字的文案都不产生。
func (n NIC) Judge() Verdict {
	v := Verdict{USB: USBKind(n.Name)}
	switch {
	case n.Loop:
		v.Code = VerdictLoopback
		return v
	case n.Virtual:
		v.Code = VerdictVirtual
		return v
	case !n.Up:
		v.Code = VerdictDown
		return v
	case !n.Running:
		v.Code = VerdictNoCarrier
		return v
	}

	v.Networks = n.Networks()
	v4, v6 := n.HasUsableV4(), n.HasUsableV6()
	switch {
	case v4 && v6:
		v.Code = VerdictDualStack
	case v4:
		// ★ 不判成「正常」。IPv6 没地址在今天多数现场是常态，但它**是个事实**，
		//   排查「某些网站打不开 / 连接很慢」时要用到，不能不报。
		v.Code = VerdictV4Only
	case v6:
		v.Code = VerdictV6Only
	case n.HasLinkLocalV6():
		// 只有 fe80:: 是个**很具体**的故障形态：网卡本身是好的，
		// 但 IPv4 的 DHCP 没要到地址、IPv6 也没收到路由通告（RA）。
		// 和「什么都没有」要分开，因为下一步该做什么不一样。
		v.Code = VerdictLinkLocal
	default:
		v.Code = VerdictNoAddress
	}
	return v
}
