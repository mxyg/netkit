package throughput

import (
	"net"
	"strconv"
	"syscall"
)

// TCPInfo 是这条连接在自己那侧的内核里的账。
//
// ★ 外层那些数（速率、往返）只说明「慢」，这一层才说明「为什么慢」：
//
//	重传在涨 —— 链路真在丢包，不是我们发得慢；
//	拥塞窗口 × 8 ÷ 往返 远小于实测 —— 速率的顶是 TCP 自己压下来的；
//	发送缓冲里囤着一大块 —— 内核也发不出去，卡在链路上而不是应用层。
//
// 哪些字段取得到，取决于这台机器的内核给不给：拿不到的一律明说，
// 不拿「0」冒充「没有重传」。
type TCPInfo struct {
	Given bool   `json:"given"`
	Why   string `json:"why,omitempty"`
	// Source 说清这一份账是从哪个接口取的 —— 出问题时得能判断是不是这台给错了。
	Source          string  `json:"source,omitempty"`
	State           string  `json:"state,omitempty"`
	SrttMs          float64 `json:"srttMs"`
	RttvarMs        float64 `json:"rttvarMs"`
	RetransSegments int64   `json:"retransSegments"`
	SndCwndBytes    int64   `json:"sndCwndBytes"`
	MaxSegBytes     int64   `json:"maxSegBytes"`
	// SndBufBytes 是发送缓冲里囤着的字节（含在途）。不是每台内核都给，所以是可选的。
	SndBufBytes *int64 `json:"sndBufBytes,omitempty"`
}

func absentTCPInfo(why string) TCPInfo {
	return TCPInfo{Why: why}
}

// enableTCPInfo 在一条刚握完手、还没开打的连接上尽力打开内核那份账的采集开关。
//
// ★★ 为什么要在传输之前调：Windows 的每连接统计默认不采，且重传这类计数是「自开启起累加」的
//
//	—— 等到传完再开，只能数到最后那几帧，报出来的「重传 0 段」是假的。macOS/Linux 上这一步是空操作
//	（那两份账现取现得）。这一步 best-effort：成不成都不报，读账时再按「这台给不给」说话。
func enableTCPInfo(c net.Conn) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) { enableConnTCPStats(fd) })
}

// tcpInfoOf 从一条还开着的连接上取内核的账。★ 只在连接关闭前取：
//
//	另起一条连接去问，问回来的是另一条的状态，与刚才那一段传输无关。
func tcpInfoOf(c net.Conn) TCPInfo {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return absentTCPInfo("这条连接拿不到内核句柄，取不到它的账")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return absentTCPInfo("拿不到内核句柄：" + err.Error())
	}
	var out TCPInfo
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		out, cerr = socketTCPInfo(fd)
	}); err != nil {
		return absentTCPInfo("读内核的账这一步没走成：" + err.Error())
	}
	if cerr != nil {
		return absentTCPInfo(cerr.Error())
	}
	out.Given = true
	return out
}

// CeilingMbps 是按「拥塞窗口 ÷ 往返」算出来的那一侧的顶：TCP 在这一条连接上
//
//	自己允许跑多快。实测贴近它，说明速率是内核的算法压的，不是链路饱和；
//	实测远低于它，说明还有别的东西在拦（对面收得慢、限速、应用层）。
//	取不到这两个数就返回 false —— 别拿一个猜出来的顶去比对。
func (t TCPInfo) CeilingMbps() (float64, bool) {
	if !t.Given || t.SrttMs <= 0 || t.SndCwndBytes <= 0 {
		return 0, false
	}
	return float64(t.SndCwndBytes) * 8 / (t.SrttMs / 1000) / 1e6, true
}

// tcpStates 取自 RFC 793 那套状态号（Linux 与 macOS 在这一段是一致的）。
var tcpStates = [...]string{
	"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSE_WAIT",
	"CLOSING", "LAST_ACK", "FIN_WAIT_1", "FIN_WAIT_2", "TIME_WAIT",
}

func tcpStateName(n uint8) string {
	if int(n) < len(tcpStates) {
		return tcpStates[n]
	}
	return "未知状态(" + strconv.Itoa(int(n)) + ")"
}
