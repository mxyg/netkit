package throughput

// Windows 每连接扩展统计（iphlpapi 的 GetPerTcpConnectionEStats / SetPerTcpConnectionEStats）
// 用得到那几份结构体，以及「把系统写回来的字节解成 TCPInfo」这一步。
//
// ★★ 这个文件不带构建标记，和 bandwidth_parse.go / portproc_parse.go 同一个套路：
//
//	「解量到的字节」这件事必须能在开发机（darwin/linux）上被同一批测试解一遍，
//	留在 windows 文件里就只剩编译过、从没被真正解过。真正碰 iphlpapi.dll 的那几层
//	（getsockopt、Set、Get、缓冲不够就放大重问）都在 tcpinfo_windows.go 里。
//
// 结构体的偏移不是猜的：TCPSaturationV0/MIB_TCP_ESTATS_* 是更早那一代 Vista 的东西，
// 现在 Win7/Win10/Win11 上 iphlpapi 导出的是 RFC4898 那一代（Tcpestats.h）——
// 下面的字段与顺序按 Microsoft Learn 的 VERSION_0 结构逐条核对过（见每个字段后面的注释）。

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

// TCP_ESTATS_TYPE（Tcpestats.h）里我们只用得上这两组：
//
//	estatsPath   → TCP_ESTATS_PATH_ROD_v0   ：往返、往返方差、重传段数、当前 MSS
//	estatsSndCong → TCP_ESTATS_SND_CONG_ROD_v0：当前拥塞窗口（字节）
const (
	estatsSndCong uint32 = 2
	estatsPath    uint32 = 3
)

// iphlpapi 这两个函数直接 return 一个 ULONG 状态码（0 == NO_ERROR），不走 GetLastError。
// 这里只列我们分得清、且要各给一句话的那些。
const (
	estatNoError          uint32 = 0
	estatNotFound         uint32 = 2    // ERROR_NOT_FOUND：这条连接不在表里了（对测里跑到一半关了，正常）
	estatAccessDenied     uint32 = 5    // ERROR_ACCESS_DENIED：开统计要管理员
	estatInvalidParameter uint32 = 87   // ERROR_INVALID_PARAMETER
	estatNotSupported     uint32 = 50   // ERROR_NOT_SUPPORTED：版本/偏移参数没给 0
	estatInsufficientBuf  uint32 = 122  // ERROR_INSUFFICIENT_BUFFER == ERROR_MORE_DATA：缓冲太小，放大重问
	estatInvalidUsrBuf    uint32 = 1784 // ERROR_INVALID_USER_BUFFER：Win7 上「缓冲太小/缓冲非法」这一类
)

// mibTCPRow 是 MIB_TCPROW（iprtrmib.h）：五个 DWORD，全 32 位对齐，任何平台都是 20 字节。
// Get/SetPerTcpConnectionEStats 靠这五格（本机地址端口 + 对端地址端口）认是哪一条连接。
//
// ★ 地址与端口都按 Windows 的规矩存成「网络字节序」：
//   - dwAddr = IPv4 四字节按大端拼成的 DWORD（127.0.0.1 → 0x7F000001）
//   - dwPort = 把主机序端口转网络序后放进低 16 位（htons(port)）
type mibTCPRow struct {
	dwState      uint32 // 我们只按四元组查，填 0（这两函数不看它）
	dwLocalAddr  uint32
	dwLocalPort  uint32
	dwRemoteAddr uint32
	dwRemotePort uint32
}

// rwEnable 是 TCP_ESTATS_{PATH,SND_CONG}_RW_v0：都只有一个 BOOLEAN EnableCollection（1 字节）。
// 开统计时写 1；读回来的这一格为 0 就说明「这台机器上这条连接的统计没开起来」，
// 那 Ros/Rod 里是随机数，绝不当账用（MSDN 明说 EnableCollection=FALSE 时数据未定义）。
type rwEnable struct {
	enableCollection uint8
}

// pathRodV0 是 TCP_ESTATS_PATH_ROD_v0（全部 ULONG，40 个）：整份结构在 386 与 amd64 上
// 布局完全一致（没有任何宽度随架构变的字段），所以按字节偏移读最稳。我们只取其中四格。
type pathRodV0 struct {
	FastRetran            uint32 // 0
	Timeouts              uint32 // 4
	SubsequentTimeouts    uint32 // 8
	CurTimeoutCount       uint32 // 12
	AbruptTimeouts        uint32 // 16
	PktsRetrans           uint32 // 20  含重传数据的段数（tcpEStatsPerfSegsRetrans）
	BytesRetrans          uint32 // 24
	DupAcksIn             uint32 // 28
	SacksRcvd             uint32 // 32
	SackBlocksRcvd        uint32 // 36
	CongSignals           uint32 // 40
	PreCongSumCwnd        uint32 // 44
	PreCongSumRtt         uint32 // 48
	PostCongSumRtt        uint32 // 52
	PostCongCountRtt      uint32 // 56
	EcnSignals            uint32 // 60
	EceRcvd               uint32 // 64
	SendStall             uint32 // 68
	QuenchRcvd            uint32 // 72
	RetranThresh          uint32 // 76
	SndDupAckEpisodes     uint32 // 80
	SumBytesReordered     uint32 // 84
	NonRecovDa            uint32 // 88
	NonRecovDaEpisodes    uint32 // 92
	AckAfterFr            uint32 // 96
	DsackDups             uint32 // 100
	SampleRtt             uint32 // 104
	SmoothedRtt           uint32 // 108 平滑往返，单位「毫秒」（MSDN 明说）
	RttVar                uint32 // 112 往返方差，单位「毫秒」
	MaxRtt                uint32 // 116
	MinRtt                uint32 // 120
	SumRtt                uint32 // 124
	CountRtt              uint32 // 128
	CurRto                uint32 // 132
	MaxRto                uint32 // 136
	MinRto                uint32 // 140
	CurMss                uint32 // 144 当前 MSS，单位「字节」
	MaxMss                uint32 // 148
	MinMss                uint32 // 152
	SpuriousRtoDetections uint32 // 156
}

// sndCongRodV0 是 TCP_ESTATS_SND_CONG_ROD_v0。它里面有三格 SIZE_T
// （SndLimBytesRwin/Cwnd/Snd）—— SIZE_T 在 386 上是 4 字节、amd64 上是 8 字节，
// 且两边都按自身宽度对齐，所以 CurCwnd 的偏移两档不一样（386→48，amd64→60）。
//
// ★★ 这正是「写死十进制偏移就会在一档上读出错数」的那个坑。所以这里把 SIZE_T 记成
//
//	uintptr（Go 里 uintptr 在 386 是 4、amd64 是 8，对齐也随平台，和 Windows 的 SIZE_T 同步），
//	读的时候直接把缓冲当成这份结构用 unsafe.Offsetof 取字段，让编译器替我们对齐 ——
//	不数偏移。测试里再拿 unsafe.Offsetof 钉住这份定义自己没被改歪。
type sndCongRodV0 struct {
	SndLimTransRwin uint32
	SndLimTimeRwin  uint32
	SndLimBytesRwin uintptr // SIZE_T
	SndLimTransCwnd uint32
	SndLimTimeCwnd  uint32
	SndLimBytesCwnd uintptr // SIZE_T
	SndLimTransSnd  uint32
	SndLimTimeSnd   uint32
	SndLimBytesSnd  uintptr // SIZE_T
	SlowStart       uint32
	CongAvoid       uint32
	OtherReductions uint32
	CurCwnd         uint32 // 当前拥塞窗口，单位「字节」
	MaxSsCwnd       uint32
	MaxCaCwnd       uint32
	CurSsthresh     uint32
	MaxSsthresh     uint32
	MinSsthresh     uint32
}

var (
	errIPv6Row  = errors.New("对测这一侧不是 IPv4，这份 Windows 账只核对过 IPv4 那一张结构")
	errShortRow = errors.New("系统给回的地址长度不够，认不出这条连接")
)

// endpointToRow 把两份 Windows SOCKADDR_IN 原始字节（getsockopt 拿回来的那份）
// 拼成查 eStats 用的 MIB_TCPROW。这是纯函数，开发机上拿造的字节就能测。
func endpointToRow(local, remote []byte) (mibTCPRow, error) {
	la, lp, err := sockaddrInToDWord(local)
	if err != nil {
		return mibTCPRow{}, err
	}
	ra, rp, err := sockaddrInToDWord(remote)
	if err != nil {
		return mibTCPRow{}, err
	}
	return mibTCPRow{
		dwLocalAddr:  la,
		dwLocalPort:  lp,
		dwRemoteAddr: ra,
		dwRemotePort: rp,
	}, nil
}

// sockaddrInToDWord 从一份 SOCKADDR_IN 里取出（地址 DWORD、端口 DWORD），都按网络序摆好。
// 布局：[0:2]=sa_family（小端）、[2:4]=sin_port（网络序）、[4:8]=sin_addr（网络序四字节）。
func sockaddrInToDWord(sa []byte) (addr, port uint32, err error) {
	if len(sa) < 8 {
		return 0, 0, errShortRow
	}
	if family := uint16(binary.LittleEndian.Uint16(sa[:2])); family != windowsAF_INET {
		return 0, 0, errIPv6Row
	}
	// 地址四字节是大端语义拼 DWORD；端口那两字节本来就是网络序，
	// 按小端读进 DWORD 低 16 位，正好等于 Windows 要的 htons 值。
	addr = binary.BigEndian.Uint32(sa[4:8])
	port = uint32(binary.LittleEndian.Uint16(sa[2:4]))
	return addr, port, nil
}

// windowsAF_INET 就是 AF_INET；放在不带构建标记的文件里，测试才造得出这份地址族。
const windowsAF_INET = 2

// parsePathROD 把 TCP_ESTATS_PATH_ROD_v0 的字节解进 info。
// 返回 false 表示这份缓冲连最靠后的 CurMss 都没到 —— 那时一个字段都不该写（宁可整格空，
// 也不拿半截缓冲里已经落好的 srtt 配一个还没落到的 cwnd 去算顶速）。
func parsePathROD(rod []byte, info *TCPInfo) bool {
	// CurMss 是这四个里偏移最大的一格；到得了它，前面三格必然到得了。
	need := int(unsafe.Offsetof(pathRodV0{}.CurMss)) + 4
	if len(rod) < need {
		return false
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(rod[off:]) }
	info.SrttMs = float64(u32(int(unsafe.Offsetof(pathRodV0{}.SmoothedRtt))))
	info.RttvarMs = float64(u32(int(unsafe.Offsetof(pathRodV0{}.RttVar))))
	info.RetransSegments = int64(u32(int(unsafe.Offsetof(pathRodV0{}.PktsRetrans))))
	info.MaxSegBytes = int64(u32(int(unsafe.Offsetof(pathRodV0{}.CurMss))))
	return true
}

// parseSndCongROD 解 TCP_ESTATS_SND_CONG_ROD_v0 里的 CurCwnd。这份有 SIZE_T 字段，
// 偏移随架构变，所以走 unsafe 把缓冲当结构用，让编译器替我们按本平台对齐；
// 这在 darwin/amd64（uintptr=8，与 windows/amd64 同布局）上拿 fixture 也测得出同一格。
func parseSndCongROD(rod []byte, info *TCPInfo) bool {
	if len(rod) < int(unsafe.Sizeof(sndCongRodV0{})) {
		return false
	}
	// make([]byte) 至少 8 字节对齐，够放这份里最宽的对齐要求（uintptr）。
	p := (*sndCongRodV0)(unsafe.Pointer(unsafe.SliceData(rod)))
	info.SndCwndBytes = int64(p.CurCwnd)
	return true
}
