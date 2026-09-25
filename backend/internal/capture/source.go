// 取包这一层的口径：每个平台各一档（Linux 的 AF_PACKET 环、macOS 的 /dev/bpf、Windows 的 pktmon），
// 但对上层只露一张脸 —— 现场抓来的包和读 pcapng 文件得到的是同一个 Packet。
// 理由很实在：「抓一份」和「拿同事抓好的那一份」必须走同一套解包与聚合，
// 两套代码就会有两套脾气，同一台设备在两张表上给出两个结论。
package capture

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// 采集口的错误。分开是有原因的：「没权限」和「这个口不存在」在界面上是两句话，
// 给用户的建议也完全不同（一个去提权，一个换块网卡）。
var (
	// ErrNeedPrivilege：这一档要 root 或 CAP_NET_RAW，普通用户起不来。
	ErrNeedPrivilege = errors.New("capture: 要 root 或 CAP_NET_RAW 才起得来这个口")
	// ErrUnsupported：这个平台还没有采集档（能读文件，不能现场抓）。
	ErrUnsupported = errors.New("capture: 这个平台还没有现场抓包这一档")
	// ErrClosed：口已经关了还在读。
	ErrClosed = errors.New("capture: 这个抓包口已经关了")
	// ErrNoSuchInterface：点名的口在这台机器上没有。
	ErrNoSuchInterface = errors.New("capture: 这台机器上没有这个口")
)

// Options 是一次采集的口径。零值 = 「所有口、按默认留长、别改系统」。
type Options struct {
	// Interface 是要抓的口名；空 = 这台机器上所有口。
	// ★ 点名的口不存在时 Open 直接报 ErrNoSuchInterface，不许悄悄退化成「抓所有口」——
	//   现场最常见的误判就是「抓了半天没有对方的包」，因为抓的是另一块网卡。
	Interface string
	// SnapLen 是一包最多留多少字节；0 = DefaultSnapLen。
	SnapLen int
	// BufferSize 是环的大小（字节）；0 = DefaultBufferSize。
	// 现场丢包十有八九是环小了，不是「网络慢了」，所以这一格要能在界面上调、
	// 也要能报出「这一路丢了几包」。
	BufferSize int
	// Promisc 开混杂模式：不是发给本机的帧也收。
	// 交换机上本来也收不到别人的单播，开了只对集线器和镜像口有意义 —— 它不是「抓到别人的包」的开关。
	Promisc bool
	// BlockRetire 是一块攒多久就强制交给用户（哪怕没装满）；0 = DefaultBlockRetire。
	// ★ 没有这一档，低流量时界面会「抓到了但看不见」：包躺在没退休的块里，
	//   看着就像网络没流量。这一格专门用来把「等不到包」和「真的没包」分开。
	BlockRetire time.Duration
	// Timestamp 要哪一种打戳方式。
	Timestamp TimestampKind
}

// TimestampKind 是要哪一种打戳方式。
type TimestampKind uint8

const (
	// TSDefault：内核给什么用什么（绝大多数是软中断那一刻）。
	TSDefault TimestampKind = iota
	// TSSoftware：进内核那一刻的戳。
	TSSoftware
	// TSHardware：网卡打的戳。拿不到时如实报错，不许悄悄退回软件时刻 ——
	// 拿它算出来的延迟会差一截，而报表上完全看不出来。
	TSHardware
)

// Stats 是这一路的账。
type Stats struct {
	Packets uint64 // 已经递到用户手里的包数
	Dropped uint64 // 内核那份计数：环满丢的（不是我们没读）
	// Lossy：内核在包上标过「这一路丢过」（TP_STATUS_LOSING）。
	// 单列不并进 Dropped：那份计数拿不到时，这一格是「确实丢过、但说不出几包」唯一的凭据。
	// 界面上这两种口径要分开写，别混成一个数。
	Lossy      bool
	Interfaces int // 这一路见过几个口
}

// Source 是一个开着的采集口。
type Source interface {
	// Next 取下一包，没有就等着（块按 BlockRetire 那档按时交出来，不会一直等）。
	// Close 之后还在读的这一路拿 ErrClosed，不 panic。
	Next() (Packet, error)
	// Stats 回这一路的账；平台给不了的字段如实填 0，不许猜。
	Stats() Stats
	// Interfaces 回这一路见过的口，顺序稳定：包里的 InterfaceIndex 按它对应，
	// 也直接就是写 pcapng 时要的那几条 IDB。
	Interfaces() []Interface
	// Close 收口。
	Close() error
}

// DefaultSnapLen 是一包默认留多少字节。
// 取 1600 不是凑整：1500 MTU 的全帧连链路头一起放得下，
// 再往上就是 Jumbo 口，抓全帧会把环撑爆 —— 那种口径要让调用方明写。
const DefaultSnapLen = 1600

// DefaultBufferSize 是环的默认大小。
const DefaultBufferSize = 4 << 20

// DefaultBlockRetire 是一块最多攒多久就交出去。
// 100ms 是「界面看得出在动」和「系统调用不碎」之间的那一档。
const DefaultBlockRetire = 100 * time.Millisecond

// sourceIfaces 把「要哪个口」落成口名列表。空 = 所有口
// （含 lo：现场往往只有回环上的东西抓得到，比如本机服务自己连自己）。
// 放在平台中立这一份里：两档的「要哪个口」必须是同一句话，不然界面上同样的勾
// 在两个平台上抓到的东西不一样，那种差别没人能从结果里看出来。
func sourceIfaces(want string) ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("capture: 列不出网卡：%w", err)
	}
	if want == "" {
		out := make([]string, 0, len(ifs))
		for _, in := range ifs {
			out = append(out, in.Name)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("capture: 这台机器上一个口都列不出来")
		}
		return out, nil
	}
	for _, in := range ifs {
		if in.Name == want {
			return []string{want}, nil
		}
	}
	// ★ 点名的口不存在时直接报，不许退化成「那就全抓」：
	//   现场最常见的误判就是「抓了半天没有对方的包」，因为抓的是另一块网卡。
	return nil, fmt.Errorf("capture: 这台机器上没有叫 %q 的口（%w）", want, ErrNoSuchInterface)
}

// linkTypeOfARPHRD 把 Linux 的 ARPHRD_* 换成 pcapng 的链路类型号。
// 认不出的如实返回 false：写错号不会报错，只会让上层把裸 IP 当以太网解，
// 解出来的「源地址」是链路头的前四字节 —— 所以这一张表宁缺勿滥。
func linkTypeOfARPHRD(arphrd uint16) (uint16, bool) {
	switch arphrd {
	case arphrdEthernet:
		return LinkTypeEN10MB, true
	case arphrdLoopback:
		// Linux 的 lo 带一段假以太网头，真产物（dumpcap）也把 lo 写成以太网，这里跟着走。
		return LinkTypeEN10MB, true
	case arphrdPPP:
		return LinkTypeRaw, true
	case arphrdIEEE80211:
		return LinkTypeIEEE80211, true
	case arphrdRadioTap:
		return LinkTypeRadioTap, true
	}
	return 0, false
}

// Linux 的 ARPHRD_* 号（只列这张表用到的）。
const (
	arphrdEthernet = 1
	arphrdLoopback = 772
	arphrdPPP      = 24
	// ARPHRD_IEEE80211 与 _RADIOTAP 是一对：前者是裸 802.11 帧，后者带 RadioTap 头。
	arphrdIEEE80211 = 800
	arphrdRadioTap  = 803
)

// 环的排布（linux/if_packet.h 那一套）。
//
// ★ 这几格是临时容器里拿 gcc 对着内核头量出来的（sizeof 与 offsetof 各印了一遍），
//
//	不是按名字猜的：读错偏移不会崩，它只会把链路头的第二个字节当成时刻的低位，
//	于是一份错账绿着通过。所以每一格都拿内核真填出来的环对过一遍，
//	见 source_linux_test.go 里那条「用现场环字节钉住这张表」的测试。
const (
	tpacketAlignment = 16

	tpacket3HdrSize = 48 // sizeof(struct tpacket3_hdr)：next/sec/nsec/snaplen/len/status + mac/net + 补
	sockaddrLLSize  = 20 // sizeof(struct sockaddr_ll)：内核把它写在包头后面那 48..68
	// tpacket3HdrLen 就是内核那个宏 TPACKET3_HDRLEN（= align(48) + 20 = 68）：
	// 内核拿它当「一帧至少要多大」的下限。
	tpacket3HdrLen = tpacket3HdrSize + sockaddrLLSize

	// tpacketFrameHeadroom 是一帧里「包头 + 到链路副本起点」占掉的那一份。
	// 实测（lo 与 eth0 各一遍）：sockaddr_ll 到 68 结束，链路头从帧首 +82 开始 ——
	// 也就是别按 TPACKET3_HDRLEN 排数据，中间还有对齐那几格。
	// 留 96 是往上进到整格：多十几字节，换「哪一版内核把 mac 偏移算大一点都不写穿下一帧」。
	tpacketFrameHeadroom = 96

	// tpacketBlockHdrLen = sizeof(struct tpacket_block_desc)，块头那 48 字节。
	// 第一包从块首 + offset_to_first_pkt 开始（实测也是 48，正好接在块头后面）。
	tpacketBlockHdrLen = 48

	// tpacketMinPktSpan 是一包在块里至少占多少字节 —— 就是上面那条「链路头从帧首 +82
	// 开始」那个数：包头加 sockaddr_ll 加对齐，一包再怎么小也要先吃掉这么多。
	// 拿它反推「这一块说塞了 num 包，兜不兜得住」，兜不住就是布局对不上（见 checkBlock）。
	tpacketMinPktSpan = 82
)

func tpacketAlign(n int) int { return (n + tpacketAlignment - 1) &^ (tpacketAlignment - 1) }

// maxRingBytes 是环的字节数上限（超出就如实报错，不去试那一下）。
// 内核给这一格的限制每一版写的形式不同（有的看总长、有的看单个块），
// 撞上去只回一句 EINVAL，看不出是哪一格挤的 —— 能在这里挡住的先挡住。
//
// 用 int64 而不是 int：32 位平台上「块数 × 块大小」本身就可能在 int 里绕回负数，
// 拿 int 比较等于把溢出那一路当成合法值放过去。
const maxRingBytes int64 = 1 << 31

// ringPlan 把「想要多大环、一包留多少」算成内核要的那四个数。
//
// ★ 内核这一档要求很硬：块大小必须是页的整数倍、帧数 = 每块帧数 × 块数
//
//	（差一格就是一句 EINVAL，什么都不细说），所以先把数算对。
//	另：V3 往块里塞包是按 tp_next_offset 紧挨着排的（一块能塞下远超「块÷帧」的包数），
//	frame_size 只用来定容量口径 —— 它不是读包时的步长，那是另一个坑，见 takePacket。
func ringPlan(bufferSize, snapLen, pageSize int) (blockSize, blockNr, frameSize, frameNr int, err error) {
	if snapLen < 0 {
		return 0, 0, 0, 0, fmt.Errorf("capture: 留长不能为负（%d）", snapLen)
	}
	if bufferSize < 0 {
		return 0, 0, 0, 0, fmt.Errorf("capture: 环大小不能为负（%d）", bufferSize)
	}
	if snapLen == 0 {
		snapLen = DefaultSnapLen
	}
	if bufferSize == 0 {
		bufferSize = DefaultBufferSize
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	frameSize = tpacketAlign(tpacketFrameHeadroom + snapLen)
	// 一块至少装得下一整帧，还得把块头本身那 48 字节算进去。
	blockSize = tpacketAlign(frameSize + tpacketBlockHdrLen)
	if rem := blockSize % pageSize; rem != 0 {
		blockSize += pageSize - rem
	}
	if blockSize/frameSize < 1 {
		return 0, 0, 0, 0, fmt.Errorf("capture: 块算出来 %d 字节，装不下一帧（%d 字节，留长 %d）", blockSize, frameSize, snapLen)
	}
	// 环至少两块：只有一块的话，用户还没读完这一块，新包就得干等它空出来。
	blockNr = bufferSize / blockSize
	if blockNr < 2 {
		blockNr = 2
	}
	// 乘法在 int64 里做：32 位平台上先绕回负数再比较，等于没挡。
	if total := int64(blockSize) * int64(blockNr); total >= maxRingBytes {
		return 0, 0, 0, 0, fmt.Errorf("capture: 环要 %d 块 × %d 字节，大到这一个口记不下了（留长 %d）", blockNr, blockSize, snapLen)
	}
	frameNr = (blockSize / frameSize) * blockNr
	return blockSize, blockNr, frameSize, frameNr, nil
}

// defaultPageSize 是算环时假定的页大小。真取值由平台档传进来（这一格不能猜：
// 4K 与 64K 的机器上，同一个「4MB 环」会被切成不同块数，丢包口径就不一样了）。
const defaultPageSize = 4096
