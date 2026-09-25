package capture

// pktmon 这一档里「不碰系统」的那一份：命令怎么拼、一段多大、包该不该递上去。
//
// ★ 为什么单独一份、而且不带 build tag：Windows 那一档要 exec 系统命令，它的测试得
//   交叉编译到 windows 才跑得动；纯算术和纯解析留在这一份里，改代码的这台机器上
//   就能把它按红，反证不必挑一台 Windows 做。
//
// 这里的每一个数、每一种形状都是在 UTM 里那台 Win11 ARM64（26200，中文系统）上量出来的，
// 清单在 source_windows.go 顶上。

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// pktmonCompNics 是「只收网卡」那一个组件选择器，也是这一档唯一在用的选择器。
	// ★ 不许换成 `--comp <某块网卡的号>`：实测那样只有出的方向，一个进来的包都没有
	//   （同一台机器、同样十个 ping：nics 收到 26 进 14 出，--comp 1 收到 0 进 7 出）。
	//   也不许不写：默认 ALL 组件会把同一个包抄四份。
	pktmonCompNics = "nics"

	// pktmonBusyExit 是「这台机器上已经有一路在录」那一个退出码（实测 159）。
	// 只认这一格的数，不认它说的话 —— 它在这种情况下说的是「已启动数据包监视器。」。
	pktmonBusyExit = 159

	// pktmonMinSegment 是一段的最小长度。
	// 这一档看不见正在录的东西：包要等 stop + 转成 pcapng 才读得到，所以「多久交一次」
	// 就是段长，跟另外两档的 BlockRetire 不是一回事。下限取 1s 的依据是实测：
	// 一次换段（stop → 立刻起下一段 → 转旧段）在那台机器上约 0.1s，1s 留了十倍余量。
	pktmonMinSegment = time.Second

	// mib 与 maxPktmonBuffer 是「一段多大」这一格的边界。
	// 上限不是 pktmon 给的，是我们这边给的：BufferSize 是 int，32 位档
	// （windows/386 在出货清单里）最大就是 2^31-1 ≈ 2047MB，再大的数在乘法之前
	// 就已经绕回负数了，比较起来等于没挡。
	mib               = 1 << 20
	maxPktmonBuffer   = 1 << 30
	ethHdrSize        = 14
	ethDstOff         = 0
	ethSrcOff         = 6
	pktmonErrTextSize = 320
)

// pktmonPktSize 把 Options.SnapLen 落成 --pkt-size 那一格。
// 0 按契约是默认留长，不是「整包」——这一格要是直通 0，界面上「留长填 0」
// 在三个平台上的意思会差出一截（0 在 pktmon 那里是「一包全记」）。
//
// ★ 这一格不许不传：不传时 pktmon 默认每包只记前 128 字节，1500 MTU 的包会被剪断，
//
//	而剪痕只体现在 caplen 上 —— 数包、算时长这类不看线上长度的用法完全看不出被剪过。
func pktmonPktSize(snapLen int) (int, error) {
	if snapLen < 0 {
		return 0, fmt.Errorf("capture: 留长不能为负（%d）", snapLen)
	}
	if snapLen == 0 {
		return DefaultSnapLen, nil
	}
	if snapLen > maxPktmonBuffer {
		return 0, fmt.Errorf("capture: 留长 %d 大到这一档记不下了（上限 %d 字节）", snapLen, maxPktmonBuffer)
	}
	return snapLen, nil
}

// pktmonFileMB 把「想要多大一段」换成 -s 那一格要的 MB 数。
//
// ★ 向上取整：向下取整会把「1.5MB」变成 0，而实测 0 在 pktmon 那里
//
//	不是「不限」，是「按默认的 512MB」—— 用户说环 1.5MB、系统实际录到 512MB，
//	这种差别在结果里一个字都看不出来。
//	取整本身已经把最低那一格抬到 1（上面挡了 0 与负数），所以这里不再另加下限钳：
//	钳了就把「哪天有人把取整改成往下」这个错藏住，测试也照样绿（这么试过）。
func pktmonFileMB(bufferSize int64) (int, error) {
	if bufferSize < 0 {
		return 0, fmt.Errorf("capture: 环大小不能为负（%d）", bufferSize)
	}
	if bufferSize == 0 {
		bufferSize = DefaultBufferSize
	}
	if bufferSize > maxPktmonBuffer {
		return 0, fmt.Errorf("capture: 环要 %d 字节，超出这一档一段的上限（%d）", bufferSize, maxPktmonBuffer)
	}
	mb := int((bufferSize + mib - 1) / mib)
	return mb, nil
}

// pktmonStartArgs 拼那一条 start。顺序照实测那一版写，测试里整条钉住。
func pktmonStartArgs(snapLen int, bufferSize int64, etlPath string) ([]string, error) {
	ps, err := pktmonPktSize(snapLen)
	if err != nil {
		return nil, err
	}
	mb, err := pktmonFileMB(bufferSize)
	if err != nil {
		return nil, err
	}
	if etlPath == "" {
		return nil, fmt.Errorf("capture: 没给这一段落哪儿")
	}
	return []string{
		"start", "--capture",
		"--comp", pktmonCompNics,
		"--pkt-size", strconv.Itoa(ps),
		"-s", strconv.Itoa(mb),
		"-f", etlPath,
	}, nil
}

// pktmonIsBusyExit 问的是「这一个退出码是不是『已经有一路在录』」。
// 是 → 界面该说「先把在录的那一路停了」，而不是「权限不够」。
func pktmonIsBusyExit(code int) bool { return code == pktmonBusyExit }

// pktmonSegment 把 Options.BlockRetire 落成「一段最多多久」。
// 不到下限的按下限：这一档再快也快不到 100ms 那一档，换段是有成本的。
// 上层（#92）要把这句话原样带给界面：勾了「100ms 交一次」在 Windows 上是拿不到的。
func pktmonSegment(retire time.Duration) time.Duration {
	if retire <= 0 {
		retire = DefaultBlockRetire
	}
	if retire < pktmonMinSegment {
		return pktmonMinSegment
	}
	return retire
}

// pktmonFilters 从 `pktmon filter list` 的输出里把行认出来。
//
// ★ 只认「第一个字段是十进制序号」这一条形状，不去读表头、列名和那句「无」：
//
//	中文系统上表头是「# 名称 MAC 地址 协议」，换一台英文机器就换了；
//	序号那一格是 pktmon 自己排出来的，跟显示语言无关。
//	实测的三种形状：空表（只有一行「无」）、`1 netkit ICMP`、
//	`1 m1 00-11-22-33-44-55 TCP`。
func pktmonFilters(out string) []string {
	var names []string
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		idx, err := strconv.Atoi(fields[0])
		if err != nil || idx <= 0 {
			continue
		}
		names = append(names, fields[1])
	}
	return names
}

// pktmonFrameHere 问「这一帧算不算那块网卡上的」。
//
// 为什么要在我们自己这边认：pktmon 定口的两条路都只有出的方向 ——
// `filter add -m <MAC>` 实测把进来的方向全滤掉（它自己的帮助写「匹配源或目标 MAC」，
// 量出来的结果不是这么回事），`--comp <网卡那一格>` 同样只剩出的方向。
// 所以这一档只能整块网卡一起收，再拿帧头自己分。
//
// 分的口径要如实：出的那一头源 MAC 就是本机这块口，一定认得出；
// 进的那一头只有单播认得出（目的 MAC = 这块口的），广播/组播（ARP 谁在找、
// mDNS、DHCP）在多块口的机器上认不出是哪块口进来的 —— 那种包两头上都放行，
// 宁可一块口上多看见几包，也不要在对的那块口上少看见。
func pktmonFrameHere(data []byte, mac []byte) bool {
	if len(mac) != 6 || len(data) < ethHdrSize {
		return false
	}
	return sameMAC(data[ethDstOff:ethDstOff+6], mac) || sameMAC(data[ethSrcOff:ethSrcOff+6], mac)
}

// pktmonFrameBroadcast 问这一帧的目的地是不是组播/广播那一片（第一字节的最低位是 1）。
func pktmonFrameBroadcast(data []byte) bool {
	return len(data) >= 1 && data[0]&0x01 != 0
}

func sameMAC(a, b []byte) bool { return len(a) == len(b) && string(a) == string(b) }

// pktmonSegmentFilled 判断一段的 .etl 有没有写到循环日志的上限。
//
// 为什么要判断：这一档的日志模式是 circular，写满之后新事件会盖掉最早的 ——
// 被盖掉的那些不报错、也不进「丢弃计数」，看上去就是一份抓得干干净净的空账。
// 实测：日志按需增长（20 个包 → 3,538 字节，上限 16MB），没按 -s 预分配，
// 所以「这一段有没有写过上限」这一问才有得问。
//
// 取上限的 99% 当线：ETW 按页落盘，写满时不一定一寸不差地停在那一格上。
// 宁可多报一次「这一段可能写满过」（它只是不给「全须全尾」那句话背书），
// 也不要少报 —— 少报那一次，会有人拿一份缺了开头的账去下结论。
func pktmonSegmentFilled(size int64, mb int) bool {
	if size < 0 || mb <= 0 {
		return false
	}
	capBytes := int64(mb) * mib
	return size >= capBytes-capBytes/100
}

// countFilePackets 数一个 pcapng 里有多少包。
// 用它数「只含丢包」那一份转换的产物：pktmon 自己的丢弃计数是跟着它说的话递出来的（中文），
// 而文件里有几包是我们自己能数清的。
func countFilePackets(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("capture: 打不开 %s：%w", path, err)
	}
	defer f.Close()
	return countPackets(f)
}

func countPackets(r io.Reader) (int, error) {
	rd, err := Open(r)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		_, err := rd.Read()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		n++
	}
}
