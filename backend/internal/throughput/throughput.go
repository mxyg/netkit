// Package throughput 是「局域网两点对测」的两端：一台开一个对测口接流，另一台连过去打流。
//
// ★★ 为什么要自己写这一套：现场要回答的是「这两台之间此刻能吃下多少」，
//
//	而 iperf3 是第三方二进制 —— 安装包不许带任何专有或第三方组件，
//	Win7 那头上装 iperf 更是现场最招人嫌的一件事。协议本身就几十行，
//	两端都在我们手里，反而能把「光看吞吐看不出来的东西」一起带回来：
//
//	  · 每 200 毫秒一个点的曲线（平均数会骗人：稳定 900M 和 1800M/0 交替，平均值一样）
//	  · 空载 RTT 与带载 RTT 分开量 —— 吞吐很高而带载 RTT 涨十几倍，那是中间那台的队列
//	    在囤包（缓冲膨胀），现场表现是「带宽明明够，画面就是卡」
//	  · 发送侧与接收侧各记一份耗时 —— 差得远说明数据堆在本机的发送缓冲里，
//	    链路其实没吃下那么多
//	  · TCP 自己那本账（rtt / 重传 / 拥塞窗口），Linux 与 macOS 用 getsockopt 就取得到
//
// 只测 TCP：UDP 那一档要的是「丢包率」，而局域网里 TCP 的重传计数已经把同一件事说了，
//
//	不必为了它再开一个无连接端口（那口一旦开着就是别人眼里的反射面）。
//
// 安全口径：对测口一旦开出去，同一网段任何机器都能让它收发字节。所以下行有硬上限、
//
//	同时只接有限几路、每一路有总时长上限，并且开这个口是 mutate —— 要人批准、要记账。
package throughput

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// 协议版本串。★ 对端版本不对就直接拒，别拿半懂不懂的字节当数据往下读。
const protoMagic = "NETKIT-THRU/1"

// 一次会话里允许的最大帧长与最长的一行。
const (
	maxFrame     = 1 << 20
	maxLineBytes = 256
)

// 模式。up/down 说的是**发起方**看过去的方向。
const (
	ModeUp   = "up"
	ModeDown = "down"
	ModePing = "ping"
)

var (
	// ErrProto 对面回的不是这套协议（多半是端口配错，或那台没开对测口）。
	ErrProto = errors.New("对端回的不是 NetKit 对测协议")
	// ErrBusy 对测口同时在测的路数已满。
	ErrBusy = errors.New("对端对测口已满")
)

// requestLine 是发起方上线后说的第一句。
//
// down 模式里 bytes 是「对面最多给我多少」；up/ping 填 0，实际量由时长决定。
func requestLine(mode string, bytes int64, nonce string) string {
	return fmt.Sprintf("%s %s %d %s\n", protoMagic, mode, bytes, nonce)
}

// statsLine 是数据跑完后两边各说的一句：我这边数到/写出多少字节、花了多久。
//
// ★ 两端都要说，也都要听 —— 「发送侧写完」和「接收侧收完」是两个不同的数，
//
//	它们的差正是本机发送缓冲里囤了多少东西。
func statsLine(count int64, elapsed time.Duration) string {
	return fmt.Sprintf("STATS %d %d\n", count, elapsed.Microseconds())
}

func parseStatsLine(line string) (int64, time.Duration, error) {
	f := strings.Fields(line)
	if len(f) != 3 || f[0] != "STATS" {
		return 0, 0, fmt.Errorf("不是 STATS 那一句：%q", line)
	}
	n, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("字节数不是数：%q", line)
	}
	us, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("耗时不是数：%q", line)
	}
	return n, time.Duration(us) * time.Microsecond, nil
}

// reply 是接收方对第一句的答复。
type reply struct {
	ok       bool
	code     string // OK / BUSY / ERR
	maxBytes int64
	nonce    string
}

func replyLine(code string, maxBytes int64, nonce string) string {
	if code == "OK" {
		return fmt.Sprintf("%s OK %d %s\n", protoMagic, maxBytes, nonce)
	}
	return fmt.Sprintf("%s %s\n", protoMagic, code)
}

func parseReply(line string) (reply, error) {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != protoMagic {
		return reply{}, ErrProto
	}
	r := reply{code: f[1]}
	switch f[1] {
	case "OK":
		// ★ nonce 必须原样回来：连接是从池子里拿的，晚到的上一轮回执
		//   混进这一轮读的话，会把别人的字节数当成自己的结果。
		if len(f) != 4 {
			return reply{}, ErrProto
		}
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return reply{}, ErrProto
		}
		r.ok, r.maxBytes, r.nonce = true, n, f[3]
		return r, nil
	case "BUSY", "ERR":
		return r, nil
	}
	return reply{}, ErrProto
}

// readLine 读一行，并挡住「对面一句话就撑爆内存」那种写法。
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		// ★ 断线前已经收到的那半句要带回去：「一句没说就关线」和「说了半句就关线」
		//   在对面那台是两件事，前者多半是端口上跑的别的服务。
		return line, err
	}
	if len(line) > maxLineBytes {
		// 同样把原句带回去：这一句「说了很多但不是这一套」，别退化成「一句没说」。
		return line, fmt.Errorf("那一句太长了（%d 字节），不是对测该说的话", len(line))
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// writeFrame 写一帧：4 字节大端长度 + 正文。长度 0 就是「我说完了」。
func writeFrame(w *bufio.Writer, p []byte) error {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if len(p) == 0 {
		return w.Flush()
	}
	if _, err := w.Write(p); err != nil {
		return err
	}
	return nil
}

// readFrame 读一帧。返回 (正文, 是否结束帧, 错误)。
//
// ★ 正文是复用缓冲的一部分，调用方不许留着不放 —— 只有结束帧与错误值得往上带。
func readFrame(br *bufio.Reader, buf []byte) ([]byte, bool, error) {
	var h [4]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, false, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 {
		return nil, true, nil
	}
	if n > maxFrame {
		return nil, false, fmt.Errorf("那一帧 %d 字节，超过单帧上限 %d", n, maxFrame)
	}
	if int(n) > len(buf) {
		return nil, false, fmt.Errorf("那一帧 %d 字节，比读缓冲还大", n)
	}
	if _, err := io.ReadFull(br, buf[:n]); err != nil {
		return nil, false, err
	}
	return buf[:n], false, nil
}
