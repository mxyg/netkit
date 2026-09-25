//go:build linux

package capture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 与 tcpdump 逐包对账。
//
// 票面口径写的是「行为以 tcpdump/dumpcap 的真产物为参照」，这一条就是那一步：
// 同一段流量，tcpdump 写它的 pcap、我们写我们的 pcapng，然后按标号配对，
// 比正文、比长度、比时刻。
//
// ★ 为什么这一条不能只看「两边包数一样」：包数一样而正文错位（步长走错就会这样）
//
//	是最阴的一种错 —— 数量对、时刻对、内容全是别人的。所以配对按正文里的标号来，
//	比的是字节。
//
// 要 tcpdump 在场、要 CAP_NET_RAW，两样缺一就明写跳过，不许让这一条变成摆设：
//
//	docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN -v $PWD:/w -w /w ubuntu:22.04 \
//	  bash -c 'apt-get update -qq && apt-get install -y -qq tcpdump && ./capture.test -test.run 与tcpdump -test.v'
func Test与tcpdump逐包对账(t *testing.T) {
	const rounds = 40
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("这台机器上没有 tcpdump：参照物不在，这一条没得对")
	}
	dir := t.TempDir()
	ref := filepath.Join(dir, "ref.pcap")
	mine := filepath.Join(dir, "ours.pcapng")

	// 服务先起来：端口得先定下来，tcpdump 的过滤器要按它写。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	go echoLoop(ln)

	cmd := exec.Command("tcpdump", "-i", "lo", "-nn", "-s", "0", "-w", ref,
		fmt.Sprintf("tcp and port %d", addr.Port))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("tcpdump 起不来：%v", err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	}()
	time.Sleep(800 * time.Millisecond) // 给它把过滤器装到口上的时间

	src, err := OpenSource(Options{Interface: "lo", SnapLen: 0, BlockRetire: 100 * time.Millisecond})
	if err != nil {
		t.Skipf("这一档要 CAP_NET_RAW，这台机器上起不来（%v）—— 与参照对账这一条没做", err)
	}
	defer src.Close()

	f, err := os.Create(mine)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := NewWriter(f, src.Interfaces())
	if err != nil {
		t.Fatalf("建写手失败：%v", err)
	}

	// 流量：每一轮一个能数得清的标号，正文长度故意不齐（齐了就走不出步长那格）。
	// 读包那一路必须先跑起来 —— 环里退休一块才交一份，边发边读才对得上口径。
	sendDone := make(chan error, 1)
	go func() { sendDone <- knockRounds(addr.String(), rounds) }()

	var (
		seenByRound = map[int]string{}
		minePkt     []pkRef
	)
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) && len(seenByRound) < rounds {
		p, err := src.Next()
		if err != nil {
			t.Fatalf("读不下去了：%v", err)
		}
		if err := w.WritePacket(p.InterfaceIndex, p.Timestamp, p.Data, p.OrigLen); err != nil {
			t.Fatalf("写 pcapng 失败：%v", err)
		}
		if n, body, ok := markOf(p.Data); ok {
			seenByRound[n] = body
			minePkt = append(minePkt, pkRef{round: n, data: append([]byte(nil), p.Data...), ts: p.Timestamp, orig: p.OrigLen})
		}
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("造流量那一路坏了：%v", err)
	}
	if len(seenByRound) < rounds {
		t.Fatalf("只抓到 %d/%d 轮的标号，后面的没法对账", len(seenByRound), rounds)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	// 先别停 tcpdump：它在 linux 上走的也是 TPACKET_V3，块没装满就得等「到点」才交出来。
	// 实测（这一条第一次跑就是这么红的）：一打断它，环里那几百包跟着没了 ——
	// 它自己报「0 packets captured / 800 packets received by filter」。
	// 所以先把最后一轮的标号等进文件，再停它；不等就成了拿一份半成品来对账。
	settle := time.Now().Add(12 * time.Second)
	var refPkt []pkRef
	for time.Now().Before(settle) {
		// 这一圈里读失败不当错：文件可能还只有那个全局头（我们自己的读手对「断在半路」
		// 是照实报错的），那正是「参照还没写好」，等它。
		pkts, err := readMarked(ref)
		if err == nil && maxRound(pkts) >= rounds-1 {
			refPkt = pkts
			break
		}
		refPkt = pkts
		time.Sleep(300 * time.Millisecond)
	}
	// 打断 + 收尸：SIGINT 让它把缓冲写出来再退出。
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("停 tcpdump 失败：%v", err)
	}
	_ = cmd.Wait()
	// 停完之后那一圈缓冲才真正落盘，最后再读一遍为准。
	final, err := readMarked(ref)
	if err != nil {
		t.Fatalf("读 tcpdump 那一份失败：%v（等了一轮还读不回，说明它压根没往文件里写）", err)
	}
	if len(final) >= len(refPkt) {
		refPkt = final
	}
	ours, err := readMarked(mine)
	if err != nil {
		t.Fatalf("读我们那一份失败：%v（自己写的读不回来，界面上就是「抓到却看不见」）", err)
	}
	if len(refPkt) == 0 {
		t.Fatal("tcpdump 那一份里一个标号都没有：过滤器没吃上，这一条等于没对")
	}

	// 逐标号比字节。
	byRound := map[int][]byte{}
	for _, p := range refPkt {
		if _, has := byRound[p.round]; !has {
			byRound[p.round] = p.data
		}
	}
	oursByRound := map[int][]byte{}
	for _, p := range ours {
		if _, has := oursByRound[p.round]; !has {
			oursByRound[p.round] = p.data
		}
	}
	miss, diff := 0, 0
	for n, rb := range byRound {
		ob, has := oursByRound[n]
		if !has {
			miss++
			continue
		}
		if string(ob) != string(rb) {
			diff++
			if diff <= 3 {
				t.Errorf("第 %d 轮正文与参照不一致：我们 %d 字节 %q / 它 %d 字节 %q", n, len(ob), trim(ob), len(rb), trim(rb))
			}
		}
	}
	if miss > 0 {
		t.Errorf("参照里有 %d 个标号我们没抓到（一共 %d 个）—— 少的那一些界面上就凭空消失了", miss, len(byRound))
	}
	if diff > 0 {
		t.Errorf("%d 个标号的正文与参照不同：数量对、内容错位，是最阴的一种错", diff)
	}

	// 时刻：我们这一包的轮号，去参照里同一轮的所有包里找「离得最近的那个戳」比差值。
	// 为什么不直接配第一包：一轮里往返两包的正文一模一样（回环上自己发自己收），
	// 「谁先出现在文件里」两边可以不同，配错了就把一次往返的时长当成了戳的误差。
	// 读错秒与纳秒的落点会差出几十年，这一眼就看得见。
	var worst time.Duration
	for _, ob := range ours {
		best := time.Duration(-1)
		for _, rb := range refPkt {
			if rb.round != ob.round {
				continue
			}
			d := ob.ts.Sub(rb.ts)
			if d < 0 {
				d = -d
			}
			if best < 0 || d < best {
				best = d
			}
		}
		if best < 0 {
			continue // 这一轮参照里没有（上面已经按标号配过一遍了，这里不重复报）
		}
		if best > worst {
			worst = best
		}
	}
	if worst > time.Second {
		t.Errorf("与参照的时刻差到 %v 去了 —— 秒与纳秒那两格的落点不对", worst)
	}
	st := src.Stats()
	t.Logf("对上了：%d 个标号、两边字节一致；时刻最大偏差 %v；我们 %d 包 / 参照 %d 包（内核计数：递出 %d、丢掉 %d、标过丢包 %v）",
		len(byRound), worst, len(ours), len(refPkt), st.Packets, st.Dropped, st.Lossy)
	if len(seenByRound) != rounds {
		t.Errorf("抓到 %d 个标号，比要发的 %d 还多（标号算重了？）", len(seenByRound), rounds)
	}
}

type pkRef struct {
	round int
	data  []byte
	ts    time.Time
	orig  int
}

// maxRound 回这份文件里见到过的最大轮号（一个标号都没有时回 -1）。
// 用它判断「参照那一份是不是已经写到最后一轮了」—— 没写完就对账，比的是半成品。
func maxRound(all []pkRef) int {
	n := -1
	for _, p := range all {
		if p.round > n {
			n = p.round
		}
	}
	return n
}

// markOf 从一包里找「netkit-对照-XXX-」那一条标号。
// 只认带标号的正文：回环上别的流量（内核自己的、别的进程的）不该搅进这次对账。
func markOf(b []byte) (int, string, bool) {
	s := string(b)
	i := strings.Index(s, markPrefix)
	if i < 0 {
		return 0, "", false
	}
	var n int
	rest := s[i+len(markPrefix):]
	if len(rest) < 3 {
		return 0, "", false
	}
	if _, err := fmt.Sscanf(rest[:3], "%03d", &n); err != nil {
		return 0, "", false
	}
	return n, s[i:], true
}

const markPrefix = "netkit-对照-"

// readMarked 读一份抓包文件（pcap 与 pcapng 都走我们自己的读手），只留带标号的那些包。
func readMarked(name string) ([]pkRef, error) {
	fh, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	r, err := Open(fh)
	if err != nil {
		return nil, err
	}
	var out []pkRef
	for {
		p, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		if n, _, ok := markOf(p.Data); ok {
			out = append(out, pkRef{round: n, data: append([]byte(nil), p.Data...), ts: p.Timestamp, orig: p.OrigLen})
		}
	}
}

// knockRounds 发 rounds 轮「写一条带标号的话、读回来」，正文长度一轮一变。
func knockRounds(addr string, rounds int) error {
	for i := 0; i < rounds; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("第 %d 轮连不上：%w", i, err)
		}
		msg := fmt.Sprintf("%s%03d-%s", markPrefix, i, strings.Repeat("x", 7+i%131))
		if _, err := c.Write([]byte(msg)); err != nil {
			c.Close()
			return fmt.Errorf("第 %d 轮写失败：%w", i, err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil || n <= 0 {
			return fmt.Errorf("第 %d 轮没读回自己写的东西（%v）", i, err)
		}
		if !strings.Contains(string(buf[:n]), fmt.Sprintf("%s%03d", markPrefix, i)) {
			return fmt.Errorf("第 %d 轮回读对不上：%q", i, buf[:n])
		}
	}
	return nil
}

// echoLoop 把收到的原样写回去 —— 服务端与客户端两侧都在同一条回环上，
// 一次往返就有两包含标号，正好互相印证。
func echoLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}

func trim(b []byte) string {
	if len(b) > 48 {
		return string(b[:48]) + "…"
	}
	return string(b)
}
