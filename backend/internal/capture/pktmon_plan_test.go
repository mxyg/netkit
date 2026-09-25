package capture

// pktmon 这一档的「不碰系统」那一份的测试：命令怎么拼、一段多大、筛选器怎么认、
// 帧该不该递上去，再加上两份真 pktmon 转出来的文件。
//
// ★ 这一份不带 build tag 是有意的：改代码的这台机器上没有 Windows，
//   纯算术和纯解析在这里就能按红。反证不该挑一台 Windows 做。

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// ==================== 那两份真产物 ====================

// pktmonMAC 是那台验证机上唯一一块网卡的 MAC（VirtIO，ifIndex 5）。
var pktmonMAC = []byte{0xc6, 0xde, 0x5e, 0xde, 0xd9, 0xbc}

func openTestdata(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// 这一条钉的是「pktmon 转出来的那一份，我们的读侧认不认」。
// 认不出的话，界面上是「Windows 上抓完了打不开自己抓的文件」——最贵的那种失败。
func Test真pktmon转出来的文件读得动(t *testing.T) {
	rd, err := Open(openTestdata(t, "pktmon-nics.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	// 顶上第 9 条：只有一条 unnamed 接口记录，名字是空的。
	// 也就是说「这一包来自哪块网卡」在文件里根本没有 —— 定口只能在代码里按 MAC 分。
	ifaces := rd.Ifaces()
	if len(ifaces) != 1 {
		t.Fatalf("接口记录 %d 条， pktmon 只写 1 条", len(ifaces))
	}
	if ifaces[0].Name != "" {
		t.Errorf("接口名是 %q， pktmon 那一份转出来不带名字", ifaces[0].Name)
	}
	if ifaces[0].LinkType != LinkTypeEN10MB {
		t.Errorf("链路类型 %d， 以太网应为 %d", ifaces[0].LinkType, LinkTypeEN10MB)
	}
	// ★ 接口那一格 snaplen 写的是 0：它不在接口里记留长。
	//   谁要是拿这一格当「这份文件截到多长」，就会当成没截。
	if ifaces[0].SnapLen != 0 {
		t.Errorf("接口留长 %d， pktmon 那一格恒为 0", ifaces[0].SnapLen)
	}

	var pkts []Packet
	for {
		p, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("读到一半报错：%v", err)
		}
		pkts = append(pkts, p)
	}
	// 现场是「ping -n 5」：出去 5 包、回来 5 包。
	if len(pkts) != 10 {
		t.Fatalf("读到 %d 包， 这一段是 5 去 5 回", len(pkts))
	}
	for i, p := range pkts {
		if !p.HasTimestamp {
			t.Errorf("第 %d 包没带时刻", i)
		}
		// 这一份是用 --pkt-size 1600 录的，74 字节的 ICMP 全须全尾。
		// 反过来看：caplen 与 origlen 相等才说明没被剪 —— 剪痕只在这两格不等时才看得见。
		if p.OrigLen != len(p.Data) {
			t.Errorf("第 %d 包被剪过（留 %d / 线 %d）", i, len(p.Data), p.OrigLen)
		}
		if p.InterfaceIndex != 0 {
			t.Errorf("第 %d 包挂在口 %d 上， 只有一条接口记录", i, p.InterfaceIndex)
		}
	}
	// 一出一回交替：出去的那一头源 MAC 是本机口，回来的那一头是目的 MAC。
	// 这一条是 pktmonFrameHere 两个方向都要查的凭据 —— 只查一头的实现在这儿就红。
	for i, p := range pkts {
		if !pktmonFrameHere(p.Data, pktmonMAC) {
			t.Errorf("第 %d 包两个方向都不认本机 MAC， 点名这一块口时它会被丢掉", i)
		}
	}
	if d := pkts[len(pkts)-1].Timestamp.Sub(pkts[0].Timestamp); d < 3*time.Second || d > 5*time.Second {
		t.Errorf("首尾相差 %v， 现场是 3.36 秒内录的这一段（刻度对不对就看这一格）", d)
	}
}

// 「一段录完一个包都没有」是这个形状 —— 界面要说「这一段没抓到」，
// 不能说「文件坏了」。空文件跟读不动是两句话。
func TestPktmon转出来的空文件读得动且零包(t *testing.T) {
	rd, err := Open(openTestdata(t, "pktmon-empty.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rd.Ifaces()) != 1 {
		t.Fatalf("接口记录 %d 条， 没抓到包也该有一条", len(rd.Ifaces()))
	}
	if _, err := rd.Read(); err != io.EOF {
		t.Errorf("空文件读到 %v， 应为 io.EOF", err)
	}
}

// 这两份文件同时是「正在录的那一份转出来是 172 字节」（顶上第 6 条）的凭据：
// 那一格的字节数就是这一条。谁改了转换顺序，测试里这个数会先告诉他为什么。
func Test没停干净的转换只有一百七十二字节(t *testing.T) {
	st, err := os.Stat("testdata/pktmon-empty.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 172 {
		t.Errorf("空转换产物是 %d 字节， 实测那份正在录的转出来就是 172 字节", st.Size())
	}
}

// ==================== --pkt-size 那一格 ====================

func Test留长落成pkt_size那一格(t *testing.T) {
	cases := []struct {
		name    string
		snapLen int
		want    int
		wantErr bool
	}{
		// ★ 0 不是「整包」，是契约里的默认留长。直通 0 的话，
		//   「留长填 0」在三个平台上会差出一截（pktmon 那里 0 = 全记）。
		{"填零走默认", 0, DefaultSnapLen, false},
		{"照抄", 96, 96, false},
		{"整包口径", 1600, 1600, false},
		{"负数", -1, 0, true},
		{"大到记不下", maxPktmonBuffer + 1, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pktmonPktSize(tc.snapLen)
			if (err != nil) != tc.wantErr {
				t.Fatalf("错 = %v， 想要错 = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("得 %d， 要 %d", got, tc.want)
			}
		})
	}
}

// ==================== -s 那一格（MB） ====================

func Test环大小落成段上限MB(t *testing.T) {
	cases := []struct {
		name       string
		bufferSize int64
		want       int
		wantErr    bool
	}{
		// 0 在 pktmon 那里是「按默认的 512MB」，不是「不限」，所以要落成默认环的大小。
		{"填零走默认环", 0, 4, false},
		{"一格不满也要占一格", 1, 1, false},
		{"一点五兆向上取整", 3 << 19, 2, false},
		{"正好整兆", 2 << 20, 2, false},
		{"默认", DefaultBufferSize, 4, false},
		{"负数", -1, 0, true},
		{"超出这一档", maxPktmonBuffer + 1, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pktmonFileMB(tc.bufferSize)
			if (err != nil) != tc.wantErr {
				t.Fatalf("错 = %v， 想要错 = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("得 %d MB， 要 %d MB", got, tc.want)
			}
		})
	}
}

// 向下取整会把 1.5MB 变成 0，而 0 在那儿是 512MB —— 用户说环 1.5MB、系统录到 512MB，
// 这种差别在结果里一个字都看不出来，所以单独立一条。
func Test段上限绝不落成零(t *testing.T) {
	for _, n := range []int64{1, 1 << 10, mib - 1, mib, mib + 1} {
		mb, err := pktmonFileMB(n)
		if err != nil {
			t.Fatal(err)
		}
		if mb < 1 {
			t.Errorf("环 %d 字节落成 %d MB， 落成零等于让 pktmon 按默认 512MB 录", n, mb)
		}
	}
}

// ==================== 那一条 start ====================

// 整条参数序列钉死：--comp 只认 nics、--pkt-size 必须在、-f 必须是我们给的路径。
// 少任何一格都不会报错，只会让抓出来的东西变成另一回事（128 字节剪断 / 一份包抄四份 /
// 只剩出的方向）。
func Test起段那条命令一字不改(t *testing.T) {
	args, err := pktmonStartArgs(0, 0, `C:\Windows\Temp\netkit\seg-0.etl`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"start", "--capture", "--comp", "nics", "--pkt-size", "1600", "-s", "4", "-f", `C:\Windows\Temp\netkit\seg-0.etl`}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Errorf("拼出来是\n%v\n要\n%v", args, want)
	}
	if _, err := pktmonStartArgs(96, 1<<20, ""); err == nil {
		t.Error("没给落点也拼得出命令， 那一段会录到别人目录里去")
	}
}

// ==================== 状态只认退出码 ====================

func Test只有退出码说真话(t *testing.T) {
	if !pktmonIsBusyExit(159) {
		t.Error("159 不是「已经有一路在录」， 实测就是这一个码")
	}
	// stop 一个没在录的 → 退出码 0， 但话说的是「没有运行」。
	// 反过来 0 不许被当成「已经有一路在录」，界面会叫人去停一个不存在的东西。
	for _, code := range []int{0, 1, 3, -1, 158, 160} {
		if pktmonIsBusyExit(code) {
			t.Errorf("%d 被当成了「在录」", code)
		}
	}
}

// ==================== 一段多久 ====================

// Windows 上「多久交一次」等于段长：包要等 stop + 转换才读得到。
// 这一条把「界面上勾了 100ms， Windows 上拿不到」这句话变成可测的东西。
func Test段长按下限钳(t *testing.T) {
	cases := []struct {
		retire time.Duration
		want   time.Duration
	}{
		{0, pktmonMinSegment},
		{100 * time.Millisecond, pktmonMinSegment},
		{-time.Second, pktmonMinSegment},
		{pktmonMinSegment, pktmonMinSegment},
		{30 * time.Second, 30 * time.Second},
	}
	for _, tc := range cases {
		if got := pktmonSegment(tc.retire); got != tc.want {
			t.Errorf("BlockRetire %v 落成 %v， 要 %v", tc.retire, got, tc.want)
		}
	}
}

// ==================== filter list ====================

// 实测的三种形状（中文系统的表头不进这里：只认「第一个字段是十进制序号」）。
func Test场上有没有筛选器(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []string
	}{
		{"空表只有一句无", "暂无数据包筛选器。\r\n", nil},
		{"英文空表", "No packet filters exist.\r\n", nil},
		{"只有一条", "# 名称\t\tMAC 地址 协议\r\n1 netkit ICMP\r\n", []string{"netkit"}},
		{"两条", "1 m1 00-11-22-33-44-55 TCP\n2 m2 UDP\n", []string{"m1", "m2"}},
		{"表头不当条目", "# 名称 MAC 地址 协议\n\n", nil},
		// 序号从 1 排；0 那一条不是筛选器（真产物里没这种行，挡的是把表头数字认进来）。
		{"零号不算", "0 x TCP\n", nil},
		{"空的", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pktmonFilters(tc.out)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("认成 %v， 要 %v", got, tc.want)
			}
			if len(tc.want) == 0 && len(got) != 0 {
				t.Errorf("把没有的认成了有：这一路会拒绝起口")
			}
		})
	}
}

// ==================== 按 MAC 认口 ====================

func Test这一帧算不算那块口的(t *testing.T) {
	other := []byte{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	broadcast := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	frame := func(dst, src []byte) []byte {
		b := make([]byte, ethHdrSize+4)
		copy(b[ethDstOff:], dst)
		copy(b[ethSrcOff:], src)
		return b
	}
	cases := []struct {
		name string
		data []byte
		mac  []byte
		want bool
	}{
		// 出的方向：源是本机口 —— --comp <网卡号> 只剩这一头，所以只认这头等于只看得到自己发的。
		{"本机发出去的", frame(other, pktmonMAC), pktmonMAC, true},
		{"发给本机的", frame(pktmonMAC, other), pktmonMAC, true},
		{"别块口的单播", frame(other, []byte{1, 2, 3, 4, 5, 6}), pktmonMAC, false},
		{"广播", frame(broadcast, other), pktmonMAC, false}, // 认不出是谁家的， 由放行广播那一条兜
		{"半截帧", frame(pktmonMAC, other)[:8], pktmonMAC, false},
		{"空", nil, pktmonMAC, false},
		{"没给MAC", frame(pktmonMAC, other), nil, false},
		{"MAC长短不对", frame(pktmonMAC, other), pktmonMAC[:4], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pktmonFrameHere(tc.data, tc.mac); got != tc.want {
				t.Errorf("得 %v， 要 %v", got, tc.want)
			}
		})
	}
}

// 广播/组播的认法只看第一字节最低位：ARP 谁在找、mDNS、DHCP 都在这一片。
// 多块口的机器上这种包认不出是从哪块口进来的 —— 宁可一块口上多看见几包。
func Test组播位认得出(t *testing.T) {
	cases := []struct {
		b    []byte
		want bool
	}{
		{[]byte{0x01}, true},        // 组播
		{[]byte{0xff}, true},        // 广播
		{[]byte{0x52, 0x55}, false}, // 单播
		{nil, false},
	}
	for _, tc := range cases {
		if got := pktmonFrameBroadcast(tc.b); got != tc.want {
			t.Errorf("% x 得 %v， 要 %v", tc.b, got, tc.want)
		}
	}
}

// ==================== 这一段写满过没有 ====================

// 循环日志写满之后新事件盖掉最早的：不报错、不进丢弃计数，看上去是一份抓得干干净净的空账。
// 这一条挡住的是「少报一次写满」——少报那一次，会有人拿一份缺了开头的账去下结论。
func Test段写满按大小认(t *testing.T) {
	cases := []struct {
		name string
		size int64
		mb   int
		want bool
	}{
		{"刚起步", 3538, 16, false},
		{"差一点到顶（九成九以内）", 16*mib - 16*mib/100 - 1, 16, false},
		{"到线", 16*mib - 16*mib/100, 16, true},
		{"正好上限", 16 * mib, 16, true},
		{"负数", -1, 16, false},
		{"上限没落到（不该出现）", 100, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pktmonSegmentFilled(tc.size, tc.mb); got != tc.want {
				t.Errorf("得 %v， 要 %v", got, tc.want)
			}
		})
	}
}

// ==================== 数包 ====================

func Test数一份pcapng里有几包(t *testing.T) {
	f := openTestdata(t, "pktmon-nics.pcapng")
	n, err := countPackets(f)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Errorf("数出 %d 包， 那一份是 10 包（丢弃计数就按这一格数）", n)
	}
	if _, err := countFilePackets("testdata/根本没有这个文件.pcapng"); err == nil {
		t.Error("打不开也回包数， 那等于把「数不清」报成「零包丢弃」")
	}
	// 不像抓包文件的东西：这一格不许回 0 而不报错， 否则丢包数会是干净的 0。
	if _, err := countPackets(strings.NewReader("这不是抓包文件")); err == nil {
		t.Error("认不出的正文回了没有错")
	} else if errors.Is(err, io.EOF) {
		t.Error("空文件与坏文件混成一格， 界面上分不出「没丢包」和「数不清」")
	}
}
