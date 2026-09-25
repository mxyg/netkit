package media

import (
	"strings"
	"testing"
	"time"
)

// pkt 造一个 RTP 包。载荷默认是「非关键帧」的一包 H.264（NAL 类型 1）。
func pkt(seq, ts int, marker bool, ssrc uint32, payload ...byte) []byte {
	b := make([]byte, 12+len(payload))
	b[0] = 0x80
	if marker {
		b[1] |= 0x80
	}
	b[1] |= 96
	b[2], b[3] = byte(seq>>8), byte(seq)
	b[4], b[5], b[6], b[7] = byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts)
	b[8], b[9], b[10], b[11] = byte(ssrc>>24), byte(ssrc>>16), byte(ssrc>>8), byte(ssrc)
	copy(b[12:], payload)
	return b
}

func h264NonKey() []byte      { return []byte{0x61, 0xAA, 0xBB} }
func h264IDR() []byte         { return []byte{0x65, 0xAA, 0xBB} }
func h264IDRFragment() []byte { return []byte{0x7C, 0x85, 0xAA} } // FU-A：S=1, 类型 5

func Test非RTP的杂包一个数都不计入(t *testing.T) {
	c := NewCollector("h264", 90000)
	bad := [][]byte{
		nil,
		{0x01, 0x02}, // 太短
		{0x00, 0x60, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // 版本 0（多半是别的协议）
	}
	for i, b := range bad {
		if c.Add(b, time.Now()) {
			t.Errorf("第 %d 个杂包被当成 RTP 收进账里了", i+1)
		}
	}
	if r := c.Report(); r.Packets != 0 || r.BitrateKbps != 0 {
		t.Errorf("一个包都没收，账上却有了数：%+v", r)
	}
}

func Test码率与到达帧率按到达口径算(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	// 3 秒、每包 1000 字节载荷、每 30 包一帧（marker）：
	// 90 包 → 90×1000×8/3 = 240 kbps；3 帧 → 1.0 fps
	for i := 0; i < 90; i++ {
		payload := make([]byte, 1000)
		at := t0.Add(time.Duration(i) * 33 * time.Millisecond) // 约 2.97 秒
		c.Add(append([]byte{}, pkt(i, i*3600, i%30 == 29, 0x1234, payload...)...), at)
	}
	r := c.Report()
	if r.MeasuredMs < 2900 {
		t.Fatalf("窗口不对：%d ms", r.MeasuredMs)
	}
	if r.BitrateKbps < 235 || r.BitrateKbps > 245 {
		t.Errorf("码率该按载荷字节/到达时间折算，实得 %d kbps", r.BitrateKbps)
	}
	if r.ReceivedFps < 0.9 || r.ReceivedFps > 1.1 {
		t.Errorf("到达帧率该数 marker 位，实得 %v", r.ReceivedFps)
	}
	if r.LostPackets != 0 {
		t.Errorf("连号的一串被判成丢了 %d 包", r.LostPackets)
	}
}

// 序号跨过 65535：一秒九十来个包，十几分钟就绕一次，不补圈数就是「丢了六万个包」。
// ★ 这条特意在跨圈**前后各缺一个** —— 只断言「不该报六万」的那一版用例，
//
//	把补圈数那一格删掉照样绿（读数会退成「一个没丢」），那是一条不会红的用例。
func Test序号跨回绕不算丢六万包(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	seqs := []int{65530, 65531, 65533, 65534, 65535, 0, 2, 3, 4} // 缺 65532 与 1
	for i, sq := range seqs {
		c.Add(pkt(sq, i*3000, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
	}
	r := c.Report()
	if r.LostPackets != 2 {
		t.Errorf("跨圈这一段该报丢 2 包，实得 %d（想要「不该报六万」是拦不住错的）", r.LostPackets)
	}
	if r.Reordered != 0 {
		t.Errorf("跨圈被当成乱序 %d 次 —— 圈数没补上就是这个读数", r.Reordered)
	}
}

func Test真丢的那几包要数出来(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	i := 0
	for seq := 0; seq < 100; seq++ {
		if seq == 50 || seq == 51 {
			continue // 这两包在路上没了
		}
		c.Add(pkt(seq, seq*300, seq%10 == 9, 7, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
		i++
	}
	r := c.Report()
	if r.LostPackets != 2 {
		t.Fatalf("丢了 %d 包，想要 2", r.LostPackets)
	}
	if r.LossPercent < 1.9 || r.LossPercent > 2.1 {
		t.Errorf("丢包率不对：%v", r.LossPercent)
	}
	if r.Reordered != 0 {
		t.Errorf("乱序数不该有：%d", r.Reordered)
	}
}

func Test迟到的那一包算乱序不算丢(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	for i, sq := range []int{0, 1, 2, 4, 5, 3, 6} { // 3 迟到
		c.Add(pkt(sq, i*300, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
	}
	r := c.Report()
	if r.LostPackets != 0 {
		t.Errorf("迟到的包被记成丢了：%+v", r)
	}
	if r.Reordered == 0 {
		t.Error("乱序没记上 —— 现场「画面卡顿一下」多半就是它")
	}
}

func Test重复包不重复计费(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	// 0..9 各来一发，其中 0、1、2 各多来一发（重复），7 那一发在路上没了
	for i, sq := range []int{0, 1, 2, 3, 4, 5, 6, 8, 9, 0, 1, 2} {
		c.Add(pkt(sq, i*300, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
	}
	r := c.Report()
	if r.Duplicates != 3 {
		t.Errorf("重复包没记上：%d", r.Duplicates)
	}
	// 序号 0..9 只缺 7：把重复包也算进「收到的」，这一格就会退成「一个没丢」。
	if r.LostPackets != 1 {
		t.Errorf("重复的 %d 包被当成收到了，丢包数实得 %d，想要 1", r.Duplicates, r.LostPackets)
	}
}

// 号段凭空跳了一大截：那是中间重新起了一路流，不是路上丢了三千包。
// ★ 不拦这一手，读数会是「丢了 2994 包」—— 现场照着这个数字去查网络，查不出来。
func Test号段跳了一大截不算丢三千包(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	seqs := []int{0, 1, 2, 3, 4, 5, 3000, 3001, 3002}
	for i, sq := range seqs {
		c.Add(pkt(sq, i*300, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
	}
	r := c.Report()
	if r.LostPackets > 0 {
		t.Errorf("重新起流被算成丢了 %d 包", r.LostPackets)
	}
	found := false
	for _, n := range r.Other {
		if strings.Contains(n, "重新起了流") {
			found = true
		}
	}
	if !found {
		t.Errorf("这一段重新起过流这件事没在账上留话：%q", r.Other)
	}
}

// 跨圈之后迟到的那一包，属于上一圈 —— 号数要减一圈，不然它会被读成一个从未来过的大号。
func Test跨圈迟到的包回到上一圈(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	// 65534, 65535, 0（跨圈）之后，65533 才到：它补的是开头那个缺号，不是跳到十万号之外
	for i, sq := range []int{65534, 65535, 0, 65533} {
		c.Add(pkt(sq, i*300, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
	}
	r := c.Report()
	if r.Reordered != 1 {
		t.Errorf("跨圈迟到的那包该记一次乱序，实得 %d（丢包 %+v）", r.Reordered, r)
	}
	if r.LostPackets != 0 {
		t.Errorf("它已经到了，却还报丢 %d 包", r.LostPackets)
	}
	for _, n := range r.Other {
		if strings.Contains(n, "重新起了流") {
			t.Fatalf("一个补号的迟到包被当成重新起流：%q", r.Other)
		}
	}
}

// 重复包带着 marker 位时不能再计一帧：两路并一份会把到达帧率凭空读高一倍。
func Test重复包不再计一帧(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	seqs := []int{0, 1, 2, 3, 4, 3} // 3 带 marker，重发了一次
	for i, sq := range seqs {
		c.Add(pkt(sq, i*300, sq == 3, 7, h264NonKey()...), t0.Add(time.Duration(i)*100*time.Millisecond))
	}
	r := c.Report()
	if r.Duplicates != 1 {
		t.Fatalf("重复没记上：%+v", r)
	}
	// 6 包 × 100 毫秒 = 0.5 秒窗口，一帧 → 2.0 fps；两帧（把重复也数进去）会是 4.0
	if r.ReceivedFps > 2.5 {
		t.Errorf("重复的那一发被数成了第二帧：到达帧率 %v，想要 2.0", r.ReceivedFps)
	}
}

func TestTCP那一问不出丢包(t *testing.T) {
	c := NewCollector("h264", 90000)
	c.Transport = "tcp-interleaved"
	t0 := time.Unix(1700000000, 0)
	for i, sq := range []int{0, 1, 5, 9} { // 看着像丢了一串
		c.Add(pkt(sq, i*300, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*100*time.Millisecond))
	}
	r := c.Report()
	if r.LostPackets != 0 || r.LossPercent != 0 {
		t.Errorf("TCP 这一路报出了丢包数：%+v", r)
	}
	if r.LossNote == "" {
		t.Fatal("没写「为什么没有丢包这一格」—— 空栏会被读成「0%，网络很好」")
	}
}

func Test关键帧间隔按RTP时间戳算(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	// 三张 IDR，时间戳隔 450000（90kHz）= 5 秒
	for i, ts := range []int{0, 450000, 900000} {
		c.Add(pkt(i, ts, true, 7, h264IDR()...), t0.Add(time.Duration(i)*5*time.Second))
	}
	r := c.Report()
	if r.Keyframes != 3 {
		t.Fatalf("关键帧数不对：%d", r.Keyframes)
	}
	if r.KeyframeEveryMs < 4800 || r.KeyframeEveryMs > 5200 {
		t.Errorf("关键帧间隔 = %d ms，想要 5000", r.KeyframeEveryMs)
	}
}

func Test分片装的IDR也认(t *testing.T) {
	for _, tt := range []struct {
		codec string
		in    []byte
	}{
		{"h264", h264IDRFragment()},
		{"h265", []byte{0x62, 0x00, 0x26, 0x41, 0xAA}}, // AGG(49) + 内层 IDR_W_RADL(19) + S=1
	} {
		if !keyframeStart(tt.in, tt.codec) {
			t.Errorf("%s 的分片关键帧没认出来：% x", tt.codec, tt.in)
		}
	}
}

func Test中途换了源就分开数(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	for i := 0; i < 10; i++ { // 第一路
		c.Add(pkt(i, i*300, false, 0xAAAA, h264NonKey()...), t0.Add(time.Duration(i)*30*time.Millisecond))
	}
	for i := 0; i < 3; i++ { // 又冒出一路（组播里别人的会话）
		c.Add(pkt(i, i*300, false, 0xBBBB, h264NonKey()...), t0.Add(time.Duration(300+i*30)*time.Millisecond))
	}
	r := c.Report()
	if r.Sources != 2 {
		t.Fatalf("源的数量 = %d，想要 2", r.Sources)
	}
	if r.Packets != 10 {
		t.Errorf("给人看的那一路该是包多的那 10 包，实得 %d —— 两路加一起算帧率会凭空多一倍", r.Packets)
	}
	found := false
	for _, n := range r.Other {
		if n != "" {
			found = true
		}
	}
	if !found {
		t.Error("换了源这件事没在账上留一句话")
	}
}

func Test窗口太短不出码率(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	for i := 0; i < 5; i++ {
		c.Add(pkt(i, i*300, false, 7, h264NonKey()...), t0.Add(time.Duration(i)*time.Millisecond))
	}
	r := c.Report()
	if r.BitrateKbps != 0 || r.ReceivedFps != 0 {
		t.Errorf("5 毫秒的窗口就敢出码率：%+v", r)
	}
	if r.RateNote == "" {
		t.Error("没写为什么这一格空着")
	}
}

func Test没给时钟时折算口径要留话(t *testing.T) {
	c := NewCollector("h264", 0)
	if c.clock != 90000 {
		t.Fatalf("退回的时钟不对：%d", c.clock)
	}
	joined := ""
	for _, n := range c.notes {
		joined += n
	}
	if !strings.Contains(joined, "90kHz") {
		t.Fatalf("拿 90kHz 折算这件事没写清（notes=%q）—— 那句「关键帧隔 5 秒」就有可能是编的", joined)
	}
}

func Test别的编码只数包不说关键帧(t *testing.T) {
	c := NewCollector("mpeg4-generic", 90000)
	t0 := time.Unix(1700000000, 0)
	for i := 0; i < 20; i++ {
		c.Add(pkt(i, i*300, i%5 == 4, 7, make([]byte, 500)...), t0.Add(time.Duration(i)*50*time.Millisecond))
	}
	r := c.Report()
	if r.Keyframes != 0 || r.KeyframeEveryMs != 0 {
		t.Errorf("认不出的编码却报了关键帧：%+v", r)
	}
	if r.Packets != 20 || r.BitrateKbps == 0 {
		t.Errorf("包和码率还是要给的：%+v", r)
	}
}

// 一张关键帧被切成十几包时，只有**开头**那一包算一张。
// ★ 不看起始位的话，GOP 会被数出十几倍的小，「隔 200 毫秒一个关键帧」是编出来的。
func Test分片的中间几包不算新关键帧(t *testing.T) {
	h264Mid := []byte{0x7C, 0x45, 0xAA}             // FU-A：类型 5，但 S=0（中间一片）
	h265Mid := []byte{0x62, 0x00, 0x26, 0x01, 0xAA} // AGG：内层 IDR，但起始位没置
	if keyframeStart(h264Mid, "h264") {
		t.Error("H.264 分片的中间一片被当成新关键帧")
	}
	if keyframeStart(h265Mid, "h265") {
		t.Error("H.265 分片的中间一片被当成新关键帧")
	}
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	c.Add(pkt(0, 0, false, 7, h264IDRFragment()...), t0)
	for i := 1; i < 12; i++ { // 同一张 IDR 后面那十几片
		c.Add(pkt(i, 0, false, 7, h264Mid...), t0.Add(time.Duration(i)*10*time.Millisecond))
	}
	c.Add(pkt(20, 270000, false, 7, h264IDRFragment()...), t0.Add(time.Second))
	if r := c.Report(); r.Keyframes != 2 {
		t.Errorf("两张 IDR 却数出 %d 张", r.Keyframes)
	}
}

// 关键帧间隔取**中位数**：被网络挤在一起的那一对不该把 GOP 整个带偏。
func Test关键帧间隔取中位数(t *testing.T) {
	c := NewCollector("h264", 90000)
	t0 := time.Unix(1700000000, 0)
	// 时间戳：0, 2000, 452000, 902000 → 间隔 22 / 5000 / 5000（毫秒）。
	// ★ 挤在一起的放最前面：取第一个而不是中位数的那种写法，读数正好是那个 22。
	for i, ts := range []int{0, 2000, 452000, 902000} {
		c.Add(pkt(i, ts, true, 7, h264IDR()...), t0.Add(time.Duration(i)*1200*time.Millisecond))
	}
	r := c.Report()
	if r.KeyframeEveryMs < 4800 || r.KeyframeEveryMs > 5200 {
		t.Errorf("间隔被开头那一对挤在一起的读数带偏了：实得 %d ms，想要 5000", r.KeyframeEveryMs)
	}
}

// 带填充的包只按载荷算：填充字节不是画面，算进码率就凭空高一截。
func Test填充字节不进码率(t *testing.T) {
	c := NewCollector("h264", 90000)
	withPad := make([]byte, 12+1000+20)
	withPad[0] = 0x80 | 0x20                                      // P 位置起来才有填充可言
	withPad[1] = 96 | 0x80                                        // marker
	withPad[8], withPad[9], withPad[10], withPad[11] = 0, 0, 0, 7 // 和上一包同一个源
	for i := 12; i < 12+1000; i++ {
		withPad[i] = 0x41
	}
	withPad[len(withPad)-1] = 20 // 最后一片是填充长度
	c.Add(pkt(0, 0, true, 7, make([]byte, 1000)...), time.Unix(1700000000, 0))
	c.Add(withPad, time.Unix(1700000001, 0))
	if r := c.Report(); r.PayloadBytes != 2000 {
		t.Errorf("载荷字节该是 2000（含头 12 不算、填充不算），实得 %d", r.PayloadBytes)
	}
}
