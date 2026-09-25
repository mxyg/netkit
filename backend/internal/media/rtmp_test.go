package media

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/media/rtmptest"
)

// 这一组测试是拿 rtmptest 那台**另写一份编解码**的假服务器打的：
// 探测端与假服务器共用一套编码的话，两边一起写错的地方永远测不出来。

// rtmpProbe 把探测方那一条完整问法走一遍，最后把观测窗口读满。
// 返回值：连接、connect 那条答案、整段窗口的账。
func rtmpProbe(t *testing.T, s *rtmptest.Server, app, stream string, watch time.Duration) (*Session, RTMPCommand, Observation, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sess, err := RTMPDial(ctx, s.Host(), s.Port(), 2*time.Second)
	if err != nil {
		return nil, RTMPCommand{}, Observation{}, err
	}
	t.Cleanup(func() { _ = sess.Close() })
	if err := sess.Begin(2 * time.Second); err != nil {
		return sess, RTMPCommand{}, Observation{}, err
	}
	c, err := sess.Connect(app, "rtmp://"+s.Host()+":"+strconv.Itoa(s.Port())+"/"+app, nil, 2*time.Second)
	if err != nil {
		return sess, c, Observation{}, err
	}
	if _, err := sess.CreateStream(2, 2*time.Second); err != nil {
		return sess, c, Observation{}, err
	}
	if stream == "" {
		return sess, c, Observation{}, nil
	}
	if err := sess.Play(stream, 0, 2*time.Second); err != nil {
		return sess, c, Observation{}, err
	}
	ob := sess.Observe(watch, func(cm RTMPCommand) bool {
		return strings.HasPrefix(cm.Code(), "NetStream.Play.")
	})
	return sess, c, ob, ob.Closed
}

// 握手 → connect → createStream → play 一路问到底，最后那一段真收到媒体。
func Test一路问到媒体(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeOK)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sess, connCmd, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("一路问到底却没问成：%v", err)
	}
	if ob.Status.Code() != "NetStream.Play.Start" {
		t.Errorf("没等到 play 的开始回包，拿到的是 %q %v", connCmd.Name, ob.Status.Code())
	}
	// ★ 媒体字节要等得齐：8 条 × 1000 字节，间隔 50 毫秒 = 400 毫秒发完，
	//   窗口给 1200 毫秒，多出来的是余量，不是靠运气。
	want := s.MediaBurst * s.MediaSize
	if ob.MediaBytes < want {
		t.Errorf("窗口里收到的媒体字节 %d 比假服务器发出来的 %d 少 —— 有消息没被数进去",
			ob.MediaBytes, want)
	}
	if ob.AudioBytes == 0 || ob.VideoBytes == 0 {
		t.Errorf("音频与视频要分开数，拿到 audio=%d video=%d",
			ob.AudioBytes, ob.VideoBytes)
	}
	if sess.Stats.KeyFrames == 0 {
		t.Errorf("关键帧一条都没数到：视频消息第一个字节的高 4 位是帧型，读错了")
	}
	// ★ 元数据要单独认：那是推流端声明的「打算发多大」。它不算进媒体字节，
	//   但界面要能拿它和实测码率对着看 —— 声明 2M 实际到 200k 是一类毛病。
	if ob.Meta == nil {
		t.Errorf("窗口里的 onMetaData 没带回来")
	} else if ob.Meta["width"] != float64(1920) || ob.Meta["height"] != float64(1080) {
		t.Errorf("元数据解歪了：%+v", ob.Meta)
	}
	if !ob.MetadataSeen {
		t.Errorf("MetadataSeen 没跟上")
	}
	got := s.Commands()
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "connect") || !strings.Contains(joined, "createStream") ||
		!strings.Contains(joined, "play") {
		t.Errorf("服务器侧看到的命令少了：%v", got)
	}
	// ★ 探测绝不能变成推流：这几条一旦发出去就是往别人服务器上挂了一路流。
	for _, forbidden := range []string{"publish", "FCPublish", "releaseStream", "deleteStream"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("探测发出了 %s —— 那是改动，不是问话", forbidden)
		}
	}
	if p := s.ConnectParams(); p == nil || p["app"] != "live" {
		t.Errorf("connect 里的应用名不对：%v", p)
	}
}

// 对端把块大小改成 16：回包被切成一小块一小块，探测端要跟着切。
func Test对端把块大小切成16也读得回来(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeTinyChunks)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sess, _, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("块大小 16 就读不下去了：%v", err)
	}
	if sess.PeerChunk != 16 {
		t.Errorf("没跟着对端改块大小，还以为是 %d", sess.PeerChunk)
	}
	if ob.MediaBytes == 0 {
		t.Error("块大小改小之后一条媒体都没数到：续块拼错了")
	}
}

// 中途改一次块大小（先 4096 答命令，play 之后改 128）。
func Test中途改块大小后面的媒体照样数得清(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeChunkMidway)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sess, _, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ob.Status.Code() != "NetStream.Play.Start" {
		t.Errorf("play 的回包没认出来：%+v", ob.Status)
	}
	if sess.PeerChunk != 128 {
		t.Errorf("改完之后没跟上，块大小记的是 %d", sess.PeerChunk)
	}
	if ob.MediaBytes < s.MediaBurst*s.MediaSize {
		t.Errorf("换块大小之后媒体少收了：%d", ob.MediaBytes)
	}
}

// 时间戳大到 3 字节能写的范围之外，要走 4 字节扩展形式。
func Test时间戳走四字节扩展形式(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeExtendedTS)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ob.MediaBytes == 0 {
		t.Error("扩展时间戳那一条没读回来")
	}
	// ★ 光「字节到了」不够：头里那 4 字节没读对的话字节照样到，时间戳却停在
	//   3 字节能写的最大值。假服务器最后一条写的是 0x01000000。
	if ob.Stats.LastMediaTS < 0x01000000 {
		t.Errorf("四字节扩展时间戳没读对，拿到的是 0x%x", ob.Stats.LastMediaTS)
	}
}

// 命令装在 AMF3 壳里（类型 17，正文前多两字节）。
func Test命令装在AMF3壳里也认(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeAMF3Command)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, connCmd, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("AMF3 壳就认不出了：%v", err)
	}
	if connCmd.Name != "_result" {
		t.Errorf("AMF3 壳里的 connect 答案没认出来：%s", connCmd.Name)
	}
	if ob.Status.Code() != "NetStream.Play.Start" {
		t.Errorf("AMF3 壳里的 onStatus 没解开：%+v", ob.Status)
	}
}

// 命令里的 transaction id 没带 0x00 类型标记（8 个裸 double 字节）。
//
// ★ 这一条不是洁癖：Adobe 的规范里命令的第二格是 number，各家实现有的干脆不写
//
//	标记。探测端要是不认，那 8 字节会被当成一个不认识的 AMF0 标记，
//	连 connect 的答案都解不开 —— 现场看起来就像「这台服务器不回话」。
func Test命令里的transactionId没带类型标记(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeBareTx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, connCmd, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("裸 double 的 transaction id 就认不出了：%v", err)
	}
	if connCmd.Name != "_result" || connCmd.Tx != 1 {
		t.Errorf("connect 的答案没解开：名字 %s 序号 %v", connCmd.Name, connCmd.Tx)
	}
	if connCmd.Info() == nil {
		t.Error("那 8 字节要是不被当成裸 double，后面的属性就整体错位了")
	}
	if ob.Status.Code() != "NetStream.Play.Start" {
		t.Errorf("onStatus 没解开：%+v", ob.Status)
	}
}

// 只握手、不答命令：这一档必须停在 connect 上，并且说的是「没回话」。
func Test它只握手不答命令(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeSilent)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	sess, err := RTMPDial(ctx, s.Host(), s.Port(), 2*time.Second)
	if err != nil {
		t.Fatalf("握手本身是通的，不该在这儿报错：%v", err)
	}
	defer sess.Close()
	if err := sess.Begin(2 * time.Second); err != nil {
		t.Fatalf("开场协议消息发不出去：%v", err)
	}
	_, err = sess.Connect("live", "rtmp://x/live", nil, 800*time.Millisecond)
	var re *RTMPError
	if !errors.As(err, &re) {
		t.Fatalf("没回话却没报错：%v", err)
	}
	if re.Kind != RTMPKindTimeout || re.Stage != "connect" {
		t.Errorf("要的是 connect 这一步超时，拿到 %s / %s", re.Stage, re.Kind)
	}
}

// 端口开着，可回的那一句是 HTTP —— 现场真有把 1935 配成 Web 端口的。
func Test端口开着但回的不是RTMP(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeJunk)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = RTMPDial(context.Background(), s.Host(), s.Port(), 2*time.Second)
	var re *RTMPError
	if !errors.As(err, &re) || re.Kind != RTMPKindNotRTMP {
		t.Fatalf("没判成「不是 RTMP」：%v", err)
	}
	var hang *RTMPHangError
	if !errors.As(err, &hang) {
		t.Fatalf("not-rtmp 没把已经看到的那一截带回来：%v", err)
	}
	if hang.Info.Sig != "http" {
		t.Errorf("那一截看着像 %q，想要 http", hang.Info.Sig)
	}
}

// 连上就一句不说：这一档是 handshake 超时，不是「连不上」。
func Test连上就一句不说(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeHang)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = RTMPDial(context.Background(), s.Host(), s.Port(), 600*time.Millisecond)
	var re *RTMPError
	if !errors.As(err, &re) {
		t.Fatalf("%v", err)
	}
	if re.Kind != RTMPKindTimeout || re.Stage != "handshake" {
		t.Errorf("要的是 handshake 超时，拿到 %s / %s", re.Stage, re.Kind)
	}
}

// 应用被拒时，拒绝的原文要带回来 —— 那是「查应用名」还是「去找平台要 key」的分界。
func Test拒绝应用时把拒绝原文带回来(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{rtmptest.ModeRejected, "not found"},
		{rtmptest.ModeAuth, "auth failed"},
	} {
		s, err := rtmptest.Start(tc.mode)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		sess, err := RTMPDial(ctx, s.Host(), s.Port(), 2*time.Second)
		if err != nil {
			s.Close()
			t.Fatalf("%s：%v", tc.mode, err)
		}
		if err := sess.Begin(2 * time.Second); err != nil {
			sess.Close()
			s.Close()
			t.Fatalf("%v", err)
		}
		c, err := sess.Connect("live", "rtmp://x/live", nil, 2*time.Second)
		if err != nil {
			sess.Close()
			s.Close()
			t.Fatalf("%s：%v", tc.mode, err)
		}
		if c.Name != "onStatus" {
			sess.Close()
			s.Close()
			t.Errorf("%s：要的是 onStatus，拿到 %s", tc.mode, c.Name)
			continue
		}
		info := c.Info()
		if info == nil || !strings.Contains(asString(info["description"]), tc.want) {
			t.Errorf("%s：拒绝原因没带回来（想要包含 %q）：%v", tc.mode, tc.want, info)
		}
		sess.Close()
		s.Close()
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// 这路名上没有流：play 直接回 Failed / StreamNotFound。
func Test这路名上没有流(t *testing.T) {
	for _, tc := range []struct{ mode, code string }{
		{rtmptest.ModeStreamGone, "NetStream.Play.Failed"},
		{rtmptest.ModeNotFound, "NetStream.Play.StreamNotFound"},
	} {
		s, err := rtmptest.Start(tc.mode)
		if err != nil {
			t.Fatal(err)
		}
		_, _, ob, err := rtmpProbe(t, s, "live", "cam1", 1200*time.Millisecond)
		if err != nil {
			s.Close()
			t.Fatalf("%s：%v", tc.mode, err)
		}
		if ob.Status.Code() != tc.code {
			t.Errorf("%s：想要 %s，拿到 %q", tc.mode, tc.code, ob.Status.Code())
		}
		s.Close()
	}
}

// 说有这路、可一个媒体字节都不发 —— 这一档和「在推」必须分开。
func Test说有这路可一个媒体字节都没发(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeNoMedia)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, ob, err := rtmpProbe(t, s, "live", "cam1", 500*time.Millisecond)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ob.Status.Code() != "NetStream.Play.Start" {
		t.Errorf("服务器确实说了在播：%q", ob.Status.Code())
	}
	if ob.MediaBytes != 0 {
		t.Errorf("一条媒体都没发，账上却记了 %d 字节", ob.MediaBytes)
	}
}

// 刚说要开始播就把连接断了：这一段是**真发生了事**，要报错，
// 但已经问到的那些（Play.Start、读满多久）必须照样交回去 —— 判定要用它。
func Test刚问到一半它把连接断了(t *testing.T) {
	s, err := rtmptest.Start(rtmptest.ModeCloseOnPlay)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, ob, err := rtmpProbe(t, s, "live", "cam1", 500*time.Millisecond)
	if err == nil {
		t.Fatal("对端中途断线却报「窗口读满了」—— 那会把这一档抹平成正常")
	}
	if ob.Status.Code() != "NetStream.Play.Start" {
		t.Errorf("play 开始那一句没收到：%+v", ob.Status)
	}
	if ob.Messages == 0 {
		t.Error("一条消息都没记上")
	}
	if ob.Elapsed >= 500*time.Millisecond {
		t.Errorf("连接早就没了，窗口却记成读满：%v", ob.Elapsed)
	}
}

// 拨一个没人听的端口：这一档留给工具层去分 closed / filtered，这里只管报错。
func Test没人听的端口(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	_, err = RTMPDial(context.Background(), "127.0.0.1", port, time.Second)
	if err == nil {
		t.Fatal("没人听却报成功")
	}
	var re *RTMPError
	if !errors.As(err, &re) || re.Stage != "dial" {
		t.Errorf("要的是 dial 阶段的错：%v", err)
	}
}
