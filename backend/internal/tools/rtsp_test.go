package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

// ★ 真实的 SPS（x264/x265 在已知分辨率下编出来的），不是手写的。
const (
	sps2K     = "Z/QAMpGbKAUAFrYCIAAAAwAgAAAGQeMGMsA="
	sps1080p  = "Z/QAKJGbKA8ARPxOAiAAAAMAIAAABkHjBjLA"
	sps265x2K = "QgEBBAgAAAMAnggAAAMAAJaQACgEALQssrNJJleAtwICAAQAAAMABAAAAwBkIA=="
)

// fakeRTSP 起一个最小 RTSP 服务器。
//
// ★ 为什么要有它：RTSP 探测的价值全在**对真东西说对话**。
// 只测 SDP 解析函数，证明不了握手、认证、状态码这些真正容易错的地方。
type fakeRTSP struct {
	needAuth bool
	status   int    // 认证通过后回的状态码，0 = 200
	sdp      string //
	garbage  bool   // 回一段不是 RTSP 的东西
}

func (f *fakeRTSP) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return ln.Addr().String()
}

func (f *fakeRTSP) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		var head []string
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				return
			}
			l = strings.TrimRight(l, "\r\n")
			if l == "" {
				break
			}
			head = append(head, l)
		}
		if f.garbage {
			c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n<html>我不是 RTSP</html>"))
			return
		}
		cseq, hasAuth := "1", false
		for _, l := range head {
			if strings.HasPrefix(strings.ToLower(l), "cseq:") {
				cseq = strings.TrimSpace(l[5:])
			}
			if strings.HasPrefix(l, "Authorization:") {
				hasAuth = true
			}
		}
		switch {
		case f.needAuth && !hasAuth:
			fmt.Fprintf(c, "RTSP/1.0 401 Unauthorized\r\nCSeq: %s\r\n"+
				"WWW-Authenticate: Digest realm=\"IPCamera\", nonce=\"abc123\", qop=\"auth,auth-int\"\r\n\r\n", cseq)
		case f.status != 0 && f.status != 200:
			fmt.Fprintf(c, "RTSP/1.0 %d Error\r\nCSeq: %s\r\n\r\n", f.status, cseq)
		default:
			fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Type: application/sdp\r\n"+
				"Content-Length: %d\r\n\r\n%s", cseq, len(f.sdp), f.sdp)
		}
	}
}

func sdpH264(sps string) string {
	return "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Media\r\nt=0 0\r\n" +
		"m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n" +
		"a=fmtp:96 packetization-mode=1;sprop-parameter-sets=" + sps + ",aO48gA==\r\n" +
		"a=control:track1\r\n" +
		"m=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=control:track2\r\n"
}

func probe(t *testing.T, args string) (string, map[string]any) {
	t.Helper()
	out, err := probeRTSP(context.Background(), json.RawMessage(args))
	if err != nil {
		t.Fatalf("探测出错：%v", err)
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	vals, _ := m["values"].(map[string]any)
	return m["verdict"].(string), vals
}

// ★★ 这条是那次现场排查的核心：相机实际出的是 2K，
// 而盒子的帧池按 1080p 建 —— 分辨率这个数准不准，决定排查方向对不对。
func Test探出相机真实分辨率是2K(t *testing.T) {
	addr := (&fakeRTSP{sdp: sdpH264(sps2K)}).start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/cam/realmonitor?channel=1"}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q，期望 %q", code, verdictStreamOK)
	}
	if vals["width"] != 2560.0 || vals["height"] != 1440.0 {
		t.Fatalf("分辨率 = %vx%v，期望 2560x1440 —— 这个数错了，整条排查就走偏了",
			vals["width"], vals["height"])
	}
	if vals["codec"] != "h264" {
		t.Errorf("codec = %v", vals["codec"])
	}
	// 音视频两路都要认出来
	if vals["trackCount"] != 2.0 {
		t.Errorf("轨数 = %v，期望 2（视频 + 音频）", vals["trackCount"])
	}
}

func Test探出1080p不会报成1088(t *testing.T) {
	addr := (&fakeRTSP{sdp: sdpH264(sps1080p)}).start(t)
	_, vals := probe(t, `{"url":"rtsp://`+addr+`/"}`)
	if vals["height"] != 1080.0 {
		t.Fatalf("高 = %v，期望 1080", vals["height"])
	}
}

func TestH265的流也能探出分辨率(t *testing.T) {
	sdp := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Media\r\nt=0 0\r\n" +
		"m=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n" +
		"a=fmtp:96 sprop-sps=" + sps265x2K + "\r\n"
	addr := (&fakeRTSP{sdp: sdp}).start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/"}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q", code)
	}
	if vals["width"] != 2560.0 || vals["height"] != 1440.0 {
		t.Fatalf("分辨率 = %vx%v，期望 2560x1440 —— 2K 相机现在普遍用 H.265，"+
			"只支持 H.264 等于在最需要的场合用不上", vals["width"], vals["height"])
	}
}

// ★ 主流网络摄像机（大华、海康）默认都是 Digest 认证，只做 Basic 等于用不了。
func Test没给密码时明确说要认证(t *testing.T) {
	addr := (&fakeRTSP{needAuth: true, sdp: sdpH264(sps2K)}).start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/"}`)
	if code != verdictAuthRequired {
		t.Fatalf("判定 = %q，期望 %q", code, verdictAuthRequired)
	}
	if vals["authScheme"] != "digest" {
		t.Errorf("认证方式 = %v，期望 digest", vals["authScheme"])
	}
}

func TestDigest认证能过(t *testing.T) {
	addr := (&fakeRTSP{needAuth: true, sdp: sdpH264(sps2K)}).start(t)
	code, vals := probe(t, `{"url":"rtsp://admin:pass@`+addr+`/"}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q，期望认证后取到流", code)
	}
	if vals["width"] != 2560.0 {
		t.Errorf("分辨率 = %v", vals["width"])
	}
	// ★ 凭据不许出现在结果里 —— 结果会进日志、会发给 AI
	if s := fmt.Sprint(vals); strings.Contains(s, "pass") || strings.Contains(s, "admin") {
		t.Errorf("结果里带上了凭据：%v", vals)
	}
}

func Test路径不对报notfound(t *testing.T) {
	addr := (&fakeRTSP{status: 404}).start(t)
	code, _ := probe(t, `{"url":"rtsp://`+addr+`/错的通道"}`)
	if code != verdictNotFound {
		t.Fatalf("判定 = %q，期望 %q —— 这和「连不上」是两回事，"+
			"一个是通道号写错、一个是网络不通", code, verdictNotFound)
	}
}

func Test对面不是RTSP服务(t *testing.T) {
	addr := (&fakeRTSP{garbage: true}).start(t)
	code, _ := probe(t, `{"url":"rtsp://`+addr+`/"}`)
	if code != verdictNoResponse {
		t.Fatalf("判定 = %q，期望 %q", code, verdictNoResponse)
	}
}

func Test连不上(t *testing.T) {
	code, _ := probe(t, `{"url":"rtsp://127.0.0.1:9/","timeoutMs":800}`)
	if code != verdictRTSPUnreach {
		t.Fatalf("判定 = %q，期望 %q", code, verdictRTSPUnreach)
	}
}

func Test没有参数集时如实说拿不到而不是编一个(t *testing.T) {
	sdp := "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
	addr := (&fakeRTSP{sdp: sdp}).start(t)
	code, vals := probe(t, `{"url":"rtsp://`+addr+`/"}`)
	if code != verdictStreamOK {
		t.Fatalf("判定 = %q —— 没给参数集不代表流不通", code)
	}
	if _, has := vals["width"]; has {
		t.Error("没有参数集却报出了分辨率 —— 那是编的")
	}
	tracks, _ := vals["tracks"].([]any)
	if len(tracks) == 0 {
		t.Fatal("没解出轨")
	}
	if note, _ := tracks[0].(map[string]any)["paramsNote"].(string); note == "" {
		t.Error("该说明为什么拿不到分辨率")
	}
}

// Digest 挑战里 qop="auth,auth-int" 带逗号，按逗号切会把它切坏。
func TestDigest挑战里带逗号的qop(t *testing.T) {
	p := parseChallenge(`Digest realm="IPCamera", nonce="abc", qop="auth,auth-int"`)
	if p["realm"] != "IPCamera" || p["nonce"] != "abc" {
		t.Fatalf("解出来 = %v", p)
	}
	if p["qop"] != "auth,auth-int" {
		t.Errorf("qop = %q —— 引号里的逗号不该被当成分隔符", p["qop"])
	}
}
