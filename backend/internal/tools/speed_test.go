package tools

// net.speed.test 的测试。
//
// ★ 口径与生产一致：下载/上传那两头是**真在搬字节**（靶子起在回环上，走的是同一份
//
//	speedTransfer），不是把中间步骤换成假函数看它调没调。
//	判定那张表用合成的 sides 走一遍 —— 「公网」这类目标在测试机上没有，
//	拿真外网做测试就是一条迟早自己坏掉、而且坏了说不清是谁的锅的测试。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/ots"
)

// speedRig 是一个只听回环的测速靶子：给下载、收上传、还有一条永远给不完流。
type speedRig struct {
	srv      *httptest.Server
	up       *int64
	dlBytes  int64
	lastCode int32
}

func (r *speedRig) url(path string) string { return r.srv.URL + path }

func (r *speedRig) uploaded() int64 { return atomic.LoadInt64(r.up) }

func speedNewRig(t *testing.T, dlSize int64) *speedRig {
	t.Helper()
	rig := &speedRig{up: new(int64), dlBytes: dlSize}
	mux := http.NewServeMux()
	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(rig.dlBytes))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(w, io.LimitReader(speedPadding(), rig.dlBytes))
	})
	mux.HandleFunc("/ul", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		atomic.AddInt64(rig.up, n)
		fmt.Fprintf(w, "%d", n)
	})
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "没有这个", http.StatusNotFound)
	})
	mux.HandleFunc("/endless", func(w http.ResponseWriter, r *http.Request) {
		// 一直给、永远给不完，但**按每秒十几兆给**：验「到秒数收的」那一档写成下界而不是实测上限。
		// ★ 不节流的话回环上一秒就能搬完 64 MiB，先撞的是字节闸，那道表的弦就没验到。
		flusher, _ := w.(http.Flusher)
		chunk := speedPadBytes(64 << 10)
		for r.Context().Err() == nil {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	rig.srv = httptest.NewServer(mux)
	t.Cleanup(rig.srv.Close)
	return rig
}

func speedIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("测试里写了个不是 IP 的东西：" + s)
	}
	return ip
}

func speedURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := speedParseURL(s)
	if err != nil {
		t.Fatalf("%q 当成地址读不出来：%v", s, err)
	}
	if u == nil {
		t.Fatalf("%q 是空的", s)
	}
	return u
}

// ── 端到端：真搬字节的那几条 ──

func Test测速下载量到的是真搬了多少(t *testing.T) {
	rig := speedNewRig(t, 4<<20)
	x := speedTransfer(context.Background(), speedURL(t, rig.url("/dl")), speedIP("127.0.0.1"), 5, 64, false)
	if x.End != xferComplete {
		t.Errorf("收尾写成 %s，要 %s（它给了 Content-Length，四兆我们全读到了）", x.End, xferComplete)
	}
	if x.Bytes != 4<<20 {
		t.Errorf("读到 %d 字节，要 %d —— 速率的分子就不是真搬的那份了", x.Bytes, int64(4<<20))
	}
	if x.Mbps <= 0 || x.MS <= 0 {
		t.Errorf("速率或耗时是 0：%+v", x)
	}
	if x.Length != 4<<20 {
		t.Errorf("contentLength = %d，要 4194304", x.Length)
	}
	if x.TTFBMs <= 0 {
		t.Error("没记下等到首字节花了多久")
	}
}

func Test测速下载按字节闸收的必须写成下界(t *testing.T) {
	rig := speedNewRig(t, 4<<20)
	x := speedTransfer(context.Background(), speedURL(t, rig.url("/dl")), speedIP("127.0.0.1"), 5, 1, false)
	if x.End != xferByteCap {
		t.Errorf("收尾 = %s，要 %s：它还有 3 兆我们没读，报成 complete 就是把下界当实测", x.End, xferByteCap)
	}
	if x.Bytes != 1<<20 {
		t.Errorf("读了 %d 字节，闸是 1 MiB，不该多读", x.Bytes)
	}
}

func Test测速下载秒数到点的也写成下界(t *testing.T) {
	rig := speedNewRig(t, 0)
	x := speedTransfer(context.Background(), speedURL(t, rig.url("/endless")), speedIP("127.0.0.1"), 1, 64, false)
	if x.End != xferTimeCap {
		t.Errorf("收尾 = %s，要 %s（那条流永远给不完）", x.End, xferTimeCap)
	}
	if x.Bytes <= 0 {
		t.Fatalf("一秒里一个字节都没读到：%+v", x)
	}
	// ★ 搬运那一段的表要**不含**建连与等首字节：混进来的话，
	//	握手慢两秒就把一条快路报成「一秒只搬了这么多」。
	if x.MS > 1200 {
		t.Errorf("搬运记成 %d ms，闸是 1 秒：那道闸把握手的表也算进去了", x.MS)
	}
}

func Test测速上传发出去的就是对面收到的(t *testing.T) {
	rig := speedNewRig(t, 0)
	x := speedTransfer(context.Background(), speedURL(t, rig.url("/ul")), speedIP("127.0.0.1"), 5, 1, true)
	if x.End != xferComplete {
		t.Fatalf("收尾 = %s，要 %s（%v）", x.End, xferComplete, x.Err)
	}
	if x.Bytes != 1<<20 {
		t.Errorf("记成交出 %d 字节，闸是 1 MiB", x.Bytes)
	}
	if x.Mbps <= 0 {
		t.Error("上传速率 0，等于这一头白测")
	}
	// 我们记的分子必须是**真上路**的：对面少收了就说明数里掺了还没出门的。
	if got := rig.uploaded(); got != x.Bytes {
		t.Errorf("对面收到 %d，我们记成交出 %d", got, x.Bytes)
	}
}

func Test测速上传不把对面存文件的时间算进速率(t *testing.T) {
	// 收完正文先睡两秒再回执：那两秒是它在忙，不是这条路慢。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	x := speedTransfer(context.Background(), speedURL(t, srv.URL), speedIP("127.0.0.1"), 10, 1, true)
	if x.End != xferComplete {
		t.Fatalf("收尾 = %s，要 %s", x.End, xferComplete)
	}
	if x.MS >= 2000 {
		t.Errorf("上传耗时 %d ms：把对面存完再回执的两秒算成链路慢了", x.MS)
	}
}

func Test测速对面回错误时那一头不算搬到(t *testing.T) {
	rig := speedNewRig(t, 0)
	x := speedTransfer(context.Background(), speedURL(t, rig.url("/404")), speedIP("127.0.0.1"), 3, 1, false)
	if x.Status != http.StatusNotFound {
		t.Errorf("状态码 %d，要 404：目标回的不是数据，这一趟的数不代表链路", x.Status)
	}
	if x.End != xferFailed {
		t.Errorf("收尾 = %s，要 %s", x.End, xferFailed)
	}
	if x.Mbps > 0 {
		t.Errorf("一个 404 也给出了 %s Mbps", ftos(x.Mbps))
	}
}

func Test测速连不上的时候不许编一个速率出来(t *testing.T) {
	// 一个没人听的口：连都没连上，那一头就该是 failed，不是 0 Mbps 的 complete。
	u := speedURL(t, fmt.Sprintf("http://127.0.0.1:%d/dl", freePort(t)))
	x := speedTransfer(context.Background(), u, speedIP("127.0.0.1"), 2, 1, false)
	if x.End != xferFailed {
		t.Errorf("收尾 = %s，要 %s", x.End, xferFailed)
	}
	if x.ErrKind != "refused" {
		t.Errorf("错归成 %s，要 refused：关着与一声不响是两种病", x.ErrKind)
	}
	if x.Bytes != 0 || x.Mbps != 0 {
		t.Errorf("没连上却记了 %d 字节 / %s Mbps", x.Bytes, ftos(x.Mbps))
	}
}

// ── 工具层：参数、目标、闸 ──

func Test测速没给目标一个包都不发(t *testing.T) {
	v := mustSpeedVerdict(t, map[string]any{})
	if v.Code != speedNoTarget {
		t.Errorf("判定 = %s，要 %s", v.Code, speedNoTarget)
	}
	if _, ok := v.Values["sides"]; ok {
		t.Error("没目标也跑出了 sides：那一趟发过东西")
	}
}

func Test测速参数在被发出去之前就被拦掉(t *testing.T) {
	for name, args := range map[string]map[string]any{
		"协议不是 http":  {"url": "ftp://example.invalid/x"},
		"端口越界":       {"host": "example.invalid", "port": 70000},
		"family 不认识": {"host": "example.invalid", "family": "ipv4"},
		"两家写成两个名字":   {"url": "https://a.invalid/dl", "uploadUrl": "https://b.invalid/ul"},
	} {
		_, err := callShare(t, speedTestTool, args)
		if err == nil {
			t.Errorf("%s：这一条本该在发任何东西之前就被拦掉", name)
			continue
		}
		var oe *ots.Error
		if !asOtsError(err, &oe) || oe.Code != ots.ErrInvalidArgument {
			t.Errorf("%s：错误是 %v，要参数错", name, err)
		}
	}
}

func Test测速内网目标默认不搬数据(t *testing.T) {
	rig := speedNewRig(t, 1<<20)
	v := mustSpeedVerdict(t, map[string]any{"url": rig.url("/dl"), "family": "v4"})
	if v.Code != speedLocalTarget {
		t.Errorf("判定 = %s，要 %s", v.Code, speedLocalTarget)
	}
	s := speedFirstSide(t, v)
	if s["skipped"] != "local" {
		t.Errorf("那一栈记成 %v，要 local", s["skipped"])
	}
	if _, ok := s["download"]; ok {
		t.Error("默认就把数据打进内网那台机器了：现场一台弱交换机会被这一趟打趴")
	}
	if rig.uploaded() != 0 {
		t.Error("靶子收到了东西：默认那一趟根本没打算发")
	}
}

func Test测速开了内网开关之后数照给但写明不是公网(t *testing.T) {
	rig := speedNewRig(t, 1<<20)
	v := mustSpeedVerdict(t, map[string]any{
		"url": rig.url("/dl"), "family": "v4", "allowPrivate": true, "seconds": 5})
	if v.Code != speedLocalTarget {
		t.Errorf("判定 = %s，要 %s：量到内网的数，更要把那句「这不是公网」摆在最响的位置", v.Code, speedLocalTarget)
	}
	if !strings.Contains(v.Note, "内网") {
		t.Errorf("那句话里没写内网：%s", v.Note)
	}
	s := speedFirstSide(t, v)
	if s["private"] != true {
		t.Error("这一栈没标 private：界面就没了「这是内网数」那个记号")
	}
	dl, ok := s["download"].(map[string]any)
	if !ok {
		t.Fatalf("没有下载那本账：%v", s)
	}
	if dl["bytes"] != int64(1<<20) {
		t.Errorf("下载记成 %v 字节，要 1048576", dl["bytes"])
	}
}

func Test测速那条栈没地址时报没地址而不是报零(t *testing.T) {
	v := mustSpeedVerdict(t, map[string]any{"host": "127.0.0.1", "family": "v6", "allowPrivate": true})
	if v.Code != speedSingleFamily {
		t.Errorf("判定 = %s，要 %s", v.Code, speedSingleFamily)
	}
	s := speedFirstSide(t, v)
	if s["skipped"] != "no-address" {
		t.Errorf("那一栈记成 %v，要 no-address", s["skipped"])
	}
	if _, ok := s["latency"]; ok {
		t.Error("那一栈没地址却给出了往返数")
	}
}

// ── 往返那本账 ──

func Test测速往返对着关着的口一发就收表(t *testing.T) {
	rt := speedMeasureRTT(context.Background(), speedIP("127.0.0.1"), freePort(t), 10)
	if rt.Done != 0 {
		t.Errorf("没人听的口连上了 %d 发", rt.Done)
	}
	if rt.Refused != 1 {
		t.Errorf("拒的记录 %d 发，要 1：同一句话不必说九遍", rt.Refused)
	}
	if rt.Untried != 9 || rt.Sent != 1 {
		t.Errorf("没发的 %d、发过的 %d：收表后剩下的不该算进分母", rt.Untried, rt.Sent)
	}
}

func Test测速往返的统计口径(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	rt := speedMeasureRTT(context.Background(), speedIP("127.0.0.1"), speedPort(t, srv.URL), 6)
	if rt.Done != 6 {
		t.Fatalf("连上 %d 发，要 6", rt.Done)
	}
	if !(rt.MinMS <= rt.MedMS && rt.MedMS <= rt.MaxMS && rt.P95MS >= rt.MinMS) {
		t.Errorf("min %v / med %v / max %v / p95 %v 排不拢", rt.MinMS, rt.MedMS, rt.MaxMS, rt.P95MS)
	}
	if rt.AvgMS <= 0 {
		t.Error("平均往返是 0")
	}
	// 抖动按发的先后算：这例子按大小算是 0，按先后算是 2。
	if got := speedJitter([]float64{1, 3, 1, 3}); got != 2 {
		t.Errorf("抖动 = %v，要 2", got)
	}
	if got := speedJitter([]float64{1}); got != 0 {
		t.Errorf("一发谈不上抖，抖动 = %v", got)
	}
}

func Test测速只给host时只量往返(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	v := mustSpeedVerdict(t, map[string]any{
		"host": strings.TrimPrefix(srv.URL, "http://"), "family": "v4", "allowPrivate": true})
	if v.Code != speedLatencyOnly {
		t.Errorf("判定 = %s，要 %s（那句话：%s）", v.Code, speedLatencyOnly, v.Note)
	}
	s := speedFirstSide(t, v)
	if _, ok := s["latency"]; !ok {
		t.Error("连往返都没给")
	}
	if _, ok := s["download"]; ok {
		t.Error("没给下载地址却搬了数据")
	}
}

// ── 判定表：合成 sides 走一遍 ──

func Test测速判定按证据先后挑那一个(t *testing.T) {
	lat := func(done, sent, refused, timeout int) *speedRT {
		return &speedRT{Done: done, Sent: sent, Refused: refused, TimedOut: timeout}
	}
	xf := func(end string, mbps float64, status int, bytes int64) *speedXfer {
		return &speedXfer{End: end, Mbps: mbps, Status: status, Bytes: bytes}
	}
	okDown := xf(xferComplete, 88.4, 200, 4<<20)
	okUp := xf(xferComplete, 12.1, 200, 1<<20)
	cases := []struct {
		name  string
		sides []*speedSide
		asked int
		want  string
	}{
		{"两头都量到了", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0), Down: okDown, Up: okUp}}, 1, speedOK},
		{"只量到下载一头", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0), Down: okDown}}, 1, speedOneSided},
		{"一条栈没地址", []*speedSide{
			{Family: "v4", Lat: lat(10, 10, 0, 0), Down: okDown, Up: okUp},
			{Family: "v6", Skip: "no-address"}}, 2, speedSingleFamily},
		{"秒数到点的下界", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0),
			Down: xf(xferTimeCap, 30, 200, 1<<20), Up: okUp}}, 1, speedCapped},
		{"字节闸收的下界", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0),
			Down: okDown, Up: xf(xferByteCap, 5, 200, 1<<20)}}, 1, speedCapped},
		{"搬到一半断了", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0),
			Down: xf(xferCut, 20, 200, 1<<20), Up: okUp}}, 1, speedCutShort},
		{"回的不是数据", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0),
			Down: xf(xferFailed, 0, 404, 0), Up: okUp}}, 1, speedBadStatus},
		{"一发都没连上（关着）", []*speedSide{{Family: "v4", Lat: lat(0, 1, 1, 0)}}, 1, speedUnreachable},
		{"一发都没连上（静默）", []*speedSide{{Family: "v4", Lat: lat(0, 3, 0, 3)}}, 1, speedUnreachable},
		{"有几发没通", []*speedSide{{Family: "v4", Lat: lat(7, 10, 0, 3), Down: okDown, Up: okUp}}, 1, speedFlaky},
		{"一条连上一条没连上", []*speedSide{
			{Family: "v4", Lat: lat(10, 10, 0, 0), Down: okDown, Up: okUp},
			{Family: "v6", Lat: lat(0, 3, 0, 3)}}, 2, speedFlaky},
		{"默认不收内网这一趟", []*speedSide{{Family: "v4", Addr: "192.168.1.1", Skip: "local"}}, 1, speedLocalTarget},
		{"开了开关的内网数", []*speedSide{{Family: "v4", Private: true, Lat: lat(10, 10, 0, 0), Down: okDown, Up: okUp}}, 1, speedLocalTarget},
		{"内网且只量到一头", []*speedSide{{Family: "v4", Private: true, Lat: lat(10, 10, 0, 0), Down: okDown}}, 1, speedLocalTarget},
		{"内网但一发没连上", []*speedSide{{Family: "v4", Private: true, Lat: lat(0, 3, 0, 3)}}, 1, speedUnreachable},
		{"只量往返", []*speedSide{{Family: "v4", Lat: lat(10, 10, 0, 0)}}, 1, speedLatencyOnly},
	}
	for _, tc := range cases {
		values := map[string]any{"v4Addresses": []string{"1.2.3.4"}, "v6Addresses": []string{}}
		v, err := speedVerdict(values, tc.sides, tc.asked, 5, 64)
		if err != nil {
			t.Errorf("%s：%v", tc.name, err)
			continue
		}
		if v.Code != tc.want {
			t.Errorf("%s → %s，要 %s（那句话：%s）", tc.name, v.Code, tc.want, v.Note)
		}
		if v.Values == nil {
			t.Errorf("%s：判定没带着账回来 [OTS-5.3]", tc.name)
		}
		// Note 是会被界面 esc() 之后原样摆在人眼前的（app.js speedPaint），
		// 那里没有 markdown 引擎：写 ** 就是让人看一对星号。
		if strings.Contains(v.Note, "**") {
			t.Errorf("%s：那句话里带着 markdown 星号，界面会原样显示：%s", tc.name, v.Note)
		}
	}
}

func Test测速最响的那个理由不许把另一本账盖掉(t *testing.T) {
	// 「这是内网数」和「只量到一头」「那条栈没量」是三件事，同时成立时三件都要说。
	// 判定码只能有一个，剩下的那几件全靠这句话兜住 —— 少一件就是说假话。
	lat := &speedRT{Done: 10, Sent: 10}
	sides := []*speedSide{
		{Family: "v4", Private: true, Lat: lat, Down: &speedXfer{End: xferComplete, Mbps: 88.4, Status: 200, Bytes: 4 << 20}},
		{Family: "v6", Skip: "no-address"},
	}
	values := map[string]any{"v4Addresses": []string{"1.2.3.4"}, "v6Addresses": []string{}}
	v, err := speedVerdict(values, sides, 2, 5, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v.Code != speedLocalTarget {
		t.Errorf("判定 = %s，要 %s", v.Code, speedLocalTarget)
	}
	for _, want := range []string{"内网", "只量到了下载一头", "v6 那条栈那个名字下没地址"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("那句话里没写 %q：%s", want, v.Note)
		}
	}
	// 句子得读得通：不能出来「…；）」或两个「——」。
	for _, bad := range []string{"；）", "；。", "。。", "；；"} {
		if strings.Contains(v.Note, bad) {
			t.Errorf("那句话里出现了 %q：%s", bad, v.Note)
		}
	}
}

// 只量到一头时，那句话必须点名**量到的那一头**：点名错了，人就照着去填已经填过的那个地址。
func Test测速只量到一头时点名的是量到的那一头(t *testing.T) {
	for _, tc := range []struct {
		name  string
		side  *speedSide
		want  string
		avoid string
	}{
		{"只有下载", &speedSide{Family: "v4", Lat: &speedRT{Done: 10, Sent: 10},
			Down: &speedXfer{End: xferComplete, Mbps: 90, Status: 200, Bytes: 1 << 20}}, "只量到了下载一头", "上传一头"},
		{"只有上传", &speedSide{Family: "v4", Lat: &speedRT{Done: 10, Sent: 10},
			Up: &speedXfer{End: xferComplete, Mbps: 12, Status: 200, Bytes: 1 << 20}}, "只量到了上传一头", "下载一头"},
	} {
		values := map[string]any{"v4Addresses": []string{"203.0.113.9"}, "v6Addresses": []string{}}
		v, err := speedVerdict(values, []*speedSide{tc.side}, 1, 5, 64)
		if err != nil {
			t.Errorf("%s：%v", tc.name, err)
			continue
		}
		if v.Code != speedOneSided {
			t.Errorf("%s → %s，要 %s", tc.name, v.Code, speedOneSided)
		}
		if !strings.Contains(v.Note, tc.want) {
			t.Errorf("%s：那句话没写 %q：%s", tc.name, tc.want, v.Note)
		}
		if strings.Contains(v.Note, tc.avoid) {
			t.Errorf("%s：那句话点名点反了（出现了 %q）：%s", tc.name, tc.avoid, v.Note)
		}
		// 内网那一档走的是另一条 case，点名不许反过来。
		priv := *tc.side
		priv.Private = true
		vp, err := speedVerdict(values, []*speedSide{&priv}, 1, 5, 64)
		if err != nil {
			t.Fatal(err)
		}
		if vp.Code != speedLocalTarget || !strings.Contains(vp.Note, tc.want) {
			t.Errorf("%s（内网那一档）：%s → %q", tc.name, vp.Code, vp.Note)
		}
	}
}

func Test测速的判定码都合规(t *testing.T) {
	for _, code := range []string{speedNoTarget, speedLocalTarget, speedUnreachable, speedFlaky,
		speedBadStatus, speedCutShort, speedCapped, speedLatencyOnly, speedOneSided,
		speedSingleFamily, speedOK} {
		if !speedCodeOK(code) {
			t.Errorf("判定码 %q 不合 [OTS-5.5]（只能小写字母、数字、连字符）", code)
		}
	}
}

// ── 批准与凭据 ──

func Test测速的批准说明说到人能拍板(t *testing.T) {
	s := describeSpeedTest(json.RawMessage(`{"url":"https://ok.example/f.bin",` +
		`"uploadUrl":"https://ok.example/up","seconds":7,"maxMiB":200}`))
	for _, want := range []string{"200", "7", "POST", "填充字节", "ok.example", "内网"} {
		if !strings.Contains(s, want) {
			t.Errorf("批准说明里没有 %q：\n%s", want, s)
		}
	}
}

func Test测速结果里不带凭据(t *testing.T) {
	rig := speedNewRig(t, 1<<20)
	v := mustSpeedVerdict(t, map[string]any{
		"url":          strings.Replace(rig.url("/dl"), "http://", "http://admin:s3cr3tpw@", 1),
		"family":       "v4",
		"allowPrivate": true,
	})
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "s3cr3tpw") {
		t.Error("口令进了结果：这东西会发给 AI，也可能被打进诊断包")
	}
}

func Test测速是mutate且只读符合性里不出现(t *testing.T) {
	if speedTestTool.Class != ots.ClassMutate {
		t.Error("这一张会往别人家发一批数据，标成 read 就是骗批准机制")
	}
	if speedTestTool.Describe == nil {
		t.Fatal("mutate 工具没有 Describe [OTS-7.2]")
	}
	on := ots.NewRegistry(true)
	on.MustRegister(speedTestTool)
	off := ots.NewRegistry(false)
	off.MustRegister(speedTestTool)
	for _, v := range off.Visible() {
		if v.Name == speedTestTool.Name {
			t.Error("mutations=false 时测速还在对外提供")
		}
	}
	if len(on.Visible()) == 0 {
		t.Error("开着 mutate 反而一个都看不见")
	}
	// 没有批准渠道时，注册表不许替人放行。
	if _, err := on.Invoke(context.Background(), speedTestTool.Name, json.RawMessage(`{"host":"127.0.0.1"}`)); err == nil {
		t.Error("没人点头也跑成了")
	} else if !errors.Is(err, ots.Errf(ots.ErrApprovalRequired, "")) && err.Code != ots.ErrApprovalRequired {
		t.Errorf("错是 %v，要「需要批准」", err)
	}
}

// ── 辅助 ──

func mustSpeedVerdict(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	v, err := callShare(t, speedTestTool, args)
	if err != nil {
		t.Fatalf("这一趟失败了：%v", err)
	}
	return v
}

func speedFirstSide(t *testing.T, v ots.Verdict) map[string]any {
	t.Helper()
	var first any
	switch sl := v.Values["sides"].(type) {
	case []map[string]any: // 直接调 Invoke 时拿到的是没经过 JSON 的那一份
		if len(sl) > 0 {
			first = sl[0]
		}
	case []any: // 经诊断包/接口出去再回来时是这份
		if len(sl) > 0 {
			first = sl[0]
		}
	}
	m, ok := first.(map[string]any)
	if !ok {
		t.Fatalf("判定里没有 sides：%#v", v.Values["sides"])
	}
	return m
}

func speedPort(t *testing.T, rawurl string) int {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	if _, err := fmt.Sscanf(u.Port(), "%d", &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func speedCodeOK(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}
