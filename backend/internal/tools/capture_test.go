package tools

// net.capture.* 的测试。
//
// ★ 一路抓包的「怎么取包」全部走 captureOpen 这个变量，所以这里用一台假的采集口
//   把每一种判定钉住：不必碰这台机器此刻有没有提权，也不必真等一个会抖的网络。
//
// ★ 但有两件事不许只靠注入验：
//   ① 落盘的那一份文件必须用生产的写手真写一遍，再让 net.capture.open 真读回来 ——
//      「文件里 100 包、表上 87 包」这种错，只有把文件当真读一遍才看得见；
//   ② 「抓来的表」与「读文件的表」必须是同一张：同一批包走两条路，
//      逐格对得上，才对得起 flow.Table 只写一份这件事。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/capture"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

// ── 环境 ──

// fixCaptureEnv 换掉落盘目录与改动账本，并把全局那一份状态清干净。
//
// ★ 必须清：captureSource 是包级的，上一个测试留下的账会让下一个测试
//
//	看见「上一次那份账还在」，于是「手上没账」这一种判定永远测不到。
func fixCaptureEnv(t *testing.T) string {
	t.Helper()
	oldDir, oldJ, oldOpen := captureDir, journal, captureOpen
	base := t.TempDir()
	j, err := state.Open(filepath.Join(base, "changes.json"))
	if err != nil {
		t.Fatalf("开不了测试账本：%v", err)
	}
	captureDir = filepath.Join(base, "captures")
	journal = j
	t.Cleanup(func() {
		haltCapture(t)
		captureDir, journal, captureOpen = oldDir, oldJ, oldOpen
	})
	return base
}

// haltCapture 收掉可能还在跑的那一路：测试失败中途退出时，
// 留着它会把下一个测试的「第二次开被拒」变成必然。
func haltCapture(t *testing.T) {
	t.Helper()
	captureSource.mu.Lock()
	r := captureSource.run
	captureSource.mu.Unlock()
	if r != nil {
		// ★ 先等它真退出再清空：finish 会把这一路的账挂回 ledger，
		//   先清后等等于亲手把上一个测试的账漏给下一个测试 —— 于是「手上没账」那一种
		//   判定永远测不到，而它恰恰是界面上第一屏要说的话。
		r.requestStop(capWhyUser)
		if !r.waitFor(3 * time.Second) {
			t.Error("这一路抓包到 cleanup 还没退出 —— 它会不会一直在写文件？")
		}
	}
	captureSource.mu.Lock()
	captureSource.run, captureSource.ledger = nil, nil
	captureSource.mu.Unlock()
}

func useFakeSource(t *testing.T, s capture.Source) *int {
	t.Helper()
	old := captureOpen
	opens := 0
	captureOpen = func(capture.Options) (capture.Source, error) {
		opens++
		return s, nil
	}
	t.Cleanup(func() { captureOpen = old })
	return &opens
}

func failSource(t *testing.T, err error) {
	t.Helper()
	old := captureOpen
	captureOpen = func(capture.Options) (capture.Source, error) { return nil, err }
	t.Cleanup(func() { captureOpen = old })
}

func capArgs(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func callCap(t *testing.T, tool ots.Tool, m map[string]any) ots.Verdict {
	t.Helper()
	out, err := tool.Invoke(context.Background(), capArgs(t, m))
	if err != nil {
		t.Fatalf("%s 直接报错：%v", tool.Name, err)
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("%s 返回的不是判定：%T", tool.Name, out)
	}
	if !ots.ValidVerdictCode(v.Code) {
		t.Errorf("%s 的判定码 %q 不合形状（只能小写字母、数字、连字符）", tool.Name, v.Code)
	}
	return v
}

func capRows(v ots.Verdict) []map[string]any {
	out := []map[string]any{}
	raw, _ := json.Marshal(v.Values["flows"])
	_ = json.Unmarshal(raw, &out)
	return out
}

// ── 假采集口 ──

type fakeSource struct {
	mu        sync.Mutex
	pkts      []capture.Packet
	ifaces    []capture.Interface
	stats     capture.Stats
	nextErr   error
	closed    chan struct{}
	closeOnce sync.Once
}

func newFake(pkts []capture.Packet, st capture.Stats) *fakeSource {
	return &fakeSource{
		pkts:   pkts,
		stats:  st,
		ifaces: []capture.Interface{{Name: "eth0", LinkType: capture.LinkTypeEN10MB, SnapLen: capture.DefaultSnapLen}},
		closed: make(chan struct{}),
	}
}

func (s *fakeSource) Next() (capture.Packet, error) {
	s.mu.Lock()
	if len(s.pkts) > 0 {
		p := s.pkts[0]
		s.pkts = s.pkts[1:]
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()
	if s.nextErr != nil {
		return capture.Packet{}, s.nextErr
	}
	<-s.closed
	return capture.Packet{}, capture.ErrClosed
}

func (s *fakeSource) Stats() capture.Stats            { return s.stats }
func (s *fakeSource) Interfaces() []capture.Interface { return s.ifaces }
func (s *fakeSource) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

// ── 造包 ──

var (
	capMACc = net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	capMACd = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
)

func capEth(dst, src net.HardwareAddr, body []byte) []byte {
	b := make([]byte, 0, 14+len(body))
	b = append(b, dst...)
	b = append(b, src...)
	b = binary.BigEndian.AppendUint16(b, 0x0800)
	return append(b, body...)
}

func capIP4(proto byte, src, dst string, body []byte) []byte {
	sip, dip := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	b := make([]byte, 20)
	b[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(body)))
	b[8] = 64
	b[9] = proto
	copy(b[12:16], sip)
	copy(b[16:20], dip)
	return append(b, body...)
}

func capTCP(sp, dp uint16, flags byte, seq uint32, payload []byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sp)
	binary.BigEndian.PutUint16(b[2:4], dp)
	binary.BigEndian.PutUint32(b[4:8], seq)
	b[12] = 5 << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], 64240)
	return append(b, payload...)
}

func capPkt(at time.Time, raw []byte) capture.Packet {
	return capture.Packet{
		InterfaceIndex: 0, Timestamp: at, Data: raw,
		OrigLen: len(raw), HasTimestamp: true,
	}
}

// 这一格里只有这两串是秘密：表上不许出现，文件里必须原样在。
const (
	capSecret   = "CapDigestResp-1a2b3c4d5e6f"
	capIdentity = "capadmin"
)

// rtspSession 是一条点播起手：客户机带 Digest 认证问 DESCRIBE，设备回 200 加一段 SDP。
func rtspSession(base time.Time) []capture.Packet {
	return rtspSessionOn(base, 51234)
}

const (
	capClient = "192.168.1.10"
	capDevice = "10.0.0.9"
)

// rtspSessionOn 同上，客户机端口由调用方给。
//
// ★ 回的那一包必须整个反过来（两个 MAC、源/目的 IP、源/目的端口全部对调）：
//   两包都写成「客户机→设备」时聚合器会归成两条流，界面上那条「一问一答」压根不存在，
//   而这种假一路能绿着通过所有断言。
func rtspSessionOn(base time.Time, cport uint16) []capture.Packet {
	req := "DESCRIBE rtsp://" + capDevice + "/Streaming/Channels/101 RTSP/1.0\r\n" +
		"CSeq: 2\r\n" +
		"Authorization: Digest username=\"" + capIdentity + "\", realm=\"cam\", " +
		"nonce=\"CapNonce-7a6b5c\", uri=\"rtsp://" + capDevice + "/Streaming/Channels/101\", " +
		"response=\"" + capSecret + "\"\r\n\r\n"
	resp := "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\n" +
		"v=0\r\no=- 0 0 IN IP4 " + capDevice + "\r\ns=Live\r\nc=IN IP4 " + capDevice + "\r\n" +
		"t=0 0\r\nm=video 0 RTP/AVP 96\r\na=control:trackID=1\r\n"
	return []capture.Packet{
		capPkt(base, capEth(capMACd, capMACc,
			capIP4(6, capClient, capDevice, capTCP(cport, 554, 0x18, 1001, []byte(req))))),
		capPkt(base.Add(12*time.Millisecond), capEth(capMACc, capMACd,
			capIP4(6, capDevice, capClient, capTCP(554, cport, 0x18, 7001, []byte(resp))))),
	}
}

// arpOnly 是一条与设备无关的广播：收得到包，但归不出一条像样的流。
func arpGarbage(base time.Time, n int) []capture.Packet {
	out := make([]capture.Packet, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, capPkt(base.Add(time.Duration(i)*time.Millisecond),
			[]byte{0x01, 0x02, 0x03}))
	}
	return out
}

func twoSessions(base time.Time) []capture.Packet {
	out := rtspSession(base)
	out = append(out, rtspSessionOn(base.Add(20*time.Millisecond), 51999)...)
	return out
}

// ── 前置闸 ──

func Test没装落盘目录就不许开抓包(t *testing.T) {
	fixCaptureEnv(t)
	opens := useFakeSource(t, newFake(rtspSession(time.Now()), capture.Stats{}))
	dir := captureDir
	captureDir = ""
	t.Cleanup(func() { captureDir = dir })

	_, err := captureStartTool.Invoke(context.Background(), capArgs(t, map[string]any{}))
	if err == nil {
		t.Fatal("落盘目录没装上却开起来了 —— 一份记不下来的抓包等于没抓")
	}
	if !strings.Contains(err.Error(), "用户配置目录") {
		t.Errorf("报错没指到真原因（目录没装），而是说成了别的：%v", err)
	}
	if *opens != 0 {
		t.Errorf("这一路压根该不起采集口，却起了 %d 次", *opens)
	}
}

func Test没装改动账本就不许开抓包(t *testing.T) {
	fixCaptureEnv(t)
	opens := useFakeSource(t, newFake(rtspSession(time.Now()), capture.Stats{}))
	old := journal
	journal = nil
	t.Cleanup(func() { journal = old })

	_, err := captureStartTool.Invoke(context.Background(), capArgs(t, map[string]any{}))
	if err == nil {
		t.Fatal("没有改动账本也开起来了 —— 一路会一直往盘上写的改动记不下来")
	}
	if *opens != 0 {
		t.Errorf("账本都没有还起了 %d 次采集口", *opens)
	}
}

func Test负数与超上限的参数当场拒(t *testing.T) {
	fixCaptureEnv(t)
	opens := useFakeSource(t, newFake(nil, capture.Stats{}))
	cases := []struct {
		name string
		tool ots.Tool
		m    map[string]any
		want string
	}{
		{"snapLen 负", captureStartTool, map[string]any{"snapLen": -1}, "不能是负数"},
		{"bufferMB 负", captureStartTool, map[string]any{"bufferMB": -2}, "不能是负数"},
		{"seconds 负", captureStartTool, map[string]any{"seconds": -3}, "不能是负数"},
		{"maxMB 负", captureStartTool, map[string]any{"maxMB": -1}, "不能是负数"},
		{"blockRetireMs 负", captureStartTool, map[string]any{"blockRetireMs": -1}, "不能是负数"},
		{"snapLen 超上限", captureStartTool, map[string]any{"snapLen": 70000}, "65535"},
		{"seconds 超上限", captureStartTool, map[string]any{"seconds": 999999}, "net.quality"},
		{"maxMB 超上限", captureStartTool, map[string]any{"maxMB": 999999}, "maxMB"},
		{"flows 超上限", captureFlowsTool, map[string]any{"flows": 9999}, "flows"},
		{"flows 负", captureFlowsTool, map[string]any{"flows": -1}, "flows"},
		{"messages 超上限", captureFlowTool, map[string]any{"key": "tcp:x", "messages": 9999}, "messages"},
		{"没给 key", captureFlowTool, map[string]any{}, "key"},
		{"packets 超上限", captureOpenTool, map[string]any{"file": "/tmp/x.pcapng", "packets": 99999999}, "packets"},
		{"没给 file", captureOpenTool, map[string]any{}, "file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.tool.Invoke(context.Background(), capArgs(t, tc.m))
			if err == nil {
				t.Fatalf("%v 这种参数居然收了", tc.m)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("报错里没有 %q：%v", tc.want, err)
			}
			if ots.AsError(err).Code != ots.ErrInvalidArgument {
				t.Errorf("参数写错了应该报 invalid-argument，报到的是 %v —— "+
					"混成 internal 就等于承认是自己的缺陷", ots.AsError(err).Code)
			}
		})
	}
	if *opens != 0 {
		t.Errorf("参数没定下来就不该碰采集口，起了 %d 次", *opens)
	}
}

func Test起不来的四种各给各的下一步(t *testing.T) {
	cases := []struct {
		err    error
		code   string
		wantIn string
	}{
		{capture.ErrNeedPrivilege, capNoPriv, "提权"},
		{capture.ErrUnsupported, capUnsupported, "net.capture.open"},
		{capture.ErrFilterPresent, capFilterOn, "不替你删"},
		{capture.ErrNoSuchInterface, capNoIface, "net.interfaces"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			fixCaptureEnv(t)
			failSource(t, tc.err)
			v := callCap(t, captureStartTool, map[string]any{"interface": "eth0"})
			if v.Code != tc.code {
				t.Fatalf("起不来的这一种应该报 %s，报成了 %s（note：%s）", tc.code, v.Code, v.Note)
			}
			if !strings.Contains(v.Note, tc.wantIn) {
				t.Errorf("下一步里没有 %q：%s", tc.wantIn, v.Note)
			}
			// ★ 四种不许混成同一段话：混了人就只会一遍遍点同一个按钮。
			for _, other := range cases {
				if other.code == tc.code {
					continue
				}
				if v.Code == other.code {
					t.Errorf("%v 和 %v 混成了同一个码", tc.err, other.err)
				}
			}
			entries := journal.Outstanding()
			if len(entries) != 0 {
				t.Errorf("没开起来的这一路在账本上留了 %d 笔 —— 看账本的人会去停一路压根没跑的包", len(entries))
			}
			if _, err := os.Stat(captureDir); err == nil {
				if fs, _ := filepath.Glob(filepath.Join(captureDir, "*")); len(fs) != 0 {
					t.Errorf("起不来却留下了文件 %v —— 第二天会被当成「昨天抓的没有包」", fs)
				}
			}
		})
	}
}

// ── 一路完整的抓包 ──

func Test一路抓包从开到停的账对得上(t *testing.T) {
	fixCaptureEnv(t)
	base := time.Now().Add(-time.Second)
	pkts := rtspSession(base)
	src := newFake(pkts, capture.Stats{Packets: uint64(len(pkts)), Interfaces: 1})
	useFakeSource(t, src)

	v := callCap(t, captureStartTool, map[string]any{"interface": "eth0"})
	if v.Code != capRunning {
		t.Fatalf("开起来应该报 %s，报成 %s（%s）", capRunning, v.Code, v.Note)
	}
	path, _ := v.Values["file"].(string)
	if path == "" {
		t.Fatal("判定里没写文件落在哪 —— 人拿着这个数没法回去找那份包")
	}
	if got := v.Values["interface"]; got != "eth0" {
		t.Errorf("抓的是哪块口没写对：%v", got)
	}
	waitFor(t, "这一路的包都进表", func() bool {
		l := currentLedger()
		return l != nil && l.packets == len(pkts)
	})

	s := callCap(t, captureStatusTool, map[string]any{})
	if s.Code != capRunning {
		t.Errorf("还在跑却报成 %s", s.Code)
	}
	if got := s.Values["packets"]; got != len(pkts) {
		t.Errorf("已经收了 %v 包，应该 %d", got, len(pkts))
	}

	fl := callCap(t, captureFlowsTool, map[string]any{})
	if fl.Code != capFlows {
		t.Fatalf("表应该出得来：%s（%s）", fl.Code, fl.Note)
	}
	rows := capRows(fl)
	if len(rows) != 1 {
		t.Fatalf("这一条点播应该归成一条流，归成了 %d 条：%v", len(rows), keysOfRows(rows))
	}
	if rows[0]["app"] != "rtsp" {
		t.Errorf("RTSP 没认出来（app=%v），协议专解和这条链就断在工具层了", rows[0]["app"])
	}

	stop := callCap(t, captureStopTool, map[string]any{})
	if stop.Code != capStopped {
		t.Fatalf("停了应该报 %s，报成 %s", capStopped, stop.Code)
	}
	if stop.Values["running"] != false {
		t.Error("停了却没写 running=false")
	}

	// ★ 文件里的包数必须与表上说的是同一个数：写文件与更新表在同一次加锁里做，
	//   这句话才立得住；不然界面上那两个数迟早差几包。
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("停完之后文件读不到了：%v", err)
	}
	if n := countFilePackets(t, b); n != len(pkts) {
		t.Errorf("文件里 %d 包，表上 %v 包 —— 两头对不上，现场分不清哪份是哪路",
			n, stop.Values["packets"])
	}
	if len(journal.Outstanding()) != 0 {
		t.Errorf("停了之后账本上还挂着 %d 笔", len(journal.Outstanding()))
	}
	all := journal.All()
	var found bool
	for _, e := range all {
		if e.Kind == "capture" && e.Status == state.StatusReverted {
			found = true
			if !strings.Contains(e.Note, "共 2 包") {
				t.Errorf("账本里那一笔没把这一路的包数写进去：%q", e.Note)
			}
		}
	}
	if !found {
		t.Error("停了却没在账本上落一笔已了结的 —— 下次看账本的人不知道这一路去哪了")
	}

	// 停完之后 status 必须说清「上一次那份账还在」，不许和「压根没抓过」混成一句。
	after := callCap(t, captureStatusTool, map[string]any{})
	if after.Code != capIdle {
		t.Fatalf("停了应该报 %s，报成 %s", capIdle, after.Code)
	}
	if !strings.Contains(after.Note, path) {
		t.Errorf("没告诉人上一次那份账在哪个文件：%s", after.Note)
	}
	// 表还在，直接问得出。
	if callCap(t, captureFlowsTool, map[string]any{}).Code != capFlows {
		t.Error("停了之后表就没了 —— 停这一路不该把人查完的结论一起扔掉")
	}
}

func countFilePackets(t *testing.T, b []byte) int {
	t.Helper()
	rd, err := capture.Open(strings.NewReader(string(b)))
	if err != nil {
		t.Fatalf("写出来的文件自己都读不回来：%v", err)
	}
	n := 0
	for {
		_, err := rd.Read()
		if err == nil {
			n++
			continue
		}
		if errors.Is(err, context.Canceled) {
			t.Fatal("读包卡住了")
		}
		return n
	}
}

func keysOfRows(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		s, _ := r["key"].(string)
		out = append(out, s)
	}
	return out
}

// ── 这一格里最要紧的那条不变量 ──

// 文件里是原始包，表是脱敏的。★ 两边都要验，只验一边都会骗人：
// 只验表脱了敏，可能只是「什么都没解出来所以没东西可漏」；
// 只验文件里有原文，就可能把脱敏做过了头，把现场要拿去对账的证据洗成了一份改过的东西。
func Test文件里是原始包而表是脱敏的(t *testing.T) {
	fixCaptureEnv(t)
	src := newFake(rtspSession(time.Now().Add(-time.Second)), capture.Stats{Packets: 2})
	useFakeSource(t, src)
	v := callCap(t, captureStartTool, map[string]any{})
	path, _ := v.Values["file"].(string)
	waitFor(t, "两包都进表", func() bool {
		l := currentLedger()
		return l != nil && l.packets == 2
	})

	fl := callCap(t, captureFlowsTool, map[string]any{})
	// ★ 脱没漏要连明细一起扫：报文那几格只在 net.capture.flow 里出，
	//   只扫列表这一层，「没漏」多半是「那几格压根没在这份结果里」。
	detail := callCap(t, captureFlowTool, map[string]any{"key": capRows(fl)[0]["key"]})
	b, err := json.Marshal([]any{fl.Values, detail.Values})
	if err != nil {
		t.Fatal(err)
	}
	table := string(b)
	if !strings.Contains(table, capIdentity) {
		t.Fatal("反证前提不成立：这条流压根没解出认证头 —— 那「口令没漏」是「没东西可漏」的假绿")
	}
	if strings.Contains(table, capSecret) {
		t.Errorf("口令漏进了表里 —— 这份是要发给 AI 与界面的\n%s", table)
	}
	if strings.Contains(table, "CapNonce-7a6b5c") {
		t.Error("nonce 漏进了表里：拿它可以重放认证")
	}
	if !strings.Contains(table, capIdentity) {
		t.Error("用户名也被一起洗掉了 —— 表上连是谁在认证都看不出来，脱敏过了头")
	}
	if !strings.Contains(fl.Note, "脱过敏") {
		t.Error("没在结论里写明这张表脱过敏：看不到口令会被当成设备没带口令")
	}
	if creds := capRows(fl)[0]["creds"]; creds == nil || creds.(float64) == 0 {
		t.Errorf("这条流上一格脱敏都没记（creds=%v）—— 上面那句「没漏」就无从核对", creds)
	}

	stop := callCap(t, captureStopTool, map[string]any{})
	if !strings.Contains(stop.Note, "明文") {
		t.Error("停的时候没把「文件里有明文」再给一次：那句话只在文档里，没人看")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), capSecret) {
		t.Error("文件里的原始包被洗过了 —— 拿去跟设备厂商对账的那一份必须一个字都没动")
	}
}

// ── 丢包的三种口径 ──

func Test丢包三种口径不许互相冒充(t *testing.T) {
	cases := []struct {
		name      string
		st        capture.Stats
		code      string
		account   string
		wantIn    string
		notInNote string
	}{
		{"报了包数", capture.Stats{Packets: 10, Dropped: 7}, capLossy, "counted", "内核报了 7 包", ""},
		{"只标过丢过", capture.Stats{Packets: 10, Lossy: true}, capLossy, "flagged-only", "给不出丢了几包", ""},
		{"这一档报没丢", capture.Stats{Packets: 10}, capRunning, "none-reported", "没报丢包", ""},
		{"什么都说不出", capture.Stats{}, capRunning, "unknown", "没报丢包", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixCaptureEnv(t)
			useFakeSource(t, newFake(rtspSession(time.Now()), tc.st))
			v := callCap(t, captureStartTool, map[string]any{})
			if v.Code != tc.code {
				t.Fatalf("应该报 %s，报成 %s", tc.code, v.Code)
			}
			if got := v.Values["dropAccount"]; got != tc.account {
				t.Errorf("丢包口径应该是 %s，成了 %v —— "+
					"把「说不出」当成「没丢」，环开小了的罪就记到链路上了", tc.account, got)
			}
			if !strings.Contains(v.Note, tc.wantIn) {
				t.Errorf("note 里少了 %q：%s", tc.wantIn, v.Note)
			}
			if got := v.Values["lossy"]; tc.st.Lossy && got != true {
				t.Errorf("内核标过丢包却没报出来：%v", got)
			}
		})
	}
}

// ── 自动停的两种 ──

func Test到文件大小上限自动停并说不是一帆风顺(t *testing.T) {
	fixCaptureEnv(t)
	base := time.Now().Add(-time.Minute)
	// 一包塞到接近留长上限，几百包就把 1MB 撑满 —— 用真刻度而不是把上限调成几百字节：
	// 「bytes 与 maxBytes 比的是同一个单位」这件事只有真尺寸能验。
	payload := strings.Repeat("A", 1500)
	var pkts []capture.Packet
	for i := 0; i < 900; i++ {
		pkts = append(pkts, capPkt(base.Add(time.Duration(i)*time.Millisecond),
			capEth(capMACd, capMACc, capIP4(6, "192.168.1.10", "10.0.0.9",
				capTCP(51234, 554, 0x18, uint32(1000+i*1500), []byte(payload))))))
	}
	src := newFake(pkts, capture.Stats{Packets: uint64(len(pkts))})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{"maxMB": 1})

	waitFor(t, "到量自己停", func() bool {
		captureSource.mu.Lock()
		defer captureSource.mu.Unlock()
		return captureSource.run == nil && captureSource.ledger != nil &&
			captureSource.ledger.stopWhy == capWhyMaxBytes
	})
	v := callCap(t, captureStatusTool, map[string]any{})
	if v.Code != capIdle {
		t.Fatalf("停了应该报 %s，报成 %s", capIdle, v.Code)
	}
	if v.Values["stopWhy"] != capWhyMaxBytes {
		t.Errorf("没说是到量停的（stopWhy=%v）—— 「到顶了」和「这条链路真的没流量」是两种相反的下一步",
			v.Values["stopWhy"])
	}
	if !strings.Contains(v.Note, "不是没流量") {
		t.Errorf("note 里没把那句反过来说清楚：%s", v.Note)
	}
	fl := callCap(t, captureFlowsTool, map[string]any{})
	if !strings.Contains(fl.Note, "文件大小上限") && !strings.Contains(fl.Note, "上限") {
		t.Errorf("出表时不带上「这份是被上限截的」，人就会拿半截文件下整份的结论：%s", fl.Note)
	}
}

func Test到时长自己停(t *testing.T) {
	fixCaptureEnv(t)
	src := newFake(rtspSession(time.Now()), capture.Stats{Packets: 2})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{"seconds": 1})
	waitFor(t, "到时长自己停", func() bool {
		captureSource.mu.Lock()
		defer captureSource.mu.Unlock()
		return captureSource.run == nil && captureSource.ledger != nil &&
			captureSource.ledger.stopWhy == capWhyDuration
	})
	v := callCap(t, captureStatusTool, map[string]any{})
	if !strings.Contains(v.Note, "时长") {
		t.Errorf("没说是到时长停的：%s", v.Note)
	}
	if v.Values["running"] != false {
		t.Error("自己停了却没写 running=false")
	}
}

func Test人停与到量停之外还有一种是出错停(t *testing.T) {
	fixCaptureEnv(t)
	src := newFake(rtspSession(time.Now()), capture.Stats{Packets: 2})
	src.nextErr = errors.New("这台机器的采集口被人从外面关了")
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "出错的那一路把账收口", func() bool {
		captureSource.mu.Lock()
		defer captureSource.mu.Unlock()
		return captureSource.run == nil && captureSource.ledger != nil
	})
	v := callCap(t, captureStatusTool, map[string]any{})
	if v.Code != capIdle {
		t.Fatalf("应该报 %s，报成 %s", capIdle, v.Code)
	}
	if v.Values["stopWhy"] != capWhyIOError {
		t.Errorf("出错停的报成了「正常收口」（stopWhy=%v）—— 那种绿最坏", v.Values["stopWhy"])
	}
	if !strings.Contains(v.Note, "采集口被人从外面关了") {
		t.Errorf("没把错的原话带出来：%s", v.Note)
	}
}

// ── 出表的几种情形 ──

func Test一个包都没有时把几种可能分开列(t *testing.T) {
	fixCaptureEnv(t)
	src := newFake(nil, capture.Stats{})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{"interface": "eth0"})
	waitFor(t, "表是空的", func() bool {
		l := currentLedger()
		return l != nil && l.packets == 0
	})
	v := callCap(t, captureFlowsTool, map[string]any{})
	if v.Code != capNoPackets {
		t.Fatalf("一个包都没有应该报 %s，报成 %s", capNoPackets, v.Code)
	}
	for _, want := range []string{"抓的是不是这块口", "根本没流量", "回环", "端口镜像"} {
		if !strings.Contains(v.Note, want) {
			t.Errorf("下一步里少了「%s」：%s", want, v.Note)
		}
	}
	if strings.Contains(v.Note, "链路是空的") {
		t.Error("不许把「没抓到」说成「链路是空的」")
	}
}

func Test收到包却归不出一条流时不说是链路空(t *testing.T) {
	fixCaptureEnv(t)
	pkts := arpGarbage(time.Now().Add(-time.Second), 5)
	src := newFake(pkts, capture.Stats{Packets: uint64(len(pkts))})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "五包都进了账", func() bool {
		l := currentLedger()
		return l != nil && l.packets == len(pkts)
	})
	v := callCap(t, captureFlowsTool, map[string]any{})
	if v.Code != capNoFlows {
		t.Fatalf("有包没流应该报 %s，报成 %s（%s）", capNoFlows, v.Code, v.Note)
	}
	if !strings.Contains(v.Note, "不代表链路是空的") {
		t.Errorf("少了那句要紧的：%s", v.Note)
	}
	// ★ 「有包没流」最要紧的一句是这些包到底去哪儿了：包数账必须跟着出来，
	//   不然人就只剩「网络是空的」这一个解释。
	if !strings.Contains(v.Note, "没拆开") {
		t.Errorf("包数账没跟着出来：%s", v.Note)
	}
	if v.Values["packetAccount"] == nil {
		t.Error("判定里没留包数账那一格：界面想单独显示它也拿不到")
	}
}

func Test筛光了不说成没流量(t *testing.T) {
	fixCaptureEnv(t)
	pkts := rtspSession(time.Now().Add(-time.Second))
	src := newFake(pkts, capture.Stats{Packets: 2})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "表有东西", func() bool { return currentLedger() != nil && currentLedger().packets == 2 })
	v := callCap(t, captureFlowsTool, map[string]any{"app": "modbus"})
	if v.Code != capNoFlows {
		t.Fatalf("筛光了应该报 %s（说清是被筛掉的），报成 %s", capNoFlows, v.Code)
	}
	if !strings.Contains(v.Note, "筛") {
		t.Errorf("没说是被 app/host 筛掉的：%s", v.Note)
	}
	if !strings.Contains(v.Note, "去掉筛项") {
		t.Errorf("没给出下一步：%s", v.Note)
	}
}

func Test只列前N条时明写还有多少条没列(t *testing.T) {
	fixCaptureEnv(t)
	pkts := twoSessions(time.Now().Add(-time.Second))
	src := newFake(pkts, capture.Stats{Packets: uint64(len(pkts))})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "两条流都进了表", func() bool {
		l := currentLedger()
		return l != nil && len(l.table.Flows()) == 2
	})
	v := callCap(t, captureFlowsTool, map[string]any{"flows": 1})
	if v.Code != capFlows {
		t.Fatalf("报成了 %s", v.Code)
	}
	if got := v.Values["flowCount"]; got != 2 {
		t.Errorf("flowCount 应该是整张表有几条（2），成了 %v", got)
	}
	if len(capRows(v)) != 1 {
		t.Errorf("说好只列 1 条，列了 %d 条", len(capRows(v)))
	}
	if !strings.Contains(v.Note, "还有 1 条没列出来") {
		t.Errorf("没写还有几条没列：%s", v.Note)
	}
	all := callCap(t, captureFlowsTool, map[string]any{})
	if len(capRows(all)) != 2 {
		t.Error("默认档位上两条都该列出来")
	}
	// ★ 排序按「哪条最忙」，不是「哪条先来」。
	if capRows(all)[0]["packets"].(float64) < capRows(all)[1]["packets"].(float64) {
		t.Error("表没按包数从多到少排：现场翻表要的是最忙的那条在上面")
	}
}

func Test单条流的明细与一个不存在的key(t *testing.T) {
	fixCaptureEnv(t)
	pkts := rtspSession(time.Now().Add(-time.Second))
	src := newFake(pkts, capture.Stats{Packets: 2})
	useFakeSource(t, src)
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "表有东西", func() bool { return currentLedger() != nil && currentLedger().packets == 2 })
	key := capRows(callCap(t, captureFlowsTool, map[string]any{}))[0]["key"].(string)

	v := callCap(t, captureFlowTool, map[string]any{"key": key})
	if v.Code != capFlows {
		t.Fatalf("明细应该出得来：%s", v.Code)
	}
	msgs, _ := json.Marshal(v.Values["messagesList"])
	if !strings.Contains(string(msgs), "DESCRIBE") {
		t.Errorf("报文列表里没有那条 DESCRIBE：%s", msgs)
	}
	if !strings.Contains(string(msgs), "200") {
		t.Error("设备的 200 OK 没解出来")
	}
	if !strings.Contains(v.Note, "脱过敏") {
		t.Error("明细里没重申脱敏口径")
	}

	bad := callCap(t, captureFlowTool, map[string]any{"key": "tcp:9.9.9.9:1<->8.8.8.8:2"})
	if bad.Code != capNoFlow {
		t.Errorf("表上没有这一条，应该回判定（%s）而不是错误，报成了 %s", capNoFlow, bad.Code)
	}
	if !strings.Contains(bad.Note, "作废") {
		t.Errorf("没解释清楚为什么 key 会不见：%s", bad.Note)
	}
}

// ── 手上什么都没有的那几种问法 ──

func Test没账时四个问法各回一句而不是报错(t *testing.T) {
	fixCaptureEnv(t)
	for _, tc := range []struct {
		name  string
		tool  ots.Tool
		wants []string
	}{
		{"status", captureStatusTool, []string{"net.capture.start", "net.capture.open"}},
		{"stop", captureStopTool, []string{"没有正在抓"}},
		{"flows", captureFlowsTool, []string{"net.capture.start"}},
		{"flow", captureFlowTool, []string{"net.capture.start"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := callCap(t, tc.tool, map[string]any{"key": "tcp:x"})
			if v.Code != capNothing {
				t.Fatalf("应该报 %s，报成 %s（%s）", capNothing, v.Code, v.Note)
			}
			for _, w := range tc.wants {
				if !strings.Contains(v.Note, w) {
					t.Errorf("note 里少了 %q：%s", w, v.Note)
				}
			}
		})
	}
}

func Test第二次开被拒且不顶掉正在跑的那一路(t *testing.T) {
	fixCaptureEnv(t)
	first := newFake(rtspSession(time.Now().Add(-time.Second)), capture.Stats{Packets: 2})
	second := newFake(arpGarbage(time.Now(), 3), capture.Stats{})
	opens := useFakeSource(t, first)
	// 第二路只在第二次调用时给出去：拒得要早，压根不该起第二个口。
	captureOpen = func(o capture.Options) (capture.Source, error) {
		if *opens == 0 {
			*opens++
			return first, nil
		}
		*opens++
		return second, nil
	}
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "第一路收了包", func() bool { return currentLedger() != nil && currentLedger().packets == 2 })

	_, err := captureStartTool.Invoke(context.Background(), capArgs(t, map[string]any{}))
	if err == nil {
		t.Fatal("第二路也开起来了 —— 两路同时往一台机器写原始包，现场分不清哪份是哪路")
	}
	if !strings.Contains(err.Error(), "已经有一路") {
		t.Errorf("报错没说清冲突：%v", err)
	}
	if got := currentLedger(); got == nil || got.origin != "live" || got.packets != 2 {
		t.Errorf("第二路把第一路的账顶掉了：%+v", got)
	}
	if callCap(t, captureStatusTool, map[string]any{}).Code != capRunning {
		t.Error("第一路被顶掉了")
	}
}

// ── 导入已有文件 ──

// ★ 这一条是 flow.Table 只写一份的凭据：同一批包，从采集口接的和从磁盘上读的，
// 必须给出逐格一样的表。两套口径迟早给出两个数，那时候这张表连自己都不如。
func Test导入自己抓的那一份出同一张表(t *testing.T) {
	fixCaptureEnv(t)
	src := newFake(rtspSession(time.Now().Add(-time.Second)), capture.Stats{Packets: 2})
	useFakeSource(t, src)
	v := callCap(t, captureStartTool, map[string]any{})
	path := v.Values["file"].(string)
	waitFor(t, "两包进表", func() bool { return currentLedger() != nil && currentLedger().packets == 2 })

	live := callCap(t, captureFlowsTool, map[string]any{})
	callCap(t, captureStopTool, map[string]any{})
	imported := callCap(t, captureOpenTool, map[string]any{"file": path})

	if imported.Code != capFlows {
		t.Fatalf("导入这份出不了表：%s（%s）", imported.Code, imported.Note)
	}
	a, _ := json.Marshal(live.Values["flows"])
	b, _ := json.Marshal(imported.Values["flows"])
	if string(a) != string(b) {
		t.Errorf("同一批包，抓的与读的文件给出不一样的一张表：\n抓：%s\n读：%s", a, b)
	}
	if got := imported.Values["origin"]; got != "file" {
		t.Errorf("表的来路没写清（origin=%v）：来路要能查，但「看表」那一栏不许因为它换算法", got)
	}
	// 导入之后「看表」问到的就是这一份，不必分辨包从哪来。
	if callCap(t, captureFlowsTool, map[string]any{}).Code != capFlows {
		t.Error("导入的文件没成为当前那份账")
	}
	// ★ 只读不改：导入前后文件一个字节都没变。
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) == 0 {
		t.Error("导入把文件读空了")
	}
}

// writeCapFile 用生产的写手落一份文件，返回路径。
func writeCapFile(t *testing.T, dir string, pkts []capture.Packet) string {
	t.Helper()
	path := filepath.Join(dir, "in.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	wr, err := capture.NewWriter(f, []capture.Interface{
		{Name: "eth0", LinkType: capture.LinkTypeEN10MB, SnapLen: capture.DefaultSnapLen},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkts {
		if err := wr.WritePacket(p.InterfaceIndex, p.Timestamp, p.Data, p.OrigLen); err != nil {
			t.Fatal(err)
		}
	}
	if err := wr.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func Test导入撞上限与读完两种说法分开(t *testing.T) {
	fixCaptureEnv(t)
	dir := t.TempDir()
	pkts := rtspSession(time.Now().Add(-time.Second))
	pkts = append(pkts, arpGarbage(time.Now(), 4)...)
	path := writeCapFile(t, dir, pkts)

	// 读得完：不许出现「只读了前一段」那一句。
	full := callCap(t, captureOpenTool, map[string]any{"file": path, "packets": 100})
	if strings.Contains(full.Note, "只读了前") {
		t.Errorf("整份读完了还说只读了一段：%s", full.Note)
	}
	if full.Values["partialRead"] == true {
		t.Error("partialRead 被误置")
	}
	// 撞上限：必须停下并明写。
	part := callCap(t, captureOpenTool, map[string]any{"file": path, "packets": 2})
	if part.Values["partialRead"] != true {
		t.Errorf("只读了 2 包却没标 partialRead（读到了 %v 包）—— "+
			"半截文件的结论会被当成整份的", part.Values["packets"])
	}
	if !strings.Contains(part.Note, "只读了前 2 包") {
		t.Errorf("note 里没写只读了前几包：%s", part.Note)
	}
	if !strings.Contains(part.Note, "只对这一段成立") {
		t.Errorf("没把「结论的范围」写出来：%s", part.Note)
	}
	if got := part.Values["packets"]; got != 2 {
		t.Errorf("撞上限时读到了 %v 包", got)
	}
}

func Test那不是抓包文件与文件不在两种说法(t *testing.T) {
	fixCaptureEnv(t)
	dir := t.TempDir()
	garbage := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(garbage, []byte("这不是抓包文件，是一句说明"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := callCap(t, captureOpenTool, map[string]any{"file": garbage})
	if v.Code != capFileBad {
		t.Fatalf("应该报 %s，报成 %s", capFileBad, v.Code)
	}
	if strings.Contains(v.Note, "不存在") {
		t.Error("格式不对的这一次却扯上了「不存在」：两种下一步混成一句")
	}

	missing := callCap(t, captureOpenTool, map[string]any{"file": filepath.Join(dir, "nope.pcapng")})
	if missing.Code != capFileBad {
		t.Fatalf("应该报 %s，报成 %s", capFileBad, missing.Code)
	}
	if !strings.Contains(missing.Note, "路径") {
		t.Errorf("文件不在的时候没让人先确认路径：%s", missing.Note)
	}
	// ★ 这两种都是对那份文件的一个说法，不是这个工具坏了 —— 所以都回判定。
}

func Test不许覆盖已有的现场文件(t *testing.T) {
	fixCaptureEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keep.pcapng")
	if err := os.WriteFile(path, []byte("SENTINEL-昨天的现场"), 0o600); err != nil {
		t.Fatal(err)
	}
	useFakeSource(t, newFake(rtspSession(time.Now()), capture.Stats{}))
	_, err := captureStartTool.Invoke(context.Background(), capArgs(t, map[string]any{"file": path}))
	if err == nil {
		t.Fatal("同名的文件被接受了 —— 一次手滑就把昨天的现场盖掉，那不可逆")
	}
	if !strings.Contains(err.Error(), "不覆盖") {
		t.Errorf("报错没说是为了不覆盖：%v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "SENTINEL") {
		t.Error("原来那份文件被改了")
	}
	if n := len(journal.Outstanding()); n != 0 {
		t.Errorf("被拒的这一路在账本上留了 %d 笔", n)
	}
}

func Test相对路径直接拒(t *testing.T) {
	fixCaptureEnv(t)
	opens := useFakeSource(t, newFake(rtspSession(time.Now()), capture.Stats{}))
	_, err := captureStartTool.Invoke(context.Background(), capArgs(t, map[string]any{"file": "cap.pcapng"}))
	if err == nil {
		t.Fatal("相对路径也收了 —— 那种文件会落在后端自己的工作目录里，现场没人找得到")
	}
	if !strings.Contains(err.Error(), "完整路径") {
		t.Errorf("报错没说清：%v", err)
	}
	if *opens != 0 {
		t.Errorf("路径都没定就起了采集口 %d 次", *opens)
	}
}

func Test点名网卡时把名字原样带给采集口(t *testing.T) {
	fixCaptureEnv(t)
	var got capture.Options
	old := captureOpen
	captureOpen = func(o capture.Options) (capture.Source, error) {
		got = o
		return newFake(nil, capture.Stats{}), nil
	}
	t.Cleanup(func() { captureOpen = old })
	callCap(t, captureStartTool, map[string]any{
		"interface": "eth0", "snapLen": 100, "bufferMB": 8,
		"promisc": true, "blockRetireMs": 50,
	})
	if got.Interface != "eth0" || got.SnapLen != 100 || got.BufferSize != 8<<20 ||
		!got.Promisc || got.BlockRetire != 50*time.Millisecond {
		t.Errorf("参数没原样带下去，而是中间换了一套：%+v", got)
	}
	if got.BlockRetire == capture.DefaultBlockRetire {
		t.Error("blockRetireMs 没生效：低流量时那会看着「没流量」")
	}
}

// ── 启动时了结上次的账 ──

func Test启动时了结上次没停的抓包账(t *testing.T) {
	fixCaptureEnv(t)
	id, err := journal.Register("capture", "在本机开一路抓包：所有网卡（含回环）", nil,
		map[string]any{"file": "/nowhere/x.pcapng"})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkApplied(id); err != nil {
		t.Fatal(err)
	}
	restoreCapture(slog.New(slog.DiscardHandler))
	if len(journal.Outstanding()) != 0 {
		t.Errorf("挂了 %d 笔没了结 —— 下次看账本的人会去查一路早就不抓了的包", len(journal.Outstanding()))
	}
	// ★ 别的种类不许被顺手打掉。
	other, err := journal.Register("dhcp-server", "起 DHCP 服务", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = journal.MarkApplied(other)
	restoreCapture(slog.New(slog.DiscardHandler))
	if len(journal.Outstanding()) != 1 {
		t.Error("了结抓包那一笔时把 DHCP 的账一起结了")
	}
}

// ── 登记与界面配码 ──

func Test抓包工具登记了且改系统的都带批准文案(t *testing.T) {
	fixCaptureEnv(t)
	want := map[string]ots.Class{
		"net.capture.start":  ots.ClassMutate,
		"net.capture.stop":   ots.ClassMutate,
		"net.capture.status": ots.ClassRead,
		"net.capture.flows":  ots.ClassRead,
		"net.capture.flow":   ots.ClassRead,
		"net.capture.open":   ots.ClassRead,
	}
	got := map[string]ots.Tool{}
	for _, tl := range localTools {
		if _, ok := want[tl.Name]; ok {
			got[tl.Name] = tl
		}
	}
	for name, class := range want {
		tl, ok := got[name]
		if !ok {
			t.Errorf("%s 没登记进 localTools —— 注册表和界面都问不到它", name)
			continue
		}
		if tl.Class != class {
			t.Errorf("%s 类别应该是 %v，成了 %v", name, class, tl.Class)
		}
		if class == ots.ClassMutate && tl.Describe == nil {
			t.Errorf("%s 会占着采集口、一直往盘上写，却没写批准框里那句话", name)
		}
		if class == ots.ClassRead && tl.Describe != nil {
			t.Errorf("%s 只是看，不该要求批准", name)
		}
	}
	// Describe 那句话必须把「文件里有明文」写进人话里：那是点下按钮之前唯一一次提醒。
	d := captureStartTool.Describe(capArgs(t, map[string]any{"seconds": 30}))
	for _, wantIn := range []string{"明文", "30 秒", "所有网卡"} {
		if !strings.Contains(d, wantIn) {
			t.Errorf("批准框里少了 %q：%s", wantIn, d)
		}
	}
	if !strings.Contains(captureStopTool.Describe(nil), "不删") {
		t.Error("停的这一句没写明文件不删")
	}
}

func Test抓包判定码在界面里都配了人话(t *testing.T) {
	fixCaptureEnv(t)
	b, err := os.ReadFile("../../../ui/src/app.js")
	if err != nil {
		t.Fatalf("读不到界面文件：%v", err)
	}
	ui := string(b)
	// 把代码里声明的每个码都拿来对一遍：码加了、界面没配，人看到的就是一串英文。
	codes := []string{capRunning, capLossy, capIdle, capStopped, capNoPriv, capUnsupported,
		capFilterOn, capNoIface, capFlows, capNoPackets, capNoFlows, capNothing, capNoFlow, capFileBad}
	for _, c := range codes {
		if !strings.Contains(ui, "'"+c+"'") {
			t.Errorf("判定码 %s 在界面里没配人话", c)
		}
	}
}

// ── 反证 ──

// ★ 上面那些「没漏」「只读了前一段」「口径不混」的说法，都要有一条反证压着：
// 把被验的那件事弄坏，测试必须变红。不然绿只是覆盖有洞。
func Test反证明文与两种停法都抓得住(t *testing.T) {
	// ① 扫的是这一层真正发出去的那几个数（flow 层那一条扫的是聚合器交出来的一张表）：
	//   flowRow 是新加的一层形状，哪天有人在这里顺手把 raw 字节贴上去，只有扫这几个数才看得见。
	fixCaptureEnv(t)
	useFakeSource(t, newFake(rtspSession(time.Now()), capture.Stats{Packets: 2}))
	callCap(t, captureStartTool, map[string]any{})
	waitFor(t, "两包进表", func() bool { return currentLedger() != nil && currentLedger().packets == 2 })
	fl := callCap(t, captureFlowsTool, map[string]any{})
	detail := callCap(t, captureFlowTool, map[string]any{"key": capRows(fl)[0]["key"]})
	carried, err := json.Marshal([]any{fl.Values, detail.Values})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(carried), capIdentity) {
		t.Fatal("反证前提不成立：这条流压根没解出来 —— 那「表上一个字的凭据都没漏」是「没东西可漏」的假绿")
	}
	if strings.Contains(string(carried), capSecret) {
		t.Error("这一层把明文带了出去")
	}
	// ② 到量与到时长必须落在两个不同的码上：合成一个，界面就没法反着说。
	if capWhyMaxBytes == capWhyDuration {
		t.Fatal("两种停法共用一个理由码")
	}
	if captureWhyClause(capWhyMaxBytes) == captureWhyClause(capWhyDuration) {
		t.Error("到量停与到时长停的人话是一样的 —— 那「分开说」只是分了两个常量")
	}
	// ③ 丢包口径：说不出与没丢必须分开。
	if captureDropAccount(capture.Stats{}) == captureDropAccount(capture.Stats{Packets: 5}) {
		t.Error("「这一档说不出丢没丢」和「这一档报了没丢」混成了同一个口径")
	}
	// ④ 起不来的四种如果共用一个下一步，上面那条表驱动测试就会红：这里直接压一遍。
	if captureRefused(capNoPriv, "a", "提权重开").Note == captureRefused(capFilterOn, "b", "先问清是谁下的").Note {
		t.Error("没权限与场上有筛选器给的是同一句话")
	}
}
