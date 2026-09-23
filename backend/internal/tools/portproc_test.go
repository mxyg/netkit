package tools

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"net.yuhox.com/netkit/internal/ots"
)

// net.port.process 的测试钉三件事：
//
//	① 「在听」和「本机连出去占着这个口」不许混 —— 后者被说成占用的话，人会去停自己的客户端；
//	② 读不全时**绝不能**说 free —— 这条是整个工具唯一真正伤人的错法；
//	③ 三个平台的输出格式各解各的，且都用**真实命令输出**当样本（自己编的样本只能证明代码自洽）。

// ── 夹具 ──

func ppFix(t *testing.T, uses []portUse, partial bool) {
	t.Helper()
	old := localPorts
	localPorts = func(context.Context) ([]portUse, bool, error) { return uses, partial, nil }
	t.Cleanup(func() { localPorts = old })
}

func ppFail(t *testing.T, err error) {
	t.Helper()
	old := localPorts
	localPorts = func(context.Context) ([]portUse, bool, error) { return nil, false, err }
	t.Cleanup(func() { localPorts = old })
}

func ppRun(t *testing.T, args map[string]any) ots.Verdict {
	t.Helper()
	b, _ := json.Marshal(args)
	v, err := doPortProc(context.Background(), b)
	if err != nil {
		t.Fatalf("跑不动：%v", err)
	}
	return v.(ots.Verdict)
}

func ppListening(t *testing.T, v ots.Verdict) []portUse {
	t.Helper()
	raw, _ := json.Marshal(v.Values["listening"])
	var out []portUse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("listening 反序列化不了：%v", err)
	}
	return out
}

func use(proto, local string, port int, state string, pid int, proc, user string) portUse {
	return portUse{Proto: proto, Local: local, Port: port, State: state, Pid: pid, Process: proc, User: user}
}

// ── 判定 ──

// 有进程在听，就把该停的那个点名出来。
func Test有人在听就报占用并点名(t *testing.T) {
	ppFix(t, []portUse{
		use("tcp", "*", 554, ppStateListen, 412, "mediaserver", "liuman"),
	}, false)
	v := ppRun(t, map[string]any{"port": 554})
	if v.Code != ppOccupied {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppOccupied)
	}
	if !strings.Contains(v.Note, "mediaserver") || !strings.Contains(v.Note, "412") {
		t.Errorf("话里没点名该停谁：%s", v.Note)
	}
}

// ★★ 这条是这一栏存在的理由：本机当客户端连出去时，内核也会占住一个本地端口。
// 把它说成「被占用」，人会去停掉自己正在跑的会话。
func Test本机连出去占的口不算被占用(t *testing.T) {
	ppFix(t, []portUse{
		use("tcp", "192.168.1.10", 554, "established", 900, "vlc", "liuman"),
	}, false)
	v := ppRun(t, map[string]any{"port": 554})
	if v.Code != ppOutbound {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppOutbound)
	}
	if !strings.Contains(v.Note, "不是") || !strings.Contains(v.Note, "掐断") {
		t.Errorf("话里没说清别停它：%s", v.Note)
	}
	if len(ppListening(t, v)) != 0 {
		t.Error("外发连接不该被算进「在听的进程」")
	}
}

// ★★ 第二重要的分界：看不见 != 没人用。
// 报 free 会让人去起服务，然后撞「地址已在使用」，回头再骂工具。
func Test读不全时不许说没人用(t *testing.T) {
	ppFix(t, []portUse{use("tcp", "*", 8080, ppStateListen, 7, "nginx", "")}, true)
	v := ppRun(t, map[string]any{"port": 554})
	if v.Code != ppPartial {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppPartial)
	}
	if !strings.Contains(v.Note, "管理员") {
		t.Errorf("没告诉人下一步怎么办：%s", v.Note)
	}
}

func Test读全了没有才算free(t *testing.T) {
	ppFix(t, []portUse{use("tcp", "*", 8080, ppStateListen, 7, "nginx", "")}, false)
	v := ppRun(t, map[string]any{"port": 554})
	if v.Code != ppFree {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppFree)
	}
}

// 占着口的进程看不到名字（PID 有、名字空）时，结论照样给，不降级成读不到。
func Test半开的监听也算占着(t *testing.T) {
	ppFix(t, []portUse{use("tcp", "*", 554, ppStateSynRecv, 412, "srv", "")}, false)
	if got := ppRun(t, map[string]any{"port": 554}).Code; got != ppOccupied {
		t.Fatalf("syn-recv 被判成 %s：那是监听队列里的口，起服务照样撞", got)
	}
}

// UDP 没有「监听」这个状态位，绑上就算 —— 空状态不等于未知。
func TestUDP没有状态位绑上就算在听(t *testing.T) {
	ppFix(t, []portUse{use("udp", "*", 3722, "", 505, "airplay", "liuman")}, false)
	v := ppRun(t, map[string]any{"port": 3722, "proto": "udp"})
	if v.Code != ppOccupied {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppOccupied)
	}
}

// v4 与 v6 各一条监听是常态（:: 与 0.0.0.0 两个套接字），两条都要留。
func Test同一个口两族各一条时两条都给(t *testing.T) {
	ppFix(t, []portUse{
		use("tcp", "*", 80, ppStateListen, 31, "httpd", ""),
		use("tcp", "*", 80, ppStateListen, 31, "httpd", ""),
		use("tcp", "*", 81, ppStateListen, 31, "httpd", ""),
	}, false)
	v := ppRun(t, map[string]any{"port": 80})
	if got := len(ppListening(t, v)); got != 2 {
		t.Errorf("80 上留了 %d 条，想要 2", got)
	}
}

// 只问 tcp 时不许把 udp 的占用算进来（反过来也一样）—— 否则「554 被谁占了」
// 会被一条无关的 UDP 记录答成占用，人去停一个不相干的进程。
func Test指定协议时另一族被筛掉(t *testing.T) {
	ppFix(t, []portUse{
		use("udp", "*", 554, "", 21, "streamer", ""),
	}, false)
	if got := ppRun(t, map[string]any{"port": 554, "proto": "tcp"}).Code; got != ppFree {
		t.Errorf("只问 tcp 时判定是 %s，想要 %s", got, ppFree)
	}
	if got := ppRun(t, map[string]any{"port": 554, "proto": "udp"}).Code; got != ppOccupied {
		t.Errorf("只问 udp 时判定是 %s，想要 %s", got, ppOccupied)
	}
}

// 不填端口 = 列本机在听的口。★ 外发的那些不算：混进来会有几百条临时端口，
// 把「这台机器提供哪些服务」这个问题冲没了。
func Test不填端口只列监听不列外发(t *testing.T) {
	ppFix(t, []portUse{
		use("tcp", "*", 22, ppStateListen, 60, "sshd", "root"),
		use("tcp", "*", 443, ppStateListen, 61, "nginx", "root"),
		use("tcp", "192.168.1.10", 54111, "established", 62, "chrome", "liuman"),
	}, false)
	v := ppRun(t, map[string]any{})
	if v.Code != ppListed {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppListed)
	}
	if got := len(ppListening(t, v)); got != 2 {
		t.Errorf("列了 %d 条，想要 2", got)
	}
}

func Test一个监听都没有时如实说(t *testing.T) {
	ppFix(t, []portUse{use("tcp", "192.168.1.10", 54111, "established", 62, "chrome", "liuman")}, false)
	if got := ppRun(t, map[string]any{}).Code; got != ppNoListen {
		t.Fatalf("判定是 %s，想要 %s", got, ppNoListen)
	}
}

// ★ 判成 outbound-only 时必须把那几条连接给出去：界面要指着行说「就是这几条
// 本机连出去的」，只给一个词等于让人自己去猜哪条。
func Test外发连接单独给一栏(t *testing.T) {
	ppFix(t, []portUse{
		use("tcp", "192.168.1.10", 54111, "established", 62, "chrome", "liuman"),
		use("tcp", "192.168.1.10", 54111, "time-wait", 0, "", ""),
	}, false)
	v := ppRun(t, map[string]any{"port": 54111})
	if v.Code != ppOutbound {
		t.Fatalf("判定是 %s，想要 %s", v.Code, ppOutbound)
	}
	raw, _ := json.Marshal(v.Values["connections"])
	var conns []portUse
	if err := json.Unmarshal(raw, &conns); err != nil {
		t.Fatalf("connections 反序列化不了：%v", err)
	}
	if len(conns) != 2 {
		t.Errorf("connections 留了 %d 条，想要 2", len(conns))
	}
	for _, c := range conns {
		if c.Port != 54111 {
			t.Errorf("串进别的端口了：%+v", c)
		}
	}
}

// ★ 不填端口时本机轻松上百条（实测 227）。这份结果整份发给 AI，
// 行数必须设顶 —— 但截了多少要如实说，不能假装这就是全部。
func Test列全部时行数设顶并说清截断(t *testing.T) {
	var uses []portUse
	for i := 0; i < maxPPRows+30; i++ {
		uses = append(uses, use("tcp", "*", 1024+i, ppStateListen, 100+i, "srv", "root"))
	}
	ppFix(t, uses, false)
	v := ppRun(t, map[string]any{})
	if got := len(ppListening(t, v)); got != maxPPRows {
		t.Errorf("列了 %d 条，想要上限 %d", got, maxPPRows)
	}
	if v.Values["listenerCount"] != maxPPRows+30 {
		t.Errorf("listenerCount 是 %v，想要 %d（总数，不是列出的条数）", v.Values["listenerCount"], maxPPRows+30)
	}
	if v.Values["truncated"] != true {
		t.Error("截断了却没标 truncated —— 调用方会以为本机只有这些口")
	}
	if !strings.Contains(v.Note, strconv.Itoa(maxPPRows)) || !strings.Contains(v.Note, "只列出前") {
		t.Errorf("话里没说清只列了一部分：%s", v.Note)
	}
}

// 没截断时不许留一个 truncated=true 让人白疑心。
func Test没到上限就不标截断(t *testing.T) {
	ppFix(t, []portUse{use("tcp", "*", 22, ppStateListen, 60, "sshd", "root")}, false)
	v := ppRun(t, map[string]any{})
	if v.Values["truncated"] != false {
		t.Errorf("truncated 是 %v，想要 false", v.Values["truncated"])
	}
	if !strings.Contains(v.Note, "1 个端口") {
		t.Errorf("话里的条数不对：%s", v.Note)
	}
}

// 平台没有可靠读法时说的是「读不到」，不是「没人用」。
func Test读不到时说的是读不到(t *testing.T) {
	ppFail(t, errPortSource)
	v, err := doPortProc(context.Background(), json.RawMessage(`{"port":554}`))
	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	got := v.(ots.Verdict)
	if got.Code != ppUnsupported {
		t.Fatalf("判定是 %s，想要 %s", got.Code, ppUnsupported)
	}
	if !strings.Contains(got.Note, "不等于") {
		t.Errorf("没写清「读不到」和「没人用」的差别：%s", got.Note)
	}
}

// ── 参数 ──

func Test参数越界当场拒(t *testing.T) {
	ppFix(t, []portUse{use("tcp", "*", 22, ppStateListen, 60, "sshd", "root")}, false)
	for _, args := range []map[string]any{
		{"port": -1}, {"port": 70000}, {"proto": "sctp"},
	} {
		b, _ := json.Marshal(args)
		if _, err := doPortProc(context.Background(), b); err == nil {
			t.Errorf("%v 竟然收了", args)
		}
	}
	// 给了 0 当没填（分不出「没给」和「给了 0」，按列全部走比报错靠近人想问的）
	if got := ppRun(t, map[string]any{"port": 0}).Code; got != ppListed {
		t.Errorf("port 0 的判定是 %s，想要 %s", got, ppListed)
	}
	if _, err := doPortProc(context.Background(), json.RawMessage(`{`)); err == nil {
		t.Error("坏 JSON 竟然收了")
	}
	if _, err := doPortProc(context.Background(), json.RawMessage(`{`)); !strings.Contains(err.Error(), "JSON") {
		t.Errorf("坏 JSON 的话不对：%v", err)
	}
}

// ── macOS：lsof -F ──

// 真机 `lsof -nP -i -FpcuLtTPn` 的片段（字段顺序照原样：f → t → P → n → T；
// 地址里的 MAC 派生部分换成了示例值，格式照抄）。
const lsofSample = `p505
crapportd
u501
Lliuman
f9
tIPv4
PTCP
n*:56633
TST=LISTEN
TQR=0
TQS=0
f13
tIPv6
PTCP
n*:56633
TST=LISTEN
TQR=0
TQS=0
f17
tIPv6
PTCP
n[fe80::1]:1024->[fe80::2]:59607
TST=ESTABLISHED
f18
tIPv6
PUDP
n*:3722
p556
cidentityservicesd
u501
Lliuman
f18
tIPv4
PUDP
n*:*
p888
cGoogle Chrome
u501
Lliuman
f45
tIPv4
PTCP
n127.0.0.1:9222
TST=LISTEN
`

func TestLsof按字段解不按空格对齐(t *testing.T) {
	uses := parseLsofFields(lsofSample)
	if len(uses) != 6 {
		t.Fatalf("解出 %d 条：%+v", len(uses), uses)
	}
	// ★ 进程名本身带空格 —— 表格式切列就会串位，这里必须还是完整的一个名字
	if uses[5].Process != "Google Chrome" || uses[5].Pid != 888 || uses[5].Port != 9222 {
		t.Errorf("带空格的名字串位了：%+v", uses[5])
	}
	if uses[0].State != ppStateListen || uses[0].Port != 56633 || uses[0].User != "liuman" {
		t.Errorf("第一条不对：%+v", uses[0])
	}
	if uses[2].State != "established" {
		t.Errorf("ESTABLISHED 没翻出来：%+v", uses[2])
	}
	if uses[2].Foreign == "" {
		t.Error("已建立连接没带对端 —— 分不清是谁连谁")
	}
	if uses[3].Proto != "udp" || uses[3].State != "" {
		t.Errorf("UDP 那条不该有状态：%+v", uses[3])
	}
}

// ★★ 本机实测的坑：rapportd 在 56633 上 v4、v6 各听一遍，两条记录除了地址族
//
//	完全一样。少了 t 那一列，界面就会显示「tcp/rapportd:505、tcp/rapportd:505」，
//	人以为有两个进程占着同一个口。
func Test两族各听一遍时分得清是几条(t *testing.T) {
	ppFix(t, parseLsofFields(lsofSample), false)
	v := ppRun(t, map[string]any{"port": 56633})
	got := ppListening(t, v)
	if len(got) != 2 {
		t.Fatalf("56633 上留了 %d 条：%+v", len(got), got)
	}
	fams := map[string]bool{got[0].Family: true, got[1].Family: true}
	if !fams["ipv4"] || !fams["ipv6"] {
		t.Errorf("两族没分开：%+v", got)
	}
	if !strings.Contains(v.Note, "tcp4/") || !strings.Contains(v.Note, "tcp6/") {
		t.Errorf("话里把两族混成一个词了：%s", v.Note)
	}
}

// `n*:*` 是「这个进程开了个还没绑口的套接字」，不是「所有端口都被占了」。
// 混进按端口的筛选，每个口都会被一条无关记录报成占用。
func Test没有端口的套接字不算占任何口(t *testing.T) {
	uses := parseLsofFields(lsofSample)
	if uses[4].Port != 0 {
		t.Errorf("identityservicesd 那条被解成端口 %d", uses[4].Port)
	}
	ppFix(t, uses, false)
	// 3722 上只有 rapportd 那条真的绑了口的记录，*:* 那条不该被算进来
	v := ppRun(t, map[string]any{"port": 3722, "proto": "udp"})
	got := ppListening(t, v)
	if len(got) != 1 || got[0].Pid != 505 || got[0].Port != 3722 {
		t.Errorf("3722 的监听是 %+v，想要只有 rapportd 那一条", got)
	}
	// ★ 列全部时更要防这一手：UDP 没有状态位，没绑口的套接字要是留在列表里，
	// 界面就显示成「某个进程在听 0 号端口」——本机实测十几条，真在听的反而被淹没。
	all := ppRun(t, map[string]any{})
	for _, u := range ppListening(t, all) {
		if u.Port == 0 {
			t.Errorf("没绑口的套接字混进了监听列表：%+v", u)
		}
	}
	if all.Values["listenerCount"] != 4 {
		t.Errorf("列出 %v 个监听，想要 4（两条 56633 + 3722 + 9222）", all.Values["listenerCount"])
	}
}

// ── Linux：/proc ──

const procTCPSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 30229 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:E821 01 00000000:00000000 00:00000000 00000000  1000        0 41875 2 0000000000000000 20 4 30 10 -1
   2: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 10 0 0 10 0
`

const procTCP6Sample = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27100 1 0000000000000000 100 0 0 10 0
`

func TestProc表头不当记录(t *testing.T) {
	got := parseProcNetSOCK(procTCPSample, "tcp")
	if len(got) != 3 {
		t.Fatalf("解出 %d 条：%+v", len(got), got)
	}
	if got[0].State != ppStateListen || got[0].Port != 8080 {
		t.Errorf("第一条不对：%+v", got[0])
	}
	if got[0].Local != "*" {
		t.Errorf("00000000 要解成所有地址，得到 %s", got[0].Local)
	}
	if got[0].Family != "ipv4" {
		t.Errorf("v4 那张表解出来的地址族是 %q —— 少了这一列，两族的两条记录看起来像重复输出", got[0].Family)
	}
	// ★ 小端：0100007F 是 127.0.0.1，不反字节就成 1.0.0.127
	if got[1].Local != "127.0.0.1" {
		t.Errorf("v4 字节序反了：%s", got[1].Local)
	}
	if got[1].State != "established" {
		t.Errorf("状态码 01 要解成 established，得到 %s", got[1].State)
	}
}

func TestProc六与四两张表都要读(t *testing.T) {
	v4 := parseProcNetSOCK(procTCPSample, "tcp")
	v6 := parseProcNetSOCK(procTCP6Sample, "tcp")
	if len(v6) != 1 || v6[0].Port != 443 || v6[0].Local != "*" || v6[0].State != ppStateListen {
		t.Fatalf("tcp6 不对：%+v", v6)
	}
	if v6[0].Family != "ipv6" {
		t.Errorf("tcp6 那条的地址族是 %q", v6[0].Family)
	}
	// 只听在 :: 上的服务（最常见的部署方式）：只读 v4 那张表就会报「没人占用」
	owners := map[string]procOwner{
		"30229": {Pid: 60, Process: "srv", User: "root"},
		"41875": {Pid: 900, Process: "curl", User: "liuman"},
		"0":     {Pid: 1, Process: "systemd", User: "root"},
		"27100": {Pid: 61, Process: "nginx", User: "root"},
	}
	uses, partial := socketsToPortUses(append(v4, v6...), owners)
	if partial {
		t.Fatal("四张表都有主人，却报读不全")
	}
	ppFix(t, uses, false)
	if got := ppRun(t, map[string]any{"port": 443}).Code; got != ppOccupied {
		t.Errorf("只听在 v6 上的口被判成 %s", got)
	}
}

// ★★ 非管理员看不到别人进程的 fd 目录：有一堆 socket 认不出主人，
//
//	这时候必须 partial，不能报 free。
func Test认不出主人的socket报读不全(t *testing.T) {
	socks := parseProcNetSOCK(procTCPSample, "tcp")
	owners := map[string]procOwner{
		"41875": {Pid: 900, Process: "curl", User: "liuman"},
	}
	uses, partial := socketsToPortUses(socks, owners)
	if !partial {
		t.Fatal("有两条约 1/3 的 socket 没主人，却没报读不全")
	}
	var named int
	for _, u := range uses {
		if u.Process != "" {
			named++
		}
	}
	if named != 1 {
		t.Errorf("认出主人 %d 条，想要 1", named)
	}
}

// ★★ 这条是 Linux 上最容易踩的：/proc/net/udp 里一个绑好在等包的 socket
//
//	状态列写 07（close）。照原样交给判定层，跑着的 DNS / NTP / 流媒体服务
//	会被说成「本机连出去占的口，别去停它」—— 和事实正好相反。
const procUDPSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 51001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0044 0200007F:D344 01 00000000:00000000 00:00000000 00000000     0        0 51002 1 0000000000000000 100 0 0 10 0
`

func TestLinux的UDP绑上就算在听(t *testing.T) {
	socks := parseProcNetSOCK(procUDPSample, "udp")
	if len(socks) != 2 {
		t.Fatalf("解出 %d 条：%+v", len(socks), socks)
	}
	if socks[0].State != "" {
		t.Errorf("07 那条留了状态 %q：UDP 的 close 不是「没在听」", socks[0].State)
	}
	if socks[1].State != "established" {
		t.Errorf("01 那条应当留 established（真被 connect 过），得到 %q", socks[1].State)
	}
	owners := map[string]procOwner{
		"51001": {Pid: 300, Process: "dnsmasq", User: "nobody"},
		"51002": {Pid: 300, Process: "dnsmasq", User: "nobody"},
	}
	uses, partial := socketsToPortUses(socks, owners)
	if partial {
		t.Fatal("都有主人，却报读不全")
	}
	ppFix(t, uses, false)
	v := ppRun(t, map[string]any{"port": 68, "proto": "udp"})
	if v.Code != ppOccupied {
		t.Fatalf("绑在 68 上的 UDP 服务被判成 %s", v.Code)
	}
}

// ★★ inode 0 是内核自己占着的套接字（TIME_WAIT / CLOSE_WAIT 还没交还给任何进程），
//
//	不是「看不到主人」。算进 partial 的话，这台机器上永远查不出 free ——
//	而 free 恰恰是「这个口能腾出来」的那个答案。
func Test内核占的TIME_WAIT不算读不全(t *testing.T) {
	socks := parseProcNetSOCK(procTCPSample, "tcp")
	owners := map[string]procOwner{}
	var tw int
	for _, s := range socks {
		if s.Inode == "0" {
			tw++
			continue // 没有主人
		}
		owners[s.Inode] = procOwner{Pid: 7, Process: "srv", User: "root"}
	}
	if tw == 0 {
		t.Fatal("样本里没有 inode 0 的行，这条测试就没意义了")
	}
	uses, partial := socketsToPortUses(socks, owners)
	if partial {
		t.Errorf("只有内核占的 %d 条没主人，却报了读不全", tw)
	}
	for _, u := range uses {
		if u.State == "close" && u.Process != "" {
			t.Errorf("内核那条被安了个进程名：%+v", u)
		}
	}
	// 症状检查：查一个没人用的口，这时候应当是 free，不是 partial
	ppFix(t, uses, false)
	if got := ppRun(t, map[string]any{"port": 9999}).Code; got != ppFree {
		t.Errorf("判定是 %s，想要 %s", got, ppFree)
	}
}

// inode 认得出主人时才是干净的读数。
func Test全部认得出主人时算读全了(t *testing.T) {
	socks := parseProcNetSOCK(procTCPSample, "tcp")
	owners := map[string]procOwner{}
	for _, s := range socks {
		owners[s.Inode] = procOwner{Pid: 1, Process: "x", User: "root"}
	}
	if _, partial := socketsToPortUses(socks, owners); partial {
		t.Error("全都认得出来，却报读不全")
	}
}

// ── Windows ──

// 中文 Windows 的 `netstat -ano`（表头是中文，UDP 行没有状态列）。
const netstatWindowsSample = `活动连接

  协议  本地地址          外部地址        状态           PID

  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    [::]:135               [::]:0                 LISTENING       1234
  TCP    192.168.1.10:54111     203.0.113.9:554        ESTABLISHED     4321
  TCP    127.0.0.1:9222         127.0.0.1:54321        TIME_WAIT       0
  UDP    0.0.0.0:500            *:*                                    5678
  UDP    [::]:500               *:*                                    5678
`

func TestWindows的LISTENING要翻成同一个码(t *testing.T) {
	uses := parseNetstatWindows(netstatWindowsSample)
	if len(uses) != 6 {
		t.Fatalf("解出 %d 条：%+v", len(uses), uses)
	}
	for _, u := range uses[:2] {
		// ★ 不规整的话这里得到 "listening"，判定层认的是 "listen" ——
		// 症状是把在听的服务报成 free，人去起服务才撞口。
		if u.State != ppStateListen {
			t.Errorf("135 的状态没翻出来：%+v", u)
		}
		if !u.listening() {
			t.Errorf("%+v 没被当成监听", u)
		}
	}
	// netstat 用中括号表示 v6，且这两行的本地地址最后都收成 `*` —— 只有一开始的形状分得出族
	if uses[0].Family != "ipv4" || uses[1].Family != "ipv6" {
		t.Errorf("135 的两行没分出地址族：%+v / %+v", uses[0], uses[1])
	}
	ppFix(t, uses, false)
	v := ppRun(t, map[string]any{"port": 135})
	if v.Code != ppOccupied {
		t.Fatalf("Windows 上 135 被判成 %s", v.Code)
	}
	if !strings.Contains(v.Note, "tcp4/") || !strings.Contains(v.Note, "tcp6/") {
		t.Errorf("话里把两族混成一个词了：%s", v.Note)
	}
}

// UDP 行没有状态列，按下标取列会把 *:* 当成 PID。
func TestWindows的UDP行少一列不错位(t *testing.T) {
	uses := parseNetstatWindows(netstatWindowsSample)
	udp := uses[4]
	if udp.Proto != "udp" || udp.Port != 500 || udp.Pid != 5678 {
		t.Errorf("UDP 行列错位了：%+v", udp)
	}
	if udp.State != "" {
		t.Errorf("UDP 不该有状态：%+v", udp)
	}
	if uses[2].State != "established" || uses[2].Foreign != "203.0.113.9:554" {
		t.Errorf("已建立那条不对：%+v", uses[2])
	}
}

func TestTasklist合并进程名(t *testing.T) {
	names := parseTasklistCSV(`"chrome.exe","4321","Console","1","50,000 K"
"nginx.exe","1234","Services","0","1,234 K"
`)
	uses := attachNames(parseNetstatWindows(netstatWindowsSample), names)
	if uses[0].Process != "nginx.exe" {
		t.Errorf("PID 1234 的名字没并进来：%+v", uses[0])
	}
	if uses[2].Process != "chrome.exe" {
		t.Errorf("PID 4321 的名字没并进来：%+v", uses[2])
	}
	// 认不出 PID 的那条（TIME_WAIT 常归给 0）留空，不编一个名字
	if uses[3].Process != "" {
		t.Errorf("没有主人的记录被安了名字：%+v", uses[3])
	}
}

// 表头 / 说明行 / 「活动连接」这些都不该被当成记录。
func TestWindows的表头不当记录(t *testing.T) {
	for _, junk := range []string{"活动连接", "  协议  本地地址          外部地址        状态           PID",
		"Active Connections", ""} {
		if got := parseNetstatWindows(junk); len(got) != 0 {
			t.Errorf("%q 被解成了 %d 条", junk, len(got))
		}
	}
}

// ── 凭据面 ──

// ★ 结果里只有进程名和 PID，**没有命令行**：命令行常带口令、token、连接串，
//
//	而这份结果会原样发给 AI、以后还要进诊断包。这条钉住字段集，
//	以后谁想加 cmdline 就得先改掉这个测试（并想清楚泄漏面）。
func Test结果里只有进程名没有命令行(t *testing.T) {
	b, err := json.Marshal(portUse{
		Proto: "tcp", Local: "*", Port: 554, State: ppStateListen,
		Pid: 1, Process: "srv", User: "root",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"proto": true, "family": true, "local": true, "port": true,
		"state": true, "pid": true, "process": true, "user": true}
	for k := range m {
		if !want[k] {
			t.Errorf("多出一个字段 %q —— 命令行一类的内容不许进结果", k)
		}
	}
}

// ── 声明 ──

func Test端口占用工具声明(t *testing.T) {
	r := ots.NewRegistry(true)
	r.MustRegister(portProcTool)
	got, ok := r.Lookup("net.port.process")
	if !ok {
		t.Fatal("net.port.process 没注册进注册表")
	}
	if got.Class != ots.ClassRead {
		t.Errorf("纯读本机内核表，不该是 %s", got.Class)
	}
	if !strings.Contains(portProcTool.Summary, "命令行") {
		t.Error("说明里没写明「不给命令行」—— 调用方（AI）得知道这条边界")
	}
	var schema map[string]any
	if err := json.Unmarshal(portProcTool.Schema, &schema); err != nil {
		t.Fatalf("schema 不是合法 JSON：%v", err)
	}
	if !strings.Contains(string(portProcTool.Schema), "outbound") {
		t.Error("schema 里没提外发连接那种情形，AI 会把它当占用")
	}
}
