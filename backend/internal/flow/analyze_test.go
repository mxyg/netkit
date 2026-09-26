package flow

// 这一份钉的是「别人给的一份文件，读进来落成一张什么样的表」。
//
// 内部造包永远是自己喂自己那一种形状：口表齐、时刻全、包没剪过。
// 现场拿到的那份不是 —— 同事用 tcpdump 抓的、摄像头导出的一段、
// Wireshark 转出来的、pktmon 那份连口名都没有。
// ★ 这些文件是**真的**从那些工具手里出来的（internal/capture/testdata/），
// 拿它们过一遍，口径错在哪一格才会暴露：
// 自己造的包只会按自己以为的格式通过。

import (
	"io"
	"os"
	"strings"
	"testing"
)

const testdata = "../capture/testdata/"

// openTable 读一份真文件并停在「读完了」那一步。
// ★ 不在这里断言：读不动本身就是这条用例要说的话。
func openTable(t *testing.T, name string) *Table {
	t.Helper()
	f, err := os.Open(testdata + name)
	if err != nil {
		t.Fatalf("开 %s：%v（这一份是随仓库带的真文件，开不动就是测试自己坏了）", name, err)
	}
	defer f.Close()
	tbl := NewTable(Options{})
	if _, err := tbl.ReadFile(f); err != nil {
		t.Fatalf("读 %s：%v", name, err)
	}
	return tbl
}

func Test导入dumpcap那份回环包(t *testing.T) {
	tbl := openTable(t, "dumpcap-lo.pcapng")
	l := tbl.Ledger()
	if l.Total != 30 || l.Decoded != 30 {
		t.Errorf("包数账 = %s，要 30 包全部拆到 IP", l.String())
	}
	if !l.Reconciles() {
		t.Errorf("账对不平：%s（对不平的表连「这里没流量」都不该说）", l.String())
	}
	fls := tbl.Flows()
	if len(fls) != 1 {
		t.Fatalf("表上 %d 条流，要 1 条：%s", len(fls), keysOf(fls))
	}
	fl := fls[0]
	// ★ 这一格是这一档最贵的教训：回环上 ping 的正文头八字节是发包时刻，
	// 0x84 开头 + 一个像载荷类型的字节，正好凑得过 RTP 那把形状刀。
	// 一旦让应用层去嗅 ICMP 的正文，表上就会写着「127.0.0.1 上有一条 RTP 媒体流」，
	// 后面的丢包判定全跟着这句假话算。
	if fl.App != "" {
		t.Errorf("ICMP 的正文被定了应用层协议：%q（依据 %q）—— 没有端口的那一条流不该有这一格", fl.App, fl.AppBy)
	}
	if len(fl.Messages) != 0 {
		t.Errorf("解出了 %d 条报文：%s", len(fl.Messages), msgsOf(fl))
	}
	if fl.Proto != "icmp" {
		t.Errorf("流的协议 = %q", fl.Proto)
	}
	// 每一问都有一答：这两格分开数，才谈得上「谁没答」。
	if fl.ICMP == nil || fl.ICMP.Req[0] == 0 || fl.ICMP.Reply[1] == 0 {
		t.Fatalf("回环上的一问一答没分开： %+v（★按地址分不出方向时得按报文角色分）", fl.ICMP)
	}
	if _, ok := finding(fl, "icmp-no-reply"); ok {
		t.Errorf("这份文件里每一问都答了，却说着没人答：%s", codesOf(fl))
	}
	if fl.Iface != "lo" {
		t.Errorf("口名 = %q，要 lo（IDB 里写着，不该丢）", fl.Iface)
	}
	if fl.First.IsZero() || fl.Last.Before(fl.First) {
		t.Errorf("时间线 = %v → %v", fl.First, fl.Last)
	}
	for _, s := range tbl.Report() {
		// 一份干净的文件不该在口径栏留下任何一句话。
		t.Errorf("口径栏不该有话：%s", s)
	}
}

func Test同一份包两种文件格式给出同一张表(t *testing.T) {
	// editcap 与 tcpdump 读的是同一次抓包（同一批包、同一个刻度差别在文件里）。
	// ★ 两条路给出两个数，现场就不知道该信哪一个 —— 而这两条路都得支持。
	a := openTable(t, "editcap-lo.pcapng")
	b := openTable(t, "tcpdump-lo.pcap")
	la, lb := a.Ledger(), b.Ledger()
	if la.Total != lb.Total || la.Decoded != lb.Decoded {
		t.Fatalf("包数不一样：pcapng %s / pcap %s", la.String(), lb.String())
	}
	fa, fb := a.Flows(), b.Flows()
	if len(fa) != 1 || len(fb) != 1 {
		t.Fatalf("流数 %d / %d", len(fa), len(fb))
	}
	if fa[0].Key != fb[0].Key {
		t.Errorf("同一次抓包在两种格式里成了两条流：%s / %s", fa[0].Key, fb[0].Key)
	}
	if fa[0].Packets != fb[0].Packets || fa[0].Bytes != fb[0].Bytes {
		t.Errorf("包数或字节对不上：%d/%d vs %d/%d", fa[0].Packets, fa[0].Bytes, fb[0].Packets, fb[0].Bytes)
	}
	if !fa[0].First.Equal(fb[0].First) {
		t.Errorf("首包时刻不一样：%v vs %v（★文件里那个刻度没按 IDB/文件头折算的话就是这么个错法）", fa[0].First, fb[0].First)
	}
	// 老 pcap 的文件头里根本没有口名 —— 这一格不许编一个像真的出来。
	if !strings.Contains(fb[0].Iface, "老 pcap") {
		t.Errorf("pcap 那份的口名 = %q，要如实说文件头里没有", fb[0].Iface)
	}
}

func Test导入pktmon那份没有口描述的文件(t *testing.T) {
	tbl := openTable(t, "pktmon-nics.pcapng")
	fls := tbl.Flows()
	if len(fls) != 2 {
		t.Fatalf("表上 %d 条流：%s", len(fls), keysOf(fls))
	}
	for _, fl := range fls {
		if fl.ICMP == nil || fl.ICMP.Req[0]+fl.ICMP.Req[1] == 0 {
			t.Errorf("%s 没记下回声请求：这一条上的 ICMP 账没算起来", fl.Key)
		}
		if fl.ICMP.Reply[0]+fl.ICMP.Reply[1] == 0 {
			t.Errorf("%s 一个回包都没记着 —— 现场是 ping 通着抓的，那就是方向分错了", fl.Key)
		}
	}
	// 这一份的 IDB 里口名与描述都是空的（pktmon 转出来的那一种）。
	// 不许为了界面好看编一个名字：拿着「以太网 0」去设备上找口是找不到的。
	for _, s := range tbl.Report() {
		if strings.Contains(s, "口表里没有") {
			t.Errorf("口表只有一个口、包也全挂在这个口上，口径栏却在报缺口：%s", s)
		}
	}
	if l := tbl.Ledger(); !l.Reconciles() {
		t.Errorf("账对不平：%s", l.String())
	}
}

func Test空文件出一张空表但不说假话(t *testing.T) {
	tbl := openTable(t, "pktmon-empty.pcapng")
	if n := len(tbl.Flows()); n != 0 {
		t.Fatalf("空文件读出 %d 条流", n)
	}
	if l := tbl.Ledger(); l.Total != 0 || !l.Reconciles() {
		t.Errorf("空账 = %s", l.String())
	}
	// ★ 「零包」与「读完了但一个包都没拆出来」是两句话：前者不报错，后者必须在口径栏里。
	for _, s := range tbl.Report() {
		if strings.Contains(s, "拆不开") || strings.Contains(s, "对不上") {
			t.Errorf("空文件报出了毛病：%s", s)
		}
	}
}

func Test文件读不动时要停下并说停在哪(t *testing.T) {
	// 只放前面 60 字节过去：块写到一半就断了，这是现场最常见的坏法（抓的时候掉了电）。
	// ★ 用 LimitReader 而不是自己截 []byte：真实工具读文件是流式的，
	// 「在块中间遇到 EOF」与「一开始就给了半份字节」在 Reader 里走的是两条路。
	f, err := os.Open(testdata + "dumpcap-lo.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tbl := NewTable(Options{})
	n, err := tbl.ReadFile(io.LimitReader(f, 60))
	if err == nil {
		t.Fatalf("只给前 60 字节却「读完了」：读了 %d 包", n)
	}
	if n != 0 {
		t.Errorf("读了 %d 包 —— 这一段连一个完整块都没有", n)
	}
	// 坏在哪儿要能说出来。★「不是字节序魔数」在这一刻是假话：
	// 头都读完了、是后面的块没读到 —— 拿着这句去换字节序重试，永远修不好一个断掉的文件。
	if !strings.Contains(err.Error(), "短") && !strings.Contains(err.Error(), "断") {
		t.Errorf("错误里没说清是「文件断了」：%v", err)
	}
}

func Test不是抓包文件的文件要一口回绝(t *testing.T) {
	tbl := NewTable(Options{})
	_, err := tbl.ReadFile(strings.NewReader("这不是抓包文件，是一份文本日志\n"))
	if err == nil {
		t.Fatal("一份文本被当成抓包文件读完了 —— 那会把日志的字节当成包拆，什么结论都出得来")
	}
}
