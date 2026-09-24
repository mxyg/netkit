package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/state"
)

// 这个包里的假凭据：断言它们**不在**包内与结果内。
const (
	bundleSecretCommunity = "Bundle-Community-SuperSecret"
	bundleSecretPassword  = "Bundle-Proxy-P@ssword-9"
)

var bundleWhen = time.Date(2026, 9, 25, 11, 0, 0, 0, time.UTC)

// bundleFixture 一台「什么都读得到」的机器。★ 每个源都是一个函数：
// 判定层（哪几项算没读出来、结果该给 bundle-written 还是 bundle-partial）
// 不该只能靠把一台真机器搞坏来验。
func bundleFixture(t *testing.T) (bundleSources, string) {
	t.Helper()
	dir := t.TempDir()
	src := bundleSources{
		nics: func() ([]netif.NIC, error) {
			return []netif.NIC{
				{
					Name: "en0", Index: 5, MAC: "a4:5e:60:11:22:33", MTU: 1500,
					Up: true, Running: true, Kind: "ethernet", KindSrc: "os",
					Verdict: netif.Verdict{Code: "dual-ok", Networks: []string{"10.0.12.0/22"}},
					Addrs: []netaddr.Addr{
						{IP: netip.MustParseAddr("10.0.12.34"), Prefix: 22},
						{IP: netip.MustParseAddr("fe80::1234"), Prefix: 64, Zone: "en0"},
						{IP: netip.MustParseAddr("2408:8207:1234::ab"), Prefix: 64, Zone: "en0"},
						{IP: netip.MustParseAddr("2408:8207:1234::cd"), Prefix: 64, Zone: "en0", Temporary: true},
						{IP: netip.MustParseAddr("fd00::9"), Prefix: 64, Zone: "en0"},
					},
				},
				{Name: "en1", Index: 6, MTU: 1500, Up: true, Running: false,
					Kind: "wifi", KindSrc: "name",
					Verdict: netif.Verdict{Code: "link-up-no-address"}},
				{Name: "lo0", Index: 1, Loop: true, Up: true, Running: true, MTU: 16384,
					Verdict: netif.Verdict{Code: "loopback"},
					Addrs:   []netaddr.Addr{{IP: netip.MustParseAddr("127.0.0.1"), Prefix: 8}}},
			}, nil
		},
		routes: func() ([]netif.Route, error) {
			return []netif.Route{
				{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "10.0.12.1", Iface: "en0", Metric: 100},
				{Family: "ipv4", Destination: "10.0.12.0/22", Iface: "en0", Metric: 0, Direct: true, Src: "10.0.12.34"},
				{Family: "ipv6", Destination: "::/0", Gateway: "fe80::1", Iface: "en0", Metric: 100},
			}, nil
		},
		defRoute: func() ([]netif.DefaultRoute, error) {
			return []netif.DefaultRoute{
				{Family: "ipv4", Gateway: "10.0.12.1", Iface: "en0"},
				{Family: "ipv6", Gateway: "fe80::1", Iface: "en0"},
			}, nil
		},
		neigh4: func(context.Context) ([]neighbor, error) {
			return []neighbor{
				{Addr: "10.0.12.1", MAC: "00:1b:21:aa:bb:cc", Iface: "en0", Family: "ipv4", State: "REACHABLE"},
				{Addr: "10.0.12.77", MAC: "aa:bb:cc:dd:ee:ff", Iface: "en0", Family: "ipv4", State: "STALE"},
			}, nil
		},
		neigh6: func(context.Context) ([]neighbor, error) {
			return []neighbor{{Addr: "fe80::1", MAC: "00:1b:21:aa:bb:cc", Iface: "en0", Family: "ipv6"}}, nil
		},
		dns: func() ([]netif.DNSServer, error) {
			return []netif.DNSServer{{Addr: "223.5.5.5"}, {Addr: "10.0.0.53", Iface: "utun3"}}, nil
		},
		hosts: func() (string, string, error) {
			return "/etc/hosts", "##\n# 本机指向\n127.0.0.1\tlocalhost\n10.0.0.9\tbox.local # 现场临时指的\n", nil
		},
		proxy: func(context.Context) (string, map[string]any) {
			return "http=10.0.0.5:3128", map[string]any{
				"设置项":        []string{"http_proxy"},
				"http_proxy": "http://10.0.0.5:3128",
				"代理口令":       bundleSecretPassword, // 假装有：这一条必须被抹掉（systemProxy 自己不会给，但源可以被换）
			}
		},
		ports: func(context.Context) ([]portUse, bool, error) {
			return []portUse{
				{Proto: "tcp", Family: "ipv4", Local: "0.0.0.0", Port: 443, State: "LISTEN", Pid: 4242, Process: "nginx", User: "root"},
				{Proto: "tcp", Family: "ipv6", Local: "::", Port: 443, State: "LISTEN", Pid: 4242, Process: "nginx"},
				{Proto: "tcp", Family: "ipv4", Local: "10.0.12.34", Port: 52344, Foreign: "10.0.0.53:53", State: "ESTABLISHED"},
			}, true, nil
		},
		journal: func() []state.Entry {
			before, _ := json.Marshal(map[string]any{"community": bundleSecretCommunity})
			return []state.Entry{
				{Kind: "static-address", What: "把 en0 从 DHCP 改成 10.0.12.34/22",
					Before: before, Status: state.StatusApplied, At: bundleWhen.Add(-time.Hour)},
				{Kind: "dhcp-server", What: "在 en0 上开了 DHCP 服务",
					Status: state.StatusReverted, Note: "已还原", At: bundleWhen.Add(-time.Minute)},
			}
		},
		hostname: func() (string, error) { return "eng-laptop-07", nil },
		outDir:   func() (string, error) { return dir, nil },
		now:      func() time.Time { return bundleWhen },
		checkup: func(context.Context, checkupArgs, int, time.Duration, checkProbes) ([]checkItem, map[string]any, error) {
			return []checkItem{
				{Step: stepIface, Code: "iface-ok", Severity: sevOK,
					Facts: map[string]any{"inUse": "en0", "mtu": 1500}},
				{Step: stepGateway, Code: "gateway-loss", Severity: sevWarn,
					Facts: map[string]any{"lossPct": 16.7, "sent": 6, "说明": "★ 也可能是它自己拦了 ICMP"}},
				{Step: stepDNS, Code: "dns-ok", Severity: sevOK},
			}, map[string]any{"v4": map[string]any{"egress": "ok"}}, nil
		},
		probes: func() checkProbes { return checkProbes{} },
	}
	return src, dir
}

func runBundle(t *testing.T, src bundleSources, a bundleArgs, want []string) ots.Verdict {
	t.Helper()
	if want == nil {
		want = append([]string{}, sectionOrder...)
	}
	got, err := writeBundle(context.Background(), a, want, src)
	if err != nil {
		t.Fatalf("writeBundle 报错：%v", err)
	}
	v, ok := got.(ots.Verdict)
	if !ok {
		t.Fatalf("结果不是判定：%T", got)
	}
	if !ots.ValidVerdictCode(v.Code) {
		t.Errorf("判定码不合规范：%q", v.Code)
	}
	return v
}

// bundleFiles 解开包，返回 名字→内容，并顺手检查每个名字都带了 UTF-8 标志位。
func bundleFiles(t *testing.T, path string) (map[string]string, []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("解不开（现场就是这样解不开上一版的）：%v", err)
	}
	texts := map[string]string{}
	var names []string
	for i, f := range zr.File {
		names = append(names, f.Name)
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
		texts[f.Name] = buf.String()
		// general purpose bit 11：本地文件头在签名后偏移 6
		_ = i
	}
	// 逐字节查那一位（本地头与中心目录头都要）
	var local, central []uint16
	for i := 0; i+4 <= len(raw); i++ {
		switch binary.LittleEndian.Uint32(raw[i:]) {
		case 0x04034b50:
			local = append(local, binary.LittleEndian.Uint16(raw[i+6:]))
		case 0x02014b50:
			central = append(central, binary.LittleEndian.Uint16(raw[i+8:]))
		}
	}
	if len(local) == 0 || len(local) != len(central) {
		t.Fatalf("zip 头读不出来：local %d central %d", len(local), len(central))
	}
	for i, fl := range local {
		if fl&0x800 == 0 {
			t.Errorf("第 %d 个本地文件头没置 UTF-8 位（flags=0x%04x）", i, fl)
		}
	}
	for i, fl := range central {
		if fl&0x800 == 0 {
			t.Errorf("第 %d 个中心目录头没置 UTF-8 位（flags=0x%04x）", i, fl)
		}
	}
	return texts, names
}

// Test诊断包把每一项的原文都放进去 核心承诺：对方不必再回来问「网关是哪台」。
func Test诊断包把每一项的原文都放进去(t *testing.T) {
	src, dir := bundleFixture(t)
	v := runBundle(t, src, bundleArgs{Label: "金宇建安-盒1"}, nil)
	if v.Code != bundleWritten {
		t.Errorf("判定 = %v，要 %v（missingItems=%v）", v.Code, bundleWritten, v.Values["missingItems"])
	}
	path, _ := v.Values["path"].(string)
	if path == "" || filepath.Dir(path) != dir {
		t.Fatalf("path = %v，要落在 %s 下", v.Values["path"], dir)
	}
	if !strings.Contains(filepath.Base(path), "金宇建安-盒1") {
		t.Errorf("包名里没带上标签：%s", filepath.Base(path))
	}
	texts, names := bundleFiles(t, path)
	for _, want := range []string{
		"网卡与地址.txt", "路由表.txt", "邻居表.txt", "DNS服务器.txt", "hosts文件.txt",
		"代理设置.txt", "端口占用.txt", "NetKit改动.txt", "连通性体检.txt", "系统与时间.txt",
		"00 先看这里.txt", "结果.json",
	} {
		hit := false
		for n := range texts {
			if strings.HasSuffix(n, want) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("包里没有 %q，实际：%v", want, names)
		}
	}
	all := strings.Join(mapVals(texts), "\n")
	// 每一项都带原文，不是结论的复述
	for _, want := range []string{
		"a4:5e:60:11:22:33", "10.0.12.34/22", "fe80::1234", "fd00::9", // 网卡
		"0.0.0.0/0", "10.0.12.1", "metric 100", "::/0", // 路由
		"10.0.12.77", "aa:bb:cc:dd:ee:ff", // 邻居
		"223.5.5.5", "utun3", // DNS
		"box.local",       // hosts
		"nginx", "LISTEN", // 端口
		"static-address", "已还原", // 账本
		"gateway-loss", "16.7", // 体检
		"eng-laptop-07", "2026-09-25 11:00:00", // 系统
	} {
		if !strings.Contains(all, want) {
			t.Errorf("包里没有 %q 这条原文 —— 对方一定会回来问它", want)
		}
	}
	// v6 隐私临时地址：现场会把它抄进白名单，必须就地提醒
	if !strings.Contains(all, "会定期换") {
		t.Error("临时地址没标出来")
	}
	// 介质是按名字猜的要写出来（现场照这一列去插线）
	if !strings.Contains(all, "按网卡名猜的") {
		t.Error("KindSrc=name 没标出来：把猜测当事实报出去比不报还糟")
	}
	// 环回不是毛病，但不能混在「插了线」里
	if !strings.Contains(all, "环回") {
		t.Error("环回没标")
	}
	// note 第一句要能抄进工单：路径在最前
	if !strings.Contains(v.Note, path) {
		t.Errorf("note 里没带包的路径：%s", v.Note)
	}
	if !strings.Contains(v.Note, "UTF-8") {
		t.Errorf("note 该说明文件名是 UTF-8（上一版就是解不开）：%s", v.Note)
	}
	if !strings.Contains(v.Note, "发出去就等于") {
		t.Errorf("note 少了发之前的提示：%s", v.Note)
	}
	assertNoBundleSecret(t, v, path)
}

// Test凭据既不進包也不进结果 ★ 包的作者们（各个读法的实现）只考虑过「这条结论要不要发给 AI」，
// 没考虑过这个包会被发到工单里 —— 所以脱敏必须在写盘这一刻统一做一遍，不问是谁写的。
func Test凭据既不进包也不进结果(t *testing.T) {
	src, _ := bundleFixture(t)
	v := runBundle(t, src, bundleArgs{}, nil)
	assertNoBundleSecret(t, v, v.Values["path"].(string))
	// 而且不能整行删掉：留着的键名才区分得开「配了但没给你看」和「没配」
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n, s := range texts {
		if strings.Contains(s, bundleSecretCommunity) || strings.Contains(s, bundleSecretPassword) {
			t.Errorf("%s 里漏出了凭据", n)
		}
	}
	man := ""
	for n, s := range texts {
		if strings.HasSuffix(n, "00 先看这里.txt") {
			man = s
		}
	}
	if !strings.Contains(man, "共抹掉") {
		t.Errorf("清单没写抹过几处：\n%s", man)
	}
	red, _ := v.Values["redacted"].(map[string]int)
	if len(red) == 0 {
		t.Errorf("values.redacted 应该是命中计数，给了 %v", v.Values["redacted"])
	}
	if !strings.Contains(fmt.Sprint(v.Values["redactedHow"]), "共抹掉") {
		t.Errorf("redactedHow 该是给人看的那一句：%v", v.Values["redactedHow"])
	}
}

func assertNoBundleSecret(t *testing.T, v ots.Verdict, path string) {
	t.Helper()
	blob := fmt.Sprintf("%#v|%s|%s", v.Values, v.Code, v.Note)
	if strings.Contains(blob, bundleSecretCommunity) || strings.Contains(blob, bundleSecretPassword) {
		t.Errorf("结果里漏出了凭据：%s", blob)
	}
	if path == "" {
		t.Fatal("没有包路径")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{bundleSecretCommunity, bundleSecretPassword} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("包里漏出了 %q ——  zip 是存明文的，脱敏必须在写盘前做完", s)
		}
	}
}

// Test读不到的项要留在包里并写明原因 「安静地少一个文件」会被读成「这台没配」，
// 而真相多半是没权限 —— 这两种情况下一步查的地方完全不同。
func Test读不到的项要留在包里并写明原因(t *testing.T) {
	src, _ := bundleFixture(t)
	src.neigh4 = func(context.Context) ([]neighbor, error) { return nil, errors.New("要 root") }
	src.neigh6 = func(context.Context) ([]neighbor, error) { return nil, errors.New("要 root") }
	src.hosts = func() (string, string, error) { return "/etc/hosts", "", os.ErrPermission }
	src.routes = func() ([]netif.Route, error) { return nil, errors.New("这台没有读路由表的命令") }

	v := runBundle(t, src, bundleArgs{}, nil)
	if v.Code != bundlePartial {
		t.Fatalf("判定 = %v，要 %v", v.Code, bundlePartial)
	}
	missing, _ := v.Values["missingItems"].([]string)
	for _, want := range []string{secNeighbors, secHosts, secRoutes} {
		if !containsStr(missing, want) {
			t.Errorf("missingItems 少了 %v：%v", want, missing)
		}
	}
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n, s := range texts {
		switch {
		case strings.HasSuffix(n, "邻居表.txt"):
			if !strings.Contains(s, "要 root") || !strings.Contains(s, "不要把它当成「这台机器上没有」") {
				t.Errorf("邻居表这一页没把「读不到」和「没有」分开：\n%s", s)
			}
		case strings.HasSuffix(n, "hosts文件.txt"):
			if !strings.Contains(s, "/etc/hosts") {
				t.Errorf("hosts 读不到时得把路径说给人看（他要手动去查）：\n%s", s)
			}
		case strings.HasSuffix(n, "路由表.txt"):
			if !strings.Contains(s, "读不到") {
				t.Errorf("路由表这一页没写原因：\n%s", s)
			}
		}
	}
	if !strings.Contains(v.Note, "缺") {
		t.Errorf("note 该说缺了几项：%s", v.Note)
	}
	// sections 里要能逐项看到（界面要把它渲染成一行行，而不是只给一个数字）
	items, _ := v.Values["sections"].([]bundleItem)
	if len(items) != len(sectionOrder) {
		t.Fatalf("sections = %d 项，要 %d 项", len(items), len(sectionOrder))
	}
	for _, it := range items {
		if !ots.ValidVerdictCode(it.Code) {
			t.Errorf("%s 的项内判定码不合规：%q", it.Item, it.Code)
		}
		if it.Label == "" || it.File == "" {
			t.Errorf("%s 少了界面要用的字段：%+v", it.Item, it)
		}
	}
}

// breakEveryRead 把「会碰系统」的读法全换成失败：邻居表、路由、hosts 这些在一台
// 没给权限的机器上就是这样一起塌掉的。
func breakEveryRead(src bundleSources) bundleSources {
	boom := errors.New("这台什么都读不到")
	src.nics = func() ([]netif.NIC, error) { return nil, boom }
	src.routes = func() ([]netif.Route, error) { return nil, boom }
	src.defRoute = func() ([]netif.DefaultRoute, error) { return nil, boom }
	src.neigh4 = func(context.Context) ([]neighbor, error) { return nil, boom }
	src.neigh6 = func(context.Context) ([]neighbor, error) { return nil, boom }
	src.dns = func() ([]netif.DNSServer, error) { return nil, boom }
	src.hosts = func() (string, string, error) { return "/etc/hosts", "", boom }
	src.ports = func(context.Context) ([]portUse, bool, error) { return nil, false, boom }
	src.checkup = func(context.Context, checkupArgs, int, time.Duration, checkProbes) ([]checkItem, map[string]any, error) {
		return nil, nil, boom
	}
	return src
}

// Test全都读不出来时不能报成功 一台什么都没读出来的包，对方拿到会以为「这台干净」——
// 必须在判定与包里两处都喊出来。
//
// ★ 「什么都没读出来」按**这一趟要读的项**算，不按十项全算：系统与时间、代理、
//
//	改动账本这三页本来就不碰那些读法，它们成功了不代表包里有实测内容。
func Test全都读不出来时不能报成功(t *testing.T) {
	all, _ := bundleFixture(t)
	src := breakEveryRead(all)
	want, err := pickSections([]string{secNIC, secRoutes, secNeighbors, secHosts, secPorts, secCheckup})
	if err != nil {
		t.Fatal(err)
	}
	v := runBundle(t, src, bundleArgs{}, want)
	if v.Code != bundlePartial {
		t.Fatalf("判定 = %v", v.Code)
	}
	missing, _ := v.Values["missingItems"].([]string)
	if fmt.Sprint(missing) != fmt.Sprint(want) {
		t.Errorf("missingItems = %v，要 %v", missing, want)
	}
	if v.Values["nothingRead"] != true {
		t.Errorf("空壳这件事要给成机器可读的字段，不能只写在 note 里（界面不许自己数行）：%v",
			v.Values["nothingRead"])
	}
	if !strings.Contains(v.Note, "一项都没读出来") {
		t.Errorf("note 要说明这个包里全是原因、没有内容：%s", v.Note)
	}
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	man := ""
	for n, s := range texts {
		if strings.HasSuffix(n, "00 先看这里.txt") {
			man = s
		}
	}
	if !strings.Contains(man, "一项都没读出来") {
		t.Errorf("包的第一页也没喊这一句：\n%s", man)
	}
}

// Test有一部分读出来时不许喊全都没读到 反过来也要守：
// 包里明明有六页内容，第一页却喊「一项都没读出来」，对方会整个不信这个包。
func Test有一部分读出来时不许喊全都没读到(t *testing.T) {
	all, _ := bundleFixture(t)
	src := breakEveryRead(all)
	v := runBundle(t, src, bundleArgs{}, nil)
	if v.Code != bundlePartial {
		t.Fatalf("判定 = %v", v.Code)
	}
	if v.Values["nothingRead"] != false {
		t.Errorf("有几项读到就不许报空壳：%v", v.Values["nothingRead"])
	}
	missing, _ := v.Values["missingItems"].([]string)
	if len(missing) != len(sectionOrder)-3 { // 系统与时间、代理、改动账本不碰这些源
		t.Errorf("missingItems = %v", missing)
	}
	if strings.Contains(v.Note, "一项都没读出来") {
		t.Errorf("还有页读出来了，note 不该喊全部失败：%s", v.Note)
	}
	if !strings.Contains(v.Note, fmt.Sprintf("缺 %d 项", len(missing))) {
		t.Errorf("note 要说缺几项：%s", v.Note)
	}
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n, s := range texts {
		if !strings.HasSuffix(n, "网卡与地址.txt") {
			continue
		}
		if !strings.Contains(s, "这台什么都读不到") {
			t.Errorf("读不到的那一页没把原因留在包里：\n%s", s)
		}
	}
}

// Test跳过体检不算读不到 skipLive 是调用方的选择，不是这台的毛病 ——
// 判定里不能把它和「读不到」混成一档，但包里必须留一行。
func Test跳过体检不算读不到(t *testing.T) {
	src, _ := bundleFixture(t)
	v := runBundle(t, src, bundleArgs{SkipLive: true}, nil)
	if v.Code != bundleWritten {
		t.Errorf("判定 = %v，要 %v（跳过是选择，不是缺项）", v.Code, bundleWritten)
	}
	items, _ := v.Values["sections"].([]bundleItem)
	var found bool
	for _, it := range items {
		if it.Item == secCheckup {
			found = true
			if it.Code != secSkipped {
				t.Errorf("体检项的判定 = %v，要 %v", it.Code, secSkipped)
			}
			if it.Reason != "skipped-live" {
				t.Errorf("reason = %v，要给界面一个可判的词", it.Reason)
			}
		}
	}
	if !found {
		t.Fatal("sections 里没有体检那一项")
	}
	// ★ 跳过时不许把 "skipped-live" 当体检顶层判定送出去：界面上那是一颗看着像结论的胶囊。
	if cu, ok := v.Values["checkup"]; ok {
		t.Errorf("体检没跑，values 里不该有 checkup 这一栏：%v", cu)
	}
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n, s := range texts {
		if strings.HasSuffix(n, "连通性体检.txt") && !strings.Contains(s, "去掉 skipLive") {
			t.Errorf("跳过的那一页要写清楚怎么跑回来：\n%s", s)
		}
	}
}

// Testonly 按排查顺序回来 调用方可能随手给顺序（AI 尤其会），
// 而包里的项顺序是「对方先看什么」的一部分。
func TestOnly项按排查顺序回来(t *testing.T) {
	src, _ := bundleFixture(t)
	want, err := pickSections([]string{secCheckup, secNIC, secSystem})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(want) != fmt.Sprint([]string{secSystem, secNIC, secCheckup}) {
		t.Errorf("pickSections 没按排查顺序排回去：%v", want)
	}
	v := runBundle(t, src, bundleArgs{}, want)
	items, _ := v.Values["sections"].([]bundleItem)
	got := []string{}
	for _, it := range items {
		got = append(got, it.Item)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("项的顺序 = %v，要 %v", got, want)
	}
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n := range texts {
		if strings.HasSuffix(n, "邻居表.txt") || strings.HasSuffix(n, "路由表.txt") {
			t.Errorf("只要三项却把 %s 也放进去了", n)
		}
	}
}

func Test不认识的项名要报错并给出可选值(t *testing.T) {
	_, err := pickSections([]string{"nic", "snmp"})
	if err == nil {
		t.Fatal("不认识的项名被收下了")
	}
	if !strings.Contains(err.Error(), "checkup") || !strings.Contains(err.Error(), "snmp") {
		t.Errorf("报错没把可选值和错的那一个一起给出：%v", err)
	}
}

// Test写不出来不能报成功 输出目录拿不到、或者那个目录写不了：
// 界面上必须能直接说「这台写不出来」，而且不能留一个半截的包让人以为是坏机器。
func Test写不出来不能报成功(t *testing.T) {
	t.Run("目录拿不到", func(t *testing.T) {
		src, dir := bundleFixture(t)
		src.outDir = func() (string, error) { return "", errors.New("这台找不到用户配置目录") }
		v := runBundle(t, src, bundleArgs{}, nil)
		if v.Code != bundleNotWritten {
			t.Fatalf("判定 = %v", v.Code)
		}
		if !strings.Contains(v.Note, "找不到用户配置目录") {
			t.Errorf("note 要带上原因：%s", v.Note)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			var left []string
			for _, e := range entries {
				left = append(left, e.Name())
			}
			t.Errorf("一个文件都没读出来之前先把目录写脏了：%v", left)
		}
		if _, ok := v.Values["reason"]; !ok {
			t.Errorf("values 里要留着原因：%v", v.Values)
		}
	})
	t.Run("目录写不了", func(t *testing.T) {
		src, dir := bundleFixture(t)
		blocker := filepath.Join(dir, "占位")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		src.outDir = func() (string, error) { return blocker, nil } // 是个文件，建不了子目录也写不了
		v := runBundle(t, src, bundleArgs{}, nil)
		if v.Code != bundleNotWritten {
			t.Fatalf("判定 = %v，要 %v", v.Code, bundleNotWritten)
		}
		if !strings.Contains(v.Note, "没有新文件") && !strings.Contains(v.Note, "别去翻半截的包") {
			t.Errorf("note 该说明没有文件留下：%s", v.Note)
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".part") {
				t.Errorf("留下了半截的包：%s", e.Name())
			}
		}
		// ★ 内容其实全读到了，只是写不出去：逐项判定照样要给，键名也不许换成 items。
		//   换了名，界面上那张表在这一档就空着，看起来像「这台什么都没配」。
		items, ok := v.Values["sections"].([]bundleItem)
		if !ok || len(items) != len(sectionOrder) {
			t.Errorf("sections = %v，要 %v 项", v.Values["sections"], len(sectionOrder))
		}
	})
}

// Test包名里的标签洗过 标签来自用户输入或 AI，会变成一个真实存在的文件名。
func Test包名里的标签洗过(t *testing.T) {
	src, dir := bundleFixture(t)
	v := runBundle(t, src, bundleArgs{Label: "../../恶意/名称:*?"}, nil)
	path := v.Values["path"].(string)
	base := filepath.Base(path)
	if strings.Contains(base, "..") || strings.Contains(base, "/") || strings.Contains(base, "*") {
		t.Errorf("包名里还有危险字符：%s", base)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("包写到指定目录外面去了：%s", path)
	}
}

// Test结果能直接渲染成界面要的东西 sections / 缺失项 / 字节数 / 耗时，
// 每一项界面都要单独一行，不能只给一个数字。
func Test结果能直接渲染成界面要的东西(t *testing.T) {
	src, _ := bundleFixture(t)
	v := runBundle(t, src, bundleArgs{Label: "x"}, nil)
	for k, want := range map[string]string{
		"entries":      "int",
		"bytes":        "int64",
		"tookMs":       "int64",
		"sections":     "[]tools.bundleItem",
		"missingItems": "[]string",
		"checkup":      "map[string]interface {}",
		"dir":          "string",
	} {
		got := fmt.Sprintf("%T", v.Values[k])
		if got != want {
			t.Errorf("values[%q] 类型 = %s，要 %s", k, got, want)
		}
	}
	if cb, _ := v.Values["checkup"].(map[string]any); cb["top"] != "degraded" {
		t.Errorf("体检顶层判定没提出来：%v", v.Values["checkup"])
	}
	// note 不许有 markdown：它是给人抄进工单的那一行（界面会自己渲染判定码）
	if strings.Contains(v.Note, "**") {
		for _, line := range strings.Split(v.Note, "\n") {
			if strings.Contains(line, "**") {
				t.Errorf("note 里有手抄记号：%s", line)
			}
		}
	}
	// 机读的 结果.json 要在包里，且 items 与 note 一致
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n, s := range texts {
		if !strings.HasSuffix(n, "结果.json") {
			continue
		}
		var doc struct {
			Kind  string `json:"kind"`
			Items []struct {
				Item string `json:"item"`
				Code string `json:"code"`
			} `json:"items"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatalf("结果.json 解不开：%v", err)
		}
		if doc.Kind != "netkit.diag.bundle" {
			t.Errorf("kind = %q", doc.Kind)
		}
		if len(doc.Items) != len(sectionOrder) {
			t.Errorf("结果.json 里的 items = %d 项", len(doc.Items))
		}
		if doc.Version == "" {
			t.Error("版本没写进包：远程的人第一句一定问「那台是什么版本」")
		}
	}
}

// Test体检那一项带的是它自己的顶层判定 界面上包的路径旁边要能说出「断在哪一步」。
func Test体检那一项带的是它自己的顶层判定(t *testing.T) {
	src, _ := bundleFixture(t)
	src.checkup = func(context.Context, checkupArgs, int, time.Duration, checkProbes) ([]checkItem, map[string]any, error) {
		return []checkItem{
			{Step: stepRoute, Code: "route-no-default", Severity: sevBad},
			{Step: stepDNS, Code: "dns-timeout", Severity: sevBad},
		}, nil, nil
	}
	v := runBundle(t, src, bundleArgs{}, nil)
	cb, _ := v.Values["checkup"].(map[string]any)
	if cb["top"] != topBrokenRoute {
		t.Errorf("checkup.top = %v，要 %v（第一个坏掉的是路由，不是 DNS）", cb["top"], topBrokenRoute)
	}
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	for n, s := range texts {
		if strings.HasSuffix(n, "连通性体检.txt") {
			if !strings.Contains(s, topBrokenRoute) || !strings.Contains(s, "route-no-default") {
				t.Errorf("体检那一页要带顶层判定和每一步：\n%s", s)
			}
			if !strings.Contains(s, "dns-timeout") {
				t.Errorf("坏掉之后的步骤也要留在包里（「网关丢包、DNS 也慢」和「只有网关丢」不是同一个毛病）：\n%s", s)
			}
		}
	}
}

// Test工具入口校验参数 only 里不认识的词、非法 JSON 都要在动手前挡住 ——
// 这一栏会写文件，不能先写完再报错。
func Test工具入口校验参数(t *testing.T) {
	if _, err := doDiagBundle(context.Background(), json.RawMessage(`{"only":["nope"]}`)); err == nil {
		t.Error("不认识的项名没报错")
	}
	if _, err := doDiagBundle(context.Background(), json.RawMessage(`{`)); err == nil {
		t.Error("非法 JSON 没报错")
	} else if !strings.Contains(err.Error(), "JSON") {
		t.Errorf("报错没说清是参数问题：%v", err)
	}
	// 真跑一次全项（用这台机器真实的读法）：只要求它不崩、且给出的判定在三个之内。
	// ★ 结果内容随机器变化，所以这里不钉内容，只钉「跑得完」。
	got, err := doDiagBundle(context.Background(), json.RawMessage(`{"skipLive":true,"only":["system","nic"]}`))
	if err != nil {
		t.Fatalf("真读一次报错了：%v", err)
	}
	v := got.(ots.Verdict)
	if v.Code != bundleWritten && v.Code != bundlePartial && v.Code != bundleNotWritten {
		t.Errorf("判定 = %v，只允许那三种", v.Code)
	}
	assertNoCommunity(t, v)
	if p, _ := v.Values["path"].(string); p != "" {
		t.Cleanup(func() { os.Remove(p) })
	}
}

// Test包内文件名与界面用词对得上 界面按 file 显示「哪一项在哪个文件里」，
// 名字对不上就等于让人去猜。
func Test包内文件名与界面用词对得上(t *testing.T) {
	src, _ := bundleFixture(t)
	v := runBundle(t, src, bundleArgs{}, nil)
	texts, _ := bundleFiles(t, v.Values["path"].(string))
	items, _ := v.Values["sections"].([]bundleItem)
	for _, it := range items {
		hit := false
		for n := range texts {
			if strings.HasSuffix(n, it.File) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s（%s）说文件是 %q，包里却没有", it.Item, it.Label, it.File)
		}
	}
	if len(items) != len(sectionOrder) {
		t.Errorf("项数 = %d，要 %d", len(items), len(sectionOrder))
	}
}

func mapVals(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
