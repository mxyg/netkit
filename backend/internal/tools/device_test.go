package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"net.yuhox.com/netkit/internal/broadcast"
	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
)

// 这一栏的测试全部打在替身上。★ 理由写在 deviceSources 的注释里：
// 「收上来几条自报、怎么归并成一台、该给哪个判定」不该只能靠
// 办公室里恰好摆着一台摄像头来验 —— 那样最容易错的恰好是判定那一层。

func devNIC(name, cidr string) netif.NIC {
	p := netip.MustParsePrefix(cidr)
	return netif.NIC{
		Name: name, Index: 3, Up: true, Running: true, MTU: 1500,
		Kind: "ethernet", KindSrc: "os",
		Addrs: []netaddr.Addr{{IP: p.Addr(), Prefix: p.Bits()}},
	}
}

func devDownNIC(name string) netif.NIC {
	return netif.NIC{Name: name, Index: 4, Up: true, Running: false, Kind: "wifi"}
}

// devReport 造一条自报。★ 只填要用的那几栏，其余留空 —— 空本身就是这一栏要测的东西。
func devReport(src, addr string) broadcast.Report {
	return broadcast.Report{Source: src, From: addr}
}

func devSources(nics []netif.NIC, ask func(context.Context, identifyPlan) (askResult, error)) deviceSources {
	return deviceSources{
		nics: func() ([]netif.NIC, error) { return nics, nil },
		ask:  ask,
		fetch: func(context.Context, string) ([]byte, error) {
			return nil, errors.New("测试里不该去取描述文件")
		},
	}
}

func runDev(t *testing.T, src deviceSources, args string) (ots.Verdict, map[string]any) {
	t.Helper()
	out, err := runIdentify(context.Background(), json.RawMessage(args), src)
	if err != nil {
		t.Fatalf("runIdentify 返回了错误：%v", err)
	}
	v, ok := out.(ots.Verdict)
	if !ok {
		t.Fatalf("结果不是一个判定，而是 %T", out)
	}
	if v.Values == nil {
		t.Fatalf("判定没带取值：界面拿不到任何可渲染的东西")
	}
	return v, v.Values
}

func Test设备识别四种结果各给一个判定码(t *testing.T) {
	cases := []struct {
		name    string
		nics    []netif.NIC
		ask     func(context.Context, identifyPlan) (askResult, error)
		args    string
		want    string
		skipErr bool
	}{
		{
			name: "一块可用网卡都没有",
			nics: []netif.NIC{devDownNIC("en1")},
			ask: func(context.Context, identifyPlan) (askResult, error) {
				t.Error("没有可用网卡时一个包都不该发出去")
				return askResult{}, nil
			},
			want: verdictNoInterface,
		},
		{
			name: "组播发不出去",
			nics: []netif.NIC{devNIC("en0", "10.0.12.34/22")},
			ask: func(context.Context, identifyPlan) (askResult, error) {
				return askResult{}, fmt.Errorf("%w：en0 设不了组播出口", errNoMulticast)
			},
			want: verdictNoMulticast,
		},
		{
			name: "问了没人应",
			nics: []netif.NIC{devNIC("en0", "10.0.12.34/22")},
			ask:  func(context.Context, identifyPlan) (askResult, error) { return askResult{}, nil },
			want: verdictNothingHeard,
		},
		{
			name: "有东西应了但一句身份没说",
			nics: []netif.NIC{devNIC("en0", "10.0.12.34/22")},
			ask: func(context.Context, identifyPlan) (askResult, error) {
				return askResult{Reports: []broadcast.Report{
					// 只带来源地址的报文是真的会有：别的网段转出来的一个 SSDP  Alive，
					// 头里没有任何身份字段。
					{Source: broadcast.SourceSSDP, From: "10.0.12.77", Text: map[string]string{"bootid": "12"}},
				}}, nil
			},
			want: verdictHeardAnonymous,
		},
		{
			name: "认出了设备",
			nics: []netif.NIC{devNIC("en0", "10.0.12.34/22")},
			ask: func(context.Context, identifyPlan) (askResult, error) {
				return askResult{Reports: []broadcast.Report{
					{Source: broadcast.SourceWSDiscovery, From: "10.0.12.77",
						Type: "dn:NetworkVideoTransmitter", URL: "http://10.0.12.77/onvif/device_service",
						Name: "AXIS M30", Iface: "en0"},
				}}, nil
			},
			want: verdictDevicesFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, vals := runDev(t, devSources(tc.nics, tc.ask), `{}`)
			if v.Code != tc.want {
				t.Errorf("判定码 = %q，想要 %q（note：%s）", v.Code, tc.want, v.Note)
			}
			if !ots.ValidVerdictCode(v.Code) {
				t.Errorf("判定码 %q 不合规范", v.Code)
			}
			if strings.Contains(v.Note, "**") {
				t.Errorf("note 里漏进了 Markdown 星号：%s", v.Note)
			}
			// ★ 只要带了逐路的那本账，形状就必须是同一份。「没人应」「组播发不出去」
			//   「跑完了」这些判定里 protocols 若是两种形状，界面就得先猜这次是哪一种 ——
			//   而它猜的时候页面上是不报错的，只是那一栏空着。
			assertProtocolTally(t, vals)
		})
	}
}

func Test识别结果里不许出现猜测(t *testing.T) {
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22")}
	src := devSources(nics, func(context.Context, identifyPlan) (askResult, error) {
		return askResult{Reports: []broadcast.Report{
			{Source: broadcast.SourceNetBIOS, From: "10.0.12.77", Name: "NAS-01",
				MAC: "a4:5e:60:11:22:33", Detail: "文件与打印共享", Iface: "en0"},
			{Source: broadcast.SourceMDNS, From: "10.0.12.77", Instance: "NAS-01",
				Type: "_smb._tcp.local", Host: "NAS-01.local", Port: 445, Iface: "en0"},
			{Source: broadcast.SourceSSDP, From: "10.0.12.88", Type: "urn:schemas-upnp-org:device:MediaServer:1",
				Name: "客厅播放器", URL: "http://10.0.12.88:49152/desc.xml"},
			// 这一台什么都没说过，只应了一个包
			{Source: broadcast.SourceSSDP, From: "10.0.12.99"},
		}}, nil
	})
	v, vals := runDev(t, src, `{"rounds":1}`)
	if v.Code != verdictDevicesFound {
		t.Fatalf("判定 = %q，想要 %q", v.Code, verdictDevicesFound)
	}
	raw, err := json.Marshal(vals)
	if err != nil {
		t.Fatalf("结果编不成 JSON：%v", err)
	}
	s := string(raw)
	if strings.ContainsRune(s, 0xFFFD) {
		t.Error("结果里出现了替换字符：某处按字节截断了设备给的文字")
	}
	for _, guess := range []string{"海康", "大华", "可能是", "大概率"} {
		if strings.Contains(s, guess) {
			t.Errorf("结果里出现了猜出来的话（%q）：这一栏只放设备自己说过的", guess)
		}
	}
	devs, ok := vals["devices"].([]identifiedDevice)
	if !ok {
		t.Fatalf("devices 类型不对：%T", vals["devices"])
	}
	if len(devs) != 3 {
		t.Fatalf("归并成 %d 台，想要 3 台", len(devs))
	}
	// ★ 认出来的排前面，什么都没说的排最后：那一屏是给人抄进工单的。
	if devs[2].Addr != "10.0.12.99" {
		t.Errorf("排最后的是 %s，想要没认出来的那台", devs[2].Addr)
	}
	if devs[0].MAC != "a4:5e:60:11:22:33" {
		t.Errorf("MAC 没并进来：%+v", devs[0])
	}
	if !devs[0].Identified || devs[2].Identified {
		t.Errorf("Identified 标错了：%+v / %+v", devs[0], devs[2])
	}
	if got := vals["identified"]; got != 2 {
		t.Errorf("identified = %v，想要 2（应了的 3 个地址里认出 2 个）", got)
	}
}

func Test归并只按地址不按名字(t *testing.T) {
	// 两台机器同名是现场真会碰到的；一台 NAS 报出十几个实例也是。
	reports := []broadcast.Report{
		{Source: broadcast.SourceNetBIOS, From: "10.0.0.11", Name: "PC"},
		{Source: broadcast.SourceNetBIOS, From: "10.0.0.12", Name: "PC"},
		{Source: broadcast.SourceMDNS, From: "10.0.0.13", Instance: "NAS 1", Type: "_smb._tcp.local"},
		{Source: broadcast.SourceMDNS, From: "10.0.0.13", Instance: "NAS 2", Type: "_afpovertcp._tcp.local"},
	}
	devs := mergeDevices(reports)
	if len(devs) != 3 {
		t.Fatalf("归并成 %d 台，想要 3 台：%+v", len(devs), devs)
	}
	var nas *identifiedDevice
	for i := range devs {
		if devs[i].Addr == "10.0.0.13" {
			nas = &devs[i]
		}
	}
	if nas == nil {
		t.Fatal("NAS 那一台没了")
	}
	if len(nas.Instances) != 2 {
		t.Errorf("实例并成了 %d 个，想要 2 个：%v", len(nas.Instances), nas.Instances)
	}
	if len(nas.Protocols) != 1 || nas.Protocols[0] != broadcast.SourceMDNS {
		t.Errorf("协议清单 = %v，想要只有 mdns", nas.Protocols)
	}
}

func Test空地址的记录不当一台设备(t *testing.T) {
	devs := mergeDevices([]broadcast.Report{
		{Source: broadcast.SourceSSDP, From: ""},
		{Source: broadcast.SourceSSDP, From: "10.0.0.5"},
	})
	if len(devs) != 1 {
		t.Fatalf("得到 %d 台，想要 1 台：%+v", len(devs), devs)
	}
	if devs[0].Identified {
		t.Error("只有一个地址、什么都没说过，不该算认出来了")
	}
}

func Test类型只写协议自己定义过的词(t *testing.T) {
	cases := []struct {
		in   broadcast.Report
		want string
	}{
		{broadcast.Report{Type: "dn:NetworkVideoTransmitter"}, "网络摄像头（ONVIF 定义的网络视频设备）"},
		{broadcast.Report{Type: "urn:schemas-upnp-org:device:MediaServer:1"}, "媒体服务器（UPnP 定义的设备类型）"},
		{broadcast.Report{Type: "_smb._tcp.local"}, "文件共享（它自己报的服务类型）"},
		{broadcast.Report{Type: "_googlecast._tcp.local"}, "投屏接收端（它自己报的服务类型）"},
		{broadcast.Report{Source: broadcast.SourceNetBIOS, Type: "<20>", Detail: "文件与打印共享"},
			"开了文件共享的 Windows 机器"},
		// ★ 表外的类型：把设备自己写的词原样给出去，不套「大概是摄像头吧」
		{broadcast.Report{Type: "urn:schemas-my-vendor:device:DoorLock:1"}, kindUnknownSpoke},
		{broadcast.Report{}, ""},
	}
	for _, tc := range cases {
		if got := kindOf(tc.in); got != tc.want {
			t.Errorf("kindOf(%+v) = %q，想要 %q", tc.in, got, tc.want)
		}
	}
	// 表外的类型在结果里必须还原成设备自己那句话，而不是那个哨兵值。
	devs := mergeDevices([]broadcast.Report{
		{Source: broadcast.SourceSSDP, From: "10.0.0.9", Type: "urn:schemas-my-vendor:device:DoorLock:1"},
	})
	if devs[0].Kind == kindUnknownSpoke {
		t.Error("哨兵值漏进了结果：那一栏是给人抄进工单的，不该出现内部标记")
	}
	if !strings.Contains(devs[0].Kind, "DoorLock") {
		t.Errorf("表外的类型该把设备自己的词给出去，拿到 %q", devs[0].Kind)
	}
}

func Test友好名不被序列号盖掉(t *testing.T) {
	// 先收到一串像序列号的实例名，后收到友好名。
	devs := mergeDevices([]broadcast.Report{
		{Source: broadcast.SourceMDNS, From: "10.0.0.7", Instance: "3F-A1B2C3", Name: "3F-A1B2C3",
			Type: "_rtsp._tcp.local"},
		{Source: broadcast.SourceSSDP, From: "10.0.0.7", Name: "前台那台球机",
			Type: "urn:schemas-upnp-org:device:MediaServer:1"},
	})
	if devs[0].Name != "前台那台球机" {
		t.Errorf("名字 = %q，想要友好名那一个", devs[0].Name)
	}
	// 反过来先来友好名，后到的序列号不许盖掉它。
	devs = mergeDevices([]broadcast.Report{
		{Source: broadcast.SourceSSDP, From: "10.0.0.7", Name: "前台那台球机"},
		{Source: broadcast.SourceMDNS, From: "10.0.0.7", Name: "3F-A1B2C3", Instance: "3F-A1B2C3"},
	})
	if devs[0].Name != "前台那台球机" {
		t.Errorf("名字被序列号盖掉了：%q", devs[0].Name)
	}
	for s, want := range map[string]bool{
		"3F-A1B2C3": true, "PC-01": true, "NAS 1": false, "en0": false,
		"AXIS M30": false, "": false, "a1b2c3": false,
	} {
		if got := looksLikeSerial(s); got != want {
			t.Errorf("looksLikeSerial(%q) = %v，想要 %v", s, got, want)
		}
	}
}

func TestNetBIOS只点没有MAC的那些(t *testing.T) {
	reports := []broadcast.Report{
		{Source: broadcast.SourceSSDP, From: "10.0.0.11"},
		{Source: broadcast.SourceSSDP, From: "10.0.0.11"}, // 同一台应了两次
		{Source: broadcast.SourceMDNS, From: "10.0.0.12"},
		{Source: broadcast.SourceNetBIOS, From: "10.0.0.13", MAC: "aa:bb:cc:dd:ee:ff"},
		{Source: broadcast.SourceMDNS, From: "fe80::1234"}, // v6 不问：这一路只有 v4 的写法
		{Source: broadcast.SourceSSDP, From: ""},
	}
	got := netBIOTargets(reports)
	want := []string{"10.0.0.11", "10.0.0.12"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("点名清单 = %v，想要 %v", got, want)
	}
}

func Test点名地址认单个和网段(t *testing.T) {
	out, skipped, err := parseTargets([]string{"10.0.0.5", "10.0.0.0/30", "fd00::1", "不是地址"})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	// /30 的主机地址是 .1 .2；.5 已经在清单里，去重不该出现两次
	want := "10.0.0.5,10.0.0.1,10.0.0.2"
	if strings.Join(out, ",") != want {
		t.Errorf("点名清单 = %v，想要 %v", out, want)
	}
	if len(skipped) != 2 {
		t.Errorf("该把 v6 和坏写法列出来给人看，拿到 %v", skipped)
	}
	// 同一个地址写两遍只问一次
	out2, _, _ := parseTargets([]string{"10.0.0.5", "10.0.0.5"})
	if len(out2) != 1 {
		t.Errorf("去重没做：%v", out2)
	}
	// 全都不是地址：这是参数错误，不能悄悄问一个空的然后报「没人应」
	if _, _, err := parseTargets([]string{"abc"}); err == nil {
		t.Error("addrs 全认不出来时报了个空清单：应该报错")
	} else if !strings.Contains(err.Error(), "abc") {
		t.Errorf("报错里要带上那句认不出来的原文：%v", err)
	}
	// 没给参数时是空清单、不报错（走组播那一版）
	if o, s, err := parseTargets(nil); err != nil || len(o) != 0 || len(s) != 0 {
		t.Errorf("空参数应该原样返回空：%v %v %v", o, s, err)
	}
}

func Test每一路的账分开记(t *testing.T) {
	reports := []broadcast.Report{
		{Source: broadcast.SourceSSDP, From: "10.0.0.11"},
		{Source: broadcast.SourceSSDP, From: "10.0.0.12"},
		{Source: broadcast.SourceNetBIOS, From: "10.0.0.11", MAC: "aa:bb:cc:dd:ee:ff"},
	}
	tally := protocolTally([]string{protoSSDP, protoMDNS, protoNetBIOS}, 2, reports, 1)
	if len(tally) != len(allProtocols) {
		t.Fatalf("每一路都要有一行，拿到 %d 行", len(tally))
	}
	byProto := map[string]map[string]any{}
	for _, row := range tally {
		p, _ := row["protocol"].(string)
		byProto[p] = row
	}
	if byProto[protoSSDP]["asked"] != true || byProto[protoSSDP]["reports"] != 2 ||
		byProto[protoSSDP]["hosts"] != 2 || byProto[protoSSDP]["targets"] != 2 {
		t.Errorf("ssdp 那行不对：%v", byProto[protoSSDP])
	}
	// ★ 没问过的那一路必须写 asked:false，不能只报「0 条」——
	//   「0 条」和「没问」在现场是两个完全不同的下一步。
	if byProto[protoWSDisco]["asked"] != false || byProto[protoWSDisco]["reports"] != 0 {
		t.Errorf("没问的那一路该标出来：%v", byProto[protoWSDisco])
	}
	// NetBIOS 那行的 targets 是「点名叫了几台」，不是网卡数
	if byProto[protoNetBIOS]["targets"] != 1 {
		t.Errorf("netbios 的 targets = %v，想要 1（点名问了几台）", byProto[protoNetBIOS]["targets"])
	}
}

func Test网卡挑选跳过不该问的(t *testing.T) {
	nics := []netif.NIC{
		devNIC("en0", "10.0.12.34/22"),
		devDownNIC("en1"),
		{Name: "lo0", Loop: true, Up: true, Running: true,
			Addrs: []netaddr.Addr{{IP: netip.MustParseAddr("127.0.0.1"), Prefix: 8}}},
		{Name: "utun5", Up: true, Running: true, Virtual: true,
			Addrs: []netaddr.Addr{{IP: netip.MustParseAddr("192.168.99.7"), Prefix: 32}}},
		{Name: "en5", Up: true, Running: true,
			Addrs: []netaddr.Addr{{IP: netip.MustParseAddr("169.254.3.9"), Prefix: 16}}},
	}
	got, skipped := pickIdentifyNICs(nics, "")
	if len(got) != 1 || got[0].Name != "en0" {
		t.Errorf("选了 %v，想要只有 en0", ifaceNames(got))
	}
	// ★ 跳过的要分成两拨说清楚：没插线的、和只有 169.254 的，下一步查的东西不一样。
	if len(skipped) != 2 || !strings.Contains(skipped[0], "en1") || !strings.Contains(skipped[1], "en5") {
		t.Errorf("跳过清单 = %v，想要 en1（没插线）与 en5（只有 169.254）", skipped)
	}
	// 回环与虚拟网卡不列进跳过：那本来就不是用来问设备的，列出来是噪音
	for _, s := range skipped {
		if strings.Contains(s, "lo0") || strings.Contains(s, "utun") {
			t.Errorf("把 %s 当成跳过了：它压根不该参与", s)
		}
	}
	// 用户点名虚拟网卡时要放行：他在容器里跑的时候只有那一个口
	if got, _ := pickIdentifyNICs(nics, "utun5"); len(got) != 1 {
		t.Errorf("点名 utun5 时该放行，拿到 %v", ifaceNames(got))
	}
	// 点名一块没插线的网卡：给的是 no-interface 那一档，而不是悄悄换成别的网卡
	if got, _ := pickIdentifyNICs(nics, "en1"); len(got) != 0 {
		t.Errorf("点名 en1（没插线）时不该选出网卡，拿到 %v", ifaceNames(got))
	}
	// 169.254 不能当源地址：拿它发组播没人应答，界面上却是「问了」
	if src := ifaceSources([]netif.NIC{nics[4]}); len(src) != 0 {
		t.Errorf("链路本地地址当不了源，却还是给了 %v", src)
	}
	// 一块网卡挂两个地址时用排在前面的那个（netif 已经把主地址排在最前）
	both := devNIC("en0", "10.0.12.34/22")
	both.Addrs = append([]netaddr.Addr{{IP: netip.MustParseAddr("10.9.9.9"), Prefix: 24}}, both.Addrs...)
	if src := ifaceSources([]netif.NIC{both}); src["en0"] != "10.9.9.9" {
		t.Errorf("源地址 = %v，想要排在前面的那个", src["en0"])
	}
}

func Test协议参数只认那四种(t *testing.T) {
	if got, err := pickProtocols(nil); err != nil || len(got) != 4 {
		t.Errorf("不给参数时四种全问，拿到 %v %v", got, err)
	}
	if got, err := pickProtocols([]string{"MDNS", "mdns", " netbios "}); err != nil ||
		strings.Join(got, ",") != "mdns,netbios" {
		t.Errorf("大小写与空格该容忍、重复该去掉：%v %v", got, err)
	}
	for _, bad := range [][]string{{"arp"}, {""}, {"mdns", "snmp"}} {
		if _, err := pickProtocols(bad); err == nil {
			t.Errorf("%v 里不是会自报的协议，该报错", bad)
		}
	}
	if _, err := runIdentify(context.Background(), json.RawMessage(`{"protocols":["arp"]}`),
		devSources([]netif.NIC{devNIC("en0", "10.0.12.34/22")},
			func(context.Context, identifyPlan) (askResult, error) { return askResult{}, nil })); err == nil {
		t.Error("工具入口没拦住非法协议")
	}
}

func Test没问成的地址单独说且不改判定码(t *testing.T) {
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22")}
	src := devSources(nics, func(_ context.Context, p identifyPlan) (askResult, error) {
		// 点名的两个地址，一个包都没发出去；另一个照常没人应
		return askResult{Failed: p.Targets[:min(1, len(p.Targets))]}, nil
	})
	v, vals := runDev(t, src, `{"addrs":["10.0.12.77","10.0.12.78"],"rounds":1}`)
	if v.Code != verdictNothingHeard {
		t.Errorf("判定码 = %q，想要 %q：没问成不该被说成另一种结果", v.Code, verdictNothingHeard)
	}
	unsent, _ := vals["notAsked"].([]string)
	if len(unsent) != 1 {
		t.Fatalf("notAsked = %v，想要记下那一个地址", vals["notAsked"])
	}
	if !strings.Contains(v.Note, "一个包都没发出去") {
		t.Errorf("note 里没交代清楚：%s", v.Note)
	}
	if got := vals["targets"]; len(got.([]string)) != 2 {
		t.Errorf("targets 该把点名的两个都列出来：%v", got)
	}
}

func Test描述文件默认不取(t *testing.T) {
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22")}
	fetched := 0
	src := devSources(nics, func(context.Context, identifyPlan) (askResult, error) {
		return askResult{Reports: []broadcast.Report{
			{Source: broadcast.SourceSSDP, From: "10.0.12.77",
				Name: "播放器", URL: "http://10.0.12.77:49152/desc.xml"},
		}}, nil
	})
	src.fetch = func(_ context.Context, u string) ([]byte, error) {
		fetched++
		return []byte(`<root><device><friendlyName>播放器</friendlyName></device></root>`), nil
	}
	v, vals := runDev(t, src, `{"rounds":1}`)
	if fetched != 0 {
		t.Errorf("describe 没开也去取了描述文件（%d 次）：那是往设备上发 HTTP，会留访问记录", fetched)
	}
	if v.Code != verdictDevicesFound {
		t.Fatalf("判定 = %q，想要 %q", v.Code, verdictDevicesFound)
	}
	// ★ 关掉 describe 时不碰设备；打开时才多取那一份，取回来的东西并进同一台设备
	fetched = 0
	v2, vals2 := runDev(t, src, `{"rounds":1,"describe":true}`)
	if fetched == 0 {
		t.Error("describe=true 时一份描述文件都没取")
	}
	_ = vals
	if v2.Code != verdictDevicesFound {
		t.Errorf("开了 describe 反而把结果弄坏了：%s", v2.Note)
	}
	if got := vals2["count"]; got != 1 {
		t.Errorf("描述文件该并进同一台设备，现在 %v 台", got)
	}
}

func Test取描述文件只认http且限量(t *testing.T) {
	var reports []broadcast.Report
	for i := 1; i <= 20; i++ {
		r := broadcast.Report{Source: broadcast.SourceSSDP, From: fmt.Sprintf("10.0.0.%d", i),
			URL: fmt.Sprintf("http://10.0.0.%d/desc.xml", i)}
		if i == 3 {
			r.URL = "ftp://10.0.0.3/desc.xml" // 不是 http/https：这一栏不去碰别的东西
		}
		reports = append(reports, r)
	}
	reports = append(reports, broadcast.Report{
		Source: broadcast.SourceMDNS, From: "10.0.9.9", URL: "http://10.0.9.9/"}) // 不是 SSDP 的 URL

	// ★ describeKnown 是并发取描述文件的（最多 maxDescribeFetches 份），
	//   所以这本账要上锁 —— 不加锁 -race 立刻红，而那正是这一栏要验的东西。
	var (
		mu    sync.Mutex
		asked []string
	)
	src := deviceSources{fetch: func(_ context.Context, u string) ([]byte, error) {
		mu.Lock()
		asked = append(asked, u)
		mu.Unlock()
		if strings.HasPrefix(u, "ftp://") {
			t.Errorf("去取了非 http 的 LOCATION：%s", u)
		}
		return nil, errors.New("测试里不取")
	}}
	describeKnown(context.Background(), src, reports)
	mu.Lock()
	defer mu.Unlock()
	if len(asked) > maxDescribeFetches {
		t.Errorf("取了 %d 份描述文件，上限是 %d", len(asked), maxDescribeFetches)
	}
	for _, u := range asked {
		if strings.Contains(u, "10.0.9.9") || strings.HasPrefix(u, "ftp") {
			t.Errorf("不该问的还是问了：%s", u)
		}
	}
}

func Test一轮问完会把要问的东西带全(t *testing.T) {
	var plans []identifyPlan
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22"), devNIC("en3", "192.168.1.5/24")}
	src := devSources(nics, func(_ context.Context, p identifyPlan) (askResult, error) {
		plans = append(plans, p)
		return askResult{Reports: []broadcast.Report{
			{Source: broadcast.SourceSSDP, From: "10.0.12.77", Name: "球机"},
		}}, nil
	})
	if _, err := runIdentify(context.Background(), json.RawMessage(`{"rounds":2,"seconds":1}`), src); err != nil {
		t.Fatalf("%v", err)
	}
	if len(plans) != 4 {
		// 两轮 × (组播一轮 + NetBIOS 一轮)：第二轮的 NetBIOS 目标来自第一轮
		t.Errorf("一共问了 %d 次，想要 4 次：%+v", len(plans), plans)
	}
	first := plans[0]
	if len(first.Ifaces) != 2 {
		t.Errorf("两块网卡都该用上，拿到 %v", first.Ifaces)
	}
	if first.Ifaces["en0"] != "10.0.12.34" || first.Ifaces["en3"] != "192.168.1.5" {
		t.Errorf("源地址绑错了：%v", first.Ifaces)
	}
	if first.Window != time.Second {
		t.Errorf("窗口 = %v，想要 1s", first.Window)
	}
	// ★ 组播那一轮不许带上 NetBIOS：它要点名，而名字要靠这一轮的结果给。
	if containsStr(first.Protocols, protoNetBIOS) {
		t.Errorf("第一轮就问 NetBIOS 了：%v", first.Protocols)
	}
	if len(first.Services) < len(defaultMDNSServices) {
		t.Errorf("DNS-SD 该问默认那几种：%v", first.Services)
	}
	// 第二轮的 NetBIOS 目标来自第一轮的应答
	var nb *identifyPlan
	for i := range plans {
		if containsStr(plans[i].Protocols, protoNetBIOS) {
			p := plans[i]
			nb = &p
		}
	}
	if nb == nil {
		t.Fatal("问到第二轮时该有 NetBIOS 那一路")
	}
	if strings.Join(nb.NBAddrs, ",") != "10.0.12.77" {
		t.Errorf("NetBIOS 点名清单 = %v，想要第一轮应了的那台", nb.NBAddrs)
	}
}

func Test单播点名时组播那三路也改打单播(t *testing.T) {
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22")}
	var sawTargets []string
	src := devSources(nics, func(_ context.Context, p identifyPlan) (askResult, error) {
		sawTargets = append(sawTargets, strings.Join(p.Targets, " "))
		return askResult{}, nil
	})
	if _, err := runIdentify(context.Background(),
		json.RawMessage(`{"addrs":["10.0.20.77"],"protocols":["ssdp","netbios"],"rounds":1}`), src); err != nil {
		t.Fatalf("%v", err)
	}
	// ★ 跨网段的设备收不到组播：给了 addrs，SSDP 那一路也必须单播发过去，
	//   否则「问过了」这句话是假的。
	for _, s := range sawTargets {
		if !strings.Contains(s, "10.0.20.77") {
			t.Errorf("有一路还是发组播的：%v", sawTargets)
		}
	}
}

func Test取消时不报成没设备(t *testing.T) {
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asks := 0
	src := devSources(nics, func(context.Context, identifyPlan) (askResult, error) {
		asks++
		cancel() // 模拟用户点了「停」：第二轮就不该再问出去
		return askResult{}, nil
	})
	out, err := runIdentify(ctx, json.RawMessage(`{"rounds":3}`), src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	v := out.(ots.Verdict)
	if asks != 1 {
		t.Errorf("停了之后还问了 %d 次", asks)
	}
	// ★ 中途停了不能报成「这个网段没人应」：那只说得出「停之前没收到」。
	if v.Code != verdictStopped {
		t.Errorf("判定码 = %q，想要 %q：%s", v.Code, verdictStopped, v.Note)
	}
	if strings.Contains(v.Note, "这个网段里没有设备") {
		t.Errorf("中途停了却把结论下到了整个网段：%s", v.Note)
	}
}

func Test识别工具已注册且形状合法(t *testing.T) {
	r := ots.NewRegistry(false)
	Register(r)
	tool, ok := r.Lookup("net.device.identify")
	if !ok {
		t.Fatal("net.device.identify 没装进注册表")
	}
	if tool.Class != ots.ClassRead {
		t.Errorf("设备识别是观察不是改动，Class = %v", tool.Class)
	}
	var schema map[string]any
	if err := json.Unmarshal(tool.Schema, &schema); err != nil {
		t.Fatalf("Schema 不是合法 JSON：%v", err)
	}
	if schema["additionalProperties"] != false {
		t.Error("Schema 要明写拒收多余字段")
	}
	if strings.Contains(tool.Summary, "\n\n") {
		t.Error("Summary 里有空行：界面按段落排版时会断开")
	}
}

// ── 真正碰网的那一层 ──
//
// 下面几个打在回环上：绑口、设出口、发包、收包、解码这一整条是这一栏唯一
// 「测试里从来没跑过」的部分，而它一旦错了是**静默的** —— 界面上只会显示
// 「一个设备都没应答」，跟网上真没设备长得一模一样。

// loopBackNIC 回环网卡的名字与 IPv4。★ 拿真接口而不是写死 "lo0"：
// macOS 是 lo0、Linux 是 lo、Windows 是 Loopback Pseudo-Interface 1（那个没有普通可绑的 IPv4，返回 false 让测试自己跳过）。
func loopBackNIC(t *testing.T) (string, string, bool) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skipf("列不出网卡：%v", err)
	}
	for _, in := range ifs {
		if in.Flags&net.FlagLoopback == 0 {
			continue
		}
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return in.Name, ipn.IP.String(), true
			}
		}
	}
	return "", "", false
}

func Test造出来的查询报文是各协议认的那种(t *testing.T) {
	plan := identifyPlan{Window: 3 * time.Second, Services: []string{"_smb._tcp.local"},
		WSDTypes: "dn:NetworkVideoTransmitter"}
	ssdp, err := planPayloads(protoSSDP, plan)
	if err != nil || len(ssdp) != 1 {
		t.Fatalf("ssdp 查询造不出来：%v", err)
	}
	if !strings.HasPrefix(string(ssdp[0]), "M-SEARCH * HTTP/1.1") {
		t.Errorf("SSDP 那一路发出去的不是 M-SEARCH：%q", ssdp[0])
	}
	if !strings.Contains(string(ssdp[0]), "ssdp:all") {
		t.Errorf("没写搜索目标，设备不会理：%q", ssdp[0])
	}
	// ★ 头名按 SSDP 自己的写法是大写的 HOST；这里不比大小写，比的是「组地址和 1900
	//   口在不在那一行上」——设备就是照这一行决定要不要答的。
	hostLine := ""
	for _, ln := range strings.Split(string(ssdp[0]), "\r\n") {
		if strings.HasPrefix(strings.ToUpper(ln), "HOST:") {
			hostLine = strings.TrimSpace(ln[len("HOST:"):])
		}
	}
	if hostLine != "239.255.255.250:1900" {
		t.Errorf("HOST 头 = %q：%q", hostLine, ssdp[0])
	}
	// ★ 自己造的查询必须**解不出设备**：组播是会回声的（IP_MULTICAST_LOOP），
	//   解得出来的话界面上会多出一台我们自己。
	if r, err := broadcast.ParseSSDP(ssdp[0], "127.0.0.1"); err == nil || r != nil {
		t.Errorf("自己发的 M-SEARCH 被当成了设备自报：%+v %v", r, err)
	}

	wsd, err := planPayloads(protoWSDisco, plan)
	if err != nil {
		t.Fatalf("ws-discovery 查询造不出来：%v", err)
	}
	// ★ 解自己造出来的报文：造的和解的必须对得上，否则真设备上回了我们也认不出。
	r, err := broadcast.ParseWSDiscovery(wsd[0], "127.0.0.1")
	if err == nil || r != nil {
		t.Errorf("自己造的 Probe 被当成了设备自报：%v %v", r, err)
	}
	if !strings.Contains(string(wsd[0]), "<d:Probe") {
		t.Errorf("发的不是 Probe：%q", wsd[0])
	}

	mdns, err := planPayloads(protoMDNS, plan)
	if err != nil {
		t.Fatalf("mDNS 查询造不出来：%v", err)
	}
	m, err := broadcast.ParseMDNS(mdns[0])
	if err != nil {
		t.Fatalf("自己造的 mDNS 查询解不开：%v", err)
	}
	if len(m.Questions) == 0 || m.Questions[0].Name != "_smb._tcp.local" {
		t.Errorf("问题段没带上要问的服务类型：%+v", m.Questions)
	}
	if got := m.Reports("127.0.0.1"); len(got) != 0 {
		t.Errorf("自己发的 mDNS 查询里解出了设备：%+v", got)
	}
	// ★ QU 位在**问题段的 class 字段**里（RFC 6762 §6.7），解码层原样带出来不掩掉，
	//   所以这里按位查。0x8000 写死是故意的：它要盯的就是「这一位有没有置」。
	if m.Questions[0].Class&0x8000 == 0 {
		t.Errorf("没置 QU 位（class=%#x）：应答会多播回 5353，而我们开的是临时端口，收不到",
			m.Questions[0].Class)
	}
	// netbios 不是组播的：这一路要单播点名，走另一个函数
	if _, err := planPayloads(protoNetBIOS, plan); err == nil {
		t.Error("NetBIOS 被当成了组播的一路")
	}
}

func Test回环上真的发得出也收得解(t *testing.T) {
	name, ip, ok := loopBackNIC(t)
	if !ok {
		t.Skip("这台机器上没有可绑的回环 IPv4 地址")
	}
	l, err := multicastListener(protoSSDP, map[string]string{name: ip})
	if err != nil {
		t.Skipf("回环上开不了这个口：%v", err)
	}
	defer l.close()
	if len(l.conns) != 1 || l.ifaces[0] != name {
		t.Fatalf("套接字与网卡没配成对：%v", l.ifaces)
	}
	local, ok := l.conns[0].LocalAddr().(*net.UDPAddr)
	if !ok || local.Port == 0 {
		t.Fatalf("拿不到临时端口：%v", l.conns[0].LocalAddr())
	}

	// 一台「设备」在回环上答我们一条 SSDP 200
	reply := []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n" +
		"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n" +
		"USN: uuid:2f4f2c1b-1111-2222-3333-444455556666::urn:schemas-upnp-org:device:MediaServer:1\r\n" +
		"EXT:\r\nSERVER: Linux/5.10 UPnP/1.0 MiniDNPHA/1.0\r\n" +
		"BOOTID.UPNP.ORG: 17\r\nLOCATION: http://127.0.0.1:49152/desc.xml\r\n\r\n")
	go func() {
		c, err := net.Dial("udp", l.conns[0].LocalAddr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(reply)
	}()

	var got []broadcast.Report
	l.collect(context.Background(), time.Now().Add(1200*time.Millisecond), func(rs []broadcast.Report) {
		got = append(got, rs...)
	})
	if len(got) == 0 {
		t.Fatal("回环上发的一条 SSDP 应答没收到或没解出来：收包那一段是断的")
	}
	r := got[0]
	if r.Source != broadcast.SourceSSDP || r.From != ip {
		t.Errorf("记录不对：%+v", r)
	}
	if r.Iface != name {
		t.Errorf("没盖上「从哪块网卡看到的」：%+v", r) // ★ 工具层负责盖，解码层盖不出来
	}
	if r.URL != "http://127.0.0.1:49152/desc.xml" {
		t.Errorf("管理地址没解出来：%+v", r)
	}
	if r.Name != "" {
		t.Errorf("SSDP 应答里没这句名字，却凭空给出 %q", r.Name)
	}
}

func Test单播目的地用协议自己的端口(t *testing.T) {
	// ★ 不真开口：这一栏只查「目的地怎么算」，而 destinations 只用到 group 那一栏。
	//   拿真网卡开口的路有上面那个回环测试覆盖。
	g := mcastGroups()[protoWSDisco]
	l := &mcastListener{proto: g.proto, group: &net.UDPAddr{IP: net.ParseIP(g.group), Port: g.port}}
	dsts, err := l.destinations(identifyPlan{})
	if err != nil || len(dsts) != 1 || dsts[0].String() != "239.255.255.250:3702" {
		t.Errorf("默认目的地 = %v %v，想要 WS-Discovery 的组播组与 3702 口", dsts, err)
	}
	dsts, err = l.destinations(identifyPlan{Targets: []string{"10.0.20.77"}})
	if err != nil || len(dsts) != 1 || dsts[0].IP.String() != "10.0.20.77" || dsts[0].Port != 3702 {
		t.Errorf("点名时还是发组播：%v %v", dsts, err)
	}
	if _, err := l.destinations(identifyPlan{Targets: []string{"不是地址"}}); err == nil {
		t.Error("坏地址该报错")
	}
	if got := l.unsentAddrs(); len(got) != 0 {
		t.Errorf("还没发就问出「没发出去」：%v", got)
	}
	l.markUnsent("10.0.0.9")
	l.markUnsent("10.0.0.1")
	l.clearUnsent("10.0.0.9")
	if got := l.unsentAddrs(); strings.Join(got, ",") != "10.0.0.1" {
		t.Errorf("没问成的清单 = %v，想要只剩 10.0.0.1 且按序", got)
	}
}

func Test网卡开不了口时如实报错(t *testing.T) {
	// ★ 一块都不存在：必须报错，不许返回一个空监听器假装「问了、没人应」。
	if _, err := multicastListener(protoSSDP, map[string]string{"不存在0": "10.0.0.1"}); err == nil {
		t.Error("网卡不存在时报了个成功")
	} else if !errors.Is(err, errNoMulticast) {
		t.Errorf("错误没带上 errNoMulticast，判定层会当成内部错误：%v", err)
	}
	// 存在但源地址不是它的：也开不了
	name, _, ok := loopBackNIC(t)
	if !ok {
		t.Skip("没有回环 IPv4")
	}
	if _, err := multicastListener(protoMDNS, map[string]string{name: "240.0.0.1"}); err == nil {
		t.Error("源地址不属于这块网卡时报了个成功")
	}
}

func Test组播发不出去时不许说成没人应(t *testing.T) {
	// 用一块真的网卡（回环）把出口指向一个不可能有路由的组播目的：
	// 这里要验的是「发不出去 → 返回错误」这条通路，不是某个平台的错误文本。
	name, ip, ok := loopBackNIC(t)
	if !ok {
		t.Skip("没有回环 IPv4")
	}
	l, err := multicastListener(protoSSDP, map[string]string{name: ip})
	if err != nil {
		t.Skipf("开不了口：%v", err)
	}
	defer l.close()
	// 回环上发 239.255.255.250 一般是被拒的（no route to host / 网络不可达）。
	// 如果这台机器允许，那就当发成功了 —— 两种情况都不该 panic。
	err = l.sendPlan(context.Background(), identifyPlan{Ifaces: map[string]string{name: ip}})
	if err != nil && !errors.Is(err, errNoMulticast) && !strings.Contains(err.Error(), "组播") {
		t.Errorf("错误文本没交代是哪一路发不出去：%v", err)
	}
}

func Test点名问不出去时记在Failed里(t *testing.T) {
	// 一个不可能有路由的地址：Dial 或 Write 至少要失败一次。
	res := netbiosRound(context.Background(), identifyPlan{
		NBAddrs: []string{"240.0.0.1", "fe80::1", "不是地址"}, Window: 200 * time.Millisecond})
	if len(res.Reports) != 0 {
		t.Errorf("问不出去却收到了应答：%+v", res.Reports)
	}
	// v6 与坏写法一律不问，也就一律不算「没问成」
	for _, a := range res.Failed {
		if a != "240.0.0.1" {
			t.Errorf("把 %s 记成了没问成：它压根没进发问清单", a)
		}
	}
	if len(res.Failed) > 1 {
		t.Errorf("Failed 里重复了：%v", res.Failed)
	}
}

// Test入口只挡坏参数不碰网 打的是 doIdentify（真接线：列真网卡、真发包那一条）。
//
// ★ 这里刻意**只喂坏参数**：这一栏一跑起来就往网段里灌广播，测试不许替人做这个决定。
//
//	所以这几条各自都必须在碰到网卡之前返回 —— 顺带把「参数错」和「环境问题」分开钉住：
//	seconds/rounds 超上限、addrs 全是坏写法，都该是一句参数错误，
//	而不是先列完网卡再报错（那种顺序下人改好了网卡还是撞同一个错）。
func Test入口只挡坏参数不碰网(t *testing.T) {
	cases := []struct {
		name, args, want string
	}{
		{"非法 JSON", `{`, "JSON"},
		{"不认识的协议", `{"protocols":["nope"]}`, "ssdp"},
		{"一轮太长", `{"seconds":99}`, "上限"},
		{"轮数太多", `{"rounds":99}`, "上限"},
		{"点名地址全是坏的", `{"addrs":["垃圾","also-bad"]}`, "地址"},
	}
	for _, c := range cases {
		_, err := doIdentify(context.Background(), json.RawMessage(c.args))
		if err == nil {
			t.Errorf("%s：没报错", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：报错里没提 %q：%v", c.name, c.want, err)
		}
	}
}

// Test取描述文件真的走一次HTTP 打的是真的 fetchDescription（默认接线那一半）。
// ★ 前面那几个测试把它换成了替身，那是为了验「取几份、取哪些」的账；
//
//	这一栏自己那三件事——只认 200、按上限截断、把非 http 挡在门口——只有真发一次才验得到。
func Test取描述文件真的走一次HTTP(t *testing.T) {
	var big = strings.Repeat("a", maxDescribeBytes+4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.xml":
			fmt.Fprint(w, "<root>hi</root>")
		case "/gone.xml":
			w.WriteHeader(http.StatusNotFound)
		case "/big.xml":
			fmt.Fprint(w, big)
		}
	}))
	defer srv.Close()

	got, err := fetchDescription(context.Background(), srv.URL+"/ok.xml")
	if err != nil || string(got) != "<root>hi</root>" {
		t.Errorf("正常的一份没取回来：%q %v", got, err)
	}
	if _, err := fetchDescription(context.Background(), srv.URL+"/gone.xml"); err == nil {
		t.Error("404 被当成了描述文件")
	} else if !strings.Contains(err.Error(), "404") {
		t.Errorf("报错没把状态码带出来：%v", err)
	}
	// ★ 截断而不是失败：设备吐一个几百兆的 XML 是它的问题，不是我们停手的理由，
	//   但绝不能把整份读进内存。
	got, err = fetchDescription(context.Background(), srv.URL+"/big.xml")
	if err != nil {
		t.Errorf("超大描述文件报错了：%v", err)
	}
	if len(got) != maxDescribeBytes {
		t.Errorf("取回 %d 字节，正好卡在上限 %d 才对", len(got), maxDescribeBytes)
	}
	// 别的协议一律不碰：LOCATION 是设备自己写的
	if _, err := fetchDescription(context.Background(), "ftp://10.0.0.1/desc.xml"); err == nil {
		t.Error("ftp 也去取了")
	} else if strings.Contains(err.Error(), "lookup") {
		t.Error("非 http 的没挡在门口，走到 DNS 去了")
	}
}

// Test回环上问一遍真的解得出设备 打的是 askDevices：造报文、发出去、按窗口收、
// 解成一条自报 —— 中间一个替身都不接。
//
// ★ 前面那些要么打在替身上（归并与判定的账），要么只走一半（一个套接字上收发）。
//
//	这一整条接错了是**静默的**：界面上就是「这个网段里没有设备」，而人会照着这句话
//	去查设备那一侧。所以这里摆一台只活在回环上的假设备。
//
// ★ mDNS 那一路不在这里验：它要设备回一份**响应**（QR=1），而造响应是设备固件的事，
//
//	这一栏只造查询。它的两头分别钉住了：解报文在 broadcast 自己的测试里，
//	收与盖网卡名在上面那个回环测试里。
func Test回环上问一遍真的解得出设备(t *testing.T) {
	name, ip, ok := loopBackNIC(t)
	if !ok {
		t.Skip("这台机器上没有可绑的回环 IPv4 地址")
	}
	cases := []struct {
		proto string
		port  int
		reply func() []byte
		want  string
	}{
		{protoSSDP, broadcast.PortSSDP, func() []byte {
			return []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n" +
				"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n" +
				"USN: uuid:0badc0de-1111-2222-3333-444455556666::urn:schemas-upnp-org:device:MediaServer:1\r\n" +
				"LOCATION: http://127.0.0.1:8080/desc.xml\r\n\r\n")
		}, broadcast.SourceSSDP},
		{protoWSDisco, broadcast.PortWSDiscovery, func() []byte {
			// 设备被问到时是回 ProbeMatch，自己上线时喊 Hello —— 两种都是「它说自己是谁」，
			// 解码那一层一视同仁，这里用现成的造 Hello 的那一个。
			return broadcast.WSDHello("urn:uuid:cam-loop", "dn:NetworkVideoTransmitter",
				"onvif://www.onvif.org/name/LOOP%20CAM",
				[]string{"http://127.0.0.1:8081/onvif/device_service"}, 1)
		}, broadcast.SourceWSDiscovery},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: c.port})
			if err != nil {
				// macOS 的 SSDP、Windows 的 Function Discovery 会占这两个口。
				t.Skipf("%s 的 %d 口被系统服务占着，这台机器上验不了这一路：%v", c.proto, c.port, err)
			}
			defer ln.Close()

			// 假设备：收到查询就把自报回给**来包的那个地址端口**。
			// ★ 回给来源正是「我们敢用临时端口」的前提；真设备要的是这个，
			//   回成组播组的话我们收不到 —— 而那在真网上和「没设备」长得一模一样。
			go func() {
				buf := make([]byte, 65535)
				ln.SetReadDeadline(time.Now().Add(4 * time.Second))
				for {
					n, from, err := ln.ReadFromUDP(buf)
					if err != nil {
						return
					}
					if n == 0 {
						continue
					}
					if _, werr := ln.WriteTo(c.reply(), from); werr != nil {
						return
					}
				}
			}()

			res, err := askDevices(context.Background(), identifyPlan{
				Ifaces:    map[string]string{name: ip},
				Targets:   []string{ip}, // 单播点名：直接打到回环上这个端口
				Protocols: []string{c.proto},
				Window:    1500 * time.Millisecond,
				WSDTypes:  "dn:NetworkVideoTransmitter",
			})
			if err != nil {
				t.Fatalf("问这一路报错了（发不出去还是收不到？）：%v", err)
			}
			if len(res.Reports) == 0 {
				t.Fatal("设备就在回环上答了，一条都没收到：发或收那一段是断的")
			}
			r := res.Reports[0]
			if r.Source != c.want {
				t.Errorf("来源 = %q，想要 %q", r.Source, c.want)
			}
			if r.From != ip {
				t.Errorf("应答地址 = %q，想要 %q", r.From, ip)
			}
			if r.Iface != name {
				t.Errorf("没盖上「从哪块网卡看到的」：%q", r.Iface)
			}
			if len(res.Failed) != 0 {
				t.Errorf("明明问出去了，却记了没问成：%v", res.Failed)
			}
		})
	}
}

// assertProtocolTally protocols 这一栏只允许一种形状：每一路一行，
// 行里必有 asked / reports / hosts / targets。缺了形状不报错，界面只会空一栏。
func assertProtocolTally(t *testing.T, vals map[string]any) {
	t.Helper()
	raw, ok := vals["protocols"]
	if !ok {
		return
	}
	list, ok := raw.([]map[string]any)
	if !ok {
		t.Fatalf("protocols = %T，想要 []map[string]any：同一个字段在别的判定里是另一种形状", raw)
	}
	for _, row := range list {
		for _, k := range []string{"protocol", "asked", "reports", "hosts", "targets"} {
			if _, ok := row[k]; !ok {
				t.Errorf("protocols 里少了一栏 %s：%+v", k, row)
			}
		}
	}
}

// Test只问一路时不许把另外三路算成问过 只勾了 NetBIOS 的一次问，收回来说的
// 必须只是「NetBIOS 没人应」。写成「四种口径都没应」就等于把没问过的三路
// 也算成问过 —— 人据此会直接下「这片设备都不响应发现服务」的结论。
func Test只问一路时不许把另外三路算成问过(t *testing.T) {
	nics := []netif.NIC{devNIC("en0", "10.0.12.34/22")}
	src := devSources(nics, func(context.Context, identifyPlan) (askResult, error) {
		return askResult{}, nil
	})
	v, vals := runDev(t, src, `{"protocols":["netbios"],"addrs":["10.0.12.77"],"rounds":1}`)
	if v.Code != verdictNothingHeard {
		t.Fatalf("判定 = %q，想要 %q", v.Code, verdictNothingHeard)
	}
	if strings.Contains(v.Note, "四种") {
		t.Errorf("只问了一路，note 却报四种口径都没应：%s", v.Note)
	}
	if !strings.Contains(v.Note, "netbios") {
		t.Errorf("note 没点名问过的是哪一路：%s", v.Note)
	}
	n, names := askedProtocols(vals)
	if n != 1 || names[0] != protoNetBIOS {
		t.Errorf("问过的口径 = %d %v，想要只有 netbios", n, names)
	}
	// 四种全问时仍说「四种」：这句话在默认那一档得是原样。
	// ★ 带上点名地址，NetBIOS 那一路才有得问（它要靠另外三路先问出「谁在」）。
	v2, _ := runDev(t, devSources(nics, func(context.Context, identifyPlan) (askResult, error) {
		return askResult{}, nil
	}), `{"rounds":1,"addrs":["10.0.12.77"]}`)
	if !strings.Contains(v2.Note, "四种自报口径") {
		t.Errorf("默认四种全问，note 却换了说法：%s", v2.Note)
	}
}
