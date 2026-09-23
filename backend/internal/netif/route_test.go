package netif

import "testing"

// ★ 解析函数不带 build tag，所以在任何机器上都能把三个平台的样本一起测。

func TestParseNetstatDefault(t *testing.T) {
	// macOS `netstat -rn -f inet` 的真实样子（含表头、多行、Expire 列有时缺）
	in := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
default            10.0.0.1           UGScI          en7     59
127                127.0.0.1          UCS            lo0
`
	got := parseNetstatDefault(in, "ipv4")
	if len(got) != 2 {
		t.Fatalf("该认出 2 条 default，拿到 %d：%v", len(got), got)
	}
	if got[0].Gateway != "192.168.1.1" || got[0].Iface != "en0" || got[0].Family != "ipv4" {
		t.Errorf("第一条不对：%+v", got[0])
	}
	// 第二条带 Expire 列，Iface 仍要认成 en7 而不是把 59 当网卡
	if got[1].Gateway != "10.0.0.1" || got[1].Iface != "en7" {
		t.Errorf("带 Expire 的行认错了网卡：%+v", got[1])
	}
}

func TestParseNetstatDefaultV6Zone(t *testing.T) {
	// v6 的网关常是链路本地、带 zone；必须原样收进来
	in := `Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                       UGc             en0
`
	got := parseNetstatDefault(in, "ipv6")
	if len(got) != 1 || got[0].Gateway != "fe80::1%en0" || got[0].Iface != "en0" {
		t.Fatalf("v6 默认路由解析不对：%v", got)
	}
}

func TestParseIPRouteDefault(t *testing.T) {
	in := `default via 192.168.1.1 dev en0 proto dhcp src 192.168.1.50 metric 600
default via 10.0.0.1 dev eth1 metric 100
`
	got := parseIPRouteDefault(in, "ipv4")
	if len(got) != 2 {
		t.Fatalf("该认出 2 条，拿到 %d：%v", len(got), got)
	}
	if got[0].Gateway != "192.168.1.1" || got[0].Iface != "en0" {
		t.Errorf("第一条不对：%+v", got[0])
	}
	if got[1].Gateway != "10.0.0.1" || got[1].Iface != "eth1" {
		t.Errorf("第二条不对：%+v", got[1])
	}
}

func TestParseGetNetRoute(t *testing.T) {
	// 多条：ConvertTo-Json 给数组
	arr := `[{"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","InterfaceAlias":"Ethernet"},
{"DestinationPrefix":"::/0","NextHop":"fe80::1","InterfaceAlias":"Wi-Fi"}]`
	got := parseGetNetRoute(arr)
	if len(got) != 2 {
		t.Fatalf("该认出 2 条，拿到 %d：%v", len(got), got)
	}
	if got[0].Family != "ipv4" || got[0].Gateway != "192.168.1.1" || got[0].Iface != "Ethernet" {
		t.Errorf("v4 不对：%+v", got[0])
	}
	if got[1].Family != "ipv6" || got[1].Gateway != "fe80::1" {
		t.Errorf("v6 不对：%+v", got[1])
	}

	// 单条：ConvertTo-Json 给对象（不是数组）—— 这一支最容易漏
	one := `{"DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","InterfaceAlias":"Ethernet"}`
	if g := parseGetNetRoute(one); len(g) != 1 || g[0].Family != "ipv4" {
		t.Errorf("单条对象没认出来：%v", g)
	}

	// 空输出（没有任何默认路由）不报错、给空
	if g := parseGetNetRoute("  "); g != nil {
		t.Errorf("空输出该给 nil，拿到 %v", g)
	}
}
