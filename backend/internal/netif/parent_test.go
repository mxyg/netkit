package netif

import (
	"reflect"
	"testing"
)

// 真机量回来的片段（这台 Mac 上 bridge0 下面挂着三块口）。
// ★ 逐字抄，不整理：整理过一遍就成了「我们以为的格式」。
const ifconfigWithBridge = `en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether ae:bb:cc:dd:ee:ff
	inet 192.168.0.107 netmask 0xffffff00 broadcast 192.168.0.255
	media: autoselect
	status: active
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 36:c2:40:ea:c0:00
	Configuration:
		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
		maxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
	member: en1 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 10 priority 0 path cost 0
	member: en2 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 11 priority 0 path cost 0
	member: en3 flags=3<LEARNING,DISCOVER>
	        ifmaxaddr 0 port 12 priority 0 path cost 0
awdl0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 6a:5b:4c:3d:2e:1f
`

func Test父母口桥的成员口折叠到桥上(t *testing.T) {
	got := parseIfconfigParents(ifconfigWithBridge)
	want := map[string]string{"en1": "bridge0", "en2": "bridge0", "en3": "bridge0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("折叠结果不对\n 得到 %v\n 想要 %v", got, want)
	}
}

func Test父母口没有桥时是空表而不是猜一个(t *testing.T) {
	got := parseIfconfigParents(`lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether aa:bb:cc:dd:ee:ff
`)
	if len(got) != 0 {
		t.Fatalf("没有一行 member: 却折叠出东西来：%v", got)
	}
}

// ★ 认不出的写法一律**不折叠**。这一条钉的是最坏的那种错：
// 把不认识的一行当成父子关系，等于把一块真实的物理口从图上抹掉。
func Test父母口认不出的行一律不当数(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"member 后面没有东西", "bridge0: flags=1<UP>\n\tmember:\n"},
		{"member 带尖括号（把 flags 当成了名字）", "bridge0: flags=1<UP>\n\tmember: <LEARNING>\n"},
		{"缩进里出现别的带冒号的键", "bridge0: flags=1<UP>\n\tifmaxaddr: 0\n"},
		{"顶格却没有冒号的一行（不当成新网卡）", "bridge0: flags=1<UP>\n\tmember: en1\nrandom text\n\tmember: en2\n"},
	}
	for _, c := range cases {
		got := parseIfconfigParents(c.in)
		t.Run(c.name, func(t *testing.T) {
			switch c.name {
			case "顶格却没有冒号的一行（不当成新网卡）":
				// en1 在 bridge0 段里认到了；换段那行不认，所以 en2 不该进来
				if !reflect.DeepEqual(got, map[string]string{"en1": "bridge0"}) {
					t.Fatalf("该只认到 en1：%v", got)
				}
			default:
				if len(got) != 0 {
					t.Fatalf("认不出的写法被当成了父子关系：%v", got)
				}
			}
		})
	}
}

// 桥套桥（成员本身也是个桥）：每一层各记一次，折叠按**直接**父口走。
func Test父母口两段桥各自记自己的成员(t *testing.T) {
	got := parseIfconfigParents(`bridge1: flags=1<UP>
	member: bridge0 flags=3<LEARNING,DISCOVER>
bridge0: flags=1<UP>
	member: en1 flags=3<LEARNING,DISCOVER>
`)
	want := map[string]string{"bridge0": "bridge1", "en1": "bridge0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("两段桥记错：%v", got)
	}
}
