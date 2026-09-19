package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// ★ 解析用的是各平台命令的**真实输出样本**，不是编的格式。
func Test解析各平台的邻居表(t *testing.T) {
	t.Run("linux ip neigh", func(t *testing.T) {
		out := parseIPNeigh(`192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.99 dev eth0 FAILED
10.0.0.5 dev eth1 lladdr 11:22:33:44:55:66 STALE`, "ipv4")
		if len(out) != 3 {
			t.Fatalf("解出 %d 条：%v", len(out), out)
		}
		if out[0].MAC != "aa:bb:cc:dd:ee:ff" || out[0].Iface != "eth0" || out[0].State != "REACHABLE" {
			t.Errorf("第一条 = %+v", out[0])
		}
		// ★ FAILED 的条目要留着：「这个地址试过但没人应」本身就是线索
		if out[1].State != "FAILED" || out[1].MAC != "" {
			t.Errorf("FAILED 条目 = %+v", out[1])
		}
	})

	t.Run("macOS arp -an", func(t *testing.T) {
		out := parseArpAn(`? (192.168.2.1) at fc:fa:21:a3:34:82 on en0 ifscope [ethernet]
? (192.168.2.99) at (incomplete) on en0 [ethernet]`)
		if len(out) != 2 {
			t.Fatalf("解出 %d 条", len(out))
		}
		if out[0].Addr != "192.168.2.1" || out[0].MAC != "fc:fa:21:a3:34:82" || out[0].Iface != "en0" {
			t.Errorf("第一条 = %+v", out[0])
		}
		if out[1].MAC != "" || out[1].State != "incomplete" {
			t.Errorf("incomplete 条目不该当成有 MAC：%+v", out[1])
		}
	})

	t.Run("macOS ndp -an", func(t *testing.T) {
		out := parseNdpAn(`Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                          fc:fa:21:a3:34:82  en0   23h59m50s R  R
2408:832e::1                         d6:b0:ca:3f:e7:ab  en0   permanent R`)
		if len(out) != 2 {
			t.Fatalf("解出 %d 条：%+v", len(out), out)
		}
		// ★ 地址带 zone，接口名要从 zone 里取出来，不能手工切 %
		if out[0].Addr != "fe80::1%en0" || out[0].Iface != "en0" {
			t.Errorf("链路本地条目 = %+v", out[0])
		}
		if out[0].MAC != "fc:fa:21:a3:34:82" {
			t.Errorf("MAC = %q", out[0].MAC)
		}
	})

	t.Run("windows arp -a", func(t *testing.T) {
		out := parseWinArp(`接口: 192.168.1.10 --- 0xb
  Internet 地址         物理地址              类型
  192.168.1.1           aa-bb-cc-dd-ee-ff     动态`)
		if len(out) != 1 {
			t.Fatalf("解出 %d 条：%+v", len(out), out)
		}
		// Windows 用连字符，统一成冒号，免得同一个 MAC 出现两种写法
		if out[0].MAC != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("MAC = %q，该统一成冒号分隔", out[0].MAC)
		}
	})
}

// ★ 一族读不到不该把另一族的结果也丢掉 —— 双栈机器上 v6 那张表读不到很常见。
func Test一族读不到时另一族照常给(t *testing.T) {
	out, err := readNeighbors(context.Background(), json.RawMessage(`{"family":"ipv4"}`))
	if err != nil {
		t.Fatalf("出错：%v", err)
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, has := m["neighbors"]; !has {
		t.Fatal("没有 neighbors 字段")
	}
	for _, n := range m["neighbors"].([]any) {
		if f := n.(map[string]any)["family"]; f != "ipv4" {
			t.Errorf("只要了 ipv4 却给了 %v", f)
		}
	}
}

func Test非法family报错(t *testing.T) {
	_, err := readNeighbors(context.Background(), json.RawMessage(`{"family":"ipv7"}`))
	if err == nil || !strings.Contains(err.Error(), "invalid-argument") {
		t.Errorf("err = %v，期望 invalid-argument", err)
	}
}
