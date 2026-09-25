package snmp

// 起口的那一条栈跟着设备走（dialLocked）。
//
// ★ 这几条钉的是「口开成哪一族」，不是报文内容 —— 所以必须伸进包里看那个 socket：
//
//	从外面看，v4 设备对 v4 口和对 [::] 双栈口回的话一模一样，
//	而整包跑时偶尔丢的那一包，恰恰只走在这条 v4 映射的路上的那一跳。

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func dialed(t *testing.T, c *Client) *net.UDPAddr {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, _, err := c.dialLocked()
	if err != nil {
		t.Fatalf("起口就失败了：%v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("本地地址不是 UDP 地址：%v", conn.LocalAddr())
	}
	return la
}

func Test问v4设备时起的是真v4口(t *testing.T) {
	// Go 拿到 "udp" + wildcard 开的是 [::]:port 双栈口，报回来的 IP 是 16 字节的 v4-in-v6；
	// 那种口问 v4 设备要走 v4 映射那一条路。这一条就是不许再走它。
	la := dialed(t, &Client{Addr: "127.0.0.1:161", Community: "public"})
	if len(la.IP) != net.IPv4len || la.IP.To4() == nil {
		t.Errorf("本机口是 %v（IP %d 字节）—— 这不是 AF_INET 口，问 v4 设备又要走映射那条路",
			la, len(la.IP))
	}
	if !la.IP.Equal(net.IPv4zero) {
		t.Errorf("没指定本机地址时该绑 v4 的 wildcard，得到的是 %v", la.IP)
	}
}

func Test问v6设备时起的是v6口(t *testing.T) {
	la := dialed(t, &Client{Addr: "[::1]:161", Community: "public"})
	if la.IP.To4() != nil {
		t.Errorf("本机口是 %v —— v6 设备要开 udp6，别拿 v4 口去问它", la)
	}
	if !la.IP.IsUnspecified() {
		t.Errorf("没指定本机地址时该绑 v6 的 wildcard，得到的是 %v", la.IP)
	}
}

func Test指定了本机地址时口就开在那个地址上(t *testing.T) {
	// 外面那条「绑了回环反而问不通」的测试分不出绑与没绑（wildcard 也问得通回环设备），
	// 而多网卡机器上指定的意义正是「别从办公口/公网口去问这台设备」。
	la := dialed(t, &Client{Addr: "127.0.0.1:161", LocalAddr: "127.0.0.1", Community: "public"})
	if la.IP.String() != "127.0.0.1" {
		t.Errorf("指定了 127.0.0.1，口却开在 %v 上", la.IP)
	}
}

func Test本机地址和设备不同栈时当场说清(t *testing.T) {
	// 症状必须是「地址写错了」，不是「设备没回话」：这一问出得去回不来，
	// 而界面上那句「没回话」会把人支去查一个根本没挡着的防火墙。
	c := &Client{
		Addr: "127.0.0.1:161", LocalAddr: "::1",
		Community: "public", Timeout: 80 * time.Millisecond,
	}
	_, err := c.Get(context.Background(), "1.3.6.1.2.1.1.1.0")
	if err == nil {
		t.Fatal("v6 的本机地址去问 v4 的设备，不该问成「成功」")
	}
	if errors.Is(err, ErrNoReply) {
		t.Errorf("等成了「设备没回话」：%v —— 两栈对不上是起口之前就知道的事", err)
	}
	for _, want := range []string{"IPv4", "IPv6"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("那句话没点名 %s：\n%v", want, err)
		}
	}
}
