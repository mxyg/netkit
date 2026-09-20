package netif

import (
	"os"
	"path/filepath"
	"strings"
)

// kinds 在 Linux 上问系统：直接读 `/sys/class/net`。
//
// ★★ 这里**不起子进程**，全是读文件 —— 现场的嵌入式盒子上常常
// 没有 `iw` / `nmcli` / `ethtool`，靠命令行工具的做法在那种机器上直接失效。
// `/sys` 是内核导出的，只要跑的是 Linux 就一定在。
//
// 判据（按可靠程度从高到低）：
//
//	wireless/ 或 phy80211/ 存在     → 无线。内核只给注册了 cfg80211 的设备建这两个目录
//	device 符号链接指向 .../usb...  → USB 网卡。路径里有 usb 总线就是插在 USB 上的
//	  再看 ../uevent 里有没有蜂窝模组的痕迹 → 4G/5G 上网卡
//	device 链接不存在，且在 devices/virtual/ 下 → 虚拟（docker/veth/bridge/tun）
//	有 device 链接、又不是无线不是 USB → 有线网口
//
// ★ 「有 device 链接」这一条是**有证据的**：它意味着内核把这块网卡挂在了
// 一条真实的总线（PCI/USB/platform）上，而不是软件造出来的。
// 光看名字是 eth0 判不出这个 —— USB 网卡在不少发行版上也叫 eth0。
func kinds() map[string]string {
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, e := range ents {
		name := e.Name()
		base := filepath.Join("/sys/class/net", name)

		if exists(filepath.Join(base, "wireless")) || exists(filepath.Join(base, "phy80211")) {
			m[name] = KindWiFi
			continue
		}

		// device 是指向真实设备的符号链接。解出来的绝对路径里带总线信息。
		dev, err := filepath.EvalSymlinks(filepath.Join(base, "device"))
		if err != nil {
			// 没有 device：要么是虚拟设备，要么是回环。回环交给上层判（它有 flag）
			if link, e2 := os.Readlink(base); e2 == nil && strings.Contains(link, "devices/virtual/") {
				m[name] = KindVirtual
			}
			continue
		}
		if strings.Contains(dev, "/usb") {
			// ★ USB 网线网卡和 4G 棒都挂在 USB 上，但用途完全不同：
			//   前者是拿去接设备网的口，后者是上行出口。标成同一个，
			//   用户就分不清哪张该插交换机。靠驱动名区分。
			if cellularDriver(dev) {
				m[name] = KindCellular
			} else {
				m[name] = KindUSBLan
			}
			continue
		}
		if strings.Contains(dev, "/wwan") || strings.Contains(dev, "/mhi") {
			m[name] = KindCellular
			continue
		}
		m[name] = KindEthernet
	}
	return m
}

// cellularDriver 看这个 USB 设备用的是不是蜂窝模组 / USB 共享网络那几个驱动。
// cdc_ether 这类既可能是 4G 模组也可能是手机 USB 共享，两者都归 cellular ——
// 共同点是「上行出口」，正是用户要区分的那件事。
func cellularDriver(devPath string) bool {
	b, err := os.ReadFile(filepath.Join(devPath, "uevent"))
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	for _, d := range []string{"rndis", "cdc_ether", "cdc_ncm", "cdc_mbim", "qmi_wwan", "ipheth", "huawei_cdc"} {
		if strings.Contains(s, d) {
			return true
		}
	}
	return false
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
