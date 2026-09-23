package netif

// 给网卡设 / 撤一个静态 IPv4。各平台实现见 setaddr_<os>.go。
//
// ★★ 为什么要这个能力（2026-09-20 现场）：DHCP 服务器自己必须先有一个固定 IP。
//   而「USB 网卡插交换机、网里没人发地址」的场景里，系统只会给它一个
//   169.254 的自派地址 —— net.dhcp.defaults 会（正确地）拒绝在这种网卡上开服务，
//   但界面若只会说"请先设一个地址"，用户根本没有地方去设。这条路必须能走通。
//
// ★ 需要管理员/root 权限。拿不到就如实报错，由工具层翻成人话 ——
//   不静默失败，也不假装设上了。

// SetStaticIPv4 给一块网卡设静态 IPv4（幂等：已有同地址的平台上直接覆盖）。
func SetStaticIPv4(iface, ip string, prefix int) error { return setStaticIPv4(iface, ip, prefix) }

// UnsetStaticIPv4 撤掉设上去的静态 IPv4，恢复自动获取（还原用）。
func UnsetStaticIPv4(iface, ip string, prefix int) error { return unsetStaticIPv4(iface, ip, prefix) }
