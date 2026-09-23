//go:build !darwin && !linux && !windows

package netif

// systemDNSServers 其它平台暂不读 DNS 配置：返回空。
// 查询工具会如实说「这个平台上拿不到系统 DNS，请显式给服务器地址」。
func systemDNSServers() ([]DNSServer, error) { return nil, nil }
