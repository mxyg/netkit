//go:build !darwin && !linux && !windows

package netif

// defaultRoutes 其它平台暂不读路由：返回空，体检会如实说「这个平台上拿不到默认路由」。
func defaultRoutes() ([]DefaultRoute, error) { return nil, nil }
