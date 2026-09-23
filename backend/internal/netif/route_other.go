//go:build !darwin && !linux && !windows

package netif

// defaultRoutes 其它平台暂不读路由：返回空，体检会如实说「这个平台上拿不到默认路由」。
func defaultRoutes() ([]DefaultRoute, error) { return nil, nil }

// routes 其它平台读不到全表。★ 返回空而不是错误：调用方要的是「这台机器上读不到」
// 这个事实，好把它和「这台机器没有路由」区分开 —— 后者是个诊断结论，不能瞎给。
func routes() ([]Route, error) { return nil, nil }

// routeFor 其它平台问不到系统，调用方按表算（表也是空的，所以判定会是「读不到」）。
func routeFor(ctx context.Context, dst netip.Addr) (Route, error) {
	return Route{}, errNoRouteCmd
}
