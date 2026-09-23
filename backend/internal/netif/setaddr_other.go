//go:build !darwin && !linux && !windows

package netif

import (
	"fmt"
	"runtime"
)

func setStaticIPv4(iface, ip string, prefix int) error {
	return fmt.Errorf("在 %s 上还不会设静态地址", runtime.GOOS)
}

func unsetStaticIPv4(iface, ip string, prefix int) error {
	return fmt.Errorf("在 %s 上还不会还原地址", runtime.GOOS)
}
