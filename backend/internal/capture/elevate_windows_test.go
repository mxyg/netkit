//go:build windows

// 提权探测那一份的测试。
//
// 那一格只被用来把错话说准（起不来时是「要去提权」还是「原样转述」），
// 不用来放行、也不用来拦路 —— 所以「它会不会拦路」在 source_windows_test.go
// 那两条（TestWin06、TestWin07）里钉； 这里只验探测本身报得准不准。
//
// 旁证用的是 net session 的退出码：那一条命令本身就要管理员才回 0，
// 跟它说什么话、系统是什么显示语言都无关。pktmon 说的话我们一个字都不判断（顶上第 7、11 条）。
package capture

import (
	"os/exec"
	"testing"
)

func TestWin23令牌提权位与net_session的退出码对得上(t *testing.T) {
	got := probeElevated()
	err := exec.Command("net", "session").Run()
	code := 0
	if err != nil {
		code = exitCode(err)
	}
	if code == 0 {
		if got != 1 {
			t.Errorf("net session 回 0（ 这一会话是管理员）， 令牌里却报 %d", got)
		}
		return
	}
	// net session 回非 0 有两种： 没提权（ 错 5）， 以及别的（ 服务没起、 账号策略）。
	// 所以这一头只挡一种错法： 把「提过权」说出去。
	if got == 1 {
		t.Errorf("令牌说提过权（ 1）， net session 却回 %d：%v", code, err)
	}
	if got == -1 {
		t.Logf("这一格问不出来（ net session 回 %d）—— 起口失败时不会因此说「要去提权」", code)
	}
}

// 只许三档：多出一个值就意味着「猜」混进来了（比如把失败当 0 填）。
func TestWin24探测只回三档(t *testing.T) {
	if got := probeElevated(); got != 1 && got != 0 && got != -1 {
		t.Errorf("探测回了 %d， 只许 1 / 0 / -1", got)
	}
}
