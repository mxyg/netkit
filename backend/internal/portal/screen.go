package portal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// ── 主机屏幕的外送通道：截一帧 ──
//
// ★ 用系统自带的截屏路子（macOS screencapture / Windows PowerShell），不引依赖：
//   这两条在各自系统上都是**装好就有**的，而第三方截屏库在 headless/远程会话里
//   恰恰是最容易起不来的那种。
//   Linux 没有统一把握的路子，宁可不给（screenSupported=false）也不端半套。

// screenTTL 多个手机同时看时共享同一张截图：800 毫秒内的请求不再截第二次。
const screenTTL = 800 * time.Millisecond

// screenReady 这台机器上有没有那条把握的截屏路子 —— 判断本身仍是 screenSupported 那张
// OS 表，做成变量只是为了让「不支持的系统」这一档能在 mac 上也被钉住：那一条代码在这台
// 机器上永远走不到，而它是 Linux 用户唯一会看到的说法。
var screenReady = screenSupported

func (s *Service) capturedScreen(ctx context.Context) ([]byte, error) {
	s.screenMu.Lock()
	defer s.screenMu.Unlock()
	if len(s.screenCache) > 0 && time.Since(s.screenAt) < screenTTL {
		return s.screenCache, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	tmp, err := os.CreateTemp("", "netkit-screen-*.jpg")
	if err != nil {
		return nil, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := captureScreen(ctx, tmp.Name()); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("截出来的图是空的")
	}
	s.screenCache = data
	s.screenAt = time.Now()
	return data, nil
}

// captureScreen 是「往那个路径上截一帧」这只手。
//
// ★ 做成包级变量而不是函数：测试要能把它换成假采集器。真打系统截屏就得要屏幕录制
//
//	权限（没给权限时 macOS 还回你好，只是截出来是一片黑），CI 上两样都给不了。
var captureScreen = func(ctx context.Context, dst string) error {
	switch runtime.GOOS {
	case "darwin":
		// -x 不出声、-o 不带窗口阴影、全屏；jpg 比 png 小得多，外送走的就是量。
		return exec.CommandContext(ctx, "/usr/sbin/screencapture",
			"-x", "-o", "-t", "jpg", dst).Run()
	case "windows":
		cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-Command", screenScriptWindows(dst))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %s", err, firstLine(string(out)))
		}
		return nil
	}
	return fmt.Errorf("这个系统上没有把握的截屏路子")
}

// screenScriptWindows Windows 上那一串 PowerShell：单独抽出来是为了让测试能把这句话
// 读一遍 —— 真跑要等到 Windows 机器上，而路径拼接写错一个格式化动词，整条屏幕外送
// 就是死的（PowerShell 把图存到一个不存在的怪路径上，我们再去读那个空文件）。
func screenScriptWindows(dst string) string {
	ps := `Add-Type -AssemblyName System.Drawing;` +
		`$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;` +
		`$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;` +
		`$g=[System.Drawing.Graphics]::FromImage($bmp);` +
		`$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);` +
		`$bmp.Save('%s',[System.Drawing.Imaging.ImageFormat]::Jpeg);`
	return `Add-Type -AssemblyName System.Windows.Forms; ` +
		fmt.Sprintf(ps, filepath.FromSlash(dst))
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
