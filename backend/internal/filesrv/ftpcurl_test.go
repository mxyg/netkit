package filesrv

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// 拿 **curl** 当独立实现互测：自己写的客户端测自己，永远只能证明自洽。
func Test用curl独立实现取一份固件(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("这台机器上没有 curl")
	}
	s, addr, _ := ftpShare(t, nil)
	out := t.TempDir()

	// 1) 列目录 + 取文件（curl 默认走 PASV）
	cmd := exec.Command("curl", "-s", "-S", "--max-time", "20",
		"-o", out+"/fw.bin", "ftp://"+addr+"/fw.bin")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("curl 取文件失败：%v\n%s", err, b)
	}
	got, err := os.ReadFile(out + "/fw.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.Repeat("Z", 4000) {
		t.Errorf("curl 取到的内容不对：%d 字节", len(got))
	}

	// 2) 列目录
	cmd = exec.Command("curl", "-s", "-S", "--max-time", "20", "ftp://"+addr+"/")
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("curl 列目录失败：%v", err)
	}
	if !strings.Contains(string(b), "fw.bin") || !strings.Contains(string(b), "tiny.bin") {
		t.Errorf("curl 看到的目录不对：%q", b)
	}

	// 3) 上传必须失败，而且本机不许多出文件
	cmd = exec.Command("curl", "-s", "-S", "--max-time", "20", "-T", out+"/fw.bin",
		"ftp://"+addr+"/up.bin")
	_ = cmd.Run()
	if _, err := os.Stat(strings.TrimSuffix(out, "/") + "/up.bin"); err == nil {
		t.Fatal("curl 的 -T 在本机落了文件")
	}
	if _, err := os.Stat(s.cfg.Root + "/up.bin"); err == nil {
		t.Error("上传被拒了，但共享目录里多出了一个文件")
	}
	if st := s.Status(); st.Denied == 0 {
		t.Error("curl 那次上传得在台账里留一笔被拒")
	}

	// 4) 取不存在的文件
	cmd = exec.Command("curl", "-s", "-S", "--max-time", "20", "ftp://"+addr+"/没有这个.bin")
	if err := cmd.Run(); err == nil {
		t.Error("取不存在的文件，curl 不该成功")
	}
}
