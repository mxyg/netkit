package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Transfer 一次文件传输的结果。
type Transfer struct {
	Local       string  `json:"local"`
	Remote      string  `json:"remote"`
	Bytes       int64   `json:"bytes"`       // 本次实际传的字节数
	Total       int64   `json:"total"`       // 文件总大小
	ResumedFrom int64   `json:"resumedFrom"` // 断点续传：从哪儿接着传的（0 = 从头）
	SHA256      string  `json:"sha256"`      // 本地算的整包校验和
	Verified    string  `json:"verified"`    // 对端复核结果：match / mismatch / unavailable
	Seconds     float64 `json:"seconds"`
}

// Push 把本机文件送到设备上（docs/设计.md「软件分发 · 文件传输」）。
//
// 硬要求逐条落地：
//   - **断点续传**：对端已有半截文件就从那个长度接着传（半截比目标还大则重传）
//   - **整包校验**：本地算 SHA256；传完在对端复核（sha256sum / certutil），
//     复核不了就如实说 unavailable，**不假装校验过**
//   - 目标目录不存在就建（装软件送的包常在不存在的路径上）
func Push(ctx context.Context, c *ssh.Client, x SSHExecer, d *Device, local, remote string) (*Transfer, error) {
	fi, err := os.Stat(local)
	if err != nil {
		return nil, fmt.Errorf("本地文件打不开：%w", err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s 是目录 —— 目录传输还没做，先打包成单个文件", local)
	}
	sc, err := sftp.NewClient(c)
	if err != nil {
		return nil, fmt.Errorf("设备 %s 没开 SFTP 子系统（OpenSSH 默认带；老设备可能只有 SCP）：%w", d.ID, err)
	}
	defer sc.Close()

	if dir := path.Dir(remote); dir != "" && dir != "." {
		if err := sc.MkdirAll(dir); err != nil {
			return nil, fmt.Errorf("在对端建目录 %s 失败：%w", dir, err)
		}
	}
	lf, err := os.Open(local)
	if err != nil {
		return nil, err
	}
	defer lf.Close()

	// 断点：对端已有的半截文件
	var resume int64
	if rfi, serr := sc.Stat(remote); serr == nil && rfi.Size() > 0 {
		if rfi.Size() >= fi.Size() {
			// 已经齐了（甚至更大）——不续传，让校验说话
			resume = 0
		} else {
			resume = rfi.Size()
		}
	}

	// ★ 不用 O_APPEND 续传：SSH_FXF_APPEND 各实现对得不齐（有的服务端直接忽略，
	//   写会从 0 开始把前半截盖掉）。显式 Seek 到断点再写，语义不靠协议旗标。
	rf, err := sc.OpenFile(remote, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return nil, fmt.Errorf("在对端打开 %s 失败：%w", remote, err)
	}
	defer rf.Close()
	if resume > 0 {
		if _, err := rf.Seek(resume, io.SeekStart); err != nil {
			return nil, fmt.Errorf("对端文件定位到断点 %d 失败：%w", resume, err)
		}
	} else if err := rf.Truncate(0); err != nil {
		return nil, fmt.Errorf("清空对端旧文件失败：%w", err)
	}

	start := time.Now()
	h := sha256.New()
	var sent int64
	if resume > 0 {
		// 续传：前半截也要进校验和 —— 校验的是**整包**，不是这一段
		if _, err := lf.Seek(resume, io.SeekStart); err != nil {
			return nil, err
		}
		if _, err := io.Copy(h, io.LimitReader(newSectionReader(local), resume)); err != nil {
			return nil, err
		}
	}
	sent, err = io.Copy(io.MultiWriter(rf, h), lf)
	if err != nil {
		return nil, fmt.Errorf("传到 %d/%d 字节时断了（%s）—— 再跑一次会从断点接着传",
			resume+sent, fi.Size(), err)
	}
	t := &Transfer{
		Local: local, Remote: remote,
		Bytes: sent, Total: fi.Size(), ResumedFrom: resume,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Seconds: time.Since(start).Seconds(),
	}
	t.Verified = verifyRemote(ctx, x, d, remote, t.SHA256)
	return t, nil
}

// Pull 把设备上的文件拉回来（日志、诊断包、崩溃转储 —— 双向是硬要求）。
func Pull(ctx context.Context, c *ssh.Client, x SSHExecer, d *Device, remote, local string) (*Transfer, error) {
	sc, err := sftp.NewClient(c)
	if err != nil {
		return nil, fmt.Errorf("设备 %s 没开 SFTP 子系统：%w", d.ID, err)
	}
	defer sc.Close()

	rfi, err := sc.Stat(remote)
	if err != nil {
		return nil, fmt.Errorf("对端没有 %s 这个文件（或没权限读）：%w", remote, err)
	}
	if rfi.IsDir() {
		return nil, fmt.Errorf("%s 是目录 —— 目录传输还没做，先在对端打包成单个文件", remote)
	}
	if dir := filepath.Dir(local); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	var resume int64
	if lfi, lerr := os.Stat(local); lerr == nil && lfi.Size() > 0 && lfi.Size() < rfi.Size() {
		resume = lfi.Size()
	}
	rf, err := sc.Open(remote)
	if err != nil {
		return nil, err
	}
	defer rf.Close()
	if resume > 0 {
		if _, err := rf.Seek(resume, io.SeekStart); err != nil {
			return nil, err
		}
	}
	flags := os.O_WRONLY | os.O_CREATE
	if resume > 0 {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	lf, err := os.OpenFile(local, flags, 0o644)
	if err != nil {
		return nil, err
	}
	defer lf.Close()

	start := time.Now()
	sent, err := io.Copy(lf, rf)
	if err != nil {
		return nil, fmt.Errorf("拉到 %d/%d 字节时断了（%s）—— 再跑一次会从断点接着拉",
			resume+sent, rfi.Size(), err)
	}
	t := &Transfer{
		Local: local, Remote: remote,
		Bytes: sent, Total: rfi.Size(), ResumedFrom: resume,
		Seconds: time.Since(start).Seconds(),
	}
	// 校验：拉回来后本地算整包 SHA256，和对端算的比
	t.SHA256, err = fileSHA256(local)
	if err != nil {
		return t, nil
	}
	remoteSum := remoteSHA256(ctx, x, d, remote)
	switch {
	case remoteSum == "":
		t.Verified = "unavailable"
	case strings.EqualFold(remoteSum, t.SHA256):
		t.Verified = "match"
	default:
		t.Verified = "mismatch"
	}
	return t, nil
}

// verifyRemote 在对端复核整包 SHA256。
func verifyRemote(ctx context.Context, x SSHExecer, d *Device, remote, want string) string {
	got := remoteSHA256(ctx, x, d, remote)
	switch {
	case got == "":
		return "unavailable"
	case strings.EqualFold(got, want):
		return "match"
	default:
		return "mismatch"
	}
}

// remoteSHA256 让对端自己算一遍校验和。Windows 用 certutil，Unix 用 sha256sum。
// 算不出来返回空串 —— 调用方如实报 unavailable，不假装校验过。
func remoteSHA256(ctx context.Context, x SSHExecer, d *Device, remote string) string {
	var cmd string
	if d.OS == "windows" {
		cmd = fmt.Sprintf("certutil -hashfile %s SHA256", winQuote(remote))
	} else {
		cmd = "sha256sum " + shellQuote(remote)
	}
	out, err := x.Exec(ctx, d, cmd, 2*time.Minute)
	if err != nil || out.ExitCode != 0 {
		return ""
	}
	for _, f := range strings.Fields(out.Stdout) {
		if len(f) == 64 && isHex(f) {
			return strings.ToLower(f)
		}
	}
	return ""
}

func winQuote(p string) string {
	if strings.ContainsAny(p, " &()") {
		return `"` + p + `"`
	}
	return p
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// newSectionReader 从头重读一个文件（续传时给前半截算校验和用）。
func newSectionReader(p string) io.Reader {
	f, err := os.Open(p)
	if err != nil {
		return strings.NewReader("")
	}
	return &closingReader{f: f}
}

type closingReader struct{ f *os.File }

func (c *closingReader) Read(p []byte) (int, error) {
	n, err := c.f.Read(p)
	if err == io.EOF {
		c.f.Close()
	}
	return n, err
}
