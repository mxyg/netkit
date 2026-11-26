package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/remote"
)

// ═══════════════════════════════════════════════════════════════════════
// 远端文件系统浏览（remote.file.list / mkdir / remove / rename）
//
// 为什么必须有：remote.file.push/pull 是「盲传」—— 路径填错只会失败，
// 不知道远端长什么样。浏览是传文件的前半件事。
//
// list 是只读；mkdir / remove / rename 改的是**别人的文件系统** → mutate，
// 每次批准框里写明动哪个路径，全程审计。删东西永远不递归猜：要删整个
// 目录必须显式 recursive=true，且批准框里写清「连里面的 N 项一起删」。
// ═══════════════════════════════════════════════════════════════════════

// sftpOf 连一台设备的 SFTP。★ 调用方负责 close 两个返回值。
func sftpOf(ctx context.Context, device string) (*remote.Device, *ssh.Client, *sftp.Client, error) {
	d, c, _, err := dial(ctx, device)
	if err != nil {
		return nil, nil, nil, err
	}
	cl, err := sftp.NewClient(c)
	if err != nil {
		c.Close()
		return nil, nil, nil, ots.Errf(ots.ErrNotSupported, "对端不开 SFTP 子系统（多数 OpenSSH 都开）：%s", err)
	}
	return d, c, cl, nil
}

type fileEntry struct {
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	MTime string `json:"mtime"`
}

// ── remote.file.list（read）──

var fileListTool = ots.Tool{
	Name:  "remote.file.list",
	Class: ots.ClassRead,
	Summary: "看远端一个目录里有什么（名字、大小、权限、修改时间，目录排前）。" +
		"这是 remote.file.push/pull 的眼睛 —— 先看再传，不再盲传。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device"],
	  "properties": {
	    "device": {"type": "string"},
	    "path": {"type": "string", "description": "目录路径。不填 = 登录账号的家目录（.）"}
	  }
	}`),
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device string
			Path   string
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		p := a.Path
		if p == "" {
			p = "."
		}
		d, c, cl, err := sftpOf(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		defer cl.Close()

		infos, err := cl.ReadDir(p)
		if err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "读不了 %s（多半是路径不存在或没权限）：%s", p, err)
		}
		entries := make([]fileEntry, 0, len(infos))
		for _, fi := range infos {
			entries = append(entries, fileEntry{
				Name:  fi.Name(),
				Dir:   fi.IsDir(),
				Size:  fi.Size(),
				Mode:  fi.Mode().String(),
				MTime: fi.ModTime().Format("2006-01-02 15:04"),
			})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Dir != entries[j].Dir {
				return entries[i].Dir // 目录排前
			}
			return entries[i].Name < entries[j].Name
		})
		home := "."
		if wd, err := cl.Getwd(); err == nil {
			home = wd
		}
		return map[string]any{
			"device":  d.ID,
			"path":    p,
			"home":    home,
			"entries": entries,
			"count":   len(entries),
		}, nil
	},
}

// ── remote.file.mkdir（mutate）──

var fileMkdirTool = ots.Tool{
	Name:  "remote.file.mkdir",
	Class: ots.ClassMutate,
	Summary: "在远端建目录（连带父目录一起建，MkdirAll 语义）。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device", "path"],
	  "properties": {"device": {"type": "string"}, "path": {"type": "string"}}
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Device, Path string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("在设备 %s 上建目录：%s（父目录缺就一起建）", a.Device, a.Path)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ Device, Path string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if strings.TrimSpace(a.Path) == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument, "path 不能是空的")
		}
		d, c, cl, err := sftpOf(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		defer cl.Close()
		if fi, err := cl.Stat(a.Path); err == nil {
			return ots.Verdict{Code: "exists",
				Note: fmt.Sprintf("%s 已经在了（%s）", a.Path, modeWord(fi.IsDir()))}, nil
		}
		if err := sftpMkdirAll(cl, a.Path); err != nil {
			mgr.Audit(ots.CallerFrom(ctx), "file.mkdir", d.ID, a.Path, "failed: "+err.Error())
			return nil, ots.Errf(ots.ErrPermissionRequired, "建不了 %s（多半是没写权限）：%s", a.Path, err)
		}
		mgr.Audit(ots.CallerFrom(ctx), "file.mkdir", d.ID, a.Path, "ok")
		return ots.Verdict{Code: "created", Note: "已建 " + a.Path}, nil
	},
}

// ── remote.file.remove（mutate）──

var fileRemoveTool = ots.Tool{
	Name:  "remote.file.remove",
	Class: ots.ClassMutate,
	Summary: "删远端的一个文件或目录。★ 目录**不递归不删** —— 要连里面的东西一起删必须 recursive=true，" +
		"批准框会把要删的项数写出来。删完不可恢复。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device", "path"],
	  "properties": {
	    "device": {"type": "string"},
	    "path": {"type": "string"},
	    "recursive": {"type": "boolean", "description": "目录非空时必须 true 才删（连里面的项一起）"}
	  }
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct {
			Device, Path string
			Recursive    bool
		}
		_ = json.Unmarshal(nonEmpty(raw), &a)
		if a.Recursive {
			return fmt.Sprintf("删设备 %s 上的 %s —— **连目录里所有东西一起删**（不可恢复）", a.Device, a.Path)
		}
		return fmt.Sprintf("删设备 %s 上的 %s（目录非空就报错，不动里面的东西）", a.Device, a.Path)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct {
			Device, Path string
			Recursive    bool
		}
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if strings.TrimSpace(a.Path) == "" || a.Path == "/" || a.Path == "." {
			return nil, ots.Errf(ots.ErrInvalidArgument, "path 必须指到一个具体文件/目录 —— 不删模糊路径")
		}
		d, c, cl, err := sftpOf(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		defer cl.Close()

		fi, err := cl.Stat(a.Path)
		if err != nil {
			return ots.Verdict{Code: "not-found", Note: a.Path + " 本来就不在了"}, nil
		}
		n := 1
		if fi.IsDir() && a.Recursive {
			if n, err = sftpCount(cl, a.Path); err != nil {
				return nil, ots.Errf(ots.ErrInternal, "数不清里面有什么：%s", err)
			}
			if err := sftpRemoveAll(cl, a.Path); err != nil {
				mgr.Audit(ots.CallerFrom(ctx), "file.remove", d.ID,
					fmt.Sprintf("%s（recursive，%d 项）", a.Path, n), "failed: "+err.Error())
				return nil, ots.Errf(ots.ErrPermissionRequired, "删不动（多半是没写权限）：%s", err)
			}
		} else if fi.IsDir() {
			if err := cl.RemoveDirectory(a.Path); err != nil {
				mgr.Audit(ots.CallerFrom(ctx), "file.remove", d.ID, a.Path, "failed: "+err.Error())
				return nil, ots.Errf(ots.ErrInvalidArgument,
					"%s 是个非空目录 —— 要连里面的东西一起删，带 recursive=true 再来（那是不可恢复的）", a.Path)
			}
		} else {
			if err := cl.Remove(a.Path); err != nil {
				mgr.Audit(ots.CallerFrom(ctx), "file.remove", d.ID, a.Path, "failed: "+err.Error())
				return nil, ots.Errf(ots.ErrPermissionRequired, "删不动（多半是没写权限）：%s", err)
			}
		}
		mgr.Audit(ots.CallerFrom(ctx), "file.remove", d.ID,
			fmt.Sprintf("%s（%s，%d 项）", a.Path, modeWord(fi.IsDir()), n), "ok")
		return ots.Verdict{Code: "removed", Note: fmt.Sprintf("已删 %s（%s，%d 项）", a.Path, modeWord(fi.IsDir()), n)}, nil
	},
}

// ── remote.file.rename（mutate）──

var fileRenameTool = ots.Tool{
	Name:  "remote.file.rename",
	Class: ots.ClassMutate,
	Summary: "远端改名/挪位置（同盘 rename）。目标名已存在时拒绝 —— 不悄悄覆盖。",
	Schema: json.RawMessage(`{
	  "type": "object", "additionalProperties": false, "required": ["device", "from", "to"],
	  "properties": {"device": {"type": "string"}, "from": {"type": "string"}, "to": {"type": "string"}}
	}`),
	Describe: func(raw json.RawMessage) string {
		var a struct{ Device, From, To string }
		_ = json.Unmarshal(nonEmpty(raw), &a)
		return fmt.Sprintf("在设备 %s 上把 %s 改名为 %s", a.Device, a.From, a.To)
	},
	Invoke: func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := needRemote(); err != nil {
			return nil, err
		}
		var a struct{ Device, From, To string }
		if err := json.Unmarshal(nonEmpty(raw), &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
		if strings.TrimSpace(a.From) == "" || strings.TrimSpace(a.To) == "" {
			return nil, ots.Errf(ots.ErrInvalidArgument, "from / to 都不能是空的")
		}
		d, c, cl, err := sftpOf(ctx, a.Device)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		defer cl.Close()
		if _, err := cl.Stat(a.To); err == nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s 已经有同名目标 —— 不悄悄覆盖，换个名字", a.To)
		}
		if _, err := cl.Lstat(a.From); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "%s 不存在：%s", a.From, err)
		}
		if err := cl.PosixRename(a.From, a.To); err != nil {
			// PosixRename 不被支持的文件系统退回纯 rename（不能跨盘）
			if err2 := cl.Rename(a.From, a.To); err2 != nil {
				mgr.Audit(ots.CallerFrom(ctx), "file.rename", d.ID, a.From+" → "+a.To, "failed: "+err2.Error())
				return nil, ots.Errf(ots.ErrPermissionRequired, "改不了名（多半是没权限或跨盘）：%s", err2)
			}
		}
		mgr.Audit(ots.CallerFrom(ctx), "file.rename", d.ID, a.From+" → "+a.To, "ok")
		return ots.Verdict{Code: "renamed", Note: "已改名 " + a.From + " → " + a.To}, nil
	},
}

// ── sftp 辅助 ──

func modeWord(dir bool) string {
	if dir {
		return "目录"
	}
	return "文件"
}

// sftpMkdirAll 沿路径逐级建目录（SFTP 没有 MkdirAll，自己走一遍）。
func sftpMkdirAll(cl *sftp.Client, path string) error {
	parts := splitPath(path)
	acc := ""
	for _, part := range parts {
		if acc == "" {
			acc = part
		} else {
			acc = filepath.Join(acc, part)
		}
		// Windows 路径的反斜杠归一化
		acc = strings.ReplaceAll(acc, "\\", "/")
		if err := cl.Mkdir(acc); err != nil {
			if fi, serr := cl.Stat(acc); serr == nil && fi.IsDir() {
				continue // 已经在了
			}
			return err
		}
	}
	return nil
}

// splitPath 把绝对/相对路径拆成逐级片段，保留开头（/ 或 C:/）。
func splitPath(p string) []string {
	p = strings.ReplaceAll(p, "\\", "/")
	var out []string
	cur := ""
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			if cur != "" || i == 0 {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(p[i])
	}
	if cur != "" {
		out = append(out, cur)
	}
	if len(out) > 0 && out[0] == "" {
		out[0] = "/"
	}
	return out
}

// sftpCount 数目录里的项数（不递归进去删之前给人看个总数）。
func sftpCount(cl *sftp.Client, path string) (int, error) {
	infos, err := cl.ReadDir(path)
	if err != nil {
		return 0, err
	}
	n := len(infos)
	for _, fi := range infos {
		if fi.IsDir() {
			sub, err := sftpCount(cl, path+"/"+fi.Name())
			if err != nil {
				return n, nil // 数不清的子目录不拦人，按已数到的算
			}
			n += sub
		}
	}
	return n, nil
}

// sftpRemoveAll 递归删。★ 只在 recursive=true 且人批准后走到这里。
func sftpRemoveAll(cl *sftp.Client, path string) error {
	infos, err := cl.ReadDir(path)
	if err != nil {
		return err
	}
	for _, fi := range infos {
		p := path + "/" + fi.Name()
		if fi.IsDir() {
			if err := sftpRemoveAll(cl, p); err != nil {
				return err
			}
			if err := cl.RemoveDirectory(p); err != nil {
				return err
			}
			continue
		}
		if err := cl.Remove(p); err != nil {
			return err
		}
	}
	return cl.RemoveDirectory(path)
}
