// Package remote 是「远程设备诊断 / 远程控制 / 远程文件 / 远程桌面」共用的地基。
//
// ★★ 安全规矩（docs/设计.md「远程控制三件套」「软件分发」）：
//
//  1. 每一次连接、执行、传输都写审计日志 —— 谁、何时、对哪台、做了什么、结果如何。
//     审计独立于 remote.notify_target：**静默模式只关目标机屏幕提示，不关留痕**。
//     把两者绑在同一个开关上等于给了一个「隐身模式」，那是另一回事。
//  2. 口令与私钥只落盘在 0600 的设备登记文件里，**永远不进结果、不进日志** ——
//     结果会发给 AI（见 rtsp.go 的同一条规矩）。
//  3. 主机密钥首连记录（TOFU），之后变了就拒绝连接并说清后果 ——
//     悄悄接受变化的主机密钥等于给中间人开门。
package remote

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Config 远程功能的配置。落在 <配置目录>/remote.json。
type Config struct {
	// NotifyTarget 连接/控制时是否在目标机屏幕上给提示。
	// ★ 默认 true：装上就能被静默围观不是一个可接受的默认值。
	//   要关是使用者的明确选择（界面上会当场弹一次责任告知）。
	NotifyTarget *bool `json:"notifyTarget,omitempty"`
}

func (c Config) notify() bool {
	// 指针为空 = 用户从没动过这个开关 = 默认开
	return c.NotifyTarget == nil || *c.NotifyTarget
}

// Manager 远程功能的全部落盘状态：设备登记、配置、审计。
type Manager struct {
	dir string

	mu      sync.Mutex
	devices []*Device
	cfg     Config
}

// Open 打开（或新建）远程功能的数据目录。
func Open(dir string) (*Manager, error) {
	if dir == "" {
		return nil, fmt.Errorf("没有给远程数据目录")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("建远程数据目录失败：%w", err)
	}
	m := &Manager{dir: dir}

	if b, err := os.ReadFile(filepath.Join(dir, "devices.json")); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &m.devices); err != nil {
			return nil, fmt.Errorf("设备登记文件解不开（别删，人工看一下 %s）：%w",
				filepath.Join(dir, "devices.json"), err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "remote.json")); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &m.cfg); err != nil {
			return nil, fmt.Errorf("远程配置解不开：%w", err)
		}
	}
	return m, nil
}

// DefaultDir 用户配置目录下的默认位置。
func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "yuhox-netkit"), nil
}

// NotifyTarget 当前是否「对方可见」。
func (m *Manager) NotifyTarget() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.notify()
}

// SetNotifyTarget 改「对方可见」开关并落盘。
//
// ★ 返回改动前后的值，调用方（tools 层）拿它写审计 ——
//
//	把提示关掉是一次**要被记住**的选择，不是普通配置项。
func (m *Manager) SetNotifyTarget(v bool) (before, after bool, err error) {
	m.mu.Lock()
	before = m.cfg.notify()
	m.cfg.NotifyTarget = &v
	cfg := m.cfg
	m.mu.Unlock()
	after = v
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(m.dir, "remote.json"), b, 0o600); err != nil {
		return before, after, fmt.Errorf("写远程配置失败：%w", err)
	}
	return before, after, nil
}

// saveDevices 设备登记落盘。0600 —— 里面可能有口令。
func (m *Manager) saveDevices() error {
	b, err := json.MarshalIndent(m.devices, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(m.dir, "devices.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("写设备登记失败：%w", err)
	}
	return os.Rename(tmp, p)
}
