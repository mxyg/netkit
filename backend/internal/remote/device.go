package remote

import (
	"fmt"
	"strings"
	"time"
)

// Device 一台登记过的远程设备。
type Device struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`

	// ★ Password / KeyPassphrase 永远不出后端：不进 Public()、不进日志、不进结果。
	Password string `json:"password,omitempty"`
	// KeyPath 本机私钥路径。★ 优先用它 —— 私钥不离开这台机器，
	//   登记文件里只有一个路径，比存口令安全一个量级。
	KeyPath string `json:"keyPath,omitempty"`

	// HostKey 首连记下的服务器主机密钥（TOFU）。之后变了就拒绝连接。
	HostKey string `json:"hostKey,omitempty"`

	OS       string    `json:"os,omitempty"` // windows / linux / darwin / unknown
	Identity *Identity `json:"identity,omitempty"`
	AddedAt  time.Time `json:"addedAt"`
	LastSeen time.Time `json:"lastSeen,omitempty"`
}

// Identity 设备回报的身份。
//
// ★ 由来（docs/设计.md「设备信息自动获取」）：现场连一台 Windows，
//
//	公钥装好了、22 也通了，却因为**不知道账号名**猜了四遍全被拒。
//	连上之后这些信息必须自动拿到并显示，不让人来回传话。
type Identity struct {
	Hostname  string   `json:"hostname,omitempty"`
	User      string   `json:"user,omitempty"`
	OS        string   `json:"os,omitempty"`
	OSDetail  string   `json:"osDetail,omitempty"`
	Addrs     []string `json:"addrs,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Listening []string `json:"listening,omitempty"`
	At        string   `json:"at,omitempty"`
}

// Public 给调用方看的版本 —— 凭据字段一律抹掉。
func (d *Device) Public() map[string]any {
	out := map[string]any{
		"id": d.ID, "name": d.Name, "host": d.Host, "port": d.Port, "user": d.User,
		"auth":     authKind(d),
		"os":       d.OS,
		"addedAt":  d.AddedAt.Format(time.RFC3339),
		"identity": d.Identity,
	}
	if !d.LastSeen.IsZero() {
		out["lastSeen"] = d.LastSeen.Format(time.RFC3339)
	}
	if d.HostKey != "" {
		out["hostKeyKnown"] = true
	}
	return out
}

func authKind(d *Device) string {
	switch {
	case d.KeyPath != "" && d.Password != "":
		return "key+password"
	case d.KeyPath != "":
		return "key"
	case d.Password != "":
		return "password"
	}
	return "none"
}

// AddDevice 登记一台设备。host+user 相同的算同一台，覆盖更新。
func (m *Manager) AddDevice(d Device) (*Device, error) {
	if d.Host == "" || d.User == "" {
		return nil, fmt.Errorf("host 和 user 都得给 —— 现场那次猜账号名的教训，账号不能空着让人猜")
	}
	if d.Port == 0 {
		d.Port = 22
	}
	d.ID = deviceID(d.Host, d.User)
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.devices {
		if x.ID == d.ID {
			// 覆盖更新，但**没给新凭据就保留旧的** —— 改个名字不该把口令丢了
			if d.Password == "" {
				d.Password = x.Password
			}
			if d.KeyPath == "" {
				d.KeyPath = x.KeyPath
			}
			if d.HostKey == "" {
				d.HostKey = x.HostKey
			}
			if d.AddedAt.IsZero() {
				d.AddedAt = x.AddedAt
			}
			d.Identity, d.OS, d.LastSeen = x.Identity, x.OS, x.LastSeen
			m.devices[i] = &d
			return &d, m.saveDevices()
		}
	}
	if d.AddedAt.IsZero() {
		d.AddedAt = time.Now()
	}
	m.devices = append(m.devices, &d)
	return &d, m.saveDevices()
}

// Devices 全部设备（公开版本，无凭据）。
func (m *Manager) Devices() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]map[string]any, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, d.Public())
	}
	return out
}

// Get 按 ID 或 host 找设备。找不到报错并列出登记过的 ——
// 让人不用翻文件就知道该填什么。
func (m *Manager) Get(idOrHost string) (*Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.devices {
		if d.ID == idOrHost || d.Host == idOrHost {
			cp := *d
			return &cp, nil
		}
	}
	known := make([]string, 0, len(m.devices))
	for _, d := range m.devices {
		known = append(known, d.ID)
	}
	if len(known) == 0 {
		return nil, fmt.Errorf("没有登记过任何设备（用 remote.device.add 先登记）")
	}
	return nil, fmt.Errorf("没有叫 %s 的设备；登记过的有：%s", idOrHost, strings.Join(known, "、"))
}

// UpdateDevice 把连接后拿到的信息（主机密钥、身份、OS）写回登记。
func (m *Manager) UpdateDevice(d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.devices {
		if x.ID == d.ID {
			d.AddedAt = x.AddedAt
			if d.Password == "" {
				d.Password = x.Password
			}
			m.devices[i] = d
			return m.saveDevices()
		}
	}
	return fmt.Errorf("登记里没有 %s 这台设备", d.ID)
}

// RemoveDevice 删掉一台设备的登记（不碰设备本身）。
func (m *Manager) RemoveDevice(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.devices {
		if d.ID == id || d.Host == id {
			m.devices = append(m.devices[:i], m.devices[i+1:]...)
			return m.saveDevices()
		}
	}
	return fmt.Errorf("登记里没有 %s 这台设备", id)
}

// deviceID 稳定 ID：user@host。同一台设备重复登记要落在同一个 ID 上。
func deviceID(host, user string) string {
	return user + "@" + host
}
