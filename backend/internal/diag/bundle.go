// Package diag 是「把这一趟查到的东西打成一个能发人的包」。
//
// ★★ 为什么脱敏在这个包里做，而不是让每个工具自己注意：
//
//	包里的内容是**别处写好的文本**（网卡配置、路由表、代理设置、命令回显），
//	它们的作者只考虑过「这条结论要不要发给 AI」，没考虑过「这个包会被上传到工单系统、
//	发进微信群、给厂商售后看」。凭据漏出去的往往正是那条没人想到的。
//	所以这里对**每一段**内容都过一遍，不管是谁写的 —— 漏一次就是漏到公网上了。
//
// ★ 为什么文件名必须是 UTF-8：[已确认的历史毛病] 上一版诊断包用 GBK 存名字，
//
//	macOS/Linux 的 unzip 直接报 Illegal byte sequence —— 现场把包发回来却解不开。
//	这里写出的 zip 一律带 general purpose bit 11（UTF-8 标志），测试逐字节查那一位。
//
// ★ 为什么「读不到的项」也要进包：诊断包的价值在于**远程那个人不必再问一遍**。
//
//	安静地少一个文件，他会判成「这台没配」；写一行「这项读不到，因为…」，
//	他才知道是没权限、是没这个功能、还是真的没有。
package diag

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 限量。★ 为什么要有：这个包是要发人的 —— 微信、邮件、工单附件都有大小线，
// 而且一台机器上跑出来的文本没有上界（转发表能有好几万行）。
// 撞到线的时候**在包里写明截断了**，不许安静地少内容。
const (
	MaxSections      = 64
	MaxSectionBytes  = 512 << 10
	MaxTotalBytes    = 8 << 20
	rootDirPrefix    = "NetKit 诊断包"
	manifestName     = "00 先看这里.txt"
	machineReadName  = "结果.json"
	truncatedMarkFmt = "\n……（本节在 %d 字节处截断，原长 %d 字节：内容太长，包有大小上限）\n"
)

// Row 一项的判定，进机读清单。★ Code 保留原文（各工具自己的判定码），
// 这里不翻译、不改写 —— 翻译是界面的事。
type Row struct {
	Item    string `json:"item"`
	Code    string `json:"code"`
	Note    string `json:"note,omitempty"`
	Missing bool   `json:"missing,omitempty"`
}

// Header 包的头信息。零值可用，但 HostName/Created 空着会让远程的人分不清是哪台、哪一次。
type Header struct {
	Label     string // 文件名与根目录里的一段，如「金宇建安-盒1」
	Created   time.Time
	HostName  string
	GOOS      string
	GOARCH    string
	Version   string // NetKit 版本
	Rows      []Row
	Warnings  []string // 必须在清单里显眼写出的话（比如「这台没配 v6，别按双栈查」）
	ToolCalls int
}

// Section 一段文本。Name 是包内相对路径，允许中文与 /。
type Section struct {
	Name string
	Text string
	// Missing 为真表示这一项**没读出来**：Text 里写的是为什么读不出来。
	Missing bool
	// TruncateAt 非零时把本节限到这么长（取 Min(MaxSectionBytes, 它)）。
	TruncateAt int
}

// Result 写包的结果。
type Result struct {
	Path       string
	Entries    []string
	Bytes      int64
	Redactions map[string]int
	Truncated  []string // 哪些节被截断了
}

// DefaultDir 是包的落盘位置：用户配置目录下的 yuhox-netkit/诊断包。
//
// ★ 为什么固定、不让调用方传目录：这个工具会被 AI 调到，
//
//	能指定任意路径就等于能往启动项、计划任务目录里写文件。
//	发人的东西放在哪不该由被调用的那一方决定。
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("找不到用户配置目录：%w", err)
	}
	return filepath.Join(base, "yuhox-netkit", "诊断包"), nil
}

// Build 把若干段文本写成一个 zip，落在 dir 下面，返回绝对路径。
//
// ★ 先写 .part 再改名：界面/用户会去打开这个文件，半截的 zip 会被解压机当成坏包，
//
//	而「坏了」在诊断场景里读起来像「这台机器的结果不可信」。
func Build(dir string, h Header, secs []Section) (Result, error) {
	if len(secs) == 0 {
		return Result{}, errors.New("一个内容都没有，不出包：空的诊断包会让人以为这台机器什么都没查到")
	}
	if len(secs) > MaxSections {
		return Result{}, fmt.Errorf("内容有 %d 段，超过上限 %d 段 —— 诊断包不是日志倾倒", len(secs), MaxSections)
	}
	label := CleanName(h.Label)
	if label == "" {
		label = "本机"
	}
	root := rootDirPrefix + " " + label
	created := h.Created
	if created.IsZero() {
		created = time.Now()
	}

	// 名字先全部算出来查重：撞名必须报错，不能静默覆盖 ——
	// 覆盖掉的那一项在包里根本不存在，而清单会说他存在。
	seen := map[string]bool{}
	files := make([][2]string, 0, len(secs)+2)
	redactions := map[string]int{}
	truncated := []string{}
	var total int

	manifestRows := make([]string, 0, len(secs))
	for _, s := range secs {
		name, err := cleanSection(s.Name, root)
		if err != nil {
			return Result{}, err
		}
		if seen[name] {
			return Result{}, fmt.Errorf("包里有两段都叫 %s：后一段会把前一段顶掉，而那种丢法在包里看不出来", name)
		}
		seen[name] = true

		text := s.Text
		if text == "" {
			text = "（空）"
		}
		limit := MaxSectionBytes
		if s.TruncateAt > 0 && s.TruncateAt < limit {
			limit = s.TruncateAt
		}
		if n := len([]byte(text)); n > limit {
			text = cutAtRune(text, limit) + fmt.Sprintf(truncatedMarkFmt, limit, n)
			truncated = append(truncated, s.Name)
		}
		scrubbed, hits := Scrub(text)
		for k, v := range hits {
			redactions[k] += v
		}
		if s.Missing {
			scrubbed = "★ 这一项没读出来。下面写的是为什么 —— 不要把它当成「这台机器上没有」。\n\n" + scrubbed
		}
		files = append(files, [2]string{name, scrubbed})
		total += len(scrubbed)
		mark := ""
		if s.Missing {
			mark = "（没读出来）"
		}
		manifestRows = append(manifestRows, fmt.Sprintf("  %s%s", strings.TrimPrefix(name, root+"/"), mark))
	}
	if total > MaxTotalBytes {
		return Result{}, fmt.Errorf("内容合计 %d 字节，超过整包上限 %d 字节", total, MaxTotalBytes)
	}

	manifest := manifestText(h, label, created, manifestRows, redactions, truncated)
	jsonBlob, err := machineReadable(h, label, created, files, redactions, truncated)
	if err != nil {
		return Result{}, err
	}
	// 清单排最前：解压出来的第一眼看的是它。
	out := make([][2]string, 0, len(files)+2)
	out = append(out, [2]string{root + "/" + manifestName, manifest})
	out = append(out, files...)
	out = append(out, [2]string{root + "/" + machineReadName, jsonBlob})

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("建输出目录 %s：%w", dir, err)
	}
	path, err := uniquePath(dir, label, created)
	if err != nil {
		return Result{}, err
	}
	part := path + ".part"
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("建 %s：%w", part, err)
	}
	zw := zip.NewWriter(f)
	entries := make([]string, 0, len(out))
	var written int64
	for _, e := range out {
		// 目录项显式写出来：不写，部分解压工具（和 Windows 上的一些老资源管理器）
		// 会按名字顺序把文件挤到一起，看起来像少了层级。
		for _, d := range dirsOf(e[0]) {
			if err := writeEntry(zw, d, "", created); err != nil {
				f.Close()
				os.Remove(part)
				return Result{}, err
			}
		}
		if err := writeEntry(zw, e[0], e[1], created); err != nil {
			f.Close()
			os.Remove(part)
			return Result{}, err
		}
		written += int64(len(e[1]))
		entries = append(entries, e[0])
	}
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(part)
		return Result{}, fmt.Errorf("收尾 zip：%w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return Result{}, fmt.Errorf("落盘：%w", err)
	}
	if err := os.Rename(part, path); err != nil {
		return Result{}, fmt.Errorf("把写完的包挪到 %s：%w", path, err)
	}
	return Result{Path: path, Entries: entries, Bytes: written,
		Redactions: redactions, Truncated: truncated}, nil
}

// writeEntry 写一个条目。★ 名字直接给 zip.Writer：它会在含非 ASCII 时自动置
// general purpose bit 11（UTF-8 标志）—— 测试从字节层面确认那一位真的在。
func writeEntry(zw *zip.Writer, name, text string, when time.Time) error {
	fh := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: when,
	}
	if strings.HasSuffix(name, "/") {
		fh.SetMode(os.ModeDir | 0o755)
		fh.Method = zip.Store
	} else {
		fh.SetMode(0o644)
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		return fmt.Errorf("写 %s：%w", name, err)
	}
	if text == "" {
		return nil
	}
	if _, err := io.WriteString(w, text); err != nil {
		return fmt.Errorf("写 %s 的内容：%w", name, err)
	}
	return nil
}

// dirsOf 一个条目路径上所有父目录（zip 里目录就是名字以 / 结尾的条目）。
func dirsOf(name string) []string {
	var ds []string
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts)-1; i++ {
		ds = append(ds, strings.Join(parts[:i+1], "/")+"/")
	}
	return ds
}

// manifestText 是包里第一眼看的那一页。
func manifestText(h Header, label string, created time.Time, rows []string,
	red map[string]int, trunc []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "NetKit 诊断包\n")
	fmt.Fprintf(&b, "==============\n\n")
	fmt.Fprintf(&b, "打出来的时间：%s\n", created.Format("2006-01-02 15:04:05 -0700"))
	if h.HostName != "" {
		fmt.Fprintf(&b, "机器名：%s\n", h.HostName)
	}
	if h.GOOS != "" || h.GOARCH != "" {
		fmt.Fprintf(&b, "系统：%s/%s\n", h.GOOS, h.GOARCH)
	}
	if h.Version != "" {
		fmt.Fprintf(&b, "NetKit 版本：%s\n", h.Version)
	}
	if label != "" {
		fmt.Fprintf(&b, "标签：%s\n", label)
	}
	fmt.Fprintf(&b, "查了的项数：%d\n\n", len(h.Rows))

	b.WriteString("【先说清楚的两件事】\n")
	b.WriteString("1. 这个包「发出去就等于把这些信息给了对方」：里面有内网地址、机器名、\n")
	b.WriteString("   网卡名、路由表、进程名。发之前请过一眼。\n")
	fmt.Fprintf(&b, "2. 口令、团体名、令牌、私钥这类东西已经抹掉（见下一节）。抹掉的地方\n")
	b.WriteString("   留了键名，所以「配了但没给你看」和「没配」在包里是分得开的。\n\n")

	b.WriteString("【脱敏】\n  " + HitList(red) + "\n")
	if len(trunc) > 0 {
		b.WriteString("\n【被截断的节】（原文太长，包有大小上限；要看全文请用对应的工具单独再查一次）\n")
		for _, t := range trunc {
			fmt.Fprintf(&b, "  %s\n", t)
		}
	}
	if len(h.Warnings) > 0 {
		b.WriteString("\n【看每一项之前要知道的】\n")
		for _, w := range h.Warnings {
			fmt.Fprintf(&b, "  ★ %s\n", plain(w))
		}
	}
	if len(h.Rows) > 0 {
		b.WriteString("\n【每一项的判定】\n")
		for _, r := range h.Rows {
			mark := ""
			if r.Missing {
				mark = "（没读出来）"
			}
			if r.Note == "" {
				fmt.Fprintf(&b, "  %-22s %s%s\n", r.Item, r.Code, mark)
			} else {
				fmt.Fprintf(&b, "  %-22s %s%s —— %s\n", r.Item, r.Code, mark, plain(r.Note))
			}
		}
	}
	b.WriteString("\n【包里有什么】\n")
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	return b.String()
}

// plain 把工具判定里那对手抄记号去掉。
//
// ★ 为什么要去掉：工具的 Note 里用 ** 强调，是因为界面上会把它渲染成粗体；
//
//	清单是记事本里看的纯文本，留着就成了一对压在字中间的星号。
func plain(s string) string {
	return strings.ReplaceAll(s, "**", "")
}

// machineReadable 一份机读的：另一个 NetKit（或脚本）拿它能直接判，不必读中文文本。
func machineReadable(h Header, label string, created time.Time,
	files [][2]string, red map[string]int, trunc []string) (string, error) {
	type fileOut struct {
		Name   string `json:"name"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	out := make([]fileOut, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256([]byte(f[1]))
		out = append(out, fileOut{Name: f[0], Bytes: len(f[1]), SHA256: hex.EncodeToString(sum[:])})
	}
	doc := map[string]any{
		"kind":          "netkit.diag.bundle",
		"label":         label,
		"created":       created.Format(time.RFC3339),
		"hostname":      h.HostName,
		"goos":          h.GOOS,
		"goarch":        h.GOARCH,
		"version":       h.Version,
		"items":         h.Rows,
		"files":         out,
		"redacted":      red,
		"truncated":     trunc,
		"warnings":      h.Warnings,
		"toolCalls":     h.ToolCalls,
		"filenames":     "utf-8（general purpose bit 11 已置位）",
		"redactionNote": "口令/团体名/令牌/私钥已抹掉；键名保留，所以「配了但没给你看」与「没配」分得开",
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("写 %s：%w", machineReadName, err)
	}
	return string(blob) + "\n", nil
}

// uniquePath 算输出路径，撞了就加 -2、-3。
//
// ★ 为什么不覆盖：上一次那份可能已经发出去了、或者正在被人解压。
func uniquePath(dir, label string, created time.Time) (string, error) {
	base := fmt.Sprintf("NetKit 诊断包 %s %s", label, created.Format("20060102-150405"))
	if len([]byte(base)) > 120 {
		base = cutAtRune(base, 120)
	}
	for i := 1; i <= 50; i++ {
		name := base + ".zip"
		if i > 1 {
			name = fmt.Sprintf("%s-%d.zip", base, i)
		}
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return p, nil
		}
	}
	return "", errors.New("同一秒里已经有 50 个包了，先停一停")
}

// CleanName 把「用户/AI 给的一段话」洗成一个安全的文件名片段：
// 去掉路径分隔符、控制字符、Windows 保留字符与非法结尾。
//
// ★ 中文留着：这个产品的用户就是中文环境，包名里写「金宇建安-盒1」比写
//
//	jinyu-01 有用得多 —— 但正因为允许中文，才必须确认 zip 里那位 UTF-8 flag。
func CleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return ' '
		case r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' ||
			r == '"' || r == '<' || r == '>' || r == '|' || r == 0x2026:
			return ' '
		}
		return r
	}, s)
	keep := make([]string, 0, 4)
	for _, f := range strings.Fields(s) {
		if strings.Trim(f, ".") == "" {
			continue // 光一串点：要么是上级目录，要么是想把文件名糊成 ".zip"
		}
		keep = append(keep, strings.Trim(f, "."))
	}
	name := strings.Join(keep, " ")
	name = strings.TrimRight(name, ". ") // Windows：结尾的点与空格会被悄悄吃掉
	switch strings.ToUpper(name) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
		"LPT1", "LPT2", "LPT3", "CLOCK$":
		return ""
	}
	if len([]byte(name)) > 96 {
		name = cutAtRune(name, 96)
	}
	return name
}

// cleanSection 校验并规范化包内相对路径。
//
// ★ 这里必须较真：段名会进 zip 的名字字段，而 zip 被解开时**名字就是路径**。
//
//	放一段 "../" 进去，包就变成了一次任意路径写入。
func cleanSection(name, root string) (string, error) {
	raw := strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	if raw == "" {
		return "", errors.New("有一段内容没有名字")
	}
	if strings.HasPrefix(raw, "/") || filepath.IsAbs(raw) || (len(raw) >= 2 && raw[1] == ':') {
		return "", fmt.Errorf("段名 %q 是绝对路径：包里的东西只能落在包内", name)
	}
	parts := strings.Split(raw, "/")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, ".")
		switch {
		case p == "":
			return "", fmt.Errorf("段名 %q 里有空的一段", name)
		case p == ".." || p == ".":
			return "", fmt.Errorf("段名 %q 里有 %q：诊断包不许往自己外面写", name, parts[i])
		}
		if strings.ContainsAny(p, ":*?\"<>|") {
			return "", fmt.Errorf("段名 %q 里有 Windows 不许的字符", name)
		}
		for _, r := range p {
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("段名 %q 里有控制字符", name)
			}
		}
		parts[i] = p
	}
	if len(parts) > 3 {
		return "", fmt.Errorf("段名 %q 层级太深（最多 3 层：根目录/分类/文件）", name)
	}
	last := parts[len(parts)-1]
	if !strings.Contains(last, ".") {
		parts[len(parts)-1] = last + ".txt"
	}
	return root + "/" + strings.Join(parts, "/"), nil
}

// cutAtRune 按字节上限截断，但不把多字节字符劈一半 —— 劈一半会让整个文件在
// 别人眼里变成乱码，那就白脱敏了。
func cutAtRune(s string, maxBytes int) string {
	b := []byte(s)
	if len(b) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && b[cut]&0xC0 == 0x80 { // 0x80：UTF-8 续字节
		cut--
	}
	return string(b[:cut])
}

// SortRedactions 给界面用：命中计数按次数从多到少排。
func SortRedactions(hits map[string]int) [][2]any {
	out := make([][2]any, 0, len(hits))
	for k, v := range hits {
		out = append(out, [2]any{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][1].(int) != out[j][1].(int) {
			return out[i][1].(int) > out[j][1].(int)
		}
		return out[i][0].(string) < out[j][0].(string)
	})
	return out
}
