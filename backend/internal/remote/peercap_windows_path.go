package remote

// Windows 对端这一路：在那台机器上用系统自带的 pktmon 起一路采集。
//
// ★★ 为什么这里没有 build tag：这一份代码不是「在 Windows 上跑」，是「从任何平台
//   （macOS/Linux/Windows）经 SSH 去驱动一台 Windows 对端」。出货那台跑 NetKit 的
//   机器多半是 macOS/Linux，它手上没有 pktmon，所以转换必须在对端做、把转好的
//   pcapng 取回来。这一份要能在 windows/386 上编得过（它只碰字符串和 SSHExecer）。
//
// ★★ 为什么不能照抄上面 tcpdump 那一套 nohup / kill -0 / wc -c：
//   Windows 上 OpenSSH 服务器默认的 shell 是 cmd.exe（也可能配成 powershell），
//   那里面这三句一个都没有。可这一路也不需要它们 —— pktmon 的 start 起的是一路
//   **全机器唯一的系统级会话**（ETW），命令自己当场返回，录影在会话里继续写。
//   所以我们既不「后台挂起一个进程」也不「发信号停它」：
//   起 = 跑一句 pktmon start（它返回退出码），看 = 问那一份 .etl 多大，
//   停 = 跑一句 pktmon stop，再把已经停掉的那一份 etl2pcap 转成 pcapng。
//   这一路没有进程号可发信号 —— 收口这件事只有 pktmon stop 说了算。
//
// ★ 下面每一条命令的形状、退出码的含义，都是在 UTM 里那台 Win11 ARM64（26200，中文系统）
//   上量出来的（见 internal/capture/source_windows.go 顶上那份清单，这一路照它复用，不重推）：
//     - 退出码 159 = 这台机器上已经有一路 pktmon 在录（全机器只能一路），不是「没权限」。
//     - --pkt-size 这一格永远要传：不传时 pktmon 默认每包只记 128 字节，1500 MTU 的包
//       会被悄悄剪断（caplen=128），数长度以外的用法完全看不出来。
//     - -s（文件大小 MB）永远要向上取整：0 在 pktmon 那里不是「不限」，是「按默认 512MB」。
//     - 正在录的那一份 .etl 直接拿去 etl2pcap → 退出码 0、转出来只有 172 字节一个包没有。
//       所以转换一定排在 stop 之后，这一路的顺序写死不许改。
//     - etl2pcap 这项能力靠 `pktmon /?` 里认不认得「etl2pcap」这个命令名判（命令名不翻译，实测过）。
//   清单里没写、这一路只能先假设的，逐条标了 `// TODO(实机)`。

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// pktmonWinBusyExit 是「这台机器上已经有一路 pktmon 在录」那一个退出码（实测 159，
// 与 internal/capture 那一份同源）。它跟「没权限」下一步完全相反，单独分一档。
const pktmonWinBusyExit = 159

// peerWinScratchFallback 是问不出 %TEMP% 时的落点。
// TODO(实机) 非交互 SSH 会话里 %TEMP% 到底指哪儿（会不会是 System32 那种不可写的目录）——
// 量出来之前先退回一个管理员一定可写、且抓包本就是管理员才起得来的地方。
const peerWinScratchFallback = `C:\Windows\Temp`

// winQuotePath cmd.exe 那一套的双引号转义（无条件引起来）。
// ★ 不复用 file.go 里的 winQuote：那个只在路径含空格/&/() 时才引；这一路的落点里
//
//	可能出现等号、百分号之外的一堆分隔，无条件引起来最省事也最不容易漏。
//
// ★ 不能用 POSIX 的单引号：cmd.exe 不认单引号当引号，`'C:\Program Files\x'` 会被拆成两截。
// cmd/pktmon 认双引号，内部的双引号按 Windows 惯例反斜杠转义。我们生成的路径里不会有引号，
// 但对端回给我们的命令路径（where 出来的）要引起来，别拿它裸拼。
func winQuotePath(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// probePeerCaptureWindows 问那台 Windows：有没有 pktmon、会不会转 pcapng、那份能落哪儿。
//
// ★ 探不到 pktmon 不是错误，是一句能拿去决定的事实（Win7 那一档根本没有它）。
func probePeerCaptureWindows(ctx context.Context, x SSHExecer, d *Device) (*PeerCaptureCaps, error) {
	caps := &PeerCaptureCaps{}

	out, err := x.Exec(ctx, d, "where pktmon", 15*time.Second)
	if err != nil {
		return nil, err
	}
	if out.ExitCode != 0 {
		caps.Note = "那台 Windows 上没有 pktmon（系统自带的报文监视器，Win10 1809 / Server 2019 起才有，Win7 那一档压根没有）"
		caps.Dir = peerScratchDirWindows(ctx, x, d)
		return caps, nil
	}
	caps.Tool = "pktmon"
	caps.Path = firstLineOf(out.Stdout) // where 报出来的全路径（起不来时这一格是唯一能指着说的东西）

	// ★ 能力探测只认「help 里有没有 etl2pcap 这个命令名」—— 命令名不受显示语言影响（实测）。
	h, err := x.Exec(ctx, d, "pktmon /?", 15*time.Second)
	if err != nil {
		return nil, err
	}
	caps.Etl2Pcap = strings.Contains(strings.ToLower(h.Stdout+h.Stderr), "etl2pcap")
	if !caps.Etl2Pcap {
		caps.Note = "那台的 pktmon 没有 etl2pcap 那一项（老 Win10 build）：抓得出 .etl 但转不成我们能读的表"
	}
	caps.Dir = peerScratchDirWindows(ctx, x, d)
	// ★ 不给口列表：pktmon 这一档抓的是 --comp nics（全部网卡），点名单块口做不到双向
	//   （实测：--comp <网卡号> 与 filter add -m <MAC> 都只剩出的方向）。列了口名反而会
	//   让人以为挑了它就只抓那一块。口名这一格如实留空 + Note 说清。
	if caps.Note == "" {
		caps.Note = "pktmon 这一档抓的是那台机器上全部网卡（--comp nics），不逐块点名"
	}
	return caps, nil
}

// peerScratchDirWindows 问那台一句「临时文件往哪儿放」。不许直接写死。
func peerScratchDirWindows(ctx context.Context, x SSHExecer, d *Device) string {
	out, err := x.Exec(ctx, d, "echo %TEMP%", 10*time.Second)
	if err != nil || out.ExitCode != 0 {
		return peerWinScratchFallback
	}
	s := strings.ReplaceAll(out.Stdout, "\r", "")
	s = strings.TrimSpace(s)
	if s != "" && !strings.Contains(s, "\n") && strings.Contains(s, `\`) {
		return strings.TrimRight(s, `\`)
	}
	return peerWinScratchFallback
}

// winPktmonStartArgv 拼那一条 start。顺序照 internal/capture 实测那一版（pktmonStartArgs）。
// --comp nics 是这一档唯一能两个方向都收的选择器（实测清单第 2、3 条）。
// 数字（snap / mb）都是我们算出来的纯数字，不进任何外人给的字符串。
func winPktmonStartArgv(collector string, snapLen, mb int, etlPath string) string {
	return winQuotePath(collector) +
		" start --capture --comp nics" +
		" --pkt-size " + strconv.Itoa(snapLen) +
		" -s " + strconv.Itoa(mb) +
		" -f " + winQuotePath(etlPath)
}

// startPeerCaptureWindows 起一路 pktmon，回来确认那一份 .etl 真的在长。
//
// ★ 「起了再看一眼」这一条在 Windows 上照样要，只是问的东西换了：没有进程号可 kill -0，
//
//	改成问「那一份 .etl 建出来了没」。非管理员那一种，pktmon start 会直接以退出码失败，
//	比 tcpdump「收条据一秒后再死」更早说话，所以这里退出码不 0 当场就分档。
func startPeerCaptureWindows(ctx context.Context, x SSHExecer, d *Device, spec PeerCaptureSpec) (*PeerRun, error) {
	if spec.Collector == "" {
		return nil, &PeerStartError{Problem: PeerProblemNoTool, Detail: "那台上没有 pktmon"}
	}
	if spec.SnapLen <= 0 {
		return nil, fmt.Errorf("snapLen 要给正数，现在是 %d", spec.SnapLen)
	}
	if spec.EtlPath == "" || spec.PcapPath == "" {
		return nil, fmt.Errorf("Windows 这一路要同时给出 .etl 与 .pcapng 两个落点")
	}
	if spec.MaxMB <= 0 {
		// ★ 不许把 0 递给 pktmon：0 在它那里不是「不限」，是「按默认 512MB」（实测清单第 5 条）。
		return nil, fmt.Errorf("-s 那一格（MaxMB）要 >=1，现在是 %d", spec.MaxMB)
	}

	cmd := winPktmonStartArgv(spec.Collector, spec.SnapLen, spec.MaxMB, spec.EtlPath)
	out, err := x.Exec(ctx, d, cmd, 30*time.Second)
	if err != nil {
		return nil, err
	}
	switch {
	case out.ExitCode == pktmonWinBusyExit:
		// 全机器只能一路：这一档不去猜是谁那一录、也不替人 stop（那是别人的现场）。
		return nil, &PeerStartError{Problem: PeerProblemBusy, Detail: firstLineOf(out.Stdout + " " + out.Stderr)}
	case out.ExitCode != 0:
		return nil, &PeerStartError{Problem: classifyWinStart(out.Stdout + " " + out.Stderr),
			Detail: firstLineOf(out.Stdout + " " + out.Stderr)}
	}

	// run.PeerFile 指向**转好后那份 pcapng**（pull 取的就是 PeerFile，POSIX 那一档同名同义）；
	// EtlPath 指向正在录的那一份，用来「看一眼还在不在长」和收口时删干净。
	run := &PeerRun{Windows: true, PeerFile: spec.PcapPath, EtlPath: spec.EtlPath, StartedAt: time.Now()}

	// ★ 先看一眼之前等一会儿：pktmon 刚落盘要一拍。
	time.Sleep(peerStartSettle)
	deadline := time.Now().Add(peerStartWatch)
	for {
		exists, _, err := peerWinFileSize(ctx, x, d, run.EtlPath)
		if err != nil {
			return nil, err
		}
		if exists {
			return run, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	// .etl 迟迟没出现：start 回了 0 却没落地，说不出为什么 —— 老实归 died-at-start。
	return nil, &PeerStartError{Problem: PeerProblemDied,
		Detail: firstLineOf("start 回了 0 但没见着 " + run.EtlPath + "：" + out.Stdout + " " + out.Stderr)}
}

// classifyWinStart 把 pktmon start 失败那一下分成一档。
// ★ 只认「要管理员/权限」这一类真出现过的话，认不出就 died-at-start（见 internal/capture 同一口径）。
// TODO(实机) 非管理员跑 pktmon start 的确切退出码与那句话的原话 —— 现在靠关键词猜，量出来后可只认码。
func classifyWinStart(detail string) PeerCaptureProblem {
	s := strings.ToLower(detail)
	switch {
	case strings.Contains(s, "access is denied"), strings.Contains(s, "permission"),
		strings.Contains(s, "denied"), strings.Contains(s, "administrator"),
		strings.Contains(s, "elevated"), strings.Contains(s, "privilege"),
		strings.Contains(s, "拒绝访问"), strings.Contains(s, "管理员"), strings.Contains(s, "权限"):
		return PeerProblemPrivilege
	}
	return PeerProblemDied
}

// peerWinFileSize 问那台一份文件多大。cmd.exe 里没有 wc，用 for 的 %~zI 展开文件大小。
// 返回 (存在?, 字节数, 通道错)。文件不在 → 那句 for 什么都不 echo → exists=false。
func peerWinFileSize(ctx context.Context, x SSHExecer, d *Device, path string) (bool, int64, error) {
	out, err := x.Exec(ctx, d, `for %I in (`+winQuotePath(path)+`) do @echo %~zI`, 20*time.Second)
	if err != nil {
		return false, 0, err
	}
	s := strings.ReplaceAll(out.Stdout, "\r", "")
	s = strings.TrimSpace(s)
	if s == "" || !isAllDigits(s) {
		return false, 0, nil
	}
	n, cerr := strconv.ParseInt(s, 10, 64)
	if cerr != nil {
		return false, 0, nil
	}
	return true, n, nil
}

// peerCaptureStatWindows 看一眼那一份 .etl 还在不在、多大了。
//
// ★ Alive = 那一份 .etl 还在。pktmon 是一路系统级会话，没有进程号可查，也没有「它自己退了」
//
//	这种中间态：会话要么还在往这份文件写（文件在、会长），要么被谁 stop/删了（文件没了）。
//	读不到大小不许报成 0（BytesKnown 留着说话），「到量了自己停」那一档全靠这个数。
func peerCaptureStatWindows(ctx context.Context, x SSHExecer, d *Device, run *PeerRun) (*PeerStat, error) {
	exists, size, err := peerWinFileSize(ctx, x, d, run.EtlPath)
	if err != nil {
		return nil, err
	}
	return &PeerStat{Alive: exists, Bytes: size, BytesKnown: exists}, nil
}

// stopPeerCaptureWindows 收口：stop → 确认会话停了 → 转 pcapng。
//
// ★★ 顺序是死的：先 stop、再确认、最后才转。
//
//	正在录的那一份 .etl 拿去 etl2pcap 会回退出码 0、转出一个 172 字节的空壳（实测清单第 6 条）。
//	stop 之后还要再看一眼 .etl 不再长 —— 不信「stop 回了 0 就等于会话真关了」那句。
//	TODO(实机) stop 从返回到文件彻底不被写之间要等多久（这里用两拍稳定 + 兜底时长判）。
func stopPeerCaptureWindows(ctx context.Context, x SSHExecer, d *Device, run *PeerRun, wait time.Duration) (*PeerStopInfo, error) {
	if wait <= 0 {
		wait = 5 * time.Second
	}
	info := &PeerStopInfo{}

	// 1) 打招呼 = pktmon stop。没有第二下可发（不是发信号那套），一句就够。
	stopOut, err := x.Exec(ctx, d, "pktmon stop", wait+20*time.Second)
	if err != nil {
		return nil, err
	}
	info.Log = stopOut.Stdout + " " + stopOut.Stderr

	// 2) 确认会话真的停了：盯 .etl 大小不再变。stop 回了 0 不等于文件当场松手，
	//    而拿一份还在被写的 .etl 去转就是实测里那个「退出码 0 的空壳」。
	if !waitWinEtlSettled(ctx, x, d, run.EtlPath, wait) {
		// 到点还在长：这一路没被停干净。转出去的那一份会短一截，明写成 forced。
		info.Forced = true
	}

	// 3) 已经停掉的这一份才准转。转换排在 stop 之后 —— 上面第 6 条实测就是这么来的。
	//    裸名 pktmon 起得来：它一定在 System32 里，PATH 里必有（起 start 时用的是 where
	//    出来的全路径，这里 stop/convert 阶段用不着那个路径，用系统那份同一个 pktmon）。
	convOut, cerr := x.Exec(ctx, d,
		"pktmon etl2pcap "+winQuotePath(run.EtlPath)+" --out "+winQuotePath(run.PeerFile),
		wait+60*time.Second)
	if cerr != nil {
		info.ConvertErr = cerr.Error()
		return info, nil
	}
	if ok, size, eerr := peerWinFileSize(ctx, x, d, run.PeerFile); eerr == nil && ok && size > 0 {
		// 转出来的 pcapng 在、非空 —— 交给上层用现成的 SFTP 取回。
		info.HasCounts = false // pktmon 不打 tcpdump 那三行账；包数由上层从文件里数
		_ = convOut
	} else {
		info.ConvertErr = firstLineOf(convOut.Stdout + " " + convOut.Stderr)
	}
	return info, nil
}

// waitWinEtlSettled 盯那一份 .etl 两拍不变就算停干净了。到点没停返回 false。
func waitWinEtlSettled(ctx context.Context, x SSHExecer, d *Device, etl string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	prev := int64(-1)
	stable := 0
	for {
		_, size, err := peerWinFileSize(ctx, x, d, etl)
		if err != nil {
			return false
		}
		if size == prev && size >= 0 {
			stable++
			if stable >= 2 {
				return true
			}
		} else {
			stable = 0
		}
		prev = size
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// removePeerFilesWindows 用 cmd.exe 的 del 删对端那几份（.etl 与 .pcapng 都要删干净）。
// ★ 默认要删的理由和 POSIX 那一路一模一样：那份里是原始包，含明文口令与团体名。
func removePeerFilesWindows(ctx context.Context, x SSHExecer, d *Device, paths []string) error {
	q := make([]string, 0, len(paths))
	for _, pp := range paths {
		q = append(q, winQuotePath(pp))
	}
	// /q 安静、/f 强制只读。del 一次能吃多个引起来的路径。
	if _, err := x.Exec(ctx, d, "del /q /f "+strings.Join(q, " "), 30*time.Second); err != nil {
		return err
	}
	return nil
}
