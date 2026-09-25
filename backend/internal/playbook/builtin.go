package playbook

// BuiltinBoxCheck 是那一路的编号 —— 界面上「内置」那一档就认它。
const BuiltinBoxCheck = "box-check"

// Builtins 返回随包内置的剧本。
//
// ★ 内置必须自己过 Validate（有测试钉着），而且不许被界面上的编辑盖掉：
//
//	一旦有人能改它，「照着官方那本跑」这句话就成了假的。
func Builtins() []Playbook {
	out := []Playbook{boxCheck}
	for i := range out {
		out[i].BuiltIn = true
	}
	return out
}

// boxCheck 照 2026-09-19 辽宁金宇建安现场那一趟录的：
//
//	「40 路摄像头只有 11 路出画面」。当时的顺序是 先看它是不是活着、资源够不够 →
//	看解码这一路吃没吃满 → 看服务在不在、端口在不在 → 回头读日志找丢帧 →
//	再对配置里的通道数和许可上限。★ 结论最后落在帧池容量上，所以日志那几条
//	的高亮直接把「帧池」「丢帧」「解码器没装」写在旁边，跑完不用再手工 grep。
var boxCheck = Playbook{
	ID:   BuiltinBoxCheck,
	Name: "盒子体检（40 路只出 11 路那一路）",
	Note: "按现场那趟的顺序问：它活着吗 → 资源与解码口子 → 服务与端口 → 日志里丢帧的那句原话 → 配置对得上吗。" +
		"全程只读，最后两条一键动作会改那台机器的状态，标了出来。",
	Steps: []Step{
		{Name: "它是谁、多久没重启了", Run: "uname -a && cat /etc/os-release 2>/dev/null | head -5 && uptime",
			Why: "固件版本和上次重启时间先落地 —— 后面所有读数都要放到这台具体的机器上解释",
			OS:  []string{Linux, Darwin},
			// ★ 两位数才算过载：写成 [3-9]\d*|1\d\d 会漏掉 10~29 这一整段
			//   （1\d\d 要三位数），而现场最常见的高负载恰恰就落在十几。
			Marks: []Mark{{Match: `load average:\s*([3-9]\.|\d{2,}\.)`,
				Say: "平均负载已经在两位数以上：这台机器不只是某一路流的问题，先按整体过载查"}},
			TimeoutSec: 20},
		{Name: "它是谁、多久没重启了（Windows）", Run: `cmd /c ver & systeminfo | findstr /i /c:"OS Name" /c:"System Boot Time"`,
			Why:        "Windows 上的对等一问：版本和开机时间",
			OS:         []string{Windows},
			TimeoutSec: 60},

		{Name: "CPU 与内存此刻多少", Run: "top -bn1 | head -12; free -m",
			Why: "解码吃 CPU、帧池吃内存 —— 这两个数决定后面要不要往池子上想",
			OS:  []string{Linux},
			Marks: []Mark{
				{Match: `(?i)argus|dss|ffmpeg|decode`, Say: "排在前面的就是正在吃 CPU 的那个进程，后面读日志时认准它"},
				{Match: `^Mem:.*\s0\s*$`, Say: "可用内存见底的读数：池子再建大也放不下，先减通道"},
			}, TimeoutSec: 30},
		{Name: "CPU 与内存此刻多少（Windows）", Run: `powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize; Get-Process | Sort-Object CPU -Desc | Select-Object -First 8 Name,CPU"`,
			Why: "Windows 上的对等一问", OS: []string{Windows}, TimeoutSec: 60},

		// ★ 那一路的最后一块拼图就在这条：池子按什么分辨率建的，得先看它实际在出几路的画面。
		{Name: "GPU / NPU 占用与显存", Run: "if command -v tegrastats >/dev/null 2>&1; then tegrastats --interval 1000 --iter 3; " +
			"elif command -v nvidia-smi >/dev/null 2>&1; then nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv; " +
			"else echo '这台没有 tegrastats 也没有 nvidia-smi'; fi",
			Why: "解码在 GPU/NPU 上，池子在显存里。占用打满和占用很低是两种完全不同的毛病：前者是路数超了，后者是根本没在解",
			OS:  []string{Linux},
			Marks: []Mark{
				{Match: `没有 tegrastats 也没有 nvidia-smi`, Say: "这一问在这台机器上问不出东西（不是没问题）：它是纯 CPU 解码，显存那本账不存在"},
				{Match: `\b(9[5-9]|100)%`, Say: "解码口子基本打满：再加路数必然丢帧，先看池子和路数"},
			}, TimeoutSec: 40},

		{Name: "磁盘还剩多少、日志把盘写满没有", Run: "df -h | grep -Ev 'tmpfs|overlay' ; du -sh /var/log 2>/dev/null",
			Why:        "盘满时服务不停但日志和录像会静默失败，症状经常是「有几路没画面」",
			OS:         []string{Linux, Darwin},
			Marks:      []Mark{{Match: `100%|9[89]%`, Say: "某个挂载点已经满了：先清盘再看流，这时候任何「取不到流」都可能是它造成的"}},
			TimeoutSec: 40},

		{Name: "温度有没有压频", Run: "for z in /sys/class/thermal/thermal_zone*/; do printf '%s ' $(cat $z/type 2>/dev/null); cat $z/temp 2>/dev/null; done",
			Why:        "机柜里闷到的机器会主动降频，症状是路数一多就掉画面",
			OS:         []string{Linux},
			Marks:      []Mark{{Match: `\b(9\d{4}|1\d{5})\b`, Say: "有温度读数在 90℃ 以上：先解决散热，再谈软件配置"}},
			TimeoutSec: 20},

		{Name: "服务在不在、有没有正在失败的单元", Run: "systemctl --no-pager --failed; systemctl is-active argus-engine argus-watchdog dss 2>/dev/null",
			Why: "服务侧先给个是非：单元起不来时，后面日志里那些丢帧只是它的回声",
			OS:  []string{Linux},
			Marks: []Mark{
				{Match: `\bfailed\b`, Say: "有单元处于失败状态：先把那一个单元的日志读掉，再回头看画面"},
				{Match: `^inactive$|\bdead\b`, Say: "服务根本没在跑：这不需要再看流，去把它起起来"},
			}, TimeoutSec: 30},
		{Name: "服务在不在（Windows）", Run: `powershell -NoProfile -Command "Get-Service | Where-Object {$_.Status -ne 'Running' -and $_.StartType -eq 'Automatic'} | Select-Object Name,Status"`,
			Why: "Windows 上开了却没起来的服务", OS: []string{Windows}, TimeoutSec: 60},

		{Name: "它在听哪些端口", Run: "ss -tlnp 2>/dev/null || netstat -tlnp",
			Why:        "取流、信令、Web 各占一个口 —— 端口在不在，决定后面是查网络还是查服务",
			OS:         []string{Linux},
			Marks:      []Mark{{Match: `:554\b`, Say: "RTSP 口在听：可以拿「取流探测」那一页直接问它要一路流"}},
			TimeoutSec: 20},

		{Name: "跟平台之间连上了几条", Run: "ss -s; ss -tnp state established 2>/dev/null | head -40",
			Why: "出画面的路数应该等于建立起来的取流会话数：这个数一比，「11 路」到底是设备没发还是平台没拉就分开了",
			OS:  []string{Linux},
			// ss -s 那一行长这样：TCP: 38 (estab 3, closed 20, ...)。
			// 只有一位数才当「拉得不够」，写成 estab\s*\(\d\) 既打不中真格式，
			// 又会把 estab 412 那种满负荷读数说成个位数。
			Marks:      []Mark{{Match: `\(estab\s+([1-9])\b`, Say: "建立的连接只有个位数：多半不是解码的问题，是上游压根没拉够路数"}},
			TimeoutSec: 20},

		{Name: "日志里最近有没有丢帧那句原话", Run: "tail -n 400 /var/log/argus/argus-engine.log 2>/dev/null; " +
			"journalctl -u argus-engine -u argus-watchdog --no-pager -p warning -n 200 2>/dev/null",
			Why: "★ 那一路的结论就是从这里读出来的：池子按旧分辨率建小了，日志里明写了帧池耗尽",
			OS:  []string{Linux},
			Marks: []Mark{
				{Match: `(?i)帧池|frame pool|pool.*(exhaust|full)|no available frame`,
					Say: "命中帧池耗尽：这是「多路只出少数几路」的经典症状 —— 去对池子是按什么分辨率建的，和相机实际出的分辨率是不是一致"},
				{Match: `(?i)drop(ped)?\s.*frame|丢帧`,
					Say: "命中丢帧：只说明结果，要找的是它为什么丢 —— 上面那行通常带着通道号和当时在解的分辨率"},
				{Match: `(?i)decoder.*(fail|not found|no plugin)|引擎.*(没装|未安装)`,
					Say: "命中解码器/引擎缺失：这一路压根没在解，去确认这台装的是哪个解码引擎、许可让不让解"},
				{Match: `(?i)license|未授权|not licensed`,
					Say: "命中许可：路数上限可能被许可卡住，界面上看着是「没画面」，实际是不让解"},
				{Match: `(?i)No space left|OutOfMemory|cannot allocate`,
					Say: "命中盘满或内存不够：先看上面磁盘和内存那两条，这条只是回声"},
			}, TimeoutSec: 60},

		{Name: "配置里的通道数与许可上限", Run: "sed -n '1,120p' /etc/argus/engine.yaml 2>/dev/null; grep -RniE 'channel|limit|schema_version' /etc/argus 2>/dev/null | head -40",
			Why: "池子容量是按配置里的通道数算的：路数、上限、每路预留几帧，这三个数对不上就是它",
			OS:  []string{Linux},
			// 复数也得认：配置文件里写的就是 channels: 16，光写 channel 会因为它打不中，
			// 于是界面上显示「这一样没提到」—— 而这一样恰恰是最该被看到的数。
			Marks: []Mark{{Match: `(?i)(channels?|limits?)\s*[:=]\s*(\d{1,3})`,
				Say: "把这里的通道数/上限和实际接进来的路数对一遍：池子按下限建、相机按实际上报，中间那段就是「没画面」的那几路"}},
			TimeoutSec: 30},

		{Name: "它自己说现在几点、跟谁对时", Run: "timedatectl 2>/dev/null | head -8; cat /etc/timezone 2>/dev/null",
			Why: "日志时间轴歪了，前面读到的先后顺序就都是错的 —— 先确认这把尺本身准不准",
			OS:  []string{Linux}, TimeoutSec: 20},

		{Name: "它的地址与路由", Run: "ip -brief addr 2>/dev/null; ip route 2>/dev/null | head -10; cat /etc/resolv.conf 2>/dev/null | grep -v '^#'",
			Why: "地址、网关、DNS 三个数先落地，后面凡是「连不上平台」都要拿它当底色",
			OS:  []string{Linux, Darwin}, TimeoutSec: 20},

		{Name: "装的哪一版、插件在不在", Run: "cat /usr/share/argus/VERSION /etc/argus/version 2>/dev/null; dpkg -l 2>/dev/null | grep -i argus; ls /usr/lib/argus/plugins 2>/dev/null",
			Why: "版本和插件清单决定上面那些问哪几条在这台上根本问不出来",
			OS:  []string{Linux}, TimeoutSec: 30},

		// ★★ 下面两条会改那台机器的状态。它们留在同一本里是有理由的：
		//	现场读完日志后的动作就是这两下，分开录两本反而让人漏掉。
		//	但它们各自单独标 Write —— 批准那一步会数出「有几条会改东西」，
		//	界面上也是单独一色，不许和上面那些只读的混在一句「跑完了，一切正常」里。
		{Name: "重启解码服务", Run: "systemctl restart argus-engine && sleep 3 && systemctl is-active argus-engine",
			Why: "会改那台机器的运行状态：服务停几秒，正在拉流的一起断。读完日志再决定要不要按它",
			OS:  []string{Linux}, Write: true, TimeoutSec: 60},
		{Name: "把这一段日志导成包", Run: "d=/tmp/netkit-box-log-$(date +%s); mkdir -p $d && cp -a /var/log/argus $d/ 2>/dev/null; " +
			"journalctl -u argus-engine --no-pager -n 5000 > $d/journal.txt 2>/dev/null; tar czf $d.tar.gz -C $d . && echo $d.tar.gz",
			Why: "会改那台机器的磁盘：在 /tmp 下多写一个几 MB 的包。要发给二线时用它，别自己敲一遍",
			OS:  []string{Linux}, Write: true, TimeoutSec: 120},
	},
}
