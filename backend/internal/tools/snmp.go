package tools

// ── SNMP 工具共用的一层 ──
//
// ★ 为什么团体名必填、不给默认 "public"：
//
//	"public" 确实是多数设备的出厂值，但把默认写成它等于替用户蒙着试一次 ——
//	而 SNMP 的失败特别省：团体名不对时 v2c 设备**根本不答**，和防火墙丢包、
//	设备没开 SNMP 是同一个「超时」。默认值省下的那一次填写，
//	换来的是界面上多一种判不出来的可能，这笔账不划算。
//
// ★ 团体名绝不进 values / note / 错误文本：结果会原样发给 AI，也可能进诊断包。
//   所以这一层每一条报错只说「团体名不对」这类**原因**，不回显它的内容。
//   snmp_test.go 里有一条专门扫这个。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"net.yuhox.com/netkit/internal/netaddr"
	"net.yuhox.com/netkit/internal/netif"
	"net.yuhox.com/netkit/internal/ots"
	"net.yuhox.com/netkit/internal/snmp"
)

// SNMP 工具共用的判定码。★ 每一条都对应「下一步查什么」不一样，
// 能揉成一句「SNMP 不通」的话，这几个工具就白做了。
const (
	snmpOk      = "snmp-ok"       // 团体名对、路通、设备答了
	snmpNoReply = "snmp-no-reply" // 没回话：团体名 / 防火墙 / 没开 SNMP，三种同形
	snmpError   = "snmp-error"    // 设备答了，但答的是「不行」（error-status 非 0）
	snmpV1Only  = "snmp-v1-only"  // v2c 没答、v1 答了：这台只认 v1
	snmpV2cOnly = "snmp-v2c-only" // 指定了 v1 却没答、v2c 答了
	// snmpReplyUnmatched 是「有回包，但对不上号」：多半是设备在往这台机器推 trap，
	// 那 SNMP 其实是通的 —— 这一条和「没回话」的下一步完全相反，必须分开。
	snmpReplyUnmatched = "snmp-reply-unmatched"
	snmpNoData         = "snmp-no-data"    // 设备活着，但这棵子树它没填
	snmpNotWalked      = "snmp-not-walked" // 表读到一半设备不走了：少给的那几行不能当「没有」
)

// 系统组（SNMPv2-MIB）。这几栏是 RFC 要求**必须实现**的，所以拿它当「设备通不通」的探针。
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
	oidSysServices = "1.3.6.1.2.1.1.7.0"
)

// snmpArgs 是所有 net.snmp.* 工具共用的一段参数（各工具的参数结构体内嵌它）。
type snmpArgs struct {
	Addr      string `json:"addr"`
	Community string `json:"community"`
	Port      int    `json:"port,omitempty"`
	// Version 不填 = v2c。★ 这里没有「自动判断」这一档：判断只能靠
	// 「这一档没答就换另一档再问一次」，那是一条对照探测，得给一个明确的开关（见 probe）。
	Version   string `json:"version,omitempty"`
	Iface     string `json:"iface,omitempty"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
	Retries   int    `json:"retries,omitempty"`
}

// snmpTarget 是校验过的一台设备，外加「怎么问它」。
type snmpTarget struct {
	host    string // host:port，端口已补齐成 161
	addr    netaddr.Addr
	port    int
	iface   string
	client  *snmp.Client
	version snmp.ClientVersion
}

// snmpSchemaProps 是各 SNMP 工具 schema 共用那段参数定义。
// 手写五遍迟早写歪（界面上同一个参数两个说法），所以拼一次。
const snmpSchemaProps = `"addr": {"type": "string",
      "description": "设备地址。只收 IP，可以只写地址（192.168.1.2）也可以带端口（192.168.1.2:1161）。域名先用 net.dns.query 查出地址。"},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535,
      "description": "UDP 端口，不填按 161。addr 里带了端口就以 addr 里的为准。"},
    "community": {"type": "string",
      "description": "读团体名（read-only community）。★ 必填、没有默认值：团体名不对时 v2c 设备直接不答，和防火墙丢包、没开 SNMP 在报文上完全同形，猜一个默认值只会把三种病揉成一种。这个值不会出现在结果里。"},
    "version": {"type": "string", "enum": ["v2c", "v1"],
      "description": "SNMP 版本，不填按 v2c。只认 v1 的老交换机填 v1 —— v1 没有 GETBULK，走表会退回一栏一栏问，慢很多。"},
    "iface": {"type": "string",
      "description": "从本机哪块网卡出去（填网卡名，如 en0 / eth0 / 以太网 2）。多网卡机器上这一条常常决定设备答不答：管理 VLAN 只放行一个口、或设备 ACL 按源地址收口时，走错口就等于「没回话」。解不开时直接报错，不会退化成「随便哪块网卡都行」。"},
    "timeoutMs": {"type": "integer", "minimum": 200, "maximum": 20000,
      "description": "单个请求等多久，默认 2000。走表时最坏耗时是这个值乘上问的次数再乘轮数。"},
    "retries": {"type": "integer", "minimum": 2, "maximum": 6,
      "description": "没回话时一共问几次（含首发），默认 3。填 2 就是只重传一次：丢包多的链路上问太少会把「设备慢」判成「设备没答」，问太多则是让现场干等。"}`

func snmpArgsFrom(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
	}
	return nil
}

// snmpDial 校验参数并起一个客户端。
//
// ★ 这一步**不做网络观测**，所以这里的失败全是「参数不对」而不是「设备不通」：
//
//	观测没做成要报 ots.Unknown，参数写错要直接报错，两者混了就没人知道该去改参数。
func snmpDial(a snmpArgs) (*snmpTarget, error) {
	if a.Addr == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 addr")
	}
	addr, port, err := netaddr.SplitHostPort(a.Addr)
	if err != nil {
		if host, ok := addrLooksLikeName(a.Addr); ok {
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"%q 不是 IP —— SNMP 这一层只收 IP，域名先用 net.dns.query 查出地址再来", host)
		}
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	if port == 0 {
		port = a.Port
	}
	if port < 0 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "端口 %d 不在 1-65535 之间", port)
	}
	if port == 0 {
		port = snmp.DefaultPort
	}
	if strings.TrimSpace(a.Community) == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"没给 community（读团体名）—— 这里故意不给默认值：团体名不对时设备**压根不答**，"+
				"和防火墙丢包、没开 SNMP 长得一模一样，所以这一层不能猜")
	}
	version, err := snmpVersion(a.Version)
	if err != nil {
		return nil, err
	}
	timeout := 2 * time.Second
	if a.TimeoutMS > 0 {
		timeout = time.Duration(a.TimeoutMS) * time.Millisecond
	}
	// 参数是「一共问几次」（含首发），Client 那边要的是「重传几次」。
	// ★ 下限是 2 不是 1：Client 的零值语义是「按默认重传两次」，
	//   这里填 1 会变成 0，反而拿不到「只问一次」，是个说不出口的谎。
	retries := 2
	if a.Retries >= 2 {
		retries = a.Retries - 1
	}
	// ★ HostPort 负责 v6 链路本地地址的 zone 写法：每个平台不一样（Linux/macOS 用
	//   接口名、Windows 用索引）。这里拼错的话设备回包我们收不到，又变成「没回话」。
	host, err := addr.HostPort(port, runtime.GOOS)
	if err != nil {
		return nil, ots.Errf(ots.ErrInvalidArgument, "%s", err)
	}
	t := &snmpTarget{addr: addr, port: port, host: host, iface: a.Iface, version: version}
	local := ""
	if a.Iface != "" {
		// ★ 解不开就**当场失败**，不许退化成「不绑」：
		//   不绑的意思是这台机器其余每块网卡都可能成为出口，
		//   而指定网卡的意义正是「别从办公口/公网口出去」。
		local, err = snmpSourceAddr(a.Iface, addr.Is6())
		if err != nil {
			return nil, err
		}
	}
	t.client = &snmp.Client{
		Addr:      host,
		Community: a.Community,
		Version:   version,
		LocalAddr: local,
		Timeout:   timeout,
		Retries:   retries,
	}
	return t, nil
}

func (t *snmpTarget) close() { _ = t.client.Close() }

// values 是每个 SNMP 工具结果里共用的那几栏。★ 里面没有 community。
func (t *snmpTarget) values() map[string]any {
	v := map[string]any{
		"target":  t.host,
		"port":    t.port,
		"family":  udpFamily(t.addr),
		"version": snmpVersionName(t.client.Version),
	}
	if t.iface != "" {
		v["iface"] = t.iface
	}
	return v
}

// askWithOtherVersion 换到另一档版本再问一次，返回的函数把版本换回来。
//
// ★ 复用同一条连接（只换报文里的版本号），源端口因此不变：
//
//	设备 ACL 按源地址收口时，换一条连接可能把「v2c 不通」和「从另一个口出去又不通」搅在一起。
func (t *snmpTarget) askWithOtherVersion() (snmp.ClientVersion, func()) {
	other := snmp.V1
	if t.client.Version == snmp.V1 {
		other = snmp.V2c
	}
	before := t.client.Version
	t.client.Version = other
	return other, func() { t.client.Version = before }
}

func snmpVersion(s string) (snmp.ClientVersion, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "v2c", "2c", "2":
		return snmp.V2c, nil
	case "v1", "1":
		return snmp.V1, nil
	case "v3", "3":
		return snmp.V2c, ots.Errf(ots.ErrNotSupported,
			"不支持 v3 —— v3 要用户名和密钥，这一层只做 v1/v2c")
	}
	return snmp.V2c, ots.Errf(ots.ErrInvalidArgument, "版本 %q 看不懂，要 v1 或 v2c", s)
}

func snmpVersionName(v snmp.ClientVersion) string {
	if v == snmp.V1 {
		return "v1"
	}
	return "v2c"
}

// snmpSourceAddr 从网卡名取出「该从哪个地址出去」。
//
// ★ 地址族要和对端一致：往 v4 的设备绑一个 v6 源地址，连接根本起不来，
//
//	而报出来的错是「起不了本地端口」，人看不懂那句话。
func snmpSourceAddr(iface string, want6 bool) (string, error) {
	nics, err := netif.Interfaces()
	if err != nil {
		return "", ots.Errf(ots.ErrInternal, "读网卡列表失败：%s", err)
	}
	found := false
	var have []string
	for _, n := range nics {
		if n.Name != iface {
			continue
		}
		found = true
		for _, ad := range n.Addrs {
			if ad.Is6() != want6 {
				have = append(have, ad.String())
				continue
			}
			switch ad.Scope() {
			case netaddr.ScopeLoopback, netaddr.ScopeMulticast, netaddr.ScopeLinkLocal:
				// 链路本地当源地址：设备会把回包发往 fe80::，这条路不通。
				have = append(have, ad.String())
				continue
			}
			if ad.Temporary {
				// 隐私临时地址隔一阵就换，拿它当源地址的话，设备侧的 ACL 和日志过一会儿就对不上了。
				have = append(have, ad.String())
				continue
			}
			return ad.IP.String(), nil
		}
		break
	}
	if !found {
		return "", ots.Errf(ots.ErrInvalidArgument, "没有叫 %s 的网卡（net.interfaces 看有哪些）", iface)
	}
	fam := "IPv4"
	if want6 {
		fam = "IPv6"
	}
	return "", ots.Errf(ots.ErrInvalidArgument, "%s 上没有能用来跟 %s 设备说话的地址（它上面是 %s）",
		iface, fam, strings.Join(have, "、"))
}

// snmpFail 把一次 SNMP 失败翻成判定。**这是所有 SNMP 工具共用的收口**：
//
//	「没回话」「设备答了但说不行」「有回包但对不上号」「包根本没出去」是四件不同的事，
//	各自的下一步也完全不同，任何一栏都不许把它们并成一句错误。
func snmpFail(err error, values map[string]any) (ots.Verdict, bool) {
	values["answered"] = false
	if err == nil {
		return ots.Verdict{}, false
	}
	var noReply *snmp.NoReplyError
	if errors.As(err, &noReply) {
		if noReply.Seen.Any() {
			// ★ 有包回来，只是对不上号 —— 这**不是**「没人答」。硬说三种病同形，
			//   人就会去查 ACL，而真正该查的是设备上那条 trap 目标配置。
			values["answered"] = true
			values["matched"] = false
			if noReply.Seen.NotReply > 0 {
				values["sawTrap"] = true
			}
			return ots.Verdict{Code: snmpReplyUnmatched, Values: values,
				Note: fmt.Sprintf("问了 %s，回来的包对不上号：%s。"+
					"这不是「没人答」，路上有东西在回话 —— 最常见的是设备上把 trap 目标配成了这台机器"+
					"（那 SNMP 本身是通的，把团体名和视图核一遍再试），其次是同网段有第二台在答同一个请求。",
					noReply.Addr, strings.TrimPrefix(noReply.Seen.Note(), "；"))}, true
		}
		return ots.Verdict{Code: snmpNoReply, Values: values,
			Note: fmt.Sprintf("%s 没有回话（一共问了 %d 次，一条包都没回来）。这三种病在报文层面长得一模一样，分不开："+
				"团体名不对（v2c 不报错、直接丢包）、防火墙或设备 ACL 没放行、这台设备没开 SNMP。"+
				"先核团体名，再用 net.udp.probe 看 161/udp 有没有反应。",
				noReply.Addr, noReply.Tries)}, true
	}
	var devErr *snmp.Error
	if errors.As(err, &devErr) {
		// 设备认这个请求、只是这一栏不给 —— 说明 SNMP 是通的、团体名也是对的。
		// 这一条和「没回话」必须分开：前者查视图/权限，后者查防火墙。
		values["answered"] = true
		values["errorStatus"] = devErr.Status
		values["errorIndex"] = devErr.Index
		if devErr.OID != "" {
			values["errorOID"] = devErr.OID
		}
		return ots.Verdict{Code: snmpError, Values: values,
			Note: fmt.Sprintf("有回话：%s 设备认这个请求（团体名是对的、SNMP 也开着），"+
				"只是这一栏不给读或读不了 —— 这种要去看设备的视图/权限配置，不是网络不通",
				err.Error())}, true
	}
	var stuck *snmp.WalkStuckError
	if errors.As(err, &stuck) {
		// ★ 设备在答话，只是走表走到一半不往前走了 —— 这既不是「没回话」也不是
		//   「这棵树没有」：读回来的那几栏是真的，少的可能还有。判成没数据，
		//   现场就会拿着一张缺了尾巴的表去下「这台没有几个口」的结论。
		values["answered"] = true
		values["walkStoppedAt"] = stuck.At
		values["walkGiven"] = stuck.Given
		values["walkRead"] = stuck.Read
		return ots.Verdict{Code: snmpNotWalked, Values: values,
			Note: fmt.Sprintf("有回话，但这张表只读到一半：%s 这棵树读到 %s 时设备不再往前走"+
				"（它给回来的是 %s），卡住前读回 %d 栏。"+
				"★ 上面这些是真的，但少的那几行不能当「没有」 —— 这是设备的毛病（walk 实现有缺陷、"+
				"或这一棵被视图切断了），不是这台设备真的没有。下一步：把已经读到的拿去用，"+
				"缺的部分换成点名问（按口、按端口号一栏一栏 GET），或者换 v1 走 GETNEXT 再试一次。",
				stuck.Prefix, stuck.At, stuck.Given, stuck.Read)}, true
	}
	// 剩下的是「这一趟观测根本没做成」：地址解不开、本地起不了端口、被取消。
	values["detail"] = err.Error()
	return ots.Unknown(values), true
}

// ── net.snmp.probe ──

var snmpProbeTool = ots.Tool{
	Name:  "net.snmp.probe",
	Class: ots.ClassRead,
	Summary: "问一台交换机的管理信息（sysDescr / 型号 / 开机多久 / 设备名 / 位置），用来定「SNMP 到底通不通」。" +
		"★ 判定按下一步怎么查来分：snmp-ok（团体名对、路也通）、" +
		"snmp-no-reply（没回话 —— 团体名不对、防火墙或 ACL 没放行、设备没开 SNMP，这三种在报文上同形，只能一起摆出来）、" +
		"snmp-reply-unmatched（有回包但对不上号，多半是设备在往这台机器推 trap，那 SNMP 其实是通的）、" +
		"snmp-v1-only / snmp-v2c-only（换一档版本就答了，这台只认那一档）、" +
		"snmp-error（设备答了，但答的是「这一栏不给读」）。" +
		"团体名必填且**不会出现在结果里**。这是 SNMP 那几栏的第一步：MAC 表、端口、PoE、LLDP 不通时先回来看这一条。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["addr", "community"],
	  "properties": {
	    ` + snmpSchemaProps + `,
	    "noVersionProbe": {"type": "boolean",
	      "description": "关掉「这一档版本没回话就换另一档再问一次」的对照探测。对照只多一个请求，但它打在设备上，生产设备上要保守就关掉 —— 关掉之后 v2c 不通就只剩「三种病分不开」这一句了。"}
	  }
	}`),
	Invoke: doSnmpProbe,
}

type snmpProbeArgs struct {
	snmpArgs
	NoVersionProbe bool `json:"noVersionProbe,omitempty"`
}

func doSnmpProbe(ctx context.Context, raw json.RawMessage) (any, error) {
	var a snmpProbeArgs
	if err := snmpArgsFrom(raw, &a); err != nil {
		return nil, err
	}
	t, err := snmpDial(a.snmpArgs)
	if err != nil {
		return nil, err
	}
	defer t.close()

	values := t.values()
	start := time.Now()
	info, err := t.systemInfo(ctx, values)
	if err != nil {
		verdict, done := snmpFail(err, values)
		if !done {
			return nil, ots.Errf(ots.ErrInternal, "%s", err)
		}
		// ★ 没回话时换一档版本再对照一次：这一条能把「这台只认另一档」从三种病里摘出去 ——
		//   另一档答了，说明团体名和路都是对的，剩下的只是版本的事。
		if verdict.Code == snmpNoReply && !a.NoVersionProbe {
			other, restore := t.askWithOtherVersion()
			otherName := snmpVersionName(other)
			otherInfo, oerr := t.systemInfo(ctx, nil)
			restore()
			values["versionProbe"] = otherName
			if oerr == nil {
				values["answered"] = true
				code := snmpV2cOnly
				if other == snmp.V1 {
					code = snmpV1Only
				}
				// ★ 这里把 version 改写成**答话那一档**，而不是留成用户填的那一档：
				//   后面几栏（MAC 表、端口、PoE、LLDP）要照这一栏去填版本，
				//   填成刚才那个没答的 v2c 就又是一片「没回话」。
				//   用户填的那一档另存 askedVersion，不覆盖掉这次问的到底是啥。
				values["askedVersion"] = snmpVersionName(t.version)
				values["version"] = otherName
				t.systemValues(values, otherInfo)
				return ots.Verdict{Code: code, Values: values,
					Note: fmt.Sprintf("%s 对 %s 没回话，换成 %s 就答了 —— 这台只认 %s。"+
						"后面几栏（MAC 表、端口、PoE、LLDP）都要把 version 填成 %s：%s",
						t.host, snmpVersionName(t.version), otherName, otherName, otherName,
						otherInfo.note())}, nil
			}
			// 两档都不答：把「对照做过了、也没答」写进结果，
			// 不然看的人会以为我们只试了一档，版本这一条还没排除。
			values["otherVersionSilent"] = true
		}
		return verdict, nil
	}
	values["answered"] = true
	t.systemValues(values, info)
	values["elapsedMs"] = time.Since(start).Milliseconds()
	return ots.Verdict{Code: snmpOk, Values: values,
		Note: fmt.Sprintf("%s 答了（%s，团体名可用）：%s", t.host,
			snmpVersionName(t.client.Version), info.note())}, nil
}

// sysInfo 是从系统组读回来的那几栏，外加一句给人看的话。
type sysInfo struct {
	descr    string
	objectID string
	upTicks  uint64
	name     string
	location string
	missing  []string
}

// note 攒一句设备身份。★ 什么都没读到时不许空着：
// 「设备答了但系统组是空的」本身是一条信息，界面上要看得见。
func (s sysInfo) note() string {
	if s.descr == "" && s.name == "" {
		if len(s.missing) > 0 {
			return "设备答了，但系统组基本是空的（没填：" + strings.Join(s.missing, "、") + "）"
		}
		return "设备答了，但没读到 sysDescr"
	}
	if s.descr == "" {
		return "设备名 " + s.name
	}
	first := s.descr
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if s.name != "" && !strings.Contains(first, s.name) {
		first += "（设备名 " + s.name + "）"
	}
	if s.upTicks > 0 {
		first += "，已开机 " + humanUptime(s.upTicks/100)
	}
	return first
}

// sysOIDs 按这个顺序问，也按这个顺序记「哪几栏设备没填」。
var sysOIDs = []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysContact,
	oidSysName, oidSysLocation, oidSysServices}

// systemInfo 问系统组。
//
// ★ 一次 GET 问七栏，但 v1 设备里「这一栏没有」是用 error-status=noSuchName
//
//	表达**整个报文**的（v2c 才是一栏一个 noSuchInstance）—— 所以 v1 且整包被拒时
//	退成一栏一栏问。不退这一步的话，一台少填一栏的老设备会什么都读不到，
//	而界面上显示的是「这台设备没回话」。
func (t *snmpTarget) systemInfo(ctx context.Context, values map[string]any) (sysInfo, error) {
	vs, err := t.client.Get(ctx, sysOIDs...)
	if err != nil {
		var de *snmp.Error
		if t.client.Version == snmp.V1 && errors.As(err, &de) && de.Status == 2 {
			if vs, err = t.systemInfoOneByOne(ctx); err != nil {
				return sysInfo{}, err
			}
		} else {
			return sysInfo{}, err
		}
	}
	s := readSys(vs)
	if values != nil {
		t.systemValues(values, s)
	}
	return s, nil
}

// systemInfoOneByOne 一栏一栏问（v1 整包被拒时的退路）。
// 第一栏就问不通就不再往下问 —— 那是设备不通，不是它少填一栏。
func (t *snmpTarget) systemInfoOneByOne(ctx context.Context) ([]snmp.VarBind, error) {
	var out []snmp.VarBind
	for i, oid := range sysOIDs {
		vs, err := t.client.Get(ctx, oid)
		if err != nil {
			var de *snmp.Error
			if errors.As(err, &de) && de.Status == 2 {
				continue // 这一栏它没有
			}
			if i == 0 {
				return nil, err
			}
			continue
		}
		out = append(out, vs...)
	}
	return out, nil
}

func readSys(vs []snmp.VarBind) sysInfo {
	byOID := make(map[string]snmp.VarBind, len(vs))
	for _, v := range vs {
		byOID[strings.TrimPrefix(v.OID, ".")] = v
	}
	var s sysInfo
	for _, oid := range sysOIDs {
		v, ok := byOID[strings.TrimPrefix(oid, ".")]
		if !ok || v.Missing() || v.EndOfMib() {
			s.missing = append(s.missing, sysKey(oid))
			continue
		}
		switch oid {
		case oidSysDescr:
			s.descr = printable(v.Str())
		case oidSysObjectID:
			if o, err := snmp.AsOID(v.Val); err == nil {
				s.objectID = strings.TrimPrefix(o, ".")
			}
		case oidSysUpTime:
			s.upTicks = v.UintOr0()
		case oidSysName:
			s.name = printable(v.Str())
		case oidSysLocation:
			s.location = printable(v.Str())
		}
	}
	return s
}

// systemValues 把系统组写进结果。★ 没读到的栏**不写成空字符串**：
// 「设备没填 sysLocation」和「设备填了一个空串」在现场是两件事，
// 前者出现在 values["sysMissing"] 里。
func (t *snmpTarget) systemValues(values map[string]any, s sysInfo) {
	if s.descr != "" {
		values["sysDescr"] = s.descr
	}
	if s.objectID != "" {
		values["sysObjectID"] = s.objectID
		if v := snmpVendor(s.objectID); v != "" {
			values["vendor"] = v
		}
	}
	if s.name != "" {
		values["sysName"] = s.name
	}
	if s.location != "" {
		values["sysLocation"] = s.location
	}
	if s.upTicks > 0 {
		secs := s.upTicks / 100 // TimeTicks 的单位是 1/100 秒
		values["uptimeSeconds"] = secs
		values["uptime"] = humanUptime(secs)
	}
	if len(s.missing) > 0 {
		values["sysMissing"] = s.missing
	}
}

func sysKey(oid string) string {
	switch oid {
	case oidSysDescr:
		return "sysDescr"
	case oidSysObjectID:
		return "sysObjectID"
	case oidSysUpTime:
		return "sysUpTime"
	case oidSysContact:
		return "sysContact"
	case oidSysName:
		return "sysName"
	case oidSysLocation:
		return "sysLocation"
	case oidSysServices:
		return "sysServices"
	}
	return oid
}

// printable 把设备上读回来的字符串收成人和 AI 都能看的写法。
//
// ★ sysDescr 经常带尾部的 \r\n 甚至二进制填充（有些实现按定长补 0），
//
//	原样贴进结果会把界面顶成一堆乱码；但它确实是设备给的内容，
//	所以留其形、去其害：不可打印的字节换成一个 □，不删整段。
func printable(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.Trim(s, "\n\x00 ")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteRune('□')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func humanUptime(secs uint64) string {
	const (
		d   = 86400
		hur = 3600
	)
	var parts []string
	if x := secs / d; x > 0 {
		parts = append(parts, strconv.FormatUint(x, 10)+" 天")
	}
	if x := secs % d / hur; x > 0 || len(parts) > 0 {
		parts = append(parts, strconv.FormatUint(x, 10)+" 小时")
	}
	if x := secs % hur / 60; x > 0 || len(parts) == 0 && secs >= 60 {
		parts = append(parts, strconv.FormatUint(x, 10)+" 分")
	}
	// ★ 一小时以内把秒也带上：「这个口 0 分前才翻过状态」在现场等于没说 ——
	//   查的就是这一格，10 秒前和 59 分前是两个完全不同的结论。
	if secs < hur {
		if x := secs % 60; x > 0 || len(parts) == 0 {
			parts = append(parts, strconv.FormatUint(x, 10)+" 秒")
		}
	}
	return strings.Join(parts, "")
}

// snmpVendor 从 sysObjectID 认厂商。
//
// ★ 只看企业号那一段（1.3.6.1.4.1.<PEN>），认不出来就**什么都不写**：
//
//	界面上「厂商」是照着这一栏排顺序的，猜一个名字比空着更害人。
func snmpVendor(objectID string) string {
	const pen = "1.3.6.1.4.1."
	if !strings.HasPrefix(objectID, pen) {
		return ""
	}
	rest := objectID[len(pen):]
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		rest = rest[:i]
	}
	switch rest {
	case "9":
		return "Cisco"
	case "11":
		return "HP"
	case "2636":
		return "Huawei"
	case "2011", "25506":
		return "Ruijie"
	case "4881":
		return "ZTE"
	case "171":
		return "Nokia"
	case "1916":
		return "Extreme"
	case "19104":
		return "MikroTik"
	case "2637":
		return "TP-Link"
	case "674", "4526":
		return "D-Link"
	case "45941":
		return "VMware"
	}
	return ""
}
