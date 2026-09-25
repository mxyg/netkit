package tools

// ── media.gb28181.probe / media.gb28181.register ──
//
// ★ 一句「国标设备接不上」在现场落在七种完全不同的地方，而这七种在界面上
//
//	长得一模一样（都是「没回应」或一个状态码）：
//	这个口是关的 / 口开着没人答 / 口上跑着别的东西 / 它回的是 SIP 但读不成句 /
//	它接 OPTIONS 却不接查询 / 它接了查询不给正文 / 它答得清清楚楚而通道表是空的。
//	所以判定码按「死在哪一步、下一步各不一样」分档，不按协议报文分档。
//	底座那一份（internal/gb28181）把这几件事分成封闭的 Kind，这里只按 Kind 选码 ——
//	★ 不拿中文文本匹配：文案要改，判定不能跟着漂。
//
// ★ probe 归 read、register 归 mutate [OTS-4.3]：
//
//	发一条 OPTIONS 或 MESSAGE 只是问话，不改谁的状态；而 REGISTER 会**让那台平台
//	多出一个在线设备** —— 填的要是真设备的编号，这一发会顶掉那条真注册，
//	现场立刻表现为「那台相机掉线」。所以注册必须走批准与账本，并且问完就注销
//	（不提供一个「留着注册」的开关：本机没有能把别人的注册收回来的东西，
//	留着一个收不回的改动等于埋雷）。
//
// ★★ 凭据纪律：注册口令只进那一次 MD5 计算。
//
//	它不进结果、不进日志、不进账本、不进批准框那句话，连「签名对不上」的报错里
//	都不复述 —— 结果会被发给 AI，也可能被打进诊断包。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"net.yuhox.com/netkit/internal/gb28181"
	"net.yuhox.com/netkit/internal/ots"
)

// 判定码。前缀一律 gb28181-，两条问法共用传输那几档：
// 「口是关的」「没人答」「回的不是 SIP」在探测与注册里是同一句话、同一个下一步。
const (
	verdictGBPortClosed   = "gb28181-port-closed"
	verdictGBSilent       = "gb28181-silent"
	verdictGBNotSIP       = "gb28181-not-sip"
	verdictGBUnreadable   = "gb28181-sip-unreadable"
	verdictGBAuthRequired = "gb28181-auth-required"
	verdictGBDenied       = "gb28181-denied"
	verdictGBBusy         = "gb28181-busy"
	verdictGBAlive        = "gb28181-alive"
	verdictGBResponsive   = "gb28181-responsive"
	verdictGBQuerySilent  = "gb28181-query-silent"
	verdictGBEmptyBody    = "gb28181-empty-body"
	verdictGBBadBody      = "gb28181-bad-body"
	verdictGBCatalogEmpty = "gb28181-catalog-empty"
	verdictGBCutShort     = "gb28181-cut-short" // 预算到点，问到哪儿算哪儿

	verdictGBRegistered         = "gb28181-registered"
	verdictGBRegisteredAccepted = "gb28181-registered-accepted"
	verdictGBRegisteredNoAuth   = "gb28181-registered-unauthenticated"
	verdictGBChallengeMissing   = "gb28181-challenge-missing"
	verdictGBCredentialRejected = "gb28181-credential-rejected"
)

const (
	gbDefaultPort = 5060
	// MANSCDP 正文的类型。★ 只在这一处写死拼法：Content-Length 由底座跟着正文算，
	// 这一串写错的表现是「设备收了却不答」，而那看着和网络不通一模一样。
	gbContentType = "Application/MANSCDP+xml"
	gbUserAgent   = "netkit"
)

// 每一问的落点（写进 queries 里，界面按它逐条说话）。
const (
	gbAskOK        = "ok"
	gbAskSilent    = "silent"
	gbAskStatus    = "status"
	gbAskFault     = "transport" // 这一问连收发都没成（口关了 / 回的不是 SIP）
	gbAskEmptyBody = "empty-body"
	gbAskBadBody   = "bad-body"
	gbAskCut       = "cut-short" // 这一问是我们自己到的时间掐断的，不是它不答
)

var gbProbeTool = ots.Tool{
	Name:  "media.gb28181.probe",
	Class: ots.ClassRead,
	Summary: "问一个国标（GB28181）信令口：先发 OPTIONS 看它在不在这个行当，" +
		"再按需要发 MESSAGE 问设备自述（DeviceInfo）、在线状态（DeviceStatus）与通道表（Catalog），" +
		"把「国标设备接不上」拆成口是关的、口开着没人答、口上跑着别的东西、回的是 SIP 但读不成句、" +
		"它只接 OPTIONS 不接查询、接了查询不给正文、正文是坏的、答得清楚但通道是空的这几档。" +
		"★ 这问的是**信令这一层**：全程不解码、不放播放器、不发 INVITE —— 点播会真的占住一路码流，那是改动，本工具不做。" +
		"只读：三类查询都只是问一句，不改设备配置、不动通道。" +
		"中文名按 GBK 发的老固件也读得通：那一条会单独说明「看着像乱码是设备发的编码，不是工具坏了」。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["host"],
	  "properties": {
	    "host": {"type": "string", "description": "国标设备或平台的地址（IP 或域名）。问的是它的 SIP 信令口，不是取流口"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "SIP 信令口，默认 5060。国标另常用 5061，那一个通常挂 TLS —— 本工具只按 UDP 问，问到 5061 多半报「回的不是 SIP」"},
	    "deviceId": {"type": "string", "description": "被问的那台，20 位国标编号。填了才能问 MESSAGE 那三类（查询正文里要写目标编号，请求行也按它拼）；只发 OPTIONS 时可以不填"},
	    "platformId": {"type": "string", "description": "本端这一头的 20 位编号（国标里叫采集控制点）。★ 发查询必填：设备按自己配好的那个平台编号核对来路，没报上名字的表现就是它一声不吭 —— 那不是网络不通"},
	    "ask": {"type": "array", "items": {"type": "string", "enum": ["deviceInfo", "deviceStatus", "catalog"]}, "description": "OPTIONS 通了之后接着问哪几样，每样各一问、各自记账。不填 = 只问 OPTIONS"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 60000, "description": "一问的总预算毫秒数（内含 500 毫秒起翻倍的超时重发），默认 3000。★ 只发一条就下「没人答」的结论不算：UDP 丢一个包就冤枉一台设备"},
	    "catalogStart": {"type": "integer", "minimum": 1, "description": "通道表从第几条开始问（分页），与 catalogCount 一起填才生效；都不填是要全量"},
	    "catalogCount": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "通道表这一页最多要几条。★ 只问一页就按「它一共几路」下结论是把账混了 —— 设备自己声明的 SumNum 与这一页数到的条数分开给"}
	  }
	}`),
	Invoke: probeGB28181,
}

type gbProbeArgs struct {
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"`
	DeviceID     string   `json:"deviceId,omitempty"`
	PlatformID   string   `json:"platformId,omitempty"`
	Ask          []string `json:"ask,omitempty"`
	TimeoutMS    int      `json:"timeoutMs,omitempty"`
	CatalogStart int      `json:"catalogStart,omitempty"`
	CatalogCount int      `json:"catalogCount,omitempty"`
}

func probeGB28181(ctx context.Context, raw json.RawMessage) (any, error) {
	var a gbProbeArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	host := strings.TrimSpace(a.Host)
	if host == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"没给 host —— 要问的是国标设备或平台的 SIP 信令口地址")
	}
	port := a.Port
	if port == 0 {
		port = gbDefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "port 是 %d，不在 1-65535 之间", port)
	}
	step, err := gbTimeout(a.TimeoutMS)
	if err != nil {
		return nil, err
	}
	deviceID, err := gbCode(a.DeviceID, "deviceId")
	if err != nil {
		return nil, err
	}
	platformID, err := gbCode(a.PlatformID, "platformId")
	if err != nil {
		return nil, err
	}
	asks, err := gbAsks(a.Ask)
	if err != nil {
		return nil, err
	}
	if len(asks) > 0 && (deviceID == "" || platformID == "") {
		// ★ 这里不代填一个编号：设备按它配好的那个平台编号核对来路，
		//   随手编一个只会换来一句「没回应」，而那正是这一层最难看的假象。
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"要发查询（ask）就得同时给 deviceId 与 platformId：查询正文里要写目标编号，"+
				"来路也要报一个采集控制点编号 —— 没报上名字的表现是它一声不吭，那不是网络不通")
	}
	if a.CatalogStart < 0 || a.CatalogCount < 0 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "分页只能从第 1 条起、最多 1000 条")
	}

	values := map[string]any{
		"peer":   net.JoinHostPort(host, strconv.Itoa(port)),
		"host":   host,
		"port":   port,
		"proto":  "udp",
		"device": deviceID,
		"domain": platformID,
	}
	c, err := gb28181.DialClient(host, strconv.Itoa(port))
	if err != nil {
		return nil, gbDialError(err)
	}
	defer c.Close()
	values["local"] = net.JoinHostPort(c.LocalHost(), c.LocalPort())

	// ── 第一问：OPTIONS。它在不在、肯不肯答、报的什么能力，全在这一问里 ──
	uri := gb28181.SIPURI(deviceID, host, strconv.Itoa(port))
	optReq := gbRequest(c, gb28181.MethodOptions, uri, platformID, platformID, nil, "", -1)
	reply, err := c.Request(optReq, "options", gbStep(ctx, step))
	gbFillReply(values, "options", reply)
	if err != nil {
		if gb28181.KindOf(err) == gb28181.KindStatus && gb28181.StatusOf(err) == 401 {
			// ★ 401 单独说一句：这一档的下一步是「带编号与口令走注册」，
			//   与「去查防火墙」完全是两条路。
			values["status"] = 401
			return ots.Verdict{Code: verdictGBAuthRequired, Values: values,
				Note: "这个口认 SIP，但它要先看凭据才答 —— 它是按国标在收设备的那一头。" +
					"想问出内容就带上编号与口令走一趟注册，或让这台把本机放进口令清单"}, nil
		}
		return gbFault(values, err), nil
	}
	gbFillOptions(values, reply.Final)
	if len(asks) == 0 {
		// ★ 「只问到它在」不能写成「它什么都答得出」：没问的那几样在这条判定里根本没出现过。
		return ots.Verdict{Code: verdictGBAlive, Values: values,
			Note: "OPTIONS 通了，这是一个 SIP/国标信令口" + gbAllowNote(values) +
				" —— 设备自述与通道表这次没问，要问就带 ask"}, nil
	}

	// ── 接着按样问：每样各一问，各自记账 ──
	results := make([]gbAskResult, 0, len(asks))
	for i, cmdType := range asks {
		if ctx.Err() != nil {
			break
		}
		results = append(results, gbAskOne(ctx, c, step, uri, platformID, deviceID,
			cmdType, strconv.Itoa(i+1), a.CatalogStart, a.CatalogCount))
	}
	return gbProbeOutcome(values, results, step), nil
}

// gbAskResult 是一类查询这一问的账。★ 键名是给界面读的，所以每格都自带「问到哪儿了」——
// 现场要对照的是「自述答了、通道表没答」这种一半一半的情形。
type gbAskResult struct {
	CmdType   string            `json:"cmdType"`
	SN        string            `json:"sn"`
	Kind      string            `json:"outcome"`
	FaultKind string            `json:"transport,omitempty"`
	RTTMS     int64             `json:"ms,omitempty"`
	Sent      int               `json:"sent,omitempty"`
	Status    int               `json:"status,omitempty"`
	Detail    string            `json:"detail,omitempty"`
	Root      string            `json:"root,omitempty"`
	Matches   bool              `json:"answersThisQuery,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	// ★ 这两格用指针：通道表「数到 0 条」与「它自己声明 0 路」都是事实，
	//   非零缺省时 omitempty 会把 0 抹掉，屏幕上就只剩判定那句话在说 0 —— 判定与账分了家。
	//   Items 只在通道表那一问带：自述/状态问没有「条数」这回事，报 0 是无中生有。
	Items     *int     `json:"items,omitempty"`
	SumNum    *int     `json:"sumNum,omitempty"`
	DeviceIDs []string `json:"channelIds,omitempty"`
	Missing   int      `json:"channelsWithoutId,omitempty"`
	NonUTF8   bool     `json:"nonUTF8,omitempty"`
	Repeated  []string `json:"repeatedKeys,omitempty"`
	Shape     []string `json:"oddShape,omitempty"`
}

func gbAskOne(ctx context.Context, c *gb28181.Client, step time.Duration,
	uri, platformID, deviceID, cmdType, sn string, start, count int) gbAskResult {
	var body []byte
	switch cmdType {
	case gb28181.CmdDeviceInfo:
		body = gb28181.DeviceInfoQuery(sn, deviceID)
	case gb28181.CmdDeviceStatus:
		body = gb28181.DeviceStatusQuery(sn, deviceID)
	case gb28181.CmdCatalog:
		body = gb28181.CatalogQuery(sn, deviceID, start, count)
	}
	req := gbRequest(c, gb28181.MethodMessage, uri, platformID, platformID, body, gbContentType, 0)
	res := gbAskResult{CmdType: cmdType, SN: sn}
	budget := gbStep(ctx, step)
	// ★ 「这一问的预算是被整体截止时间压出来的」必须在动手之前记：
	//   到点之后再问「还剩多少」只会得到负数，那种问法分不开「它不答」与「我们没等够」。
	dl, hasDeadline := ctx.Deadline()
	clamped := hasDeadline && time.Until(dl) < step
	askedAt := time.Now()
	reply, err := c.Request(req, "message", budget)
	if reply != nil { // 本机这一步就没起来时 reply 是 nil：那一格空着，不拿 0 冒充「发了 0 次」
		res.Sent = reply.Sent
		res.RTTMS = reply.Elapsed.Milliseconds()
	}
	if err != nil {
		res.Status = gb28181.StatusOf(err)
		res.Detail = maskSecretText(gbDetail(err))
		switch {
		case res.Status > 0:
			res.Kind = gbAskStatus
		case gb28181.KindOf(err) == gb28181.KindTimeout:
			// 「超时」有两种：它不回，和**我们自己的预算到点了**。把后者报成前者，
			// 人会拿着一句「它不认这个查询」去翻一台好设备的能力表。
			if clamped && time.Since(askedAt)+50*time.Millisecond >= budget {
				res.Kind = gbAskCut
			} else {
				res.Kind = gbAskSilent
			}
		default:
			// ★ 不能把「口这会儿又不通了」「回的不是 SIP」也记成「没人答」：
			//   OPTIONS 明明答过，这一档的下一步是去查中间那台，不是查它答不答这句。
			res.Kind = gbAskFault
			res.FaultKind = gb28181.KindOf(err)
		}
		return res
	}
	cmd, berr := gb28181.BodyCmd(reply.Final)
	if berr != nil {
		res.Kind = gbAskBadBody
		res.Detail = maskSecretText(gbDetail(berr))
		if gb28181.KindOf(berr) == gb28181.KindNoBody {
			res.Kind = gbAskEmptyBody
		}
		return res
	}
	res.Kind = gbAskOK
	res.Root = cmd.Root
	res.Matches = cmd.IsResponseTo(cmdType, sn)
	res.Fields = gbMaskFields(cmd.Fields)
	// ★ 条数只有通道表那一问才成其为账：自述与状态问没有「几条」这回事，
	//   给它们记一个 0 会让人以为「这台自述里数到 0 条」。
	if cmdType == gb28181.CmdCatalog {
		n := cmd.ItemCount()
		res.Items = &n
	}
	if s, ok := cmd.SumNum(); ok {
		res.SumNum = &s
	}
	res.DeviceIDs, res.Missing = cmd.ItemDeviceIDs()
	res.NonUTF8 = cmd.NonUTF8
	res.Repeated = cmd.Repeated
	res.Shape = cmd.Ambiguous
	return res
}

// gbProbeOutcome 把「OPTIONS 的答案 + 每样查询的答案」收成一条判定。
// ★ 取第一条没问成的落点：现场要的是「先死在哪一步」，
//
//	把后面问成的并列上去会让人以为前面那条不重要。全部问成了才报「 responsive」。
func gbProbeOutcome(values map[string]any, results []gbAskResult, step time.Duration) ots.Verdict {
	values["queries"] = results
	for _, r := range results {
		switch r.Kind {
		case gbAskFault:
			values["queryOutcome"] = r.CmdType
			code, line := gbTransportWords(r.FaultKind, r.Detail)
			return ots.Verdict{Code: code, Values: values,
				Note: fmt.Sprintf("OPTIONS 它答了，「%s」这一问却连收发都没成 —— %s", r.CmdType, line)}
		case gbAskSilent:
			values["queryOutcome"] = r.CmdType
			return ots.Verdict{Code: verdictGBQuerySilent, Values: values,
				Note: fmt.Sprintf("OPTIONS 它答了，「%s」这一问发了 %d 次、%s 之内没回音 —— "+
					"这一档多半是它不认这个查询（来路编号不对、或这条能力没开），"+
					"不是网络不通：网络不通的话 OPTIONS 也回不来。★ 也有源端口的另一种：它从另一个口回话，"+
					"这一问的套接字只收对端那一对地址，那种表现同样是超时",
					r.CmdType, r.Sent, step)}
		case gbAskStatus:
			values["queryOutcome"] = r.CmdType
			code, line := gbStatusWords(r.Status, r.Detail)
			// ★ 不再在头上写一遍「它回了 405」：下面那一栏自己就带着码开头，
			//   重复一遍屏幕上就成了「它回了 405 —— 它回了 405 ——」，像没写完的话。
			return ots.Verdict{Code: code, Values: values,
				Note: fmt.Sprintf("OPTIONS 它答了，「%s」这一问：%s", r.CmdType, line)}
		case gbAskCut:
			values["queryOutcome"] = r.CmdType
			values["asked"] = len(results)
			return ots.Verdict{Code: verdictGBCutShort, Values: values,
				Note: fmt.Sprintf("问到哪儿算哪儿：%s；「%s」这一问是这次的预算到点了，"+
					"不是它不答 —— 把 timeoutMs 放宽（或少问几样）再跑一次，这一条不能用来判断它有没有这项能力",
					gbCutAskedNote(results, r.CmdType), r.CmdType)}
		case gbAskEmptyBody:
			values["queryOutcome"] = r.CmdType
			return ots.Verdict{Code: verdictGBEmptyBody, Values: values,
				Note: fmt.Sprintf("它对「%s」回了 200，可正文是空的 —— 这句它接了但没答内容。"+
					"多半是固件把这一类查询当形式应答（或它要求先注册再答）；下一步走注册那条问法", r.CmdType)}
		case gbAskBadBody:
			values["queryOutcome"] = r.CmdType
			return ots.Verdict{Code: verdictGBBadBody, Values: values,
				Note: "它回了正文，可读不成 MANSCDP：" + r.Detail +
					" —— 有的固件在这一句上发的是别的内容类型，那种要按它发的算，不能当没答"}
		}
	}
	// 一问都没发出去（整趟在问完 OPTIONS 之前就被取消了）：报「问到哪儿算哪儿」，
	// 不报「它什么都答不上」—— 那是我们没问，不是它没答。
	if len(results) == 0 {
		values["asked"] = 0
		return ots.Verdict{Code: verdictGBAlive, Values: values,
			Note: "OPTIONS 通了，但后面那几问一问都没发出去（这一趟在问完之前就到了时间）—— " +
				"这次只能回答「它是一个 SIP/国标信令口」，把 timeoutMs 放宽或少问几样再跑一次"}
	}
	// 到这儿每样都答了。通道表答了 0 条是单独一档：那是「在线但通道是空的」这条线的头。
	shapes := gbShapeNote(results)
	for _, r := range results {
		if r.CmdType == gb28181.CmdCatalog && gbItems(r) == 0 {
			declared := "它自己没声明 SumNum"
			if r.SumNum != nil {
				declared = fmt.Sprintf("它自己声明有 %d 路", *r.SumNum)
			}
			note := fmt.Sprintf("通道表答了，可这一页数到 0 条（%s）—— 现场「平台说设备在线、通道是空的」就死在这一格。"+
				"先看是不是只问了第一页、或这台把通道挂在别的编号下", declared)
			return ots.Verdict{Code: verdictGBCatalogEmpty, Values: values,
				Note: withShape(note, shapes)}
		}
	}
	first := results[0]
	note := fmt.Sprintf("问到内容了：%s", gbAskedNote(results))
	if !first.Matches {
		note += "；★ 有一问的正文里 CmdType/SN 与发出去的那一问对不上，条数照数，但别按「它就是答我这一问」用"
	}
	return ots.Verdict{Code: verdictGBResponsive, Values: values, Note: withShape(note, shapes)}
}

// gbTransportWords 一个传输落点 => 判定码 + 那句话。★ 按 Kind 选，不看中文。
// probe 的「某一问」与 register 的「整趟」共用这一张表：同一句毛病在两处得是同一个码。
func gbTransportWords(kind string, detail string) (string, string) {
	switch kind {
	case gb28181.KindRefused:
		return verdictGBPortClosed, "这个 UDP 口是关的（对端回了不可达）—— 先看地址与口抄对没有，" +
			"再看那一头上 SIP 服务起没起来。这一档和「开着没人答」的下一步完全不同"
	case gb28181.KindTimeout:
		return verdictGBSilent, "发出去了，到点一个字节都没回来 —— 中间有东西吃掉（防火墙、交换机 ACL、平台白名单）" +
			"或它压根不理这一句。★ 还有一种：它从**另一个端口**回话，而这一问的套接字只收对端那一对地址，" +
			"那种表现也是超时 —— 换个口再问一次看看"
	case gb28181.KindNotSIP:
		return verdictGBNotSIP, "这个口上有东西在答话，可回的不是 SIP：" + detail +
			" —— 口的号配错了服务，先核对它到底在跑什么"
	case gb28181.KindBadMessage:
		return verdictGBUnreadable, "起始行看着是 SIP，可这条报文读不成句：" + detail +
			" —— 多半是中间有那台（SIP 网关、ALG）改写了报文，或它的固件发的不是标准 CRLF"
	}
	return "", ""
}

// gbItems 取通道表数到的条数（没记这一格时按 0 算，只有「压根没问通道表」时才会没这一格）。
func gbItems(r gbAskResult) int {
	if r.Items == nil {
		return 0
	}
	return *r.Items
}

// gbAskedNote 那句「 responsive」要说清这次真问到了什么 —— 判定与它的账必须同源。
func gbAskedNote(results []gbAskResult) string {
	var parts []string
	for _, r := range results {
		switch r.CmdType {
		case gb28181.CmdCatalog:
			parts = append(parts, fmt.Sprintf("通道表 %d 路", gbItems(r)))
		case gb28181.CmdDeviceStatus:
			parts = append(parts, "在线状态：状态 "+firstNonEmpty(r.Fields["status"], "没带 Status"))
		case gb28181.CmdDeviceInfo:
			parts = append(parts, "设备自述 "+strconv.Itoa(len(r.Fields))+" 个字段")
		}
	}
	return strings.Join(parts, "、")
}

// gbCutAskedNote 被掐断之前问成了哪几样 —— 「问到哪儿算哪儿」得说清那个「哪儿」。
func gbCutAskedNote(results []gbAskResult, cut string) string {
	var done []gbAskResult
	for _, r := range results {
		if r.CmdType == cut || r.Kind != gbAskOK {
			break
		}
		done = append(done, r)
	}
	if len(done) == 0 {
		return "在问出内容之前就到了时间"
	}
	return "前面问成了：" + gbAskedNote(done)
}

// gbShapeNote 每一问各带一处「读得动但形状不规矩」的账 —— 报出来，不替人判断。
// ★ 按问法归拢：三条查询里是哪一个的正文有非 UTF-8 字节，说清了人才知道去哪儿找。
func gbShapeNote(results []gbAskResult) string {
	var s []string
	for _, r := range results {
		note := gbShapeOf(r)
		if note == "" {
			continue
		}
		label := r.CmdType
		if label == "" {
			label = "应答"
		}
		s = append(s, label+"："+note)
	}
	if len(s) == 0 {
		return ""
	}
	return "形状上有几处要留心的：" + strings.Join(s, " ｜ ")
}

// gbShapeOf 某一问的形状账；干净时回空串。
// ★ 回空串而不是「条目里都带着编号」那种客套话：调用方靠「有没有话」决定说不说，
//
//	把没毛病写成一句陈述，判定里就凭空多出一段谁也没问的东西。
func gbShapeOf(r gbAskResult) string {
	var s []string
	if r.NonUTF8 {
		s = append(s, "正文里有按 UTF-8 解不出来的字节：中文名看着像乱码是设备发的编码，不是工具坏了")
	}
	if len(r.Repeated) > 0 {
		s = append(s, "同层出现多次的同名键："+strings.Join(r.Repeated, "、")+"（取的是第一个）")
	}
	if len(r.Shape) > 0 {
		s = append(s, "按条目记了数、但形状上也可能只是字段包装的那一层："+strings.Join(r.Shape, "、"))
	}
	if r.Missing > 0 {
		s = append(s, fmt.Sprintf("有 %d 条条目没带编号", r.Missing))
	}
	return strings.Join(s, "；")
}

// withShape 有形状账就接在后面，没有就不留一个孤零零的分号。
func withShape(note, shapes string) string {
	if shapes == "" {
		return note
	}
	return note + "。" + shapes + "。"
}

// gbFillOptions 把 OPTIONS 答案里能用上的那几样留下。
// ★ Allow 是这一问最值钱的一格：它不列 MESSAGE，后面那三类查询就别指望。
func gbFillOptions(values map[string]any, msg *gb28181.Message) {
	if msg == nil {
		return
	}
	if v := msg.Get(gb28181.HAllow); v != "" {
		var list []string
		for _, m := range strings.Split(v, ",") {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
				list = append(list, m)
			}
		}
		values["allow"] = list
	}
	if v := msg.Get(gb28181.HUserAgent); v != "" {
		values["userAgent"] = maskSecretText(v)
	}
	if v := msg.Get("Server"); v != "" {
		values["server"] = maskSecretText(v)
	}
	values["bodyBytes"] = len(msg.Body)
}

func gbAllowNote(values map[string]any) string {
	list, ok := values["allow"].([]string)
	if !ok || len(list) == 0 {
		return "（它没报 Allow，所以能接哪几句还不知道）"
	}
	return "，它报的能力有 " + strings.Join(list, "、")
}

// gbRequest 起一条发给对端的请求。
//
// ★ 被叫只写在 uri 里：To 照它包一层尖括号，不再单传一个 toUser ——
//
//	两处各写一遍时，「Request-URI 与 To 不是同一个」恰好是最容易拼错、
//	又最难从现象看出来的那种（对端按 To 认目标，按 Request-URI 路由）。
//
// ★ From/Contact 用本机这一头**实际**用到的地址与口（Client.LocalHost/LocalPort），
//
//	不用配置里那个：绑在通配地址上时两者经常不是一回事，写错了对端的回包
//	就发给一个没人听的口 —— 表现成「发了，超时」。
//
// ★ expires 传 -1 是「这一句不带 Expires 头」，传 0 是「带 Expires: 0」——
//
//	注销靠的就是后者，把两者并成一档的话，注销那发看起来跟普通注册一模一样。
func gbRequest(c *gb28181.Client, method, uri, fromUser, contactUser string,
	body []byte, contentType string, expires int) *gb28181.Message {
	via := gb28181.NewVia(c.LocalHost(), c.LocalPort())
	from := "<" + gb28181.SIPURI(fromUser, c.LocalHost(), c.LocalPort()) + ">;tag=" + gb28181.NewTag()
	to := "<" + uri + ">"
	req := gb28181.NewRequest(method, uri, from, to,
		gb28181.NewTag()+"@"+c.LocalHost(), via.String(), c.NextCSeq())
	if contactUser == "" {
		contactUser = fromUser // 没报采集控制点时，Contact 至少要说清这一发是从哪个身份发出的
	}
	contact := "<" + gb28181.SIPURI(contactUser, c.LocalHost(), c.LocalPort()) + ">"
	req.Set(gb28181.HContact, contact)
	req.Set(gb28181.HUserAgent, gbUserAgent)
	if expires >= 0 {
		req.Set(gb28181.HExpires, strconv.Itoa(expires))
	}
	if len(body) > 0 {
		req.Body = body
		req.Set(gb28181.HContentType, contentType)
	}
	return req
}

// gbFillReply 把一次问答的收发账留下。★ sent 与 interims 是给「没人答」这句话作证的：
// 只发一条就报超时，与发过三次、收到过 100 Trying 之后没下文，是两种毛病。
func gbFillReply(values map[string]any, prefix string, reply *gb28181.Reply) {
	if reply == nil {
		return
	}
	values[prefix+"Sent"] = reply.Sent
	values[prefix+"Ms"] = reply.Elapsed.Milliseconds()
	if n := len(reply.Interims); n > 0 {
		values[prefix+"Interims"] = n
	}
}

// gbFault 把一次收发失败落成判定码。★ 按 Kind 选码，不看中文。
func gbFault(values map[string]any, err error) ots.Verdict {
	kind := gb28181.KindOf(err)
	detail := maskSecretText(gbDetail(err))
	values["detail"] = detail
	if code, line := gbTransportWords(kind, detail); code != "" {
		return ots.Verdict{Code: code, Values: values, Note: line}
	}
	if kind == gb28181.KindStatus {
		code, line := gbStatusWords(gb28181.StatusOf(err), detail)
		values["status"] = gb28181.StatusOf(err)
		return ots.Verdict{Code: code, Values: values, Note: line}
	}
	values["kind"] = kind
	return ots.Verdict{Code: ots.CodeUnknown, Values: values,
		Note: "这一问的落点我们没有一个对应判定，把已经问到的照实给出：" + detail}
}

// gbStatusWords 一个状态码在这个行当里意味着哪一步下一步。
// ★ 只按码分档、不猜它的文案：原因短语是给人看的，各家写得不一样。
func gbStatusWords(code int, detail string) (string, string) {
	switch code {
	case 401, 407:
		return verdictGBAuthRequired, "它要先看凭据才答（" + strconv.Itoa(code) + "）—— " +
			"这一档下一步是带上编号与口令走一趟注册，不是去查网络"
	case 403:
		return verdictGBDenied, "它回了 403 —— 本机或这个编号不在它的清单里。先核编号，再核那台上的授权名单"
	case 404:
		return verdictGBDenied, "它回了 404 —— 这个编号它那儿没有：查询目标写错，或那台设备压根没在它这里注册过"
	case 405, 501:
		return verdictGBDenied, "它回了 " + strconv.Itoa(code) + " —— 这一句它不接（这个方法不在它的能力里）。" +
			"问通道表就别看这一句，改走注册那一条让它自己来问"
	case 480, 486, 500, 503, 504:
		return verdictGBBusy, "它回了 " + strconv.Itoa(code) + " —— 它在，可这一刻腾不出手（占用满、正在重启、内部出错）。" +
			"这一档不该连着重试，先看它那台机器上在忙什么"
	}
	return verdictGBDenied, "它回了 " + strconv.Itoa(code) + "：" + firstNonEmpty(detail, "没有说明") +
		" —— 这个码我们没档，先照实留着"
}

// gbDetail 从 error 里取那句最能说明问题的话（不含任何凭据）。
func gbDetail(err error) string {
	var e *gb28181.Error
	if errors.As(err, &e) {
		if e.Detail != "" {
			return e.Detail
		}
		if e.Err != nil {
			return e.Err.Error()
		}
	}
	return err.Error()
}

// gbDialError 本机这一头就没起来 —— 这是参数或本机的问题，不是对端的病，报成错误而不是判定。
func gbDialError(err error) error {
	code := ots.ErrUnreachable
	if gb28181.KindOf(err) == gb28181.KindDial && strings.Contains(gbDetail(err), "解析不了") {
		code = ots.ErrInvalidArgument
	}
	return ots.Errf(code, "%s", maskSecretText(gbDetail(err)))
}

// gbTimeout 校验并折算一问的预算。★ 下限 500 毫秒不是凑数：
// 比这更短的预算里连一次 500 毫秒的重发都排不下，那条「没人答」是我们自己制造的。
func gbTimeout(ms int) (time.Duration, error) {
	if ms == 0 {
		return 3 * time.Second, nil
	}
	if ms < 500 || ms > 60000 {
		return 0, ots.Errf(ots.ErrInvalidArgument,
			"timeoutMs 只能填 500 到 60000 毫秒，给的是 %d（不填按 3000）—— "+
				"比 500 毫秒更短的预算里连一次超时重发都排不下，那种「没人答」是我们自己造出来的", ms)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// gbStep 把这一问的预算再按整趟的 ctx 剩余收一刀。ctx 没给截止时间时原样返回。
func gbStep(ctx context.Context, step time.Duration) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return step
	}
	left := time.Until(dl)
	if left < step {
		return left
	}
	return step
}

// gbCode 校验一段 20 位国标编号；空串放过（由各问法自己决定必填还是选填）。
// ★ 报错只说差在哪一位、差多少，不复述整串：抄错的编号是配置信息，
//
//	但把整串带进报错里，人反而看不出是哪一位错。
func gbCode(s, field string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if _, err := gb28181.ParseCode(s); err != nil {
		return "", ots.Errf(ots.ErrInvalidArgument, "%s 不像一段国标编号：%s —— 编号抄错一格，问出来的就是另一台设备", field, err)
	}
	return s, nil
}

// gbAsks 把 ask 里那几种写法归一成 CmdType，去重、按给定的顺序。
func gbAsks(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		var cmd string
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "deviceinfo", "device-info", "info":
			cmd = gb28181.CmdDeviceInfo
		case "devicestatus", "device-status", "status":
			cmd = gb28181.CmdDeviceStatus
		case "catalog":
			cmd = gb28181.CmdCatalog
		case "":
			continue
		default:
			return nil, ots.Errf(ots.ErrInvalidArgument,
				"ask 里有我们不认的一项：%q —— 能问的是 deviceInfo、deviceStatus、catalog", strings.TrimSpace(s))
		}
		if seen[cmd] {
			continue
		}
		seen[cmd] = true
		out = append(out, cmd)
	}
	return out, nil
}

// gbMaskFields 把应答里的叶子字段过一遍再进结果。
// ★ 控制字符吃掉、长串截断：这一份是要进结果、进日志、发给 AI 的。
func gbMaskFields(f gb28181.Fields) map[string]string {
	if len(f) == 0 {
		return nil
	}
	out := make(map[string]string, len(f))
	for _, k := range f.Keys() {
		out[k] = maskSecretText(f.Get(k))
	}
	return out
}

// ── media.gb28181.register ──

var gbRegisterTool = ots.Tool{
	Name:  "media.gb28181.register",
	Class: ots.ClassMutate,
	Summary: "本机按国标（GB28181）走一趟注册：REGISTER → 收 401 挑战 → 按 RFC 2617 算 MD5 摘要重试 → 看它给不给 200，" +
		"注册成功之后再看一段窗口：那台平台有没有回过头来问通道表、发点播 —— 那是「它真把这台当设备认下了」最硬的证据。" +
		"把「设备注册不上」拆成口是关的、开着没人答、口上跑着别的东西、它回 401 却不带挑战、" +
		"带了摘要还被 401（口令或算法不对）、编号不被认（403/404）、它此刻忙、以及注册上了但平台不认这台这几档。" +
		"★★ 这是 mutate：注册会让那台平台多出一个在线设备。填的是真设备的编号时，这一发会**顶掉那条真注册**，" +
		"现场立刻表现为那台相机掉线 —— 所以要人点头、要进改动账本。" +
		"问完就发 Expires:0 注销（不留一个本机收不回的改动），并把注销那一发的结果如实记账。" +
		"★ 这台不做真设备：平台回头问通道表时我们不应答（编不出也不该编一路通道），只把那一句收进证据里。" +
		"口令只进那一次 MD5：不进结果、不进日志、不进账本、不进批准框那句话，报错里也不复述。",
	Schema: json.RawMessage(`{
	  "type": "object",
	  "additionalProperties": false,
	  "required": ["host", "deviceId"],
	  "properties": {
	    "host": {"type": "string", "description": "国标平台的地址（IP 或域名）"},
	    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "平台 SIP 信令口，默认 5060"},
	    "deviceId": {"type": "string", "description": "这台「设备」的 20 位国标编号。★ 填真设备的编号会顶掉那条真注册，先确认那是可以动的"},
	    "password": {"type": "string", "description": "注册口令。★ 只用于这一次的 MD5 计算，不进任何输出。空着是按空口令走一趟（有的平台真没收口令，那一趟的结果本身就是一条事实）"},
	    "platformId": {"type": "string", "description": "平台编号（20 位）。填了用它拼请求行；不填就按 deviceId 的前 10 位当所属域（国标里那一段就是中心编码+行业编码，通常等同域）—— 用了哪一种，结果里会写清"},
	    "expires": {"type": "integer", "minimum": 30, "maximum": 3600, "description": "注册时长秒数，默认 60。★ 这一问最后总会注销，这个数只是万一注销没成时那台平台留着这条注册的上限"},
	    "timeoutMs": {"type": "integer", "minimum": 500, "maximum": 60000, "description": "每一发的总预算毫秒数，默认 3000"},
	    "watchMs": {"type": "integer", "minimum": 0, "maximum": 15000, "description": "注册成功之后再听多久，看平台有没有回头来问（0 = 不听）。默认 3000"},
	    "realm": {"type": "string", "description": "口令摘要里该用的域（realm）。不填就照平台 401 给的那个算 —— 现场最常见的一种错就是设备配的 realm 与平台给的不是一个"}
	  }
	}`),
	Describe: describeGB28181Register,
	Invoke:   registerGB28181,
}

type gbRegisterArgs struct {
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	DeviceID   string `json:"deviceId"`
	Password   string `json:"password,omitempty"`
	PlatformID string `json:"platformId,omitempty"`
	Expires    int    `json:"expires,omitempty"`
	TimeoutMS  int    `json:"timeoutMs,omitempty"`
	// WatchMS 用指针：这一栏「没填」和「填 0」是两种问法 ——
	// 没填按默认听 3 秒，填 0 是明说「别听，我只问它收不收注册」。用 int 就把这两种并成一种了。
	WatchMS *int   `json:"watchMs,omitempty"`
	Realm   string `json:"realm,omitempty"`
}

// gbWatchOf 折算「注册后再听多久」。
func gbWatchOf(p *int) (time.Duration, error) {
	if p == nil {
		return 3 * time.Second, nil
	}
	if *p < 0 || *p > 15000 {
		return 0, ots.Errf(ots.ErrInvalidArgument, "watchMs 只能填 0 到 15000 毫秒，给的是 %d", *p)
	}
	return time.Duration(*p) * time.Millisecond, nil
}

// describeGB28181Register 批准框里那句话 [OTS-7.2]。
// ★ 说清要改动什么：往哪一台、以哪个编号注册、注册多久、什么时候收回来。
// ★★ 这里绝不读 a.Password —— 连「已带口令」这种说法都只回一句「带口令」，
//
//	口令内容不进这句话，也不进账本。
func describeGB28181Register(raw json.RawMessage) string {
	var a gbRegisterArgs
	_ = json.Unmarshal(nonEmpty(raw), &a)
	port := a.Port
	if port == 0 {
		port = gbDefaultPort
	}
	exp := a.Expires
	if exp == 0 {
		exp = 60
	}
	s := fmt.Sprintf("以编号 %s 往 %s:%d 发一次国标注册（REGISTER），注册时长 %d 秒，"+
		"问完立刻发 Expires:0 注销。★ 这一发会让那台平台多出一个在线设备；"+
		"如果 %s 是现场真在用的设备编号，它会顶掉那条真注册、那台相机会掉线",
		strings.TrimSpace(a.DeviceID), strings.TrimSpace(a.Host), port, exp, strings.TrimSpace(a.DeviceID))
	if strings.TrimSpace(a.Password) != "" {
		s += "。带注册口令（口令内容不会被记录）"
	}
	if a.WatchMS != nil && *a.WatchMS == 0 {
		s += "。这一趟关掉了「注册后听平台回话」，所以只回答它收不收注册，不回答它认不认这台"
	}
	return s
}

func registerGB28181(ctx context.Context, raw json.RawMessage) (any, error) {
	var a gbRegisterArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, ots.Errf(ots.ErrInvalidArgument, "参数不是合法 JSON：%s", err)
		}
	}
	host := strings.TrimSpace(a.Host)
	if host == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 host —— 要注册的是那台国标平台的地址")
	}
	deviceID, err := gbCode(a.DeviceID, "deviceId")
	if err != nil {
		return nil, err
	}
	if deviceID == "" {
		return nil, ots.Errf(ots.ErrInvalidArgument, "没给 deviceId —— 注册就是拿这个编号去报名字，不能空")
	}
	platformID, err := gbCode(a.PlatformID, "platformId")
	if err != nil {
		return nil, err
	}
	port := a.Port
	if port == 0 {
		port = gbDefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, ots.Errf(ots.ErrInvalidArgument, "port 是 %d，不在 1-65535 之间", port)
	}
	step, err := gbTimeout(a.TimeoutMS)
	if err != nil {
		return nil, err
	}
	expires := a.Expires
	if expires == 0 {
		expires = 60
	}
	if expires < 30 || expires > 3600 {
		return nil, ots.Errf(ots.ErrInvalidArgument,
			"expires 只能填 30 到 3600 秒，给的是 %d —— 这一问最后总会注销，这个数是注销没成时那台平台留着它的上限，别拿它当「挂着别掉」的开关", expires)
	}
	watch, err := gbWatchOf(a.WatchMS)
	if err != nil {
		return nil, err
	}
	if journal == nil {
		// ★ 没有账本就不动手：以哪个编号往哪儿注册过一条，这条必须留得下痕
		return nil, ots.Errf(ots.ErrInternal, "没有改动账本，拒绝动手")
	}

	// 请求行与 To 里那个域：填了平台编号就用它，没填就按这台编号的前 10 位
	//（国标里那一段是中心编码+行业编码，通常就等同所属域）。
	domain := platformID
	domainFrom := "platformId"
	if domain == "" {
		domain = deviceID[:10]
		domainFrom = "deviceId 前 10 位"
	}

	values := map[string]any{
		"peer":         net.JoinHostPort(host, strconv.Itoa(port)),
		"host":         host,
		"port":         port,
		"proto":        "udp",
		"device":       deviceID,
		"domain":       domain,
		"domainSource": domainFrom,
		"expires":      expires,
		"hasPassword":  a.Password != "",
	}
	id, jerr := journal.Register("gb28181-register", describeGB28181Register(raw), nil, map[string]any{
		"peer": values["peer"], "device": deviceID, "expires": expires,
	})
	if jerr != nil {
		return nil, ots.Errf(ots.ErrInternal, "登记改动失败，没有动手：%s", jerr)
	}

	c, err := gb28181.DialClient(host, strconv.Itoa(port))
	if err != nil {
		_ = journal.Drop(id, "没发出去："+gbDetail(err))
		return nil, gbDialError(err)
	}
	defer c.Close()
	values["local"] = net.JoinHostPort(c.LocalHost(), c.LocalPort())

	var got gbCollector
	c.OnMessage = func(m *gb28181.Message, _ *net.UDPAddr) { got.add(m) }

	uri := gb28181.SIPURI(domain, host, strconv.Itoa(port))
	req := gbRequest(c, gb28181.MethodRegister, uri, deviceID, deviceID, nil, "", expires)
	reply, rerr := c.Request(req, "register", gbStep(ctx, step))
	gbFillReply(values, "first", reply)

	authed := false
	// auth 留着是给注销那一发用的：它可能也要凭据（见 gbDeregister）。
	var auth *gb28181.Challenge
	switch {
	case rerr == nil:
		// 第一发就 200：这台不收凭据。★ 这是一条事实，不是「认证成功」——
		// 内网裸放的平台在现场真实存在，把它报成「口令对」会让人以为口令管住了这道门。
		values["authenticated"] = false
	case gb28181.StatusOf(rerr) == 401:
		values["firstStatus"] = 401
		ch, cerr := gb28181.ChallengeFrom(reply.Final)
		if cerr != nil {
			// ★ authenticated 要等摘要真的算出来才置真：回 401 不等于给了能用的挑战，
			//   这一趟上界面上写「本机按 RFC 2617 算了摘要」就是一句没发生的事。
			values["detail"] = maskSecretText(gbDetail(cerr))
			_ = journal.Drop(id, "它回了 401 却没带能用的挑战，没往下走")
			return ots.Verdict{Code: verdictGBChallengeMissing, Values: values,
				Note: "它回了 401，可那一条里读不出一枚能用的挑战（realm / nonce 这些缺一项）：" +
					values["detail"].(string) +
					" —— 设备侧在这一格上只能干等，现场表现就是「一直重复注册」。先核对那台上 SIP 的认证配置"}, nil
		}
		authed = true
		values["authenticated"] = true
		values["realm"] = ch.Realm
		if strings.TrimSpace(a.Realm) != "" && a.Realm != ch.Realm {
			// ★ 只看、不改写：口令摘要用的是它给的那个 realm，
			//   而「配的 realm 与平台给的不是一个」正是要报出来的那条事实。
			values["realmGiven"] = maskSecretText(a.Realm)
			values["realmDiffers"] = true
		}
		if len(ch.QOP) > 0 {
			values["qop"] = strings.Join(ch.QOP, ",")
		}
		if err := gb28181.AuthorizeRequest(req, ch, deviceID, a.Password); err != nil {
			_ = journal.Drop(id, "签名这一步就没成")
			return nil, ots.Errf(ots.ErrInternal, "按它给的那枚挑战算摘要没成：%s", maskSecretText(gbDetail(err)))
		}
		// 同一趟事务：Call-ID、CSeq 都不动，只把 Authorization 添上去再发一次 ——
		// ★ 换 Call-ID 重发就是开了第二趟，平台那边两条注册并排挂着，现场看到的
		//   是「注册上了又掉、掉了又注册」。
		reply, rerr = c.Request(req, "register", gbStep(ctx, step))
		gbFillReply(values, "second", reply)
		if rerr != nil {
			return gbRegisterFault(values, id, rerr)
		}
		auth = ch // 注销那一发先照这一枚签；它嫌旧了再走一轮拿新的
	case gb28181.KindOf(rerr) == gb28181.KindTimeout && reply != nil && len(reply.Interims) > 0:
		values["gotTrying"] = true
		fallthrough
	default:
		return gbRegisterFault(values, id, rerr)
	}

	// ── 注册上了 ──
	// ★ 这一格是给后面两栏开闸的：「它回头问了吗」与「收回来没有」只在真注册上之后才成立。
	//   没注册上还去写「这条注册会留在平台上」，等于凭空报出一条不存在的改动。
	values["registered"] = true
	gbFillRegisterOK(values, reply.Final)
	_ = journal.MarkApplied(id)

	// 听一段窗口：平台回头来问，才是它真把这台当设备。
	if watch > 0 && ctx.Err() == nil {
		got.add(c.WaitFor(watch, func(m *gb28181.Message) bool { return m.IsRequest() })...)
	}
	seen := gbInbound(got.all())
	values["watchMs"] = int(watch / time.Millisecond)
	values["platformRequests"] = seen.Methods
	values["platformCmdTypes"] = seen.CmdTypes
	values["platformInvite"] = seen.Invite
	if seen.SDP != "" {
		values["inviteSDP"] = seen.SDP // 已经过 clip：那份正文里最多是编号与地址，不含凭据
	}

	// ── 收尾：注销。★ 这一发不发，那台平台就挂着一条我们收不回来的在线设备 ──
	deregOK, deregDetail, deregTries := gbDeregister(ctx, c, gbStep(ctx, step), uri, req, auth, deviceID, a.Password)
	values["deregistered"] = deregOK
	values["deregisterTries"] = deregTries
	if !deregOK {
		values["deregisterDetail"] = deregDetail
	}
	deregLine := "发了，它答了 2xx"
	if !deregOK {
		deregLine = "没成：" + deregDetail
	}
	_ = journal.MarkReverted(id, fmt.Sprintf("注销那一发：%s（这条注册最长在平台上留 %d 秒）", deregLine, expires))

	code := verdictGBRegistered
	note := "注册上了：它给了 200"
	if !authed {
		code = verdictGBRegisteredNoAuth
		note = "注册上了，可这一趟没要凭据 —— 第一发 REGISTER 就直接 200。★ 这是一条安全事实：这道门没收口令"
	}
	if len(seen.Methods) > 0 {
		code = verdictGBRegisteredAccepted
		note = "注册上了，而且它回过头来问了：" + gbAskedBackNote(seen) +
			" —— 这才是「那台平台真把这台当设备」的证据。" +
			"★ 我们没替它编一路通道去答（这台不做真设备），所以它那几问是没答的"
	} else if watch > 0 {
		note += fmt.Sprintf("；听了 %d 毫秒，它一句都没回头来问 —— 注册收下不等于它把这台当成能点播的设备。"+
			"要看它问不问，等久一点或去那台上确认这台的状态", int(watch/time.Millisecond))
	}
	if !deregOK {
		note += fmt.Sprintf("。★ 注销那一发没成（%s）：这条注册会留在那台平台上，最长到 %d 秒才自己过期；"+
			"如果占用的是真设备的编号，得去那台上把它请回去", values["deregisterDetail"], expires)
	} else {
		note += "。问完已发 Expires:0 注销，那台平台上不会留着这台"
	}
	return ots.Verdict{Code: code, Values: values, Note: note}, nil
}

// gbDeregister 把这条注册收回来，返回「成没成、没成是因为什么、一共发了几发」。
//
// ★★ 这一步不能省，也不能只发一发就算完：注册是**留在别人机器上的状态**，
//
//	本机没有任何东西能把它收回来 —— 除了这一发 Expires:0。
//
// 为什么要走两轮：注销带着注册那一枚凭据（同一个 nonce）通常就直接收；
// 但管 nc 的那类平台会把它当重放，回一枚新挑战。只发一发就报「注销没成」，
// 表现是「查完留下一个假在线设备」—— 那比没查还难查。所以它要新单子就给它新的，
// 补发一发；第二发还是不回，才如实报没成。
func gbDeregister(ctx context.Context, c *gb28181.Client, step time.Duration,
	uri string, reg *gb28181.Message, ch *gb28181.Challenge, deviceID, password string) (bool, string, int) {
	dereg := gbRequest(c, gb28181.MethodRegister, uri, deviceID, deviceID, nil, "", 0)
	dereg.Set(gb28181.HCallID, reg.CallID()) // 同一趟对话，只把 Expires 归零
	if v := reg.Get(gb28181.HAuthorization); v != "" {
		dereg.Set(gb28181.HAuthorization, v) // 照注册那一发的凭据带上
	}
	reply, err := c.Request(dereg, "deregister", gbStep(ctx, step))
	if err == nil {
		return true, "", 1
	}
	if ch != nil && reply != nil && gb28181.StatusOf(err) == 401 {
		if fresh, cerr := gb28181.ChallengeFrom(reply.Final); cerr == nil {
			if serr := gb28181.AuthorizeRequest(dereg, fresh, deviceID, password); serr == nil {
				if _, rerr := c.Request(dereg, "deregister", gbStep(ctx, step)); rerr == nil {
					return true, "", 2 // 它要新单子，给了新单子它就收了
				} else {
					return false, maskSecretText(gbDetail(rerr)), 2
				}
			}
		}
	}
	return false, maskSecretText(gbDetail(err)), 1
}

// gbRegisterFault 注册这一路上的收发失败。★ 带摘要之后又被 401 单独一档：
// 那一句的意思就是「口令不对」，把它和 403 混在一起，人就去找网络而不去改口令。
func gbRegisterFault(values map[string]any, id string, err error) (ots.Verdict, error) {
	reason := maskSecretText(gbDetail(err))
	_ = journal.Drop(id, "注册没成："+reason)
	if gb28181.StatusOf(err) == 401 && values["authenticated"] == true {
		code := gb28181.ReasonPhrase(401)
		values["status"] = 401
		return ots.Verdict{Code: verdictGBCredentialRejected, Values: values,
			Note: "带上摘要之后它还是回 401（" + code + "）—— 口令不对，或摘要用的 realm/URI 与它算的不是一个。" +
				"★ 口令内容这里不复述。先核那台上给这个编号配的注册口令；" +
				"再看是不是配了 realm（这一次用的是它给的那个）"}, nil
	}
	return gbFault(values, err), nil
}

// gbFillRegisterOK 留下 200 里那几样：它实际应允的时长与它的来路签名。
// ★ Expires 要读回来看：设备报了 3600、平台只应 60 是很常见的配置差，
//
//	而「每隔一分钟重注册一次」这种现场毛病就藏在这一格里。
func gbFillRegisterOK(values map[string]any, msg *gb28181.Message) {
	if msg == nil {
		return
	}
	values["status"] = msg.Status
	if got, ok := msg.Expires(); ok {
		values["expiresAccepted"] = got
	}
	if v := msg.Get(gb28181.HUserAgent); v != "" {
		values["serverAgent"] = maskSecretText(v)
	}
	to := msg.To()
	if v := to.Param("tag"); v != "" {
		values["toTag"] = true // 200 带 tag 才算这一趟对话成了；缺 tag 设备会当没答、重发一趟
	}
}

// gbSeen 是窗口里从平台那侧打进来的请求的摘要。
type gbSeen struct {
	Methods  []string
	CmdTypes []string
	Invite   bool
	SDP      string
}

// gbCollector 收「不是回给我们正在等的这一条」的报文。
//
// ★ 收拢成一个带锁的小对象，而不是让 OnMessage 与主流程各自去 append 同一个切片：
//
//	平台回头问通道表的那一发，可能正落在我们读这堆证据的当口上。
type gbCollector struct {
	mu   sync.Mutex
	list []*gb28181.Message
}

func (g *gbCollector) add(ms ...*gb28181.Message) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, m := range ms {
		if m != nil && m.IsRequest() {
			g.list = append(g.list, m)
		}
	}
}

func (g *gbCollector) all() []*gb28181.Message {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*gb28181.Message, len(g.list))
	copy(out, g.list)
	return out
}

// gbInbound 把这堆请求收成「它回过头来问了什么」。★ 只挑方法名与 CmdType：
// 正文里那些地址与编号原样进结果没好处（结果会被发给 AI），够用就行。
func gbInbound(list []*gb28181.Message) gbSeen {
	var s gbSeen
	seenMethod := map[string]bool{}
	seenCmd := map[string]bool{}
	for _, m := range list {
		method := strings.ToUpper(m.Method)
		if !seenMethod[method] {
			seenMethod[method] = true
			s.Methods = append(s.Methods, method)
		}
		switch method {
		case gb28181.MethodMessage, gb28181.MethodNotify:
			if cmd, err := gb28181.BodyCmd(m); err == nil && cmd.CmdType != "" && !seenCmd[cmd.CmdType] {
				seenCmd[cmd.CmdType] = true
				s.CmdTypes = append(s.CmdTypes, cmd.CmdType)
			}
		case gb28181.MethodInvite:
			s.Invite = true
			if s.SDP == "" {
				s.SDP = gbSDPNote(m)
			}
		}
	}
	sort.Strings(s.Methods)
	sort.Strings(s.CmdTypes)
	return s
}

// gbAskedBackNote 把平台回头问的那几句说清。★ 只写 MESSAGE 在现场等于没写：
// 「它问的是哪一类」才是「它把这台当成设备」的那条证据，而正文里的 CmdType 就是这条证据本身。
func gbAskedBackNote(seen gbSeen) string {
	var parts []string
	for _, m := range seen.Methods {
		if (m == gb28181.MethodMessage || m == gb28181.MethodNotify) && len(seen.CmdTypes) > 0 {
			parts = append(parts, m+"（"+gbCmdWords(seen.CmdTypes)+"）")
			continue
		}
		if m == gb28181.MethodInvite {
			// ★ 点播在这里就地翻成人话：外面那句再补一次「还发来了点播（INVITE）」，
			//   同一格在屏幕上就出现两遍。
			parts = append(parts, "点播（INVITE）")
			continue
		}
		parts = append(parts, m)
	}
	return strings.Join(parts, "、")
}

func gbCmdWords(cmds []string) string {
	var s []string
	for _, c := range cmds {
		switch c {
		case gb28181.CmdCatalog:
			s = append(s, c+"，问的是通道表")
		case gb28181.CmdDeviceStatus:
			s = append(s, c+"，问的是在线状态")
		case gb28181.CmdDeviceInfo:
			s = append(s, c+"，问的是设备自述")
		default:
			s = append(s, c)
		}
	}
	return strings.Join(s, "、")
}

// gbSDPNote 把点播正文里最能说明问题的那两样说出来：落到哪个口、要哪个方向。
//
// ★ 方向必须单独看：sendonly 与 recvonly 反过来是「谁在发」反了，
//
//	现场那两种下一步（去设备侧看推流 / 看本机这头收不收）就是由它分的。
func gbSDPNote(m *gb28181.Message) string {
	sess, err := gb28181.BodySDP(m)
	if err != nil {
		return "点播正文读不成 SDP：" + maskSecretText(gbDetail(err))
	}
	port, okPort := sess.MediaPort()
	dir, okDir := sess.Direction()
	switch {
	case okPort && okDir:
		note := fmt.Sprintf("媒体口 %d，方向 %s", port, dir)
		if dir == "sendonly" {
			// ★ 底座那条口径：点播里平台是收流的一方，正常写 recvonly；
			//   反过来看到 sendonly 就说明这一条不是点播（是要本机往上推）。
			note += " —— ★ 点播里这一格正常应是 recvonly（平台收），它写了 sendonly，那就不是点播"
		}
		return note
	case okPort:
		return fmt.Sprintf("媒体口 %d，方向没标（按国标默认算双向）", port)
	case okDir:
		return "没数到媒体口，方向 " + dir
	}
	return "正文里既没有媒体口也没有方向"
}
