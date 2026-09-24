package diag

import (
	"strings"
	"testing"
)

// TestScrub抹掉值留下键名 是这张表的全部要点：**键名还在**。
//
// ★ 为什么键名必须留着：整行删掉，读包的人判的是「这台没配代理认证」；
//
//	留着键名他才知道是「配了，口令没给我看」—— 这两种情况下一步查的地方不一样。
func TestScrub抹掉值留下键名(t *testing.T) {
	cases := []struct {
		name, in, wantOut string
		wantHit           string
	}{
		{"英文 community", `community: public`, `community: ***`, "键值形式的口令/团体名/令牌"},
		{"中文团体名", `团体名 = NetKit-ReadOnly-2026`, `团体名 = ***`, "键值形式的口令/团体名/令牌"},
		{"全角冒号", `密码：abc123`, `密码：***`, "键值形式的口令/团体名/令牌"},
		{"双引号包着的值", `community: "s3cr3t-read"`, `community: "***"`, "键值形式的口令/团体名/令牌"},
		{"单引号", `Community: 'ro-view-1'`, `Community: '***'`, "键值形式的口令/团体名/令牌"},
		{"交换机配置里的团体名", `snmp-server community MyView2026 RO`,
			`snmp-server community *** RO`, "配置里的 snmp-server 团体名"},
		{"proxy 口令", `http_proxy_password=Pr0xy!`, `http_proxy_password=***`, "键值形式的口令/团体名/令牌"},
		{"token", `access_token: 9f8a7b6c5d4e`, `access_token: ***`, "键值形式的口令/团体名/令牌"},
		{"URL 口令", `rtsp://admin:Hunter2@10.0.0.12/live`,
			`rtsp://admin:***@10.0.0.12/live`, "URL 里的口令"},
		{"Authorization", `Authorization: Basic YWJjOjEyMw==`,
			`Authorization: Basic ***`, "HTTP Authorization 头"},
		{"Cookie 行", `Cookie: session=abc; other=def`, `Cookie: ***`, "Cookie"},
		{"snmp 命令行的 -c", `snmpwalk -v2c -c NetKit-Priv 10.0.0.1`,
			`snmpwalk -v2c -c *** 10.0.0.1`, "命令行的 -c 团体名"},
		{"net user", `net user administrator P@ssw0rd`, `net user administrator ***`, "带口令的命令行写法"},
	}
	for _, c := range cases {
		got, hits := Scrub(c.in)
		if got != c.wantOut {
			t.Errorf("%s：Scrub(%q) = %q，要 %q", c.name, c.in, got, c.wantOut)
		}
		if hits[c.wantHit] == 0 {
			t.Errorf("%s：没记到 %q 这一类头上（hits=%v）", c.name, c.wantHit, hits)
		}
	}
}

// TestScrub私钥整块移除 私钥不是「一个键一个值」，是一块内容 —— 只抹那一行 BEGIN 等于没抹。
func TestScrub私钥整块移除(t *testing.T) {
	pem := "hostkey:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n" +
		"AAAAVGhpcyBpcyBhIHNlY3JldCBibG9jaw==\n-----END OPENSSH PRIVATE KEY-----\n完了"
	got, hits := Scrub(pem)
	if strings.Contains(got, "b3BlbnNzaC1rZXk") || strings.Contains(got, "c2VjcmV0") {
		t.Errorf("私钥内容还在包里：%q", got)
	}
	if !strings.Contains(got, "[已移除：一段私钥]") {
		t.Errorf("没写明这里移除过东西：%q", got)
	}
	if !strings.Contains(got, "完了") {
		t.Errorf("私钥后面的内容被吃掉了：%q", got)
	}
	if hits["私钥（整块移除）"] != 1 {
		t.Errorf("计数 = %v，要私钥 1 处", hits)
	}
}

// TestScrub排成列的键值与带引号的键 这两型都是**本包自己产出的形状**：
// 代理设置那一页按列排（键名单独占一列，没有冒号），改动账本里塞的是 JSON。
// 只认「键: 值」的规则抓不到它们，于是包会把口令原样发出去。
func TestScrub排成列的键值与带引号的键(t *testing.T) {
	cases := []struct{ name, in, wantOut, wantHit string }{
		{"列里的口令", "  代理口令      Bundle-Proxy-P@ssword-9", "  代理口令      ***", "排成列的口令/团体名"},
		{"列里的团体名", "community   ro-view-1", "community   ***", "排成列的口令/团体名"},
		{"JSON 里的键", `{"community":"Bundle-Community-SuperSecret"}`,
			`{"community":"***"}`, "键值形式的口令/团体名/令牌"},
	}
	for _, c := range cases {
		got, hits := Scrub(c.in)
		if got != c.wantOut {
			t.Errorf("%s：Scrub(%q) = %q，要 %q", c.name, c.in, got, c.wantOut)
		}
		if hits[c.wantHit] != 1 {
			t.Errorf("%s：命中要记在 %q 头上（hits=%v）", c.name, c.wantHit, hits)
		}
	}
	// 一个空格的不是列，是句子 —— 正文里「口令 是 …」这种不许当凭据抹。
	for _, line := range []string{
		"口令 是 现场临时改过的",
		"这一台 密码 没人配过",
	} {
		got, hits := Scrub(line)
		if got != line || len(hits) != 0 {
			t.Errorf("正文被当成配置列抹掉了：%q → %q（hits=%v）", line, got, hits)
		}
	}
}

// TestScrub不碰排障要看的东西 反向用例：网卡名、MAC、OID、路由、证书指纹这些
// 是诊断包**存在的理由**，一条都不许被误抹。
//
// ★ 误抹的代价比漏抹更隐蔽：漏抹看得见（*** 就在那儿），误抹会让人以为这台机器没配。
func TestScrub不碰排障要看的东西(t *testing.T) {
	keep := []string{
		"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
		"inet 10.0.12.34  netmask 255.255.252.0  broadcast 10.0.15.255",
		"ether a4:5e:60:11:22:33  txqueuelen 1000  (Ethernet)",
		"inet6 fe80::21b:21ff:fe15:5a47  prefixlen 64  scopeid 0x2<link-local>",
		"default via 10.0.12.1 dev eth0 proto dhcp src 10.0.12.34 metric 100",
		"10.0.12.0/22 dev eth0 proto kernel scope link src 10.0.12.34",
		"ifName.1 = GigabitEthernet1/0/1",
		"1.0.8802.1.1.2.1.4.1.1.9.0.1.1 = STRING: switch-01",
		"SHA-256 指纹 F1:2E:3A:4B:5C:6D:7E:8F:90:A1:B2:C3:D4:E5:F6:07",
		"nameserver 223.5.5.5",
		"options timeout:1 attempts:2",
		"证书 notAfter=2027-01-02T03:04:05Z",
		"curl -c cookies.txt https://example.com",
		"proxy = 10.0.0.5:3128",
		"http://10.0.0.9:8080/status",
	}
	for _, line := range keep {
		got, hits := Scrub(line)
		if got != line {
			t.Errorf("这一行被改了：\n  输入 %q\n  输出 %q（hits=%v）", line, got, hits)
		}
		if len(hits) != 0 {
			t.Errorf("这一行不该命中任何规则：%q（hits=%v）", line, hits)
		}
	}
}

// TestScrub一行里两处 一行被抹两次不能互相踩位：替换是从后往前做的。
func TestScrub一行里两处(t *testing.T) {
	in := "read community: ro-secret, write community: rw-secret"
	got, hits := Scrub(in)
	want := "read community: ***, write community: ***"
	if got != want {
		t.Errorf("两个值只抹掉一个：%q，要 %q", got, want)
	}
	if hits["键值形式的口令/团体名/令牌"] != 2 {
		t.Errorf("命中计数 = %v，要 2 处", hits)
	}
}

// TestScrub空值不算命中 「community: 」这种是配置写漏了，不是藏了个口令 ——
// 计数要能区分，否则「脱敏 1 处」会误导人。
func TestScrub空值不算命中(t *testing.T) {
	in := "community: \n下一行正常"
	got, hits := Scrub(in)
	if len(hits) != 0 {
		t.Errorf("空值被判成口令了：%v（输出 %q）", hits, got)
	}
}

// TestHitList没命中也要说一句 界面上这行要能直接贴，不能是空串。
func TestHitList没命中也要说一句(t *testing.T) {
	if s := HitList(map[string]int{}); !strings.Contains(s, "没发现") {
		t.Errorf("空命中 = %q", s)
	}
	s := HitList(map[string]int{"Cookie": 2, "URL 里的口令": 1})
	if !strings.HasPrefix(s, "共抹掉 3 处") {
		t.Errorf("合计不对：%q", s)
	}
	if strings.Index(s, "Cookie") > strings.Index(s, "URL") {
		t.Errorf("列的顺序要稳定：%q", s)
	}
}
