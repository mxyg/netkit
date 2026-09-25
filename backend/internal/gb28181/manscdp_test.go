package gb28181

import (
	"strings"
	"testing"
)

// 两份 catalog 样本：一份规规矩矩，一份带着现场常见的四种不规矩
// （自闭标签、多余空白、容器名换写法、同名兄弟各带半截）。
const catalogClean = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <CmdType>Catalog</CmdType>
  <SN>17</SN>
  <DeviceID>34020000001110000001</DeviceID>
  <SumNum>2</SumNum>
  <DeviceList Num="2">
    <Item>
      <DeviceID>34020000001320000001</DeviceID>
      <Name>东门</Name>
      <Status>ON</Status>
      <Parental>0</Parental>
    </Item>
    <Item>
      <DeviceID>34020000001320000002</DeviceID>
      <Name>西门</Name>
      <Status>OFF</Status>
      <Parental>0</Parental>
    </Item>
  </DeviceList>
</Response>`

const catalogDirty = `<?xml version="1.0" encoding="UTF-8"?>
\r\n<Response>
<CmdType>Catalog</CmdType>
  <SN>
     42
  </SN>
	<DeviceID>34020000001110000001</DeviceID>
	<SumNum>2</SumNum>
	<Manufacture></Manufacture>
	<model/>
	<ItemList>
		<Item><deviceID>34020000001320000001</deviceID><Name>东门</Name></Item>
		<Item><DeviceID>34020000001320000002</DeviceID><name>西门</name></Item>
	</ItemList>
</Response>`

func TestParseCatalog干净样本(t *testing.T) {
	cmd, err := ParseCmd([]byte(catalogClean))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if cmd.Root != "Response" {
		t.Errorf("根 = %q", cmd.Root)
	}
	if cmd.CmdType != "Catalog" {
		t.Errorf("CmdType = %q", cmd.CmdType)
	}
	if cmd.SN != "17" {
		t.Errorf("SN = %q", cmd.SN)
	}
	if cmd.DeviceID != "34020000001110000001" {
		t.Errorf("DeviceID = %q", cmd.DeviceID)
	}
	if cmd.ItemCount() != 2 {
		t.Fatalf("条目数 = %d，要 2", cmd.ItemCount())
	}
	if cmd.Lists["devicelist"] != 2 {
		t.Errorf("容器记账 = %v，键要一律小写（工具层按一个拼法去查，查不到就报 0 条）", cmd.Lists)
	}
	ids, missing := cmd.ItemDeviceIDs()
	if missing != 0 || len(ids) != 2 {
		t.Fatalf("编号 = %v，缺 %d", ids, missing)
	}
	if cmd.Items[0].Get("name") != "东门" || cmd.Items[1].Get("status") != "OFF" {
		t.Errorf("条目内容 = %v / %v", cmd.Items[0], cmd.Items[1])
	}
	if len(cmd.Repeated) != 0 {
		t.Errorf("干净样本被记了重复键：%v", cmd.Repeated)
	}
	if cmd.NonUTF8 {
		t.Error("干净样本不该报非 UTF-8")
	}
}

func TestParseCatalog现场那些不规矩(t *testing.T) {
	cmd, err := ParseCmd([]byte(catalogDirty))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if cmd.SN != "42" {
		t.Errorf("SN = %q，要 42（换行与缩进都是噪声）", cmd.SN)
	}
	// 自闭标签与空元素都算「有这一项、值是空的」。
	if !cmd.Fields.Has("manufacture") || cmd.Fields.Get("manufacture") != "" {
		t.Errorf("空元素没按「有键、值为空」记下来：%v", cmd.Fields)
	}
	if !cmd.Fields.Has("model") {
		t.Error("自闭标签 <model/> 没记成字段")
	}
	if got := cmd.Lists["itemlist"]; got != 2 {
		t.Errorf("容器名要照收到的写法小写后记：Lists = %v，要 2", cmd.Lists)
	}
	// 条目里 <deviceID> 与 <DeviceID> 是同一个字段。
	ids, missing := cmd.ItemDeviceIDs()
	if missing != 0 || len(ids) != 2 {
		t.Fatalf("大小写混着写就读不全：ids=%v missing=%d", ids, missing)
	}
	if cmd.Items[1].Get("name") != "西门" {
		t.Errorf("条目里的 <name> 小写没被认成同一个字段：%v", cmd.Items[1])
	}
}

func TestParseCatalog同层重复键要留证据(t *testing.T) {
	// 两个 Item 各带半截信息，合起来才是一条完整的通道。
	body := `<Response><CmdType>Catalog</CmdType><SN>1</SN>` +
		`<DeviceList><Item><DeviceID>34020000001320000001</DeviceID><Name>东门</Name></Item>` +
		`<Item><DeviceID>34020000001320000002</DeviceID></Item></DeviceList>` +
		`<Status>ON</Status><Status>OFF</Status></Response>`
	cmd, err := ParseCmd([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Get("status") != "ON" {
		t.Errorf("同名键要保留第一个，实得 %q", cmd.Get("status"))
	}
	if len(cmd.Repeated) == 0 || cmd.Repeated[0] != "Status" {
		t.Fatalf("同层内容不一样的重复键没记进 Repeated：%v", cmd.Repeated)
	}
	// ★ 同值的重复不算毛病：自闭标签在解码器那儿就是两次，报出来就是冤枉。
	same, err := ParseCmd([]byte(`<Response><CmdType>Catalog</CmdType><SN>1</SN><Status/><Status>ON</Status></Response>`))
	if err != nil {
		t.Fatal(err)
	}
	if same.Get("status") != "" {
		t.Errorf("自闭标签把值盖掉了：%q", same.Get("status"))
	}
	// 同层出现第二个同名容器：条数照样累加，但这一笔要记账。
	two, err := ParseCmd([]byte(`<Response><CmdType>Catalog</CmdType><SN>1</SN>` +
		`<DeviceList><Item><DeviceID>34020000001320000001</DeviceID></Item></DeviceList>` +
		`<DeviceList><Item><DeviceID>34020000001320000002</DeviceID></Item></DeviceList></Response>`))
	if err != nil {
		t.Fatal(err)
	}
	if two.ItemCount() != 2 || two.Lists["devicelist"] != 2 {
		t.Errorf("两个同名容器要都数进来：%d 条 %v", two.ItemCount(), two.Lists)
	}
	if len(two.Repeated) == 0 {
		t.Error("一份 Catalog 里两个 DeviceList 是「得由人来判断分页与去重」的硬证据，没记账")
	}
}

// 中文名按 GBK 发的那类老固件：整份正文不能判死。
func TestParseCatalog非UTF8时按占位符解下去(t *testing.T) {
	// "东门" 写成两个 GBK 双字节序列（首字节在 UTF-8 里是非法起始）。
	gbk := []byte{0xC4, 0xE3, 0xB6, 0xAA}
	body := "<Response><CmdType>Catalog</CmdType><SN>9</SN><DeviceList>" +
		"<Item><DeviceID>34020000001320000001</DeviceID><Name>" + string(gbk) + "</Name></Item>" +
		"</DeviceList></Response>"
	cmd, err := ParseCmd([]byte(body))
	if err != nil {
		t.Fatalf("非 UTF-8 中文名把整份 Catalog 判死了：编号、条数这些 ASCII 一个都不该丢：%v", err)
	}
	if !cmd.NonUTF8 {
		t.Error("没记下「这份正文里有按 UTF-8 解不出来的字节」")
	}
	if cmd.ItemCount() != 1 {
		t.Errorf("条目数 = %d", cmd.ItemCount())
	}
	if ids, _ := cmd.ItemDeviceIDs(); len(ids) != 1 || ids[0] != "34020000001320000001" {
		t.Errorf("编号丢了：%v", ids)
	}
	if !strings.Contains(cmd.Items[0].Get("name"), "\uFFFD") {
		t.Errorf("坏字节要换成占位符留着，实得 %q", cmd.Items[0].Get("name"))
	}
}

func TestParseCmd认不出来的几种(t *testing.T) {
	cases := map[string]string{
		"空":      "",
		"不是XML":  "hello",
		"根不对":    "<Foo><SN>1</SN></Foo>",
		"少了闭合":   "<Response><CmdType>Catalog</CmdType>",
		"根是注释前的": "<!--x--><Response><CmdType>Catalog</CmdType></Response>",
		"只有一层壳":  "<Response></Response>",
	}
	for name, body := range cases {
		cmd, err := ParseCmd([]byte(body))
		switch name {
		case "空", "不是XML", "根不对", "少了闭合":
			if err == nil {
				t.Errorf("%s：本该报错，实得 %+v", name, cmd)
			}
		default:
			// 注释与空壳都得能读通：读不通就等于把一条答对了的回包判成没答。
			if err != nil {
				t.Errorf("%s：本该读通，实得 %v", name, err)
			}
		}
	}
}

func TestBuildAndParse往返(t *testing.T) {
	b := NewBuilder(RootQuery, "Catalog", "88", "34020000001110000001")
	b.Set("StartPoint", "1").Set("Count", "36").
		List("DeviceList", "Item").
		Item(F{Name: "DeviceID", Value: "34020000001320000001"}, F{Name: "Name", Value: "东门 <测试> & \"引号\""}).
		Item(F{Name: "DeviceID", Value: "34020000001320000002"})
	raw := b.Bytes()
	cmd, err := ParseCmd(raw)
	if err != nil {
		t.Fatalf("自己拼的发不出去或读不回来：%v\n%s", err, raw)
	}
	if cmd.Root != RootQuery || cmd.CmdType != "Catalog" || cmd.SN != "88" {
		t.Errorf("根/CmdType/SN 走样：%+v", cmd)
	}
	if cmd.Get("startpoint") != "1" || cmd.Get("count") != "36" {
		t.Errorf("字段丢了：%v", cmd.Fields)
	}
	if cmd.ItemCount() != 2 {
		t.Fatalf("条目 %d", cmd.ItemCount())
	}
	// 特殊字符必须原样回来（转义漏了的话，第二条通道的编号就会串进第一条的名字里）。
	if got := cmd.Items[0].Get("name"); got != "东门 <测试> & \"引号\"" {
		t.Errorf("转义走样：%q", got)
	}
	if ids, missing := cmd.ItemDeviceIDs(); missing != 0 || len(ids) != 2 {
		t.Errorf("编号 = %v 缺 = %d", ids, missing)
	}
}

func Test各类查询与应答的正文(t *testing.T) {
	di, err := ParseCmd(DeviceInfoQuery("1", "34020000001110000001"))
	if err != nil || di.CmdType != "DeviceInfo" || di.Root != RootQuery {
		t.Errorf("DeviceInfo 查询 = %+v err=%v", di, err)
	}
	ds, err := ParseCmd(DeviceStatusQuery("2", "34020000001110000001"))
	if err != nil || ds.CmdType != "DeviceStatus" {
		t.Errorf("DeviceStatus 查询 = %+v err=%v", ds, err)
	}
	ca, err := ParseCmd(CatalogQuery("3", "34020000001110000001", 1, 10))
	if err != nil || ca.Get("sumnum") == "" && ca.Get("count") != "10" {
		t.Errorf("Catalog 查询没带上分页：%v err=%v", ca.Fields, err)
	}
	if ca.Get("startpoint") != "1" || ca.Get("count") != "10" {
		t.Errorf("分页字段 = %v", ca.Fields)
	}
	all, err := ParseCmd(CatalogQuery("4", "34020000001110000001", 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if all.Fields.Has("startpoint") || all.Fields.Has("count") {
		t.Errorf("要全量时不该写分页：%v", all.Fields)
	}
	ka, err := ParseCmd(KeepaliveNotify("5", "34020000001110000001", "OK"))
	if err != nil || ka.Root != RootNotify || ka.CmdType != "Keepalive" {
		t.Errorf("心跳通知 = %+v err=%v", ka, err)
	}
	resp, err := ParseCmd(DeviceInfoResponsePayload("6", "34020000001110000001",
		F{Name: "DeviceName", Value: "测试枪机"}, F{Name: "Result", Value: "OK"}))
	if err != nil || resp.Root != RootResponse || resp.Get("devicename") != "测试枪机" {
		t.Errorf("自述应答 = %+v err=%v", resp, err)
	}
	if !resp.IsResponseTo("DeviceInfo", "6") {
		t.Error("应答认不出自己是对哪一问的（CmdType 或 SN 对不上）")
	}
	catResp, err := ParseCmd(CatalogResponsePayload("7", "34020000001110000001", 1, [][]F{
		{{Name: "DeviceID", Value: "34020000001320000001"}, {Name: "Status", Value: "ON"}},
	}))
	if err != nil || catResp.ItemCount() != 1 {
		t.Fatalf("通道应答 = %+v err=%v", catResp, err)
	}
	if sum, ok := catResp.SumNum(); !ok || sum != 1 {
		t.Errorf("SumNum = %v/%v", sum, ok)
	}
	st, err := ParseCmd(DeviceStatusResponsePayload("8", "34020000001110000001", "ON", "2026-01-01T00:00:00"))
	if err != nil || st.Get("status") != "ON" || st.Get("time") != "2026-01-01T00:00:00" {
		t.Errorf("状态应答 = %+v err=%v", st, err)
	}
}

func TestBodyCmd分得清空正文与坏正文(t *testing.T) {
	noBody := &Message{Status: 200, Reason: "OK"}
	if _, err := BodyCmd(noBody); KindOf(err) != KindNoBody {
		t.Errorf("200 空正文 = %q，要 %q（这一档是「它接了这句但没答内容」）", KindOf(err), KindNoBody)
	}
	junk := &Message{Status: 200, Body: []byte("<html><body>nope</body></html>")}
	if _, err := BodyCmd(junk); KindOf(err) != KindBadBody {
		t.Errorf("正文不是 MANSCDP = %q，要 %q", KindOf(err), KindBadBody)
	}
	good := &Message{Status: 200, Body: []byte(catalogClean)}
	cmd, err := BodyCmd(good)
	if err != nil || cmd.CmdType != "Catalog" {
		t.Errorf("正常正文读不出来：%+v err=%v", cmd, err)
	}
}

func TestFields大小写与取值(t *testing.T) {
	f := Fields{"devicename": "x"}
	if !f.Has("DeviceName") || f.Get("DEVICENAME") != "x" {
		t.Errorf("取值要大小写无关：%v", f)
	}
	if f.Has("Model") {
		t.Error("没写的键报成了有")
	}
	if n, ok := f.Int("devicename"); ok || n != 0 {
		t.Errorf("非数字要报失败，实得 %d/%v", n, ok)
	}
	n, ok := f.Int("sum")
	if ok || n != 0 {
		t.Error("缺键要报失败")
	}
}
