package gb28181

import "testing"

func Test编号切开按位置(t *testing.T) {
	c, err := ParseCode("34020000001320000001")
	if err != nil {
		t.Fatal(err)
	}
	if c.Center != "34020000" || c.Industry != "00" || c.Type != "132" || c.Serial != "0000001" {
		t.Fatalf("切分不对：%+v", c)
	}
	if n, ok := c.TypeName(); !ok || n != "网络摄像机" {
		t.Fatalf("132 该认得：%q %v", n, ok)
	}
	if c.Class() != CodeClassDevice {
		t.Fatalf("132 属于设备类：%q", c.Class())
	}
}

func Test编号只对两条有把握下结论(t *testing.T) {
	// 131 在几份资料里一会儿是摄像机、一会儿是 DVR/NVR —— 冲突的码不解释，
	// 界面上给原样数字，别拿一个猜的名字让人去查错设备。
	c, err := ParseCode("34020000001310000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.TypeName(); ok {
		t.Fatal("有争议的 131 不该给出名字")
	}
	if c.Class() != CodeClassDevice {
		t.Fatalf("区间口径（111~199 为设备）是几份资料一致的，这一条该有：%q", c.Class())
	}
	plat, err := ParseCode("34020000002000000001")
	if err != nil {
		t.Fatal(err)
	}
	if plat.Class() != CodeClassCenter {
		t.Fatalf("200 段该是中心/平台类：%q", plat.Class())
	}
	if n, ok := plat.TypeName(); !ok || n == "" {
		t.Fatal("200 该认得（平台自己）")
	}
	if got, _ := ParseCode("34020000009990000001"); got.Class() != CodeClassUnknown {
		t.Fatalf("区间外的类型标识该说不知道：%q", got.Class())
	}
}

func Test编号报错要说清差在哪(t *testing.T) {
	if _, err := ParseCode("3402000000132000000"); err == nil {
		t.Fatal("19 位该报错")
	} else if got := err.Error(); len(got) == 0 {
		t.Fatal("错误没内容")
	}
	if _, err := ParseCode("3402000000132000000A"); err == nil {
		t.Fatal("含字母该报错")
	}
	if _, err := ParseCode("  "); err == nil {
		t.Fatal("空白该报错（不能当「没填」）")
	}
	if !ValidCode("34020000001110000001") || ValidCode("3402000000111000000") || ValidCode("340200000011100000 1") {
		t.Fatal("ValidCode 判得不对")
	}
}
