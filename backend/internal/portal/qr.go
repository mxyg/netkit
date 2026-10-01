package portal

import (
	"encoding/base64"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// QRDataURI 把一条链接编成可直接进 <img src> 的 PNG data URI。
// ★ 二维码只活 10 分钟、用一次即废，所以它就是**当前**这一张的画像；
//
//	主机界面每次看状态都要用返回里的链接重新要一张，不许缓存旧图。
func QRDataURI(text string) (string, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, 512)
	if err != nil {
		return "", fmt.Errorf("造二维码失败：%s", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
