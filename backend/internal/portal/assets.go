package portal

import _ "embed"

// pageHTML 手机端门户页（单文件，内联样式与脚本 —— 和桌面界面同一条「无构建」路线）。
//
//go:embed web/index.html
var pageHTML []byte
