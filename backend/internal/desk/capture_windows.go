//go:build windows

package desk

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errNeedToken = errors.New("共享屏幕必须带令牌")

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procGetMetrics       = user32.NewProc("GetSystemMetrics")
	procGetDesktop       = user32.NewProc("GetDesktopWindow")
	procMessageBox       = user32.NewProc("MessageBoxW")
	procSendInput        = user32.NewProc("SendInput")
	procCreateCompatDC   = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection = gdi32.NewProc("CreateDIBSection")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procBitBlt           = gdi32.NewProc("BitBlt")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procDeleteDC         = gdi32.NewProc("DeleteDC")
	procGetCursorInfo    = user32.NewProc("GetCursorInfo")
	procGetIconInfo      = user32.NewProc("GetIconInfo")
	procDrawIconEx       = user32.NewProc("DrawIconEx")
)

const (
	srcCopy    = 0x00CC0020
	biRGB      = 0
	dibRGB     = 0
	inputMouse = 0
	inputKey   = 1
	mouseMove  = 0x0001
	mouseAbs   = 0x8000
	mouseLDown = 0x0002
	mouseLUp   = 0x0004
	mouseRDown = 0x0008
	mouseRUp   = 0x0010
	keyUp      = 0x0002
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// FrameJPEG 抓当前屏幕，缩到不超过 1280 宽，压成 JPEG。
func FrameJPEG() ([]byte, error) { return FrameJPEGOpts(82, 1280) }

// FrameJPEGOpts 抓当前屏幕，缩到不超过 maxWidth 宽，按 quality 压 JPEG。
// quality 30–95、maxWidth 480–屏幕原宽之外的范围都收敛进边界 —— 控制端传什么都不炸。
func FrameJPEGOpts(quality, maxWidth int) ([]byte, error) {
	w, _, _ := procGetMetrics.Call(0)
	h, _, _ := procGetMetrics.Call(1)
	width, height := int(w), int(h)
	if width < 16 || height < 16 {
		return nil, errors.New("拿不到屏幕尺寸")
	}
	if quality < 30 {
		quality = 30
	}
	if quality > 95 {
		quality = 95
	}
	if maxWidth < 480 {
		maxWidth = 480
	}
	if maxWidth > width {
		maxWidth = width
	}
	hwnd, _, _ := procGetDesktop.Call()
	hdc, _, _ := procGetDC.Call(hwnd)
	if hdc == 0 {
		return nil, errors.New("拿不到屏幕")
	}
	defer procReleaseDC.Call(hwnd, hdc)
	mem, _, _ := procCreateCompatDC.Call(hdc)
	if mem == 0 {
		return nil, errors.New("建不成画布")
	}
	defer procDeleteDC.Call(mem)
	hdr := bitmapInfoHeader{
		Size: 40, Width: int32(width), Height: -int32(height),
		Planes: 1, BitCount: 32, Compression: biRGB,
	}
	var bits uintptr
	dib, _, _ := procCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&hdr)), dibRGB, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if dib == 0 || bits == 0 {
		return nil, errors.New("建不成位图")
	}
	defer procDeleteObject.Call(dib)
	old, _, _ := procSelectObject.Call(mem, dib)
	defer procSelectObject.Call(mem, old)
	procBitBlt.Call(mem, 0, 0, uintptr(width), uintptr(height), hdc, 0, 0, srcCopy)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(bits)), width*height*4)
	step := 1
	if width > maxWidth {
		step = (width + maxWidth - 1) / maxWidth
	}
	outW, outH := width/step, height/step
	out := image.NewRGBA(image.Rect(0, 0, outW, outH))
	for y := 0; y < outH; y++ {
		for x := 0; x < outW; x++ {
			i := (y*step*width + x*step) * 4
			o := out.PixOffset(x, y)
			out.Pix[o+0] = raw[i+2]
			out.Pix[o+1] = raw[i+1]
			out.Pix[o+2] = raw[i+0]
			out.Pix[o+3] = 255
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type cursorInfoW struct {
	CbSize  uint32
	Flags   uint32
	HCursor uintptr
	X       int32
	Y       int32
}

type iconInfoW struct {
	FIcon    uint32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

// Cursor 读当前远端光标的位置和形状。
func Cursor() CursorInfo {
	var info cursorInfoW
	info.CbSize = uint32(unsafe.Sizeof(info))
	r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 || info.HCursor == 0 {
		return CursorInfo{}
	}
	sw, _, _ := procGetMetrics.Call(0)
	sh, _, _ := procGetMetrics.Call(1)
	out := CursorInfo{}
	if sw > 0 && sh > 0 {
		out.X = float64(info.X) / float64(sw)
		out.Y = float64(info.Y) / float64(sh)
	}
	var icon iconInfoW
	if ok, _, _ := procGetIconInfo.Call(info.HCursor, uintptr(unsafe.Pointer(&icon))); ok != 0 {
		out.HotX = int(icon.XHotspot)
		out.HotY = int(icon.YHotspot)
		if icon.HbmMask != 0 {
			procDeleteObject.Call(icon.HbmMask)
		}
		if icon.HbmColor != 0 {
			procDeleteObject.Call(icon.HbmColor)
		}
	}
	hwnd, _, _ := procGetDesktop.Call()
	hdc, _, _ := procGetDC.Call(hwnd)
	if hdc == 0 {
		return out
	}
	defer procReleaseDC.Call(hwnd, hdc)
	const cw, ch = 64, 64
	mem, _, _ := procCreateCompatDC.Call(hdc)
	if mem == 0 {
		return out
	}
	defer procDeleteDC.Call(mem)
	hdr := bitmapInfoHeader{Size: 40, Width: cw, Height: -ch, Planes: 1, BitCount: 32, Compression: biRGB}
	var bits uintptr
	dib, _, _ := procCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&hdr)), dibRGB, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if dib == 0 || bits == 0 {
		return out
	}
	defer procDeleteObject.Call(dib)
	old, _, _ := procSelectObject.Call(mem, dib)
	defer procSelectObject.Call(mem, old)
	pix := unsafe.Slice((*uint32)(unsafe.Pointer(bits)), cw*ch)
	for i := range pix {
		pix[i] = 0xFFFF00FF
	}
	procDrawIconEx.Call(mem, 0, 0, info.HCursor, 0, 0, 0, 0, 3)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(bits)), cw*ch*4)
	img := image.NewRGBA(image.Rect(0, 0, cw, ch))
	for i := 0; i < len(img.Pix); i += 4 {
		if raw[i] == 0xFF && raw[i+1] == 0x00 && raw[i+2] == 0xFF {
			continue
		}
		img.Pix[i+0] = raw[i+2]
		img.Pix[i+1] = raw[i+1]
		img.Pix[i+2] = raw[i+0]
		img.Pix[i+3] = 255
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err == nil {
		out.PNG = buf.Bytes()
	}
	return out
}

func notifySharing() error {
	title, _ := syscall.UTF16PtrFromString("昱弘网通")
	text, _ := syscall.UTF16PtrFromString("这台电脑的屏幕正在被另一台昱弘网通查看。关掉共享进程即可停止。")
	procMessageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0)
	return nil
}

type mouseInput struct {
	Type      uint32
	Pad       uint32
	Dx        int32
	Dy        int32
	MouseData uint32
	Flags     uint32
	Time      uint32
	Extra     uintptr
}

type keyInput struct {
	Type  uint32
	Pad   uint32
	Vk    uint16
	Scan  uint16
	Flags uint32
	Time  uint32
	Extra uintptr
	Pad2  uint64
}

// Apply 把键鼠送到当前登录的桌面。坐标是 0 到 1。
func Apply(ev Event) error {
	switch ev.Kind {
	case "mouse":
		if ev.X < 0 {
			ev.X = 0
		}
		if ev.Y < 0 {
			ev.Y = 0
		}
		if ev.X > 1 {
			ev.X = 1
		}
		if ev.Y > 1 {
			ev.Y = 1
		}
		var flags uint32 = mouseMove | mouseAbs
		switch ev.Button + ":" + ev.Action {
		case "left:down":
			flags |= mouseLDown
		case "left:up":
			flags |= mouseLUp
		case "right:down":
			flags |= mouseRDown
		case "right:up":
			flags |= mouseRUp
		}
		in := mouseInput{
			Type:  inputMouse,
			Dx:    int32(ev.X * 65535),
			Dy:    int32(ev.Y * 65535),
			Flags: flags,
		}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
		return nil
	case "key":
		vk, ok := vkOf(ev.Key)
		if !ok {
			return nil
		}
		flags := uint32(0)
		if ev.Action == "up" {
			flags = keyUp
		}
		in := keyInput{Type: inputKey, Vk: vk, Flags: flags}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
		return nil
	default:
		return nil
	}
}

func vkOf(k string) (uint16, bool) {
	if len(k) == 1 {
		c := k[0]
		switch {
		case c >= 'a' && c <= 'z':
			return uint16(c - 'a' + 'A'), true
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			return uint16(c), true
		}
	}
	switch k {
	case "Enter":
		return 0x0D, true
	case "Backspace":
		return 0x08, true
	case "Tab":
		return 0x09, true
	case "Escape":
		return 0x1B, true
	case "ArrowLeft":
		return 0x25, true
	case "ArrowUp":
		return 0x26, true
	case "ArrowRight":
		return 0x27, true
	case "ArrowDown":
		return 0x28, true
	case " ":
		return 0x20, true
	default:
		return 0, false
	}
}
