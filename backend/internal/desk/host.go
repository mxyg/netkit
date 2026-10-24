package desk

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Port 被控端画面服务端口。
const Port = 8790

// CursorInfo 远端光标的位置（0 到 1）和形状图。
type CursorInfo struct {
	X, Y       float64
	HotX, HotY int
	PNG        []byte
}

// Serve 在 addr 上提供画面和键鼠。token 为空且地址不是回环时拒绝启动。
func Serve(addr, token string) error {
	if token == "" {
		return errNeedToken
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if !allow(r, token) {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/frame.jpg", func(w http.ResponseWriter, r *http.Request) {
		if !allow(r, token) {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		jpg, err := FrameJPEG()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cur := Cursor()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jpeg": jpg,
			"cx":   cur.X,
			"cy":   cur.Y,
			"hotx": cur.HotX,
			"hoty": cur.HotY,
			"png":  cur.PNG,
		})
	})
	mux.HandleFunc("/input", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !allow(r, token) {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		var ev Event
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&ev); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := Apply(ev); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = notifySharing() }()
	return srv.ListenAndServe()
}

func allow(r *http.Request, token string) bool {
	got := r.Header.Get("X-Desk-Token")
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	if len(got) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// Event 控制端发来的一次键鼠。坐标是画面上的比例，0 到 1。
type Event struct {
	Kind   string  `json:"kind"` // mouse | key
	Action string  `json:"action"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Button string  `json:"button"`
	Key    string  `json:"key"`
}
