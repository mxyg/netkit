package portal

import "net/http"

// localHandler 回环口：只服务主机自己的界面。
//
// ★★ 这一组路由**不鉴权**（能连上 127.0.0.1 的本来就在这台机器上，
//
//	和 API 主服务同一个前提），所以反过来更要守住：这里只许出现
//	「看」和「存当前帧」，任何工具调用、上传、下载、目录信息都不挂在这上面。
//	局域网口和回环口用的是两张 mux，加路由的人必须想清楚加到哪张。
func (s *Service) localHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /local/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Status())
	})
	m.HandleFunc("GET /local/cast/live", s.handleCastLive)
	m.HandleFunc("GET /local/cast/frame", s.handleCastFrameLatest)
	m.HandleFunc("POST /local/cast/save", s.handleCastSave)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "回环口只有 /local/* 这几条路", http.StatusNotFound)
	})
	return m
}
