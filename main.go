package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

func main() {
	cfg := LoadConfig()
	manager := NewSessionManager()
	projectStore, err := NewProjectStore(cfg.ProjectDBPath)
	if err != nil {
		log.Fatalf("failed to init sqlite: %v", err)
	}
	feishu := NewFeishuHandler(cfg, manager, projectStore)

	mux := http.NewServeMux()

	mux.HandleFunc("/", withCORS(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"service": "Claude Code Stream API",
			"version": "2.0.0",
			"status":  "running",
			"backend": "claude-cli-stream-json",
			"features": []string{
				"基于 Claude Code CLI",
				"双向流式通信 (stream-json)",
				"持久进程连接",
				"完整工具执行能力",
				"兼容 Codex API",
			},
			"endpoints": map[string]any{
				"POST /api/threads":                             "创建新会话",
				"GET /api/threads":                              "列出所有会话",
				"POST /api/threads/{thread_id}/resume":          "恢复会话",
				"DELETE /api/threads/{thread_id}":               "归档会话",
				"POST /api/threads/{thread_id}/messages":        "发送消息（同步）",
				"POST /api/threads/{thread_id}/messages/stream": "发送消息（流式SSE）",
				"WS /api/threads/{thread_id}/ws":                "WebSocket 连接",
				"POST /api/threads/{thread_id}/interrupt":       "中断当前回合",
				"GET /api/auth":                                 "查询认证状态",
			},
		})
	}))

	mux.HandleFunc("/api/threads", withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var cfg ThreadConfig
			_ = json.NewDecoder(r.Body).Decode(&cfg)
			if cfg.Tools == "" {
				cfg.Tools = "default"
			}
			resp, err := manager.CreateThread(cfg)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeJSON(w, resp)
			return
		}
		if r.Method == http.MethodGet {
			cursor := r.URL.Query().Get("cursor")
			limit := 25
			if v := r.URL.Query().Get("limit"); v != "" {
				if n, err := strconvAtoiSafe(v); err == nil {
					limit = n
				}
			}
			var cur *string
			if cursor != "" {
				cur = &cursor
			}
			resp := manager.ListThreads(cur, limit)
			writeJSON(w, resp)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))

	mux.HandleFunc("/api/threads/", withCORS(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		threadID := parts[2]
		if strings.HasSuffix(r.URL.Path, "/ws") && r.Method == http.MethodGet {
			handleWebsocket(manager, threadID, w, r)
			return
		}
		// /api/threads/{id}/resume
		if len(parts) == 4 && parts[3] == "resume" && r.Method == http.MethodPost {
			resp, err := manager.ResumeThread(threadID)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeJSON(w, resp)
			return
		}
		// /api/threads/{id}
		if len(parts) == 3 && r.Method == http.MethodDelete {
			_ = manager.ArchiveThread(threadID)
			writeJSON(w, map[string]any{"success": true})
			return
		}
		// /api/threads/{id}/messages
		if len(parts) == 4 && parts[3] == "messages" && r.Method == http.MethodPost {
			var req MessageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp, err := manager.SendMessage(threadID, req.Message)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeJSON(w, resp)
			return
		}
		// /api/threads/{id}/messages/stream
		if len(parts) == 5 && parts[3] == "messages" && parts[4] == "stream" && r.Method == http.MethodPost {
			var req MessageRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Accel-Buffering", "no")
			flusher, ok := w.(http.Flusher)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = manager.SendMessageStream(threadID, req.Message, func(line string) error {
				_, _ = w.Write([]byte("data: " + line + "\n\n"))
				flusher.Flush()
				return nil
			})
			return
		}
		// /api/threads/{id}/interrupt
		if len(parts) == 4 && parts[3] == "interrupt" && r.Method == http.MethodPost {
			if p, ok := manager.GetProcess(threadID); ok && p.cmd != nil {
				_ = p.cmd.Process.Signal(os.Interrupt)
				writeJSON(w, map[string]any{"success": true, "note": "Interrupt signal sent"})
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	mux.HandleFunc("/api/auth", withCORS(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"authenticated": true, "provider": "claude-cli", "note": "Claude CLI uses local configuration"})
	}))

	mux.HandleFunc("/feishu/events", withCORS(func(w http.ResponseWriter, r *http.Request) {
		feishu.HandleEvents(w, r)
	}))
	mux.HandleFunc("/feishu/callback", withCORS(func(w http.ResponseWriter, r *http.Request) {
		feishu.HandleCardCallback(w, r)
	}))

	log.Println("Claude Code Stream API Server")
	log.Println("Listening on :6000")
	if err := http.ListenAndServe(":6000", mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func handleWebsocket(manager *SessionManager, threadID string, w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	process, ok := manager.GetProcess(threadID)
	if !ok {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4004, "Thread not found"))
		return
	}

	eventCh := process.SubscribeEvents("*")
	defer process.UnsubscribeEvents("*", eventCh)

	go func() {
		for ev := range eventCh {
			_ = conn.WriteJSON(ev)
		}
	}()

	for {
		var msg map[string]any
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}
		switch msg["type"] {
		case "message":
			if text, ok := msg["text"].(string); ok {
				_ = process.SendMessage(text)
			}
		case "interrupt":
			// no-op
		}
	}
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
