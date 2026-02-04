package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
)

type FeishuHandler struct {
	cfg      Config
	manager  *SessionManager
	projects *ProjectStore
	sdk      *lark.Client

	dedupMu sync.Mutex
	dedup   map[string]time.Time

	chatThreadMu sync.Mutex
	chatThread   map[string]string

	pendingMu     sync.Mutex
	pendingByUser map[string]string

	modelMu      sync.Mutex
	modelCache   []string
	modelCacheAt time.Time
}

func NewFeishuHandler(cfg Config, manager *SessionManager, projects *ProjectStore) *FeishuHandler {
	return &FeishuHandler{
		cfg:           cfg,
		manager:       manager,
		projects:      projects,
		sdk:           lark.NewClient(cfg.FeishuAppID, cfg.FeishuAppSecret),
		dedup:         map[string]time.Time{},
		chatThread:    map[string]string{},
		pendingByUser: map[string]string{},
	}
}

func (h *FeishuHandler) replyText(messageID, text string) error {
	req := larkim.NewReplyMessageReqBuilder().
		MessageId(messageID).
		Body(larkim.NewReplyMessageReqBodyBuilder().
			MsgType("text").
			Content(mustJSON(map[string]string{"text": text})).
			ReplyInThread(false).
			Build()).
		Build()
	resp, err := h.sdk.Im.V1.Message.Reply(context.Background(), req)
	if err != nil {
		return err
	}
	if !resp.Success() {
		log.Printf("Feishu reply error: code=%v msg=%v req=%v", resp.Code, resp.Msg, resp.RequestId())
	}
	return nil
}

func (h *FeishuHandler) sendText(chatID, text string) error {
	return h.sendMessage("chat_id", map[string]any{
		"receive_id": chatID,
		"msg_type":   "text",
		"content":    mustJSON(map[string]string{"text": text}),
	})
}

func (h *FeishuHandler) isDuplicate(eventID string) bool {
	if eventID == "" {
		return false
	}
	h.dedupMu.Lock()
	defer h.dedupMu.Unlock()
	now := time.Now()
	for k, v := range h.dedup {
		if now.Sub(v) > 8*time.Hour {
			delete(h.dedup, k)
		}
	}
	if _, ok := h.dedup[eventID]; ok {
		return true
	}
	h.dedup[eventID] = now
	return false
}

func (h *FeishuHandler) HandleEvents(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	ts := r.Header.Get("X-Lark-Request-Timestamp")
	nonce := r.Header.Get("X-Lark-Request-Nonce")
	sig := r.Header.Get("X-Lark-Signature")
	log.Printf("[feishu] headers ts=%s nonce=%s sig=%s", ts, nonce, sig)

	if h.cfg.FeishuEncryptKey != "" && !VerifyFeishuSignature(raw, ts, nonce, sig, h.cfg.FeishuEncryptKey) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	log.Printf("[feishu] payload keys=%v", keys(payload))
	if schema, ok := payload["schema"].(string); ok {
		log.Printf("[feishu] schema=%s", schema)
	}

	if payload["type"] == "url_verification" {
		if token, _ := payload["token"].(string); h.cfg.FeishuVerificationToken != "" && token != h.cfg.FeishuVerificationToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := map[string]any{"challenge": payload["challenge"]}
		writeJSON(w, resp)
		return
	}

	if payload["type"] == "event_callback" || payload["schema"] == "2.0" {
		header, _ := payload["header"].(map[string]any)
		log.Printf("[feishu] header keys=%v", keys(header))
		token, _ := header["token"].(string)
		if token == "" {
			if t, ok := payload["token"].(string); ok {
				token = t
			}
		}
		if h.cfg.FeishuVerificationToken != "" && token != h.cfg.FeishuVerificationToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		eventID, _ := header["event_id"].(string)
		eventType, _ := header["event_type"].(string)
		log.Printf("[feishu] event_id=%s event_type=%s", eventID, eventType)
		if h.isDuplicate(eventID) {
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		if _, ok := payload["encrypt"]; ok {
			log.Printf("[feishu] encrypted event payload detected; decrypt not implemented")
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		event, _ := payload["event"].(map[string]any)
		log.Printf("[feishu] event keys=%v", keys(event))
		switch eventType {
		case "im.message.receive_v1":
			go h.handleMessageEvent(event)
		case "application.bot.menu_v6":
			go h.handleMenuEvent(event)
		}
		writeJSON(w, map[string]any{"ok": true})
		return
	}

	writeJSON(w, map[string]any{"ok": true})
}

func (h *FeishuHandler) HandleCardCallback(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		log.Printf("[feishu] card callback invalid json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Printf("[feishu] card callback keys=%v", keys(payload))

	if t, _ := payload["type"].(string); t == "url_verification" {
		writeJSON(w, map[string]any{"challenge": payload["challenge"]})
		return
	}

	// 新版回调 schema=2.0，数据在 event 里
	if payload["schema"] == "2.0" {
		header, _ := payload["header"].(map[string]any)
		eventType, _ := header["event_type"].(string)
		if eventType != "" {
			log.Printf("[feishu] card callback event_type=%s", eventType)
		}
		if eventType == "card.action.trigger" || eventType == "card.action.trigger_v1" {
			event, _ := payload["event"].(map[string]any)
			log.Printf("[feishu] card callback event keys=%v", keys(event))
			if b, err := json.Marshal(event); err == nil {
				log.Printf("[feishu] card callback event=%s", string(b))
			}
			// 兼容字段
			token, _ := event["token"].(string)
			userID := extractUserIDFromCardEvent(event)
			// action 可能在 event["action"] 或 event["action_list"]
			var action map[string]any
			switch a := event["action"].(type) {
			case map[string]any:
				action = a
			case []any:
				if len(a) > 0 {
					if m, ok := a[0].(map[string]any); ok {
						action = m
					}
				}
			}
			if action == nil {
				switch a := event["action_list"].(type) {
				case []any:
					if len(a) > 0 {
						if m, ok := a[0].(map[string]any); ok {
							action = m
						}
					}
				}
			}
			value, _ := action["value"].(map[string]any)
			form, _ := event["form"].(map[string]any)
			if form == nil {
				form, _ = event["form_value"].(map[string]any)
			}
			if form == nil {
				form, _ = action["form_value"].(map[string]any)
			}
			chatID := ""
			if ctx, ok := event["context"].(map[string]any); ok {
				if v, ok := ctx["open_chat_id"].(string); ok {
					chatID = v
				}
			}
			log.Printf("[feishu] card callback parsed token=%v user=%s value=%v form=%v", token != "", userID, value, form != nil)
			resp := h.handleCardAction(eventType, token, userID, chatID, value, form)
			writeJSON(w, resp)
			return
		}
	}

	token, _ := payload["token"].(string)

	// action 可能是对象或数组
	var action map[string]any
	switch a := payload["action"].(type) {
	case map[string]any:
		action = a
	case []any:
		if len(a) > 0 {
			if m, ok := a[0].(map[string]any); ok {
				action = m
			}
		}
	}
	value, _ := action["value"].(map[string]any)

	form, _ := payload["form"].(map[string]any)
	if form == nil {
		form, _ = payload["form_value"].(map[string]any)
	}

	userID, _ := payload["user_id"].(string)
	if userID == "" {
		if v, ok := payload["open_id"].(string); ok {
			userID = v
		}
	}

	resp := h.handleCardAction("card.action.trigger_v1", token, userID, "", value, form)
	writeJSON(w, resp)
}

func (h *FeishuHandler) handleCardAction(eventType, token, userID, chatID string, value map[string]any, form map[string]any) map[string]any {
	if token == "" || value == nil || userID == "" {
		log.Printf("[feishu] card callback missing token/value/user_id. token=%v user=%v value=%v", token != "", userID, value != nil)
		return map[string]any{
			"toast": map[string]any{"type": "error", "content": "缺少用户信息或动作参数"},
		}
	}

	actionName, _ := value["action"].(string)
	page := intFromAny(value["page"])
	refreshCard := true
	toastType := "success"
	toastText := "已更新"

	if actionName == "set_model" {
		return h.handleSetModel(userID, chatID, value, eventType)
	}

	switch actionName {
	case "load_more":
		// no-op, just update card
	case "open_create":
		if eventType == "card.action.trigger" {
			go h.sendProjectFormCard(userID, page, "create")
			return map[string]any{
				"toast": map[string]any{"type": "info", "content": "已打开表单"},
			}
		}
		return h.cardResp("info", "请填写项目表单", h.buildProjectFormCard(userID, page, "create"), eventType)
	case "open_bind":
		if eventType == "card.action.trigger" {
			go h.sendProjectFormCard(userID, page, "bind")
			return map[string]any{
				"toast": map[string]any{"type": "info", "content": "已打开表单"},
			}
		}
		return h.cardResp("info", "请填写目录路径", h.buildProjectFormCard(userID, page, "bind"), eventType)
	case "resume":
		id := int64FromAny(value["project_id"])
		h.handleResumeProject(userID, chatID, id, token)
		refreshCard = false
		toastText = "已切换"
	case "delete":
		id := int64FromAny(value["project_id"])
		_ = h.projects.Delete(userID, id)
	case "create":
		name := ""
		cwd := ""
		if form != nil {
			name = strFromAny(form["project_name"])
			cwd = strFromAny(form["project_cwd"])
		}
		if strings.TrimSpace(cwd) == "" {
			if eventType == "card.action.trigger" {
				go h.sendProjectFormCard(userID, page, "create")
				return map[string]any{
					"toast": map[string]any{"type": "warning", "content": "请填写目录路径"},
				}
			}
			return h.cardResp("warning", "请填写目录路径", h.buildProjectFormCard(userID, page, "create"), eventType)
		}
		threadID, err := h.handleCreateProject(userID, name, cwd, token)
		if err != nil {
			log.Printf("[feishu] create project failed: %v", err)
			if eventType == "card.action.trigger" {
				go h.sendProjectFormCard(userID, page, "create")
				return map[string]any{
					"toast": map[string]any{"type": "error", "content": err.Error()},
				}
			}
			return h.cardResp("error", err.Error(), h.buildProjectFormCard(userID, page, "create"), eventType)
		}
		if chatID != "" && threadID != "" {
			h.setChatThread(chatID, threadID)
			if h.projects != nil && userID != "" {
				_ = h.projects.UpsertChatThread(chatID, userID, threadID)
			}
		}
	case "bind":
		cwd := ""
		if form != nil {
			cwd = strFromAny(form["project_cwd"])
		}
		if strings.TrimSpace(cwd) == "" {
			if eventType == "card.action.trigger" {
				go h.sendProjectFormCard(userID, page, "bind")
				return map[string]any{
					"toast": map[string]any{"type": "warning", "content": "请填写目录路径"},
				}
			}
			return h.cardResp("warning", "请填写目录路径", h.buildProjectFormCard(userID, page, "bind"), eventType)
		}
		threadID, err := h.handleCreateProject(userID, "", cwd, token)
		if err != nil {
			log.Printf("[feishu] bind project failed: %v", err)
			if eventType == "card.action.trigger" {
				go h.sendProjectFormCard(userID, page, "bind")
				return map[string]any{
					"toast": map[string]any{"type": "error", "content": err.Error()},
				}
			}
			return h.cardResp("error", err.Error(), h.buildProjectFormCard(userID, page, "bind"), eventType)
		}
		if chatID != "" && threadID != "" {
			h.setChatThread(chatID, threadID)
			if h.projects != nil && userID != "" {
				_ = h.projects.UpsertChatThread(chatID, userID, threadID)
			}
		}
	}

	if !refreshCard {
		return map[string]any{
			"toast": map[string]any{"type": toastType, "content": toastText},
		}
	}
	if eventType == "card.action.trigger" {
		go h.sendProjectCard(userID, page)
		return map[string]any{
			"toast": map[string]any{"type": toastType, "content": toastText},
		}
	}
	return h.cardResp(toastType, toastText, h.buildProjectCard(userID, page), eventType)
}

func (h *FeishuHandler) cardResp(toastType, toast string, card map[string]any, eventType string) map[string]any {
	resp := map[string]any{
		"toast": map[string]any{"type": toastType, "content": toast},
	}
	if eventType == "card.action.trigger_v1" {
		resp["card"] = card
		return resp
	}
	resp["card"] = map[string]any{
		"type": "raw",
		"data": card,
	}
	return resp
}

func extractUserIDFromCardEvent(event map[string]any) string {
	// 优先 user_id/open_id
	if v, ok := event["user_id"].(string); ok && v != "" {
		return v
	}
	if v, ok := event["open_id"].(string); ok && v != "" {
		return v
	}
	// operator.operator_id
	if op, ok := event["operator"].(map[string]any); ok {
		if opID, ok := op["operator_id"].(map[string]any); ok {
			if v, ok := opID["user_id"].(string); ok && v != "" {
				return v
			}
			if v, ok := opID["open_id"].(string); ok && v != "" {
				return v
			}
		}
		if v, ok := op["open_id"].(string); ok && v != "" {
			return v
		}
		if v, ok := op["user_id"].(string); ok && v != "" {
			return v
		}
	}
	// context
	if ctx, ok := event["context"].(map[string]any); ok {
		if v, ok := ctx["open_id"].(string); ok && v != "" {
			return v
		}
		if v, ok := ctx["user_id"].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func (h *FeishuHandler) handleMessageEvent(event map[string]any) {
	message, _ := event["message"].(map[string]any)
	messageID, _ := message["message_id"].(string)
	chatID, _ := message["chat_id"].(string)
	content, _ := message["content"].(string)
	senderID := GetSenderID(event)

	h.handleIncomingMessage(messageID, chatID, content, senderID)
}

func (h *FeishuHandler) handleMenuEvent(event map[string]any) {
	operator, _ := event["operator"].(map[string]any)
	operatorID, _ := operator["operator_id"].(map[string]any)
	userID, _ := operatorID["user_id"].(string)
	openID, _ := operatorID["open_id"].(string)
	if userID == "" {
		userID = openID
	}
	eventKey, _ := event["event_key"].(string)
	if userID == "" || eventKey == "" {
		log.Printf("[feishu] menu event missing user_id/open_id (need field permission). operator=%v", operatorID)
		return
	}

	log.Printf("[feishu] menu event_key=%s user_id=%s open_id=%s", eventKey, userID, openID)
	h.handleMenuEventKey(userID, openID, eventKey)
}

func (h *FeishuHandler) handleMenuEventKey(userID, openID, eventKey string) {
	if userID == "" {
		userID = openID
	}
	if userID == "" || eventKey == "" {
		return
	}

	if h.cfg.FeishuMenuProjectsKey != "" && eventKey == h.cfg.FeishuMenuProjectsKey {
		if err := h.sendProjectCard(userID, 0); err != nil {
			log.Printf("[feishu] send project card error: %v", err)
		}
		return
	}

	action := ""
	switch eventKey {
	case h.cfg.FeishuMenuAcceptKey:
		action = "接受"
	case h.cfg.FeishuMenuAcceptAllKey:
		action = "默认接受"
	case h.cfg.FeishuMenuRejectKey:
		action = "拒绝"
	}
	if action == "" {
		return
	}

	threadID := h.getPendingThread(userID)
	if threadID == "" {
		return
	}

	session, _ := h.manager.GetThread(threadID)
	pending := session.PendingApproval
	if pending == nil {
		return
	}

	chatID, _ := pending["chat_id"].(string)
	messageID, _ := pending["message_id"].(string)

	if action == "拒绝" {
		session.PendingApproval = nil
		h.clearPending(userID)
		_ = h.manager.RestartThread(threadID, session.BasePermissionMode)
		if messageID != "" {
			_ = h.replyText(messageID, "已拒绝，请提供替代指令。")
		} else if chatID != "" {
			_ = h.sendText(chatID, "已拒绝，请提供替代指令。")
		}
		return
	}

	toolName, _ := pending["tool"].(string)
	userMessage, _ := pending["user_message"].(string)
	if action == "默认接受" && toolName != "" {
		session.AutoAllowTools[toolName] = struct{}{}
	}

	session.PendingApproval = nil
	h.clearPending(userID)
	if messageID != "" {
		_ = h.replyText(messageID, "已接受，正在执行。")
	} else if chatID != "" {
		_ = h.sendText(chatID, "已接受，正在执行。")
	}
	_ = h.manager.RestartThread(threadID, "dontAsk")
	if userMessage != "" {
		_ = h.processAndReply(threadID, messageID, chatID, userID, userMessage)
	}
}

func (h *FeishuHandler) handleIncomingMessage(messageID, chatID, content, senderID string) {
	log.Printf("[feishu] message_id=%s chat_id=%s", messageID, chatID)
	log.Printf("[feishu] raw content=%s", content)
	if messageID == "" || chatID == "" {
		return
	}

	var contentObj map[string]any
	_ = json.Unmarshal([]byte(content), &contentObj)
	text, _ := contentObj["text"].(string)
	text = strings.TrimSpace(text)
	log.Printf("[feishu] parsed text='%s'", text)
	if text == "" {
		return
	}

	threadID := h.getOrCreateThread(chatID)
	if threadID == "" {
		log.Printf("[feishu] failed to get thread for chat_id=%s", chatID)
		return
	}
	if h.projects != nil && senderID != "" {
		_ = h.projects.UpsertChatThread(chatID, senderID, threadID)
	}
	session, ok := h.manager.GetThread(threadID)
	if !ok || session == nil {
		log.Printf("[feishu] thread not found for chat_id=%s thread_id=%s", chatID, threadID)
		return
	}
	if session.AutoAllowTools == nil || len(session.AutoAllowTools) == 0 {
		if session.AutoAllowTools == nil {
			session.AutoAllowTools = map[string]struct{}{}
		}
		for _, t := range ParseAllowedTools(h.cfg.AutoAllowTools) {
			session.AutoAllowTools[t] = struct{}{}
		}
	}

	if strings.HasPrefix(text, "/") {
		if h.handleSlashCommand(session, threadID, messageID, chatID, senderID, text) {
			return
		}
	}

	_ = h.processAndReply(threadID, messageID, chatID, senderID, text)
}

func (h *FeishuHandler) handleSlashCommand(session *Session, threadID, messageID, chatID, userID, text string) bool {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return false
	}
	switch parts[0] {
	case "/model":
		if chatID == "" {
			model := session.Config.Model
			if model == "" {
				model = "default"
			}
			if messageID != "" {
				_ = h.replyText(messageID, fmt.Sprintf("当前模型：%s", model))
			}
			return true
		}
		card := h.buildModelCard(session.Config.Model, h.getModelOptions())
		_ = h.sendModelCard(chatID, card)
		return true
	case "/compact":
		if chatID == "" || threadID == "" {
			return true
		}
		if messageID != "" {
			_ = h.replyText(messageID, "正在压缩会话，请稍候…")
		} else {
			_ = h.sendText(chatID, "正在压缩会话，请稍候…")
		}

		summary, err := h.compactSession(threadID, session)
		if err != nil || strings.TrimSpace(summary) == "" {
			if messageID != "" {
				_ = h.replyText(messageID, "压缩失败，请稍后再试。")
			} else {
				_ = h.sendText(chatID, "压缩失败，请稍后再试。")
			}
			return true
		}

		newID, err := h.createCompactedThread(session, summary)
		if err != nil {
			if messageID != "" {
				_ = h.replyText(messageID, "压缩失败，请稍后再试。")
			} else {
				_ = h.sendText(chatID, "压缩失败，请稍后再试。")
			}
			return true
		}

		if newID != "" && newID != threadID {
			if h.projects != nil {
				if p, err := h.projects.GetByThreadID(threadID); err == nil && p != nil {
					_, _ = h.projects.UpsertProject(p.UserID, p.Name, p.Cwd, newID)
				}
				if userID != "" {
					_ = h.projects.UpsertChatThread(chatID, userID, newID)
				}
			}
			h.setChatThread(chatID, newID)
			_ = h.manager.ArchiveThread(threadID)
		}

		_ = h.sendText(chatID, "已压缩，会话已更新。")
		return true
	default:
		if messageID != "" {
			_ = h.replyText(messageID, "当前模式仅支持 /model 和 /compact。")
		} else if chatID != "" {
			_ = h.sendText(chatID, "当前模式仅支持 /model 和 /compact。")
		}
		return true
	}
}

func (h *FeishuHandler) compactSession(threadID string, session *Session) (string, error) {
	prompt := "请将我们到目前为止的对话压缩成一份精简摘要，保留：目标、已完成工作、关键决定、待办与约束。请用中文条目化输出，尽量短。"
	resp, err := h.manager.SendMessage(threadID, prompt)
	if err != nil {
		return "", err
	}
	if v, ok := resp["response"].(string); ok {
		return v, nil
	}
	return "", errInternal
}

func (h *FeishuHandler) createCompactedThread(session *Session, summary string) (string, error) {
	cfg := session.Config
	base := strings.TrimSpace(cfg.System)
	summary = strings.TrimSpace(summary)
	if base != "" {
		cfg.System = base + "\n\n以下为此前对话的精简摘要，可作为后续上下文：\n" + summary
	} else {
		cfg.System = "以下为此前对话的精简摘要，可作为后续上下文：\n" + summary
	}
	thread, err := h.manager.CreateThread(cfg)
	if err != nil {
		return "", err
	}
	id := thread["thread"].(map[string]any)["id"].(string)
	return id, nil
}

func (h *FeishuHandler) handleSetModel(userID, chatID string, value map[string]any, eventType string) map[string]any {
	model := strFromAny(value["model"])
	if model == "" || chatID == "" {
		return map[string]any{
			"toast": map[string]any{"type": "error", "content": "缺少模型或会话信息"},
		}
	}
	threadID := h.getOrCreateThread(chatID)
	if threadID == "" {
		return map[string]any{
			"toast": map[string]any{"type": "error", "content": "会话不可用"},
		}
	}
	session, ok := h.manager.GetThread(threadID)
	if !ok || session == nil {
		return map[string]any{
			"toast": map[string]any{"type": "error", "content": "会话不可用"},
		}
	}

	oldModel := session.Config.Model
	session.Config.Model = model
	if err := h.manager.RestartThread(threadID, session.PermissionMode); err != nil {
		session.Config.Model = oldModel
		return map[string]any{
			"toast": map[string]any{"type": "error", "content": "切换失败，请重试"},
		}
	}

	card := h.buildModelCard(session.Config.Model, h.getModelOptions())
	return h.cardResp("success", "已切换模型", card, eventType)
}

func (h *FeishuHandler) processAndReply(threadID, messageID, chatID, senderID, text string) error {
	session, _ := h.manager.GetThread(threadID)
	process, _ := h.manager.GetProcess(threadID)
	ch := process.SubscribeEvents("*")
	defer process.UnsubscribeEvents("*", ch)

	session.LastUserMessage = text
	if err := process.SendMessage(text); err != nil {
		log.Printf("[feishu] send to claude failed: %v", err)
		return err
	}

	buffer := ""
	lastSend := time.Now()

	timeout := time.After(300 * time.Second)
	for {
		var ev map[string]any
		select {
		case ev = <-ch:
		case <-timeout:
			if messageID != "" {
				_ = h.replyText(messageID, "超时：Claude 没有在预期时间内返回。")
			} else if chatID != "" {
				_ = h.sendText(chatID, "超时：Claude 没有在预期时间内返回。")
			}
			return nil
		}
		if h.cfg.DebugEvents {
			method, _ := ev["method"].(string)
			paramsKeys := []string{}
			if params, ok := ev["params"].(map[string]any); ok {
				paramsKeys = keys(params)
			}
			log.Printf("[feishu] event method=%s keys=%v params_keys=%v", method, keys(ev), paramsKeys)
		}
		if ev["method"] == "item/agentMessage/delta" {
			params, _ := ev["params"].(map[string]any)
			if delta, ok := params["delta"].(string); ok {
				buffer += delta
			}
		}
		if ev["method"] == "tool/start" {
			params, _ := ev["params"].(map[string]any)
			toolName, _ := params["tool"].(string)
			toolInput, _ := params["input"].(map[string]any)
			if session.PermissionMode != "dontAsk" {
				if toolName != "" && ToolAutoAllowed(toolName, toolInput, session.AutoAllowTools) {
					session.PendingApproval = nil
					process.UnsubscribeEvents("*", ch)
					_ = h.manager.RestartThread(threadID, "dontAsk")
					if messageID != "" {
						_ = h.replyText(messageID, "已自动接受 "+toolName+"，正在执行。")
					} else if chatID != "" {
						_ = h.sendText(chatID, "已自动接受 "+toolName+"，正在执行。")
					}
					resend := session.LastUserMessage
					if resend != "" {
						process, _ = h.manager.GetProcess(threadID)
						ch = process.SubscribeEvents("*")
						_ = process.SendMessage(resend)
						buffer = ""
						lastSend = time.Now()
					}
					continue
				}

				session.PendingApproval = map[string]any{
					"tool":         toolName,
					"user_message": session.LastUserMessage,
					"chat_id":      chatID,
					"message_id":   messageID,
					"sender_id":    senderID,
				}
				if senderID != "" {
					h.setPending(senderID, threadID)
				}
				if messageID != "" {
					_ = h.replyText(messageID, "需要权限以执行工具："+toolName+"。请点击菜单“接受/默认接受/拒绝”。")
				} else if chatID != "" {
					_ = h.sendText(chatID, "需要权限以执行工具："+toolName+"。请点击菜单“接受/默认接受/拒绝”。")
				}
				process.Stop()
				return nil
			}
		}

		if h.cfg.FeishuStreamMode == "stream" {
			if buffer != "" && (len(buffer) >= h.cfg.FeishuStreamMinChars || time.Since(lastSend).Seconds() >= h.cfg.FeishuStreamInterval) {
				for _, chunk := range SplitTextByBytes(buffer, h.cfg.FeishuTextMaxBytes) {
					if messageID != "" {
						_ = h.replyText(messageID, chunk)
					} else if chatID != "" {
						_ = h.sendText(chatID, chunk)
					}
				}
				buffer = ""
				lastSend = time.Now()
			}
		}

		if ev["method"] == "turn/completed" {
			if buffer != "" {
				for _, chunk := range SplitTextByBytes(buffer, h.cfg.FeishuTextMaxBytes) {
					if messageID != "" {
						_ = h.replyText(messageID, chunk)
					} else if chatID != "" {
						_ = h.sendText(chatID, chunk)
					}
				}
			}
			if session.PermissionMode == "dontAsk" {
				if session.BasePermissionMode != "dontAsk" {
					_ = h.manager.RestartThread(threadID, session.BasePermissionMode)
				}
			}
			return nil
		}
		if ev["method"] == "error" {
			if messageID != "" {
				_ = h.replyText(messageID, "发生错误")
			} else if chatID != "" {
				_ = h.sendText(chatID, "发生错误")
			}
			return nil
		}
	}
}

func (h *FeishuHandler) handleCreateProject(userID, name, cwd, token string) (string, error) {
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		return "", fmt.Errorf("目录路径不能为空")
	}
	if name == "" {
		name = cwd
	}
	info, err := os.Stat(cwd)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(cwd, 0o755); mkErr != nil {
				return "", fmt.Errorf("无法创建目录: %s", cwd)
			}
			info, err = os.Stat(cwd)
		}
	}
	if err != nil {
		return "", fmt.Errorf("目录不可访问: %s", cwd)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("不是目录: %s", cwd)
	}
	thread, err := h.manager.CreateThread(ThreadConfig{Cwd: cwd, Tools: "default", PermissionMode: "acceptEdits"})
	if err != nil {
		return "", err
	}
	id := thread["thread"].(map[string]any)["id"].(string)
	if _, err := h.projects.UpsertProject(userID, name, cwd, id); err != nil {
		return "", err
	}
	return id, nil
}

func (h *FeishuHandler) handleResumeProject(userID, chatID string, projectID int64, token string) {
	p, err := h.projects.GetByID(userID, projectID)
	if err != nil {
		return
	}
	threadID := p.ThreadID
	if _, err := h.manager.ResumeThread(threadID); err != nil {
		if errors.Is(err, errNotFound) {
			cfg := ThreadConfig{Cwd: p.Cwd, Tools: "default", PermissionMode: "acceptEdits"}
			if _, resumeErr := h.manager.ResumeThreadWithConfig(threadID, cfg); resumeErr == nil {
				// resumed using persisted session id
			} else {
				newID, createErr := h.handleCreateProject(userID, p.Name, p.Cwd, token)
				if createErr != nil {
					log.Printf("[feishu] resume project failed: %v", createErr)
					return
				}
				threadID = newID
			}
		} else {
			newID, createErr := h.handleCreateProject(userID, p.Name, p.Cwd, token)
			if createErr != nil {
				log.Printf("[feishu] resume project failed: %v", createErr)
				return
			}
			threadID = newID
		}
	}
	if chatID != "" && threadID != "" {
		h.setChatThread(chatID, threadID)
		if h.projects != nil && userID != "" {
			_ = h.projects.UpsertChatThread(chatID, userID, threadID)
		}
		_ = h.sendText(chatID, fmt.Sprintf("已切换到项目：【%s】 路径：%s", p.Name, p.Cwd))
	}
}

func (h *FeishuHandler) getOrCreateThread(chatID string) string {
	h.chatThreadMu.Lock()
	if id, ok := h.chatThread[chatID]; ok {
		h.chatThreadMu.Unlock()
		return id
	}
	h.chatThreadMu.Unlock()

	if h.projects != nil {
		if threadID, userID, err := h.projects.GetChatThread(chatID); err == nil && threadID != "" {
			cfg := ThreadConfig{PermissionMode: "acceptEdits"}
			if p, err := h.projects.GetByThreadID(threadID); err == nil && p != nil {
				cfg.Cwd = p.Cwd
				cfg.Tools = "default"
			}
			if _, err := h.manager.ResumeThreadWithConfig(threadID, cfg); err == nil {
				h.chatThreadMu.Lock()
				h.chatThread[chatID] = threadID
				h.chatThreadMu.Unlock()
				if userID != "" {
					_ = h.projects.UpsertChatThread(chatID, userID, threadID)
				}
				return threadID
			}
		}
	}
	thread, err := h.manager.CreateThread(ThreadConfig{PermissionMode: "acceptEdits"})
	if err != nil {
		return ""
	}
	id := thread["thread"].(map[string]any)["id"].(string)
	h.chatThread[chatID] = id
	return id
}

func (h *FeishuHandler) setChatThread(chatID, threadID string) {
	h.chatThreadMu.Lock()
	defer h.chatThreadMu.Unlock()
	if chatID == "" || threadID == "" {
		return
	}
	h.chatThread[chatID] = threadID
}

func (h *FeishuHandler) setPending(userID, threadID string) {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	h.pendingByUser[userID] = threadID
}

func (h *FeishuHandler) clearPending(userID string) {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	delete(h.pendingByUser, userID)
}

func (h *FeishuHandler) getPendingThread(userID string) string {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	return h.pendingByUser[userID]
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (h *FeishuHandler) sendProjectCard(userID string, page int) error {
	card := h.buildProjectCard(userID, page)
	receiveType := "user_id"
	if strings.HasPrefix(userID, "ou_") {
		receiveType = "open_id"
	}
	payload := map[string]any{
		"receive_id": userID,
		"msg_type":   "interactive",
		"content":    mustJSON(card),
	}
	return h.sendMessage(receiveType, payload)
}

func (h *FeishuHandler) sendProjectFormCard(userID string, page int, mode string) error {
	card := h.buildProjectFormCard(userID, page, mode)
	receiveType := "user_id"
	if strings.HasPrefix(userID, "ou_") {
		receiveType = "open_id"
	}
	payload := map[string]any{
		"receive_id": userID,
		"msg_type":   "interactive",
		"content":    mustJSON(card),
	}
	return h.sendMessage(receiveType, payload)
}

func (h *FeishuHandler) updateProjectCard(token, userID string, page int) error {
	return nil
}

func (h *FeishuHandler) buildProjectCard(userID string, page int) map[string]any {
	limit := 5
	offset := page * limit
	list, _ := h.projects.List(userID, limit+1, offset)
	hasMore := len(list) > limit
	if hasMore {
		list = list[:limit]
	}

	elements := []any{
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"tag":     "lark_md",
				"content": "**最近项目**",
			},
		},
	}

	if len(list) == 0 {
		elements = append(elements, map[string]any{
			"tag": "div",
			"text": map[string]any{
				"tag":     "lark_md",
				"content": "暂无项目，使用下方表单创建或绑定目录。",
			},
		})
	} else {
		for _, p := range list {
			elements = append(elements,
				map[string]any{
					"tag": "div",
					"text": map[string]any{
						"tag":     "lark_md",
						"content": "【" + p.Name + "】 ｜ `" + p.Cwd + "`",
					},
				},
				map[string]any{
					"tag":    "action",
					"layout": "bisected",
					"actions": []any{
						map[string]any{
							"tag":  "button",
							"text": map[string]any{"tag": "plain_text", "content": "恢复会话"},
							"type": "primary",
							"size": "small",
							"value": map[string]any{
								"action":     "resume",
								"project_id": p.ID,
								"page":       page,
							},
						},
						map[string]any{
							"tag":  "button",
							"text": map[string]any{"tag": "plain_text", "content": "删除"},
							"type": "danger",
							"size": "small",
							"value": map[string]any{
								"action":     "delete",
								"project_id": p.ID,
								"page":       page,
							},
							"confirm": map[string]any{
								"title":   map[string]any{"tag": "plain_text", "content": "确认删除？"},
								"text":    map[string]any{"tag": "plain_text", "content": "删除后无法恢复"},
								"confirm": map[string]any{"tag": "plain_text", "content": "删除"},
								"cancel":  map[string]any{"tag": "plain_text", "content": "取消"},
							},
						},
					},
				},
			)
		}
	}

	elements = append(elements,
		map[string]any{"tag": "hr"},
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"tag":     "lark_md",
				"content": "**创建/绑定项目**",
			},
		},
		map[string]any{
			"tag":    "action",
			"layout": "trisection",
			"actions": []any{
				map[string]any{
					"tag":   "button",
					"text":  map[string]any{"tag": "plain_text", "content": "新建项目"},
					"type":  "primary",
					"size":  "small",
					"value": map[string]any{"action": "open_create", "page": page},
				},
				map[string]any{
					"tag":   "button",
					"text":  map[string]any{"tag": "plain_text", "content": "绑定目录"},
					"type":  "default",
					"size":  "small",
					"value": map[string]any{"action": "open_bind", "page": page},
				},
				map[string]any{
					"tag":   "button",
					"text":  map[string]any{"tag": "plain_text", "content": "刷新"},
					"type":  "default",
					"size":  "small",
					"value": map[string]any{"action": "load_more", "page": 0},
				},
			},
		},
	)

	if hasMore {
		elements = append(elements, map[string]any{
			"tag": "action",
			"actions": []any{
				map[string]any{
					"tag":  "button",
					"text": map[string]any{"tag": "plain_text", "content": "加载更多"},
					"type": "default",
					"value": map[string]any{
						"action": "load_more",
						"page":   page + 1,
					},
				},
			},
		})
	}

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": "项目管理",
			},
			"template": "blue",
		},
		"elements": elements,
	}
}

func (h *FeishuHandler) buildProjectFormCard(userID string, page int, mode string) map[string]any {
	title := "新建项目"
	submitAction := "create"
	if mode == "bind" {
		title = "绑定目录"
		submitAction = "bind"
	}

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": title,
			},
			"template": "blue",
		},
		"elements": []any{
			map[string]any{
				"tag": "div",
				"text": map[string]any{
					"tag":     "lark_md",
					"content": "**" + title + "**",
				},
			},
			map[string]any{
				"tag":  "form",
				"name": "project_form",
				"elements": []any{
					map[string]any{
						"tag":            "input",
						"name":           "project_name",
						"placeholder":    map[string]any{"tag": "plain_text", "content": "项目名（可选）"},
						"label":          map[string]any{"tag": "plain_text", "content": "项目名"},
						"label_position": "left",
					},
					map[string]any{
						"tag":            "input",
						"name":           "project_cwd",
						"placeholder":    map[string]any{"tag": "plain_text", "content": "目录路径（必填）"},
						"label":          map[string]any{"tag": "plain_text", "content": "目录路径"},
						"label_position": "left",
					},
					map[string]any{
						"tag":         "button",
						"name":        "form_submit",
						"action_type": "form_submit",
						"text":        map[string]any{"tag": "plain_text", "content": "提交"},
						"type":        "primary",
						"value":       map[string]any{"action": submitAction, "page": page},
					},
					map[string]any{
						"tag":   "button",
						"name":  "form_back",
						"text":  map[string]any{"tag": "plain_text", "content": "返回"},
						"type":  "default",
						"value": map[string]any{"action": "load_more", "page": page},
					},
				},
			},
		},
	}
}

func (h *FeishuHandler) sendMessage(receiveType string, payload map[string]any) error {
	receiveID, _ := payload["receive_id"].(string)
	msgType, _ := payload["msg_type"].(string)
	content, _ := payload["content"].(string)
	if receiveID == "" || msgType == "" {
		return errInternal
	}
	req := larkim.NewCreateMessageReqBuilder().
		ReceiveIdType(receiveType).
		Body(larkim.NewCreateMessageReqBodyBuilder().
			ReceiveId(receiveID).
			MsgType(msgType).
			Content(content).
			Build()).
		Build()
	resp, err := h.sdk.Im.V1.Message.Create(context.Background(), req)
	if err != nil {
		return err
	}
	if !resp.Success() {
		log.Printf("[feishu] send error code=%v msg=%v req=%v", resp.Code, resp.Msg, resp.RequestId())
	}
	return nil
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		if n, err := strconvAtoiSafe(t); err == nil {
			return n
		}
	}
	return 0
}

func int64FromAny(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case string:
		if n, err := strconvAtoiSafe(t); err == nil {
			return int64(n)
		}
	}
	return 0
}

func strFromAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
