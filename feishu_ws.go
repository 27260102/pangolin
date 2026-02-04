package main

import (
	"context"
	"log"

	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"
	larkapplication "github.com/larksuite/oapi-sdk-go/v3/service/application/v6"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkws "github.com/larksuite/oapi-sdk-go/v3/ws"
)

func (h *FeishuHandler) StartFeishuWS(ctx context.Context) error {
	eventHandler := dispatcher.NewEventDispatcher(h.cfg.FeishuVerificationToken, h.cfg.FeishuEncryptKey).
		OnP2MessageReceiveV1(func(ctx context.Context, event *larkim.P2MessageReceiveV1) error {
			h.handleMessageEventV2(event)
			return nil
		}).
		OnP2BotMenuV6(func(ctx context.Context, event *larkapplication.P2BotMenuV6) error {
			h.handleMenuEventV2(event)
			return nil
		}).
		OnP2CardActionTrigger(func(ctx context.Context, event *callback.CardActionTriggerEvent) (*callback.CardActionTriggerResponse, error) {
			return h.handleCardActionWS(event)
		})

	cli := larkws.NewClient(h.cfg.FeishuAppID, h.cfg.FeishuAppSecret,
		larkws.WithEventHandler(eventHandler),
		larkws.WithLogLevel(larkcore.LogLevelInfo),
	)
	log.Printf("[feishu] websocket connecting...")
	return cli.Start(ctx)
}

func (h *FeishuHandler) handleMessageEventV2(event *larkim.P2MessageReceiveV1) {
	if event == nil || event.Event == nil || event.Event.Message == nil {
		return
	}
	if event.EventV2Base != nil && event.EventV2Base.Header != nil && h.isDuplicate(event.EventV2Base.Header.EventID) {
		return
	}
	senderType := ""
	if event.Event.Sender != nil {
		senderType = strPtr(event.Event.Sender.SenderType)
	}
	if senderType != "" && senderType != "user" {
		return
	}
	messageID := strPtr(event.Event.Message.MessageId)
	chatID := strPtr(event.Event.Message.ChatId)
	content := strPtr(event.Event.Message.Content)
	senderID := senderIDFromP2(event.Event.Sender)
	h.handleIncomingMessage(messageID, chatID, content, senderID)
}

func (h *FeishuHandler) handleMenuEventV2(event *larkapplication.P2BotMenuV6) {
	if event == nil || event.Event == nil {
		return
	}
	if event.EventV2Base != nil && event.EventV2Base.Header != nil && h.isDuplicate(event.EventV2Base.Header.EventID) {
		return
	}
	eventKey := strPtr(event.Event.EventKey)
	userID, openID := userIDFromMenu(event.Event.Operator)
	log.Printf("[feishu] menu event_key=%s user_id=%s open_id=%s", eventKey, userID, openID)
	h.handleMenuEventKey(userID, openID, eventKey)
}

func (h *FeishuHandler) handleCardActionWS(event *callback.CardActionTriggerEvent) (*callback.CardActionTriggerResponse, error) {
	if event == nil || event.Event == nil {
		return &callback.CardActionTriggerResponse{
			Toast: &callback.Toast{Type: "error", Content: "缺少回调信息"},
		}, nil
	}
	token := event.Event.Token
	userID, openID := userIDFromCard(event.Event.Operator)
	if userID == "" {
		userID = openID
	}
	chatID := ""
	if event.Event.Context != nil {
		chatID = event.Event.Context.OpenChatID
	}
	var value map[string]any
	var form map[string]any
	if event.Event.Action != nil {
		value = event.Event.Action.Value
		form = event.Event.Action.FormValue
	}
	respMap := h.handleCardAction("card.action.trigger", token, userID, chatID, value, form)
	return cardRespFromMap(respMap), nil
}

func cardRespFromMap(resp map[string]any) *callback.CardActionTriggerResponse {
	if resp == nil {
		return nil
	}
	out := &callback.CardActionTriggerResponse{}
	if toastRaw, ok := resp["toast"].(map[string]any); ok {
		toast := &callback.Toast{}
		if v, ok := toastRaw["type"].(string); ok {
			toast.Type = v
		}
		if v, ok := toastRaw["content"].(string); ok {
			toast.Content = v
		}
		out.Toast = toast
	}
	if cardRaw, ok := resp["card"].(map[string]any); ok {
		card := &callback.Card{}
		if v, ok := cardRaw["type"].(string); ok {
			card.Type = v
		}
		if v, ok := cardRaw["data"]; ok {
			card.Data = v
		}
		if card.Type == "" {
			card.Type = "raw"
			card.Data = cardRaw
		}
		out.Card = card
	}
	return out
}

func senderIDFromP2(sender *larkim.EventSender) string {
	if sender == nil || sender.SenderId == nil {
		return ""
	}
	if sender.SenderId.UserId != nil && *sender.SenderId.UserId != "" {
		return *sender.SenderId.UserId
	}
	if sender.SenderId.OpenId != nil {
		return *sender.SenderId.OpenId
	}
	return ""
}

func userIDFromMenu(op *larkapplication.Operator) (string, string) {
	if op == nil || op.OperatorId == nil {
		return "", ""
	}
	userID := ""
	openID := ""
	if op.OperatorId.UserId != nil {
		userID = *op.OperatorId.UserId
	}
	if op.OperatorId.OpenId != nil {
		openID = *op.OperatorId.OpenId
	}
	return userID, openID
}

func userIDFromCard(op *callback.Operator) (string, string) {
	if op == nil {
		return "", ""
	}
	userID := ""
	openID := op.OpenID
	if op.UserID != nil {
		userID = *op.UserID
	}
	return userID, openID
}

func strPtr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
