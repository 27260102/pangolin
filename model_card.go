package main

import "strings"

func (h *FeishuHandler) sendModelCard(chatID string, card map[string]any) error {
	if chatID == "" {
		return nil
	}
	payload := map[string]any{
		"receive_id": chatID,
		"msg_type":   "interactive",
		"content":    mustJSON(card),
	}
	return h.sendMessage("chat_id", payload)
}

func (h *FeishuHandler) buildModelCard(current string, models []string) map[string]any {
	current = strings.TrimSpace(current)
	if current == "" {
		current = "default"
	}
	models = dedupeModels(append([]string{current}, models...))

	elements := []any{
		map[string]any{
			"tag": "div",
			"text": map[string]any{
				"tag":     "lark_md",
				"content": "**当前模型**：" + current,
			},
		},
	}

	const perRow = 2
	for i := 0; i < len(models); i += perRow {
		end := i + perRow
		if end > len(models) {
			end = len(models)
		}
		buttons := []any{}
		for _, m := range models[i:end] {
			btnType := "default"
			if m == current {
				btnType = "primary"
			}
			buttons = append(buttons, map[string]any{
				"tag": "button",
				"text": map[string]any{
					"tag":     "plain_text",
					"content": m,
				},
				"type":  btnType,
				"value": map[string]any{"action": "set_model", "model": m},
			})
		}
		elements = append(elements, map[string]any{
			"tag":     "action",
			"actions": buttons,
		})
	}

	return map[string]any{
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": "模型选择",
			},
		},
		"elements": elements,
	}
}

func dedupeModels(models []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, m := range models {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}
