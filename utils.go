package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func ParseAllowedTools(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func SplitTextByBytes(text string, maxBytes int) []string {
	if text == "" {
		return []string{}
	}
	chunks := []string{}
	buf := strings.Builder{}
	size := 0
	for _, ch := range text {
		b := []byte(string(ch))
		if size+len(b) > maxBytes && buf.Len() > 0 {
			chunks = append(chunks, buf.String())
			buf.Reset()
			size = 0
		}
		buf.WriteRune(ch)
		size += len(b)
	}
	if buf.Len() > 0 {
		chunks = append(chunks, buf.String())
	}
	return chunks
}

func ParseBashRule(rule string) (string, bool) {
	if !strings.HasPrefix(rule, "Bash(") || !strings.HasSuffix(rule, ")") {
		return "", false
	}
	inner := strings.TrimSpace(rule[len("Bash(") : len(rule)-1])
	if inner == "" {
		return "", false
	}
	return inner, true
}

func MatchBashRule(command, rule string) bool {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return false
	}
	var head, tail string
	if strings.Contains(rule, ":") {
		parts := strings.SplitN(rule, ":", 2)
		head = strings.TrimSpace(parts[0])
		tail = strings.TrimSpace(parts[1])
	} else {
		head = strings.TrimSpace(rule)
		tail = ""
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	if head != "" && fields[0] != head {
		return false
	}
	if tail == "" || tail == "*" {
		return true
	}
	if len(fields) < 2 {
		return false
	}
	return fields[1] == tail
}

func ToolAutoAllowed(toolName string, toolInput map[string]any, autoAllow map[string]struct{}) bool {
	if _, ok := autoAllow[toolName]; ok {
		return true
	}
	if toolName == "Bash" {
		cmd := ""
		if toolInput != nil {
			if v, ok := toolInput["command"].(string); ok {
				cmd = v
			}
		}
		for rule := range autoAllow {
			if parsed, ok := ParseBashRule(rule); ok {
				if MatchBashRule(cmd, parsed) {
					return true
				}
			}
		}
	}
	return false
}

func GetSenderID(event map[string]any) string {
	sender, _ := event["sender"].(map[string]any)
	senderID, _ := sender["sender_id"].(map[string]any)
	if v, ok := senderID["user_id"].(string); ok && v != "" {
		return v
	}
	if v, ok := senderID["open_id"].(string); ok {
		return v
	}
	return ""
}

func VerifyFeishuSignature(rawBody []byte, timestamp, nonce, signature, encryptKey string) bool {
	if encryptKey == "" {
		return true
	}
	if timestamp == "" || nonce == "" || signature == "" {
		return false
	}
	seed := []byte(timestamp + nonce + encryptKey)
	payload := append(seed, rawBody...)
	hash := sha256.Sum256(payload)
	calc := hex.EncodeToString(hash[:])
	return calc == signature
}
