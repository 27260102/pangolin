package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os/exec"
	"sync"
)

type ClaudeProcessManager struct {
	sessionID string
	config    ThreadConfig
	cmd       *exec.Cmd
	stdin     *bufio.Writer
	stdout    *bufio.Reader
	stderr    *bufio.Reader

	lock           sync.Mutex
	eventHandlers  map[string][]chan map[string]any
	initialized    bool
	fullResponse   string
	sawStreamDelta bool
}

func NewClaudeProcessManager(sessionID string, cfg ThreadConfig) *ClaudeProcessManager {
	return &ClaudeProcessManager{
		sessionID:     sessionID,
		config:        cfg,
		eventHandlers: map[string][]chan map[string]any{},
	}
}

func (p *ClaudeProcessManager) Start(resume bool) error {
	if p.cmd != nil {
		log.Printf("Process already running for session %s", p.sessionID)
		return nil
	}

	args := []string{
		"--print",
		"--verbose",
		"--input-format=stream-json",
		"--output-format=stream-json",
		"--include-partial-messages",
		"--strict-mcp-config",
	}

	if resume {
		args = append(args, "--resume="+p.sessionID)
	} else {
		args = append(args, "--session-id="+p.sessionID)
	}

	if p.config.Model != "" {
		args = append(args, "--model="+p.config.Model)
	}
	if p.config.System != "" {
		args = append(args, "--system-prompt="+p.config.System)
	}
	if p.config.Tools != "" {
		args = append(args, "--tools="+p.config.Tools)
	}
	permMode := p.config.PermissionMode
	if permMode == "" {
		permMode = "default"
	}
	args = append(args, "--permission-mode="+permMode)

	if len(p.config.AllowedTools) > 0 {
		for _, t := range p.config.AllowedTools {
			args = append(args, "--allowed-tools="+t)
		}
	}
	if len(p.config.DisallowedTools) > 0 {
		for _, t := range p.config.DisallowedTools {
			args = append(args, "--disallowed-tools="+t)
		}
	}
	if len(p.config.AddDirs) > 0 {
		for _, d := range p.config.AddDirs {
			args = append(args, "--add-dir="+d)
		}
	}
	if p.config.Cwd != "" {
		args = append(args, "--add-dir="+p.config.Cwd)
	}

	log.Printf("Command: claude %s", stringJoin(args, " "))

	cmd := exec.Command("claude", args...)
	if p.config.Cwd != "" {
		cmd.Dir = p.config.Cwd
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	p.cmd = cmd
	p.stdin = bufio.NewWriter(stdinPipe)
	p.stdout = bufio.NewReader(stdoutPipe)
	p.stderr = bufio.NewReader(stderrPipe)
	p.initialized = true

	go p.readStdout()
	go p.readStderr()

	log.Printf("Claude process started for session %s", p.sessionID)
	return nil
}

func (p *ClaudeProcessManager) Stop() {
	if p.cmd != nil {
		log.Printf("Stopping claude process for session %s", p.sessionID)
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
		p.cmd = nil
		p.initialized = false
	}
}

func (p *ClaudeProcessManager) readStdout() {
	for {
		line, err := p.stdout.ReadString('\n')
		if err != nil {
			return
		}
		line = trimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			log.Printf("Failed to parse JSON line: %s", line)
			continue
		}
		p.handleEvent(event)
	}
}

func (p *ClaudeProcessManager) readStderr() {
	for {
		line, err := p.stderr.ReadString('\n')
		if err != nil {
			return
		}
		line = trimSpace(line)
		if line != "" {
			log.Printf("[claude stderr] %s", line)
		}
	}
}

func (p *ClaudeProcessManager) handleEvent(event map[string]any) {
	eventType, _ := event["type"].(string)
	if eventType != "stream_event" {
		log.Printf("Received event: %s", eventType)
	}

	switch eventType {
	case "system":
		subtype, _ := event["subtype"].(string)
		if subtype == "init" {
			normalized := map[string]any{
				"method": "system/init",
				"params": map[string]any{
					"session_id": event["session_id"],
					"model":      event["model"],
					"tools":      event["tools"],
				},
			}
			p.dispatch("*", normalized)
		}
	case "stream_event":
		inner, _ := event["event"].(map[string]any)
		innerType, _ := inner["type"].(string)
		switch innerType {
		case "content_block_delta":
			delta, _ := inner["delta"].(map[string]any)
			deltaType, _ := delta["type"].(string)
			if deltaType == "text_delta" {
				text, _ := delta["text"].(string)
				if text != "" {
					p.sawStreamDelta = true
					p.fullResponse += text
					normalized := map[string]any{
						"method": "item/agentMessage/delta",
						"params": map[string]any{"delta": text},
					}
					p.dispatch("*", normalized)
				}
			}
		case "content_block_start":
			contentBlock, _ := inner["content_block"].(map[string]any)
			if t, _ := contentBlock["type"].(string); t == "tool_use" {
				normalized := map[string]any{
					"method": "tool/start",
					"params": map[string]any{
						"tool":  contentBlock["name"],
						"id":    contentBlock["id"],
						"input": contentBlock["input"],
					},
				}
				p.dispatch("*", normalized)
			}
		}
	case "assistant":
		message, _ := event["message"].(map[string]any)
		content, _ := message["content"].([]any)
		for _, item := range content {
			block, _ := item.(map[string]any)
			switch block["type"] {
			case "text":
				text, _ := block["text"].(string)
				if text != "" && !p.sawStreamDelta && text != p.fullResponse {
					p.fullResponse = text
					normalized := map[string]any{
						"method": "item/agentMessage/delta",
						"params": map[string]any{"delta": text},
					}
					p.dispatch("*", normalized)
				}
			case "tool_use":
				normalized := map[string]any{
					"method": "tool/executing",
					"params": map[string]any{
						"tool":  block["name"],
						"id":    block["id"],
						"input": block["input"],
					},
				}
				p.dispatch("*", normalized)
			case "tool_result":
				normalized := map[string]any{
					"method": "tool/result",
					"params": map[string]any{
						"tool_use_id": block["tool_use_id"],
						"content":     block["content"],
					},
				}
				p.dispatch("*", normalized)
			}
		}
	case "result":
		if v, ok := event["result"].(string); ok {
			p.fullResponse = v
		}
		normalized := map[string]any{
			"method": "turn/completed",
			"params": map[string]any{
				"result":   p.fullResponse,
				"usage":    event["usage"],
				"cost_usd": event["total_cost_usd"],
				"is_error": event["is_error"],
			},
		}
		p.dispatch("*", normalized)
	case "error":
		normalized := map[string]any{
			"method": "error",
			"params": map[string]any{"error": event["message"]},
		}
		p.dispatch("*", normalized)
	}
}

func (p *ClaudeProcessManager) dispatch(eventType string, event map[string]any) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if handlers, ok := p.eventHandlers[eventType]; ok {
		for _, ch := range handlers {
			select {
			case ch <- event:
			default:
			}
		}
	}
}

func (p *ClaudeProcessManager) SendMessage(message string) error {
	if p.cmd == nil || !p.initialized {
		return errProcessNotStarted
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.fullResponse = ""
	p.sawStreamDelta = false
	input := map[string]any{
		"type":    "user",
		"message": map[string]any{"role": "user", "content": message},
	}
	b, _ := json.Marshal(input)
	_, err := p.stdin.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	return p.stdin.Flush()
}

func (p *ClaudeProcessManager) SubscribeEvents(eventType string) chan map[string]any {
	p.lock.Lock()
	defer p.lock.Unlock()
	ch := make(chan map[string]any, 100)
	p.eventHandlers[eventType] = append(p.eventHandlers[eventType], ch)
	return ch
}

func (p *ClaudeProcessManager) UnsubscribeEvents(eventType string, ch chan map[string]any) {
	p.lock.Lock()
	defer p.lock.Unlock()
	arr := p.eventHandlers[eventType]
	for i, c := range arr {
		if c == ch {
			p.eventHandlers[eventType] = append(arr[:i], arr[i+1:]...)
			close(c)
			break
		}
	}
}
