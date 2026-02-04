package main

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

var errProcessNotStarted = errors.New("process not started")

// Session state

type Session struct {
	Config             ThreadConfig
	CreatedAt          int64
	Preview            string
	PermissionMode     string
	BasePermissionMode string
	AutoAllowTools     map[string]struct{}
	PendingApproval    map[string]any
	LastUserMessage    string
}

type SessionManager struct {
	mu        sync.Mutex
	sessions  map[string]*Session
	processes map[string]*ClaudeProcessManager
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:  map[string]*Session{},
		processes: map[string]*ClaudeProcessManager{},
	}
}

func (m *SessionManager) CreateThread(cfg ThreadConfig) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	threadID := uuid.New().String()
	pm := NewClaudeProcessManager(threadID, cfg)
	if err := pm.Start(false); err != nil {
		return nil, err
	}

	perm := cfg.PermissionMode
	if perm == "" {
		perm = "acceptEdits"
	}

	s := &Session{
		Config:             cfg,
		CreatedAt:          time.Now().Unix(),
		Preview:            "",
		PermissionMode:     perm,
		BasePermissionMode: perm,
		AutoAllowTools:     map[string]struct{}{},
		PendingApproval:    nil,
		LastUserMessage:    "",
	}

	m.sessions[threadID] = s
	m.processes[threadID] = pm

	return map[string]any{
		"thread": map[string]any{
			"id":        threadID,
			"preview":   "",
			"model":     cfg.Model,
			"createdAt": s.CreatedAt,
		},
	}, nil
}

func (m *SessionManager) GetThread(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *SessionManager) GetProcess(id string) (*ClaudeProcessManager, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.processes[id]
	return p, ok
}

func (m *SessionManager) ListThreads(cursor *string, limit int) ThreadListResponse {
	m.mu.Lock()
	defer m.mu.Unlock()
	threads := make([]ThreadInfo, 0, len(m.sessions))
	for id, s := range m.sessions {
		model := s.Config.Model
		if model == "" {
			model = "opus"
		}
		threads = append(threads, ThreadInfo{ID: id, Preview: s.Preview, Model: model, CreatedAt: s.CreatedAt})
	}
	// simple sort by CreatedAt desc
	for i := 0; i < len(threads); i++ {
		for j := i + 1; j < len(threads); j++ {
			if threads[j].CreatedAt > threads[i].CreatedAt {
				threads[i], threads[j] = threads[j], threads[i]
			}
		}
	}

	start := 0
	if cursor != nil {
		if v, err := strconvAtoiSafe(*cursor); err == nil {
			start = v
		}
	}
	end := start + limit
	if end > len(threads) {
		end = len(threads)
	}
	page := threads[start:end]
	var next *string
	if end < len(threads) {
		n := intToString(end)
		next = &n
	}
	return ThreadListResponse{Data: page, NextCursor: next}
}

func (m *SessionManager) ResumeThread(id string) (map[string]any, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return nil, errNotFound
	}
	if p, ok := m.GetProcess(id); ok && p.initialized {
		return map[string]any{"thread": map[string]any{"id": id, "preview": s.Preview, "model": s.Config.Model, "createdAt": s.CreatedAt}}, nil
	}

	pm := NewClaudeProcessManager(id, s.Config)
	if err := pm.Start(true); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.processes[id] = pm
	m.mu.Unlock()

	return map[string]any{"thread": map[string]any{"id": id, "preview": s.Preview, "model": s.Config.Model, "createdAt": s.CreatedAt}}, nil
}

func (m *SessionManager) ResumeThreadWithConfig(id string, cfg ThreadConfig) (map[string]any, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if ok {
		return m.ResumeThread(id)
	}

	pm := NewClaudeProcessManager(id, cfg)
	if err := pm.Start(true); err != nil {
		return nil, err
	}

	perm := cfg.PermissionMode
	if perm == "" {
		perm = "acceptEdits"
	}
	s = &Session{
		Config:             cfg,
		CreatedAt:          time.Now().Unix(),
		Preview:            "",
		PermissionMode:     perm,
		BasePermissionMode: perm,
		AutoAllowTools:     map[string]struct{}{},
		PendingApproval:    nil,
		LastUserMessage:    "",
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.processes[id] = pm
	m.mu.Unlock()

	return map[string]any{"thread": map[string]any{"id": id, "preview": s.Preview, "model": s.Config.Model, "createdAt": s.CreatedAt}}, nil
}

func (m *SessionManager) ArchiveThread(id string) error {
	m.mu.Lock()
	p, ok := m.processes[id]
	if ok {
		delete(m.processes, id)
	}
	delete(m.sessions, id)
	m.mu.Unlock()

	if ok {
		p.Stop()
	}
	return nil
}

func (m *SessionManager) RestartThread(id, permissionMode string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return errNotFound
	}

	cfg := s.Config
	cfg.PermissionMode = permissionMode

	if p, ok := m.GetProcess(id); ok {
		p.Stop()
		m.mu.Lock()
		delete(m.processes, id)
		m.mu.Unlock()
	}

	pm := NewClaudeProcessManager(id, cfg)
	if err := pm.Start(true); err != nil {
		return err
	}

	m.mu.Lock()
	m.processes[id] = pm
	m.sessions[id].PermissionMode = permissionMode
	m.mu.Unlock()
	return nil
}

func (m *SessionManager) SendMessage(id, message string) (map[string]any, error) {
	p, ok := m.GetProcess(id)
	if !ok {
		return nil, errNotFound
	}
	s, _ := m.GetThread(id)
	if s.Preview == "" {
		s.Preview = truncate(message, 50)
	}

	ch := p.SubscribeEvents("*")
	defer p.UnsubscribeEvents("*", ch)

	if err := p.SendMessage(message); err != nil {
		return nil, err
	}

	respText := ""
	deadline := time.After(300 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev["method"] == "item/agentMessage/delta" {
				params, _ := ev["params"].(map[string]any)
				if delta, ok := params["delta"].(string); ok {
					respText += delta
				}
			}
			if ev["method"] == "turn/completed" {
				params, _ := ev["params"].(map[string]any)
				return map[string]any{
					"response": respText,
					"usage":    params["usage"],
					"cost_usd": params["cost_usd"],
				}, nil
			}
			if ev["method"] == "error" {
				return nil, errInternal
			}
		case <-deadline:
			return nil, errTimeout
		}
	}
}

func (m *SessionManager) SendMessageStream(id, message string, writer func(string) error) error {
	p, ok := m.GetProcess(id)
	if !ok {
		return errNotFound
	}
	s, _ := m.GetThread(id)
	if s.Preview == "" {
		s.Preview = truncate(message, 50)
	}

	ch := p.SubscribeEvents("*")
	defer p.UnsubscribeEvents("*", ch)

	if err := p.SendMessage(message); err != nil {
		return err
	}

	deadline := time.After(300 * time.Second)
	for {
		select {
		case ev := <-ch:
			b, _ := json.Marshal(ev)
			if err := writer(string(b)); err != nil {
				return err
			}
			if ev["method"] == "turn/completed" || ev["method"] == "error" {
				return nil
			}
		case <-deadline:
			_ = writer(`{"method":"error","params":{"error":"timeout"}}`)
			return nil
		}
	}
}
