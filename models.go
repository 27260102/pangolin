package main

type ThreadConfig struct {
	Model           string   `json:"model,omitempty"`
	System          string   `json:"system,omitempty"`
	Cwd             string   `json:"cwd,omitempty"`
	Tools           string   `json:"tools,omitempty"`
	PermissionMode  string   `json:"permissionMode,omitempty"`
	AllowedTools    []string `json:"allowedTools,omitempty"`
	DisallowedTools []string `json:"disallowedTools,omitempty"`
	AddDirs         []string `json:"addDirs,omitempty"`
}

type ThreadInfo struct {
	ID        string `json:"id"`
	Preview   string `json:"preview"`
	Model     string `json:"model"`
	CreatedAt int64  `json:"createdAt"`
}

type ThreadListResponse struct {
	Data       []ThreadInfo `json:"data"`
	NextCursor *string      `json:"nextCursor"`
}

type MessageRequest struct {
	Message string `json:"message"`
	Model   string `json:"model,omitempty"`
}
