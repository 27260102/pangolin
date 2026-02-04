package main

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	FeishuAppID             string
	FeishuAppSecret         string
	FeishuVerificationToken string
	FeishuEncryptKey        string
	FeishuAPIBase           string

	FeishuStreamMode     string
	FeishuStreamInterval float64
	FeishuStreamMinChars int
	FeishuTextMaxBytes   int

	FeishuMenuAcceptKey    string
	FeishuMenuAcceptAllKey string
	FeishuMenuRejectKey    string
	FeishuMenuProjectsKey  string

	AutoAllowTools string
	ProjectDBPath  string
}

func LoadConfig() Config {
	return Config{
		FeishuAppID:             strings.TrimSpace(os.Getenv("FEISHU_APP_ID")),
		FeishuAppSecret:         strings.TrimSpace(os.Getenv("FEISHU_APP_SECRET")),
		FeishuVerificationToken: strings.TrimSpace(os.Getenv("FEISHU_VERIFICATION_TOKEN")),
		FeishuEncryptKey:        strings.TrimSpace(os.Getenv("FEISHU_ENCRYPT_KEY")),
		FeishuAPIBase:           envDefault("FEISHU_API_BASE", "https://open.feishu.cn/open-apis"),

		FeishuStreamMode:     strings.ToLower(envDefault("FEISHU_STREAM_MODE", "merge")),
		FeishuStreamInterval: envFloat("FEISHU_STREAM_INTERVAL", 1.2),
		FeishuStreamMinChars: envInt("FEISHU_STREAM_MIN_CHARS", 120),
		FeishuTextMaxBytes:   envInt("FEISHU_TEXT_MAX_BYTES", 150*1024),

		FeishuMenuAcceptKey:    strings.TrimSpace(os.Getenv("FEISHU_MENU_ACCEPT_KEY")),
		FeishuMenuAcceptAllKey: strings.TrimSpace(os.Getenv("FEISHU_MENU_ACCEPT_ALL_KEY")),
		FeishuMenuRejectKey:    strings.TrimSpace(os.Getenv("FEISHU_MENU_REJECT_KEY")),
		FeishuMenuProjectsKey:  strings.TrimSpace(os.Getenv("FEISHU_MENU_PROJECTS_KEY")),

		AutoAllowTools: envDefault("AUTO_ALLOW_TOOLS",
			"Read;Search;List;Glob;Bash(ls:*);Bash(pwd);Bash(cat:*);Bash(head:*);Bash(tail:*);Bash(wc:*);Bash(stat:*);Bash(git:status,git:diff)"),
		ProjectDBPath: envDefault("PROJECT_DB_PATH", "./projects.db"),
	}
}

func envDefault(key, def string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	return val
}

func envInt(key string, def int) int {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return def
	}
	n, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return def
	}
	return n
}
