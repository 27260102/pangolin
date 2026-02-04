package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (h *FeishuHandler) getModelOptions() []string {
	h.modelMu.Lock()
	if time.Since(h.modelCacheAt) < 5*time.Minute && len(h.modelCache) > 0 {
		out := append([]string{}, h.modelCache...)
		h.modelMu.Unlock()
		return out
	}
	h.modelMu.Unlock()

	models := collectClaudeModels(200, 200)

	h.modelMu.Lock()
	h.modelCache = append([]string{}, models...)
	h.modelCacheAt = time.Now()
	h.modelMu.Unlock()
	return models
}

func collectClaudeModels(maxFiles, maxLines int) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	root := filepath.Join(home, ".claude", "projects")
	stat, err := os.Stat(root)
	if err != nil || !stat.IsDir() {
		return nil
	}

	seen := map[string]struct{}{}
	out := []string{}
	filesVisited := 0

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filesVisited >= maxFiles {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(path, ".jsonl") && !strings.HasSuffix(path, "sessions-index.json") {
			return nil
		}
		filesVisited++

		file, err := os.Open(path)
		if err != nil {
			return nil
		}

		scanner := bufio.NewScanner(file)
		lines := 0
		for scanner.Scan() {
			lines++
			if lines > maxLines {
				break
			}
			line := scanner.Text()
			for _, m := range extractModelsFromLine(line) {
				if _, ok := seen[m]; ok {
					continue
				}
				seen[m] = struct{}{}
				out = append(out, m)
			}
		}
		_ = file.Close()
		return nil
	})

	return out
}

func extractModelsFromLine(line string) []string {
	out := []string{}
	for {
		idx := strings.Index(line, `"model":`)
		if idx == -1 {
			break
		}
		line = line[idx+len(`"model":`):]
		line = strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		line = line[1:]
		end := strings.IndexByte(line, '"')
		if end == -1 {
			continue
		}
		model := line[:end]
		line = line[end+1:]
		if model == "" || model == "<synthetic>" {
			continue
		}
		out = append(out, model)
	}
	return out
}
