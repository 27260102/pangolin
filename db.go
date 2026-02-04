package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type Project struct {
	ID        int64
	UserID    string
	Name      string
	Cwd       string
	ThreadID  string
	UpdatedAt int64
}

type ProjectStore struct {
	db *sql.DB
}

func NewProjectStore(path string) (*ProjectStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &ProjectStore{db: db}
	if err := store.initSchema(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *ProjectStore) initSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  cwd TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(user_id, cwd)
);
CREATE INDEX IF NOT EXISTS idx_projects_user_updated ON projects(user_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS chat_threads (
  chat_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
`)
	return err
}

func (s *ProjectStore) UpsertProject(userID, name, cwd, threadID string) (*Project, error) {
	now := time.Now().Unix()
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO projects(user_id,name,cwd,thread_id,updated_at) VALUES(?,?,?,?,?)`, userID, name, cwd, threadID, now)
	_, _ = s.db.Exec(`UPDATE projects SET name=?, thread_id=?, updated_at=? WHERE user_id=? AND cwd=?`, name, threadID, now, userID, cwd)
	return s.GetByCwd(userID, cwd)
}

func (s *ProjectStore) GetByID(userID string, id int64) (*Project, error) {
	row := s.db.QueryRow(`SELECT id,user_id,name,cwd,thread_id,updated_at FROM projects WHERE user_id=? AND id=?`, userID, id)
	p := &Project{}
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.Cwd, &p.ThreadID, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProjectStore) GetByCwd(userID, cwd string) (*Project, error) {
	row := s.db.QueryRow(`SELECT id,user_id,name,cwd,thread_id,updated_at FROM projects WHERE user_id=? AND cwd=?`, userID, cwd)
	p := &Project{}
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.Cwd, &p.ThreadID, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProjectStore) List(userID string, limit, offset int) ([]Project, error) {
	rows, err := s.db.Query(`SELECT id,user_id,name,cwd,thread_id,updated_at FROM projects WHERE user_id=? ORDER BY updated_at DESC LIMIT ? OFFSET ?`, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Cwd, &p.ThreadID, &p.UpdatedAt); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *ProjectStore) Delete(userID string, id int64) error {
	_, err := s.db.Exec(`DELETE FROM projects WHERE user_id=? AND id=?`, userID, id)
	return err
}

func (s *ProjectStore) GetByThreadID(threadID string) (*Project, error) {
	row := s.db.QueryRow(`SELECT id,user_id,name,cwd,thread_id,updated_at FROM projects WHERE thread_id=?`, threadID)
	p := &Project{}
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.Cwd, &p.ThreadID, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProjectStore) UpsertChatThread(chatID, userID, threadID string) error {
	now := time.Now().Unix()
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO chat_threads(chat_id,user_id,thread_id,updated_at) VALUES(?,?,?,?)`, chatID, userID, threadID, now)
	_, err := s.db.Exec(`UPDATE chat_threads SET user_id=?, thread_id=?, updated_at=? WHERE chat_id=?`, userID, threadID, now, chatID)
	return err
}

func (s *ProjectStore) GetChatThread(chatID string) (string, string, error) {
	row := s.db.QueryRow(`SELECT thread_id,user_id FROM chat_threads WHERE chat_id=?`, chatID)
	var threadID, userID string
	if err := row.Scan(&threadID, &userID); err != nil {
		return "", "", err
	}
	return threadID, userID, nil
}
