package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  remote_ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);
`)
	if err != nil {
		return fmt.Errorf("ensure schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) EnsureAdmin(ctx context.Context, email, password string) error {
	if email == "" || password == "" {
		return nil
	}
	var existing int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE email = ?`, email).Scan(&existing); err != nil {
		return fmt.Errorf("check admin: %w", err)
	}
	if existing > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO users(email, password_hash, is_admin, created_at)
VALUES(?, ?, 1, ?)
`, email, string(hash), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("insert admin: %w", err)
	}
	return nil
}

func (s *SQLiteStore) AuthenticateUser(ctx context.Context, email, password string) (*User, error) {
	user := &User{}
	var isAdmin int
	err := s.db.QueryRowContext(ctx, `
SELECT id, email, password_hash, is_admin
FROM users
WHERE email = ?
`, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("query user: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return nil, nil
	}
	user.IsAdmin = isAdmin == 1
	_, _ = s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), user.ID)
	return user, nil
}

func (s *SQLiteStore) GetUserByID(ctx context.Context, id int64) (*User, error) {
	user := &User{}
	var isAdmin int
	err := s.db.QueryRowContext(ctx, `
SELECT id, email, password_hash, is_admin
FROM users
WHERE id = ?
`, id).Scan(&user.ID, &user.Email, &user.PasswordHash, &isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	user.IsAdmin = isAdmin == 1
	return user, nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, email, password_hash, is_admin FROM users ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var isAdmin int
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &isAdmin); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.IsAdmin = isAdmin == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) AppendAudit(ctx context.Context, ev AuditEvent) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log(action, actor, remote_ip, user_agent, created_at)
VALUES(?, ?, ?, ?, ?)
`, ev.Action, ev.Actor, ev.RemoteIP, ev.UserAgent, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}
