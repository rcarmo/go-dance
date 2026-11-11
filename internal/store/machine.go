package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/rcarmo/dance/internal/enrollment"
)

type MachineStore interface {
	AuthenticateMachine(context.Context, string) (*enrollment.Principal, error)
}

// MintMachine is operator-only. The caller must deliver token through a private
// channel; only its digest and public grants are persisted in SQLite.
func (s *SQLiteStore) MintMachine(ctx context.Context, p enrollment.Principal) (string, error) {
	id := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	p.ID = hex.EncodeToString(id)
	if err := p.Validate(); err != nil {
		return "", err
	}
	if !p.ExpiresAt.After(time.Now()) {
		return "", enrollment.E("invalid_request")
	}
	token := "dance_" + p.ID + "." + hex.EncodeToString(secret)
	digest := sha256.Sum256([]byte(token))
	data, _ := json.Marshal(p)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO machine_credentials(id,digest,principal_json,created_at) VALUES(?,?,?,?)`, p.ID, digest[:], string(data), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(action,actor,remote_ip,user_agent,created_at) VALUES('machine_granted',?,'','',?)`, p.ID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}
func (s *SQLiteStore) AuthenticateMachine(ctx context.Context, token string) (*enrollment.Principal, error) {
	if len(token) != 103 || !strings.HasPrefix(token, "dance_") || token[38] != '.' {
		return nil, nil
	}
	id := token[6:38]
	var digest []byte
	var data string
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT digest,principal_json,revoked FROM machine_credentials WHERE id=?`, id).Scan(&digest, &data, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, enrollment.E("backend_unavailable")
	}
	got := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(got[:], digest) != 1 || revoked != 0 {
		return nil, nil
	}
	var p enrollment.Principal
	if json.Unmarshal([]byte(data), &p) != nil {
		return nil, enrollment.E("backend_unavailable")
	}
	if !p.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	return &p, nil
}
func (s *SQLiteStore) RevokeMachine(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE machine_credentials SET revoked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return enrollment.E("not_found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_log(action,actor,remote_ip,user_agent,created_at) VALUES('machine_revoked',?,'','',?)`, id, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

// ProjectMachineAudit makes retries/restarts of the CA audit outbox harmless.
func (s *SQLiteStore) ProjectMachineAudit(ctx context.Context, id string, ev AuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO machine_audit_receipts(event_id) VALUES(?)`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(action,actor,remote_ip,user_agent,created_at) VALUES(?,?,'','',?)`, ev.Action, ev.Actor, ev.CreatedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}
