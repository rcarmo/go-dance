package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSQLiteAdminBootstrapAndAuth(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "dance.sqlite")
	st, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureAdmin(ctx, "admin@example.com", "secret"); err != nil {
		t.Fatal(err)
	}
	user, err := st.AuthenticateUser(ctx, "admin@example.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || !user.IsAdmin {
		t.Fatal("expected admin user")
	}
}

func TestSQLiteAuditList(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "dance.sqlite")
	st, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, AuditEvent{Action: "login", Actor: "admin@example.com", RemoteIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, AuditEvent{Action: "revoke_certificate", Actor: "admin@example.com", RemoteIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	events, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Action != "revoke_certificate" {
		t.Fatalf("got newest action %q", events[0].Action)
	}
}
