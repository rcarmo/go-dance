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
