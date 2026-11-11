package main

import (
	"context"
	"github.com/rcarmo/dance/internal/store"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorGrantAndRevokeWithoutBrowserOrSecretStdout(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "app.sqlite")
	st, err := store.NewSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "token")
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = run(context.Background(), []string{"admin", "grant", "-db", db, "-target", "host-a", "-provisioners", "acme/default", "-out", out})
	w.Close()
	os.Stdout = old
	stdout, _ := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stdout), strings.TrimSpace(string(secret))) {
		t.Fatal("operator stdout leaked bearer credential")
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe credential file permissions")
	}
	principal, err := st.AuthenticateMachine(context.Background(), strings.TrimSpace(string(secret)))
	if err != nil || principal == nil {
		t.Fatal("grant not usable")
	}
	if err := run(context.Background(), []string{"admin", "grant", "-db", db, "-target", "host-a", "-provisioners", "acme/default", "-out", out}); err == nil {
		t.Fatal("existing output file overwritten")
	}
	if err := run(context.Background(), []string{"admin", "revoke", "-db", db, "-id", principal.ID}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.AuthenticateMachine(context.Background(), strings.TrimSpace(string(secret))); got != nil {
		t.Fatal("revoked grant usable")
	}
}

func TestCLIRejectsUnknownCommandsWithoutStartingServer(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"serve", "unexpected"}, {"admin", "unknown"}, {"admin", "grant", "-db", "missing.sqlite"}} {
		if err := run(context.Background(), args); err == nil {
			t.Fatalf("accepted invalid command %v", args)
		}
	}
}
