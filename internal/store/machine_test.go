package store

import (
	"context"
	"github.com/rcarmo/dance/internal/enrollment"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMachineGrantsAuthenticationRevocationAndExpiry(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLite(filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	p := enrollment.Principal{Target: "host-a", Provisioners: []string{"acme/default"}, Operations: []string{"eab:create", "eab:read-own"}, ExpiresAt: time.Now().Add(time.Hour)}
	token, err := s.MintMachine(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := s.AuthenticateMachine(ctx, token)
	if err != nil || principal == nil || principal.Target != "host-a" {
		t.Fatal("valid credential rejected")
	}
	if !principal.Allows("eab:create", "acme/default") || principal.Allows("eab:invalidate-own", "acme/default") || principal.Allows("eab:create", "other") {
		t.Fatal("scope broadened")
	}
	for _, bad := range []string{"", token + "x", "Bearer " + token, strings.Replace(token, "dance_", "other_", 1), token[:len(token)-1] + "z"} {
		if got, _ := s.AuthenticateMachine(ctx, bad); got != nil {
			t.Fatal("invalid credential accepted")
		}
	}
	var data string
	var digest []byte
	if err := s.db.QueryRowContext(ctx, `SELECT principal_json,digest FROM machine_credentials WHERE id=?`, principal.ID).Scan(&data, &digest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, token) || string(digest) == token {
		t.Fatal("plaintext credential persisted")
	}
	if err := s.RevokeMachine(ctx, principal.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.AuthenticateMachine(ctx, token); got != nil {
		t.Fatal("revoked credential accepted")
	}
	p.ExpiresAt = time.Now().Add(-time.Hour)
	if _, err := s.MintMachine(ctx, p); err == nil {
		t.Fatal("expired grant minted")
	}
	p.ExpiresAt = time.Now().Add(time.Hour)
	p.Operations = []string{"admin:*"}
	if _, err := s.MintMachine(ctx, p); err == nil {
		t.Fatal("unscoped privilege minted")
	}
}
