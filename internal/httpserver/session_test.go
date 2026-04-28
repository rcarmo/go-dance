package httpserver

import (
	"encoding/base64"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	sm := newSessionManager("secret")
	token := sm.Sign(42)
	uid, ok := sm.Verify(token)
	if !ok {
		t.Fatal("expected valid token")
	}
	if uid != 42 {
		t.Fatalf("got uid %d, want 42", uid)
	}
}

func TestCSRFTokenRoundTrip(t *testing.T) {
	m := newCSRFManager("secret")
	token := m.Token("login")
	if !m.Verify("login", token) {
		t.Fatal("expected csrf token to verify")
	}
	if m.Verify("admin", token) {
		t.Fatal("expected scope mismatch to fail verification")
	}
}

func TestSessionRejectsTamperedToken(t *testing.T) {
	sm := newSessionManager("secret")
	token := sm.Sign(42)
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, ok := sm.Verify(tampered); ok {
		t.Fatal("expected tampered token to fail verification")
	}
}
