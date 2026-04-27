package httpserver

import "testing"

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
