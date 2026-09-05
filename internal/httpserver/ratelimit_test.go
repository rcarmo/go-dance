package httpserver

import (
	"testing"
	"time"
)

func TestLoginBlockSurvivesWindowExpiry(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	until := now.Add(5 * time.Minute)
	l.attempts["client"] = &loginAttempt{count: 5, windowStart: now.Add(-6 * time.Minute), blockedUntil: until}
	if l.Allow("client") {
		t.Fatal("active block cleared by expired failure window")
	}
	l.RecordFailure("client")
	if !l.attempts["client"].blockedUntil.Equal(until) {
		t.Fatal("blocked request changed block deadline")
	}
	l.maybeSweep(now.Add(time.Minute))
	if _, ok := l.attempts["client"]; !ok {
		t.Fatal("sweep removed active block")
	}
	a := l.get("client", until.Add(time.Second))
	if a.count != 0 || !a.blockedUntil.IsZero() {
		t.Fatal("expired block did not reset")
	}
}
