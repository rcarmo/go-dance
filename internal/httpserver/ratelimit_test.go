package httpserver

import (
	"strconv"
	"sync"
	"sync/atomic"
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
	l.Allow("client")
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

// Attempts must be reserved before password verification finishes. Otherwise a
// burst can pass Allow before any goroutine reports its failed password.
func TestLoginLimiterReservesConcurrentAttempts(t *testing.T) {
	l := newLoginLimiter()
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("client") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != int32(l.maxAttempts) {
		t.Fatalf("admitted %d concurrent attempts, want %d", got, l.maxAttempts)
	}
}

func TestLoginLimiterBoundsClientEntries(t *testing.T) {
	l := newLoginLimiter()
	for i := range maxLoginEntries {
		if !l.Allow(strconv.Itoa(i)) {
			t.Fatalf("rejected client %d before capacity", i)
		}
	}
	if l.Allow("overflow") {
		t.Fatal("admitted new client after capacity")
	}
	if len(l.attempts) != maxLoginEntries {
		t.Fatalf("retained %d entries, want %d", len(l.attempts), maxLoginEntries)
	}
	if !l.Allow("0") {
		t.Fatal("capacity rejected an existing client's remaining attempts")
	}
	l.Reset("0")
	if !l.Allow("replacement") {
		t.Fatal("did not reuse released capacity")
	}
}
