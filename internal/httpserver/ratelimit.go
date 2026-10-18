package httpserver

import (
	"sync"
	"time"
)

// Bound retained client state even when many sources arrive within one window.
const maxLoginEntries = 4096

type loginAttempt struct {
	count        int
	blockedUntil time.Time
	windowStart  time.Time
}

type loginLimiter struct {
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	blockFor    time.Duration
	attempts    map[string]*loginAttempt
	lastSweep   time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		maxAttempts: 5,
		window:      5 * time.Minute,
		blockFor:    10 * time.Minute,
		attempts:    make(map[string]*loginAttempt),
		lastSweep:   time.Now(),
	}
}

func (l *loginLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.maybeSweep(now)
	a := l.get(key, now)
	if a == nil || now.Before(a.blockedUntil) {
		return false
	}
	// Reserve the attempt before bcrypt runs: concurrent requests must not all
	// pass the check while earlier password verifications are still in flight.
	// A successful login clears its client's budget through Reset.
	a.count++
	if a.count >= l.maxAttempts {
		a.blockedUntil = now.Add(l.blockFor)
	}
	return true
}

func (l *loginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

func (l *loginLimiter) get(key string, now time.Time) *loginAttempt {
	a, ok := l.attempts[key]
	if !ok {
		if len(l.attempts) >= maxLoginEntries {
			return nil
		}
		a = &loginAttempt{windowStart: now}
		l.attempts[key] = a
		return a
	}
	if !now.Before(a.blockedUntil) && now.Sub(a.windowStart) > l.window {
		*a = loginAttempt{windowStart: now}
	}
	return a
}

// maybeSweep removes expired entries to prevent unbounded memory growth.
func (l *loginLimiter) maybeSweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	for key, a := range l.attempts {
		expired := now.Sub(a.windowStart) > l.window && now.After(a.blockedUntil)
		if expired {
			delete(l.attempts, key)
		}
	}
	l.lastSweep = now
}
