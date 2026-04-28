package httpserver

import (
	"sync"
	"time"
)

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
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		maxAttempts: 5,
		window:      5 * time.Minute,
		blockFor:    10 * time.Minute,
		attempts:    make(map[string]*loginAttempt),
	}
}

func (l *loginLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.get(key, now)
	if now.Before(a.blockedUntil) {
		return false
	}
	return true
}

func (l *loginLimiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.get(key, now)
	if now.Before(a.blockedUntil) {
		return
	}
	a.count++
	if a.count >= l.maxAttempts {
		a.blockedUntil = now.Add(l.blockFor)
	}
}

func (l *loginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

func (l *loginLimiter) get(key string, now time.Time) *loginAttempt {
	a, ok := l.attempts[key]
	if !ok {
		a = &loginAttempt{windowStart: now}
		l.attempts[key] = a
		return a
	}
	if now.Sub(a.windowStart) > l.window {
		*a = loginAttempt{windowStart: now}
	}
	return a
}
