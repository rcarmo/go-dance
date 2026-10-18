package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

type blockingLoginStore struct {
	store.Store
	entered chan struct{}
	release chan struct{}
}

func (s *blockingLoginStore) AuthenticateUser(context.Context, string, string) (*store.User, error) {
	s.entered <- struct{}{}
	<-s.release
	return nil, nil
}

func TestLoginLimitsInFlightPasswordChecks(t *testing.T) {
	st := &blockingLoginStore{entered: make(chan struct{}, 6), release: make(chan struct{})}
	cfg := &config.Config{SessionKey: strings.Repeat("x", 32), CookieName: "dance_session"}
	h, err := New(cfg, st, &stepca.Manager{})
	if err != nil {
		t.Fatal(err)
	}
	token := newCSRFManager(cfg.SessionKey).Token("login")
	request := func() int {
		form := url.Values{"email": {"admin@example.com"}, "password": {"wrong"}, "csrf_token": {token}}
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { close(st.release); wg.Wait() })
	for range 5 {
		wg.Add(1)
		go func() { defer wg.Done(); request() }()
	}
	for range 5 {
		select {
		case <-st.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("password checks did not start")
		}
	}
	response := make(chan int, 1)
	wg.Add(1)
	go func() { defer wg.Done(); response <- request() }()
	select {
	case code := <-response:
		if code != http.StatusTooManyRequests {
			t.Fatalf("sixth request returned %d, want 429", code)
		}
	case <-st.entered:
		t.Fatal("sixth request entered password verification before earlier attempts finished")
	case <-time.After(5 * time.Second):
		t.Fatal("rate-limited request waited for password verification")
	}
}
