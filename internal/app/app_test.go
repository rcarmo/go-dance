package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCloseDrainsRequests(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		res, err := http.Get(server.URL)
		if err == nil {
			res.Body.Close()
		}
	}()
	<-entered
	done := make(chan error, 1)
	go func() { done <- (&App{Server: server.Config}).Close() }()
	select {
	case <-done:
		close(release)
		t.Fatal("Close returned while a request was active")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close failed to finish")
	}
	<-requestDone
}
