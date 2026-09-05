package httpserver

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnknownRouteAndUnsupportedMethod(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"GET", "/missing", 404}, {"POST", "/", 405}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s %s = %d", tc.method, tc.path, w.Code)
		}
	}
}
func TestRenderFailureIsAtomic(t *testing.T) {
	s := &server{tpl: template.Must(template.New("bad").Parse(`partial secret {{.Certificate.Subject}}`))}
	w := httptest.NewRecorder()
	s.render(w, "bad", templateData{})
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "partial secret") {
		t.Fatalf("response: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive HTML may be cached")
	}
}
