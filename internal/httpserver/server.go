package httpserver

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type server struct {
	cfg      *config.Config
	store    store.Store
	sessions *sessionManager
	tpl      *template.Template
	stepCA   *stepca.Manager
}

type templateData struct {
	Title              string
	BaseURL            string
	RootCertURL        string
	StepCAURL          string
	StepCAMode         string
	AdminEmail         string
	Users              []store.User
	Error              string
	HasRootCert        bool
	RootCertificates   []stepca.CertificateRecord
	IssuedCertificates []stepca.CertificateRecord
}

func New(cfg *config.Config, st store.Store, mgr *stepca.Manager) (http.Handler, error) {
	tpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s := &server{cfg: cfg, store: st, sessions: newSessionManager(cfg.SessionKey), tpl: tpl, stepCA: mgr}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /admin", s.requireAuth(s.handleAdmin))
	mux.HandleFunc("GET /enroll/root.pem", s.handleRootCert)

	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	if handler := mgr.Handler(); handler != nil {
		mux.Handle("/acme/", http.StripPrefix("/acme", handler))
		mux.Handle("/2.0/acme/", http.StripPrefix("/2.0/acme", handler))
	} else if upstream := mgr.Upstream(); upstream != nil {
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		mux.Handle("/acme/", proxy)
	}
	return loggingMiddleware(mux), nil
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func (s *server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "index.html", templateData{
		Title:       "dance",
		BaseURL:     s.cfg.BaseURL,
		RootCertURL: "/enroll/root.pem",
		StepCAURL:   stepCAEndpoint(s.cfg, s.stepCA),
		StepCAMode:  s.stepCA.Mode(),
		HasRootCert: s.cfg.RootCertPath != "" || len(s.stepCA.RootPEM()) > 0,
	})
}

func (s *server) handleLoginForm(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "login.html", templateData{Title: "Admin login"})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	user, err := s.store.AuthenticateUser(r.Context(), email, password)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	if user == nil || !user.IsAdmin {
		s.render(w, "login.html", templateData{Title: "Admin login", Error: "Invalid credentials"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    s.sessions.Sign(user.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{Action: "login", Actor: email, RemoteIP: clientIP(r), UserAgent: r.UserAgent()})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: s.cfg.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "failed to load users", http.StatusInternalServerError)
		return
	}
	issued, err := s.stepCA.IssuedCertificates(20)
	if err != nil {
		http.Error(w, "failed to load certificate inventory", http.StatusInternalServerError)
		return
	}
	s.render(w, "admin.html", templateData{
		Title:              "dance admin",
		AdminEmail:         user.Email,
		Users:              users,
		StepCAURL:          stepCAEndpoint(s.cfg, s.stepCA),
		StepCAMode:         s.stepCA.Mode(),
		HasRootCert:        s.cfg.RootCertPath != "" || len(s.stepCA.RootPEM()) > 0,
		RootCertificates:   s.stepCA.RootCertificates(),
		IssuedCertificates: issued,
	})
}

func (s *server) handleRootCert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="dance-root-ca.pem"`)
	if s.cfg.RootCertPath != "" {
		f, err := os.Open(filepath.Clean(s.cfg.RootCertPath))
		if err != nil {
			http.Error(w, "root certificate unavailable", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		_, _ = io.Copy(w, f)
		return
	}
	if pemBytes := s.stepCA.RootPEM(); len(pemBytes) > 0 {
		_, _ = w.Write(pemBytes)
		return
	}
	http.NotFound(w, nil)
}

func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.cfg.CookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		uid, ok := s.sessions.Verify(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := s.store.GetUserByID(r.Context(), uid)
		if err != nil || user == nil || !user.IsAdmin {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
	}
}

func (s *server) render(w http.ResponseWriter, name string, data templateData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type userContextKey struct{}

func userFromContext(ctx context.Context) *store.User {
	user, _ := ctx.Value(userContextKey{}).(*store.User)
	return user
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func stepCAEndpoint(cfg *config.Config, mgr *stepca.Manager) string {
	if mgr.Mode() == "embedded" {
		return strings.TrimRight(cfg.BaseURL, "/") + "/acme"
	}
	if cfg.StepCAURL != "" {
		return cfg.StepCAURL
	}
	return ""
}
