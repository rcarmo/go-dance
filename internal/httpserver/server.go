package httpserver

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type server struct {
	cfg          *config.Config
	store        store.Store
	sessions     *sessionManager
	csrf         *csrfManager
	loginLimiter *loginLimiter
	tpl          *template.Template
	stepCA       *stepca.Manager
}

type enrollPage struct {
	Slug    string
	Title   string
	Summary string
	Steps   []string
}

type templateData struct {
	Title                  string
	BaseURL                string
	RootCertURL            string
	StepCAURL              string
	StepCAMode             string
	AdminEmail             string
	Users                  []store.User
	Error                  string
	Notice                 string
	HasRootCert            bool
	RootCertificates       []stepca.CertificateRecord
	IssuedCertificates     []stepca.CertificateRecord
	RevocationHistory      []stepca.RevocationRecord
	AuditEvents            []store.AuditEvent
	Certificate            *stepca.CertificateDetail
	ACMEProvisioners       []stepca.ACMEProvisionerInfo
	SelectedProvisioner    string
	ExternalAccountKeys    []stepca.ExternalAccountKeyRecord
	NewExternalAccountKey  *stepca.ExternalAccountKeyRecord
	CertificateDownloadPEM string
	CertificateDownloadCRT string
	EnrollPage             *enrollPage
	CSRFToken              string
}

func New(cfg *config.Config, st store.Store, mgr *stepca.Manager) (http.Handler, error) {
	tpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s := &server{
		cfg:          cfg,
		store:        st,
		sessions:     newSessionManager(cfg.SessionKey),
		csrf:         newCSRFManager(cfg.SessionKey),
		loginLimiter: newLoginLimiter(),
		tpl:          tpl,
		stepCA:       mgr,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /admin", s.requireAuth(s.handleAdmin))
	mux.HandleFunc("GET /admin/certificates/{serial}", s.requireAuth(s.handleCertificateDetail))
	mux.HandleFunc("GET /admin/certificates/{serial}/pem", s.requireAuth(s.handleCertificatePEM))
	mux.HandleFunc("GET /admin/certificates/{serial}/crt", s.requireAuth(s.handleCertificateCRT))
	mux.HandleFunc("POST /admin/certificates/{serial}/revoke", s.requireAuth(s.handleCertificateRevoke))
	mux.HandleFunc("POST /admin/eab", s.requireAuth(s.handleCreateEAB))
	mux.HandleFunc("POST /admin/eab/{keyID}/delete", s.requireAuth(s.handleDeleteEAB))
	mux.HandleFunc("GET /enroll/root.pem", s.handleRootCert)
	mux.HandleFunc("GET /enroll/macos", s.handleEnrollPage("macos"))
	mux.HandleFunc("GET /enroll/ios", s.handleEnrollPage("ios"))
	mux.HandleFunc("GET /enroll/windows", s.handleEnrollPage("windows"))
	mux.HandleFunc("GET /enroll/linux", s.handleEnrollPage("linux"))
	mux.HandleFunc("GET /enroll/apple.mobileconfig", s.handleAppleMobileConfig)
	mux.HandleFunc("GET /enroll/windows.ps1", s.handleWindowsScript)
	mux.HandleFunc("GET /enroll/linux.sh", s.handleLinuxScript)

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

func (s *server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.stepCA.Ready(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, err.Error()+"\n")
		return
	}
	_, _ = io.WriteString(w, "ready\n")
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

func (s *server) handleEnrollPage(slug string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		page := enrollPages()[slug]
		if page == nil {
			http.NotFound(w, nil)
			return
		}
		s.render(w, "enroll.html", templateData{
			Title:       page.Title,
			RootCertURL: "/enroll/root.pem",
			EnrollPage:  page,
			HasRootCert: s.cfg.RootCertPath != "" || len(s.stepCA.RootPEM()) > 0,
		})
	}
}

func (s *server) handleLoginForm(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "login.html", templateData{Title: "Admin login", CSRFToken: s.csrf.Token("login")})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.csrf.Verify("login", r.FormValue("csrf_token")) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	remote := clientIP(r)
	if !s.loginLimiter.Allow(remote) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
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
		s.loginLimiter.RecordFailure(remote)
		s.render(w, "login.html", templateData{Title: "Admin login", Error: "Invalid credentials", CSRFToken: s.csrf.Token("login")})
		return
	}
	s.loginLimiter.Reset(remote)
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    s.sessions.Sign(user.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{Action: "login", Actor: email, RemoteIP: remote, UserAgent: r.UserAgent()})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.csrf.Verify("admin", r.FormValue("csrf_token")) {
		http.Redirect(w, r, "/admin?error=invalid+csrf+token", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cfg.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, nil)
}

func (s *server) renderAdmin(w http.ResponseWriter, r *http.Request, newKey *stepca.ExternalAccountKeyRecord) {
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
	revoked, err := s.stepCA.RevocationHistory(20)
	if err != nil {
		http.Error(w, "failed to load revocation history", http.StatusInternalServerError)
		return
	}
	auditEvents, err := s.store.ListAudit(r.Context(), 30)
	if err != nil {
		http.Error(w, "failed to load audit log", http.StatusInternalServerError)
		return
	}
	provisioners := s.stepCA.ACMEProvisioners()
	selectedProvisioner := r.URL.Query().Get("provisioner")
	if selectedProvisioner == "" && len(provisioners) > 0 {
		selectedProvisioner = provisioners[0].ID
	}
	keys, err := s.stepCA.ListExternalAccountKeys(selectedProvisioner)
	if err != nil {
		http.Error(w, "failed to load EAB keys", http.StatusInternalServerError)
		return
	}
	s.render(w, "admin.html", templateData{
		Title:                 "dance admin",
		AdminEmail:            user.Email,
		Users:                 users,
		StepCAURL:             stepCAEndpoint(s.cfg, s.stepCA),
		StepCAMode:            s.stepCA.Mode(),
		HasRootCert:           s.cfg.RootCertPath != "" || len(s.stepCA.RootPEM()) > 0,
		RootCertificates:      s.stepCA.RootCertificates(),
		IssuedCertificates:    issued,
		RevocationHistory:     revoked,
		AuditEvents:           auditEvents,
		ACMEProvisioners:      provisioners,
		SelectedProvisioner:   selectedProvisioner,
		ExternalAccountKeys:   keys,
		NewExternalAccountKey: newKey,
		Notice:                r.URL.Query().Get("notice"),
		Error:                 r.URL.Query().Get("error"),
		CSRFToken:             s.csrf.Token("admin"),
	})
}

func (s *server) handleCertificateDetail(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	cert, err := s.stepCA.GetCertificateDetail(serial)
	if err != nil {
		http.Error(w, "failed to load certificate detail", http.StatusInternalServerError)
		return
	}
	if cert == nil {
		http.NotFound(w, r)
		return
	}
	user := userFromContext(r.Context())
	s.render(w, "certificate.html", templateData{
		Title:                  "Certificate detail",
		AdminEmail:             user.Email,
		Certificate:            cert,
		CertificateDownloadPEM: "/admin/certificates/" + serial + "/pem",
		CertificateDownloadCRT: "/admin/certificates/" + serial + "/crt",
		Notice:                 r.URL.Query().Get("notice"),
		Error:                  r.URL.Query().Get("error"),
		CSRFToken:              s.csrf.Token("admin"),
	})
}

func (s *server) handleCertificatePEM(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	cert, err := s.stepCA.GetCertificateDetail(serial)
	if err != nil || cert == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", serial+".pem"))
	_, _ = io.WriteString(w, cert.PEM)
}

func (s *server) handleCertificateCRT(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	cert, err := s.stepCA.GetCertificateDetail(serial)
	if err != nil || cert == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", serial+".crt"))
	_, _ = w.Write(cert.DER)
}

func (s *server) handleCertificateRevoke(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/certificates/"+serial+"?error=bad+form", http.StatusSeeOther)
		return
	}
	if !s.csrf.Verify("admin", r.FormValue("csrf_token")) {
		http.Redirect(w, r, "/admin/certificates/"+serial+"?error=invalid+csrf+token", http.StatusSeeOther)
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	reasonCode, _ := strconv.Atoi(r.FormValue("reason_code"))
	if err := s.stepCA.RevokeCertificate(serial, reason, reasonCode); err != nil {
		http.Redirect(w, r, "/admin/certificates/"+serial+"?error="+urlpkg.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{Action: "revoke_certificate", Actor: userFromContext(r.Context()).Email, RemoteIP: clientIP(r), UserAgent: r.UserAgent()})
	http.Redirect(w, r, "/admin/certificates/"+serial+"?notice=certificate+revoked", http.StatusSeeOther)
}

func (s *server) handleCreateEAB(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin?error=bad+form", http.StatusSeeOther)
		return
	}
	if !s.csrf.Verify("admin", r.FormValue("csrf_token")) {
		http.Redirect(w, r, "/admin?error=invalid+csrf+token", http.StatusSeeOther)
		return
	}
	provisionerID := r.FormValue("provisioner_id")
	reference := strings.TrimSpace(r.FormValue("reference"))
	key, err := s.stepCA.CreateExternalAccountKey(provisionerID, reference)
	if err != nil {
		http.Redirect(w, r, "/admin?provisioner="+urlpkg.QueryEscape(provisionerID)+"&error="+urlpkg.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{Action: "create_eab", Actor: userFromContext(r.Context()).Email, RemoteIP: clientIP(r), UserAgent: r.UserAgent()})
	r.URL.RawQuery = "provisioner=" + urlpkg.QueryEscape(provisionerID) + "&notice=eab+created"
	s.renderAdmin(w, r, key)
}

func (s *server) handleDeleteEAB(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin?error=bad+form", http.StatusSeeOther)
		return
	}
	if !s.csrf.Verify("admin", r.FormValue("csrf_token")) {
		http.Redirect(w, r, "/admin?error=invalid+csrf+token", http.StatusSeeOther)
		return
	}
	provisionerID := r.FormValue("provisioner_id")
	keyID := r.PathValue("keyID")
	if err := s.stepCA.DeleteExternalAccountKey(provisionerID, keyID); err != nil {
		http.Redirect(w, r, "/admin?provisioner="+urlpkg.QueryEscape(provisionerID)+"&error="+urlpkg.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.store.AppendAudit(r.Context(), store.AuditEvent{Action: "delete_eab", Actor: userFromContext(r.Context()).Email, RemoteIP: clientIP(r), UserAgent: r.UserAgent()})
	http.Redirect(w, r, "/admin?provisioner="+urlpkg.QueryEscape(provisionerID)+"&notice=eab+deleted", http.StatusSeeOther)
}

func (s *server) handleRootCert(w http.ResponseWriter, _ *http.Request) {
	pemBytes, err := s.currentRootPEM()
	if err != nil || len(pemBytes) == 0 {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="dance-root-ca.pem"`)
	_, _ = w.Write(pemBytes)
}

func (s *server) handleAppleMobileConfig(w http.ResponseWriter, _ *http.Request) {
	pemBytes, err := s.currentRootPEM()
	if err != nil || len(pemBytes) == 0 {
		http.NotFound(w, nil)
		return
	}
	der, err := firstCertificateDER(pemBytes)
	if err != nil {
		http.Error(w, "invalid root certificate", http.StatusInternalServerError)
		return
	}
	id := profileID(der)
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadCertificateFileName</key><string>dance-root-ca.cer</string>
<key>PayloadContent</key><data>%s</data>
<key>PayloadDescription</key><string>Installs the dance root certificate.</string>
<key>PayloadDisplayName</key><string>dance Root CA</string>
<key>PayloadIdentifier</key><string>io.rcarmo.dance.root.%s</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDescription</key><string>Installs the dance root certificate authority.</string>
<key>PayloadDisplayName</key><string>dance Root CA</string>
<key>PayloadIdentifier</key><string>io.rcarmo.dance.profile.%s</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
`, base64.StdEncoding.EncodeToString(der), id, id, id, id)
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="dance-root-ca.mobileconfig"`)
	_, _ = io.WriteString(w, payload)
}

func (s *server) handleWindowsScript(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	content := fmt.Sprintf(`$url = "%s/enroll/root.pem"
$out = Join-Path $env:TEMP "dance-root-ca.pem"
Invoke-WebRequest -Uri $url -OutFile $out
Import-Certificate -FilePath $out -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Write-Host "Installed dance root CA into LocalMachine\\Root"
`, base)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="install-dance-root.ps1"`)
	_, _ = io.WriteString(w, content)
}

func (s *server) handleLinuxScript(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	content := fmt.Sprintf(`#!/usr/bin/env sh
set -eu
URL="%s/enroll/root.pem"
DEST="/usr/local/share/ca-certificates/dance-root-ca.crt"
curl -fsSL "$URL" -o "$DEST"
if command -v update-ca-certificates >/dev/null 2>&1; then
  update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
  update-ca-trust
else
  echo "Please refresh your trust store manually" >&2
fi
echo "Installed dance root CA to $DEST"
`, base)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="install-dance-root.sh"`)
	_, _ = io.WriteString(w, content)
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

func (s *server) currentRootPEM() ([]byte, error) {
	if s.cfg.RootCertPath != "" {
		return os.ReadFile(filepath.Clean(s.cfg.RootCertPath))
	}
	if pemBytes := s.stepCA.RootPEM(); len(pemBytes) > 0 {
		return pemBytes, nil
	}
	return nil, fmt.Errorf("root certificate unavailable")
}

func firstCertificateDER(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate block found")
	}
	return block.Bytes, nil
}

func profileID(der []byte) string {
	sum := sha256.Sum256(der)
	hex := fmt.Sprintf("%x", sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
}

func enrollPages() map[string]*enrollPage {
	return map[string]*enrollPage{
		"macos": {
			Slug:    "macos",
			Title:   "Enroll macOS",
			Summary: "Install the root certificate into Keychain Access and trust it for SSL.",
			Steps: []string{
				"Download the root certificate from the link below.",
				"Open the PEM file in Keychain Access and import it into the System or login keychain.",
				"Open the certificate, expand Trust, and set 'When using this certificate' to 'Always Trust' if macOS does not trust it automatically.",
				"Re-open your browser or restart services that need the updated trust store.",
			},
		},
		"ios": {
			Slug:    "ios",
			Title:   "Enroll iPhone / iPad",
			Summary: "Install the root certificate profile and enable full trust for the installed root CA.",
			Steps: []string{
				"Download the root certificate to the device.",
				"Open Settings and install the downloaded profile or certificate.",
				"Go to Settings → General → About → Certificate Trust Settings.",
				"Enable full trust for the installed root certificate.",
			},
		},
		"windows": {
			Slug:    "windows",
			Title:   "Enroll Windows",
			Summary: "Import the root certificate into Trusted Root Certification Authorities.",
			Steps: []string{
				"Download the root certificate.",
				"Open the certificate file and choose Install Certificate.",
				"Install it into the Local Machine or Current User Trusted Root Certification Authorities store.",
				"Restart browsers or services if they do not pick up trust changes immediately.",
			},
		},
		"linux": {
			Slug:    "linux",
			Title:   "Enroll Linux",
			Summary: "Install the root certificate into the system trust store and refresh CA bundles.",
			Steps: []string{
				"Download the root certificate.",
				"Copy it into your distro's local CA directory, such as /usr/local/share/ca-certificates/ or /etc/pki/ca-trust/source/anchors/.",
				"Run the appropriate refresh command, such as update-ca-certificates or update-ca-trust.",
				"For Firefox or NSS-backed tools, import the certificate into the NSS database if needed.",
			},
		},
	}
}
