package stepca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	acmeNoSQL "github.com/smallstep/certificates/acme/db/nosql"
	"github.com/smallstep/certificates/authority"
	stepconfig "github.com/smallstep/certificates/authority/config"
	stepdb "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
)

var (
	certsTable     = []byte("x509_certs")
	certsDataTable = []byte("x509_certs_data")
)

type Manager struct {
	upstream   *url.URL
	handler    http.Handler
	rootPEM    []byte
	mode       string
	publicHost string
	auth       *authority.Authority
	db         nosql.DB
}

type CertificateRecord struct {
	Subject         string
	Issuer          string
	Serial          string
	NotBefore       time.Time
	NotAfter        time.Time
	DNSNames        []string
	FingerprintSHA  string
	ProvisionerName string
	ProvisionerType string
	IsCA            bool
}

func New(ctx context.Context, publicBaseURL, rawURL, configPath, password string) (*Manager, error) {
	if configPath != "" {
		return newEmbedded(ctx, publicBaseURL, configPath, password)
	}
	if rawURL == "" {
		return &Manager{mode: "disabled"}, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse step-ca url: %w", err)
	}
	return &Manager{upstream: u, mode: "proxy", publicHost: u.Host}, nil
}

func newEmbedded(_ context.Context, publicBaseURL, configPath, password string) (*Manager, error) {
	cfg, err := stepconfig.LoadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("load step-ca config: %w", err)
	}
	auth, err := authority.New(cfg, authority.WithPassword([]byte(password)), authority.WithQuietInit())
	if err != nil {
		return nil, fmt.Errorf("initialize embedded step-ca authority: %w", err)
	}

	var rootPEM []byte
	for _, crt := range auth.GetInfo().RootX509Certs {
		rootPEM = append(rootPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})...)
	}

	m := &Manager{
		mode:       "embedded",
		publicHost: hostForLinks(publicBaseURL, cfg),
		rootPEM:    rootPEM,
		auth:       auth,
	}

	if cfg.DB != nil && auth.GetDatabase() != nil {
		rawDB, ok := auth.GetDatabase().(nosql.DB)
		if ok {
			m.db = rawDB
		}
		acmeDB, err := acmeNoSQL.New(rawDB)
		if err != nil {
			return nil, fmt.Errorf("configure embedded acme db: %w", err)
		}
		linker := acme.NewLinker(m.publicHost, "acme")
		baseCtx := authority.NewContext(context.Background(), auth)
		baseCtx = acme.NewContext(baseCtx, acmeDB, acme.NewClient(), linker, nil)

		mux := chi.NewRouter()
		mux.Use(middleware.GetHead)
		acmeAPI.Route(mux)
		m.handler = withBaseContext(mux, baseCtx)
	}

	return m, nil
}

func (m *Manager) Upstream() *url.URL    { return m.upstream }
func (m *Manager) Handler() http.Handler { return m.handler }
func (m *Manager) RootPEM() []byte       { return m.rootPEM }
func (m *Manager) Mode() string          { return m.mode }
func (m *Manager) PublicHost() string    { return m.publicHost }
func (m *Manager) Enabled() bool         { return m.handler != nil || m.upstream != nil }

func (m *Manager) Close() error { return nil }

func (m *Manager) RootCertificates() []CertificateRecord {
	if m.auth == nil {
		return nil
	}
	roots := m.auth.GetInfo().RootX509Certs
	out := make([]CertificateRecord, 0, len(roots))
	for _, crt := range roots {
		out = append(out, recordFromCert(crt, nil))
	}
	return out
}

func (m *Manager) IssuedCertificates(limit int) ([]CertificateRecord, error) {
	if m.db == nil {
		return nil, nil
	}
	entries, err := m.db.List(certsTable)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	dataEntries, err := m.db.List(certsDataTable)
	if err != nil {
		return nil, fmt.Errorf("list certificate metadata: %w", err)
	}
	metadataBySerial := make(map[string]stepdb.CertificateData, len(dataEntries))
	for _, entry := range dataEntries {
		var meta stepdb.CertificateData
		if err := json.Unmarshal(entry.Value, &meta); err == nil {
			metadataBySerial[string(entry.Key)] = meta
		}
	}
	out := make([]CertificateRecord, 0, len(entries))
	for _, entry := range entries {
		crt, err := x509.ParseCertificate(entry.Value)
		if err != nil {
			continue
		}
		meta := metadataBySerial[string(entry.Key)]
		out = append(out, recordFromCert(crt, &meta))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NotBefore.After(out[j].NotBefore)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func hostForLinks(publicBaseURL string, cfg *stepconfig.Config) string {
	if publicBaseURL != "" {
		if u, err := url.Parse(publicBaseURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if cfg != nil && len(cfg.DNSNames) > 0 {
		if strings.Contains(cfg.Address, ":") {
			if u, err := url.Parse("https://" + cfg.Address); err == nil {
				if port := u.Port(); port != "" && port != "443" {
					return cfg.DNSNames[0] + ":" + port
				}
			}
		}
		return cfg.DNSNames[0]
	}
	return "localhost"
}

func withBaseContext(next http.Handler, base context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(base))
	})
}

func EncodeCertificatesPEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, crt := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})...)
	}
	return out
}

func recordFromCert(crt *x509.Certificate, meta *stepdb.CertificateData) CertificateRecord {
	rec := CertificateRecord{
		Subject:        crt.Subject.String(),
		Issuer:         crt.Issuer.String(),
		Serial:         crt.SerialNumber.String(),
		NotBefore:      crt.NotBefore,
		NotAfter:       crt.NotAfter,
		DNSNames:       append([]string(nil), crt.DNSNames...),
		FingerprintSHA: fingerprintSHA256(crt.Raw),
		IsCA:           crt.IsCA,
	}
	if meta != nil && meta.Provisioner != nil {
		rec.ProvisionerName = meta.Provisioner.Name
		rec.ProvisionerType = meta.Provisioner.Type
	}
	return rec
}

func fingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
