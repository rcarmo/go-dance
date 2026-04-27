package stepca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	"github.com/smallstep/certificates/authority/provisioner"
	stepdb "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql"
)

var (
	certsTable        = []byte("x509_certs")
	certsDataTable    = []byte("x509_certs_data")
	revokedCertsTable = []byte("revoked_x509_certs")
)

type Manager struct {
	upstream   *url.URL
	handler    http.Handler
	rootPEM    []byte
	mode       string
	publicHost string
	auth       *authority.Authority
	cfg        *stepconfig.Config
	db         nosql.DB
	acmeDB     acme.DB
}

type CertificateRecord struct {
	Subject         string
	Issuer          string
	Serial          string
	NotBefore       time.Time
	NotAfter        time.Time
	DNSNames        []string
	FingerprintSHA  string
	ProvisionerID   string
	ProvisionerName string
	ProvisionerType string
	IsCA            bool
	IsRevoked       bool
}

type CertificateDetail struct {
	CertificateRecord
	PEM string
	DER []byte
}

type RevocationRecord struct {
	Serial        string
	Reason        string
	ReasonCode    int
	RevokedAt     time.Time
	ExpiresAt     time.Time
	ProvisionerID string
	ACME          bool
	MTLS          bool
}

type ACMEProvisionerInfo struct {
	ID         string
	Name       string
	RequireEAB bool
}

type ExternalAccountKeyRecord struct {
	ID              string
	ProvisionerID   string
	ProvisionerName string
	Reference       string
	AccountID       string
	CreatedAt       time.Time
	BoundAt         time.Time
	Bound           bool
	HMACKey         string
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
		cfg:        cfg,
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
		m.acmeDB = acmeDB
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
func (m *Manager) Close() error          { return nil }

func (m *Manager) RootCertificates() []CertificateRecord {
	if m.auth == nil {
		return nil
	}
	roots := m.auth.GetInfo().RootX509Certs
	out := make([]CertificateRecord, 0, len(roots))
	for _, crt := range roots {
		out = append(out, recordFromCert(crt, nil, false))
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
	metadataBySerial, err := m.certificateMetadata()
	if err != nil {
		return nil, err
	}
	out := make([]CertificateRecord, 0, len(entries))
	for _, entry := range entries {
		crt, err := x509.ParseCertificate(entry.Value)
		if err != nil {
			continue
		}
		meta := metadataBySerial[string(entry.Key)]
		revoked := false
		if m.auth != nil {
			revoked, _ = m.auth.IsRevoked(crt.SerialNumber.String())
		}
		out = append(out, recordFromCert(crt, meta, revoked))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotBefore.After(out[j].NotBefore) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) GetCertificateDetail(serial string) (*CertificateDetail, error) {
	if m.auth == nil || m.auth.GetDatabase() == nil {
		return nil, nil
	}
	crt, err := m.auth.GetDatabase().GetCertificate(serial)
	if err != nil {
		return nil, nil
	}
	metaBySerial, err := m.certificateMetadata()
	if err != nil {
		return nil, err
	}
	revoked, _ := m.auth.IsRevoked(serial)
	rec := recordFromCert(crt, metaBySerial[serial], revoked)
	return &CertificateDetail{
		CertificateRecord: rec,
		PEM:               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})),
		DER:               append([]byte(nil), crt.Raw...),
	}, nil
}

func (m *Manager) RevocationHistory(limit int) ([]RevocationRecord, error) {
	if m.db == nil {
		return nil, nil
	}
	entries, err := m.db.List(revokedCertsTable)
	if err != nil {
		return nil, fmt.Errorf("list revoked certificates: %w", err)
	}
	out := make([]RevocationRecord, 0, len(entries))
	for _, entry := range entries {
		var info stepdb.RevokedCertificateInfo
		if err := json.Unmarshal(entry.Value, &info); err != nil {
			continue
		}
		out = append(out, RevocationRecord{
			Serial:        info.Serial,
			Reason:        info.Reason,
			ReasonCode:    info.ReasonCode,
			RevokedAt:     info.RevokedAt,
			ExpiresAt:     info.ExpiresAt,
			ProvisionerID: info.ProvisionerID,
			ACME:          info.ACME,
			MTLS:          info.MTLS,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RevokedAt.After(out[j].RevokedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) RevokeCertificate(serial, reason string, reasonCode int) error {
	if m.auth == nil || m.auth.GetDatabase() == nil {
		return fmt.Errorf("embedded authority is not available")
	}
	crt, err := m.auth.GetDatabase().GetCertificate(serial)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.RevokeMethod)
	return m.auth.Revoke(ctx, &authority.RevokeOptions{
		Serial:      serial,
		Reason:      reason,
		ReasonCode:  reasonCode,
		PassiveOnly: true,
		ACME:        true,
		Crt:         crt,
	})
}

func (m *Manager) ACMEProvisioners() []ACMEProvisionerInfo {
	if m.cfg == nil || m.cfg.AuthorityConfig == nil {
		return nil
	}
	var out []ACMEProvisionerInfo
	for _, p := range m.cfg.AuthorityConfig.Provisioners {
		acmeProv, ok := p.(*provisioner.ACME)
		if !ok {
			continue
		}
		out = append(out, ACMEProvisionerInfo{
			ID:         acmeProv.GetID(),
			Name:       acmeProv.GetName(),
			RequireEAB: acmeProv.RequireEAB,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Manager) ListExternalAccountKeys(provisionerID string) ([]ExternalAccountKeyRecord, error) {
	if m.acmeDB == nil {
		return nil, nil
	}
	keys, _, err := m.acmeDB.GetExternalAccountKeys(context.Background(), provisionerID, "", 100)
	if err != nil {
		return nil, fmt.Errorf("list external account keys: %w", err)
	}
	provNames := make(map[string]string)
	for _, p := range m.ACMEProvisioners() {
		provNames[p.ID] = p.Name
	}
	out := make([]ExternalAccountKeyRecord, 0, len(keys))
	for _, key := range keys {
		out = append(out, ExternalAccountKeyRecord{
			ID:              key.ID,
			ProvisionerID:   key.ProvisionerID,
			ProvisionerName: provNames[key.ProvisionerID],
			Reference:       key.Reference,
			AccountID:       key.AccountID,
			CreatedAt:       key.CreatedAt,
			BoundAt:         key.BoundAt,
			Bound:           key.AlreadyBound(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Manager) CreateExternalAccountKey(provisionerID, reference string) (*ExternalAccountKeyRecord, error) {
	if m.acmeDB == nil {
		return nil, fmt.Errorf("embedded ACME DB is not available")
	}
	key, err := m.acmeDB.CreateExternalAccountKey(context.Background(), provisionerID, reference)
	if err != nil {
		return nil, fmt.Errorf("create external account key: %w", err)
	}
	provName := provisionerID
	for _, p := range m.ACMEProvisioners() {
		if p.ID == provisionerID {
			provName = p.Name
			break
		}
	}
	return &ExternalAccountKeyRecord{
		ID:              key.ID,
		ProvisionerID:   key.ProvisionerID,
		ProvisionerName: provName,
		Reference:       key.Reference,
		AccountID:       key.AccountID,
		CreatedAt:       key.CreatedAt,
		BoundAt:         key.BoundAt,
		Bound:           key.AlreadyBound(),
		HMACKey:         base64URLString(key.HmacKey),
	}, nil
}

func (m *Manager) DeleteExternalAccountKey(provisionerID, keyID string) error {
	if m.acmeDB == nil {
		return fmt.Errorf("embedded ACME DB is not available")
	}
	if err := m.acmeDB.DeleteExternalAccountKey(context.Background(), provisionerID, keyID); err != nil {
		return fmt.Errorf("delete external account key: %w", err)
	}
	return nil
}

func (m *Manager) certificateMetadata() (map[string]*stepdb.CertificateData, error) {
	if m.db == nil {
		return nil, nil
	}
	entries, err := m.db.List(certsDataTable)
	if err != nil {
		return nil, fmt.Errorf("list certificate metadata: %w", err)
	}
	out := make(map[string]*stepdb.CertificateData, len(entries))
	for _, entry := range entries {
		var meta stepdb.CertificateData
		if err := json.Unmarshal(entry.Value, &meta); err == nil {
			copyMeta := meta
			out[string(entry.Key)] = &copyMeta
		}
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

func recordFromCert(crt *x509.Certificate, meta *stepdb.CertificateData, revoked bool) CertificateRecord {
	rec := CertificateRecord{
		Subject:        crt.Subject.String(),
		Issuer:         crt.Issuer.String(),
		Serial:         crt.SerialNumber.String(),
		NotBefore:      crt.NotBefore,
		NotAfter:       crt.NotAfter,
		DNSNames:       append([]string(nil), crt.DNSNames...),
		FingerprintSHA: fingerprintSHA256(crt.Raw),
		IsCA:           crt.IsCA,
		IsRevoked:      revoked,
	}
	if meta != nil && meta.Provisioner != nil {
		rec.ProvisionerID = meta.Provisioner.ID
		rec.ProvisionerName = meta.Provisioner.Name
		rec.ProvisionerType = meta.Provisioner.Type
	}
	return rec
}

func fingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func base64URLString(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
