package stepca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	stepconfig "github.com/smallstep/certificates/authority/config"
	stepdb "github.com/smallstep/certificates/db"
	"github.com/smallstep/nosql/database"
)

type fakeNoSQL struct {
	buckets map[string][]*database.Entry
}

func (f *fakeNoSQL) Open(string, ...database.Option) error  { return nil }
func (f *fakeNoSQL) Close() error                           { return nil }
func (f *fakeNoSQL) Get(bucket, key []byte) ([]byte, error) { return nil, database.ErrNotFound }
func (f *fakeNoSQL) Set(bucket, key, value []byte) error    { return nil }
func (f *fakeNoSQL) CmpAndSwap(bucket, key, oldValue, newValue []byte) ([]byte, bool, error) {
	return nil, false, nil
}
func (f *fakeNoSQL) Del(bucket, key []byte) error    { return nil }
func (f *fakeNoSQL) Update(tx *database.Tx) error    { return nil }
func (f *fakeNoSQL) CreateTable(bucket []byte) error { return nil }
func (f *fakeNoSQL) DeleteTable(bucket []byte) error { return nil }
func (f *fakeNoSQL) List(bucket []byte) ([]*database.Entry, error) {
	return f.buckets[string(bucket)], nil
}

func TestIssuedCertificatesAndRevocationHistory(t *testing.T) {
	cert1 := mustTestCert(t, "one.internal", time.Now().Add(-2*time.Hour), time.Now().Add(24*time.Hour))
	cert2 := mustTestCert(t, "two.internal", time.Now().Add(-1*time.Hour), time.Now().Add(48*time.Hour))
	meta1, _ := json.Marshal(stepdb.CertificateData{Provisioner: &stepdb.ProvisionerData{ID: "acme/acme", Name: "acme", Type: "ACME"}})
	meta2, _ := json.Marshal(stepdb.CertificateData{Provisioner: &stepdb.ProvisionerData{ID: "acme/eab", Name: "acme-eab", Type: "ACME"}})
	revokedJSON, _ := json.Marshal(stepdb.RevokedCertificateInfo{Serial: cert1.SerialNumber.String(), Reason: "superseded", ReasonCode: 4, RevokedAt: time.Now().UTC()})

	mgr := &Manager{db: &fakeNoSQL{buckets: map[string][]*database.Entry{
		string(certsTable): {
			{Key: []byte(cert1.SerialNumber.String()), Value: cert1.Raw},
			{Key: []byte(cert2.SerialNumber.String()), Value: cert2.Raw},
		},
		string(certsDataTable): {
			{Key: []byte(cert1.SerialNumber.String()), Value: meta1},
			{Key: []byte(cert2.SerialNumber.String()), Value: meta2},
		},
		string(revokedCertsTable): {
			{Key: []byte(cert1.SerialNumber.String()), Value: revokedJSON},
		},
	}}}

	issued, err := mgr.IssuedCertificates(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(issued) != 2 {
		t.Fatalf("got %d issued certs", len(issued))
	}
	if issued[0].Subject == issued[1].Subject {
		t.Fatal("expected distinct issued certificates")
	}
	if issued[0].ProvisionerName == "" || issued[1].ProvisionerName == "" {
		t.Fatal("expected provisioner metadata")
	}

	revocations, err := mgr.RevocationHistory(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(revocations) != 1 {
		t.Fatalf("got %d revocations", len(revocations))
	}
	if revocations[0].Reason != "superseded" {
		t.Fatalf("got reason %q", revocations[0].Reason)
	}
}

func TestHostForLinks(t *testing.T) {
	tests := []struct {
		name string
		base string
		cfg  *stepconfig.Config
		want string
	}{
		{name: "base url wins", base: "https://dance.example:8443", cfg: &stepconfig.Config{Address: ":9000", DNSNames: []string{"ca.lan"}}, want: "dance.example:8443"},
		{name: "dns name with port", base: "", cfg: &stepconfig.Config{Address: ":9000", DNSNames: []string{"ca.lan"}}, want: "ca.lan:9000"},
		{name: "dns name default", base: "", cfg: &stepconfig.Config{Address: ":443", DNSNames: []string{"ca.lan"}}, want: "ca.lan"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hostForLinks(tc.base, tc.cfg)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func mustTestCert(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(notBefore.UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		DNSNames:     []string{cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func TestNewProxyMode(t *testing.T) {
	mgr, err := New(t.Context(), "", "https://ca.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if mgr.Mode() != "proxy" {
		t.Fatalf("got mode %q", mgr.Mode())
	}
	if mgr.Upstream().String() != (&url.URL{Scheme: "https", Host: "ca.example"}).String() {
		t.Fatalf("unexpected upstream %v", mgr.Upstream())
	}
}
