package httpserver

import (
	"bytes"
	"html/template"
	"testing"
	"time"

	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

func TestAdminTemplateRendersKeySections(t *testing.T) {
	tpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	data := templateData{
		Title:      "dance admin",
		AdminEmail: "admin@example.com",
		Users:      []store.User{{Email: "admin@example.com", IsAdmin: true}},
		RootCertificates: []stepca.CertificateRecord{{
			Subject:        "CN=Root CA",
			Serial:         "1",
			NotBefore:      time.Unix(0, 0).UTC(),
			NotAfter:       time.Unix(86400, 0).UTC(),
			FingerprintSHA: "ABC123",
		}},
		IssuedCertificates: []stepca.CertificateRecord{{
			Subject:         "CN=svc.internal",
			Serial:          "2",
			DNSNames:        []string{"svc.internal"},
			ProvisionerName: "acme",
			ProvisionerType: "ACME",
			NotAfter:        time.Unix(86400, 0).UTC(),
		}},
		RevocationHistory:   []stepca.RevocationRecord{{Serial: "2", RevokedAt: time.Unix(10, 0).UTC(), Reason: "superseded", ACME: true}},
		AuditEvents:         []store.AuditEvent{{Action: "login", Actor: "admin@example.com", CreatedAt: "2026-01-01T00:00:00Z"}},
		ACMEProvisioners:    []stepca.ACMEProvisionerInfo{{ID: "acme/acme", Name: "acme", RequireEAB: false}},
		SelectedProvisioner: "acme/acme",
		ExternalAccountKeys: []stepca.ExternalAccountKeyRecord{{ID: "kid-1", Reference: "gateway", CreatedAt: time.Unix(10, 0).UTC()}},
		StepCAURL:           "http://example/acme",
		StepCAMode:          "embedded",
		HasRootCert:         true,
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "admin.html", data); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	for _, want := range []string{"dance admin", "Root certificates", "Recent issued certificates", "Revocation history", "Audit log", "EAB / enrollment tokens"} {
		if !contains(body, want) {
			t.Fatalf("expected template output to contain %q", want)
		}
	}
}

func TestCertificateTemplateShowsDownloads(t *testing.T) {
	tpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	data := templateData{
		Title:                  "Certificate detail",
		AdminEmail:             "admin@example.com",
		CertificateDownloadPEM: "/admin/certificates/123/pem",
		CertificateDownloadCRT: "/admin/certificates/123/crt",
		Certificate: &stepca.CertificateDetail{
			CertificateRecord: stepca.CertificateRecord{
				Subject:        "CN=svc.internal",
				Serial:         "123",
				FingerprintSHA: "ABC123",
				NotBefore:      time.Unix(0, 0).UTC(),
				NotAfter:       time.Unix(86400, 0).UTC(),
			},
			PEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "certificate.html", data); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	for _, want := range []string{"Download PEM", "Download CRT", "BEGIN CERTIFICATE"} {
		if !contains(body, want) {
			t.Fatalf("expected template output to contain %q", want)
		}
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
