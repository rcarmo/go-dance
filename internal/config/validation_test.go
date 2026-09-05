package config

import "testing"

func TestRejectMalformedURLs(t *testing.T) {
	for _, raw := range []string{"relative", "ftp://ca.example", "http://", "https://user:pass@ca.example", "https://ca.example?q=x", "https://ca.example#x"} {
		c := &Config{StepCAURL: raw, AdminEmail: "a@example.com", AdminPassword: "secret"}
		if c.Validate() == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
func TestRejectDirectoryAsCertificate(t *testing.T) {
	c := &Config{StepCAURL: "https://ca.example", AdminEmail: "a@example.com", AdminPassword: "secret", RootCertPath: t.TempDir()}
	if c.Validate() == nil {
		t.Fatal("accepted directory as certificate")
	}
}
