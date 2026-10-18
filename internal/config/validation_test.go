package config

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRejectMalformedURLs(t *testing.T) {
	for _, raw := range []string{"relative", "ftp://ca.example", "http://", "https://user:pass@ca.example", "https://ca.example?q=x", "https://ca.example#x"} {
		c := &Config{SessionKey: strings.Repeat("x", 32), StepCAURL: raw, AdminEmail: "a@example.com", AdminPassword: "secret"}
		if c.Validate() == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
func TestRejectDirectoryAsCertificate(t *testing.T) {
	c := &Config{SessionKey: strings.Repeat("x", 32), StepCAURL: "https://ca.example", AdminEmail: "a@example.com", AdminPassword: "secret", RootCertPath: t.TempDir()}
	if c.Validate() == nil {
		t.Fatal("accepted directory as certificate")
	}
}

func TestRejectUnsafeProductionSessionKeys(t *testing.T) {
	for _, baseURL := range []string{"http://dance.example", "https://dance.example"} {
		for _, key := range []string{"", "short-secret", strings.Repeat("x", 31)} {
			t.Run(baseURL+"/"+strconv.Itoa(len(key)), func(t *testing.T) {
				c := &Config{
					BaseURL: baseURL, CookieSecure: hasHTTPSPrefix(baseURL),
					StepCAURL: "https://ca.example", AdminEmail: "admin@example.com", AdminPassword: "secret",
					SessionKey: key,
				}
				if c.Validate() == nil {
					t.Fatal("accepted missing or weak production session signing key")
				}
			})
		}
	}
	for _, dev := range []bool{false, true} {
		c := &Config{
			StepCAURL: "https://ca.example", AdminEmail: "admin@example.com", AdminPassword: "secret",
			SessionKey: strings.Repeat("x", 32), EphemeralSessionKey: true, DevelopmentMode: dev,
		}
		if got := c.Validate(); (got == nil) != dev {
			t.Fatalf("ephemeral key with development=%t: %v", dev, got)
		}
		c.EphemeralSessionKey = false
		if err := c.Validate(); err != nil {
			t.Fatalf("rejected stable 32-byte key: %v", err)
		}
	}
}

func TestLoadSessionKeyPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, key      string
		dev, wantError bool
	}{
		{"production missing", "", false, true},
		{"production weak", "short-secret", false, true},
		{"production stable", strings.Repeat("x", 32), false, false},
		{"development ephemeral", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DANCE_DB_PATH", filepath.Join(t.TempDir(), "dance.sqlite"))
			t.Setenv("DANCE_BASE_URL", "http://localhost:8088")
			t.Setenv("DANCE_STEPCA_CONFIG", "")
			t.Setenv("DANCE_ROOT_CERT_PATH", "")
			t.Setenv("DANCE_STEPCA_URL", "https://ca.example")
			t.Setenv("DANCE_ADMIN_EMAIL", "admin@example.com")
			t.Setenv("DANCE_ADMIN_PASSWORD", "test-password")
			t.Setenv("DANCE_SESSION_KEY", tc.key)
			t.Setenv("DANCE_DEVELOPMENT_MODE", strconv.FormatBool(tc.dev))
			cfg, err := Load()
			if (err != nil) != tc.wantError {
				t.Fatalf("Load error = %v, wantError = %t", err, tc.wantError)
			}
			if err == nil && cfg.EphemeralSessionKey != (tc.key == "") {
				t.Fatal("incorrect ephemeral key flag")
			}
		})
	}
}
