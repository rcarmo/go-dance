package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollmentAdminTokenPolicy(t *testing.T) {
	c := &Config{BaseURL: "https://dance.test", StepCAURL: "https://ca.test", AdminEmail: "admin@example.test", AdminPassword: "browser-password", SessionKey: strings.Repeat("s", 32)}
	for _, token := range []string{"short", strings.Repeat("a", 31), strings.Repeat("a", 32) + "\n", strings.Repeat("a", 4097)} {
		c.APIAdminToken = token
		if c.Validate() == nil {
			t.Fatal("accepted invalid API token")
		}
	}
	c.APIAdminToken = strings.Repeat("a", 64)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.BaseURL = "http://dance.test"
	if c.Validate() == nil {
		t.Fatal("accepted admin API without HTTPS outside development")
	}
	c.DevelopmentMode = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.APIAdminToken = c.SessionKey
	if c.Validate() == nil {
		t.Fatal("allowed session-key reuse as API credential")
	}
	c.APIAdminToken = strings.Repeat("a", 64)
	c.APIAdminTokenFile = "also-configured"
	if c.Validate() == nil {
		t.Fatal("accepted ambiguous token sources")
	}
}
func TestEnrollmentAdminTokenFileRotationAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-token")
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	if err := os.WriteFile(path, []byte(first+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Config{APIAdminTokenFile: path}
	got, err := c.EnrollmentAdminToken()
	if err != nil || got != first {
		t.Fatal("private token not loaded")
	}
	if err := os.WriteFile(path, []byte(second), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = c.EnrollmentAdminToken()
	if err != nil || got != second {
		t.Fatal("rotation not observed")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = c.EnrollmentAdminToken(); err == nil {
		t.Fatal("world-readable token accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Config{APIAdminTokenFile: link}).EnrollmentAdminToken(); err == nil {
		t.Fatal("symlinked token accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	got, err = c.EnrollmentAdminToken()
	if err != nil || got != "" {
		t.Fatal("removed file did not revoke token")
	}
}
