package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRequiresBackendAndAdmin(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateEmbeddedRequiresPasswordAndStableSessionOutsideDev(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		BaseURL:             "https://dance.example",
		StepCAConfig:        filepath.Join(dir, "ca.json"),
		AdminEmail:          "admin@example.com",
		AdminPassword:       "secret",
		EphemeralSessionKey: true,
		CookieSecure:        true,
	}
	if err := os.WriteFile(cfg.StepCAConfig, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for missing step-ca password and stable session key")
	}
	cfg.StepCAPassword = "changeme"
	cfg.DevelopmentMode = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidateRootPath(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(root, []byte("pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		StepCAURL:     "https://ca.example",
		AdminEmail:    "admin@example.com",
		AdminPassword: "secret",
		RootCertPath:  root,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
