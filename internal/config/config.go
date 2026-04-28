package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Addr                string
	BaseURL             string
	DBPath              string
	SessionKey          string
	RootCertPath        string
	StepCAURL           string
	StepCAConfig        string
	StepCAPassword      string
	AdminEmail          string
	AdminPassword       string
	CookieSecure        bool
	CookieName          string
	DevelopmentMode     bool
	EphemeralSessionKey bool
}

func Load() (*Config, error) {
	cfg := &Config{
		Addr:            envOrDefault("DANCE_ADDR", ":8088"),
		BaseURL:         envOrDefault("DANCE_BASE_URL", "http://localhost:8088"),
		DBPath:          envOrDefault("DANCE_DB_PATH", filepath.Join(".dance", "dance.sqlite")),
		SessionKey:      os.Getenv("DANCE_SESSION_KEY"),
		RootCertPath:    os.Getenv("DANCE_ROOT_CERT_PATH"),
		StepCAURL:       os.Getenv("DANCE_STEPCA_URL"),
		StepCAConfig:    os.Getenv("DANCE_STEPCA_CONFIG"),
		StepCAPassword:  os.Getenv("DANCE_STEPCA_PASSWORD"),
		AdminEmail:      os.Getenv("DANCE_ADMIN_EMAIL"),
		AdminPassword:   os.Getenv("DANCE_ADMIN_PASSWORD"),
		CookieName:      envOrDefault("DANCE_COOKIE_NAME", "dance_session"),
		DevelopmentMode: envBool("DANCE_DEVELOPMENT_MODE"),
	}
	cfg.CookieSecure = hasHTTPSPrefix(cfg.BaseURL)

	if cfg.SessionKey == "" {
		cfg.SessionKey = randomHex(32)
		cfg.EphemeralSessionKey = true
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envBool(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func (c *Config) Validate() error {
	if c.StepCAConfig == "" && c.StepCAURL == "" {
		return fmt.Errorf("either DANCE_STEPCA_CONFIG or DANCE_STEPCA_URL must be set")
	}
	if c.StepCAConfig != "" && c.StepCAPassword == "" {
		return fmt.Errorf("DANCE_STEPCA_PASSWORD is required when DANCE_STEPCA_CONFIG is set")
	}
	if c.AdminEmail == "" || c.AdminPassword == "" {
		return fmt.Errorf("DANCE_ADMIN_EMAIL and DANCE_ADMIN_PASSWORD are required")
	}
	if c.CookieSecure && c.EphemeralSessionKey && !c.DevelopmentMode {
		return fmt.Errorf("DANCE_SESSION_KEY must be set explicitly outside development mode")
	}
	if c.RootCertPath != "" {
		if _, err := os.Stat(c.RootCertPath); err != nil {
			return fmt.Errorf("root certificate path: %w", err)
		}
	}
	if c.StepCAConfig != "" {
		if _, err := os.Stat(c.StepCAConfig); err != nil {
			return fmt.Errorf("step-ca config path: %w", err)
		}
	}
	return nil
}

func hasHTTPSPrefix(v string) bool {
	return len(v) >= 8 && v[:8] == "https://"
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
