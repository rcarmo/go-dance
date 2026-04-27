package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Addr           string
	BaseURL        string
	DBPath         string
	SessionKey     string
	RootCertPath   string
	StepCAURL      string
	StepCAConfig   string
	StepCAPassword string
	AdminEmail     string
	AdminPassword  string
	CookieSecure   bool
	CookieName     string
}

func Load() (*Config, error) {
	cfg := &Config{
		Addr:           envOrDefault("DANCE_ADDR", ":8088"),
		BaseURL:        envOrDefault("DANCE_BASE_URL", "http://localhost:8088"),
		DBPath:         envOrDefault("DANCE_DB_PATH", filepath.Join(".dance", "dance.sqlite")),
		SessionKey:     os.Getenv("DANCE_SESSION_KEY"),
		RootCertPath:   os.Getenv("DANCE_ROOT_CERT_PATH"),
		StepCAURL:      os.Getenv("DANCE_STEPCA_URL"),
		StepCAConfig:   os.Getenv("DANCE_STEPCA_CONFIG"),
		StepCAPassword: os.Getenv("DANCE_STEPCA_PASSWORD"),
		AdminEmail:     os.Getenv("DANCE_ADMIN_EMAIL"),
		AdminPassword:  os.Getenv("DANCE_ADMIN_PASSWORD"),
		CookieName:     envOrDefault("DANCE_COOKIE_NAME", "dance_session"),
	}
	cfg.CookieSecure = hasHTTPSPrefix(cfg.BaseURL)

	if cfg.SessionKey == "" {
		cfg.SessionKey = randomHex(32)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	return cfg, nil
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
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
