package config

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// EnrollmentAdminToken is a separate enrollment-management bearer credential,
// never a browser password, session or CA key. File-backed credentials are read
// on each request so removal/rotation revokes the old value without a restart.
func (c *Config) EnrollmentAdminToken() (string, error) {
	if c.APIAdminToken != "" && c.APIAdminTokenFile != "" {
		return "", fmt.Errorf("configure only one API admin token source")
	}
	token := c.APIAdminToken
	if c.APIAdminTokenFile != "" {
		info, err := os.Lstat(c.APIAdminTokenFile)
		if os.IsNotExist(err) {
			return "", nil
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("API admin token file must be a private regular file")
		}
		f, err := os.Open(c.APIAdminTokenFile)
		if err != nil {
			return "", fmt.Errorf("API admin token file unavailable")
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("API admin token file changed or is not private")
		}
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil {
			return "", fmt.Errorf("API admin token file unavailable")
		}
		if len(b) > 4096 {
			return "", fmt.Errorf("API admin token file is too large")
		}
		token = strings.TrimSpace(string(b))
		if token == "" {
			return "", fmt.Errorf("API admin token file is empty")
		}
	}
	if token != "" {
		if len(token) < 32 || len(token) > 4096 {
			return "", fmt.Errorf("API admin token must contain 32 to 4096 non-whitespace ASCII characters")
		}
		if token == c.AdminPassword || token == c.SessionKey || token == c.StepCAPassword {
			return "", fmt.Errorf("API admin token must be independent of browser/session/CA credentials")
		}
		for _, ch := range token {
			if ch <= 32 || ch > 126 {
				return "", fmt.Errorf("API admin token must contain non-whitespace ASCII characters")
			}
		}
	}
	return token, nil
}
