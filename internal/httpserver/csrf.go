package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type csrfManager struct {
	secret []byte
	maxAge time.Duration
}

func newCSRFManager(secret string) *csrfManager {
	return &csrfManager{secret: []byte(secret), maxAge: 2 * time.Hour}
}

func (m *csrfManager) Token(scope string) string {
	expires := time.Now().Add(m.maxAge).Unix()
	payload := fmt.Sprintf("%s:%d", scope, expires)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + ":" + sig))
}

func (m *csrfManager) Verify(scope, token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	raw := string(decoded)
	sigIdx := strings.LastIndex(raw, ":")
	if sigIdx <= 0 {
		return false
	}
	payload := raw[:sigIdx]
	sig := raw[sigIdx+1:]
	expIdx := strings.LastIndex(payload, ":")
	if expIdx <= 0 {
		return false
	}
	tokenScope := payload[:expIdx]
	if tokenScope != scope {
		return false
	}
	expires, err := strconv.ParseInt(payload[expIdx+1:], 10, 64)
	if err != nil || time.Now().Unix() > expires {
		return false
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}
