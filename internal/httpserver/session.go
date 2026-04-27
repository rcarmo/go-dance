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

type sessionManager struct {
	secret []byte
}

func newSessionManager(secret string) *sessionManager {
	return &sessionManager{secret: []byte(secret)}
}

func (s *sessionManager) Sign(userID int64) string {
	expires := time.Now().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("%d:%d", userID, expires)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + ":" + sig))
}

func (s *sessionManager) Verify(raw string) (int64, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return 0, false
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 3 {
		return 0, false
	}
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expires {
		return 0, false
	}
	payload := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return 0, false
	}
	return userID, true
}
