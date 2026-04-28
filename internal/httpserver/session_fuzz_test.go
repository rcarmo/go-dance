package httpserver

import "testing"

func FuzzSessionVerify(f *testing.F) {
	sm := newSessionManager("secret")
	f.Add("")
	f.Add(sm.Sign(1))
	f.Add("not-a-token")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = sm.Verify(raw)
	})
}
