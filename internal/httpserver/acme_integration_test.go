package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

// Exercise the mounted, embedded authority with the URLs a normal ACME client
// receives from its directory. No reverse proxy or rewritten JWS is involved.
func TestEmbeddedACMESignedRequests(t *testing.T) {
	for _, prefix := range []string{"/acme", "/2.0/acme"} {
		t.Run(prefix, func(t *testing.T) {
			dir := t.TempDir()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
			cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
			write := func(p string, b []byte) {
				t.Helper()
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
			der, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
			caConfig := map[string]any{"root": []string{certPath}, "crt": certPath, "key": keyPath, "address": ":443", "dnsNames": []string{"ca.test"}, "db": map[string]any{"type": "badgerv2", "dataSource": filepath.Join(dir, "ca-db")}, "authority": map[string]any{"provisioners": []any{map[string]any{"type": "ACME", "name": "enroll", "requireEAB": true}}}}
			cfgBytes, _ := json.Marshal(caConfig)
			cfgPath := filepath.Join(dir, "ca.json")
			write(cfgPath, cfgBytes)
			mgr, err := stepca.New(context.Background(), "https://ca.test", "", cfgPath, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mgr.Close() })
			st, err := store.NewSQLite(filepath.Join(dir, "dance.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			if err := st.EnsureSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
			handler, err := New(&config.Config{BaseURL: "https://ca.test", SessionKey: strings.Repeat("s", 32), CookieName: "dance_session"}, st, mgr)
			if err != nil {
				t.Fatal(err)
			}
			call := func(method, url string, body []byte) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, url, bytes.NewReader(body))
				if method == http.MethodPost {
					r.Header.Set("Content-Type", "application/jose+json")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			landing := call(http.MethodGet, "https://ca.test/", nil)
			if !strings.Contains(landing.Body.String(), "https://ca.test/acme/enroll/directory") {
				t.Fatal("landing page did not use the configured provisioner name")
			}
			directoryURL := "https://ca.test" + prefix + "/enroll/directory"
			response := call(http.MethodGet, directoryURL, nil)
			if response.Code != 200 {
				t.Fatalf("directory: %d %s", response.Code, response.Body)
			}
			var directory map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &directory); err != nil {
				t.Fatal(err)
			}
			endpoints := map[string]string{}
			for _, n := range []string{"newNonce", "newAccount", "newOrder"} {
				var endpoint string
				if err := json.Unmarshal(directory[n], &endpoint); err != nil {
					t.Fatal(err)
				}
				endpoints[n] = endpoint
				if !strings.HasPrefix(endpoints[n], "https://ca.test"+prefix+"/enroll/") {
					t.Fatalf("incorrect %s URL: %s", n, endpoints[n])
				}
			}
			accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			b64 := base64.RawURLEncoding.EncodeToString
			jwk := map[string]string{"kty": "EC", "crv": "P-256", "x": b64(accountKey.X.FillBytes(make([]byte, 32))), "y": b64(accountKey.Y.FillBytes(make([]byte, 32)))}
			encode := func(v any) string {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b64(b)
			}
			post := func(url, signedURL, kid string, payload any) *httptest.ResponseRecorder {
				t.Helper()
				nonce := call(http.MethodHead, endpoints["newNonce"], nil)
				if nonce.Code != 200 || nonce.Header().Get("Replay-Nonce") == "" {
					t.Fatalf("nonce: %d", nonce.Code)
				}
				protected := map[string]any{"alg": "ES256", "url": signedURL, "nonce": nonce.Header().Get("Replay-Nonce")}
				if kid == "" {
					protected["jwk"] = jwk
				} else {
					protected["kid"] = kid
				}
				p := encode(protected)
				data := ""
				if payload != nil {
					data = encode(payload)
				}
				digest := sha256.Sum256([]byte(p + "." + data))
				r, s, err := ecdsa.Sign(rand.Reader, accountKey, digest[:])
				if err != nil {
					t.Fatal(err)
				}
				sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
				body, _ := json.Marshal(map[string]string{"protected": p, "payload": data, "signature": b64(sig)})
				return call(http.MethodPost, url, body)
			}
			missing := post(endpoints["newAccount"], endpoints["newAccount"], "", map[string]any{"termsOfServiceAgreed": true})
			if missing.Code != 400 || !strings.Contains(missing.Body.String(), "externalAccountRequired") {
				t.Fatalf("EAB requirement: %d %s", missing.Code, missing.Body)
			}
			provisioner := mgr.ACMEProvisioners()[0]
			eab, err := mgr.CreateExternalAccountKey(context.Background(), provisioner.ID, "integration")
			if err != nil {
				t.Fatal(err)
			}
			protected := encode(map[string]string{"alg": "HS256", "kid": eab.ID, "url": endpoints["newAccount"]})
			payload := encode(jwk)
			secret, err := base64.RawURLEncoding.DecodeString(eab.HMACKey)
			if err != nil {
				t.Fatal(err)
			}
			mac := hmac.New(sha256.New, secret)
			_, _ = io.WriteString(mac, protected+"."+payload)
			account := post(endpoints["newAccount"], endpoints["newAccount"], "", map[string]any{"termsOfServiceAgreed": true, "externalAccountBinding": map[string]string{"protected": protected, "payload": payload, "signature": b64(mac.Sum(nil))}})
			if account.Code != 201 {
				t.Fatalf("new account: %d %s", account.Code, account.Body)
			}
			kid := account.Header().Get("Location")
			if !strings.HasPrefix(kid, "https://ca.test"+prefix+"/enroll/account/") {
				t.Fatalf("account location: %s", kid)
			}
			order := post(endpoints["newOrder"], endpoints["newOrder"], kid, map[string]any{"identifiers": []any{map[string]string{"type": "dns", "value": "host.test"}}})
			if order.Code != 201 {
				t.Fatalf("new order: %d %s", order.Code, order.Body)
			}
			var orderBody struct {
				Authorizations []string `json:"authorizations"`
			}
			if err := json.Unmarshal(order.Body.Bytes(), &orderBody); err != nil || len(orderBody.Authorizations) != 1 {
				t.Fatalf("order response: %s", order.Body)
			}
			authURL := orderBody.Authorizations[0]
			auth := post(authURL, authURL, kid, nil)
			if auth.Code != 200 {
				t.Fatalf("POST-as-GET: %d %s", auth.Code, auth.Body)
			}
			wrongURL := post(authURL, strings.Replace(authURL, prefix, "/wrong", 1), kid, nil)
			if wrongURL.Code != 400 {
				t.Fatalf("mismatched signed URL accepted: %d %s", wrongURL.Code, wrongURL.Body)
			}
		})
	}
}
