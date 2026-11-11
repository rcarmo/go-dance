// Disposable integration fixture, never a deployment or trust-bootstrap tool.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/enrollment"
	"github.com/rcarmo/dance/internal/httpserver"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

func run() error {
	dir := flag.String("dir", "", "disposable fixture directory")
	init := flag.Bool("init", false, "create disposable test state")
	flag.Parse()
	if *dir == "" {
		return fmt.Errorf("fixture directory required")
	}
	p := func(name string) string { return filepath.Join(*dir, name) }
	if *init {
		if _, err := os.Stat(p("ca.json")); err == nil {
			return fmt.Errorf("refusing to replace fixture")
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable Dance integration root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
		if err != nil {
			return err
		}
		root, err = x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		write := func(name string, b []byte) error { return os.WriteFile(p(name), b, 0600) }
		if err = write("root.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		if err = write("root.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
			return err
		}
		tlskey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dance-ca"}, DNSNames: []string{"dance-ca", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err = x509.CreateCertificate(rand.Reader, leaf, root, &tlskey.PublicKey, key)
		if err != nil {
			return err
		}
		keyDER, err = x509.MarshalECPrivateKey(tlskey)
		if err != nil {
			return err
		}
		if err = write("tls.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		if err = write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
			return err
		}
		// Container paths are fixed by the test harness, never model input.
		conf := map[string]any{"root": []string{"/fixture/root.pem"}, "crt": "/fixture/root.pem", "key": "/fixture/root.key", "address": ":8443", "dnsNames": []string{"dance-ca"}, "db": map[string]any{"type": "badgerv2", "dataSource": "/fixture/ca-db"}, "authority": map[string]any{"claims": map[string]any{"minTLSCertDuration": "5s", "maxTLSCertDuration": "5m", "defaultTLSCertDuration": "60s"}, "provisioners": []any{map[string]any{"type": "ACME", "name": "default", "requireEAB": true, "challenges": []string{"http-01", "tls-alpn-01"}}}}}
		b, _ := json.Marshal(conf)
		if err = write("ca.json", b); err != nil {
			return err
		}
		st, err := store.NewSQLite(p("dance.sqlite"))
		if err != nil {
			return err
		}
		defer st.Close()
		if err = st.EnsureSchema(context.Background()); err != nil {
			return err
		}
		token, err := st.MintMachine(context.Background(), enrollment.Principal{Target: "fixture-host", Provisioners: []string{"acme/default"}, Operations: []string{"provisioners:read", "eab:create", "eab:read-own", "eab:invalidate-own"}, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			return err
		}
		if err := write("token", []byte(token+"\n")); err != nil {
			return err
		}
		admin := make([]byte, 32)
		if _, err := rand.Read(admin); err != nil {
			return err
		}
		return write("admin-token", []byte(hex.EncodeToString(admin)+"\n"))
	}
	cfg := &config.Config{Addr: ":8443", BaseURL: "https://dance-ca:8443", DBPath: p("dance.sqlite"), SessionKey: strings.Repeat("fixture-only-session-key-", 2), CookieName: "dance_fixture", APIAdminTokenFile: p("admin-token")}
	st, err := store.NewSQLite(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err = st.EnsureSchema(context.Background()); err != nil {
		return err
	}
	mgr, err := stepca.New(context.Background(), cfg.BaseURL, "", p("ca.json"), "")
	if err != nil {
		return err
	}
	defer mgr.Close()
	handler, err := httpserver.New(cfg, st, mgr)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: cfg.Addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	return server.ListenAndServeTLS(p("tls.pem"), p("tls.key"))
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "disposable enrollment fixture failed:", err)
		os.Exit(1)
	}
}
