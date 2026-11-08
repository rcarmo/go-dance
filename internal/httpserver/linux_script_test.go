package httpserver

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxScriptInstallsEmbeddedRootWithoutNetwork(t *testing.T) {
	h, st, cfg := newTestHandler(t, true)
	defer st.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll/linux.sh", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	script := w.Body.String()
	if strings.Contains(script, "curl ") || strings.Contains(script, "wget ") {
		t.Fatal("bootstrap script must not download its trust anchor")
	}
	root, err := os.ReadFile(cfg.RootCertPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	// Stub privileged operations: this test never changes the host trust store.
	commands := map[string]string{
		"id":                     "echo 0",
		"openssl":                "exit \"$VALIDATION_EXIT\"",
		"install":                "cp \"$3\" \"$TEST_DIR/installed.pem\"",
		"update-ca-certificates": "touch \"$TEST_DIR/refreshed\"",
	}
	for name, body := range commands {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!"+shell+"\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, valid := range []bool{false, true} {
		code := "1"
		if valid {
			code = "0"
		}
		cmd := exec.Command(shell, "-s")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TEST_DIR="+dir, "VALIDATION_EXIT="+code)
		output, err := cmd.CombinedOutput()
		if !valid {
			if err == nil {
				t.Fatal("installed root despite failed certificate validation")
			}
			for _, name := range []string{"installed.pem", "refreshed"} {
				if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
					t.Fatalf("%s created before validation", name)
				}
			}
			continue
		}
		if err != nil {
			t.Fatalf("script: %v: %s", err, output)
		}
		installed, err := os.ReadFile(filepath.Join(dir, "installed.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(installed, root) {
			t.Fatal("installed certificate differs from configured root")
		}
		if _, err := os.Stat(filepath.Join(dir, "refreshed")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxScriptRequiresRootCertificate(t *testing.T) {
	h, st, _ := newTestHandler(t, false)
	defer st.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll/linux.sh", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
