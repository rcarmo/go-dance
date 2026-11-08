package httpserver

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rcarmo/dance/internal/stepca"
)

func TestACMEDirectoryURLUsesConfiguredName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		items []stepca.ACMEProvisionerInfo
		want  string
	}{
		{"none", nil, ""},
		{"default", []stepca.ACMEProvisionerInfo{{Name: "default"}}, "https://ca.test/acme/default/directory"},
		{"legacy", []stepca.ACMEProvisionerInfo{{Name: "acme"}}, "https://ca.test/acme/acme/directory"},
		{"custom", []stepca.ACMEProvisionerInfo{{Name: "lan"}}, "https://ca.test/acme/lan/directory"},
		{"prefer default", []stepca.ACMEProvisionerInfo{{Name: "other"}, {Name: "default"}}, "https://ca.test/acme/default/directory"},
		{"escaped", []stepca.ACMEProvisionerInfo{{Name: "lan devices"}}, "https://ca.test/acme/lan%20devices/directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := acmeDirectoryURL("https://ca.test/", tc.items); got != tc.want {
				t.Fatalf("directory = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIndexDirectoryDisplayAndCaddySnippetAgree(t *testing.T) {
	tpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"https://ca.test/acme/default/directory", "https://ca.test/acme/acme/directory", ""} {
		var buf bytes.Buffer
		if err := tpl.ExecuteTemplate(&buf, "index.html", templateData{Title: "dance", BaseURL: "https://ca.test", StepCAURL: "https://ca.test/acme", ACMEDirectoryURL: directory}); err != nil {
			t.Fatal(err)
		}
		if directory == "" {
			if strings.Contains(buf.String(), "acme_ca ") {
				t.Fatal("rendered a guessed directory without a configured provisioner")
			}
		} else if strings.Count(buf.String(), directory) != 2 {
			t.Fatalf("display/snippet did not agree on %q", directory)
		}
	}
}

func TestSampleUsesOneDefaultProvisioner(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "ca.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Authority struct {
			Provisioners []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"provisioners"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Authority.Provisioners) != 1 || cfg.Authority.Provisioners[0].Type != "ACME" || cfg.Authority.Provisioners[0].Name != "default" {
		t.Fatal("sample must have a single ACME provisioner named default")
	}
}
