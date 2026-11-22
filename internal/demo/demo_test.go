package demo_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/demo"
	"github.com/mansoor-mamnoon/wormsign/internal/report"
	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

// Exercise the embedded files through discovery, local detection and output.
// Embedded-file read errors and mid-write disk failures need fault injection;
// they cannot be forced portably without test doubles.
func TestOfflineDemoAndRevocationAdvice(t *testing.T) {
	dir, err := demo.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	result := scan.Run(context.Background(), scan.Options{Roots: []string{dir}, Home: dir, ProjectOnly: true, Offline: true})
	if !result.Critical() {
		t.Fatal("demo did not detect its harmless indicators")
	}
	result.Credentials = demo.Credentials()
	var out bytes.Buffer
	report.Text(&out, result, report.NewStyle(false), dir, "test")
	if !strings.Contains(out.String(), "Revoke at github.com/settings/applications") || strings.Contains(out.String(), "gh auth refresh") {
		t.Fatalf("rotation advice must revoke compromised credentials, not refresh scopes: %s", out.String())
	}
}

func TestDemoUnavailableTemporaryDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, missing)
	}
	if dir, err := demo.Create(); err == nil {
		os.RemoveAll(dir)
		t.Fatal("expected failure for unavailable temporary directory")
	}
}
