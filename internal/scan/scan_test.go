package scan

import (
	"context"
	"github.com/mansoor-mamnoon/wormsign/internal/ioc"
	"os"
	"path/filepath"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/demo"
)

// TestDemoEndToEnd runs every local check against the demo fixture.
func TestDemoEndToEnd(t *testing.T) {
	dir, err := demo.Create()
	if err != nil {
		t.Fatal(err)
	}
	res := Run(context.Background(), Options{Roots: []string{dir}, Home: dir, Offline: true, NoGlobals: true})
	if !res.Critical() {
		t.Fatal("demo fixture should be critical")
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.Check]++
	}
	for _, c := range []string{"claude-hooks", "vscode-tasks", "payload-files"} {
		if got[c] == 0 {
			t.Errorf("expected a %s finding, got %v", c, got)
		}
	}
	if res.Packages != 3 {
		t.Errorf("want 3 packages, got %d", res.Packages)
	}
}

func TestIncompleteScansCannotPass(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		canceled      bool
	}{
		{name: "malformed lockfile", content: "{"},
		{name: "canceled scan", canceled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.content != "" {
				if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			res := Run(ctx, Options{Roots: []string{dir}, Home: dir, Offline: true, ProjectOnly: true})
			if !res.Incomplete() || res.ExitCode(false) != 2 || res.ExitCode(true) != 2 {
				t.Fatalf("incomplete scan must exit 2: %+v", res)
			}
		})
	}
}

func TestCriticalDetectionTakesPrecedenceOverErrors(t *testing.T) {
	res := &Result{OSVError: "unavailable", Findings: []ioc.Finding{{Severity: ioc.Critical}}}
	if res.ExitCode(false) != 1 {
		t.Fatal("critical detection must still fail with exit 1")
	}
}
