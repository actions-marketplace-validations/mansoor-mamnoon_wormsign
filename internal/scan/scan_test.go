package scan

import (
	"context"
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
