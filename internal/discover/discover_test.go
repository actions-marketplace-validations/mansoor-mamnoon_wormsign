package discover

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestWalk(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"app/package-lock.json":                                                    `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`,
		"app/node_modules/a/package.json":                                          `{"name":"a","version":"1.0.0"}`,
		"app/node_modules/b/package-lock.json":                                     `{"lockfileVersion":3,"packages":{"node_modules/zzz":{"version":"9.9.9"}}}`,
		"app/.vscode/tasks.json":                                                   `{}`,
		"app/.claude/settings.json":                                                `{}`,
		"app/.github/workflows/ci.yml":                                             `on: push`,
		"app/docs/workflows/not-a-workflow.yml":                                    ``,
		"py/.venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA": ``,
		"py/uv.lock":                               "[[package]]\nname = \"idna\"\nversion = \"3.6\"\n",
		"Library/ignored/package-lock.json":        `{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"}}}`,
		".claude/plugins/marketplaces/m/.mcp.json": `{}`,
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}

	inv := Walk(Options{Roots: []string{root}})
	inv.ScanProjectNodeModules()

	var got []string
	for _, p := range inv.AllPackages() {
		got = append(got, p.String())
	}
	sort.Strings(got)
	want := "a@1.0.0 idna@3.6 requests@2.31.0"
	if strings.Join(got, " ") != want {
		t.Errorf("packages: got %q want %q", strings.Join(got, " "), want)
	}
	if len(inv.Configs) != 2 {
		t.Errorf("configs: %v", inv.Configs)
	}
	if len(inv.Workflows) != 1 {
		t.Errorf("workflows: %v", inv.Workflows)
	}
	if len(inv.NodeModules) != 1 {
		t.Errorf("node_modules: %v", inv.NodeModules)
	}
}

func TestMissingRootIsReported(t *testing.T) {
	inv := Walk(Options{Roots: []string{filepath.Join(t.TempDir(), "missing")}})
	if len(inv.Errors) != 1 {
		t.Fatalf("missing root errors: %v", inv.Errors)
	}
}

func TestDepthLimitIsReported(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0700); err != nil {
		t.Fatal(err)
	}
	inv := Walk(Options{Roots: []string{root}, MaxDepth: 1})
	if len(inv.Errors) != 1 || !strings.Contains(inv.Errors[0].Error(), "maximum scan depth") {
		t.Fatalf("depth errors: %v", inv.Errors)
	}
}
