package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentConfigFailuresMakeScanIncomplete(t *testing.T) {
	for _, name := range []string{".claude/settings.json", ".vscode/tasks.json", ".mcp.json"} {
		for _, contents := range []string{"{", "null", `{"hooks":"invalid","tasks":"invalid","mcpServers":"invalid"}`} {
			t.Run(name+"/"+contents, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				result := Run(context.Background(), Options{Roots: []string{dir}, Home: dir, Offline: true, ProjectOnly: true})
				if !result.Incomplete() || result.ExitCode(false) != 2 {
					t.Fatalf("unreadable config passed: %+v", result)
				}
			})
		}
	}
}
