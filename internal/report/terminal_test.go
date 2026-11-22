package report

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

func TestScanReportEscapesUntrustedTerminalControls(t *testing.T) {
	root := t.TempDir()
	// A server name is repository-controlled. Rendering it must not execute
	// OSC clipboard operations, erase the screen, or forge a clean verdict.
	name := "\u202e\r\x07\x1b]52;c;x\x07\nCLEAN"
	config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{name: map[string]string{"command": "node"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
	result := scan.Run(context.Background(), scan.Options{Roots: []string{root}, Home: root, ProjectOnly: true, Offline: true})
	if len(result.MCPServers) != 1 {
		t.Fatal("fixture not inventoried")
	}
	for _, color := range []bool{false, true} {
		var out bytes.Buffer
		Text(&out, result, NewStyle(color), root, "test")
		if strings.ContainsAny(out.String(), "\r\x07\u202e") || strings.Contains(out.String(), "\x1b]52") {
			t.Fatalf("unsafe terminal output: %q", out.String())
		}
		if color && !strings.Contains(out.String(), "\x1b[") {
			t.Fatal("trusted ANSI styles were removed")
		}
	}
}
