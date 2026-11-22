// Package demo materializes a harmless fake "infected" project so people can
// see what a wormsign detection looks like without being infected.
//
// The fixture is stored with renamed paths (dot-vscode, *.txt, ...) so that
// scanning a checkout of wormsign itself doesn't raise false alarms.
package demo

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mansoor-mamnoon/wormsign/internal/ioc"
)

//go:embed fixture
var fixture embed.FS

// Create writes the fixture to a fresh temp directory and returns its path.
func Create() (string, error) {
	dir, err := os.MkdirTemp("", "wormsign-demo-")
	if err != nil {
		return "", err
	}
	err = fs.WalkDir(fixture, "fixture", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fixture.ReadFile(path)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, "fixture/")
		dst := filepath.Join(dir, "acme-dashboard", realName(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	return dir, err
}

func realName(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, p := range parts {
		switch {
		case p == "dot-node_modules":
			parts[i] = "node_modules"
		case strings.HasPrefix(p, "dot-"):
			parts[i] = "." + strings.TrimPrefix(p, "dot-")
		}
	}
	last := len(parts) - 1
	parts[last] = strings.TrimSuffix(parts[last], ".txt")
	return filepath.Join(parts...)
}

// Credentials is a fixed, fake rotation list for the demo, so screenshots of
// --demo never show anything about the real machine.
func Credentials() []ioc.Credential {
	return []ioc.Credential{
		{Name: "npm token", Path: "~/.npmrc", Rotate: "npm token revoke <id> (npmjs.com, Access Tokens page), then `npm login`"},
		{Name: "GitHub CLI token", Path: "~/.config/gh/hosts.yml", Rotate: "Revoke GitHub CLI access at github.com/settings/applications, then authenticate again"},
		{Name: "AWS keys", Path: "~/.aws/credentials", Rotate: "Deactivate the access keys in IAM and issue new ones"},
		{Name: "SSH key id_ed25519", Path: "~/.ssh/id_ed25519", Rotate: "Generate a new key, replace it on GitHub/servers"},
		{Name: "Claude Code login", Path: "~/.claude/.credentials.json", Rotate: "`claude /logout`, then log in again"},
	}
}
