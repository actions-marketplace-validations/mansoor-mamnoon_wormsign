package ioc

import (
	"os"
	"path/filepath"
	"strings"
)

// payloadFiles are filenames worms drop into the root of an infected
// package. They have no legitimate reason to exist there.
var payloadFiles = map[string]string{
	"setup_bun.js":        "Shai-Hulud-family worm loader",
	"bun_environment.js":  "Shai-Hulud-family worm payload",
	"truffleSecrets.json": "Shai-Hulud stolen-secrets dump",
	"actionsSecrets.json": "Shai-Hulud stolen-secrets dump",
}

// NodeModulesPayloads looks for worm payload files in the root of every
// installed package. It reads directory listings only, never file contents.
func NodeModulesPayloads(nodeModules []string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	var visit func(dir string, depth int)
	visit = func(dir string, depth int) {
		if depth > 24 || seen[dir] {
			return
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if strings.HasPrefix(e.Name(), "@") {
				visit(p, depth) // scope dir holds packages directly
				continue
			}
			out = append(out, packagePayloads(p)...)
			if nested := filepath.Join(p, "node_modules"); isDir(nested) {
				visit(nested, depth+1)
			}
		}
	}
	for _, nm := range nodeModules {
		visit(nm, 0)
	}
	return out
}

func packagePayloads(pkgDir string) []Finding {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, e := range entries {
		what, ok := payloadFiles[e.Name()]
		if !ok {
			continue
		}
		out = append(out, Finding{
			Severity: Critical, Check: "payload-files",
			Title: what + " found inside an installed package",
			Path:  filepath.Join(pkgDir, e.Name()),
			Fix:   "Delete node_modules, reinstall from a clean lockfile, rotate credentials.",
		})
	}
	return out
}

// TempArtifacts checks for staging files and directories left in temp and
// home directories by known worms.
func TempArtifacts(home string) []Finding {
	tmp := os.TempDir()
	checks := []struct {
		glob, what string
		weak       bool // generic enough that something benign could create it
	}{
		{filepath.Join(tmp, "bun-dl-*"), "ChainDrop bun staging directory", true},
		{filepath.Join(tmp, "tmp.dpkg.lock"), "ChainDrop lock file", false},
		{filepath.Join(home, ".truffler-cache"), "Shai-Hulud 2.0 TruffleHog cache", false},
		{filepath.Join(home, ".dev-env/config.sh"), "Shai-Hulud 2.0 self-hosted GitHub runner install", false},
		{filepath.Join(home, ".config/gh-token-monitor*"), "ChainDrop token monitor", false},
		{filepath.Join(home, "Library/LaunchAgents/com.user.gh-token-monitor.plist"), "ChainDrop persistence agent", false},
		{filepath.Join(home, ".config/systemd/user/gh-token-monitor.service"), "ChainDrop persistence service", false},
		{"/tmp/inventory.txt", "s1ngularity exfil staging file", true},
	}
	var out []Finding
	for _, c := range checks {
		matches, _ := filepath.Glob(c.glob)
		for _, m := range matches {
			sev := Critical
			if c.weak {
				sev = Warn
			}
			out = append(out, Finding{
				Severity: sev, Check: "worm-artifacts",
				Title: c.what + " present", Path: m,
				Fix: "This machine likely ran the payload. Rotate credentials from a different, clean machine, then remove the file.",
			})
		}
	}
	return out
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
