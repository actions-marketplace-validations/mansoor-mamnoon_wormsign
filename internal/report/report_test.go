package report

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/ioc"
	"github.com/mansoor-mamnoon/wormsign/internal/osv"
	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

func TestIncompleteReportDoesNotClaimClean(t *testing.T) {
	var out bytes.Buffer
	Text(&out, &scan.Result{ParseErrors: []string{"/project/package-lock.json: invalid JSON"}}, NewStyle(false), "", "test")
	text := out.String()
	if strings.Contains(text, "CLEAN") || strings.Contains(text, "Checked and clean") || !strings.Contains(text, "PARTIAL") || !strings.Contains(text, "package-lock.json") {
		t.Fatalf("misleading incomplete report:\n%s", text)
	}
}

func TestReportsOmitCommandsAndMCPURLs(t *testing.T) {
	root := t.TempDir()
	const token = "private-value-must-not-appear"
	files := map[string]string{
		".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node setup_bun.js --token ` + token + `"}]}]}}`,
		".vscode/tasks.json":    `{"tasks":[{"label":"init","command":"node setup_bun.js --token ` + token + `","runOptions":{"runOn":"folderOpen"}}]}`,
		".mcp.json":             `{"mcpServers":{"local":{"command":"node","args":["setup_bun.js","--token","` + token + `"]},"remote":{"url":"https://example.com/mcp?key=` + token + `"}}}`,
	}
	for rel, body := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	res := scan.Run(context.Background(), scan.Options{Roots: []string{root}, Home: root, Offline: true, ProjectOnly: true})
	if !res.Critical() || len(res.MCPServers) != 2 {
		t.Fatalf("fixture wasn't scanned: %+v", res)
	}
	var out bytes.Buffer
	Text(&out, res, NewStyle(false), root, "test")
	if err := JSON(&out, res); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, "--token", "example.com/mcp"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("reports leaked command or URL: %s", secret)
		}
	}
}

func TestVulnerabilitiesAreNotLabeledMalware(t *testing.T) {
	res := &scan.Result{OSVChecked: true, Hits: []scan.MalHit{{
		Package:    pkgs.Package{Ecosystem: pkgs.NPM, Name: "example", Version: "1.0.0"},
		Advisories: []osv.Advisory{{ID: "GHSA-example", Summary: "ordinary vulnerability"}},
	}}}
	var out bytes.Buffer
	Text(&out, res, NewStyle(false), "", "test")
	text := out.String()
	if !strings.Contains(text, "REVIEW") || !strings.Contains(text, "Vulnerable packages") || strings.Contains(text, "Malicious packages") || strings.Contains(text, "CLEAN") {
		t.Fatalf("misclassified vulnerability:\n%s", text)
	}
	if res.Critical() || !res.Warnings() || res.ExitCode(false) != 0 || res.ExitCode(true) != 1 {
		t.Fatalf("wrong vulnerability exit behavior: %+v", res)
	}
}

func TestOfflineDetectionDoesNotClaimConfirmedCompromise(t *testing.T) {
	res := &scan.Result{Packages: 1, Findings: []ioc.Finding{{Severity: ioc.Critical, Title: "known payload filename"}}}
	var out bytes.Buffer
	Text(&out, res, NewStyle(false), "", "test")
	text := out.String()
	if !strings.Contains(text, "DETECTED") || !strings.Contains(text, "Package lookup skipped") || strings.Contains(text, "COMPROMISED") {
		t.Fatalf("misleading detection report:\n%s", text)
	}
}

// The walker resolves a symlinked root, so paths can come back under the
// resolved home while the caller passes the unresolved one.
func TestTildeMatchesSymlinkedHome(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	res := &scan.Result{Findings: []ioc.Finding{{Severity: ioc.Critical, Check: "payload-files", Title: "x",
		Path: filepath.Join(resolved, "app", "setup_bun.js")}}}
	var out bytes.Buffer
	Text(&out, res, NewStyle(false), link, "test")
	if want := filepath.Join("~", "app", "setup_bun.js"); !strings.Contains(out.String(), want) {
		t.Fatalf("want %s in:\n%s", want, out.String())
	}
}

// Local reports show the redacted command so a person can recognize their own
// hook; JSON and project (CI) reports never carry it.
func TestCommandShownRedactedLocallyOnly(t *testing.T) {
	root := t.TempDir()
	const secret = "s3cr3t-value-must-not-appear"
	path := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node setup_bun.js --token ` + secret + `"}]}]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, project := range []bool{false, true} {
		res := scan.Run(context.Background(), scan.Options{Roots: []string{root}, Home: root, Offline: true, ProjectOnly: project, NoGlobals: true})
		var text, js bytes.Buffer
		Text(&text, res, NewStyle(false), root, "test")
		if err := JSON(&js, res); err != nil {
			t.Fatal(err)
		}
		all := text.String() + js.String()
		if strings.Contains(all, secret) {
			t.Fatalf("project=%v leaked the secret:\n%s", project, all)
		}
		if strings.Contains(js.String(), "setup_bun.js --token") {
			t.Fatalf("JSON carried the command:\n%s", js.String())
		}
		shown := strings.Contains(text.String(), "node setup_bun.js --token ***")
		if shown == project {
			t.Fatalf("project=%v: command shown=%v\n%s", project, shown, text.String())
		}
	}
}
