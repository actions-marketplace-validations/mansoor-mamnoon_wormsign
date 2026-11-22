package ioc

import (
	"regexp"
	"strings"
)

// Indicator patterns seen across 2025–2026 npm/PyPI worms (Shai-Hulud,
// Mini Shai-Hulud, SANDWORM_MODE, ChainDrop, s1ngularity). They are
// deliberately behaviour-shaped rather than hash-shaped, so they keep working
// when the next campaign renames its files.
var suspiciousRules = []struct {
	re     *regexp.Regexp
	reason string
	strong bool // a single match is enough to call it critical
}{
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(ba|z|da)?sh\b`), "pipes a download into a shell", false},
	{regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest)\b.*\b(-d|--data|--upload-file|-F|-T|POST)\b`), "uploads data to a remote server", false},
	{regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)\b|frombase64string|atob\(`), "decodes a base64 payload", false},
	{regexp.MustCompile(`(?i)\b(node|bun|deno)\s+(-e|--eval|-p)\b`), "runs inline JavaScript", false},
	{regexp.MustCompile(`(?i)\bpython3?\s+-c\b.*(exec|eval|urllib|socket|base64)`), "runs inline Python that fetches or evals", false},
	{regexp.MustCompile(`(?i)\beval\s*[\("$]`), "evals dynamic code", false},
	{regexp.MustCompile(`(?i)(^|[\s"'=])(/tmp/|/var/tmp/|/dev/shm/|\$TMPDIR|%TEMP%|/private/var/folders/)`), "runs something from a temp directory", false},
	{regexp.MustCompile(`(?i)\bnohup\b|\bdisown\b|\bsetsid\b|start-process.*-windowstyle\s+hidden`), "detaches a hidden background process", false},
	{regexp.MustCompile(`(?i)\bgh\s+auth\s+token\b|\bnpm\s+token\b|_authToken|\.npmrc|\.git-credentials|\.aws/credentials|id_rsa|id_ed25519`), "reads credentials", false},
	{regexp.MustCompile(`(?i)\btrufflehog\b|truffler|truffleSecrets`), "runs a secret scanner (classic worm behaviour)", true},
	{regexp.MustCompile(`(?i)setup_bun\.js|bun_environment\.js|bun-dl-|tmp\.dpkg\.lock|gh-token-monitor`), "matches a known worm artifact name", true},
	{regexp.MustCompile(`(?i)webhook\.site|pipedream\.net|requestbin|ngrok(-free)?\.(io|app)|trycloudflare\.com|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|transfer\.sh|paste(bin)?\.(com|ee)`), "talks to a known exfiltration endpoint", true},
	{regexp.MustCompile(`(?i)npm-cache\.com|pypi-get\.com|js-mirror\.com`), "talks to a known worm C2 domain", true},
	{regexp.MustCompile(`(?i)\b(printenv|env)\s*(\||>)|process\.env\)|JSON\.stringify\(process\.env`), "dumps environment variables", false},
	{regexp.MustCompile(`(?i)\bchmod\s+\+x\b.*&&`), "makes a dropped file executable and runs it", false},
}

// Suspicious returns the reasons a command line looks malicious, if any.
func Suspicious(cmd string) []string {
	r, _ := classify(cmd)
	return r
}

// classify returns matched reasons and the severity they add up to: one
// strong indicator or two weak ones is critical, a single weak one a warning.
func classify(cmd string) ([]string, Severity) {
	var reasons []string
	strong := false
	for _, r := range suspiciousRules {
		if r.re.MatchString(cmd) {
			reasons = append(reasons, r.reason)
			strong = strong || r.strong
		}
	}
	switch {
	case strong || len(reasons) >= 2:
		return reasons, Critical
	case len(reasons) == 1:
		return reasons, Warn
	}
	return nil, Info
}

func joinReasons(r []string) string { return strings.Join(r, "; ") }
