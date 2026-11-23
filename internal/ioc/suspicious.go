package ioc

import (
	"net/url"
	"regexp"
	"strings"
)

// Behavioral matches need review; only campaign-specific indicators are strong.
var suspiciousRules = []struct {
	re     *regexp.Regexp
	reason string
	strong bool // a single match is enough to call it critical
}{
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*\|\s*(ba|z|da)?sh\b`), "pipes a download into a shell", false},
	{regexp.MustCompile(`(?i:\b(curl|wget|iwr|invoke-webrequest)\b).*(?:\s(?:-d|--data(?:-ascii|-binary|-raw|-urlencode)?|--upload-file|-F|-T)(?:[\s=]|$)|(?i:\bPOST\b))`), "uploads data to a remote server", false},
	{regexp.MustCompile(`(?i)base64\s+(-d|--decode|-D)\b|frombase64string|atob\(`), "decodes a base64 payload", false},
	{regexp.MustCompile(`(?i)\b(node|bun|deno)\s+(-e|--eval|-p)\b`), "runs inline JavaScript", false},
	{regexp.MustCompile(`(?i)\bpython3?\s+-c\b.*(exec|eval|urllib|socket|base64)`), "runs inline Python that fetches or evals", false},
	{regexp.MustCompile(`(?i)\beval\s*[\("$]`), "evals dynamic code", false},
	{regexp.MustCompile(`(?i)(^|[\s"'=])(/tmp/|/var/tmp/|/dev/shm/|\$TMPDIR|%TEMP%|/private/var/folders/)`), "runs something from a temp directory", false},
	{regexp.MustCompile(`(?i)\bnohup\b|\bdisown\b|\bsetsid\b|start-process.*-windowstyle\s+hidden`), "starts a hidden background process", false},
	{regexp.MustCompile(`(?i)\bgh\s+auth\s+token\b|\bnpm\s+token\b|_authToken|\.npmrc|\.git-credentials|\.aws/credentials|id_rsa|id_ed25519`), "reads credentials", false},
	{regexp.MustCompile(`(?i)\btrufflehog\b|truffler|truffleSecrets`), "runs a secret scanner", false},
	{regexp.MustCompile(`(?i)setup_bun\.js|bun_environment\.js|bun-dl-|tmp\.dpkg\.lock|gh-token-monitor`), "references a known worm file", true},
	{regexp.MustCompile(`(?i)\b(printenv|env)\s*(\||>)|process\.env\)|JSON\.stringify\(process\.env`), "dumps environment variables", false},
	{regexp.MustCompile(`(?i)\bchmod\s+\+x\b.*&&`), "makes a dropped file executable and runs it", false},
}

// Commands may contain either full URLs or bare hostnames.
func domainIndicators(cmd string) (service, campaign bool) {
	for _, word := range strings.FieldsFunc(cmd, func(r rune) bool {
		return strings.ContainsRune(" \t\r\n\"'()<>|`;", r)
	}) {
		if key, value, ok := strings.Cut(word, "="); ok && !strings.ContainsAny(key, "/:?") {
			word = value
		}
		if !strings.Contains(word, "://") {
			word = "//" + strings.TrimPrefix(word, "//")
		}
		u, err := url.Parse(word)
		if err != nil {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		for suffix := host; suffix != ""; {
			switch suffix {
			case "npm-cache.com", "pypi-get.com", "js-mirror.com":
				campaign = true
			case "webhook.site", "pipedream.net", "requestbin.com", "requestbin.net", "ngrok.io", "ngrok.app", "ngrok-free.io", "ngrok-free.app", "trycloudflare.com", "transfer.sh", "pastebin.com", "pastebin.ee", "paste.com", "paste.ee":
				service = true
			case "discord.com", "discordapp.com":
				service = service || strings.HasPrefix(u.Path, "/api/webhooks")
			case "api.telegram.org":
				service = service || strings.HasPrefix(u.Path, "/bot")
			}
			_, suffix, _ = strings.Cut(suffix, ".")
		}
	}
	return service, campaign
}

// Suspicious returns the reasons a command line looks malicious, if any.
func Suspicious(cmd string) []string {
	r, _ := classify(cmd)
	return r
}

// Generic behaviors can occur together in legitimate developer commands.
// Keep them at warning level even when several match.
func classify(cmd string) ([]string, Severity) {
	var reasons []string
	service, strong := domainIndicators(cmd)
	if service {
		reasons = append(reasons, "uses a service that can receive exfiltrated data")
	}
	if strong {
		reasons = append(reasons, "talks to a known worm C2 domain")
	}
	for _, r := range suspiciousRules {
		if r.re.MatchString(cmd) {
			reasons = append(reasons, r.reason)
			strong = strong || r.strong
		}
	}
	switch {
	case strong:
		return reasons, Critical
	case len(reasons) > 0:
		return reasons, Warn
	}
	return nil, Info
}

func joinReasons(r []string) string { return strings.Join(r, "; ") }
