package ioc

import "regexp"

// redactions mask credential-shaped values in a command line before it is
// shown. Each pattern keeps the key or prefix that makes the line readable
// (--token, API_KEY=, ghp_) and replaces only the value.
var redactions = []struct {
	re   *regexp.Regexp
	repl string
}{
	// --token VALUE, --api-key=VALUE: any flag whose name mentions a secret
	{regexp.MustCompile(`(?i)(--?[\w-]*(?:token|secret|password|passwd|pass|key|auth|credential)[\w-]*)(?:=|\s+)("[^"]*"|'[^']*'|\S+)`), "$1 ***"},
	// TOKEN=value, export NPM_TOKEN=value
	{regexp.MustCompile(`(?i)\b([\w.]*(?:token|secret|password|passwd|key|auth|credential)[\w.]*)=("[^"]*"|'[^']*'|[^\s&"']+)`), "$1=***"},
	// Authorization: Bearer value
	{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)[^\s"']+`), "$1***"},
	// https://user:password@host
	{regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`), "$1***@"},
	// ?key=value&token=value in URLs
	{regexp.MustCompile(`(?i)([?&][\w-]*(?:token|secret|key|sig|auth|password)[\w-]*=)[^&\s"']+`), "$1***"},
	// Known token formats: GitHub, npm, OpenAI/Anthropic style, Slack, AWS
	{regexp.MustCompile(`\b(gh[pousr]_|github_pat_|npm_|sk-(?:ant-)?|xox[abpr]-)[A-Za-z0-9_-]{8,}`), "${1}***"},
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), "${1}***"},
	// Long random-looking strings (hex, base64, JWT segments)
	{regexp.MustCompile(`[A-Za-z0-9+/_=-]{40,}`), "***"},
}

// Redact masks credential-shaped values in a command line.
func Redact(cmd string) string {
	for _, r := range redactions {
		cmd = r.re.ReplaceAllString(cmd, r.repl)
	}
	return cmd
}
