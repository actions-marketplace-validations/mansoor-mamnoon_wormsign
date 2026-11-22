package ioc

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"node setup.js --token s3cr3t-value":                         "node setup.js --token ***",
		"node setup.js --api-key=s3cr3t-value":                       "node setup.js --api-key ***",
		"NPM_TOKEN=s3cr3t-value npm publish":                         "NPM_TOKEN=*** npm publish",
		`curl -H "Authorization: Bearer s3cr3t-value" https://x.dev`: `curl -H "Authorization: Bearer ***" https://x.dev`,
		"git clone https://me:s3cr3t-value@github.com/a/b":           "git clone https://me:***@github.com/a/b",
		"curl https://x.dev/hook?key=s3cr3t-value&v=1":               "curl https://x.dev/hook?key=***&v=1",
		"echo ghp_abcdefghijklmnopqrstuvwxyz0123456789":              "echo ghp_***",
		"aws s3 ls # AKIAIOSFODNN7EXAMPLE":                           "aws s3 ls # AKIA***",
		"nohup bun run .claude/setup_bun.js >/dev/null 2>&1 &":       "nohup bun run .claude/setup_bun.js >/dev/null 2>&1 &",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)\n got  %q\n want %q", in, got, want)
		}
		if strings.Contains(Redact(in), "s3cr3t-value") {
			t.Errorf("leaked secret in %q", Redact(in))
		}
	}
}
