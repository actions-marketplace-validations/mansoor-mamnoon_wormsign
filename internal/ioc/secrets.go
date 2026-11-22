package ioc

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Credential is a secret this machine holds that a worm would steal. Only
// presence is recorded: wormsign never reads values into its output.
type Credential struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Rotate string `json:"rotate"`
}

type credCheck struct {
	name, rel, rotate string
	// contains, when set, must appear in the file for it to count
	contains *regexp.Regexp
}

var credChecks = []credCheck{
	{"npm token", ".npmrc", "npm token revoke <id> (npmjs.com, Access Tokens page), then `npm login`", regexp.MustCompile(`_authToken|_auth\s*=`)},
	{"GitHub CLI token", ".config/gh/hosts.yml", "`gh auth refresh` or revoke at github.com/settings/applications", regexp.MustCompile(`oauth_token`)},
	{"git credential store", ".git-credentials", "Revoke the PATs at github.com/settings/tokens and delete the file", nil},
	{"AWS keys", ".aws/credentials", "Deactivate the access keys in IAM and issue new ones", regexp.MustCompile(`aws_secret_access_key`)},
	{"Google Cloud ADC", ".config/gcloud/application_default_credentials.json", "`gcloud auth application-default revoke` then log in again", nil},
	{"Azure CLI", ".azure/msal_token_cache.json", "`az logout` and revoke sessions in Entra ID", nil},
	{"Docker registry auth", ".docker/config.json", "`docker logout` each registry and rotate the tokens", regexp.MustCompile(`"auth"\s*:`)},
	{"Kubernetes config", ".kube/config", "Rotate cluster credentials / service-account tokens", regexp.MustCompile(`token:|client-key-data:`)},
	{"PyPI token", ".pypirc", "Revoke at pypi.org/manage/account/token/", regexp.MustCompile(`password`)},
	{".netrc", ".netrc", "Rotate every password listed in it", nil},
	{"Cargo registry token", ".cargo/credentials.toml", "Revoke at crates.io/settings/tokens", nil},
	{"Claude Code login", ".claude/.credentials.json", "`claude /logout`, then log in again", nil},
	{"Codex login", ".codex/auth.json", "Log out of Codex and revoke the API key", nil},
	{"Vercel token", ".vercel/auth.json", "Revoke at vercel.com/account/tokens", nil},
	{"Fly.io token", ".fly/config.yml", "`fly auth logout` and revoke tokens", regexp.MustCompile(`access_token`)},
	{"Terraform Cloud token", ".terraform.d/credentials.tfrc.json", "Revoke at app.terraform.io/app/settings/tokens", nil},
}

var secretEnv = regexp.MustCompile(`(?i)(TOKEN|SECRET|API_?KEY|PASSWORD|PRIVATE_KEY|ACCESS_KEY)`)

// Credentials inventories the secrets on this machine.
func Credentials(home string) []Credential {
	var out []Credential
	for _, c := range credChecks {
		p := filepath.Join(home, c.rel)
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		if c.contains != nil && !c.contains.Match(data) {
			continue
		}
		out = append(out, Credential{Name: c.name, Path: p, Rotate: c.rotate})
	}
	keys, _ := filepath.Glob(filepath.Join(home, ".ssh/id_*"))
	for _, k := range keys {
		if strings.HasSuffix(k, ".pub") {
			continue
		}
		out = append(out, Credential{Name: "SSH key " + filepath.Base(k), Path: k,
			Rotate: "Generate a new key, replace it on GitHub/servers, remove the old public key everywhere"})
	}
	var envs []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if secretEnv.MatchString(name) {
			envs = append(envs, name)
		}
	}
	sort.Strings(envs)
	if len(envs) > 0 {
		out = append(out, Credential{Name: "secret-looking env vars: " + strings.Join(envs, ", "), Path: "environment",
			Rotate: "Rotate each at its provider, and find where your shell sets them"})
	}
	return out
}
