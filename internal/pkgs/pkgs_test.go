package pkgs

import (
	"reflect"
	"testing"
)

func names(ps []Package) []string {
	var out []string
	for _, p := range Dedupe(ps) {
		out = append(out, p.String())
	}
	return out
}

func check(t *testing.T, p Parser, in string, want ...string) {
	t.Helper()
	got, err := p([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if g := names(got); !reflect.DeepEqual(g, want) {
		t.Errorf("got  %q\nwant %q", g, want)
	}
}

func TestNPMLockV3(t *testing.T) {
	check(t, ParseNPMLock, `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/keyv": {"version": "6.0.0"},
    "node_modules/@scope/pkg": {"version": "2.1.0"},
    "node_modules/a/node_modules/b": {"version": "0.1.0"},
    "packages/local": {"version": "0.0.1", "link": true},
    "node_modules/gitdep": {"version": "git+ssh://git@github.com/x/y.git#abc"}
  }}`, "@scope/pkg@2.1.0", "b@0.1.0", "keyv@6.0.0")
}

func TestNPMLockV1(t *testing.T) {
	check(t, ParseNPMLock, `{"lockfileVersion": 1, "dependencies": {
	  "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}`,
		"a@1.0.0", "b@2.0.0")
}

func TestYarnClassic(t *testing.T) {
	check(t, ParseYarnLock, `# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.1.2"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.1.2.tgz"

lodash@^4.17.0:
  version "4.17.21"
`, "@babel/core@7.1.2", "lodash@4.17.21")
}

func TestYarnBerry(t *testing.T) {
	check(t, ParseYarnLock, `__metadata:
  version: 6

"@scope/pkg@npm:^1.0.0":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"

"app@workspace:.":
  version: 0.0.0-use.local

"left-pad@npm:1.3.0, left-pad@npm:^1.3.0":
  version: 1.3.0
`, "@scope/pkg@1.2.3", "left-pad@1.3.0")
}

func TestPNPM(t *testing.T) {
	v5 := `lockfileVersion: 5.4
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
  /@scope/pkg/1.0.0_react@18.2.0:
    dev: false
`
	check(t, ParsePNPMLock, v5, "@scope/pkg@1.0.0", "lodash@4.17.21")

	v6 := `lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-x}
  /@scope/pkg@1.0.0(react@18.2.0):
    dev: false
  /my_pkg@2.0.0:
    dev: false
`
	check(t, ParsePNPMLock, v6, "@scope/pkg@1.0.0", "lodash@4.17.21", "my_pkg@2.0.0")

	v9 := `lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-x}
  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-y}
snapshots:
  '@scope/pkg@1.0.0(react@18.2.0)':
    dependencies:
      react: 18.2.0
`
	check(t, ParsePNPMLock, v9, "@scope/pkg@1.0.0", "lodash@4.17.21")
}

func TestBun(t *testing.T) {
	check(t, ParseBunLock, `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "keyv": "^6" } } },
  "packages": {
    "keyv": ["keyv@6.0.0", "", { "dependencies": {} }, "sha512-x"],
    "@scope/pkg": ["@scope/pkg@1.0.0", "", {}, "sha512-y"],
    "app": ["app@workspace:."],
  }
}`, "@scope/pkg@1.0.0", "keyv@6.0.0")
}

func TestRequirements(t *testing.T) {
	check(t, ParseRequirements, `# comment
Requests==2.31.0
urllib3[socks]==2.0.7 ; python_version > "3.8"
flask>=2
-e git+https://github.com/x/y.git#egg=y
Django_Rest.framework===3.14.0
`, "django-rest-framework@3.14.0", "requests@2.31.0", "urllib3@2.0.7")
}

func TestTOMLLocks(t *testing.T) {
	check(t, ParseTOMLPackages, `version = 1

[[package]]
name = "Requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]

[package.optional-dependencies]
socks = [{ name = "pysocks" }]

[[package]]
name = "idna"
version = "3.6"

[metadata]
lock-version = "2.0"
`, "idna@3.6", "requests@2.31.0")
}

func TestPipfileLock(t *testing.T) {
	check(t, ParsePipfileLock, `{"_meta": {"hash": {}}, "default": {"requests": {"version": "==2.31.0"}},
	  "develop": {"pytest": {"version": "==8.0.0"}}}`, "pytest@8.0.0", "requests@2.31.0")
}

func TestParserFor(t *testing.T) {
	for path, kind := range map[string]string{
		"/x/package-lock.json": "npm", "/x/requirements-dev.txt": "pip", "/x/uv.lock": "uv",
		"/x/pnpm-lock.yaml": "pnpm", "/x/README.md": "",
	} {
		if _, k := ParserFor(path); k != kind {
			t.Errorf("%s: got %q want %q", path, k, kind)
		}
	}
}
