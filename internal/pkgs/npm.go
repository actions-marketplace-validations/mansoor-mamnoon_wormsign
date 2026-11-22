package pkgs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// ParseNPMLock handles package-lock.json / npm-shrinkwrap.json v1, v2 and v3.
func ParseNPMLock(data []byte) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]npmV1Dep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for path, p := range lock.Packages {
		if path == "" || p.Link {
			continue
		}
		name := p.Name
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
			name = path[i+len("node_modules/"):]
		}
		if name == "" {
			continue
		}
		out = append(out, Package{NPM, name, p.Version})
	}
	if len(lock.Packages) == 0 {
		walkV1(lock.Dependencies, &out)
	}
	return out, nil
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func walkV1(deps map[string]npmV1Dep, out *[]Package) {
	for name, d := range deps {
		*out = append(*out, Package{NPM, name, d.Version})
		walkV1(d.Dependencies, out)
	}
}

// ParseYarnLock handles both Yarn classic (v1) and Berry (v2+) lockfiles.
func ParseYarnLock(data []byte) ([]Package, error) {
	var out []Package
	var name string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' {
			// Header: "@babel/core@^7.0.0", "@babel/core@npm:^7.1.0":
			name = ""
			spec := strings.TrimSuffix(line, ":")
			spec = strings.SplitN(spec, ",", 2)[0]
			spec = strings.Trim(strings.TrimSpace(spec), `"`)
			if len(spec) < 2 {
				continue
			}
			// Berry protocols: name@npm:range, name@patch:..., name@workspace:...
			at := strings.Index(spec[1:], "@")
			if at < 0 {
				continue
			}
			name = spec[:at+1]
			rest := spec[at+2:]
			if strings.HasPrefix(rest, "workspace:") || strings.HasPrefix(rest, "link:") || strings.HasPrefix(rest, "portal:") || strings.HasPrefix(rest, "file:") {
				name = ""
			}
			continue
		}
		if name == "" {
			continue
		}
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "version ") || strings.HasPrefix(t, "version:") {
			v := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "version"), ":"))
			v = strings.Trim(v, `"`)
			out = append(out, Package{NPM, name, v})
			name = ""
		}
	}
	return out, sc.Err()
}

var pnpmPeerSuffix = regexp.MustCompile(`\(.*$`)

// ParsePNPMLock handles pnpm lockfile v5 through v9 without a YAML dependency.
// Package keys look like:
//
//	v5:  /lodash/4.17.21:
//	v6:  /lodash@4.17.21:   /@scope/pkg@1.0.0(react@18.2.0):
//	v9:  lodash@4.17.21:    '@scope/pkg@1.0.0':
func ParsePNPMLock(data []byte) ([]Package, error) {
	var out []Package
	inSection := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			inSection = line == "packages:" || line == "snapshots:"
			continue
		}
		if !inSection || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		key := strings.TrimSuffix(strings.TrimSpace(line), ":")
		key = strings.Trim(key, `'"`)
		key = strings.TrimPrefix(key, "/")
		key = pnpmPeerSuffix.ReplaceAllString(key, "")
		if key == "" {
			continue
		}
		slashes := strings.Count(key, "/")
		v5 := (key[0] == '@' && slashes >= 2) || (key[0] != '@' && slashes >= 1)
		if v5 {
			// name/version or @scope/name/version, peers as _suffix
			i := strings.LastIndex(key, "/")
			v, _, _ := strings.Cut(key[i+1:], "_")
			out = append(out, Package{NPM, key[:i], v})
			continue
		}
		if n, v, ok := splitNameVersion(key); ok {
			out = append(out, Package{NPM, n, v})
		}
	}
	return out, sc.Err()
}

var bunEntry = regexp.MustCompile(`^\s*"[^"]+":\s*\[\s*"((?:@[^"@/]+/)?[^"@]+)@([^"]+)"`)

// ParseBunLock handles bun's text lockfile (bun.lock, JSONC). The binary
// bun.lockb format is not supported.
func ParseBunLock(data []byte) ([]Package, error) {
	var out []Package
	inPackages := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), `"packages"`) {
			inPackages = true
			continue
		}
		if !inPackages {
			continue
		}
		if m := bunEntry.FindStringSubmatch(line); m != nil {
			out = append(out, Package{NPM, m[1], m[2]})
		}
	}
	return out, sc.Err()
}
