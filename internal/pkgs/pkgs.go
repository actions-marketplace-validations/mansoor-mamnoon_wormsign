// Package pkgs extracts the exact (ecosystem, name, version) tuples that are
// installed or pinned on disk, from lockfiles and from installed package trees.
package pkgs

import (
	"path/filepath"
	"sort"
	"strings"
)

// Ecosystem names as used by OSV.dev.
const (
	NPM  = "npm"
	PyPI = "PyPI"
)

// Package is one resolved package version.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

func (p Package) Key() string { return p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version }

func (p Package) String() string { return p.Name + "@" + p.Version }

// Source is a file or directory that pins/installs packages.
type Source struct {
	Path     string    `json:"path"`
	Kind     string    `json:"kind"`
	Packages []Package `json:"-"`
}

// Parser parses a lockfile's bytes.
type Parser func(data []byte) ([]Package, error)

// ParserFor returns the parser for a filename, or nil if the file is not a
// lockfile wormsign understands.
func ParserFor(path string) (Parser, string) {
	base := filepath.Base(path)
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", ".package-lock.json":
		return ParseNPMLock, "npm"
	case "yarn.lock":
		return ParseYarnLock, "yarn"
	case "pnpm-lock.yaml":
		return ParsePNPMLock, "pnpm"
	case "bun.lock":
		return ParseBunLock, "bun"
	case "poetry.lock", "uv.lock", "pdm.lock":
		return ParseTOMLPackages, strings.TrimSuffix(base, ".lock")
	case "Pipfile.lock":
		return ParsePipfileLock, "pipenv"
	}
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return ParseRequirements, "pip"
	}
	return nil, ""
}

// validVersion filters out non-registry versions (git URLs, file: links,
// workspace placeholders) that can never match an advisory.
func validVersion(v string) bool {
	if v == "" || strings.ContainsAny(v, ":/ ") || strings.HasPrefix(v, "0.0.0-use.local") {
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}

// Dedupe returns packages sorted and unique.
func Dedupe(in []Package) []Package {
	seen := make(map[string]bool, len(in))
	out := make([]Package, 0, len(in))
	for _, p := range in {
		if !validVersion(p.Version) || p.Name == "" {
			continue
		}
		if k := p.Key(); !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// splitNameVersion splits "name@version" or "@scope/name@version".
func splitNameVersion(s string) (string, string, bool) {
	i := strings.LastIndex(s, "@")
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}
