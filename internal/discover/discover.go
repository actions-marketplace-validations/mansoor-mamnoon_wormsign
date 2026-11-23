// Package discover walks the filesystem once and collects everything the
// other checks need: lockfiles, installed package trees, and the editor/agent
// config files that worms use for persistence.
package discover

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
)

// Inventory is the result of a walk.
type Inventory struct {
	Sources     []pkgs.Source
	Configs     []string // project-level configs: .vscode/tasks.json, .claude/settings*.json, MCP files
	Workflows   []string // .github/workflows/*.yml
	NodeModules []string // every top-level node_modules dir found
	DirsWalked  int
	// Skipped lists directories that were not read: deeper than MaxDepth,
	// or unreadable (permission denied, removed during the walk). They are
	// coverage notes, not failures.
	Skipped []string
	Errors  []error
}

// Options controls the walk.
type Options struct {
	Context  context.Context
	Roots    []string
	MaxDepth int
	Progress *atomic.Int64 // incremented per directory, for a live counter
}

// skipNames are directories never worth descending into: caches, VCS
// internals, toolchains, and cloud-synced folders where reading a file can
// trigger a download.
var skipNames = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".Trash": true, ".cache": true,
	".npm": true, ".pnpm-store": true, ".yarn": true, ".bun": true, ".gradle": true, ".m2": true,
	".cargo": true, ".rustup": true, ".docker": true, ".colima": true, ".orbstack": true,
	".vscode-server": true, ".cursor-server": true, ".local": true, ".nvm": true, ".volta": true,
	".pyenv": true, ".rbenv": true, ".gem": true, ".android": true, ".gradle-cache": true,
	".ollama": true, ".lmstudio": true, ".huggingface": true, ".terraform": true, ".next": true,
	".nuxt": true, ".turbo": true, ".parcel-cache": true, ".svelte-kit": true, ".venv-cache": true,
	"__pycache__": true, ".mypy_cache": true, ".pytest_cache": true, ".ruff_cache": true, ".tox": true,
	"Library": true, "Applications": true, "Movies": true, "Music": true, "Pictures": true,
	"OneDrive": true, "Dropbox": true, "Google Drive": true, "Creative Cloud Files": true,
	"DerivedData": true, "Pods": true, "AppData": true, "scoop": true,
}

func skipDir(name string) bool {
	if skipNames[name] {
		return true
	}
	return strings.HasPrefix(name, "iCloud Drive") || strings.HasPrefix(name, "OneDrive")
}

// Walk scans every root.
func Walk(opt Options) *Inventory {
	if opt.Context == nil {
		opt.Context = context.Background()
	}
	if opt.MaxDepth == 0 {
		opt.MaxDepth = 14
	}
	inv := &Inventory{}
	seen := map[string]bool{}
	for _, root := range opt.Roots {
		// Resolve explicitly requested roots, but do not follow directory
		// symlinks encountered during traversal (which may form cycles).
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			inv.Errors = append(inv.Errors, err)
			continue
		}
		root = filepath.Clean(resolved)
		base := strings.Count(strings.TrimRight(root, string(os.PathSeparator)), string(os.PathSeparator))
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err := opt.Context.Err(); err != nil {
				return err
			}
			if err != nil {
				if path != root && (os.IsPermission(err) || os.IsNotExist(err)) {
					inv.Skipped = append(inv.Skipped, path)
				} else {
					inv.Errors = append(inv.Errors, err)
				}
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if path != root && skipDir(name) {
					return fs.SkipDir
				}
				// Agent plugin catalogs list plugins you *could* install;
				// their MCP configs aren't active on this machine.
				if name == "marketplaces" && filepath.Base(filepath.Dir(path)) == "plugins" ||
					name == ".tmp" && filepath.Base(filepath.Dir(path)) == ".codex" {
					return fs.SkipDir
				}
				if seen[path] {
					return fs.SkipDir
				}
				inv.DirsWalked++
				if opt.Progress != nil {
					opt.Progress.Add(1)
				}
				if strings.Count(path, string(os.PathSeparator))-base > opt.MaxDepth {
					inv.Skipped = append(inv.Skipped, path)
					return fs.SkipDir
				}
				// A depth-limited directory was not scanned and can still be
				// visited when explicitly supplied as a later root.
				seen[path] = true
				switch name {
				case "node_modules":
					inv.NodeModules = append(inv.NodeModules, path)
					return fs.SkipDir
				case "site-packages":
					inv.Sources = append(inv.Sources, pkgs.Source{Path: path, Kind: "site-packages", Packages: pkgs.ScanSitePackages(path)})
					return fs.SkipDir
				}
				return nil
			}
			inv.file(path, name, d.Type())
			return nil
		})
		if walkErr != nil {
			inv.Errors = append(inv.Errors, walkErr)
			break
		}
	}
	return inv
}

func (inv *Inventory) file(path, name string, mode fs.FileMode) {
	parent := filepath.Base(filepath.Dir(path))
	parse, kind := pkgs.ParserFor(path)
	config := parent == ".vscode" && (name == "tasks.json" || name == "mcp.json") ||
		parent == ".claude" && strings.HasPrefix(name, "settings") && strings.HasSuffix(name, ".json") ||
		parent == ".cursor" && name == "mcp.json" ||
		parent == ".devcontainer" && name == "devcontainer.json" ||
		name == ".devcontainer.json" ||
		name == ".mcp.json"
	workflow := parent == "workflows" && filepath.Base(filepath.Dir(filepath.Dir(path))) == ".github" &&
		(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml"))
	if !config && !workflow && parse == nil {
		return
	}
	if !mode.IsRegular() {
		inv.Errors = append(inv.Errors, fmt.Errorf("%s: scan input is not a regular file", path))
		return
	}
	if config {
		inv.Configs = append(inv.Configs, path)
		return
	}
	if workflow {
		inv.Workflows = append(inv.Workflows, path)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		inv.Errors = append(inv.Errors, err)
		return
	}
	ps, err := parse(data)
	if err != nil {
		inv.Errors = append(inv.Errors, &ParseError{path, err})
		return
	}
	inv.Sources = append(inv.Sources, pkgs.Source{Path: path, Kind: kind, Packages: ps})
}

// ParseError wraps a lockfile that could not be parsed.
type ParseError struct {
	Path string
	Err  error
}

func (e *ParseError) Error() string { return e.Path + ": " + e.Err.Error() }

// AddGlobals scans package managers' global install locations and caches,
// which live outside any project: npm -g, pnpm/bun globals, and the npx cache
// (where most MCP servers actually run from).
func (inv *Inventory) AddGlobals(home string) {
	var globs []string
	globs = append(globs,
		"/usr/local/lib/node_modules",
		"/opt/homebrew/lib/node_modules",
		"/usr/lib/node_modules",
		filepath.Join(home, ".nvm/versions/node/*/lib/node_modules"),
		filepath.Join(home, ".volta/tools/image/packages/*/lib/node_modules"),
		filepath.Join(home, ".npm-global/lib/node_modules"),
		filepath.Join(home, ".bun/install/global/node_modules"),
		filepath.Join(home, ".local/share/fnm/node-versions/*/installation/lib/node_modules"),
		filepath.Join(home, ".local/share/pnpm/global/*/node_modules"),
		filepath.Join(home, ".npm/_npx/*/node_modules"),
		filepath.Join(home, ".cache/pre-commit/*/node_env-*/lib/node_modules"),
	)
	if runtime.GOOS == "darwin" {
		globs = append(globs,
			filepath.Join(home, "Library/pnpm/global/*/node_modules"),
			filepath.Join(home, "Library/Application Support/fnm/node-versions/*/installation/lib/node_modules"),
		)
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		globs = append(globs, filepath.Join(appdata, "npm/node_modules"))
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				inv.Sources = append(inv.Sources, pkgs.Source{Path: m, Kind: "global", Packages: pkgs.ScanNodeModules(m)})
				inv.NodeModules = append(inv.NodeModules, m)
			}
		}
	}
	// User-level Python: pipx venvs and ~/.local site-packages.
	for _, g := range []string{
		filepath.Join(home, ".local/pipx/venvs/*/lib/python*/site-packages"),
		filepath.Join(home, ".local/share/pipx/venvs/*/lib/python*/site-packages"),
		filepath.Join(home, ".local/lib/python*/site-packages"),
		filepath.Join(home, ".local/share/uv/tools/*/lib/python*/site-packages"),
		filepath.Join(home, "Library/Python/*/lib/python/site-packages"),
	} {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			inv.Sources = append(inv.Sources, pkgs.Source{Path: m, Kind: "site-packages", Packages: pkgs.ScanSitePackages(m)})
		}
	}
}

// ScanProjectNodeModules reads installed packages in project node_modules
// dirs. Lockfiles usually cover these, but a node_modules without a lockfile
// (or one that drifted) is where a bad version hides.
func (inv *Inventory) ScanProjectNodeModules() {
	have := map[string]bool{}
	for _, s := range inv.Sources {
		have[s.Path] = true
	}
	for _, nm := range inv.NodeModules {
		if have[nm] {
			continue
		}
		inv.Sources = append(inv.Sources, pkgs.Source{Path: nm, Kind: "node_modules", Packages: pkgs.ScanNodeModules(nm)})
	}
}

// AllPackages returns every unique package across sources.
func (inv *Inventory) AllPackages() []pkgs.Package {
	var all []pkgs.Package
	for _, s := range inv.Sources {
		all = append(all, s.Packages...)
	}
	return pkgs.Dedupe(all)
}
