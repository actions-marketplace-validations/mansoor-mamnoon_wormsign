package pkgs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ScanNodeModules reads every package.json under a node_modules directory,
// including scoped packages and nested node_modules.
func ScanNodeModules(dir string) []Package {
	var out []Package
	scanNodeModules(dir, &out, 0)
	return out
}

func scanNodeModules(dir string, out *[]Package, depth int) {
	if depth > 32 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == ".pnpm" && e.IsDir() {
			// pnpm keeps transitive packages in its virtual store, not
			// beneath each direct dependency's own node_modules.
			store := filepath.Join(dir, name)
			packages, _ := os.ReadDir(store)
			for _, p := range packages {
				if p.IsDir() {
					scanNodeModules(filepath.Join(store, p.Name(), "node_modules"), out, depth+1)
				}
			}
			continue
		}
		if strings.HasPrefix(name, ".") || !isDirish(dir, e) {
			continue
		}
		if strings.HasPrefix(name, "@") {
			scoped, _ := os.ReadDir(filepath.Join(dir, name))
			for _, s := range scoped {
				if isDirish(filepath.Join(dir, name), s) {
					readPkg(filepath.Join(dir, name, s.Name()), out, depth)
				}
			}
			continue
		}
		readPkg(filepath.Join(dir, name), out, depth)
	}
}

func isDirish(parent string, e os.DirEntry) bool {
	if e.IsDir() {
		return true
	}
	if e.Type()&os.ModeSymlink != 0 {
		fi, err := os.Stat(filepath.Join(parent, e.Name()))
		return err == nil && fi.IsDir()
	}
	return false
}

func readPkg(pkgDir string, out *[]Package, depth int) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err == nil {
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &pj) == nil && pj.Name != "" {
			*out = append(*out, Package{NPM, pj.Name, pj.Version})
		}
	}
	nested := filepath.Join(pkgDir, "node_modules")
	if fi, err := os.Stat(nested); err == nil && fi.IsDir() {
		scanNodeModules(nested, out, depth+1)
	}
}

// ScanSitePackages reads *.dist-info and *.egg-info directory names in a
// Python site-packages directory.
func ScanSitePackages(dir string) []Package {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Package
	for _, e := range entries {
		n := e.Name()
		var stem string
		switch {
		case strings.HasSuffix(n, ".dist-info"):
			stem = strings.TrimSuffix(n, ".dist-info")
		case strings.HasSuffix(n, ".egg-info"):
			stem = strings.TrimSuffix(n, ".egg-info")
			// name-1.0-py3.11.egg-info
			if i := strings.Index(stem, "-py"); i > 0 {
				stem = stem[:i]
			}
		default:
			continue
		}
		name, version, ok := strings.Cut(stem, "-")
		if !ok {
			continue
		}
		out = append(out, Package{PyPI, NormalizePyPI(name), version})
	}
	return out
}
