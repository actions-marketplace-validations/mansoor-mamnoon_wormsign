package pkgs

import (
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"strings"
)

// ScanNodeModules reads every package.json under a node_modules directory,
// including scoped packages and nested node_modules.
func ScanNodeModules(dir string) []Package {
	var out []Package
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil
	}
	defer root.Close()
	scanNodeModules(root.FS(), ".", &out, 0)
	return out
}

func scanNodeModules(tree fs.FS, dir string, out *[]Package, depth int) {
	if depth > 32 {
		return
	}
	entries, err := fs.ReadDir(tree, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == ".pnpm" && e.IsDir() {
			// pnpm keeps transitive packages in its virtual store, not
			// beneath each direct dependency's own node_modules.
			store := path.Join(dir, name)
			packages, _ := fs.ReadDir(tree, store)
			for _, p := range packages {
				if p.IsDir() {
					scanNodeModules(tree, path.Join(store, p.Name(), "node_modules"), out, depth+1)
				}
			}
			continue
		}
		if strings.HasPrefix(name, ".") || !isDirish(tree, dir, e) {
			continue
		}
		if strings.HasPrefix(name, "@") {
			scoped, _ := fs.ReadDir(tree, path.Join(dir, name))
			for _, s := range scoped {
				if isDirish(tree, path.Join(dir, name), s) {
					readPkg(tree, path.Join(dir, name, s.Name()), out, depth)
				}
			}
			continue
		}
		readPkg(tree, path.Join(dir, name), out, depth)
	}
}

func isDirish(tree fs.FS, parent string, e os.DirEntry) bool {
	if e.IsDir() {
		return true
	}
	if e.Type()&os.ModeSymlink != 0 {
		fi, err := fs.Stat(tree, path.Join(parent, e.Name()))
		return err == nil && fi.IsDir()
	}
	return false
}

func readPkg(tree fs.FS, pkgDir string, out *[]Package, depth int) {
	manifest := path.Join(pkgDir, "package.json")
	if info, err := fs.Stat(tree, manifest); err == nil && info.Mode().IsRegular() {
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if data, err := fs.ReadFile(tree, manifest); err == nil && json.Unmarshal(data, &pj) == nil && pj.Name != "" {
			*out = append(*out, Package{NPM, pj.Name, pj.Version})
		}
	}

	nested := path.Join(pkgDir, "node_modules")
	if fi, err := fs.Stat(tree, nested); err == nil && fi.IsDir() {
		scanNodeModules(tree, nested, out, depth+1)
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
