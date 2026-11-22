// Package scan runs every wormsign check and assembles the result.
package scan

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mansoor-mamnoon/wormsign/internal/discover"
	"github.com/mansoor-mamnoon/wormsign/internal/ioc"
	"github.com/mansoor-mamnoon/wormsign/internal/osv"
	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
)

// Options for a scan.
type Options struct {
	Roots        []string
	Home         string
	Offline      bool
	IncludeVulns bool
	NoGlobals    bool
	// ProjectOnly scans only the given roots: no global installs, user-level
	// agent configs, autostart entries or credential inventory. For CI.
	ProjectOnly bool
	Progress    *atomic.Int64
	OSV         *osv.Client
}

// MalHit is a malicious package and everywhere it was found.
type MalHit struct {
	Package    pkgs.Package   `json:"package"`
	Advisories []osv.Advisory `json:"advisories"`
	Locations  []string       `json:"locations"`
}

// Result of a scan.
type Result struct {
	Roots       []string         `json:"roots"`
	Duration    time.Duration    `json:"duration_ns"`
	Sources     int              `json:"sources"`
	Packages    int              `json:"packages"`
	Dirs        int              `json:"dirs_walked"`
	Workflows   int              `json:"workflows"`
	Configs     int              `json:"configs"`
	Hits        []MalHit         `json:"malicious_packages"`
	Findings    []ioc.Finding    `json:"findings"`
	MCPServers  []ioc.MCPServer  `json:"mcp_servers"`
	Credentials []ioc.Credential `json:"credentials"`
	OSVChecked  bool             `json:"osv_checked"`
	ProjectOnly bool             `json:"project_only"`
	OSVError    string           `json:"osv_error,omitempty"`
	ScanErrors  []string         `json:"scan_errors,omitempty"`
	ParseErrors []string         `json:"parse_errors,omitempty"`
}

// Critical reports whether anything critical was found.
func (r *Result) Critical() bool {
	if len(r.Hits) > 0 {
		for _, h := range r.Hits {
			for _, a := range h.Advisories {
				if a.Malicious {
					return true
				}
			}
		}
	}
	for _, f := range r.Findings {
		if f.Severity == ioc.Critical {
			return true
		}
	}
	return false
}

// Warnings reports whether any warning-level finding exists.
func (r *Result) Warnings() bool {
	for _, f := range r.Findings {
		if f.Severity == ioc.Warn {
			return true
		}
	}
	return false
}

// Incomplete reports failures that prevent a complete verdict.
func (r *Result) Incomplete() bool {
	return r.OSVError != "" || len(r.ParseErrors) > 0 || len(r.ScanErrors) > 0
}

// ExitCode preserves critical detections even when another check fails.
func (r *Result) ExitCode(strict bool) int {
	if r.Critical() {
		return 1
	}
	if r.Incomplete() {
		return 2
	}
	if strict && r.Warnings() {
		return 1
	}
	return 0
}

// Run performs the scan.
func Run(ctx context.Context, opt Options) *Result {
	start := time.Now()
	inv := discover.Walk(discover.Options{Roots: opt.Roots, Progress: opt.Progress, Context: ctx})
	machine := !opt.ProjectOnly
	if machine && !opt.NoGlobals {
		inv.AddGlobals(opt.Home)
	}
	inv.ScanProjectNodeModules()

	res := &Result{Roots: opt.Roots, Dirs: inv.DirsWalked, Sources: len(inv.Sources),
		Workflows: len(inv.Workflows), Configs: len(inv.Configs)}
	for _, e := range inv.Errors {
		if pe, ok := e.(*discover.ParseError); ok {
			res.ParseErrors = append(res.ParseErrors, pe.Error())
		} else {
			res.ScanErrors = append(res.ScanErrors, e.Error())
		}
	}

	all := inv.AllPackages()
	res.Packages = len(all)

	if !opt.Offline && len(all) > 0 {
		c := opt.OSV
		if c == nil {
			c = osv.New()
		}
		c.IncludeVulns = opt.IncludeVulns
		hits, err := c.Check(ctx, all)
		if err != nil {
			res.OSVError = err.Error()
		} else {
			res.OSVChecked = true
			res.Hits = locate(hits, inv.Sources)
		}
	}

	// Coding agents and editors.
	globalClaude := map[string]bool{}
	var servers []ioc.MCPServer
	if machine {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			p := filepath.Join(opt.Home, ".claude", name)
			globalClaude[p] = true
			res.Findings = append(res.Findings, ioc.ClaudeHooks(p, false)...)
		}
		for path, client := range ioc.MCPConfigPaths(opt.Home) {
			servers = append(servers, ioc.ReadMCP(path, client)...)
		}
	}
	for _, p := range inv.Configs {
		dir, base := filepath.Base(filepath.Dir(p)), filepath.Base(p)
		switch {
		case dir == ".claude" && !globalClaude[p]:
			res.Findings = append(res.Findings, ioc.ClaudeHooks(p, true)...)
		case dir == ".vscode" && base == "tasks.json":
			res.Findings = append(res.Findings, ioc.VSCodeTasks(p)...)
		case base == ".mcp.json" || base == "mcp.json":
			servers = append(servers, ioc.ReadMCP(p, mcpOwner(p, opt.Home))...)
		}
	}
	servers = dedupeServers(servers)
	res.MCPServers = servers
	res.Findings = append(res.Findings, ioc.MCPFindings(servers)...)

	for _, w := range inv.Workflows {
		res.Findings = append(res.Findings, ioc.Workflow(w)...)
	}
	res.Findings = append(res.Findings, ioc.NodeModulesPayloads(inv.NodeModules)...)
	if machine {
		res.Findings = append(res.Findings, ioc.TempArtifacts(opt.Home)...)
		res.Findings = append(res.Findings, ioc.LaunchItems(opt.Home)...)
		res.Findings = append(res.Findings, ioc.ShellRC(opt.Home)...)
		res.Credentials = ioc.Credentials(opt.Home)
	}
	res.ProjectOnly = opt.ProjectOnly

	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Severity > res.Findings[j].Severity })
	if err := ctx.Err(); err != nil && len(res.ScanErrors) == 0 {
		res.ScanErrors = append(res.ScanErrors, err.Error())
	}
	res.Duration = time.Since(start)
	return res
}

func locate(hits []osv.Hit, sources []pkgs.Source) []MalHit {
	where := map[string][]string{}
	for _, s := range sources {
		for _, p := range s.Packages {
			k := p.Key()
			if l := where[k]; len(l) == 0 || l[len(l)-1] != s.Path {
				where[k] = append(where[k], s.Path)
			}
		}
	}
	out := make([]MalHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, MalHit{Package: h.Package, Advisories: h.Advisories, Locations: where[h.Package.Key()]})
	}
	return out
}

// mcpOwner names who a project-level MCP file belongs to: an installed
// agent plugin, or the project directory it sits in.
func mcpOwner(path, home string) string {
	dir := filepath.Dir(path)
	if b := filepath.Base(dir); b == ".cursor" || b == ".vscode" {
		dir = filepath.Dir(dir)
	}
	if strings.HasPrefix(path, filepath.Join(home, ".claude", "plugins")) {
		return "plugin " + filepath.Base(dir)
	}
	return "repo " + filepath.Base(dir)
}

func dedupeServers(in []ioc.MCPServer) []ioc.MCPServer {
	seen := map[string]bool{}
	var out []ioc.MCPServer
	for _, s := range in {
		k := s.Path + "\x00" + s.Name
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// DefaultRoots returns the directories scanned when none are given.
func DefaultRoots() ([]string, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return []string{home}, home
}
