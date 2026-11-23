// Package scan runs every wormsign check and assembles the result.
package scan

import (
	"context"
	"fmt"
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
	// Stage, when set, holds a short description of the current phase for
	// a progress display.
	Stage *atomic.Value
	OSV   *osv.Client
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
	// HideCommands keeps redacted command lines out of the text report.
	// Project (CI) scans set it because job summaries can be public.
	HideCommands bool     `json:"-"`
	OSVError     string   `json:"osv_error,omitempty"`
	ScanErrors   []string `json:"scan_errors,omitempty"`
	// Skipped lists directories not read (depth limit or no permission). Any
	// skipped directory makes the result incomplete because it may contain evidence.
	Skipped     []string `json:"skipped_dirs,omitempty"`
	ParseErrors []string `json:"parse_errors,omitempty"`
}

// Malicious distinguishes malware from ordinary vulnerability advisories.
func (h MalHit) Malicious() bool {
	for _, a := range h.Advisories {
		if a.Malicious {
			return true
		}
	}
	return false
}

// Critical reports whether anything critical was found.
func (r *Result) Critical() bool {
	for _, h := range r.Hits {
		if h.Malicious() {
			return true
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
	for _, h := range r.Hits {
		if !h.Malicious() {
			return true
		}
	}
	for _, f := range r.Findings {
		if f.Severity == ioc.Warn {
			return true
		}
	}
	return false
}

// Incomplete reports failures that prevent a complete verdict.
func (r *Result) Incomplete() bool {
	return r.OSVError != "" || len(r.ParseErrors) > 0 || len(r.ScanErrors) > 0 || len(r.Skipped) > 0
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
		Workflows: len(inv.Workflows), Configs: len(inv.Configs), Skipped: inv.Skipped}
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
		opt.setStage(fmt.Sprintf("checking %d packages against OSV.dev", len(all)))
		c := opt.OSV
		if c == nil {
			c = osv.New()
		}
		c.IncludeVulns = opt.IncludeVulns
		hits, err := c.Check(ctx, all)
		res.Hits = locate(hits, inv.Sources)
		if err != nil {
			res.OSVError = err.Error()
		} else {
			res.OSVChecked = true
		}
	}

	// Coding agents and editors.
	opt.setStage("checking agent configs, workflows and autostart")
	globalClaude := map[string]bool{}
	var servers []ioc.MCPServer
	if machine {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			p := filepath.Join(opt.Home, ".claude", name)
			globalClaude[p] = true
			findings, err := ioc.CheckClaudeHooks(p, false)
			res.addConfigFindings(p, findings, err, true)
		}
		for path, client := range ioc.MCPConfigPaths(opt.Home) {
			found, err := ioc.CheckMCP(path, client)
			res.addConfigFindings(path, nil, err, true)
			servers = append(servers, found...)
		}
	}
	for _, p := range inv.Configs {
		dir, base := filepath.Base(filepath.Dir(p)), filepath.Base(p)
		switch {
		case dir == ".claude" && !globalClaude[p]:
			findings, err := ioc.CheckClaudeHooks(p, true)
			res.addConfigFindings(p, findings, err, false)
		case dir == ".vscode" && base == "tasks.json":
			findings, err := ioc.CheckVSCodeTasks(p)
			res.addConfigFindings(p, findings, err, false)
		case base == "devcontainer.json" || base == ".devcontainer.json":
			findings, err := ioc.CheckDevcontainer(p)
			res.addConfigFindings(p, findings, err, false)
		case base == ".mcp.json" || base == "mcp.json":
			found, err := ioc.CheckMCP(p, mcpOwner(p, opt.Home))
			res.addConfigFindings(p, nil, err, false)
			servers = append(servers, found...)
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
	res.HideCommands = opt.ProjectOnly

	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Severity > res.Findings[j].Severity })
	if err := ctx.Err(); err != nil && len(res.ScanErrors) == 0 {
		res.ScanErrors = append(res.ScanErrors, err.Error())
	}
	res.Duration = time.Since(start)
	return res
}

func (o Options) setStage(s string) {
	if o.Stage != nil {
		o.Stage.Store(s)
	}
}

func (r *Result) addConfigFindings(path string, findings []ioc.Finding, err error, optional bool) {
	r.Findings = append(r.Findings, findings...)
	if err != nil && !(optional && os.IsNotExist(err)) {
		r.ScanErrors = append(r.ScanErrors, fmt.Sprintf("Could not inspect %s: %v", path, err))
	}
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
