// Package report renders scan results for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mansoor-mamnoon/wormsign/internal/ioc"
	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

// Style holds ANSI codes; empty when color is off.
type Style struct{ red, yellow, green, dim, bold, reset string }

func NewStyle(color bool) Style {
	if !color {
		return Style{}
	}
	return Style{"\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"}
}

// ColorEnabled decides whether to color output for f.
func ColorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") != "" {
		return true
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, r *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type section struct {
	label  string
	checks []string
	ok     string
}

var sections = []section{
	{"Coding agents", []string{"claude-hooks", "mcp"}, "no malicious hooks or MCP servers"},
	{"Editors", []string{"vscode-tasks"}, "no suspicious auto-run tasks"},
	{"CI workflows", []string{"workflows"}, "no backdoored workflows"},
	{"Autostart", []string{"autostart", "shell-rc"}, "launch agents, services, cron and shell rc clean"},
	{"Worm artifacts", []string{"payload-files", "worm-artifacts"}, "no known payload files"},
}

// Text renders the human report.
func Text(w io.Writer, r *scan.Result, s Style, home, version string) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	tilde := func(path string) string {
		if home != "" && strings.HasPrefix(path, home) {
			return "~" + path[len(home):]
		}
		return path
	}
	ok := s.green + "✓" + s.reset
	bad := s.red + "✗" + s.reset
	warn := s.yellow + "!" + s.reset

	p("\n%swormsign%s %s%s%s\n\n", s.bold, s.reset, s.dim, version, s.reset)

	// Packages.
	switch {
	case r.OSVError != "":
		p("  %s %-15s could not reach OSV.dev: %s\n", warn, "Packages", r.OSVError)
	case !r.OSVChecked && r.Packages > 0:
		p("  %s %-15s %s packages found, not checked (--offline)\n", warn, "Packages", commas(r.Packages))
	case len(r.Hits) == 0:
		p("  %s %-15s %s packages in %s lockfiles/installs — none known-malicious\n", ok, "Packages", commas(r.Packages), commas(r.Sources))
	default:
		p("  %s %s%-15s %d MALICIOUS%s of %s packages\n", bad, s.red+s.bold, "Packages", len(r.Hits), s.reset, commas(r.Packages))
		for _, h := range r.Hits {
			a := h.Advisories[0]
			sum := a.Summary
			if sum == "" {
				sum = "known malicious release"
			}
			p("      %s%s%s  %s  %s%s%s\n", s.bold, h.Package.String(), s.reset, a.ID, s.dim, sum, s.reset)
			for i, loc := range h.Locations {
				if i == 5 {
					p("        %s… and %d more%s\n", s.dim, len(h.Locations)-5, s.reset)
					break
				}
				p("        %s\n", tilde(loc))
			}
		}
	}

	// IOC sections.
	for _, sec := range sections {
		if r.ProjectOnly && sec.label == "Autostart" {
			continue
		}
		var fs []ioc.Finding
		for _, f := range r.Findings {
			for _, c := range sec.checks {
				if f.Check == c {
					fs = append(fs, f)
				}
			}
		}
		if len(fs) == 0 {
			p("  %s %-15s %s\n", ok, sec.label, s.dim+sec.ok+s.reset)
			continue
		}
		icon := warn
		for _, f := range fs {
			if f.Severity == ioc.Critical {
				icon = bad
			}
		}
		p("  %s %-15s %d finding(s)\n", icon, sec.label, len(fs))
		for _, f := range fs {
			col := s.yellow
			if f.Severity == ioc.Critical {
				col = s.red
			}
			p("      %s%s%s %s\n", col, strings.ToUpper(f.Severity.String()), s.reset, f.Title)
			if f.Path != "" {
				p("        %s\n", tilde(f.Path))
			}
			if f.Evidence != "" {
				p("        %s%s%s\n", s.dim, f.Evidence, s.reset)
			}
			if f.Fix != "" {
				p("        → %s\n", f.Fix)
			}
		}
	}

	// MCP inventory: injected servers are the newest worm trick, and only a
	// human knows which ones they installed.
	if len(r.MCPServers) > 0 {
		p("\n  %sMCP servers on this machine%s %s— do you recognise every one?%s\n", s.bold, s.reset, s.dim, s.reset)
		for i, m := range r.MCPServers {
			if i == 15 {
				p("    %s… and %d more (see --json)%s\n", s.dim, len(r.MCPServers)-15, s.reset)
				break
			}
			p("    %-15s %-24s %s%s%s\n", m.Client, truncate(m.Name, 24), s.dim, truncate(m.CommandLine(), 60), s.reset)
		}
	}

	// Verdict.
	p("\n")
	switch {
	case r.Critical():
		p("  %s%sLikely compromised.%s Assume every credential below was stolen.\n", s.red, s.bold, s.reset)
		p("  Rotate them from a %sdifferent, clean machine%s — the worm may still be watching this one.\n\n", s.bold, s.reset)
		for _, c := range r.Credentials {
			p("    %s•%s %-32s %s%s%s\n", s.red, s.reset, truncate(c.Name, 32), s.dim, c.Rotate, s.reset)
		}
	case r.Warnings():
		p("  %s%sNothing malicious found%s, but review the warnings above.\n", s.yellow, s.bold, s.reset)
	default:
		p("  %s%sNo signs of a supply-chain worm.%s\n", s.green, s.bold, s.reset)
	}
	if !r.Critical() && len(r.Credentials) > 0 {
		names := make([]string, 0, len(r.Credentials))
		for _, c := range r.Credentials {
			names = append(names, strings.SplitN(c.Name, ":", 2)[0])
		}
		p("  %sIf this ever changes, you'd need to rotate %d credentials: %s%s\n", s.dim, len(r.Credentials), truncate(strings.Join(names, ", "), 120), s.reset)
	}
	p("  %sScanned %s dirs, %d workflows, %d configs in %s%s\n\n", s.dim, commas(r.Dirs), r.Workflows, r.Configs, r.Duration.Round(100*time.Millisecond), s.reset)
}

func commas(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
