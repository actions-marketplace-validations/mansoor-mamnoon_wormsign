// Package report renders scan results for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/mansoor-mamnoon/wormsign/internal/ioc"
	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

// Style holds ANSI codes; empty when color is off.
type Style struct{ red, yellow, green, dim, bold, reset styleCode }

// styleCode distinguishes trusted formatting from untrusted scanned strings.
type styleCode string

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

// groups names the finding categories for the "Checked and clean" line.
var groups = []struct {
	label  string
	checks []string
}{
	{"coding agents", []string{"claude-hooks", "mcp"}},
	{"editor tasks", []string{"vscode-tasks"}},
	{"CI workflows", []string{"workflows"}},
	{"autostart", []string{"autostart", "shell-rc"}},
	{"payload files", []string{"payload-files", "worm-artifacts"}},
}

// Text renders the human report: the verdict first, then what was found and
// where, then numbered steps.
func Text(w io.Writer, r *scan.Result, s Style, home, version string) {
	p := func(format string, a ...any) {
		for i, value := range a {
			if text, ok := value.(string); ok {
				a[i] = terminalText(text)
			}
		}
		fmt.Fprintf(w, format, a...)
	}
	// The walker resolves symlinked roots (macOS /var is /private/var), so
	// match home in both its given and resolved forms.
	homes := []string{home}
	if resolved, err := filepath.EvalSymlinks(home); err == nil && resolved != home {
		homes = append(homes, resolved)
	}
	tilde := func(path string) string {
		for _, h := range homes {
			if h != "" && (path == h || strings.HasPrefix(path, h+string(os.PathSeparator))) {
				return "~" + path[len(h):]
			}
		}
		return path
	}

	p("\n%swormsign%s %s%s  scanned %s packages, %s and %s in %s%s\n\n",
		s.bold, s.reset, s.dim, version, commas(r.Packages), count(r.Configs, "config"),
		count(r.Workflows, "workflow"), r.Duration.Round(100*time.Millisecond), s.reset)

	var crit, warns int
	for _, f := range r.Findings {
		switch f.Severity {
		case ioc.Critical:
			crit++
		case ioc.Warn:
			warns++
		}
	}

	traces := crit + warns
	malicious := 0
	for _, h := range r.Hits {
		if h.Malicious() {
			malicious++
		} else {
			warns++
		}
	}

	// 1. Verdict.
	switch {
	case r.Critical():
		p("  %s%s✗ DETECTED%s  %s\n\n", s.red, s.bold, s.reset, joinNonEmpty(
			countIf(malicious, "malicious package"), countIf(traces, "worm trace")))
	case r.Incomplete():
		p("  %s%s! PARTIAL%s  some checks failed; see scan limitations below\n\n", s.yellow, s.bold, s.reset)
	case warns > 0:
		p("  %s%s! REVIEW%s  %s to look at; see findings below\n\n", s.yellow, s.bold, s.reset, count(warns, "warning"))
	case !r.OSVChecked && r.Packages > 0:
		p("  %s%s! PARTIAL%s  no worm traces; packages not checked (--offline)\n\n", s.yellow, s.bold, s.reset)
	default:
		p("  %s%s✓ CLEAN%s  no known indicators found in the files checked\n\n", s.green, s.bold, s.reset)
	}

	if !r.OSVChecked && r.Packages > 0 && r.OSVError == "" {
		p("  Package lookup skipped (--offline); package versions were not checked.\n\n")
	}

	if r.Incomplete() {
		p("  %sScan limitations%s\n", s.bold, s.reset)
		if r.OSVError != "" {
			p("    Package lookup failed: %s\n", r.OSVError)
		}
		for _, err := range r.ParseErrors {
			p("    Could not parse %s\n", tilde(err))
		}
		for _, err := range r.ScanErrors {
			p("    %s\n", tilde(err))
		}
		p("\n")
	}

	for _, malware := range []bool{true, false} {
		heading := "Vulnerable packages"
		col := s.yellow
		if malware {
			heading, col = "Malicious packages", s.red
		}
		printed := false
		for _, h := range r.Hits {
			if h.Malicious() != malware {
				continue
			}
			if !printed {
				p("  %s%s%s\n", s.bold, heading, s.reset)
				printed = true
			}
			p("    %s%s%s\n", col+s.bold, h.Package.String(), s.reset)
			for _, a := range h.Advisories {
				p("      %s%s  %s%s\n", s.dim, a.ID, a.Summary, s.reset)
			}
			for i, loc := range h.Locations {
				if i == 3 {
					p("      %s... and %d more (see --json)%s\n", s.dim, len(h.Locations)-3, s.reset)
					break
				}
				p("      %s\n", tilde(loc))
			}
		}
		if printed {
			p("\n")
		}
	}

	// 3. Worm traces.
	if traces > 0 {
		heading := "Worm traces"
		if crit == 0 {
			heading = "Warnings"
		}
		p("  %s%s%s\n", s.bold, heading, s.reset)
		for _, f := range r.Findings {
			if f.Severity == ioc.Info {
				continue
			}
			col := s.red
			if f.Severity == ioc.Warn {
				col = s.yellow
			}
			p("    %s%s%s\n", col, f.Title, s.reset)
			if f.Path != "" {
				p("      %s\n", tilde(f.Path))
			}
			if f.Evidence != "" {
				p("      %s%s%s\n", s.dim, truncate(f.Evidence, 100), s.reset)
			}
			// The redacted command lets a person recognize their own hook or
			// task. CI runs (--project) leave it out: job summaries can be public.
			if f.Command != "" && !r.HideCommands {
				p("      %s%s%s\n", s.dim, truncate(f.Command, 100), s.reset)
			}
		}
		p("\n")
	}

	// 4. What was checked and came back clean.
	var clean []string
	if r.OSVChecked && len(r.Hits) == 0 {
		clean = append(clean, fmt.Sprintf("packages (%s lockfiles and installs)", commas(r.Sources)))
	}
	for _, g := range groups {
		if r.ProjectOnly && g.label == "autostart" {
			continue
		}
		found := false
		for _, f := range r.Findings {
			if f.Severity != ioc.Info && slices.Contains(g.checks, f.Check) {
				found = true
			}
		}
		if !found {
			clean = append(clean, g.label)
		}
	}
	if len(clean) > 0 && !r.Incomplete() {
		p("  %s✓%s %sNo matching indicators: %s%s\n\n", s.green, s.reset, s.dim, strings.Join(clean, ", "), s.reset)
	}

	if n := len(r.Skipped); n > 0 {
		p("  %sSkipped %s (too deep or not readable); listed in --json.%s\n\n", s.dim, count(n, "directory"), s.reset)
	}

	// 5. MCP inventory: injected servers are a recent worm trick, and only a
	// person knows which ones they installed.
	if len(r.MCPServers) > 0 {
		p("  %sMCP servers on this machine%s %s(check that you installed each one)%s\n", s.bold, s.reset, s.dim, s.reset)
		for i, m := range r.MCPServers {
			if i == 15 {
				p("    %s... and %d more (see --json)%s\n", s.dim, len(r.MCPServers)-15, s.reset)
				break
			}
			p("    %-15s %-24s %s%s%s\n", m.Client, truncate(m.Name, 24), s.dim, tilde(m.Path), s.reset)
		}
		p("\n")
	}

	// 6. Steps.
	var fixes []string
	for _, f := range r.Findings {
		if f.Severity != ioc.Info && f.Fix != "" && !slices.Contains(fixes, f.Fix) {
			fixes = append(fixes, f.Fix)
		}
	}
	if r.Critical() {
		p("  %sWhat to do now%s\n", s.bold, s.reset)
		p("    Confirm the finding before treating it as evidence that code ran.\n")
		if len(r.Credentials) == 0 {
			p("    1. If the payload ran, rotate the credentials it could access from a different machine.\n")
		} else {
			p("    1. If the payload ran, rotate these credentials from a %sdifferent machine%s:\n", s.bold, s.reset)
		}
		for _, c := range r.Credentials {
			p("         %-22s %s%s%s\n", truncate(c.Name, 22), s.dim, c.Rotate, s.reset)
		}
		step := 2
		if malicious > 0 {
			p("    %d. Delete the node_modules or virtualenv that holds each package above, and reinstall\n       from a lockfile that does not pin those versions.\n", step)
			step++
		}
		if traces > 0 {
			p("    %d. Remove each worm trace listed above, unless you added it yourself.\n", step)
			step++
		}
		for _, f := range r.Findings {
			if f.Check == "workflows" && f.Severity == ioc.Critical {
				p("    %d. Rotate the repository and organization secrets on GitHub; the workflow could read them.\n", step)
				break
			}
		}
		p("\n")
	} else if len(fixes) > 0 {
		p("  %sTo check%s\n", s.bold, s.reset)
		for i, fx := range fixes {
			p("    %d. %s\n", i+1, fx)
		}
		p("\n")
	}
}

func terminalText(text string) string {
	var out strings.Builder
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&out, "\\u%04x", r)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func countIf(n int, noun string) string {
	if n == 0 {
		return ""
	}
	return count(n, noun)
}

func joinNonEmpty(parts ...string) string {
	var out []string
	for _, x := range parts {
		if x != "" {
			out = append(out, x)
		}
	}
	return strings.Join(out, ", ")
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "y") {
		return fmt.Sprintf("%s %sies", commas(n), strings.TrimSuffix(noun, "y"))
	}
	return fmt.Sprintf("%s %ss", commas(n), noun)
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
	return string(r[:n-3]) + "..."
}
