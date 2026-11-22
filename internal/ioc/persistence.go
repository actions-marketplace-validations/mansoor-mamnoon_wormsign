package ioc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// LaunchItems inspects user-level autostart entries: macOS LaunchAgents,
// systemd user units, XDG autostart and crontab. ChainDrop, for example,
// installs a "gh-token-monitor" agent to keep stealing tokens after cleanup.
func LaunchItems(home string) []Finding {
	var files []string
	if runtime.GOOS == "darwin" {
		m, _ := filepath.Glob(filepath.Join(home, "Library/LaunchAgents/*.plist"))
		files = append(files, m...)
	}
	for _, g := range []string{".config/systemd/user/*.service", ".config/systemd/user/*.timer", ".config/autostart/*.desktop"} {
		m, _ := filepath.Glob(filepath.Join(home, g))
		files = append(files, m...)
	}
	var out []Finding
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		text := string(data)
		cmd := launchCommand(text)
		reasons, sev := classify(filepath.Base(f) + " " + cmd)
		// Hidden scripts merit review but are also used by developer tools.
		if sev == Info && hiddenScript.MatchString(cmd) {
			reasons, sev = []string{"runs a script from a hidden directory with node/bun/python"}, Warn
		}
		if sev == Info {
			continue
		}
		out = append(out, Finding{
			Severity: sev,
			Check:    "autostart",
			Title:    fmt.Sprintf("Autostart item %s %s", filepath.Base(f), joinReasons(reasons)),
			Path:     f,
			Command:  Redact(cmd),
			Fix:      "Unload it (launchctl bootout / systemctl --user disable), delete the file, then rotate credentials.",
		})
	}
	if c := crontab(); c != "" {
		for _, line := range strings.Split(c, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if reasons, sev := classify(line); sev != Info {
				out = append(out, Finding{
					Severity: sev, Check: "autostart", Path: "crontab",
					Title:   "crontab entry " + joinReasons(reasons),
					Command: Redact(line),
					Fix:     "Remove it with `crontab -e` if you didn't add it.",
				})
			}
		}
	}
	return out
}

var (
	plistString  = regexp.MustCompile(`<string>([^<]*)</string>`)
	execLine     = regexp.MustCompile(`(?m)^\s*(ExecStart|Exec)\s*=\s*(.+)$`)
	hiddenScript = regexp.MustCompile(`(?i)\b(node|bun|deno|python3?)\b\S*\s+\S*/\.[^/\s]+/\S+\.(js|mjs|cjs|ts|py)\b`)
)

func launchCommand(text string) string {
	if m := execLine.FindAllStringSubmatch(text, -1); m != nil {
		var parts []string
		for _, x := range m {
			parts = append(parts, x[2])
		}
		return strings.Join(parts, " ; ")
	}
	var parts []string
	for _, m := range plistString.FindAllStringSubmatch(text, -1) {
		parts = append(parts, m[1])
	}
	return strings.Join(parts, " ")
}

func crontab() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	if _, err := exec.LookPath("crontab"); err != nil {
		return ""
	}
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// ShellRC looks for payloads appended to shell startup files.
func ShellRC(home string) []Finding {
	var out []Finding
	for _, name := range []string{".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"} {
		path := filepath.Join(home, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			// Only strong indicators: rc files are full of legitimate
			// curl/eval lines (nvm, brew shellenv, starship, ...).
			reasons, sev := classify(t)
			if sev != Critical {
				continue
			}
			out = append(out, Finding{
				Severity: Critical, Check: "shell-rc",
				Title:   fmt.Sprintf("%s line %d %s", name, i+1, joinReasons(reasons)),
				Path:    path,
				Command: Redact(t),
				Fix:     "Delete the line if you didn't add it.",
			})
		}
	}
	return out
}
