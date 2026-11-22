package ioc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// ClaudeHooks inspects Claude Code settings files for hooks. Worms add
// SessionStart hooks to project .claude/settings.json so their payload runs
// every time someone opens the repo in Claude Code.
func ClaudeHooks(path string, projectLevel bool) []Finding {
	findings, _ := CheckClaudeHooks(path, projectLevel)
	return findings
}

// CheckClaudeHooks inspects hooks and returns read or configuration errors.
func CheckClaudeHooks(path string, projectLevel bool) ([]Finding, error) {
	var s struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := readJSONC(path, &s); err != nil {
		return nil, err
	}
	events := make([]string, 0, len(s.Hooks))
	for e := range s.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)

	// One finding per file: suspicious hooks, then (for repo-level files)
	// clean SessionStart hooks, which are the exact persistence trick worms
	// use and worth a look even when the command looks harmless.
	type agg struct {
		sev     Severity
		events  []string
		reasons []string
		n       int
	}
	var bad, auto agg
	addUnique := func(list []string, items ...string) []string {
		for _, it := range items {
			if !slices.Contains(list, it) {
				list = append(list, it)
			}
		}
		return list
	}
	for _, event := range events {
		for _, group := range s.Hooks[event] {
			for _, h := range group.Hooks {
				if h.Command == "" {
					continue
				}
				reasons, sev := classify(h.Command)
				a := &bad
				if sev == Info {
					if !projectLevel || event != "SessionStart" {
						continue
					}
					a = &auto
				}
				a.n++
				a.sev = max(a.sev, sev)
				a.events = addUnique(a.events, event)
				a.reasons = addUnique(a.reasons, reasons...)
			}
		}
	}
	var out []Finding
	if bad.n > 0 {
		out = append(out, Finding{
			Severity: bad.sev, Check: "claude-hooks", Path: path,
			Title: fmt.Sprintf("Claude Code %s hook %s", strings.Join(bad.events, "/"), joinReasons(bad.reasons)),
			Fix:   "If you did not add this hook, delete it and treat this machine's credentials as stolen.",
		})
	}
	if auto.n > 0 {
		out = append(out, Finding{
			Severity: Warn, Check: "claude-hooks", Path: path,
			Title: "Repo-level Claude Code SessionStart hook runs a command every time the repo is opened",
			Fix:   "Confirm a teammate added this on purpose (git log -- .claude/settings.json).",
		})
	}
	return out, nil
}

// VSCodeTasks flags tasks that auto-run when a folder is opened. Worms inject
// these into .vscode/tasks.json so opening the repo re-infects the machine.
func VSCodeTasks(path string) []Finding {
	findings, _ := CheckVSCodeTasks(path)
	return findings
}

// CheckVSCodeTasks inspects automatic tasks and returns configuration errors.
func CheckVSCodeTasks(path string) ([]Finding, error) {
	var s struct {
		Tasks []struct {
			Label      string                 `json:"label"`
			Command    string                 `json:"command"`
			Args       []any                  `json:"args"`
			RunOptions struct{ RunOn string } `json:"runOptions"`
		} `json:"tasks"`
	}
	if err := readJSONC(path, &s); err != nil {
		return nil, err
	}
	var out []Finding
	for _, t := range s.Tasks {
		if !strings.EqualFold(t.RunOptions.RunOn, "folderOpen") {
			continue
		}
		cmd := t.Command
		for _, a := range t.Args {
			cmd += " " + fmt.Sprint(a)
		}
		reasons, sev := classify(cmd)
		f := Finding{
			Severity: max(sev, Warn),
			Check:    "vscode-tasks",
			Path:     path,
			Fix:      "If you did not add this task, delete it.",
		}
		if len(reasons) > 0 {
			f.Title = fmt.Sprintf("VS Code task %q runs on folder open and %s", t.Label, joinReasons(reasons))
		} else {
			f.Title = fmt.Sprintf("VS Code task %q runs automatically when the folder is opened", t.Label)
		}
		out = append(out, f)
	}
	return out, nil
}

// MCPServer is one configured MCP server.
type MCPServer struct {
	Name    string   `json:"name"`
	Client  string   `json:"client"`
	Path    string   `json:"path"`
	Command string   `json:"-"`
	Args    []string `json:"-"`
	URL     string   `json:"-"`
}

func (m MCPServer) CommandLine() string {
	if m.URL != "" {
		return m.URL
	}
	return strings.TrimSpace(m.Command + " " + strings.Join(m.Args, " "))
}

type mcpEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
	HTTPURL string   `json:"httpUrl"`
	Type    string   `json:"type"`
}

// MCPConfigPaths are the global config files of every popular MCP client.
func MCPConfigPaths(home string) map[string]string {
	p := map[string]string{
		filepath.Join(home, ".claude.json"):                              "Claude Code",
		filepath.Join(home, ".cursor/mcp.json"):                          "Cursor",
		filepath.Join(home, ".codeium/windsurf/mcp_config.json"):         "Windsurf",
		filepath.Join(home, ".gemini/settings.json"):                     "Gemini CLI",
		filepath.Join(home, ".codex/config.toml"):                        "Codex",
		filepath.Join(home, ".config/opencode/opencode.json"):            "opencode",
		filepath.Join(home, ".continue/config.json"):                     "Continue",
		filepath.Join(home, ".config/zed/settings.json"):                 "Zed",
		filepath.Join(home, ".kiro/settings/mcp.json"):                   "Kiro",
		filepath.Join(home, ".aws/amazonq/mcp.json"):                     "Amazon Q",
		filepath.Join(home, ".config/Code/User/mcp.json"):                "VS Code",
		filepath.Join(home, ".config/Claude/claude_desktop_config.json"): "Claude Desktop",
	}
	if runtime.GOOS == "darwin" {
		as := filepath.Join(home, "Library/Application Support")
		p[filepath.Join(as, "Claude/claude_desktop_config.json")] = "Claude Desktop"
		p[filepath.Join(as, "Code/User/mcp.json")] = "VS Code"
		p[filepath.Join(as, "Code/User/settings.json")] = "VS Code"
		p[filepath.Join(as, "Cursor/User/settings.json")] = "Cursor"
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		p[filepath.Join(appdata, "Claude/claude_desktop_config.json")] = "Claude Desktop"
		p[filepath.Join(appdata, "Code/User/mcp.json")] = "VS Code"
	}
	return p
}

// ReadMCP returns the servers declared in one MCP config file.
func ReadMCP(path, client string) []MCPServer {
	servers, _ := CheckMCP(path, client)
	return servers
}

// CheckMCP inventories servers and returns read or configuration errors.
func CheckMCP(path, client string) ([]MCPServer, error) {
	if strings.HasSuffix(path, ".toml") {
		return readCodexTOML(path, client)
	}
	var raw struct {
		MCPServers map[string]mcpEntry `json:"mcpServers"`
		Servers    map[string]mcpEntry `json:"servers"`
		MCP        struct {
			Servers map[string]mcpEntry `json:"servers"`
		} `json:"mcp"`
		ContextServers map[string]struct {
			Command mcpEntry `json:"command"`
		} `json:"context_servers"`
		Projects map[string]struct {
			MCPServers map[string]mcpEntry `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := readJSONC(path, &raw); err != nil {
		return nil, err
	}
	var out []MCPServer
	add := func(m map[string]mcpEntry, scope string) {
		for name, e := range m {
			if scope != "" {
				name = name + " (" + scope + ")"
			}
			url := e.URL
			if url == "" {
				url = e.HTTPURL
			}
			out = append(out, MCPServer{Name: name, Client: client, Path: path, Command: e.Command, Args: e.Args, URL: url})
		}
	}
	add(raw.MCPServers, "")
	add(raw.Servers, "")
	add(raw.MCP.Servers, "")
	for name, cs := range raw.ContextServers {
		add(map[string]mcpEntry{name: cs.Command}, "")
	}
	for proj, p := range raw.Projects {
		add(p.MCPServers, filepath.Base(proj))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var tomlServer = regexp.MustCompile(`^\[mcp_servers\.("?)([^"\]]+)("?)\]$`)

func readCodexTOML(path, client string) ([]MCPServer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []MCPServer
	var cur *MCPServer
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			cur = nil
			if m := tomlServer.FindStringSubmatch(line); m != nil && !strings.Contains(m[2], ".") {
				out = append(out, MCPServer{Name: m[2], Client: client, Path: path})
				cur = &out[len(out)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "command":
			cur.Command = strings.Trim(v, `"'`)
		case "url":
			cur.URL = strings.Trim(v, `"'`)
		case "args":
			for _, a := range strings.Split(strings.Trim(v, "[]"), ",") {
				if a = strings.Trim(strings.TrimSpace(a), `"'`); a != "" {
					cur.Args = append(cur.Args, a)
				}
			}
		}
	}
	return out, sc.Err()
}

// MCPFindings flags MCP servers whose launch command looks malicious. A
// worm-injected MCP server runs with full access every time the agent starts.
func MCPFindings(servers []MCPServer) []Finding {
	var out []Finding
	for _, s := range servers {
		cmd := s.CommandLine()
		reasons, sev := classify(cmd)
		if sev == Info {
			continue
		}
		out = append(out, Finding{
			Severity: sev,
			Check:    "mcp",
			Title:    fmt.Sprintf("%s MCP server %q %s", s.Client, s.Name, joinReasons(reasons)),
			Path:     s.Path,
			Fix:      "If you did not install this server, remove it from the config and rotate the secrets it could reach.",
		})
	}
	return out
}
