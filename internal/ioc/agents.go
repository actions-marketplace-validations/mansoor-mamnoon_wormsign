package ioc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// ClaudeHooks inspects Claude Code settings files for hooks. Worms add
// SessionStart hooks to project .claude/settings.json so their payload runs
// every time someone opens the repo in Claude Code.
func ClaudeHooks(path string, projectLevel bool) []Finding {
	var s struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if readJSONC(path, &s) != nil {
		return nil
	}
	var out []Finding
	events := make([]string, 0, len(s.Hooks))
	for e := range s.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, group := range s.Hooks[event] {
			for _, h := range group.Hooks {
				if h.Command == "" {
					continue
				}
				reasons, sev := classify(h.Command)
				if sev == Info && !projectLevel {
					continue // the user's own global hooks, nothing odd about them
				}
				f := Finding{
					Severity: sev,
					Check:    "claude-hooks",
					Path:     path,
					Evidence: truncate(h.Command, 200),
					Fix:      "If you didn't add this hook, delete it and treat this machine's credentials as exposed.",
				}
				if sev == Info {
					// A committed hook that runs on every session is the exact
					// persistence trick worms use; it's worth a look even if clean.
					f.Severity = Warn
					f.Title = fmt.Sprintf("Repo-level Claude Code %s hook runs a command automatically", event)
					f.Fix = "Confirm a teammate added this on purpose (check git log for this file)."
				} else {
					f.Title = fmt.Sprintf("Claude Code %s hook %s", event, joinReasons(reasons))
				}
				out = append(out, f)
			}
		}
	}
	return out
}

// VSCodeTasks flags tasks that auto-run when a folder is opened. Worms inject
// these into .vscode/tasks.json so opening the repo re-infects the machine.
func VSCodeTasks(path string) []Finding {
	var s struct {
		Tasks []struct {
			Label      string                 `json:"label"`
			Command    string                 `json:"command"`
			Args       []any                  `json:"args"`
			RunOptions struct{ RunOn string } `json:"runOptions"`
		} `json:"tasks"`
	}
	if readJSONC(path, &s) != nil {
		return nil
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
			Evidence: truncate(strings.TrimSpace(cmd), 200),
			Fix:      "Remove the task (or its runOn: folderOpen) unless you added it deliberately.",
		}
		if len(reasons) > 0 {
			f.Title = fmt.Sprintf("VS Code task %q runs on folder open and %s", t.Label, joinReasons(reasons))
		} else {
			f.Title = fmt.Sprintf("VS Code task %q runs automatically when the folder is opened", t.Label)
		}
		out = append(out, f)
	}
	return out
}

// MCPServer is one configured MCP server.
type MCPServer struct {
	Name    string   `json:"name"`
	Client  string   `json:"client"`
	Path    string   `json:"path"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	URL     string   `json:"url,omitempty"`
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
	if readJSONC(path, &raw) != nil {
		return nil
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
	return out
}

var tomlServer = regexp.MustCompile(`^\[mcp_servers\.("?)([^"\]]+)("?)\]$`)

func readCodexTOML(path, client string) []MCPServer {
	f, err := os.Open(path)
	if err != nil {
		return nil
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
	return out
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
			Evidence: truncate(cmd, 200),
			Fix:      "If you don't recognise this server, remove it from the config and rotate the secrets it could reach.",
		})
	}
	return out
}
