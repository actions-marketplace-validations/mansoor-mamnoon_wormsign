package ioc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// devcontainerHooks are the lifecycle commands a dev container config runs
// without further confirmation. initializeCommand runs on the host when the
// folder is opened in a container, which makes it the riskiest of them.
var devcontainerHooks = []string{
	"initializeCommand", "onCreateCommand", "updateContentCommand",
	"postCreateCommand", "postStartCommand", "postAttachCommand",
}

// CheckDevcontainer flags lifecycle commands in .devcontainer/devcontainer.json
// or .devcontainer.json. Worms plant these so that opening a repository in a
// dev container runs their payload.
func CheckDevcontainer(path string) ([]Finding, error) {
	var cfg map[string]json.RawMessage
	if err := readJSONC(path, &cfg); err != nil {
		return nil, err
	}
	var out []Finding
	for _, hook := range devcontainerHooks {
		raw, ok := cfg[hook]
		if !ok {
			continue
		}
		cmd := devcontainerCommand(raw)
		if cmd == "" {
			continue
		}
		reasons, sev := classify(cmd)
		if sev == Info && hook != "initializeCommand" {
			continue // ordinary setup such as `npm ci` inside the container
		}
		f := Finding{
			Severity: max(sev, Warn),
			Check:    "devcontainer",
			Path:     path,
			Command:  Redact(cmd),
			Fix:      "If you did not add this command, remove it before opening the folder in a container.",
		}
		if len(reasons) > 0 {
			f.Title = fmt.Sprintf("Dev container %s %s", hook, joinReasons(reasons))
		} else {
			f.Title = "Dev container initializeCommand runs on the host when the folder is opened"
		}
		out = append(out, f)
	}
	return out, nil
}

// devcontainerCommand flattens the three accepted shapes of a lifecycle
// command: a string, an argv array, or an object of named commands.
func devcontainerCommand(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		return strings.TrimSpace(strings.Join(argv, " "))
	}
	var named map[string]json.RawMessage
	if json.Unmarshal(raw, &named) == nil {
		keys := make([]string, 0, len(named))
		for k := range named {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			if c := devcontainerCommand(named[k]); c != "" {
				parts = append(parts, c)
			}
		}
		return strings.Join(parts, " ; ")
	}
	return ""
}
