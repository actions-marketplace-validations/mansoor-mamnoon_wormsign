// Package ioc looks for the things supply-chain worms leave behind once they
// run: persistence hooks in editors and coding agents, injected MCP servers,
// backdoored CI workflows, launch agents, and dropped payload files.
package ioc

// Severity of a finding.
type Severity int

const (
	Info Severity = iota
	Warn
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case Warn:
		return "warning"
	}
	return "info"
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Finding is one thing worth a human's attention.
type Finding struct {
	Severity Severity `json:"severity"`
	Check    string   `json:"check"`
	Title    string   `json:"title"`
	Path     string   `json:"path,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Fix      string   `json:"fix,omitempty"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
