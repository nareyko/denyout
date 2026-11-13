package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Event is schema_version 1 JSONL (D09).
type Event struct {
	SchemaVersion  int       `json:"schema_version"`
	EventID        string    `json:"event_id"`
	TS             string    `json:"ts"`
	SessionID      string    `json:"session_id"`
	AgentID        *string   `json:"agent_id"`
	Verdict        string    `json:"verdict"`
	Reasons        []string  `json:"reasons"`
	RuleID         *string   `json:"rule_id"`
	Mode           string    `json:"mode"`
	Inspection     string    `json:"inspection,omitempty"`
	Network        Network   `json:"network"`
	HTTP           *HTTPInfo `json:"http,omitempty"`
	Detectors      []string  `json:"detectors,omitempty"`
	BytesOut       int64     `json:"bytes_out"`
	LatencyMS      int64     `json:"latency_ms"`
	PolicyHash     string    `json:"policy_hash"`
	DenyOutVersion string    `json:"denyout_version"`
	WouldDeny      bool      `json:"would_deny,omitempty"`
}

// Network fields.
type Network struct {
	DestHost   string   `json:"dest_host"`
	DestPort   int      `json:"dest_port"`
	DestIPs    []string `json:"dest_ips,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
}

// HTTPInfo redacted HTTP metadata.
type HTTPInfo struct {
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	QueryRedacted string `json:"query_redacted,omitempty"`
}

// Sink writes JSONL events.
type Sink struct {
	mu      sync.Mutex
	path    string
	stdout  bool
	version string
	file    *os.File
}

// Open creates a sink. Empty path disables file output.
func Open(path string, stdout bool, version string) (*Sink, error) {
	s := &Sink{path: path, stdout: stdout, version: version}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		s.file = f
	}
	return s, nil
}

// Close closes the file.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// Log writes one event (fills id/ts/schema if empty).
func (s *Sink) Log(ev Event) error {
	if s == nil {
		return nil
	}
	ev.SchemaVersion = 1
	if ev.EventID == "" {
		ev.EventID = uuid.NewString()
	}
	if ev.TS == "" {
		ev.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.DenyOutVersion == "" {
		ev.DenyOutVersion = s.version
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line := append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		if _, err := s.file.Write(line); err != nil {
			return err
		}
	}
	if s.stdout {
		_, _ = os.Stdout.Write(line)
	}
	return nil
}

// ExpandPath replaces leading ~/ with home.
func ExpandPath(p string) string {
	if p == "" {
		return ""
	}
	if len(p) >= 2 && p[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

// DefaultDesktopPath returns XDG state audit path.
func DefaultDesktopPath() string {
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "denyout-audit.jsonl"
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(state, "denyout", "audit.jsonl")
}

// MustOpen is Open with stderr fallback message.
func MustOpen(path string, stdout bool, version string) *Sink {
	s, err := Open(path, stdout, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout: audit sink: %v (continuing without file)\n", err)
		s, _ = Open("", stdout, version)
	}
	return s
}
