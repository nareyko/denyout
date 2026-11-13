package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// DefaultMaxBytes is the audit.jsonl size before rotation (~32 MiB).
const DefaultMaxBytes int64 = 32 << 20

// DefaultKeepRotated is how many rotated *.bak files to keep.
const DefaultKeepRotated = 3

// Sink writes JSONL events.
type Sink struct {
	mu       sync.Mutex
	path     string
	stdout   bool
	version  string
	file     *os.File
	maxBytes int64 // 0 → DefaultMaxBytes; <0 disables rotation
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

// SetMaxBytes overrides rotation threshold (bytes). Negative disables rotation.
func (s *Sink) SetMaxBytes(n int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.maxBytes = n
	s.mu.Unlock()
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
		s.maybeRotateLocked()
	}
	if s.stdout {
		_, _ = os.Stdout.Write(line)
	}
	return nil
}

// maybeRotateLocked rotates the file when over maxBytes. Caller holds s.mu.
func (s *Sink) maybeRotateLocked() {
	if s.file == nil || s.path == "" {
		return
	}
	max := s.maxBytes
	if max == 0 {
		max = DefaultMaxBytes
	}
	if max < 0 {
		return
	}
	fi, err := s.file.Stat()
	if err != nil || fi.Size() < max {
		return
	}
	_ = s.file.Close()
	s.file = nil
	rotated := s.path + "." + time.Now().UTC().Format("20060102T150405") + ".bak"
	if err := os.Rename(s.path, rotated); err != nil {
		// Re-open original path if rename failed.
		f, openErr := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr == nil {
			s.file = f
		}
		return
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	s.file = f
	pruneRotated(s.path, DefaultKeepRotated)
}

func pruneRotated(path string, keep int) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var baks []string
	prefix := base + "."
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".bak") {
			baks = append(baks, filepath.Join(dir, name))
		}
	}
	if len(baks) <= keep {
		return
	}
	// Lexicographic order matches timestamp suffix YYYYMMDDThhmmss.
	sort.Strings(baks)
	for _, old := range baks[:len(baks)-keep] {
		_ = os.Remove(old)
	}
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

// RecentDenials returns up to limit recent deny / would_deny events from a JSONL file (newest last).
func RecentDenials(path string, limit int) ([]Event, error) {
	return TailEvents(path, limit, true)
}

// TailEvents returns up to limit recent events (newest last). If denialsOnly, only deny / would_deny.
func TailEvents(path string, limit int, denialsOnly bool) ([]Event, error) {
	if path == "" || limit <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if denialsOnly && !(ev.Verdict == "deny" || ev.WouldDeny) {
			continue
		}
		all = append(all, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}
