package desktop

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/nareyko/denyout/internal/policy"
)

// AgentProfile is a named wrap / optional Computer policy overlay.
type AgentProfile struct {
	ID string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
	Command []string `yaml:"command" json:"command"`
	WorkDir string `yaml:"workdir,omitempty" json:"workdir,omitempty"`
	Preset string `yaml:"preset" json:"preset"` // models | agent | none
	ExtraAllow []string `yaml:"extra_allow,omitempty" json:"extra_allow,omitempty"`
	PendingOnce []string `yaml:"pending_once,omitempty" json:"pending_once,omitempty"`
	AppliedPacks []AppliedPack `yaml:"applied_packs,omitempty" json:"applied_packs,omitempty"`
	AskMode bool `yaml:"ask_mode" json:"ask_mode"`
	Notify bool `yaml:"notify" json:"notify"`
	TLSMode string `yaml:"tls_mode,omitempty" json:"tls_mode,omitempty"`
	RequireIsolation bool `yaml:"require_isolation,omitempty" json:"require_isolation,omitempty"`
	Sandbox string `yaml:"sandbox,omitempty" json:"sandbox,omitempty"` // srt
	Learning Learning `yaml:"learning" json:"learning"`
}

// Learning tracks Once->Pin flow.
type Learning struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	StartedAt string `yaml:"started_at,omitempty" json:"started_at,omitempty"`
	DurationHours int `yaml:"duration_hours,omitempty" json:"duration_hours,omitempty"`
}

// NormalizeProfileName clamps display name.
func NormalizeProfileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Agent 1"
	}
	if utf8.RuneCountInString(name) > 40 {
		r := []rune(name)
		name = string(r[:40])
	}
	return name
}

// NewAgentProfile returns defaults (Agent+Cursor + learning on).
func NewAgentProfile(name string, command []string) AgentProfile {
	id := slugID(name)
	return AgentProfile{
		ID: id,
		Name: NormalizeProfileName(name),
		Command: command,
		Preset: "agent",
		AskMode: true,
		Notify: true,
		TLSMode: "intercept",
		Learning: Learning{Enabled: true, StartedAt: time.Now().UTC().Format(time.RFC3339), DurationHours: 24},
	}
}

func slugID(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = fmt.Sprintf("agent-%d", time.Now().Unix()%100000)
	}
	return out
}

func profilePath(id string) string {
	return filepath.Join(ProfilesDir(), id+".yaml")
}

// ListProfiles loads all profiles.
func ListProfiles() ([]AgentProfile, error) {
	dir := ProfilesDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []AgentProfile
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p, err := LoadProfile(strings.TrimSuffix(e.Name(), ".yaml"))
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// LoadProfile loads one profile by id.
func LoadProfile(id string) (AgentProfile, error) {
	b, err := os.ReadFile(profilePath(id))
	if err != nil {
		return AgentProfile{}, err
	}
	var p AgentProfile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return AgentProfile{}, err
	}
	if p.ID == "" {
		p.ID = id
	}
	return p, nil
}

// SaveProfile writes a profile.
func SaveProfile(p AgentProfile) error {
	p.Name = NormalizeProfileName(p.Name)
	if p.ID == "" {
		p.ID = slugID(p.Name)
	}
	if err := os.MkdirAll(ProfilesDir(), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(&p)
	if err != nil {
		return err
	}
	return os.WriteFile(profilePath(p.ID), b, 0o600)
}

// DeleteProfile removes a profile file.
func DeleteProfile(id string) error {
	return os.Remove(profilePath(id))
}

// AddPendingOnce records a Once host for Pin later.
func (p *AgentProfile) AddPendingOnce(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	for _, h := range p.PendingOnce {
		if strings.EqualFold(h, host) {
			return
		}
	}
	for _, h := range p.ExtraAllow {
		if strings.EqualFold(h, host) {
			return
		}
	}
	p.PendingOnce = append(p.PendingOnce, host)
}

// PinPending merges pending into extra_allow and clears pending.
func (p *AgentProfile) PinPending(hosts []string) {
	if len(hosts) == 0 {
		hosts = append([]string{}, p.PendingOnce...)
	}
	set := map[string]struct{}{}
	for _, h := range p.ExtraAllow {
		set[strings.ToLower(h)] = struct{}{}
	}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := set[h]; !ok {
			p.ExtraAllow = append(p.ExtraAllow, h)
			set[h] = struct{}{}
		}
	}
	// Remove pinned from pending.
	var left []string
	for _, h := range p.PendingOnce {
		if _, ok := set[strings.ToLower(h)]; !ok {
			left = append(left, h)
		}
	}
	p.PendingOnce = left
}

// DiscardPending clears pending Once hosts.
func (p *AgentProfile) DiscardPending() {
	p.PendingOnce = nil
}

// PolicyConfig builds a denyout Config for this wrap profile.
func (p AgentProfile) PolicyConfig() (*policy.Config, error) {
	preset := strings.TrimSpace(p.Preset)
	if preset == "" {
		preset = "agent"
	}
	hosts := append([]string{}, p.ExtraAllow...)
	hosts = append(hosts, p.PendingOnce...)
	var rules []policy.Rule
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h != "" {
			rules = append(rules, policy.Rule{Host: h, Reason: "profile"})
		}
	}
	switch preset {
	case "models":
		cfg, err := policy.DefaultEnforceModels()
		if err != nil {
			return nil, err
		}
		cfg.Allow = append(cfg.Allow, rules...)
		return cfg, nil
	case "none":
		minimal := []byte(`
apiVersion: denyout/v1
kind: Config
mode: enforce
preset: none
allow_private: false
allow_ip_literals: false
allowed_ports: [443, 80]
allow: []
deny: []
scanners:
 min_value_len: 6
 named_query:
 enabled: true
 canaries:
 - "DENYOUT_CANARY_"
 - "ARVISER_CANARY_"
`)
		cfg, err := policy.LoadBytes(minimal)
		if err != nil {
			return nil, err
		}
		cfg.Allow = append(cfg.Allow, rules...)
		return cfg, nil
	default: // agent
		if p.AskMode || len(rules) > 0 {
			return policy.DefaultWholeDeviceAsk(rules)
		}
		return policy.DefaultWholeDevice()
	}
}

// WriteTempConfig writes a denyout YAML for denyout run --config.
func (p AgentProfile) WriteTempConfig() (string, error) {
	cfg, err := p.PolicyConfig()
	if err != nil {
		return "", err
	}
	// Serialize via JSON round-trip is lossy; build minimal YAML from known fields.
	type rule struct {
		Host string `yaml:"host"`
		Reason string `yaml:"reason,omitempty"`
	}
	doc := map[string]any{
		"apiVersion": "denyout/v1",
		"kind": "Config",
		"mode": "enforce",
		"preset": p.Preset,
		"allow_private": false,
		"allow_ip_literals": false,
		"allowed_ports": []int{443, 80},
		"tls": map[string]any{"mode": "intercept", "session_ca": true},
		"scanners": map[string]any{
			"min_value_len": 6,
			"named_query": map[string]any{"enabled": true},
			"canaries": []string{"DENYOUT_CANARY_", "ARVISER_CANARY_"},
		},
	}
	if p.Preset == "" {
		doc["preset"] = "agent"
	}
	var allow []rule
	for _, r := range cfg.Allow {
		allow = append(allow, rule{Host: r.Host, Reason: r.Reason})
	}
	// Also ensure pending/extra present
	seen := map[string]struct{}{}
	for _, r := range allow {
		seen[strings.ToLower(r.Host)] = struct{}{}
	}
	for _, h := range append(append([]string{}, p.ExtraAllow...), p.PendingOnce...) {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, ok := seen[strings.ToLower(h)]; ok {
			continue
		}
		allow = append(allow, rule{Host: h, Reason: "profile"})
	}
	doc["allow"] = allow
	b, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(os.TempDir(), "denyout-profiles")
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, p.ID+".yaml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// CommandLine returns a short display string for the command.
func (p AgentProfile) CommandLine() string {
	if len(p.Command) == 0 {
		return ""
	}
	s := strings.Join(p.Command, " ")
	if utf8.RuneCountInString(s) > 48 {
		return string([]rune(s)[:45]) + "..."
	}
	return s
}

// MarshalJSON for tests/debug.
func (p AgentProfile) String() string {
	b, _ := json.Marshal(p)
	return string(b)
}
