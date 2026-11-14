package desktop

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed packs/*.yaml
var packsFS embed.FS

// AllowPack is a curated Book A allow fragment (DenyOut-maintained).
type AllowPack struct {
	ID string `yaml:"id" json:"id"`
	Version int `yaml:"version" json:"version"`
	Name string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Hosts []string `yaml:"hosts" json:"hosts"`
}

// AppliedPack tracks which pack hosts were added to a profile (for Undo pack).
type AppliedPack struct {
	ID string `yaml:"id" json:"id"`
	Version int `yaml:"version" json:"version"`
	Hosts []string `yaml:"hosts" json:"hosts"` // hosts this pack introduced
}

// ListAllowPacks returns embedded starter packs (sorted by id).
func ListAllowPacks() ([]AllowPack, error) {
	ents, err := packsFS.ReadDir("packs")
	if err != nil {
		return nil, err
	}
	var out []AllowPack
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := packsFS.ReadFile("packs/" + e.Name())
		if err != nil {
			return nil, err
		}
		var p AllowPack
		if err := yaml.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if p.ID == "" {
			return nil, fmt.Errorf("%s: missing id", e.Name())
		}
		if p.Version <= 0 {
			p.Version = 1
		}
		p.Hosts = normalizePackHosts(p.Hosts)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// LookupAllowPack returns one pack by id.
func LookupAllowPack(id string) (AllowPack, error) {
	id = strings.TrimSpace(id)
	packs, err := ListAllowPacks()
	if err != nil {
		return AllowPack{}, err
	}
	for _, p := range packs {
		if p.ID == id {
			return p, nil
		}
	}
	return AllowPack{}, fmt.Errorf("unknown pack %q", id)
}

func normalizePackHosts(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// SuggestPackID picks a starter pack from agent name/command (empty if unclear).
func SuggestPackID(name string, command []string) string {
	blob := strings.ToLower(name + " " + strings.Join(command, " "))
	switch {
	case strings.Contains(blob, "cursor"):
		return "cursor-starter"
	case strings.Contains(blob, "claude") || strings.Contains(blob, "anthropic"):
		return "claude-starter"
	default:
		return ""
	}
}

// ApplyPack merges pack hosts into ExtraAllow idempotently and records AppliedPacks.
// Only newly added hosts are owned for Undo. Returns hosts newly added this call.
func ApplyPack(p *AgentProfile, packID string) (added []string, err error) {
	pack, err := LookupAllowPack(packID)
	if err != nil {
		return nil, err
	}
	have := map[string]struct{}{}
	for _, h := range p.ExtraAllow {
		have[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	var newly []string
	for _, h := range pack.Hosts {
		if _, ok := have[h]; ok {
			continue
		}
		p.ExtraAllow = append(p.ExtraAllow, h)
		have[h] = struct{}{}
		newly = append(newly, h)
	}

	owned := map[string]struct{}{}
	var rest []AppliedPack
	had := false
	for _, ap := range p.AppliedPacks {
		if ap.ID == pack.ID {
			had = true
			for _, h := range ap.Hosts {
				owned[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
			}
			continue
		}
		rest = append(rest, ap)
	}
	for _, h := range newly {
		owned[h] = struct{}{}
	}
	if len(owned) == 0 {
		// Nothing to undo (all hosts already present, never owned).
		p.AppliedPacks = rest
		if had {
			// Keep empty ownership cleared; treat as idempotent no-op.
			return nil, nil
		}
		return nil, nil
	}
	var ownedList []string
	for h := range owned {
		ownedList = append(ownedList, h)
	}
	sort.Strings(ownedList)
	rest = append(rest, AppliedPack{ID: pack.ID, Version: pack.Version, Hosts: ownedList})
	sort.Slice(rest, func(i, j int) bool { return rest[i].ID < rest[j].ID })
	p.AppliedPacks = rest
	return newly, nil
}

// UndoPack removes hosts that pack introduced and drops the AppliedPacks entry.
func UndoPack(p *AgentProfile, packID string) (removed []string, err error) {
	packID = strings.TrimSpace(packID)
	var target *AppliedPack
	var rest []AppliedPack
	for i := range p.AppliedPacks {
		if p.AppliedPacks[i].ID == packID {
			cp := p.AppliedPacks[i]
			target = &cp
			continue
		}
		rest = append(rest, p.AppliedPacks[i])
	}
	if target == nil {
		return nil, fmt.Errorf("pack %q is not applied", packID)
	}
	drop := map[string]struct{}{}
	for _, h := range target.Hosts {
		drop[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	var keep []string
	for _, h := range p.ExtraAllow {
		key := strings.ToLower(strings.TrimSpace(h))
		if _, ok := drop[key]; ok {
			removed = append(removed, key)
			continue
		}
		keep = append(keep, h)
	}
	p.ExtraAllow = keep
	p.AppliedPacks = rest
	return removed, nil
}
