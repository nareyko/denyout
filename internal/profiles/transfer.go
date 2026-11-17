package profiles

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxImportBytes caps an imported profile file.
const MaxImportBytes = 256 << 10

var importHostRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)

// validAllowEntry accepts a DNS name or a "*.name" wildcard that still has at
// least two labels after the star (so "*", "*.com", IP literals, URLs and
// ports are rejected).
func validAllowEntry(h string) bool {
	h = strings.TrimSpace(h)
	if len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	h = strings.TrimPrefix(h, "*.")
	return importHostRE.MatchString(h)
}

// ValidateImport checks a profile that comes from outside the UI (a file the
// user was handed). It enforces that an imported profile cannot do anything the
// desktop UI would not let the user create: no TLS passthrough (which would
// switch off body/secret scanning), no unknown presets or sandboxes, no
// wildcard-everything allow entries, and sane sizes. The profile id is
// validated separately by the caller-supplied id.
func ValidateImport(p AgentProfile) error {
	if len(p.Command) == 0 || len(p.Command) > 64 {
		return fmt.Errorf("command: need 1-64 arguments")
	}
	for _, a := range p.Command {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return fmt.Errorf("command: argument too long or contains NUL")
		}
	}
	if strings.ContainsRune(p.WorkDir, 0) || len(p.WorkDir) > 4096 {
		return fmt.Errorf("workdir: invalid")
	}
	switch p.Preset {
	case "", "agent", "models":
	default:
		return fmt.Errorf("preset %q: imports may only use agent or models", p.Preset)
	}
	switch p.TLSMode {
	case "", "intercept":
	default:
		return fmt.Errorf("tls_mode %q: only intercept is allowed (passthrough disables scanning)", p.TLSMode)
	}
	switch p.Sandbox {
	case "", "srt":
	default:
		return fmt.Errorf("sandbox %q: only srt is allowed", p.Sandbox)
	}
	for _, list := range []struct {
		name string
		v    []string
	}{{"extra_allow", p.ExtraAllow}, {"pending_once", p.PendingOnce}} {
		if len(list.v) > 500 {
			return fmt.Errorf("%s: more than 500 entries", list.name)
		}
		for _, h := range list.v {
			if !validAllowEntry(h) {
				return fmt.Errorf("%s: %q is not an allowed host entry", list.name, h)
			}
		}
	}
	if len(p.AppliedPacks) > 50 {
		return fmt.Errorf("applied_packs: too many entries")
	}
	for _, ap := range p.AppliedPacks {
		for _, h := range ap.Hosts {
			if !validAllowEntry(h) {
				return fmt.Errorf("applied_packs %q: %q is not an allowed host entry", ap.ID, h)
			}
		}
	}
	if p.Learning.DurationHours < 0 || p.Learning.DurationHours > 24*365 {
		return fmt.Errorf("learning.duration_hours out of range")
	}
	return nil
}

// ExportProfile writes profile id to path (0600). Nothing in a profile is a
// secret by design (the UI warns on token-looking commands), but the file is
// still created private.
func ExportProfile(id, path string) error {
	if !ValidProfileID(id) {
		return fmt.Errorf("invalid profile id %q", id)
	}
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	p.ID = id
	b, err := yaml.Marshal(&p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ImportProfile reads path, validates it and saves it as profile id. The id is
// the caller's argument; any id inside the file is ignored, so the file can
// never choose where it lands. An existing profile is only replaced when
// overwrite is true.
func ImportProfile(id, path string, overwrite bool) (AgentProfile, error) {
	var zero AgentProfile
	if !ValidProfileID(id) {
		return zero, fmt.Errorf("invalid profile id %q (use letters, digits, - and _, max 64)", id)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return zero, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxImportBytes {
		return zero, fmt.Errorf("%s: not a regular file or larger than %d bytes", path, MaxImportBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	var p AgentProfile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // unknown keys could be flags from a newer/hostile exporter
	if err := dec.Decode(&p); err != nil {
		return zero, fmt.Errorf("profile yaml: %w", err)
	}
	p.ID = id
	if err := ValidateImport(p); err != nil {
		return zero, err
	}
	if !overwrite {
		if _, err := os.Stat(filepath.Clean(profilePath(id))); err == nil {
			return zero, fmt.Errorf("profile %q already exists (use --force to replace)", id)
		}
	}
	if err := SaveProfile(p); err != nil {
		return zero, err
	}
	return p, nil
}
