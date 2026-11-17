//go:build darwin

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const pfAnchor = "com.denyout"

func applyRedirect(spec Spec) error {
	rules := renderDarwinPF(spec)
	dir := "/etc/pf.anchors"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("pf anchors dir: %w", err)
	}
	path := filepath.Join(dir, pfAnchor)
	if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
		return fmt.Errorf("write pf anchor: %w", err)
	}
	// Ensure anchor is referenced (best-effort append once).
	ensurePFAnchorReferenced()
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-f", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl load: %w", err)
	}
	_ = exec.Command("pfctl", "-e").Run()
	return nil
}

func removeRedirect(spec Spec) error {
	_ = spec
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-F", "all")
	_ = cmd.Run()
	path := filepath.Join("/etc/pf.anchors", pfAnchor)
	_ = os.Remove(path)
	return nil
}

// ensurePFAnchorReferenced appends the DenyOut anchor to /etc/pf.conf once (pure Go: no shell).
func ensurePFAnchorReferenced() {
	const conf = "/etc/pf.conf"
	b, err := os.ReadFile(conf)
	if err != nil || strings.Contains(string(b), pfAnchor) {
		return
	}
	f, err := os.OpenFile(conf, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "\nrdr-anchor \"%s\"\nanchor \"%s\"\n", pfAnchor, pfAnchor)
}
