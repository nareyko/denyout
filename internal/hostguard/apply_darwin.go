//go:build darwin

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	_ = exec.Command("sh", "-c",
		fmt.Sprintf(`grep -q '%s' /etc/pf.conf || echo 'rdr-anchor "%s"\nanchor "%s"' >> /etc/pf.conf`, pfAnchor, pfAnchor, pfAnchor),
	).Run()
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
