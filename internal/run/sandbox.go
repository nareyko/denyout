package run

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SRTAvailable reports whether the Anthropic sandbox-runtime `srt` binary is on PATH.
func SRTAvailable() bool {
	_, err := exec.LookPath("srt")
	return err == nil
}

// WrapSandbox optionally prefixes argv with srt. Returns argv, extra env, cleanup, error.
// Fail-closed when name is srt and binary missing. Empty name → passthrough + residual nil.
func WrapSandbox(name string, cmd []string, proxyURL string) (argv []string, env []string, cleanup func(), err error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cleanup = func() {}
	if name == "" || name == "none" {
		return cmd, nil, cleanup, nil
	}
	if name != "srt" {
		return nil, nil, cleanup, fmt.Errorf("unsupported sandbox %q (supported: srt)", name)
	}
	srt, lookErr := exec.LookPath("srt")
	if lookErr != nil {
		return nil, nil, cleanup, fmt.Errorf("srt not found in PATH — install Anthropic sandbox-runtime, or unset --sandbox / require_isolation")
	}
	settings, clean, err := writeSRTSettings(proxyURL)
	if err != nil {
		return nil, nil, cleanup, err
	}
	cleanup = clean
	argv = append([]string{srt, "--settings", settings}, cmd...)
	// Ensure child still sees DenyOut proxy; srt may pick HTTP_PROXY as parentProxy.
	env = []string{}
	if proxyURL != "" {
		env = append(env,
			"HTTP_PROXY="+proxyURL,
			"HTTPS_PROXY="+proxyURL,
			"http_proxy="+proxyURL,
			"https_proxy="+proxyURL,
		)
	}
	return argv, env, cleanup, nil
}

func writeSRTSettings(proxyURL string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "denyout-srt-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	// Allow all domains at srt layer; DenyOut proxy enforces policy.
	// parentProxy routes srt's network hop through DenyOut when supported.
	doc := map[string]any{
		"network": map[string]any{
			"allowedDomains": []string{"*"},
		},
		"filesystem": map[string]any{
			"denyRead":   []string{},
			"allowWrite": []string{".", "/tmp", os.TempDir()},
		},
	}
	if proxyURL != "" {
		net := doc["network"].(map[string]any)
		net["parentProxy"] = proxyURL
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	path = filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}
