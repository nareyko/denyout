//go:build darwin

package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func registerAutostartDarwin(self string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	args := fmt.Sprintf(` <string>%s</string>
 <string>desktop</string>`, self)
	if strings.Contains(filepath.Base(self), "denyout-desktop") {
		args = fmt.Sprintf(` <string>%s</string>`, self)
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>Label</key><string>com.denyout.desktop</string>
 <key>ProgramArguments</key>
 <array>
%s
 </array>
 <key>RunAtLoad</key><true/>
 <key>KeepAlive</key><false/>
</dict>
</plist>
`, args)
	path := filepath.Join(dir, "com.denyout.desktop.plist")
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "load", "-w", path).Run()
	return nil
}

func unregisterAutostartDarwin() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, "Library", "LaunchAgents", "com.denyout.desktop.plist")
	_ = exec.Command("launchctl", "unload", "-w", path).Run()
	_ = os.Remove(path)
	return nil
}

func updateMacAutostartEnv(proxyURL, caFile string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, "Library", "LaunchAgents", "com.denyout.desktop.plist")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(b)
	// Strip previous EnvironmentVariables block if present.
	if i := strings.Index(s, "<key>EnvironmentVariables</key>"); i >= 0 {
		rest := s[i:]
		if j := strings.Index(rest, "</dict>"); j >= 0 {
			// find closing of EnvironmentVariables dict - rough: remove from key through next </dict>
			end := i + j + len("</dict>")
			s = s[:i] + s[end:]
		}
	}
	if proxyURL == "" {
		return os.WriteFile(path, []byte(s), 0o644)
	}
	env := fmt.Sprintf(` <key>EnvironmentVariables</key>
 <dict>
 <key>HTTP_PROXY</key><string>%s</string>
 <key>HTTPS_PROXY</key><string>%s</string>
 <key>http_proxy</key><string>%s</string>
 <key>https_proxy</key><string>%s</string>
`, proxyURL, proxyURL, proxyURL, proxyURL)
	if caFile != "" {
		env += fmt.Sprintf(` <key>SSL_CERT_FILE</key><string>%s</string>
 <key>NODE_EXTRA_CA_CERTS</key><string>%s</string>
`, caFile, caFile)
	}
	env += ` </dict>
`
	s = strings.Replace(s, "</dict>\n</plist>", env+"</dict>\n</plist>", 1)
	return os.WriteFile(path, []byte(s), 0o644)
}

func detachCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
