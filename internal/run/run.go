package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
)

// Options for denyout run.
type Options struct {
	ConfigPath string
	TLSMode    proxy.TLSMode
	Version    string
	Command    []string
	Sandbox    string // stub only
}

// Exec starts proxy, wraps child, returns child exit code.
func Exec(opts Options) (int, error) {
	if len(opts.Command) == 0 {
		return 2, fmt.Errorf("no command after --")
	}
	if opts.TLSMode == "" {
		opts.TLSMode = proxy.TLSIntercept
	}

	var (
		cfg *policy.Config
		raw []byte
		err error
	)
	if opts.ConfigPath != "" {
		raw, err = os.ReadFile(opts.ConfigPath)
		if err != nil {
			return 2, err
		}
		cfg, err = policy.LoadBytes(raw)
	} else {
		cfg, err = policy.DefaultEnforceModels()
		if err == nil {
			raw = []byte("preset:models")
		}
	}
	if err != nil {
		return 2, fmt.Errorf("config: %w", err)
	}

	if opts.TLSMode == proxy.TLSPassthrough {
		fmt.Fprintln(os.Stderr, "denyout: WARNING: tls-mode=passthrough — secret-in-URL / canary scanning on HTTPS is limited to CONNECT host only; not full R-20 protection")
	}
	if opts.Sandbox != "" {
		fmt.Fprintf(os.Stderr, "denyout: --sandbox=%s is documented stub only in this build; proceeding without OS sandbox\n", opts.Sandbox)
	}

	sessionID := uuid.NewString()
	sum := sha256.Sum256(raw)
	policyHash := "sha256:" + hex.EncodeToString(sum[:])

	auditPath := audit.ExpandPath(cfg.Audit.JSONLPath)
	if auditPath == "" {
		auditPath = audit.DefaultDesktopPath()
	}
	sink := audit.MustOpen(auditPath, cfg.Audit.Stdout, opts.Version)
	defer sink.Close()

	var ca *proxy.SessionCA
	if opts.TLSMode == proxy.TLSIntercept {
		caDir := filepath.Join(os.TempDir(), "denyout-ca-"+sessionID)
		ca, err = proxy.NewSessionCA(caDir)
		if err != nil {
			return 2, fmt.Errorf("session CA: %w", err)
		}
		defer ca.Shred()
	}

	eng := policy.NewEngine(cfg)
	eng.Resolve = func(host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := proxy.Start(ctx, proxy.Config{
		Engine:     eng,
		Audit:      sink,
		SessionID:  sessionID,
		PolicyHash: policyHash,
		Version:    opts.Version,
		TLSMode:    opts.TLSMode,
		CA:         ca,
		ListenHost: "127.0.0.1",
		ListenPort: 0,
	})
	if err != nil {
		return 2, err
	}
	defer srv.Close()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", srv.Port())
	fmt.Fprintf(os.Stderr, "denyout: mode=%s preset=%s tls=%s proxy=%s session=%s\n",
		cfg.Mode, cfg.Preset, opts.TLSMode, proxyURL, sessionID)

	_ = sink.Log(audit.Event{
		SessionID: sessionID,
		Verdict:   "session_start",
		Reasons:   []string{},
		Mode:      cfg.Mode,
		Network: audit.Network{
			DestHost: "localhost",
			DestPort: srv.Port(),
			Protocol: "proxy",
		},
		PolicyHash:     policyHash,
		DenyOutVersion: opts.Version,
	})

	cmd := exec.Command(opts.Command[0], opts.Command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = childEnv(os.Environ(), proxyURL, sessionID, ca)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return 2, err
	}
	waitErr := cmd.Wait()
	cancel()
	_ = srv.Close()

	code := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return 2, waitErr
		}
	}
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	_ = sink.Log(audit.Event{
		SessionID:      sessionID,
		Verdict:        "session_end",
		Reasons:        []string{},
		Mode:           cfg.Mode,
		Network:        audit.Network{DestHost: "localhost", DestPort: srv.Port()},
		PolicyHash:     policyHash,
		DenyOutVersion: opts.Version,
	})
	return code, nil
}

func childEnv(base []string, proxyURL, sessionID string, ca *proxy.SessionCA) []string {
	out := make([]string, 0, len(base)+16)
	skip := map[string]struct{}{
		"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "http_proxy": {}, "https_proxy": {},
		"ALL_PROXY": {}, "all_proxy": {}, "NO_PROXY": {}, "no_proxy": {},
		"SSL_CERT_FILE": {}, "REQUESTS_CA_BUNDLE": {}, "CURL_CA_BUNDLE": {},
		"NODE_EXTRA_CA_CERTS": {}, "GIT_SSL_CAINFO": {},
		"DENYOUT_SESSION_ID": {}, "DENYOUT_PROXY": {},
	}
	for _, e := range base {
		key := e
		if i := indexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		if _, ok := skip[key]; ok {
			continue
		}
		out = append(out, e)
	}
	out = append(out,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		"DENYOUT_SESSION_ID="+sessionID,
		"DENYOUT_PROXY="+proxyURL,
	)
	if ca != nil {
		p := ca.CertFile()
		out = append(out,
			"SSL_CERT_FILE="+p,
			"REQUESTS_CA_BUNDLE="+p,
			"CURL_CA_BUNDLE="+p,
			"NODE_EXTRA_CA_CERTS="+p,
			"GIT_SSL_CAINFO="+p,
		)
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
