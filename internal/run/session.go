package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
)

// SessionOptions starts a proxy wrap without necessarily spawning a child.
type SessionOptions struct {
	ConfigPath    string
	Config        *policy.Config // if set, used instead of ConfigPath / default models
	TLSMode       proxy.TLSMode
	Version       string
	Sandbox       string
	OnDeny        proxy.DenyHook
	ListenPort    int    // 0 = ephemeral
	CADir         string // empty = temp session CA
	PersistCA     bool   // if true, do not shred CA on Stop
	Transparent   bool   // raw TCP redirect mode for hostguard
	PolicyProfile string // agent | browse (audit attribution)
	Process       string // best-effort client label
}

// Status is a snapshot of an active wrap session.
type Status struct {
	Running    bool              `json:"running"`
	SessionID  string            `json:"session_id,omitempty"`
	Mode       string            `json:"mode,omitempty"`
	Preset     string            `json:"preset,omitempty"`
	TLSMode    string            `json:"tls_mode,omitempty"`
	ProxyURL   string            `json:"proxy_url,omitempty"`
	PolicyHash string            `json:"policy_hash,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	AuditPath  string            `json:"audit_path,omitempty"`
}

// Session holds a live local proxy for GUI / programmatic wrap.
type Session struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	srv       *proxy.Server
	sink      *audit.Sink
	ca        *proxy.SessionCA
	eng       *policy.Engine
	persistCA bool
	status    Status
}

// StartSession starts the policy proxy (same engine as denyout run).
func StartSession(opts SessionOptions) (*Session, error) {
	if opts.TLSMode == "" {
		opts.TLSMode = proxy.TLSIntercept
	}

	var (
		cfg *policy.Config
		raw []byte
		err error
	)
	switch {
	case opts.Config != nil:
		cfg = opts.Config
		raw = []byte("inline-config")
	case opts.ConfigPath != "":
		raw, err = os.ReadFile(opts.ConfigPath)
		if err != nil {
			return nil, err
		}
		cfg, err = policy.LoadBytes(raw)
	default:
		cfg, err = policy.DefaultEnforceModels()
		if err == nil {
			raw = []byte("preset:models")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
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

	var ca *proxy.SessionCA
	if opts.TLSMode == proxy.TLSIntercept {
		caDir := opts.CADir
		if caDir == "" {
			caDir = filepath.Join(os.TempDir(), "denyout-ca-"+sessionID)
		}
		if opts.PersistCA {
			ca, err = proxy.LoadOrCreatePersistentCA(caDir)
		} else {
			ca, err = proxy.NewSessionCA(caDir)
		}
		if err != nil {
			_ = sink.Close()
			return nil, fmt.Errorf("session CA: %w", err)
		}
	}

	eng := policy.NewEngine(cfg)
	eng.Resolve = func(host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	}

	ctx, cancel := context.WithCancel(context.Background())
	profile := opts.PolicyProfile
	if profile == "" {
		profile = "agent"
		if cfg.Mode == "blocklist" {
			profile = "browse"
		}
	}
	srv, err := proxy.Start(ctx, proxy.Config{
		Engine:        eng,
		Audit:         sink,
		SessionID:     sessionID,
		PolicyHash:    policyHash,
		Version:       opts.Version,
		TLSMode:       opts.TLSMode,
		CA:            ca,
		ListenHost:    "127.0.0.1",
		ListenPort:    opts.ListenPort,
		OnDeny:        opts.OnDeny,
		Transparent:   opts.Transparent,
		PolicyProfile: profile,
		Process:       opts.Process,
	})
	if err != nil {
		cancel()
		if ca != nil && !opts.PersistCA {
			ca.Shred()
		}
		_ = sink.Close()
		return nil, err
	}

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", srv.Port())
	envList := childEnv(nil, proxyURL, sessionID, ca)
	envMap := map[string]string{}
	for _, e := range envList {
		if i := indexByte(e, '='); i >= 0 {
			envMap[e[:i]] = e[i+1:]
		}
	}

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

	s := &Session{
		cancel:    cancel,
		srv:       srv,
		sink:      sink,
		ca:        ca,
		eng:       eng,
		persistCA: opts.PersistCA,
		status: Status{
			Running:    true,
			SessionID:  sessionID,
			Mode:       cfg.Mode,
			Preset:     cfg.Preset,
			TLSMode:    string(opts.TLSMode),
			ProxyURL:   proxyURL,
			PolicyHash: policyHash,
			Env:        envMap,
			AuditPath:  auditPath,
		},
	}
	return s, nil
}

// CACertFile returns the active CA PEM path, if any.
func (s *Session) CACertFile() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ca == nil {
		return ""
	}
	return s.ca.CertFile()
}

// Port returns the proxy listen port.
func (s *Session) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv == nil {
		return 0
	}
	return s.srv.Port()
}

// AllowHost updates the live policy allowlist (Ask once / Always).
func (s *Session) AllowHost(host, reason string) {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng != nil {
		eng.AllowHost(host, reason)
	}
}

// Status returns a copy of the session snapshot.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	if st.Env != nil {
		cp := make(map[string]string, len(st.Env))
		for k, v := range st.Env {
			cp[k] = v
		}
		st.Env = cp
	}
	return st
}

// Stop tears down the proxy and CA.
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.status.Running {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.srv != nil {
		_ = s.srv.Close()
	}
	_ = s.sink.Log(audit.Event{
		SessionID:      s.status.SessionID,
		Verdict:        "session_end",
		Reasons:        []string{},
		Mode:           s.status.Mode,
		Network:        audit.Network{DestHost: "localhost"},
		PolicyHash:     s.status.PolicyHash,
		DenyOutVersion: "",
	})
	_ = s.sink.Close()
	if s.ca != nil && !s.persistCA {
		s.ca.Shred()
	}
	s.status.Running = false
	s.status.ProxyURL = ""
	s.status.Env = nil
	return nil
}
