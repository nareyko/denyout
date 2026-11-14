package serve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
)

// Options for denyout serve (long-running sidecar proxy).
type Options struct {
	ConfigPath    string
	Listen        string // host:port; empty → config listen or 127.0.0.1:8080
	MetricsListen string
	HealthListen  string
	TLSMode       proxy.TLSMode
	CADir         string
	Version       string
}

// Run loads policy, starts the proxy, optional health/metrics, and blocks until ctx is done.
func Run(ctx context.Context, opts Options) error {
	if os.Getenv("DENYOUT_KILL") == "1" || strings.EqualFold(os.Getenv("DENYOUT_KILL"), "true") {
		return fmt.Errorf("DENYOUT_KILL set — refuse to serve (fail closed)")
	}
	if opts.ConfigPath == "" {
		return fmt.Errorf("--config is required for serve (sidecar needs an explicit policy)")
	}

	raw, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return err
	}
	cfg, err := policy.LoadBytes(raw)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	host, port, err := resolveListen(opts.Listen, cfg)
	if err != nil {
		return err
	}
	tlsMode := resolveTLSMode(opts.TLSMode, cfg)
	if tlsMode == proxy.TLSPassthrough {
		fmt.Fprintln(os.Stderr, "denyout serve: WARNING: tls-mode=passthrough — secret-in-URL / canary scanning on HTTPS is limited; not full R-20 protection")
	}

	metricsListen := firstNonEmpty(opts.MetricsListen, cfg.Server.MetricsListen)
	healthListen := firstNonEmpty(opts.HealthListen, cfg.Server.HealthListen)

	sessionID := uuid.NewString()
	sum := sha256.Sum256(raw)
	policyHash := "sha256:" + hex.EncodeToString(sum[:])

	auditPath := audit.ExpandPath(cfg.Audit.JSONLPath)
	// Container-friendly: empty path + stdout true is fine; empty both → stdout.
	stdout := cfg.Audit.Stdout
	if auditPath == "" && !stdout {
		stdout = true
	}
	sink := audit.MustOpen(auditPath, stdout, opts.Version)
	defer sink.Close()

	var ca *proxy.SessionCA
	caDir := opts.CADir
	if tlsMode == proxy.TLSIntercept {
		if caDir == "" {
			caDir = filepath.Join(os.TempDir(), "denyout-serve-ca")
		}
		ca, err = proxy.NewSessionCA(caDir)
		if err != nil {
			return fmt.Errorf("session CA: %w", err)
		}
		defer ca.Shred()
	}

	eng := policy.NewEngine(cfg)
	eng.Resolve = func(h string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(context.Background(), "ip", h)
	}

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	var ready atomic.Bool
	srv, err := proxy.Start(proxyCtx, proxy.Config{
		Engine:     eng,
		Audit:      sink,
		SessionID:  sessionID,
		PolicyHash: policyHash,
		Version:    opts.Version,
		TLSMode:    tlsMode,
		CA:         ca,
		ListenHost: host,
		ListenPort: port,
	})
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	defer srv.Close()
	ready.Store(true)

	proxyURL := fmt.Sprintf("http://%s", net.JoinHostPort(hostForURL(host), strconv.Itoa(srv.Port())))
	fmt.Fprintf(os.Stderr, "denyout serve: mode=%s preset=%s tls=%s listen=%s session=%s\n",
		cfg.Mode, cfg.Preset, tlsMode, srv.Addr(), sessionID)
	fmt.Fprintf(os.Stderr, "denyout serve: set HTTPS_PROXY=%s HTTP_PROXY=%s\n", proxyURL, proxyURL)
	if ca != nil {
		fmt.Fprintf(os.Stderr, "denyout serve: CA cert=%s (mount into agent trust store for intercept)\n", ca.CertFile())
	}
	fmt.Fprintln(os.Stderr, "denyout serve: hardened claim requires NetworkPolicy / host firewall so the agent cannot bypass this proxy — see docs/08-server.md")

	_ = sink.Log(audit.Event{
		SessionID: sessionID,
		Verdict:   "session_start",
		Reasons:   []string{},
		Mode:      cfg.Mode,
		Network: audit.Network{
			DestHost: host,
			DestPort: srv.Port(),
			Protocol: "proxy",
		},
		PolicyHash:     policyHash,
		DenyOutVersion: opts.Version,
	})

	aux, err := startOpsListeners(healthListen, metricsListen, cfg, opts.Version, &ready)
	if err != nil {
		return err
	}
	defer shutdownHTTP(aux)

	<-ctx.Done()
	ready.Store(false)
	_ = sink.Log(audit.Event{
		SessionID:      sessionID,
		Verdict:        "session_end",
		Reasons:        []string{},
		Mode:           cfg.Mode,
		Network:        audit.Network{DestHost: host, DestPort: srv.Port()},
		PolicyHash:     policyHash,
		DenyOutVersion: opts.Version,
	})
	return nil
}

func healthHandler(ready *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/livez":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		case "/readyz":
			if !ready.Load() {
				http.Error(w, "not ready\n", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready\n"))
		default:
			http.NotFound(w, r)
		}
	}
}

func startOpsListeners(healthListen, metricsListen string, cfg *policy.Config, version string, ready *atomic.Bool) ([]*http.Server, error) {
	var aux []*http.Server
	hh := healthHandler(ready)
	if healthListen != "" {
		hs := &http.Server{Handler: hh, ReadHeaderTimeout: 5 * time.Second}
		hl, err := net.Listen("tcp", healthListen)
		if err != nil {
			return nil, fmt.Errorf("health listen: %w", err)
		}
		aux = append(aux, hs)
		fmt.Fprintf(os.Stderr, "denyout serve: health=%s (/healthz /readyz)\n", hl.Addr())
		go func() { _ = hs.Serve(hl) }()
	}
	if metricsListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			fmt.Fprintf(w, "# HELP denyout_up 1 if proxy is ready\n# TYPE denyout_up gauge\ndenyout_up %d\n", boolInt(ready.Load()))
			fmt.Fprintf(w, "# HELP denyout_info Build/session labels\n# TYPE denyout_info gauge\ndenyout_info{mode=%q,preset=%q,version=%q} 1\n",
				cfg.Mode, cfg.Preset, version)
		})
		if healthListen == "" {
			mux.HandleFunc("/healthz", hh)
			mux.HandleFunc("/readyz", hh)
			mux.HandleFunc("/livez", hh)
		}
		ms := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		ml, err := net.Listen("tcp", metricsListen)
		if err != nil {
			shutdownHTTP(aux)
			return nil, fmt.Errorf("metrics listen: %w", err)
		}
		aux = append(aux, ms)
		fmt.Fprintf(os.Stderr, "denyout serve: metrics=%s (/metrics)\n", ml.Addr())
		go func() { _ = ms.Serve(ml) }()
	}
	return aux, nil
}

func shutdownHTTP(aux []*http.Server) {
	for _, a := range aux {
		shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.Shutdown(shCtx)
		cancel()
	}
}

func resolveListen(flag string, cfg *policy.Config) (host string, port int, err error) {
	listen := flag
	if listen == "" {
		h := cfg.Listen.Host
		p := cfg.Listen.Port
		if h == "" {
			h = "127.0.0.1"
		}
		if p == 0 {
			p = 8080
		}
		listen = net.JoinHostPort(h, strconv.Itoa(p))
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, fmt.Errorf("listen %q: %w", listen, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("listen port: %w", err)
	}
	return host, port, nil
}

func resolveTLSMode(flag proxy.TLSMode, cfg *policy.Config) proxy.TLSMode {
	if flag != "" {
		return flag
	}
	if cfg.TLS.Mode == string(proxy.TLSPassthrough) {
		return proxy.TLSPassthrough
	}
	return proxy.TLSIntercept
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func hostForURL(host string) string {
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1"
	}
	return host
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
