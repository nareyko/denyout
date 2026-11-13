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

	listen := opts.Listen
	if listen == "" {
		host := cfg.Listen.Host
		port := cfg.Listen.Port
		if host == "" {
			host = "127.0.0.1"
		}
		if port == 0 {
			port = 8080
		}
		listen = net.JoinHostPort(host, strconv.Itoa(port))
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", listen, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("listen port: %w", err)
	}

	tlsMode := opts.TLSMode
	if tlsMode == "" {
		if cfg.TLS.Mode == string(proxy.TLSPassthrough) {
			tlsMode = proxy.TLSPassthrough
		} else {
			tlsMode = proxy.TLSIntercept
		}
	}
	if tlsMode == proxy.TLSPassthrough {
		fmt.Fprintln(os.Stderr, "denyout serve: WARNING: tls-mode=passthrough — secret-in-URL / canary scanning on HTTPS is limited; not full R-20 protection")
	}

	metricsListen := opts.MetricsListen
	if metricsListen == "" {
		metricsListen = cfg.Server.MetricsListen
	}
	healthListen := opts.HealthListen
	if healthListen == "" {
		healthListen = cfg.Server.HealthListen
	}

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

	var aux []*http.Server
	shutdownAux := func() {
		for _, a := range aux {
			shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = a.Shutdown(shCtx)
			cancel()
		}
	}
	defer shutdownAux()

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
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

	if healthListen != "" {
		hs := &http.Server{Handler: http.HandlerFunc(healthHandler), ReadHeaderTimeout: 5 * time.Second}
		aux = append(aux, hs)
		hl, err := net.Listen("tcp", healthListen)
		if err != nil {
			return fmt.Errorf("health listen: %w", err)
		}
		fmt.Fprintf(os.Stderr, "denyout serve: health=%s (/healthz /readyz)\n", hl.Addr())
		go func() { _ = hs.Serve(hl) }()
	}

	if metricsListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			fmt.Fprintf(w, "# HELP denyout_up 1 if proxy is ready\n# TYPE denyout_up gauge\ndenyout_up %d\n", boolInt(ready.Load()))
			fmt.Fprintf(w, "# HELP denyout_info Build/session labels\n# TYPE denyout_info gauge\ndenyout_info{mode=%q,preset=%q,version=%q} 1\n",
				cfg.Mode, cfg.Preset, opts.Version)
		})
		if healthListen == "" {
			mux.HandleFunc("/healthz", healthHandler)
			mux.HandleFunc("/readyz", healthHandler)
			mux.HandleFunc("/livez", healthHandler)
		}
		ms := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		aux = append(aux, ms)
		ml, err := net.Listen("tcp", metricsListen)
		if err != nil {
			return fmt.Errorf("metrics listen: %w", err)
		}
		fmt.Fprintf(os.Stderr, "denyout serve: metrics=%s (/metrics)\n", ml.Addr())
		go func() { _ = ms.Serve(ml) }()
	}

	// If neither health nor metrics: still expose health on a loopback admin derived from proxy port+1? Skip — readinessProbe can use TCP on proxy port.

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
