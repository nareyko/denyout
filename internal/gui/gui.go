package gui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

//go:embed static/*
var staticFS embed.FS

// Options for denyout gui.
type Options struct {
	ConfigPath  string
	TLSMode     proxy.TLSMode
	Version     string
	Listen      string // default 127.0.0.1:0
	OpenBrowser bool
}

// Server is the local desktop UI (same engine as CLI).
type Server struct {
	opts Options
	cfg  *policy.Config

	mu   sync.Mutex
	sess *run.Session
}

// Run listens on localhost, optionally opens a browser, blocks until ctx done.
func Run(ctx context.Context, opts Options) error {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	if opts.TLSMode == "" {
		opts.TLSMode = proxy.TLSIntercept
	}

	var (
		cfg *policy.Config
		err error
	)
	if opts.ConfigPath != "" {
		cfg, err = policy.LoadFile(opts.ConfigPath)
	} else {
		cfg, err = policy.DefaultEnforceModels()
	}
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	s := &Server{opts: opts, cfg: cfg}
	mux := http.NewServeMux()
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/wrap/start", s.handleWrapStart)
	mux.HandleFunc("/api/wrap/stop", s.handleWrapStop)
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/api/denials", s.handleDenials)

	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	url := "http://" + addr + "/"
	fmt.Fprintf(os.Stderr, "denyout gui: mode=%s preset=%s ui=%s (localhost only)\n", cfg.Mode, cfg.Preset, url)

	httpSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(ln)
	}()

	if opts.OpenBrowser {
		go openBrowser(url)
	}

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
		s.stopWrap()
		return nil
	case err := <-errCh:
		s.stopWrap()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) stopWrap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil {
		_ = s.sess.Stop()
		s.sess = nil
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	sess := s.sess
	s.mu.Unlock()

	st := run.Status{
		Running: false,
		Mode:    s.cfg.Mode,
		Preset:  s.cfg.Preset,
		TLSMode: string(s.opts.TLSMode),
	}
	if sess != nil {
		st = sess.Status()
		if !st.Running {
			st.Mode = s.cfg.Mode
			st.Preset = s.cfg.Preset
			st.TLSMode = string(s.opts.TLSMode)
		}
	}
	writeJSON(w, st)
}

func (s *Server) handleWrapStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil && s.sess.Status().Running {
		writeJSON(w, s.sess.Status())
		return
	}
	sess, err := run.StartSession(run.SessionOptions{
		ConfigPath: s.opts.ConfigPath,
		TLSMode:    s.opts.TLSMode,
		Version:    s.opts.Version,
	})
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	s.sess = sess
	writeJSON(w, sess.Status())
}

func (s *Server) handleWrapStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil {
		_ = s.sess.Stop()
		s.sess = nil
	}
	writeJSON(w, run.Status{
		Running: false,
		Mode:    s.cfg.Mode,
		Preset:  s.cfg.Preset,
		TLSMode: string(s.opts.TLSMode),
	})
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		writeErr(w, fmt.Errorf("url required"), http.StatusBadRequest)
		return
	}
	res, err := check.URL(s.cfg, body.URL)
	if err != nil {
		writeErr(w, err, http.StatusBadRequest)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleDenials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := audit.ExpandPath(s.cfg.Audit.JSONLPath)
	if path == "" {
		path = audit.DefaultDesktopPath()
	}
	s.mu.Lock()
	if s.sess != nil {
		st := s.sess.Status()
		if st.AuditPath != "" {
			path = st.AuditPath
		}
	}
	s.mu.Unlock()

	evs, err := audit.RecentDenials(path, 50)
	if err != nil {
		writeErr(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"events": evs, "path": path})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func openBrowser(url string) {
	time.Sleep(300 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
