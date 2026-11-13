package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// startControlServer listens on 127.0.0.1 for proxyd Ask IPC.
// GET/POST /ask?host=… → native dialog → {"action":"once|always|deny"}
// POST /always {"host":"…"} persists Always allow.
func (a *App) startControlServer(ctx context.Context) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ask", a.handleControlAsk)
	mux.HandleFunc("/always", a.handleControlAlways)
	mux.HandleFunc("/deny-event", a.handleControlDenyEvent)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	go func() { _ = srv.Serve(ln) }()
	url := "http://" + ln.Addr().String()
	a.mu.Lock()
	a.controlURL = url
	a.mu.Unlock()
	return url, nil
}

func (a *App) handleControlAsk(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" && r.Method == http.MethodPost {
		var body struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		host = strings.TrimSpace(body.Host)
	}
	if host == "" {
		http.Error(w, `{"error":"host required"}`, 400)
		return
	}
	a.mu.Lock()
	a.lastDeny = host
	a.state.LastDenyHost = host
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	action := nativeAllowDialog(host)
	if action == "" {
		action = "deny"
	}
	switch action {
	case "once", "always":
		if action == "always" {
			_ = a.persistAlwaysHost(host)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"action": action, "host": host})
}

func (a *App) handleControlAlways(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := a.persistAlwaysHost(body.Host); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"ok":true}`)
}

func (a *App) handleControlDenyEvent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string   `json:"host"`
		Reasons []string `json:"reasons"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Host != "" {
		a.mu.Lock()
		a.lastDeny = body.Host
		a.state.LastDenyHost = body.Host
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"ok":true}`)
}

func (a *App) persistAlwaysHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	a.mu.Lock()
	found := false
	for _, h := range a.state.AlwaysAllowHosts {
		if h == host {
			found = true
			break
		}
	}
	if !found {
		a.state.AlwaysAllowHosts = append(a.state.AlwaysAllowHosts, host)
	}
	st := a.state
	sess := a.session
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if sess != nil {
		sess.AllowHost(host, "user_always")
	}
	return nil
}
