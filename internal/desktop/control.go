package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// startControlServer listens on 127.0.0.1 for proxyd Ask IPC and the Activity page.
// GET/POST /ask?host=… → native dialog → {"action":"once|always|deny"}
// POST /always {"host":"…"} persists Always allow.
// GET /activity + /api/desktop/* for local Activity/Settings UI.
func (a *App) startControlServer(ctx context.Context) (string, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ask", a.handleControlAsk)
	mux.HandleFunc("/always", a.handleControlAlways)
	mux.HandleFunc("/deny-event", a.handleControlDenyEvent)
	a.registerActivityRoutes(mux)

	listen := "127.0.0.1:0"
	if a.opts.ControlListen != "" {
		listen = a.opts.ControlListen
	}
	ln, err := net.Listen("tcp", listen)
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
	AppendDesktopLog("INFO activity page %s/activity", url)
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
		Notify  *bool    `json:"notify"` // default true; false when Ask dialog follows
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	doNotify := body.Notify == nil || *body.Notify
	if body.Host != "" {
		summary := notify.HumanReasons(body.Reasons)
		a.mu.Lock()
		a.lastDeny = body.Host
		a.state.LastDenyHost = body.Host
		a.state.LastDenySummary = summary
		ask := a.state.AskMode
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)

		hostNotAllowed := false
		for _, rsn := range body.Reasons {
			if rsn == "host_not_allowed" {
				hostNotAllowed = true
				break
			}
		}
		if doNotify && !(ask && hostNotAllowed) {
			notify.Deny(body.Host, body.Reasons)
		}
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
