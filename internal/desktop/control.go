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

// startControlServer listens on 127.0.0.1 for proxyd Ask IPC (no browser UI).
// GET/POST /ask?host=… → native dialog → {"action":"once|always|deny"}
// POST /always {"host":"…"} persists Always allow.
// POST /deny-event updates last-deny + optional toast.
// GET /ready for readiness (tests).
func (a *App) startControlServer(ctx context.Context) (string, error) {
	if a.asks == nil {
		a.asks = newAskFlight()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ask", a.handleControlAsk)
	mux.HandleFunc("/always", a.handleControlAlways)
	mux.HandleFunc("/deny-event", a.handleControlDenyEvent)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	})

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
	AppendDesktopLog("INFO control IPC %s", url)
	return url, nil
}

func (a *App) handleControlAsk(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if reason == "" {
		reason = "host_not_allowed"
	}
	if host == "" && r.Method == http.MethodPost {
		var body struct {
			Host   string `json:"host"`
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		host = strings.TrimSpace(body.Host)
		if body.Reason != "" {
			reason = strings.TrimSpace(body.Reason)
		}
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

	action := a.coalescedAsk(host, reason)
	switch action {
	case "once":
		_ = a.allowHostOnce(host)
	case "always":
		_ = a.persistAlwaysHost(host)
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
		URL     string   `json:"url"`    // redacted
		Notify  *bool    `json:"notify"` // default true; false when Ask dialog follows
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	doNotify := body.Notify == nil || *body.Notify
	redURL := strings.TrimSpace(body.URL)
	if body.Host != "" {
		summary := notify.HumanReasons(body.Reasons)
		a.mu.Lock()
		a.lastDeny = body.Host
		a.state.LastDenyHost = body.Host
		a.state.LastDenySummary = summary
		a.state.LastDenyURL = redURL
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
		profile := normalizePolicyProfile(a.state.PolicyProfile)
		safeDesktop := profile == PolicyProfileBrowse && !ask
		if isIPLiteral(body.Host) {
			if doNotify {
				if a.asks == nil {
					a.asks = newAskFlight()
				}
				a.asks.notifyIPBlocked(body.Host)
			}
		} else if doNotify && !(ask && hostNotAllowed) {
			if safeDesktop && isClearPostBlock(body.Reasons) {
				go a.handlePostBlockDeny(body.Host, body.Reasons, redURL)
			} else if isClearPostBlock(body.Reasons) {
				// Agents-only / wraps: same hard-block decision dialog as Safe desktop.
				go a.handlePostBlockDeny(body.Host, body.Reasons, redURL)
			}
			// Non-clear denies: History / Home only (no passive OS toast).
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
	if isIPLiteral(host) {
		return fmt.Errorf("IP literals cannot be always-allowed while allow_ip_literals is false")
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

func (a *App) removeAlwaysHost(host string) {
	host = strings.TrimSpace(host)
	a.mu.Lock()
	out := a.state.AlwaysAllowHosts[:0]
	for _, h := range a.state.AlwaysAllowHosts {
		if !strings.EqualFold(h, host) {
			out = append(out, h)
		}
	}
	a.state.AlwaysAllowHosts = out
	st := a.state
	wasOn := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	_ = SaveState(st)
	if wasOn {
		a.restartActiveProtector()
	}
}
