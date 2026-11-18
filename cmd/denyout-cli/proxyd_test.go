package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/run"
)

func TestDecideDeny(t *testing.T) {
	notAllowed := []string{"host_not_allowed"}
	other := []string{"secret_in_url"}
	for _, c := range []struct {
		name    string
		o       proxydOpts
		host    string
		reasons []string
		want    denyAction
	}{
		{"plain notify", proxydOpts{}, "a.com", notAllowed, denyNotify},
		{"control report", proxydOpts{controlURL: "c"}, "a.com", other, denyReport},
		{"ip literal never asks (control)", proxydOpts{ask: true, controlURL: "c"}, "1.2.3.4", notAllowed, denyReport},
		{"ip literal never asks (local)", proxydOpts{ask: true, allowBase: "b"}, "::1", notAllowed, denyNotify},
		{"ask via control", proxydOpts{ask: true, controlURL: "c", allowBase: "b"}, "a.com", notAllowed, denyAskControl},
		{"ask via wizard", proxydOpts{ask: true, allowBase: "b"}, "a.com", notAllowed, denyAskNotifier},
		{"ask without targets", proxydOpts{ask: true}, "a.com", notAllowed, denyNotify},
		{"ask but other reason", proxydOpts{ask: true, controlURL: "c"}, "a.com", other, denyReport},
		{"no ask flag", proxydOpts{controlURL: "c"}, "a.com", notAllowed, denyReport},
	} {
		if got := decideDeny(c.o, c.host, c.reasons); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestAskURL(t *testing.T) {
	if got := askURL("http://x/wiz//", "a.com"); got != "http://x/wiz/allow.html?host=a.com" {
		t.Fatal(got)
	}
}

type denyRec struct {
	mu    sync.Mutex
	log   []string
	askIs string
}

func (r *denyRec) add(s string) { r.mu.Lock(); r.log = append(r.log, s); r.mu.Unlock() }

func (r *denyRec) deps() denyDeps {
	return denyDeps{
		spawn: func(f func()) { f() },
		postEvent: func(base, host string, _ []string, u string, n bool) {
			r.add("event:" + base + ":" + host + ":" + u + ":" + map[bool]string{true: "notify", false: "silent"}[n])
		},
		ask:         func(base, host string) string { r.add("ask:" + host); return r.askIs },
		postAlways:  func(base, host string) { r.add("always:" + host) },
		notifyDeny:  func(host string, _ []string, u string) { r.add("deny:" + host + ":" + u) },
		notifyAsk:   func(o notify.AskOptions) { r.add("notifyask:" + o.Host + ":" + o.OpenURL) },
		allowHostFn: func(host, reason string) { r.add("allow:" + host + ":" + reason) },
	}
}

func TestNewDenyHandler(t *testing.T) {
	na := []string{"host_not_allowed"}
	for _, c := range []struct {
		name string
		o    proxydOpts
		ask  string
		host string
		want string
	}{
		{"toast", proxydOpts{}, "", "a.com", "deny:a.com:u"},
		{"report", proxydOpts{controlURL: "C"}, "", "a.com", "event:C:a.com:u:notify"},
		{"ask once", proxydOpts{ask: true, controlURL: "C"}, "once", "a.com", "event:C:a.com:u:silent|ask:a.com|allow:a.com:user_once"},
		{"ask always", proxydOpts{ask: true, controlURL: "C"}, "always", "a.com", "event:C:a.com:u:silent|ask:a.com|allow:a.com:user_always|always:a.com"},
		{"ask deny", proxydOpts{ask: true, controlURL: "C"}, "deny", "a.com", "event:C:a.com:u:silent|ask:a.com"},
		{"wizard", proxydOpts{ask: true, allowBase: "http://w"}, "", "a.com", "notifyask:a.com:http://w/allow.html?host=a.com"},
	} {
		r := &denyRec{askIs: c.ask}
		newDenyHandler(c.o, r.deps())(c.host, na, "u")
		if got := strings.Join(r.log, "|"); got != c.want {
			t.Errorf("%s: %q want %q", c.name, got, c.want)
		}
	}
}

func TestProxydPolicy(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg, profile, err := proxydPolicy(proxydOpts{}, noEnv)
	if err != nil || profile != "agent" || cfg == nil || cfg.AllowPrivate {
		t.Fatalf("%v %q %v", cfg, profile, err)
	}
	cfg, _, err = proxydPolicy(proxydOpts{}, env(map[string]string{"DENYOUT_ALLOW_PRIVATE": "1"}))
	if err != nil || !cfg.AllowPrivate {
		t.Fatalf("allow private: %v %v", cfg, err)
	}
	ask, _, err := proxydPolicy(proxydOpts{ask: true}, noEnv)
	if err != nil || ask == nil {
		t.Fatal(err)
	}
	always, _, err := proxydPolicy(proxydOpts{}, env(map[string]string{"DENYOUT_ALWAYS_ALLOW": "a.example,b.example"}))
	if err != nil || !hasAllow(always, "a.example") || !hasAllow(always, "b.example") {
		t.Fatalf("always: %v %v", always, err)
	}
	base, _, _ := proxydPolicy(proxydOpts{}, noEnv)
	if hasAllow(base, "a.example") {
		t.Fatal("always-allow leaked into default policy")
	}
	browse, profile, err := proxydPolicy(proxydOpts{}, env(map[string]string{"DENYOUT_POLICY_PROFILE": "  Browse ", "DENYOUT_ALWAYS_ALLOW": "c.example"}))
	if err != nil || profile != "browse" || !hasAllow(browse, "c.example") {
		t.Fatalf("browse: %q %v %v", profile, browse, err)
	}
}

func hasAllow(c *policy.Config, host string) bool {
	for _, r := range c.Allow {
		if r.Host == host {
			return true
		}
	}
	return false
}

type fakeSession struct {
	port    int
	stopped bool
	allowed []string
}

func (f *fakeSession) Port() int                     { return f.port }
func (f *fakeSession) Stop() error                   { f.stopped = true; return nil }
func (f *fakeSession) AllowHost(host, reason string) { f.allowed = append(f.allowed, host+":"+reason) }

func TestRunProxyd(t *testing.T) {
	sess := &fakeSession{port: 4321}
	var gotOpts run.SessionOptions
	waited := false
	d := proxydDeps{
		getenv:      func(k string) string { return map[string]string{"DENYOUT_TLS_INSECURE_UPSTREAM": "1"}[k] },
		openThreats: func(context.Context) (policy.ThreatChecker, error) { return nil, errors.New("offline") },
		debugStats:  func() {},
		startSession: func(o run.SessionOptions) (proxySession, error) {
			gotOpts = o
			return sess, nil
		},
		wait: func(onSignal func()) { waited = true; onSignal() },
	}
	d.denyDeps = func(allow func(host, reason string)) denyDeps {
		r := &denyRec{}
		dd := r.deps()
		dd.allowHostFn = allow
		return dd
	}
	o := proxydOpts{port: 99, caDir: "/ca", ask: true, controlURL: "C"}
	code, _, errS := capture(t, func() int { return runProxyd(o, d) })
	if code != 0 || !waited || !sess.stopped {
		t.Fatalf("%d %v %v", code, waited, sess.stopped)
	}
	if !strings.Contains(errS, "threatlists: offline (continuing)") || !strings.Contains(errS, "listening :4321 transparent") {
		t.Fatalf("stderr %q", errS)
	}
	if gotOpts.ListenPort != 99 || gotOpts.CADir != "/ca" || !gotOpts.Transparent || !gotOpts.PersistCA || !gotOpts.InsecureSkipVerify ||
		gotOpts.Process != "proxyd" || gotOpts.PolicyProfile != "agent" || gotOpts.Threats != nil || gotOpts.OnDeny == nil {
		t.Fatalf("%+v", gotOpts)
	}
	// the Ask path reaches the session once it exists
	gotOpts.OnDeny("x.com", []string{"host_not_allowed"}, "u")

	d.startSession = func(run.SessionOptions) (proxySession, error) { return nil, errors.New("bind") }
	code, _, errS = capture(t, func() int { return runProxyd(o, d) })
	if code != 2 || !strings.HasSuffix(errS, "denyout-cli hostctl proxyd: bind\n") {
		t.Fatalf("%d %q", code, errS)
	}
}

func TestControlClient(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var bodies []string
	askReply := `{"action":"once"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		bodies = append(bodies, string(b))
		mu.Unlock()
		if r.URL.Path == "/ask" {
			_, _ = io.WriteString(w, askReply)
		}
	}))
	defer srv.Close()

	if got := askViaControl(srv.URL+"/", "a b.com"); got != "once" || paths[0] != "/ask?host=a+b.com" {
		t.Fatalf("%q %v", got, paths)
	}
	for reply, want := range map[string]string{`{"action":"always"}`: "always", `{"action":"deny"}`: "deny", `{"action":"zzz"}`: "deny", `not json`: "deny"} {
		askReply = reply
		if got := askViaControl(srv.URL, "h"); got != want {
			t.Errorf("%s: %q", reply, got)
		}
	}
	if got := askViaControl("http://127.0.0.1:1", "h"); got != "deny" {
		t.Fatalf("unreachable: %q", got)
	}

	postControlAlways(srv.URL, "h.com")
	postControlDenyEvent(srv.URL+"/", "h.com", []string{"r1"}, "http://h.com/x", true)
	postControlAlways("http://127.0.0.1:1", "h")
	postControlDenyEvent("http://127.0.0.1:1", "h", nil, "", false)
	n := len(paths)
	if paths[n-2] != "/always" || paths[n-1] != "/deny-event" {
		t.Fatalf("%v", paths)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(bodies[n-1]), &ev); err != nil || ev["host"] != "h.com" || ev["url"] != "http://h.com/x" || ev["notify"] != true {
		t.Fatalf("%v %v", ev, err)
	}
	if bodies[n-2] != `{"host":"h.com"}` {
		t.Fatalf("%q", bodies[n-2])
	}
}
