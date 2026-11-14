package desktop

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUICheckForUpdatesNewer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"9.9.9","url":"https://example.com/rel","notes":"test notes"}`))
	}))
	defer srv.Close()

	a := &App{
		opts: Options{Version: "0.1.0"},
		state: DefaultState(),
		updateHTTP: srv.Client(),
	}
	a.state.UpdateManifestURL = srv.URL

	view, err := a.UICheckForUpdates()
	if err != nil {
		t.Fatal(err)
	}
	if !view.Newer || view.RemoteVersion != "9.9.9" {
		t.Fatalf("%+v", view)
	}
	if view.Message == "" || containsSignIn(view.Message) {
		t.Fatalf("bad message %q", view.Message)
	}
	snap := a.GetUISnapshot()
	if !snap.UpdateAvailable || snap.UpdateVersion != "9.9.9" {
		t.Fatalf("%+v", snap)
	}
}

func TestUICheckForUpdatesFailOpen(t *testing.T) {
	a := &App{
		opts: Options{Version: "0.1.0"},
		state: DefaultState(),
		updateHTTP: &http.Client{},
	}
	a.state.UpdateManifestURL = "http://127.0.0.1:1"
	view, err := a.UICheckForUpdates()
	if err != nil {
		t.Fatal(err)
	}
	if view.Newer {
		t.Fatal("expected not newer")
	}
	if view.Message == "" || containsSignIn(view.Message) {
		t.Fatalf("%q", view.Message)
	}
}

func containsSignIn(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "sign in") || strings.Contains(low, "register") || strings.Contains(low, "account")
}
