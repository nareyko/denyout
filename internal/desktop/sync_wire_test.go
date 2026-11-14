package desktop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUISyncNowLocalOnlyWhenSignedOut(t *testing.T) {
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	res, err := a.UISyncNow()
	if err != nil || !res.OK || !strings.Contains(res.Message, "Local only") {
		t.Fatalf("%v %+v", err, res)
	}
	if res.Pushed || res.Pulled {
		t.Fatal(res)
	}
}

func TestUISyncNowPushAndPull(t *testing.T) {
	var stored []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if len(stored) == 0 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"schema_version": 1,
					"updated_at": time.Time{}.UTC().Format(time.RFC3339),
					"settings": map[string]any{},
				})
				return
			}
			_, _ = w.Write(stored)
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			stored = append([]byte(nil), b...)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	a := &App{opts: Options{Version: "test"}, state: DefaultState(), accountHTTP: ts.Client()}
	a.state.AccountAPIBase = ts.URL
	a.state.AccountEmail = "u@example.com"
	a.state.AccountToken = "tok"
	a.state.SyncEnabled = true
	a.state.SyncEnabledSet = true
	a.state.NotifyLevel = "detailed"
	a.state.ConfigUpdatedAt = time.Now().UTC().Format(time.RFC3339)

	res, err := a.UISyncNow()
	if err != nil || !res.Pushed {
		t.Fatalf("first push: %v %+v", err, res)
	}
	if len(stored) == 0 || !strings.Contains(string(stored), "detailed") {
		t.Fatalf("stored %s", stored)
	}

	// Newer remote should pull
	newer := `{"schema_version":1,"updated_at":"2099-01-01T00:00:00Z","settings":{"notify_level":"quiet","always_allow_hosts":["cloud.example"]}}`
	stored = []byte(newer)
	a.state.ConfigUpdatedAt = "2020-01-01T00:00:00Z"
	res, err = a.UISyncNow()
	if err != nil || !res.Pulled {
		t.Fatalf("pull: %v %+v", err, res)
	}
	if a.state.NotifyLevel != "quiet" || len(a.state.AlwaysAllowHosts) != 1 {
		t.Fatalf("%+v", a.state)
	}
}

func TestUISyncNowDisabled(t *testing.T) {
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	a.state.AccountEmail = "u@example.com"
	a.state.AccountToken = "tok"
	a.state.SyncEnabled = false
	a.state.SyncEnabledSet = true
	res, err := a.UISyncNow()
	if err != nil || res.Pushed || !strings.Contains(res.Message, "turned off") {
		t.Fatalf("%v %+v", err, res)
	}
}
