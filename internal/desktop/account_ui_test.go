package desktop

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountSignInOut(t *testing.T) {
	var lastOTP string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/magic-link", func(w http.ResponseWriter, r *http.Request) {
		lastOTP = "424242"
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	mux.HandleFunc("/v1/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "424242") {
			http.Error(w, `{"error":"bad"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok-test", "email": "a@example.com"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	a := &App{opts: Options{Version: "test"}, state: DefaultState(), accountHTTP: ts.Client()}
	a.state.AccountAPIBase = ts.URL

	if a.GetAccountView().SignedIn {
		t.Fatal("expected signed out")
	}
	if !strings.Contains(a.GetAccountView().TrustLine, "without an account") {
		t.Fatal(a.GetAccountView().TrustLine)
	}
	if err := a.UIRequestMagicLink("a@example.com"); err != nil {
		t.Fatal(err)
	}
	if lastOTP == "" {
		t.Fatal("otp not requested")
	}
	if err := a.UIVerifyMagicLink("a@example.com", lastOTP); err != nil {
		t.Fatal(err)
	}
	v := a.GetAccountView()
	if !v.SignedIn || v.Email != "a@example.com" {
		t.Fatalf("%+v", v)
	}
	snap := a.GetUISnapshot()
	if !snap.AccountSignedIn || snap.AccountEmail != "a@example.com" {
		t.Fatalf("%+v", snap)
	}
	// Protect / mode fields still work without requiring account
	if snap.Mode == "" {
		t.Fatal("mode empty")
	}
	if err := a.UISignOut(); err != nil {
		t.Fatal(err)
	}
	if a.GetAccountView().SignedIn {
		t.Fatal("still signed in")
	}
}

func TestAccountInvalidEmail(t *testing.T) {
	a := &App{state: DefaultState()}
	if err := a.UIRequestMagicLink("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestUIDeleteCloudData(t *testing.T) {
	a := &App{opts: Options{Version: "test"}, state: DefaultState()}
	if err := a.UIDeleteCloudData(); err == nil {
		t.Fatal("expected sign in first")
	}
	deleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		deleted = true
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	a.state.AccountAPIBase = ts.URL
	a.state.AccountEmail = "a@example.com"
	a.state.AccountToken = "tok"
	a.accountHTTP = ts.Client()
	if err := a.UIDeleteCloudData(); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("API not called")
	}
	if a.GetAccountView().SignedIn {
		t.Fatal("should be signed out")
	}
}
