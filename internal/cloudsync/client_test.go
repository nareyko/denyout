package cloudsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientMagicLinkVerify(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/magic-link", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("/v1/auth/verify", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "abc"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := &Client{BaseURL: ts.URL, HTTP: ts.Client()}
	if err := c.RequestMagicLink(context.Background(), "u@example.com"); err != nil {
		t.Fatal(err)
	}
	tok, err := c.VerifyMagicLink(context.Background(), "u@example.com", "1")
	if err != nil || tok != "abc" {
		t.Fatalf("%v %q", err, tok)
	}
}

func TestClientGetPutConfig(t *testing.T) {
	var putBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"schema_version":1}`))
		case http.MethodPut:
			putBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	unsigned := &Client{BaseURL: ts.URL, HTTP: ts.Client()}
	if _, err := unsigned.GetConfig(context.Background()); err == nil {
		t.Fatal("expected not signed in")
	}
	if err := unsigned.PutConfig(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected not signed in")
	}

	c := &Client{BaseURL: ts.URL, HTTP: ts.Client(), Token: "tok"}
	raw, err := c.GetConfig(context.Background())
	if err != nil || string(raw) != `{"schema_version":1}` {
		t.Fatalf("%v %s", err, raw)
	}
	if err := c.PutConfig(context.Background(), []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if string(putBody) != `{"ok":true}` {
		t.Fatalf("put body %s", putBody)
	}

	c.Token = "bad"
	if _, err := c.GetConfig(context.Background()); err == nil {
		t.Fatal("expected api error")
	}
}

func TestClientDeleteAccount(t *testing.T) {
	deleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		deleted = true
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := &Client{BaseURL: ts.URL, HTTP: ts.Client()}
	if err := c.DeleteAccount(context.Background()); err == nil {
		t.Fatal("expected not signed in")
	}
	c.Token = "tok"
	if err := c.DeleteAccount(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("delete not called")
	}
}
