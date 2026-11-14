package updates

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest([]byte(`{"version":"0.3.0","url":"https://example.com/r","notes":"hi","channel":"stable","published_at":"2026-11-14T00:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.3.0" || m.URL == "" || m.Notes != "hi" {
		t.Fatalf("%+v", m)
	}
	if _, err := ParseManifest([]byte(`{}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		remote, local string
		want          bool
	}{
		{"0.3.0", "0.2.1", true},
		{"0.2.1", "0.2.1", false},
		{"0.2.0", "0.2.1", false},
		{"v1.0.0", "0.9.9", true},
		{"1.0.0-beta", "0.9.0", true},
		{"1.0.0", "dev", false},
		{"1.0.0", "", false},
	}
	for _, c := range cases {
		if got := IsNewer(c.remote, c.local); got != c.want {
			t.Fatalf("IsNewer(%q,%q)=%v want %v", c.remote, c.local, got, c.want)
		}
	}
}

func TestFetchAndCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("no auth expected")
		}
		_, _ = w.Write([]byte(`{"version":"9.9.9","url":"https://example.com/x"}`))
	}))
	defer srv.Close()

	m, err := Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil || m.Version != "9.9.9" {
		t.Fatalf("%v %+v", err, m)
	}
	res, err := Check(context.Background(), srv.Client(), srv.URL, "1.0.0")
	if err != nil || !res.Newer {
		t.Fatalf("%v %+v", err, res)
	}
	res, err = Check(context.Background(), srv.Client(), srv.URL, "dev")
	if err != nil || res.Newer {
		t.Fatalf("dev should not be newer: %v %+v", err, res)
	}
}

func TestFetchFailOpen(t *testing.T) {
	_, err := Fetch(context.Background(), &http.Client{}, "http://127.0.0.1:1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func BenchmarkIsNewer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = IsNewer("1.2.3", "1.2.2")
	}
}
