package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/policy"
)

func TestStripDeniedRedirect(t *testing.T) {
	cfg, err := policy.DefaultWholeDevice()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	s := &Server{cfg: Config{Engine: eng, SessionID: "redir-test", Version: "test", PolicyProfile: "agent"}}

	resp := &http.Response{Header: make(http.Header), StatusCode: http.StatusFound}
	resp.Header.Set("Location", "https://evil.example/exfil")
	s.stripDeniedRedirect(resp, time.Now())
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("expected Location stripped, got %q", loc)
	}
	if resp.Header.Get("X-DenyOut-Redirect") != "stripped" {
		t.Fatal("expected X-DenyOut-Redirect=stripped")
	}

	ok := &http.Response{Header: make(http.Header), StatusCode: http.StatusFound}
	ok.Header.Set("Location", "https://api.anthropic.com/")
	s.stripDeniedRedirect(ok, time.Now())
	if got := ok.Header.Get("Location"); got != "https://api.anthropic.com/" {
		t.Fatalf("allowlisted Location should remain, got %q", got)
	}

	rel := &http.Response{Header: make(http.Header), StatusCode: http.StatusFound}
	rel.Header.Set("Location", "/relative/path")
	s.stripDeniedRedirect(rel, time.Now())
	if got := rel.Header.Get("Location"); got != "/relative/path" {
		t.Fatalf("relative Location should remain, got %q", got)
	}
}
