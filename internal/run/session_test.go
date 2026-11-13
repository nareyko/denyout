package run_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

func TestStartSessionStop(t *testing.T) {
	sess, err := run.StartSession(run.SessionOptions{
		TLSMode: proxy.TLSIntercept,
		Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	st := sess.Status()
	if !st.Running || st.ProxyURL == "" || st.Mode != "enforce" || st.Preset != "models" {
		t.Fatalf("status=%+v", st)
	}
	if st.Env["HTTPS_PROXY"] == "" || st.Env["SSL_CERT_FILE"] == "" {
		t.Fatalf("env incomplete: %+v", st.Env)
	}

	proxyURL, err := url.Parse(st.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	if err := sess.Stop(); err != nil {
		t.Fatal(err)
	}
	if sess.Status().Running {
		t.Fatal("expected stopped")
	}
}

func TestExecChildExit(t *testing.T) {
	code, err := run.Exec(run.Options{
		TLSMode: proxy.TLSPassthrough,
		Version: "test",
		Command: []string{"true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
}
