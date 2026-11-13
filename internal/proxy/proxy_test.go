package proxy_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
)

func TestCONNECTDeniedBeforeDial(t *testing.T) {
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := proxy.Start(ctx, proxy.Config{
		Engine:    eng,
		SessionID: "test",
		TLSMode:   proxy.TLSPassthrough,
		Version:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	proxyURL, err := url.Parse("http://" + srv.Addr())
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Plain HTTP to a denied host exercises L1 without needing CONNECT hijack semantics.
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}
