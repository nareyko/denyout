package httpsafe

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckRedirect(t *testing.T) {
	mk := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	if err := CheckRedirect(mk("https://b/"), []*http.Request{mk("https://a/")}); err != nil {
		t.Errorf("https->https: %v", err)
	}
	if err := CheckRedirect(mk("http://b/"), []*http.Request{mk("https://a/")}); err == nil {
		t.Error("https->http must be refused")
	}
	if err := CheckRedirect(mk("https://b/"), []*http.Request{mk("http://a/")}); err != nil {
		t.Errorf("http->https upgrade should pass: %v", err)
	}
	via := make([]*http.Request, MaxRedirects)
	for i := range via {
		via[i] = mk("https://a/")
	}
	if err := CheckRedirect(mk("https://b/"), via); err == nil {
		t.Error("long chain must be refused")
	}
}

func TestClientStopsDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downgraded request reached the plain server")
	}))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()
	c := tls.Client() // trusts the test cert
	c.CheckRedirect = NewClient(time.Second).CheckRedirect
	if _, err := c.Get(tls.URL); err == nil {
		t.Fatal("expected redirect downgrade error")
	}
}
