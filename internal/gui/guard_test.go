package gui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGuardLocal(t *testing.T) {
	h := guardLocal("127.0.0.1:9000", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	do := func(method, host, origin, ct string) int {
		req := httptest.NewRequest(method, "http://"+host+"/api/wrap/start", strings.NewReader("{}"))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := do("POST", "127.0.0.1:9000", "", "application/json"); c != 204 {
		t.Errorf("legit=%d", c)
	}
	if c := do("POST", "evil.example:9000", "", "application/json"); c != 403 {
		t.Errorf("rebinding host=%d", c)
	}
	if c := do("POST", "127.0.0.1:9000", "https://evil.example", "application/json"); c != 403 {
		t.Errorf("foreign origin=%d", c)
	}
	if c := do("POST", "127.0.0.1:9000", "", "text/plain"); c != 415 {
		t.Errorf("form post=%d", c)
	}
}
