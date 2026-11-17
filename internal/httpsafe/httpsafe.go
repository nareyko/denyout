// Package httpsafe holds small hardening helpers for the HTTP clients that talk to
// remote services (cloud sync, update manifest, threat feeds).
package httpsafe

import (
	"errors"
	"net/http"
	"time"
)

// MaxRedirects bounds redirect chains (net/http allows 10).
const MaxRedirects = 5

// CheckRedirect refuses redirect chains that leave https for plain http (which would
// expose bearer tokens and make the payload tamperable) and caps the chain length.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return errors.New("too many redirects")
	}
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing https -> http redirect")
	}
	return nil
}

// NewClient returns a client with the given timeout and the hardened redirect policy.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: CheckRedirect}
}
