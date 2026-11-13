package check

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/secrets"
)

const (
	VerdictAllow = "allow"
	VerdictDeny  = "deny"
)

// Result is the output of denyout check.
type Result struct {
	URL     string   `json:"url"`
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
	Mode    string   `json:"mode"`
	Preset  string   `json:"preset,omitempty"`
}

// URL evaluates rawURL against cfg (no network dial).
func URL(cfg *policy.Config, rawURL string) (*Result, error) {
	d, err := policy.EvaluateURL(cfg, rawURL)
	if err != nil {
		return nil, err
	}
	return &Result{
		URL:     secrets.RedactURL(rawURL),
		Verdict: d.Verdict,
		Reasons: d.Reasons,
		Mode:    cfg.Mode,
		Preset:  cfg.Preset,
	}, nil
}

// Human formats a one-line human result without raw secrets.
func (r *Result) Human() string {
	rs := strings.Join(r.Reasons, ",")
	if rs == "" {
		rs = "-"
	}
	return fmt.Sprintf("verdict=%s reasons=%s url=%s", r.Verdict, rs, r.URL)
}

// JSON returns compact JSON.
func (r *Result) JSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"verdict":"deny","reasons":["internal_error"]}`
	}
	return string(b)
}
