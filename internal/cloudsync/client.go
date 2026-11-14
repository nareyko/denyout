package cloudsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultAPIBase is the production API host.
const DefaultAPIBase = "https://api.denyout.com"

// Client talks to the DenyOut cloud API (auth + settings sync).
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Token   string
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *Client) base() string {
	u := DefaultAPIBase
	if c != nil && strings.TrimSpace(c.BaseURL) != "" {
		u = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	}
	return u
}

// RequestMagicLink starts email OTP (server may only log code in stub).
func (c *Client) RequestMagicLink(ctx context.Context, email string) error {
	body, _ := json.Marshal(map[string]string{"email": strings.TrimSpace(email)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/v1/auth/magic-link", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return apiErr(res)
	}
	return nil
}

// VerifyMagicLink exchanges email+code for a session token.
func (c *Client) VerifyMagicLink(ctx context.Context, email, code string) (token string, err error) {
	body, _ := json.Marshal(map[string]string{
		"email": strings.TrimSpace(email),
		"code":  strings.TrimSpace(code),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/v1/auth/verify", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return "", apiErr(res)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token")
	}
	return out.Token, nil
}

// GetConfig downloads the signed-in settings document (raw JSON).
func (c *Client) GetConfig(ctx context.Context) ([]byte, error) {
	if c == nil || strings.TrimSpace(c.Token) == "" {
		return nil, fmt.Errorf("not signed in")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+"/v1/me/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return nil, apiErr(res)
	}
	return io.ReadAll(io.LimitReader(res.Body, 1<<20))
}

// PutConfig uploads the settings document JSON.
func (c *Client) PutConfig(ctx context.Context, raw []byte) error {
	if c == nil || strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("not signed in")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base()+"/v1/me/config", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return apiErr(res)
	}
	return nil
}

// DeleteAccount removes the cloud account and synced config (GDPR baseline).
func (c *Client) DeleteAccount(ctx context.Context) error {
	if c == nil || strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("not signed in")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base()+"/v1/me", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return apiErr(res)
	}
	return nil
}

func apiErr(res *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	if e.Error != "" {
		return fmt.Errorf("api %d: %s", res.StatusCode, e.Error)
	}
	return fmt.Errorf("api %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
}
