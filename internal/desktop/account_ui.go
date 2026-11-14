package desktop

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/cloudsync"
)

// AccountView is Settings -> Account status (optional; never required for Protect).
type AccountView struct {
	SignedIn    bool   `json:"signed_in"`
	Email       string `json:"email,omitempty"`
	APIBase     string `json:"api_base,omitempty"`
	SyncEnabled bool   `json:"sync_enabled"`
	TrustLine   string `json:"trust_line"`
}

const accountTrustLine = "Sign in to sync settings across computers. DenyOut works fully without an account."

func (a *App) accountClientLocked() *cloudsync.Client {
	base := strings.TrimSpace(a.state.AccountAPIBase)
	if base == "" {
		base = strings.TrimSpace(os.Getenv("DENYOUT_API_BASE"))
	}
	return &cloudsync.Client{
		BaseURL: base,
		HTTP:    a.accountHTTP,
		Token:   a.state.AccountToken,
	}
}

// GetAccountView returns account status for the UI.
func (a *App) GetAccountView() AccountView {
	a.mu.Lock()
	defer a.mu.Unlock()
	return accountViewLocked(a)
}

func accountViewLocked(a *App) AccountView {
	email := strings.TrimSpace(a.state.AccountEmail)
	tok := strings.TrimSpace(a.state.AccountToken)
	base := strings.TrimSpace(a.state.AccountAPIBase)
	if base == "" {
		base = strings.TrimSpace(os.Getenv("DENYOUT_API_BASE"))
	}
	if base == "" {
		base = cloudsync.DefaultAPIBase
	}
	syncOn := a.state.SyncEnabled
	if !a.state.SyncEnabledSet {
		syncOn = true // default ON after login; meaningless when signed out
	}
	return AccountView{
		SignedIn:    email != "" && tok != "",
		Email:       email,
		APIBase:     base,
		SyncEnabled: syncOn,
		TrustLine:   accountTrustLine,
	}
}

// UISetAccountAPIBase stores the API base URL (Advanced / local stub).
func (a *App) UISetAccountAPIBase(base string) error {
	a.mu.Lock()
	a.state.AccountAPIBase = strings.TrimSpace(base)
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// UISetSyncEnabled toggles cloud config sync when signed in (pull/push in SYNC-WIRE).
func (a *App) UISetSyncEnabled(on bool) error {
	a.mu.Lock()
	a.state.SyncEnabled = on
	a.state.SyncEnabledSet = true
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// UIRequestMagicLink emails (or stub-logs) a one-time code.
func (a *App) UIRequestMagicLink(email string) error {
	email = strings.TrimSpace(email)
	if email == "" || !strings.Contains(email, "@") {
		return errAccount("enter a valid email")
	}
	a.mu.Lock()
	cli := a.accountClientLocked()
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return cli.RequestMagicLink(ctx, email)
}

// UIVerifyMagicLink completes sign-in and stores the session token locally.
func (a *App) UIVerifyMagicLink(email, code string) error {
	email = strings.TrimSpace(email)
	code = strings.TrimSpace(code)
	if email == "" || code == "" {
		return errAccount("email and code required")
	}
	a.mu.Lock()
	cli := a.accountClientLocked()
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tok, err := cli.VerifyMagicLink(ctx, email, code)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.state.AccountEmail = strings.ToLower(email)
	a.state.AccountToken = tok
	if !a.state.SyncEnabledSet {
		a.state.SyncEnabled = true
	}
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// UISignOut clears the local session (does not require network).
func (a *App) UISignOut() error {
	a.mu.Lock()
	a.state.AccountEmail = ""
	a.state.AccountToken = ""
	st := a.state
	a.mu.Unlock()
	return SaveState(st)
}

// UIDeleteCloudData deletes the cloud account + synced config, then signs out locally.
// Local Protect settings stay on disk.
func (a *App) UIDeleteCloudData() error {
	a.mu.Lock()
	cli := a.accountClientLocked()
	signedIn := strings.TrimSpace(a.state.AccountToken) != ""
	a.mu.Unlock()
	if !signedIn {
		return errAccount("sign in first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := cli.DeleteAccount(ctx); err != nil {
		return err
	}
	return a.UISignOut()
}

func errAccount(msg string) error {
	return &accountError{msg: msg}
}

type accountError struct{ msg string }

func (e *accountError) Error() string { return e.msg }
