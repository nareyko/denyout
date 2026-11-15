package desktop

import (
	"fmt"
	"strings"
	"time"
)

const (
	undoOfferAllow         = "allow"
	undoOfferResumePause   = "resume_pause"
	undoOfferDefaultAllow  = 10 * time.Second
	undoOfferDefaultResume = 5 * time.Second
)

// UndoOfferView is the in-app Undo strip (Pass 29 — no OS Undo button).
type UndoOfferView struct {
	Kind      string `json:"kind"` // allow | resume_pause
	Host      string `json:"host,omitempty"`
	Body      string `json:"body"`
	ExpiresAt string `json:"expires_at"` // RFC3339
}

type undoOffer struct {
	kind    string
	host    string
	body    string
	expires time.Time
	onUndo  func()
}

// armUndoOffer stores a short-lived in-app Undo. Replaces any previous offer.
func (a *App) armUndoOffer(kind, host, body string, ttl time.Duration, onUndo func()) {
	if ttl <= 0 {
		ttl = undoOfferDefaultAllow
	}
	host = strings.TrimSpace(strings.ToLower(host))
	body = strings.TrimSpace(body)
	if body == "" {
		body = "Undo within a few seconds."
	}
	a.mu.Lock()
	a.undoOffer = &undoOffer{
		kind:    kind,
		host:    host,
		body:    body,
		expires: time.Now().Add(ttl),
		onUndo:  onUndo,
	}
	a.mu.Unlock()
}

func (a *App) clearUndoOfferLocked() {
	a.undoOffer = nil
}

func (a *App) undoOfferViewLocked() *UndoOfferView {
	u := a.undoOffer
	if u == nil {
		return nil
	}
	if !time.Now().Before(u.expires) {
		a.clearUndoOfferLocked()
		return nil
	}
	return &UndoOfferView{
		Kind:      u.kind,
		Host:      u.host,
		Body:      u.body,
		ExpiresAt: u.expires.UTC().Format(time.RFC3339),
	}
}

// undoOfferActive reports a live offer for tray tooltip (no lock held by caller).
func (a *App) undoOfferActive() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.undoOfferViewLocked() != nil
}

// UITakeUndoOffer runs the pending Undo callback (Allow revoke or pause-again).
func (a *App) UITakeUndoOffer() error {
	a.mu.Lock()
	u := a.undoOffer
	if u == nil || !time.Now().Before(u.expires) {
		a.clearUndoOfferLocked()
		a.mu.Unlock()
		return fmt.Errorf("Nothing to undo (expired or already used)")
	}
	fn := u.onUndo
	a.clearUndoOfferLocked()
	a.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

// UIDismissUndoOffer clears the strip without undoing.
func (a *App) UIDismissUndoOffer() error {
	a.mu.Lock()
	a.clearUndoOfferLocked()
	a.mu.Unlock()
	return nil
}
