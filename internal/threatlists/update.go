package threatlists

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// UndersizeRatio rejects a new body smaller than this fraction of the previous
// successful byte size (unless first fetch). Locked plan: 25%.
const UndersizeRatio = 0.25

// StaleAttentionAge is when all enabled feeds trigger Problems attention.
const StaleAttentionAge = 7 * 24 * time.Hour

// HTTPDoer is satisfied by *http.Client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Updater fetches subscriptions into a Store.
type Updater struct {
	Store  *Store
	Client HTTPDoer
	Now    func() time.Time
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

func (u *Updater) client() HTTPDoer {
	if u.Client != nil {
		return u.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// RefreshResult is one feed attempt outcome.
type RefreshResult struct {
	ID      string
	OK      bool
	Skipped bool
	Error   string
	Entries int
	Bytes   int
}

// RefreshEnabled fetches every enabled feed that is due (or all if force).
// Failures keep prior cache. Seeds core catalog defaults first.
func (u *Updater) RefreshEnabled(ctx context.Context, force bool) []RefreshResult {
	_ = u.Store.EnsureCatalogDefaults()
	subs := append(CoreCatalog(), AdvancedCatalog()...)
	var out []RefreshResult
	status := u.Store.Status()
	for _, sub := range subs {
		st, ok := status.Feeds[sub.ID]
		enabled := sub.Enabled
		if ok {
			enabled = st.Enabled
		}
		if !enabled {
			continue
		}
		if !force && !u.due(sub, st) {
			out = append(out, RefreshResult{ID: sub.ID, Skipped: true})
			continue
		}
		out = append(out, u.RefreshOne(ctx, sub))
	}
	return out
}

func (u *Updater) due(sub Subscription, st FeedStatus) bool {
	if st.LastSuccess.IsZero() {
		return true
	}
	hours := u.Store.Status().PollHours
	if sub.PollHours > 0 {
		hours = sub.PollHours
	}
	hours = ClampPollHours(hours)
	return u.now().Sub(st.LastSuccess) >= time.Duration(hours)*time.Hour
}

// RefreshOne downloads, validates, parses, and atomically swaps one feed.
func (u *Updater) RefreshOne(ctx context.Context, sub Subscription) RefreshResult {
	res := RefreshResult{ID: sub.ID}
	now := u.now()

	u.Store.mu.Lock()
	st := u.Store.status.Feeds[sub.ID]
	st.ID = sub.ID
	st.Category = sub.Category
	st.Format = sub.Format
	st.LastAttempt = now
	if _, ok := u.Store.status.Feeds[sub.ID]; !ok {
		st.Enabled = sub.Enabled
	}
	u.Store.status.Feeds[sub.ID] = st
	prevBytes := st.Bytes
	_ = u.Store.saveStatusLocked()
	u.Store.mu.Unlock()

	raw, err := u.download(ctx, sub.URL)
	if err != nil {
		return u.fail(sub, res, err.Error())
	}
	res.Bytes = len(raw)
	if len(raw) == 0 {
		return u.fail(sub, res, "empty body")
	}
	if prevBytes > 0 && float64(len(raw)) < UndersizeRatio*float64(prevBytes) {
		return u.fail(sub, res, fmt.Sprintf("undersized body: %d bytes (previous %d)", len(raw), prevBytes))
	}

	set := Parse(raw, sub.Format)
	if len(set) == 0 {
		return u.fail(sub, res, "parsed zero hosts")
	}

	if err := u.Store.atomicWriteFeed(sub.ID, raw); err != nil {
		return u.fail(sub, res, err.Error())
	}

	u.Store.mu.Lock()
	defer u.Store.mu.Unlock()
	u.Store.sets[sub.ID] = set
	st = u.Store.status.Feeds[sub.ID]
	st.LastSuccess = now
	st.LastAttempt = now
	st.LastError = ""
	st.EntryCount = len(set)
	st.Bytes = len(raw)
	// Keep user Enabled if already set; otherwise catalog default.
	if _, ok := u.Store.status.Feeds[sub.ID]; !ok {
		st.Enabled = sub.Enabled
	}
	st.Active = st.Enabled // first successful fetch activates (incl. URLhaus)
	u.Store.status.Feeds[sub.ID] = st
	_ = u.Store.saveStatusLocked()

	res.OK = true
	res.Entries = len(set)
	res.Bytes = len(raw)
	return res
}

func (u *Updater) fail(sub Subscription, res RefreshResult, msg string) RefreshResult {
	u.Store.mu.Lock()
	defer u.Store.mu.Unlock()
	st := u.Store.status.Feeds[sub.ID]
	st.ID = sub.ID
	st.Category = sub.Category
	st.Format = sub.Format
	st.LastAttempt = u.now()
	st.LastError = msg
	// Keep prior Active/EntryCount/Bytes/cache. Never-succeeded ActiveAfterFirstOK stays inactive.
	if sub.ActiveAfterFirstOK && st.LastSuccess.IsZero() {
		st.Active = false
	}
	u.Store.status.Feeds[sub.ID] = st
	_ = u.Store.saveStatusLocked()
	res.OK = false
	res.Error = msg
	return res
}

func (u *Updater) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DenyOut-threatlists/1.0 (+https://github.com/nareyko/denyout)")
	resp, err := u.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
}

// NeedsAttention is true when every enabled feed is stale > 7 days.
func (u *Updater) NeedsAttention() bool {
	return u.Store.AllEnabledStale(u.now(), StaleAttentionAge)
}
