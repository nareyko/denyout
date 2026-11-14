package threatlists

import (
	"context"
	"time"
)

// AttachResult is Open + optional refresh outcome for Protect start.
type AttachResult struct {
	Store   *Store
	Refresh []RefreshResult
}

// OpenDefault opens the XDG threatlists store and seeds core catalog defaults.
func OpenDefault() (*Store, error) {
	st, err := Open(DefaultDir())
	if err != nil {
		return nil, err
	}
	_ = st.EnsureCatalogDefaults()
	return st, nil
}

// OpenAndRefresh opens the default store and refreshes enabled feeds (best-effort).
// Fetch failures do not return an error — Protect stays up with last good cache.
func OpenAndRefresh(ctx context.Context, force bool) (*AttachResult, error) {
	st, err := OpenDefault()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	u := &Updater{Store: st}
	res := u.RefreshEnabled(ctx, force)
	return &AttachResult{Store: st, Refresh: res}, nil
}
