package threatlists

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBadFetchKeepsPreviousCache(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	good := "127.0.0.1 keep.me\n"
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = io.WriteString(w, good)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "nope")
	}))
	t.Cleanup(srv.Close)

	sub := Subscription{
		ID:       "test-hosts",
		URL:      srv.URL,
		Category: CategoryMalware,
		Format:   FormatHosts,
		Enabled:  true,
	}
	u := &Updater{Store: store}
	r1 := u.RefreshOne(context.Background(), sub)
	if !r1.OK {
		t.Fatalf("first: %+v", r1)
	}
	if id, ok := store.Contains("keep.me", CategoryMalware); !ok || id != "test-hosts" {
		t.Fatalf("expected hit after first fetch")
	}

	r2 := u.RefreshOne(context.Background(), sub)
	if r2.OK {
		t.Fatalf("second should fail: %+v", r2)
	}
	st := store.Status().Feeds["test-hosts"]
	if st.LastError == "" {
		t.Fatal("expected last_error")
	}
	if st.EntryCount != 1 {
		t.Fatalf("cache entries: %d", st.EntryCount)
	}
	if _, ok := store.Contains("keep.me", CategoryMalware); !ok {
		t.Fatal("previous cache must remain active")
	}
}

func TestUndersizedFetchRejected(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	big := strings.Repeat("evil.example\n", 40) // enough bytes
	small := "x.y\n"
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = io.WriteString(w, big)
			return
		}
		_, _ = io.WriteString(w, small)
	}))
	t.Cleanup(srv.Close)

	sub := Subscription{
		ID:       "test-dom",
		URL:      srv.URL,
		Category: CategoryPhishing,
		Format:   FormatDomains,
		Enabled:  true,
	}
	u := &Updater{Store: store}
	if r := u.RefreshOne(context.Background(), sub); !r.OK {
		t.Fatalf("first: %+v", r)
	}
	prev := store.Status().Feeds["test-dom"].Bytes
	if prev < 100 {
		t.Fatalf("expected large first body, got %d", prev)
	}
	r2 := u.RefreshOne(context.Background(), sub)
	if r2.OK {
		t.Fatalf("undersized must fail: %+v", r2)
	}
	if !strings.Contains(r2.Error, "undersized") {
		t.Fatalf("error: %q", r2.Error)
	}
	if store.Status().Feeds["test-dom"].Bytes != prev {
		t.Fatal("bytes must stay at previous good size")
	}
	if _, ok := store.Contains("evil.example", CategoryPhishing); !ok {
		t.Fatal("old domains must remain")
	}
}

func TestURLHausInactiveUntilFirstOK(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	sub := Subscription{
		ID:                 IDURLHaus,
		URL:                srv.URL,
		Category:           CategoryMalware,
		Format:             FormatHosts,
		Enabled:            true,
		ActiveAfterFirstOK: true,
	}
	u := &Updater{Store: store}
	r := u.RefreshOne(context.Background(), sub)
	if r.OK {
		t.Fatal("expected fail")
	}
	st := store.Status().Feeds[IDURLHaus]
	if st.Active {
		t.Fatal("URLhaus must stay inactive without successful fetch")
	}
	if _, ok := store.Contains("anything.example", CategoryMalware); ok {
		t.Fatal("no active set")
	}
}

func TestAtomicSwapReload(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "127.0.0.1 reload.me\n")
	}))
	t.Cleanup(srv.Close)

	sub := Subscription{ID: "reload", URL: srv.URL, Category: CategoryMalware, Format: FormatHosts, Enabled: true}
	u := &Updater{Store: store, Now: func() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) }}
	if r := u.RefreshOne(context.Background(), sub); !r.OK {
		t.Fatalf("%+v", r)
	}

	store2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store2.Contains("reload.me", CategoryMalware); !ok {
		t.Fatal("reopened store must load cache")
	}
}

func TestDisabledFeedNotInContains(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "phish.example\n")
	}))
	t.Cleanup(srv.Close)
	sub := Subscription{ID: IDPhishingArmy, URL: srv.URL, Category: CategoryPhishing, Format: FormatDomains, Enabled: true}
	u := &Updater{Store: store}
	if r := u.RefreshOne(context.Background(), sub); !r.OK {
		t.Fatal(r.Error)
	}
	if err := store.SetEnabled(IDPhishingArmy, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Contains("phish.example", CategoryPhishing); ok {
		t.Fatal("disabled feed must not hit")
	}
}

func TestClampPollHours(t *testing.T) {
	if ClampPollHours(0) != DefaultPollHours {
		t.Fatal()
	}
	if ClampPollHours(1) != MinPollHours {
		t.Fatal()
	}
	if ClampPollHours(999) != MaxPollHours {
		t.Fatal()
	}
}
