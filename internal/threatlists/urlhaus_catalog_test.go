package threatlists

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestURLHausCatalogUsesMirrorNotRetiredKeyless(t *testing.T) {
	sub, ok := CatalogByID(IDURLHaus)
	if !ok {
		t.Fatal("urlhaus-hosts missing from catalog")
	}
	if strings.Contains(sub.URL, "urlhaus.abuse.ch/downloads") {
		t.Fatalf("legacy keyless abuse.ch URL retired (HTTP 410): %s", sub.URL)
	}
	if !strings.Contains(sub.URL, "urlhaus-filter-hosts") {
		t.Fatalf("expected urlhaus-filter hosts mirror, got %s", sub.URL)
	}
	if sub.Format != FormatHosts {
		t.Fatalf("format=%s want hosts", sub.Format)
	}
	if !sub.ActiveAfterFirstOK {
		t.Fatal("URLhaus must stay inactive until first OK")
	}
}

func TestURLHausMirrorRefreshLive(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sub, ok := CatalogByID(IDURLHaus)
	if !ok {
		t.Fatal("missing catalog")
	}
	u := &Updater{Store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r := u.RefreshOne(ctx, sub)
	if !r.OK {
		t.Fatalf("mirror refresh failed: %+v", r)
	}
	if r.Entries < 100 {
		t.Fatalf("entries=%d too small", r.Entries)
	}
	st := store.Status().Feeds[IDURLHaus]
	if !st.Active || st.LastError != "" {
		t.Fatalf("status active=%v err=%q", st.Active, st.LastError)
	}
}
