package desktop

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestUndoOfferArmTakeDismiss(t *testing.T) {
	a := &App{state: DefaultState()}
	var n atomic.Int32
	a.armUndoOffer(undoOfferAllow, "ex.com", "Allowed ex.com", 2*time.Second, func() {
		n.Add(1)
	})
	a.mu.Lock()
	view := a.undoOfferViewLocked()
	a.mu.Unlock()
	if view == nil || view.Host != "ex.com" || view.Kind != undoOfferAllow {
		t.Fatalf("view=%+v", view)
	}
	if err := a.UITakeUndoOffer(); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 1 {
		t.Fatalf("undo calls=%d", n.Load())
	}
	if err := a.UITakeUndoOffer(); err == nil {
		t.Fatal("second take should fail")
	}
	a.armUndoOffer(undoOfferResumePause, "", "Protect on again", time.Second, nil)
	if err := a.UIDismissUndoOffer(); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	if a.undoOfferViewLocked() != nil {
		t.Fatal("expected dismissed")
	}
	a.mu.Unlock()
}

func TestEmitAllowUndoBannerInAppOnly(t *testing.T) {
	a := &App{state: DefaultState()}
	undoBannerMu.Lock()
	undoBannerHost = ""
	undoBannerAt = time.Time{}
	undoBannerMu.Unlock()
	var n atomic.Int32
	a.emitAllowUndoBanner("a.example", "Allowed a.example", func() { n.Add(1) })
	a.emitAllowUndoBanner("a.example", "Allowed again", func() { n.Add(1) }) // throttle
	a.mu.Lock()
	v := a.undoOfferViewLocked()
	a.mu.Unlock()
	if v == nil || v.Host != "a.example" {
		t.Fatalf("offer=%+v", v)
	}
	if err := a.UITakeUndoOffer(); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 1 {
		t.Fatalf("want 1 undo, got %d", n.Load())
	}
}

func TestUndoOfferExpires(t *testing.T) {
	a := &App{state: DefaultState()}
	a.armUndoOffer(undoOfferAllow, "gone.example", "temp", time.Millisecond, nil)
	time.Sleep(20 * time.Millisecond)
	a.mu.Lock()
	v := a.undoOfferViewLocked()
	a.mu.Unlock()
	if v != nil {
		t.Fatalf("expired offer still visible: %+v", v)
	}
}
