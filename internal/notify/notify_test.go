package notify_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/notify"
)

func TestHumanReasonsStable(t *testing.T) {
	notify.SetEnabled(false)
	// Must not panic when disabled.
	notify.Deny("example.com", []string{"host_not_allowed", "secret_in_url"})
	notify.SetEnabled(true)
}

func TestEnabledToggle(t *testing.T) {
	notify.SetEnabled(false)
	if notify.Enabled() {
		t.Fatal("expected disabled")
	}
	notify.SetEnabled(true)
	if !notify.Enabled() {
		t.Fatal("expected enabled")
	}
}
