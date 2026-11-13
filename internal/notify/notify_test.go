package notify_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/notify"
)

func TestHumanReasonsStable(t *testing.T) {
	notify.SetEnabled(false)
	notify.Deny("example.com", []string{"host_not_allowed", "secret_in_url"})
	notify.SetEnabled(true)

	s := notify.HumanReasons([]string{"host_not_allowed", "secret_in_url"})
	if !strings.Contains(s, "allowed list") || !strings.Contains(s, "secret") {
		t.Fatalf("%q", s)
	}
	if notify.HumanReasons(nil) == "" {
		t.Fatal("empty reasons should still explain")
	}
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
