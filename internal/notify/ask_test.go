package notify_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/notify"
)

func TestAskDisabledNoPanic(t *testing.T) {
	notify.SetEnabled(false)
	notify.Ask(notify.AskOptions{Host: "example.com"})
	notify.AskNotify("example.com")
	notify.SetEnabled(true)
}

func TestAskActionConstants(t *testing.T) {
	if notify.AskOnce != "once" || notify.AskAlways != "always" || notify.AskDeny != "deny" {
		t.Fatal("action constants")
	}
}
