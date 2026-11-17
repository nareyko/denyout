package hostguard

import (
	"testing"

	"github.com/nareyko/denyout/internal/protectstate"
)

func TestFailPolicyEnvAndSetting(t *testing.T) {
	t.Setenv("DENYOUT_FAIL_CLOSED", "")
	t.Setenv("DENYOUT_FAIL_POLICY", "")
	defer SetFailPolicy("")
	if FailPolicy() != protectstate.FailOpen {
		t.Fatal("default must be open")
	}
	SetFailPolicy(protectstate.FailClosed)
	if FailPolicy() != protectstate.FailClosed {
		t.Fatal("configured closed")
	}
	t.Setenv("DENYOUT_FAIL_POLICY", "open")
	if FailPolicy() != protectstate.FailOpen {
		t.Fatal("env open overrides setting")
	}
	t.Setenv("DENYOUT_FAIL_CLOSED", "1")
	if FailPolicy() != protectstate.FailClosed {
		t.Fatal("legacy env wins")
	}
}

func TestDegradedHook(t *testing.T) {
	n := 0
	SetDegradedHook(func() { n++ })
	defer SetDegradedHook(nil)
	fireDegraded()
	if n != 1 {
		t.Fatal("hook not fired")
	}
}
