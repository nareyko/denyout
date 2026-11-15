package hostguard

import (
	"errors"
	"fmt"
	"testing"
)

func TestElevateDisabledByEnv(t *testing.T) {
	t.Setenv("DENYOUT_TEST_NO_ELEVATE", "")
	t.Setenv("GITHUB_ACTIONS", "")
	if ElevateDisabledByEnv() {
		t.Fatal("expected elevate enabled with empty env")
	}
	t.Setenv("DENYOUT_TEST_NO_ELEVATE", "1")
	if !ElevateDisabledByEnv() {
		t.Fatal("DENYOUT_TEST_NO_ELEVATE=1 should disable")
	}
	t.Setenv("DENYOUT_TEST_NO_ELEVATE", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	if !ElevateDisabledByEnv() {
		t.Fatal("GITHUB_ACTIONS=true should disable")
	}
}

func TestIsElevateDisabled(t *testing.T) {
	if IsElevateDisabled(nil) {
		t.Fatal("nil")
	}
	if IsElevateDisabled(ErrNeedsAdmin) {
		t.Fatal("plain NeedsAdmin is not test skip")
	}
	wrapped := fmt.Errorf("%w (linux): %w", ErrNeedsAdmin, ErrElevateDisabled)
	if !IsElevateDisabled(wrapped) {
		t.Fatalf("wrapped: %v", wrapped)
	}
	if !errors.Is(wrapped, ErrNeedsAdmin) {
		t.Fatal("still NeedsAdmin for callers")
	}
}
