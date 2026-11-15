package desktop_test

import (
	"os"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestReexecDetachedIfTTYSkipNoop(t *testing.T) {
	// Must not exit the test process.
	desktop.ReexecDetachedIfTTY(true)
}

func TestReexecDetachedIfTTYAlreadyDetachedNoop(t *testing.T) {
	t.Setenv("DENYOUT_DETACHED", "1")
	desktop.ReexecDetachedIfTTY(false)
}

func TestReexecDetachedIfTTYNonTTYNoop(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	// Pipe is not a char device — must not re-exec / exit.
	desktop.ReexecDetachedIfTTY(false)
}
