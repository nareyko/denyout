package hostguard

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestPkexecActionIdIsNotAProgram: polkit pkexec has no --action-id flag.
// Passing it makes pkexec treat "--action-id=…" as PROGRAM (Protect broken when
// com.denyout.hostctl.policy is installed).
func TestPkexecActionIdIsNotAProgram(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if _, err := exec.LookPath("pkexec"); err != nil {
		t.Skip("pkexec missing")
	}
	out, _ := exec.Command("pkexec", "--action-id=com.denyout.hostctl", "/bin/true").CombinedOutput()
	msg := string(out)
	if !strings.Contains(msg, "Cannot run program --action-id=com.denyout.hostctl") {
		t.Fatalf("expected pkexec to reject --action-id as PROGRAM, got %q", msg)
	}

	// elevateLinux source must not reintroduce the invalid flag as a Command arg.
	src, err := os.ReadFile("elevate.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `"--action-id`) || strings.Contains(string(src), "`--action-id") {
		t.Fatal("elevate.go must not pass an action-id flag to pkexec (invalid on modern polkit)")
	}
}
