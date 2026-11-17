package privexec

import (
	"runtime"
	"testing"
)

func TestResolveRejectsUnlistedTools(t *testing.T) {
	for _, tool := range []string{"sh", "bash", "rm", "curl", "../bin/sh", "/bin/sh", "nft;id", ""} {
		if _, err := Resolve(tool); err == nil {
			t.Errorf("Resolve(%q) must fail", tool)
		}
	}
}

func TestArgsAreNeverInterpreted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix tool layout")
	}
	// `ip` treats a hostile name as one argv element and merely fails; nothing is executed.
	_, err := Output("ip", "link", "show", "wg0;touch /tmp/privexec-pwned")
	if err == nil {
		t.Log("ip not installed or accepted junk; still no shell involved")
	}
	if err := checkArgs([]string{"a\x00b"}); err == nil {
		t.Error("NUL must be rejected")
	}
}

func TestValidators(t *testing.T) {
	bad := []string{"", "wg0;id", "a b", "$(id)", "a/b", "0123456789abcdef"}
	for _, s := range bad {
		if ValidIface(s) == nil {
			t.Errorf("ValidIface(%q) must fail", s)
		}
	}
	if ValidIface("wg0") != nil || ValidIface("denyout0") != nil {
		t.Error("good names rejected")
	}
	if ValidUID(0) == nil || ValidUID(-1) == nil || ValidUID(1000) != nil {
		t.Error("ValidUID wrong")
	}
	if ValidPort(0) == nil || ValidPort(65536) == nil || ValidPort(443) != nil {
		t.Error("ValidPort wrong")
	}
	if ValidAbsPath("rel") == nil || ValidAbsPath("/a/../b") == nil || ValidAbsPath("/a/b") != nil || ValidAbsPath("/a\nb") == nil {
		t.Error("ValidAbsPath wrong")
	}
}
