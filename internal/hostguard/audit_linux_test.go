//go:build linux

package hostguard

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fakeProc(t *testing.T, pid int, exeTarget, comm, stat string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if exeTarget != "" {
		if err := os.Symlink(exeTarget, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	return root
}

func TestDescribePeerFromProc(t *testing.T) {
	root := fakeProc(t, 4242, "/usr/bin/nc (deleted)", "nc\n", "4242 (nc) S 77 4242 4242 0 -1")
	p := describePeer(peerCreds{PID: 4242, UID: 1000, OK: true}, 1000, root)
	if p.PID != 4242 || p.UID != 1000 || p.PPID != 77 || p.Comm != "nc" {
		t.Fatalf("%+v", p)
	}
	// The kernel appends " (deleted)" to a replaced binary; the path is reported without it.
	if p.Exe != "/usr/bin/nc (deleted)"[:len("/usr/bin/nc")] && p.Exe != "/usr/bin/nc" {
		t.Fatalf("exe %q", p.Exe)
	}
	if p.ExeClass != ExeOther || p.Trusted {
		t.Fatalf("nc must be untrusted: %+v", p)
	}
}

func TestDescribePeerExitedOrUnreadable(t *testing.T) {
	root := t.TempDir() // no /proc/<pid> at all
	p := describePeer(peerCreds{PID: 999999, UID: 1000, OK: true}, 1000, root)
	if p.ExeClass != ExeUnknown || p.Trusted || p.Exe != "" || p.PID != 999999 || p.UID != 1000 {
		t.Fatalf("%+v", p)
	}
	if p := describePeer(peerCreds{}, 1000, root); p.UID != -1 || p.ExeClass != ExeUnknown || p.Trusted {
		t.Fatalf("no creds: %+v", p)
	}
}

func TestDescribePeerTrustsTheHelpersOwnBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	root := fakeProc(t, 7, self, "x", "7 (x) S 1 7 7 0")
	// /proc/self/exe of the fake root must resolve to the same inode as the peer exe.
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(self, filepath.Join(root, "self", "exe")); err != nil {
		t.Fatal(err)
	}
	p := describePeer(peerCreds{PID: 7, UID: 1000, OK: true}, 1000, root)
	if p.ExeClass != ExeHelper || !p.Trusted {
		t.Fatalf("%+v", p)
	}
}

// helperTestConn runs handleHelperConn on a real unix socket (SO_PEERCRED needs one) and
// returns the reply line.
func serveOnce(t *testing.T, owner int, line string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		handleHelperConn(c, owner)
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte(line + "\n"))
	resp, _ := bufio.NewReader(c).ReadString('\n')
	<-done
	return strings.TrimSpace(resp)
}

func freshAuditLog(t *testing.T) *AuditLog {
	t.Helper()
	old := currentAuditLog()
	l := NewAuditLog(filepath.Join(t.TempDir(), "a.jsonl"), 0)
	setAuditLog(l)
	t.Cleanup(func() { setAuditLog(old) })
	return l
}

func TestHandleConnAuditsMutatingCountsReadOnly(t *testing.T) {
	stubFx(t)
	l := freshAuditLog(t)
	owner := os.Getuid()
	if owner == 0 {
		owner = 1000 // root peers are always authorized
	}
	if r := serveOnce(t, owner, "remove 0 0 -"); !strings.HasPrefix(r, "OK") {
		t.Fatalf("remove: %q", r)
	}
	if r := serveOnce(t, owner, "caps 0 0 -"); !strings.HasPrefix(r, "OK") {
		t.Fatalf("caps: %q", r)
	}
	if r := serveOnce(t, owner, "nonsense"); !strings.HasPrefix(r, "ERR") {
		t.Fatalf("bad: %q", r)
	}
	tail := l.Tail(10)
	if len(tail.Events) != 2 {
		t.Fatalf("want remove + bad_request, got %+v", tail.Events)
	}
	rm, bad := tail.Events[0], tail.Events[1]
	if rm.Verb != "remove" || rm.Result != AuditOK || !rm.Mutating || !rm.Lowers || rm.Peer.PID != os.Getpid() || rm.Peer.UID != os.Getuid() {
		t.Fatalf("remove event: %+v", rm)
	}
	if rm.Peer.Exe == "" || rm.Peer.ExeClass == ExeUnknown || rm.Peer.Comm == "" {
		t.Fatalf("peer facts missing: %+v", rm.Peer)
	}
	if !rm.Peer.Trusted || rm.Peer.ExeClass != ExeHelper {
		t.Fatalf("the test binary is the helper's own binary here: %+v", rm.Peer)
	}
	if bad.Result != AuditDenied || bad.Reason != "bad_request" || bad.Verb != "" {
		t.Fatalf("bad request event: %+v", bad)
	}
	if tail.ReadCounts["caps"] != 1 {
		t.Fatalf("caps must be counted, not logged: %+v", tail.ReadCounts)
	}
}

func TestHandleConnAuditsUnauthorizedPeer(t *testing.T) {
	stubFx(t)
	l := freshAuditLog(t)
	if os.Getuid() == 0 {
		t.Skip("root peers are always authorized")
	}
	// A configured owner that is neither this uid nor root: the peer is refused.
	owner := os.Getuid() + 12345
	if r := serveOnce(t, owner, "remove 0 0 -"); r != "ERR unauthorized" {
		t.Fatalf("%q", r)
	}
	e := l.Tail(5).Events
	if len(e) != 1 || e[0].Result != AuditDenied || e[0].Reason != "unauthorized" || e[0].Verb != "" {
		t.Fatalf("%+v", e)
	}
}

func TestHandleConnErrorResultAndAuditTailVerb(t *testing.T) {
	calls := stubFx(t)
	_ = calls
	fx.remove = func(Spec) error { return os.ErrPermission }
	l := freshAuditLog(t)
	owner := os.Getuid()
	if owner == 0 {
		owner = 1000
	}
	if r := serveOnce(t, owner, "remove 0 0 -"); !strings.HasPrefix(r, "ERR") {
		t.Fatalf("%q", r)
	}
	e := l.Tail(5).Events
	if len(e) != 1 || e[0].Result != AuditError || e[0].Reason != "handler_failed" {
		t.Fatalf("%+v", e)
	}
	resp := serveOnce(t, owner, "audit-tail 10 0 -")
	tail, err := ParseAuditTailReply(resp)
	if err != nil || len(tail.Events) != 1 || tail.Events[0].Verb != "remove" {
		t.Fatalf("%q %+v %v", resp, tail, err)
	}
	// The same verb over the JSON encoding.
	jr := serveOnce(t, owner, `{"verb":"audit-tail","port":5}`)
	if !strings.Contains(jr, `"ok":true`) || !strings.Contains(jr, "audit1") {
		t.Fatalf("%q", jr)
	}
	// Reading the trail is counted, never logged as an event.
	if got := l.Tail(10); len(got.Events) != 1 || got.ReadCounts["audit-tail"] != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestHelperRequestLowersUsesAppliedState(t *testing.T) {
	lastApplyMu.Lock()
	old, oldOK := lastApplySpec, lastApplyOK
	lastApplySpec, lastApplyOK = Spec{ProxyPort: 18443}, true
	lastApplyMu.Unlock()
	t.Cleanup(func() { lastApplyMu.Lock(); lastApplySpec, lastApplyOK = old, oldOK; lastApplyMu.Unlock() })
	if helperRequestLowers(Request{Verb: "apply", Port: 18443}) {
		t.Fatal("same port is not lowering")
	}
	if !helperRequestLowers(Request{Verb: "apply", Port: 1}) {
		t.Fatal("different port is lowering")
	}
	if !helperRequestLowers(Request{Verb: "teardown"}) {
		t.Fatal("teardown lowers")
	}
}

func TestCapsAdvertiseAudit(t *testing.T) {
	r, _ := handleCaps(Request{}, Spec{})
	if !ParseCapsReply(r).HasCap(CapAudit) {
		t.Fatal(r)
	}
}
