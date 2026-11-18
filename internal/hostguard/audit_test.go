package hostguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nareyko/denyout/internal/protectstate"
)

var t0 = time.Date(2026, 11, 18, 10, 0, 0, 123, time.UTC)

func TestAuditVerbTable(t *testing.T) {
	r, err := ParseRequest("audit-tail 7 0 -", 1000)
	if err != nil || r.Verb != "audit-tail" || r.Count != 7 || r.Mutating() {
		t.Fatalf("%+v %v", r, err)
	}
	for line, want := range map[string]int{
		"audit-tail 0 0 -":                  auditDefaultTail,
		"audit-tail 9999 0 -":               auditMaxTail,
		`{"verb":"audit-tail"}`:             auditDefaultTail,
		`{"verb":"AUDIT-TAIL","port":200}`:  200,
		`{"verb":"audit-tail","port":1000}`: auditMaxTail,
	} {
		got, err := ParseRequest(line, 1000)
		if err != nil || got.Count != want {
			t.Errorf("%q: %+v %v want count %d", line, got, err, want)
		}
	}
	// Unknown fields stay rejected (the closed table still applies to the new verb).
	if _, err := ParseRequest(`{"verb":"audit-tail","path":"/etc/shadow"}`, 1000); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// Every mutating verb must be a conscious decision for the audit "lowers" flag: adding a
// mutating verb without listing it here fails the build of this test.
func TestEveryMutatingVerbHasAuditDecision(t *testing.T) {
	lowering := map[string]Request{
		"remove":           {Verb: "remove"},
		"teardown":         {Verb: "teardown"},
		"uninstall-helper": {Verb: "uninstall-helper"},
		"tun-stop":         {Verb: "tun-stop"},
		"fail-policy":      {Verb: "fail-policy", FailPolicy: protectstate.FailOpen},
	}
	notLowering := map[string]Request{
		"apply":             {Verb: "apply", Port: 18443},
		"tun-start":         {Verb: "tun-start"},
		"vpn-egress-apply":  {Verb: "vpn-egress-apply", Iface: "wg0"},
		"vpn-egress-remove": {Verb: "vpn-egress-remove"},
	}
	for v, def := range verbs {
		if !def.mutating {
			continue
		}
		if req, ok := lowering[v]; ok {
			if !requestLowers(req, Spec{}, false, protectstate.FailClosed) {
				t.Errorf("%s should lower protection", v)
			}
			continue
		}
		req, ok := notLowering[v]
		if !ok {
			t.Errorf("mutating verb %q has no audit decision: add it to lowering or notLowering", v)
			continue
		}
		if requestLowers(req, Spec{}, false, protectstate.FailClosed) {
			t.Errorf("%s must not be flagged as lowering", v)
		}
	}
}

func TestRequestLowers(t *testing.T) {
	prev := Spec{ProxyPort: 18443}
	cases := []struct {
		name string
		req  Request
		eff  protectstate.FailPolicy
		prev bool
		want bool
	}{
		{"fail-policy open from closed", Request{Verb: "fail-policy", FailPolicy: "open"}, "closed", false, true},
		{"fail-policy open when already open", Request{Verb: "fail-policy", FailPolicy: "open"}, "open", false, false},
		{"fail-policy closed", Request{Verb: "fail-policy", FailPolicy: "closed"}, "open", false, false},
		{"apply same port", Request{Verb: "apply", Port: 18443}, "open", true, false},
		{"apply other port", Request{Verb: "apply", Port: 9999}, "open", true, true},
		{"apply allow quic", Request{Verb: "apply", Port: 18443, AllowQUIC: true}, "open", true, true},
		{"apply open over closed", Request{Verb: "apply", Port: 18443, FailPolicy: "open"}, "closed", true, true},
		{"first apply", Request{Verb: "apply", Port: 9999, AllowQUIC: true}, "open", false, false},
		{"caps", Request{Verb: "caps"}, "open", true, false},
		{"audit-tail", Request{Verb: "audit-tail"}, "open", true, false},
	}
	for _, c := range cases {
		if got := requestLowers(c.req, prev, c.prev, c.eff); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestBuildAuditEventKeepsOnlyValidatedFields(t *testing.T) {
	peer := PeerInfo{PID: 42, UID: 1000, Exe: "/usr/bin/nc", ExeClass: ExeOther, Comm: "nc"}
	req := Request{Verb: "apply", Port: 18443, UID: 1000, CA: "/home/u/secret-ca-path.pem", AllowQUIC: true, FailPolicy: "closed", Iface: "", JSON: true}
	ev := buildAuditEvent(t0, req, peer, AuditOK, "", false)
	if ev.Verb != "apply" || !ev.Mutating || ev.Port != 18443 || !ev.AllowQUIC || ev.FailPolicy != "closed" || ev.Result != AuditOK {
		t.Fatalf("%+v", ev)
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), "secret-ca-path") {
		t.Fatalf("CA path leaked into the audit event: %s", b)
	}
	if ev.Time != "2026-11-18T10:00:00.000000123Z" || ev.TS != t0.UnixNano() {
		t.Fatalf("time %q ts %d", ev.Time, ev.TS)
	}
	vpn := buildAuditEvent(t0, Request{Verb: "vpn-egress-apply", Iface: "wg0"}, peer, AuditError, "handler_failed", false)
	if vpn.Iface != "wg0" || vpn.Port != 0 || vpn.Reason != "handler_failed" {
		t.Fatalf("%+v", vpn)
	}
	if ro := buildAuditEvent(t0, Request{Verb: "caps"}, peer, AuditOK, "", false); ro.Mutating {
		t.Fatal("caps is not mutating")
	}
}

// The event schema is a closed set of fields: nothing that could carry a command line,
// environment or request payload exists, so none can be logged by accident.
func TestAuditEventSchemaHasNoPayloadFields(t *testing.T) {
	b, _ := json.Marshal(AuditEvent{})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	b2, _ := json.Marshal(PeerInfo{})
	var pm map[string]any
	_ = json.Unmarshal(b2, &pm)
	for _, k := range []string{"cmdline", "args", "argv", "env", "environ", "ca", "line", "payload", "request"} {
		if _, ok := m[k]; ok {
			t.Errorf("event has field %q", k)
		}
		if _, ok := pm[k]; ok {
			t.Errorf("peer has field %q", k)
		}
	}
}

func TestClassifyExe(t *testing.T) {
	root := func(d string) bool { return d == "/usr/lib/denyout" || d == "/usr/bin" || d == "/usr/local/bin" }
	cases := []struct {
		exe     string
		same    bool
		home    string
		class   string
		trusted bool
	}{
		{"", false, "/home/u", ExeUnknown, false},
		{"/anything/at/all", true, "/home/u", ExeHelper, true},
		{"/usr/lib/denyout/denyout-cli", false, "/home/u", ExeSystem, true},
		{"/usr/local/bin/denyout", false, "/home/u", ExeSystem, true},
		{"/home/u/.local/bin/denyout-cli", false, "/home/u", ExeUserInstall, true},
		{"/home/u/bin/denyout", false, "/home/u", ExeUserInstall, true},
		{"/home/u/.local/bin/denyout-cli", false, "", ExeOther, false},
		{"/home/u/.local/bin/denyout-cli", false, "/", ExeOther, false},
		{"/tmp/x/denyout-cli", false, "/home/u", ExeOther, false},
		{"/home/u/project/denyout", false, "/home/u", ExeOther, false},
		{"/usr/bin/nc", false, "/home/u", ExeOther, false},
		{"/usr/bin/bash", false, "/home/u", ExeOther, false},
		{"/usr/bin/denyout-cli-evil", false, "/home/u", ExeOther, false},
		{"relative/denyout", false, "/home/u", ExeOther, false},
	}
	for _, c := range cases {
		class, trusted := classifyExe(c.exe, c.same, c.home, root)
		if class != c.class || trusted != c.trusted {
			t.Errorf("%q same=%v home=%q: got %s/%v want %s/%v", c.exe, c.same, c.home, class, trusted, c.class, c.trusted)
		}
	}
}

func TestSanitizeCommAndStat(t *testing.T) {
	if got := sanitizeComm("a\x00b\n\x1b[31mevilé" + strings.Repeat("x", 80)); strings.ContainsAny(got, "\x00\n\x1b") || len(got) > 33 {
		t.Fatalf("%q", got)
	}
	for stat, want := range map[string]int{
		"123 (bash) S 77 123 123 0 -1 4194560": 77,
		"9 (a b) c) S 5 9 9 0":                 5, // comm with spaces and a ')'
		"1 (init) S 0 1 1":                     0,
		"garbage":                              0,
		"5 (x) S":                              0,
		"5 (x) S notanumber 1":                 0,
		"5 (x) S -3 1":                         0,
	} {
		if got := parseStatPPID(stat); got != want {
			t.Errorf("%q: %d want %d", stat, got, want)
		}
	}
}

func TestSuspiciousReason(t *testing.T) {
	trusted := PeerInfo{PID: 50, PPID: 10, ExeClass: ExeSystem, Trusted: true}
	untrusted := PeerInfo{PID: 51, PPID: 10, ExeClass: ExeOther}
	lower := func(p PeerInfo) AuditEvent { return AuditEvent{Verb: "remove", Result: AuditOK, Lowers: true, Peer: p} }
	cases := []struct {
		name    string
		ev      AuditEvent
		desktop int
		want    string
	}{
		{"untrusted, no desktop known", lower(untrusted), 0, "untrusted_exe"},
		{"trusted, no desktop known", lower(trusted), 0, ""},
		{"desktop itself (even untrusted exe)", lower(PeerInfo{PID: 10, ExeClass: ExeOther}), 10, ""},
		{"trusted direct child of desktop", lower(trusted), 10, ""},
		{"untrusted direct child of desktop", lower(untrusted), 10, "untrusted_exe"},
		{"trusted binary, not from desktop (agent ran the CLI)", lower(PeerInfo{PID: 60, PPID: 61, Trusted: true, ExeClass: ExeSystem}), 10, "not_from_desktop"},
		{"errored attempt is still flagged", AuditEvent{Verb: "remove", Result: AuditError, Lowers: true, Peer: untrusted}, 0, "untrusted_exe"},
		{"denied is not flagged", AuditEvent{Verb: "remove", Result: AuditDenied, Lowers: true, Peer: untrusted}, 0, ""},
		{"non-lowering never flagged", AuditEvent{Verb: "apply", Result: AuditOK, Peer: untrusted}, 10, ""},
	}
	for _, c := range cases {
		if got := SuspiciousReason(c.ev, c.desktop); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if !trusted.FromDesktop(10) || untrusted.FromDesktop(10) || trusted.FromDesktop(0) {
		t.Fatal("FromDesktop")
	}
}

func TestFormatAuditEvent(t *testing.T) {
	ev := buildAuditEvent(t0, Request{Verb: "remove"}, PeerInfo{PID: 9, UID: 1000, Exe: "/usr/bin/nc", ExeClass: ExeOther, Comm: "nc"}, AuditOK, "", true)
	line := FormatAuditEvent(ev, 0)
	for _, want := range []string{"remove", "pid=9", "uid=1000", "exe=/usr/bin/nc", "class=other", "comm=nc", "lowers=1", "SUSPICIOUS:untrusted_exe"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing %q", line, want)
		}
	}
	if strings.Contains(line, "\n") {
		t.Fatal("must be one line")
	}
	fp := buildAuditEvent(t0, Request{Verb: "fail-policy", FailPolicy: "open"}, PeerInfo{}, AuditOK, "", false)
	if l := FormatAuditEvent(fp, 0); !strings.Contains(l, "fail_policy=open") || strings.Contains(l, "SUSPICIOUS") || !strings.Contains(l, "exe=?") {
		t.Fatal(l)
	}
	if l := FormatAuditEvent(AuditEvent{Result: AuditDenied, Reason: "unauthorized"}, 0); !strings.Contains(l, " - ") {
		t.Fatal(l)
	}
}

func TestAuditTailReplyRoundTrip(t *testing.T) {
	in := AuditTail{Events: []AuditEvent{buildAuditEvent(t0, Request{Verb: "remove"}, PeerInfo{PID: 1}, AuditOK, "", true)}, ReadCounts: map[string]uint64{"caps": 3}}
	line, err := FormatAuditTailReply(in)
	if err != nil || strings.Contains(line, "\n") || !strings.HasPrefix(line, "OK audit1 ") {
		t.Fatalf("%q %v", line, err)
	}
	out, err := ParseAuditTailReply(line + "\n")
	if err != nil || len(out.Events) != 1 || out.Events[0].Verb != "remove" || out.ReadCounts["caps"] != 3 {
		t.Fatalf("%+v %v", out, err)
	}
	if empty, _ := FormatAuditTailReply(AuditTail{}); !strings.Contains(empty, `"events":[]`) {
		t.Fatalf("empty tail must encode as []: %s", empty)
	}
	for _, bad := range []string{"ERR unknown verb", "OK", "OK audit1 {nope", ""} {
		if _, err := ParseAuditTailReply(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func newTestLog(t *testing.T, max int64) (*AuditLog, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper_audit.jsonl")
	l := NewAuditLog(path, max)
	n := int64(0)
	l.now = func() time.Time { n++; return t0.Add(time.Duration(n) * time.Millisecond) }
	return l, path
}

func ev(verb string) AuditEvent {
	return buildAuditEvent(t0, Request{Verb: verb}, PeerInfo{PID: 1, UID: 1000}, AuditOK, "", false)
}

func TestAuditLogRecordTailAndMode(t *testing.T) {
	l, path := newTestLog(t, 0)
	for i := 0; i < 5; i++ {
		l.Record(ev("remove"))
	}
	l.CountRead("caps")
	l.CountRead("caps")
	l.CountRead("")
	tail := l.Tail(3)
	if len(tail.Events) != 3 || tail.ReadCounts["caps"] != 2 || len(tail.ReadCounts) != 1 {
		t.Fatalf("%+v", tail)
	}
	for i := 1; i < len(tail.Events); i++ {
		if tail.Events[i].TS <= tail.Events[i-1].TS {
			t.Fatal("ts must increase")
		}
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("audit file must be 0600: %v %v", st, err)
	}
	if got := l.Tail(0); len(got.Events) != 5 {
		t.Fatalf("default tail: %d", len(got.Events))
	}
	if got := l.Tail(100000); len(got.Events) != 5 {
		t.Fatalf("clamped tail: %d", len(got.Events))
	}
	var nilLog *AuditLog
	nilLog.Record(ev("remove"))
	nilLog.CountRead("caps")
	if len(nilLog.Tail(5).Events) != 0 {
		t.Fatal("nil log")
	}
}

func TestAuditLogMonotonicTSWithFrozenClock(t *testing.T) {
	l := NewAuditLog("", 0)
	l.now = func() time.Time { return t0 }
	for i := 0; i < 3; i++ {
		l.Record(ev("remove"))
	}
	e := l.Tail(10).Events
	if !(e[0].TS < e[1].TS && e[1].TS < e[2].TS) {
		t.Fatalf("%v", e)
	}
}

func TestAuditLogRotationCapsSizeAndKeepsHistory(t *testing.T) {
	l, path := newTestLog(t, 2048)
	for i := 0; i < 60; i++ {
		l.Record(ev("remove"))
	}
	for _, p := range []string{path, path + ".1"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if st.Size() > 2048 {
			t.Fatalf("%s is %d bytes, over the cap", p, st.Size())
		}
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Fatal("only one rotated copy may exist")
	}
	// A restarted helper reloads the tail from both files, in order, ending at the newest.
	l2 := NewAuditLog(path, 2048)
	e := l2.Tail(200).Events
	if len(e) < 8 {
		t.Fatalf("reloaded only %d events", len(e))
	}
	for i := 1; i < len(e); i++ {
		if e[i].TS <= e[i-1].TS {
			t.Fatalf("reloaded events out of order at %d", i)
		}
	}
	if last := l.Tail(1).Events[0]; e[len(e)-1].TS != last.TS {
		t.Fatalf("newest event lost on reload")
	}
	// Timestamps keep increasing after a restart even with a clock that went backwards.
	l2.now = func() time.Time { return t0 }
	l2.Record(ev("remove"))
	if got := l2.Tail(1).Events[0].TS; got <= e[len(e)-1].TS {
		t.Fatal("ts went backwards after restart")
	}
}

func TestAuditLogRingBounded(t *testing.T) {
	l := NewAuditLog("", 0)
	for i := 0; i < auditRingCap+50; i++ {
		l.Record(ev("remove"))
	}
	if n := len(l.ring); n != auditRingCap {
		t.Fatalf("ring %d", n)
	}
}

// Failure to write must not break the helper: events stay served from memory.
func TestAuditLogWriteFailureIsSwallowed(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewAuditLog(filepath.Join(blocker, "sub", "audit.jsonl"), 0) // parent is a file
	l.Record(ev("remove"))
	l.Record(ev("teardown"))
	tail := l.Tail(10)
	if len(tail.Events) != 2 || tail.WriteErrors != 2 {
		t.Fatalf("%+v", tail)
	}
}

func TestAuditLogRefusesSymlinkedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, path); err != nil {
		t.Skip("symlinks unavailable")
	}
	l := NewAuditLog(path, 0)
	l.Record(ev("remove"))
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatalf("wrote through the symlink: %q", b)
	}
	if l.Tail(1).WriteErrors != 1 {
		t.Fatal("expected a counted write error")
	}
}

func TestAuditLogLoadSkipsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	good := auditLine(t, ev("remove"), 5)
	if err := os.WriteFile(path, []byte("not json\n{\"ts\":0}\n"+good+"\n\n{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewAuditLog(path, 0)
	if e := l.Tail(10).Events; len(e) != 1 || e[0].TS != 5 {
		t.Fatalf("%+v", e)
	}
}

func auditLine(t *testing.T, e AuditEvent, ts int64) string {
	t.Helper()
	e.TS = ts
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFileOnDiskHoldsNoRequestPayload(t *testing.T) {
	l, path := newTestLog(t, 0)
	req := Request{Verb: "apply", Port: 18443, CA: "/home/victim/TOPSECRET.pem", AllowQUIC: false, FailPolicy: "closed", JSON: true}
	l.Record(buildAuditEvent(t0, req, PeerInfo{PID: 3, UID: 1000, Exe: "/usr/bin/python3", Comm: "python3"}, AuditOK, "", false))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "TOPSECRET") || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("%s", b)
	}
	if !strings.Contains(string(b), fmt.Sprintf(`"port":%d`, 18443)) {
		t.Fatalf("validated value missing: %s", b)
	}
}

// Spam of other requests must not push a lowering event out of what the desktop polls.
func TestAuditFloodCannotEvictLoweringEvents(t *testing.T) {
	l := NewAuditLog("", 0)
	l.Record(buildAuditEvent(t0, Request{Verb: "remove"}, PeerInfo{PID: 66}, AuditOK, "", true))
	for i := 0; i < 3*auditRingCap; i++ {
		l.Record(buildAuditEvent(t0, Request{Verb: "fail-policy", FailPolicy: "closed"}, PeerInfo{PID: 1}, AuditOK, "", false))
	}
	tail := l.Tail(10)
	if len(tail.Events) != 11 {
		t.Fatalf("want 10 recent + 1 retained, got %d", len(tail.Events))
	}
	first := tail.Events[0]
	if first.Verb != "remove" || first.Peer.PID != 66 {
		t.Fatalf("the lowering event was evicted: %+v", first)
	}
	for i := 1; i < len(tail.Events); i++ {
		if tail.Events[i].TS <= tail.Events[i-1].TS {
			t.Fatal("tail must be ordered by ts")
		}
	}
}

func TestAuditKeepSurvivesRestartAndIsBounded(t *testing.T) {
	l, path := newTestLog(t, 0)
	l.Record(buildAuditEvent(t0, Request{Verb: "teardown"}, PeerInfo{PID: 5}, AuditOK, "", true))
	for i := 0; i < 2*auditRingCap; i++ {
		l.Record(ev("caps"))
	}
	// The ring is only 256 deep, yet a restarted helper still serves the teardown.
	got := NewAuditLog(path, 0).Tail(5).Events
	if len(got) != 6 || got[0].Verb != "teardown" {
		t.Fatalf("%+v", got)
	}
	l3 := NewAuditLog("", 0)
	for i := 0; i < auditKeepCap+40; i++ {
		l3.Record(buildAuditEvent(t0, Request{Verb: "remove"}, PeerInfo{PID: i}, AuditOK, "", true))
	}
	if n := len(l3.keep); n != auditKeepCap {
		t.Fatalf("keep ring %d", n)
	}
}

func TestAuditDeniedFloodIsRateLimited(t *testing.T) {
	l, path := newTestLog(t, 0)
	fixed := t0
	l.now = func() time.Time { fixed = fixed.Add(time.Millisecond); return fixed }
	for i := 0; i < 500; i++ {
		l.Record(buildAuditEvent(t0, Request{}, PeerInfo{PID: 9}, AuditDenied, "bad_request", false))
	}
	tail := l.Tail(200)
	if len(tail.Events) != auditDeniedPerMin || tail.DeniedDropped != 500-auditDeniedPerMin {
		t.Fatalf("stored %d dropped %d", len(tail.Events), tail.DeniedDropped)
	}
	if b, _ := os.ReadFile(path); strings.Count(string(b), "\n") != auditDeniedPerMin {
		t.Fatal("file not limited")
	}
	// A mutating request in the same window is never rate limited.
	l.Record(ev("remove"))
	if got := l.Tail(200).Events; got[len(got)-1].Verb != "remove" {
		t.Fatal("mutating verb dropped")
	}
	// A new minute opens a new window.
	l.now = func() time.Time { return fixed.Add(2 * time.Minute) }
	l.Record(buildAuditEvent(t0, Request{}, PeerInfo{PID: 9}, AuditDenied, "bad_request", false))
	if n := len(l.Tail(200).Events); n != auditDeniedPerMin+2 {
		t.Fatalf("window did not reset: %d", n)
	}
}
