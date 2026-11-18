package hostguard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/protectstate"
)

// Helper audit trail (detection, not prevention).
//
// The owner uid is inside the helper's trust boundary (see docs/10-security-boundaries.md),
// so any process running as the owner, including a sandboxed agent, can ask the helper to
// switch Protect off. The helper therefore records WHO asked, as one JSONL event per
// request, and the desktop surfaces suspicious ones. Events hold only validated verbs and
// enums plus peer facts read from /proc (pid, uid, exe path, comm name, parent pid). They
// never hold command lines, environment or any request payload (CA paths, raw lines).

// CapAudit is advertised by helpers that understand the audit-tail verb.
const CapAudit = "audit1"

// Audit results.
const (
	AuditOK     = "ok"
	AuditDenied = "denied" // refused before execution (unauthorized peer, bad request)
	AuditError  = "error"  // validated and attempted, the handler failed
)

// Executable classes (PeerInfo.ExeClass). The first three count as trusted.
const (
	ExeHelper      = "helper"       // the very file the helper itself runs
	ExeSystem      = "system"       // denyout/denyout-cli under a root-owned, non-writable dir chain
	ExeUserInstall = "user_install" // denyout/denyout-cli in the owner's ~/.local/bin or ~/bin
	ExeOther       = "other"        // anything else (shells, nc, python, agents)
	ExeUnknown     = "unknown"      // /proc/<pid>/exe unreadable (peer already exited)
)

const (
	auditRingCap      = 256
	auditMaxTail      = 200
	auditDefaultTail  = 50
	auditDefaultBytes = 1 << 20 // 1 MiB per file, one rotated copy kept (~2 MiB total)
	auditLoadChunk    = 512 << 10
	// auditKeepCap lowering events are also kept in a separate ring that spam of other
	// requests cannot evict; auditDeniedPerMin caps stored denied (bad request) events.
	auditKeepCap      = 128
	auditDeniedPerMin = 30
)

// PeerInfo is what the helper learned about the connecting process. All fields come from
// SO_PEERCRED and /proc; none from the request.
type PeerInfo struct {
	PID      int    `json:"pid"`
	UID      int    `json:"uid"`
	PPID     int    `json:"ppid,omitempty"`
	Exe      string `json:"exe,omitempty"`
	Comm     string `json:"comm,omitempty"`
	ExeClass string `json:"exe_class"`
	Trusted  bool   `json:"trusted_exe"`
}

// AuditEvent is one handled request.
type AuditEvent struct {
	TS       int64    `json:"ts"` // unix nanoseconds, strictly increasing per helper process
	Time     string   `json:"time"`
	Verb     string   `json:"verb"` // "" when the request did not parse
	Mutating bool     `json:"mutating"`
	Result   string   `json:"result"`
	Reason   string   `json:"reason,omitempty"` // unauthorized | bad_request | handler_failed
	Lowers   bool     `json:"lowers,omitempty"` // the request lowers protection (see requestLowers)
	Peer     PeerInfo `json:"peer"`

	// Effective validated values for fail-policy / apply / vpn-egress-apply.
	FailPolicy string `json:"fail_policy,omitempty"`
	Port       int    `json:"port,omitempty"`
	AllowQUIC  bool   `json:"allow_quic,omitempty"`
	Iface      string `json:"iface,omitempty"`
}

// AuditTail is the audit-tail reply payload.
type AuditTail struct {
	Events      []AuditEvent      `json:"events"`
	ReadCounts  map[string]uint64 `json:"read_counts,omitempty"` // read-only verbs are counted, not logged
	WriteErrors uint64            `json:"write_errors,omitempty"`
	// DeniedDropped counts denied requests not stored because of the per-minute cap.
	DeniedDropped uint64 `json:"denied_dropped,omitempty"`
}

// requestLowers reports whether a validated request weakens protection:
//   - remove, teardown, uninstall-helper, tun-stop
//   - fail-policy open while the effective policy is not already open
//   - apply that moves the redirect to another proxy port or newly allows QUIC while
//     Protect is on (prev/prevOK = the last applied spec)
//
// Anything else (including a first apply, tun-start, fail-policy closed) does not.
func requestLowers(req Request, prev Spec, prevOK bool, effective protectstate.FailPolicy) bool {
	switch req.Verb {
	case "remove", "teardown", "uninstall-helper", "tun-stop":
		return true
	case "fail-policy":
		return req.FailPolicy == protectstate.FailOpen && effective != protectstate.FailOpen
	case "apply":
		if !prevOK {
			return false
		}
		return req.Port != prev.ProxyPort || (req.AllowQUIC && !prev.AllowQUIC) ||
			(req.FailPolicy == protectstate.FailOpen && effective == protectstate.FailClosed)
	}
	return false
}

// buildAuditEvent is the pure event constructor. It copies only validated fields of req;
// the CA path and everything else the client sent stay out.
func buildAuditEvent(now time.Time, req Request, peer PeerInfo, result, reason string, lowers bool) AuditEvent {
	ev := AuditEvent{
		Time:     now.UTC().Format(time.RFC3339Nano),
		TS:       now.UnixNano(),
		Verb:     req.Verb,
		Mutating: req.Mutating(),
		Result:   result,
		Reason:   reason,
		Lowers:   lowers,
		Peer:     peer,
	}
	switch req.Verb {
	case "apply":
		ev.Port, ev.AllowQUIC, ev.FailPolicy = req.Port, req.AllowQUIC, string(req.FailPolicy)
	case "fail-policy":
		ev.FailPolicy = string(req.FailPolicy)
	case "vpn-egress-apply":
		ev.Iface = req.Iface
	}
	return ev
}

// classifyExe classifies a peer executable. exe is the readlink of /proc/<pid>/exe with a
// trailing " (deleted)" already removed; sameAsHelper means /proc/<pid>/exe is the same
// inode as the helper's own binary; rootDir reports whether a directory chain is owned by
// root and not writable by others (so only root could have placed the file there).
func classifyExe(exe string, sameAsHelper bool, ownerHome string, rootDir func(string) bool) (class string, trusted bool) {
	if exe == "" {
		return ExeUnknown, false
	}
	if sameAsHelper {
		return ExeHelper, true
	}
	base := filepath.Base(exe)
	if (base != "denyout" && base != "denyout-cli") || !filepath.IsAbs(exe) {
		return ExeOther, false
	}
	dir := filepath.Dir(exe)
	if rootDir != nil && rootDir(dir) {
		return ExeSystem, true
	}
	if ownerHome != "" && ownerHome != "/" {
		for _, sub := range []string{".local/bin", "bin"} {
			if dir == filepath.Join(ownerHome, sub) {
				return ExeUserInstall, true
			}
		}
	}
	return ExeOther, false
}

// sanitizeComm makes a process name safe to store and show (printable ASCII, <= 32 bytes).
func sanitizeComm(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
		if b.Len() >= 32 {
			break
		}
	}
	return b.String()
}

// parseStatPPID extracts the parent pid from /proc/<pid>/stat content. The comm field can
// contain spaces and parentheses, so fields are counted after the LAST ')'.
func parseStatPPID(stat string) int {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(stat[i+1:])
	if len(f) < 2 {
		return 0
	}
	var ppid int
	if _, err := fmt.Sscanf(f[1], "%d", &ppid); err != nil || ppid < 0 {
		return 0
	}
	return ppid
}

// SuspiciousReason says why an event is suspicious ("" when it is not).
//
// An event is suspicious when it lowers protection, was not refused outright, and:
//   - desktopPID > 0: the peer is neither the running desktop itself nor a direct child
//     of it with a trusted exe. (Agents run as descendants of the desktop, so "any
//     descendant" would exempt exactly the processes this exists to catch.)
//   - desktopPID == 0 (no desktop known, e.g. hostctl audit-tail): the peer exe is not
//     a trusted DenyOut binary.
//
// This is a heuristic over pid/exe facts. A same-uid process can lie about neither the
// pid nor the exe to the kernel, but it can run the trusted binary itself (reason
// "not_from_desktop" then catches it only while a desktop is running).
func SuspiciousReason(ev AuditEvent, desktopPID int) string {
	if !ev.Lowers || ev.Result == AuditDenied {
		return ""
	}
	if desktopPID <= 0 {
		if !ev.Peer.Trusted {
			return "untrusted_exe"
		}
		return ""
	}
	if ev.Peer.PID == desktopPID || (ev.Peer.PPID == desktopPID && ev.Peer.Trusted) {
		return ""
	}
	if !ev.Peer.Trusted {
		return "untrusted_exe"
	}
	return "not_from_desktop"
}

// FromDesktop reports whether the peer is the desktop itself (or its trusted direct child).
func (p PeerInfo) FromDesktop(desktopPID int) bool {
	return desktopPID > 0 && (p.PID == desktopPID || (p.PPID == desktopPID && p.Trusted))
}

// FormatAuditEvent is the one-line human form used by `hostctl audit-tail`.
func FormatAuditEvent(ev AuditEvent, desktopPID int) string {
	var b strings.Builder
	exe := ev.Peer.Exe
	if exe == "" {
		exe = "?"
	}
	fmt.Fprintf(&b, "%s %-16s %-6s pid=%d uid=%d exe=%s class=%s", ev.Time, verbOrDash(ev.Verb), ev.Result,
		ev.Peer.PID, ev.Peer.UID, exe, ev.Peer.ExeClass)
	if ev.Peer.Comm != "" {
		fmt.Fprintf(&b, " comm=%s", ev.Peer.Comm)
	}
	if ev.FailPolicy != "" {
		fmt.Fprintf(&b, " fail_policy=%s", ev.FailPolicy)
	}
	if ev.Port != 0 {
		fmt.Fprintf(&b, " port=%d", ev.Port)
	}
	if ev.AllowQUIC {
		b.WriteString(" allow_quic=1")
	}
	if ev.Iface != "" {
		fmt.Fprintf(&b, " iface=%s", ev.Iface)
	}
	if ev.Lowers {
		b.WriteString(" lowers=1")
	}
	if r := SuspiciousReason(ev, desktopPID); r != "" {
		b.WriteString(" SUSPICIOUS:" + r)
	}
	return b.String()
}

func verbOrDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// FormatAuditTailReply builds the audit-tail reply: "OK audit1 <json>" on ONE line.
func FormatAuditTailReply(t AuditTail) (string, error) {
	if t.Events == nil {
		t.Events = []AuditEvent{}
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return "OK " + CapAudit + " " + string(b), nil
}

// ParseAuditTailReply parses FormatAuditTailReply output.
func ParseAuditTailReply(resp string) (AuditTail, error) {
	resp = strings.TrimSpace(resp)
	prefix := "OK " + CapAudit + " "
	if !strings.HasPrefix(resp, prefix) {
		return AuditTail{}, fmt.Errorf("helper audit-tail: %s", resp)
	}
	var t AuditTail
	if err := json.Unmarshal([]byte(strings.TrimPrefix(resp, prefix)), &t); err != nil {
		return AuditTail{}, fmt.Errorf("helper audit-tail: bad reply")
	}
	return t, nil
}

// HelperAuditTail asks the helper for its last n audit events (Linux helper only).
func HelperAuditTail(n int) (AuditTail, error) { return helperAuditTail(n) }

// AuditLog is the helper's audit sink: a bounded in-memory ring (what audit-tail serves)
// backed by a size-capped JSONL file (what survives a helper restart). Every write error
// is swallowed and counted: auditing must never break the helper.
type AuditLog struct {
	mu        sync.Mutex
	path      string // "" = memory only
	maxBytes  int64
	now       func() time.Time
	ring      []AuditEvent
	keep      []AuditEvent // lowering events only (sticky, see auditKeepCap)
	deniedWin time.Time
	deniedN   int
	dropped   uint64
	counts    map[string]uint64
	writeErrs uint64
	lastTS    int64
}

// NewAuditLog opens (and loads the tail of) the audit file at path. path "" keeps events
// in memory only. maxBytes <= 0 uses 1 MiB; one rotated copy (path+".1") is kept.
func NewAuditLog(path string, maxBytes int64) *AuditLog {
	if maxBytes <= 0 {
		maxBytes = auditDefaultBytes
	}
	l := &AuditLog{path: path, maxBytes: maxBytes, now: time.Now, counts: map[string]uint64{}}
	if path != "" {
		l.ring = loadAuditTail(path+".1", l.ring)
		l.ring = loadAuditTail(path, l.ring)
		for _, ev := range l.ring { // before trimming: keep reaches back through both files
			if ev.Lowers {
				l.keep = append(l.keep, ev)
			}
		}
		if n := len(l.ring); n > auditRingCap {
			l.ring = append([]AuditEvent(nil), l.ring[n-auditRingCap:]...)
		}
		if n := len(l.keep); n > auditKeepCap {
			l.keep = append([]AuditEvent(nil), l.keep[n-auditKeepCap:]...)
		}
		if n := len(l.ring); n > 0 {
			l.lastTS = l.ring[n-1].TS
		}
	}
	return l
}

// loadAuditTail appends the valid events found in the last chunk of path to dst.
func loadAuditTail(path string, dst []AuditEvent) []AuditEvent {
	f, err := os.Open(path)
	if err != nil {
		return dst
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return dst
	}
	skipFirst := false
	if st.Size() > auditLoadChunk {
		if _, err := f.Seek(st.Size()-auditLoadChunk, io.SeekStart); err != nil {
			return dst
		}
		skipFirst = true // starts mid-line
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 256<<10)
	for sc.Scan() {
		if skipFirst {
			skipFirst = false
			continue
		}
		var ev AuditEvent
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.TS != 0 {
			dst = append(dst, ev)
		}
	}
	return dst
}

// Record stamps (time, strictly increasing ts) and stores ev. Mutating verbs and every
// denied request belong here; read-only successes go through CountRead instead.
func (l *AuditLog) Record(ev AuditEvent) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if ev.Result == AuditDenied && !ev.Lowers && !l.allowDeniedLocked(now) {
		l.dropped++
		return
	}
	ev.TS = now.UnixNano()
	if ev.TS <= l.lastTS {
		ev.TS = l.lastTS + 1
	}
	l.lastTS = ev.TS
	ev.Time = time.Unix(0, ev.TS).UTC().Format(time.RFC3339Nano)
	l.ring = append(l.ring, ev)
	if len(l.ring) > auditRingCap {
		l.ring = append([]AuditEvent(nil), l.ring[len(l.ring)-auditRingCap:]...)
	}
	if ev.Lowers {
		l.keep = append(l.keep, ev)
		if len(l.keep) > auditKeepCap {
			l.keep = append([]AuditEvent(nil), l.keep[len(l.keep)-auditKeepCap:]...)
		}
	}
	if l.path == "" {
		return
	}
	line, err := json.Marshal(ev)
	if err != nil {
		l.writeErrs++
		return
	}
	if err := l.appendLocked(append(line, '\n')); err != nil {
		l.writeErrs++
	}
}

// allowDeniedLocked is a fixed one-minute window: at most auditDeniedPerMin denied
// events are stored, so a flood of garbage requests cannot churn the file or the ring.
func (l *AuditLog) allowDeniedLocked(now time.Time) bool {
	if now.Sub(l.deniedWin) >= time.Minute || now.Before(l.deniedWin) {
		l.deniedWin, l.deniedN = now, 0
	}
	l.deniedN++
	return l.deniedN <= auditDeniedPerMin
}

// appendLocked appends one line, rotating first when the file would exceed maxBytes.
func (l *AuditLog) appendLocked(line []byte) error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	if st, err := os.Lstat(l.path); err == nil && st.Size()+int64(len(line)) > l.maxBytes {
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|auditNoFollow, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Chmod(0o600)
	_, err = f.Write(line)
	return err
}

// CountRead counts one handled read-only request (no event is stored).
func (l *AuditLog) CountRead(verb string) {
	if l == nil || verb == "" {
		return
	}
	l.mu.Lock()
	l.counts[verb]++
	l.mu.Unlock()
}

// Tail returns the last n events (oldest first) plus the read-only counters. Retained
// lowering events (up to auditKeepCap) are always merged in, so a flood of other requests
// cannot push a "remove" out of the reply before the desktop polls.
func (l *AuditLog) Tail(n int) AuditTail {
	if n <= 0 {
		n = auditDefaultTail
	}
	if n > auditMaxTail {
		n = auditMaxTail
	}
	if l == nil {
		return AuditTail{Events: []AuditEvent{}}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	start := 0
	if len(l.ring) > n {
		start = len(l.ring) - n
	}
	events := append([]AuditEvent{}, l.ring[start:]...)
	seen := make(map[int64]bool, len(events))
	for _, e := range events {
		seen[e.TS] = true
	}
	for _, e := range l.keep {
		if !seen[e.TS] {
			events = append(events, e)
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TS < events[j].TS })
	t := AuditTail{Events: events, WriteErrors: l.writeErrs, DeniedDropped: l.dropped}
	if len(l.counts) > 0 {
		t.ReadCounts = make(map[string]uint64, len(l.counts))
		keys := make([]string, 0, len(l.counts))
		for k := range l.counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.ReadCounts[k] = l.counts[k]
		}
	}
	return t
}
