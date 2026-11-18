//go:build linux

package hostguard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// helperAuditFile is root-only (0600): the audit-tail verb is the single read path. A
// group-readable file would let every process in the owner's group read it without going
// through the peer-authorized verb, and gains nothing (the owner can already call it).
var helperAuditFile = filepath.Join(helperStateDir, "helper_audit.jsonl")

var (
	auditLogMu sync.Mutex
	auditLogV  *AuditLog
)

// currentAuditLog returns the process-wide audit log, creating a memory-only one when
// ServeHelper has not opened the file (unit tests, local --real runs).
func currentAuditLog() *AuditLog {
	auditLogMu.Lock()
	defer auditLogMu.Unlock()
	if auditLogV == nil {
		auditLogV = NewAuditLog("", 0)
	}
	return auditLogV
}

func setAuditLog(l *AuditLog) {
	auditLogMu.Lock()
	auditLogV = l
	auditLogMu.Unlock()
}

// peerCreds is the SO_PEERCRED triple; ok=false when it cannot be read.
type peerCreds struct {
	PID, UID int
	OK       bool
}

func peerCred(c net.Conn) peerCreds {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peerCreds{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerCreds{}
	}
	var out peerCreds
	_ = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err == nil {
			out = peerCreds{PID: int(cred.Pid), UID: int(cred.Uid), OK: true}
		}
	})
	return out
}

// describePeer reads the peer facts from procRoot (normally /proc). Called right after
// accept, while the peer is still blocked on the reply; every failure degrades to
// "unknown" rather than an error.
func describePeer(cred peerCreds, ownerUID int, procRoot string) PeerInfo {
	p := PeerInfo{PID: cred.PID, UID: -1, ExeClass: ExeUnknown}
	if cred.OK {
		p.UID = cred.UID
	}
	if cred.PID <= 0 {
		return p
	}
	dir := filepath.Join(procRoot, strconv.Itoa(cred.PID))
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err == nil {
		exe = strings.TrimSuffix(exe, " (deleted)")
	}
	same := false
	if peerSt, perr := os.Stat(filepath.Join(dir, "exe")); perr == nil {
		if selfSt, serr := os.Stat(filepath.Join(procRoot, "self", "exe")); serr == nil {
			same = os.SameFile(peerSt, selfSt)
		}
	}
	p.Exe = exe
	p.ExeClass, p.Trusted = classifyExe(exe, same, ownerHome(ownerUID), func(d string) bool { return pathChainRootOwned(d) })
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		p.Comm = sanitizeComm(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
		p.PPID = parseStatPPID(string(b))
	}
	return p
}

func ownerHome(uid int) string {
	if uid <= 0 {
		return ""
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// recordHelperAudit stores or counts one handled request (see AuditLog). Mutating verbs
// and every denied request become events; read-only successes only bump a counter.
func recordHelperAudit(now time.Time, req Request, peer PeerInfo, result, reason string, lowers bool) {
	l := currentAuditLog()
	if result != AuditDenied && !req.Mutating() {
		l.CountRead(req.Verb)
		return
	}
	l.Record(buildAuditEvent(now, req, peer, result, reason, lowers))
}

// helperAuditTail is the client side of the audit-tail verb.
func helperAuditTail(n int) (AuditTail, error) {
	c, err := net.Dial("unix", helperSockPath)
	if err != nil {
		return AuditTail{}, fmt.Errorf("%w: %v", ErrHelperUnavailable, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(fmt.Sprintf("audit-tail %d 0 -\n", n))); err != nil {
		return AuditTail{}, err
	}
	resp, err := bufio.NewReaderSize(c, 1<<20).ReadString('\n')
	if err != nil {
		return AuditTail{}, err
	}
	if strings.Contains(resp, "unknown verb") {
		return AuditTail{}, fmt.Errorf("%w: helper lacks %s", ErrHelperUnavailable, CapAudit)
	}
	return ParseAuditTailReply(resp)
}
