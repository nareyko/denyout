package hostguard

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nareyko/denyout/internal/privexec"
	"github.com/nareyko/denyout/internal/protectstate"
)

// Helper protocol.
//
// Every request is ONE line, in one of two encodings that parse into the same typed
// Request (so validation exists exactly once):
//
//	legacy: "<verb> <port> <uid> [<arg>] [flags...]"          (older app builds)
//	JSON:   {"verb":"apply","port":18443,"ca":"/…","flags":["allow_quic"]}
//
// JSON requests get a JSON reply {"ok":bool,"reply":"…","error":"…"}; legacy requests
// keep the legacy "OK …"/"ERR …" replies.

// Request is a parsed, validated helper request.
type Request struct {
	Verb      string
	Port      int
	UID       int // always the configured owner, never client supplied
	CA        string
	Iface     string
	AllowQUIC bool
	Real      bool
	Mitm      bool
	// FailPolicy is the requested proxy-loss policy: "" (not supplied) or open|closed.
	FailPolicy protectstate.FailPolicy
	// Count is how many audit events audit-tail returns (1..200; default 50).
	Count int
	JSON  bool // reply encoding
}

type verbDef struct {
	mutating bool // changes kernel/system state (serialised, audited)
	parse    func(r *Request, a rawArgs, owner int) error
}

// rawArgs is the encoding-independent argument bag.
type rawArgs struct {
	port  int
	arg   string // CA path or interface name, depending on verb
	flags map[string]bool
	fail  string // fail_policy (JSON) / fail=<p> token (legacy); "" = absent
}

// parseFailPolicy accepts exactly "open" or "closed" (no aliases); "" means absent.
func parseFailPolicy(s string) (protectstate.FailPolicy, error) {
	s = strings.ToLower(s)
	if s != "" && !protectstate.ValidFailPolicy(s) {
		return "", fmt.Errorf("fail policy must be open or closed")
	}
	return protectstate.FailPolicy(s), nil
}

func (a rawArgs) has(f ...string) bool {
	for _, k := range f {
		if a.flags[k] {
			return true
		}
	}
	return false
}

func needPort(r *Request, a rawArgs, _ int) error {
	if err := privexec.ValidPort(a.port); err != nil {
		return err
	}
	r.Port = a.port
	return nil
}

func noArgs(*Request, rawArgs, int) error { return nil }

// verbs is the complete, closed set of operations the root helper performs.
var verbs = map[string]verbDef{
	"caps":    {parse: noArgs},
	"version": {parse: noArgs},
	"apply": {mutating: true, parse: func(r *Request, a rawArgs, owner int) error {
		if err := needPort(r, a, owner); err != nil {
			return err
		}
		if err := validateHelperCAPath(a.arg, owner); err != nil {
			return err
		}
		r.CA = a.arg
		r.AllowQUIC = a.has("1", "true", "allow_quic")
		p, err := parseFailPolicy(a.fail)
		if err != nil {
			return err
		}
		r.FailPolicy = p
		return nil
	}},
	// fail-policy changes the proxy-loss policy live (watchdog picks it up on its next
	// tick); fail-status reports the effective policy and where it came from.
	"fail-policy": {mutating: true, parse: func(r *Request, a rawArgs, _ int) error {
		v := a.fail
		if v == "" && a.arg != "-" {
			v = a.arg // legacy: fail-policy 0 0 closed
		}
		p, err := parseFailPolicy(v)
		if err != nil {
			return err
		}
		if p == "" {
			return fmt.Errorf("fail policy required")
		}
		r.FailPolicy = p
		return nil
	}},
	"fail-status": {parse: noArgs},
	// audit-tail returns the helper's recent audit events (read-only). The count rides in
	// the port field in both encodings: "audit-tail 50 0 -" / {"verb":"audit-tail","port":50}.
	"audit-tail": {parse: func(r *Request, a rawArgs, _ int) error {
		r.Count = a.port
		if r.Count <= 0 {
			r.Count = auditDefaultTail
		}
		if r.Count > auditMaxTail {
			r.Count = auditMaxTail
		}
		return nil
	}},
	"remove":           {mutating: true, parse: noArgs},
	"teardown":         {mutating: true, parse: noArgs},
	"uninstall-helper": {mutating: true, parse: noArgs},
	"quic-stats":       {parse: noArgs},
	"tun-start":        {mutating: true, parse: parseTunFlags},
	"tun-stop":         {mutating: true, parse: parseTunFlags},
	"tun-stats":        {parse: parseTunFlags},
	"vpn-egress-apply": {mutating: true, parse: func(r *Request, a rawArgs, _ int) error {
		if a.arg == "" || a.arg == "-" {
			return fmt.Errorf("vpn iface required")
		}
		if err := privexec.ValidIface(a.arg); err != nil {
			return err
		}
		r.Iface = a.arg
		return nil
	}},
	"vpn-egress-remove": {mutating: true, parse: noArgs},
}

func parseTunFlags(r *Request, a rawArgs, _ int) error {
	r.Real = a.has("real", "real=1")
	r.Mitm = a.has("mitm", "mitm=1")
	return nil
}

// ParseRequest parses one request line (legacy or JSON) for the given owner uid.
func ParseRequest(line string, ownerUID int) (Request, error) {
	line = strings.TrimSpace(line)
	var (
		verb string
		raw  rawArgs
		r    Request
	)
	raw.flags = map[string]bool{}
	if strings.HasPrefix(line, "{") {
		var j struct {
			Verb  string   `json:"verb"`
			Port  int      `json:"port"`
			CA    string   `json:"ca"`
			Iface string   `json:"iface"`
			Flags []string `json:"flags"`
			Fail  string   `json:"fail_policy"`
		}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&j); err != nil {
			return Request{}, fmt.Errorf("bad request")
		}
		verb, raw.port, raw.arg = strings.ToLower(j.Verb), j.Port, j.CA
		if j.Iface != "" {
			raw.arg = j.Iface
		}
		for _, f := range j.Flags {
			raw.flags[strings.ToLower(f)] = true
		}
		raw.fail = j.Fail
		r.JSON = true
	} else {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			return Request{}, fmt.Errorf("bad request")
		}
		verb = strings.ToLower(parts[0])
		raw.port, _ = strconv.Atoi(parts[1])
		// parts[2] is the legacy client uid: ignored on purpose (owner is authoritative).
		if len(parts) >= 4 {
			raw.arg = parts[3]
		}
		for _, p := range parts[3:] {
			lp := strings.ToLower(p)
			if strings.HasPrefix(lp, "fail=") {
				raw.fail = strings.TrimPrefix(lp, "fail=")
				if raw.fail == "" {
					raw.fail = "-" // present but empty: rejected by parseFailPolicy
				}
				continue
			}
			raw.flags[lp] = true
		}
	}
	def, ok := verbs[verb]
	if !ok {
		return Request{}, fmt.Errorf("unknown verb")
	}
	r.Verb, r.UID = verb, ownerUID
	if err := def.parse(&r, raw, ownerUID); err != nil {
		return Request{}, err
	}
	return r, nil
}

// Mutating reports whether the verb changes system state.
func (r Request) Mutating() bool { return verbs[r.Verb].mutating }

// encodeReply formats a reply in the encoding the client used.
func encodeReply(r Request, reply string, err error) string {
	if !r.JSON {
		if err != nil {
			return "ERR " + err.Error() + "\n"
		}
		return reply + "\n"
	}
	out := struct {
		OK    bool   `json:"ok"`
		Reply string `json:"reply,omitempty"`
		Error string `json:"error,omitempty"`
	}{OK: err == nil, Reply: reply}
	if err != nil {
		out.Error = err.Error()
	}
	b, _ := json.Marshal(out)
	return string(b) + "\n"
}
