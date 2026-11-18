package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/desktop"
)

const auditUsage = `Usage: denyout-cli audit tail [-n N] [--denials] [--path FILE]

  Show recent events from audit.jsonl (desktop path by default).
  --denials  only deny / would_deny
  -n N       number of events (default 50)`

type auditOpts struct {
	limit       int
	denialsOnly bool
	path        string
}

// parseAuditTail parses the flags after `audit tail` (pure).
func parseAuditTail(args []string) (auditOpts, *cliExit) {
	o := auditOpts{limit: 50}
	fs := flagSet{
		cmd:  "audit tail",
		help: auditUsage,
		values: []flagSpec{
			{names: []string{"-n", "--limit"}, missing: "-n requires a number", set: func(v string) string {
				n, err := strconv.Atoi(v)
				if err != nil || n <= 0 {
					return fmt.Sprintf("invalid -n %q", v)
				}
				o.limit = n
				return ""
			}},
			{names: []string{"--path"}, missing: "--path requires a file", set: setStr(&o.path)},
		},
		bools:   map[string]func(){"--denials": func() { o.denialsOnly = true }},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	return o, nil
}

// auditTailEvents reads the tail of the audit log; swappable in tests.
var auditTailEvents = audit.TailEvents

// auditLogPath is the default audit log; swappable in tests.
var auditLogPath = desktop.AuditLogPath

func runAuditTail(o auditOpts) *cliExit {
	if o.path == "" {
		o.path = auditLogPath()
	}
	events, err := auditTailEvents(o.path, o.limit, o.denialsOnly)
	if err != nil {
		return &cliExit{code: 1, err: fmt.Sprintf("denyout-cli audit tail: %v\n", err)}
	}
	if len(events) == 0 {
		return &cliExit{err: "denyout-cli audit tail: no events\n"}
	}
	out := ""
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		out += string(b) + "\n"
	}
	return &cliExit{out: out}
}

func cmdAudit(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		return helpExit(auditUsage).emit()
	}
	if args[0] != "tail" {
		return failExit("denyout-cli audit: unknown subcommand %q (want: tail)", args[0]).emit()
	}
	o, ex := parseAuditTail(args[1:])
	if ex != nil {
		return ex.emit()
	}
	return runAuditTail(o).emit()
}
