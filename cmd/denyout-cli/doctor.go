package main

import (
	"fmt"
	"io"
	"strconv"

	"github.com/nareyko/denyout/internal/diag"
)

const doctorUsage = `Usage: denyout-cli doctor [--json] [-n N] [--proxy-port PORT] [--protect-on] [--strict]

  Print a redacted status report: version, OS, helper, proxy, CA self-check,
  threat list freshness and the last N denials (default 10). Secrets are
  masked, so the output is safe to paste into a bug report. Nothing is
  changed on this computer.

  --json              machine-readable output
  -n N                number of recent denials (max 50)
  --proxy-port PORT   also check that 127.0.0.1:PORT accepts connections
  --protect-on        treat a missing CA or proxy as a failure
  --strict            exit 1 when any check fails`

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	in := diag.LocalInputs(version)
	jsonOut, strict := false, false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--help", "-h":
			fmt.Fprintln(stdout, doctorUsage)
			return 0
		case "--json":
			jsonOut = true
		case "--strict":
			strict = true
		case "--protect-on":
			in.ProtectionOn = true
		case "-n", "--limit", "--proxy-port":
			i++
			if i >= len(args) {
				fmt.Fprintf(stderr, "denyout-cli doctor: %s requires a number\n", a)
				return 2
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 || n > 65535 {
				fmt.Fprintf(stderr, "denyout-cli doctor: invalid %s %q\n", a, args[i])
				return 2
			}
			if a == "--proxy-port" {
				in.ProxyPort = n
			} else {
				in.MaxDenials = n
			}
		default:
			fmt.Fprintf(stderr, "denyout-cli doctor: unknown argument %q\n\n%s\n", a, doctorUsage)
			return 2
		}
	}
	r := diag.Build(in)
	if jsonOut {
		b, err := r.JSON()
		if err != nil {
			fmt.Fprintf(stderr, "denyout-cli doctor: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		fmt.Fprint(stdout, r.Text())
	}
	if strict {
		for _, c := range r.Checks {
			if c.Status == diag.Fail {
				return 1
			}
		}
	}
	return 0
}
