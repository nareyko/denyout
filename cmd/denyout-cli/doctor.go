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

type doctorOpts struct {
	jsonOut bool
	strict  bool
}

// setDoctorNumber applies -n / --limit / --proxy-port, returning the stderr
// message on invalid input ("" = ok).
func setDoctorNumber(in *diag.Inputs, flag, val string) string {
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 || n > 65535 {
		return fmt.Sprintf("denyout-cli doctor: invalid %s %q\n", flag, val)
	}
	if flag == "--proxy-port" {
		in.ProxyPort = n
	} else {
		in.MaxDenials = n
	}
	return ""
}

// parseDoctorArgs parses doctor flags, adjusting the report inputs in place.
func parseDoctorArgs(args []string, in *diag.Inputs) (doctorOpts, *cliExit) {
	var o doctorOpts
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--help", "-h":
			return o, helpExit(doctorUsage)
		case "--json":
			o.jsonOut = true
		case "--strict":
			o.strict = true
		case "--protect-on":
			in.ProtectionOn = true
		case "-n", "--limit", "--proxy-port":
			i++
			if i >= len(args) {
				return o, &cliExit{code: 2, err: fmt.Sprintf("denyout-cli doctor: %s requires a number\n", a)}
			}
			if msg := setDoctorNumber(in, a, args[i]); msg != "" {
				return o, &cliExit{code: 2, err: msg}
			}
		default:
			return o, &cliExit{code: 2, err: fmt.Sprintf("denyout-cli doctor: unknown argument %q\n\n%s\n", a, doctorUsage)}
		}
	}
	return o, nil
}

// renderDoctor formats the report; with --strict any failed check exits 1.
func renderDoctor(r diag.Report, o doctorOpts) *cliExit {
	var out string
	if o.jsonOut {
		b, err := r.JSON()
		if err != nil {
			return &cliExit{code: 1, err: fmt.Sprintf("denyout-cli doctor: %v\n", err)}
		}
		out = string(b) + "\n"
	} else {
		out = r.Text()
	}
	ex := &cliExit{out: out}
	if o.strict && hasFailedCheck(r) {
		ex.code = 1
	}
	return ex
}

func hasFailedCheck(r diag.Report) bool {
	for _, c := range r.Checks {
		if c.Status == diag.Fail {
			return true
		}
	}
	return false
}

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	in := diag.LocalInputs(version)
	o, ex := parseDoctorArgs(args, &in)
	if ex != nil {
		return ex.emitTo(stdout, stderr)
	}
	return renderDoctor(diag.Build(in), o).emitTo(stdout, stderr)
}
