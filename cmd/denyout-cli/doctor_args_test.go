package main

import (
	"testing"

	"github.com/nareyko/denyout/internal/diag"
)

func TestParseDoctorArgs(t *testing.T) {
	in := diag.Inputs{}
	o, ex := parseDoctorArgs([]string{"--json", "--strict", "--protect-on", "-n", "7", "--proxy-port", "8080"}, &in)
	if ex != nil || !o.jsonOut || !o.strict || !in.ProtectionOn || in.MaxDenials != 7 || in.ProxyPort != 8080 {
		t.Fatalf("%+v %+v %v", o, in, ex)
	}
	_, ex = parseDoctorArgs([]string{"-h"}, &in)
	wantExit(t, ex, 0, doctorUsage+"\n", "")
	_, ex = parseDoctorArgs([]string{"--limit"}, &in)
	wantExit(t, ex, 2, "", "denyout-cli doctor: --limit requires a number\n")
	_, ex = parseDoctorArgs([]string{"--proxy-port", "70000"}, &in)
	wantExit(t, ex, 2, "", "denyout-cli doctor: invalid --proxy-port \"70000\"\n")
	_, ex = parseDoctorArgs([]string{"--x"}, &in)
	wantExit(t, ex, 2, "", "denyout-cli doctor: unknown argument \"--x\"\n\n"+doctorUsage+"\n")
}
