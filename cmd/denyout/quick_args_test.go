package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandleGUIQuickArgsVersion(t *testing.T) {
	for _, a := range []string{"version", "--version", "-V"} {
		var out bytes.Buffer
		code, ok := handleGUIQuickArgs([]string{a}, "9.9.9", &out, &out)
		if !ok || code != 0 {
			t.Fatalf("%s: handled=%v code=%d", a, ok, code)
		}
		if !strings.Contains(out.String(), "denyout 9.9.9") {
			t.Fatalf("%s: %q", a, out.String())
		}
	}
}

func TestHandleGUIQuickArgsHelp(t *testing.T) {
	var out bytes.Buffer
	code, ok := handleGUIQuickArgs([]string{"help"}, "1.0", &out, &out)
	if !ok || code != 0 {
		t.Fatalf("handled=%v code=%d", ok, code)
	}
	if !strings.Contains(out.String(), "denyout-cli") {
		t.Fatalf("%q", out.String())
	}
}

func TestHandleGUIQuickArgsCLIVerb(t *testing.T) {
	var errBuf bytes.Buffer
	code, ok := handleGUIQuickArgs([]string{"check", "https://x"}, "1.0", &bytes.Buffer{}, &errBuf)
	if !ok || code != 2 {
		t.Fatalf("handled=%v code=%d", ok, code)
	}
	if !strings.Contains(errBuf.String(), "denyout-cli check") {
		t.Fatalf("%q", errBuf.String())
	}
}

func TestHandleGUIQuickArgsUnknownBare(t *testing.T) {
	var errBuf bytes.Buffer
	code, ok := handleGUIQuickArgs([]string{"versino"}, "1.0", &bytes.Buffer{}, &errBuf)
	if !ok || code != 2 {
		t.Fatalf("handled=%v code=%d", ok, code)
	}
}

func TestHandleGUIQuickArgsGUIFlagsPassThrough(t *testing.T) {
	for _, args := range [][]string{
		{"--open"},
		{"--foreground"},
		{"--no-tray"},
		nil,
		{},
	} {
		code, ok := handleGUIQuickArgs(args, "1.0", &bytes.Buffer{}, &bytes.Buffer{})
		if ok || code != 0 {
			t.Fatalf("%v: handled=%v code=%d (must start GUI)", args, ok, code)
		}
	}
}
