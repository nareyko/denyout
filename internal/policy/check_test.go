package policy

import (
	"strings"
	"testing"
)

func TestCheckValid(t *testing.T) {
	good := "apiVersion: denyout/v1\nkind: Config\nmode: enforce\npreset: none\n"
	if ds := Check([]byte(good)); len(ds) != 0 {
		t.Fatalf("valid policy flagged: %v", ds)
	}
}

func TestCheckYAMLSyntaxLine(t *testing.T) {
	ds := Check([]byte("apiVersion: denyout/v1\nkind: [unclosed\n"))
	if len(ds) != 1 || ds[0].Line == 0 {
		t.Fatalf("want one diagnostic with a line, got %+v", ds)
	}
}

func TestCheckSchemaLine(t *testing.T) {
	doc := "apiVersion: denyout/v1\nkind: Config\nallowed_ports:\n  - 443\n  - \"x\"\n"
	ds := Check([]byte(doc))
	if len(ds) == 0 {
		t.Fatal("expected diagnostics")
	}
	found := false
	for _, d := range ds {
		if d.Line == 5 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a diagnostic on line 5: %+v", ds)
	}
}

func TestCheckBadAPIVersionAndRegex(t *testing.T) {
	if ds := Check([]byte("apiVersion: nope/v9\nkind: Config\n")); len(ds) == 0 {
		t.Fatal("bad apiVersion must fail")
	}
	doc := "apiVersion: denyout/v1\nkind: Config\nscanners:\n  custom_regex:\n    - id: a\n      pattern: \"(\"\n"
	ds := Check([]byte(doc))
	if len(ds) == 0 || !strings.Contains(ds[0].Message, "custom_regex") || ds[0].Line != 4 {
		t.Fatalf("bad regex diagnostic: %+v", ds)
	}
}

func TestCheckAgreesWithLoadBytes(t *testing.T) {
	for _, doc := range []string{
		"", "kind: Config", "apiVersion: denyout/v1\nkind: Other\n",
		"apiVersion: denyout/v1\nkind: Config\nmode: bogus\n",
		"apiVersion: denyout/v1\nkind: Config\npreset: none\n",
	} {
		_, err := LoadBytes([]byte(doc))
		ds := Check([]byte(doc))
		if (err == nil) != (len(ds) == 0) {
			t.Errorf("Check/LoadBytes disagree on %q: err=%v ds=%v", doc, err, ds)
		}
	}
}

func TestFormatDiagnosticsQuotesLine(t *testing.T) {
	raw := []byte("a: 1\nb: 2\n")
	out := FormatDiagnostics(raw, []Diagnostic{{Line: 2, Message: "boom"}})
	if !strings.Contains(out, "line 2: boom") || !strings.Contains(out, "b: 2") {
		t.Fatalf("got %q", out)
	}
}
