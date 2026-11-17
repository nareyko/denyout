package explain

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// policyReasonCodes reads the Reason* constants declared in internal/policy.
func policyReasonCodes(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join("..", "policy", "*.go"))
	var parsed []*ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, f)
	}
	var out []string
	{
		for _, f := range parsed {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, s := range gd.Specs {
					vs := s.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if !strings.HasPrefix(n.Name, "Reason") || i >= len(vs.Values) {
							continue
						}
						if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
							v, _ := strconv.Unquote(bl.Value)
							out = append(out, v)
						}
					}
				}
			}
		}
	}
	return out
}

var literalReason = regexp.MustCompile(`Reasons?(?::\s*(?:\[\]string\{)?|\s*=\s*)"([a-z_]+)"`)

// emittedLiteralReasons finds reason codes written as string literals in the
// packages that produce deny decisions (policy engine, scanners, proxy).
func emittedLiteralReasons(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, dir := range []string{"policy", "secrets", "inspect", "proxy"} {
		files, _ := filepath.Glob(filepath.Join("..", dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range literalReason.FindAllStringSubmatch(string(b), -1) {
				seen[m[1]] = true
			}
		}
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestEveryPolicyReasonHasEntry(t *testing.T) {
	codes := policyReasonCodes(t)
	if len(codes) < 10 {
		t.Fatalf("parsed too few policy reason constants: %v", codes)
	}
	for _, c := range codes {
		if _, ok := Lookup(c); !ok {
			t.Errorf("policy reason %q has no entry in internal/explain table", c)
		}
	}
}

func TestEveryEmittedLiteralReasonHasEntry(t *testing.T) {
	codes := emittedLiteralReasons(t)
	if len(codes) == 0 {
		t.Fatal("found no literal reasons; scan pattern is broken")
	}
	for _, c := range codes {
		if _, ok := Lookup(c); !ok {
			t.Errorf("emitted reason %q has no entry in internal/explain table", c)
		}
	}
}

func TestEntriesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range table {
		if seen[e.Code] {
			t.Errorf("duplicate code %q", e.Code)
		}
		seen[e.Code] = true
		if e.Short == "" || e.Title == "" || e.Detail == "" || e.Rule == "" || e.Fix == "" {
			t.Errorf("%s: incomplete entry %+v", e.Code, e)
		}
		for _, s := range []string{e.Short, e.Title, e.Detail, e.Rule, e.Fix} {
			for _, r := range s {
				if r > 127 {
					t.Errorf("%s: non-ASCII %q in copy (copy-hygiene)", e.Code, r)
				}
			}
		}
	}
}

func TestContentBlocksDoNotOfferSiteAllow(t *testing.T) {
	for _, c := range []string{"secret_in_url", "secret_in_header", "secret_in_body", "canary_detected", "unsafe_ip", "ip_literal"} {
		if Describe(c).AllowHelps {
			t.Errorf("%s must not offer a per-site allow", c)
		}
	}
	for _, c := range []string{"host_not_allowed", "host_denied", "threat_phishing"} {
		if !Describe(c).AllowHelps {
			t.Errorf("%s should allow-by-site", c)
		}
	}
	if Describe("totally_new_code").AllowHelps {
		t.Error("unknown codes must not offer allow")
	}
}

func TestRuleLabelNamesDetectorsOnly(t *testing.T) {
	got := RuleLabel("secret_in_url", []string{"github_token", "aws_key"})
	if !strings.Contains(got, "aws_key, github_token") {
		t.Fatalf("got %q", got)
	}
	if RuleLabel("host_not_allowed", []string{"x"}) != Describe("host_not_allowed").Rule {
		t.Fatal("detectors only apply to secret blocks")
	}
}

func TestShortUnknownPassesThrough(t *testing.T) {
	if Short([]string{"mystery"}) != "mystery" {
		t.Fatal("unknown code should pass through")
	}
	if Short(nil) == "" {
		t.Fatal("empty reasons need generic copy")
	}
}
