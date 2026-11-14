package threatlists

import "testing"

func TestParseDomainsHostsABP(t *testing.T) {
	domains := []byte(`
# comment
evil-phish.example
GOOD.EXAMPLE.
`)
	got := Parse(domains, FormatDomains)
	if _, ok := got["evil-phish.example"]; !ok {
		t.Fatalf("missing domain: %#v", got)
	}
	if _, ok := got["good.example"]; !ok {
		t.Fatalf("normalize trailing dot: %#v", got)
	}

	hosts := []byte(`
127.0.0.1 malware.test # note
0.0.0.0 dual.a dual.b
# skip
`)
	got = Parse(hosts, FormatHosts)
	for _, h := range []string{"malware.test", "dual.a", "dual.b"} {
		if _, ok := got[h]; !ok {
			t.Fatalf("hosts missing %s: %#v", h, got)
		}
	}

	abp := []byte(`
||bad.ads^
||ok.track^$third-party
! comment
@@||whitelist^
`)
	got = Parse(abp, FormatABP)
	if _, ok := got["bad.ads"]; !ok {
		t.Fatalf("abp domain: %#v", got)
	}
	if _, ok := got["ok.track"]; !ok {
		t.Fatalf("abp with options: %#v", got)
	}
	if _, ok := got["whitelist"]; ok {
		t.Fatalf("exception rules must be ignored")
	}
}
