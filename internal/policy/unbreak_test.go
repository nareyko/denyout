package policy_test

import (
	"net"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestUnbreakSeedSize(t *testing.T) {
	hosts := policy.DefaultUnbreakHosts()
	n := len(hosts)
	if n < 15 || n > 50 {
		t.Fatalf("want ~15–30 seed, got %d: %v", n, hosts)
	}
}

func TestUnbreakBeatsThreatList(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	// github.com is in Book D; pretend it is also on a threat list.
	eng.Threats = mapThreats{"github.com": "phishing-army"}
	d := eng.Evaluate(policy.RequestView{
		DestHost: "github.com",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://github.com/",
	})
	if d.Verdict != "allow" {
		t.Fatalf("unbreak must beat threat: %+v", d)
	}
}

func TestUnbreakDoesNotBypassScanner(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	eng.Threats = mapThreats{"github.com": "phishing-army"}
	d := eng.Evaluate(policy.RequestView{
		DestHost: "github.com",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://github.com/x?api_key=sk-denyouttest000000000000000",
	})
	if d.Verdict != "deny" {
		t.Fatalf("scanner must still deny: %+v", d)
	}
	found := false
	for _, r := range d.Reasons {
		if strings.HasPrefix(r, "secret_") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want secret reason: %+v", d)
	}
}

func TestUnbreakSkipsThreatHelper(t *testing.T) {
	if !policy.UnbreakSkipsThreat("cdn.jsdelivr.net") {
		t.Fatal("expected unbreak")
	}
	if policy.UnbreakSkipsThreat("totally-evil-not-unbreak.example") {
		t.Fatal("random host must not be unbreak")
	}
}
