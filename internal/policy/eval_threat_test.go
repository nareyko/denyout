package policy_test

import (
	"net"
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

type mapThreats map[string]string // host → feedID

func (m mapThreats) CheckThreat(host string) (string, bool) {
	id, ok := m[host]
	return id, ok
}

func TestThreatListDeniesInBlocklist(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	eng.Threats = mapThreats{"evil.phish": "phishing-army"}
	d := eng.Evaluate(policy.RequestView{
		DestHost: "evil.phish",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://evil.phish/",
	})
	if d.Verdict != "deny" {
		t.Fatalf("%+v", d)
	}
	found := false
	for _, r := range d.Reasons {
		if r == policy.ReasonThreatPhishing {
			found = true
		}
	}
	if !found {
		t.Fatalf("want threat_phishing: %+v", d)
	}
}

func TestUserAlwaysBeatsThreatList(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Allow = append(cfg.Allow, policy.Rule{Host: "evil.phish", Reason: "user_always"})
	eng := policy.NewEngine(cfg)
	eng.Threats = mapThreats{"evil.phish": "phishing-army"}
	d := eng.Evaluate(policy.RequestView{
		DestHost: "evil.phish",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://evil.phish/",
	})
	if d.Verdict != "allow" {
		t.Fatalf("Always must beat threat: %+v", d)
	}
}

func TestPackAllowDoesNotBeatThreatList(t *testing.T) {
	cfg, err := policy.DefaultWholeDevice()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Allow = append(cfg.Allow, policy.Rule{Host: "evil.phish", Reason: "profile"})
	eng := policy.NewEngine(cfg)
	eng.Threats = mapThreats{"evil.phish": "urlhaus-hosts"}
	d := eng.Evaluate(policy.RequestView{
		DestHost: "evil.phish",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://evil.phish/",
	})
	if d.Verdict != "deny" {
		t.Fatalf("pack allow must not bypass threat: %+v", d)
	}
	ok := false
	for _, r := range d.Reasons {
		if r == policy.ReasonThreatMalware {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("%+v", d)
	}
}

func TestThreatAdsReason(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	eng.Threats = mapThreats{"tracker.example": "stevenblack-unified"}
	d := eng.Evaluate(policy.RequestView{
		DestHost: "tracker.example",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://tracker.example/",
	})
	if d.Verdict != "deny" {
		t.Fatalf("%+v", d)
	}
	ok := false
	for _, r := range d.Reasons {
		if r == policy.ReasonThreatAds {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("want threat_ads: %+v", d)
	}
}

func TestUserOnceBeatsThreatList(t *testing.T) {
	cfg, err := policy.DefaultWholeDeviceBrowse()
	if err != nil {
		t.Fatal(err)
	}
	eng := policy.NewEngine(cfg)
	eng.Threats = mapThreats{"temp.bad": "phishing-army"}
	eng.AllowHost("temp.bad", "user_once")
	d := eng.Evaluate(policy.RequestView{
		DestHost: "temp.bad",
		DestPort: 443,
		DestIPs:  []net.IP{net.ParseIP("1.1.1.1")},
		RawURL:   "https://temp.bad/",
	})
	if d.Verdict != "allow" {
		t.Fatalf("%+v", d)
	}
}
