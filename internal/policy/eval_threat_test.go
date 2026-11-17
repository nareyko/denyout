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

func TestUnsafeIPExtendedRanges(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "169.254.169.254": true, "100.100.100.200": true, "100.64.1.1": true,
		"0.0.0.1": true, "224.0.0.1": true, "255.255.255.255": true, "fd00:ec2::254": true,
		"64:ff9b::7f00:1": true, "64:ff9b::808:808": false, "8.8.8.8": false, "10.0.0.1": true, "::1": true,
	} {
		if got := policy.UnsafeIP(net.ParseIP(ip), false); got != want {
			t.Errorf("policy.UnsafeIP(%s,false)=%v want %v", ip, got, want)
		}
	}
	if policy.UnsafeIP(net.ParseIP("100.64.1.1"), true) || !policy.UnsafeIP(net.ParseIP("100.100.100.200"), true) || !policy.UnsafeIP(net.ParseIP("fd00:ec2::254"), true) {
		t.Error("allow_private semantics wrong")
	}
}
