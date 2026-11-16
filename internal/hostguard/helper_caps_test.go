package hostguard_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
)

func TestFormatParseCapsReply(t *testing.T) {
	line := hostguard.FormatCapsReply("0.4.12-dev", hostguard.CapQUIC, hostguard.CapTUN, hostguard.CapVPN)
	if !strings.Contains(line, "caps1") || !strings.Contains(line, "quic1") || !strings.Contains(line, "tun1") {
		t.Fatal(line)
	}
	c := hostguard.ParseCapsReply(line)
	if !c.OK || !c.HasCap(hostguard.CapTUN) || c.Version != "0.4.12-dev" {
		t.Fatalf("%+v", c)
	}
	if miss := c.MissingRequired(hostguard.RequiredProtectCaps); len(miss) != 0 {
		t.Fatalf("missing %v", miss)
	}
}

func TestCapsSatisfiedLegacyPlainOK(t *testing.T) {
	if hostguard.CapsSatisfied("OK", hostguard.RequiredProtectCaps) {
		t.Fatal("plain OK must not satisfy tun1/quic1")
	}
	if !hostguard.CapsSatisfied(hostguard.FormatCapsReply("", hostguard.CapQUIC, hostguard.CapTUN), hostguard.RequiredProtectCaps) {
		t.Fatal("expected satisfied")
	}
}
