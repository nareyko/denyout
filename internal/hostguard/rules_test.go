package hostguard_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
)

func TestRenderRulesContainsPort(t *testing.T) {
	spec := hostguard.Spec{ProxyPort: 18443, UID: 1000, CACert: "/tmp/ca.crt"}
	out, err := hostguard.Render(spec)
	if err != nil {
		if err == hostguard.ErrUnsupported {
			t.Skip("unsupported GOOS")
		}
		t.Fatal(err)
	}
	if !strings.Contains(out, "18443") {
		t.Fatalf("expected port in rules:\n%s", out)
	}
	switch runtime.GOOS {
	case "linux":
		if !strings.Contains(out, "skuid 1000") {
			t.Fatalf("linux rules missing uid:\n%s", out)
		}
		if !strings.Contains(out, "table inet denyout") {
			t.Fatalf("linux rules missing inet table:\n%s", out)
		}
		if !strings.Contains(out, "ip6 daddr") {
			t.Fatalf("linux rules missing ipv6:\n%s", out)
		}
		if !strings.Contains(out, "meta mark") {
			t.Fatalf("linux rules missing mark skip:\n%s", out)
		}
		if !strings.Contains(out, "udp dport 443 counter drop") {
			t.Fatalf("linux rules missing QUIC drop counter by default:\n%s", out)
		}
		if !strings.Contains(out, "denyout-block-quic") {
			t.Fatalf("linux rules missing QUIC comment:\n%s", out)
		}
	case "darwin":
		if !strings.Contains(out, "user 1000") {
			t.Fatalf("darwin rules missing user:\n%s", out)
		}
		if !strings.Contains(out, "proto udp") {
			t.Fatalf("darwin rules missing QUIC block by default:\n%s", out)
		}
	case "windows":
		if !strings.Contains(out, "tcp.DstPort") {
			t.Fatalf("windows filter missing:\n%s", out)
		}
	}
}

func TestDryRunApply(t *testing.T) {
	err := hostguard.Apply(hostguard.Spec{ProxyPort: 18443, UID: 1000, DryRun: true})
	if err == hostguard.ErrUnsupported {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestRenderAllowQUICSkipsUDPDrop(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("QUIC drop is Unix-oriented")
	}
	spec := hostguard.Spec{ProxyPort: 18443, UID: 1000, AllowQUIC: true}
	out, err := hostguard.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "udp dport 443 drop") || strings.Contains(out, "proto udp") {
		t.Fatalf("AllowQUIC should omit UDP drop:\n%s", out)
	}
}
