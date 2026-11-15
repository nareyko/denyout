package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestHelperReplyStartStopDisabled(t *testing.T) {
	t.Setenv(tun.EnvE2E, "")
	for _, verb := range []string{"tun-start", "tun-stop"} {
		line, err := tun.HelperReply(verb)
		if err != nil {
			t.Fatal(err)
		}
		st, err := tun.ParseHelperReply(line)
		if err != nil {
			t.Fatal(err)
		}
		if st.Enabled {
			t.Fatalf("%s must stay disabled in closed-loop: %q", verb, line)
		}
		if st.Verb != verb {
			t.Fatalf("verb=%q", st.Verb)
		}
		if st.Reason != "flag_off" {
			t.Fatalf("reason=%q line=%q", st.Reason, line)
		}
		if !strings.Contains(line, tun.CapTag) {
			t.Fatalf("missing cap: %q", line)
		}
	}
}

func TestHelperReplyStatsDisabled(t *testing.T) {
	t.Setenv(tun.EnvE2E, "")
	line, err := tun.HelperReply("tun-stats")
	if err != nil {
		t.Fatal(err)
	}
	st, err := tun.ParseHelperReply(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.Stats.Present || st.Stats.Source != tun.SourceTUN {
		t.Fatalf("%+v from %q", st.Stats, line)
	}
	if st.Enabled {
		t.Fatal("stats stub must not claim enabled")
	}
	if st.Reason != "flag_off" {
		t.Fatalf("reason=%q", st.Reason)
	}
}

func TestHelperReplyReasonStubWhenE2E(t *testing.T) {
	t.Setenv(tun.EnvE2E, "1")
	line, err := tun.HelperReply("tun-start")
	if err != nil {
		t.Fatal(err)
	}
	st, err := tun.ParseHelperReply(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Reason != "stub_no_device" {
		t.Fatalf("%+v from %q", st, line)
	}
}

func TestHelperReplyUnknown(t *testing.T) {
	if _, err := tun.HelperReply("apply"); err == nil {
		t.Fatal("expected error")
	}
}

func TestIsHelperVerb(t *testing.T) {
	if !tun.IsHelperVerb("TUN-START") || tun.IsHelperVerb("quic-stats") {
		t.Fatal("verb gate")
	}
}

func TestHelperLineMatchesReplyContract(t *testing.T) {
	req, err := tun.HelperLine("tun-start", 1000)
	if err != nil {
		t.Fatal(err)
	}
	verb := strings.Fields(req)[0]
	reply, err := tun.HelperReply(verb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply, "OK "+tun.CapTag) {
		t.Fatalf("%q", reply)
	}
}
