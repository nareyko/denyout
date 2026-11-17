package desktop

import (
	"path/filepath"
	"testing"
)

func TestPrimaryPostBlockReason(t *testing.T) {
	if primaryPostBlockReason([]string{"host_not_allowed"}) != "" {
		t.Fatal("host_not_allowed is Pre-act, not post-block")
	}
	if primaryPostBlockReason([]string{"secret_in_url"}) != "secret_in_url" {
		t.Fatal("secret")
	}
	if primaryPostBlockReason([]string{"canary_detected", "secret_in_url"}) != "canary_detected" {
		t.Fatal("first clear reason")
	}
	if primaryPostBlockReason([]string{"threat_list"}) != "threat_list" {
		t.Fatal("threat_list is clear post-block")
	}
	if primaryPostBlockReason([]string{"threat_ads"}) != "threat_ads" {
		t.Fatal("threat_ads is clear post-block")
	}
	if primaryPostBlockReason([]string{"threat_phishing"}) != "threat_phishing" {
		t.Fatal("threat_phishing is clear post-block")
	}
}

func TestRememberedKeepRoundTrip(t *testing.T) {
	st := DefaultState()
	if st.RememberedKeep("evil.example", "secret_in_url") {
		t.Fatal("empty")
	}
	st.RememberedKeeps = append(st.RememberedKeeps, postBlockKey("Evil.Example", "secret_in_url"))
	if !st.RememberedKeep("evil.example", "secret_in_url") {
		t.Fatal("want remembered")
	}
}

func TestProfilePathCannotEscape(t *testing.T) {
	for _, id := range []string{"../../etc/x", "a/b", "..", "x\x00y", ""} {
		got := profilePath(id)
		if filepath.Dir(got) != filepath.Clean(ProfilesDir()) {
			t.Errorf("profilePath(%q)=%q escapes ProfilesDir", id, got)
		}
		if err := DeleteProfile(id); err == nil {
			t.Errorf("DeleteProfile(%q) should fail", id)
		}
	}
	if !ValidProfileID("my-agent_1") || ValidProfileID("../x") {
		t.Error("ValidProfileID wrong")
	}
}
