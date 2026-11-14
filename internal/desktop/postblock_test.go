package desktop

import "testing"

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
