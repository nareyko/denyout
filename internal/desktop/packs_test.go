package desktop

import (
	"testing"
)

func TestListAllowPacks(t *testing.T) {
	packs, err := ListAllowPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) < 2 {
		t.Fatalf("want cursor+claude, got %d", len(packs))
	}
	ids := map[string]bool{}
	for _, p := range packs {
		ids[p.ID] = true
		if len(p.Hosts) == 0 {
			t.Fatalf("%s empty hosts", p.ID)
		}
	}
	if !ids["cursor-starter"] || !ids["claude-starter"] {
		t.Fatalf("%v", ids)
	}
}

func TestApplyPackIdempotentAndUndo(t *testing.T) {
	p := NewAgentProfile("Cursor CLI", []string{"cursor", "agent"})
	added, err := ApplyPack(&p, "cursor-starter")
	if err != nil {
		t.Fatal(err)
	}
	if len(added) == 0 {
		t.Fatal("expected hosts added")
	}
	n := len(p.ExtraAllow)
	added2, err := ApplyPack(&p, "cursor-starter")
	if err != nil {
		t.Fatal(err)
	}
	if len(added2) != 0 {
		t.Fatalf("idempotent: got %v", added2)
	}
	if len(p.ExtraAllow) != n {
		t.Fatal("extra_allow grew on second apply")
	}
	if len(p.AppliedPacks) != 1 || p.AppliedPacks[0].ID != "cursor-starter" {
		t.Fatalf("%+v", p.AppliedPacks)
	}

	removed, err := UndoPack(&p, "cursor-starter")
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 {
		t.Fatal("expected removals")
	}
	if len(p.ExtraAllow) != 0 {
		t.Fatalf("allow should be empty after undo: %v", p.ExtraAllow)
	}
	if len(p.AppliedPacks) != 0 {
		t.Fatalf("applied: %+v", p.AppliedPacks)
	}
}

func TestApplyPackDoesNotClaimPreexisting(t *testing.T) {
	p := NewAgentProfile("x", []string{"claude"})
	p.ExtraAllow = []string{"api.anthropic.com", "github.com"}
	added, err := ApplyPack(&p, "claude-starter")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range added {
		if h == "api.anthropic.com" || h == "github.com" {
			t.Fatalf("must not re-claim existing: %v", added)
		}
	}
	removed, err := UndoPack(&p, "claude-starter")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range removed {
		if h == "api.anthropic.com" || h == "github.com" {
			t.Fatal("undo must not remove pre-existing hosts")
		}
	}
	if !containsFold(p.ExtraAllow, "api.anthropic.com") || !containsFold(p.ExtraAllow, "github.com") {
		t.Fatalf("preexisting kept: %v", p.ExtraAllow)
	}
}

func TestSuggestPackID(t *testing.T) {
	if SuggestPackID("My Cursor", []string{"cursor"}) != "cursor-starter" {
		t.Fatal()
	}
	if SuggestPackID("Claude", []string{"claude"}) != "claude-starter" {
		t.Fatal()
	}
	if SuggestPackID("Bot", []string{"python"}) != "" {
		t.Fatal()
	}
}
