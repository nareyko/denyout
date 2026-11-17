package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailEventsRingAndLongLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, `{"event_id":"e%d","verdict":"deny"}`+"\n", i)
		if i == 20 {
			b.WriteString(`{"x":"` + strings.Repeat("a", 2<<20) + `"}` + "\n") // > 1 MiB: skipped, not fatal
		}
		if i%2 == 0 {
			fmt.Fprintf(&b, `{"event_id":"allow%d","verdict":"allow"}`+"\n", i)
		}
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := TailEvents(p, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0].EventID != "e45" || got[4].EventID != "e49" {
		t.Fatalf("want e45..e49 oldest-first, got %+v", got)
	}
	all, _ := TailEvents(p, 1000, false)
	if len(all) != 50+25 {
		t.Fatalf("want 75 events (long line skipped), got %d", len(all))
	}
}

func TestSinkReopensAfterFailedRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	s, err := Open(p, false, "t")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.mu.Lock()
	_ = s.file.Close()
	s.file = nil // simulate rotation whose reopen failed
	s.mu.Unlock()
	if err := s.Log(Event{Verdict: "deny"}); err != nil {
		t.Fatalf("log after lost file: %v", err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"verdict":"deny"`) {
		t.Fatalf("event not written after reopen: %q", b)
	}
}
