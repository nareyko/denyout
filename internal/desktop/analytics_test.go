package desktop

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetLocalAnalyticsCounts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_ = os.MkdirAll(LogDir(), 0o755)
	writeLines(t, BlocksLogPath(), []string{
		`{"ts":"` + now + `","type":"deny","host":"a.example"}`,
		`{"ts":"` + now + `","type":"deny","host":"b.example"}`,
		`{"ts":"` + now + `","type":"always_allow_add","host":"ok.example"}`,
		`{"ts":"` + now + `","type":"ask_shown","host":"new.example"}`,
		`{"ts":"` + now + `","type":"hardblock_answered","action":"allow","host":"c.example"}`,
	})
	writeLines(t, EventsLogPath(), []string{
		`{"ts":"` + now + `","type":"protect_on","source":"enable"}`,
		`{"ts":"` + now + `","type":"protect_pause","choice":"forever"}`,
	})
	writeLines(t, filepath.Join(LogDir(), "notify.jsonl"), []string{
		`{"ts":"` + now + `","kind":"open_app","shown":false,"reason":"quiet"}`,
		`{"ts":"` + now + `","kind":"protect_failed","shown":true,"reason":""}`,
	})

	got := a.GetLocalAnalytics(7)
	if got.Blocked != 2 {
		t.Fatalf("blocked=%d", got.Blocked)
	}
	if got.YouAllowed != 2 { // always_allow_add + hardblock allow
		t.Fatalf("you_allowed=%d", got.YouAllowed)
	}
	if got.Asked != 1 {
		t.Fatalf("asked=%d", got.Asked)
	}
	if got.QuietWeek {
		t.Fatal("not a quiet week")
	}
	if len(got.ProtectTimeline) < 2 {
		t.Fatalf("timeline=%+v", got.ProtectTimeline)
	}
	if got.BannersShown != 1 || got.BannersHeldBack != 1 {
		t.Fatalf("banners shown=%d held=%d", got.BannersShown, got.BannersHeldBack)
	}
}

func TestGetLocalAnalyticsQuietWeek(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	got := a.GetLocalAnalytics(7)
	if !got.QuietWeek {
		t.Fatalf("%+v", got)
	}
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	var b []byte
	for _, l := range lines {
		b = append(b, l...)
		b = append(b, '\n')
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
