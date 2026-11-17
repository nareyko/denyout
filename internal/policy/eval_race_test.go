package policy

import (
	"fmt"
	"sync"
	"testing"
)

// Run with -race: Evaluate must not race with AllowHost/RevokeHost.
func TestEvaluateAllowHostRace(t *testing.T) {
	cfg, err := DefaultEnforceModels()
	if err != nil {
		t.Skip(err)
	}
	e := NewEngine(cfg)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h := fmt.Sprintf("h%d-%d.example.com", i, j%5)
				e.AllowHost(h, "t")
				e.RevokeHost(h)
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				e.Evaluate(RequestView{DestHost: "example.com", DestPort: 443, Protocol: "https"})
			}
		}()
	}
	wg.Wait()
}

func TestCustomRegexIsApplied(t *testing.T) {
	cfg, err := DefaultEnforceModels()
	if err != nil {
		t.Skip(err)
	}
	cfg.Scanners.CustomRegex = []CustomRegex{{ID: "corp", Pattern: `CORP-[0-9]{6}`}}
	e := NewEngine(cfg)
	d := e.Evaluate(RequestView{DestHost: "example.com", DestPort: 443, Protocol: "https",
		RawURL: "https://example.com/?x=CORP-123456", Method: "GET"})
	if d.Verdict != "deny" {
		t.Fatalf("custom regex not enforced: %+v", d)
	}
}

func TestEvaluateURLRejectsWrappedPort(t *testing.T) {
	cfg, err := DefaultEnforceModels()
	if err != nil {
		t.Skip(err)
	}
	d, _ := NewEngine(cfg).EvaluateURL("https://example.com:65616/")
	if d.Verdict != "deny" {
		t.Fatalf("port 65616 must not wrap to 80: %+v", d)
	}
}
