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
