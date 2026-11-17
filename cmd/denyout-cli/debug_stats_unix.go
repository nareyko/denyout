//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// startDebugStats prints "debug-stats goroutines=N" to stderr on SIGUSR1 when
// DENYOUT_DEBUG_STATS=1. Used only by the Docker soak test to bound goroutine growth.
func startDebugStats() {
	if os.Getenv("DENYOUT_DEBUG_STATS") != "1" {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
			fmt.Fprintf(os.Stderr, "debug-stats goroutines=%d\n", runtime.NumGoroutine())
		}
	}()
}
