package tun

import (
	"sync"
	"sync/atomic"
)

// Runtime holds live TUN dataplane state inside helper-serve (Linux).
// Non-Linux builds keep a no-op stub.
type Runtime struct {
	mu      sync.Mutex
	active  bool
	uid     int
	packets atomic.Uint64
	bytes   atomic.Uint64
	cancel  func()
}

var globalRuntime = &Runtime{}

// GlobalRuntime is the process-wide helper TUN state.
func GlobalRuntime() *Runtime { return globalRuntime }

// StatsSnapshot returns DropStats for tun-stats.
func (r *Runtime) StatsSnapshot() DropStats {
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	return DropStats{
		Packets: r.packets.Load(),
		Bytes:   r.bytes.Load(),
		Present: active,
		Source:  SourceTUN,
	}
}

// IsActive reports whether denyout0 steer/reader is up.
func (r *Runtime) IsActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

func (r *Runtime) addDrop(n int) {
	if n <= 0 {
		return
	}
	r.packets.Add(1)
	r.bytes.Add(uint64(n))
}
