package tun

import (
	"sync"
	"sync/atomic"
)

// Runtime holds live TUN dataplane state inside helper-serve (Linux).
// Non-Linux builds keep a no-op stub.
type Runtime struct {
	mu        sync.Mutex
	active    bool
	uid       int
	packets   atomic.Uint64
	bytes     atomic.Uint64
	sightings atomic.Uint64
	lastSNI   atomic.Value // string
	cancel    func()
}

var globalRuntime = &Runtime{}

// GlobalRuntime is the process-wide helper TUN state.
func GlobalRuntime() *Runtime { return globalRuntime }

// StatsSnapshot returns DropStats for tun-stats.
func (r *Runtime) StatsSnapshot() DropStats {
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	last, _ := r.lastSNI.Load().(string)
	return DropStats{
		Packets:   r.packets.Load(),
		Bytes:     r.bytes.Load(),
		Present:   active,
		Source:    SourceTUN,
		Sightings: r.sightings.Load(),
		LastSNI:   last,
	}
}

// RecordSighting increments QUIC sight telemetry (called from OnSighting / readLoop).
func (r *Runtime) RecordSighting(sni string) {
	r.sightings.Add(1)
	if sni != "" {
		r.lastSNI.Store(sni)
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

// resetCountersLocked clears counters; caller must hold r.mu (active/uid only).
func (r *Runtime) resetCountersLocked() {
	r.packets.Store(0)
	r.bytes.Store(0)
	r.sightings.Store(0)
	r.lastSNI.Store("")
}
