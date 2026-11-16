package tun

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Source identifies which path produced QUIC drop telemetry.
type Source string

const (
	SourceNFT Source = "nft"
	SourceTUN Source = "tun"
)

// DropStats mirrors hostguard.QUICDropStats with an explicit source tag.
type DropStats struct {
	Packets   uint64
	Bytes     uint64
	Present   bool
	Source    Source
	Sightings uint64 // QUIC Initial sightings (SNI best-effort)
	LastSNI   string // last sighted SNI (may be empty)
}

// Counter accumulates DropLog decisions in userspace (T1 closed-loop).
type Counter struct {
	mu sync.Mutex
	st DropStats
}

// NewCounter starts a present=true tun-sourced counter.
func NewCounter() *Counter {
	return &Counter{st: DropStats{Present: true, Source: SourceTUN}}
}

// Record adds one dropped packet of size n (IP total length when known).
func (c *Counter) Record(n int) {
	if c == nil || n < 0 {
		return
	}
	c.mu.Lock()
	c.st.Packets++
	c.st.Bytes += uint64(n)
	c.st.Present = true
	if c.st.Source == "" {
		c.st.Source = SourceTUN
	}
	c.mu.Unlock()
}

// Snapshot returns a copy of current totals.
func (c *Counter) Snapshot() DropStats {
	if c == nil {
		return DropStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

// FormatDropStatsLine is the helper/hostctl payload after OK (includes source=).
func FormatDropStatsLine(st DropStats) string {
	src := st.Source
	if src == "" {
		src = SourceNFT
	}
	line := fmt.Sprintf("packets=%d bytes=%d present=%t source=%s", st.Packets, st.Bytes, st.Present, src)
	if st.Sightings > 0 || st.LastSNI != "" {
		line += fmt.Sprintf(" sightings=%d", st.Sightings)
		if st.LastSNI != "" {
			line += " last_sni=" + sanitizeSNIToken(st.LastSNI)
		}
	}
	return line
}

func sanitizeSNIToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// hostctl replies are space-delimited; keep SNI a single token.
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

// ParseDropStatsLine parses "OK … packets=… bytes=… present=… [source=…]" fields.
func ParseDropStatsLine(resp string) (DropStats, error) {
	var st DropStats
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return st, fmt.Errorf("tun-stats: %s", resp)
	}
	st.Source = SourceNFT // default for T0-shaped lines without source=
	for _, f := range strings.Fields(resp) {
		switch {
		case strings.HasPrefix(f, "packets="):
			st.Packets, _ = strconv.ParseUint(strings.TrimPrefix(f, "packets="), 10, 64)
		case strings.HasPrefix(f, "bytes="):
			st.Bytes, _ = strconv.ParseUint(strings.TrimPrefix(f, "bytes="), 10, 64)
		case strings.HasPrefix(f, "present="):
			v := strings.TrimPrefix(f, "present=")
			st.Present = v == "true" || v == "1"
		case strings.HasPrefix(f, "source="):
			st.Source = Source(strings.TrimPrefix(f, "source="))
		case strings.HasPrefix(f, "sightings="):
			st.Sightings, _ = strconv.ParseUint(strings.TrimPrefix(f, "sightings="), 10, 64)
		case strings.HasPrefix(f, "last_sni="):
			st.LastSNI = strings.TrimPrefix(f, "last_sni=")
		}
	}
	return st, nil
}
