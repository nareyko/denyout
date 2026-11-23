package proxy

import "time"

// SetIdleForTest shortens the intercept idle limits and returns a restore func.
func SetIdleForTest(request, body, upstream time.Duration) (restore func()) {
	r, b, u := clientRequestIdle, clientBodyIdle, upstreamIdle
	clientRequestIdle, clientBodyIdle, upstreamIdle = request, body, upstream
	return func() { clientRequestIdle, clientBodyIdle, upstreamIdle = r, b, u }
}

// HostHeaderMatchesForTest exposes the domain-fronting guard to table tests.
func HostHeaderMatchesForTest(hdr, host string) bool { return hostHeaderMatches(hdr, host) }
