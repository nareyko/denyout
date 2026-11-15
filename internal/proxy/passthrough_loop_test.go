package proxy

import (
	"testing"
)

// Closed-loop: with global intercept + CA present, Cursor hosts still select passthrough.
func TestUseTLSPassthroughCursorUnderIntercept(t *testing.T) {
	s := &Server{cfg: Config{
		TLSMode: TLSIntercept,
		CA:      &SessionCA{}, // non-nil so global mode is not forced passthrough
	}}
	if !s.useTLSPassthrough("api2.cursor.sh") {
		t.Fatal("api2.cursor.sh must passthrough under intercept")
	}
	if !s.useTLSPassthrough("api2direct.cursor.sh") {
		t.Fatal("api2direct.cursor.sh must passthrough")
	}
	if s.useTLSPassthrough("chat.google.com") {
		t.Fatal("google must stay on MITM path")
	}
	if s.useTLSPassthrough("example.com") {
		t.Fatal("example.com must stay on MITM path")
	}

	s.cfg.TLSMode = TLSPassthrough
	if !s.useTLSPassthrough("example.com") {
		t.Fatal("global passthrough mode")
	}
}
