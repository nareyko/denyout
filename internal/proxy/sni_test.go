package proxy

import "testing"

func TestParseSNI(t *testing.T) {
	if parseSNI(nil) != "" {
		t.Fatal("nil")
	}
	if parseSNI([]byte{0x16, 0x03}) != "" {
		t.Fatal("short")
	}
}
