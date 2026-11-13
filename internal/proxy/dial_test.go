package proxy

import (
	"net"
	"testing"
)

func TestSafeDialIPRejectsUnsafe(t *testing.T) {
	_, err := safeDialIP("meta", []net.IP{net.ParseIP("169.254.169.254")}, false)
	if err != errUnsafeIP {
		t.Fatalf("err=%v", err)
	}
}

func TestSafeDialIPRejectsEmpty(t *testing.T) {
	_, err := safeDialIP("invalid.invalid.denyout.test.", nil, false)
	if err != errDNSFailure {
		t.Fatalf("err=%v", err)
	}
}

func TestSafeDialIPPrefersIPv4(t *testing.T) {
	ip, err := safeDialIP("h", []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("203.0.113.9"),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "203.0.113.9" {
		t.Fatalf("got %s", ip)
	}
}
