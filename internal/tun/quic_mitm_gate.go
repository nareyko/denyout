package tun

import "os"

// EnvQUICMITM opts into experimental HTTP/3 MITM (never default Protect).
const EnvQUICMITM = "DENYOUT_QUIC_MITM"

// WantQUICMITM reports whether QUIC terminate+reencrypt may run.
// Requires WantDevice()/TunDataplane path in the product; this flag is the second gate.
func WantQUICMITM() bool {
	return os.Getenv(EnvQUICMITM) == "1"
}
