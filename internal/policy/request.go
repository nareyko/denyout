package policy

import "net"

// RequestView is the policy input (D03/D04). Socket-free when DestIPs pre-filled or Resolve=false.
type RequestView struct {
	SessionID   string
	DestHost    string
	DestPort    uint16
	DestIPs     []net.IP
	Protocol    string // http|https|tcp
	ServerName  string
	Method      string
	Path        string
	RawQuery    string
	RawURL      string // full URL when known (check / L2)
	Inspection  string // passthrough|intercept|cleartext
	Headers     map[string][]string
	BodyPrefix  []byte
}
