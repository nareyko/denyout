package policy

// Stable reason codes (D04 / D05).
const (
	ReasonInvalidURL       = "invalid_url"
	ReasonUnsafeIP         = "unsafe_ip"
	ReasonHostNotAllowed   = "host_not_allowed"
	ReasonHostDenied       = "host_denied"
	ReasonPortNotAllowed   = "port_not_allowed"
	ReasonSecretInURL      = "secret_in_url"
	ReasonCanaryDetected   = "canary_detected"
	ReasonRateLimited      = "rate_limited"
	ReasonDNSFailure       = "dns_failure"
	ReasonInsecureAllowAll = "insecure_allow_all_used"
)
