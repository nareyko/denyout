package policy

// Stable reason codes (D04 / D05).
const (
	ReasonInvalidURL       = "invalid_url"
	ReasonUnsafeIP         = "unsafe_ip"
	ReasonIPLiteral        = "ip_literal" // raw IP while allow_ip_literals=false (agents)
	ReasonHostNotAllowed   = "host_not_allowed"
	ReasonHostDenied       = "host_denied"
	ReasonThreatList       = "threat_list"     // legacy umbrella Book C hit
	ReasonThreatPhishing   = "threat_phishing" // Book C phishing feed
	ReasonThreatMalware    = "threat_malware"  // Book C malware feed
	ReasonThreatAds        = "threat_ads"      // Book C ads/trackers feed
	ReasonPortNotAllowed   = "port_not_allowed"
	ReasonSecretInURL      = "secret_in_url"
	ReasonCanaryDetected   = "canary_detected"
	ReasonRateLimited      = "rate_limited"
	ReasonDNSFailure       = "dns_failure"
	ReasonInsecureAllowAll = "insecure_allow_all_used"
)
