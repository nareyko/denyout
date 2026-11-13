package policy

// Config is the in-memory denyout/v1 policy (subset needed for check stub).
type Config struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`
	Mode       string `yaml:"mode" json:"mode"`
	Preset     string `yaml:"preset" json:"preset"`
	Allow      []Rule `yaml:"allow" json:"allow"`
	Deny       []Rule `yaml:"deny" json:"deny"`
	Scanners   Scanners `yaml:"scanners" json:"scanners"`
	AllowPrivate     bool   `yaml:"allow_private" json:"allow_private"`
	AllowIPLiterals  bool   `yaml:"allow_ip_literals" json:"allow_ip_literals"`
	DenyOnDNSFailure *bool  `yaml:"deny_on_dns_failure" json:"deny_on_dns_failure"`
	InsecureAllowAll bool   `yaml:"insecure_allow_all" json:"insecure_allow_all"`
	AllowedPorts     []int  `yaml:"allowed_ports" json:"allowed_ports"`
	Limits           Limits `yaml:"limits" json:"limits"`
	Audit            Audit  `yaml:"audit" json:"audit"`
	TLS              TLS    `yaml:"tls" json:"tls"`
}

// Limits are optional RPM caps.
type Limits struct {
	PerHostRPM int `yaml:"per_host_rpm" json:"per_host_rpm"`
	GlobalRPM  int `yaml:"global_rpm" json:"global_rpm"`
}

// Audit sink settings.
type Audit struct {
	JSONLPath string `yaml:"jsonl_path" json:"jsonl_path"`
	Stdout    bool   `yaml:"stdout" json:"stdout"`
}

// TLS settings.
type TLS struct {
	Mode      string `yaml:"mode" json:"mode"` // intercept|passthrough
	SessionCA *bool  `yaml:"session_ca" json:"session_ca"`
}

// Rule is a host allow/deny entry.
type Rule struct {
	Host   string `yaml:"host" json:"host"`
	Reason string `yaml:"reason" json:"reason"`
}

// Scanners holds secret-detection settings.
type Scanners struct {
	HardSecretsInAuditMode *bool    `yaml:"hard_secrets_in_audit_mode" json:"hard_secrets_in_audit_mode"`
	MinValueLen            int      `yaml:"min_value_len" json:"min_value_len"`
	Canaries               []string `yaml:"canaries" json:"canaries"`
	NamedQuery             *struct {
		Enabled *bool `yaml:"enabled" json:"enabled"`
	} `yaml:"named_query" json:"named_query"`
	HighEntropy *struct {
		Enabled *bool `yaml:"enabled" json:"enabled"`
	} `yaml:"high_entropy" json:"high_entropy"`
}

// MinValueLenOrDefault returns scanner min value length.
func (c *Config) MinValueLenOrDefault() int {
	if c.Scanners.MinValueLen > 0 {
		return c.Scanners.MinValueLen
	}
	return 6
}

// NamedQueryEnabled reports whether named query scanning is on (default true).
func (c *Config) NamedQueryEnabled() bool {
	if c.Scanners.NamedQuery == nil || c.Scanners.NamedQuery.Enabled == nil {
		return true
	}
	return *c.Scanners.NamedQuery.Enabled
}
