package threatlists

// Category groups Book C subscriptions for Settings toggles.
type Category string

const (
	CategoryPhishing  Category = "phishing"
	CategoryMalware   Category = "malware"
	CategoryTelemetry Category = "telemetry"
)

// Format is the on-wire list format.
type Format string

const (
	FormatDomains Format = "domains" // one domain per line
	FormatHosts   Format = "hosts"   // hosts file (IP domain)
	FormatABP     Format = "abp"     // simple ||domain^ lines
)

// Subscription describes one Book C feed in the product catalog.
type Subscription struct {
	ID                 string
	URL                string
	Category           Category
	Format             Format
	Enabled            bool // catalog default; user may override later
	ActiveAfterFirstOK bool // e.g. URLhaus: not active in policy until first good fetch
	PollHours          int  // 0 → use Store default
	LicenseURL         string
	Homepage           string
}

const (
	IDPhishingArmy    = "phishing-army"
	IDURLHaus         = "urlhaus-hosts"
	IDHageziTIFMedium = "hagezi-tif-medium"
	IDOISDSmall       = "oisd-small"
	IDOISDBig         = "oisd-big"
	IDStevenBlack     = "stevenblack-unified"
)

// DefaultPollHours is the locked default refresh interval.
const DefaultPollHours = 24

// MinPollHours / MaxPollHours bound Settings.
const (
	MinPollHours = 6
	MaxPollHours = 168
)

// CoreCatalog is day-1 Book C (Phishing + Malware + optional Stronger).
// Advanced OISD/StevenBlack live in AdvancedCatalog (L7).
func CoreCatalog() []Subscription {
	return []Subscription{
		{
			ID:         IDPhishingArmy,
			URL:        "https://phishing.army/download/phishing-army-domains.txt",
			Category:   CategoryPhishing,
			Format:     FormatDomains,
			Enabled:    true,
			LicenseURL: "https://phishing.army/",
			Homepage:   "https://phishing.army/",
		},
		{
			ID:                 IDURLHaus,
			URL:                "https://urlhaus.abuse.ch/downloads/hostfile/",
			Category:           CategoryMalware,
			Format:             FormatHosts,
			Enabled:            true,
			ActiveAfterFirstOK: true,
			LicenseURL:         "https://urlhaus.abuse.ch/",
			Homepage:           "https://urlhaus.abuse.ch/",
		},
		{
			ID:         IDHageziTIFMedium,
			URL:        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.medium.txt",
			Category:   CategoryMalware,
			Format:     FormatDomains,
			Enabled:    false, // Stronger — opt-in (L5 UI)
			LicenseURL: "https://github.com/hagezi/dns-blocklists",
			Homepage:   "https://github.com/hagezi/dns-blocklists",
		},
	}
}

// AdvancedCatalog is optional broader lists (default off). Wired in L7 Settings.
func AdvancedCatalog() []Subscription {
	return []Subscription{
		{
			ID:         IDOISDSmall,
			URL:        "https://small.oisd.nl/domainswild",
			Category:   CategoryTelemetry, // closest bucket; UI labels as ads/trackers job
			Format:     FormatDomains,
			Enabled:    false,
			LicenseURL: "https://oisd.nl/",
			Homepage:   "https://oisd.nl/",
		},
		{
			ID:         IDOISDBig,
			URL:        "https://big.oisd.nl/domainswild",
			Category:   CategoryTelemetry,
			Format:     FormatDomains,
			Enabled:    false,
			LicenseURL: "https://oisd.nl/",
			Homepage:   "https://oisd.nl/",
		},
		{
			ID:         IDStevenBlack,
			URL:        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			Category:   CategoryTelemetry,
			Format:     FormatHosts,
			Enabled:    false,
			LicenseURL: "https://github.com/StevenBlack/hosts",
			Homepage:   "https://github.com/StevenBlack/hosts",
		},
	}
}

// CatalogByID returns a subscription from core+advanced, or false.
func CatalogByID(id string) (Subscription, bool) {
	for _, s := range CoreCatalog() {
		if s.ID == id {
			return s, true
		}
	}
	for _, s := range AdvancedCatalog() {
		if s.ID == id {
			return s, true
		}
	}
	return Subscription{}, false
}

// ClampPollHours enforces Settings bounds.
func ClampPollHours(h int) int {
	if h <= 0 {
		return DefaultPollHours
	}
	if h < MinPollHours {
		return MinPollHours
	}
	if h > MaxPollHours {
		return MaxPollHours
	}
	return h
}
