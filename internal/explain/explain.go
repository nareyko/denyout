// Package explain is the single table that turns internal deny reason codes
// into plain-language explanations for the desktop UI, notifications and
// diagnostics. Add new reason codes here (a test fails when one is missing).
package explain

import (
	"sort"
	"strings"
)

// Entry explains one reason code.
type Entry struct {
	Code string
	// Short is the one-sentence summary used by toasts and History rows.
	Short string
	// Title is a 2-4 word heading for the detail view.
	Title string
	// Detail says what happened and why it matters.
	Detail string
	// Rule names the rule family that fired.
	Rule string
	// Fix is the safe next step for the user.
	Fix string
	// AllowHelps is true when allowing the site releases this kind of block.
	// It is false for blocks about the request content (secrets) or the
	// destination address, which a per-site allow does not change.
	AllowHelps bool
}

const secretFix = " Allowing the site does not release this block."

var table = []Entry{
	{
		Code:       "host_not_allowed",
		Short:      "That site is not on your allowed list.",
		Title:      "Not on your allowed list",
		Detail:     "This site is not on your allowlist, and the current policy blocks anything that is not listed.",
		Rule:       "Allowlist (default deny)",
		Fix:        "Allow it only if you recognise the site and expect your agent or app to use it.",
		AllowHelps: true,
	},
	{
		Code:       "host_denied",
		Short:      "This site is on your deny list.",
		Title:      "On your deny list",
		Detail:     "You or a preset marked this site as blocked.",
		Rule:       "Deny list",
		Fix:        "Allow it only if you added it by mistake.",
		AllowHelps: true,
	},
	{
		Code:       "threat_phishing",
		Short:      "This site is on a known phishing list.",
		Title:      "Known phishing site",
		Detail:     "The site appears on a public phishing feed. Pages like this try to steal passwords or payment details.",
		Rule:       "Threat list: phishing",
		Fix:        "Keep it blocked unless you are sure the list is wrong.",
		AllowHelps: true,
	},
	{
		Code:       "threat_malware",
		Short:      "This site is on a known malware list.",
		Title:      "Known malware site",
		Detail:     "The site appears on a public malware feed. It is known to serve harmful software.",
		Rule:       "Threat list: malware",
		Fix:        "Keep it blocked unless you are sure the list is wrong.",
		AllowHelps: true,
	},
	{
		Code:       "threat_ads",
		Short:      "This site is on an ads or trackers list.",
		Title:      "Ads or tracker site",
		Detail:     "The site appears on an ads and trackers feed. Blocking it is usually harmless but can break some pages.",
		Rule:       "Threat list: ads and trackers",
		Fix:        "Allow it if a page you need stops working.",
		AllowHelps: true,
	},
	{
		Code:       "threat_list",
		Short:      "This site is on a known phishing or malware list.",
		Title:      "Known threat site",
		Detail:     "The site appears on a public threat feed (older log entries do not say which one).",
		Rule:       "Threat list",
		Fix:        "Keep it blocked unless you are sure the list is wrong.",
		AllowHelps: true,
	},
	{
		Code:       "secret_in_url",
		Short:      "Blocked a link that looked like it contained a secret.",
		Title:      "Secret in the link",
		Detail:     "The address contains something shaped like a token, key or password. Sending it could leak it to the site.",
		Rule:       "Secret scanner (URL)",
		Fix:        "Keep it blocked and check which tool built the link." + secretFix,
		AllowHelps: false,
	},
	{
		Code:       "secret_in_header",
		Short:      "Blocked a link that looked like it contained a secret.",
		Title:      "Secret in a header",
		Detail:     "A request header carries something shaped like a token, key or password to a site that is not trusted with it.",
		Rule:       "Secret scanner (headers)",
		Fix:        "Keep it blocked and check which tool added the header." + secretFix,
		AllowHelps: false,
	},
	{
		Code:       "secret_in_body",
		Short:      "Blocked a link that looked like it contained a secret.",
		Title:      "Secret in the request body",
		Detail:     "The data being sent contains something shaped like a token, key or password.",
		Rule:       "Secret scanner (body)",
		Fix:        "Keep it blocked and check what the tool was uploading." + secretFix,
		AllowHelps: false,
	},
	{
		Code:       "canary_detected",
		Short:      "A canary/test secret was found in the request.",
		Title:      "Canary value sent",
		Detail:     "A planted decoy secret was about to leave this computer. That is a strong sign something is reading files it should not.",
		Rule:       "Canary detector",
		Fix:        "Keep it blocked and find out which program sent it.",
		AllowHelps: false,
	},
	{
		Code:       "unsafe_ip",
		Short:      "The destination looked like a private or metadata address.",
		Title:      "Private or metadata address",
		Detail:     "The destination resolves to a private network, loopback or cloud metadata address. Agents are often tricked into reaching these.",
		Rule:       "Unsafe address guard",
		Fix:        "Keep it blocked unless you run that service yourself.",
		AllowHelps: false,
	},
	{
		Code:       "ip_literal",
		Short:      "Blocked a raw IP address (not allowed in this mode).",
		Title:      "Raw IP address",
		Detail:     "The request went to a bare IP address instead of a site name. This mode does not allow that.",
		Rule:       "No raw IPs rule",
		Fix:        "Use the site name instead, or switch mode if you need raw IPs.",
		AllowHelps: false,
	},
	{
		Code:       "port_not_allowed",
		Short:      "That network port is not allowed.",
		Title:      "Port not allowed",
		Detail:     "The request used a network port that is not on the allowed ports list.",
		Rule:       "Allowed ports",
		Fix:        "Add the port in your policy if the traffic is expected.",
		AllowHelps: false,
	},
	{
		Code:       "rate_limited",
		Short:      "Too many requests in a short time.",
		Title:      "Too many requests",
		Detail:     "The request rate went over the limit, which can mean a runaway loop or a data dump.",
		Rule:       "Rate limit",
		Fix:        "Wait a moment. Raise the limit in your policy if the volume is expected.",
		AllowHelps: false,
	},
	{
		Code:       "invalid_url",
		Short:      "The request address could not be understood.",
		Title:      "Malformed address",
		Detail:     "The address was malformed or used an unsupported form, so DenyOut could not tell where it was going.",
		Rule:       "URL validation",
		Fix:        "Keep it blocked and check the tool that built the address.",
		AllowHelps: false,
	},
	{
		Code:       "dns_failure",
		Short:      "The site name could not be looked up.",
		Title:      "Name lookup failed",
		Detail:     "DenyOut could not resolve the site name, so it could not check where the request would go.",
		Rule:       "DNS safety check",
		Fix:        "Check your network connection and try again.",
		AllowHelps: false,
	},
	{
		Code:       "upstream_unsafe_ip",
		Short:      "The site resolved to a private or metadata address, so DenyOut did not connect.",
		Title:      "Unsafe upstream address",
		Detail:     "The site name resolved to a private network, loopback or cloud metadata address at connect time, so the connection was refused.",
		Rule:       "Unsafe address guard",
		Fix:        "Keep it blocked unless you run that service yourself.",
		AllowHelps: false,
	},
	{
		Code:       "upstream_dial_failed",
		Short:      "DenyOut could not connect to the site.",
		Title:      "Could not connect",
		Detail:     "The request was allowed, but the connection to the site failed or timed out.",
		Rule:       "Upstream connection",
		Fix:        "Check your network connection and that the site is up, then try again.",
		AllowHelps: false,
	},
	{
		Code:       "upstream_write_failed",
		Short:      "The connection to the site broke while sending the request.",
		Title:      "Send to site failed",
		Detail:     "The request was allowed, but the connection to the site closed before DenyOut could send it.",
		Rule:       "Upstream connection",
		Fix:        "Try again. If it keeps failing, check your network connection.",
		AllowHelps: false,
	},
	{
		Code:       "insecure_allow_all_used",
		Short:      "The allow-everything setting let this request through.",
		Title:      "Allow-all was used",
		Detail:     "The policy is set to allow everything, so nothing is being filtered for this request.",
		Rule:       "Insecure allow-all setting",
		Fix:        "Turn the allow-all setting off in your policy.",
		AllowHelps: false,
	},
}

var byCode = func() map[string]Entry {
	m := make(map[string]Entry, len(table))
	for _, e := range table {
		m[e.Code] = e
	}
	return m
}()

// Lookup returns the entry for code.
func Lookup(code string) (Entry, bool) {
	e, ok := byCode[strings.TrimSpace(code)]
	return e, ok
}

// Describe returns the entry for code, or a generic one for unknown codes.
// Unknown codes never offer allow-by-site: the UI cannot know what it would do.
func Describe(code string) Entry {
	code = strings.TrimSpace(code)
	if e, ok := byCode[code]; ok {
		return e
	}
	short := "Your agent tried to reach something outside the allowlist."
	title := "Blocked"
	if code != "" {
		short = code
		title = "Blocked (" + code + ")"
	}
	return Entry{
		Code:   code,
		Short:  short,
		Title:  title,
		Detail: "DenyOut blocked this request. The reason code is not one this version can explain in plain words.",
		Rule:   "Policy",
		Fix:    "Open the technical details or run denyout-cli doctor to see more.",
	}
}

// Short joins the short summaries for reasons (unknown codes pass through).
func Short(reasons []string) string {
	if len(reasons) == 0 {
		return "Your agent tried to reach something outside the allowlist."
	}
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if e, ok := byCode[r]; ok {
			parts = append(parts, e.Short)
		} else {
			parts = append(parts, r)
		}
	}
	return strings.Join(parts, " ")
}

// RuleLabel names the rule that fired for a denial. Detector ids (never
// matched values) are appended for secret blocks so users see which scanner hit.
func RuleLabel(primary string, detectors []string) string {
	e := Describe(primary)
	secretLike := strings.HasPrefix(primary, "secret_") || primary == "canary_detected"
	if len(detectors) == 0 || !secretLike {
		return e.Rule
	}
	ids := append([]string(nil), detectors...)
	sort.Strings(ids)
	return e.Rule + ": " + strings.Join(ids, ", ")
}

// Codes lists every explained reason code.
func Codes() []string {
	out := make([]string, 0, len(table))
	for _, e := range table {
		out = append(out, e.Code)
	}
	sort.Strings(out)
	return out
}
