/** Human labels for stable deny / keep reason codes (History, Settings silenced). */
export function humanReasonLabel(code: string): string {
  switch (code) {
    case "secret_in_url":
      return "secret in link";
    case "secret_in_header":
      return "secret in header";
    case "secret_in_body":
      return "secret in body";
    case "canary_detected":
      return "canary";
    case "threat_phishing":
      return "phishing list";
    case "threat_malware":
      return "malware list";
    case "threat_ads":
      return "ads / trackers list";
    case "threat_list":
      return "threat list";
    case "host_denied":
      return "host denied";
    case "unsafe_ip":
      return "unsafe IP";
    case "ip_literal":
      return "raw IP";
    case "host_not_allowed":
      return "not on allowlist";
    default:
      return code || "blocked";
  }
}
