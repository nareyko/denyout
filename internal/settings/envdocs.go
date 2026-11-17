package settings

// EnvDoc documents an environment variable that is not a user setting
// (install, test, lab and plumbing variables). Settings-backed variables are
// documented through Specs.
type EnvDoc struct {
	Name   string
	Scope  string // where it is read
	Doc    string
	Danger string // security note; empty when none
}

// OtherEnv lists the remaining DENYOUT_* variables. A test keeps this list and
// docs/configuration.md in sync with the source tree.
var OtherEnv = []EnvDoc{
	{"DENYOUT_NOTIFY", "denyout-cli run", "Set to 0 to suppress CLI notifications.", ""},
	{"DENYOUT_DESKTOP_NOTIFY", "denyout-cli run", "Set to 1 to also raise desktop notifications.", ""},
	{"DENYOUT_OPEN_UI", "desktop", "Set to 1 to open the window at start.", ""},
	{"DENYOUT_DETACHED", "desktop", "Internal marker: the process re-executed itself detached.", ""},
	{"DENYOUT_TUN_E2E", "tun gate", "Enables the experimental TUN data plane (see tun_dataplane).", "Experimental."},
	{"DENYOUT_QUIC_MITM", "tun gate", "Enables experimental HTTP/3 decryption (see quic_mitm).", "Experimental."},
	{"DENYOUT_VPN_EGRESS_E2E", "tun gate", "Enables the VPN-egress end-to-end lab path.", "Lab only."},
	{"DENYOUT_TEST_NO_ELEVATE", "hostguard", "Tests: never prompt for elevation.", "Tests only."},
	{"DENYOUT_UNINSTALL_NO_ELEVATE", "uninstall", "Skip the elevated uninstall step.", ""},
	{"DENYOUT_INSTALL_DIR", "desktop reinstall, install.sh", "Override the install directory.", ""},
	{"DENYOUT_VERIFY_SIG", "install.sh", "auto | require | skip signature verification.", "skip disables cosign verification."},
	{"DENYOUT_BASE_URL", "install.sh", "Override the release base URL (validated).", "Must be https."},
	{"DENYOUT_VERSION", "install.sh", "Pin a release tag (validated).", ""},
	{"DENYOUT_INSTALL_MODE", "install.sh", "Install mode selector.", ""},
	{"DENYOUT_REPO", "install.sh", "Override the GitHub repo slug.", ""},
	{"DENYOUT_NO_DESKTOP", "install.sh", "Skip installing the desktop app.", ""},
	{"DENYOUT_INSTALL_PROMPT", "install.sh", "Control the install prompt.", ""},
	{"DENYOUT_INSTALL_OPEN", "install.sh", "Open the app after install.", ""},
	{"DENYOUT_BIN", "scripts/tests", "Path of the binary under test.", "Tests only."},
	{"DENYOUT_G6LAB_BIN", "scripts/tests", "Path of the g6lab binary.", "Lab only."},
	{"DENYOUT_LAB_IP", "denyout-g6lab", "Lab origin address.", "Lab only."},
	{"DENYOUT_DOGFOOD_IMAGE", "scripts", "Docker image for dogfood runs.", "Lab only."},
	{"DENYOUT_E2E", "scripts/tests", "Enable end-to-end test paths.", "Tests only."},
	{"DENYOUT_E2E_SKIP_ELEVATE", "scripts/tests", "Skip elevation in e2e.", "Tests only."},
	{"DENYOUT_FETCH_RETRIES", "scripts/tests", "Lab fetch retry count.", "Lab only."},
	{"DENYOUT_FETCH_RETRY_SECS", "scripts/tests", "Lab fetch retry delay.", "Lab only."},
	{"DENYOUT_ALLOW_INSECURE_OVERRIDE", "scripts/tests", "Lab-only override of safety checks.", "Lab only; never set in production."},
	{"DENYOUT_CA_CERT", "desktop session env file", "Output: path of the session CA written to the env file for child tools (not read back).", ""},
	{"DENYOUT_PROXY", "lab scripts", "Proxy URL used by lab clients.", "Lab only."},
	{"DENYOUT_CACERT", "lab scripts", "CA bundle used by lab clients.", "Lab only."},
	{"DENYOUT_SNI", "lab scripts", "SNI used by lab clients.", "Lab only."},
	{"DENYOUT_SESSION_ID", "lab scripts", "Session id used in lab output.", "Lab only."},
	{"DENYOUT_CONFIG", "lab scripts", "Config path used in lab scripts.", "Lab only."},
	{"DENYOUT_MODE", "lab scripts", "Mode used in lab scripts.", "Lab only."},
	{"DENYOUT_TLS_MODE", "lab scripts", "TLS mode used in lab scripts.", "Lab only."},
	{"DENYOUT_LISTEN_PORT", "lab scripts", "Listen port used in lab scripts.", "Lab only."},
	{"DENYOUT_PROFILE_ID", "lab scripts", "Profile id used in lab scripts.", "Lab only."},
}
