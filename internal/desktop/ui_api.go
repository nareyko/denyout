package desktop

// DenialView is a UI-friendly denial row (secrets already redacted in URL).
type DenialView struct {
	ID            string   `json:"id"`
	TS            string   `json:"ts"`
	Host          string   `json:"host"`
	URL           string   `json:"url"`
	Why           string   `json:"why"`
	Reasons       []string `json:"reasons"`
	PrimaryReason string   `json:"primary_reason,omitempty"`
	Process       string   `json:"process"`
	Method        string   `json:"method,omitempty"`
	Detectors     []string `json:"detectors,omitempty"`
	PolicyProfile string   `json:"policy_profile,omitempty"`
	Remembered    bool     `json:"remembered"`
	// Explainable block (table: internal/explain).
	Title      string `json:"title,omitempty"`       // short heading
	Explain    string `json:"explain,omitempty"`     // what happened and why
	Rule       string `json:"rule,omitempty"`        // which rule fired
	Fix        string `json:"fix,omitempty"`         // safe next step
	AllowHelps bool   `json:"allow_helps,omitempty"` // allowing the site releases this block
}

// DenialQuery filters ListDenials.
type DenialQuery struct {
	Search     string `json:"search"`
	Reason     string `json:"reason"`
	Process    string `json:"process"`
	Remembered bool   `json:"remembered_only"`
	Limit      int    `json:"limit"`
}

// UISnapshot is top-bar / settings state for the Wails shell.
type UISnapshot struct {
	Version             string          `json:"version"`
	Status              string          `json:"status"`
	Mode                string          `json:"mode"` // safe | agents | off | session
	ModeLabel           string          `json:"mode_label"`
	ProtectionOn        bool            `json:"protection_on"`
	Notify              bool            `json:"notify"`
	NotifyLevel         string          `json:"notify_level"`
	DecisionTimeoutSec  int             `json:"decision_timeout_sec"`
	ReaskIntervalSec    int             `json:"reask_interval_sec"`
	ProtectPausedUntil  string          `json:"protect_paused_until,omitempty"`
	ProtectPauseLast    string          `json:"protect_pause_last,omitempty"`
	TimedAllows         []TimedRule     `json:"timed_allows"`
	TimedDenies         []TimedRule     `json:"timed_denies"`
	AskMode             bool            `json:"ask_mode"`
	PolicyProfile       string          `json:"policy_profile"`
	Autostart           bool            `json:"autostart"`
	AlwaysAllow         []string        `json:"always_allow"`
	RememberedKeeps     []string        `json:"remembered_keeps"`
	LastDenyHost        string          `json:"last_deny_host"`
	LastDenyURL         string          `json:"last_deny_url"`
	LastDenySummary     string          `json:"last_deny_summary"`
	LastDenyProcess     string          `json:"last_deny_process,omitempty"`
	BlockedToday        int             `json:"blocked_today"`
	YourSetupShown      bool            `json:"your_setup_shown"`
	SetupDone           bool            `json:"setup_done"`
	HelperOK            bool            `json:"helper_ok"`
	ProtectConfirmTitle string          `json:"protect_confirm_title,omitempty"`
	ProtectConfirmBody  string          `json:"protect_confirm_body,omitempty"`
	NewDenials          int             `json:"new_denials"`
	ControlURL          string          `json:"control_url,omitempty"`
	AuditPath           string          `json:"audit_path"`
	LogDir              string          `json:"log_dir"`
	DismissedTips       []string        `json:"dismissed_tips"`
	AskPaused           bool            `json:"ask_paused"`
	ProblemsAlert       bool            `json:"problems_alert"`
	YourSetupText       string          `json:"your_setup_text"`
	ChecklistDone       bool            `json:"checklist_done"`
	NeedsUXv2Migration  bool            `json:"needs_uxv2_migration"`
	AskPausedUntil      string          `json:"ask_paused_until,omitempty"`
	UpdateAvailable     bool            `json:"update_available"`
	UpdateVersion       string          `json:"update_version,omitempty"`
	UpdateURL           string          `json:"update_url,omitempty"`
	UpdateNotes         string          `json:"update_notes,omitempty"`
	AccountSignedIn     bool            `json:"account_signed_in"`
	AccountEmail        string          `json:"account_email,omitempty"`
	AccountTrustLine    string          `json:"account_trust_line,omitempty"`
	SyncEnabled         bool            `json:"sync_enabled"`
	ComputerAvailable   bool            `json:"computer_available"`
	AgentsRunning       int             `json:"agents_running"`
	ThreatListsWarn     bool            `json:"threat_lists_warn"` // lists on but missing/stale (not Protect failure)
	Notice              string          `json:"notice,omitempty"`  // one-shot in-app note (e.g. legacy Session cleared)
	QuietWhileAway      bool            `json:"quiet_while_away"`  // Stay quiet while locked/idle (default on)
	Away                bool            `json:"away"`              // currently treated as Away
	AwayUnread          int             `json:"away_unread"`       // suppressed prompts while Away
	AwayDigest          *AwayDigestView `json:"away_digest,omitempty"`
	NotifySnoozeUntil   string          `json:"notify_snooze_until,omitempty"` // RFC3339 if active
	NotifySnoozeActive  bool            `json:"notify_snooze_active"`
	QuietOvernight      bool            `json:"quiet_overnight"`
	SoundOnlyAnswer     bool            `json:"sound_only_answer"`
	SystemBanners       bool            `json:"system_banners"`
	RespectFullscreen   bool            `json:"respect_fullscreen"`
	BlockBrowserQUIC    bool            `json:"block_browser_quic"` // inverse of AllowBrowserQUIC; default on
	FailPolicy          FailPolicyView  `json:"fail_policy"`        // "If DenyOut's proxy stops" setting + effective policy
	TunDataplane        bool            `json:"tun_dataplane"`      // experimental UDP via denyout0 (Linux)
	QuicMITM            bool            `json:"quic_mitm"`          // experimental HTTP/3 MITM (Linux; needs TunDataplane)
	ExperimentalLinux   bool            `json:"experimental_linux"` // show Settings → Experimental (GOOS==linux)
	FullscreenDetect    bool            `json:"fullscreen_detect"`  // can see fullscreen apps right now
	FullscreenNow       bool            `json:"fullscreen_now"`     // active window fullscreen (only if detect)
	FullscreenWayland   bool            `json:"fullscreen_wayland"` // session looks Wayland (copy hint)
	SilentWhenOpen      bool            `json:"silent_when_open"`
	UndoOffer           *UndoOfferView  `json:"undo_offer,omitempty"`   // in-app Undo (no OS button)
	QuietReason         string          `json:"quiet_reason,omitempty"` // shared: Quiet · away · fullscreen · snoozed…
	Quieting            bool            `json:"quieting"`               // any quiet reason active
}

// AwayDigestView is the one-shot "Quiet items waiting" card (Away or fullscreen).
type AwayDigestView struct {
	Pending      bool     `json:"pending"`
	Blocks       int      `json:"blocks"`        // auto-kept / keep-repeat while Away
	Waiting      int      `json:"waiting"`       // hard-block Decide later while Away
	Hosts        []string `json:"hosts"`         // block hosts only
	WaitingHosts []string `json:"waiting_hosts"` // waiting-decision hosts
}

// ProblemsView is the Problems screen payload.
type ProblemsView struct {
	LastError           string `json:"last_error"`
	LastDenyHost        string `json:"last_deny_host"`
	LastDenyURL         string `json:"last_deny_url"`
	LastDenySummary     string `json:"last_deny_summary"`
	ControlOK           bool   `json:"control_ok"`
	ProxydRunning       bool   `json:"proxyd_running"`
	SessionRunning      bool   `json:"session_running"`
	CAPresent           bool   `json:"ca_present"`
	ClipboardOK         bool   `json:"clipboard_ok"`
	HelperOK            bool   `json:"helper_ok"`
	ProtectionOn        bool   `json:"protection_on"`
	Unhealthy           bool   `json:"unhealthy"`         // Protect intended on but broken
	ThreatListsWarn     bool   `json:"threat_lists_warn"` // enabled lists missing/stale (not Protect failure)
	LogDir              string `json:"log_dir"`
	AuditPath           string `json:"audit_path"`
	Status              string `json:"status"`
	Mode                string `json:"mode"` // safe | agents | off | session (live)
	ModeLabel           string `json:"mode_label"`
	PolicyProfile       string `json:"policy_profile"`
	ProtectConfirmTitle string `json:"protect_confirm_title,omitempty"`
	ProtectConfirmBody  string `json:"protect_confirm_body,omitempty"`
	ProtectPausedUntil  string `json:"protect_paused_until,omitempty"`
	ProtectPauseLast    string `json:"protect_pause_last,omitempty"`
	AgentsRunning       int    `json:"agents_running,omitempty"`
	ComputerAvailable   bool   `json:"computer_available"`
	UpdateAvailable     bool   `json:"update_available"`
	UpdateVersion       string `json:"update_version,omitempty"`
	UpdateURL           string `json:"update_url,omitempty"`
}

// ProfileView is a profile row for the Profiles screen.
type ProfileView struct {
	AgentProfile
	Running bool `json:"running"`
	PID     int  `json:"pid,omitempty"`
}
