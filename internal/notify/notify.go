package notify

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gen2brain/beeep"
)

var (
	mu                sync.Mutex
	enabled           = true
	level             = "quiet"  // quiet | normal | detailed — new installs default Quiet
	uiFocused         bool       // main window focused/visible
	away              bool       // screen locked / idle
	snoozeUntil       time.Time  // zero = not snoozed
	bannersAllowed    = true     // master: Allow system banners (protect_failed still passes when off)
	silentWhenOpen    = true     // If DenyOut is open, stay silent in the system
	respectFullscreen = true     // Respect fullscreen / games
	fullscreen        bool       // runtime: currently fullscreen (Phase E detector wires this)
	quietOvernight    = true     // No sound at night (sound gate; Emit banners unchanged)
	soundOnlyAnswer   = true     // Sound only when you must answer
	nowFunc           = time.Now // overridable in tests (night window)
)

// Kind is an OS-toast category. Only whitelisted kinds may reach the desktop.
type Kind string

const (
	// KindKeepRepeat is retained for call sites / future tray counts but must NEVER
	// reach the OS (lock-screen flood). Prefer History + tray.
	KindKeepRepeat     Kind = "keep_repeat"
	KindAllowUndo      Kind = "allow_undo"
	KindProtectResumed Kind = "protect_resumed"
	KindProtectFailed  Kind = "protect_failed"
	// KindOpenApp is a soft "Open DenyOut" nudge (return digest / missed waiting).
	// Quiet suppresses it; never while Away or while the UI is focused.
	KindOpenApp Kind = "open_app"
	// KindTrayHidden is the one-shot "window closed → still in tray" hint.
	// Allowed even on Quiet / banners-off / focused so close≠Quit is never silent.
	KindTrayHidden Kind = "tray_hidden"
)

// AllowedKind reports whether kind may emit an OS notification.
func AllowedKind(kind Kind) bool {
	switch kind {
	case KindAllowUndo, KindProtectResumed, KindProtectFailed, KindOpenApp, KindTrayHidden:
		return true
	default:
		// keep_repeat and unknowns stay off the OS whitelist
		return false
	}
}

// SetUIFocused suppresses non-critical OS toasts while the DenyOut window is focused
// (when SilentWhenOpen is on). Protect-failed still gets through.
func SetUIFocused(on bool) {
	mu.Lock()
	uiFocused = on
	mu.Unlock()
}

// UIFocused reports whether the main UI is focused (tests / diagnostics).
func UIFocused() bool {
	mu.Lock()
	defer mu.Unlock()
	return uiFocused
}

// SetAway suppresses non-critical OS toasts while the user is away (locked / idle).
func SetAway(on bool) {
	mu.Lock()
	away = on
	mu.Unlock()
}

// Away reports the Away suppress flag (tests / diagnostics).
func Away() bool {
	mu.Lock()
	defer mu.Unlock()
	return away
}

// SetSnoozeUntil mutes non-critical OS toasts until t (zero clears).
func SetSnoozeUntil(t time.Time) {
	mu.Lock()
	snoozeUntil = t
	mu.Unlock()
}

// Snoozed reports whether a snooze window is active.
func Snoozed() bool {
	mu.Lock()
	defer mu.Unlock()
	return !snoozeUntil.IsZero() && time.Now().Before(snoozeUntil)
}

// SnoozeUntil returns the snooze end time (zero if none).
func SnoozeUntil() time.Time {
	mu.Lock()
	defer mu.Unlock()
	return snoozeUntil
}

// SetBannersAllowed is the Advanced "Allow system banners" master.
// When off, only protect_failed and tray_hidden may still reach the OS.
func SetBannersAllowed(on bool) {
	mu.Lock()
	bannersAllowed = on
	mu.Unlock()
}

// BannersAllowed reports the banners master switch.
func BannersAllowed() bool {
	mu.Lock()
	defer mu.Unlock()
	return bannersAllowed
}

// SetSilentWhenOpen toggles "If DenyOut is open, stay silent in the system".
func SetSilentWhenOpen(on bool) {
	mu.Lock()
	silentWhenOpen = on
	mu.Unlock()
}

// SilentWhenOpen reports the silent-when-open preference.
func SilentWhenOpen() bool {
	mu.Lock()
	defer mu.Unlock()
	return silentWhenOpen
}

// SetRespectFullscreen toggles "Respect fullscreen / games".
func SetRespectFullscreen(on bool) {
	mu.Lock()
	respectFullscreen = on
	mu.Unlock()
}

// RespectFullscreen reports the preference.
func RespectFullscreen() bool {
	mu.Lock()
	defer mu.Unlock()
	return respectFullscreen
}

// SetFullscreen marks whether a fullscreen/game session is active (detector in Phase E).
func SetFullscreen(on bool) {
	mu.Lock()
	fullscreen = on
	mu.Unlock()
}

// Fullscreen reports the runtime fullscreen flag.
func Fullscreen() bool {
	mu.Lock()
	defer mu.Unlock()
	return fullscreen
}

// SetQuietOvernight toggles night sound suppression preference (sound gate).
func SetQuietOvernight(on bool) {
	mu.Lock()
	quietOvernight = on
	mu.Unlock()
}

// QuietOvernight reports the preference.
func QuietOvernight() bool {
	mu.Lock()
	defer mu.Unlock()
	return quietOvernight
}

// SetSoundOnlyWhenAnswer toggles "Sound only when you must answer".
func SetSoundOnlyWhenAnswer(on bool) {
	mu.Lock()
	soundOnlyAnswer = on
	mu.Unlock()
}

// SoundOnlyWhenAnswer reports the preference.
func SoundOnlyWhenAnswer() bool {
	mu.Lock()
	defer mu.Unlock()
	return soundOnlyAnswer
}

// SetNowFunc overrides the clock used for night-window checks (tests). Pass nil to reset.
func SetNowFunc(f func() time.Time) {
	mu.Lock()
	defer mu.Unlock()
	if f == nil {
		nowFunc = time.Now
		return
	}
	nowFunc = f
}

// SoundAllowed reports whether an OS sound may play (night + answer-only prefs).
// Banner visibility (Emit) is separate — night only mutes sound.
func SoundAllowed(mustAnswer bool) bool {
	mu.Lock()
	qo := quietOvernight
	soa := soundOnlyAnswer
	now := nowFunc
	mu.Unlock()
	if soa && !mustAnswer {
		return false
	}
	if qo && inNightWindow(now()) {
		return false
	}
	return true
}

// KindWantsSound reports whether this OS kind is treated as "must answer" for sound.
func KindWantsSound(kind Kind) bool {
	return kind == KindProtectFailed
}

// ExpireFor returns how long an OS banner of this kind should live.
// Zero means sticky / long-lived (Protect failed).
func ExpireFor(kind Kind) time.Duration {
	switch kind {
	case KindProtectFailed:
		return 0
	case KindAllowUndo:
		return 10 * time.Second
	case KindOpenApp:
		return 12 * time.Second
	case KindTrayHidden:
		return 8 * time.Second
	case KindProtectResumed:
		return 5 * time.Second
	default:
		return 8 * time.Second
	}
}

// Night window: 22:00–08:00 local (wave Findings).
func inNightWindow(now time.Time) bool {
	h := now.Hour()
	return h >= 22 || h < 8
}

// InNightWindow reports whether local time is in the quiet-overnight window.
func InNightWindow() bool {
	mu.Lock()
	now := nowFunc
	mu.Unlock()
	return inNightWindow(now())
}

// SetEnabled turns OS notifications on or off (desktop preference).
// When off, maps to Quiet behavior for Emit filtering.
func SetEnabled(on bool) {
	mu.Lock()
	enabled = on
	if !on && level == "normal" {
		level = "quiet"
	}
	if on && level == "quiet" {
		level = "normal"
	}
	mu.Unlock()
}

// SetLevel sets Quiet / Normal / Detailed (case-insensitive).
func SetLevel(s string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quiet":
		level = "quiet"
		enabled = true // dialogs still on; OS filtered
	case "detailed":
		level = "detailed"
		enabled = true
	default:
		level = "normal"
		enabled = true
	}
}

// Level returns the current notification level.
func Level() string {
	mu.Lock()
	defer mu.Unlock()
	return level
}

// Enabled reports whether notifications are on (legacy bool; Quiet still "enabled").
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled && level != "quiet"
}

func levelAllows(kind Kind) bool {
	if !AllowedKind(kind) {
		return false
	}
	switch level {
	case "quiet":
		return kind == KindProtectFailed || kind == KindTrayHidden
	case "normal":
		// Protect-resumed OS banner is Detailed-only so the level is not a no-op vs Normal.
		return kind != KindProtectResumed
	default: // detailed
		return true
	}
}

// emitAllowedLocked requires mu held. Returns ok and suppress reason when !ok.
func emitAllowedLocked(kind Kind) (ok bool, reason string) {
	if !AllowedKind(kind) {
		return false, "kind_not_allowed"
	}
	if !levelAllows(kind) {
		if level == "quiet" {
			return false, "quiet"
		}
		return false, "level"
	}
	critical := kind == KindProtectFailed
	trayHint := kind == KindTrayHidden
	if !bannersAllowed && !critical && !trayHint {
		return false, "banners_off"
	}
	if !snoozeUntil.IsZero() && time.Now().Before(snoozeUntil) && !critical && !trayHint {
		return false, "snooze"
	}
	focusSuppress := uiFocused && silentWhenOpen
	fsSuppress := fullscreen && respectFullscreen
	if focusSuppress && !critical && !trayHint {
		return false, "ui_focused"
	}
	if away && !critical && !trayHint {
		return false, "away"
	}
	if fsSuppress && !critical && !trayHint {
		return false, "fullscreen"
	}
	return true, ""
}

func emitAllowed(kind Kind) bool {
	ok, _ := emitAllowedLocked(kind)
	return ok
}

// Emit shows an OS notification only for a whitelisted kind (and when level allows).
func Emit(kind Kind, title, body string) {
	mu.Lock()
	ok, reason := emitAllowedLocked(kind)
	lvl, isAway, focused, fs := level, away, uiFocused, fullscreen
	snoozed := !snoozeUntil.IsZero() && time.Now().Before(snoozeUntil)
	mu.Unlock()
	if title == "" {
		title = "DenyOut"
	}
	logAttempt(kind, title, body, ok, reason, lvl, isAway, focused, fs, snoozed)
	if !ok {
		return
	}
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("notify-send"); err == nil {
			runNotifySendPlain(kind, title, body)
			return
		}
	}
	if err := beeep.Notify(title, body, ""); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
	}
}

// Action is a button on an actionable OS toast (Linux notify-send).
type Action struct {
	ID    string // returned when chosen
	Label string
}

// EmitAction shows a whitelisted toast with optional action buttons.
// On Linux with notify-send, waits up to wait and returns the action id (or "").
// Elsewhere (or on failure) falls back to Emit and returns "".
// onAction is called asynchronously with the chosen id when non-empty.
func EmitAction(kind Kind, title, body string, wait time.Duration, actions []Action, onAction func(id string)) {
	mu.Lock()
	ok, reason := emitAllowedLocked(kind)
	lvl, isAway, focused, fs := level, away, uiFocused, fullscreen
	snoozed := !snoozeUntil.IsZero() && time.Now().Before(snoozeUntil)
	mu.Unlock()
	if title == "" {
		title = "DenyOut"
	}
	logAttempt(kind, title, body, ok, reason, lvl, isAway, focused, fs, snoozed)
	if !ok {
		return
	}
	if wait <= 0 {
		wait = ExpireFor(kind)
	}
	if wait <= 0 {
		wait = 60 * time.Second // sticky kinds still need a wait bound for --wait
	}
	if runtime.GOOS == "linux" && len(actions) > 0 {
		if _, err := exec.LookPath("notify-send"); err == nil {
			go func() {
				id := runNotifySendActions(kind, title, body, wait, actions)
				if id != "" && onAction != nil {
					onAction(id)
				}
			}()
			return
		}
	}
	Emit(kind, title, body)
}

func notifySendSoundArgs(kind Kind) []string {
	if SoundAllowed(KindWantsSound(kind)) {
		return nil
	}
	// Mute OS sound while still showing the banner (night / answer-only).
	return []string{"--hint=byte:suppress-sound:1"}
}

func runNotifySendPlain(kind Kind, title, body string) {
	expire := ExpireFor(kind)
	args := []string{"--app-name=DenyOut"}
	if kind == KindProtectFailed {
		args = append(args, "--urgency=critical")
	} else {
		args = append(args, "--urgency=normal")
	}
	if expire > 0 {
		args = append(args, fmt.Sprintf("--expire-time=%d", int(expire.Milliseconds())))
	}
	args = append(args, notifySendSoundArgs(kind)...)
	args = append(args, title, body)
	cmd := exec.Command("notify-send", args...)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
	}
}

var (
	waitProcsMu sync.Mutex
	waitProcs   []*os.Process
)

func trackWaitProc(p *os.Process) {
	if p == nil {
		return
	}
	waitProcsMu.Lock()
	waitProcs = append(waitProcs, p)
	waitProcsMu.Unlock()
}

func untrackWaitProc(p *os.Process) {
	if p == nil {
		return
	}
	waitProcsMu.Lock()
	out := waitProcs[:0]
	for _, x := range waitProcs {
		if x != p {
			out = append(out, x)
		}
	}
	waitProcs = out
	waitProcsMu.Unlock()
}

// CloseAll dismisses lingering DenyOut OS banners (tracked --wait children + Linux pkill fallback).
// Call on Quit unload and Uninstall so sticky Protect-failed / Undo toasts do not outlive the app.
// Killing --wait notify-send processes removes the matching GNOME shade entries; orphaned
// children reparented to systemd are caught by the pkill fallback.
func CloseAll() {
	waitProcsMu.Lock()
	procs := waitProcs
	waitProcs = nil
	waitProcsMu.Unlock()
	for _, p := range procs {
		if p != nil {
			_ = p.Kill()
		}
	}
	if runtime.GOOS == "linux" {
		killDenyOutNotifySend()
	}
}

// killDenyOutNotifySend best-effort clears Linux notify-send processes that used --app-name=DenyOut
// (including orphans whose parent already exited without CloseAll).
func killDenyOutNotifySend() {
	if _, err := exec.LookPath("pkill"); err != nil {
		return
	}
	// Prefer the literal argv form Emit/EmitAction/Ask use; keep a looser pattern as backup.
	_ = exec.Command("pkill", "-f", "notify-send --app-name=DenyOut").Run()
	_ = exec.Command("pkill", "-f", "notify-send.*--app-name=DenyOut").Run()
}

func runNotifySendActions(kind Kind, title, body string, wait time.Duration, actions []Action) string {
	args := []string{"--app-name=DenyOut"}
	if kind == KindProtectFailed {
		args = append(args, "--urgency=critical")
	} else {
		args = append(args, "--urgency=normal")
	}
	expireMs := int(wait.Milliseconds())
	if exp := ExpireFor(kind); exp > 0 && (expireMs <= 0 || int(exp.Milliseconds()) < expireMs) {
		expireMs = int(exp.Milliseconds())
	}
	if expireMs > 0 {
		args = append(args, fmt.Sprintf("--expire-time=%d", expireMs))
	}
	args = append(args, notifySendSoundArgs(kind)...)
	args = append(args, "--wait")
	for _, a := range actions {
		args = append(args, "--action="+a.ID+"="+a.Label)
	}
	args = append(args, title, body)
	cmd := exec.Command("notify-send", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout: notification: %v\n", err)
		return ""
	}
	trackWaitProc(cmd.Process)
	defer untrackWaitProc(cmd.Process)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return ""
		}
		return strings.TrimSpace(stdout.String())
	case <-time.After(wait + 2*time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ""
	}
}

// Info is a no-op. Status / teaching / Protect on-off nags must not use OS toasts;
// use Emit with a whitelist kind, or in-app UI only.
func Info(title, body string) {
	_ = title
	_ = body
}

// Deny is a no-op for passive OS banners. Hard-block HITL uses the decision dialog
// (or transitional notify-send actions in postblock until that lands).
func Deny(host string, reasons []string, redactedURL ...string) {
	_ = host
	_ = reasons
	_ = redactedURL
}

// HumanReasons turns stable reason codes into plain-language copy.
func HumanReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "Your agent tried to reach something outside the allowlist."
	}
	var parts []string
	for _, r := range reasons {
		switch r {
		case "host_not_allowed":
			parts = append(parts, "That site is not on your allowed list.")
		case "ip_literal":
			parts = append(parts, "Blocked a raw IP address (not allowed in this mode).")
		case "host_denied":
			parts = append(parts, "This site is on your deny list.")
		case "threat_list":
			parts = append(parts, "This site is on a known phishing or malware list.")
		case "secret_in_url", "secret_in_header", "secret_in_body":
			parts = append(parts, "Blocked a link that looked like it contained a secret.")
		case "canary_detected":
			parts = append(parts, "A canary/test secret was found in the request.")
		case "unsafe_ip":
			parts = append(parts, "The destination looked like a private or metadata address.")
		case "port_not_allowed":
			parts = append(parts, "That network port is not allowed.")
		case "rate_limited":
			parts = append(parts, "Too many requests in a short time.")
		default:
			parts = append(parts, r)
		}
	}
	return strings.Join(parts, " ")
}
