//go:build wails

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nareyko/denyout/internal/desktop"
	"github.com/nareyko/denyout/internal/notify"
)

//go:embed all:frontend/dist
var assets embed.FS

var version = "dev"

// Bridge exposes desktop.App methods to the React UI.
type Bridge struct {
	app *desktop.App

	mu        sync.Mutex
	presentMu sync.Mutex // one in-app Ask / hard-block decision at a time
	ctx       context.Context
	hideToast bool
	pending   string
	decisions map[string]chan string
}

func (b *Bridge) startup(ctx context.Context) {
	b.mu.Lock()
	b.ctx = ctx
	if b.decisions == nil {
		b.decisions = map[string]chan string{}
	}
	route := b.pending
	b.pending = ""
	b.mu.Unlock()
	if route != "" {
		runtime.EventsEmit(ctx, "navigate", route)
	}
}

// UIReady registers the in-app decision presenter once the React shell is mounted.
func (b *Bridge) UIReady() {
	desktop.SetDecisionPresenter(b.presentDecision)
	b.app.UIReadyRestore()
}

func (b *Bridge) presentDecision(p desktop.DecisionPrompt) string {
	// Serialize so Ask + hard-block cannot overwrite each other's modal.
	b.presentMu.Lock()
	defer b.presentMu.Unlock()

	b.mu.Lock()
	ctx := b.ctx
	if b.decisions == nil {
		b.decisions = map[string]chan string{}
	}
	id := p.ID
	if id == "" {
		id = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	ch := make(chan string, 1)
	b.decisions[id] = ch
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.decisions, id)
		b.mu.Unlock()
	}()

	if ctx == nil {
		return desktop.PresentDecisionNative(p)
	}
	runtime.WindowShow(ctx)
	kind := strings.TrimSpace(p.Kind)
	if kind == "" {
		kind = "hard"
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if kind == "ask" && timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	// Emit the effective timeout so the UI countdown matches the Bridge wait.
	runtime.EventsEmit(ctx, "decision", map[string]interface{}{
		"id":           id,
		"host":         p.Host,
		"reason":       p.Reason,
		"why":          p.Why,
		"url":          p.URL,
		"timeout":      int(timeout.Seconds()),
		"taught":       p.Taught,
		"kind":         kind,
		"profile_name": p.ProfileName,
		"profile_id":   p.ProfileID,
		"batch":        p.Batch,
		"multi_agent":  p.MultiAgent,
	})
	// UI countdown matches timeout; keep channel open a few seconds longer so a
	// late click is not silently dropped after Bridge already returned "later".
	select {
	case action := <-ch:
		return action
	case <-time.After(timeout + 3*time.Second):
		// Drop a zombie modal if the UI timer was throttled (background tab).
		runtime.EventsEmit(ctx, "decision-done", map[string]interface{}{"id": id})
		return desktop.DecisionLater
	}
}

// UIResolveDecision completes an in-app hard-block decision.
func (b *Bridge) UIResolveDecision(id, action string) error {
	b.mu.Lock()
	ch := b.decisions[id]
	b.mu.Unlock()
	if ch == nil {
		act := strings.TrimSpace(strings.ToLower(action))
		// Frontend countdown may fire after Bridge already timed out to later/deny.
		if act == "later" || act == "deny" || act == "open" {
			return nil
		}
		return fmt.Errorf("That choice expired — open History if you still want to allow the site")
	}
	select {
	case ch <- action:
		return nil
	default:
		return fmt.Errorf("That choice was already applied")
	}
}

func (b *Bridge) openUI(route string) {
	b.mu.Lock()
	ctx := b.ctx
	b.mu.Unlock()
	if ctx == nil {
		b.mu.Lock()
		b.pending = route
		b.mu.Unlock()
		return
	}
	runtime.WindowShow(ctx)
	runtime.EventsEmit(ctx, "navigate", route)
}

func (b *Bridge) GetUISnapshot() desktop.UISnapshot { return b.app.GetUISnapshot() }
func (b *Bridge) MarkYourSetupShown() error         { return b.app.MarkYourSetupShown() }
func (b *Bridge) UIClearNotice()                    { b.app.UIClearNotice() }
func (b *Bridge) ListDenials(q desktop.DenialQuery) ([]desktop.DenialView, error) {
	return b.app.ListDenials(q)
}
func (b *Bridge) UIAlwaysAllowHost(host, reason string) error {
	return b.app.UIAlwaysAllowHost(host, reason)
}
func (b *Bridge) UIAlwaysAllowHostFrom(host, reason, process string) error {
	return b.app.UIAlwaysAllowHostFrom(host, reason, process)
}
func (b *Bridge) UIForgetKeep(host, reason string) error { return b.app.UIForgetKeep(host, reason) }
func (b *Bridge) UIClearAllKeeps() error                 { return b.app.UIClearAllKeeps() }
func (b *Bridge) UIRemoveAlwaysAllow(host string) error {
	return b.app.UIRemoveAlwaysAllow(host)
}
func (b *Bridge) UISetNotify(on bool) error             { return b.app.UISetNotify(on) }
func (b *Bridge) UISetNotifyLevel(level string) error   { return b.app.UISetNotifyLevel(level) }
func (b *Bridge) UISetNotifyUIFocused(on bool)          { b.app.UISetNotifyUIFocused(on) }
func (b *Bridge) UISetQuietWhileAway(on bool) error     { return b.app.UISetQuietWhileAway(on) }
func (b *Bridge) UIClearAwayUnread() error              { return b.app.UIClearAwayUnread() }
func (b *Bridge) UIDismissAwayDigest() error            { return b.app.UIDismissAwayDigest() }
func (b *Bridge) UISetNotifySnooze(choice string) error  { return b.app.UISetNotifySnooze(choice) }
func (b *Bridge) UISetQuietOvernight(on bool) error     { return b.app.UISetQuietOvernight(on) }
func (b *Bridge) UISetSoundOnlyAnswer(on bool) error    { return b.app.UISetSoundOnlyAnswer(on) }
func (b *Bridge) UISetSystemBanners(on bool) error      { return b.app.UISetSystemBanners(on) }
func (b *Bridge) UISetRespectFullscreen(on bool) error  { return b.app.UISetRespectFullscreen(on) }
func (b *Bridge) UISetSilentWhenOpen(on bool) error     { return b.app.UISetSilentWhenOpen(on) }
func (b *Bridge) UISetDecisionTimeoutSec(sec int) error { return b.app.UISetDecisionTimeoutSec(sec) }
func (b *Bridge) UISetReaskIntervalSec(sec int) error   { return b.app.UISetReaskIntervalSec(sec) }
func (b *Bridge) UIRemoveTimedAllow(host string) error  { return b.app.UIRemoveTimedAllow(host) }
func (b *Bridge) UIRemoveTimedDeny(host, reason string) error {
	return b.app.UIRemoveTimedDeny(host, reason)
}
func (b *Bridge) UISetAutostart(on bool) error { return b.app.UISetAutostart(on) }
func (b *Bridge) UIEnableSafeDesktop() error   { return b.app.UIEnableSafeDesktop() }
func (b *Bridge) UIEnableAgentsOnly() error    { return b.app.UIEnableAgentsOnly() }
func (b *Bridge) UIOnboardingNotNow() error    { return b.app.UIOnboardingNotNow() }
func (b *Bridge) UIOnboardingAgents() error    { return b.app.UIOnboardingAgents() }
func (b *Bridge) UIResetSetup() error          { return b.app.UIResetSetup() }
func (b *Bridge) UIMigrateUXv2(switchToSafe bool) error {
	return b.app.UIMigrateUXv2(switchToSafe)
}
func (b *Bridge) UISwitchSafe() error     { return b.app.UISwitchSafe() }
func (b *Bridge) UIStopProtection() error { return b.app.UIStopProtection() }
func (b *Bridge) UIStopProtectionWithChoice(choice string) error {
	return b.app.UIStopProtectionWithChoice(choice)
}
func (b *Bridge) GetProblems() desktop.ProblemsView { return b.app.GetProblems() }
func (b *Bridge) UIOpenLogs() error                 { return b.app.UIOpenLogs() }
func (b *Bridge) UICopyLastError() (string, error)  { return b.app.UICopyLastError() }
func (b *Bridge) UIRetryProtect() error             { return b.app.UIRetryProtect() }
func (b *Bridge) ListProfileViews() ([]desktop.ProfileView, error) {
	return b.app.ListProfileViews()
}
func (b *Bridge) UISaveProfile(p desktop.AgentProfile) error { return b.app.UISaveProfile(p) }
func (b *Bridge) ListAllowPacks() ([]desktop.AllowPack, error) {
	return b.app.ListAllowPacks()
}
func (b *Bridge) UIApplyAllowPack(profileID, packID string) ([]string, error) {
	return b.app.UIApplyAllowPack(profileID, packID)
}
func (b *Bridge) UIUndoAllowPack(profileID, packID string) ([]string, error) {
	return b.app.UIUndoAllowPack(profileID, packID)
}
func (b *Bridge) UISuggestAllowPack(name string, command []string) string {
	return b.app.UISuggestAllowPack(name, command)
}
func (b *Bridge) UIDeleteProfile(id string) error   { return b.app.UIDeleteProfile(id) }
func (b *Bridge) UIStartProfile(id string) error    { return b.app.UIStartProfile(id) }
func (b *Bridge) UIStopProfile(id string)           { b.app.UIStopProfile(id) }
func (b *Bridge) UIPinLearning(id string) error     { return b.app.UIPinLearning(id) }
func (b *Bridge) UIDiscardLearning(id string) error { return b.app.UIDiscardLearning(id) }
func (b *Bridge) HealthPing() string                { return b.app.HealthPing() }
func (b *Bridge) TipDismissed(id string) bool       { return b.app.TipDismissed(id) }
func (b *Bridge) UIDismissTip(id string) error      { return b.app.UIDismissTip(id) }
func (b *Bridge) UIPauseAsks() string               { return b.app.UIPauseAsks() }
func (b *Bridge) UIResumeAsks() string              { return b.app.UIResumeAsks() }
func (b *Bridge) UIUndoLastAlwaysAllow() (string, error) {
	return b.app.UIUndoLastAlwaysAllow()
}
func (b *Bridge) UITestProtection() string { return b.app.UITestProtection() }
func (b *Bridge) UIBulkAlwaysAllow(hosts []string) (string, error) {
	return b.app.UIBulkAlwaysAllow(hosts)
}
func (b *Bridge) GetThreatLists() desktop.ThreatListsView { return b.app.GetThreatLists() }
func (b *Bridge) UISetBlockPhishing(on bool) error        { return b.app.UISetBlockPhishing(on) }
func (b *Bridge) UISetBlockMalware(on bool) error         { return b.app.UISetBlockMalware(on) }
func (b *Bridge) UISetBlockStronger(on bool) error        { return b.app.UISetBlockStronger(on) }
func (b *Bridge) UISetAdvancedThreatFeed(id string, on bool) error {
	return b.app.UISetAdvancedThreatFeed(id, on)
}
func (b *Bridge) UISetThreatPollHours(hours int) error {
	return b.app.UISetThreatPollHours(hours)
}
func (b *Bridge) UIRefreshThreatLists() (desktop.ThreatListsView, error) {
	return b.app.UIRefreshThreatLists()
}
func (b *Bridge) UICheckForUpdates() (desktop.UpdateCheckView, error) {
	return b.app.UICheckForUpdates()
}
func (b *Bridge) UIOpenUpdateURL() error              { return b.app.UIOpenUpdateURL() }
func (b *Bridge) GetAccountView() desktop.AccountView { return b.app.GetAccountView() }
func (b *Bridge) UIRequestMagicLink(email string) error {
	return b.app.UIRequestMagicLink(email)
}
func (b *Bridge) UIVerifyMagicLink(email, code string) error {
	return b.app.UIVerifyMagicLink(email, code)
}
func (b *Bridge) UISignOut() error         { return b.app.UISignOut() }
func (b *Bridge) UIDeleteCloudData() error { return b.app.UIDeleteCloudData() }
func (b *Bridge) UISetAccountAPIBase(base string) error {
	return b.app.UISetAccountAPIBase(base)
}
func (b *Bridge) UISetSyncEnabled(on bool) error         { return b.app.UISetSyncEnabled(on) }
func (b *Bridge) UISyncNow() (desktop.SyncResult, error) { return b.app.UISyncNow() }
func (b *Bridge) UIQuitNeedsChoice() bool                { return b.app.UIQuitNeedsChoice() }
func (b *Bridge) UIQuit(choice string) error {
	if err := b.app.UIQuit(choice); err != nil {
		return err
	}
	b.mu.Lock()
	ctx := b.ctx
	b.mu.Unlock()
	if ctx != nil {
		runtime.Quit(ctx)
	} else {
		os.Exit(0)
	}
	return nil
}

func main() {
	noTray := flag.Bool("no-tray", false, "disable system tray (debug)")
	openUI := flag.Bool("open", false, "show window on start (install / first run)")
	flag.Parse()
	if os.Getenv("DENYOUT_OPEN_UI") == "1" {
		*openUI = true
	}

	bridge := &Bridge{}
	appCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := desktop.Options{
		Version:             version,
		NoTray:              *noTray,
		SkipNativeYourSetup: true,
		OpenUI:              bridge.openUI,
	}
	core := desktop.NewApp(opts)
	bridge.app = core
	if err := core.Bootstrap(appCtx); err != nil {
		fmt.Fprintf(os.Stderr, "denyout-desktop: bootstrap: %v\n", err)
		os.Exit(1)
	}

	if !*noTray {
		go func() {
			if err := core.RunTray(appCtx); err != nil {
				fmt.Fprintf(os.Stderr, "denyout-desktop: tray: %v\n", err)
			}
			cancel()
		}()
	}

	startHidden := !*noTray && !*openUI
	err := wails.Run(&options.App{
		Title:             "DenyOut",
		Width:             1100,
		Height:            720,
		MinWidth:          860,
		MinHeight:         560,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       startHidden,
		HideWindowOnClose: false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 246, G: 247, B: 249, A: 255},
		OnStartup:        bridge.startup,
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			if *noTray {
				// No tray: hiding would strand the only UI. Unload and allow the window to close.
				if err := bridge.app.UIQuit("off"); err != nil {
					notify.Emit(notify.KindTrayHidden, "DenyOut",
						"Could not exit yet — finish the password prompt or fix Problems, then close again. (No tray in this mode.)")
					return true
				}
				return false
			}
			runtime.WindowHide(ctx)
			bridge.mu.Lock()
			shown := bridge.hideToast
			bridge.hideToast = true
			bridge.mu.Unlock()
			if !shown {
				// Info is a no-op; tray-hidden must reach the OS even on Quiet.
				notify.Emit(notify.KindTrayHidden, "DenyOut",
					"Still running in the tray — closing the window is not Quit. Use Quit in the tray menu to exit.")
			}
			return true
		},
		Bind: []interface{}{
			bridge,
		},
		Linux: &linux.Options{
			WebviewGpuPolicy: linux.WebviewGpuPolicyNever,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout-desktop: %v\n", err)
		os.Exit(1)
	}
}
