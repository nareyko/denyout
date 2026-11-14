//go:build wails

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
}

func (b *Bridge) presentDecision(p desktop.DecisionPrompt) string {
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
	runtime.EventsEmit(ctx, "decision", map[string]interface{}{
		"id":      id,
		"host":    p.Host,
		"reason":  p.Reason,
		"why":     p.Why,
		"url":     p.URL,
		"timeout": int(p.Timeout.Seconds()),
		"taught":  p.Taught,
	})
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	select {
	case action := <-ch:
		return action
	case <-time.After(timeout):
		return desktop.DecisionLater
	}
}

// UIResolveDecision completes an in-app hard-block decision.
func (b *Bridge) UIResolveDecision(id, action string) {
	b.mu.Lock()
	ch := b.decisions[id]
	b.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- action:
	default:
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
func (b *Bridge) ListDenials(q desktop.DenialQuery) ([]desktop.DenialView, error) {
	return b.app.ListDenials(q)
}
func (b *Bridge) UIAlwaysAllowHost(host, reason string) error {
	return b.app.UIAlwaysAllowHost(host, reason)
}
func (b *Bridge) UIForgetKeep(host, reason string) error { return b.app.UIForgetKeep(host, reason) }
func (b *Bridge) UIClearAllKeeps() error                 { return b.app.UIClearAllKeeps() }
func (b *Bridge) UIRemoveAlwaysAllow(host string) error {
	return b.app.UIRemoveAlwaysAllow(host)
}
func (b *Bridge) UISetNotify(on bool) error             { return b.app.UISetNotify(on) }
func (b *Bridge) UISetNotifyLevel(level string) error   { return b.app.UISetNotifyLevel(level) }
func (b *Bridge) UISetDecisionTimeoutSec(sec int) error { return b.app.UISetDecisionTimeoutSec(sec) }
func (b *Bridge) UISetReaskIntervalSec(sec int) error   { return b.app.UISetReaskIntervalSec(sec) }
func (b *Bridge) UIRemoveTimedAllow(host string) error  { return b.app.UIRemoveTimedAllow(host) }
func (b *Bridge) UIRemoveTimedDeny(host, reason string) error {
	return b.app.UIRemoveTimedDeny(host, reason)
}
func (b *Bridge) UISetAutostart(on bool) error      { return b.app.UISetAutostart(on) }
func (b *Bridge) UIEnableSafeDesktop() error        { return b.app.UIEnableSafeDesktop() }
func (b *Bridge) UIEnableAgentsOnly() error         { return b.app.UIEnableAgentsOnly() }
func (b *Bridge) UISwitchSafe()                     { b.app.UISwitchSafe() }
func (b *Bridge) UIStopProtection()                 { b.app.UIStopProtection() }
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
func (b *Bridge) UIResumeAsks()                     { b.app.UIResumeAsks() }
func (b *Bridge) UIUndoLastAlwaysAllow()            { b.app.UIUndoLastAlwaysAllow() }
func (b *Bridge) UITestProtection()                 { b.app.UITestProtection() }
func (b *Bridge) UIBulkAlwaysAllow(hosts []string) error {
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

func main() {
	noTray := flag.Bool("no-tray", false, "disable system tray (debug)")
	flag.Parse()

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

	err := wails.Run(&options.App{
		Title:             "DenyOut",
		Width:             1100,
		Height:            720,
		MinWidth:          860,
		MinHeight:         560,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       !*noTray, // tray mode: start hidden until Open
		HideWindowOnClose: false,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 246, G: 247, B: 249, A: 255},
		OnStartup:        bridge.startup,
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			runtime.WindowHide(ctx)
			bridge.mu.Lock()
			shown := bridge.hideToast
			bridge.hideToast = true
			bridge.mu.Unlock()
			if !shown {
				notify.Info("DenyOut", "Still running in the tray. Quit from the tray menu when you are done.")
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
