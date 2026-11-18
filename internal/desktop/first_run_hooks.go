package desktop

import "github.com/nareyko/denyout/internal/diag"

// firstRunHooks lets tests replace every dialog and every system-changing step
// of first run. All fields are nil in production and fall back to the real
// implementation.
type firstRunHooks struct {
	toolkit             func() bool
	choose              func() string
	confirm             func(title, text, yes, no string) bool
	enableSafe          func() error
	selfCheck           func() []diag.Check
	registerAutostart   func() error
	unregisterAutostart func() error
}

func (a *App) toolkitAvailable() bool {
	if h := a.hooks.toolkit; h != nil {
		return h()
	}
	return dialogToolkitAvailable()
}

func (a *App) firstRunChoice() string {
	if h := a.hooks.choose; h != nil {
		return h()
	}
	return nativeFirstRunChoice()
}

func (a *App) confirmDialog(title, text, yes, no string) bool {
	if h := a.hooks.confirm; h != nil {
		return h(title, text, yes, no)
	}
	return nativeConfirm(title, text, yes, no)
}

func (a *App) firstRunSelfCheck() []diag.Check {
	if h := a.hooks.selfCheck; h != nil {
		return h()
	}
	return a.UIRunSelfCheck()
}

func (a *App) registerAutostart() error {
	if h := a.hooks.registerAutostart; h != nil {
		return h()
	}
	return RegisterAutostart()
}

func (a *App) unregisterAutostart() error {
	if h := a.hooks.unregisterAutostart; h != nil {
		return h()
	}
	return UnregisterAutostart()
}
