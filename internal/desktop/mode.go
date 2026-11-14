package desktop

// Protection mode from live processes (not only desktop.json).
const (
	ModeOff = "off"
	ModeSession = "session"
	ModeComputer = "computer"
)

// currentMode returns the live protection mode.
func (a *App) currentMode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxyd != nil {
		return ModeComputer
	}
	if a.session != nil {
		return ModeSession
	}
	return ModeOff
}

func modeLabel(mode string) string {
	switch mode {
	case ModeComputer:
		return "Computer"
	case ModeSession:
		return "Session"
	default:
		return "Off"
	}
}
