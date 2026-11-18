package desktop

import (
	"fmt"
	"strings"
	"time"

	"github.com/gogpu/systray"
)

type trayIcon int

const (
	trayIconIdle trayIcon = iota
	trayIconOn
	trayIconQuiet
	trayIconAlert
)

// trayInputs is the snapshot of app state the tray reflects on each tick.
type trayInputs struct {
	Mode           string
	Profile        string // normalized policy profile
	Avail          bool
	PauseUntil     string // active pause deadline (RFC3339) or ""
	PauseLast      string
	LeaveOn        bool
	NeedsAttention bool
	ThreatWarn     bool
	Unread         int
	SnoozeUntil    string
	Status         string
	QuietPhrase    string
	UndoActive     bool
	WrapsRunning   bool
	Now            time.Time
}

// trayModel is everything the tray shows for one tick.
type trayModel struct {
	StatusLabel       string
	Tooltip           string
	Icon              trayIcon
	ComputerLabel     string
	ComputerOff       bool // disabled
	OffLabel          string
	OffDisabled       bool
	Snooze1hOff       bool
	SnoozeTomorrowOff bool
	ClearSnoozeOff    bool
}

func trayPauseLabel(in trayInputs, agentsIntent bool) string {
	label := userModeLabel(in.Mode, in.Profile)
	pausePrefix := ""
	if agentsIntent {
		pausePrefix = "Agents only "
	}
	switch {
	case in.Mode == ModeOff && in.PauseUntil != "":
		label = pausePrefix + "Paused"
		if t, err := time.Parse(time.RFC3339, in.PauseUntil); err == nil {
			local := t.Local()
			// 24h local clock — matches chrome formatPauseUntil (hour12: false).
			if local.Format("2006-01-02") == in.Now.Local().Format("2006-01-02") {
				label = pausePrefix + "paused until " + local.Format("15:04")
			} else {
				label = pausePrefix + "paused until " + local.Format("Jan 2, 15:04")
			}
		}
	case in.Mode == ModeOff && in.PauseLast == "forever":
		if agentsIntent {
			label = "Agents only off until you turn it on"
		} else {
			label = "Off until you turn it on"
		}
	case in.Mode == ModeOff && !in.Avail:
		label = "Off (unavailable)"
	}
	if in.NeedsAttention {
		label = "Needs attention"
	}
	return label
}

// trayOffItem returns label and disabled state for the Off/Pause menu item.
func trayOffItem(in trayInputs, paused, agentsIntent bool) (string, bool) {
	offNoun := "Protect"
	switch {
	case in.Mode == ModeComputer && in.Profile == PolicyProfileAgent:
		offNoun = "Agents only"
	case in.Mode == ModeSession:
		offNoun = "Session protection"
	case agentsIntent && (paused || in.Mode == ModeOff):
		offNoun = "Agents only"
	}
	switch {
	case paused:
		return "Change " + offNoun + " pause…", false
	case in.NeedsAttention && in.Mode == ModeOff:
		// Match Home/Jump: Clear intent only when Protect is not live.
		if agentsIntent {
			return "Clear Agents only intent…", false
		}
		return "Clear Protect intent…", false
	case in.NeedsAttention || in.Mode != ModeOff || in.LeaveOn:
		return "Pause / turn off " + offNoun + "…", false
	}
	return checkedLabel("Off", true), true
}

func trayUnreadBit(unread int) string {
	switch {
	case unread == 1:
		return " · 1 quiet"
	case unread > 1:
		return fmt.Sprintf(" · %d quiet", unread)
	}
	return ""
}

// trayQuietExtras returns the tooltip and status-line suffixes.
func trayQuietExtras(in trayInputs) (tip, status string) {
	switch {
	case in.QuietPhrase != "":
		tip = " · " + in.QuietPhrase
	case in.SnoozeUntil != "":
		tip = " · snoozed" // fallback if phrase empty but snooze set
	}
	tip += trayUnreadBit(in.Unread)
	status = tip
	if in.UndoActive {
		tip += " · Undo available — open DenyOut"
		status += " · Undo"
	}
	return tip, status
}

func trayIconFor(in trayInputs) trayIcon {
	switch {
	case in.NeedsAttention, strings.Contains(strings.ToLower(in.Status), "error"), strings.Contains(in.Status, "Needs"):
		return trayIconAlert
	case in.QuietPhrase != "":
		return trayIconQuiet
	case in.Mode != ModeOff:
		return trayIconOn
	}
	return trayIconIdle
}

// trayView computes the tray presentation for one tick. Pure.
func trayView(in trayInputs) trayModel {
	paused := in.Mode == ModeOff && (in.PauseUntil != "" || in.PauseLast == "forever")
	agentsIntent := in.Profile == PolicyProfileAgent
	label := trayPauseLabel(in, agentsIntent)
	m := trayModel{
		StatusLabel:       label,
		Tooltip:           "DenyOut - " + label,
		Snooze1hOff:       in.SnoozeUntil != "",
		SnoozeTomorrowOff: in.SnoozeUntil != "",
		ClearSnoozeOff:    in.SnoozeUntil == "",
	}
	browse := in.Mode == ModeComputer && in.Profile == PolicyProfileBrowse
	m.ComputerLabel = checkedLabel("Protect computer", browse)
	m.ComputerOff = browse
	m.OffLabel, m.OffDisabled = trayOffItem(in, paused, agentsIntent)
	if !in.NeedsAttention {
		// Mirror chrome: Needs attention pill drops snooze/quiet extras.
		tip, status := trayQuietExtras(in)
		m.Tooltip += tip
		m.StatusLabel += status
	}
	m.Icon = trayIconFor(in)
	m.applyIconRules(in, paused)
	return m
}

// applyIconRules adds the threat-list warning or the agents-running summary.
func (m *trayModel) applyIconRules(in trayInputs, paused bool) {
	const warn = " · Threat lists need a refresh"
	switch {
	case m.Icon == trayIconAlert:
	case m.Icon == trayIconQuiet, m.Icon == trayIconOn, in.ThreatWarn:
		// Threat-list warn keeps the icon (chrome: mode pill + warn chip).
		if in.ThreatWarn {
			m.Tooltip += warn
		}
	case in.WrapsRunning && !paused:
		// Protect computer is Off — don't imply whole-PC Protect with the on icon.
		if base := trayAgentsRunningBase(in); base != "" {
			bits := trayUnreadBit(in.Unread)
			if in.SnoozeUntil != "" {
				bits = " · snoozed" + bits
			}
			m.StatusLabel = base + bits
			m.Tooltip = "DenyOut - " + base + bits
		}
	}
}

func trayAgentsRunningBase(in trayInputs) string {
	switch {
	case in.Mode != ModeOff:
		return ""
	case !in.Avail:
		// Match chrome: unavailable wins, agents still visible; keep snooze+quiet.
		return "Off (unavailable) · agents running"
	case in.PauseUntil == "" && in.PauseLast != "forever":
		return "Off · agents running"
	}
	return ""
}

func trayIconBytes(i trayIcon) []byte {
	switch i {
	case trayIconOn:
		return iconOnPNG
	case trayIconQuiet:
		return iconQuietPNG
	case trayIconAlert:
		return iconAlertPNG
	}
	return iconIdlePNG
}

func applyTrayModel(m trayModel, tray *systray.SystemTray, ti trayItems) {
	ti.snooze1h.SetDisabled(m.Snooze1hOff)
	ti.snoozeTomorrow.SetDisabled(m.SnoozeTomorrowOff)
	ti.clearSnooze.SetDisabled(m.ClearSnoozeOff)
	ti.status.SetLabel(m.StatusLabel)
	ti.computer.SetLabel(m.ComputerLabel)
	ti.computer.SetDisabled(m.ComputerOff)
	ti.off.SetLabel(m.OffLabel)
	ti.off.SetDisabled(m.OffDisabled)
	tray.SetTooltip(m.Tooltip)
	tray.SetIcon(trayIconBytes(m.Icon))
}
