package desktop

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/run"
)

// wizardNewAgent creates a profile via native dialogs; optionally starts it.
func (a *App) wizardNewAgent(start bool) {
	if !dialogToolkitAvailable() {
		notify.Info("DenyOut", "Install zenity for the agent wizard, or: denyout profile create --name ... -- cmd")
		return
	}
	name, ok := nativeEntry("DenyOut - new agent", "Name for this agent (1-40 characters):", "My agent")
	if !ok || strings.TrimSpace(name) == "" {
		return
	}
	cmdLine, ok := nativeEntry("DenyOut - command", "Command to run under protection (e.g. python app.py or claude):", "")
	if !ok || strings.TrimSpace(cmdLine) == "" {
		return
	}
	if looksLikeSecretInCmd(cmdLine) {
		if !nativeConfirm("DenyOut", "That command may contain a secret (token/key-looking text).\n\nSave it anyway? Prefer env vars or a secrets file.", "Save anyway", "Cancel") {
			return
		}
	}
	workdir, _ := nativeEntry("DenyOut - working folder", "Working directory (optional, leave blank for current):", "")
	preset := "agent"
	if nativeConfirm("DenyOut - allowlist", "Use Agent + Cursor allowlist? (Recommended)\n\nNo = Models only (stricter).", "Agent + Cursor", "Models only") {
		preset = "agent"
	} else {
		preset = "models"
	}
	isolation := false
	if run.SRTAvailable() {
		isolation = nativeConfirm(
			"DenyOut - stronger isolation",
			"Enable Stronger isolation (srt)?\n\nBlocks bypass of the proxy. Requires the srt tool installed.",
			"Enable",
			"Skip",
		)
	} else {
		notify.Info("DenyOut", "Stronger isolation needs srt (sandbox-runtime). Wrap will run without it. Some tools can bypass the proxy.")
	}
	p := NewAgentProfile(name, splitCommand(cmdLine))
	p.WorkDir = strings.TrimSpace(workdir)
	p.Preset = preset
	if isolation {
		p.Sandbox = "srt"
		p.RequireIsolation = true
	}
	if err := SaveProfile(p); err != nil {
		notify.Info("DenyOut", "Could not save profile: "+err.Error())
		return
	}
	packID := SuggestPackID(p.Name, p.Command)
	if packID == "" {
		packID = "cursor-starter"
	}
	if pack, err := LookupAllowPack(packID); err == nil {
		if nativeConfirm(
			"DenyOut - recommended hosts",
			"Add recommended hosts?\n\n"+pack.Name+": "+pack.Description+"\n\nYou can Undo the pack later in My agents -> Edit.",
			"Add hosts",
			"Skip",
		) {
			if added, err := ApplyPack(&p, pack.ID); err != nil {
				notify.Info("DenyOut", "Could not apply pack: "+err.Error())
			} else if err := SaveProfile(p); err != nil {
				notify.Info("DenyOut", "Could not save pack hosts: "+err.Error())
			} else if len(added) > 0 {
				notify.Info("DenyOut", fmt.Sprintf("Added %d host(s) from %s", len(added), pack.Name))
			}
		}
	}
	notify.Info("DenyOut", "Saved agent: "+p.Name)
	if start {
		if err := a.startProfile(p.ID); err != nil {
			notify.Info("DenyOut", "Start failed: "+err.Error())
		}
	}
}

func looksLikeSecretInCmd(s string) bool {
	low := strings.ToLower(s)
	needles := []string{"sk-", "ghp_", "xoxb-", "api_key=", "token=", "bearer ", "AKIA"}
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func (a *App) myAgentsMenu() {
	// UX2 Q8: with Wails, open the My agents screen in-app (list lives in the window).
	if a.opts.OpenUI != nil {
		a.RequestOpenUI("profiles")
		return
	}
	profiles, err := ListProfiles()
	if err != nil {
		notify.Info("DenyOut", "Could not list agents: "+err.Error())
		return
	}
	a.ensureWraps()
	a.mu.Lock()
	running := map[string]bool{}
	for id := range a.wraps {
		running[id] = true
	}
	a.mu.Unlock()

	choices := []string{"➕ New agent..."}
	ids := []string{""}
	for _, p := range profiles {
		mark := "○"
		if running[p.ID] {
			mark = "-"
		}
		pending := ""
		if n := len(p.PendingOnce); n > 0 {
			pending = fmt.Sprintf(" - learning %d", n)
		}
		choices = append(choices, fmt.Sprintf("%s %s - %s%s", mark, p.Name, p.CommandLine(), pending))
		ids = append(ids, p.ID)
	}
	choices = append(choices, "Stop all agents")
	ids = append(ids, "__stop_all__")

	sel, ok := nativeListPick("DenyOut - My agents", "Select an agent:", choices)
	if !ok {
		return
	}
	idx := -1
	for i, c := range choices {
		if c == sel {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	id := ids[idx]
	switch {
	case id == "":
		a.wizardNewAgent(true)
	case id == "__stop_all__":
		a.stopAllWraps("Stop all from My agents")
	default:
		a.agentActions(id)
	}
}

func (a *App) agentActions(id string) {
	p, err := LoadProfile(id)
	if err != nil {
		notify.Info("DenyOut", err.Error())
		return
	}
	a.mu.Lock()
	_, running := a.wraps[id]
	a.mu.Unlock()
	items := []string{}
	if running {
		items = append(items, "Stop", "Edit...")
	} else {
		items = append(items, "Start", "Edit...", "Delete")
	}
	if len(p.PendingOnce) > 0 {
		items = append(items, fmt.Sprintf("Pin learning (%d)...", len(p.PendingOnce)))
	}
	items = append(items, "Cancel")
	sel, ok := nativeListPick("DenyOut - "+p.Name, "Action:", items)
	if !ok {
		return
	}
	switch {
	case sel == "Start":
		if err := a.startProfile(id); err != nil {
			notify.Info("DenyOut", err.Error())
		}
	case sel == "Stop":
		a.stopProfile(id)
	case strings.HasPrefix(sel, "Pin learning"):
		a.pinLearningUI(id)
	case sel == "Edit...":
		a.editProfileUI(id)
	case sel == "Delete":
		if nativeConfirm("DenyOut", "Delete agent "+p.Name+"?", "Delete", "Cancel") {
			_ = DeleteProfile(id)
			notify.Info("DenyOut", "Deleted "+p.Name)
		}
	}
}

func (a *App) editProfileUI(id string) {
	p, err := LoadProfile(id)
	if err != nil {
		return
	}
	a.mu.Lock()
	_, running := a.wraps[id]
	a.mu.Unlock()
	if running {
		if !nativeConfirm("DenyOut", "This agent is running. Stop, save, and start again?", "Stop, save, restart", "Cancel") {
			return
		}
		a.stopProfile(id)
	}
	name, ok := nativeEntry("DenyOut - name", "Name:", p.Name)
	if !ok {
		return
	}
	cmdLine, ok := nativeEntry("DenyOut - command", "Command:", strings.Join(p.Command, " "))
	if !ok {
		return
	}
	if looksLikeSecretInCmd(cmdLine) {
		if !nativeConfirm("DenyOut", "Command may contain a secret. Save anyway?", "Save anyway", "Cancel") {
			return
		}
	}
	wd, _ := nativeEntry("DenyOut - workdir", "Working directory:", p.WorkDir)
	oldCmd := strings.Join(p.Command, " ")
	oldPreset := p.Preset
	p.Name = NormalizeProfileName(name)
	p.Command = splitCommand(cmdLine)
	p.WorkDir = strings.TrimSpace(wd)
	if err := SaveProfile(p); err != nil {
		notify.Info("DenyOut", err.Error())
		return
	}
	restart := running || oldCmd != strings.Join(p.Command, " ") || oldPreset != p.Preset
	if restart {
		if err := a.startProfile(id); err != nil {
			notify.Info("DenyOut", "Saved but start failed: "+err.Error())
			return
		}
	}
	notify.Info("DenyOut", "Updated "+p.Name)
}

func nativeListPick(title, text string, items []string) (string, bool) {
	if len(items) == 0 {
		return "", false
	}
	if zenity, err := exec.LookPath("zenity"); err == nil {
		args := []string{"--list", "--title=" + title, "--text=" + text, "--column=Choice", "--hide-header", "--width=560", "--height=360"}
		args = append(args, items...)
		out, err := exec.Command(zenity, args...).Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}
	if kdialog, err := exec.LookPath("kdialog"); err == nil {
		pairs := make([]string, 0, len(items)*2)
		for i, it := range items {
			pairs = append(pairs, fmt.Sprintf("%d", i), it)
		}
		args := append([]string{"--menu", text, "--title", title}, pairs...)
		out, err := exec.Command(kdialog, args...).Output()
		if err != nil {
			return "", false
		}
		idx := strings.TrimSpace(string(out))
		var i int
		if _, err := fmt.Sscanf(idx, "%d", &i); err == nil && i >= 0 && i < len(items) {
			return items[i], true
		}
	}
	// Fallback: first item via confirm
	if nativeConfirm(title, text+"\n\nUse: "+items[0]+"?", "OK", "Cancel") {
		return items[0], true
	}
	return "", false
}
