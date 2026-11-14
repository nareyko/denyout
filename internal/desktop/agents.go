package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

type wrapProc struct {
	id      string
	name    string
	cmd     *exec.Cmd
	sess    *run.Session
	started time.Time
}

func (a *App) ensureWraps() {
	a.mu.Lock()
	if a.wraps == nil {
		a.wraps = map[string]*wrapProc{}
	}
	a.mu.Unlock()
}

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

func (a *App) startProfile(id string) error {
	a.ensureWraps()
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if _, ok := a.wraps[id]; ok {
		a.mu.Unlock()
		return fmt.Errorf("%s is already running", p.Name)
	}
	a.mu.Unlock()

	cfg, err := p.PolicyConfig()
	if err != nil {
		return err
	}
	sandbox := strings.TrimSpace(p.Sandbox)
	if p.RequireIsolation && sandbox == "" {
		sandbox = "srt"
	}
	if (sandbox == "srt" || p.RequireIsolation) && !run.SRTAvailable() {
		return fmt.Errorf("stronger isolation required but srt was not found in PATH - install sandbox-runtime or turn off require_isolation")
	}

	var sessRef *run.Session
	profileName := p.Name
	profileID := p.ID
	ask := p.AskMode
	threats := a.ensureThreatStore(false)
	sess, err := run.StartSession(run.SessionOptions{
		Config:        cfg,
		TLSMode:       proxy.TLSIntercept,
		Version:       a.opts.Version,
		Sandbox:       sandbox,
		PolicyProfile: "agent",
		Process:       "wrap:" + p.ID,
		Threats:       threats,
		OnDeny: func(host string, reasons []string, redactedURL string) {
			a.onWrapDeny(sessRef, profileID, profileName, ask, host, reasons, redactedURL)
		},
	})
	if err != nil {
		return err
	}
	sessRef = sess

	cmdArgs := append([]string{}, p.Command...)
	if len(cmdArgs) == 0 {
		_ = sess.Stop()
		return fmt.Errorf("profile has empty command")
	}
	st := sess.Status()
	argv, envExtra, clean, err := run.WrapSandbox(sandbox, cmdArgs, st.ProxyURL)
	if clean != nil {
		defer clean()
	}
	if err != nil {
		_ = sess.Stop()
		return err
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	if p.WorkDir != "" {
		cmd.Dir = p.WorkDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	base := os.Environ()
	for k, v := range st.Env {
		base = append(base, k+"="+v)
	}
	base = append(base, envExtra...)
	base = append(base, "DENYOUT_DESKTOP_NOTIFY=1", "DENYOUT_PROFILE_ID="+p.ID)
	cmd.Env = base

	if err := cmd.Start(); err != nil {
		_ = sess.Stop()
		return err
	}
	wp := &wrapProc{id: p.ID, name: p.Name, cmd: cmd, sess: sess, started: time.Now()}
	a.mu.Lock()
	a.wraps[p.ID] = wp
	a.state.WrapPIDs = appendPID(a.state.WrapPIDs, cmd.Process.Pid)
	stSave := a.state
	a.mu.Unlock()
	_ = SaveState(stSave)
	notify.Info("DenyOut", "Started: "+p.Name)
	if sandbox == "" {
		fmt.Fprintln(os.Stderr, "denyout: note - without Stronger isolation (srt), some tools can bypass the proxy")
	}

	go func() {
		_ = cmd.Wait()
		_ = sess.Stop()
		a.mu.Lock()
		delete(a.wraps, p.ID)
		a.state.WrapPIDs = removePID(a.state.WrapPIDs, cmd.Process.Pid)
		st2 := a.state
		a.mu.Unlock()
		_ = SaveState(st2)
	}()
	return nil
}

func (a *App) onWrapDeny(sess *run.Session, profileID, profileName string, ask bool, host string, reasons []string, redactedURL string) {
	a.mu.Lock()
	a.lastDeny = host
	a.state.LastDenyHost = host
	a.state.LastDenySummary = notify.HumanReasons(reasons)
	a.state.LastDenyURL = strings.TrimSpace(redactedURL)
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	hostNotAllowed := false
	for _, r := range reasons {
		if r == "host_not_allowed" {
			hostNotAllowed = true
		}
	}
	if isIPLiteral(host) {
		if a.asks == nil {
			a.asks = newAskFlight()
		}
		a.asks.notifyIPBlocked(host)
		return
	}
	if ask && hostNotAllowed {
		action := a.coalescedAskProfile(host, "host_not_allowed", profileName)
		switch action {
		case "once":
			if sess != nil {
				sess.AllowHost(host, "user_once")
			}
			_ = a.recordProfileOnce(profileID, host)
		case "always":
			if sess != nil {
				sess.AllowHost(host, "user_always")
			}
			_ = a.recordProfileAlways(profileID, host)
		}
		return
	}
	if isClearPostBlock(reasons) {
		go a.handlePostBlockDeny(host, reasons, redactedURL)
		return
	}
	// Other denies (e.g. host_not_allowed without Ask): History only.
}

func (a *App) recordProfileOnce(id, host string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	if p.Learning.Enabled {
		p.AddPendingOnce(host)
	} else {
		// Learning off: Once is session-only (already AllowHost).
		return nil
	}
	return SaveProfile(p)
}

func (a *App) recordProfileAlways(id, host string) error {
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	p.PinPending([]string{host})
	if len(p.ExtraAllow) == 0 || !containsFold(p.ExtraAllow, host) {
		p.ExtraAllow = append(p.ExtraAllow, strings.ToLower(strings.TrimSpace(host)))
	}
	return SaveProfile(p)
}

func containsFold(list []string, host string) bool {
	for _, h := range list {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func (a *App) stopProfile(id string) {
	a.ensureWraps()
	a.mu.Lock()
	wp := a.wraps[id]
	delete(a.wraps, id)
	a.mu.Unlock()
	if wp == nil {
		return
	}
	if wp.cmd != nil && wp.cmd.Process != nil {
		_ = wp.cmd.Process.Kill()
		_, _ = wp.cmd.Process.Wait()
		a.mu.Lock()
		a.state.WrapPIDs = removePID(a.state.WrapPIDs, wp.cmd.Process.Pid)
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
	}
	if wp.sess != nil {
		_ = wp.sess.Stop()
	}
	notify.Info("DenyOut", "Stopped: "+wp.name)
}

func (a *App) stopAllWraps(reason string) {
	a.stopAllWrapsOpts(reason, false)
}

func (a *App) stopAllWrapsOpts(reason string, force bool) {
	a.ensureWraps()
	a.mu.Lock()
	ids := make([]string, 0, len(a.wraps))
	for id := range a.wraps {
		ids = append(ids, id)
	}
	n := len(ids)
	a.mu.Unlock()
	if n == 0 {
		return
	}
	if !force && n > 1 {
		msg := fmt.Sprintf("Stop %d running agents?", n)
		if reason != "" {
			msg += "\n\n" + reason
		}
		if !nativeConfirm("DenyOut", msg, "Stop all", "Cancel") {
			return
		}
	}
	for _, id := range ids {
		a.stopProfile(id)
	}
}

func (a *App) runningWrapCount() int {
	a.ensureWraps()
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.wraps)
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

func appendPID(list []int, pid int) []int {
	if pid <= 0 {
		return list
	}
	for _, p := range list {
		if p == pid {
			return list
		}
	}
	return append(list, pid)
}

func removePID(list []int, pid int) []int {
	out := list[:0]
	for _, p := range list {
		if p != pid {
			out = append(out, p)
		}
	}
	return out
}

// ProfilePathForCLI exposes profile path for CLI messages.
func ProfilePathForCLI(id string) string {
	return filepath.Join(ProfilesDir(), id+".yaml")
}
